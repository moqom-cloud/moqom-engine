//! Drives a relay with one publisher and many subscribers, and reports what it
//! did.
//!
//! # What this is for
//!
//! The arithmetic a relay exists to perform is fan-out: one publisher is read
//! once and the bytes are copied to everybody watching. Every claim in the plan
//! about how many viewers a machine carries rests on that, and until this existed
//! none of those numbers had been measured here — the only published figures for
//! fan-out over this protocol belong to somebody else's implementation.
//!
//! # Why it drives the real client
//!
//! Subscribers here are `moqom_client::Session`, the same type a customer links.
//! A generator with its own cut-down client would measure a path nobody uses, and
//! the first thing anybody would ask of a surprising number is whether the
//! generator was the reason — so the client is shared and the question does not
//! arise. The same rule the CLI keeps, for the same reason.
//!
//! # Why it also reads the relay's metrics
//!
//! A generator that reports only what its subscribers received cannot distinguish
//! a relay that delivered to everyone from one that delivered to most and gave up
//! on the rest, because the subscribers it gave up on are the ones whose numbers
//! went quiet. The relay counts what it decided to do, so the two views together
//! catch a class of failure neither sees alone.
//!
//! That is not hypothetical. The relay used to abandon a subgroup once four chunks
//! had queued for a subscriber, which measured its own scheduler rather than the
//! subscriber's link, and it shed healthy viewers whenever a writer task lost the
//! CPU. It was found because a test flaked under load. `moqom_relay_subgroups_shed_total`
//! staying at zero while every subscriber is being drained promptly is that bug
//! as an assertion.
//!
//! # What it does not do
//!
//! No packet loss, no added latency, no reordering: this saturates a healthy path
//! and says what happened. Impairment is the lossy-link harness, which is a
//! separate tool and the thing `moqom-cc` waits on.
//!
//! # Running it
//!
//! A relay has to be told to trust the tokens this mints, and the subscribers all
//! come from one machine, so:
//!
//! ```text
//! moqom-load jwks > /tmp/loadgen-jwks.json
//! MOQOM_RELAY_JWKS=/tmp/loadgen-jwks.json \
//!   MOQOM_RELAY_ISSUER=https://loadgen.moqom.invalid \
//!   MOQOM_RELAY_ADMIN_ADDR=127.0.0.1:9091 \
//!   moqom-relay &
//! ulimit -n 4096   # one UDP socket per subscriber, and the default is far below
//! moqom-load fanout --relay 127.0.0.1:4433 --metrics 127.0.0.1:9091 \
//!   --subscribers 200 --seconds 20 --insecure
//! ```

mod film;
mod mint;
mod scrape;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use moqom_client::{
    Announcement, Bytes, Credentials, DeviceKey, FullTrackName, Metadata, Object, ObjectProperties,
    OutgoingObject, Session, TrackNamespace,
};
use moqom_media::annexb::{AccessUnit, Codec};
use tokio::sync::{mpsc, watch};

use crate::film::Film;
use crate::mint::{Identity, Mint};
use crate::scrape::Reading;

/// The seed the token-signing key is derived from.
///
/// Fixed so that the key set a relay is configured with stays valid across runs.
/// See `mint` for why that matters and why this key being public is a property
/// rather than an oversight.
const SEED: [u8; 32] = [0x6d; 32];

/// How long a minted token lasts: the fifteen minutes a relay accepts at most.
///
/// As long as allowed, because a session whose credential lapses is closed by
/// the relay and would appear in the results as a subscriber that stopped
/// receiving — which is a real behaviour, correctly implemented, and nothing to
/// do with fan-out. Runs longer than this renew every [`RENEW_EVERY`].
const TOKEN_SECONDS: u64 = moqom_token::MAX_LIFETIME.as_secs();

/// How often every session presents a fresh token.
///
/// Two thirds of the way through a token's life, so a renewal the relay is slow
/// to apply still lands before the old deadline.
const RENEW_EVERY: Duration = Duration::from_secs(TOKEN_SECONDS * 2 / 3);

/// Holds an announcement and renews its session's token until dropped.
///
/// Dropping withdraws the announcement, exactly as dropping the announcement
/// itself would.
struct Renewing(tokio::task::JoinHandle<()>);

impl Drop for Renewing {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Keep the publisher's session alive past its first token.
fn keep_renewed(mut announcement: Announcement, mint: Arc<Mint>, who: Identity) -> Renewing {
    Renewing(tokio::spawn(async move {
        let mut renew =
            tokio::time::interval_at(tokio::time::Instant::now() + RENEW_EVERY, RENEW_EVERY);
        loop {
            renew.tick().await;
            let renewed = match mint.token(&who, 0b11, TOKEN_SECONDS) {
                Ok(token) => announcement
                    .renew(&Credentials::proven(token.as_bytes(), &who.key))
                    .await
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            if let Err(e) = renewed {
                eprintln!("renewing the publisher's token: {e}");
            }
        }
    }))
}

/// How long to wait for every subscriber to be watching before publishing.
///
/// Generous, because this is the part of a run that is genuinely serial in the
/// relay: a few hundred handshakes, each with a signature to verify.
const READY_PATIENCE: Duration = Duration::from_mins(1);

/// How often the drain checks whether objects are still arriving.
const SETTLE_POLL: Duration = Duration::from_millis(100);

/// How long delivery has to be quiet before the drain calls it finished.
///
/// Longer than a frame interval and longer than an ordinary retransmission, so a
/// gap between two arrivals is not mistaken for the end of the stream.
const SETTLE_QUIET: Duration = Duration::from_millis(1500);

/// The longest the drain will wait for delivery to go quiet.
///
/// A bound rather than a target: a subscriber the relay has abandoned stops
/// receiving and never resumes, and without this the run would wait for a tail
/// that is not coming.
const SETTLE_LIMIT: Duration = Duration::from_secs(30);

/// How long a stopped subscriber waits for objects that are already in its buffer.
const LAST_GASP: Duration = Duration::from_millis(250);

/// `DOES_NOT_EXIST`, which is how a relay says nothing here publishes that name.
///
/// Written as the number rather than reached for through `moqom-proto`, because a
/// harness that linked the wire crate to read one constant would be the beginning
/// of a second implementation of the protocol living in the test tools.
const DOES_NOT_EXIST: u64 = 0x10;

/// How long to leave a track alone before asking for it again.
const RETRY_SUBSCRIBE: Duration = Duration::from_millis(500);

/// Stands in for the parameter sets a real keyframe carries.
///
/// Present because a group's first object carrying a configuration is what a
/// subscriber uses to start decoding, so a load that omitted it would be
/// exercising a slightly easier encoding than the real one.
const CONFIGURATION: &[u8] = &[0x27; 64];

#[derive(Parser)]
#[command(
    name = "moqom-load",
    about = "Drive a relay with one publisher and many subscribers"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Publish one track and watch it from many subscribers, all here.
    ///
    /// Convenient and self-contained, and limited by being self-contained: the
    /// generator competes with the relay for the machine, so a result near the
    /// ceiling says as much about this host as about the relay. Use `publish` and
    /// `watch` on separate hosts for a number worth quoting.
    Fanout(Box<FanoutArgs>),
    /// Publish one track and nothing else, for the host that feeds a fleet.
    Publish(Box<PublishArgs>),
    /// Watch a track published elsewhere, for the hosts that make up the load.
    Watch(Box<WatchArgs>),
    /// Print the key set a relay must trust to admit this harness's tokens.
    Jwks,
    /// Print one token, for a relay that needs a credential of its own, and write
    /// the device key it is bound to.
    ///
    /// An edge relay authenticates to its parent like anything else, so a tier whose
    /// parent verifies credentials needs one of these in
    /// `MOQOM_RELAY_UPSTREAM_TOKEN` and the key in `MOQOM_RELAY_UPSTREAM_KEY`. It is minted as a viewer in the room, which is
    /// enough to read the tracks an edge is there to forward and no more. A real
    /// fleet would give its relays a service credential scoped to the tenant rather
    /// than to one room.
    Token(Box<TokenArgs>),
}

#[derive(clap::Args)]
struct TokenArgs {
    /// The tenant the credential belongs to.
    #[arg(long, default_value = "acme")]
    tenant: String,

    /// The room it admits its holder to.
    #[arg(long, default_value = "room-42")]
    room: String,

    /// How long it lasts, in seconds.
    ///
    /// The fifteen-minute maximum by default, because an edge holds one for the
    /// life of the process and a link that drops mid-run because a token expired
    /// looks exactly like the tiering not working. Longer is refused: no relay
    /// accepts it.
    #[arg(long, default_value_t = TOKEN_SECONDS)]
    seconds: u64,

    /// Where to write the PKCS#8 device key the token is bound to.
    #[arg(long)]
    key: std::path::PathBuf,
}

/// Where the relay is and who the identities belong to.
///
/// Identical on every host in a run. The track name is derived from the tenant
/// and the room rather than passed, so a publisher and a subscriber given the same
/// pair agree on what they are talking about without being told.
#[derive(clap::Args, Clone)]
struct Common {
    /// Relay address, `HOST:PORT`.
    #[arg(long)]
    relay: String,

    /// The relay's admin listener, `HOST:PORT`, for reading its own counters.
    ///
    /// Optional, and worth setting: without it a run reports what arrived and
    /// cannot report what the relay decided, which is half the point. Needs
    /// `MOQOM_RELAY_ADMIN_ADDR` set on the relay. On a multi-host run, set it on
    /// one host only — every scrape competes with the load for the relay's CPU.
    #[arg(long, value_name = "HOST:PORT")]
    metrics: Option<String>,

    /// The tenant the identities belong to.
    #[arg(long, default_value = "acme")]
    tenant: String,

    /// The room they are in.
    #[arg(long, default_value = "room-42")]
    room: String,

    /// Skip certificate verification, for a self-signed development relay.
    #[arg(long)]
    insecure: bool,

    /// How often to print a live line while the run is in progress, in seconds.
    ///
    /// Zero is silent until the end, which is how a fleet generator should stay
    /// so eight hosts do not flood one terminal. The default is on for a local
    /// `fanout` and for the publisher, because those are the processes an
    /// operator is watching.
    #[arg(long, default_value_t = 2)]
    live: u64,
}

/// The traffic a run consists of.
///
/// Given to both roles, because a subscriber needs to know what a complete group
/// looks like in order to say it lost something. That is what lets the two roles
/// be separate processes on separate machines with no channel between them: the
/// subscriber checks arrivals against the shape it was told to expect rather than
/// against a count reported by the publisher.
///
/// `fps` and `frame-bytes` are the publisher's business alone, and are accepted by
/// `watch` only so that every host in a run takes the same flags.
///
/// `file` is the exception that has to be given to both: a subscriber reads it to
/// learn how long each group is, which is what keeps loss detection exact when
/// group lengths come from an encoder instead of from a flag.
#[derive(clap::Args, Clone)]
struct Shape {
    /// How long to publish, or to watch for.
    #[arg(long, default_value_t = 10)]
    seconds: u64,

    /// Frames per second to publish.
    #[arg(long, default_value_t = 30.0)]
    fps: f64,

    /// Bytes per frame, when publishing synthetic frames.
    ///
    /// The default is a small frame rather than a realistic one on purpose: it
    /// puts the cost in packets and objects, which is where a relay's own
    /// bottleneck is, instead of in the link. Ignored when `--file` is given,
    /// where the frames are whatever the encoder made them.
    #[arg(long, default_value_t = 4096)]
    frame_bytes: usize,

    /// Frames per group, when publishing synthetic frames.
    ///
    /// This is the interval a subscriber could join on. Ignored when `--file` is
    /// given, where a group is a GOP and the encoder decided how long it is.
    #[arg(long, default_value_t = 30)]
    frames_per_group: u64,

    /// Publish a real Annex B elementary stream instead of synthetic frames.
    ///
    /// `ffmpeg -i clip.mp4 -c:v copy -bsf:v h264_mp4toannexb clip.h264` makes
    /// one. Looped to fill a run longer than the clip. Every host in the run
    /// needs the same file at the same path, subscribers included: that is where
    /// they learn how many frames each group should hold.
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,

    /// Which codec's NAL headers `--file` carries.
    #[arg(long, value_enum, default_value_t = Codec::H264)]
    codec: Codec,
}

impl Shape {
    /// Read the clip, if this run publishes one.
    fn film(&self) -> Fallible<Option<Film>> {
        match &self.file {
            Some(path) => Ok(Some(Film::load(path, self.codec)?)),
            None => Ok(None),
        }
    }

    /// How many objects each group should hold.
    fn expected(&self, film: Option<&Film>) -> Expected {
        match film {
            Some(film) => Expected::Cycle(film.gops().to_vec()),
            None => Expected::Flat(self.frames_per_group),
        }
    }
}

/// How many objects a complete group holds.
///
/// A subscriber needs this to read loss out of the numbering, and gets it without
/// being told anything by the publisher: either both roles were given the same
/// count, or both roles were given the same file.
enum Expected {
    /// Every group the same length, as synthetic frames are.
    Flat(u64),
    /// Group lengths from a clip, cycling as publishing loops it.
    Cycle(Vec<u64>),
}

impl Expected {
    /// How many objects group `group` should hold.
    fn objects_in(&self, group: u64) -> u64 {
        match self {
            Self::Flat(count) => *count,
            Self::Cycle(gops) => {
                if gops.is_empty() {
                    return 0;
                }
                let index = usize::try_from(group % gops.len() as u64).unwrap_or(0);
                gops.get(index).copied().unwrap_or(0)
            }
        }
    }
}

/// How many subscribers this host contributes.
#[derive(clap::Args, Clone)]
struct Crowd {
    /// How many subscribers to run here.
    ///
    /// Each is a separate session with its own identity and its own UDP socket,
    /// so the file-descriptor limit is the first ceiling a large run meets.
    #[arg(long, default_value_t = 50)]
    subscribers: usize,

    /// Where this host's viewer numbering starts.
    ///
    /// Every subscriber must be a distinct identity or the relay charges several
    /// of them the same allowance and the run measures the rate limiter. Hosts
    /// therefore take disjoint ranges: with 500 each, the second host passes
    /// `--first-viewer 500`. Overlapping ranges are the one configuration
    /// mistake here that produces a plausible-looking wrong answer.
    #[arg(long, default_value_t = 0)]
    first_viewer: usize,
}

#[derive(clap::Args)]
struct FanoutArgs {
    #[command(flatten)]
    common: Common,
    #[command(flatten)]
    shape: Shape,
    #[command(flatten)]
    crowd: Crowd,
}

#[derive(clap::Args)]
struct PublishArgs {
    #[command(flatten)]
    common: Common,
    #[command(flatten)]
    shape: Shape,

    /// How long to hold the track open after publishing stops.
    ///
    /// The last group is still in flight when the frames run out, and dropping the
    /// session withdraws the track — so a publisher that exits immediately takes
    /// its own tail with it and every subscriber reports the loss.
    #[arg(long, default_value_t = 10)]
    linger: u64,
}

#[derive(clap::Args)]
struct WatchArgs {
    #[command(flatten)]
    common: Common,
    #[command(flatten)]
    shape: Shape,
    #[command(flatten)]
    crowd: Crowd,

    /// How long to wait for the track to appear before giving up.
    ///
    /// A subscriber that starts before the publisher is refused, because a relay
    /// holding no publisher for a namespace says so rather than waiting. Hosts in
    /// a fleet cannot be started simultaneously, so this retries instead.
    #[arg(long, default_value_t = 60)]
    wait: u64,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(true) => ExitCode::SUCCESS,
        // A run that completed and failed its own checks. Distinguished from an
        // error because the numbers are still worth reading, and were printed.
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

async fn run() -> Fallible<bool> {
    match Cli::parse().command {
        Command::Jwks => {
            let mint = Mint::from_seed(&SEED)?;
            eprintln!(
                "# The signing key for this key set is public: it is derived from a \
                 constant in\n# moqom-loadgen. Give it only to a relay you are \
                 measuring. Anyone can mint\n# tokens it will accept.\n\
                 # Set MOQOM_RELAY_ISSUER={} alongside it.",
                mint::ISSUER
            );
            println!("{}", mint.jwks());
            Ok(true)
        }
        Command::Token(args) => {
            let mint = Mint::from_seed(&SEED)?;
            // A viewer rather than a publisher: an edge reads from its parent and
            // never announces there, and a credential that could publish would let a
            // compromised edge inject tracks into the fleet.
            let who = Identity::relay(&args.tenant, &args.room);
            std::fs::write(&args.key, Identity::pkcs8(&who.user))?;
            println!("{}", mint.token(&who, 0, args.seconds)?);
            Ok(true)
        }
        Command::Fanout(args) => fanout(&args).await,
        Command::Publish(args) => publish_only(&args).await,
        Command::Watch(args) => watch_only(&args).await,
    }
}

/// The track a run is about, derived from the tenant and the room.
///
/// Both roles compute it the same way from the same two flags, which is why no
/// host has to be told the publisher's identity.
fn track_of(common: &Common) -> Fallible<(Identity, FullTrackName)> {
    let publisher = Identity::publisher(&common.tenant, &common.room);
    let slot = publisher.slot();
    let namespace = TrackNamespace::from_parts(slot.split('/'))?;
    let track = FullTrackName::new(namespace, Bytes::from_static(b"video/720p"))?;
    Ok((publisher, track))
}

/// One publisher, many subscribers, and a report.
async fn fanout(args: &FanoutArgs) -> Fallible<bool> {
    let (server_name, addr) = resolve(&args.common.relay)?;
    let mint = Arc::new(Mint::from_seed(&SEED)?);
    let (publisher, track) = track_of(&args.common)?;
    // Before connecting, so that an unreadable file fails the run immediately
    // rather than after a few hundred subscribers have been stood up.
    let film = args.shape.film()?;

    // Before anything connects, because the counters this is compared against
    // include the subscriptions themselves. A baseline taken once everybody is
    // watching would show no subscriptions at all during the run and report the
    // fan-out deduplication as missing.
    let before = read_metrics(args.common.metrics.as_deref()).await;

    let token = mint.token(&publisher, 0b11, TOKEN_SECONDS)?;
    let mut session = connect(
        addr,
        &server_name,
        args.common.insecure,
        &token,
        &publisher.key,
    )
    .await?;
    let announcement = session
        .announce(track.namespace().clone())
        .await
        .map_err(|e| format!("announcing the track: {e}"))?;

    // Subscribers first, so the publisher is asked for the track before it sends
    // anything. A subscription arriving mid-group would start at the next one,
    // and a run where some subscribers joined late would be reporting on a
    // different number of frames per subscriber.
    let mut crowd = gather(
        &args.common,
        &args.crowd,
        &mint,
        addr,
        &server_name,
        &track,
        0,
    );
    let refused = wait_for_subscribers(&mut crowd.arrived, args.crowd.subscribers).await?;
    if refused > 0 {
        eprintln!("{refused} subscriber(s) never started; the rest continue");
    }
    // The relay asks for a track once however many people are watching, so this
    // is the moment the publisher learns anybody is there at all.
    tokio::time::timeout(READY_PATIENCE, announcement.subscribed())
        .await
        .map_err(|_| "the relay never asked for the track")?;
    let alias = announcement.alias();
    let _renewing = keep_renewed(announcement, Arc::clone(&mint), publisher.clone());

    let live = spawn_live(
        args.common.live,
        args.shape.seconds,
        args.common.metrics.clone(),
        Some(Arc::clone(&crowd.progress)),
    );
    let sent = publish(&session, alias, &args.shape, film.as_ref()).await?;
    live.abort();
    // Drop nothing yet: the publisher's session has to outlive the drain below,
    // or the relay withdraws the track and the tail of the last group is lost for
    // reasons that would read as loss.
    let drained = drain(&crowd.stop, crowd.watchers, &crowd.progress).await;
    let after = read_metrics(args.common.metrics.as_deref()).await;
    drop(session);

    Ok(report(
        &Reporting {
            shape: &args.shape,
            per_group: &args.shape.expected(film.as_ref()),
            expected: args.crowd.subscribers,
            sent: Some(&sent),
        },
        &drained,
        before.as_ref(),
        after.as_ref(),
    ))
}

/// Publish the track and hold it, for the one host that feeds a fleet.
async fn publish_only(args: &PublishArgs) -> Fallible<bool> {
    let (server_name, addr) = resolve(&args.common.relay)?;
    let mint = Arc::new(Mint::from_seed(&SEED)?);
    let (publisher, track) = track_of(&args.common)?;
    let film = args.shape.film()?;

    // Before connecting, so the subscriptions themselves fall inside the window
    // the growth is measured over.
    let before = read_metrics(args.common.metrics.as_deref()).await;

    let token = mint.token(&publisher, 0b11, TOKEN_SECONDS)?;
    let mut session = connect(
        addr,
        &server_name,
        args.common.insecure,
        &token,
        &publisher.key,
    )
    .await?;
    let announcement = session
        .announce(track.namespace().clone())
        .await
        .map_err(|e| format!("announcing the track: {e}"))?;
    eprintln!("announced {track}; waiting for the first subscriber");

    // Nothing is published until somebody is watching, because objects sent before
    // the relay has asked for the track are not pulled and would be silently lost
    // — and on a fleet the subscriber hosts start after this one.
    tokio::time::timeout(READY_PATIENCE, announcement.subscribed())
        .await
        .map_err(|_| "nobody subscribed, so there was nothing to publish to")?;
    let alias = announcement.alias();
    let _renewing = keep_renewed(announcement, Arc::clone(&mint), publisher.clone());

    let live = spawn_live(
        args.common.live,
        args.shape.seconds + args.linger,
        args.common.metrics.clone(),
        None,
    );
    let sent = publish(&session, alias, &args.shape, film.as_ref()).await?;
    println!(
        "published     {} frames in {} group(s), {:.1} MiB at {:.1}/s",
        sent.frames,
        sent.groups,
        bytes_as_mib(sent.bytes),
        rate(sent.frames, sent.elapsed),
    );

    eprintln!("holding the track open for {}s", args.linger);
    tokio::time::sleep(Duration::from_secs(args.linger)).await;
    live.abort();

    // The relay's own account belongs to whichever host was given --metrics, and
    // on a fleet that should be this one: it is the host that started first, so
    // its baseline is the only one taken before anybody had subscribed.
    let after = read_metrics(args.common.metrics.as_deref()).await;
    let mut findings = Vec::new();
    if let (Some(before), Some(after)) = (before.as_ref(), after.as_ref()) {
        findings = what_the_relay_says(
            &Reporting {
                shape: &args.shape,
                per_group: &args.shape.expected(film.as_ref()),
                // This host runs no subscribers of its own, which is what makes
                // the relay-wide comparisons safe to leave switched on.
                expected: 0,
                sent: Some(&sent),
            },
            before,
            after,
        );
    }
    for finding in &findings {
        println!("PROBLEM      {finding}");
    }
    Ok(findings.is_empty())
}

/// Watch a track somebody else is publishing, for the hosts that are the load.
async fn watch_only(args: &WatchArgs) -> Fallible<bool> {
    let (server_name, addr) = resolve(&args.common.relay)?;
    let mint = Arc::new(Mint::from_seed(&SEED)?);
    let (_, track) = track_of(&args.common)?;
    // Read for its group lengths, not to publish it: this host has to know how
    // long a complete group is to say whether one arrived whole, and a clip is
    // where that comes from when an encoder chose the boundaries.
    let film = args.shape.film()?;

    let before = read_metrics(args.common.metrics.as_deref()).await;
    let mut crowd = gather(
        &args.common,
        &args.crowd,
        &mint,
        addr,
        &server_name,
        &track,
        args.wait,
    );
    let refused = wait_for_subscribers(&mut crowd.arrived, args.crowd.subscribers).await?;
    if refused > 0 {
        eprintln!("{refused} subscriber(s) never started; the rest continue");
    }

    eprintln!("watching for {}s", args.shape.seconds);
    let live = spawn_live(
        args.common.live,
        args.shape.seconds,
        args.common.metrics.clone(),
        Some(Arc::clone(&crowd.progress)),
    );
    tokio::time::sleep(Duration::from_secs(args.shape.seconds)).await;
    live.abort();

    let drained = drain(&crowd.stop, crowd.watchers, &crowd.progress).await;
    let after = read_metrics(args.common.metrics.as_deref()).await;

    Ok(report(
        &Reporting {
            shape: &args.shape,
            per_group: &args.shape.expected(film.as_ref()),
            expected: args.crowd.subscribers,
            // Nothing here knows what the publisher sent, which is the point:
            // loss is read out of the numbering instead.
            sent: None,
        },
        &drained,
        before.as_ref(),
        after.as_ref(),
    ))
}

/// The subscribers this host is running, and the handles to stop and collect them.
struct Crowded {
    watchers: Vec<tokio::task::JoinHandle<Tally>>,
    arrived: mpsc::Receiver<Result<(), String>>,
    stop: watch::Sender<bool>,
    progress: Arc<AtomicU64>,
}

/// Start this host's share of the subscribers.
fn gather(
    common: &Common,
    crowd: &Crowd,
    mint: &Arc<Mint>,
    addr: SocketAddr,
    server_name: &str,
    track: &FullTrackName,
    wait: u64,
) -> Crowded {
    eprintln!(
        "connecting {} subscribers, numbered from {}",
        crowd.subscribers, crowd.first_viewer
    );
    let (ready, arrived) = mpsc::channel(crowd.subscribers.max(1));
    let (stop, listening) = watch::channel(false);
    let progress = Arc::new(AtomicU64::new(0));
    let mut watchers = Vec::with_capacity(crowd.subscribers);

    for n in 0..crowd.subscribers {
        let who = Identity::viewer(&common.tenant, &common.room, crowd.first_viewer + n);
        let token = mint
            .token(&who, 0, TOKEN_SECONDS)
            .expect("TOKEN_SECONDS is within the lifetime a token may have");
        watchers.push(tokio::spawn(watch_track(
            Watching {
                addr,
                server_name: server_name.to_owned(),
                insecure: common.insecure,
                token,
                mint: Arc::clone(mint),
                who,
                track: track.clone(),
                progress: Arc::clone(&progress),
                wait: Duration::from_secs(wait),
            },
            ready.clone(),
            listening.clone(),
        )));
    }

    Crowded {
        watchers,
        arrived,
        stop,
        progress,
    }
}

/// Everything one subscriber needs to start watching.
struct Watching {
    addr: SocketAddr,
    server_name: String,
    insecure: bool,
    token: String,
    /// What renews `token`, for the identity it was minted for.
    mint: Arc<Mint>,
    who: Identity,
    track: FullTrackName,
    /// Objects received across every subscriber, so the drain can tell delivery
    /// still in flight from delivery that has stopped.
    progress: Arc<AtomicU64>,
    /// How long to keep retrying a track the relay says nobody publishes.
    wait: Duration,
}

/// What the publisher managed to send.
struct Sent {
    frames: u64,
    groups: u64,
    bytes: u64,
    elapsed: Duration,
}

/// What one subscriber received.
#[derive(Default)]
struct Tally {
    objects: u64,
    bytes: u64,
    keyframes: u64,
    /// How many objects arrived in each group, keyed by group.
    ///
    /// This is what makes a subscriber able to say it lost something without
    /// being told what was sent. Objects are numbered from zero within a group
    /// and groups ascend by one, so a count short of the group size is a hole and
    /// a group ID never seen is a group that never came. A subscriber on another
    /// machine can therefore report loss with no channel back to the publisher,
    /// which is what lets the two roles be separate processes.
    per_group: BTreeMap<u64, u64>,
    /// Every latency, kept rather than summarised so percentiles are exact.
    latencies: Vec<Duration>,
    /// Why this subscriber stopped early, if it did.
    fault: Option<String>,
}

/// What a subscriber did not get, read out of the numbering.
#[derive(Debug, Default, PartialEq, Eq)]
struct Losses {
    /// Objects missing from groups that did arrive.
    holes: u64,
    /// Groups between the first and the last that never arrived at all.
    absent_groups: u64,
}

impl Losses {
    const fn any(&self) -> bool {
        self.holes > 0 || self.absent_groups > 0
    }
}

impl Tally {
    fn record(&mut self, object: &Object) {
        self.objects = self.objects.saturating_add(1);
        self.bytes = self.bytes.saturating_add(object.payload.len() as u64);
        *self.per_group.entry(object.group.get()).or_default() += 1;
        if object.properties.configuration.is_some() {
            self.keyframes = self.keyframes.saturating_add(1);
        }
        if let Some(captured) = object.properties.capture_time_micros {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            // Saturating rather than signed: both ends read the same clock here,
            // so a negative figure would mean the clock went backwards, which is
            // a statement about the clock and not a latency worth averaging.
            self.latencies
                .push(now.saturating_sub(Duration::from_micros(captured)));
        }
    }

    /// What went missing, given how long a full group is.
    ///
    /// The first and last groups are excluded from the count. A subscriber joins
    /// partway through one group and is stopped partway through another, so both
    /// are legitimately short and counting them would report the run's own edges
    /// as loss.
    fn losses(&self, expected: &Expected) -> Losses {
        let mut losses = Losses::default();
        let (Some(first), Some(last)) = (
            self.per_group.keys().next().copied(),
            self.per_group.keys().next_back().copied(),
        ) else {
            return losses;
        };

        for group in first.saturating_add(1)..last {
            match self.per_group.get(&group) {
                Some(&count) => losses.holes += expected.objects_in(group).saturating_sub(count),
                None => losses.absent_groups += 1,
            }
        }
        losses
    }
}

/// Connect and subscribe, then drain until told to stop.
async fn watch_track(
    watching: Watching,
    ready: mpsc::Sender<Result<(), String>>,
    mut listening: watch::Receiver<bool>,
) -> Tally {
    let mut tally = Tally::default();

    let session = connect(
        watching.addr,
        &watching.server_name,
        watching.insecure,
        &watching.token,
        &watching.who.key,
    )
    .await;
    let mut session = match session {
        Ok(session) => session,
        Err(e) => {
            let _ = ready.send(Err(e.to_string())).await;
            tally.fault = Some(e.to_string());
            return tally;
        }
    };

    let mut subscription =
        match subscribe_when_published(&mut session, &watching.track, watching.wait).await {
            Ok(subscription) => subscription,
            Err(e) => {
                let _ = ready.send(Err(e.to_string())).await;
                tally.fault = Some(e.to_string());
                return tally;
            }
        };
    if ready.send(Ok(())).await.is_err() {
        return tally;
    }

    let mut renew =
        tokio::time::interval_at(tokio::time::Instant::now() + RENEW_EVERY, RENEW_EVERY);
    while !*listening.borrow() {
        tokio::select! {
            _ = listening.changed() => break,
            _ = renew.tick() => {
                let renewed = match watching.mint.token(&watching.who, 0, TOKEN_SECONDS) {
                    Ok(token) => subscription
                        .renew(&Credentials::proven(token.as_bytes(), &watching.who.key))
                        .await
                        .map_err(|e| e.to_string()),
                    Err(e) => Err(e.to_string()),
                };
                if let Err(e) = renewed {
                    tally.fault = Some(format!("renewing the token: {e}"));
                    break;
                }
            }
                next = subscription.next_object() => match next {
                Ok(Some(object)) => {
                    tally.record(&object);
                    watching.progress.fetch_add(1, Ordering::Relaxed);
                }
                // The session ended, which at this point means the publisher
                // stopped or the relay hung up.
                Ok(None) => break,
                Err(e) => {
                    tally.fault = Some(e.to_string());
                    break;
                }
            },
        }
    }

    // Whatever has already arrived is part of what the relay delivered, so it is
    // collected rather than dropped on the floor. Stopping the loop above the
    // instant the run ends would count objects sitting in this subscriber's own
    // buffer as objects that never came, which reads as loss and is not.
    while let Ok(Ok(Some(object))) =
        tokio::time::timeout(LAST_GASP, subscription.next_object()).await
    {
        tally.record(&object);
    }
    tally
}

/// Subscribe, retrying while the relay says the track is not published here.
///
/// A relay with no publisher for a namespace refuses rather than waiting, which is
/// the right behaviour and awkward for a fleet: the hosts cannot be started at the
/// same instant, so the early ones would fail on a track that is about to exist.
/// Only that one refusal is retried — an unauthorised or malformed request would
/// be refused identically on every attempt, and retrying it would turn a
/// configuration mistake into a timeout.
async fn subscribe_when_published(
    session: &mut Session,
    track: &FullTrackName,
    wait: Duration,
) -> Result<moqom_client::Subscription, moqom_client::Error> {
    let deadline = Instant::now() + wait;
    loop {
        match session.subscribe(track.clone()).await {
            Ok(subscription) => return Ok(subscription),
            Err(moqom_client::Error::Refused { code, reason })
                if code == DOES_NOT_EXIST && Instant::now() < deadline =>
            {
                let _ = reason;
                tokio::time::sleep(RETRY_SUBSCRIBE).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Publish frames at the requested rate for the requested time.
///
/// One loop for both kinds of frame. What differs between a clip and synthetic
/// traffic is only where a frame's bytes come from and where a group ends, so
/// those are decided per frame and everything about pacing, timing and accounting
/// is shared -- which is what makes a before-and-after pair of runs comparable
/// when one of them used a file.
async fn publish(
    session: &Session,
    alias: moqom_client::TrackAlias,
    shape: &Shape,
    film: Option<&Film>,
) -> Fallible<Sent> {
    let synthetic = vec![0x5a; shape.frame_bytes];
    let interval = Duration::from_secs_f64(1.0 / shape.fps.max(0.001));
    let mut ticker = tokio::time::interval(interval);
    // Delay rather than catch up. A generator that cannot keep up should report a
    // rate below the one asked for, not fire a burst that arrives as a spike and
    // reads as the relay's jitter.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let began = Instant::now();
    let deadline = began + Duration::from_secs(shape.seconds);
    let mut sent = Sent {
        frames: 0,
        groups: 0,
        bytes: 0,
        elapsed: Duration::ZERO,
    };

    let mut group = 0_u64;
    let mut within = shape.frames_per_group;
    let mut frame = 0_usize;
    let mut writer: Option<moqom_client::GroupWriter> = None;
    match film {
        Some(film) => eprintln!(
            "publishing for {}s from {} frames in {} group(s), {:.2} Mbit/s at {} fps",
            shape.seconds,
            film.units().len(),
            film.groups(),
            film.bits_per_second(shape.fps) / 1_000_000.0,
            shape.fps,
        ),
        None => eprintln!("publishing for {}s", shape.seconds),
    }

    while Instant::now() < deadline {
        ticker.tick().await;

        // A clip's groups begin where the encoder put a keyframe; synthetic ones
        // begin on a count. Either way the decision is made before the frame is
        // written, because a group's first object is the one that carries the
        // configuration a joining subscriber needs.
        let unit = film.map(|film| &film.units()[frame % film.units().len()]);
        let opens_group = match unit {
            Some(unit) => unit.is_keyframe,
            None => within >= shape.frames_per_group,
        };

        if opens_group {
            if let Some(open) = writer.take() {
                open.finish()?;
            }
            writer = Some(session.open_group(alias, group, Metadata::Present).await?);
            group = group.saturating_add(1);
            sent.groups = sent.groups.saturating_add(1);
            within = 0;
        }
        let open = writer.as_mut().ok_or("a group to write into")?;

        let payload: &[u8] = match unit {
            Some(unit) => &unit.payload,
            None => &synthetic,
        };
        let properties = ObjectProperties {
            capture_time_micros: Some(micros_now()),
            // Only on the frame that opens a group, which is where a real
            // publisher puts them.
            configuration: opens_group.then(|| configuration(unit)),
            temporal_layer: unit.and_then(|unit| unit.temporal_layer),
            ..ObjectProperties::default()
        };
        open.write(&OutgoingObject::tagged(payload, properties))
            .await?;

        within = within.saturating_add(1);
        frame = frame.saturating_add(1);
        sent.frames = sent.frames.saturating_add(1);
        sent.bytes = sent.bytes.saturating_add(payload.len() as u64);
    }

    if let Some(open) = writer.take() {
        open.finish()?;
    }
    sent.elapsed = began.elapsed();
    Ok(sent)
}

/// The parameter sets to open a group with.
///
/// A clip carries its own; synthetic traffic gets a stand-in of about the right
/// size, so that both shapes of run put a configuration on the object a
/// subscriber would join on rather than one of them exercising a cheaper
/// encoding than the other.
fn configuration(unit: Option<&AccessUnit>) -> Bytes {
    match unit {
        Some(unit) if !unit.configuration.is_empty() => unit.configuration.clone(),
        _ => Bytes::from_static(CONFIGURATION),
    }
}

/// Tell the subscribers to stop, and collect what they saw.
///
/// Waits for delivery to go quiet rather than for a fixed moment. The last frames
/// are still in flight when the publisher finishes, and under load that tail is
/// as long as the tail latency — so a fixed grace shorter than it reports frames
/// that were about to arrive as frames that never did, which is loss the relay
/// did not cause.
async fn drain(
    stop: &watch::Sender<bool>,
    watchers: Vec<tokio::task::JoinHandle<Tally>>,
    progress: &AtomicU64,
) -> Vec<Tally> {
    let limit = Instant::now() + SETTLE_LIMIT;
    let mut last = progress.load(Ordering::Relaxed);
    let mut quiet_since = Instant::now();
    while Instant::now() < limit {
        tokio::time::sleep(SETTLE_POLL).await;
        let now = progress.load(Ordering::Relaxed);
        if now == last {
            if quiet_since.elapsed() >= SETTLE_QUIET {
                break;
            }
        } else {
            last = now;
            quiet_since = Instant::now();
        }
    }
    let _ = stop.send(true);

    let mut tallies = Vec::with_capacity(watchers.len());
    for watcher in watchers {
        match watcher.await {
            Ok(tally) => tallies.push(tally),
            Err(e) => tallies.push(Tally {
                fault: Some(format!("the subscriber's task failed: {e}")),
                ..Tally::default()
            }),
        }
    }
    tallies
}

/// Wait for every subscriber to be watching, or for them all to have answered.
async fn wait_for_subscribers(
    arrived: &mut mpsc::Receiver<Result<(), String>>,
    expected: usize,
) -> Fallible<usize> {
    let mut watching = 0;
    let mut refused = 0;
    let mut first_reason = None;

    while watching + refused < expected {
        let next = tokio::time::timeout(READY_PATIENCE, arrived.recv())
            .await
            .map_err(|_| {
                format!("only {watching} of {expected} subscribers were watching in time")
            })?;
        match next {
            Some(Ok(())) => watching += 1,
            Some(Err(reason)) => {
                refused += 1;
                first_reason.get_or_insert(reason);
            }
            None => break,
        }
    }

    if watching == 0 {
        let reason = first_reason.unwrap_or_else(|| "no reason given".to_owned());
        return Err(format!("no subscriber could watch the track: {reason}").into());
    }
    if let Some(reason) = first_reason {
        eprintln!("a subscriber was refused: {reason}");
    }
    Ok(refused)
}

/// Print a one-line snapshot every `every` seconds so a run is readable while
/// it is still happening, not only after it ends.
///
/// The relay scrape is optional and belongs on one host: every GET competes
/// with the load for the relay's CPU, which is why `watch` on a fleet is not
/// given `--metrics`. Progress is the subscribers' own count, which costs
/// nothing to read.
fn spawn_live(
    every: u64,
    for_secs: u64,
    metrics: Option<String>,
    progress: Option<Arc<AtomicU64>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if every == 0 || for_secs == 0 {
            return;
        }
        let began = Instant::now();
        let limit = Duration::from_secs(for_secs);
        let mut ticker = tokio::time::interval(Duration::from_secs(every));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut previous: Option<Reading> = None;
        let mut previous_at = began;
        loop {
            ticker.tick().await;
            if began.elapsed() >= limit {
                break;
            }
            let mut line = format!("live         t+{}s", began.elapsed().as_secs());
            if let Some(progress) = &progress {
                let _ = write!(line, "  objects={}", progress.load(Ordering::Relaxed));
            }
            if let Some(addr) = &metrics {
                match Reading::take(addr).await {
                    Ok(reading) => {
                        let sess = reading.get("moqom_relay_sessions");
                        let shed = previous.as_ref().map_or_else(
                            || reading.get("moqom_relay_subgroups_shed_total"),
                            |before| before.growth(&reading, "moqom_relay_subgroups_shed_total"),
                        );
                        let dt = previous_at.elapsed().as_secs_f64().max(0.001);
                        let gbit = previous.as_ref().map_or(0.0, |before| {
                            before.growth(&reading, "moqom_relay_egress_bytes_total") * 8.0
                                / dt
                                / 1_000_000_000.0
                        });
                        let _ = write!(line, "  sess={sess:.0}  shed={shed:.0}  {gbit:.2} Gbit/s");
                        previous = Some(reading);
                        previous_at = Instant::now();
                    }
                    Err(error) => {
                        let _ = write!(line, "  relay=({error})");
                    }
                }
            }
            eprintln!("{line}");
        }
    })
}

/// Scrape the relay, reporting rather than failing if it cannot be reached.
///
/// A run without metrics is still worth having: it measures arrival, and only
/// loses the relay's own account of what it decided.
async fn read_metrics(addr: Option<&str>) -> Option<Reading> {
    let addr = addr?;
    match Reading::take(addr).await {
        Ok(reading) => Some(reading),
        Err(e) => {
            eprintln!("no metrics from {addr}: {e}");
            None
        }
    }
}

async fn connect(
    addr: SocketAddr,
    server_name: &str,
    insecure: bool,
    token: &str,
    key: &DeviceKey,
) -> Result<Session, moqom_client::Error> {
    let tls = if insecure {
        moqom_client::tls::insecure()
    } else {
        moqom_client::tls::native()
    };
    let credentials = Credentials::proven(token.as_bytes(), key);
    Session::connect(addr, server_name, tls, Some(&credentials)).await
}

/// `HOST:PORT` as the name to verify and the address to reach.
fn resolve(relay: &str) -> Fallible<(String, SocketAddr)> {
    let (host, _) = relay
        .rsplit_once(':')
        .ok_or("a relay address needs a port, as HOST:PORT")?;
    let addr = relay
        .to_socket_addrs()?
        .next()
        .ok_or("that relay address resolved to nothing")?;
    Ok((host.to_owned(), addr))
}

fn micros_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

/// Print what happened, and say whether it was what should have happened.
///
/// Counts become `f64` only to be printed. An `f64` is exact to 2^53, which is
/// more objects and more bytes than a run will produce.
#[allow(clippy::cast_precision_loss)]
fn report(
    about: &Reporting<'_>,
    tallies: &[Tally],
    before: Option<&Reading>,
    after: Option<&Reading>,
) -> bool {
    let watching = tallies.iter().filter(|t| t.objects > 0).count();
    let faulted: Vec<&String> = tallies.iter().filter_map(|t| t.fault.as_ref()).collect();
    let received: u64 = tallies.iter().map(|t| t.objects).sum();
    let bytes: u64 = tallies.iter().map(|t| t.bytes).sum();
    let least = tallies.iter().map(|t| t.objects).min().unwrap_or(0);
    let most = tallies.iter().map(|t| t.objects).max().unwrap_or(0);

    // The publisher's own elapsed time when there is one, and the nominal run
    // length otherwise. A subscriber host has no view of when the publisher
    // started, so its rates are over the window it was asked to watch.
    let seconds = about
        .sent
        .map_or_else(
            || Duration::from_secs(about.shape.seconds),
            |sent| sent.elapsed,
        )
        .as_secs_f64()
        .max(f64::EPSILON);

    let mut latencies: Vec<Duration> = tallies.iter().flat_map(|t| t.latencies.clone()).collect();
    latencies.sort_unstable();

    let losses: Vec<Losses> = tallies.iter().map(|t| t.losses(about.per_group)).collect();
    let holes: u64 = losses.iter().map(|l| l.holes).sum();
    let absent: u64 = losses.iter().map(|l| l.absent_groups).sum();
    let lossy = losses.iter().filter(|l| l.any()).count();

    println!();
    if let Some(sent) = about.sent {
        println!(
            "publisher    {} frames in {} group(s), {:.1} MiB at {:.1}/s (asked for {:.1})",
            sent.frames,
            sent.groups,
            bytes_as_mib(sent.bytes),
            rate(sent.frames, sent.elapsed),
            about.shape.fps,
        );
    }
    println!(
        "subscribers  {watching} of {} received anything; each got between {least} and {most} objects",
        about.expected,
    );
    println!(
        "objects      {received} received in total, {:.1} MiB",
        bytes_as_mib(bytes),
    );
    if latencies.is_empty() {
        println!("latency      nothing carried a capture time");
    } else {
        println!(
            "latency      p50 {:.1}ms  p95 {:.1}ms  p99 {:.1}ms  max {:.1}ms",
            millis(percentile(&latencies, 50)),
            millis(percentile(&latencies, 95)),
            millis(percentile(&latencies, 99)),
            millis(latencies[latencies.len() - 1]),
        );
    }
    println!(
        "loss         {lossy} subscriber(s) missed something: {holes} object(s) inside a group, {absent} whole group(s)",
    );
    println!(
        "throughput   {:.0} Mbit/s delivered across every subscriber",
        (bytes as f64 * 8.0) / seconds / 1_000_000.0,
    );

    for fault in faulted.iter().take(3) {
        println!("fault        {fault}");
    }
    if faulted.len() > 3 {
        println!("fault        and {} more like it", faulted.len() - 3);
    }

    let mut findings = Vec::new();
    if holes > 0 || absent > 0 {
        findings.push(format!(
            "{lossy} subscriber(s) lost data: {holes} object(s) missing from groups that arrived, and {absent} group(s) that never arrived at all"
        ));
    }
    if watching < about.expected {
        findings.push(format!(
            "{} of {} subscribers received nothing",
            about.expected - watching,
            about.expected
        ));
    }

    if let (Some(before), Some(after)) = (before, after) {
        findings.extend(what_the_relay_says(about, before, after));
    } else {
        println!("relay        not scraped; pass --metrics to check what it decided");
    }

    println!();
    if findings.is_empty() {
        println!("Every subscriber received every object, and the relay gave up on nothing.");
        return true;
    }
    // Named here rather than left implied, because on a fleet this is the
    // difference between a relay that failed and a load host that could not keep
    // up, and the report cannot tell them apart on its own.
    if lossy > 0 {
        println!(
            "note         loss can be this host rather than the relay; check its dropped\n\
             note         datagrams and whether it was short of CPU before blaming the relay"
        );
    }
    for finding in &findings {
        println!("PROBLEM      {finding}");
    }
    false
}

/// What a report is about, so one function serves both roles.
struct Reporting<'a> {
    shape: &'a Shape,
    /// How long a complete group is, which is how loss is read.
    per_group: &'a Expected,
    /// How many subscribers this host meant to run.
    expected: usize,
    /// What the publisher sent, when this host is also the publisher.
    sent: Option<&'a Sent>,
}

/// The relay's own account, and the invariants it has to satisfy.
#[allow(clippy::cast_precision_loss)]
fn what_the_relay_says(about: &Reporting<'_>, before: &Reading, after: &Reading) -> Vec<String> {
    let ingress = before.growth(after, "moqom_relay_ingress_bytes_total");
    let egress = before.growth(after, "moqom_relay_egress_bytes_total");
    let shed = before.growth(after, "moqom_relay_subgroups_shed_total");
    let failures = before.growth(after, "moqom_relay_fanout_failures_total");
    let shared = before.growth(
        after,
        r#"moqom_relay_subscriptions_total{outcome="shared"}"#,
    );
    let established = before.growth(
        after,
        r#"moqom_relay_subscriptions_total{outcome="established"}"#,
    );

    println!(
        "relay        read {:.1} MiB and wrote {:.1} MiB, a fan-out of {:.1}x",
        ingress / (1024.0 * 1024.0),
        egress / (1024.0 * 1024.0),
        if ingress > 0.0 { egress / ingress } else { 0.0 },
    );
    println!("             {shed:.0} subgroup(s) shed, {failures:.0} fan-out failure(s)");
    println!(
        "             the publisher was asked {established:.0} time(s); {shared:.0} subscription(s) shared it",
    );

    let mut findings = Vec::new();
    // The one this harness exists to catch. Every subscriber here is drained as
    // fast as it arrives, so a shed copy is the relay deciding a healthy viewer
    // was too slow -- which is what it used to do under nothing worse than its
    // own scheduling.
    if shed > 0.0 {
        findings.push(format!(
            "the relay shed {shed:.0} subgroup(s) from subscribers that were being drained promptly"
        ));
    }
    if failures > 0.0 {
        findings.push(format!("the relay failed {failures:.0} fan-out write(s)"));
    }
    // Deduplicating the upstream pull is the arithmetic a relay is for: however
    // many people watch, the publisher is asked once. This one holds however many
    // hosts are generating load, since it is a statement about the relay rather
    // than about who asked.
    if established > 1.0 {
        findings.push(format!(
            "the publisher was asked for the track {established:.0} times, not once"
        ));
    }

    // The remaining two compare a relay-wide counter against what this host did,
    // so they only mean something when this host is the whole run. On a fleet the
    // relay's totals include everybody else's subscribers and the arithmetic would
    // be against the wrong denominator.
    if let Some(sent) = about.sent {
        let expected_shared = about.expected.saturating_sub(1) as f64;
        if shared < expected_shared {
            findings.push(format!(
                "only {shared:.0} of {expected_shared:.0} subscriptions shared the publisher's stream"
            ));
        }
        if sent.frames > 0 && ingress <= 0.0 {
            findings.push("the relay read nothing from the publisher".to_owned());
        }
    }
    findings
}

/// Bytes as mebibytes, for printing.
#[allow(clippy::cast_precision_loss)]
fn bytes_as_mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

/// A count per second over `elapsed`.
#[allow(clippy::cast_precision_loss)]
fn rate(count: u64, elapsed: Duration) -> f64 {
    count as f64 / elapsed.as_secs_f64().max(f64::EPSILON)
}

/// The value at `percent` through a sorted slice.
///
/// Integer arithmetic on the index, so there is no float in a percentile of
/// durations and nothing to round inconsistently.
fn percentile(sorted: &[Duration], percent: usize) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let last = sorted.len() - 1;
    sorted[last * percent / 100]
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_renew_well_before_their_token_lapses() {
        let margin = Duration::from_secs(TOKEN_SECONDS)
            .checked_sub(RENEW_EVERY)
            .expect("renewal comes before the token lapses");
        assert!(margin >= READY_PATIENCE);
    }

    const PER_GROUP: u64 = 30;

    fn shape() -> Shape {
        Shape {
            seconds: 1,
            fps: 30.0,
            frame_bytes: 16,
            frames_per_group: PER_GROUP,
            file: None,
            codec: Codec::H264,
        }
    }

    /// Every group the same length, as synthetic frames make them.
    fn flat() -> Expected {
        Expected::Flat(PER_GROUP)
    }

    fn sent(frames: u64) -> Sent {
        Sent {
            frames,
            groups: 1,
            bytes: frames * 16,
            elapsed: Duration::from_secs(1),
        }
    }

    /// A report about a host that is also the publisher, and so knows everything.
    fn whole_run(shape: &Shape, sent: &Sent, subscribers: usize) -> Reporting<'static> {
        // Leaked rather than juggled through lifetimes: this is a test helper and
        // the values live as long as the test binary either way.
        Reporting {
            shape: Box::leak(Box::new(shape.clone())),
            per_group: Box::leak(Box::new(flat())),
            expected: subscribers,
            sent: Some(Box::leak(Box::new(Sent {
                frames: sent.frames,
                groups: sent.groups,
                bytes: sent.bytes,
                elapsed: sent.elapsed,
            }))),
        }
    }

    /// A tally that received `groups` complete groups.
    fn complete(groups: u64) -> Tally {
        let mut tally = Tally::default();
        for group in 0..groups {
            tally.per_group.insert(group, PER_GROUP);
            tally.objects += PER_GROUP;
        }
        tally
    }

    #[test]
    fn a_relay_address_yields_the_name_to_verify() {
        let (name, _) = resolve("127.0.0.1:4433").expect("an address");
        assert_eq!(name, "127.0.0.1");
        assert!(resolve("127.0.0.1").is_err(), "a port is required");
    }

    #[test]
    fn percentiles_come_from_the_ends_of_the_distribution() {
        let sorted: Vec<Duration> = (0..=100).map(Duration::from_millis).collect();
        assert_eq!(percentile(&sorted, 50), Duration::from_millis(50));
        assert_eq!(percentile(&sorted, 99), Duration::from_millis(99));
        assert_eq!(percentile(&[], 50), Duration::ZERO);
    }

    /// The assertion the harness exists for: a shed copy is a finding, because
    /// every subscriber here is drained as fast as objects arrive.
    #[test]
    fn a_shed_subgroup_is_reported_as_a_problem() {
        let before = Reading::of(&[("moqom_relay_subgroups_shed_total", 0.0)]);
        let after = Reading::of(&[("moqom_relay_subgroups_shed_total", 3.0)]);
        let findings = what_the_relay_says(&whole_run(&shape(), &sent(30), 2), &before, &after);
        assert!(
            findings.iter().any(|f| f.contains("shed 3")),
            "expected the shed copies to be reported: {findings:?}"
        );
    }

    /// Fan-out deduplication is the arithmetic a relay is for, so a publisher
    /// asked more than once is a finding even when every byte arrived.
    #[test]
    fn asking_the_publisher_more_than_once_is_a_problem() {
        let before = Reading::of(&[]);
        let after = Reading::of(&[
            (
                r#"moqom_relay_subscriptions_total{outcome="established"}"#,
                4.0,
            ),
            (r#"moqom_relay_subscriptions_total{outcome="shared"}"#, 0.0),
            ("moqom_relay_ingress_bytes_total", 480.0),
        ]);
        let findings = what_the_relay_says(&whole_run(&shape(), &sent(30), 4), &before, &after);
        assert!(
            findings.iter().any(|f| f.contains("not once")),
            "expected the duplicated pull to be reported: {findings:?}"
        );
    }

    #[test]
    fn a_clean_run_has_nothing_to_report() {
        let before = Reading::of(&[]);
        let after = Reading::of(&[
            (
                r#"moqom_relay_subscriptions_total{outcome="established"}"#,
                1.0,
            ),
            (r#"moqom_relay_subscriptions_total{outcome="shared"}"#, 3.0),
            ("moqom_relay_ingress_bytes_total", 480.0),
            ("moqom_relay_egress_bytes_total", 1920.0),
        ]);
        let findings = what_the_relay_says(&whole_run(&shape(), &sent(30), 4), &before, &after);
        assert!(findings.is_empty(), "expected no findings: {findings:?}");
    }

    /// On a fleet the relay's totals cover every host, so comparing them against
    /// one host's subscriber count would invent a shortfall that is not there.
    #[test]
    fn a_subscriber_only_host_does_not_judge_the_relay_wide_totals() {
        let before = Reading::of(&[]);
        let after = Reading::of(&[
            (
                r#"moqom_relay_subscriptions_total{outcome="established"}"#,
                1.0,
            ),
            // Far fewer than this host's 400, because this host is one of several
            // and took its baseline after the others had already subscribed.
            (r#"moqom_relay_subscriptions_total{outcome="shared"}"#, 3.0),
        ]);
        let watching = Reporting {
            shape: &shape(),
            per_group: &flat(),
            expected: 400,
            sent: None,
        };
        let findings = what_the_relay_says(&watching, &before, &after);
        assert!(
            findings.is_empty(),
            "a watch-only host should not report a shortfall it cannot see: {findings:?}"
        );
    }

    /// Loss is read out of the numbering, which is what lets a subscriber host
    /// report it without knowing what the publisher sent.
    #[test]
    fn a_hole_inside_a_group_is_found_without_the_publishers_count() {
        let mut tally = complete(5);
        // Group 2 arrives one object short. Interior, so it is not the run's edge.
        tally.per_group.insert(2, PER_GROUP - 1);
        assert_eq!(
            tally.losses(&flat()),
            Losses {
                holes: 1,
                absent_groups: 0
            }
        );
    }

    #[test]
    fn a_group_that_never_arrived_is_found_the_same_way() {
        let mut tally = complete(5);
        tally.per_group.remove(&2);
        assert_eq!(
            tally.losses(&flat()),
            Losses {
                holes: 0,
                absent_groups: 1
            }
        );
    }

    /// The first and last groups are short because of when the subscriber joined
    /// and when it was stopped, not because anything was lost.
    #[test]
    fn the_groups_at_the_edges_of_a_run_are_not_counted_as_loss() {
        let mut tally = complete(4);
        tally.per_group.insert(0, 7);
        tally.per_group.insert(3, 11);
        assert_eq!(tally.losses(&flat()), Losses::default());
    }

    #[test]
    fn a_subscriber_that_saw_one_group_cannot_be_short() {
        let tally = complete(1);
        assert_eq!(tally.losses(&flat()), Losses::default());
        assert_eq!(Tally::default().losses(&flat()), Losses::default());
    }

    /// Loss has to fail the run even when the relay's own counters look fine.
    #[test]
    fn a_subscriber_that_missed_objects_is_a_problem() {
        let mut short = complete(5);
        short.per_group.insert(2, 3);
        let tallies = vec![complete(5), short];
        let clean = report(&whole_run(&shape(), &sent(150), 2), &tallies, None, None);
        assert!(!clean, "a subscriber with a hole should fail the run");
    }
}
