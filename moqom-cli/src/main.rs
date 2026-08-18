//! The `moqom` CLI: subscribe to a track, or publish bytes or video onto one.
//!
//! Uses only [`moqom_client`]'s public API. A privileged path here would make
//! that API second-class; if a flag cannot be implemented through it, the
//! flag does not belong here yet. `--file` is what forced [`Session::open_group`]
//! to exist, which is the arrangement working as intended.
//!
//! The video path exists to make the media path testable without a device, and to
//! give the latency harness something repeatable to measure. A camera produces a
//! different stream every run, so a number taken from one cannot be compared with
//! a number taken from another; a file produces the same frames at the same sizes
//! in the same order on every machine.

mod annexb;

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use moqom_client::{
    FullTrackName, Metadata, Object, ObjectProperties, OutgoingObject, Session, TrackNamespace,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::annexb::{AccessUnit, Codec};

/// Speak MOQT as a subscriber or a publisher.
#[derive(Parser)]
#[command(
    name = "moqom",
    about = "Subscribe to a MOQT track, or publish bytes onto one"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print each object on a track, and optionally save the video.
    Subscribe(SubscribeArgs),
    /// Publish a video file, or each line of stdin.
    Publish(PublishArgs),
}

#[derive(clap::Args)]
struct Common {
    /// Relay address, `HOST:PORT`.
    #[arg(long)]
    relay: String,
    /// Track namespace, fields separated by `/`.
    #[arg(long)]
    namespace: String,
    /// Track name within that namespace.
    #[arg(long)]
    name: String,
    /// Path to a session token, sent as `AUTHORIZATION_TOKEN`.
    #[arg(long)]
    token: Option<PathBuf>,
    /// Skip certificate verification. For a self-signed development relay.
    #[arg(long)]
    insecure: bool,
}

#[derive(clap::Args)]
struct SubscribeArgs {
    #[command(flatten)]
    common: Common,

    /// Write the received video to this path as an Annex B elementary stream.
    ///
    /// Playable with `ffplay`. Parameter sets arrive as a group's configuration
    /// rather than in the frames, and are written back in front of the keyframe
    /// that carried them, so the file stands on its own.
    #[arg(long, value_name = "PATH")]
    out: Option<PathBuf>,

    /// Report arrival rate, and latency for objects that carry a capture time.
    ///
    /// The latency is the difference between two clocks. On one machine that is a
    /// real end-to-end figure; across two it is only as good as their agreement,
    /// so a number from an unsynchronised pair says more about NTP than about the
    /// relay.
    #[arg(long)]
    stats: bool,
}

#[derive(clap::Args)]
struct PublishArgs {
    #[command(flatten)]
    common: Common,

    /// Publish this Annex B elementary stream instead of reading stdin.
    ///
    /// `ffmpeg -i clip.mp4 -c:v copy -bsf:v hevc_mp4toannexb clip.h265` makes one.
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,

    /// Which codec's NAL headers the file uses.
    ///
    /// Not sniffed, because the two layouts are close enough that a wrong guess
    /// does not fail: it reads every NAL as the wrong kind and publishes a stream
    /// that arrives intact and decodes to nothing.
    #[arg(long, value_enum, default_value_t = Codec::Hevc)]
    codec: Codec,

    /// Frames per second to pace the file at.
    #[arg(long, default_value_t = 30.0)]
    fps: f64,

    /// Start the file again when it ends, for a publisher that runs as long as
    /// the measurement does.
    #[arg(long)]
    repeat: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(error) = run().await {
        eprintln!("{error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

type Fallible = Result<(), Box<dyn std::error::Error>>;

async fn run() -> Fallible {
    let cli = Cli::parse();
    match cli.command {
        Command::Subscribe(args) => subscribe(args).await,
        Command::Publish(args) => publish(args).await,
    }
}

async fn subscribe(args: SubscribeArgs) -> Fallible {
    let (mut session, track) = connect(&args.common).await?;
    let mut subscription = session.subscribe(track).await?;

    let mut sink = match &args.out {
        Some(path) => Some(Sink::create(path).await?),
        None => None,
    };
    let mut stats = args.stats.then(Stats::default);

    // C-c is a normal way to stop a subscriber -- a live track does not end -- so
    // it has to leave a written file playable rather than truncated.
    loop {
        let object = tokio::select! {
            received = subscription.next_object() => match received? {
                Some(object) => object,
                None => break,
            },
            _ = tokio::signal::ctrl_c() => {
                eprintln!("interrupted");
                break;
            }
        };

        if let Some(stats) = stats.as_mut() {
            stats.record(&object);
        }
        match sink.as_mut() {
            Some(sink) => sink.write(&object).await?,
            None if stats.is_none() => print_object(&object),
            None => {}
        }
    }

    if let Some(mut sink) = sink {
        sink.flush().await?;
    }
    if let Some(stats) = stats {
        stats.report();
    }
    Ok(())
}

async fn publish(args: PublishArgs) -> Fallible {
    let (mut session, _track) = connect(&args.common).await?;
    let namespace = namespace(&args.common.namespace)?;
    let announcement = session.announce(namespace).await?;
    eprintln!("announced; waiting for a subscriber");
    announcement.subscribed().await;

    match &args.file {
        Some(path) => publish_file(&session, &announcement, &args, path).await,
        None => publish_stdin(&session, &announcement).await,
    }
}

/// Publish each line of stdin as an object on successive groups.
async fn publish_stdin(session: &Session, announcement: &moqom_client::Announcement) -> Fallible {
    let alias = announcement.alias();
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut group = 0u64;
    while let Some(line) = lines.next_line().await? {
        session
            .publish_group(alias, group, &[line.as_bytes()])
            .await?;
        group = group.checked_add(1).ok_or("group id overflow")?;
    }
    Ok(())
}

/// Publish a file's frames, one group per group of pictures, paced at `--fps`.
async fn publish_file(
    session: &Session,
    announcement: &moqom_client::Announcement,
    args: &PublishArgs,
    path: &Path,
) -> Fallible {
    if !(args.fps.is_finite() && args.fps > 0.0) {
        return Err(format!("--fps must be a positive number, not {}", args.fps).into());
    }
    let frame_interval = Duration::from_secs_f64(1.0 / args.fps);

    let stream = std::fs::read(path)?;
    let units = annexb::access_units(&stream, args.codec);
    if units.is_empty() {
        return Err(format!(
            "{} contains no {:?} access units. Is it Annex B, and is --codec right?",
            path.display(),
            args.codec
        )
        .into());
    }
    if !units[0].is_keyframe {
        eprintln!(
            "warning: the first frame is not a keyframe, so a viewer cannot decode \
             until the next one"
        );
    }
    let keyframes = units.iter().filter(|unit| unit.is_keyframe).count();
    eprintln!(
        "publishing {} frames in {keyframes} group(s) at {} fps",
        units.len(),
        args.fps
    );

    let alias = announcement.alias();
    let mut group = 0u64;
    let mut open: Option<moqom_client::GroupWriter> = None;
    let mut frames = 0u64;
    // A monotonic schedule rather than sleeping for an interval after each frame,
    // which would add however long publishing took to every frame and drift.
    let began = Instant::now();
    let mut sent = 0u32;

    loop {
        for unit in &units {
            tokio::time::sleep_until(tokio::time::Instant::from_std(
                began + frame_interval.saturating_mul(sent),
            ))
            .await;
            sent = sent.saturating_add(1);

            // A keyframe ends the group before it, because a group is a group of
            // pictures: everything in one depends on the keyframe that starts it,
            // which is what makes a group the unit a relay can drop and a joiner
            // can start at.
            if unit.is_keyframe
                && let Some(previous) = open.take()
            {
                previous.finish()?;
                group = group.checked_add(1).ok_or("group id overflow")?;
            }
            // Either that keyframe just closed one, or this is a delta frame
            // arriving before any keyframe. The second is a file that starts
            // mid-GOP, and it gets a group anyway rather than being dropped: a
            // viewer recovers at the next keyframe either way, and silently
            // discarding encoder output gets diagnosed as a broken encoder.
            if open.is_none() {
                open = Some(session.open_group(alias, group, Metadata::Present).await?);
            }
            let writer = open.as_mut().expect("opened just above");

            writer
                .write(&OutgoingObject::tagged(&unit.payload, properties(unit)))
                .await?;
            frames = frames.saturating_add(1);
        }

        if !args.repeat {
            break;
        }
        // The next pass is a new group either way, since the file starts on a
        // keyframe: leaving the last group open across the loop would put the
        // first frame of the repeat into the last group of the previous pass.
        if let Some(previous) = open.take() {
            previous.finish()?;
            group = group.checked_add(1).ok_or("group id overflow")?;
        }
    }

    if let Some(last) = open {
        last.finish()?;
    }
    eprintln!("published {frames} frames in {} group(s)", group + 1);
    Ok(())
}

/// What to say about a frame.
///
/// The capture time is the moment the frame is handed to the transport, not a
/// timestamp computed from the frame rate. They are the same to within the pacing
/// error, and only the first is a clock a subscriber can subtract from its own:
/// a synthetic one starting at zero would report a latency of however long the
/// file has been playing.
fn properties(unit: &AccessUnit) -> ObjectProperties {
    let mut properties = ObjectProperties::default();
    if let Ok(since_epoch) = SystemTime::now().duration_since(UNIX_EPOCH) {
        properties = properties
            .captured_at_micros(u64::try_from(since_epoch.as_micros()).unwrap_or(u64::MAX));
    }
    if unit.is_keyframe && !unit.configuration.is_empty() {
        properties = properties.opening(unit.configuration.clone());
    }
    properties.temporal_layer = unit.temporal_layer;
    properties
}

/// A file being written from received objects.
struct Sink {
    file: tokio::fs::File,
    buffer: Vec<u8>,
}

impl Sink {
    async fn create(path: &Path) -> std::io::Result<Self> {
        Ok(Self {
            file: tokio::fs::File::create(path).await?,
            buffer: Vec::new(),
        })
    }

    async fn write(&mut self, object: &Object) -> std::io::Result<()> {
        self.buffer.clear();
        // The parameter sets came as this group's configuration rather than in the
        // frame, and a file has nowhere else to put them: in front of the keyframe
        // they configure is where a decoder reading the file will look.
        if let Some(configuration) = &object.properties.configuration {
            annexb::to_annex_b(configuration, &mut self.buffer);
        }
        annexb::to_annex_b(&object.payload, &mut self.buffer);
        self.file.write_all(&self.buffer).await
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush().await
    }
}

/// Arrival counts, and latency where the publisher stated a capture time.
#[derive(Default)]
struct Stats {
    objects: u64,
    bytes: u64,
    keyframes: u64,
    groups: std::collections::BTreeSet<u64>,
    /// Every latency, kept rather than summarised so the percentiles are exact.
    /// At thirty frames a second an hour of this is a few megabytes.
    latencies: Vec<Duration>,
    began: Option<Instant>,
}

impl Stats {
    fn record(&mut self, object: &Object) {
        self.began.get_or_insert_with(Instant::now);
        self.objects = self.objects.saturating_add(1);
        self.bytes = self.bytes.saturating_add(object.payload.len() as u64);
        self.groups.insert(object.group.get());
        if object.properties.configuration.is_some() {
            self.keyframes = self.keyframes.saturating_add(1);
        }

        if let Some(captured) = object.properties.capture_time_micros {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            // Saturating rather than signed: a negative figure means the two
            // clocks disagree about the order of events, which is a statement
            // about the clocks and not a latency worth averaging in.
            let latency = now.saturating_sub(Duration::from_micros(captured));
            self.latencies.push(latency);
        }
    }

    // Counts become f64 only to be printed. An f64 is exact to 2^53, which is
    // eight petabytes of payload and rather more objects than a run will produce.
    #[allow(clippy::cast_precision_loss)]
    fn report(mut self) {
        let elapsed = self.began.map_or(Duration::ZERO, |began| began.elapsed());
        eprintln!();
        eprintln!(
            "{} objects, {} in {} group(s), {:.1} MiB over {:.1}s ({:.1}/s)",
            self.objects,
            self.keyframes,
            self.groups.len(),
            self.bytes as f64 / (1024.0 * 1024.0),
            elapsed.as_secs_f64(),
            self.objects as f64 / elapsed.as_secs_f64().max(f64::EPSILON),
        );

        if self.latencies.is_empty() {
            eprintln!("no capture times, so no latency: the publisher stated none");
            return;
        }
        self.latencies.sort_unstable();
        // Integer arithmetic on the index, so a percentile is a sample that was
        // actually measured rather than a rounded float landing next to one.
        let last = self.latencies.len() - 1;
        let at = |percent: usize| self.latencies[last * percent / 100];
        let millis = |latency: Duration| latency.as_secs_f64() * 1000.0;
        eprintln!(
            "latency p50 {:.1}ms  p95 {:.1}ms  p99 {:.1}ms  max {:.1}ms  (n={})",
            millis(at(50)),
            millis(at(95)),
            millis(at(99)),
            millis(at(100)),
            self.latencies.len(),
        );
        eprintln!(
            "measured between the publisher's clock and this one; across two \
             machines it is only as good as their agreement"
        );
    }
}

async fn connect(common: &Common) -> Result<(Session, FullTrackName), Box<dyn std::error::Error>> {
    let (server_name, addr) = resolve(&common.relay)?;
    let tls = if common.insecure {
        moqom_client::tls::insecure()
    } else {
        moqom_client::tls::native()
    };
    let token = match &common.token {
        Some(path) => Some(std::fs::read(path)?),
        None => None,
    };
    let session = Session::connect(addr, &server_name, tls, token.as_deref()).await?;
    let track = FullTrackName::new(
        namespace(&common.namespace)?,
        common.name.as_bytes().to_vec().into(),
    )?;
    Ok((session, track))
}

fn namespace(spec: &str) -> Result<TrackNamespace, moqom_client::NameError> {
    TrackNamespace::from_parts(spec.split('/').filter(|field| !field.is_empty()))
}

fn resolve(relay: &str) -> Result<(String, SocketAddr), Box<dyn std::error::Error>> {
    let host = host_of(relay).to_owned();
    let addr = relay
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| format!("could not resolve {relay}"))?;
    Ok((host, addr))
}

fn host_of(relay: &str) -> &str {
    if let Some(rest) = relay.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(relay);
    }
    relay.rsplit_once(':').map_or(relay, |(host, _)| host)
}

fn print_object(object: &Object) {
    let bytes = object.payload.len();
    if bytes <= 32 {
        eprintln!(
            "group={} object={} bytes={bytes} {}",
            object.group,
            object.object,
            Hex(&object.payload)
        );
    } else {
        eprintln!(
            "group={} object={} bytes={bytes}",
            object.group, object.object
        );
    }
}

struct Hex<'a>(&'a [u8]);

impl std::fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
