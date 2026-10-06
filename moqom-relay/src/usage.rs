//! Billable usage: what each session cost, cut into intervals and reported.
//!
//! Nothing a tenant is charged for streaming exists until a relay says so, and
//! the relay is the only party that can: it is the one writing the bytes. This
//! module meters every participant session on the relay and hands the control
//! plane's billing endpoint one record per session per interval. The sending
//! half is [`report`].
//!
//! # What a record says
//!
//! One record covers one session for one wall-clock interval — sixty seconds
//! by default, aligned to the epoch so that every relay cuts at the same
//! instants. A session that spans three boundaries is four records: the
//! partial interval it joined in, two whole ones, and the partial one it left
//! in. Each carries:
//!
//! - **seconds** connected in the interval, measured on the monotonic clock so
//!   a stepped wall clock cannot invent or erase time. Interim cuts floor and
//!   the final cut rounds, against the session's running total, so a session's
//!   records sum to its length rather than to its length less a fraction per
//!   interval.
//! - **`egress_bytes`**, payload written to this participant: every forwarded
//!   subgroup copy, counted where `moqom_relay_egress_bytes_total` is, plus
//!   fetches served from history, which that metric does not count.
//! - **`ingress_bytes`**, payload read from this participant's tracks.
//! - **`direct_seconds`**, time in the interval during which the participant
//!   held at least one live direct ticket — see [`crate::ticket`]. Rounded the
//!   way `seconds` is, and omitted when zero so that an endpoint that predates
//!   it reads the same record it always did. Direct media is never in the byte
//!   counts: it does not pass through this relay.
//! - **role** and **tier**, below.
//!
//! # Roles
//!
//! A token says what somebody may do, not which price list they are on, so the
//! role is read from the grants the session holds:
//!
//! | Grants | Role |
//! | --- | --- |
//! | owns the room, or may publish audio, video or screen and is not backstage | `host` |
//! | admitted to a room, otherwise — viewers, backstage guests, moderators | `audience` |
//! | no room: watching a personal channel outside a call | `broadcast_audience` |
//!
//! A room viewer is `audience` rather than `broadcast_audience` because a room
//! viewer can be put on stage in place, on the connection they are watching on
//! — that is what a regrant is — and the token carries nothing that says a
//! given viewer never will be. The hosted recorder joins as a room viewer and
//! is billed as one; nothing here tells it apart.
//!
//! The highest role held at any sample during an interval is the interval's,
//! so a viewer promoted for the last ten seconds of a minute is a host for that
//! minute. A relay holding no verification keys has no grants to read; there a
//! session that sent media in the interval is a host and any other is
//! audience.
//!
//! # Tiers
//!
//! The tier is the largest sum, over the interval, of the pixels of every video
//! track the participant was subscribed to at once — the rule the price list is
//! written in. Geometry comes from each publisher's `.catalog`, the one payload
//! a relay may read. Where a catalog is missing or omits a dimension the
//! track's name decides: `video/720p` is a 720-line rung at 16:9, and a camera
//! or screen track whose name gives no rung is taken as 1280×720. Audio, data,
//! reserved and unrecognised tracks count nothing, so a session receiving no
//! video is `audio`.
//!
//! The sum is recomputed when a subscription starts and every [`SAMPLE`]
//! otherwise, so a resolution change mid-subscription is seen within that
//! period.
//!
//! # Identifiers
//!
//! `{relay}:{interval start, RFC 3339}:{user}/{device}#{boot}.{session}`. The
//! billing endpoint charges an identifier once, so these must be unique per
//! session-interval and identical across retries. The session number restarts
//! with the process, so the boot time in milliseconds goes beside it, and a
//! participant who reconnects within one interval is two sessions and two
//! records. An identifier over the endpoint's 200-character limit is replaced
//! by a digest of itself, which is just as deterministic.
//!
//! The relay's name has to be unique in the fleet: two relays sharing one would
//! have each other's records counted as duplicates.

pub mod report;

use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use moqom_proto::model::{FullTrackName, TrackNamespace};
use serde::Serialize;
use tokio::sync::{Notify, watch};

use crate::catalog::{self, Described};
use crate::fabric::SessionId;
use crate::media::{self, Kinds};
use crate::scope::{Permission, Publish};

/// How often live meters are re-sampled for role and tier between boundaries.
pub const SAMPLE: Duration = Duration::from_secs(5);

/// Most records in one report, the billing endpoint's limit.
pub const MOST_RECORDS: usize = 5000;
/// Most bytes of records in one report: the endpoint takes 1 MiB, and this
/// leaves room for the envelope.
pub const MOST_BODY_BYTES: usize = 1_000_000;
/// Longest identifier the endpoint accepts.
pub const LONGEST_ID: usize = 200;
/// Most seconds one record may claim.
const LONGEST_RECORD: u64 = 86_400;

/// The upper bound of each tier, in pixels.
const HD: u64 = 1280 * 720;
const FULL_HD: u64 = 1920 * 1080;
const TWO_K: u64 = 2560 * 1440;

/// Audio, video and screen, the kinds that make somebody a host. The bit
/// positions are protocol; see [`Publish`].
const MEDIA: Publish = Publish::from_bits(0b0111);

/// Whose bytes these are, which decides who pays and how a record names its
/// tenant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hosting {
    /// A relay MOQOM runs, reporting with its operator credential. Records name
    /// their tenant, so only sessions with a verified token are metered.
    Cloud,
    /// A customer's relay, reporting with their `mqk_` relay key. The key names
    /// the tenant, so records omit it, every session is metered, and each
    /// answer says whether to keep admitting.
    SelfHosted,
}

/// How a relay meters and reports.
#[derive(Clone, Debug)]
pub struct Config {
    /// This relay's name, the first part of every record identifier.
    pub relay_id: String,
    /// How long one record covers. Whole seconds; boundaries fall on multiples
    /// of it since the epoch.
    pub interval: Duration,
    /// Who pays.
    pub hosting: Hosting,
    /// Most records held unsent. Past this the oldest are dropped.
    pub capacity: usize,
    /// The first wait after a failed report.
    pub first_retry: Duration,
    /// The longest wait between attempts.
    pub longest_retry: Duration,
}

impl Config {
    /// Sixty-second records, room for 100,000 of them, and retries from one
    /// second up to a minute.
    ///
    /// 100,000 records is ten minutes of a relay with ten thousand sessions,
    /// in roughly 30 MB.
    #[must_use]
    pub fn new(relay_id: impl Into<String>, hosting: Hosting) -> Self {
        Self {
            relay_id: relay_id.into(),
            interval: Duration::from_mins(1),
            hosting,
            capacity: 100_000,
            first_retry: Duration::from_secs(1),
            longest_retry: Duration::from_mins(1),
        }
    }

    fn interval_seconds(&self) -> u64 {
        self.interval.as_secs().max(1)
    }
}

/// A billing role, as the endpoint spells it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Role {
    /// Publishes.
    #[serde(rename = "host")]
    Host,
    /// Watches at interactive latency and may be brought on stage.
    #[serde(rename = "audience")]
    Audience,
    /// Only watches.
    #[serde(rename = "broadcast_audience")]
    BroadcastAudience,
}

impl Role {
    /// The role `permission` describes. `sent` is whether the session sent any
    /// media this interval, which decides only when there are no grants.
    #[must_use]
    pub fn of(permission: &Permission, sent: bool) -> Self {
        match permission {
            Permission::Scoped(scope) => {
                if scope.owner || (!scope.backstage && !scope.publish.intersect(MEDIA).is_none()) {
                    Self::Host
                } else if scope.room.is_some() {
                    Self::Audience
                } else {
                    Self::BroadcastAudience
                }
            }
            Permission::Unrestricted | Permission::Nothing if sent => Self::Host,
            Permission::Unrestricted | Permission::Nothing => Self::Audience,
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::BroadcastAudience => 0,
            Self::Audience => 1,
            Self::Host => 2,
        }
    }

    const fn higher(self, other: Self) -> Self {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

/// A billing tier, as the endpoint spells it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Tier {
    /// No video received.
    #[serde(rename = "audio")]
    Audio,
    /// Up to 1280×720.
    #[serde(rename = "hd")]
    Hd,
    /// Up to 1920×1080.
    #[serde(rename = "full_hd")]
    FullHd,
    /// Up to 2560×1440.
    #[serde(rename = "2k")]
    TwoK,
    /// Above that.
    #[serde(rename = "2k_plus")]
    TwoKPlus,
}

impl Tier {
    /// The tier for `pixels` of video received at once.
    #[must_use]
    pub const fn of(pixels: u64) -> Self {
        if pixels == 0 {
            Self::Audio
        } else if pixels <= HD {
            Self::Hd
        } else if pixels <= FULL_HD {
            Self::FullHd
        } else if pixels <= TWO_K {
            Self::TwoK
        } else {
            Self::TwoKPlus
        }
    }
}

/// How many pixels a track called `name` carries, given what its publisher's
/// catalog said about it, if anything.
///
/// The catalog wins where it gives both dimensions. Otherwise a camera or
/// screen track is estimated from its name, and anything else is not video.
#[must_use]
pub fn pixels(name: &[u8], described: Option<Described>) -> u64 {
    match described {
        Some(Described::Other) => return 0,
        Some(Described::Video {
            width: Some(width),
            height: Some(height),
        }) => return u64::from(width) * u64::from(height),
        Some(Described::Video { .. }) | None => {}
    }
    match media::classify(name) {
        Some(kinds) if kinds == Kinds::VIDEO || kinds == Kinds::SCREEN => {
            rung_lines(name).map_or(HD, |lines| lines * lines * 16 / 9)
        }
        // A catalog that called it video outranks a name this relay does not
        // recognise.
        Some(_) if described.is_some() => HD,
        _ => 0,
    }
}

/// The line count a rung name gives, as in `video/720p`.
fn rung_lines(name: &[u8]) -> Option<u64> {
    let slash = name.iter().position(|byte| *byte == b'/')?;
    let rung = name.get(slash + 1..)?.strip_suffix(b"p")?;
    if rung.is_empty() || rung.len() > 5 || !rung.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(rung)
        .ok()?
        .parse()
        .ok()
        .filter(|&lines| lines > 0)
}

/// One record, as the billing endpoint reads it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Record {
    /// Unique per session-interval; see the module docs.
    pub id: String,
    /// Present for [`Hosting::Cloud`] and absent for a relay key, which names
    /// the tenant itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// The room, absent for a personal channel.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub room: String,
    /// `user/device`, absent for a session with no verified identity.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub participant: String,
    /// See the module docs.
    pub role: Role,
    /// See the module docs.
    pub tier: Tier,
    /// Connected time in this interval.
    pub seconds: u64,
    /// Bytes sent to this participant.
    pub egress_bytes: u64,
    /// Bytes received from this participant.
    pub ingress_bytes: u64,
    /// Time on a direct path in this interval. See the module docs.
    #[serde(skip_serializing_if = "is_zero")]
    pub direct_seconds: u64,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's signature
const fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// A record's identifier. See the module docs.
#[must_use]
pub fn record_id(
    relay: &str,
    interval_start: u64,
    participant: &str,
    boot: u64,
    session: SessionId,
) -> String {
    let who = if participant.is_empty() {
        "anonymous"
    } else {
        participant
    };
    let id = format!(
        "{relay}:{}:{who}#{boot}.{}",
        rfc3339(interval_start),
        session.number()
    );
    if id.len() <= LONGEST_ID {
        return id;
    }
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, id.as_bytes());
    let mut short = String::with_capacity(66);
    short.push_str("h:");
    for byte in digest.as_ref() {
        let _ = write!(short, "{byte:02x}");
    }
    short
}

/// `seconds` since the epoch as `YYYY-MM-DDTHH:MM:SSZ`.
#[must_use]
pub fn rfc3339(seconds: u64) -> String {
    let days = seconds / 86_400;
    let of_day = seconds % 86_400;
    let (year, month, day) = civil(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        of_day / 3600,
        of_day % 3600 / 60,
        of_day % 60
    )
}

/// The proleptic Gregorian date `days` after 1970-01-01, after Howard Hinnant's
/// `civil_from_days`, specialised to dates on or after the epoch.
const fn civil(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let of_era = z - era * 146_097;
    let year_of_era = (of_era - of_era / 1460 + of_era / 36_524 - of_era / 146_096) / 365;
    let of_year = of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted = (5 * of_year + 2) / 153;
    let day = of_year - (153 * shifted + 2) / 5 + 1;
    let month = if shifted < 10 {
        shifted + 3
    } else {
        shifted - 9
    };
    let year = year_of_era + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

/// Seconds since the epoch, or zero for a clock set before it.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// What each publisher's catalog says about each track, for tiering the
/// people watching them.
///
/// Keyed by namespace, which is what a subscription names, and owned by the
/// session whose catalog track carried it so that the entry goes when that
/// session does.
#[derive(Debug, Default)]
struct Catalogs {
    by_namespace: Mutex<HashMap<TrackNamespace, Catalogued>>,
}

#[derive(Debug)]
struct Catalogued {
    owner: SessionId,
    tracks: HashMap<Vec<u8>, Described>,
}

impl Catalogs {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<TrackNamespace, Catalogued>> {
        self.by_namespace
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn pixels(&self, tracks: impl Iterator<Item = FullTrackName>) -> u64 {
        let catalogs = self.lock();
        tracks
            .map(|track| {
                let described = catalogs
                    .get(track.namespace())
                    .and_then(|entry| entry.tracks.get(track.name().as_ref()))
                    .copied();
                pixels(track.name().as_ref(), described)
            })
            .sum()
    }
}

/// Where one session's usage accumulates.
///
/// The counters are atomics because they are bumped on the media path, once
/// per chunk written; everything else is behind a lock only the reporter's
/// tasks and subscription changes take.
#[derive(Debug)]
pub struct Meter {
    session: SessionId,
    tenant: Option<String>,
    room: String,
    participant: String,
    permission: watch::Receiver<Option<Arc<Permission>>>,
    egress: AtomicU64,
    ingress: AtomicU64,
    catalogs: Arc<Catalogs>,
    state: Mutex<Period>,
}

#[derive(Debug)]
struct Period {
    opened: Instant,
    /// Start of the interval now accumulating, in seconds since the epoch.
    label: u64,
    reported_seconds: u64,
    reported_egress: u64,
    reported_ingress: u64,
    peak_pixels: u64,
    role: Option<Role>,
    watching: HashMap<FullTrackName, u32>,
    /// Ticket subscriptions open now. Direct time is time with at least one,
    /// whoever they are for: the price is per participant, not per pair.
    direct_open: u32,
    /// When `direct_open` last rose from zero.
    direct_since: Option<Instant>,
    /// Direct time in spans already closed, over the whole session.
    direct_closed: Duration,
    reported_direct: u64,
    /// Set by the final cut, after which nothing more is recorded.
    closed: bool,
}

impl Period {
    fn direct_total(&self, now: Instant) -> Duration {
        self.direct_closed
            + self
                .direct_since
                .map_or(Duration::ZERO, |since| now.saturating_duration_since(since))
    }
}

impl Meter {
    /// Payload written to this participant.
    pub fn egress(&self, bytes: usize) {
        self.egress.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Payload read from this participant.
    pub fn ingress(&self, bytes: usize) {
        self.ingress.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Period> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A direct ticket subscription opened.
    pub fn direct_began(&self) {
        self.direct_began_at(Instant::now());
    }

    /// A direct ticket subscription closed.
    pub fn direct_ended(&self) {
        self.direct_ended_at(Instant::now());
    }

    fn direct_began_at(&self, now: Instant) {
        let mut period = self.lock();
        if period.direct_open == 0 {
            period.direct_since = Some(now);
        }
        period.direct_open += 1;
    }

    fn direct_ended_at(&self, now: Instant) {
        let mut period = self.lock();
        period.direct_open = period.direct_open.saturating_sub(1);
        if period.direct_open == 0
            && let Some(since) = period.direct_since.take()
        {
            period.direct_closed += now.saturating_duration_since(since);
        }
    }

    /// A subscription to `track` was established.
    pub fn watch(&self, track: &FullTrackName) {
        let mut period = self.lock();
        *period.watching.entry(track.clone()).or_default() += 1;
        self.sample_locked(&mut period);
    }

    /// A subscription to `track` ended.
    pub fn unwatch(&self, track: &FullTrackName) {
        let mut period = self.lock();
        if let Some(count) = period.watching.get_mut(track) {
            *count -= 1;
            if *count == 0 {
                period.watching.remove(track);
            }
        }
    }

    fn sample(&self) {
        let mut period = self.lock();
        self.sample_locked(&mut period);
    }

    fn sample_locked(&self, period: &mut Period) {
        if period.closed {
            return;
        }
        let now = self.catalogs.pixels(period.watching.keys().cloned());
        period.peak_pixels = period.peak_pixels.max(now);
        let role = self.role_now(period);
        period.role = Some(period.role.map_or(role, |held| held.higher(role)));
    }

    fn role_now(&self, period: &Period) -> Role {
        let sent = self.ingress.load(Ordering::Relaxed) > period.reported_ingress;
        self.permission
            .borrow()
            .as_deref()
            .map_or(Role::Audience, |permission| Role::of(permission, sent))
    }

    /// Close the period accumulating at `now`, returning its record if it
    /// holds anything, and start the one labelled `next`.
    ///
    /// `last` is the session ending: the running total is rounded rather than
    /// floored, and nothing is recorded after it.
    fn cut(
        &self,
        config: &Config,
        boot: u64,
        now: Instant,
        next: u64,
        last: bool,
    ) -> Option<Record> {
        let mut period = self.lock();
        if period.closed {
            return None;
        }
        self.sample_locked(&mut period);

        let elapsed = now.saturating_duration_since(period.opened).as_millis();
        let total = u64::try_from(if last {
            (elapsed + 500) / 1000
        } else {
            elapsed / 1000
        })
        .unwrap_or(u64::MAX);
        let seconds = total.saturating_sub(period.reported_seconds);
        let direct = period.direct_total(now).as_millis();
        let direct_total = u64::try_from(if last {
            (direct + 500) / 1000
        } else {
            direct / 1000
        })
        .unwrap_or(u64::MAX);
        let egress = self.egress.load(Ordering::Relaxed);
        let ingress = self.ingress.load(Ordering::Relaxed);
        let record = Record {
            id: record_id(
                &config.relay_id,
                period.label,
                &self.participant,
                boot,
                self.session,
            ),
            tenant: self.tenant.clone(),
            room: self.room.clone(),
            participant: self.participant.clone(),
            role: period.role.unwrap_or(Role::Audience),
            tier: Tier::of(period.peak_pixels),
            seconds: seconds.min(LONGEST_RECORD),
            egress_bytes: egress.saturating_sub(period.reported_egress),
            ingress_bytes: ingress.saturating_sub(period.reported_ingress),
            direct_seconds: direct_total
                .saturating_sub(period.reported_direct)
                .min(LONGEST_RECORD),
        };

        period.reported_seconds = total;
        period.reported_direct = direct_total;
        period.reported_egress = egress;
        period.reported_ingress = ingress;
        // Always forward: a wall clock that stepped back must not hand two
        // periods of one session the same identifier.
        period.label = next.max(period.label + config.interval_seconds());
        period.peak_pixels = 0;
        period.role = None;
        period.closed = last;
        if !last {
            self.sample_locked(&mut period);
        }
        drop(period);

        (record.seconds > 0
            || record.egress_bytes > 0
            || record.ingress_bytes > 0
            || record.direct_seconds > 0)
            .then_some(record)
    }
}

/// Counts of what happened to records, for the scrape and for tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Records cut and queued.
    pub queued: u64,
    /// Records the endpoint accepted, charged or not.
    pub sent: u64,
    /// Of those, ones it had already charged.
    pub duplicates: u64,
    /// Of those, ones it accepted and did not charge.
    pub unbilled: u64,
    /// Dropped because the queue was full.
    pub dropped_overflow: u64,
    /// Dropped because the endpoint refused them as invalid.
    pub dropped_rejected: u64,
    /// Dropped because the relay stopped before they could be sent.
    pub dropped_shutdown: u64,
    /// Records queued or being sent now.
    pub waiting: u64,
    /// Sessions being metered now.
    pub meters: u64,
    /// Reports answered, by outcome: accepted, refused as invalid, refused
    /// credential, other failure.
    pub reports_ok: u64,
    /// See [`Self::reports_ok`].
    pub reports_rejected: u64,
    /// See [`Self::reports_ok`].
    pub reports_unauthorized: u64,
    /// See [`Self::reports_ok`].
    pub reports_failed: u64,
    /// When a report last succeeded, in seconds since the epoch; zero for never.
    pub last_success: u64,
    /// Whether new sessions are being admitted.
    pub admitting: bool,
}

#[derive(Debug, Default)]
struct Counters {
    queued: AtomicU64,
    sent: AtomicU64,
    duplicates: AtomicU64,
    unbilled: AtomicU64,
    dropped_overflow: AtomicU64,
    dropped_rejected: AtomicU64,
    dropped_shutdown: AtomicU64,
    reports_ok: AtomicU64,
    reports_rejected: AtomicU64,
    reports_unauthorized: AtomicU64,
    reports_failed: AtomicU64,
    last_success: AtomicU64,
    /// Report latency, cumulative by [`LATENCY_BUCKETS`], with one more for
    /// `+Inf`, and the sum in microseconds.
    latency: [AtomicU64; LATENCY_BUCKETS.len() + 1],
    latency_micros: AtomicU64,
}

/// Seconds. A report is one small POST a minute, so the interesting range is
/// a healthy tens of milliseconds up to the request timeout.
const LATENCY_BUCKETS: [f64; 9] = [0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 10.0, 30.0];

#[derive(Debug)]
struct Inner {
    config: Config,
    boot: u64,
    meters: Mutex<HashMap<SessionId, Arc<Meter>>>,
    catalogs: Arc<Catalogs>,
    queue: Mutex<Queue>,
    /// Raised when there is something to send, or an interval has passed and a
    /// self-hosted relay should ask whether it may still admit.
    wake: Notify,
    heartbeat: AtomicBool,
    admitting: AtomicBool,
    /// Records taken from the queue by the sender and not yet accepted or
    /// dropped.
    in_flight: AtomicU64,
    counters: Counters,
}

#[derive(Debug, Default)]
struct Queue {
    records: VecDeque<Record>,
    /// Whether the overflow warning has been logged for the current episode.
    overflowing: bool,
}

/// Usage metering for one relay, shared by every session on it.
///
/// Cheap to clone. The default meters nothing and admits everybody, which is
/// what a relay with no billing endpoint configured runs as.
#[derive(Debug, Clone, Default)]
pub struct Usage {
    inner: Option<Arc<Inner>>,
}

impl Usage {
    /// Metering that records nothing.
    #[must_use]
    pub const fn disabled() -> Self {
        Self { inner: None }
    }

    /// Metering per `config`. Nothing is sent until [`Self::report_to`].
    #[must_use]
    pub fn new(config: Config) -> Self {
        let boot = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| {
                u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
            });
        Self {
            inner: Some(Arc::new(Inner {
                config,
                boot,
                meters: Mutex::default(),
                catalogs: Arc::default(),
                queue: Mutex::default(),
                wake: Notify::new(),
                heartbeat: AtomicBool::new(false),
                admitting: AtomicBool::new(true),
                in_flight: AtomicU64::new(0),
                counters: Counters::default(),
            })),
        }
    }

    /// Whether anything is metered.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// Whether a new session may be admitted.
    ///
    /// False only after a self-hosted relay's report was answered with
    /// `admitted: false`, and true again once one is answered with `true`.
    /// Sessions already open are not affected: the credential they hold stops
    /// renewing, which is what ends them.
    #[must_use]
    pub fn admitting(&self) -> bool {
        self.inner
            .as_ref()
            .is_none_or(|inner| inner.admitting.load(Ordering::Relaxed))
    }

    /// Start metering a session that has just been admitted.
    ///
    /// `None` when nothing is metered, or when this is a hosted relay and the
    /// session has no verified tenant to charge.
    #[must_use]
    pub fn begin(
        &self,
        session: SessionId,
        permission: watch::Receiver<Option<Arc<Permission>>>,
    ) -> Option<Arc<Meter>> {
        self.begin_at(session, permission, Instant::now(), unix_now())
    }

    fn begin_at(
        &self,
        session: SessionId,
        permission: watch::Receiver<Option<Arc<Permission>>>,
        opened: Instant,
        wall: u64,
    ) -> Option<Arc<Meter>> {
        let inner = self.inner.as_ref()?;
        let (tenant, room, participant) = match permission.borrow().as_deref() {
            // Another relay's link. Its viewers are metered where they are
            // connected; metering the link as well would bill them twice.
            Some(Permission::Scoped(scope)) if scope.relay => return None,
            Some(Permission::Scoped(scope)) => (
                Some(scope.tenant.to_string()),
                scope.room.as_deref().unwrap_or_default().to_owned(),
                format!("{}/{}", scope.user, scope.device),
            ),
            Some(Permission::Unrestricted) => (None, String::new(), String::new()),
            Some(Permission::Nothing) | None => return None,
        };
        let tenant = match inner.config.hosting {
            Hosting::Cloud => Some(tenant?),
            Hosting::SelfHosted => None,
        };
        let interval = inner.config.interval_seconds();
        let meter = Arc::new(Meter {
            session,
            tenant,
            room,
            participant,
            permission,
            egress: AtomicU64::new(0),
            ingress: AtomicU64::new(0),
            catalogs: Arc::clone(&inner.catalogs),
            state: Mutex::new(Period {
                opened,
                label: wall - wall % interval,
                reported_seconds: 0,
                reported_egress: 0,
                reported_ingress: 0,
                peak_pixels: 0,
                role: None,
                watching: HashMap::new(),
                direct_open: 0,
                direct_since: None,
                direct_closed: Duration::ZERO,
                reported_direct: 0,
                closed: false,
            }),
        });
        meter.sample();
        inner.lock_meters().insert(session, Arc::clone(&meter));
        Some(meter)
    }

    /// Stop metering a session, recording the interval it ended in.
    pub fn end(&self, session: SessionId) {
        let Some(inner) = &self.inner else {
            return;
        };
        inner
            .catalogs
            .lock()
            .retain(|_, entry| entry.owner != session);
        let Some(meter) = inner.lock_meters().remove(&session) else {
            return;
        };
        let next = unix_now();
        if let Some(record) = meter.cut(&inner.config, inner.boot, Instant::now(), next, true) {
            inner.enqueue(record);
        }
    }

    /// Note what a `.catalog` object from `owner` says about the tracks under
    /// `namespace`.
    pub fn catalog(&self, owner: SessionId, namespace: &TrackNamespace, payload: &[u8]) {
        let Some(inner) = &self.inner else {
            return;
        };
        let Some(tracks) = catalog::tracks_in(payload) else {
            return;
        };
        inner.catalogs.lock().insert(
            namespace.clone(),
            Catalogued {
                owner,
                tracks: tracks
                    .into_iter()
                    .map(|(name, described)| (name.into_bytes(), described))
                    .collect(),
            },
        );
    }

    /// The counts behind the scrape.
    #[must_use]
    pub fn stats(&self) -> Stats {
        let Some(inner) = &self.inner else {
            return Stats {
                admitting: true,
                ..Stats::default()
            };
        };
        let c = &inner.counters;
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        Stats {
            queued: load(&c.queued),
            sent: load(&c.sent),
            duplicates: load(&c.duplicates),
            unbilled: load(&c.unbilled),
            dropped_overflow: load(&c.dropped_overflow),
            dropped_rejected: load(&c.dropped_rejected),
            dropped_shutdown: load(&c.dropped_shutdown),
            waiting: inner.lock_queue().records.len() as u64
                + inner.in_flight.load(Ordering::Relaxed),
            meters: inner.lock_meters().len() as u64,
            reports_ok: load(&c.reports_ok),
            reports_rejected: load(&c.reports_rejected),
            reports_unauthorized: load(&c.reports_unauthorized),
            reports_failed: load(&c.reports_failed),
            last_success: load(&c.last_success),
            admitting: inner.admitting.load(Ordering::Relaxed),
        }
    }

    /// The Prometheus exposition for usage reporting, empty when disabled.
    #[must_use]
    #[allow(clippy::too_many_lines)] // one block per series, read top to bottom
    pub fn expose(&self) -> String {
        let Some(inner) = &self.inner else {
            return String::new();
        };
        let stats = self.stats();
        let mut out = String::with_capacity(2048);
        let mut family = |kind: &str, name: &str, help: &str, series: &[(&str, u64)]| {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} {kind}");
            for (labels, value) in series {
                let _ = writeln!(out, "{name}{labels} {value}");
            }
        };
        family(
            "counter",
            "moqom_relay_usage_records_queued_total",
            "Usage records cut and queued for the billing endpoint.",
            &[("", stats.queued)],
        );
        family(
            "counter",
            "moqom_relay_usage_records_sent_total",
            "Usage records the billing endpoint accepted.",
            &[("", stats.sent)],
        );
        family(
            "counter",
            "moqom_relay_usage_records_duplicate_total",
            "Accepted usage records the endpoint had already charged.",
            &[("", stats.duplicates)],
        );
        family(
            "counter",
            "moqom_relay_usage_records_unbilled_total",
            "Accepted usage records the endpoint did not charge.",
            &[("", stats.unbilled)],
        );
        family(
            "counter",
            "moqom_relay_usage_records_dropped_total",
            "Usage records discarded unsent, by why.",
            &[
                (r#"{reason="overflow"}"#, stats.dropped_overflow),
                (r#"{reason="rejected"}"#, stats.dropped_rejected),
                (r#"{reason="shutdown"}"#, stats.dropped_shutdown),
            ],
        );
        family(
            "gauge",
            "moqom_relay_usage_records_waiting",
            "Usage records queued and not yet accepted.",
            &[("", stats.waiting)],
        );
        family(
            "gauge",
            "moqom_relay_usage_meters",
            "Sessions currently metered.",
            &[("", stats.meters)],
        );
        family(
            "counter",
            "moqom_relay_usage_reports_total",
            "Usage reports sent, by outcome.",
            &[
                (r#"{outcome="ok"}"#, stats.reports_ok),
                (r#"{outcome="rejected"}"#, stats.reports_rejected),
                (r#"{outcome="unauthorized"}"#, stats.reports_unauthorized),
                (r#"{outcome="failed"}"#, stats.reports_failed),
            ],
        );
        family(
            "gauge",
            "moqom_relay_usage_last_success_timestamp_seconds",
            "When a usage report last succeeded; zero for never.",
            &[("", stats.last_success)],
        );
        family(
            "gauge",
            "moqom_relay_usage_admitting",
            "Whether billing lets this relay admit new sessions.",
            &[("", u64::from(stats.admitting))],
        );

        let name = "moqom_relay_usage_report_seconds";
        let _ = writeln!(
            out,
            "# HELP {name} Time for the billing endpoint to answer a report."
        );
        let _ = writeln!(out, "# TYPE {name} histogram");
        let mut running = 0;
        for (i, count) in inner.counters.latency.iter().enumerate() {
            running += count.load(Ordering::Relaxed);
            match LATENCY_BUCKETS.get(i) {
                Some(bound) => {
                    let _ = writeln!(out, "{name}_bucket{{le=\"{bound}\"}} {running}");
                }
                None => {
                    let _ = writeln!(out, "{name}_bucket{{le=\"+Inf\"}} {running}");
                }
            }
        }
        #[allow(clippy::cast_precision_loss)] // microseconds, far below any query's resolution
        let sum = inner.counters.latency_micros.load(Ordering::Relaxed) as f64 / 1e6;
        let _ = writeln!(out, "{name}_sum {sum}");
        let _ = writeln!(out, "{name}_count {running}");
        out
    }

    /// Re-sample every live meter for role and tier.
    fn sample_all(&self) {
        let Some(inner) = &self.inner else {
            return;
        };
        let meters: Vec<Arc<Meter>> = inner.lock_meters().values().cloned().collect();
        for meter in &meters {
            meter.sample();
        }
    }

    /// Cut every live meter at an interval boundary.
    fn cut_all(&self, now: Instant, boundary: u64, last: bool) {
        let Some(inner) = &self.inner else {
            return;
        };
        let meters: Vec<Arc<Meter>> = if last {
            inner
                .lock_meters()
                .drain()
                .map(|(_, meter)| meter)
                .collect()
        } else {
            inner.lock_meters().values().cloned().collect()
        };
        for meter in meters {
            if let Some(record) = meter.cut(&inner.config, inner.boot, now, boundary, last) {
                inner.enqueue(record);
            }
        }
        inner.heartbeat.store(true, Ordering::Relaxed);
        inner.wake.notify_one();
    }
}

impl Inner {
    fn lock_meters(&self) -> std::sync::MutexGuard<'_, HashMap<SessionId, Arc<Meter>>> {
        self.meters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lock_queue(&self) -> std::sync::MutexGuard<'_, Queue> {
        self.queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Queue a record, dropping the oldest if the queue is full.
    ///
    /// Never waits. The oldest goes rather than the newest because an outage
    /// long enough to fill the queue is one where the newest records describe
    /// sessions still running, which are the ones somebody will ask about.
    fn enqueue(&self, record: Record) {
        let mut queue = self.lock_queue();
        if queue.records.len() >= self.config.capacity.max(1)
            && let Some(oldest) = queue.records.pop_front()
        {
            self.counters
                .dropped_overflow
                .fetch_add(1, Ordering::Relaxed);
            if !queue.overflowing {
                queue.overflowing = true;
                tracing::warn!(
                    capacity = self.config.capacity,
                    oldest = %oldest.id,
                    "usage queue is full; dropping the oldest records until the billing endpoint catches up"
                );
            }
        }
        queue.records.push_back(record);
        self.counters.queued.fetch_add(1, Ordering::Relaxed);
    }

    /// The next batch: at most [`MOST_RECORDS`], and at most
    /// [`MOST_BODY_BYTES`] of them serialised.
    fn take_batch(&self) -> Vec<Record> {
        let mut queue = self.lock_queue();
        let mut batch = Vec::new();
        let mut bytes = 0;
        while batch.len() < MOST_RECORDS {
            let Some(next) = queue.records.front() else {
                break;
            };
            let size = serde_json::to_vec(next).map_or(usize::MAX, |encoded| encoded.len() + 1);
            if size > MOST_BODY_BYTES {
                // Cannot be sent in any batch. Not reachable with identifiers
                // capped at 200 characters and names bounded by the token, but
                // a record that wedged the queue forever would be worse.
                let dropped = queue.records.pop_front();
                self.counters
                    .dropped_rejected
                    .fetch_add(1, Ordering::Relaxed);
                tracing::error!(id = ?dropped.map(|r| r.id), "usage record too large to send; dropped");
                continue;
            }
            if bytes + size > MOST_BODY_BYTES {
                break;
            }
            bytes += size;
            batch.extend(queue.records.pop_front());
        }
        if queue.records.len() < self.config.capacity / 2 {
            queue.overflowing = false;
        }
        batch
    }

    fn observe_latency(&self, took: Duration) {
        let seconds = took.as_secs_f64();
        let bucket = LATENCY_BUCKETS.partition_point(|&bound| bound < seconds);
        self.counters.latency[bucket].fetch_add(1, Ordering::Relaxed);
        let micros = u64::try_from(took.as_micros()).unwrap_or(u64::MAX);
        self.counters
            .latency_micros
            .fetch_add(micros, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::Scope;

    fn scope(publish: Publish, room: Option<&str>) -> Scope {
        Scope {
            tenant: "t_acme".into(),
            user: "bea".into(),
            device: "41d07a9e".into(),
            room: room.map(Into::into),
            publish,
            capabilities: 0,
            owner: false,
            backstage: false,
            relay: false,
        }
    }

    fn permission(scope: Scope) -> watch::Receiver<Option<Arc<Permission>>> {
        watch::channel(Some(Arc::new(Permission::scoped(scope)))).1
    }

    fn usage(hosting: Hosting) -> Usage {
        Usage::new(Config::new("relay-eu-1", hosting))
    }

    fn track(namespace: &[&str], name: &str) -> FullTrackName {
        FullTrackName::new(
            TrackNamespace::from_parts(namespace).expect("namespace"),
            bytes::Bytes::copy_from_slice(name.as_bytes()),
        )
        .expect("track")
    }

    #[test]
    fn tiers_follow_the_price_list_boundaries() {
        assert_eq!(Tier::of(0), Tier::Audio);
        assert_eq!(Tier::of(1), Tier::Hd);
        assert_eq!(Tier::of(1280 * 720), Tier::Hd);
        assert_eq!(Tier::of(1280 * 720 + 1), Tier::FullHd);
        assert_eq!(
            Tier::of(4 * 640 * 360),
            Tier::Hd,
            "four 360p tiles are one 720p"
        );
        assert_eq!(Tier::of(2 * 1280 * 720), Tier::FullHd);
        assert_eq!(Tier::of(1920 * 1080), Tier::FullHd);
        assert_eq!(Tier::of(2560 * 1440), Tier::TwoK);
        assert_eq!(Tier::of(9 * 640 * 360 + 1280 * 720), Tier::TwoK);
        assert_eq!(Tier::of(2560 * 1440 + 1), Tier::TwoKPlus);
        assert_eq!(Tier::of(3840 * 2160), Tier::TwoKPlus);
    }

    #[test]
    fn a_catalog_decides_pixels_and_a_name_stands_in_for_one() {
        let described = |w, h| {
            Some(Described::Video {
                width: Some(w),
                height: Some(h),
            })
        };
        assert_eq!(pixels(b"video/720p", described(1280, 720)), 921_600);
        // Portrait is the same pixels.
        assert_eq!(pixels(b"video/720p", described(720, 1280)), 921_600);
        // The catalog wins over the name.
        assert_eq!(pixels(b"video/720p", described(640, 360)), 230_400);
        // No catalog: the rung, at 16:9.
        assert_eq!(pixels(b"video/1080p", None), 1920 * 1080);
        assert_eq!(pixels(b"screen/1440p", None), 2560 * 1440);
        // No rung either: taken as HD.
        assert_eq!(pixels(b"video", None), HD);
        assert_eq!(pixels(b"screen/best", None), HD);
        // A catalog that gave one dimension falls back to the name.
        let partial = Some(Described::Video {
            width: Some(1920),
            height: None,
        });
        assert_eq!(pixels(b"video/360p", partial), 640 * 360);
        // A catalog calling an unfamiliar name video is believed.
        assert_eq!(pixels(b"hologram", partial), HD);
        // Not video.
        assert_eq!(pixels(b"audio", None), 0);
        assert_eq!(pixels(b".catalog", None), 0);
        assert_eq!(pixels(b"telemetry", None), 0);
        assert_eq!(pixels(b"video/720p", Some(Described::Other)), 0);
    }

    #[test]
    fn roles_come_from_grants() {
        let role = |scope: Scope| Role::of(&Permission::scoped(scope), false);
        assert_eq!(role(scope(Publish::AUDIO, Some("r"))), Role::Host);
        assert_eq!(
            role(scope(Publish::VIDEO, None)),
            Role::Host,
            "a broadcaster outside a call"
        );
        assert_eq!(role(scope(Publish::NONE, Some("r"))), Role::Audience);
        assert_eq!(role(scope(Publish::NONE, None)), Role::BroadcastAudience);
        assert_eq!(
            role(scope(Publish::DATA, Some("r"))),
            Role::Audience,
            "data is not audio or video"
        );
        assert_eq!(
            role(Scope {
                backstage: true,
                ..scope(Publish::VIDEO, Some("r"))
            }),
            Role::Audience,
            "waiting backstage is not on stage"
        );
        assert_eq!(
            role(Scope {
                owner: true,
                ..scope(Publish::NONE, Some("r"))
            }),
            Role::Host
        );
        assert_eq!(Role::of(&Permission::Unrestricted, true), Role::Host);
        assert_eq!(Role::of(&Permission::Unrestricted, false), Role::Audience);
    }

    #[test]
    fn identifiers_are_deterministic_and_bounded() {
        let session = SessionId::for_tests(42);
        let id = record_id(
            "relay-eu-1",
            1_791_278_100,
            "bea/41d07a9e",
            1_791_270_000_123,
            session,
        );
        assert_eq!(
            id,
            "relay-eu-1:2026-10-06T09:15:00Z:bea/41d07a9e#1791270000123.42"
        );
        assert_eq!(
            id,
            record_id(
                "relay-eu-1",
                1_791_278_100,
                "bea/41d07a9e",
                1_791_270_000_123,
                session
            )
        );
        assert_ne!(
            id,
            record_id(
                "relay-eu-1",
                1_791_278_160,
                "bea/41d07a9e",
                1_791_270_000_123,
                session
            ),
            "the next interval"
        );
        assert_ne!(
            id,
            record_id(
                "relay-eu-1",
                1_791_278_100,
                "bea/41d07a9e",
                1_791_270_000_123,
                SessionId::for_tests(43)
            ),
            "a reconnection in the same interval"
        );
        assert!(record_id("r", 0, "", 0, session).contains(":anonymous#"));

        let long = "x".repeat(300);
        let hashed = record_id("relay-eu-1", 0, &long, 7, session);
        assert!(hashed.len() <= LONGEST_ID && hashed.starts_with("h:"));
        assert_eq!(hashed, record_id("relay-eu-1", 0, &long, 7, session));
        assert_ne!(hashed, record_id("relay-eu-1", 60, &long, 7, session));
    }

    #[test]
    fn dates_are_civil() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_791_278_100), "2026-10-06T09:15:00Z");
        assert_eq!(rfc3339(4_102_444_799), "2099-12-31T23:59:59Z");
    }

    #[test]
    fn a_session_is_cut_into_intervals_that_sum_to_its_length() {
        let usage = usage(Hosting::Cloud);
        let inner = usage.inner.as_ref().expect("enabled");
        let opened = Instant::now();
        // Joined 23 s into the 09:15 minute.
        let wall = 1_791_278_100 + 23;
        let meter = usage
            .begin_at(
                SessionId::for_tests(1),
                permission(scope(Publish::NONE, Some("live/42"))),
                opened,
                wall,
            )
            .expect("metered");
        meter.egress(1000);
        meter.ingress(10);

        let first = meter
            .cut(
                &inner.config,
                inner.boot,
                opened + Duration::from_millis(37_400),
                1_791_278_160,
                false,
            )
            .expect("a record");
        assert!(
            first
                .id
                .starts_with("relay-eu-1:2026-10-06T09:15:00Z:bea/41d07a9e#")
        );
        assert_eq!(first.tenant.as_deref(), Some("t_acme"));
        assert_eq!(first.room, "live/42");
        assert_eq!(first.participant, "bea/41d07a9e");
        assert_eq!(first.role, Role::Audience);
        assert_eq!(first.tier, Tier::Audio);
        assert_eq!(
            (first.seconds, first.egress_bytes, first.ingress_bytes),
            (37, 1000, 10)
        );

        meter.egress(500);
        let second = meter
            .cut(
                &inner.config,
                inner.boot,
                opened + Duration::from_millis(97_400),
                1_791_278_220,
                false,
            )
            .expect("a record");
        assert!(second.id.contains(":2026-10-06T09:16:00Z:"));
        assert_eq!(
            (second.seconds, second.egress_bytes, second.ingress_bytes),
            (60, 500, 0)
        );

        let last = meter
            .cut(
                &inner.config,
                inner.boot,
                opened + Duration::from_millis(110_600),
                0,
                true,
            )
            .expect("a record");
        assert!(last.id.contains(":2026-10-06T09:17:00Z:"));
        assert_eq!(
            last.seconds, 14,
            "rounded at the end, so the total is 111 s of 110.6"
        );
        assert_eq!(first.seconds + second.seconds + last.seconds, 111);

        assert!(
            meter
                .cut(
                    &inner.config,
                    inner.boot,
                    opened + Duration::from_secs(200),
                    0,
                    true
                )
                .is_none(),
            "nothing after the final cut"
        );
    }

    #[test]
    fn an_empty_interval_is_not_a_record() {
        let usage = usage(Hosting::Cloud);
        let inner = usage.inner.as_ref().expect("enabled");
        let opened = Instant::now();
        let meter = usage
            .begin_at(
                SessionId::for_tests(1),
                permission(scope(Publish::NONE, Some("r"))),
                opened,
                120,
            )
            .expect("metered");
        assert!(
            meter
                .cut(
                    &inner.config,
                    inner.boot,
                    opened + Duration::from_millis(400),
                    180,
                    false
                )
                .is_none()
        );
    }

    #[test]
    fn the_tier_is_the_peak_of_what_was_watched_at_once() {
        let usage = usage(Hosting::Cloud);
        let inner = usage.inner.as_ref().expect("enabled");
        let publisher = ["t_acme", "r", "live", "ada", "phone"];
        let namespace = TrackNamespace::from_parts(publisher).expect("namespace");
        usage.catalog(
            SessionId::for_tests(9),
            &namespace,
            br#"{"version":1,"tracks":[
                {"name":"video/1080p","kind":"video","width":1920,"height":1080},
                {"name":"video/360p","kind":"video","width":640,"height":360},
                {"name":"audio","kind":"audio"}
            ]}"#,
        );
        let opened = Instant::now();
        let meter = usage
            .begin_at(
                SessionId::for_tests(1),
                permission(scope(Publish::NONE, Some("live"))),
                opened,
                0,
            )
            .expect("metered");

        meter.watch(&track(&publisher, "audio"));
        meter.watch(&track(&publisher, "video/360p"));
        meter.watch(&track(
            &["t_acme", "r", "live", "cy", "laptop"],
            "video/720p",
        ));
        // 640x360 + an uncatalogued 720p rung: Full HD.
        meter.unwatch(&track(&publisher, "video/360p"));
        meter.watch(&track(&publisher, "video/1080p"));
        // 1080p + 720p at once: 2K, and that peak holds for the interval.
        meter.unwatch(&track(&publisher, "video/1080p"));
        meter.egress(1);

        let first = meter
            .cut(
                &inner.config,
                inner.boot,
                opened + Duration::from_mins(1),
                60,
                false,
            )
            .expect("a record");
        assert_eq!(first.tier, Tier::TwoK);
        meter.egress(1);
        let second = meter
            .cut(
                &inner.config,
                inner.boot,
                opened + Duration::from_mins(2),
                120,
                false,
            )
            .expect("a record");
        assert_eq!(
            second.tier,
            Tier::Hd,
            "the next interval starts from what is still watched"
        );

        usage.end(SessionId::for_tests(9));
        assert!(
            inner.catalogs.lock().is_empty(),
            "a publisher's catalog goes with it"
        );
    }

    #[test]
    fn a_promotion_makes_the_interval_a_hosts() {
        let usage = usage(Hosting::Cloud);
        let inner = usage.inner.as_ref().expect("enabled");
        let (grants, receiver) = watch::channel(Some(Arc::new(Permission::scoped(scope(
            Publish::NONE,
            Some("r"),
        )))));
        let opened = Instant::now();
        let meter = usage
            .begin_at(SessionId::for_tests(1), receiver, opened, 0)
            .expect("metered");
        grants.send_replace(Some(Arc::new(Permission::scoped(scope(
            Publish::VIDEO,
            Some("r"),
        )))));
        meter.sample();
        grants.send_replace(Some(Arc::new(Permission::scoped(scope(
            Publish::NONE,
            Some("r"),
        )))));
        let record = meter
            .cut(
                &inner.config,
                inner.boot,
                opened + Duration::from_mins(1),
                60,
                false,
            )
            .expect("a record");
        assert_eq!(record.role, Role::Host);
        let next = meter
            .cut(
                &inner.config,
                inner.boot,
                opened + Duration::from_mins(2),
                120,
                false,
            )
            .expect("a record");
        assert_eq!(next.role, Role::Audience);
    }

    #[test]
    fn hosted_relays_meter_only_verified_tenants_and_self_hosted_omit_them() {
        let unrestricted = || watch::channel(Some(Arc::new(Permission::Unrestricted))).1;
        assert!(
            usage(Hosting::Cloud)
                .begin(SessionId::for_tests(1), unrestricted())
                .is_none()
        );
        assert!(
            usage(Hosting::SelfHosted)
                .begin(SessionId::for_tests(1), unrestricted())
                .is_some()
        );
        let nothing = watch::channel(Some(Arc::new(Permission::Nothing))).1;
        assert!(
            usage(Hosting::SelfHosted)
                .begin(SessionId::for_tests(1), nothing)
                .is_none()
        );

        let usage = usage(Hosting::SelfHosted);
        let meter = usage
            .begin(
                SessionId::for_tests(1),
                permission(scope(Publish::NONE, Some("r"))),
            )
            .expect("metered");
        meter.egress(5);
        usage.end(SessionId::for_tests(1));
        let batch = usage.inner.as_ref().expect("enabled").take_batch();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].tenant, None);
        let json = serde_json::to_string(&batch[0]).expect("json");
        assert!(!json.contains("tenant"), "{json}");
        assert!(json.contains(r#""role":"audience""#), "{json}");
        assert!(json.contains(r#""tier":"audio""#), "{json}");
    }

    #[test]
    fn another_relays_link_is_not_metered_in_either_mode() {
        for hosting in [Hosting::Cloud, Hosting::SelfHosted] {
            let link = Scope {
                relay: true,
                ..scope(Publish::NONE, Some("r"))
            };
            let usage = usage(hosting);
            assert!(
                usage
                    .begin(SessionId::for_tests(1), permission(link))
                    .is_none()
            );
            assert_eq!(usage.stats().meters, 0);
        }
    }

    fn filler(n: usize, participant: &str) -> Record {
        Record {
            id: format!("relay:{n}"),
            tenant: Some("t_acme".to_owned()),
            room: "room".to_owned(),
            participant: participant.to_owned(),
            role: Role::Audience,
            tier: Tier::Hd,
            seconds: 60,
            egress_bytes: 1,
            ingress_bytes: 0,
            direct_seconds: 0,
        }
    }

    /// Direct time is time with any ticket live, cut and rounded like
    /// connected time, and absent from the JSON when there was none.
    #[test]
    fn direct_seconds_are_ticket_time_in_each_interval() {
        let usage = usage(Hosting::Cloud);
        let inner = usage.inner.as_ref().expect("enabled");
        let opened = Instant::now();
        let at = |millis: u64| opened + Duration::from_millis(millis);
        let meter = usage
            .begin_at(
                SessionId::for_tests(1),
                permission(scope(Publish::from_bits(0b11), Some("r"))),
                opened,
                1_791_278_100,
            )
            .expect("metered");

        let before = meter
            .cut(&inner.config, inner.boot, at(10_000), 1_791_278_160, false)
            .expect("a record");
        assert_eq!(before.direct_seconds, 0);
        assert!(
            !serde_json::to_string(&before)
                .expect("json")
                .contains("direct")
        );

        // Two peers at once count once, and the time runs until both close.
        meter.direct_began_at(at(20_000));
        meter.direct_began_at(at(30_000));
        meter.direct_ended_at(at(40_000));
        let during = meter
            .cut(&inner.config, inner.boot, at(70_000), 1_791_278_220, false)
            .expect("a record");
        assert_eq!(during.direct_seconds, 50);
        assert!(
            serde_json::to_string(&during)
                .expect("json")
                .contains(r#""direct_seconds":50"#)
        );

        meter.direct_ended_at(at(85_600));
        let last = meter
            .cut(&inner.config, inner.boot, at(100_000), 0, true)
            .expect("a record");
        assert_eq!(last.direct_seconds, 16, "65.6 s in all, rounded at the end");
        assert_eq!(during.direct_seconds + last.direct_seconds, 66);
    }

    #[test]
    fn batches_respect_the_record_and_byte_limits() {
        let usage = Usage::new(Config {
            capacity: 20_000,
            ..Config::new("relay", Hosting::Cloud)
        });
        let inner = usage.inner.as_ref().expect("enabled");
        for n in 0..12_000 {
            inner.enqueue(filler(n, "p"));
        }
        let first = inner.take_batch();
        assert_eq!(first.len(), MOST_RECORDS);
        assert_eq!(first[0].id, "relay:0", "oldest first");
        assert_eq!(inner.take_batch().len(), MOST_RECORDS);
        assert_eq!(inner.take_batch().len(), 2000);
        assert!(inner.take_batch().is_empty());

        // Records big enough that 5000 would pass a mebibyte.
        let wide = "p".repeat(400);
        for n in 0..5000 {
            inner.enqueue(filler(n, &wide));
        }
        let batch = inner.take_batch();
        assert!(batch.len() < MOST_RECORDS);
        let body = serde_json::to_vec(&serde_json::json!({ "records": batch })).expect("json");
        assert!(body.len() <= MOST_BODY_BYTES, "{} bytes", body.len());
        let mut total = batch.len();
        loop {
            let next = inner.take_batch();
            if next.is_empty() {
                break;
            }
            total += next.len();
        }
        assert_eq!(total, 5000, "nothing lost to the split");
    }

    #[test]
    fn a_full_queue_drops_the_oldest() {
        let usage = Usage::new(Config {
            capacity: 3,
            ..Config::new("relay", Hosting::Cloud)
        });
        let inner = usage.inner.as_ref().expect("enabled");
        for n in 0..5 {
            inner.enqueue(filler(n, "p"));
        }
        let ids: Vec<String> = inner.take_batch().into_iter().map(|r| r.id).collect();
        assert_eq!(ids, ["relay:2", "relay:3", "relay:4"]);
        let stats = usage.stats();
        assert_eq!((stats.queued, stats.dropped_overflow), (5, 2));
    }

    #[test]
    fn the_exposition_is_well_formed() {
        let usage = usage(Hosting::Cloud);
        usage
            .inner
            .as_ref()
            .expect("enabled")
            .observe_latency(Duration::from_millis(70));
        let exposed = usage.expose();
        let mut declared = Vec::new();
        for line in exposed.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                let name = rest.split(' ').next().expect("a name");
                assert!(
                    !declared.contains(&name.to_owned()),
                    "{name} declared twice"
                );
                declared.push(name.to_owned());
            }
        }
        assert!(
            exposed.contains(r#"moqom_relay_usage_report_seconds_bucket{le="0.1"} 1"#),
            "{exposed}"
        );
        assert!(exposed.contains("moqom_relay_usage_admitting 1"));
        assert!(Usage::disabled().expose().is_empty());
    }
}
