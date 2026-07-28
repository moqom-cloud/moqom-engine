//! What the relay counts, and what it will tell you about itself.
//!
//! # Why the labels are enums and not strings
//!
//! Every metric here has a label set fixed at compile time, stored as an array
//! indexed by an enum. That is not a micro-optimisation — it is the only
//! structural defence against the failure mode that kills Prometheus
//! deployments. A label whose values come from the wire (a room, a tenant, a
//! track name) creates one time series per distinct value, and a relay serving a
//! million rooms would try to publish a million series. The scrape gets slower
//! until it times out, and the first symptom is losing the monitoring for the
//! incident you were trying to investigate.
//!
//! So the rule is: metrics carry only dimensions this module can enumerate.
//! Anything with unbounded cardinality — which is everything interesting about
//! *who* is connected — is answered by [`crate::admin`]'s JSON snapshots, which
//! are computed per request and cost nothing when nobody asks, and by tracing
//! fields, which are per event rather than per series.
//!
//! # Why per-connection quality is sampled rather than pushed
//!
//! RTT, congestion window, and loss live in the QUIC state machine, which has no
//! reason to notify anybody when they change. A session therefore samples its
//! own connection on a timer and folds the result in here: RTT into a histogram,
//! and the monotonic counters as deltas against the previous sample. Deltas
//! rather than absolute values because a counter that resets when a session ends
//! is not a counter, and `rate()` over it would show a cliff on every
//! disconnect.
//!
//! # What the relay deliberately cannot count
//!
//! Objects forwarded. The forwarding path copies subgroup bytes without parsing
//! them, which is what keeps payloads end-to-end encrypted and removes the
//! object delta state machine from the fan-out path entirely. Counting objects
//! there would mean parsing them there. So the data plane reports subgroups and
//! bytes, and the object counts come from the cache's recorder, which parses a
//! copy off to one side and is allowed to fail without affecting a forward.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use moqom_proto::control::setup;

use crate::fabric::SessionId;
use crate::quota::{Reason, Refusal, Resource, Tier};

/// Relaxed ordering throughout: every value here is a counter or a gauge read
/// by a scrape that has no ordering relationship with anything else. Paying for
/// synchronisation between a metric and the work it describes would slow the
/// forwarding path to make a number that is stale by the time it is read
/// slightly less stale.
const ORDER: Ordering = Ordering::Relaxed;

/// How often a session samples its own transport.
///
/// Fast enough that a connection degrading mid-broadcast shows up while it is
/// still happening, slow enough that ten thousand sessions is ten thousand
/// atomic adds a second rather than a workload.
pub const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

/// Why a session stopped.
///
/// There is no `Internal` variant, because there is no session error that means
/// "this relay failed" — see `Ending::of` in [`crate::session`]. A bucket that
/// can never be non-zero is worse than a missing one: it looks like evidence
/// that something was checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// The peer went away without breaking anything.
    Clean,
    /// The peer violated the protocol and was closed for it.
    Protocol,
    /// The connection failed underneath us.
    Transport,
    /// The peer offered a credential that did not verify.
    ///
    /// Separate from `Protocol` because the two mean opposite things
    /// operationally: a spike of protocol errors is usually one broken client
    /// build, and a spike of these is usually somebody trying keys.
    Rejected,
    /// The peer was over its limit before the session began.
    Throttled,
}

impl Ending {
    const ALL: [Self; 5] = [
        Self::Clean,
        Self::Protocol,
        Self::Transport,
        Self::Rejected,
        Self::Throttled,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Protocol => "protocol",
            Self::Transport => "transport",
            Self::Rejected => "rejected",
            Self::Throttled => "throttled",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Clean => 0,
            Self::Protocol => 1,
            Self::Transport => 2,
            Self::Rejected => 3,
            Self::Throttled => 4,
        }
    }
}

/// How a SUBSCRIBE turned out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subscribed {
    /// Objects are flowing.
    Established,
    /// Nothing on this relay publishes that namespace.
    NoPublisher,
    /// The publisher session refused, or ended while being asked.
    Refused,
}

impl Subscribed {
    const ALL: [Self; 3] = [Self::Established, Self::NoPublisher, Self::Refused];

    const fn label(self) -> &'static str {
        match self {
            Self::Established => "established",
            Self::NoPublisher => "no_publisher",
            Self::Refused => "refused",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Established => 0,
            Self::NoPublisher => 1,
            Self::Refused => 2,
        }
    }
}

/// How a FETCH turned out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fetched {
    /// Records went out on a data stream.
    Served,
    /// The fetch named a track or subscription this relay does not have.
    Unresolvable,
    /// The track is known but that range is not retained.
    NoHistory,
    /// The delivered range could not be expressed on the wire.
    Unnameable,
}

impl Fetched {
    const ALL: [Self; 4] = [
        Self::Served,
        Self::Unresolvable,
        Self::NoHistory,
        Self::Unnameable,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Served => "served",
            Self::Unresolvable => "unresolvable",
            Self::NoHistory => "no_history",
            Self::Unnameable => "unnameable",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Served => 0,
            Self::Unresolvable => 1,
            Self::NoHistory => 2,
            Self::Unnameable => 3,
        }
    }
}

/// A fixed-bucket cumulative histogram.
///
/// Bucket bounds are chosen per metric rather than generically, because a
/// histogram whose buckets do not straddle the values you care about is
/// expensive to publish and useless to query.
#[derive(Debug)]
struct Histogram {
    /// Upper bounds, ascending. The implicit `+Inf` bucket is `counts.last()`.
    bounds: &'static [f64],
    /// One more than `bounds.len()`, for `+Inf`.
    counts: Vec<AtomicU64>,
    /// Summed observations, in the metric's own unit, scaled by [`Self::SCALE`]
    /// so it can be an integer add rather than a compare-and-swap loop on f64
    /// bits.
    total: AtomicU64,
}

impl Histogram {
    /// Fixed-point scale for the running sum: microseconds, for a metric in
    /// seconds. Enough resolution for an RTT and no risk of overflow inside a
    /// process lifetime.
    const SCALE: f64 = 1_000_000.0;

    fn new(bounds: &'static [f64]) -> Self {
        Self {
            bounds,
            counts: (0..=bounds.len()).map(|_| AtomicU64::new(0)).collect(),
            total: AtomicU64::new(0),
        }
    }

    fn observe(&self, value: f64) {
        // `partition_point` is the index of the first bound not less than the
        // value, which is exactly the bucket a cumulative histogram wants, and
        // is `bounds.len()` — the `+Inf` slot — when nothing bounds it.
        let bucket = self.bounds.partition_point(|&bound| bound < value);
        self.counts[bucket].fetch_add(1, ORDER);
        #[allow(clippy::cast_sign_loss)] // callers observe durations, never negative
        self.total.fetch_add((value * Self::SCALE) as u64, ORDER);
    }

    /// Bucket counts made cumulative, as Prometheus requires, plus the count and
    /// sum.
    fn snapshot(&self) -> (Vec<u64>, u64, f64) {
        let mut running = 0;
        let cumulative: Vec<u64> = self
            .counts
            .iter()
            .map(|c| {
                running += c.load(ORDER);
                running
            })
            .collect();
        // The exposition format takes a decimal, and the bits lost converting a
        // microsecond count are far below anything a query would resolve.
        #[allow(clippy::cast_precision_loss)]
        let sum = self.total.load(ORDER) as f64 / Self::SCALE;
        (cumulative, running, sum)
    }
}

/// Buckets for a round-trip time, in seconds.
///
/// Dense between 10ms and 300ms because that is the band where a decision gets
/// made about whether a connection is usable, and open at both ends because
/// same-host tests land under a millisecond and satellite links land over a
/// second.
const RTT_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.010, 0.020, 0.040, 0.060, 0.080, 0.100, 0.150, 0.200, 0.300, 0.500, 1.0, 2.0,
];

/// Buckets for how long a session lasted, in seconds.
///
/// The short end is what matters: a cluster of sessions ending inside a second
/// is a handshake or authorisation problem, and it looks identical to healthy
/// traffic in a mean.
const SESSION_BUCKETS: &[f64] = &[
    1.0, 5.0, 15.0, 60.0, 300.0, 900.0, 1800.0, 3600.0, 7200.0, 21600.0, 86400.0,
];

/// Everything one relay process counts about itself.
///
/// Cheap to clone; all clones share one set of counters.
#[derive(Debug, Clone, Default)]
pub struct Metrics {
    inner: Option<Arc<Inner>>,
}

#[derive(Debug)]
struct Inner {
    started: Instant,

    sessions_accepted: [AtomicU64; 2],
    handshakes_failed: AtomicU64,
    sessions_ended: [AtomicU64; Ending::ALL.len()],
    session_duration: Histogram,

    announcements: AtomicU64,
    subscriptions: [AtomicU64; Subscribed::ALL.len()],
    fetches: [AtomicU64; Fetched::ALL.len()],
    fetch_records: AtomicU64,

    admitted: [AtomicU64; Resource::ALL.len()],
    /// By resource, then by the tier whose allowance ran out.
    refused: [[AtomicU64; Tier::ALL.len()]; Resource::ALL.len()],
    refusal_reasons: [AtomicU64; Reason::ALL.len()],
    /// By cause, from the fixed set [`crate::AuthError::name`] returns.
    ///
    /// A map rather than an array because the causes belong to another module
    /// and giving them a dense index here would be a second enumeration to keep
    /// in step. Bounded by that fixed set, so it cannot grow with traffic.
    tokens_refused: Mutex<HashMap<&'static str, u64>>,

    subgroups_forwarded: AtomicU64,
    subgroups_dropped: AtomicU64,
    ingress_bytes: AtomicU64,
    forwarded_bytes: AtomicU64,
    fanout_failures: AtomicU64,

    rtt: Histogram,
    udp_tx_bytes: AtomicU64,
    udp_rx_bytes: AtomicU64,
    lost_packets: AtomicU64,
    congestion_events: AtomicU64,

    live: Mutex<HashMap<SessionId, Arc<Live>>>,
}

/// One connected session, as an observer sees it.
///
/// Deliberately holds no transport handle. An entry that outlived its session
/// would then keep a connection from being dropped, turning a bookkeeping bug
/// into a file-descriptor leak; this way the worst case is a stale row in a
/// diagnostic endpoint.
#[derive(Debug)]
pub struct Live {
    /// Where the peer is, which is the only identity an unauthenticated relay
    /// has for it.
    pub peer: String,
    /// Raw QUIC or WebTransport.
    pub carrier: setup::Transport,
    /// When the session was established.
    pub since: Instant,
    /// Most recent round-trip estimate, in microseconds. Zero before the first
    /// sample.
    pub rtt_micros: AtomicU64,
    /// Most recent congestion window, in bytes.
    pub cwnd: AtomicU64,
    /// Packets the path has lost, cumulative for this connection.
    pub lost_packets: AtomicU64,
    /// Largest UDP payload the path currently carries.
    pub mtu: AtomicU64,
    /// Wire bytes sent to this peer.
    pub udp_tx_bytes: AtomicU64,
    /// Wire bytes received from it.
    pub udp_rx_bytes: AtomicU64,
    /// Tracks this session is currently forwarding downstream.
    pub forwarding: AtomicU64,
}

impl Live {
    fn new(peer: String, carrier: setup::Transport) -> Self {
        Self {
            peer,
            carrier,
            since: Instant::now(),
            rtt_micros: AtomicU64::new(0),
            cwnd: AtomicU64::new(0),
            lost_packets: AtomicU64::new(0),
            mtu: AtomicU64::new(0),
            udp_tx_bytes: AtomicU64::new(0),
            udp_rx_bytes: AtomicU64::new(0),
            forwarding: AtomicU64::new(0),
        }
    }
}

/// One reading of a connection's transport state.
///
/// Absolute values as QUIC reports them. Turning them into rates is
/// [`Metrics::sample`]'s job, because only it knows the previous reading.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sample {
    /// Current round-trip estimate.
    pub rtt: Duration,
    /// Current congestion window, in bytes.
    pub cwnd: u64,
    /// Cumulative packets lost on the path.
    pub lost_packets: u64,
    /// Cumulative congestion events.
    pub congestion_events: u64,
    /// Cumulative wire bytes sent.
    pub udp_tx_bytes: u64,
    /// Cumulative wire bytes received.
    pub udp_rx_bytes: u64,
    /// Largest UDP payload the path currently carries.
    pub mtu: u16,
}

impl Metrics {
    /// A registry that counts.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Some(Arc::new(Inner {
                started: Instant::now(),
                sessions_accepted: counters(),
                handshakes_failed: AtomicU64::new(0),
                sessions_ended: counters::<{ Ending::ALL.len() }>(),
                session_duration: Histogram::new(SESSION_BUCKETS),
                announcements: AtomicU64::new(0),
                subscriptions: counters(),
                fetches: counters(),
                fetch_records: AtomicU64::new(0),
                admitted: counters(),
                refused: std::array::from_fn(|_| counters()),
                refusal_reasons: counters(),
                tokens_refused: Mutex::new(HashMap::new()),
                subgroups_forwarded: AtomicU64::new(0),
                subgroups_dropped: AtomicU64::new(0),
                ingress_bytes: AtomicU64::new(0),
                forwarded_bytes: AtomicU64::new(0),
                fanout_failures: AtomicU64::new(0),
                rtt: Histogram::new(RTT_BUCKETS),
                udp_tx_bytes: AtomicU64::new(0),
                udp_rx_bytes: AtomicU64::new(0),
                lost_packets: AtomicU64::new(0),
                congestion_events: AtomicU64::new(0),
                live: Mutex::new(HashMap::new()),
            })),
        }
    }

    /// A registry that counts nothing, for tests and for a relay run with
    /// observability off.
    ///
    /// Every method still works and every recording is a branch on `None`, so
    /// call sites do not have to know which kind they hold.
    #[must_use]
    pub const fn disabled() -> Self {
        Self { inner: None }
    }

    /// Whether anything is being recorded.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    fn inner(&self) -> Option<&Inner> {
        self.inner.as_deref()
    }

    /// How long this process has been up.
    #[must_use]
    pub fn uptime(&self) -> Duration {
        self.inner()
            .map_or(Duration::ZERO, |i| i.started.elapsed())
    }

    /// A handshake failed before a session existed.
    pub fn handshake_failed(&self) {
        if let Some(inner) = self.inner() {
            inner.handshakes_failed.fetch_add(1, ORDER);
        }
    }

    /// A session completed SETUP. The returned handle is where its samples go.
    ///
    /// Returns `None` when metrics are disabled, which callers treat as "do not
    /// bother sampling" rather than as an error.
    #[must_use]
    pub fn session_started(
        &self,
        id: SessionId,
        peer: String,
        carrier: setup::Transport,
    ) -> Option<Arc<Live>> {
        let inner = self.inner()?;
        let index = usize::from(carrier == setup::Transport::WebTransport);
        inner.sessions_accepted[index].fetch_add(1, ORDER);
        let live = Arc::new(Live::new(peer, carrier));
        inner.lock_live().insert(id, Arc::clone(&live));
        Some(live)
    }

    /// A session ended. Removes it from the live set and records its lifetime.
    pub fn session_ended(&self, id: SessionId, how: Ending) {
        let Some(inner) = self.inner() else { return };
        inner.sessions_ended[how.index()].fetch_add(1, ORDER);
        if let Some(live) = inner.lock_live().remove(&id) {
            inner
                .session_duration
                .observe(live.since.elapsed().as_secs_f64());
        }
    }

    /// Fold one reading of a connection into both the process totals and the
    /// session's own row.
    ///
    /// `previous` is the reading before this one, so the monotonic counters can
    /// be advanced by their delta. A first sample should pass
    /// `Sample::default()`, which credits the connection's whole history so far
    /// — a handful of handshake packets.
    pub fn sample(&self, live: &Live, previous: Sample, current: Sample) {
        let Some(inner) = self.inner() else { return };

        inner.rtt.observe(current.rtt.as_secs_f64());
        // `saturating_sub` because these are read from a live connection
        // without a lock, and a reading that appears to go backwards is a
        // torn read rather than a reason to underflow a process counter.
        inner.udp_tx_bytes.fetch_add(
            current.udp_tx_bytes.saturating_sub(previous.udp_tx_bytes),
            ORDER,
        );
        inner.udp_rx_bytes.fetch_add(
            current.udp_rx_bytes.saturating_sub(previous.udp_rx_bytes),
            ORDER,
        );
        inner.lost_packets.fetch_add(
            current.lost_packets.saturating_sub(previous.lost_packets),
            ORDER,
        );
        inner.congestion_events.fetch_add(
            current
                .congestion_events
                .saturating_sub(previous.congestion_events),
            ORDER,
        );

        live.rtt_micros
            .store(current.rtt.as_micros().try_into().unwrap_or(u64::MAX), ORDER);
        live.cwnd.store(current.cwnd, ORDER);
        live.lost_packets.store(current.lost_packets, ORDER);
        live.mtu.store(u64::from(current.mtu), ORDER);
        live.udp_tx_bytes.store(current.udp_tx_bytes, ORDER);
        live.udp_rx_bytes.store(current.udp_rx_bytes, ORDER);
    }

    /// How many tracks a session is forwarding, for its diagnostic row.
    pub fn forwarding(&self, live: &Live, tracks: usize) {
        if self.is_enabled() {
            live.forwarding.store(tracks as u64, ORDER);
        }
    }

    /// A namespace was announced.
    pub fn announced(&self) {
        if let Some(inner) = self.inner() {
            inner.announcements.fetch_add(1, ORDER);
        }
    }

    /// A SUBSCRIBE was answered.
    pub fn subscribed(&self, outcome: Subscribed) {
        if let Some(inner) = self.inner() {
            inner.subscriptions[outcome.index()].fetch_add(1, ORDER);
        }
    }

    /// A FETCH was answered, delivering `records` records.
    pub fn fetched(&self, outcome: Fetched, records: usize) {
        if let Some(inner) = self.inner() {
            inner.fetches[outcome.index()].fetch_add(1, ORDER);
            inner.fetch_records.fetch_add(records as u64, ORDER);
        }
    }

    /// The rate limiter let a request through.
    pub fn admitted(&self, resource: Resource) {
        if let Some(inner) = self.inner() {
            inner.admitted[resource.index()].fetch_add(1, ORDER);
        }
    }

    /// The rate limiter turned a request away.
    ///
    /// Counted by resource, tier and reason and by nothing else. The identity is
    /// deliberately absent: a label per user is unbounded cardinality, which
    /// would let anyone who can connect grow the metrics endpoint without limit,
    /// and it would also publish who is being throttled to everyone who can
    /// scrape it.
    pub fn refused(&self, resource: Resource, refusal: &Refusal) {
        let Some(inner) = self.inner() else { return };
        inner.refused[resource.index()][refusal.tier.index()].fetch_add(1, ORDER);
        inner.refusal_reasons[refusal.reason.index()].fetch_add(1, ORDER);
    }

    /// A session offered a credential that did not verify.
    ///
    /// `cause` comes from [`crate::AuthError::name`], which is a fixed set.
    pub fn token_refused(&self, cause: &'static str) {
        let Some(inner) = self.inner() else { return };
        inner
            .tokens_refused
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(cause)
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }

    /// A subgroup stream arrived and had somewhere to go.
    pub fn subgroup_forwarded(&self) {
        if let Some(inner) = self.inner() {
            inner.subgroups_forwarded.fetch_add(1, ORDER);
        }
    }

    /// A subgroup stream arrived with no subscribers and nothing retaining it.
    pub fn subgroup_dropped(&self) {
        if let Some(inner) = self.inner() {
            inner.subgroups_dropped.fetch_add(1, ORDER);
        }
    }

    /// Payload bytes read from a publisher.
    pub fn ingress(&self, bytes: usize) {
        if let Some(inner) = self.inner() {
            inner.ingress_bytes.fetch_add(bytes as u64, ORDER);
        }
    }

    /// Payload bytes written to subscribers, counted once per copy.
    ///
    /// So this exceeds [`Self::ingress`] by the fan-out ratio, and the two
    /// together are the amplification a relay exists to provide.
    pub fn egress(&self, bytes: usize) {
        if let Some(inner) = self.inner() {
            inner.forwarded_bytes.fetch_add(bytes as u64, ORDER);
        }
    }

    /// A subscriber's stream could not be written and was dropped from a
    /// fan-out.
    pub fn fanout_failed(&self) {
        if let Some(inner) = self.inner() {
            inner.fanout_failures.fetch_add(1, ORDER);
        }
    }

    /// Every live session, newest last.
    #[must_use]
    pub fn sessions(&self) -> Vec<(SessionId, Arc<Live>)> {
        let Some(inner) = self.inner() else {
            return Vec::new();
        };
        let mut sessions: Vec<(SessionId, Arc<Live>)> = inner
            .lock_live()
            .iter()
            .map(|(id, live)| (*id, Arc::clone(live)))
            .collect();
        sessions.sort_by_key(|(id, _)| *id);
        sessions
    }

    /// How many sessions are connected.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.inner().map_or(0, |i| i.lock_live().len())
    }

    /// The Prometheus text exposition for everything above, plus the gauges
    /// passed in.
    ///
    /// Gauges that are derived from live state — namespaces announced, rooms
    /// occupied, what the cache holds — are arguments rather than fields,
    /// because storing a second copy of a number the fabric already knows is
    /// how the two come to disagree.
    #[must_use]
    #[allow(clippy::too_many_lines)] // one block per metric, read as a checklist
    pub fn expose(&self, gauges: &Gauges) -> String {
        let Some(inner) = self.inner() else {
            return String::new();
        };
        let mut out = String::with_capacity(4096);

        counter(
            &mut out,
            "moqom_relay_sessions_accepted_total",
            "Sessions that completed the SETUP exchange.",
            &[
                ("carrier", "quic", inner.sessions_accepted[0].load(ORDER)),
                (
                    "carrier",
                    "webtransport",
                    inner.sessions_accepted[1].load(ORDER),
                ),
            ],
        );
        plain(
            &mut out,
            "counter",
            "moqom_relay_handshakes_failed_total",
            "Connections that never reached SETUP.",
            inner.handshakes_failed.load(ORDER),
        );
        counter(
            &mut out,
            "moqom_relay_sessions_ended_total",
            "Sessions that finished, by how.",
            &Ending::ALL
                .map(|e| ("reason", e.label(), inner.sessions_ended[e.index()].load(ORDER))),
        );
        histogram(
            &mut out,
            "moqom_relay_session_duration_seconds",
            "How long sessions lasted.",
            &inner.session_duration,
        );

        plain(
            &mut out,
            "gauge",
            "moqom_relay_sessions",
            "Sessions currently connected.",
            inner.lock_live().len() as u64,
        );
        plain(
            &mut out,
            "counter",
            "moqom_relay_announcements_total",
            "Namespaces announced.",
            inner.announcements.load(ORDER),
        );
        plain(
            &mut out,
            "gauge",
            "moqom_relay_namespaces",
            "Namespaces currently announced.",
            gauges.namespaces as u64,
        );
        plain(
            &mut out,
            "gauge",
            "moqom_relay_rooms",
            "Rooms with at least one participant publishing.",
            gauges.rooms as u64,
        );
        plain(
            &mut out,
            "gauge",
            "moqom_relay_participants",
            "Participant slots currently publishing.",
            gauges.participants as u64,
        );

        counter(
            &mut out,
            "moqom_relay_subscriptions_total",
            "SUBSCRIBE requests answered, by outcome.",
            &Subscribed::ALL.map(|s| {
                (
                    "outcome",
                    s.label(),
                    inner.subscriptions[s.index()].load(ORDER),
                )
            }),
        );
        counter(
            &mut out,
            "moqom_relay_fetches_total",
            "FETCH requests answered, by outcome.",
            &Fetched::ALL
                .map(|f| ("outcome", f.label(), inner.fetches[f.index()].load(ORDER))),
        );
        plain(
            &mut out,
            "counter",
            "moqom_relay_fetch_records_total",
            "Records delivered on fetch streams.",
            inner.fetch_records.load(ORDER),
        );

        counter(
            &mut out,
            "moqom_relay_requests_admitted_total",
            "Requests the rate limiter allowed, by resource.",
            &Resource::ALL
                .map(|r| ("resource", r.name(), inner.admitted[r.index()].load(ORDER))),
        );
        // Two labels, because "we are refusing things" and "we are refusing them
        // because one person has too many devices" call for different responses,
        // and the tier is what tells them apart. Still bounded: five resources by
        // three tiers is fifteen series no matter how much traffic arrives.
        let mut refusals = Vec::with_capacity(Resource::ALL.len() * Tier::ALL.len());
        for resource in Resource::ALL {
            for tier in Tier::ALL {
                refusals.push((
                    resource.name(),
                    tier.name(),
                    inner.refused[resource.index()][tier.index()].load(ORDER),
                ));
            }
        }
        labelled(
            &mut out,
            "moqom_relay_requests_refused_total",
            "Requests the rate limiter turned away, by resource and by which allowance ran out.",
            "resource",
            "tier",
            &refusals,
        );
        counter(
            &mut out,
            "moqom_relay_refusals_total",
            "Rate limiter refusals by reason. `saturated` means the limiter itself is full.",
            &Reason::ALL.map(|r| {
                (
                    "reason",
                    r.name(),
                    inner.refusal_reasons[r.index()].load(ORDER),
                )
            }),
        );

        // Only the causes actually seen, because the fixed set lives in another
        // module and enumerating it here would be a second list to keep in step.
        // A cause with no occurrences is a series nobody needs.
        let seen = {
            let counts = inner
                .tokens_refused
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut seen: Vec<(&'static str, u64)> =
                counts.iter().map(|(&cause, &n)| (cause, n)).collect();
            // Sorted so the exposition is stable between scrapes, which is what
            // makes a diff of two scrapes readable.
            seen.sort_unstable();
            seen
        };
        let series: Vec<(&str, &str, u64)> = seen
            .iter()
            .map(|&(cause, count)| ("cause", cause, count))
            .collect();
        counter(
            &mut out,
            "moqom_relay_tokens_refused_total",
            "Session credentials that did not verify, by cause.",
            &series,
        );

        counter(
            &mut out,
            "moqom_relay_subgroups_total",
            "Subgroup streams received, by whether anything wanted them.",
            &[
                (
                    "disposition",
                    "forwarded",
                    inner.subgroups_forwarded.load(ORDER),
                ),
                (
                    "disposition",
                    "dropped",
                    inner.subgroups_dropped.load(ORDER),
                ),
            ],
        );
        plain(
            &mut out,
            "counter",
            "moqom_relay_ingress_bytes_total",
            "Subgroup payload bytes read from publishers.",
            inner.ingress_bytes.load(ORDER),
        );
        plain(
            &mut out,
            "counter",
            "moqom_relay_egress_bytes_total",
            "Subgroup payload bytes written to subscribers, once per copy.",
            inner.forwarded_bytes.load(ORDER),
        );
        plain(
            &mut out,
            "counter",
            "moqom_relay_fanout_failures_total",
            "Subscriber streams dropped mid-forward because a write failed.",
            inner.fanout_failures.load(ORDER),
        );

        histogram(
            &mut out,
            "moqom_relay_connection_rtt_seconds",
            "Round-trip time, sampled once per session per interval.",
            &inner.rtt,
        );
        plain(
            &mut out,
            "counter",
            "moqom_relay_udp_tx_bytes_total",
            "Wire bytes sent, across all connections.",
            inner.udp_tx_bytes.load(ORDER),
        );
        plain(
            &mut out,
            "counter",
            "moqom_relay_udp_rx_bytes_total",
            "Wire bytes received, across all connections.",
            inner.udp_rx_bytes.load(ORDER),
        );
        plain(
            &mut out,
            "counter",
            "moqom_relay_lost_packets_total",
            "Packets QUIC declared lost, across all connections.",
            inner.lost_packets.load(ORDER),
        );
        plain(
            &mut out,
            "counter",
            "moqom_relay_congestion_events_total",
            "Congestion events, across all connections.",
            inner.congestion_events.load(ORDER),
        );

        counter(
            &mut out,
            "moqom_relay_cache_lookups_total",
            "Fetch lookups against retained history.",
            &[
                ("outcome", "hit", gauges.cache_hits),
                ("outcome", "miss", gauges.cache_misses),
            ],
        );
        plain(
            &mut out,
            "gauge",
            "moqom_relay_cache_tracks",
            "Tracks with retained history.",
            gauges.cache_tracks as u64,
        );
        plain(
            &mut out,
            "gauge",
            "moqom_relay_cache_groups",
            "Groups retained.",
            gauges.cache_groups as u64,
        );
        plain(
            &mut out,
            "gauge",
            "moqom_relay_cache_objects",
            "Objects retained.",
            gauges.cache_objects as u64,
        );
        plain(
            &mut out,
            "gauge",
            "moqom_relay_cache_bytes",
            "Payload bytes retained.",
            gauges.cache_bytes as u64,
        );

        plain(
            &mut out,
            "gauge",
            "moqom_relay_uptime_seconds",
            "How long this process has been running.",
            inner.started.elapsed().as_secs(),
        );

        out
    }
}

impl Inner {
    fn lock_live(&self) -> std::sync::MutexGuard<'_, HashMap<SessionId, Arc<Live>>> {
        self.live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Values read from live state at scrape time rather than counted as they
/// happen.
///
/// The fabric and the cache already know these, authoritatively. Mirroring them
/// into counters would add a second source of truth that drifts from the first
/// under exactly the conditions you would be reading it to understand.
#[derive(Debug, Clone, Copy, Default)]
pub struct Gauges {
    /// Namespaces currently announced.
    pub namespaces: usize,
    /// Distinct rooms among them.
    pub rooms: usize,
    /// Participant slots among them.
    pub participants: usize,
    /// Tracks holding retained history.
    pub cache_tracks: usize,
    /// Groups retained.
    pub cache_groups: usize,
    /// Objects retained.
    pub cache_objects: usize,
    /// Payload bytes retained.
    pub cache_bytes: usize,
    /// Fetch lookups that found history.
    pub cache_hits: u64,
    /// Fetch lookups that did not.
    pub cache_misses: u64,
}

/// An array of counters, all starting at zero.
///
/// `AtomicU64` is not `Copy`, so the array repeat syntax does not apply.
fn counters<const N: usize>() -> [AtomicU64; N] {
    std::array::from_fn(|_| AtomicU64::new(0))
}

/// A single unlabelled metric.
fn plain(out: &mut String, kind: &str, name: &str, help: &str, value: u64) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
    let _ = writeln!(out, "{name} {value}");
}

/// A counter with one label, whose values are known at compile time.
fn counter(out: &mut String, name: &str, help: &str, series: &[(&str, &str, u64)]) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} counter");
    for (label, value, count) in series {
        let _ = writeln!(out, "{name}{{{label}=\"{value}\"}} {count}");
    }
}

/// A counter with two labels.
fn labelled(
    out: &mut String,
    name: &str,
    help: &str,
    first: &str,
    second: &str,
    series: &[(&str, &str, u64)],
) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} counter");
    for (one, two, count) in series {
        let _ = writeln!(out, "{name}{{{first}=\"{one}\",{second}=\"{two}\"}} {count}");
    }
}

fn histogram(out: &mut String, name: &str, help: &str, hist: &Histogram) {
    let (cumulative, count, sum) = hist.snapshot();
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} histogram");
    for (bound, running) in hist.bounds.iter().zip(&cumulative) {
        let _ = writeln!(out, "{name}_bucket{{le=\"{bound}\"}} {running}");
    }
    let _ = writeln!(out, "{name}_bucket{{le=\"+Inf\"}} {count}");
    let _ = writeln!(out, "{name}_sum {sum}");
    let _ = writeln!(out, "{name}_count {count}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fabric::Fabric;

    /// A real identifier rather than a fabricated one, so these tests cannot
    /// drift from how identifiers are actually allocated.
    fn session_id() -> SessionId {
        Fabric::new().next_session_id()
    }

    fn sample(rtt_ms: u64, lost: u64, tx: u64) -> Sample {
        Sample {
            rtt: Duration::from_millis(rtt_ms),
            cwnd: 12_000,
            lost_packets: lost,
            congestion_events: 0,
            udp_tx_bytes: tx,
            udp_rx_bytes: 0,
            mtu: 1200,
        }
    }

    #[test]
    fn a_disabled_registry_records_nothing_and_exposes_nothing() {
        let metrics = Metrics::disabled();
        metrics.announced();
        metrics.egress(9999);
        metrics.subscribed(Subscribed::Established);
        assert!(!metrics.is_enabled());
        assert_eq!(metrics.session_count(), 0);
        assert!(metrics.expose(&Gauges::default()).is_empty());
    }

    #[test]
    fn a_session_appears_while_it_is_live_and_leaves_when_it_ends() {
        let metrics = Metrics::new();
        let id = session_id();

        let live = metrics
            .session_started(id, "203.0.113.9:443".to_owned(), setup::Transport::Quic)
            .expect("enabled");
        assert_eq!(metrics.session_count(), 1);
        assert_eq!(metrics.sessions()[0].1.peer, "203.0.113.9:443");
        drop(live);

        metrics.session_ended(id, Ending::Clean);
        assert_eq!(metrics.session_count(), 0);
        assert!(metrics.expose(&Gauges::default()).contains("moqom_relay_sessions 0"));
    }

    /// The delta arithmetic is the part that would be wrong silently: absolute
    /// values folded in as increments would multiply every connection's traffic
    /// by the number of times it was sampled.
    #[test]
    fn repeated_samples_add_their_difference_and_not_their_value() {
        let metrics = Metrics::new();
        let id = session_id();
        let live = metrics
            .session_started(id, "peer".to_owned(), setup::Transport::Quic)
            .expect("enabled");

        metrics.sample(&live, Sample::default(), sample(20, 3, 1_000));
        metrics.sample(&live, sample(20, 3, 1_000), sample(25, 5, 4_000));

        let exposed = metrics.expose(&Gauges::default());
        assert!(
            exposed.contains("moqom_relay_udp_tx_bytes_total 4000"),
            "two samples of a connection that has sent 4000 bytes total is 4000, not 5000: {exposed}"
        );
        assert!(exposed.contains("moqom_relay_lost_packets_total 5"));
        assert_eq!(live.rtt_micros.load(ORDER), 25_000);
        assert_eq!(live.lost_packets.load(ORDER), 5);
    }

    /// A torn read of a live connection can appear to move backwards. That must
    /// not underflow a process-wide counter into something astronomical.
    #[test]
    fn a_reading_that_goes_backwards_does_not_underflow() {
        let metrics = Metrics::new();
        let id = session_id();
        let live = metrics
            .session_started(id, "peer".to_owned(), setup::Transport::Quic)
            .expect("enabled");

        metrics.sample(&live, sample(20, 10, 5_000), sample(20, 4, 1_000));
        let exposed = metrics.expose(&Gauges::default());
        assert!(exposed.contains("moqom_relay_udp_tx_bytes_total 0"));
        assert!(exposed.contains("moqom_relay_lost_packets_total 0"));
    }

    #[test]
    fn outcomes_are_counted_separately() {
        let metrics = Metrics::new();
        metrics.subscribed(Subscribed::Established);
        metrics.subscribed(Subscribed::Established);
        metrics.subscribed(Subscribed::NoPublisher);
        metrics.fetched(Fetched::Served, 12);
        metrics.fetched(Fetched::NoHistory, 0);

        let exposed = metrics.expose(&Gauges::default());
        assert!(exposed.contains(r#"moqom_relay_subscriptions_total{outcome="established"} 2"#));
        assert!(exposed.contains(r#"moqom_relay_subscriptions_total{outcome="no_publisher"} 1"#));
        assert!(exposed.contains(r#"moqom_relay_subscriptions_total{outcome="refused"} 0"#));
        assert!(exposed.contains(r#"moqom_relay_fetches_total{outcome="served"} 1"#));
        assert!(exposed.contains("moqom_relay_fetch_records_total 12"));
    }

    /// Prometheus requires histogram buckets to be cumulative, and a scrape
    /// with decreasing buckets is rejected rather than tolerated.
    #[test]
    fn histogram_buckets_are_cumulative_and_end_at_the_count() {
        let hist = Histogram::new(&[0.010, 0.100, 1.0]);
        hist.observe(0.005);
        hist.observe(0.050);
        hist.observe(0.500);
        hist.observe(30.0);

        let (buckets, count, sum) = hist.snapshot();
        assert_eq!(buckets, vec![1, 2, 3, 4]);
        assert_eq!(count, 4);
        assert!((sum - 30.555).abs() < 0.001, "sum was {sum}");
        assert!(
            buckets.windows(2).all(|w| w[0] <= w[1]),
            "buckets must not decrease"
        );
    }

    /// A value exactly on a bucket bound belongs in that bucket: Prometheus
    /// bounds are inclusive upper bounds, and an off-by-one here shifts every
    /// quantile.
    #[test]
    fn a_value_on_a_bound_falls_in_that_bucket() {
        let hist = Histogram::new(&[0.010, 0.100]);
        hist.observe(0.010);
        let (buckets, _, _) = hist.snapshot();
        assert_eq!(buckets[0], 1, "0.010 belongs in le=\"0.010\"");
    }

    /// Derived gauges come from the caller, so the exposition has to actually
    /// use them rather than reporting its own idea of the same numbers.
    #[test]
    fn derived_gauges_are_reported_as_given() {
        let metrics = Metrics::new();
        let exposed = metrics.expose(&Gauges {
            namespaces: 5,
            rooms: 2,
            participants: 4,
            cache_tracks: 3,
            cache_groups: 24,
            cache_objects: 900,
            cache_bytes: 1_048_576,
            cache_hits: 40,
            cache_misses: 2,
        });
        assert!(exposed.contains("moqom_relay_namespaces 5"));
        assert!(exposed.contains("moqom_relay_rooms 2"));
        assert!(exposed.contains("moqom_relay_participants 4"));
        assert!(exposed.contains("moqom_relay_cache_bytes 1048576"));
        assert!(exposed.contains(r#"moqom_relay_cache_lookups_total{outcome="hit"} 40"#));
    }

    /// Every metric needs HELP and TYPE before its samples, and a name must not
    /// be declared twice in one scrape.
    #[test]
    fn the_exposition_is_well_formed() {
        let metrics = Metrics::new();
        let exposed = metrics.expose(&Gauges::default());

        let mut declared = Vec::new();
        for line in exposed.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                let name = rest.split_whitespace().next().expect("a name");
                assert!(
                    !declared.contains(&name.to_owned()),
                    "{name} is declared twice"
                );
                declared.push(name.to_owned());
            }
        }
        assert!(!declared.is_empty());

        for line in exposed.lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let name = line
                .split(['{', ' '])
                .next()
                .expect("a name")
                .trim_end_matches('_')
                .to_owned();
            let stem = name
                .strip_suffix("_bucket")
                .or_else(|| name.strip_suffix("_sum"))
                .or_else(|| name.strip_suffix("_count"))
                .unwrap_or(&name);
            assert!(
                declared.iter().any(|d| d == stem),
                "{stem} has samples but no TYPE"
            );
        }
    }
}
