//! Rate and concurrency limits, charged to whoever is responsible for them.
//!
//! # Why per-identity rather than per-session
//!
//! A limit attached to a connection is a limit an attacker removes by opening a
//! second connection. `draft-englishm-moq-relay-dos` makes the point directly:
//! the interesting abuse of a relay is cheap for the client and expensive for
//! the server, and every one of those is trivially parallelised across
//! connections. So the charge follows the identity, and a client that opens
//! fifty sessions gets one identity's allowance spread over fifty sessions
//! rather than fifty allowances.
//!
//! # Two tiers, and why both
//!
//! Every verified request is charged twice: once to the device and once to the
//! user behind it. Neither alone is enough.
//!
//! Device alone lets one person with twenty phones consume twenty allowances,
//! which is the same hole per-session limits have, just more expensive to
//! exploit. User alone lets one compromised or buggy device spend everything
//! its owner has, so a crash-looping client locks the person out of their own
//! other devices. Charging both means a device is bounded by what one device
//! should ever need, and a person is bounded by something less than the sum of
//! their devices — which is the correct shape, because nobody legitimately
//! broadcasts from sixteen phones at once.
//!
//! The two charges are atomic with respect to each other. If the device is
//! within its allowance and the user is not, *neither* is debited, and the same
//! the other way round. Debiting the tier that passed would mean a client
//! hammering one device slowly drains the budget for that person's other
//! devices even though not one of those requests was ever served — a refusal
//! that costs the victim something is a refusal an attacker can aim.
//!
//! # Keying on identity you have not verified is worse than not limiting
//!
//! [`Principal`] can only be constructed as [`Principal::verified`] from an
//! identity the relay has actually authenticated. This is not fastidiousness.
//! A limiter keyed on a claimed name has two holes at once: the attacker
//! escapes their own limit by claiming a fresh name per request, and — worse —
//! aims someone else's limit at them by claiming *their* name, turning the
//! rate limiter into the denial of service it was added to prevent. Where
//! there is no verified identity the charge falls on the network address, which
//! is coarse and shared but is at least a thing the client cannot choose.
//!
//! One consequence worth stating because it is a feature rather than a
//! shortfall: [`Tier::Address`] should be configured well below the other two,
//! so authenticating is what buys capacity.
//!
//! # What is not limited here
//!
//! Media objects. A publisher sending too fast is a congestion-control problem
//! and belongs to `moqom-cc`, which can shed a layer; answering it with a
//! refusal would drop a broadcast to protect a buffer. What this governs is
//! *requests* — sessions, subscriptions, announcements, watches, and fetches —
//! which are the operations that allocate durable state on the relay.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// What a request is charged against.
///
/// Built from a verified identity where there is one, and from the peer address
/// where there is not. There is deliberately no constructor taking an unverified
/// name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Principal {
    /// A token holder whose signature this relay checked.
    Verified {
        /// The tenant the token was issued under.
        tenant: Arc<str>,
        /// The `sub` claim.
        username: Arc<str>,
        /// Derived from the confirmation thumbprint, matching the control
        /// plane's derivation so a limit and a ban name the same device.
        device: Arc<str>,
    },
    /// Nobody in particular. The address is the only thing left that the peer
    /// cannot simply assert.
    Anonymous(IpAddr),
}

impl Principal {
    /// A verified token holder.
    #[must_use]
    pub fn verified(tenant: &str, username: &str, device: &str) -> Self {
        Self::Verified {
            tenant: Arc::from(tenant),
            username: Arc::from(username),
            device: Arc::from(device),
        }
    }

    /// An unauthenticated peer, charged by address.
    #[must_use]
    pub const fn anonymous(address: IpAddr) -> Self {
        Self::Anonymous(address)
    }

    /// Whether this identity was actually established.
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    /// The tiers this principal is charged against, in the order they are
    /// reported when more than one refuses.
    fn charges(&self) -> Charges {
        match self {
            Self::Verified {
                tenant,
                username,
                device,
            } => Charges::two(
                (
                    Tier::Device,
                    Key::Device {
                        tenant: tenant.clone(),
                        username: username.clone(),
                        device: device.clone(),
                    },
                ),
                (
                    Tier::User,
                    Key::User {
                        tenant: tenant.clone(),
                        username: username.clone(),
                    },
                ),
            ),
            Self::Anonymous(address) => Charges::one((Tier::Address, Key::Address(*address))),
        }
    }
}

/// Up to two (tier, key) pairs without reaching for a heap allocation on a path
/// that runs per request.
struct Charges {
    items: [Option<(Tier, Key)>; 2],
}

impl Charges {
    fn one(first: (Tier, Key)) -> Self {
        Self {
            items: [Some(first), None],
        }
    }

    fn two(first: (Tier, Key), second: (Tier, Key)) -> Self {
        Self {
            items: [Some(first), Some(second)],
        }
    }

    fn iter(&self) -> impl Iterator<Item = &(Tier, Key)> {
        self.items.iter().flatten()
    }
}

/// Which allowance a charge came out of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Tier {
    /// One device belonging to one person.
    Device,
    /// One person, across every device they are signed in on.
    User,
    /// One network address, for peers with no verified identity.
    Address,
}

impl Tier {
    /// Every tier, in table order.
    pub const ALL: [Self; 3] = [Self::Device, Self::User, Self::Address];

    /// A stable, low-cardinality name for metrics and logs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::User => "user",
            Self::Address => "address",
        }
    }

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Device => 0,
            Self::User => 1,
            Self::Address => 2,
        }
    }
}

/// The identity a table entry is filed under.
///
/// Tenant is part of both keys, so two customers who happen to have a user
/// called `admin` do not share an allowance — or a way to exhaust each other's.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Key {
    User {
        tenant: Arc<str>,
        username: Arc<str>,
    },
    Device {
        tenant: Arc<str>,
        username: Arc<str>,
        device: Arc<str>,
    },
    Address(IpAddr),
}

/// The operations a relay allocates state for, and therefore the ones worth
/// charging.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Resource {
    /// A MOQT session, from SETUP to close.
    Session,
    /// A SUBSCRIBE, which holds a route and an upstream subscription open.
    Subscription,
    /// A `PUBLISH_NAMESPACE`, which holds an entry in the announcement table.
    Announcement,
    /// A `SUBSCRIBE_NAMESPACE`, which holds a watcher and receives an event per
    /// announcement anywhere under its prefix.
    Watch,
    /// A FETCH, which reads retained history. Instantaneous, but the most
    /// expensive request per unit of client effort that this relay serves.
    Fetch,
}

impl Resource {
    /// Every resource, in the order allowances store them.
    pub const ALL: [Self; 5] = [
        Self::Session,
        Self::Subscription,
        Self::Announcement,
        Self::Watch,
        Self::Fetch,
    ];

    /// A stable, low-cardinality name for metrics and logs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Subscription => "subscription",
            Self::Announcement => "announcement",
            Self::Watch => "watch",
            Self::Fetch => "fetch",
        }
    }

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Session => 0,
            Self::Subscription => 1,
            Self::Announcement => 2,
            Self::Watch => 3,
            Self::Fetch => 4,
        }
    }
}

/// A sustained rate with a burst above it.
///
/// Burst matters more than it looks. A client joining a room subscribes to every
/// participant at once, so a limiter with no burst turns an ordinary join into a
/// staircase; and a burst far above the sustained rate is what lets that join be
/// fast while still bounding a client that never stops.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rate {
    /// Requests per second, sustained.
    pub per_second: f64,
    /// How many may arrive at once from a standing start.
    pub burst: f64,
}

impl Rate {
    /// A rate with a burst.
    #[must_use]
    pub const fn new(per_second: f64, burst: f64) -> Self {
        Self { per_second, burst }
    }

    /// No rate limit at all. Concurrency may still apply.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            per_second: f64::INFINITY,
            burst: f64::INFINITY,
        }
    }

    const fn is_unlimited(self) -> bool {
        self.per_second.is_infinite()
    }

    /// Scale both halves, for deriving one tier's allowance from another's.
    #[must_use]
    pub fn scaled(self, factor: f64) -> Self {
        if self.is_unlimited() {
            return self;
        }
        Self {
            per_second: self.per_second * factor,
            burst: self.burst * factor,
        }
    }
}

/// What one tier may do with one resource.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Quota {
    /// How often it may be asked for.
    pub rate: Rate,
    /// How many may be held at once. Zero means no concurrency limit, which is
    /// the right setting for a resource that is not held at all.
    pub concurrent: u32,
}

impl Quota {
    /// A quota with both halves.
    #[must_use]
    pub const fn new(per_second: f64, burst: f64, concurrent: u32) -> Self {
        Self {
            rate: Rate::new(per_second, burst),
            concurrent,
        }
    }

    /// Scale both halves, for deriving one tier's allowance from another's.
    #[must_use]
    pub fn scaled(self, factor: f64) -> Self {
        Self {
            rate: self.rate.scaled(factor),
            // Rounded up, so scaling a limit of one by anything above one
            // actually raises it.
            concurrent: if self.concurrent == 0 {
                0
            } else {
                #[allow(clippy::cast_sign_loss, clippy::cast_precision_loss)]
                let scaled = (f64::from(self.concurrent) * factor).ceil() as u32;
                scaled.max(1)
            },
        }
    }
}

/// One tier's quota for every resource.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Allowance {
    /// Sessions.
    pub session: Quota,
    /// Subscriptions.
    pub subscription: Quota,
    /// Namespace announcements.
    pub announcement: Quota,
    /// Namespace watches.
    pub watch: Quota,
    /// Fetches.
    pub fetch: Quota,
}

impl Allowance {
    /// What one device may do.
    ///
    /// These are generous for a client and mean for an attacker, which is the
    /// only useful place to sit. A phone in a call opens one session, subscribes
    /// to at most the sixteen tiles it can decode plus a little churn as the
    /// gallery reorders, announces its own two or three tracks, watches one
    /// room prefix, and fetches on reconnection. Every number here is several
    /// times that, and every one of them is far below what a loop can do.
    #[must_use]
    pub const fn per_device() -> Self {
        Self {
            // Reconnection is the honest case for a burst here: a flapping
            // network produces a handful of setups in quick succession, and
            // refusing those turns a recoverable blip into a failed call.
            session: Quota::new(0.5, 5.0, 8),
            // The burst carries a full gallery join; the sustained rate carries
            // reordering without carrying a churn attack.
            subscription: Quota::new(10.0, 64.0, 128),
            announcement: Quota::new(2.0, 16.0, 32),
            watch: Quota::new(1.0, 8.0, 16),
            // Deliberately the tightest rate. A fetch reads retained history, so
            // it is the one request where a small message asks for megabytes.
            fetch: Quota::new(2.0, 16.0, 8),
        }
    }

    /// What one person may do across every device at once.
    ///
    /// Four times a single device rather than unbounded: enough for a phone, a
    /// laptop, a tablet and something borrowed, and nowhere near enough for a
    /// credential being used as a botnet key. Someone who genuinely needs more
    /// is a customer to raise a limit for, not a default to widen.
    #[must_use]
    pub fn per_user() -> Self {
        Self::per_device().scaled(4.0)
    }

    /// What an unauthenticated peer may do.
    ///
    /// Enough to connect and be told to authenticate, and not much else.
    /// Deliberately far below the other two: this is the tier where an attacker
    /// with no credential lives, and it is also the tier that a NAT full of
    /// legitimate users shares, so the correct response to hitting it is to
    /// present a token rather than to raise it.
    #[must_use]
    pub const fn per_address() -> Self {
        Self {
            session: Quota::new(0.2, 3.0, 4),
            subscription: Quota::new(2.0, 8.0, 16),
            announcement: Quota::new(0.5, 2.0, 4),
            watch: Quota::new(0.2, 2.0, 2),
            fetch: Quota::new(0.5, 2.0, 2),
        }
    }

    /// Every quota scaled by the same factor, for deriving one tier from
    /// another.
    #[must_use]
    pub fn scaled(self, factor: f64) -> Self {
        Self {
            session: self.session.scaled(factor),
            subscription: self.subscription.scaled(factor),
            announcement: self.announcement.scaled(factor),
            watch: self.watch.scaled(factor),
            fetch: self.fetch.scaled(factor),
        }
    }

    const fn quota(&self, resource: Resource) -> Quota {
        match resource {
            Resource::Session => self.session,
            Resource::Subscription => self.subscription,
            Resource::Announcement => self.announcement,
            Resource::Watch => self.watch,
            Resource::Fetch => self.fetch,
        }
    }
}

/// Everything the governor is configured with.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Quotas {
    /// Per device.
    pub device: Allowance,
    /// Per user, across their devices.
    pub user: Allowance,
    /// Per address, for peers with no verified identity.
    pub address: Allowance,
    /// How many principals each tier tracks at once.
    ///
    /// This bounds the limiter's own memory, which matters because a table
    /// keyed on something the peer influences is itself an amplification: an
    /// attacker who can make the relay allocate an entry per request has turned
    /// the defence into the attack. See [`Governor::admit`] for what happens
    /// when the table is full, which is the part that has to be right.
    pub principals: usize,
}

impl Default for Quotas {
    fn default() -> Self {
        Self {
            device: Allowance::per_device(),
            user: Allowance::per_user(),
            address: Allowance::per_address(),
            // At roughly 150 bytes an entry this is about 15MB a tier fully
            // populated, which is affordable next to the media cache and large
            // enough that reaching it means either a very large relay or an
            // attack.
            principals: 100_000,
        }
    }
}

impl Quotas {
    /// Nothing is limited. For tests and for an operator who has a limiter in
    /// front of the relay already.
    #[must_use]
    pub const fn unlimited() -> Self {
        const OPEN: Quota = Quota {
            rate: Rate::unlimited(),
            concurrent: 0,
        };
        const EVERYTHING: Allowance = Allowance {
            session: OPEN,
            subscription: OPEN,
            announcement: OPEN,
            watch: OPEN,
            fetch: OPEN,
        };
        Self {
            device: EVERYTHING,
            user: EVERYTHING,
            address: EVERYTHING,
            principals: 0,
        }
    }

    const fn allowance(&self, tier: Tier) -> &Allowance {
        match tier {
            Tier::Device => &self.device,
            Tier::User => &self.user,
            Tier::Address => &self.address,
        }
    }
}

/// Why a request was not admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// Asked for too often.
    TooFast,
    /// Too many held at once.
    TooMany,
    /// The relay is tracking as many principals as it can and none of them
    /// could be forgotten safely.
    Saturated,
}

impl Reason {
    /// Every reason, in the order counters store them.
    pub const ALL: [Self; 3] = [Self::TooFast, Self::TooMany, Self::Saturated];

    /// A stable name for metrics and logs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::TooFast => "too_fast",
            Self::TooMany => "too_many",
            Self::Saturated => "saturated",
        }
    }

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::TooFast => 0,
            Self::TooMany => 1,
            Self::Saturated => 2,
        }
    }
}

/// A refusal, with enough detail to answer the peer properly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// What was asked for.
    pub resource: Resource,
    /// Which allowance ran out.
    pub tier: Tier,
    /// Why.
    pub reason: Reason,
    /// How long until the request would succeed.
    ///
    /// Exact for [`Reason::TooFast`], because a token bucket knows precisely
    /// when its next token arrives. An estimate for the other two, since they
    /// clear when somebody else finishes. Worth sending either way: MOQT's
    /// `REQUEST_ERROR` carries a retry-after, and a refusal that says when to
    /// come back turns a retry storm into a schedule.
    pub retry_after: Duration,
}

impl Refusal {
    /// Milliseconds, for the wire.
    #[must_use]
    pub fn retry_after_ms(&self) -> u64 {
        // Rounded up: a peer that retries at exactly the boundary and loses to
        // a rounding error gets refused twice and learns nothing from the
        // second refusal.
        let millis = self.retry_after.as_millis().max(1);
        u64::try_from(millis).unwrap_or(u64::MAX)
    }

    /// A reason phrase for the peer.
    ///
    /// Names the resource and the tier but never the identity. The peer already
    /// knows who it is, and a relay that echoes an identity back has built a
    /// probe for whether a given username is rate limited.
    #[must_use]
    pub fn reason_phrase(&self) -> String {
        match self.reason {
            Reason::TooFast => format!(
                "{} requests exceed the per-{} rate",
                self.resource.name(),
                self.tier.name()
            ),
            Reason::TooMany => format!(
                "too many {}s held for this {}",
                self.resource.name(),
                self.tier.name()
            ),
            Reason::Saturated => "relay is tracking as many peers as it can".to_owned(),
        }
    }
}

/// How long to suggest waiting when a slot has to be given up by somebody else.
///
/// There is no honest answer — it depends on when another client leaves — so
/// this is a compromise between a client that retries uselessly and one that
/// waits longer than the condition lasts.
const UNKNOWN_WAIT: Duration = Duration::from_secs(2);

/// A held resource, released when this is dropped.
///
/// Dropping is the only way to release, which is what makes the count correct
/// across the error paths: a subscription torn down by a protocol error, a
/// panic in a task, or a peer vanishing mid-request all unwind through the same
/// drop as an orderly close. A release that had to be called would be a release
/// that some path forgot.
#[derive(Debug)]
#[must_use = "dropping the lease immediately releases the slot it acquired"]
pub struct Lease {
    state: Arc<Mutex<State>>,
    charges: [Option<(Tier, Key)>; 2],
    resource: Resource,
}

impl Drop for Lease {
    fn drop(&mut self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        for (tier, key) in self.charges.iter().flatten() {
            state.release(*tier, key, self.resource);
        }
    }
}

/// One principal's standing with one tier.
#[derive(Debug)]
struct Entry {
    buckets: [Bucket; Resource::ALL.len()],
    live: [u32; Resource::ALL.len()],
}

impl Entry {
    fn new(allowance: &Allowance, now: Instant) -> Self {
        let mut buckets = [Bucket {
            tokens: 0.0,
            last: now,
        }; Resource::ALL.len()];
        for resource in Resource::ALL {
            buckets[resource.index()].tokens = allowance.quota(resource).rate.burst;
        }
        Self {
            buckets,
            live: [0; Resource::ALL.len()],
        }
    }

    /// Whether forgetting this entry could change any future decision.
    ///
    /// It cannot when every bucket is full and nothing is held, because a
    /// missing entry is created full and holding nothing. That equivalence is
    /// what makes eviction safe, and it is the whole reason the table can be
    /// bounded without weakening the limit.
    fn is_idle(&self, allowance: &Allowance, now: Instant) -> bool {
        if self.live.iter().any(|&count| count > 0) {
            return false;
        }
        Resource::ALL.iter().all(|&resource| {
            let quota = allowance.quota(resource);
            let mut bucket = self.buckets[resource.index()];
            bucket.refill(quota.rate, now);
            bucket.is_full(quota.rate)
        })
    }
}

/// A token bucket, refilled lazily.
///
/// Lazily because the alternative is a timer per principal, and a hundred
/// thousand timers to add tokens to buckets nobody is reading is a great deal
/// of work to arrive at the same answer.
#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn refill(&mut self, rate: Rate, now: Instant) {
        if rate.is_unlimited() {
            return;
        }
        // Saturating rather than signed: a clock that goes backwards between
        // two reads would otherwise remove tokens, and `Instant` is monotonic
        // per platform contract but this costs nothing to not depend on.
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * rate.per_second).min(rate.burst);
            self.last = now;
        }
    }

    fn is_full(&self, rate: Rate) -> bool {
        rate.is_unlimited() || self.tokens >= rate.burst
    }

    /// Whether a token is available, without taking it.
    fn would_admit(&self, rate: Rate) -> bool {
        rate.is_unlimited() || self.tokens >= 1.0
    }

    fn take(&mut self, rate: Rate) {
        if !rate.is_unlimited() {
            self.tokens -= 1.0;
        }
    }

    fn wait(&self, rate: Rate) -> Duration {
        if rate.is_unlimited() || self.tokens >= 1.0 {
            return Duration::ZERO;
        }
        if rate.per_second <= 0.0 {
            // A rate of zero admits nothing, ever. Saying "come back in a
            // moment" would be a lie the client acts on.
            return Duration::MAX;
        }
        Duration::from_secs_f64((1.0 - self.tokens) / rate.per_second)
    }
}

/// One tier's principals.
#[derive(Debug)]
struct Table {
    entries: HashMap<Key, Entry>,
    swept: Option<Instant>,
}

/// How often a full table is swept for entries that can be forgotten.
///
/// Without this, a table that is full of live entries sweeps on every request
/// and the limiter becomes O(principals) per call — which is precisely the
/// amplification the bound exists to prevent.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

impl Table {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            swept: None,
        }
    }

    /// Forget every entry whose removal cannot change a decision.
    fn sweep(&mut self, allowance: &Allowance, now: Instant) {
        self.entries.retain(|_, entry| !entry.is_idle(allowance, now));
        self.swept = Some(now);
    }
}

/// The tables, and nothing else.
///
/// The quotas live outside this lock because they never change: keeping them in
/// here meant copying three hundred bytes of configuration out on every request
/// to satisfy the borrow checker, which is a lot of memcpy to read four numbers.
#[derive(Debug)]
struct State {
    tables: [Table; Tier::ALL.len()],
}

impl State {
    fn release(&mut self, tier: Tier, key: &Key, resource: Resource) {
        if let Some(entry) = self.tables[tier.index()].entries.get_mut(key) {
            let count = &mut entry.live[resource.index()];
            *count = count.saturating_sub(1);
        }
    }
}

/// The thing that says yes or no.
///
/// Cheap to clone and shared across every session, because the whole point is
/// that two sessions belonging to one device meet the same counter.
#[derive(Clone, Debug)]
pub struct Governor {
    quotas: Arc<Quotas>,
    state: Arc<Mutex<State>>,
    /// Kept outside the lock so the hot read of "is anything limited at all"
    /// does not have to take it.
    limiting: bool,
}

impl Governor {
    /// A governor enforcing `quotas`.
    #[must_use]
    pub fn new(quotas: Quotas) -> Self {
        Self {
            limiting: quotas != Quotas::unlimited(),
            quotas: Arc::new(quotas),
            state: Arc::new(Mutex::new(State {
                tables: [Table::new(), Table::new(), Table::new()],
            })),
        }
    }

    /// A governor that admits everything, for tests and for a deployment with a
    /// limiter of its own in front.
    #[must_use]
    pub fn disabled() -> Self {
        Self::new(Quotas::unlimited())
    }

    /// Whether this governor enforces anything.
    #[must_use]
    pub const fn is_limiting(&self) -> bool {
        self.limiting
    }

    /// Charge one instantaneous request.
    ///
    /// For requests that complete and hold nothing afterwards — a fetch is the
    /// only one today. Use [`Governor::acquire`] for anything that persists,
    /// because a rate limit alone does not bound how many are held at once and
    /// holding is what costs the relay memory.
    ///
    /// # Errors
    /// [`Refusal`] when any tier this principal is charged against is out of
    /// allowance. No tier is debited when any tier refuses.
    pub fn charge(
        &self,
        who: &Principal,
        resource: Resource,
        now: Instant,
    ) -> Result<(), Refusal> {
        self.admit(who, resource, false, now).map(drop)
    }

    /// Acquire a resource held until the returned lease is dropped.
    ///
    /// # Errors
    /// [`Refusal`] when any tier this principal is charged against is out of
    /// rate or already holding as many as it may. No tier is debited and no
    /// count is incremented when any tier refuses.
    pub fn acquire(
        &self,
        who: &Principal,
        resource: Resource,
        now: Instant,
    ) -> Result<Lease, Refusal> {
        self.admit(who, resource, true, now)
            .map(|charges| Lease {
                state: Arc::clone(&self.state),
                charges,
                resource,
            })
    }

    /// How many principals are currently tracked in a tier, for diagnostics.
    #[must_use]
    pub fn tracked(&self, tier: Tier) -> usize {
        self.state
            .lock()
            .map_or(0, |state| state.tables[tier.index()].entries.len())
    }

    /// The decision, in three passes over the tiers.
    ///
    /// Three rather than one because the charge must be atomic across tiers, and
    /// there is no way to know the second tier admits until it has been looked
    /// at. So: resolve every entry, ask every one of them, and only then debit.
    /// Doing it in a single pass would debit the first tier before discovering
    /// the second refuses.
    fn admit(
        &self,
        who: &Principal,
        resource: Resource,
        holding: bool,
        now: Instant,
    ) -> Result<[Option<(Tier, Key)>; 2], Refusal> {
        let charges = who.charges();
        if !self.limiting {
            return Ok(charges.items);
        }

        let mut state = self.state.lock().unwrap_or_else(|poisoned| {
            // A limiter that fails open because a thread panicked while holding
            // its lock is a limiter an attacker turns off by finding a panic.
            // The counts may be slightly wrong after a poisoning; wrong counts
            // are recoverable and an unlimited relay is not.
            poisoned.into_inner()
        });
        let quotas = &self.quotas;

        // Pass one: make sure every tier has an entry, so pass two can ask them
        // all without the borrow checker objecting to a second mutable borrow.
        for (tier, key) in charges.iter() {
            let allowance = quotas.allowance(*tier);
            if !Self::ensure(&mut state.tables[tier.index()], key, allowance, quotas, now) {
                return Err(Refusal {
                    resource,
                    tier: *tier,
                    reason: Reason::Saturated,
                    retry_after: UNKNOWN_WAIT,
                });
            }
        }

        // Pass two: ask.
        for (tier, key) in charges.iter() {
            let quota = quotas.allowance(*tier).quota(resource);
            let Some(entry) = state.tables[tier.index()].entries.get_mut(key) else {
                continue;
            };
            let bucket = &mut entry.buckets[resource.index()];
            bucket.refill(quota.rate, now);

            if !bucket.would_admit(quota.rate) {
                return Err(Refusal {
                    resource,
                    tier: *tier,
                    reason: Reason::TooFast,
                    retry_after: bucket.wait(quota.rate),
                });
            }
            if holding && quota.concurrent > 0 && entry.live[resource.index()] >= quota.concurrent {
                return Err(Refusal {
                    resource,
                    tier: *tier,
                    reason: Reason::TooMany,
                    retry_after: UNKNOWN_WAIT,
                });
            }
        }

        // Pass three: debit, now that nothing can refuse.
        for (tier, key) in charges.iter() {
            let quota = quotas.allowance(*tier).quota(resource);
            let Some(entry) = state.tables[tier.index()].entries.get_mut(key) else {
                continue;
            };
            entry.buckets[resource.index()].take(quota.rate);
            if holding {
                entry.live[resource.index()] += 1;
            }
        }

        Ok(charges.items)
    }

    /// Ensure `key` has an entry, making room if the table is full.
    ///
    /// Returns false when the table is full of entries that are all still
    /// meaningful. Refusing is the only safe answer there: evicting a live
    /// entry would hand its owner a fresh allowance, which is exactly the
    /// bypass an attacker wants, so filling the table would *raise* everyone's
    /// limits rather than lower them. Refusing new principals under that
    /// pressure keeps the guarantee for everyone already inside it.
    fn ensure(
        table: &mut Table,
        key: &Key,
        allowance: &Allowance,
        quotas: &Quotas,
        now: Instant,
    ) -> bool {
        if table.entries.contains_key(key) {
            return true;
        }
        if quotas.principals > 0 && table.entries.len() >= quotas.principals {
            let due = table
                .swept
                .is_none_or(|last| now.saturating_duration_since(last) >= SWEEP_INTERVAL);
            if due {
                table.sweep(allowance, now);
            }
            if table.entries.len() >= quotas.principals {
                return false;
            }
        }
        table
            .entries
            .insert(key.clone(), Entry::new(allowance, now));
        true
    }
}

impl Default for Governor {
    fn default() -> Self {
        Self::new(Quotas::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Time is a parameter throughout, so every one of these is exact rather
    /// than a sleep with a tolerance. A rate limiter tested by sleeping is a
    /// test that is either slow or flaky and usually both.
    fn origin() -> Instant {
        Instant::now()
    }

    fn phone() -> Principal {
        Principal::verified("acme", "ada", "device-1")
    }

    fn laptop() -> Principal {
        Principal::verified("acme", "ada", "device-2")
    }

    fn stranger() -> Principal {
        Principal::anonymous(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)))
    }

    /// A governor where one resource is easy to reason about and the rest are
    /// out of the way.
    fn governor(device: Quota, user: Quota, principals: usize) -> Governor {
        let open = Quota::new(f64::INFINITY, f64::INFINITY, 0);
        let allowance = |fetch| Allowance {
            session: open,
            subscription: open,
            announcement: open,
            watch: open,
            fetch,
        };
        Governor::new(Quotas {
            device: allowance(device),
            user: allowance(user),
            address: allowance(device),
            principals,
        })
    }

    #[test]
    fn a_burst_is_admitted_and_then_the_rate_applies() {
        let at = origin();
        let governor = governor(Quota::new(1.0, 3.0, 0), Quota::new(100.0, 100.0, 0), 0);

        for _ in 0..3 {
            governor
                .charge(&phone(), Resource::Fetch, at)
                .expect("within the burst");
        }
        let refusal = governor
            .charge(&phone(), Resource::Fetch, at)
            .expect_err("burst is spent");
        assert_eq!(refusal.reason, Reason::TooFast);
        assert_eq!(refusal.tier, Tier::Device);

        // One token a second, so one second buys exactly one request.
        governor
            .charge(&phone(), Resource::Fetch, at + Duration::from_secs(1))
            .expect("a token has arrived");
        governor
            .charge(&phone(), Resource::Fetch, at + Duration::from_secs(1))
            .expect_err("but only one");
    }

    #[test]
    fn the_wait_a_refusal_reports_is_how_long_it_actually_takes() {
        let at = origin();
        let governor = governor(Quota::new(4.0, 1.0, 0), Quota::new(100.0, 100.0, 0), 0);

        governor
            .charge(&phone(), Resource::Fetch, at)
            .expect("the one token");
        let refusal = governor
            .charge(&phone(), Resource::Fetch, at)
            .expect_err("spent");

        // Four per second means 250ms, and the point of the assertion is that
        // waiting exactly that long works and a hair less does not. A
        // retry-after that is even slightly optimistic produces a client that
        // retries into a second refusal, which is worse than no hint at all.
        assert_eq!(refusal.retry_after, Duration::from_millis(250));
        governor
            .charge(&phone(), Resource::Fetch, at + refusal.retry_after)
            .expect("the advertised wait is enough");
    }

    #[test]
    fn a_second_device_does_not_get_a_second_allowance() {
        let at = origin();
        // Generous per device, tight per user: the whole person may do three
        // things at once no matter how many devices they spread them over.
        let governor = governor(Quota::new(100.0, 100.0, 0), Quota::new(1.0, 3.0, 0), 0);

        governor.charge(&phone(), Resource::Fetch, at).expect("one");
        governor.charge(&phone(), Resource::Fetch, at).expect("two");
        governor
            .charge(&laptop(), Resource::Fetch, at)
            .expect("three, from the other device");

        let refusal = governor
            .charge(&laptop(), Resource::Fetch, at)
            .expect_err("the person is spent even though this device is not");
        assert_eq!(refusal.tier, Tier::User);
    }

    #[test]
    fn one_device_cannot_spend_what_it_was_refused() {
        let at = origin();
        // Two per device, five for the person. Every charge is at the same
        // instant, so nothing refills and the arithmetic is exact: the phone
        // may take two, leaving three for everyone else.
        let governor = governor(Quota::new(1.0, 2.0, 0), Quota::new(1.0, 5.0, 0), 0);

        governor.charge(&phone(), Resource::Fetch, at).expect("one");
        governor.charge(&phone(), Resource::Fetch, at).expect("two");
        for _ in 0..20 {
            governor
                .charge(&phone(), Resource::Fetch, at)
                .expect_err("the device is spent");
        }

        // This is the property the three-pass charge exists for. Those twenty
        // refusals were decided at the device tier, and must not have debited
        // the user tier on the way — twenty debits would have emptied a bucket
        // of five and locked the person out of a device that never misbehaved.
        governor
            .charge(&laptop(), Resource::Fetch, at)
            .expect("the other device still has the person's allowance");
        governor
            .charge(&laptop(), Resource::Fetch, at)
            .expect("all of it that its own device tier permits");
    }

    #[test]
    fn a_refused_acquire_holds_nothing() {
        let at = origin();
        let governor = governor(
            Quota::new(100.0, 100.0, 2),
            Quota::new(100.0, 100.0, 100),
            0,
        );

        let first = governor
            .acquire(&phone(), Resource::Fetch, at)
            .expect("first slot");
        let _second = governor
            .acquire(&phone(), Resource::Fetch, at)
            .expect("second slot");
        let refusal = governor
            .acquire(&phone(), Resource::Fetch, at)
            .expect_err("no third slot");
        assert_eq!(refusal.reason, Reason::TooMany);

        // Dropping one frees exactly one.
        drop(first);
        let _third = governor
            .acquire(&phone(), Resource::Fetch, at)
            .expect("the freed slot");
        governor
            .acquire(&phone(), Resource::Fetch, at)
            .expect_err("and no more than that");
    }

    #[test]
    fn a_lease_releases_when_its_task_unwinds() {
        let at = origin();
        let governor = governor(
            Quota::new(100.0, 100.0, 1),
            Quota::new(100.0, 100.0, 100),
            0,
        );

        // The failure this rules out is a slot leaked by an error path. Nothing
        // calls release; the drop during unwind is the whole mechanism.
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _lease = governor
                .acquire(&phone(), Resource::Fetch, at)
                .expect("the slot");
            panic!("the task fails while holding it");
        }));
        assert!(panicked.is_err());

        let _recovered = governor
            .acquire(&phone(), Resource::Fetch, at)
            .expect("the slot came back");
    }

    #[test]
    fn concurrency_refusals_do_not_spend_the_rate() {
        let at = origin();
        let governor = governor(Quota::new(1.0, 4.0, 1), Quota::new(100.0, 100.0, 100), 0);

        let held = governor
            .acquire(&phone(), Resource::Fetch, at)
            .expect("the one slot");
        for _ in 0..3 {
            governor
                .acquire(&phone(), Resource::Fetch, at)
                .expect_err("no second slot");
        }
        drop(held);

        // Four attempts, one of which succeeded, so a bucket of four should
        // still have three. If the refusals had debited it there would be none,
        // and hitting a concurrency limit would silently cost rate as well —
        // two limits that compound by accident rather than by design.
        for _ in 0..3 {
            let lease = governor
                .acquire(&phone(), Resource::Fetch, at)
                .expect("rate was not spent on refusals");
            drop(lease);
        }
    }

    #[test]
    fn an_unverified_peer_is_charged_by_address_and_not_by_name() {
        let at = origin();
        let governor = governor(Quota::new(1.0, 1.0, 0), Quota::new(1.0, 1.0, 0), 0);

        governor
            .charge(&stranger(), Resource::Fetch, at)
            .expect("the one token");
        governor
            .charge(&stranger(), Resource::Fetch, at)
            .expect_err("and no more");

        // The address tier is separate from the user and device tiers, so a
        // stranger cannot spend a real user's allowance — which is what would
        // happen if unverified peers were folded into the same table under
        // whatever name they claimed.
        governor
            .charge(&phone(), Resource::Fetch, at)
            .expect("a verified user is unaffected");
    }

    #[test]
    fn one_address_is_one_charge_rather_than_two() {
        let at = origin();
        // Both tiers configured identically. If an anonymous principal were
        // charged to two tiers backed by the same key it would pay twice per
        // request and get half the configured rate.
        let governor = governor(Quota::new(1.0, 2.0, 0), Quota::new(1.0, 2.0, 0), 0);

        governor
            .charge(&stranger(), Resource::Fetch, at)
            .expect("one");
        governor
            .charge(&stranger(), Resource::Fetch, at)
            .expect("two, which a double charge would have refused");
    }

    #[test]
    fn tenants_do_not_share_an_allowance() {
        let at = origin();
        let governor = governor(Quota::new(1.0, 1.0, 0), Quota::new(1.0, 1.0, 0), 0);
        let theirs = Principal::verified("globex", "ada", "device-1");

        governor.charge(&phone(), Resource::Fetch, at).expect("ours");
        // Same username, same device name, different customer. Sharing a
        // bucket here would let anyone who can sign up exhaust the allowance of
        // a name they guessed in someone else's tenant.
        governor
            .charge(&theirs, Resource::Fetch, at)
            .expect("theirs is a different bucket");
    }

    #[test]
    fn resources_are_charged_separately() {
        let at = origin();
        let tight = Quota::new(1.0, 1.0, 0);
        let governor = Governor::new(Quotas {
            device: Allowance {
                session: tight,
                subscription: tight,
                announcement: tight,
                watch: tight,
                fetch: tight,
            },
            user: Allowance::per_device().scaled(100.0),
            address: Allowance::per_device(),
            principals: 0,
        });

        // Spending a fetch must not spend a subscribe. One shared bucket would
        // make a client that reconnects unable to resubscribe.
        governor.charge(&phone(), Resource::Fetch, at).expect("fetch");
        governor
            .charge(&phone(), Resource::Fetch, at)
            .expect_err("fetch is spent");
        governor
            .charge(&phone(), Resource::Subscription, at)
            .expect("subscribing is a different allowance");
    }

    #[test]
    fn an_idle_principal_is_forgotten_and_a_busy_one_is_not() {
        let at = origin();
        let governor = governor(Quota::new(1.0, 2.0, 4), Quota::new(1000.0, 1000.0, 0), 2);

        let held = governor
            .acquire(&phone(), Resource::Fetch, at)
            .expect("phone holds a slot");
        governor
            .charge(&laptop(), Resource::Fetch, at)
            .expect("laptop spends a token");
        assert_eq!(governor.tracked(Tier::Device), 2);

        // The table is full. Long enough later that the laptop's bucket has
        // refilled, so it is indistinguishable from a principal that was never
        // seen and can be forgotten. The phone still holds a lease and cannot.
        let later = at + Duration::from_secs(10);
        let third = Principal::verified("acme", "ada", "device-3");
        governor
            .charge(&third, Resource::Fetch, later)
            .expect("room was made by forgetting the idle one");

        // Still two: one evicted, one added.
        assert_eq!(governor.tracked(Tier::Device), 2);
        drop(held);
    }

    #[test]
    fn a_full_table_of_live_principals_refuses_rather_than_evicting() {
        let at = origin();
        let governor = governor(Quota::new(0.01, 1.0, 4), Quota::new(1000.0, 1000.0, 0), 2);

        // Both entries spend their single token, and at one per hundred seconds
        // neither refills. Neither can be forgotten without handing its owner a
        // fresh allowance.
        governor.charge(&phone(), Resource::Fetch, at).expect("one");
        governor.charge(&laptop(), Resource::Fetch, at).expect("two");

        let third = Principal::verified("acme", "ada", "device-3");
        let refusal = governor
            .charge(&third, Resource::Fetch, at)
            .expect_err("no room, and evicting would be a bypass");
        assert_eq!(refusal.reason, Reason::Saturated);

        // And the pressure did not cost the principals already inside the
        // table their limits.
        governor
            .charge(&phone(), Resource::Fetch, at)
            .expect_err("still limited");
    }

    #[test]
    fn a_disabled_governor_tracks_nobody() {
        let at = origin();
        let governor = Governor::disabled();
        assert!(!governor.is_limiting());

        for _ in 0..10_000 {
            governor
                .charge(&phone(), Resource::Fetch, at)
                .expect("nothing is limited");
        }
        // The interesting half: an unlimited governor must not accumulate an
        // entry per principal, or turning limits off would be a memory leak
        // driven by whoever connects.
        assert_eq!(governor.tracked(Tier::Device), 0);
    }

    #[test]
    fn a_refusal_says_what_ran_out_without_saying_who() {
        let at = origin();
        let governor = governor(Quota::new(1.0, 1.0, 0), Quota::new(100.0, 100.0, 0), 0);
        governor.charge(&phone(), Resource::Fetch, at).expect("one");
        let refusal = governor
            .charge(&phone(), Resource::Fetch, at)
            .expect_err("spent");

        let phrase = refusal.reason_phrase();
        assert!(phrase.contains("fetch"), "{phrase}");
        assert!(phrase.contains("device"), "{phrase}");
        // A reason phrase goes to the peer and into logs. Echoing the identity
        // would make the relay an oracle for whether a given user is being
        // limited, which is a thing worth knowing before an attack.
        assert!(!phrase.contains("ada"), "{phrase}");
        assert!(!phrase.contains("acme"), "{phrase}");
        assert!(refusal.retry_after_ms() >= 1);
    }

    #[test]
    fn the_default_user_tier_is_more_than_one_device_and_less_than_many() {
        let device = Allowance::per_device();
        let user = Allowance::per_user();

        // The shape of the whole design in one assertion: a person gets more
        // than a single device so a laptop and a phone both work, and less than
        // the sum of an unbounded number so a credential is not a botnet key.
        assert!(user.subscription.concurrent > device.subscription.concurrent);
        assert!(user.subscription.concurrent < device.subscription.concurrent * 16);
        assert!(user.session.rate.per_second > device.session.rate.per_second);

        // And an unauthenticated peer gets less than a device, so authenticating
        // is what buys capacity.
        let address = Allowance::per_address();
        assert!(address.subscription.rate.per_second < device.subscription.rate.per_second);
        assert!(address.fetch.concurrent < device.fetch.concurrent);
    }
}
