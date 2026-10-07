//! What sessions know about each other.
//!
//! A relay is only interesting because sessions are not independent: a
//! subscriber's SUBSCRIBE has to reach whichever *other* session announced the
//! namespace, and a namespace watcher has to hear about an announcement that
//! arrives after it started watching. This module is the whole of that shared
//! state, and everything else is per-session.
//!
//! # Why sessions talk by message and not by lock
//!
//! The obvious shape is a shared map from namespace to publisher, where a
//! subscriber task reaches in and calls the publisher. It does not survive
//! contact with the control stream: sending SUBSCRIBE upstream means opening a
//! stream, writing, and *waiting* for the answer, so the caller would hold a
//! lock across an await on the network. One slow publisher would then stall
//! every unrelated subscription in the process.
//!
//! So a session is reachable only by [`Command`] on a channel, and the lock is
//! held for exactly as long as it takes to clone a sender. The awaiting happens
//! in the publisher's own task, where a stall costs that session and no other.
//!
//! # Why announcements are a list
//!
//! Two sessions can hold the same namespace at once, and the case is not
//! exotic: a publisher whose connection drops reconnects and re-announces
//! before the relay has noticed the old session is gone. Treating that as a
//! conflict would refuse the live session in favour of a dead one. The newest
//! announcement wins instead, which is right for reconnection and merely
//! arbitrary for the genuine-conflict case that authorisation should be
//! rejecting earlier anyway.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use moqom_proto::control::{DoneReason, RequestErrorCode};
use moqom_proto::model::{FullTrackName, TrackAlias, TrackNamespace};
use tokio::sync::{Notify, mpsc, oneshot};

use crate::cache::Cache;
use crate::clock;
use crate::hops::Hops;
use crate::identity::Authenticator;
use crate::metrics::Metrics;
use crate::policy::{Policy, Silence};
use crate::possession::Possession;
use crate::quota::Governor;
use crate::roster::Roster;
use crate::scope::Ceiling;
use crate::ticket::TicketKeys;
use crate::usage::{Meter, Usage};

/// Identifies a session within one relay process.
///
/// Not a protocol value and never sent on the wire — it exists so an
/// announcement can be attributed to the session that made it and withdrawn
/// when that session ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(u64);

impl SessionId {
    /// The bare number, for output that has its own field for it.
    ///
    /// Everything human-facing should use [`Display`](std::fmt::Display), which
    /// prefixes it — a bare integer in a log line is indistinguishable from any
    /// other integer in that log line.
    #[must_use]
    pub const fn number(self) -> u64 {
        self.0
    }

    #[cfg(test)]
    pub(crate) const fn for_tests(number: u64) -> Self {
        Self(number)
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "session-{}", self.0)
    }
}

/// Why an upstream subscription could not be established.
///
/// Carries a MOQT error code because it is going straight back out as a
/// `REQUEST_ERROR` on the downstream request stream. Inventing a code here
/// would tell the subscriber something the specification does not define.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("upstream refused: {code:?}: {reason}")]
pub struct UpstreamError {
    /// The code to report downstream.
    pub code: RequestErrorCode,
    /// A human-readable explanation, forwarded as the reason phrase.
    pub reason: String,
}

impl UpstreamError {
    /// An error with a code and reason.
    pub fn new(code: RequestErrorCode, reason: impl Into<String>) -> Self {
        Self {
            code,
            reason: reason.into(),
        }
    }

    /// The namespace exists but the publisher session has gone.
    #[must_use]
    pub fn unavailable() -> Self {
        Self::new(RequestErrorCode::DOES_NOT_EXIST, "publisher session ended")
    }
}

/// Where forwarded objects should go.
///
/// The alias is the *downstream* one. A track alias is assigned per session, so
/// the number a publisher writes in its subgroup headers means something else —
/// or nothing at all — to a subscriber. Rewriting it is the one thing a relay
/// must do to a subgroup header, and this is the value it rewrites to.
#[derive(Clone)]
pub struct Route {
    /// The subscriber's session, used to open a stream per forwarded subgroup.
    pub session: moqom_transport::Session,
    /// Which session that is.
    ///
    /// Aliases are numbered per session and start from the same place, so two
    /// subscribers routinely hold the same one. Carried so that a subscriber
    /// letting go of a track names its own route and not a namesake's.
    pub subscriber: SessionId,
    /// The alias this subscriber knows the track by.
    pub alias: TrackAlias,
    /// Raised when the track this route carries has ended.
    ///
    /// The two halves of a subscription live on opposite sides of the relay:
    /// the request stream belongs to the subscriber's session and the pull
    /// belongs to the publisher's, and neither holds the other. This is how the
    /// news crosses. Without it a publisher going away is silence — the objects
    /// simply stop, and every viewer waits indefinitely for a frame that is
    /// never coming, which is the same thing they would see on a stalled
    /// network and calls for the opposite response.
    pub done: Arc<Notify>,
    /// How many data streams have been opened to this subscriber for this
    /// track, for `PUBLISH_DONE` to report.
    ///
    /// The draft has the subscriber use it to know when everything sent has
    /// arrived; streams already in flight when the subscription ends are the
    /// reason a count is needed at all rather than an assumption that the last
    /// one seen was the last one sent.
    pub streams: Arc<AtomicU64>,
    /// Where the bytes written to this subscriber are billed, if anywhere.
    ///
    /// Carried on the route so the writer bumps an atomic it already holds,
    /// rather than looking the subscriber up per chunk on the media path.
    pub meter: Option<Arc<Meter>>,
    /// Whether the subscriber wants objects, from the FORWARD parameter of its
    /// latest `REQUEST_UPDATE`.
    ///
    /// Read once per subgroup, because subgroups are what is forwarded: a pause
    /// lets the subgroup in flight finish and a resume starts at the next one.
    pub forward: Arc<AtomicBool>,
    /// The draft the subscriber's session speaks, which is what the subgroup
    /// streams to it are written in. When it differs from the publisher's,
    /// the fan-out re-encodes instead of copying.
    pub draft: moqom_proto::Draft,
    /// The groups the subscriber's Location filter admits, if it narrowed
    /// them. Read once per subgroup, like [`Self::forward`].
    pub window: Arc<Mutex<GroupWindow>>,
    /// Where the publisher's `PUBLISH_STATE_NOTIFY` parameters go, for a
    /// subscriber whose draft has that message.
    pub notices: Option<mpsc::UnboundedSender<moqom_proto::control::Parameters>>,
}

/// The groups a subscription's Location filter admits.
///
/// Subgroups are what the fan-out forwards, so this is applied a group at a
/// time: a filter ending mid-group delivers that whole group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupWindow {
    /// The first group admitted.
    pub first: u64,
    /// The last group admitted, or `None` for an open end.
    pub last: Option<u64>,
}

impl GroupWindow {
    /// Every group.
    pub const ALL: Self = Self {
        first: 0,
        last: None,
    };

    /// Whether objects of `group` are delivered.
    #[must_use]
    pub fn admits(self, group: u64) -> bool {
        group >= self.first && self.last.is_none_or(|last| group <= last)
    }

    /// Whether every group from `group` on is past the end.
    #[must_use]
    pub fn ended_by(self, group: u64) -> bool {
        self.last.is_some_and(|last| group > last)
    }
}

impl Route {
    /// A route to `alias` on `session`, with nothing yet delivered.
    #[must_use]
    pub fn new(
        session: moqom_transport::Session,
        subscriber: SessionId,
        alias: TrackAlias,
    ) -> Self {
        Self {
            draft: crate::session::draft_of(&session),
            session,
            subscriber,
            alias,
            done: Arc::new(Notify::new()),
            streams: Arc::new(AtomicU64::new(0)),
            meter: None,
            forward: Arc::new(AtomicBool::new(true)),
            window: Arc::new(Mutex::new(GroupWindow::ALL)),
            notices: None,
        }
    }

    /// The same route, passing the publisher's state notifications to
    /// `notices`.
    #[must_use]
    pub fn notifying(
        self,
        notices: mpsc::UnboundedSender<moqom_proto::control::Parameters>,
    ) -> Self {
        Self {
            notices: Some(notices),
            ..self
        }
    }

    /// The groups currently admitted.
    #[must_use]
    pub fn window(&self) -> GroupWindow {
        *self
            .window
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The same route, billing what it carries to `meter`.
    #[must_use]
    pub fn metered(self, meter: Option<Arc<Meter>>) -> Self {
        Self { meter, ..self }
    }
}

/// `moqom_transport::Session` has no useful `Debug`, and a connection is not
/// something a log line wants inlined regardless.
impl std::fmt::Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Route")
            .field("subscriber", &self.subscriber)
            .field("alias", &self.alias)
            .finish_non_exhaustive()
    }
}

/// The records an upstream FETCH produced.
#[derive(Debug, Default)]
pub struct Upstreamed {
    /// In stream order, as far as they arrived.
    pub records: Vec<moqom_proto::data::FetchRecord>,
    /// Whether the stream finished: `false` if the deadline cut it short or
    /// the peer refused or reset it.
    pub complete: bool,
}

/// Something one session asks another to do.
#[derive(Debug)]
pub enum Command {
    /// Subscribe upstream to `track` and forward its objects to `route`.
    ///
    /// The receiving session opens its own request stream, sends SUBSCRIBE, and
    /// waits for the answer before completing `ready` — so a caller that awaits
    /// `ready` knows objects will flow, and can answer its own downstream
    /// SUBSCRIBE without guessing.
    Subscribe {
        /// The track to pull.
        track: FullTrackName,
        /// Where to send what comes back.
        ///
        /// Boxed because a route carries a transport handle, which is most of
        /// the size of this enum; every other command would otherwise be
        /// padded out to match it.
        route: Box<Route>,
        /// How many further relays may be asked, if this command is going to a
        /// parent relay rather than to a local publisher.
        ///
        /// Carried on the command because the two ends of the decision are in
        /// different sessions: the subscriber's session reads the budget off the
        /// request that arrived, and the parent's session is what writes the
        /// decremented one onto the request that leaves. Ignored by a session
        /// serving a local publisher, which has nowhere to forward it.
        hops: Hops,
        /// Completed once upstream has answered.
        ready: oneshot::Sender<Result<Pulling, UpstreamError>>,
    },
    /// FETCH a range of `track` from this session's peer, on behalf of a
    /// draft-22 request this relay cannot answer from its cache alone
    /// (draft-22 §3.2.3).
    Fetch {
        /// The track.
        track: FullTrackName,
        /// The first location wanted.
        start: moqom_proto::model::Location,
        /// The last location wanted, inclusive, or `None` for as far as the
        /// peer has.
        end: Option<moqom_proto::model::Location>,
        /// When the requester stops waiting: its Fill Timeout.
        deadline: tokio::time::Instant,
        /// What arrived by then.
        reply: oneshot::Sender<Upstreamed>,
    },
    /// A subscriber has gone. Stop routing this track to it, and stop pulling
    /// the track altogether if it was the last one watching.
    ///
    /// Sent when the subscriber's request stream ends, which is how MOQT says
    /// unsubscribe — there is no message for it, so the transport event is the
    /// whole signal and this is what carries it across to the publisher's
    /// session.
    Release {
        /// The track being let go of.
        track: FullTrackName,
        /// Which upstream subscription it was being served from.
        upstream: TrackAlias,
        /// The departing subscriber, which with its alias names one route.
        subscriber: SessionId,
        /// The alias it knew the track by.
        downstream: TrackAlias,
    },
    /// A moderator has changed what this session may publish.
    ///
    /// Sent to the muted participant's own session, from the control-plane
    /// link, which has no connection of its own. The command channel is the
    /// right vehicle here in a way it is not for ejection: this asks a session
    /// to *do* something — stop feeding tracks upstream, and tell its peer why
    /// — rather than to stop existing, and it is served by the same loop that
    /// serves every other request the relay originates on that connection.
    Restrict {
        /// Everything the room now forbids, not the change to it. A directive
        /// that arrives twice must land twice identically, and a delta cannot
        /// promise that.
        silence: Silence,
    },
    /// A moderator has narrowed what this session may hold.
    ///
    /// Through the command channel for the reason a mute is: narrowing means
    /// withdrawing the session's own announcements and ending its own
    /// subscriptions, which only its own tasks can do.
    Regrant {
        /// The most the session may now hold. Absolute, like a mute, so that a
        /// repeated directive lands identically.
        ceiling: Ceiling,
    },
}

/// What a subscriber was attached to.
///
/// Reported back to the subscriber's session rather than kept where it is
/// decided, because both fields are things only that side can use: it accounts
/// for how the SUBSCRIBE turned out, and it names the subscription so it can
/// let go of it later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pulling {
    /// The alias the publisher's session knows this track by.
    ///
    /// Meaningless to the subscriber, whose own alias is a different number,
    /// and carried anyway: it is what [`Command::Release`] names, and asking
    /// the publisher's session to work it out again would be asking it to
    /// re-derive something it has already decided.
    pub upstream: TrackAlias,
    /// Whether this joined a subscription that was already running.
    ///
    /// Worth counting apart from the ones that opened a subscription, because
    /// the ratio between them is the relay's whole economic argument: the
    /// second viewer of a track should cost the publisher nothing.
    pub shared: bool,
}

/// A namespace appearing or going away.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceEvent {
    /// A namespace is now available.
    Available(TrackNamespace),
    /// A namespace that was announced has been withdrawn.
    ///
    /// Carries why, because the relay is the only party that can distinguish a
    /// publisher who withdrew from one whose session died, and subscribers
    /// cannot behave correctly without knowing which. See [`DoneReason`].
    Gone(TrackNamespace, DoneReason),
}

impl NamespaceEvent {
    /// The namespace this event is about.
    #[must_use]
    pub const fn namespace(&self) -> &TrackNamespace {
        match self {
            Self::Available(namespace) | Self::Gone(namespace, _) => namespace,
        }
    }
}

/// One session's announcement of one namespace.
#[derive(Debug, Clone)]
struct Announcement {
    owner: SessionId,
    commands: mpsc::Sender<Command>,
}

/// A live `SUBSCRIBE_NAMESPACE`.
#[derive(Debug)]
struct Watcher {
    owner: SessionId,
    prefix: TrackNamespace,
    events: mpsc::Sender<NamespaceEvent>,
}

#[derive(Debug, Default)]
struct State {
    /// Newest announcement last. See the module docs on why this is a list.
    namespaces: HashMap<TrackNamespace, Vec<Announcement>>,
    watchers: Vec<Watcher>,
    /// The session to a parent relay, when this relay has one.
    ///
    /// Kept beside the announcements rather than among them because it is not an
    /// announcement: nothing has said the parent holds any particular track. It is
    /// somewhere to ask, tried only when nothing here holds what was asked for.
    upstream: Option<mpsc::Sender<Command>>,
}

/// The state shared between every session on one relay.
///
/// Cheap to clone; all clones see the same state.
#[derive(Debug, Clone)]
pub struct Fabric {
    state: Arc<Mutex<State>>,
    next_session: Arc<AtomicU64>,
    /// Retained history, shared for the same reason announcements are: a fetch
    /// arrives on a different session from the one that published the objects,
    /// and the track name is the only thing the two have in common.
    cache: Cache,
    /// What the process counts about itself.
    ///
    /// Here rather than passed to [`crate::Session::serve`] because it is shared
    /// per-relay state, which is what this type is for — and because threading a
    /// second argument through every constructor would make instrumenting a new
    /// code path a signature change rather than a one-line call.
    metrics: Metrics,
    /// What limits every session on this relay is held to.
    ///
    /// Shared for the reason the limits exist: a per-session limiter is one an
    /// attacker escapes by opening a second session, so there has to be exactly
    /// one of these and every session has to meet it.
    governor: Governor,
    /// How a session's credential is checked, which is what makes the governor
    /// able to charge anybody in particular.
    authenticator: Authenticator,
    /// Whether a session must show that its credential is its own, and which
    /// proofs have already been spent.
    ///
    /// Shared for the same reason the governor is, and it is the same kind of
    /// reason: a per-session record of spent proofs is one a replay escapes by
    /// opening a second connection, which is precisely what a replay is.
    possession: Arc<Possession>,
    /// The host clock, and the kernel's opinion of how good it is.
    ///
    /// Shared so that every record this relay writes carries the same error
    /// bound, and so the health behind it is read once per second rather than
    /// once per session.
    clock: Arc<clock::Host>,
    /// Who is connected, and how to hang up on them.
    ///
    /// Here for the same reason the announcements are: it is state about
    /// sessions that no session owns. A ban arrives on the control-plane link,
    /// which is a task with no connection of its own, and this is the only thing
    /// that can turn it into a closed socket.
    roster: Roster,
    /// What the control plane has said about the rooms this relay serves.
    policy: Policy,
    /// What each session is billed for, and whether billing admits new ones.
    usage: Usage,
    /// The keys direct tickets are signed with, and how often they are
    /// reissued. `None` issues none, so no participant here can hold a direct
    /// path a peer will keep.
    tickets: Option<Ticketing>,
    /// `MAX_HOP_LIMIT`: the budget a request with none starts with, and the
    /// most this relay honours on a request that names one.
    hop_limit: u64,
}

/// How a relay issues direct tickets. See [`crate::ticket`].
#[derive(Clone, Debug)]
pub struct Ticketing {
    /// What tickets are signed with and verified against.
    pub keys: Arc<TicketKeys>,
    /// How often a ticket is reissued while its subscription is open.
    pub renew: std::time::Duration,
}

/// Defaults that limit nothing and verify nothing.
///
/// Deliberately not the safe-looking choice, and the reason is the audience: a
/// bare `Fabric` is what tests and embedders build, and a library that silently
/// throttles is one whose failures look like bugs in the caller. The binary is
/// the deployment, so the binary is where limits are on by default — see
/// `src/bin/relay.rs`.
impl Default for Fabric {
    fn default() -> Self {
        Self {
            state: Arc::default(),
            next_session: Arc::default(),
            cache: Cache::default(),
            metrics: Metrics::default(),
            governor: Governor::disabled(),
            authenticator: Authenticator::disabled(),
            possession: Arc::new(Possession::bearer()),
            clock: Arc::default(),
            roster: Roster::new(),
            policy: Policy::new(),
            usage: Usage::disabled(),
            tickets: None,
            hop_limit: crate::hops::BUDGET,
        }
    }
}

impl Fabric {
    /// An empty fabric, retaining [`crate::Limits::default()`] of history and
    /// counting nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty fabric retaining history according to `cache`.
    #[must_use]
    pub fn with_cache(cache: Cache) -> Self {
        Self {
            cache,
            ..Self::default()
        }
    }

    /// An empty fabric that retains history and reports on itself.
    #[must_use]
    pub fn observed(cache: Cache, metrics: Metrics) -> Self {
        Self {
            cache,
            metrics,
            ..Self::default()
        }
    }

    /// The same fabric, holding every session to `governor`.
    #[must_use]
    pub fn governed(self, governor: Governor) -> Self {
        Self { governor, ..self }
    }

    /// The same fabric, checking credentials with `authenticator`.
    ///
    /// Without this every session is anonymous and charged by address, which is
    /// correct but coarse: per-user and per-device limits need a user and a
    /// device, and those only exist once a signature has been checked.
    #[must_use]
    pub fn authenticated(self, authenticator: Authenticator) -> Self {
        Self {
            authenticator,
            ..self
        }
    }

    /// The same fabric, holding sessions to proving their credential is theirs.
    ///
    /// Separate from [`Self::authenticated`] rather than folded into it because
    /// the two are configured separately and deployed separately: verifying
    /// tokens is on as soon as a relay has keys, and requiring proofs cannot be
    /// until the clients dialling it send them. See
    /// [`Enforcement`](crate::possession::Enforcement).
    #[must_use]
    pub fn proving(self, possession: Possession) -> Self {
        Self {
            possession: Arc::new(possession),
            ..self
        }
    }

    /// The same fabric, metering every session's usage into `usage`.
    #[must_use]
    pub fn metered(self, usage: Usage) -> Self {
        Self { usage, ..self }
    }

    /// What sessions are billed for.
    #[must_use]
    pub const fn usage(&self) -> &Usage {
        &self.usage
    }

    /// The same fabric, issuing direct tickets.
    #[must_use]
    pub fn ticketing(self, tickets: Ticketing) -> Self {
        Self {
            tickets: Some(tickets),
            ..self
        }
    }

    /// The same fabric, forwarding a request through at most `hop_limit` relays.
    #[must_use]
    pub fn with_hop_limit(self, hop_limit: u64) -> Self {
        Self { hop_limit, ..self }
    }

    /// `MAX_HOP_LIMIT` for this relay. See [`crate::hops`].
    #[must_use]
    pub const fn hop_limit(&self) -> u64 {
        self.hop_limit
    }

    /// How direct tickets are issued, if they are.
    #[must_use]
    pub const fn tickets(&self) -> Option<&Ticketing> {
        self.tickets.as_ref()
    }

    /// The shared object cache.
    #[must_use]
    pub const fn cache(&self) -> &Cache {
        &self.cache
    }

    /// What this process counts.
    #[must_use]
    pub const fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// The host clock, with the kernel's bound on how wrong it might be.
    #[must_use]
    pub fn clock(&self) -> &clock::Host {
        &self.clock
    }

    /// What limits sessions are held to.
    #[must_use]
    pub const fn governor(&self) -> &Governor {
        &self.governor
    }

    /// How credentials are checked.
    #[must_use]
    pub const fn authenticator(&self) -> &Authenticator {
        &self.authenticator
    }

    /// Whether a credential's holder must prove it is theirs.
    #[must_use]
    pub fn possession(&self) -> &Possession {
        &self.possession
    }

    /// Who is connected.
    #[must_use]
    pub const fn roster(&self) -> &Roster {
        &self.roster
    }

    /// What the control plane has said about the rooms this relay serves.
    #[must_use]
    pub const fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Allocate an identifier for a newly accepted session.
    #[must_use]
    pub fn next_session_id(&self) -> SessionId {
        SessionId(self.next_session.fetch_add(1, Ordering::Relaxed))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // A panic while holding this lock means a bug in this module, since
        // nothing user-supplied runs under it. Recovering the guard keeps that
        // bug from cascading into every other session as a poison error.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Record that `owner` is publishing `namespace`.
    ///
    /// Notifies every watcher whose prefix matches. A watcher that has stopped
    /// reading is dropped rather than waited for: back pressure from one
    /// subscriber must not delay an announcement to the others.
    pub fn announce(
        &self,
        owner: SessionId,
        namespace: TrackNamespace,
        commands: mpsc::Sender<Command>,
    ) {
        let mut state = self.lock();
        state
            .namespaces
            .entry(namespace.clone())
            .or_default()
            .push(Announcement { owner, commands });
        broadcast(&mut state.watchers, &NamespaceEvent::Available(namespace));
    }

    /// Withdraw `owner`'s announcement of `namespace`.
    ///
    /// Watchers hear about it only if this was the last announcement of that
    /// namespace: with another session still publishing it, the namespace has
    /// not gone away, and saying otherwise would have subscribers tear down
    /// tracks that still work.
    /// Withdraw an announcement, saying why.
    ///
    /// `reason` is [`DoneReason::Stopped`] when the publisher asked, by closing
    /// the stream that announced it, and [`DoneReason::Vanished`] when the
    /// session ended without asking. Only the second is worth waiting out, so
    /// telling them apart here is what lets a subscriber hold a place open for
    /// somebody who is reconnecting without also holding one for somebody who
    /// left.
    pub fn withdraw(&self, owner: SessionId, namespace: &TrackNamespace, reason: DoneReason) {
        let mut state = self.lock();
        let Some(holders) = state.namespaces.get_mut(namespace) else {
            return;
        };
        holders.retain(|a| a.owner != owner);
        if !holders.is_empty() {
            return;
        }
        state.namespaces.remove(namespace);
        broadcast(
            &mut state.watchers,
            &NamespaceEvent::Gone(namespace.clone(), reason),
        );
    }

    /// Withdraw everything belonging to `owner`, for use when its session ends.
    ///
    /// Everything here is [`DoneReason::Vanished`] by construction: a publisher
    /// that withdrew an announcement deliberately no longer holds it, so
    /// whatever is left at teardown is precisely what nobody said goodbye for.
    pub fn remove_session(&self, owner: SessionId) {
        let published: Vec<TrackNamespace> = {
            let state = self.lock();
            state
                .namespaces
                .iter()
                .filter(|(_, holders)| holders.iter().any(|a| a.owner == owner))
                .map(|(namespace, _)| namespace.clone())
                .collect()
        };
        for namespace in published {
            self.withdraw(owner, &namespace, DoneReason::Vanished);
        }
        self.lock().watchers.retain(|w| w.owner != owner);
    }

    /// Start watching for namespaces under `prefix`.
    ///
    /// Returns the namespaces that already match, which the caller must report
    /// before anything from `events`. Both happen under the lock so that an
    /// announcement racing this call lands in exactly one of the two — a
    /// namespace reported twice or not at all is the failure mode here.
    #[must_use]
    pub fn watch(
        &self,
        owner: SessionId,
        prefix: TrackNamespace,
    ) -> (Vec<TrackNamespace>, mpsc::Receiver<NamespaceEvent>) {
        let (events, receiver) = mpsc::channel(64);
        let mut state = self.lock();
        let existing = state
            .namespaces
            .keys()
            .filter(|namespace| namespace.starts_with(&prefix))
            .cloned()
            .collect();
        state.watchers.push(Watcher {
            owner,
            prefix,
            events,
        });
        (existing, receiver)
    }

    /// Stop `owner`'s watch on `prefix`.
    pub fn unwatch(&self, owner: SessionId, prefix: &TrackNamespace) {
        self.lock()
            .watchers
            .retain(|w| w.owner != owner || &w.prefix != prefix);
    }

    /// How to reach the session currently publishing `namespace`.
    ///
    /// `None` when nothing has announced it. The newest announcement wins.
    #[must_use]
    pub fn publisher(&self, namespace: &TrackNamespace) -> Option<mpsc::Sender<Command>> {
        self.lock()
            .namespaces
            .get(namespace)
            .and_then(|holders| holders.last())
            .map(|a| a.commands.clone())
    }

    /// Record the session to this relay's parent, replacing any earlier one.
    ///
    /// Replacing rather than collecting, because a relay has one parent: a second
    /// call is a reconnection, and the session it replaces is already gone.
    pub fn attach_upstream(&self, commands: mpsc::Sender<Command>) {
        self.lock().upstream = Some(commands);
    }

    /// Forget the parent, because the session to it has ended.
    ///
    /// A subscription that arrives before the reconnection is refused, which is
    /// the honest answer: this relay cannot serve the track and does not know
    /// whether anybody can.
    pub fn detach_upstream(&self) {
        self.lock().upstream = None;
    }

    /// How to reach this relay's parent, if it has one and the link is up.
    ///
    /// Asked only when no local session publishes what was requested. An edge with
    /// no parent is the single-relay case and behaves as it always did.
    #[must_use]
    pub fn upstream(&self) -> Option<mpsc::Sender<Command>> {
        self.lock().upstream.clone()
    }

    /// Every announced namespace, for diagnostics.
    #[must_use]
    pub fn namespaces(&self) -> Vec<TrackNamespace> {
        self.lock().namespaces.keys().cloned().collect()
    }

    /// Every announcement with the session holding it.
    ///
    /// One namespace can appear more than once, because a reconnecting publisher
    /// re-announces before the relay has reaped its previous session. Callers
    /// counting participants have to collapse those; callers listing what a
    /// session publishes want them separate.
    #[must_use]
    pub fn announcements(&self) -> Vec<(TrackNamespace, SessionId)> {
        self.lock()
            .namespaces
            .iter()
            .flat_map(|(namespace, holders)| {
                holders
                    .iter()
                    .map(move |holder| (namespace.clone(), holder.owner))
            })
            .collect()
    }
}

impl Watcher {
    fn prefix_matches(&self, namespace: &TrackNamespace) -> bool {
        namespace.starts_with(&self.prefix)
    }

    /// Deliver an event, reporting whether this watcher is still usable.
    fn notify(&self, event: NamespaceEvent) -> bool {
        !matches!(
            self.events.try_send(event),
            Err(mpsc::error::TrySendError::Closed(_))
        )
    }
}

/// Tell every matching watcher about `event`, dropping the ones that have gone.
///
/// `try_send` rather than `send` because this runs under the fabric lock, and
/// because a subscriber that has stopped reading must not be able to delay an
/// announcement to anybody else. The queue is deep enough that filling it means
/// a watcher is genuinely not reading; treating a full queue as still-usable is
/// deliberate, since the alternative is disconnecting a slow reader over a
/// momentary burst.
fn broadcast(watchers: &mut Vec<Watcher>, event: &NamespaceEvent) {
    watchers.retain(|w| !w.prefix_matches(event.namespace()) || w.notify(event.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn namespace(fields: &[&str]) -> TrackNamespace {
        TrackNamespace::from_parts(fields).expect("valid namespace")
    }

    fn commands() -> (mpsc::Sender<Command>, mpsc::Receiver<Command>) {
        mpsc::channel(4)
    }

    #[test]
    fn an_announcement_is_findable_and_withdrawable() {
        let fabric = Fabric::new();
        let publisher = fabric.next_session_id();
        let (tx, _rx) = commands();

        assert!(fabric.publisher(&namespace(&["room", "1"])).is_none());
        fabric.announce(publisher, namespace(&["room", "1"]), tx);
        assert!(fabric.publisher(&namespace(&["room", "1"])).is_some());

        fabric.withdraw(publisher, &namespace(&["room", "1"]), DoneReason::Stopped);
        assert!(fabric.publisher(&namespace(&["room", "1"])).is_none());
    }

    #[test]
    fn session_ids_are_distinct() {
        let fabric = Fabric::new();
        let first = fabric.next_session_id();
        let second = fabric.next_session_id();
        assert_ne!(first, second);
    }

    /// A watcher that starts after an announcement has to be told about it, or
    /// discovery only works for subscribers that happened to arrive first.
    #[tokio::test]
    async fn watching_reports_what_already_exists() {
        let fabric = Fabric::new();
        let publisher = fabric.next_session_id();
        let (tx, _rx) = commands();
        fabric.announce(publisher, namespace(&["room", "1"]), tx);

        let watcher = fabric.next_session_id();
        let (existing, _events) = fabric.watch(watcher, namespace(&["room"]));
        assert_eq!(existing, vec![namespace(&["room", "1"])]);
    }

    #[tokio::test]
    async fn watching_reports_later_changes() {
        let fabric = Fabric::new();
        let watcher = fabric.next_session_id();
        let (existing, mut events) = fabric.watch(watcher, namespace(&["room"]));
        assert!(existing.is_empty());

        let publisher = fabric.next_session_id();
        let (tx, _rx) = commands();
        fabric.announce(publisher, namespace(&["room", "7"]), tx);
        assert_eq!(
            events.recv().await,
            Some(NamespaceEvent::Available(namespace(&["room", "7"])))
        );

        fabric.withdraw(publisher, &namespace(&["room", "7"]), DoneReason::Stopped);
        assert_eq!(
            events.recv().await,
            Some(NamespaceEvent::Gone(
                namespace(&["room", "7"]),
                DoneReason::Stopped
            ))
        );
    }

    #[tokio::test]
    async fn a_watcher_hears_nothing_outside_its_prefix() {
        let fabric = Fabric::new();
        let watcher = fabric.next_session_id();
        let (_, mut events) = fabric.watch(watcher, namespace(&["room", "1"]));

        let publisher = fabric.next_session_id();
        let (tx, _rx) = commands();
        fabric.announce(publisher, namespace(&["room", "2"]), tx);

        assert_eq!(
            events.try_recv(),
            Err(mpsc::error::TryRecvError::Empty),
            "a sibling namespace is not under this prefix"
        );
    }

    /// An empty prefix matches everything, per draft-19 §10.17. Getting this
    /// wrong makes a wildcard watch silently deliver nothing.
    #[tokio::test]
    async fn the_empty_prefix_matches_everything() {
        let fabric = Fabric::new();
        let watcher = fabric.next_session_id();
        let (_, mut events) = fabric.watch(watcher, namespace(&[]));

        let publisher = fabric.next_session_id();
        let (tx, _rx) = commands();
        fabric.announce(publisher, namespace(&["anything", "at", "all"]), tx);

        assert_eq!(
            events.recv().await,
            Some(NamespaceEvent::Available(namespace(&[
                "anything", "at", "all"
            ])))
        );
    }

    /// A reconnecting publisher re-announces before the relay has reaped its
    /// previous session, so both exist briefly. Subscriptions have to go to the
    /// new one; sending them to the dead session is a stall with no error.
    #[tokio::test]
    async fn the_newest_announcement_wins() {
        let fabric = Fabric::new();
        let stale = fabric.next_session_id();
        let fresh = fabric.next_session_id();
        let (stale_tx, _stale_rx) = commands();
        let (fresh_tx, _fresh_rx) = commands();

        fabric.announce(stale, namespace(&["room", "1"]), stale_tx.clone());
        fabric.announce(fresh, namespace(&["room", "1"]), fresh_tx.clone());

        let reached = fabric
            .publisher(&namespace(&["room", "1"]))
            .expect("announced");
        assert!(reached.same_channel(&fresh_tx));
        assert!(!reached.same_channel(&stale_tx));
    }

    /// Withdrawing one of two holders leaves the namespace available. Reporting
    /// `Gone` here would have every subscriber tear down a working track.
    #[tokio::test]
    async fn a_namespace_survives_until_its_last_holder_leaves() {
        let fabric = Fabric::new();
        let first = fabric.next_session_id();
        let second = fabric.next_session_id();
        let (a, _ra) = commands();
        let (b, _rb) = commands();

        let watcher = fabric.next_session_id();
        let (_, mut events) = fabric.watch(watcher, namespace(&[]));

        fabric.announce(first, namespace(&["room", "1"]), a);
        fabric.announce(second, namespace(&["room", "1"]), b);
        // Two `Available` events: a second holder is a real change, and a
        // watcher that deduplicates is free to ignore it.
        assert!(events.recv().await.is_some());
        assert!(events.recv().await.is_some());

        fabric.withdraw(first, &namespace(&["room", "1"]), DoneReason::Stopped);
        assert_eq!(events.try_recv(), Err(mpsc::error::TryRecvError::Empty));
        assert!(fabric.publisher(&namespace(&["room", "1"])).is_some());

        fabric.withdraw(second, &namespace(&["room", "1"]), DoneReason::Stopped);
        assert_eq!(
            events.recv().await,
            Some(NamespaceEvent::Gone(
                namespace(&["room", "1"]),
                DoneReason::Stopped
            ))
        );
    }

    #[tokio::test]
    async fn ending_a_session_withdraws_its_announcements_and_watches() {
        let fabric = Fabric::new();
        let publisher = fabric.next_session_id();
        let (tx, _rx) = commands();
        fabric.announce(publisher, namespace(&["room", "1"]), tx);
        fabric.announce(publisher, namespace(&["room", "2"]), {
            let (tx, _rx) = commands();
            tx
        });

        let watcher = fabric.next_session_id();
        let (_, mut events) = fabric.watch(watcher, namespace(&[]));

        fabric.remove_session(publisher);
        assert!(fabric.namespaces().is_empty());
        // The watcher is still live, so it saw both withdrawals.
        assert!(matches!(events.try_recv(), Ok(NamespaceEvent::Gone(_, _))));
        assert!(matches!(events.try_recv(), Ok(NamespaceEvent::Gone(_, _))));

        fabric.remove_session(watcher);
        let (tx, _rx) = commands();
        fabric.announce(publisher, namespace(&["room", "3"]), tx);
        // Disconnected rather than Empty, and the difference matters: the
        // session's event loop exits on a closed channel, so removing a watch
        // has to *close* it rather than merely stop feeding it. Leaving the
        // sender alive would strand that loop on a watch nothing can reach.
        assert_eq!(
            events.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected),
            "a removed watch is closed, not just quiet"
        );
    }

    /// A subscriber that stops reading its namespace events must not hold up
    /// announcements to anyone else, so a closed watcher is dropped rather than
    /// awaited.
    #[tokio::test]
    async fn a_closed_watcher_is_dropped_rather_than_blocking() {
        let fabric = Fabric::new();
        let watcher = fabric.next_session_id();
        let (_, events) = fabric.watch(watcher, namespace(&[]));
        drop(events);

        let publisher = fabric.next_session_id();
        let (tx, _rx) = commands();
        fabric.announce(publisher, namespace(&["room", "1"]), tx);

        assert!(fabric.lock().watchers.is_empty());
    }
}
