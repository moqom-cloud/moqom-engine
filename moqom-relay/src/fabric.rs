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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use moqom_proto::control::RequestErrorCode;
use moqom_proto::model::{FullTrackName, TrackAlias, TrackNamespace};
use tokio::sync::{mpsc, oneshot};

use crate::cache::Cache;
use crate::metrics::Metrics;

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
    /// The alias this subscriber knows the track by.
    pub alias: TrackAlias,
}

/// `moqom_transport::Session` has no useful `Debug`, and a connection is not
/// something a log line wants inlined regardless.
impl std::fmt::Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Route")
            .field("alias", &self.alias)
            .finish_non_exhaustive()
    }
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
        route: Route,
        /// Completed once upstream has answered.
        ready: oneshot::Sender<Result<(), UpstreamError>>,
    },
}

/// A namespace appearing or going away.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceEvent {
    /// A namespace is now available.
    Available(TrackNamespace),
    /// A namespace that was announced has been withdrawn.
    Gone(TrackNamespace),
}

impl NamespaceEvent {
    /// The namespace this event is about.
    #[must_use]
    pub const fn namespace(&self) -> &TrackNamespace {
        match self {
            Self::Available(namespace) | Self::Gone(namespace) => namespace,
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
}

/// The state shared between every session on one relay.
///
/// Cheap to clone; all clones see the same state.
#[derive(Debug, Clone, Default)]
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
    pub fn withdraw(&self, owner: SessionId, namespace: &TrackNamespace) {
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
            &NamespaceEvent::Gone(namespace.clone()),
        );
    }

    /// Withdraw everything belonging to `owner`, for use when its session ends.
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
            self.withdraw(owner, &namespace);
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

        fabric.withdraw(publisher, &namespace(&["room", "1"]));
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

        fabric.withdraw(publisher, &namespace(&["room", "7"]));
        assert_eq!(
            events.recv().await,
            Some(NamespaceEvent::Gone(namespace(&["room", "7"])))
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

        fabric.withdraw(first, &namespace(&["room", "1"]));
        assert_eq!(events.try_recv(), Err(mpsc::error::TryRecvError::Empty));
        assert!(fabric.publisher(&namespace(&["room", "1"])).is_some());

        fabric.withdraw(second, &namespace(&["room", "1"]));
        assert_eq!(
            events.recv().await,
            Some(NamespaceEvent::Gone(namespace(&["room", "1"])))
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
        assert!(matches!(events.try_recv(), Ok(NamespaceEvent::Gone(_))));
        assert!(matches!(events.try_recv(), Ok(NamespaceEvent::Gone(_))));

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
