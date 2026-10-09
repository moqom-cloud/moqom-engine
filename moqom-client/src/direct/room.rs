//! Direct paths in a room: the pieces of this module, driven by who is in the
//! room and what they agreed to. `MoqomKit`'s room does the same; this is it
//! for a caller that keeps its own roster and keys and says what they are with
//! [`DirectRoom::update`].
//!
//! A room never needs a direct path and never waits for one. Media starts on
//! the relay and stays there unless every rule in [`Eligibility`] holds. Then,
//! for each peer:
//!
//! 1. Bind an endpoint, asking the STUN server [`DirectPolicy::opt_in`] chose,
//!    and send its offer, sealed, on this participant's `.direct` track, again
//!    every second until the peer answers.
//! 2. Read the peer's offers on theirs, and establish with the newest one not
//!    tried yet: pinned TLS, then each side checks the other's token and proof
//!    as a relay would.
//! 3. Once up: ask this side's relay for direct tickets, present them and hold
//!    the peer to its own; copy every [`RoomPublication`] onto the direct
//!    session; and attach a direct subscription beside each
//!    [`RoomSubscription`] to the peer, where [`DualSubscription`] merges the
//!    two, pauses the relay copy, and falls back by itself.
//! 4. Anything that ends the path -- tickets, the session closing, the peer
//!    offering afresh, the room no longer qualifying -- leaves the relay doing
//!    what it was doing all along. Another attempt follows after a backoff, for
//!    as long as the room still qualifies.
//!
//! Offers travel under the participant's stage slot. A device that is
//! backstage ([`RoomView::backstage`]) never goes direct: backstage feeds a
//! broadcast that is on the relay anyway. Both offers tracks are published on the relay session when
//! the room is made, and the caller announces the slot as it does to publish
//! media: after making the room, so that a peer's subscription to the offers
//! never reaches this session before the offers track exists.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use moqom_proto::model::{FullTrackName, TrackAlias, TrackNamespace};
use tokio::sync::{mpsc, oneshot, watch};

use super::ticket::{self, TicketRefusal, TicketSettings};
use super::{
    CandidateOffer, Delivery, DirectConfig, DirectEndpoint, DirectPolicy, DualSubscription,
    Eligibility, Ineligible, IpExposure, OptIn, Path, PathSettings, PeerVerifier, RoomDirectPolicy,
    RoomSecret, VerifiedPeer,
};
use crate::Error;
use crate::device::{Credentials, DeviceKey};
use crate::properties::ObjectProperties;
use crate::session::{OutgoingObject, Publication, Session, Subscription};

/// The track offers travel on, beside the participant's media.
pub const OFFERS_TRACK: &str = ".direct";

/// How often an offer is sent again while its peer has not answered.
const RESEND: Duration = Duration::from_secs(1);
/// The longest wait between attempts.
const MAXIMUM_BACKOFF: Duration = Duration::from_mins(1);
/// The MOQT close code for refused credentials, as a relay uses it.
const REFUSED: u32 = 0x03;
/// Groups queued for one track on one direct session before the oldest are
/// dropped; the receiver's merge covers them from the relay.
const LANE_DEPTH: usize = 64;

/// A task that is aborted when dropped.
pub(crate) struct Task(tokio::task::JoinHandle<()>);

impl Task {
    pub(crate) fn spawn(future: impl Future<Output = ()> + Send + 'static) -> Self {
        Self(tokio::spawn(future))
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// What the room is, as far as direct paths are concerned. The caller keeps
/// the roster and the keys, and states this each time something changes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct RoomView {
    /// The room requires end-to-end encryption and this device has it.
    pub encrypted: bool,
    /// This device is publishing, on stage or backstage.
    pub publishing: bool,
    /// It is publishing backstage, which keeps it on the relay.
    pub backstage: bool,
    /// A watchdog (recorder, safety detector) is attached to the room.
    pub watchdog: bool,
    /// Everyone else publishing where this device is -- on stage, or
    /// backstage -- as `user/device`.
    pub peers: BTreeSet<String>,
    /// Those of them who opted in, as their catalogs say.
    pub opted_in: BTreeSet<String>,
    /// Every device holding the offer key, as `user/device`, for a room whose
    /// key comes from a group: each of them could open an offer, so each counts
    /// as a participant.
    pub members: Option<BTreeSet<String>>,
    /// Viewers outside the group. They cannot open an offer, but a room with
    /// an audience is not a small call, so each counts as a participant who
    /// has not opted in.
    pub audience: usize,
    /// The offer key's material, at least 16 bytes, the same on every
    /// participant and never held by a viewer. `None` until there is one.
    pub secret: Option<Vec<u8>>,
}

/// How one peer's media is reaching this device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathState {
    /// Through the relay, and why not directly.
    Relay(Fallback),
    /// Offers are out and a direct path is being set up. Media is on the relay.
    Connecting,
    /// A verified direct session is up and media is read over it as well.
    Direct,
}

/// Why a peer's media is on the relay rather than a direct path.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Fallback {
    /// This device does not use direct paths in this room: its policy is
    /// [`DirectPolicy::RelayOnly`], or the room's grant does not allow them.
    #[error("direct paths are off on this device in this room")]
    Off,
    /// The room does not allow them, for the first reason
    /// [`Eligibility::check`] gives.
    #[error("{0}")]
    Ineligible(Ineligible),
    /// The room qualifies but there is no offer key yet.
    #[error("waiting for the room's encryption keys")]
    AwaitingKeys,
    /// The last attempt did not open a path.
    #[error("{0}")]
    Failed(String),
    /// This device's relay would not issue direct tickets.
    #[error("the relay issues no direct tickets")]
    TicketsUnavailable,
    /// The peer's direct tickets lapsed or did not verify.
    #[error("{0}")]
    Ticket(TicketRefusal),
    /// The direct session ended: the network, or the peer starting over.
    #[error("the direct path was lost")]
    Lost,
}

/// How a room uses direct paths, beside the policy and grant.
#[derive(Clone)]
pub struct DirectRoomConfig {
    /// The endpoint each attempt binds: tenant, room and this participant,
    /// patience and the rest. Its STUN server is the one
    /// [`DirectPolicy::opt_in`] chooses.
    pub endpoint: DirectConfig,
    /// The acknowledgement that peers will learn this device's IP addresses.
    pub exposure: IpExposure,
    /// Checks a peer's token and proof as the relay would.
    pub verifier: Arc<dyn PeerVerifier>,
    /// When the merge trusts the direct path, and when it gives up on it.
    pub path: PathSettings,
    /// How patient this side is with the peer's tickets.
    pub tickets: TicketSettings,
    /// The wait before trying again after an attempt fails, doubling on each
    /// failure up to a minute.
    pub retry: Duration,
}

impl DirectRoomConfig {
    /// Defaults around `endpoint`, `exposure` and `verifier`.
    #[must_use]
    pub fn new(
        endpoint: DirectConfig,
        exposure: IpExposure,
        verifier: Arc<dyn PeerVerifier>,
    ) -> Self {
        Self {
            endpoint,
            exposure,
            verifier,
            path: PathSettings::default(),
            tickets: TicketSettings::default(),
            retry: Duration::from_secs(2),
        }
    }
}

impl std::fmt::Debug for DirectRoomConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectRoomConfig")
            .field("endpoint", &self.endpoint)
            .field("path", &self.path)
            .field("tickets", &self.tickets)
            .field("retry", &self.retry)
            .finish_non_exhaustive()
    }
}

/// The credentials in force, presented to a direct peer as to the relay.
#[derive(Debug, Clone)]
pub struct RoomCredentials {
    /// The token, as issued.
    pub token: Vec<u8>,
    /// The key it is bound to.
    pub key: Option<Arc<DeviceKey>>,
}

impl RoomCredentials {
    fn borrowed(&self) -> Credentials<'_> {
        Credentials {
            token: &self.token,
            key: self.key.as_deref(),
        }
    }
}

enum Command {
    Update(RoomView),
    Renew(RoomCredentials, RoomDirectPolicy),
    Policy(DirectPolicy),
    Close(oneshot::Sender<()>),
}

/// Direct paths for one room, beside a relay session that already works.
///
/// Dropping it ends every direct path and leaves the relay as it was.
pub struct DirectRoom {
    commands: mpsc::UnboundedSender<Command>,
    paths: watch::Receiver<BTreeMap<String, PathState>>,
    opted_in: watch::Receiver<bool>,
    shared: Arc<Shared>,
    relay: Session,
    path: PathSettings,
    _driver: Task,
}

impl std::fmt::Debug for DirectRoom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectRoom")
            .field("paths", &*self.paths.borrow())
            .finish_non_exhaustive()
    }
}

impl DirectRoom {
    /// Direct paths for the room `config.endpoint` names, on `relay`, under
    /// `policy` and the room's `grant` from the token.
    ///
    /// Make it before announcing this participant's slot on `relay`. Nothing
    /// is offered until [`Self::update`] says who is in the room.
    #[must_use]
    pub fn new(
        relay: Session,
        credentials: RoomCredentials,
        policy: DirectPolicy,
        grant: RoomDirectPolicy,
        config: DirectRoomConfig,
    ) -> Self {
        let applied = policy.opt_in(&grant);
        let (paths_tx, paths) = watch::channel(BTreeMap::new());
        let (opted_tx, opted_in) = watch::channel(applied.is_some());
        let (commands, commands_rx) = mpsc::unbounded_channel();
        let (events, events_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared::default());
        let path = config.path;
        let channels = [false, true]
            .into_iter()
            .filter_map(|backstage| {
                let track = offers_track(&config.endpoint, &config.endpoint.me, backstage)?;
                let publication = relay.publish(track).ok()?;
                Some((
                    backstage,
                    (Arc::new(publication), Arc::new(AtomicU64::new(0))),
                ))
            })
            .collect();
        let driver = Driver {
            relay: relay.clone(),
            config,
            credentials,
            policy,
            grant,
            applied,
            view: RoomView::default(),
            offers: None,
            channels,
            offer_key: None,
            generation: 0,
            peers: BTreeMap::new(),
            events,
            paths: paths_tx,
            opted: opted_tx,
            shared: Arc::clone(&shared),
            stopped: false,
        };
        Self {
            commands,
            paths,
            opted_in,
            shared,
            relay,
            path,
            _driver: Task::spawn(driver.run(commands_rx, events_rx)),
        }
    }

    /// Whether this device opts in to direct paths here, under its policy and
    /// the room's grant: what its catalog should say, which is how the others
    /// count it.
    #[must_use]
    pub fn opted_in(&self) -> bool {
        *self.opted_in.borrow()
    }

    /// The room changed.
    pub fn update(&self, view: RoomView) {
        let _ = self.commands.send(Command::Update(view));
    }

    /// A renewed token, and the room's grant that came with it. A grant that
    /// changes the limit or the STUN server sets direct paths up again; one
    /// that forbids them ends them.
    pub fn renew(&self, credentials: RoomCredentials, grant: RoomDirectPolicy) {
        let _ = self.commands.send(Command::Renew(credentials, grant));
    }

    /// Change this device's policy for the room.
    pub fn set_policy(&self, policy: DirectPolicy) {
        let _ = self.commands.send(Command::Policy(policy));
    }

    /// Each peer's path, as it changes.
    #[must_use]
    pub fn paths(&self) -> watch::Receiver<BTreeMap<String, PathState>> {
        self.paths.clone()
    }

    /// Read `track` from `peer` (`user/device`) over the relay, and over a
    /// direct path to them whenever there is one.
    ///
    /// # Errors
    /// The relay subscription failing.
    pub async fn subscribe(
        &self,
        peer: &str,
        track: FullTrackName,
    ) -> Result<RoomSubscription, Error> {
        let mut relay = self.relay.clone();
        let subscription = relay.subscribe(track.clone()).await?;
        let mut dual = DualSubscription::new(subscription, self.path);
        let (attach, attachments) = mpsc::channel(1);
        dual.attach_from(attachments);
        let link = self.shared.link(peer);
        Ok(RoomSubscription {
            dual,
            _attacher: Task::spawn(attacher(link, track, attach)),
        })
    }

    /// Publish `track` on the relay and copy it onto every direct session.
    ///
    /// # Errors
    /// Aliases exhausted.
    pub fn publish(&self, track: FullTrackName) -> Result<RoomPublication, Error> {
        let relay = self.relay.publish(track.clone())?;
        let id = self.shared.register(&track);
        Ok(RoomPublication {
            relay,
            session: self.relay.clone(),
            shared: Arc::clone(&self.shared),
            track,
            id,
        })
    }

    /// End every direct path and stop, leaving the relay as it was.
    pub async fn close(&self) {
        let (done, closed) = oneshot::channel();
        if self.commands.send(Command::Close(done)).is_ok() {
            let _ = closed.await;
        }
    }
}

/// A track published on the relay and copied onto the room's direct sessions.
///
/// The copy is queued rather than awaited: a direct path that stalls must never
/// hold up the relay, which is the fallback.
pub struct RoomPublication {
    relay: Publication,
    session: Session,
    shared: Arc<Shared>,
    track: FullTrackName,
    id: u64,
}

impl std::fmt::Debug for RoomPublication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoomPublication")
            .field("track", &self.track)
            .finish_non_exhaustive()
    }
}

impl RoomPublication {
    /// The relay alias.
    #[must_use]
    pub const fn alias(&self) -> TrackAlias {
        self.relay.alias()
    }

    /// Wait until the relay has asked for the track.
    pub async fn subscribed(&self) {
        self.relay.subscribed().await;
    }

    /// Write one subgroup into `group` on the relay and every direct session,
    /// under the same group and object numbers, which is what lets a
    /// receiver's merge deliver each object once.
    ///
    /// # Errors
    /// The relay write failing. A direct copy that fails is the receiver's
    /// fallback, not an error.
    pub async fn publish_objects(
        &self,
        group: u64,
        objects: &[OutgoingObject<'_>],
    ) -> Result<(), Error> {
        self.shared.send(&self.track, group, objects);
        self.session
            .publish_objects(self.relay.alias(), group, objects)
            .await
    }
}

impl Drop for RoomPublication {
    fn drop(&mut self) {
        self.shared.unregister(&self.track, self.id);
    }
}

/// A peer's track, read over the relay and a direct path at once.
pub struct RoomSubscription {
    dual: DualSubscription,
    _attacher: Task,
}

impl std::fmt::Debug for RoomSubscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoomSubscription")
            .field("path", &self.dual.path())
            .finish_non_exhaustive()
    }
}

impl RoomSubscription {
    /// The next object, from whichever path delivered it first, exactly once.
    /// See [`DualSubscription::next`].
    ///
    /// # Errors
    /// The relay subscription failing.
    pub async fn next(&mut self) -> Result<Option<Delivery>, Error> {
        self.dual.next().await
    }

    /// Which path objects are being delivered from.
    #[must_use]
    pub const fn path(&self) -> Path {
        self.dual.path()
    }

    /// Whether the relay has been asked to stop forwarding.
    #[must_use]
    pub const fn relay_paused(&self) -> bool {
        self.dual.relay_paused()
    }

    /// How many objects the relay has sent for this track. See
    /// [`DualSubscription::relay_objects`].
    #[must_use]
    pub const fn relay_objects(&self) -> u64 {
        self.dual.relay_objects()
    }

    /// How many times the active path has changed.
    #[must_use]
    pub const fn switches(&self) -> u32 {
        self.dual.switches()
    }
}

/// Open a direct subscription to `track` on each direct session to the peer as
/// it comes up, retrying while the peer has not published it there yet.
async fn attacher(
    mut link: watch::Receiver<Option<Session>>,
    track: FullTrackName,
    attach: mpsc::Sender<Subscription>,
) {
    loop {
        let current = link.borrow_and_update().clone();
        if let Some(mut session) = current {
            let opening = async {
                loop {
                    if let Ok(subscription) = session.subscribe(track.clone()).await {
                        return subscription;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            };
            tokio::select! {
                subscription = opening => {
                    if attach.send(subscription).await.is_err() {
                        return;
                    }
                }
                changed = link.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    continue;
                }
            }
        }
        if link.changed().await.is_err() {
            return;
        }
    }
}

/// What the room's handles share with its driver.
#[derive(Default)]
struct Shared {
    /// Each peer's live direct session, for subscriptions to attach to.
    links: Mutex<HashMap<String, watch::Sender<Option<Session>>>>,
    fanout: Mutex<Fanout>,
}

#[derive(Default)]
struct Fanout {
    next: u64,
    tracks: HashMap<FullTrackName, u64>,
    sessions: HashMap<String, Session>,
    lanes: HashMap<String, HashMap<FullTrackName, Lane>>,
}

/// One track on one direct session, written in order by its own task.
struct Lane {
    groups: mpsc::Sender<Group>,
    _writer: Task,
}

struct Group {
    number: u64,
    objects: Vec<(Bytes, ObjectProperties)>,
}

impl Lane {
    fn open(session: &Session, track: FullTrackName) -> Option<Self> {
        let publication = session.publish(track).ok()?;
        let (groups, mut queued) = mpsc::channel::<Group>(LANE_DEPTH);
        let session = session.clone();
        let writer = Task::spawn(async move {
            while let Some(group) = queued.recv().await {
                let objects: Vec<OutgoingObject<'_>> = group
                    .objects
                    .iter()
                    .map(|(payload, properties)| {
                        OutgoingObject::tagged(payload, properties.clone())
                    })
                    .collect();
                let _ = session
                    .publish_objects(publication.alias(), group.number, &objects)
                    .await;
            }
        });
        Some(Self {
            groups,
            _writer: writer,
        })
    }
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, Fanout> {
        self.fanout
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn link(&self, peer: &str) -> watch::Receiver<Option<Session>> {
        self.links
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(peer.to_owned())
            .or_insert_with(|| watch::channel(None).0)
            .subscribe()
    }

    fn set_link(&self, peer: &str, session: Option<Session>) {
        let mut links = self
            .links
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let sender = links
            .entry(peer.to_owned())
            .or_insert_with(|| watch::channel(None).0);
        sender.send_replace(session);
    }

    fn register(&self, track: &FullTrackName) -> u64 {
        let mut fanout = self.lock();
        fanout.next += 1;
        let id = fanout.next;
        fanout.tracks.insert(track.clone(), id);
        let opened: Vec<(String, Lane)> = fanout
            .sessions
            .iter()
            .filter_map(|(peer, session)| Some((peer.clone(), Lane::open(session, track.clone())?)))
            .collect();
        for (peer, lane) in opened {
            fanout
                .lanes
                .entry(peer)
                .or_default()
                .insert(track.clone(), lane);
        }
        id
    }

    fn unregister(&self, track: &FullTrackName, id: u64) {
        let mut fanout = self.lock();
        if fanout.tracks.get(track) != Some(&id) {
            return;
        }
        fanout.tracks.remove(track);
        for lanes in fanout.lanes.values_mut() {
            lanes.remove(track);
        }
    }

    fn attach(&self, peer: &str, session: &Session) {
        let mut fanout = self.lock();
        fanout.sessions.insert(peer.to_owned(), session.clone());
        let lanes: HashMap<FullTrackName, Lane> = fanout
            .tracks
            .keys()
            .filter_map(|track| Some((track.clone(), Lane::open(session, track.clone())?)))
            .collect();
        fanout.lanes.insert(peer.to_owned(), lanes);
    }

    fn detach(&self, peer: &str) {
        let mut fanout = self.lock();
        fanout.sessions.remove(peer);
        fanout.lanes.remove(peer);
    }

    fn send(&self, track: &FullTrackName, group: u64, objects: &[OutgoingObject<'_>]) {
        let fanout = self.lock();
        let lanes: Vec<&Lane> = fanout
            .lanes
            .values()
            .filter_map(|lanes| lanes.get(track))
            .collect();
        if lanes.is_empty() {
            return;
        }
        for lane in lanes {
            let _ = lane.groups.try_send(Group {
                number: group,
                objects: objects
                    .iter()
                    .map(|object| {
                        (
                            Bytes::copy_from_slice(object.payload),
                            object.properties.clone(),
                        )
                    })
                    .collect(),
            });
        }
    }
}

// The driver: one task owning every peer's attempt, fed by commands and by
// the events its own tasks send back.

enum Event {
    Bound {
        peer: String,
        attempt: u64,
        result: Result<Arc<DirectEndpoint>, String>,
    },
    Offer {
        peer: String,
        generation: u64,
        offer: CandidateOffer,
    },
    Established {
        peer: String,
        attempt: u64,
        certificate: [u8; 32],
        result: Result<Box<Established>, Fallback>,
    },
    Ended {
        peer: String,
        attempt: u64,
        reason: Fallback,
    },
    Retry {
        peer: String,
    },
}

struct Established {
    session: Session,
    verified: VerifiedPeer,
    tickets: Subscription,
}

type OfferChannel = (Arc<Publication>, Arc<AtomicU64>);

struct Offers {
    publication: Arc<Publication>,
    secret: Arc<RoomSecret>,
    backstage: bool,
    groups: Arc<AtomicU64>,
}

struct Link {
    session: Session,
    certificate: [u8; 32],
    _tasks: [Task; 2],
}

impl Drop for Link {
    fn drop(&mut self) {
        self.session.close(0, "direct path ended");
    }
}

#[derive(Default)]
struct Peer {
    state: Option<PathState>,
    /// Bumped by every attempt and every teardown, so a result from an attempt
    /// that has since been abandoned is recognised as such.
    attempt: u64,
    endpoint: Option<Arc<DirectEndpoint>>,
    sender: Option<Task>,
    establishing: Option<Task>,
    reader: Option<Task>,
    retry: Option<Task>,
    /// The newest offer the peer has addressed to this device.
    newest: Option<CandidateOffer>,
    /// Certificates already established against. Each endpoint makes a fresh
    /// one, so an offer is never worth a second try.
    tried: HashSet<[u8; 32]>,
    link: Option<Link>,
    failures: u32,
    /// An endpoint is being bound for the current attempt.
    binding: bool,
}

impl Peer {
    fn is_idle(&self) -> bool {
        self.link.is_none() && self.endpoint.is_none() && self.retry.is_none() && !self.binding
    }
}

struct Driver {
    relay: Session,
    config: DirectRoomConfig,
    credentials: RoomCredentials,
    policy: DirectPolicy,
    grant: RoomDirectPolicy,
    applied: Option<OptIn>,
    view: RoomView,
    offers: Option<Offers>,
    /// The offers track on each slot, stage and backstage, published for as
    /// long as the room lasts so that a peer's subscription always lands on it.
    channels: HashMap<bool, OfferChannel>,
    offer_key: Option<Vec<u8>>,
    generation: u64,
    peers: BTreeMap<String, Peer>,
    events: mpsc::UnboundedSender<Event>,
    paths: watch::Sender<BTreeMap<String, PathState>>,
    opted: watch::Sender<bool>,
    shared: Arc<Shared>,
    stopped: bool,
}

impl Driver {
    async fn run(
        mut self,
        mut commands: mpsc::UnboundedReceiver<Command>,
        mut events: mpsc::UnboundedReceiver<Event>,
    ) {
        loop {
            tokio::select! {
                command = commands.recv() => match command {
                    Some(Command::Update(view)) => {
                        if view != self.view {
                            self.view = view;
                            self.reconcile();
                        }
                    }
                    Some(Command::Renew(credentials, grant)) => {
                        self.credentials = credentials;
                        self.grant = grant;
                        self.reapply();
                    }
                    Some(Command::Policy(policy)) => {
                        self.policy = policy;
                        self.reapply();
                    }
                    Some(Command::Close(done)) => {
                        self.stop();
                        let _ = done.send(());
                        return;
                    }
                    None => {
                        self.stop();
                        return;
                    }
                },
                Some(event) = events.recv() => self.handle(event),
            }
        }
    }

    fn me(&self) -> &str {
        &self.config.endpoint.me
    }

    /// A participant's own slot: stage, or backstage.
    fn slot(&self, backstage: bool) -> Option<TrackNamespace> {
        let endpoint = &self.config.endpoint;
        let (user, device) = endpoint.me.split_once('/')?;
        let marker = if backstage { "bs" } else { "r" };
        TrackNamespace::from_parts([
            endpoint.tenant.as_str(),
            marker,
            endpoint.room.as_str(),
            user,
            device,
        ])
        .ok()
    }

    /// The policy or the grant changed. Anything that changes what this device
    /// opts in to sets every path up again under the new terms.
    fn reapply(&mut self) {
        let next = self.policy.opt_in(&self.grant);
        if next == self.applied {
            return;
        }
        self.applied = next;
        self.opted.send_replace(self.applied.is_some());
        let peers: Vec<String> = self.peers.keys().cloned().collect();
        for who in &peers {
            self.teardown(who, None);
            // `tried` is kept: the relay hands a new reader the last offer it
            // holds, which may be for an endpoint already given up on.
            if let Some(peer) = self.peers.get_mut(who) {
                peer.reader = None;
                peer.failures = 0;
            }
        }
        self.offers = None;
        self.offer_key = None;
        self.reconcile();
    }

    fn stop(&mut self) {
        self.stopped = true;
        let peers: Vec<String> = self.peers.keys().cloned().collect();
        for who in &peers {
            self.teardown(who, None);
        }
        self.peers.clear();
        self.offers = None;
    }

    fn reconcile(&mut self) {
        let gone: Vec<String> = self
            .peers
            .keys()
            .filter(|who| !self.view.peers.contains(*who))
            .cloned()
            .collect();
        for who in &gone {
            self.teardown(who, None);
            self.peers.remove(who);
            self.paths.send_modify(|paths| {
                paths.remove(who);
            });
        }

        if let Some(refusal) = self.refusal() {
            let peers: Vec<String> = self.peers.keys().cloned().collect();
            for who in &peers {
                self.teardown(who, None);
                if let Some(peer) = self.peers.get_mut(who) {
                    peer.reader = None;
                    peer.failures = 0;
                }
            }
            for who in self.view.peers.clone() {
                self.peers.entry(who.clone()).or_default();
                self.set_state(&who, PathState::Relay(refusal.clone()));
            }
            self.offers = None;
            self.offer_key = None;
            return;
        }

        if let Some(key) = self.view.secret.clone()
            && (Some(&key) != self.offer_key.as_ref()
                || self.offers.as_ref().map(|offers| offers.backstage) != Some(self.view.backstage))
        {
            self.rekey(&key);
        }
        for who in self.view.peers.clone() {
            self.peers.entry(who.clone()).or_default();
            if self
                .peers
                .get(&who)
                .is_some_and(|peer| peer.reader.is_none())
            {
                let reader = self.reading(&who);
                if let Some(peer) = self.peers.get_mut(&who) {
                    peer.reader = reader;
                }
            }
            if self.peers.get(&who).is_some_and(Peer::is_idle) {
                self.begin(&who);
            }
        }
    }

    /// Why the room may not use direct paths right now, or `None` if it may.
    fn refusal(&self) -> Option<Fallback> {
        let Some(applied) = self.applied.as_ref() else {
            return Some(Fallback::Off);
        };
        if self.view.backstage {
            return Some(Fallback::Ineligible(Ineligible::Backstage));
        }
        let me = self.me().to_owned();
        let mut everyone: BTreeSet<String> = self.view.peers.clone();
        everyone.extend(self.view.members.iter().flatten().cloned());
        everyone.insert(me.clone());
        let opted = everyone
            .iter()
            .filter(|who| **who != me)
            .all(|who| self.view.opted_in.contains(who))
            && self.view.audience == 0;
        let eligibility =
            self.eligibility(everyone.len() + self.view.audience, opted, applied.limit);
        if let Err(why) = eligibility.check() {
            return Some(Fallback::Ineligible(why));
        }
        self.view.secret.is_none().then_some(Fallback::AwaitingKeys)
    }

    fn eligibility(
        &self,
        participants: usize,
        everyone_opted_in: bool,
        limit: usize,
    ) -> Eligibility {
        Eligibility {
            end_to_end_encrypted: self.view.encrypted,
            participants,
            everyone_opted_in,
            watchdog_required: self.view.watchdog,
            audience: !self.view.publishing,
            limit,
        }
    }

    fn rekey(&mut self, key: &[u8]) {
        self.generation += 1;
        self.offer_key = Some(key.to_vec());
        let endpoint = &self.config.endpoint;
        let backstage = self.view.backstage;
        let secret = RoomSecret::new(key, &format!("{}/{}", endpoint.tenant, endpoint.room));
        let (Ok(secret), Some((publication, groups))) = (secret, self.channels.get(&backstage))
        else {
            self.offers = None;
            return;
        };
        self.offers = Some(Offers {
            publication: Arc::clone(publication),
            secret: Arc::new(secret),
            backstage,
            groups: Arc::clone(groups),
        });
        let peers: Vec<String> = self.peers.keys().cloned().collect();
        for who in peers {
            let reader = self.reading(&who);
            if let Some(peer) = self.peers.get_mut(&who) {
                peer.reader = reader;
            }
        }
    }

    /// Read the offers `who` addresses to this device, for as long as the key
    /// is the current one, resubscribing while the peer has not published yet.
    fn reading(&self, who: &str) -> Option<Task> {
        let offers = self.offers.as_ref()?;
        let track = offers_track(&self.config.endpoint, who, offers.backstage)?;
        let secret = Arc::clone(&offers.secret);
        let generation = self.generation;
        let me = self.me().to_owned();
        let peer = who.to_owned();
        let events = self.events.clone();
        let mut relay = self.relay.clone();
        Some(Task::spawn(async move {
            loop {
                if let Ok(mut subscription) = relay.subscribe(track.clone()).await {
                    while let Ok(Some(object)) = subscription.next_object().await {
                        let Ok(offer) = CandidateOffer::open(&object.payload, &secret, &me) else {
                            continue;
                        };
                        if offer.from != peer {
                            continue;
                        }
                        let event = Event::Offer {
                            peer: peer.clone(),
                            generation,
                            offer,
                        };
                        if events.send(event).is_err() {
                            return;
                        }
                    }
                }
                tokio::time::sleep(RESEND).await;
            }
        }))
    }

    fn handle(&mut self, event: Event) {
        if self.stopped {
            return;
        }
        match event {
            Event::Bound {
                peer,
                attempt,
                result,
            } => self.bound(&peer, attempt, result),
            Event::Offer {
                peer,
                generation,
                offer,
            } => self.received(&peer, offer, generation),
            Event::Established {
                peer,
                attempt,
                certificate,
                result,
            } => self.established(&peer, attempt, certificate, result),
            Event::Ended {
                peer,
                attempt,
                reason,
            } => self.link_ended(&peer, attempt, reason),
            Event::Retry { peer } => {
                if let Some(state) = self.peers.get_mut(&peer) {
                    state.retry = None;
                }
                self.retry_now(&peer);
            }
        }
    }

    fn received(&mut self, who: &str, offer: CandidateOffer, generation: u64) {
        if generation != self.generation {
            return;
        }
        let Some(peer) = self.peers.get_mut(who) else {
            return;
        };
        if peer.tried.contains(&offer.certificate) {
            return;
        }
        peer.newest = Some(offer.clone());
        if let Some(link) = &peer.link {
            if offer.certificate == link.certificate {
                return;
            }
            // The peer has bound afresh, so its end of this path is gone or
            // going; meet it on the new one rather than wait to notice.
            let attempt = peer.attempt;
            self.link_ended(who, attempt, Fallback::Lost);
            self.retry_now(who);
            return;
        }
        if let Some(endpoint) = peer.endpoint.clone() {
            if peer.establishing.is_none() {
                let attempt = peer.attempt;
                self.establish(who, offer, endpoint, attempt);
            }
        } else if peer.retry.is_some() {
            // Waiting out a backoff while the peer is trying now.
            self.retry_now(who);
        }
    }

    fn begin(&mut self, who: &str) {
        if self.stopped || self.refusal().is_some() {
            return;
        }
        let Some(applied) = self.applied.clone() else {
            return;
        };
        let Some(peer) = self.peers.get_mut(who) else {
            return;
        };
        if !peer.is_idle() {
            return;
        }
        peer.attempt += 1;
        peer.binding = true;
        let attempt = peer.attempt;
        self.set_state(who, PathState::Connecting);

        let mut everyone: BTreeSet<String> = self.view.peers.clone();
        everyone.extend(self.view.members.iter().flatten().cloned());
        everyone.insert(self.me().to_owned());
        let eligibility = self.eligibility(everyone.len(), true, applied.limit);
        let mut config = self.config.endpoint.clone();
        config.stun = applied.stun;
        let exposure = self.config.exposure;
        let events = self.events.clone();
        let peer = who.to_owned();
        // Not kept: the result comes back as an event, and one for an attempt
        // since abandoned is recognised by its number.
        drop(tokio::spawn(async move {
            let result = DirectEndpoint::bind(config, &eligibility, exposure)
                .await
                .map(Arc::new)
                .map_err(|error| error.to_string());
            let _ = events.send(Event::Bound {
                peer,
                attempt,
                result,
            });
        }));
    }

    fn bound(&mut self, who: &str, attempt: u64, result: Result<Arc<DirectEndpoint>, String>) {
        let current = !self.stopped
            && self
                .peers
                .get(who)
                .is_some_and(|peer| peer.attempt == attempt);
        if !current {
            return;
        }
        let Some(peer) = self.peers.get_mut(who) else {
            return;
        };
        peer.binding = false;
        let endpoint = match result {
            Err(error) => {
                self.failed(who, attempt, Fallback::Failed(error));
                return;
            }
            Ok(endpoint) => endpoint,
        };
        peer.endpoint = Some(Arc::clone(&endpoint));
        if let Some(offers) = &self.offers {
            let offer = endpoint.offer_to(who);
            let relay = self.relay.clone();
            let publication = Arc::clone(&offers.publication);
            let secret = Arc::clone(&offers.secret);
            let groups = Arc::clone(&offers.groups);
            peer.sender = Some(Task::spawn(async move {
                loop {
                    if publication.has_subscribers()
                        && let Ok(sealed) = offer.seal(&secret)
                    {
                        let group = groups.fetch_add(1, Ordering::Relaxed);
                        let _ = relay
                            .publish_objects(
                                publication.alias(),
                                group,
                                &[OutgoingObject::new(&sealed)],
                            )
                            .await;
                    }
                    tokio::time::sleep(RESEND).await;
                }
            }));
        }
        if let Some(newest) = peer.newest.clone()
            && !peer.tried.contains(&newest.certificate)
        {
            self.establish(who, newest, endpoint, attempt);
        }
    }

    fn establish(
        &mut self,
        who: &str,
        offer: CandidateOffer,
        endpoint: Arc<DirectEndpoint>,
        attempt: u64,
    ) {
        let Some(tickets) = self
            .slot(self.view.backstage)
            .and_then(|slot| ticket::relay_track(slot, who))
        else {
            return;
        };
        let Some(peer) = self.peers.get_mut(who) else {
            return;
        };
        peer.tried.insert(offer.certificate);
        let credentials = self.credentials.clone();
        let verifier = Arc::clone(&self.config.verifier);
        let mut relay = self.relay.clone();
        let events = self.events.clone();
        let name = who.to_owned();
        peer.establishing = Some(Task::spawn(async move {
            let certificate = offer.certificate;
            let result = match endpoint
                .establish(&offer, &credentials.borrowed(), verifier.as_ref())
                .await
            {
                Err(error) => Err(Fallback::Failed(error.to_string())),
                // Holding this subscription is what the relay meters, so it is
                // opened only once there is a path to meter.
                Ok((session, admitted)) => {
                    if let Ok(tickets) = relay.subscribe(tickets).await {
                        Ok(Box::new(Established {
                            session,
                            verified: admitted,
                            tickets,
                        }))
                    } else {
                        session.close(0, "no direct tickets");
                        Err(Fallback::TicketsUnavailable)
                    }
                }
            };
            let _ = events.send(Event::Established {
                peer: name,
                attempt,
                certificate,
                result,
            });
        }));
    }

    fn established(
        &mut self,
        who: &str,
        attempt: u64,
        certificate: [u8; 32],
        result: Result<Box<Established>, Fallback>,
    ) {
        let current = self
            .peers
            .get(who)
            .is_some_and(|peer| peer.attempt == attempt);
        if !current {
            if let Ok(established) = result {
                established.session.close(0, "abandoned");
            }
            return;
        }
        if let Some(peer) = self.peers.get_mut(who) {
            peer.establishing = None;
        }
        match result {
            Err(reason) => self.failed(who, attempt, reason),
            Ok(established) => self.link(who, established, certificate, attempt),
        }
    }

    fn link(
        &mut self,
        who: &str,
        established: Box<Established>,
        certificate: [u8; 32],
        attempt: u64,
    ) {
        let Established {
            session,
            verified,
            tickets,
        } = *established;
        let guard = {
            let events = self.events.clone();
            let peer = who.to_owned();
            let direct = session.clone();
            let me = self.me().to_owned();
            let settings = self.config.tickets;
            Task::spawn(async move {
                let refusal = ticket::guard(direct, tickets, verified, me, settings).await;
                let _ = events.send(Event::Ended {
                    peer,
                    attempt,
                    reason: Fallback::Ticket(refusal),
                });
            })
        };
        let watcher = {
            let events = self.events.clone();
            let peer = who.to_owned();
            let direct = session.clone();
            Task::spawn(async move {
                let _ = direct.closed().await;
                let _ = events.send(Event::Ended {
                    peer,
                    attempt,
                    reason: Fallback::Lost,
                });
            })
        };
        let Some(peer) = self.peers.get_mut(who) else {
            return;
        };
        peer.sender = None;
        peer.failures = 0;
        peer.link = Some(Link {
            session: session.clone(),
            certificate,
            _tasks: [guard, watcher],
        });
        self.shared.attach(who, &session);
        self.shared.set_link(who, Some(session));
        self.set_state(who, PathState::Direct);
    }

    fn link_ended(&mut self, who: &str, attempt: u64, reason: Fallback) {
        let live = self
            .peers
            .get(who)
            .is_some_and(|peer| peer.attempt == attempt && peer.link.is_some());
        if !live {
            return;
        }
        let close = match &reason {
            Fallback::Ticket(refusal) => Some((REFUSED, refusal.to_string())),
            _ => None,
        };
        self.teardown(who, close);
        if let Some(peer) = self.peers.get_mut(who) {
            peer.failures += 1;
        }
        self.set_state(who, PathState::Relay(reason));
        self.schedule_retry(who);
    }

    fn failed(&mut self, who: &str, attempt: u64, reason: Fallback) {
        if self
            .peers
            .get(who)
            .is_none_or(|peer| peer.attempt != attempt)
        {
            return;
        }
        self.teardown(who, None);
        if let Some(peer) = self.peers.get_mut(who) {
            peer.failures += 1;
        }
        self.set_state(who, PathState::Relay(reason));
        self.schedule_retry(who);
    }

    fn schedule_retry(&mut self, who: &str) {
        if self.stopped {
            return;
        }
        let retry = self.config.retry;
        let Some(peer) = self.peers.get_mut(who) else {
            return;
        };
        let delay = backoff(retry, peer.failures);
        let events = self.events.clone();
        let name = who.to_owned();
        peer.retry = Some(Task::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = events.send(Event::Retry { peer: name });
        }));
    }

    fn retry_now(&mut self, who: &str) {
        let Some(peer) = self.peers.get_mut(who) else {
            return;
        };
        if peer.link.is_some() || peer.endpoint.is_some() {
            return;
        }
        peer.retry = None;
        self.begin(who);
    }

    /// End whatever is open to `who`, leaving the relay as it is.
    fn teardown(&mut self, who: &str, close: Option<(u32, String)>) {
        let Some(peer) = self.peers.get_mut(who) else {
            return;
        };
        peer.attempt += 1;
        peer.binding = false;
        peer.sender = None;
        peer.establishing = None;
        peer.retry = None;
        peer.endpoint = None;
        if let Some(link) = peer.link.take() {
            self.shared.detach(who);
            self.shared.set_link(who, None);
            if let Some((code, reason)) = close {
                link.session.close(code, &reason);
            }
        }
    }

    fn set_state(&mut self, who: &str, state: PathState) {
        let Some(peer) = self.peers.get_mut(who) else {
            return;
        };
        if peer.state.as_ref() == Some(&state) {
            return;
        }
        peer.state = Some(state.clone());
        self.paths.send_modify(|paths| {
            paths.insert(who.to_owned(), state);
        });
    }
}

/// `who`'s offers track in the room `endpoint` is in, on the stage slot or the
/// backstage one.
fn offers_track(endpoint: &DirectConfig, who: &str, backstage: bool) -> Option<FullTrackName> {
    let (user, device) = who.split_once('/')?;
    let marker = if backstage { "bs" } else { "r" };
    let namespace = TrackNamespace::from_parts([
        endpoint.tenant.as_str(),
        marker,
        endpoint.room.as_str(),
        user,
        device,
    ])
    .ok()?;
    FullTrackName::new(namespace, Bytes::from_static(OFFERS_TRACK.as_bytes())).ok()
}

/// The wait before attempt `failures + 1`: `retry`, doubling with each
/// failure, never more than a minute.
fn backoff(retry: Duration, failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(16);
    retry.saturating_mul(1 << doublings).min(MAXIMUM_BACKOFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_backoff_doubles_up_to_a_minute() {
        let retry = Duration::from_secs(2);
        assert_eq!(backoff(retry, 0), retry);
        assert_eq!(backoff(retry, 1), retry);
        assert_eq!(backoff(retry, 2), Duration::from_secs(4));
        assert_eq!(backoff(retry, 4), Duration::from_secs(16));
        assert_eq!(backoff(retry, 40), MAXIMUM_BACKOFF);
    }
}
