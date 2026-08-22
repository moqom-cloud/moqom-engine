//! One MOQT session, from SETUP to teardown.
//!
//! # The stream layout this implements
//!
//! Draft-19 gives every request its own bidirectional stream, and that decision
//! shapes this whole module. There are three kinds of stream and they are told
//! apart by *when* and *what*, not by any type field:
//!
//! - The **control stream** is the first bidirectional stream the client opens.
//!   It carries SETUP in both directions and then only session-wide messages
//!   (`GOAWAY`). Nothing else may appear on it.
//! - A **request stream** is any later bidirectional stream. Its first message
//!   says what it is, the response comes back on the same stream, and closing it
//!   withdraws the request — which is why there is no `UNSUBSCRIBE` or
//!   `UNANNOUNCE` message to handle. Cancellation is a stream reset.
//! - A **data stream** is unidirectional and carries one subgroup.
//!
//! The practical consequence is that a request's lifetime *is* a stream's
//! lifetime, so each one gets a task and its cleanup lives in that task, rather
//! than in a table of outstanding requests that has to be reconciled on close.
//!
//! # Forwarding rewrites one field and copies the rest
//!
//! A track alias is assigned per session, so the alias a publisher writes into
//! its subgroup headers is meaningless to a subscriber that negotiated its own.
//! Rewriting it is the only edit a relay makes. Everything after the header —
//! object IDs, their delta encoding, payloads, properties — is copied through as
//! bytes.
//!
//! This is what keeps the relay compatible with end-to-end encryption. It also
//! means the relay does not need the object-level delta state machine at all,
//! which removes an entire class of desynchronisation bug from the fan-out path.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use bytes::{Buf, Bytes, BytesMut};
use moqom_proto::control::{
    ControlFrame, DoneReason, Fetch, FetchKind, FetchOk, MessageBody, MessageType, Namespace,
    NamespaceDone, Publish, PublishDone, PublishDoneStatus, PublishNamespace, ReasonPhrase,
    RequestError, RequestErrorCode, RequestId, RequestIdGenerator, RequestUpdate, Role, Setup,
    StreamCount, Subscribe, SubscribeNamespace, SubscribeOk, setup, write_message,
};
use moqom_proto::data::{
    FetchHeader, FetchRecord, FetchWriter, GroupOrder, SubgroupContent, SubgroupHeader,
    SubgroupObject, SubgroupReader, SubgroupSource, SubgroupWriter,
};
use moqom_proto::error::DecodeError;
use moqom_proto::model::{
    FetchEnd, FullTrackName, GroupId, Location, ObjectId, ObjectSeq, TrackAlias, TrackNamespace,
};
use moqom_proto::varint::VarInt;
use tokio::sync::{Notify, mpsc, oneshot, watch};
use web_transport_quinn::{RecvStream, SendStream};

use crate::fabric::{Command, Fabric, NamespaceEvent, Pulling, Route, SessionId, UpstreamError};
use crate::hops::Hops;
use crate::metrics::{Ending, Fetched, Flowing, Metrics, Subscribed};
use crate::policy::Silence;
use crate::quota::{Lease, Principal, Refusal, Resource};
use crate::roster::{Arrival, Departure};
use crate::scope::{Denial, Permission, Scope};
use crate::{cache, media, metrics, scope};

/// Identifies this build in Setup Options, for the other end's logs.
const IMPLEMENTATION: &[u8] = concat!("moqom-relay/", env!("CARGO_PKG_VERSION")).as_bytes();

/// Range filters a peer may have outstanding at once.
///
/// Zero — the default when the option is absent — means *none permitted*, so a
/// relay that does not send this rejects every range subscription it is asked
/// for. Announcing a real number is not optional.
const MAX_FILTER_RANGES: u64 = 64;

/// Why a session ended.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SessionError {
    /// The connection failed or was closed by the peer.
    #[error("transport: {0}")]
    Transport(#[from] web_transport_quinn::SessionError),

    /// A stream could not be written.
    #[error("write: {0}")]
    Write(#[from] web_transport_quinn::WriteError),

    /// A stream could not be read.
    #[error("read: {0}")]
    Read(#[from] web_transport_quinn::ReadError),

    /// A message did not decode.
    #[error("decode: {0}")]
    Decode(#[from] DecodeError),

    /// A message was well-formed but not allowed where it appeared.
    #[error("protocol violation: {0}")]
    Protocol(&'static str),

    /// The peer's SETUP broke a rule the specification makes mandatory.
    #[error("setup: {0}")]
    Setup(#[from] setup::SetupError),

    /// A stream ended in the middle of a message.
    #[error("stream ended mid-message")]
    Truncated,

    /// The peer offered a credential that did not verify.
    #[error("authentication: {0}")]
    Unauthenticated(#[from] crate::identity::AuthError),

    /// The peer is over the limit for something it cannot be refused piecemeal.
    ///
    /// Only a session itself: every other resource is refused with a
    /// `REQUEST_ERROR` on its own stream, which leaves the rest of the
    /// connection working. There is no smaller unit than the session to refuse
    /// when the session is what ran out.
    #[error("over limit: {0:?}")]
    OverLimit(Refusal),

    /// The credential this session was admitted on ran out, and was not renewed.
    ///
    /// Distinct from [`Self::Unauthenticated`], which is a token that never
    /// verified: this one did, and the session it opened outlived it. The
    /// difference matters to whoever reads the close reason, because the answer
    /// is different — a token that failed needs a correct one, and a token that
    /// lapsed needs a client that renews before it does.
    #[error("credential expired")]
    CredentialExpired,

    /// The token verified and the room will not have them.
    ///
    /// Separate from [`Self::Unauthenticated`] because the credential is fine
    /// and the answer is different: a client whose token failed should get a new
    /// one, and a client that is banned should stop. Separate from the
    /// authorisation denials in [`crate::scope`] because those refuse a request
    /// and this refuses the connection — there is no request a banned session
    /// could make that should succeed.
    #[error("refused: {0}")]
    Refused(#[from] crate::policy::Refusal),
}

impl Ending {
    /// Classify how a session finished, for the counter that says whether a
    /// spike of disconnections is the network's fault or the peer's.
    ///
    /// Deliberately has no catch-all arm. [`SessionError`] is `non_exhaustive`
    /// to other crates but not to this one, so adding a variant breaks this
    /// match — which is the point. A new failure silently folded into an
    /// existing bucket is a new failure nobody can see.
    fn of(result: &Result<(), SessionError>) -> Self {
        match result {
            Ok(()) => Self::Clean,
            // A peer that sent something illegal or unparseable broke the
            // protocol; that these are three variants is about how the error was
            // detected, not about whose fault it was.
            Err(SessionError::Protocol(_) | SessionError::Setup(_) | SessionError::Decode(_)) => {
                Self::Protocol
            }
            // A stream that stopped mid-message is a connection that went away,
            // not a peer that lied: the bytes it did send were well formed.
            Err(
                SessionError::Transport(_)
                | SessionError::Read(_)
                | SessionError::Write(_)
                | SessionError::Truncated,
            ) => Self::Transport,
            // A verified token refused by the room counts with the rejections:
            // both are this relay declining somebody, and the difference
            // between "who are you" and "not you" is carried by the refusal
            // counters rather than by this one.
            // A credential that lapsed counts here too, and it is the arm most
            // worth watching: a run of these is not people being turned away
            // but clients failing to renew, which looks like a network fault to
            // everybody experiencing it and like a rejection from here.
            Err(
                SessionError::Unauthenticated(_)
                | SessionError::Refused(_)
                | SessionError::CredentialExpired,
            ) => Self::Rejected,
            Err(SessionError::OverLimit(_)) => Self::Throttled,
        }
    }
}

impl Departure {
    /// Say why a session ended in the terms the control plane uses.
    ///
    /// Coarser than [`Ending`] on purpose: the control plane's question is
    /// whether to expect this person back, and every way of breaking a
    /// connection answers it the same way. No catch-all arm here either, for the
    /// same reason — a new variant should have to be classified rather than
    /// silently become a departure.
    ///
    /// Being ejected does not appear here and cannot: an ejected session sees a
    /// closed connection, exactly like one that lost the network. The roster
    /// substitutes it, because only the side that did the closing knows.
    fn of(result: &Result<(), SessionError>) -> Self {
        match result {
            Ok(()) => Self::Clean,
            Err(SessionError::Protocol(_) | SessionError::Setup(_) | SessionError::Decode(_)) => {
                Self::Protocol
            }
            // A lapsed credential belongs here rather than with the refusals,
            // and it is the one case where these two classifications genuinely
            // disagree. `Ending` calls it a rejection because this relay did the
            // closing; the room should expect them back, because a client whose
            // token ran out gets another one and reconnects inside the window.
            // Calling it `Protocol` would evict somebody who is already dialling
            // back, and the participant would vanish from the roster and
            // reappear rather than never having left.
            Err(
                SessionError::Transport(_)
                | SessionError::Read(_)
                | SessionError::Write(_)
                | SessionError::Truncated
                | SessionError::CredentialExpired,
            ) => Self::Lost,
            // Refused at the handshake, so never enrolled and never reported.
            // Classified rather than left to a catch-all so that this stays true
            // by construction if one of them ever moves later in the session.
            Err(
                SessionError::Unauthenticated(_)
                | SessionError::Refused(_)
                | SessionError::OverLimit(_),
            ) => Self::Protocol,
        }
    }
}

/// Application error codes this relay closes sessions with.
pub(crate) mod code {
    /// The peer did something the protocol forbids.
    pub const PROTOCOL_VIOLATION: u32 = 0x01;
    /// This relay failed, not the peer.
    pub const INTERNAL: u32 = 0x02;
    /// The peer's credential did not verify.
    pub const UNAUTHORIZED: u32 = 0x03;
    /// The peer is over its limit.
    ///
    /// Distinct from `UNAUTHORIZED` because the client's correct response is
    /// different and the difference matters at scale: a rejected credential
    /// should stop a client trying, and a limit should make it wait. A client
    /// that cannot tell them apart reconnects immediately in both cases, which
    /// turns a rate limit into a reconnect storm.
    pub const EXCESSIVE_LOAD: u32 = 0x04;
}

/// The track a relay pushes a participant's own restrictions to.
///
/// Reserved, like `.catalog` and `.control`, and named under the participant's
/// slot in the room rather than under their personal channel because that is
/// what it describes: the same person in another room is under other rules.
const POLICY_TRACK: &[u8] = b".policy";

/// Where to publish one session's restrictions, or `None` for a session with
/// no room to be restricted in.
///
/// Backstage is included and deliberately so: somebody muted in the queue must
/// arrive on stage still muted, and a name that only covered the stage would
/// let a promotion clear a mute.
fn policy_track(scope: &Scope) -> Option<FullTrackName> {
    let room = scope.room.as_ref()?;
    let marker: &str = if scope.backstage { "bs" } else { "r" };
    let namespace = TrackNamespace::from_parts([
        scope.tenant.as_bytes(),
        marker.as_bytes(),
        room.as_bytes(),
        scope.user.as_bytes(),
        scope.device.as_bytes(),
    ])
    .ok()?;
    FullTrackName::new(namespace, Bytes::from_static(POLICY_TRACK)).ok()
}

/// One object's worth of "here is what you may not publish".
///
/// JSON, matching the room's control log and the catalog, because the client
/// SDK already reads those with a `JSONDecoder` and a second encoding on a
/// third track would be a parser to maintain for one small message. The bit
/// values are `MediaKind`'s, shared by all three languages.
///
/// Absolute rather than a delta, and it carries both scopes even when one is
/// empty: a client that receives this knows the whole of its position, so a
/// lost object costs a moment of staleness rather than a permanent
/// disagreement about what is muted.
fn policy_payload(silence: Silence) -> Bytes {
    Bytes::from(format!(
        "{{\"version\":1,\"mutedForEveryone\":{},\"mutedForAudience\":{}}}",
        silence.everyone.bits(),
        silence.audience.bits()
    ))
}

/// Reads length-delimited control messages off a stream.
///
/// Framing is separate from interpretation because the two failures differ in
/// blast radius: a body that disagrees with its declared length has
/// desynchronised the stream and nothing after it can be trusted, whereas a body
/// that fails to parse is one message's problem. Everything this yields is a
/// complete frame, so callers only ever deal with the second kind.
struct Frames {
    stream: RecvStream,
    buffer: BytesMut,
    /// Set once the peer has finished the stream, so a subsequent short read is
    /// truncation rather than "wait for more".
    ended: bool,
}

impl Frames {
    fn new(stream: RecvStream) -> Self {
        Self {
            stream,
            buffer: BytesMut::new(),
            ended: false,
        }
    }

    /// The next complete frame, or `None` at a clean end of stream.
    async fn next(&mut self) -> Result<Option<ControlFrame>, SessionError> {
        loop {
            // Decode from a slice cursor rather than the buffer itself: a
            // partial frame must leave the buffer untouched, and advancing the
            // buffer would consume bytes a short read still needs.
            let mut cursor = &self.buffer[..];
            match ControlFrame::decode(&mut cursor) {
                Ok(frame) => {
                    let consumed = self.buffer.len() - cursor.remaining();
                    self.buffer.advance(consumed);
                    return Ok(Some(frame));
                }
                Err(DecodeError::Short { .. }) => {}
                Err(e) => return Err(e.into()),
            }

            if self.ended {
                return if self.buffer.is_empty() {
                    Ok(None)
                } else {
                    Err(SessionError::Truncated)
                };
            }
            self.fill().await?;
        }
    }

    /// The next frame, treating a clean end of stream as truncation.
    ///
    /// For the places where a message is required: SETUP, and the first message
    /// on a request stream.
    async fn expect(&mut self) -> Result<ControlFrame, SessionError> {
        self.next().await?.ok_or(SessionError::Truncated)
    }

    /// Read once, recording an end of stream.
    async fn fill(&mut self) -> Result<(), SessionError> {
        let mut chunk = [0u8; 4096];
        match self.stream.read(&mut chunk).await? {
            Some(0) | None => self.ended = true,
            Some(n) => self.buffer.extend_from_slice(&chunk[..n]),
        }
        Ok(())
    }

    /// Bytes already read but not yet consumed.
    fn take_buffered(&mut self) -> Bytes {
        self.buffer.split().freeze()
    }
}

/// Serialise a control message and write it.
async fn send<M: MessageBody>(stream: &mut SendStream, message: &M) -> Result<(), SessionError> {
    let mut buf = BytesMut::new();
    write_message(&mut buf, message).map_err(|_| SessionError::Protocol("message too long"))?;
    stream.write_all(&buf).await?;
    Ok(())
}

/// Where forwarded objects for one alias should go.
///
/// Keyed by the *upstream* alias — the number this session's peer writes into
/// its subgroup headers. A track can have several subscribers, hence the list.
type Routes = Arc<Mutex<HashMap<TrackAlias, Vec<Route>>>>;

/// The state of one track's upstream subscription. See [`Session::pulled`].
///
/// Two states rather than one because establishing a subscription is a round
/// trip, and a second subscriber routinely arrives inside it — a room where
/// four people join at once is four SUBSCRIBEs for one camera in the time the
/// first answer takes to come back. Without a pending state each of them would
/// find nothing, and the deduplication would be defeated by exactly the case it
/// is for.
#[derive(Clone)]
enum Pull {
    /// Being established. Waiters read the outcome from here.
    ///
    /// A `watch` rather than a `oneshot` because there may be any number of
    /// waiters, and rather than a `broadcast` because a late one must still see
    /// an answer that has already been sent.
    Pending(watch::Receiver<Option<Result<TrackAlias, UpstreamError>>>),
    /// Established, and carrying objects under this upstream alias.
    Ready(Upstream),
}

/// An upstream subscription that is running.
#[derive(Clone)]
struct Upstream {
    /// The alias the publisher writes in its subgroup headers.
    alias: TrackAlias,
    /// Raised to cancel the subscription when the last subscriber has gone.
    ///
    /// Cancelling means resetting the request stream the SUBSCRIBE was sent on,
    /// which is the whole of unsubscribing in this protocol — there is no
    /// message for it. Worth doing rather than leaving the pull running: a
    /// publisher on a phone is spending its uplink and its battery on this, and
    /// a room that empties should stop costing the person who left it.
    stop: Arc<Notify>,
}

/// What a new subscriber must do to start receiving a track, decided under the
/// [`Session::pulled`] lock and carried out after it is released.
enum Join {
    /// Attach to an established subscription.
    Existing(TrackAlias),
    /// Wait for somebody else's subscription to finish being established.
    Waiting(watch::Receiver<Option<Result<TrackAlias, UpstreamError>>>),
    /// Establish it, and tell the waiters how it went.
    Opening(watch::Sender<Option<Result<TrackAlias, UpstreamError>>>),
}

/// A live MOQT session with one peer.
///
/// Clonable and cheap to clone: everything shared is behind an `Arc`. The clones
/// exist so that per-stream tasks can outlive the accept loop that spawned them.
#[derive(Clone)]
pub struct Session {
    id: SessionId,
    transport: moqom_transport::Session,
    carrier: setup::Transport,
    fabric: Fabric,
    routes: Routes,
    /// Aliases handed to this peer, which must not collide with each other.
    next_alias: Arc<AtomicU64>,
    /// Request IDs for requests *this relay* originates on this session.
    ///
    /// Draft-19 §10.1 splits the space by role so the two ends can allocate
    /// without a round trip: a server's IDs are odd. Sharing one counter with
    /// the peer would collide on the first request each side sent, and the
    /// symptom would be a response matched to the wrong request.
    requests: Arc<Mutex<RequestIdGenerator>>,
    /// Reaches this session's own command loop.
    commands: mpsc::Sender<Command>,
    /// Which track each upstream alias carries, so forwarded objects can be
    /// attributed to a track name for the cache.
    ///
    /// Subgroup headers carry an alias and nothing else, and an alias is only
    /// meaningful within the session that assigned it — so without this a
    /// forwarded object cannot be filed anywhere a fetch could find it.
    ///
    /// The value is the track's [`Flowing`] record rather than its name because
    /// the two are wanted in the same place: the fan-out looks the alias up
    /// anyway, and noting that bytes arrived is then a store on something already
    /// in hand rather than a second lookup in a second map that could disagree
    /// with this one about which tracks exist.
    pulling: Arc<Mutex<HashMap<TrackAlias, Arc<Flowing>>>>,
    /// Which upstream subscription carries each track, so the second subscriber
    /// to a track joins the first one's rather than opening another.
    ///
    /// The saving this exists for is the reason a relay is worth running. A
    /// thousand viewers of one camera is one copy uphill and a thousand
    /// downhill; without this it was a thousand of each, and the publisher — a
    /// phone, on a domestic uplink — paid for every one of them. It also
    /// removes a denial of service that needed no bandwidth at all, since a
    /// subscriber could ask the relay to ask the publisher for the same track
    /// as many times as it liked.
    ///
    /// Keyed by track name rather than by namespace because that is the unit a
    /// subscription names: two viewers watching different rungs of one
    /// broadcast are two upstream subscriptions, correctly, and two watching
    /// the same rung are one.
    pulled: Arc<Mutex<HashMap<FullTrackName, Pull>>>,
    /// Tracks this peer has subscribed to, by the Request ID it used.
    ///
    /// A joining fetch names a subscription rather than a track, on purpose:
    /// deriving the range's end from the subscription is what makes the fetch and
    /// the subscription provably contiguous. Resolving that reference needs this.
    subscribed: Arc<Mutex<HashMap<RequestId, FullTrackName>>>,
    /// Who this session's limits are charged to.
    ///
    /// Written once, during SETUP, and read by every request afterwards. A
    /// `OnceLock` rather than a field because the identity is not known when the
    /// session is constructed — the token arrives in the handshake — and rather
    /// than a `Mutex<Option<_>>` because it genuinely is write-once: a peer that
    /// could change who it is mid-session could shed a limit by doing so.
    principal: Arc<OnceLock<Principal>>,

    /// What the token permitted, written beside the principal during SETUP.
    ///
    /// Separate from it for the same reason provenance is: a principal is a
    /// quota key, compared for equality to find a bucket, and a permission is
    /// not something anybody is charged for.
    permission: Arc<OnceLock<Permission>>,

    /// When the credential behind that permission lapses, and a way to be woken
    /// when it moves.
    ///
    /// A `watch` rather than a `Mutex<Option<_>>` because the reader wants both
    /// halves of what this type is: the current deadline, and notification that
    /// it changed. The watcher sleeps until the deadline it read and races that
    /// sleep against a change, so a renewal that arrives during the sleep pushes
    /// it out instead of being noticed a lifetime late.
    ///
    /// Mutable where [`Self::principal`] and [`Self::permission`] are write-once,
    /// and the asymmetry is the point. Who somebody is and what they may do must
    /// not change under an established session — a peer that could restate
    /// either would shed a quota bucket or a scope check. When their credential
    /// runs out is the one part a peer may legitimately move, and only forward,
    /// by presenting a fresh token for the same principal.
    ///
    /// `None` means nothing to enforce: a relay holding no keys, which
    /// authorises everything and has no expiry to hold anybody to.
    credential: watch::Sender<Option<SystemTime>>,

    /// Whose following brought this session, from the token's `via` claim.
    ///
    /// `Option` inside the `OnceLock` because "nobody brought them" is an
    /// answer and "SETUP has not happened yet" is not: collapsing the two would
    /// make an unset field look like a session that arrived on its own, and the
    /// count that comes out the other end is what a cohost is paid on.
    via: Arc<OnceLock<Option<Arc<str>>>>,

    /// Locale last reported from this session's catalog, so a restatement
    /// does not become a `SessionChanged`.
    locale: Arc<Mutex<Option<String>>>,

    /// Which group the next `.policy` object goes in.
    ///
    /// One group per change rather than one group with a growing object ID,
    /// because a group boundary is where a subscriber may join: a client that
    /// reconnects mid-mute wants the current state, and this way the current
    /// state is always the beginning of a group rather than the middle of one.
    policy_sequence: Arc<AtomicU64>,

    /// Which end of this session this relay is.
    ///
    /// Almost everything a session does is the same either way — the same streams
    /// carry the same messages and the fan-out does not care where bytes came from
    /// — so this is read in the few places where the difference is real: which end
    /// opens the control stream, which half of the SETUP exchange to perform, which
    /// parity of Request ID to allocate, and whether the peer is a participant to
    /// be reported to the control plane.
    facing: Facing,
}

/// Which end of a session this relay is.
///
/// A relay accepts sessions from clients and, when it is an edge, opens one to a
/// parent. The second is not a client of this relay and must not be treated as
/// one: it is where tracks come from rather than somebody watching them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Facing {
    /// A peer that connected to this relay: a publisher, a viewer, or a child
    /// relay. This relay is the server, and everything it has always done applies.
    Downstream,
    /// A parent relay this one connected to, to fetch tracks it does not hold.
    ///
    /// This relay is the client. Nothing here is charged against a quota, enrolled
    /// as a participant, or subject to the namespace grammar, because none of those
    /// describe a sibling in the fleet — the parent applies its own to us.
    Upstream,
}

/// Identity and carrier only. The rest is a connection, a lock, and channels,
/// none of which belong in a log line.
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("carrier", &self.carrier)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Run a session to completion.
    ///
    /// Performs the SETUP exchange, then serves streams until the peer goes
    /// away. Everything this session announced is withdrawn before returning,
    /// whether it ended cleanly or not.
    ///
    /// `carrier` decides which Setup Options are legal: PATH and AUTHORITY carry
    /// the `MoQ` URI, which a WebTransport session already has in its `CONNECT`
    /// URL, so receiving them there is a named session error rather than a
    /// redundancy to tolerate.
    ///
    /// # Errors
    /// [`SessionError`] if the handshake fails or the peer violates the
    /// protocol. A peer that simply disconnects is not an error.
    pub async fn serve(
        transport: moqom_transport::Session,
        carrier: moqom_transport::Carrier,
        fabric: Fabric,
    ) -> Result<(), SessionError> {
        let carrier = match carrier {
            moqom_transport::Carrier::Quic => setup::Transport::Quic,
            moqom_transport::Carrier::WebTransport => setup::Transport::WebTransport,
        };
        let id = fabric.next_session_id();
        let (commands, command_queue) = mpsc::channel(32);
        let session = Self {
            id,
            transport,
            carrier,
            fabric: fabric.clone(),
            routes: Routes::default(),
            next_alias: Arc::new(AtomicU64::new(0)),
            requests: Arc::new(Mutex::new(RequestIdGenerator::new(Role::Server))),
            commands,
            pulling: Arc::default(),
            pulled: Arc::default(),
            subscribed: Arc::default(),
            principal: Arc::default(),
            permission: Arc::default(),
            credential: watch::Sender::new(None),
            via: Arc::default(),
            locale: Arc::default(),
            policy_sequence: Arc::new(AtomicU64::new(0)),
            facing: Facing::Downstream,
        };

        let result = session.run(command_queue).await;
        fabric.remove_session(id);
        // Before the log line below, so that a relay reporting upstream says
        // somebody left at the same moment it says so locally. Harmless for a
        // session that was never enrolled, which is every session that failed
        // its handshake and every session on a relay with no keys.
        fabric.roster().release(id, Departure::of(&result));
        let ending = Ending::of(&result);
        fabric.metrics().session_ended(id, ending);
        // The one lifecycle event that was missing: a session that ends cleanly
        // used to leave no trace at all, so "did that publisher disconnect or
        // did we drop it" was unanswerable from the logs.
        tracing::info!(
            session = %id,
            outcome = ?ending,
            error = result.as_ref().err().map(tracing::field::display),
            "session ended"
        );

        match &result {
            Ok(()) => session.transport.close(0, b"bye"),
            Err(SessionError::Protocol(reason)) => session
                .transport
                .close(code::PROTOCOL_VIOLATION, reason.as_bytes()),
            Err(SessionError::Unauthenticated(e)) => session
                .transport
                .close(code::UNAUTHORIZED, e.name().as_bytes()),
            // The reason phrase is the one the moderator's tool will be asked
            // about, so it says which rule rather than merely "no".
            Err(SessionError::Refused(refusal)) => session
                .transport
                .close(code::UNAUTHORIZED, refusal.to_string().as_bytes()),
            // `UNAUTHORIZED` like the two above, because there is no separate
            // code for it, so the reason phrase is what tells a client which of
            // the three this was — and the right response differs: a credential
            // that never verified should stop a client, and one that merely got
            // old should send it back with a fresh token. Reconnecting with the
            // same token is the one thing that cannot work.
            Err(SessionError::CredentialExpired) => session.transport.close(
                code::UNAUTHORIZED,
                b"credential expired; renew and reconnect",
            ),
            // The retry-after goes in the close reason, since a session that is
            // being closed has no request stream left to carry it. A client that
            // reads it waits; one that does not is no worse off than before.
            Err(SessionError::OverLimit(refusal)) => session.transport.close(
                code::EXCESSIVE_LOAD,
                format!(
                    "{} retry_after_ms={}",
                    refusal.reason_phrase(),
                    refusal.retry_after_ms()
                )
                .as_bytes(),
            ),
            Err(_) => session.transport.close(code::INTERNAL, b"session failed"),
        }
        result
    }

    /// Run a session to a parent relay, so this one can serve tracks it does not
    /// hold.
    ///
    /// The mirror image of [`serve`](Self::serve): this relay opens the control
    /// stream and sends the first SETUP instead of waiting for one. Everything
    /// after the handshake is the same code, which is the point — an object
    /// arriving from a parent is forwarded, cached, deduplicated and shed by the
    /// machinery that already does that for an object arriving from a phone, and a
    /// second implementation of any of it would be a second set of bugs.
    ///
    /// Registers itself as the fabric's parent once the handshake completes, and
    /// withdraws on the way out, so a subscription arriving while the link is down
    /// is refused rather than queued against a session that is gone.
    ///
    /// `token`, when present, is offered to the parent as this relay's credential.
    /// The parent authenticates us exactly as it authenticates anybody: being a
    /// relay is not a way in.
    ///
    /// # Errors
    /// [`SessionError`] if the handshake fails or the parent violates the protocol.
    pub async fn attach(
        transport: moqom_transport::Session,
        fabric: Fabric,
        token: Option<&[u8]>,
    ) -> Result<(), SessionError> {
        let id = fabric.next_session_id();
        let (commands, command_queue) = mpsc::channel(32);
        let session = Self {
            id,
            transport,
            // Raw QUIC: an upstream link is relay to relay inside a fleet, with no
            // browser at either end to need WebTransport.
            carrier: setup::Transport::Quic,
            fabric: fabric.clone(),
            routes: Routes::default(),
            next_alias: Arc::new(AtomicU64::new(0)),
            // Client parity, because on this session that is what this relay is.
            // Sharing the server's parity with the parent would collide on the
            // first request either side sent.
            requests: Arc::new(Mutex::new(RequestIdGenerator::new(Role::Client))),
            commands,
            pulling: Arc::default(),
            pulled: Arc::default(),
            subscribed: Arc::default(),
            principal: Arc::default(),
            permission: Arc::default(),
            credential: watch::Sender::new(None),
            via: Arc::default(),
            locale: Arc::default(),
            policy_sequence: Arc::new(AtomicU64::new(0)),
            facing: Facing::Upstream,
        };

        let result = session.run_upstream(command_queue, token).await;
        fabric.remove_session(id);
        fabric.detach_upstream();
        let ending = Ending::of(&result);
        fabric.metrics().session_ended(id, ending);
        tracing::info!(
            session = %id,
            outcome = ?ending,
            error = result.as_ref().err().map(tracing::field::display),
            "upstream session ended"
        );
        match &result {
            Ok(()) => session.transport.close(0, b"bye"),
            Err(SessionError::Protocol(reason)) => session
                .transport
                .close(code::PROTOCOL_VIOLATION, reason.as_bytes()),
            Err(_) => session.transport.close(code::INTERNAL, b"session failed"),
        }
        result
    }

    /// Serve a session this relay opened, having introduced itself first.
    async fn run_upstream(
        &self,
        commands: mpsc::Receiver<Command>,
        token: Option<&[u8]>,
    ) -> Result<(), SessionError> {
        let (mut control_send, control_recv) = self.transport.open_bi().await?;
        let mut control = Frames::new(control_recv);
        self.introduce(&mut control_send, &mut control, token)
            .await?;

        // Available to subscribers only now. Published earlier, a subscription
        // could be handed to a session whose handshake was still in doubt, and a
        // refusal by the parent would arrive as a failure of this relay.
        self.fabric.attach_upstream(self.commands.clone());

        let peer = self.connection().remote_address();
        let live = self
            .fabric
            .metrics()
            .session_started(self.id, peer.to_string(), self.carrier);
        tracing::info!(session = %self.id, %peer, "attached to upstream relay");

        // Deliberately not `enrol()`. That reports a participant to the control
        // plane, and a parent relay is not one: enrolling it would put a
        // phantom member in every room this edge serves.
        tokio::select! {
            result = self.serve_control(control_send, control, commands) => result,
            result = self.accept_requests() => result,
            result = self.accept_data() => result,
            result = self.sample_transport(live.as_deref()) => result,
        }
    }

    /// Send our SETUP and read the parent's: the client half of the exchange.
    ///
    /// Charges nothing and authenticates nobody, which is the difference from
    /// [`handshake`](Self::handshake) beyond the order of the messages. A quota is
    /// something this relay imposes on peers that connect to it, and the parent is
    /// not one of those; the parent charges us, on its own side, by the token below.
    async fn introduce(
        &self,
        send_stream: &mut SendStream,
        control: &mut Frames,
        token: Option<&[u8]>,
    ) -> Result<(), SessionError> {
        let mut ours = Setup::new();
        ours.options
            .set_bytes(setup::option_type::MOQT_IMPLEMENTATION, IMPLEMENTATION)
            .map_err(|_| SessionError::Protocol("implementation string too long"))?;
        ours.options
            .set_varint(setup::option_type::MAX_FILTER_RANGES, MAX_FILTER_RANGES)
            .map_err(|_| SessionError::Protocol("filter range limit not encodable"))?;
        if let Some(token) = token {
            ours.options
                .set_bytes(
                    setup::option_type::AUTHORIZATION_TOKEN,
                    bytes::Bytes::copy_from_slice(token),
                )
                .map_err(|_| SessionError::Protocol("token too long for a setup option"))?;
        }
        send(send_stream, &ours).await?;

        let frame = control.expect().await?;
        if frame.message_type != MessageType::Setup {
            return Err(SessionError::Protocol(
                "first message from an upstream relay must be SETUP",
            ));
        }
        let mut body = frame.body.clone();
        let len = body.len();
        let peer = Setup::decode(&mut body, len)?;
        // The parent is the server on this session, so its options are held to the
        // server's rules -- the mirror of what `handshake` checks of a client.
        peer.validate(Role::Server, self.carrier)?;
        if let Some(implementation) = peer.options.moqt_implementation() {
            tracing::debug!(
                session = %self.id,
                peer = %String::from_utf8_lossy(implementation),
                "upstream implementation"
            );
        }
        Ok(())
    }

    /// This session's identifier within the relay.
    #[must_use]
    pub fn id(&self) -> SessionId {
        self.id
    }

    /// Which end of this session this relay is.
    #[must_use]
    pub const fn facing(&self) -> Facing {
        self.facing
    }

    /// How many tracks this session is currently forwarding, for diagnostics.
    #[must_use]
    pub fn forwarded_tracks(&self) -> usize {
        self.lock_routes().len()
    }

    /// The QUIC connection under the session.
    ///
    /// Reached through `Deref` rather than by holding a second handle.
    /// `web_transport_quinn::Session` has its own `stats` whose fields are
    /// private, so naming the target type is what selects the one with the
    /// numbers in it.
    fn connection(&self) -> &quinn::Connection {
        &self.transport
    }

    async fn run(&self, commands: mpsc::Receiver<Command>) -> Result<(), SessionError> {
        let (mut control_send, control_recv) = self.transport.accept_bi().await?;
        let mut control = Frames::new(control_recv);
        // Held for the rest of this function. Dropping it is what frees the
        // slot, and `run` returning is the one thing that happens on every path
        // out of a session.
        let _session = self.handshake(&mut control_send, &mut control).await?;

        // Enrolled only now, with the handshake complete: a session reported
        // upstream and then refused would have the control plane record a join
        // and a departure for somebody who never arrived, and a room's event
        // stream is a thing customers read.
        self.enrol();

        let peer = self.connection().remote_address();
        let live = self
            .fabric
            .metrics()
            .session_started(self.id, peer.to_string(), self.carrier);
        // Peer and session identifier together, once, at the point both are
        // known. Every later line carries the identifier alone, which is what
        // makes this the line that joins a connection to its address.
        tracing::info!(
            session = %self.id,
            %peer,
            carrier = ?self.carrier,
            "session established"
        );

        // Three loops rather than one `select!` over the accept futures: whether
        // `accept_bi` is cancel-safe is not something to bet a dropped stream
        // on, and separating them means each is only ever cancelled when the
        // session is already ending.
        //
        // The sampler is a fourth arm rather than a spawned task so that it is
        // cancelled by the same mechanism as everything else. A spawned sampler
        // would need its own shutdown signal, and the failure mode of getting
        // that wrong is a task per dead connection, polling a closed one
        // forever.
        // The credential watcher is a fifth arm for the same reason, and it is
        // the only one that ends a healthy session on purpose.
        tokio::select! {
            result = self.serve_control(control_send, control, commands) => result,
            result = self.accept_requests() => result,
            result = self.accept_data() => result,
            result = self.sample_transport(live.as_deref()) => result,
            result = self.outlive_credential() => result,
        }
    }

    /// End the session when its credential does, unless a renewal moves the
    /// deadline first.
    ///
    /// This is what makes a short token lifetime a property of the session
    /// rather than only of the handshake. Without it `exp` bounded the act of
    /// joining and nothing else: a stolen bearer token bought a connection that
    /// lasted as long as the thief kept it open, and since these tokens *are*
    /// bearer credentials, their short life was the only thing limiting the
    /// damage. It was being applied to the wrong event.
    ///
    /// Returns rather than closing the connection itself, so that expiry leaves
    /// by the same door as every other ending and is logged, counted and
    /// reported upstream by the code that already does that.
    ///
    /// Parks forever when there is no deadline, which is a relay holding no
    /// verification keys. Such a relay authorises everything, so there is
    /// nothing here to enforce and a session on it is never closed by this arm.
    async fn outlive_credential(&self) -> Result<(), SessionError> {
        let mut deadline = self.credential.subscribe();
        loop {
            // Read first, then wait for a change. `borrow_and_update` marks the
            // value seen, so a renewal that lands while this task is sleeping is
            // seen by the `changed()` below rather than missed — which is the
            // whole reason the deadline lives in a `watch` and not a mutex.
            let current = *deadline.borrow_and_update();

            let Some(until) = current else {
                if deadline.changed().await.is_err() {
                    return std::future::pending().await;
                }
                continue;
            };

            let remaining = until
                .duration_since(SystemTime::now())
                .unwrap_or(std::time::Duration::ZERO);

            tokio::select! {
                () = tokio::time::sleep(remaining) => {
                    // Re-read the clock rather than trusting the sleep. These
                    // are different clocks: the sleep is monotonic and the
                    // deadline is wall time, so a wall clock that stepped
                    // backwards during the sleep would otherwise expire a
                    // credential that has time left. Looping re-arms against
                    // whatever the deadline is now, and cannot spin, because a
                    // deadline already past yields a zero sleep and expires.
                    if SystemTime::now() >= until {
                        tracing::info!(
                            session = %self.id,
                            "credential expired without renewal, closing"
                        );
                        return Err(SessionError::CredentialExpired);
                    }
                }
                changed = deadline.changed() => if changed.is_err() {
                    return std::future::pending().await;
                },
            }
        }
    }

    /// Fold this connection's transport state into the metrics, forever.
    ///
    /// Never returns, so it never wins the `select!` it sits in. With metrics
    /// disabled it parks instead of spinning: there is nowhere to put a reading.
    async fn sample_transport(&self, live: Option<&metrics::Live>) -> Result<(), SessionError> {
        let Some(live) = live else {
            return std::future::pending().await;
        };

        let metrics = self.fabric.metrics();
        let mut previous = metrics::Sample::default();
        let mut blocked = (0u64, 0u64);
        let mut ticker = tokio::time::interval(metrics::SAMPLE_INTERVAL);
        // The first tick fires immediately, which would sample a connection that
        // has barely sent a packet. Skipping it costs one interval of history and
        // avoids seeding every RTT histogram with a handshake-time estimate.
        ticker.tick().await;

        loop {
            ticker.tick().await;
            let connection = self.connection();
            let stats = connection.stats();
            let current = metrics::Sample {
                rtt: connection.rtt(),
                cwnd: stats.path.cwnd,
                lost_packets: stats.path.lost_packets,
                congestion_events: stats.path.congestion_events,
                udp_tx_bytes: stats.udp_tx.bytes,
                udp_rx_bytes: stats.udp_rx.bytes,
                mtu: stats.path.current_mtu,
            };
            // Being blocked by a peer's flow control is not a counter anybody
            // watches, and it is the difference between "the network is slow" and
            // "we are waiting a round trip for credit we could have had". A
            // subscriber that reads slowly, or advertises a per-stream window
            // smaller than a group, stalls the forward mid-group and then lets it
            // burst — which arrives as judder rather than as loss, and looks from
            // the outside exactly like congestion it is not.
            //
            // Logged as a delta per interval rather than promoted to a metric
            // because it should normally be zero: a series that is always zero is
            // a scrape nobody reads, and a line in the log that appears the moment
            // it stops being zero is the thing that would have saved an evening.
            let stream_blocks = stats.frame_tx.stream_data_blocked - blocked.0;
            let data_blocks = stats.frame_tx.data_blocked - blocked.1;
            if stream_blocks > 0 || data_blocks > 0 {
                tracing::info!(
                    session = %self.id(),
                    stream_data_blocked = stream_blocks,
                    data_blocked = data_blocks,
                    "waiting on peer flow control"
                );
            }
            blocked = (
                stats.frame_tx.stream_data_blocked,
                stats.frame_tx.data_blocked,
            );

            metrics.sample(live, previous, current);
            metrics.forwarding(live, self.forwarded_tracks());
            previous = current;
        }
    }

    /// Exchange SETUP.
    ///
    /// The peer speaks first: it opened the stream, so it has already sent, and
    /// answering before reading would mean committing to options chosen without
    /// knowing what was asked for.
    async fn handshake(
        &self,
        send_stream: &mut SendStream,
        control: &mut Frames,
    ) -> Result<Lease, SessionError> {
        let frame = control.expect().await?;
        if frame.message_type != MessageType::Setup {
            return Err(SessionError::Protocol(
                "first message on the control stream must be SETUP",
            ));
        }

        let mut body = frame.body.clone();
        let len = body.len();
        let peer = Setup::decode(&mut body, len)?;
        peer.validate(Role::Client, self.carrier)?;

        self.establish_identity(&peer)?;

        // Charged before our SETUP goes out, not after. Answering and then
        // closing would tell the peer the session was established and take it
        // away in the same breath — and worse, a close can discard the stream
        // data that was still in flight, so the peer would see a connection that
        // vanished rather than one that said why.
        //
        // Held by the caller for the rest of the session; dropping it is what
        // frees the slot.
        let session = self
            .acquire(Resource::Session)
            .map_err(SessionError::OverLimit)?;

        if let Some(implementation) = peer.options.moqt_implementation() {
            tracing::debug!(
                session = %self.id,
                peer = %String::from_utf8_lossy(implementation),
                "peer implementation"
            );
        }

        let mut ours = Setup::new();
        ours.options
            .set_bytes(setup::option_type::MOQT_IMPLEMENTATION, IMPLEMENTATION)
            .map_err(|_| SessionError::Protocol("implementation string too long"))?;
        ours.options
            .set_varint(setup::option_type::MAX_FILTER_RANGES, MAX_FILTER_RANGES)
            .map_err(|_| SessionError::Protocol("filter range limit not encodable"))?;
        send(send_stream, &ours).await?;
        Ok(session)
    }

    /// Work out who this peer is, from the tokens it offered in SETUP.
    ///
    /// A token that fails to verify ends the session rather than downgrading it
    /// to anonymous. Downgrading would make a deliberately corrupt token the way
    /// to choose which tier you are limited under, and the address tier is the
    /// one an attacker behind a large NAT would rather share.
    ///
    /// Offering no token at all is different, and is allowed: the peer has not
    /// asserted anything, so it is charged by address and the deployment decides
    /// through [`crate::Quotas`] how far that gets it.
    fn establish_identity(&self, peer: &Setup) -> Result<(), SessionError> {
        let address = self.connection().remote_address().ip();
        let tokens: Vec<&[u8]> = peer
            .options
            .authorization_tokens()
            .map(bytes::Bytes::as_ref)
            .collect();
        let proof = peer.options.authorization_proof().map(bytes::Bytes::as_ref);

        let admitted = match self.fabric.authenticator().admit_presented(
            &tokens,
            proof,
            self.fabric.possession(),
            address,
            SystemTime::now(),
        ) {
            Ok(admitted) => admitted,
            Err(e) => {
                // Logged at info rather than warn: an expired token during a
                // reconnection is routine, and a relay that shouts about it
                // trains people to filter the category that also carries the
                // forgeries.
                tracing::info!(session = %self.id, %address, error = %e, "token refused");
                self.fabric.metrics().token_refused(e.name());
                return Err(SessionError::Unauthenticated(e));
            }
        };

        if admitted.who.is_verified() {
            tracing::debug!(session = %self.id, "session authenticated");
        }
        // Kept rather than only logged, now that there is somewhere for it to
        // go: the control-plane link reports it on the session, and the control
        // plane attributes the participant to whoever brought them.
        //
        // Deliberately not folded into the principal, which is a quota key: an
        // audience is not something anybody is charged for, and combining them
        // would hand each user one rate-limit bucket per route they arrived by.
        if let Some(via) = &admitted.via {
            tracing::debug!(session = %self.id, %via, "session was brought by somebody");
        }
        let deadline = admitted.deadline();
        let _ = self.via.set(admitted.via);
        // Only ever set once, and this is the only place that sets either. A
        // peer that could change who it is mid-session could shed a limit; one
        // that could change what it may do could shed the checks below.
        let _ = self.principal.set(admitted.who);
        let _ = self.permission.set(admitted.permission);
        // The expiry, on the other hand, is kept in something a renewal can
        // move. Enforcing it is what makes the token's short life mean anything
        // after the handshake; see `outlive_credential`.
        //
        // `send_replace` rather than `send`, and the difference is not cosmetic:
        // `send` fails when nothing is subscribed yet, and nothing is — the
        // watcher starts with the rest of the session, after this. It would
        // discard the deadline and report it in a `Result` that there is no
        // sensible way to handle here, which is exactly how this came to be
        // written once with the expiry silently never stored.
        self.credential.send_replace(deadline);

        self.admissible(address)
    }

    /// Take a renewed credential from a `REQUEST_UPDATE` and move the session's
    /// deadline out to match.
    ///
    /// The other half of [`Self::outlive_credential`], and neither is any use
    /// alone: enforcing an expiry without a way to renew would end every call at
    /// the token's lifetime, which for a ten-minute token is a ten-minute call.
    ///
    /// `REQUEST_UPDATE` is the carrier because draft-19 already defines it as
    /// one — an update overwrites parameters on a request that is established,
    /// and an authorization token is a parameter. There is no session-level
    /// message for this and inventing one was not available: the message
    /// registry here is the draft's, and an unknown type is required to close
    /// the session, so a private extension would be a code every other
    /// implementation must fail on. Any request stream will do, which matters
    /// because which streams a session has depends on what it is doing: a
    /// publisher renews on its announcement, a viewer on its namespace watch or
    /// on any subscription.
    ///
    /// Updates that carry no token are left alone. Most do not carry one — the
    /// message's ordinary job is re-prioritising a subscription — so a renewal is
    /// the exception here rather than the rule.
    ///
    /// A renewal this relay will not accept leaves the deadline alone and is
    /// logged. It does not end the session, and it does not end the stream it
    /// arrived on, which is the part worth being deliberate about: that stream is
    /// a publisher's announcement or a viewer's roster feed, and withdrawing a
    /// namespace because a token was stale would turn a recoverable client
    /// mistake into everybody in the room watching a still picture.
    ///
    /// Nor is the refusal silent, which was the alternative worry. The session
    /// carries on under the credential it already had and is closed when *that*
    /// runs out, with a close reason that says so — so a client whose renewals
    /// are being refused has until its current token expires to get one right,
    /// and finds out either way. There is nowhere better to put the denial: a
    /// `REQUEST_ERROR` on a subscription accepted ten minutes ago is a reply to a
    /// request the client has long since finished with.
    ///
    /// # Errors
    /// Only [`SessionError::Decode`], for a body that is not a `REQUEST_UPDATE`.
    /// That is a malformed message rather than a rejected credential, and it is
    /// handled where every other malformed message on a request stream is.
    fn renew_credential(&self, frame: &ControlFrame) -> Result<(), SessionError> {
        let update = RequestUpdate::decode(&mut frame.body.clone())?;
        let tokens: Vec<&[u8]> = update
            .parameters
            .authorization_tokens()
            .map(bytes::Bytes::as_ref)
            .collect();
        if tokens.is_empty() {
            return Ok(());
        }
        // Its own proof, not the one presented at setup. That proof commits to
        // the token it accompanied, so it says nothing about this one, and
        // accepting a renewal without a fresh proof would be a way to exchange a
        // proven credential for an unproven one — which is the whole guarantee,
        // undone by the mechanism that exists to keep sessions alive.
        let proof = update
            .parameters
            .authorization_proof()
            .map(bytes::Bytes::as_ref);

        let address = self.connection().remote_address().ip();
        let admitted = match self.fabric.authenticator().admit_presented(
            &tokens,
            proof,
            self.fabric.possession(),
            address,
            SystemTime::now(),
        ) {
            Ok(admitted) => admitted,
            Err(e) => {
                tracing::warn!(
                    session = %self.id,
                    error = %e,
                    "a renewed credential did not verify; the session keeps its old deadline"
                );
                self.fabric.metrics().token_refused(e.name());
                return Ok(());
            }
        };

        // Who they are and what they may do must survive a renewal unchanged.
        // Both are write-once on this session for good reasons — a principal is
        // the key a rate limit is charged against, and a permission is what
        // every announce and subscribe is checked against — so a token
        // disagreeing with either could not take effect even if it were
        // accepted. It would leave the relay enforcing one credential while
        // holding another, which is worse than refusing.
        //
        // So a promotion, a move between rooms, or a change of publishable media
        // needs a new session rather than a renewal. That is not a limitation
        // this adds: a mid-session change of powers already travels as a
        // directive from the control plane, and it does not travel in a token.
        if self.principal.get().is_some_and(|who| admitted.who != *who) {
            tracing::warn!(
                session = %self.id,
                "a renewed credential named a different holder; ignored"
            );
            return Ok(());
        }
        if self
            .permission
            .get()
            .is_some_and(|held| admitted.permission != *held)
        {
            tracing::warn!(
                session = %self.id,
                "a renewed credential carried a different scope; ignored"
            );
            return Ok(());
        }

        let deadline = admitted.deadline();
        // Forward only. A token with an earlier expiry than the one in hand is
        // accepted and changes nothing, rather than being refused: it is a
        // client renewing from a stale cache, which is a harmless mistake, and
        // it must not be able to shorten a session it is entitled to.
        self.credential.send_if_modified(|current| {
            match (*current, deadline) {
                (Some(held), Some(fresh)) if fresh <= held => false,
                // A keyless relay has nothing to enforce, and a renewal there
                // must not install a deadline out of nowhere.
                (_, None) => false,
                _ => {
                    *current = deadline;
                    true
                }
            }
        });
        tracing::debug!(session = %self.id, "credential renewed");
        Ok(())
    }

    /// Whether the room will have this session, as distinct from whether its
    /// token verified.
    ///
    /// The whole of ban enforcement against a *new* connection, and the reason
    /// it is three lines: everything expensive happened earlier, when the
    /// control plane sent the room's state. Asking it now — at the moment a
    /// phone is waiting to join — is the design this is arranged to avoid.
    fn admissible(&self, address: std::net::IpAddr) -> Result<(), SessionError> {
        let Permission::Scoped(scope) = self.permission() else {
            // Nothing to check against. Either no keys are configured, in which
            // case this relay authorises nothing and says so at startup, or the
            // token has not been verified yet — and no request is served in
            // that window.
            return Ok(());
        };
        let occupancy = scope.room.as_ref().map_or(0, |room| {
            self.fabric.roster().occupancy(&scope.tenant, room)
        });
        match self.fabric.policy().admits(scope, address, occupancy) {
            Ok(()) => Ok(()),
            Err(refusal) => {
                tracing::info!(
                    session = %self.id,
                    %address,
                    user = %scope.user,
                    room = scope.room.as_deref().unwrap_or("-"),
                    reason = refusal.name(),
                    "session refused by room policy"
                );
                self.fabric.metrics().policy_refused(refusal.name());
                Err(SessionError::Refused(refusal))
            }
        }
    }

    /// Put this session on the roster, so that it can be reported and reached.
    ///
    /// Silently does nothing for a session with no verified room, which is the
    /// correct amount of reporting about somebody the control plane cannot name.
    fn enrol(&self) {
        let Permission::Scoped(scope) = self.permission() else {
            return;
        };
        let via = self.via.get().cloned().flatten();
        self.fabric.roster().admit(
            self.id,
            scope,
            Arrival {
                address: self.connection().remote_address().ip(),
                via,
                transport: Arc::new(self.transport.clone()),
                commands: self.commands.clone(),
                credential: self.credential.subscribe(),
            },
        );

        // A mute outlives the session it was imposed on, so somebody rejoining
        // has to be told before they start their camera rather than after. The
        // policy already refuses subscriptions to what is muted; this is what
        // stops the phone spending its battery and its indicator light on a
        // track nobody will be allowed to watch.
        let silence = self.silence();
        if !silence.is_empty() {
            let session = self.clone();
            tokio::spawn(async move { session.tell_policy(silence).await });
        }
    }

    /// Whether a mute keeps this session from receiving `track`.
    ///
    /// Asked of the *publisher's* name and answered against *this* session's
    /// standing, which is the whole of the audience-only case: the same track,
    /// at the same moment, is withheld from a viewer and forwarded to a host.
    fn withheld(&self, track: &FullTrackName) -> bool {
        let Some(slot) = scope::slot(track.namespace()) else {
            return false;
        };
        let (Ok(tenant), Ok(room), Ok(user), Ok(device)) = (
            std::str::from_utf8(slot.tenant),
            std::str::from_utf8(slot.room),
            std::str::from_utf8(slot.user),
            std::str::from_utf8(slot.device),
        ) else {
            // A name this relay cannot read as text cannot be matched against a
            // mute the control plane wrote as text. It is also a name no client
            // of ours produces.
            return false;
        };

        let silence =
            self.fabric
                .policy()
                .silenced(&(Arc::from(tenant), Arc::from(room)), user, device);
        if silence.is_empty() {
            return false;
        }

        // A privileged subscriber hears through an audience mute. Read from the
        // roster rather than from this session's token so that it is the same
        // answer the fan-out gives when it drops routes, and there is only one
        // place to be wrong.
        let privileged = self
            .fabric
            .roster()
            .find(self.id)
            .is_some_and(|presence| presence.privileged());
        media::stopped(track.name(), silence.withheld_from(privileged))
    }

    /// What this session is currently forbidden to publish.
    ///
    /// Empty for a session with no verified room, which is every session on a
    /// relay that authorises nothing: there is nobody the control plane could
    /// have named in a mute.
    fn silence(&self) -> Silence {
        let Permission::Scoped(scope) = self.permission() else {
            return Silence::default();
        };
        let Some(room) = scope.room.as_ref() else {
            return Silence::default();
        };
        self.fabric.policy().silenced(
            &(Arc::clone(&scope.tenant), Arc::clone(room)),
            &scope.user,
            &scope.device,
        )
    }

    /// Who this session's requests are charged to.
    ///
    /// Falls back to the peer address, which covers the window before SETUP has
    /// completed and the case where no authenticator is configured. There is no
    /// path here that trusts an unverified claim: the fallback is derived from
    /// the connection, not from anything the peer said.
    fn principal(&self) -> &Principal {
        self.principal
            .get_or_init(|| Principal::anonymous(self.connection().remote_address().ip()))
    }

    /// What this session may publish and reach.
    ///
    /// The fallback covers a session that has somehow reached a request before
    /// SETUP wrote its permission, and it is chosen by the deployment rather
    /// than fixed: a relay with keys denies, because a request from a session
    /// whose token has not been read is exactly the case authorisation exists
    /// for, and a relay without them permits, because it has nothing to check
    /// against and refusing would leave it unable to relay at all.
    fn permission(&self) -> &Permission {
        self.permission.get_or_init(|| {
            if self.fabric.authenticator().is_enabled() {
                Permission::Nothing
            } else {
                Permission::Unrestricted
            }
        })
    }

    /// Turn a denial into the refusal that goes back on the request stream.
    ///
    /// Logged at `info` and counted, because this is the line an operator wants
    /// when somebody reports that a room will not start, and the series that
    /// says whether anybody is probing. Not at `warn`: a client still holding
    /// the token for the room it just left produces these routinely, and a
    /// level that cries wolf is one people filter.
    fn denied(&self, denial: Denial, what: &str, name: &TrackNamespace) -> RequestError {
        tracing::info!(
            session = %self.id,
            %name,
            request = what,
            reason = denial.name(),
            "request denied"
        );
        self.fabric.metrics().denied(denial.name());
        RequestError::new(denial.code(), ReasonPhrase::truncating(&denial.to_string()))
    }

    /// Take a slot held until the returned lease is dropped.
    ///
    /// Every request goes through here rather than some through
    /// [`crate::Governor::charge`], including the ones that finish immediately.
    /// A fetch holds nothing once it has been answered, but bounding how many
    /// are in flight bounds how much of the cache is being read at once, and
    /// that is worth having: the rate limit alone would let a client with a fast
    /// link start a hundred large fetches inside one second.
    fn acquire(&self, resource: Resource) -> Result<Lease, Refusal> {
        let outcome = self
            .fabric
            .governor()
            .acquire(self.principal(), resource, Instant::now());
        self.record(resource, outcome.as_ref().err());
        outcome
    }

    fn record(&self, resource: Resource, refusal: Option<&Refusal>) {
        match refusal {
            None => self.fabric.metrics().admitted(resource),
            Some(refusal) => {
                tracing::info!(
                    session = %self.id,
                    resource = resource.name(),
                    tier = refusal.tier.name(),
                    reason = refusal.reason.name(),
                    retry_after_ms = refusal.retry_after_ms(),
                    "request refused by the rate limiter"
                );
                self.fabric.metrics().refused(resource, refusal);
            }
        }
    }

    /// Watch the control stream, and act on requests from other sessions.
    ///
    /// `send_stream` is held rather than used: dropping a `SendStream` resets it,
    /// and resetting the control stream would end the session.
    async fn serve_control(
        &self,
        send_stream: SendStream,
        mut control: Frames,
        mut commands: mpsc::Receiver<Command>,
    ) -> Result<(), SessionError> {
        let _hold = send_stream;
        loop {
            tokio::select! {
                frame = control.next() => match frame? {
                    Some(frame) => self.on_control(&frame)?,
                    None => return Ok(()),
                },

                command = commands.recv() => match command {
                    // Unreachable while `self.commands` is alive, which it is
                    // for as long as this future is.
                    None => return Ok(()),
                    Some(command) => self.on_command(command),
                },
            }
        }
    }

    fn on_control(&self, frame: &ControlFrame) -> Result<(), SessionError> {
        match frame.message_type {
            // A peer that is going away stops sending requests; the session
            // ends when it closes the connection. Nothing to do but note it,
            // since this relay does not initiate the drain.
            MessageType::Goaway => {
                tracing::info!(session = %self.id, "peer sent GOAWAY");
                Ok(())
            }
            MessageType::Setup => Err(SessionError::Protocol("SETUP sent twice")),
            _ => Err(SessionError::Protocol(
                "only session-wide messages belong on the control stream",
            )),
        }
    }

    async fn accept_requests(&self) -> Result<(), SessionError> {
        loop {
            let (send_stream, recv) = self.transport.accept_bi().await?;
            let session = self.clone();
            tokio::spawn(async move { session.serve_request(send_stream, recv).await });
        }
    }

    async fn accept_data(&self) -> Result<(), SessionError> {
        loop {
            let recv = self.transport.accept_uni().await?;
            let session = self.clone();
            tokio::spawn(async move { session.forward_subgroup(recv).await });
        }
    }

    // MARK: - Requests from the peer

    /// Serve one request stream to its end.
    ///
    /// Errors are logged rather than propagated: a bad request is that request's
    /// problem, and tearing down the session over it would punish every other
    /// subscription on the connection.
    async fn serve_request(&self, mut send_stream: SendStream, recv: RecvStream) {
        let mut frames = Frames::new(recv);
        let frame = match frames.expect().await {
            Ok(frame) => frame,
            Err(e) => {
                tracing::debug!(session = %self.id, error = %e, "request stream failed");
                return;
            }
        };

        let resource = match frame.message_type {
            MessageType::PublishNamespace => Resource::Announcement,
            MessageType::SubscribeNamespace => Resource::Watch,
            MessageType::Subscribe => Resource::Subscription,
            MessageType::Fetch => Resource::Fetch,
            other => {
                tracing::debug!(session = %self.id, ?other, "unsupported request");
                let outcome = send(
                    &mut send_stream,
                    &RequestError::new(
                        RequestErrorCode::NOT_SUPPORTED,
                        ReasonPhrase::truncating("this relay does not serve that request"),
                    ),
                )
                .await;
                if let Err(e) = outcome {
                    tracing::debug!(session = %self.id, error = %e, "request failed");
                }
                let _ = send_stream.finish();
                return;
            }
        };

        // Charged here rather than inside each handler, so a request type added
        // later is limited by default instead of by remembering. The lease is
        // held for the life of this task, which for an announcement and a watch
        // is exactly the life of the thing they hold — both of those handlers
        // return only when their stream ends, and the stream ending *is* the
        // withdrawal. A subscription outlives its request stream, so
        // `on_subscribe` takes the lease over.
        let lease = match self.acquire(resource) {
            Ok(lease) => lease,
            Err(refusal) => {
                let outcome = send(
                    &mut send_stream,
                    &RequestError::retryable(
                        RequestErrorCode::EXCESSIVE_LOAD,
                        ReasonPhrase::truncating(&refusal.reason_phrase()),
                        refusal.retry_after_ms(),
                    )
                    .unwrap_or_else(|_| {
                        RequestError::new(
                            RequestErrorCode::EXCESSIVE_LOAD,
                            ReasonPhrase::truncating(&refusal.reason_phrase()),
                        )
                    }),
                )
                .await;
                if let Err(e) = outcome {
                    tracing::debug!(session = %self.id, error = %e, "refusal not delivered");
                }
                let _ = send_stream.finish();
                return;
            }
        };

        let outcome = match frame.message_type {
            MessageType::PublishNamespace => {
                self.on_publish_namespace(&frame, &mut send_stream, &mut frames)
                    .await
            }
            MessageType::SubscribeNamespace => {
                self.on_subscribe_namespace(&frame, &mut send_stream, &mut frames)
                    .await
            }
            MessageType::Subscribe => {
                self.on_subscribe(&frame, &mut send_stream, &mut frames, lease)
                    .await
            }
            _ => self.on_fetch(&frame, &mut send_stream).await,
        };

        if let Err(e) = outcome {
            tracing::debug!(session = %self.id, error = %e, "request failed");
        }
        let _ = send_stream.finish();
    }

    /// Register an announcement, and hold it for as long as the stream lives.
    ///
    /// There is no `UNANNOUNCE`: the advertisement lasts exactly as long as the
    /// stream it arrived on, so withdrawing it means waiting for that stream to
    /// end. Reading the next frame is how this task waits — and anything that
    /// actually arrives is a protocol error, since the publisher has nothing
    /// further to say here.
    async fn on_publish_namespace(
        &self,
        frame: &ControlFrame,
        send_stream: &mut SendStream,
        frames: &mut Frames,
    ) -> Result<(), SessionError> {
        let request = PublishNamespace::decode(&mut frame.body.clone())?;

        // Before the fabric hears about it. An announcement is what makes this
        // session the publisher of a name, and a name claimed by the wrong
        // session is not undone by refusing the subscriptions afterwards: the
        // rightful publisher's own announcement is the one that then fails.
        if let Err(denial) = self.permission().may_announce(&request.namespace) {
            let refusal = self.denied(denial, "publish_namespace", &request.namespace);
            return send(send_stream, &refusal).await;
        }

        tracing::info!(
            session = %self.id,
            namespace = %request.namespace,
            "namespace announced"
        );
        self.fabric.metrics().announced();
        self.fabric
            .announce(self.id, request.namespace.clone(), self.commands.clone());

        // How this stream ends is how the withdrawal is characterised, and it is
        // the only place the difference is observable. A `FIN` is the publisher
        // withdrawing on purpose -- draft-19 has no `UNANNOUNCE`, so closing
        // this stream *is* the withdrawal. Anything else is the announcement
        // outliving the thing that made it.
        //
        // A loop rather than a single read because a credential renewal arrives
        // here too, and must not be mistaken for the end of the announcement: a
        // publisher's announcement is its longest-lived stream, so it is the
        // natural place for it to renew, and reading one frame and stopping
        // would have withdrawn the namespace on the first attempt.
        let (result, reason) = loop {
            match frames.next().await {
                Ok(None) => break (Ok(()), DoneReason::Stopped),
                Ok(Some(frame)) if frame.message_type == MessageType::RequestUpdate => {
                    if let Err(e) = self.renew_credential(&frame) {
                        break (Err(e), DoneReason::Vanished);
                    }
                }
                Ok(Some(_)) => {
                    break (
                        Err(SessionError::Protocol(
                            "unexpected message on a PUBLISH_NAMESPACE stream",
                        )),
                        DoneReason::Vanished,
                    );
                }
                Err(e) => break (Err(e), DoneReason::Vanished),
            }
        };

        tracing::info!(
            session = %self.id,
            namespace = %request.namespace,
            reason = ?reason,
            "namespace withdrawn"
        );
        self.fabric.withdraw(self.id, &request.namespace, reason);
        result
    }

    /// Report matching namespaces, now and as they change.
    ///
    /// Answers carry only the fields *after* the requested prefix. Sending a
    /// whole namespace instead would decode without complaint and resolve to the
    /// wrong name, since nothing in the bytes distinguishes the two.
    async fn on_subscribe_namespace(
        &self,
        frame: &ControlFrame,
        send_stream: &mut SendStream,
        frames: &mut Frames,
    ) -> Result<(), SessionError> {
        let request = SubscribeNamespace::decode(&mut frame.body.clone())?;
        let prefix = request.prefix.clone();

        // A watch is how a client learns who is in a room, so a prefix reaching
        // past what this token covers would answer with a roster it may not
        // have -- names, devices, and the fact that the room exists at all.
        if let Err(denial) = self.permission().may_read(&prefix) {
            let refusal = self.denied(denial, "subscribe_namespace", &prefix);
            return send(send_stream, &refusal).await;
        }

        let (existing, mut events) = self.fabric.watch(self.id, prefix.clone());
        tracing::info!(session = %self.id, %prefix, "watching namespaces");

        for namespace in existing {
            if let Some(suffix) = suffix_of(&namespace, &prefix) {
                send(send_stream, &Namespace::new(suffix)).await?;
            }
        }

        let result = loop {
            tokio::select! {
                event = events.recv() => match event {
                    None => break Ok(()),
                    Some(NamespaceEvent::Available(namespace)) => {
                        if let Some(suffix) = suffix_of(&namespace, &prefix) {
                            send(send_stream, &Namespace::new(suffix)).await?;
                        }
                    }
                    Some(NamespaceEvent::Gone(namespace, reason)) => {
                        if let Some(suffix) = suffix_of(&namespace, &prefix) {
                            send(send_stream, &NamespaceDone::because(suffix, reason)).await?;
                        }
                    }
                },

                // The peer closing the stream withdraws the watch, and this is
                // the only place that close is observable.
                frame = frames.next() => match frame {
                    Ok(None) => break Ok(()),
                    // The likeliest place a renewal arrives, because this is the
                    // stream a session is likeliest to have: every participant
                    // watches a namespace to learn who else is in the room,
                    // whether or not it publishes or subscribes to anything.
                    Ok(Some(frame)) if frame.message_type == MessageType::RequestUpdate => {
                        if let Err(e) = self.renew_credential(&frame) {
                            break Err(e);
                        }
                    }
                    Ok(Some(_)) => break Err(SessionError::Protocol(
                        "unexpected message on a SUBSCRIBE_NAMESPACE stream",
                    )),
                    Err(e) => break Err(e),
                },
            }
        };

        self.fabric.unwatch(self.id, &prefix);
        result
    }

    /// Satisfy a subscription by pulling the track from whoever publishes it.
    ///
    /// The upstream subscription is established *before* answering, so a
    /// `SUBSCRIBE_OK` means objects are actually coming. Answering
    /// optimistically and failing afterwards would leave the subscriber waiting
    /// on a track that was never going to arrive, with no error to explain it.
    ///
    /// Then this call stays for the life of the subscription, because the
    /// request stream does: there is no UNSUBSCRIBE message in this protocol,
    /// so the subscriber closing the stream is the only way it can say it has
    /// stopped watching, and something has to be here to hear it.
    async fn on_subscribe(
        &self,
        frame: &ControlFrame,
        send_stream: &mut SendStream,
        frames: &mut Frames,
        slot: Lease,
    ) -> Result<(), SessionError> {
        let request = Subscribe::decode(&mut frame.body.clone())?;
        let track = request.track.clone();

        // Before the publisher is looked up, so that a refusal cannot be told
        // apart from a namespace nobody publishes. The two answers are
        // different codes and the difference is worth hiding: it is how a peer
        // would map which rooms exist by subscribing to guesses.
        if let Err(denial) = self.permission().may_read(track.namespace()) {
            let refusal = self.denied(denial, "subscribe", track.namespace());
            self.fabric.metrics().subscribed(Subscribed::Refused);
            return send(send_stream, &refusal).await;
        }

        // After the token and before the publisher, for the same reason: a
        // muted track and a track nobody publishes must be indistinguishable
        // from outside, or subscribing to guesses becomes a way to read the
        // moderation log of a room.
        if self.withheld(&track) {
            tracing::info!(session = %self.id, %track, "subscription refused: force-muted");
            self.fabric.metrics().subscribed(Subscribed::Refused);
            return send(
                send_stream,
                &RequestError::new(
                    RequestErrorCode::DOES_NOT_EXIST,
                    ReasonPhrase::truncating("namespace is not published here"),
                ),
            )
            .await;
        }

        // How many further relays may be asked, spent one per hop. Absent on a
        // subscription from a viewer, which is what starts a fresh budget; present
        // on one from a child relay, which is what makes a cycle terminate.
        let hops = Hops::asked_for(&request.parameters);

        // Nothing local, so ask the parent -- an edge fetching a track it does not
        // have is the whole of what makes a fan-out tree possible. A relay with no
        // parent, or one whose budget is spent, answers as it always did.
        let publisher = self.fabric.publisher(track.namespace()).or_else(|| {
            let upstream = self.fabric.upstream().filter(|_| hops.may_forward())?;
            tracing::debug!(
                session = %self.id,
                %track,
                remaining = hops.remaining(),
                "no local publisher; asking upstream"
            );
            Some(upstream)
        });

        let Some(publisher) = publisher else {
            tracing::debug!(session = %self.id, %track, "no publisher for namespace");
            self.fabric.metrics().subscribed(Subscribed::NoPublisher);
            return send(
                send_stream,
                &RequestError::new(
                    RequestErrorCode::DOES_NOT_EXIST,
                    ReasonPhrase::truncating("namespace is not published here"),
                ),
            )
            .await;
        };

        let alias = self.allocate_alias();
        let route = Route::new(self.transport.clone(), self.id, alias);
        let ending = Arc::clone(&route.done);
        let streams = Arc::clone(&route.streams);
        let (ready, answered) = oneshot::channel();
        let command = Command::Subscribe {
            track: track.clone(),
            route: Box::new(route),
            hops,
            ready,
        };

        // A closed channel or a dropped `ready` both mean the publisher session
        // ended between the lookup and now. That is a race, not a bug, and the
        // subscriber needs the same answer either way.
        let upstream = match publisher.send(command).await {
            Err(_) => Err(UpstreamError::unavailable()),
            Ok(()) => answered
                .await
                .unwrap_or_else(|_| Err(UpstreamError::unavailable())),
        };

        match upstream {
            Ok(pulling) => {
                tracing::info!(session = %self.id, %track, %alias, "subscription established");
                self.fabric.metrics().subscribed(if pulling.shared {
                    Subscribed::Shared
                } else {
                    Subscribed::Established
                });
                // Recorded only once established, so a joining fetch cannot name
                // a subscription that was refused.
                self.lock_subscribed()
                    .insert(request.request_id, track.clone());
                send(send_stream, &SubscribeOk::new(alias)).await?;

                // `slot` is held rather than stored, now that the subscription
                // and its request stream end together: the limit counts
                // subscriptions because this call lasts as long as one.
                let outcome = self.hold(send_stream, frames, &ending, &streams).await;
                drop(slot);

                self.lock_subscribed().remove(&request.request_id);
                self.release(&track, pulling.upstream, alias).await;
                outcome
            }
            Err(e) => {
                tracing::debug!(session = %self.id, %track, error = %e, "upstream refused");
                self.fabric.metrics().subscribed(Subscribed::Refused);
                send(
                    send_stream,
                    &RequestError::new(e.code, ReasonPhrase::truncating(&e.reason)),
                )
                .await
            }
        }
    }

    /// Stay with a subscription until one end or the other finishes it.
    ///
    /// Two ways out, and they are not symmetrical. The subscriber closing its
    /// request stream needs no reply — it has stopped listening, that being
    /// what closing means. The track ending does: objects merely stopping is
    /// indistinguishable from a network that has gone quiet, and the two call
    /// for opposite responses from a player, so `PUBLISH_DONE` is what turns a
    /// stall into news.
    async fn hold(
        &self,
        send_stream: &mut SendStream,
        frames: &mut Frames,
        ending: &Notify,
        streams: &AtomicU64,
    ) -> Result<(), SessionError> {
        loop {
            tokio::select! {
                () = ending.notified() => {
                    // Read after the pull has stopped, so nothing can open
                    // another stream under it and the count is final rather
                    // than merely recent — which is the whole use of it: a
                    // subscriber counts arrivals against this to know whether
                    // it has everything or is still owed a stream in flight.
                    let sent = streams.load(Ordering::Relaxed);
                    let mut done = PublishDone::new(
                        PublishDoneStatus::TRACK_ENDED,
                        StreamCount::Exact(sent),
                    );
                    done.reason = ReasonPhrase::truncating("publisher stopped the track");
                    return send(send_stream, &done).await;
                }

                frame = frames.next() => match frame {
                    // How unsubscribe is spelled. There is no message for it.
                    Ok(None) => return Ok(()),
                    // A subscriber may re-prioritise a subscription it holds, or
                    // renew the session's credential. Nothing here acts on
                    // priorities yet, and answering a hint by tearing down the
                    // session it was sent on would be a wildly disproportionate
                    // way to say so.
                    Ok(Some(frame)) if frame.message_type == MessageType::RequestUpdate => {
                        self.renew_credential(&frame)?;
                    }
                    Ok(Some(_)) => return Err(SessionError::Protocol(
                        "unexpected message on a SUBSCRIBE stream",
                    )),
                    Err(e) => return Err(e),
                },
            }
        }
    }

    /// Tell the publisher's session that this subscriber has stopped watching.
    ///
    /// Best-effort by nature: every reason the publisher might not hear this is
    /// a reason it no longer needs to. A session that has ended has already let
    /// go of every route it held.
    async fn release(&self, track: &FullTrackName, upstream: TrackAlias, downstream: TrackAlias) {
        let Some(publisher) = self.fabric.publisher(track.namespace()) else {
            return;
        };
        let released = Command::Release {
            track: track.clone(),
            upstream,
            subscriber: self.id,
            downstream,
        };
        let _ = publisher.send(released).await;
    }

    /// Answer a fetch from retained history.
    ///
    /// `FETCH_OK` reports the range that will *actually* be delivered, which is
    /// where a request asking for more than exists gets clipped to reality — so it
    /// cannot be sent until the answer is known. The objects then go out on their
    /// own unidirectional stream, which is why this looks like a subscription in
    /// reverse: the response arrives on the request stream and the media does not.
    async fn on_fetch(
        &self,
        frame: &ControlFrame,
        send_stream: &mut SendStream,
    ) -> Result<(), SessionError> {
        let request = Fetch::decode(&mut frame.body.clone())?;
        let cache = self.fabric.cache();

        let refuse = |code, reason: &str| RequestError::new(code, ReasonPhrase::truncating(reason));

        let Some((track, start, end)) = self.resolve_fetch(&request.kind) else {
            tracing::debug!(session = %self.id, "fetch names something this relay cannot resolve");
            self.fabric.metrics().fetched(Fetched::Unresolvable, 0);
            return send(
                send_stream,
                &refuse(
                    RequestErrorCode::DOES_NOT_EXIST,
                    "no such track or subscription here",
                ),
            )
            .await;
        };

        // Checked although a joining fetch can only name a subscription that
        // was authorised when it was made. The standalone kind names a track
        // directly, and the cache holds objects from every room on the relay --
        // so this is the difference between history being private and history
        // being readable by anyone who can guess a name.
        if let Err(denial) = self.permission().may_read(track.namespace()) {
            let refusal = self.denied(denial, "fetch", track.namespace());
            self.fabric.metrics().fetched(Fetched::Unresolvable, 0);
            return send(send_stream, &refusal).await;
        }

        let order = GroupOrder::Ascending;
        let records = cache.fetch(&track, start, end, order);
        if records.is_empty() {
            // Nothing to say about this range, which is different from saying the
            // range is empty. An empty stream would be read as "these objects do
            // not exist" and stop the client asking anyone else.
            tracing::debug!(session = %self.id, %track, "no retained history for this range");
            self.fabric.metrics().fetched(Fetched::NoHistory, 0);
            return send(
                send_stream,
                &refuse(
                    RequestErrorCode::DOES_NOT_EXIST,
                    "no retained history for that range",
                ),
            )
            .await;
        }

        // The delivered end, not the requested one: the furthest location this
        // answer reaches, plus one. Taken as a maximum rather than as the last
        // record, because under descending order the last record is the *lowest*
        // location on the stream.
        let reached = records
            .iter()
            .map(FetchRecord::location)
            .max()
            .unwrap_or(Location::ZERO);
        let Some(wire_end) = FetchEnd::Through(reached).wire() else {
            self.fabric.metrics().fetched(Fetched::Unnameable, 0);
            return send(
                send_stream,
                &refuse(RequestErrorCode::INTERNAL_ERROR, "range end is unnameable"),
            )
            .await;
        };

        send(send_stream, &FetchOk::new(wire_end)).await?;

        let count = records.len();
        self.fabric.metrics().fetched(Fetched::Served, count);
        let request_id = request.request_id;
        let session = self.clone();
        // Spawned so the request stream is free to carry a cancellation while the
        // objects are still going out. A fetch of several groups is a lot of
        // bytes, and holding this task on the write would make the cancel
        // unreadable until the write it is trying to cancel had finished.
        tokio::spawn(async move {
            if let Err(e) = session.write_fetch(request_id, &records, order).await {
                tracing::debug!(session = %session.id, error = %e, "fetch delivery failed");
            } else {
                tracing::info!(session = %session.id, objects = count, "fetch delivered");
            }
        });
        Ok(())
    }

    /// What a fetch is asking for, as a track and a range.
    ///
    /// The joining forms name a subscription instead of a track, and their range
    /// ends at that subscription's live edge — which the *publisher* has to
    /// compute, because a client working it out locally would be racing the edge
    /// it is trying to meet.
    fn resolve_fetch(&self, kind: &FetchKind) -> Option<(FullTrackName, Location, FetchEnd)> {
        match kind {
            FetchKind::Standalone { track, start, end } => {
                Some((track.clone(), *start, FetchEnd::from_wire(*end)))
            }

            FetchKind::RelativeJoining {
                request_id,
                preceding_groups,
            } => {
                let track = self.lock_subscribed().get(request_id).cloned()?;
                // A subscription starts at the *next* group, so the group in
                // progress is the first one it will not deliver. Counting back
                // from there is what makes the fetch and the subscription
                // contiguous with neither a gap nor an overlap.
                let live = self.fabric.cache().largest(&track)?;
                let first = live.group.get().saturating_sub(preceding_groups.get());
                let start = Location::new(
                    GroupId::new(VarInt::new(first).unwrap_or(VarInt::ZERO)),
                    ObjectId::ZERO,
                );
                Some((track, start, FetchEnd::Through(live)))
            }

            FetchKind::AbsoluteJoining {
                request_id,
                start_group,
            } => {
                let track = self.lock_subscribed().get(request_id).cloned()?;
                let live = self.fabric.cache().largest(&track)?;
                let start = Location::new(GroupId::new(*start_group), ObjectId::ZERO);
                Some((track, start, FetchEnd::Through(live)))
            }
        }
    }

    /// Write a fetch's objects on their own unidirectional stream.
    async fn write_fetch(
        &self,
        request_id: RequestId,
        records: &[FetchRecord],
        order: GroupOrder,
    ) -> Result<(), SessionError> {
        let mut stream = self.transport.open_uni().await?;
        let mut buf = BytesMut::new();
        FetchHeader::new(request_id).encode(&mut buf);

        let mut writer = FetchWriter::new(order);
        for record in records {
            // A refusal here means the cache produced records out of order, which
            // is this relay's bug rather than the peer's. Sending a partial stream
            // is still the better outcome: the client can tell where it stopped.
            if let Err(e) = writer.write(&mut buf, record) {
                tracing::warn!(session = %self.id, error = %e, "cache produced an unorderable answer");
                break;
            }
        }

        stream.write_all(&buf).await?;
        let _ = stream.finish();
        Ok(())
    }

    // MARK: - Requests to the peer

    fn on_command(&self, command: Command) {
        match command {
            Command::Subscribe {
                track,
                route,
                hops,
                ready,
            } => self.pull(track, route, hops, ready),
            Command::Release {
                track,
                upstream,
                subscriber,
                downstream,
            } => self.release_route(&track, upstream, subscriber, downstream),
            Command::Restrict { silence } => self.restrict(silence),
        }
    }

    // MARK: - Mutes

    /// Stop publishing what a moderator has forbidden, and say so.
    ///
    /// Three things happen, in this order, and the order is the point.
    ///
    /// The relay stops *asking* for the muted tracks first, because that is
    /// the part it can guarantee: cancelling the upstream subscription means
    /// no further object reaches anybody, whatever the peer does next. Then
    /// the routes belonging to subscribers who are no longer entitled to the
    /// track are dropped, which is what makes an audience-only mute do
    /// anything. Only then is the peer told, because telling it is a request
    /// rather than an enforcement — a client that ignores `.policy` is muted
    /// exactly as thoroughly as one that obeys it, and the difference is
    /// whether the indicator light on the phone goes out.
    fn restrict(&self, silence: Silence) {
        let stopped = self.stop_muted_pulls(silence.everyone);
        let dropped = self.drop_withheld_routes(silence);
        tracing::info!(
            session = %self.id,
            everyone = %silence.everyone,
            audience = %silence.audience,
            tracks = stopped,
            routes = dropped,
            "mute applied"
        );
        self.fabric.metrics().muted();

        let session = self.clone();
        tokio::spawn(async move { session.tell_policy(silence).await });
    }

    /// Cancel every upstream subscription a mute stops, and report how many.
    ///
    /// Cancelling rather than filtering as objects arrive. A relay that pulled
    /// a muted camera and dropped the frames would still have the phone
    /// encoding and sending them, which is the battery, the uplink and the
    /// indicator light all still running for something nobody may watch.
    fn stop_muted_pulls(&self, muted: media::Kinds) -> usize {
        if muted.is_empty() {
            return 0;
        }
        let stopping: Vec<Arc<Notify>> = self
            .lock_pulled()
            .iter()
            .filter(|(track, _)| media::stopped(track.name(), muted))
            .filter_map(|(_, pull)| match pull {
                Pull::Ready(upstream) => Some(Arc::clone(&upstream.stop)),
                // Not yet established. The subscription that is being set up
                // will find the mute when it checks, and a `Pending` entry has
                // nothing to cancel.
                Pull::Pending(_) => None,
            })
            .collect();

        for stop in &stopping {
            stop.notify_waiters();
        }
        stopping.len()
    }

    /// Drop the routes a mute withholds, and report how many.
    ///
    /// A subscriber that keeps its subscription open would otherwise keep
    /// receiving from an upstream pull that the everyone-mute did not stop,
    /// which is the whole of the audience-only case: the track is still
    /// flowing, for the hosts, and the audience must stop being a copy of it.
    fn drop_withheld_routes(&self, silence: Silence) -> usize {
        if silence.is_empty() {
            return 0;
        }

        let mut dropped = 0;
        let pulling = self.lock_pulling();
        let mut routes = self.lock_routes();
        for (alias, destinations) in routes.iter_mut() {
            let Some(flowing) = pulling.get(alias) else {
                continue;
            };
            if media::classify(flowing.track.name()).is_none() {
                continue;
            }
            destinations.retain(|route| {
                let privileged = self
                    .fabric
                    .roster()
                    .find(route.subscriber)
                    .is_some_and(|presence| presence.privileged());
                let withheld = silence.withheld_from(privileged);
                if media::stopped(flowing.track.name(), withheld) {
                    // Closed rather than merely forgotten, so the subscriber
                    // learns its subscription is over instead of watching a
                    // track that has quietly stopped arriving.
                    route.done.notify_waiters();
                    dropped += 1;
                    false
                } else {
                    true
                }
            });
        }
        dropped
    }

    /// Offer this peer its `.policy` track and write the current state to it.
    ///
    /// A server-initiated PUBLISH, which is draft-19's answer to exactly this:
    /// the relay has something the client needs and the client cannot know to
    /// ask for it. One object per change, on its own group, so a client that
    /// joins late or reconnects gets the current state rather than a diff
    /// against something it never saw.
    ///
    /// Failures are logged and dropped. Every one of them is a connection that
    /// is going away, and the mute does not depend on this arriving: it is
    /// already enforced by the pulls that were cancelled and by the policy that
    /// will refuse the next subscription.
    async fn tell_policy(&self, silence: Silence) {
        let Permission::Scoped(scope) = self.permission() else {
            return;
        };
        let Some(track) = policy_track(scope) else {
            return;
        };

        if let Err(e) = self.publish_policy(&track, silence).await {
            tracing::debug!(
                session = %self.id,
                error = %e,
                "could not tell a session about its mute"
            );
        }
    }

    /// PUBLISH `.policy` and write one object to it.
    async fn publish_policy(
        &self,
        track: &FullTrackName,
        silence: Silence,
    ) -> Result<(), SessionError> {
        let alias = self.allocate_alias();
        let offer = Publish::new(self.allocate_request_id(), track.clone(), alias);
        let (mut request, _answer) = self.transport.open_bi().await?;
        send(&mut request, &offer).await?;

        // The answer is not waited for. Draft-19 lets objects flow before a
        // PUBLISH is accepted unless FORWARD is zero, and waiting would mean a
        // client that never answers keeps a task alive per mute. A client that
        // does not want the track resets the stream, which is the same outcome
        // as never having sent it.
        let sequence = self.policy_sequence.fetch_add(1, Ordering::Relaxed);
        let header = SubgroupHeader::new(
            alias,
            GroupId::new(VarInt::new(sequence).unwrap_or(VarInt::MAX)),
            SubgroupSource::Zero,
        );
        let mut buf = BytesMut::new();
        header.encode(&mut buf);
        let object = SubgroupObject::new(ObjectSeq::from(0u32), policy_payload(silence));
        SubgroupWriter::new(&header)
            .write(&mut buf, &object)
            .map_err(|_| SessionError::Protocol("could not encode a policy object"))?;

        let mut stream = self.transport.open_uni().await?;
        stream.write_all(&buf).await?;
        let _ = stream.finish();
        // Held until the object is written: dropping the request stream is how
        // this end withdraws a publication, and withdrawing it before the
        // object has gone out would race the thing it is announcing.
        drop(request);
        Ok(())
    }

    /// Route a subscriber to this track, subscribing upstream only if nobody
    /// already has.
    ///
    /// The decision is made here, synchronously, and that is what makes it
    /// correct rather than merely usual. Commands are delivered one at a time
    /// on this session's own loop, so a look-up and the claim that follows it
    /// cannot interleave with another subscriber's — whereas deciding inside
    /// the spawned task would put a round trip between the two, which is
    /// precisely where the simultaneous joins land.
    fn pull(
        &self,
        track: FullTrackName,
        route: Box<Route>,
        hops: Hops,
        ready: oneshot::Sender<Result<Pulling, UpstreamError>>,
    ) {
        // Resolved in its own scope so the lock is not held across the await
        // points below, and so the `Vacant` arm can claim the track before
        // anything is spawned.
        let joining = {
            let mut pulled = self.lock_pulled();
            match pulled.entry(track.clone()) {
                std::collections::hash_map::Entry::Occupied(entry) => match entry.get() {
                    Pull::Ready(upstream) => Join::Existing(upstream.alias),
                    Pull::Pending(outcome) => Join::Waiting(outcome.clone()),
                },
                std::collections::hash_map::Entry::Vacant(slot) => {
                    let (announce, outcome) = watch::channel(None);
                    slot.insert(Pull::Pending(outcome));
                    Join::Opening(announce)
                }
            }
        };

        match joining {
            Join::Existing(upstream) => {
                let _ = ready.send(self.share(upstream, *route, &track));
            }
            Join::Waiting(mut outcome) => {
                let session = self.clone();
                tokio::spawn(async move {
                    // Waits for the first subscriber's round trip rather than
                    // starting a second one. A sender dropped without an answer
                    // means that task died, which the subscriber sees the same
                    // way as any other upstream failure.
                    let answer = loop {
                        if let Some(answer) = outcome.borrow_and_update().clone() {
                            break answer;
                        }
                        if outcome.changed().await.is_err() {
                            break Err(UpstreamError::unavailable());
                        }
                    };
                    let _ = ready.send(match answer {
                        Ok(upstream) => session.share(upstream, *route, &track),
                        Err(e) => Err(e),
                    });
                });
            }
            Join::Opening(announce) => {
                let session = self.clone();
                tokio::spawn(async move {
                    let result = session
                        .subscribe_upstream(track.clone(), *route, hops)
                        .await;
                    if result.is_err() {
                        // Cleared rather than left pending, so the next
                        // subscriber tries again instead of inheriting a
                        // failure that may have been momentary.
                        session.lock_pulled().remove(&track);
                    }
                    // Before the reply, so a waiter woken by it finds the track
                    // ready rather than still pending.
                    let _ = announce.send(Some(result.clone()));
                    // A dropped receiver means the downstream subscriber gave
                    // up while we were asking upstream. Its route was
                    // registered anyway, and the fan-out drops routes whose
                    // session has gone.
                    let _ = ready.send(result.map(|upstream| Pulling {
                        upstream,
                        shared: false,
                    }));
                });
            }
        }
    }

    /// Add a route to a subscription somebody else already established, unless
    /// that subscription has ended in the meantime.
    ///
    /// A publisher can stop at any moment, including between a waiter being
    /// told which alias to join and the waiter acting on it. Attaching anyway
    /// would answer `SUBSCRIBE_OK` and then deliver nothing — a black tile with
    /// no error to explain it, which is the worst failure available here. So
    /// the record is checked under the same lock that
    /// [`stop_pulling`](Self::stop_pulling) clears it under, and a subscriber
    /// that missed the broadcast is told so and can ask again.
    fn share(
        &self,
        upstream: TrackAlias,
        route: Route,
        track: &FullTrackName,
    ) -> Result<Pulling, UpstreamError> {
        let pulled = self.lock_pulled();
        if !matches!(pulled.get(track), Some(Pull::Ready(pull)) if pull.alias == upstream) {
            return Err(UpstreamError::unavailable());
        }
        // Held across this, so the route cannot be added to a subscription that
        // is being torn down. Every other path takes these two in the same
        // order, `pulled` before `routes`.
        self.add_route(upstream, route);
        drop(pulled);

        tracing::debug!(
            session = %self.id,
            %track,
            %upstream,
            "subscription shared an existing pull"
        );
        Ok(Pulling {
            upstream,
            shared: true,
        })
    }

    /// Subscribe to `track` on this session and route what comes back.
    ///
    /// Returns the upstream alias once the peer has answered, leaving a task
    /// holding the request stream open — closing it would cancel the
    /// subscription. Callers reach this through [`pull`](Self::pull), which is
    /// what keeps one track to one subscription.
    async fn subscribe_upstream(
        &self,
        track: FullTrackName,
        route: Route,
        hops: Hops,
    ) -> Result<TrackAlias, UpstreamError> {
        let internal = |context: &str, e: &dyn std::fmt::Display| {
            UpstreamError::new(RequestErrorCode::INTERNAL_ERROR, format!("{context}: {e}"))
        };

        let (mut send_stream, recv) = self
            .transport
            .open_bi()
            .await
            .map_err(|e| internal("could not open a request stream", &e))?;

        let mut request = Subscribe::new(self.allocate_request_id(), track.clone());
        // Only towards a parent relay. A publisher is the end of the chain — it has
        // nowhere to forward a subscription to — and sending it a budget would put
        // an unknown parameter on the wire for no purpose.
        if self.facing == Facing::Upstream {
            hops.spent().note(&mut request.parameters);
        }
        send(&mut send_stream, &request)
            .await
            .map_err(|e| internal("could not send SUBSCRIBE", &e))?;

        let mut frames = Frames::new(recv);
        let frame = frames
            .expect()
            .await
            .map_err(|e| internal("no answer to SUBSCRIBE", &e))?;

        match frame.message_type {
            MessageType::SubscribeOk => {
                let ok = SubscribeOk::decode(&mut frame.body.clone())
                    .map_err(|e| internal("malformed SUBSCRIBE_OK", &e))?;
                let upstream = ok.track_alias;
                self.add_route(upstream, route);
                self.lock_pulling().insert(
                    upstream,
                    self.fabric
                        .metrics()
                        .track_started(track.clone(), self.id, upstream),
                );
                let stop = Arc::new(Notify::new());
                // Published before the reply goes out and before the reading
                // task exists, so that the teardown below can only ever find a
                // record it is entitled to remove.
                self.lock_pulled().insert(
                    track.clone(),
                    Pull::Ready(Upstream {
                        alias: upstream,
                        stop: Arc::clone(&stop),
                    }),
                );
                tracing::info!(
                    session = %self.id,
                    %track,
                    %upstream,
                    "pulling track"
                );

                let session = self.clone();
                tokio::spawn(async move {
                    // `send_stream` moves in deliberately: holding it is what
                    // keeps the subscription alive, and dropping it resets the
                    // stream, which is how this end unsubscribes.
                    let hold = send_stream;
                    let ended = tokio::select! {
                        () = stop.notified() => false,
                        () = async { while let Ok(Some(_)) = frames.next().await {} } => true,
                    };
                    drop(hold);
                    if ended {
                        tracing::info!(session = %session.id, %track, %upstream, "track ended");
                    } else {
                        tracing::info!(
                            session = %session.id,
                            %track,
                            %upstream,
                            "stopped pulling: nobody is watching"
                        );
                    }
                    session.stop_pulling(&track, upstream, ended);
                });
                Ok(upstream)
            }
            MessageType::RequestError => {
                let error = RequestError::decode(&mut frame.body.clone())
                    .map_err(|e| internal("malformed REQUEST_ERROR", &e))?;
                Err(UpstreamError::new(
                    error.code,
                    error
                        .reason
                        .as_str()
                        .unwrap_or("upstream refused")
                        .to_owned(),
                ))
            }
            other => Err(UpstreamError::new(
                RequestErrorCode::INTERNAL_ERROR,
                format!("unexpected {other:?} answering SUBSCRIBE"),
            )),
        }
    }

    // MARK: - Data plane

    /// Copy one incoming subgroup to every subscriber of its track.
    ///
    /// The header is re-encoded per destination because the alias differs;
    /// everything after it is copied verbatim. The relay never *has* to look at
    /// an object, which is what lets payloads stay encrypted end to end.
    ///
    /// It does look, on a copy, to fill the cache — see [`Tee`]. That parse is
    /// downstream of the fan-out in every sense: it reads bytes already sent, and
    /// a stream it cannot parse costs a cache miss rather than a dropped forward.
    async fn forward_subgroup(&self, recv: RecvStream) {
        let mut frames = Frames::new(recv);
        // A subgroup stream is not length-delimited, so the header is read
        // directly rather than through `Frames::next`. The buffering is shared,
        // which is why anything read past the header has to be picked up below
        // rather than dropped.
        let header = match read_header(&mut frames).await {
            Ok(header) => header,
            Err(e) => {
                tracing::debug!(session = %self.id, error = %e, "unreadable subgroup header");
                return;
            }
        };

        let metrics = self.fabric.metrics();
        let routes = self.routes_for(header.track_alias);
        // Looked up before the early return below, so that a subgroup arriving on
        // a track nobody is watching still counts as the publisher being alive.
        // Otherwise the last subscriber leaving would make a healthy publisher
        // read as silent.
        let flow = self.lock_pulling().get(&header.track_alias).cloned();
        if let Some(flow) = &flow {
            flow.subgroup();
        }
        let mut tee = self.tee(&header);
        if routes.is_empty() && tee.is_none() {
            // Nowhere to put this. Reading it to the end anyway would spend the
            // bandwidth twice over for nothing.
            tracing::trace!(
                session = %self.id,
                alias = %header.track_alias,
                "subgroup with no subscribers"
            );
            metrics.subgroup_dropped();
            return;
        }
        metrics.subgroup_forwarded();

        let mut outlets: Vec<Outlet> = routes
            .into_iter()
            .map(|route| Outlet::open(&route, &header, metrics.clone()))
            .collect();

        let leftover = frames.take_buffered();
        if !leftover.is_empty() {
            metrics.ingress(leftover.len());
            if let Some(flow) = &flow {
                flow.carried(leftover.len());
            }
            if let Some(tee) = &mut tee {
                tee.absorb(&leftover);
            }
            fan_out(&mut outlets, &leftover, metrics);
        }

        let mut chunk = [0u8; 8192];
        // Kept running for the cache's sake after the last subscriber has gone:
        // the objects still belong in history, and a subscriber arriving a moment
        // later wants them. Only a stream nobody is watching *and* nothing is
        // retaining is abandoned.
        while !outlets.is_empty() || tee.is_some() {
            match frames.stream.read(&mut chunk).await {
                Ok(Some(0) | None) | Err(_) => break,
                Ok(Some(n)) => {
                    metrics.ingress(n);
                    if let Some(flow) = &flow {
                        flow.carried(n);
                    }
                    if let Some(tee) = &mut tee {
                        tee.absorb(&chunk[..n]);
                    }
                    fan_out(&mut outlets, &Bytes::copy_from_slice(&chunk[..n]), metrics);
                }
            }
        }
        // Dropping the outlets closes their queues, and each writer finishes its
        // stream once it has drained. Nothing is awaited: a subscriber still
        // taking the last of a subgroup must not hold up the next one.
    }

    /// A parser recording this stream into the cache, if it can be attributed to
    /// a track and the cache is retaining anything.
    ///
    /// Catalogs are teed even when retention is off. They are the one payload
    /// a relay is allowed to read — never encrypted, written so a third party
    /// can — and the control plane learns a publisher's locale from them.
    fn tee(&self, header: &SubgroupHeader) -> Option<Tee> {
        let track = self
            .lock_pulling()
            .get(&header.track_alias)
            .map(|flow| flow.track.clone())
            .or_else(|| {
                tracing::trace!(
                    session = %self.id,
                    alias = %header.track_alias,
                    "no track for this alias, so nothing to cache"
                );
                None
            })?;
        let catalog = track.name().as_ref() == b".catalog";
        let recorder = self.fabric.cache().record(track, header);
        (recorder.is_enabled() || catalog)
            .then(|| Tee::new(header, recorder, catalog.then(|| self.clone())))
    }

    /// Take a locale from a catalog object, if it changed.
    fn note_catalog(&self, object: &SubgroupObject) {
        let SubgroupContent::Normal { payload, .. } = &object.content else {
            return;
        };
        let Some(locale) = crate::catalog::locale_in(payload) else {
            return;
        };
        let mut held = self
            .locale
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if held.as_deref() == Some(locale.as_str()) {
            return;
        }
        *held = Some(locale.clone());
        drop(held);
        self.fabric.roster().changed(self.id, locale);
    }

    // MARK: - Bookkeeping

    fn allocate_alias(&self) -> TrackAlias {
        let next = self.next_alias.fetch_add(1, Ordering::Relaxed);
        TrackAlias::new(VarInt::new(next).expect("alias count stays within varint range"))
    }

    fn allocate_request_id(&self) -> RequestId {
        self.requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .allocate()
            .expect("request count stays within varint range")
    }

    fn lock_routes(&self) -> std::sync::MutexGuard<'_, HashMap<TrackAlias, Vec<Route>>> {
        self.routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lock_pulling(&self) -> std::sync::MutexGuard<'_, HashMap<TrackAlias, Arc<Flowing>>> {
        self.pulling
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lock_pulled(&self) -> std::sync::MutexGuard<'_, HashMap<FullTrackName, Pull>> {
        self.pulled
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lock_subscribed(&self) -> std::sync::MutexGuard<'_, HashMap<RequestId, FullTrackName>> {
        self.subscribed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn add_route(&self, alias: TrackAlias, route: Route) {
        self.lock_routes().entry(alias).or_default().push(route);
    }

    /// Forget an upstream subscription that has ended, and every route it fed.
    ///
    /// One subscription serves many subscribers, so its end is theirs too — the
    /// alias stops meaning anything the moment the publisher stops sending
    /// under it. Retained history stays: it belongs to the track, not to a
    /// subscription.
    ///
    /// `ended` distinguishes the publisher stopping from this relay letting go
    /// because nobody was left watching. Only the first is news to a
    /// subscriber; in the second there is by definition nobody to tell.
    fn stop_pulling(&self, track: &FullTrackName, upstream: TrackAlias, ended: bool) {
        // `pulled` first and held throughout, so that a subscriber joining this
        // subscription cannot slip between the record going and the routes
        // going. See [`share`](Self::share).
        let mut pulled = self.lock_pulled();
        // Cleared only if the record still names *this* subscription. A track
        // taken up again after this one ended holds a newer alias, and clearing
        // it here would strand its subscribers on a pull nothing points at.
        if matches!(pulled.get(track), Some(Pull::Ready(pull)) if pull.alias == upstream) {
            pulled.remove(track);
        }
        let orphaned = self.lock_routes().remove(&upstream);
        self.lock_pulling().remove(&upstream);
        drop(pulled);

        if ended {
            for route in orphaned.into_iter().flatten() {
                route.done.notify_one();
            }
        }
        self.fabric.metrics().track_ended(self.id, upstream);
    }

    /// Drop one subscriber's route, and stop the pull if it was the last.
    ///
    /// Called from the subscriber's own session when its request stream ends,
    /// which is how MOQT spells unsubscribe. Reaching across sessions like this
    /// is what makes the saving real: the point of noticing is not to tidy a
    /// map, it is to stop asking a publisher for a track that nobody is
    /// watching any more.
    fn release_route(
        &self,
        track: &FullTrackName,
        upstream: TrackAlias,
        subscriber: SessionId,
        downstream: TrackAlias,
    ) {
        // `pulled` before `routes` throughout. See [`share`](Self::share),
        // which is the operation this races with.
        let mut pulled = self.lock_pulled();
        let mut routes = self.lock_routes();
        let Some(remaining) = routes.get_mut(&upstream) else {
            return;
        };
        remaining.retain(|route| route.subscriber != subscriber || route.alias != downstream);
        if !remaining.is_empty() {
            return;
        }
        routes.remove(&upstream);
        drop(routes);

        tracing::info!(session = %self.id, %track, %upstream, "last subscriber left");

        // Withdrawn here rather than left for the reading task to clear on its
        // way out, and this is the whole of what makes the teardown safe. A
        // subscription is not cancelled synchronously — the notify below only
        // wakes a task — so between raising it and that task running there is a
        // window in which this record still points at a pull that is finishing.
        // A viewer arriving in that window would be attached to it and would
        // receive nothing, forever, with a SUBSCRIBE_OK saying otherwise. That
        // window is not rare: it is exactly what a phone changing rung does,
        // unsubscribing and resubscribing to the same publisher in the same
        // breath. Removing the record under the lock means such a viewer opens
        // a fresh pull instead, which costs one round trip and is always right.
        let Some(Pull::Ready(pull)) = pulled.get(track) else {
            return;
        };
        // Only if the record still names *this* subscription: a track taken up
        // again already holds a newer alias, and cancelling on its behalf would
        // stop a pull that has an audience.
        if pull.alias != upstream {
            return;
        }
        let stop = Arc::clone(&pull.stop);
        pulled.remove(track);
        drop(pulled);

        // The rest of the teardown belongs to the task holding the upstream
        // request stream, which does it on its way out — one path for a pull
        // ending, whether the publisher ended it or the audience did.
        stop.notify_one();
    }

    /// The routes for `alias`, forgetting any whose session has gone.
    ///
    /// Departures are noticed here rather than announced, because MOQT has no
    /// message for a subscriber losing interest — the connection simply closes.
    /// Pruning matters more now that one upstream subscription outlives any one
    /// subscriber: without it a track watched by a thousand people who have
    /// since left would keep trying to open a thousand streams per subgroup.
    fn routes_for(&self, alias: TrackAlias) -> Vec<Route> {
        let mut routes = self.lock_routes();
        let Some(list) = routes.get_mut(&alias) else {
            return Vec::new();
        };
        list.retain(|route| route.session.close_reason().is_none());
        list.clone()
    }
}

/// Parses a copy of a forwarded subgroup stream into the cache.
///
/// Object IDs on a subgroup stream are delta-encoded against the previous
/// object, so this cannot be done a chunk at a time without keeping the reader's
/// state — which is the whole reason it is a type and not a function. It holds
/// the tail of a partially-arrived object and picks up where it left off.
///
/// Once a stream stops parsing it stays stopped. A desynchronised delta state
/// produces wrong Object IDs indefinitely rather than failing again, and filing
/// objects under invented IDs would let a fetch serve one object in place of
/// another.
struct Tee {
    reader: SubgroupReader,
    recorder: cache::Recorder,
    /// Bytes received but not yet a whole object.
    pending: BytesMut,
    live: bool,
    /// The session whose catalog this is, when the track is `.catalog`.
    catalog: Option<Session>,
}

impl Tee {
    fn new(header: &SubgroupHeader, recorder: cache::Recorder, catalog: Option<Session>) -> Self {
        Self {
            reader: SubgroupReader::new(header),
            recorder,
            pending: BytesMut::new(),
            live: true,
            catalog,
        }
    }

    /// Take a copy of bytes already forwarded, storing whatever objects complete.
    fn absorb(&mut self, bytes: &[u8]) {
        if !self.live {
            return;
        }
        self.pending.extend_from_slice(bytes);

        loop {
            let mut cursor = &self.pending[..];
            match self.reader.read(&mut cursor) {
                Ok(object) => {
                    let consumed = self.pending.len() - cursor.len();
                    self.pending.advance(consumed);
                    self.recorder.push(&object);
                    if let Some(session) = &self.catalog {
                        session.note_catalog(&object);
                    }
                }
                Err(DecodeError::Short { .. }) => return,
                Err(e) => {
                    tracing::debug!(error = %e, "unparseable object, so this stream is not cached");
                    self.live = false;
                    self.pending.clear();
                    return;
                }
            }
        }
    }
}

/// Read a subgroup header, buffering until it is complete.
async fn read_header(frames: &mut Frames) -> Result<SubgroupHeader, SessionError> {
    loop {
        let mut cursor = &frames.buffer[..];
        match SubgroupHeader::decode(&mut cursor) {
            Ok(header) => {
                let consumed = frames.buffer.len() - cursor.remaining();
                frames.buffer.advance(consumed);
                return Ok(header);
            }
            Err(DecodeError::Short { .. }) => {}
            Err(e) => return Err(e.into()),
        }

        frames.fill().await?;
        if frames.ended {
            return Err(SessionError::Truncated);
        }
    }
}

/// How much of a subgroup may be held for one subscriber at once.
///
/// A bound on memory, and only on memory: chunks of at most eight kilobytes, so
/// half a megabyte per copy in flight at the very outside. What keeps queueing
/// from turning a bandwidth problem into a latency problem is [`SHED_AFTER`],
/// not this number, so this one can afford to be generous enough to absorb a
/// burst arriving faster than the writer is scheduled.
///
/// It was once four, which was small enough to be a latency bound in its own
/// right — and that was the bug. A publisher on loopback delivers a subgroup in
/// one burst, so four chunks meant a healthy subscriber was shed whenever its
/// writer task lost the CPU for a moment. Depth is not evidence about a
/// subscriber's connection; elapsed time is.
const QUEUE_DEPTH: usize = 64;

/// How long a subscriber may take nothing before the relay gives up on the
/// subgroup for it.
///
/// The latency bound, and the reason a deep queue is safe. For live video,
/// bytes that arrive after their moment are worse than bytes that never arrive,
/// because the second kind at least lets the subscriber ask for a smaller rung
/// and recover — so what has to be bounded is how late a picture may be, which
/// is a duration and was previously being approximated by a count of chunks.
///
/// Generous next to a frame interval, and deliberately: it has to sit above the
/// scheduling jitter of a loaded relay, or it would shed for the relay's own
/// hesitation rather than for the subscriber's connection. Well under the point
/// where a viewer would rather have the picture late than not at all.
const SHED_AFTER: Duration = Duration::from_millis(250);

/// What a shed subgroup's stream is reset with.
///
/// The subscriber is told the stream was abandoned rather than left to infer it
/// from a group that never completes. A dedicated code, so that "you were too
/// slow for this frame" is distinguishable from a relay or publisher fault.
///
/// Public because it is part of what the relay says to its subscribers, and a
/// test that asserted on its own copy of the number would not be checking the
/// relay's answer.
pub const RESET_SHED: u32 = 0x02;

/// One subscriber's copy of one subgroup, and the task writing it.
///
/// The queue exists to decouple subscribers from each other. Writing to each in
/// turn — which is what a straightforward loop does — makes every subscriber
/// wait for the slowest, because a QUIC write blocks until that connection's
/// flow control lets it through. One viewer on a bad train connection would set
/// the pace for the whole room, and worse, would back the pressure all the way
/// up to the publisher's phone. Deduplicating the pull upstream made that
/// sharper rather than milder: there is now one read loop feeding everybody.
struct Outlet {
    chunks: mpsc::Sender<Bytes>,
    /// Raised when this copy is abandoned, so the writer resets its stream
    /// instead of finishing it. Separate from closing the queue because the
    /// writer is typically blocked mid-write when that decision is made, and
    /// the point of the decision is not to wait for it.
    abandon: Arc<Notify>,
    /// When the writer last got bytes as far as the transport, as milliseconds
    /// after [`Outlet::opened`].
    ///
    /// The one fact [`Outlet::offer`] needs and cannot get from the queue: a
    /// full queue says a subscriber is behind, but not whether it is behind
    /// because its connection will not take the bytes or because the relay has
    /// not had a chance to offer them yet. Only the first is the subscriber's
    /// fault, and only the first is worth shedding a subgroup over.
    wrote: Arc<AtomicU64>,
    /// The instant `wrote` is measured from. An `Instant` is not something that
    /// can live in an atomic, and a shared origin plus milliseconds is precise
    /// enough for a quarter-second decision.
    opened: Instant,
}

/// What became of a chunk offered to a subscriber.
enum Handoff {
    /// Queued, and the writer will get to it.
    Taken,
    /// The subscriber is too far behind to be worth keeping this subgroup for.
    Shed,
    /// The writer has stopped: the stream failed, or the session went away.
    Gone,
}

impl Outlet {
    /// Start writing a subgroup to one subscriber.
    ///
    /// The stream is opened by the writer rather than here, so that a
    /// subscriber sitting at its concurrent stream limit delays only itself.
    fn open(route: &Route, header: &SubgroupHeader, metrics: Metrics) -> Self {
        let (chunks, mut queue) = mpsc::channel(QUEUE_DEPTH);
        let abandon = Arc::new(Notify::new());
        let wrote = Arc::new(AtomicU64::new(0));
        let opened = Instant::now();

        // Counted at the decision rather than at the open, because this is the
        // point of no return for the subscriber: a stream shed later was still
        // a stream it saw. Erring high is deliberate. `PUBLISH_DONE` carries
        // this so a subscriber can tell "everything arrived" from "one is still
        // in flight", and a count that came in under the truth would have it
        // conclude the first while a stream was still on its way.
        route.streams.fetch_add(1, Ordering::Relaxed);

        let session = route.session.clone();
        // Re-addressed per destination: the alias is the subscriber's own, and
        // everything after the header is copied verbatim.
        let header = SubgroupHeader {
            track_alias: route.alias,
            ..header.clone()
        };
        let abandoned = Arc::clone(&abandon);
        let progress = Arc::clone(&wrote);

        tokio::spawn(async move {
            let Ok(mut stream) = session.open_uni().await else {
                metrics.fanout_failed();
                return;
            };
            let mut prologue = BytesMut::with_capacity(header.encoded_len());
            header.encode(&mut prologue);
            if stream.write_all(&prologue).await.is_err() {
                metrics.fanout_failed();
                return;
            }
            // Opening the stream and writing the header is the relay's own
            // latency, so the clock the shed decision reads starts once that is
            // done rather than at `open`. Otherwise a subscriber sitting at its
            // stream limit would be charged for the wait.
            note(&progress, opened);

            loop {
                let chunk: Bytes = tokio::select! {
                    biased;
                    () = abandoned.notified() => break,
                    // A closed queue means every chunk was written and the
                    // source finished: an orderly end, and the only path that
                    // finishes the stream cleanly.
                    chunk = queue.recv() => if let Some(chunk) = chunk {
                        chunk
                    } else {
                        let _ = stream.finish();
                        return;
                    },
                };

                let length = chunk.len();
                // The write is inside the select because that is where the time
                // goes. Abandoning a subgroup while its last write is stuck
                // behind a congestion window is the case this whole mechanism
                // is for; cancelling a partial write costs nothing, since the
                // stream is about to be reset.
                //
                // The deadline is here as well as in `Outlet::offer` because the
                // two catch different moments. `offer` only runs when there is
                // another chunk to hand over, so it cannot notice a subscriber
                // that stalls on the last chunks of a subgroup — and a stall at
                // the end of a group is the ordinary case, since a publisher
                // sends a group and then stops. A write that has not completed
                // inside the budget means this connection's window is full and
                // the peer is not draining it, which is the definition of the
                // subscriber this mechanism exists for.
                let written = tokio::select! {
                    biased;
                    () = abandoned.notified() => break,
                    written = tokio::time::timeout(SHED_AFTER, stream.write_chunk(chunk)) => written,
                };
                let Ok(written) = written else {
                    // Counted here rather than left to `fan_out`, which will
                    // never see this copy again: the queue is what it offers
                    // to, and this task is about to stop reading it.
                    metrics.subgroup_shed();
                    break;
                };
                if written.is_err() {
                    metrics.fanout_failed();
                    return;
                }
                note(&progress, opened);
                metrics.egress(length);
            }

            let _ = stream.reset(RESET_SHED);
        });

        Self {
            chunks,
            abandon,
            wrote,
            opened,
        }
    }

    /// How long since the writer last got bytes as far as the transport.
    fn since_progress(&self) -> Duration {
        let wrote = Duration::from_millis(self.wrote.load(Ordering::Relaxed));
        self.opened.elapsed().saturating_sub(wrote)
    }

    /// How many chunks this subscriber has yet to take.
    fn outstanding(&self) -> usize {
        self.chunks.max_capacity() - self.chunks.capacity()
    }

    /// Hand this subscriber a chunk, or give up on the subgroup for it.
    ///
    /// Two reasons to give up, and they are different claims about the
    /// subscriber. Bytes that have been waiting longer than [`SHED_AFTER`] are
    /// late enough not to be worth delivering, whatever the queue looks like;
    /// that is the one that fires in practice, and it fires while there is
    /// still room, because a stalled writer stops taking chunks long before the
    /// queue is full. A full queue is the second, and is only the memory bound
    /// having been reached by a subscriber that is making progress but not
    /// enough of it.
    fn offer(&self, chunk: Bytes) -> Handoff {
        // Nothing outstanding means nothing is late: a track that sends a chunk
        // every few frames leaves the writer idle between them, and an idle
        // writer must not read as a stalled one.
        if self.outstanding() > 0 && self.since_progress() > SHED_AFTER {
            self.abandon.notify_one();
            return Handoff::Shed;
        }

        match self.chunks.try_send(chunk) {
            Ok(()) => Handoff::Taken,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.abandon.notify_one();
                Handoff::Shed
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Handoff::Gone,
        }
    }
}

/// Record that the writer got somewhere, as milliseconds after `opened`.
fn note(progress: &AtomicU64, opened: Instant) {
    // Saturating, and no ordering stronger than relaxed: the reader is deciding
    // whether a quarter of a second has passed, so a stale value costs one more
    // chunk's grace and nothing else.
    let millis = u64::try_from(opened.elapsed().as_millis()).unwrap_or(u64::MAX);
    progress.store(millis, Ordering::Relaxed);
}

/// Offer `bytes` to every destination, keeping the ones still worth writing to.
///
/// Deliberately not `async`. Nothing here waits for a subscriber, which is what
/// makes a slow one another subscriber's problem — and the reason the publisher
/// can be read at the speed it sends rather than the speed the room can take.
///
/// Egress is counted where the bytes are actually written, so it exceeds
/// ingress by the fan-out ratio. That ratio is the whole reason a relay exists,
/// and the two counters together are the only place it is visible.
fn fan_out(outlets: &mut Vec<Outlet>, bytes: &Bytes, metrics: &Metrics) {
    outlets.retain(|outlet| match outlet.offer(bytes.clone()) {
        Handoff::Taken => true,
        Handoff::Shed => {
            metrics.subgroup_shed();
            false
        }
        // The writer counted the failure that stopped it, or there was never a
        // stream to fail. Either way this destination is finished with.
        Handoff::Gone => false,
    });
}

/// The fields of `namespace` after `prefix`, or `None` if it is not under it.
fn suffix_of(namespace: &TrackNamespace, prefix: &TrackNamespace) -> Option<TrackNamespace> {
    if !namespace.starts_with(prefix) {
        return None;
    }
    TrackNamespace::new(namespace.fields()[prefix.len()..].to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn namespace(fields: &[&str]) -> TrackNamespace {
        TrackNamespace::from_parts(fields).expect("valid namespace")
    }

    #[test]
    fn a_suffix_drops_exactly_the_prefix() {
        assert_eq!(
            suffix_of(&namespace(&["acme", "room", "42"]), &namespace(&["acme"])),
            Some(namespace(&["room", "42"]))
        );
        assert_eq!(
            suffix_of(&namespace(&["acme"]), &namespace(&["acme"])),
            Some(namespace(&[])),
            "an exact match has an empty suffix, not no suffix"
        );
        assert_eq!(
            suffix_of(&namespace(&["acme", "room"]), &namespace(&[])),
            Some(namespace(&["acme", "room"])),
            "the empty prefix drops nothing"
        );
    }

    /// Tuple prefixes cannot produce the false match string prefixes can, and
    /// this is why namespaces are tuples: `("acme", "room")` must not match
    /// `("acme", "roomies")`.
    #[test]
    fn a_partial_field_is_not_a_prefix() {
        assert_eq!(
            suffix_of(
                &namespace(&["acme", "roomies"]),
                &namespace(&["acme", "room"])
            ),
            None
        );
    }

    /// The suffix computed here is resolved by the peer through
    /// `Namespace::resolve`, so the round trip is the property that matters.
    #[test]
    fn a_suffix_resolves_back_to_the_namespace() {
        let full = namespace(&["acme", "room", "42"]);
        let prefix = namespace(&["acme"]);
        let suffix = suffix_of(&full, &prefix).expect("under the prefix");
        assert_eq!(Namespace::new(suffix).resolve(&prefix), Ok(full));
    }

    /// A relay is the server on every session it accepts, and draft-19 reserves
    /// odd request IDs for the server. An even ID from here is a session error
    /// on the peer's side.
    #[test]
    fn relay_request_ids_are_odd_and_ascending() {
        let mut generator = RequestIdGenerator::new(Role::Server);
        let ids: Vec<u64> = (0..4)
            .map(|_| generator.allocate().expect("within range").get())
            .collect();
        assert_eq!(ids, vec![1, 3, 5, 7]);
    }
}
