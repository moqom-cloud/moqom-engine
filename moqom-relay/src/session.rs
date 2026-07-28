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
use std::time::{Instant, SystemTime};

use bytes::{Buf, Bytes, BytesMut};
use moqom_proto::control::{
    ControlFrame, Fetch, FetchKind, FetchOk, MessageBody, MessageType, Namespace, NamespaceDone,
    PublishNamespace, ReasonPhrase, RequestError, RequestErrorCode, RequestId, RequestIdGenerator,
    Role, Setup, Subscribe, SubscribeNamespace, SubscribeOk, setup, write_message,
};
use moqom_proto::data::{
    FetchHeader, FetchRecord, FetchWriter, GroupOrder, SubgroupHeader, SubgroupReader,
};
use moqom_proto::error::DecodeError;
use moqom_proto::model::{
    FetchEnd, FullTrackName, GroupId, Location, ObjectId, TrackAlias, TrackNamespace,
};
use moqom_proto::varint::VarInt;
use tokio::sync::{mpsc, oneshot};
use web_transport_quinn::{RecvStream, SendStream};

use crate::fabric::{Command, Fabric, NamespaceEvent, Route, SessionId, UpstreamError};
use crate::metrics::{Ending, Fetched, Metrics, Subscribed};
use crate::quota::{Lease, Principal, Refusal, Resource};
use crate::{cache, metrics};

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
            Err(SessionError::Unauthenticated(_)) => Self::Rejected,
            Err(SessionError::OverLimit(_)) => Self::Throttled,
        }
    }
}

/// Application error codes this relay closes sessions with.
mod code {
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
    pulling: Arc<Mutex<HashMap<TrackAlias, FullTrackName>>>,
    /// Tracks this peer has subscribed to, by the Request ID it used.
    ///
    /// A joining fetch names a subscription rather than a track, on purpose:
    /// deriving the range's end from the subscription is what makes the fetch and
    /// the subscription provably contiguous. Resolving that reference needs this.
    subscribed: Arc<Mutex<HashMap<RequestId, FullTrackName>>>,
    /// Quota slots held by established subscriptions.
    ///
    /// Separate from `subscribed` because they have different lifetimes in
    /// principle — a slot is released when the subscription ends, and there is
    /// no UNSUBSCRIBE here yet, so in practice both end with the session.
    /// Keyed by request rather than pushed onto a list so that when unsubscribe
    /// does land, releasing the right slot is a lookup rather than a rewrite.
    holding: Arc<Mutex<HashMap<RequestId, Lease>>>,
    /// Who this session's limits are charged to.
    ///
    /// Written once, during SETUP, and read by every request afterwards. A
    /// `OnceLock` rather than a field because the identity is not known when the
    /// session is constructed — the token arrives in the handshake — and rather
    /// than a `Mutex<Option<_>>` because it genuinely is write-once: a peer that
    /// could change who it is mid-session could shed a limit by doing so.
    principal: Arc<OnceLock<Principal>>,
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
            subscribed: Arc::default(),
            holding: Arc::default(),
            principal: Arc::default(),
        };

        let result = session.run(command_queue).await;
        fabric.remove_session(id);
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

    /// This session's identifier within the relay.
    #[must_use]
    pub fn id(&self) -> SessionId {
        self.id
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
        tokio::select! {
            result = self.serve_control(control_send, control, commands) => result,
            result = self.accept_requests() => result,
            result = self.accept_data() => result,
            result = self.sample_transport(live.as_deref()) => result,
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
        let tokens = peer
            .options
            .authorization_tokens()
            .map(bytes::Bytes::as_ref);

        let who = match self
            .fabric
            .authenticator()
            .identify(tokens, address, SystemTime::now())
        {
            Ok(who) => who,
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

        if who.is_verified() {
            tracing::debug!(session = %self.id, "session authenticated");
        }
        // Only ever set once, and this is the only place that sets it.
        let _ = self.principal.set(who);
        Ok(())
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
            MessageType::PublishNamespace => self.on_publish_namespace(&frame, &mut frames).await,
            MessageType::SubscribeNamespace => {
                self.on_subscribe_namespace(&frame, &mut send_stream, &mut frames)
                    .await
            }
            MessageType::Subscribe => self.on_subscribe(&frame, &mut send_stream, lease).await,
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
        frames: &mut Frames,
    ) -> Result<(), SessionError> {
        let request = PublishNamespace::decode(&mut frame.body.clone())?;
        tracing::info!(
            session = %self.id,
            namespace = %request.namespace,
            "namespace announced"
        );
        self.fabric.metrics().announced();
        self.fabric
            .announce(self.id, request.namespace.clone(), self.commands.clone());

        let result = match frames.next().await {
            Ok(None) => Ok(()),
            Ok(Some(_)) => Err(SessionError::Protocol(
                "unexpected message on a PUBLISH_NAMESPACE stream",
            )),
            Err(e) => Err(e),
        };

        tracing::info!(
            session = %self.id,
            namespace = %request.namespace,
            "namespace withdrawn"
        );
        self.fabric.withdraw(self.id, &request.namespace);
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
                    Some(NamespaceEvent::Gone(namespace)) => {
                        if let Some(suffix) = suffix_of(&namespace, &prefix) {
                            send(send_stream, &NamespaceDone::new(suffix)).await?;
                        }
                    }
                },

                // The peer closing the stream withdraws the watch, and this is
                // the only place that close is observable.
                frame = frames.next() => match frame {
                    Ok(None) => break Ok(()),
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
    async fn on_subscribe(
        &self,
        frame: &ControlFrame,
        send_stream: &mut SendStream,
        slot: Lease,
    ) -> Result<(), SessionError> {
        let request = Subscribe::decode(&mut frame.body.clone())?;
        let track = request.track.clone();

        let Some(publisher) = self.fabric.publisher(track.namespace()) else {
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
        let (ready, answered) = oneshot::channel();
        let command = Command::Subscribe {
            track: track.clone(),
            route: Route {
                session: self.transport.clone(),
                alias,
            },
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
            Ok(()) => {
                tracing::info!(session = %self.id, %track, %alias, "subscription established");
                self.fabric.metrics().subscribed(Subscribed::Established);
                // Recorded only once established, so a joining fetch cannot name
                // a subscription that was refused.
                self.lock_subscribed()
                    .insert(request.request_id, track.clone());
                // The slot outlives this request stream, because the
                // subscription does: the stream carries the answer and closes,
                // while objects keep flowing. Handing the lease to the session
                // here is what makes the concurrency limit count subscriptions
                // rather than requests in flight.
                self.lock_holding().insert(request.request_id, slot);
                send(send_stream, &SubscribeOk::new(alias)).await
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
                ready,
            } => {
                let session = self.clone();
                tokio::spawn(async move {
                    let result = session.subscribe_upstream(track, route).await;
                    // A dropped receiver means the downstream subscriber gave up
                    // while we were asking upstream. Its route was never
                    // registered, so there is nothing to undo.
                    let _ = ready.send(result);
                });
            }
        }
    }

    /// Subscribe to `track` on this session and route what comes back.
    ///
    /// Returns once the peer has answered, leaving a task holding the request
    /// stream open — closing it would cancel the subscription.
    async fn subscribe_upstream(
        &self,
        track: FullTrackName,
        route: Route,
    ) -> Result<(), UpstreamError> {
        let internal = |context: &str, e: &dyn std::fmt::Display| {
            UpstreamError::new(RequestErrorCode::INTERNAL_ERROR, format!("{context}: {e}"))
        };

        let (mut send_stream, recv) = self
            .transport
            .open_bi()
            .await
            .map_err(|e| internal("could not open a request stream", &e))?;

        let request = Subscribe::new(self.allocate_request_id(), track.clone());
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
                let downstream = route.alias;
                let upstream = ok.track_alias;
                self.add_route(upstream, route);
                self.lock_pulling().insert(upstream, track.clone());
                tracing::info!(
                    session = %self.id,
                    %track,
                    %upstream,
                    "pulling track"
                );

                let session = self.clone();
                tokio::spawn(async move {
                    // `send_stream` moves in deliberately: dropping it would
                    // reset the stream and cancel the subscription.
                    let _hold = send_stream;
                    while let Ok(Some(_)) = frames.next().await {}
                    session.remove_route(upstream, downstream);
                });
                Ok(())
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

        let mut outputs = Vec::with_capacity(routes.len());
        for route in routes {
            let Ok(mut stream) = route.session.open_uni().await else {
                continue;
            };
            let rewritten = SubgroupHeader {
                track_alias: route.alias,
                ..header.clone()
            };
            let mut buf = BytesMut::with_capacity(rewritten.encoded_len());
            rewritten.encode(&mut buf);
            if stream.write_all(&buf).await.is_ok() {
                outputs.push(stream);
            }
        }

        let leftover = frames.take_buffered();
        if !leftover.is_empty() {
            metrics.ingress(leftover.len());
            fan_out(&mut outputs, &leftover, metrics).await;
            if let Some(tee) = &mut tee {
                tee.absorb(&leftover);
            }
        }

        let mut chunk = [0u8; 8192];
        // Kept running for the cache's sake after the last subscriber has gone:
        // the objects still belong in history, and a subscriber arriving a moment
        // later wants them. Only a stream nobody is watching *and* nothing is
        // retaining is abandoned.
        while !outputs.is_empty() || tee.is_some() {
            match frames.stream.read(&mut chunk).await {
                Ok(Some(0) | None) | Err(_) => break,
                Ok(Some(n)) => {
                    metrics.ingress(n);
                    fan_out(&mut outputs, &chunk[..n], metrics).await;
                    if let Some(tee) = &mut tee {
                        tee.absorb(&chunk[..n]);
                    }
                }
            }
        }

        for mut stream in outputs {
            let _ = stream.finish();
        }
    }

    /// A parser recording this stream into the cache, if it can be attributed to
    /// a track and the cache is retaining anything.
    fn tee(&self, header: &SubgroupHeader) -> Option<Tee> {
        let track = self
            .lock_pulling()
            .get(&header.track_alias)
            .cloned()
            .or_else(|| {
                tracing::trace!(
                    session = %self.id,
                    alias = %header.track_alias,
                    "no track for this alias, so nothing to cache"
                );
                None
            })?;
        let recorder = self.fabric.cache().record(track, header);
        recorder.is_enabled().then(|| Tee::new(header, recorder))
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

    fn lock_pulling(&self) -> std::sync::MutexGuard<'_, HashMap<TrackAlias, FullTrackName>> {
        self.pulling
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lock_subscribed(&self) -> std::sync::MutexGuard<'_, HashMap<RequestId, FullTrackName>> {
        self.subscribed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lock_holding(&self) -> std::sync::MutexGuard<'_, HashMap<RequestId, Lease>> {
        self.holding
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn add_route(&self, alias: TrackAlias, route: Route) {
        self.lock_routes().entry(alias).or_default().push(route);
    }

    fn remove_route(&self, alias: TrackAlias, downstream: TrackAlias) {
        let mut routes = self.lock_routes();
        if let Some(list) = routes.get_mut(&alias) {
            list.retain(|r| r.alias != downstream);
            if list.is_empty() {
                routes.remove(&alias);
                // The upstream subscription existed only to feed these routes,
                // so with the last one gone the alias means nothing. Retained
                // history stays: it belongs to the track, not to a subscription.
                drop(routes);
                self.lock_pulling().remove(&alias);
            }
        }
    }

    fn routes_for(&self, alias: TrackAlias) -> Vec<Route> {
        self.lock_routes().get(&alias).cloned().unwrap_or_default()
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
}

impl Tee {
    fn new(header: &SubgroupHeader, recorder: cache::Recorder) -> Self {
        Self {
            reader: SubgroupReader::new(header),
            recorder,
            pending: BytesMut::new(),
            live: true,
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

/// Write `bytes` to every output, dropping the ones that fail.
///
/// A subscriber whose connection has gone must not stop the others from
/// receiving, so a failed write removes that output rather than aborting the
/// forward.
///
/// Egress is counted per surviving copy, so it exceeds ingress by the fan-out
/// ratio. That ratio is the whole reason a relay exists, and the two counters
/// together are the only place it is visible.
async fn fan_out(outputs: &mut Vec<SendStream>, bytes: &[u8], metrics: &Metrics) {
    let mut surviving = Vec::with_capacity(outputs.len());
    for mut stream in outputs.drain(..) {
        if stream.write_all(bytes).await.is_ok() {
            metrics.egress(bytes.len());
            surviving.push(stream);
        } else {
            metrics.fanout_failed();
        }
    }
    *outputs = surviving;
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
