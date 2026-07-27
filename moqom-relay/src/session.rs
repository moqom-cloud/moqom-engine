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
use std::sync::{Arc, Mutex};

use bytes::{Buf, Bytes, BytesMut};
use moqom_proto::control::{
    ControlFrame, MessageBody, MessageType, Namespace, NamespaceDone, PublishNamespace,
    ReasonPhrase, RequestError, RequestErrorCode, RequestId, RequestIdGenerator, Role, Setup,
    Subscribe, SubscribeNamespace, SubscribeOk, setup, write_message,
};
use moqom_proto::data::SubgroupHeader;
use moqom_proto::error::DecodeError;
use moqom_proto::model::{FullTrackName, TrackAlias, TrackNamespace};
use moqom_proto::varint::VarInt;
use tokio::sync::{mpsc, oneshot};
use web_transport_quinn::{RecvStream, SendStream};

use crate::fabric::{Command, Fabric, NamespaceEvent, Route, SessionId, UpstreamError};

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
}

/// Application error codes this relay closes sessions with.
mod code {
    /// The peer did something the protocol forbids.
    pub const PROTOCOL_VIOLATION: u32 = 0x01;
    /// This relay failed, not the peer.
    pub const INTERNAL: u32 = 0x02;
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
        };

        let result = session.run(command_queue).await;
        fabric.remove_session(id);

        match &result {
            Ok(()) => session.transport.close(0, b"bye"),
            Err(SessionError::Protocol(reason)) => session
                .transport
                .close(code::PROTOCOL_VIOLATION, reason.as_bytes()),
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

    async fn run(&self, commands: mpsc::Receiver<Command>) -> Result<(), SessionError> {
        let (mut control_send, control_recv) = self.transport.accept_bi().await?;
        let mut control = Frames::new(control_recv);
        self.handshake(&mut control_send, &mut control).await?;
        tracing::info!(session = %self.id, carrier = ?self.carrier, "session established");

        // Three loops rather than one `select!` over the accept futures: whether
        // `accept_bi` is cancel-safe is not something to bet a dropped stream
        // on, and separating them means each is only ever cancelled when the
        // session is already ending.
        tokio::select! {
            result = self.serve_control(control_send, control, commands) => result,
            result = self.accept_requests() => result,
            result = self.accept_data() => result,
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
    ) -> Result<(), SessionError> {
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
        send(send_stream, &ours).await
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

        let outcome = match frame.message_type {
            MessageType::PublishNamespace => self.on_publish_namespace(&frame, &mut frames).await,
            MessageType::SubscribeNamespace => {
                self.on_subscribe_namespace(&frame, &mut send_stream, &mut frames)
                    .await
            }
            MessageType::Subscribe => self.on_subscribe(&frame, &mut send_stream).await,
            other => {
                tracing::debug!(session = %self.id, ?other, "unsupported request");
                send(
                    &mut send_stream,
                    &RequestError::new(
                        RequestErrorCode::NOT_SUPPORTED,
                        ReasonPhrase::truncating("this relay does not serve that request"),
                    ),
                )
                .await
            }
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
    ) -> Result<(), SessionError> {
        let request = Subscribe::decode(&mut frame.body.clone())?;
        let track = request.track.clone();

        let Some(publisher) = self.fabric.publisher(track.namespace()) else {
            tracing::debug!(session = %self.id, %track, "no publisher for namespace");
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
                send(send_stream, &SubscribeOk::new(alias)).await
            }
            Err(e) => {
                tracing::debug!(session = %self.id, %track, error = %e, "upstream refused");
                send(
                    send_stream,
                    &RequestError::new(e.code, ReasonPhrase::truncating(&e.reason)),
                )
                .await
            }
        }
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
    /// everything after it is copied verbatim. The relay never looks at an
    /// object, which is what lets payloads stay encrypted end to end.
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

        let routes = self.routes_for(header.track_alias);
        if routes.is_empty() {
            // Nowhere to put this. Reading it to the end anyway would spend the
            // bandwidth twice over for nothing.
            tracing::trace!(
                session = %self.id,
                alias = %header.track_alias,
                "subgroup with no subscribers"
            );
            return;
        }

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
            fan_out(&mut outputs, &leftover).await;
        }

        let mut chunk = [0u8; 8192];
        while !outputs.is_empty() {
            match frames.stream.read(&mut chunk).await {
                Ok(Some(0) | None) | Err(_) => break,
                Ok(Some(n)) => fan_out(&mut outputs, &chunk[..n]).await,
            }
        }

        for mut stream in outputs {
            let _ = stream.finish();
        }
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

    fn add_route(&self, alias: TrackAlias, route: Route) {
        self.lock_routes().entry(alias).or_default().push(route);
    }

    fn remove_route(&self, alias: TrackAlias, downstream: TrackAlias) {
        let mut routes = self.lock_routes();
        if let Some(list) = routes.get_mut(&alias) {
            list.retain(|r| r.alias != downstream);
            if list.is_empty() {
                routes.remove(&alias);
            }
        }
    }

    fn routes_for(&self, alias: TrackAlias) -> Vec<Route> {
        self.lock_routes().get(&alias).cloned().unwrap_or_default()
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
async fn fan_out(outputs: &mut Vec<SendStream>, bytes: &[u8]) {
    let mut surviving = Vec::with_capacity(outputs.len());
    for mut stream in outputs.drain(..) {
        if stream.write_all(bytes).await.is_ok() {
            surviving.push(stream);
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
