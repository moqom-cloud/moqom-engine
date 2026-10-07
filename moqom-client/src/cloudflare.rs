//! A draft-16 subscriber, for Cloudflare's relays.
//!
//! Cloudflare runs draft-ietf-moq-transport-16 at
//! [`DEMO_HOST`], over raw QUIC with the `moqt-16` ALPN. Its session
//! credential is a JWT carried in the `PATH` Setup Parameter as `/<jwt>`; no
//! MOQOM private parameter is ever sent, since a draft-16 peer that receives
//! an unknown Message Parameter must close the session (§9.2).
//!
//! The session shape differs from [`crate::Session`]'s:
//!
//! - One bidirectional control stream carries every message, each naming its
//!   Request ID, so a reader task routes answers to the request waiting for
//!   them.
//! - Request IDs are even, from 0, and must stay below the relay's
//!   `MAX_REQUEST_ID`; a client at the limit sends `REQUESTS_BLOCKED` and
//!   waits for the limit to rise.
//! - A subscription ends with `UNSUBSCRIBE` (sent when a [`Subscription`] is
//!   dropped) or the relay's `PUBLISH_DONE`.
//!
//! Subscribing is all this does. The relay is told it may make no requests
//! of us (`MAX_REQUEST_ID` 0), so it cannot `PUBLISH` to this session; one
//! that does anyway is a protocol violation.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use moqom_proto::Draft;
use moqom_proto::control::d16::{
    ClientRequestIds, Filter, Message, TrackRequest, largest_object, setup_param,
};
use moqom_proto::control::{Parameter, Parameters, RequestId};
use moqom_proto::data::{SubgroupContent, SubgroupHeader, SubgroupReader};
use moqom_proto::error::DecodeError;
use moqom_proto::model::{FullTrackName, Location, TrackAlias};
use moqom_proto::varint::VarInt;
use tokio::sync::{Notify, mpsc, oneshot};

use crate::Error;
use crate::properties::ObjectProperties;
use crate::session::{IMPLEMENTATION, Object};
use crate::tls::install_crypto_provider;

/// Cloudflare's draft-16 relay.
pub const DEMO_HOST: &str = "draft-16.cloudflare.mediaoverquic.com";

/// The port it listens on.
pub const DEMO_PORT: u16 = 443;

const DRAFT: Draft = Draft::D16;

/// `PROTOCOL_VIOLATION` (§13.4.1).
const PROTOCOL_VIOLATION: u32 = 0x3;

/// `NO_ERROR` (§13.4.1).
const NO_ERROR: u32 = 0x0;

/// How long a data stream naming an alias not yet known is held for the
/// `SUBSCRIBE_OK` that introduces it. §10.4.2 allows buffering "for a brief
/// period"; the two race only by a round trip's worth of reordering.
const ALIAS_GRACE: Duration = Duration::from_secs(1);

/// How many unread objects a subscription holds before its reader waits.
const INBOX_DEPTH: usize = 64;

/// How a subscription ended, from `PUBLISH_DONE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ended {
    /// §13.4.3: 0x2 TRACK_ENDED, 0x3 SUBSCRIPTION_ENDED, 0x4 GOING_AWAY, ….
    pub status: u64,
    /// Data streams the relay opened for the subscription.
    pub stream_count: u64,
    /// What the relay said.
    pub reason: String,
}

/// A draft-16 session that has completed SETUP.
pub struct Session {
    connection: quinn::Connection,
    control: Arc<tokio::sync::Mutex<quinn::SendStream>>,
    shared: Arc<Shared>,
    /// Owns the socket; dropping it closes the connection.
    _endpoint: quinn::Endpoint,
}

/// State the control and data readers share with requests in flight.
#[derive(Default)]
struct Shared {
    ids: Mutex<ClientRequestIds>,
    /// Signalled when `MAX_REQUEST_ID` raises the limit.
    raised: Notify,
    /// Answers awaited, by Request ID.
    pending: Mutex<HashMap<RequestId, oneshot::Sender<Message>>>,
    /// Established subscriptions: their alias, by Request ID.
    subscriptions: Mutex<HashMap<RequestId, TrackAlias>>,
    /// Where each alias's objects go.
    inbox: Mutex<HashMap<TrackAlias, mpsc::Sender<Result<Object, Error>>>>,
    /// Subscriptions the relay ended.
    ended: Mutex<HashMap<RequestId, Ended>>,
    /// Why the control stream stopped, once it has.
    fault: Mutex<Option<String>>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A live draft-16 subscription. Dropping it sends `UNSUBSCRIBE`.
pub struct Subscription {
    /// The `SUBSCRIBE`'s Request ID.
    pub request_id: RequestId,
    /// The alias the relay assigned.
    pub alias: TrackAlias,
    /// `LARGEST_OBJECT` from `SUBSCRIBE_OK`: absent if nothing has been
    /// published on the track.
    pub largest: Option<Location>,
    rx: mpsc::Receiver<Result<Object, Error>>,
    control: Arc<tokio::sync::Mutex<quinn::SendStream>>,
    shared: Arc<Shared>,
}

impl Session {
    /// Connect to `host:port` and exchange SETUP, presenting `token` as
    /// the `PATH` `/<token>`.
    ///
    /// Trusts the webpki roots, which is what Cloudflare's certificate
    /// chains to.
    ///
    /// # Errors
    /// Resolving `host`, the handshake, or a SETUP the relay refuses.
    pub async fn connect(host: &str, port: u16, token: &str) -> Result<Self, Error> {
        let name = host.to_owned();
        let addrs = tokio::task::spawn_blocking(move || {
            (name.as_str(), port)
                .to_socket_addrs()
                .map(Iterator::collect::<Vec<_>>)
        })
        .await
        .map_err(|e| Error::Io(std::io::Error::other(e)))??;
        // IPv4 first: a v6 address the local network cannot route fails slowly.
        let addr = addrs
            .iter()
            .find(|a| a.is_ipv4())
            .or_else(|| addrs.first())
            .copied()
            .ok_or_else(|| Error::Io(std::io::Error::other(format!("{host} has no address"))))?;
        Self::connect_to(addr, host, crate::tls::native(), token).await
    }

    /// Connect to `addr`, verifying it as `server_name` with `tls`.
    ///
    /// `server_name` is also the `AUTHORITY` Setup Parameter, which §9.3.1.1
    /// requires over native QUIC.
    ///
    /// # Errors
    /// As [`Self::connect`].
    pub async fn connect_to(
        addr: SocketAddr,
        server_name: &str,
        mut tls: rustls::ClientConfig,
        token: &str,
    ) -> Result<Self, Error> {
        install_crypto_provider();
        tls.alpn_protocols = vec![DRAFT.alpn().to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(Error::tls)?;
        let local = if addr.is_ipv4() {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        };
        let mut endpoint = quinn::Endpoint::client(local)?;
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        let connection = endpoint.connect(addr, server_name)?.await?;

        let (mut send, mut recv) = connection.open_bi().await?;
        let setup = Message::ClientSetup(client_setup(server_name, token)?);
        write(&mut send, &setup).await?;

        let mut buffer = BytesMut::new();
        let shared = Arc::new(Shared::default());
        match read_message(&mut recv, &mut buffer).await {
            Ok(Some(Message::ServerSetup(parameters))) => {
                let max = parameters
                    .get(setup_param::MAX_REQUEST_ID)
                    .and_then(Parameter::as_varint)
                    .map_or(0, VarInt::get);
                lock(&shared.ids).raise(max)?;
            }
            Ok(Some(other)) => {
                connection.close(PROTOCOL_VIOLATION.into(), b"expected SERVER_SETUP");
                return Err(Error::Setup(format!("expected SERVER_SETUP, got {other:?}")));
            }
            Ok(None) | Err(_) => return Err(crate::session::rejection(&connection).await),
        }

        tokio::spawn(read_control(
            connection.clone(),
            recv,
            buffer,
            Arc::clone(&shared),
        ));
        tokio::spawn(read_data(connection.clone(), Arc::clone(&shared)));
        Ok(Self {
            connection,
            control: Arc::new(tokio::sync::Mutex::new(send)),
            shared,
            _endpoint: endpoint,
        })
    }

    /// Subscribe to `track`, from where `filter` says; `None` is the
    /// unfiltered subscription draft-16 defaults to (§9.2.2.5).
    ///
    /// # Errors
    /// The relay refused, the session failed, or the relay's request limit
    /// did not rise within ten seconds of our saying we were blocked on it.
    pub async fn subscribe(
        &self,
        track: FullTrackName,
        filter: Option<Filter>,
    ) -> Result<Subscription, Error> {
        let request_id = self.allocate().await?;
        let mut request = TrackRequest::new(request_id, track);
        if let Some(filter) = filter {
            request.parameters.push(filter.parameter());
        }

        let (answered, answer) = oneshot::channel();
        lock(&self.shared.pending).insert(request_id, answered);
        self.send(&Message::Subscribe(request)).await?;
        let answer = answer.await.map_err(|_| self.fault())?;

        match answer {
            Message::SubscribeOk {
                track_alias,
                parameters,
                ..
            } => {
                let (tx, rx) = mpsc::channel(INBOX_DEPTH);
                // A PUBLISH_DONE can overtake this task between the answer
                // arriving and here, and then there is nothing to route.
                if !lock(&self.shared.ended).contains_key(&request_id) {
                    lock(&self.shared.inbox).insert(track_alias, tx);
                    lock(&self.shared.subscriptions).insert(request_id, track_alias);
                }
                Ok(Subscription {
                    request_id,
                    alias: track_alias,
                    largest: largest_object(&parameters),
                    rx,
                    control: Arc::clone(&self.control),
                    shared: Arc::clone(&self.shared),
                })
            }
            Message::RequestError { code, reason, .. } => Err(Error::Refused {
                code: code.get(),
                reason: reason.to_string(),
            }),
            other => Err(Error::Protocol(format!(
                "{other:?} in answer to SUBSCRIBE"
            ))),
        }
    }

    /// End the session, saying nothing went wrong.
    pub fn close(&self) {
        self.connection.close(NO_ERROR.into(), b"");
    }

    /// Wait for the session to end, and report why.
    pub async fn closed(&self) -> Error {
        Error::Handshake(self.connection.closed().await)
    }

    async fn allocate(&self) -> Result<RequestId, Error> {
        let mut told = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            // Registered before checking, so a raise between the check and
            // the wait is not missed.
            let raised = self.shared.raised.notified();
            let blocked_at = {
                let mut ids = lock(&self.shared.ids);
                if let Some(id) = ids.allocate() {
                    return Ok(id);
                }
                ids.limit()
            };
            if !told {
                self.send(&Message::RequestsBlocked(VarInt::new(blocked_at)?))
                    .await?;
                told = true;
            }
            if tokio::time::timeout_at(deadline, raised).await.is_err() {
                return Err(Error::RequestIdsExhausted);
            }
        }
    }

    async fn send(&self, message: &Message) -> Result<(), Error> {
        write(&mut *self.control.lock().await, message).await
    }

    fn fault(&self) -> Error {
        match lock(&self.shared.fault).clone() {
            Some(reason) => Error::Protocol(reason),
            None => Error::Closed,
        }
    }
}

impl Subscription {
    /// The next object, or `None` once the subscription has ended — by the
    /// relay's `PUBLISH_DONE` (see [`Self::ended`]) or the session closing.
    ///
    /// # Errors
    /// A data stream that could not be decoded.
    pub async fn next_object(&mut self) -> Result<Option<Object>, Error> {
        match self.rx.recv().await {
            Some(result) => result.map(Some),
            None => Ok(None),
        }
    }

    /// How the relay ended this subscription, if it has.
    #[must_use]
    pub fn ended(&self) -> Option<Ended> {
        lock(&self.shared.ended).get(&self.request_id).cloned()
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        lock(&self.shared.inbox).remove(&self.alias);
        let ended = lock(&self.shared.subscriptions)
            .remove(&self.request_id)
            .is_none();
        if ended {
            return;
        }
        let control = Arc::clone(&self.control);
        let request_id = self.request_id;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = write(
                    &mut *control.lock().await,
                    &Message::Unsubscribe { request_id },
                )
                .await;
            });
        }
    }
}

/// `CLIENT_SETUP`'s parameters: where, who, and that the relay may not make
/// requests of us.
fn client_setup(authority: &str, token: &str) -> Result<Parameters, Error> {
    let mut parameters = Parameters::new();
    let setup = |e| Error::Setup(format!("{e}"));
    parameters.push(
        Parameter::bytes(setup_param::PATH, Bytes::from(format!("/{token}"))).map_err(setup)?,
    );
    parameters.push(Parameter::varint(setup_param::MAX_REQUEST_ID, VarInt::from_u32(0)).map_err(setup)?);
    parameters.push(
        Parameter::bytes(setup_param::AUTHORITY, Bytes::copy_from_slice(authority.as_bytes()))
            .map_err(setup)?,
    );
    parameters.push(
        Parameter::bytes(setup_param::MOQT_IMPLEMENTATION, IMPLEMENTATION).map_err(setup)?,
    );
    Ok(parameters)
}

async fn write(stream: &mut quinn::SendStream, message: &Message) -> Result<(), Error> {
    let bytes = message.to_bytes(DRAFT)?;
    stream.write_all(&bytes).await.map_err(Error::write)
}

/// The next control message, or `None` at the end of the stream.
async fn read_message(
    recv: &mut quinn::RecvStream,
    buffer: &mut BytesMut,
) -> Result<Option<Message>, Error> {
    loop {
        let mut cursor = &buffer[..];
        match Message::decode(DRAFT, &mut cursor) {
            Ok(message) => {
                let consumed = buffer.len() - cursor.len();
                let _ = buffer.split_to(consumed);
                return Ok(Some(message));
            }
            Err(DecodeError::Short { .. }) => {}
            Err(e) => return Err(e.into()),
        }
        match recv.read_chunk(64 * 1024, true).await {
            Ok(Some(chunk)) => buffer.extend_from_slice(&chunk.bytes),
            Ok(None) | Err(_) => return Ok(None),
        }
    }
}

/// Route control messages until the stream ends, closing the session on one
/// this subset may not receive.
async fn read_control(
    connection: quinn::Connection,
    mut recv: quinn::RecvStream,
    mut buffer: BytesMut,
    shared: Arc<Shared>,
) {
    let fault = loop {
        let message = match read_message(&mut recv, &mut buffer).await {
            Ok(Some(message)) => message,
            Ok(None) => break "the relay closed the control stream".to_owned(),
            Err(e) => {
                connection.close(PROTOCOL_VIOLATION.into(), b"undecodable control message");
                break format!("undecodable control message: {e}");
            }
        };
        if let Err(violation) = route(&shared, message) {
            connection.close(PROTOCOL_VIOLATION.into(), violation.as_bytes());
            break violation;
        }
    };
    *lock(&shared.fault) = Some(fault);
    // Nothing more will be answered: fail every request still waiting, and
    // end every subscription.
    lock(&shared.pending).clear();
    lock(&shared.inbox).clear();
}

fn route(shared: &Shared, message: Message) -> Result<(), String> {
    match message {
        Message::MaxRequestId(max) => {
            lock(&shared.ids)
                .raise(max.get())
                .map_err(|e| e.to_string())?;
            shared.raised.notify_waiters();
        }
        Message::SubscribeOk { request_id, .. }
        | Message::RequestError { request_id, .. }
        | Message::RequestOk { request_id, .. } => {
            let Some(waiting) = lock(&shared.pending).remove(&request_id) else {
                return Err(format!("an answer to request {request_id}, which is not open"));
            };
            let _ = waiting.send(message);
        }
        Message::PublishDone {
            request_id,
            status,
            stream_count,
            reason,
        } => {
            if let Some(alias) = lock(&shared.subscriptions).remove(&request_id) {
                lock(&shared.inbox).remove(&alias);
            }
            lock(&shared.ended).insert(
                request_id,
                Ended {
                    status: status.get(),
                    stream_count: stream_count.get(),
                    reason: reason.to_string(),
                },
            );
        }
        // The relay is blocked on the limit of 0 we set, which is the point.
        Message::RequestsBlocked(_) => {}
        // GOAWAY: the relay is leaving. Subscriptions run until it does.
        Message::Unsupported {
            message_type: 0x10, ..
        } => {}
        other => return Err(format!("unexpected {other:?}")),
    }
    Ok(())
}

/// Accept data streams for the life of the connection.
async fn read_data(connection: quinn::Connection, shared: Arc<Shared>) {
    while let Ok(recv) = connection.accept_uni().await {
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            let _ = read_subgroup(recv, &shared).await;
        });
    }
}

async fn read_subgroup(mut recv: quinn::RecvStream, shared: &Shared) -> Result<(), Error> {
    let mut buffer = BytesMut::new();
    let header = loop {
        let mut cursor = &buffer[..];
        match DRAFT.scope(|| SubgroupHeader::decode(&mut cursor)) {
            Ok(header) => {
                let consumed = buffer.len() - cursor.len();
                let _ = buffer.split_to(consumed);
                break header;
            }
            Err(DecodeError::Short { .. }) => {}
            Err(e) => return Err(e.into()),
        }
        if !fill(&mut recv, &mut buffer).await {
            return Ok(());
        }
    };

    let Some(tx) = route_for(shared, header.track_alias).await else {
        let _ = recv.stop(0u32.into());
        return Ok(());
    };
    let mut reader = DRAFT.scope(|| SubgroupReader::new(&header));
    loop {
        let mut cursor = &buffer[..];
        match reader.read(&mut cursor) {
            Ok(object) => {
                let consumed = buffer.len() - cursor.len();
                let _ = buffer.split_to(consumed);
                let SubgroupContent::Normal {
                    payload,
                    properties,
                } = object.content
                else {
                    continue;
                };
                let delivered = Object {
                    group: header.group,
                    object: object.object.get(),
                    payload,
                    properties: ObjectProperties::from_wire(&properties),
                };
                if tx.send(Ok(delivered)).await.is_err() {
                    return Ok(());
                }
            }
            Err(DecodeError::Short { .. }) => {
                if !fill(&mut recv, &mut buffer).await {
                    return Ok(());
                }
            }
            Err(e) => {
                let _ = tx.send(Err(e.into())).await;
                return Ok(());
            }
        }
    }
}

/// The inbox for `alias`, waiting briefly for a `SUBSCRIBE_OK` still in
/// flight.
async fn route_for(
    shared: &Shared,
    alias: TrackAlias,
) -> Option<mpsc::Sender<Result<Object, Error>>> {
    let deadline = tokio::time::Instant::now() + ALIAS_GRACE;
    loop {
        if let Some(tx) = lock(&shared.inbox).get(&alias).cloned() {
            return Some(tx);
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn fill(recv: &mut quinn::RecvStream, buffer: &mut BytesMut) -> bool {
    match recv.read_chunk(64 * 1024, true).await {
        Ok(Some(chunk)) => {
            buffer.extend_from_slice(&chunk.bytes);
            true
        }
        Ok(None) | Err(_) => false,
    }
}
