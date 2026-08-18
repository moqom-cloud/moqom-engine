//! A MOQT session from the client side of SETUP.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bytes::{Buf, Bytes, BytesMut};
use moqom_proto::control::{
    ControlFrame, MessageBody, MessageType, PublishNamespace, ReasonPhrase, RequestError,
    RequestErrorCode, RequestIdGenerator, Role, Setup, Subscribe, SubscribeOk, write_message,
};
use moqom_proto::data::{
    SubgroupContent, SubgroupHeader, SubgroupObject, SubgroupReader, SubgroupSource, SubgroupWriter,
};
use moqom_proto::error::DecodeError;
use moqom_proto::model::{FullTrackName, GroupId, TrackAlias, TrackNamespace};
use moqom_proto::varint::VarInt;
use tokio::sync::{mpsc, watch};
use web_transport_quinn::{RecvStream, SendStream};

use crate::Error;
use crate::properties::ObjectProperties;
use crate::tls::{apply_alpn, install_crypto_provider};

/// One object delivered on a subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    /// The group this object belongs to.
    pub group: GroupId,
    /// Absolute object ID, already resolved from the stream's deltas.
    pub object: u64,
    /// Payload bytes. Empty is a legal normal object.
    pub payload: Bytes,
    /// What the publisher said about this object, and the reason a subscriber can
    /// measure latency: the capture time is on the object rather than inferred
    /// from arrival order.
    pub properties: ObjectProperties,
}

/// One object to publish: a payload, and what to say about it.
///
/// Separate from [`Object`] because the two are not the same thing in either
/// direction — this borrows its payload, since a publisher already has the bytes
/// somewhere, and it has no object ID, those being assigned by position within
/// the group.
#[derive(Debug, Clone, Default)]
pub struct OutgoingObject<'a> {
    /// The bytes to send.
    pub payload: &'a [u8],
    /// What to say about them.
    pub properties: ObjectProperties,
}

impl<'a> OutgoingObject<'a> {
    /// A payload with nothing said about it.
    #[must_use]
    pub fn new(payload: &'a [u8]) -> Self {
        Self {
            payload,
            properties: ObjectProperties::default(),
        }
    }

    /// A payload tagged with the properties given.
    #[must_use]
    pub const fn tagged(payload: &'a [u8], properties: ObjectProperties) -> Self {
        Self {
            payload,
            properties,
        }
    }
}

/// A live subscription. Dropping it cancels the subscription.
pub struct Subscription {
    /// The alias the peer assigned, which forwarded headers must carry.
    pub alias: TrackAlias,
    rx: mpsc::Receiver<Result<Object, Error>>,
    _send: SendStream,
    _recv: RecvStream,
}

/// A live announcement. Dropping it withdraws the namespace.
pub struct Announcement {
    alias: TrackAlias,
    subscribed: watch::Receiver<bool>,
    _send: SendStream,
    _recv: RecvStream,
}

const IMPLEMENTATION: &[u8] = b"moqom-client";

type Inbox = HashMap<TrackAlias, mpsc::Sender<Result<Object, Error>>>;

/// How many unread objects a subscription will hold before the reader waits.
const INBOX_DEPTH: usize = 64;

/// A MOQT peer that has completed SETUP.
pub struct Session {
    transport: moqom_transport::Session,
    requests: RequestIdGenerator,
    next_alias: AtomicU64,
    published: Arc<Mutex<HashMap<TrackNamespace, PublishSlot>>>,
    inbox: Arc<Mutex<Inbox>>,
    /// Held open for the life of the session: closing the control stream ends it.
    _control: (SendStream, RecvStream),
    /// Owns the client socket. Dropping the endpoint closes every connection on
    /// it, so this has to outlive the session.
    _endpoint: quinn::Endpoint,
}

/// One announced namespace, and the alias objects for it will carry.
#[derive(Clone)]
struct PublishSlot {
    alias: TrackAlias,
    subscribed: watch::Sender<bool>,
    /// Upstream request streams the relay opened. Dropping one is how this
    /// protocol spells "stop publishing this track", so they have to outlive
    /// `SUBSCRIBE_OK`.
    held: Arc<Mutex<Vec<(SendStream, RecvStream)>>>,
}

impl Session {
    /// Connect to `addr` over raw QUIC and exchange SETUP.
    ///
    /// `server_name` is the SNI and the name verified against the certificate,
    /// unless `tls` skips verification. `token`, when present, is sent as
    /// `AUTHORIZATION_TOKEN`. The `moqt-19` ALPN is set on `tls` here, so a
    /// caller cannot accidentally complete a handshake that is not MOQT.
    ///
    /// # Errors
    /// Binding, the handshake, or a SETUP the peer refuses or mis-encodes.
    pub async fn connect(
        addr: SocketAddr,
        server_name: &str,
        mut tls: rustls::ClientConfig,
        token: Option<&[u8]>,
    ) -> Result<Self, Error> {
        install_crypto_provider();
        apply_alpn(&mut tls);

        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(Error::tls)?;
        let mut endpoint = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));

        let connection = endpoint.connect(addr, server_name)?.await?;
        let transport = moqom_transport::Session::raw(
            connection,
            web_transport_quinn::proto::ConnectRequest::new(placeholder_url()),
            web_transport_quinn::proto::ConnectResponse::OK,
        );

        let (mut send, recv) = transport.open_bi().await?;
        let mut ours = Setup::new();
        ours.options
            .set_bytes(
                moqom_proto::control::setup::option_type::MOQT_IMPLEMENTATION,
                IMPLEMENTATION,
            )
            .map_err(Error::setup)?;
        if let Some(token) = token {
            ours.options
                .set_bytes(
                    moqom_proto::control::setup::option_type::AUTHORIZATION_TOKEN,
                    Bytes::copy_from_slice(token),
                )
                .map_err(Error::setup)?;
        }
        write(&mut send, &ours).await?;

        let mut frames = Frames::new(recv);
        let frame = frames.next().await?.ok_or(Error::Closed)?;
        if frame.message_type != MessageType::Setup {
            return Err(Error::Unexpected {
                found: frame.message_type,
                during: "SETUP",
            });
        }
        let mut body = frame.body.clone();
        let len = body.len();
        Setup::decode(&mut body, len)?;

        let published = Arc::new(Mutex::new(HashMap::new()));
        let inbox = Arc::new(Mutex::new(HashMap::new()));
        spawn_publisher(transport.clone(), Arc::clone(&published));
        spawn_reader(transport.clone(), Arc::clone(&inbox));

        Ok(Self {
            transport,
            requests: RequestIdGenerator::new(Role::Client),
            // Not zero: the relay hands out aliases from zero, so a publisher
            // that starts at 7 makes a forgotten rewrite observable — the
            // subscriber would see 7 in a header that should carry its own 0.
            next_alias: AtomicU64::new(7),
            published,
            inbox,
            _control: (send, frames.into_inner()),
            _endpoint: endpoint,
        })
    }

    fn next_request(&mut self) -> Result<moqom_proto::control::RequestId, Error> {
        self.requests.allocate().ok_or(Error::RequestIdsExhausted)
    }

    /// Subscribe to `track`.
    ///
    /// The returned [`Subscription`] holds the request stream: dropping it
    /// cancels the subscription, so callers keep it for as long as they expect
    /// objects.
    ///
    /// # Errors
    /// The peer refused, answered with the wrong message, or the session failed.
    pub async fn subscribe(&mut self, track: FullTrackName) -> Result<Subscription, Error> {
        let (mut send, recv) = self.transport.open_bi().await?;
        let request = Subscribe::new(self.next_request()?, track);
        write(&mut send, &request).await?;

        let mut frames = Frames::new(recv);
        let frame = frames.next().await?.ok_or(Error::Closed)?;
        match frame.message_type {
            MessageType::SubscribeOk => {
                let ok = SubscribeOk::decode(&mut frame.body.clone())?;
                let (tx, rx) = mpsc::channel(INBOX_DEPTH);
                self.inbox
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(ok.track_alias, tx);
                Ok(Subscription {
                    alias: ok.track_alias,
                    rx,
                    _send: send,
                    _recv: frames.into_inner(),
                })
            }
            MessageType::RequestError => {
                let error = RequestError::decode(&mut frame.body.clone())?;
                Err(Error::Refused {
                    code: error.code.get(),
                    reason: error.reason.to_string(),
                })
            }
            found => Err(Error::Unexpected {
                found,
                during: "SUBSCRIBE",
            }),
        }
    }

    /// Announce `namespace`, returning a handle that holds the announcement.
    ///
    /// Dropping the handle withdraws it: there is no `UNANNOUNCE` message.
    /// Incoming `SUBSCRIBE` for a track in this namespace is answered with the
    /// alias on the handle, so [`publish_group`](Self::publish_group) can use
    /// that same number.
    ///
    /// # Errors
    /// Opening the request stream, encoding the announcement, or exhausting
    /// request IDs.
    pub async fn announce(&mut self, namespace: TrackNamespace) -> Result<Announcement, Error> {
        let (mut send, recv) = self.transport.open_bi().await?;
        let request = PublishNamespace::new(self.next_request()?, namespace.clone());
        write(&mut send, &request).await?;

        let raw = self.next_alias.fetch_add(1, Ordering::Relaxed);
        let alias = TrackAlias::new(VarInt::new(raw)?);
        let (subscribed, watch) = watch::channel(false);
        self.published
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                namespace,
                PublishSlot {
                    alias,
                    subscribed,
                    held: Arc::new(Mutex::new(Vec::new())),
                },
            );

        Ok(Announcement {
            alias,
            subscribed: watch,
            _send: send,
            _recv: recv,
        })
    }

    /// Write one subgroup into `group`, numbering objects from zero.
    ///
    /// Finishing the stream matters: a stream left open leaves its last objects
    /// in flight at a relay that parses as bytes arrive.
    ///
    /// # Errors
    /// Opening the data stream, encoding the subgroup, or writing it.
    pub async fn publish_group(
        &self,
        alias: TrackAlias,
        group: u64,
        payloads: &[&[u8]],
    ) -> Result<(), Error> {
        let objects: Vec<OutgoingObject<'_>> =
            payloads.iter().copied().map(OutgoingObject::new).collect();
        self.publish_objects(alias, group, &objects).await
    }

    /// Write one subgroup into `group`, with what to say about each object.
    ///
    /// This is what a media publisher wants and [`Self::publish_group`] cannot
    /// express: a frame's capture time and temporal layer travel as object
    /// properties, so a viewer can measure end-to-end latency and a relay can
    /// drop an enhancement layer without decoding anything. See
    /// [`crate::properties`] for the codes.
    ///
    /// `properties_present` is declared on the header only when something is
    /// actually said, because the flag changes the stream's type code: setting it
    /// unconditionally would put every publisher on a wire format that costs a
    /// length prefix per object to carry nothing.
    ///
    /// # Errors
    /// Opening the data stream, encoding the subgroup, or writing it.
    pub async fn publish_objects(
        &self,
        alias: TrackAlias,
        group: u64,
        objects: &[OutgoingObject<'_>],
    ) -> Result<(), Error> {
        let group = GroupId::new(VarInt::new(group)?);
        let mut stream = self.transport.open_uni().await?;
        let mut header = SubgroupHeader::new(alias, group, SubgroupSource::Zero);
        header.properties_present = objects.iter().any(|object| !object.properties.is_empty());

        let mut buf = BytesMut::new();
        header.encode(&mut buf);
        let mut writer = SubgroupWriter::new(&header);
        for (index, object) in objects.iter().enumerate() {
            let payload = Bytes::copy_from_slice(object.payload);
            let encoded = if header.properties_present {
                SubgroupObject {
                    object: (index as u32).into(),
                    content: SubgroupContent::Normal {
                        payload,
                        properties: object.properties.to_wire(),
                    },
                }
            } else {
                SubgroupObject::new(index as u32, payload)
            };
            writer.write(&mut buf, &encoded)?;
        }

        stream.write_all(&buf).await.map_err(Error::write)?;
        stream.finish().map_err(Error::write)?;
        Ok(())
    }

    /// Open a group and write objects into it as they arrive.
    ///
    /// [`Self::publish_objects`] takes a whole group at once, which a publisher
    /// reading from a file or an encoder does not have: a group is a group of
    /// pictures, so waiting to fill one delays its first frame by the entire
    /// group. On a two-second GOP that is two seconds added to every frame, and
    /// the capture times the objects carry would faithfully record it — measuring
    /// the buffer rather than the network. Frames go out as they are produced
    /// instead, which is also what the iOS publisher does.
    ///
    /// Whether objects carry properties is declared here because it is a flag on
    /// the header, which goes out before the first object.
    ///
    /// # Errors
    /// Opening the data stream, or writing the header.
    pub async fn open_group(
        &self,
        alias: TrackAlias,
        group: u64,
        metadata: Metadata,
    ) -> Result<GroupWriter, Error> {
        let group = GroupId::new(VarInt::new(group)?);
        let mut stream = self.transport.open_uni().await?;
        let mut header = SubgroupHeader::new(alias, group, SubgroupSource::Zero);
        header.properties_present = metadata == Metadata::Present;

        let mut buf = BytesMut::new();
        header.encode(&mut buf);
        stream.write_all(&buf).await.map_err(Error::write)?;

        Ok(GroupWriter {
            writer: SubgroupWriter::new(&header),
            properties_present: header.properties_present,
            stream,
            next: 0,
        })
    }
}

/// Whether the objects in a group will say anything about themselves.
///
/// Declared when the group is opened rather than inferred per object, since the
/// flag is on the header. It is not free either way: present costs a length
/// prefix on every object, so a publisher sending bytes should not ask for it,
/// and a publisher sending frames cannot do without it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Metadata {
    /// Objects may carry properties.
    Present,
    /// No object will, and the stream stays on the cheaper type code.
    Absent,
}

/// A group being written one object at a time.
///
/// Object IDs are assigned by position, starting at zero, so the caller does not
/// track them. Each object is flushed as it is written: a relay that parses as
/// bytes arrive can forward a frame before the group is done, which is the point.
///
/// Dropping this without [`Self::finish`] resets the stream rather than closing
/// it, so a group abandoned halfway is one a subscriber can tell was abandoned,
/// instead of one that looks complete and is missing its end.
pub struct GroupWriter {
    stream: SendStream,
    writer: SubgroupWriter,
    properties_present: bool,
    next: u32,
}

impl GroupWriter {
    /// Append an object, and return the ID it was given.
    ///
    /// # Errors
    /// Encoding the object, writing it, or stating properties in a group that
    /// [`Metadata::Absent`] opened.
    pub async fn write(&mut self, object: &OutgoingObject<'_>) -> Result<u64, Error> {
        if !self.properties_present && !object.properties.is_empty() {
            return Err(Error::PropertiesNotDeclared);
        }

        let id = self.next;
        let payload = Bytes::copy_from_slice(object.payload);
        let encoded = if self.properties_present {
            SubgroupObject {
                object: id.into(),
                content: SubgroupContent::Normal {
                    payload,
                    properties: object.properties.to_wire(),
                },
            }
        } else {
            SubgroupObject::new(id, payload)
        };

        let mut buf = BytesMut::new();
        self.writer.write(&mut buf, &encoded)?;
        self.stream.write_all(&buf).await.map_err(Error::write)?;

        self.next = self.next.saturating_add(1);
        Ok(u64::from(id))
    }

    /// How many objects have been written.
    #[must_use]
    pub const fn written(&self) -> u64 {
        self.next as u64
    }

    /// Close the group.
    ///
    /// Not optional. A stream left open leaves its last objects in flight at a
    /// relay that parses as bytes arrive.
    ///
    /// # Errors
    /// Finishing the underlying stream.
    pub fn finish(mut self) -> Result<(), Error> {
        self.stream.finish().map_err(Error::write)
    }
}

impl Announcement {
    /// The alias this publisher will write into subgroup headers.
    #[must_use]
    pub const fn alias(&self) -> TrackAlias {
        self.alias
    }

    /// Wait until the relay has asked for a track in this namespace.
    ///
    /// Objects published before that arrives are not pulled, so a CLI that
    /// starts writing stdin immediately would lose the first groups.
    pub async fn subscribed(&self) {
        let mut watch = self.subscribed.clone();
        let _ = watch.wait_for(|ready| *ready).await;
    }
}

impl Subscription {
    /// The next object on this subscription, or `None` if the session ended.
    ///
    /// Incoming unidirectional streams are read as subgroup objects and routed
    /// by the alias negotiated in `SUBSCRIBE_OK`.
    ///
    /// # Errors
    /// A stream that cannot be decoded, or a session failure.
    pub async fn next_object(&mut self) -> Result<Option<Object>, Error> {
        match self.rx.recv().await {
            Some(result) => result.map(Some),
            None => Ok(None),
        }
    }
}

fn spawn_publisher(
    transport: moqom_transport::Session,
    published: Arc<Mutex<HashMap<TrackNamespace, PublishSlot>>>,
) {
    tokio::spawn(async move {
        loop {
            let Ok((send, recv)) = transport.accept_bi().await else {
                return;
            };
            let published = Arc::clone(&published);
            tokio::spawn(async move {
                let _ = answer_subscribe(send, recv, &published).await;
            });
        }
    });
}

async fn answer_subscribe(
    mut send: SendStream,
    recv: RecvStream,
    published: &Mutex<HashMap<TrackNamespace, PublishSlot>>,
) -> Result<(), Error> {
    let mut frames = Frames::new(recv);
    let frame = frames.next().await?.ok_or(Error::Closed)?;
    if frame.message_type != MessageType::Subscribe {
        return Ok(());
    }
    let request = Subscribe::decode(&mut frame.body.clone())?;
    let slot = published
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(request.track.namespace())
        .cloned();
    match slot {
        Some(slot) => {
            write(&mut send, &SubscribeOk::new(slot.alias)).await?;
            let _ = slot.subscribed.send(true);
            slot.held
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((send, frames.into_inner()));
        }
        None => {
            write(
                &mut send,
                &RequestError::new(
                    RequestErrorCode::DOES_NOT_EXIST,
                    ReasonPhrase::truncating("namespace not announced"),
                ),
            )
            .await?;
        }
    }
    Ok(())
}

fn spawn_reader(transport: moqom_transport::Session, inbox: Arc<Mutex<Inbox>>) {
    tokio::spawn(async move {
        loop {
            let Ok(recv) = transport.accept_uni().await else {
                return;
            };
            let inbox = Arc::clone(&inbox);
            tokio::spawn(async move {
                let _ = read_subgroup(recv, &inbox).await;
            });
        }
    });
}

async fn read_subgroup(mut recv: RecvStream, inbox: &Mutex<Inbox>) -> Result<(), Error> {
    let mut buffer = BytesMut::new();
    let Some(header) = read_header(&mut recv, &mut buffer).await? else {
        return Ok(());
    };
    let tx = inbox
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&header.track_alias)
        .cloned();
    let Some(tx) = tx else {
        return Ok(());
    };

    let mut reader = SubgroupReader::new(&header);
    loop {
        match next_object(&mut recv, &mut buffer, &mut reader).await {
            Ok(Some(object)) => {
                let (payload, properties) = match object.content {
                    SubgroupContent::Normal {
                        payload,
                        properties,
                    } => (payload, ObjectProperties::from_wire(&properties)),
                    SubgroupContent::Terminal(_) => continue,
                };
                if tx
                    .send(Ok(Object {
                        group: header.group,
                        object: object.object.get(),
                        payload,
                        properties,
                    }))
                    .await
                    .is_err()
                {
                    return Ok(());
                }
            }
            Ok(None) => return Ok(()),
            Err(error) => {
                let _ = tx.send(Err(error)).await;
                return Ok(());
            }
        }
    }
}

async fn read_header(
    recv: &mut RecvStream,
    buffer: &mut BytesMut,
) -> Result<Option<SubgroupHeader>, Error> {
    loop {
        let mut cursor = &buffer[..];
        match SubgroupHeader::decode(&mut cursor) {
            Ok(header) => {
                let consumed = buffer.len() - cursor.len();
                buffer.advance(consumed);
                return Ok(Some(header));
            }
            Err(DecodeError::Short { .. }) => {}
            Err(error) => return Err(error.into()),
        }
        if !fill(recv, buffer).await? {
            return Ok(None);
        }
    }
}

async fn next_object(
    recv: &mut RecvStream,
    buffer: &mut BytesMut,
    reader: &mut SubgroupReader,
) -> Result<Option<SubgroupObject>, Error> {
    loop {
        let mut cursor = &buffer[..];
        match reader.read(&mut cursor) {
            Ok(object) => {
                let consumed = buffer.len() - cursor.len();
                buffer.advance(consumed);
                return Ok(Some(object));
            }
            Err(DecodeError::Short { .. }) => {}
            Err(error) => return Err(error.into()),
        }
        if !fill(recv, buffer).await? {
            return Ok(None);
        }
    }
}

async fn fill(recv: &mut RecvStream, buffer: &mut BytesMut) -> Result<bool, Error> {
    let mut chunk = [0u8; 4096];
    match recv.read(&mut chunk).await {
        Ok(Some(n)) => {
            buffer.extend_from_slice(&chunk[..n]);
            Ok(true)
        }
        Ok(None) | Err(_) => Ok(false),
    }
}

async fn write<M: MessageBody>(stream: &mut SendStream, message: &M) -> Result<(), Error> {
    let mut buf = BytesMut::new();
    write_message(&mut buf, message)?;
    stream.write_all(&buf).await.map_err(Error::write)
}

/// Reads length-delimited control messages.
struct Frames {
    stream: RecvStream,
    buffer: BytesMut,
}

impl Frames {
    fn new(stream: RecvStream) -> Self {
        Self {
            stream,
            buffer: BytesMut::new(),
        }
    }

    fn into_inner(self) -> RecvStream {
        self.stream
    }

    async fn next(&mut self) -> Result<Option<ControlFrame>, Error> {
        loop {
            let mut cursor = &self.buffer[..];
            match ControlFrame::decode(&mut cursor) {
                Ok(frame) => {
                    let consumed = self.buffer.len() - cursor.remaining();
                    self.buffer.advance(consumed);
                    return Ok(Some(frame));
                }
                Err(DecodeError::Short { .. }) => {}
                Err(error) => return Err(error.into()),
            }
            if !fill(&mut self.stream, &mut self.buffer).await? {
                return Ok(None);
            }
        }
    }
}

fn placeholder_url() -> url::Url {
    // A raw QUIC session has no CONNECT URL; the wrapper still wants one.
    "https://localhost/"
        .parse()
        .unwrap_or_else(|_| unreachable!("constant URL"))
}
