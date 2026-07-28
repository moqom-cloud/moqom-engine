//! A minimal MOQT client, and a relay to point it at.
//!
//! Everything here exists to exercise the relay over a real socket. The relay's
//! unit tests cover matching and suffix arithmetic in isolation; what they cannot
//! cover is whether the bytes it writes are the bytes a peer can read, and that
//! is the failure this catches — a codec that agrees with itself and with nothing
//! else is the specific risk of implementing a protocol from a draft.
//!
//! The client is deliberately not built on the relay's own session code. Sharing
//! it would make these tests circular: a mistake in the framing would be made by
//! both ends and observed by neither.

// Every integration test binary compiles this module in full and uses a subset of
// it, so anything only one of them needs is dead code in the others.
#![allow(dead_code)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::{Buf, Bytes, BytesMut};
use moqom_proto::control::{
    ControlFrame, Fetch, FetchKind, FetchOk, MessageBody, MessageType, Namespace, NamespaceDone,
    PublishNamespace, RequestId, RequestIdGenerator, Role, Setup, Subscribe, SubscribeNamespace,
    SubscribeOk, write_message,
};
use moqom_proto::data::{
    FetchHeader, FetchReader, FetchRecord, GroupOrder, SubgroupHeader, SubgroupSource,
};
use moqom_proto::error::DecodeError;
use moqom_proto::model::{FullTrackName, GroupId, Location, TrackAlias, TrackNamespace};
use moqom_relay::admin::Surface;
use moqom_relay::{Cache, Fabric, Governor, Limits, Metrics, Quotas, Session};
use moqom_transport::{Server, alpn, server::with_moqt_alpn};
use web_transport_quinn::{RecvStream, SendStream};

/// How long a test waits for something that should be immediate.
///
/// Generous, because a loaded CI machine is slow and a flaky test is worse than
/// a slow one. Nothing here should ever come close.
pub const PATIENCE: std::time::Duration = std::time::Duration::from_secs(10);

/// Await `future`, failing the test rather than hanging if it does not finish.
///
/// A relay bug is far more likely to present as "nothing ever arrives" than as
/// an error, and a hung test reports that as a timeout with no message.
pub async fn within<F: Future>(what: &str, future: F) -> F::Output {
    tokio::time::timeout(PATIENCE, future)
        .await
        .unwrap_or_else(|elapsed| panic!("timed out waiting for {what} ({elapsed})"))
}

/// A relay listening on a loopback port.
pub struct Relay {
    pub addr: SocketAddr,
    pub fabric: Fabric,
    /// What the relay counted, always enabled here.
    ///
    /// On rather than off in every test, including the ones that assert nothing
    /// about it: instrumentation on the forwarding path is code, and code that
    /// only runs in production is code whose first execution is in production.
    pub metrics: Metrics,
    /// The admin endpoints over this relay's state.
    pub surface: Surface,
    /// The certificate the client must trust, held so tests can pin it.
    pub certificate: rustls::pki_types::CertificateDer<'static>,
    accept: tokio::task::JoinHandle<()>,
}

impl Relay {
    /// Start a relay on an arbitrary loopback port.
    ///
    /// Must be called from within a runtime: the accept loop is spawned here, so
    /// that a test can connect immediately rather than sequencing the two.
    pub fn start() -> Self {
        Self::retaining(Limits::default())
    }

    /// Start a relay that holds every session to `quotas`.
    ///
    /// Every client here connects from loopback with no credential, so all of
    /// them share one address-tier bucket. That is not a limitation of the
    /// harness so much as the thing worth testing: it is exactly the shape of a
    /// deployment behind a load balancer that does not preserve the client
    /// address.
    pub fn governed(quotas: &Quotas) -> Self {
        Self::build(Limits::default(), Governor::new(*quotas))
    }

    /// Start a relay retaining history according to `limits`.
    pub fn retaining(limits: Limits) -> Self {
        Self::build(limits, Governor::disabled())
    }

    fn build(limits: Limits, governor: Governor) -> Self {
        install_crypto_provider();

        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generating a certificate");
        let certificate = generated.cert.der().clone();
        let key = rustls::pki_types::PrivateKeyDer::try_from(generated.signing_key.serialize_der())
            .expect("generated key is usable");
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key)
            .expect("certificate and key agree");

        let server = Server::bind(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            with_moqt_alpn(tls),
        )
        .expect("binding a loopback port");
        let addr = server.local_addr().expect("bound address");

        let metrics = Metrics::new();
        let fabric = Fabric::observed(Cache::new(limits), metrics.clone()).governed(governor);
        let surface = Surface::new(metrics.clone(), fabric.clone());
        let accept = tokio::spawn({
            let fabric = fabric.clone();
            async move {
                while let Some(incoming) = server.accept().await {
                    let fabric = fabric.clone();
                    tokio::spawn(async move {
                        let Ok((session, negotiated)) = incoming.establish().await else {
                            return;
                        };
                        let _ = Session::serve(session, negotiated.carrier, fabric).await;
                    });
                }
            }
        });

        Self {
            addr,
            fabric,
            metrics,
            surface,
            certificate,
            accept,
        }
    }

    /// The Prometheus exposition this relay would serve right now.
    pub fn scrape(&self) -> String {
        self.surface.respond("/metrics").body
    }
}

/// Why the relay hung up, as the peer sees it.
#[derive(Debug, PartialEq, Eq)]
pub struct Closed {
    /// The application error code.
    pub code: u64,
    /// The reason phrase, which is where a session-level refusal has to put its
    /// retry-after: a closing session has no request stream left to carry one.
    pub reason: String,
}

async fn closed_reason(session: &moqom_transport::Session) -> Closed {
    let error = within("the relay to close the session", session.closed()).await;
    match error {
        web_transport_quinn::SessionError::ConnectionError(
            quinn::ConnectionError::ApplicationClosed(closed),
        ) => Closed {
            code: closed.error_code.into_inner(),
            reason: String::from_utf8_lossy(&closed.reason).into_owned(),
        },
        other => panic!("expected an application close, got {other:?}"),
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

/// A MOQT peer that has completed SETUP.
pub struct Client {
    session: moqom_transport::Session,
    requests: RequestIdGenerator,
    /// Held open for the life of the session: closing the control stream ends it.
    _control: (SendStream, Frames),
    /// Owns the client socket. Dropping the endpoint closes every connection on
    /// it, so this has to outlive the session.
    _endpoint: quinn::Endpoint,
}

impl Client {
    /// Connect to `relay` over raw QUIC and exchange SETUP.
    pub async fn connect(relay: &Relay) -> Self {
        Self::try_connect(relay)
            .await
            .unwrap_or_else(|closed| panic!("the relay refused the session: {closed:?}"))
    }

    /// Connect, tolerating a relay that refuses before answering.
    ///
    /// A session the limiter turns away never receives a SETUP: the relay
    /// refuses before answering rather than after, so there is no moment where
    /// it has said yes and then hung up. That is the right behaviour and it
    /// means the ordinary [`Client::connect`] cannot observe it.
    pub async fn try_connect(relay: &Relay) -> Result<Self, Closed> {
        install_crypto_provider();

        let mut tls = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedCertificate(
                relay.certificate.clone(),
            )))
            .with_no_client_auth();
        tls.alpn_protocols = vec![alpn::MOQT_DRAFT_19.to_vec()];

        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .expect("a TLS 1.3 configuration");
        let mut endpoint = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("binding a client socket");
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));

        let connection = within("the QUIC handshake", async {
            endpoint
                .connect(relay.addr, "localhost")
                .expect("a connectable address")
                .await
                .expect("the relay accepts")
        })
        .await;

        let session = moqom_transport::Session::raw(
            connection,
            web_transport_quinn::proto::ConnectRequest::new(
                url::Url::parse("https://localhost/").expect("a constant URL"),
            ),
            web_transport_quinn::proto::ConnectResponse::OK,
        );

        // The client opens the control stream and speaks first.
        let (mut send, recv) = session.open_bi().await.expect("opening the control stream");
        let mut ours = Setup::new();
        ours.options
            .set_bytes(
                moqom_proto::control::setup::option_type::MOQT_IMPLEMENTATION,
                &b"moqom-relay-tests"[..],
            )
            .expect("a short implementation string");
        write(&mut send, &ours).await;

        let mut frames = Frames::new(recv);
        let Some(frame) = within("the relay's SETUP", frames.next()).await else {
            // The relay hung up instead of answering, and the close carries why.
            return Err(closed_reason(&session).await);
        };
        assert_eq!(
            frame.message_type,
            MessageType::Setup,
            "the relay must answer SETUP with SETUP"
        );
        let mut body = frame.body.clone();
        let len = body.len();
        Setup::decode(&mut body, len).expect("a decodable SETUP");

        Ok(Self {
            session,
            requests: RequestIdGenerator::new(Role::Client),
            _control: (send, frames),
            _endpoint: endpoint,
        })
    }

    fn next_request(&mut self) -> RequestId {
        self.requests.allocate().expect("request ids remain")
    }

    /// Announce `namespace`, returning the stream that holds the announcement.
    ///
    /// Dropping the returned stream withdraws it, which is the protocol's own
    /// mechanism rather than a convenience of this harness.
    pub async fn announce(&mut self, namespace: &TrackNamespace) -> Announcement {
        let (mut send, recv) = self
            .session
            .open_bi()
            .await
            .expect("opening a request stream");
        let request = PublishNamespace::new(self.next_request(), namespace.clone());
        write(&mut send, &request).await;
        Announcement { send, _recv: recv }
    }

    /// Watch for namespaces under `prefix`.
    pub async fn watch(&mut self, prefix: &TrackNamespace) -> Watch {
        let (send, recv) = self
            .session
            .open_bi()
            .await
            .expect("opening a request stream");
        let mut send = send;
        let request = SubscribeNamespace::new(self.next_request(), prefix.clone());
        write(&mut send, &request).await;
        Watch {
            prefix: prefix.clone(),
            frames: Frames::new(recv),
            _send: send,
        }
    }

    /// Wait for the relay to close this session, and report how.
    pub async fn closed(&self) -> Closed {
        closed_reason(&self.session).await
    }

    /// Subscribe to `track`.
    ///
    /// The returned [`Subscription`] holds the request stream: dropping it
    /// cancels the subscription, so callers keep it for as long as they expect
    /// objects.
    pub async fn subscribe(&mut self, track: &FullTrackName) -> Result<Subscription, u64> {
        self.try_subscribe(track)
            .await
            .map_err(|error| error.code.get())
    }

    /// Subscribe, keeping the whole error rather than just its code.
    ///
    /// A rate limiter's answer is more than a code — the retry-after is the part
    /// a client acts on — so the tests for it need the message intact.
    pub async fn try_subscribe(
        &mut self,
        track: &FullTrackName,
    ) -> Result<Subscription, moqom_proto::control::RequestError> {
        let (mut send, recv) = self
            .session
            .open_bi()
            .await
            .expect("opening a request stream");
        let request = Subscribe::new(self.next_request(), track.clone());
        write(&mut send, &request).await;

        let mut frames = Frames::new(recv);
        let frame = within("an answer to SUBSCRIBE", frames.expect()).await;
        match frame.message_type {
            MessageType::SubscribeOk => {
                let ok = SubscribeOk::decode(&mut frame.body.clone()).expect("a decodable answer");
                Ok(Subscription {
                    alias: ok.track_alias,
                    request_id: request.request_id,
                    _send: send,
                    _frames: frames,
                })
            }
            MessageType::RequestError => Err(moqom_proto::control::RequestError::decode(
                &mut frame.body.clone(),
            )
            .expect("a decodable error")),
            other => panic!("unexpected {other:?} answering SUBSCRIBE"),
        }
    }

    /// Answer the next SUBSCRIBE this peer receives with `alias`.
    ///
    /// This is the publisher half. The alias given here is the *upstream* one,
    /// which the relay must rewrite before forwarding — so a relay that forgot
    /// to rewrite it produces a header the subscriber does not recognise, and
    /// that is exactly what the forwarding tests check.
    pub async fn answer_subscription(&self, alias: TrackAlias) -> Served {
        let (mut send, recv) = within("the relay's SUBSCRIBE", self.session.accept_bi())
            .await
            .expect("the relay opens a request stream");

        let mut frames = Frames::new(recv);
        let frame = within("a SUBSCRIBE", frames.expect()).await;
        assert_eq!(frame.message_type, MessageType::Subscribe);
        let request = Subscribe::decode(&mut frame.body.clone()).expect("a decodable SUBSCRIBE");
        assert!(
            request.request_id.is_valid_from(Role::Server),
            "a relay's request IDs must be odd, got {}",
            request.request_id
        );

        write(&mut send, &SubscribeOk::new(alias)).await;
        Served {
            track: request.track,
            _send: send,
            _frames: frames,
        }
    }

    /// Write one subgroup of objects on a fresh unidirectional stream.
    pub async fn publish_subgroup(&self, alias: TrackAlias, payloads: &[&[u8]]) {
        self.publish_group(alias, GroupId::ZERO, payloads).await;
    }

    /// Write one subgroup into a named group, numbering objects from zero.
    pub async fn publish_group(&self, alias: TrackAlias, group: GroupId, payloads: &[&[u8]]) {
        let numbered: Vec<(u32, &[u8])> = payloads
            .iter()
            .enumerate()
            .map(|(index, payload)| (index as u32, *payload))
            .collect();
        self.publish_objects(alias, group, &numbered).await;
    }

    /// Write a subgroup carrying objects with the Object IDs given.
    ///
    /// Explicit IDs are what makes a hole expressible, which the gap tests need:
    /// a subgroup that skips from object 1 to object 4 leaves two the relay has
    /// never seen.
    ///
    /// Finishing the stream matters for the cache tests. The relay parses as bytes
    /// arrive, so a stream left open leaves its last objects in flight.
    pub async fn publish_objects(
        &self,
        alias: TrackAlias,
        group: GroupId,
        objects: &[(u32, &[u8])],
    ) {
        let mut stream = self
            .session
            .open_uni()
            .await
            .expect("opening a data stream");
        let header = SubgroupHeader::new(alias, group, SubgroupSource::Zero);

        let mut buf = BytesMut::new();
        header.encode(&mut buf);
        let mut writer = moqom_proto::data::SubgroupWriter::new(&header);
        for (id, payload) in objects {
            let object =
                moqom_proto::data::SubgroupObject::new(*id, Bytes::copy_from_slice(payload));
            writer.write(&mut buf, &object).expect("a writable object");
        }

        stream.write_all(&buf).await.expect("writing a subgroup");
        stream.finish().expect("finishing a subgroup");
    }

    /// Fetch a range, reading both the answer and the objects it produces.
    ///
    /// The two arrive on different streams — the answer on the request stream,
    /// the objects on a unidirectional one the relay opens — so this reads them
    /// in that order, which is also the order the relay writes them.
    pub async fn fetch(&mut self, kind: FetchKind) -> Result<Fetched, u64> {
        let (mut send, recv) = self
            .session
            .open_bi()
            .await
            .expect("opening a request stream");
        let request = Fetch::new(self.next_request(), kind);
        write(&mut send, &request).await;

        let mut frames = Frames::new(recv);
        let frame = within("an answer to FETCH", frames.expect()).await;
        match frame.message_type {
            MessageType::FetchOk => {
                let ok = FetchOk::decode(&mut frame.body.clone()).expect("a decodable FETCH_OK");
                let records = self.read_fetch(request.request_id).await;
                Ok(Fetched {
                    end: ok.end,
                    records,
                    _send: send,
                    _frames: frames,
                })
            }
            MessageType::RequestError => {
                let error = moqom_proto::control::RequestError::decode(&mut frame.body.clone())
                    .expect("a decodable error");
                Err(error.code.get())
            }
            other => panic!("unexpected {other:?} answering FETCH"),
        }
    }

    /// Read one fetch data stream to its end.
    async fn read_fetch(&self, expected: RequestId) -> Vec<FetchRecord> {
        let recv = within("a fetch data stream", self.session.accept_uni())
            .await
            .expect("the relay opens a data stream");
        let bytes = within("the fetch body", async move {
            let mut recv = recv;
            recv.read_to_end(1024 * 1024)
                .await
                .expect("reading a fetch stream")
        })
        .await;

        let mut cursor = &bytes[..];
        let header = FetchHeader::decode(&mut cursor).expect("a decodable fetch header");
        assert_eq!(
            header.request_id, expected,
            "a fetch stream must name the request it answers"
        );

        let mut reader = FetchReader::new(GroupOrder::Ascending);
        let mut records = Vec::new();
        while !cursor.is_empty() {
            records.push(reader.read(&mut cursor).expect("a decodable record"));
        }
        records
    }

    /// Read one forwarded subgroup: its header, and every payload on it.
    pub async fn read_subgroup(&self) -> (SubgroupHeader, Vec<Bytes>) {
        let recv = within("a forwarded subgroup", self.session.accept_uni())
            .await
            .expect("the relay opens a data stream");

        let bytes = within("the subgroup body", async move {
            let mut recv = recv;
            recv.read_to_end(64 * 1024)
                .await
                .expect("reading a subgroup")
        })
        .await;

        let mut cursor = &bytes[..];
        let header = SubgroupHeader::decode(&mut cursor).expect("a decodable header");
        let mut reader = moqom_proto::data::SubgroupReader::new(&header);
        let mut payloads = Vec::new();
        while !cursor.is_empty() {
            let object = reader.read(&mut cursor).expect("a decodable object");
            match object.content {
                moqom_proto::data::SubgroupContent::Normal { payload, .. } => {
                    payloads.push(payload);
                }
                moqom_proto::data::SubgroupContent::Terminal(_) => break,
            }
        }
        (header, payloads)
    }
}

/// A live subscription. Dropping it cancels the subscription.
pub struct Subscription {
    /// The alias the relay assigned, which forwarded headers must carry.
    pub alias: TrackAlias,
    /// The ID this subscription was requested with, which a joining fetch names.
    pub request_id: RequestId,
    _send: SendStream,
    _frames: Frames,
}

/// An answered fetch: the range delivered, and the records on its data stream.
pub struct Fetched {
    /// The end the relay reported, which is the last location delivered plus one.
    pub end: Location,
    /// Every record on the fetch stream, in the order it arrived.
    pub records: Vec<FetchRecord>,
    _send: SendStream,
    _frames: Frames,
}

impl Fetched {
    /// The payloads of the objects delivered, ignoring gap markers.
    pub fn payloads(&self) -> Vec<Bytes> {
        self.records
            .iter()
            .filter_map(|record| match record {
                FetchRecord::Object(object) => Some(object.payload.clone()),
                _ => None,
            })
            .collect()
    }

    /// Where each delivered record sits in the track.
    pub fn locations(&self) -> Vec<Location> {
        self.records.iter().map(FetchRecord::location).collect()
    }
}

/// A subscription this peer is serving as publisher.
pub struct Served {
    /// The track the relay asked for.
    pub track: FullTrackName,
    _send: SendStream,
    _frames: Frames,
}

/// A live announcement. Dropping it withdraws the namespace.
pub struct Announcement {
    send: SendStream,
    _recv: RecvStream,
}

impl Announcement {
    /// Withdraw the announcement by closing its stream.
    ///
    /// Closing is the whole mechanism: there is no `UNANNOUNCE` message.
    pub fn withdraw(mut self) {
        self.send.finish().expect("finishing an announcement");
    }
}

/// A live namespace watch.
pub struct Watch {
    prefix: TrackNamespace,
    frames: Frames,
    _send: SendStream,
}

/// What a watch reports.
#[derive(Debug, PartialEq, Eq)]
pub enum Announced {
    /// A namespace became available.
    Available(TrackNamespace),
    /// A namespace went away.
    Gone(TrackNamespace),
}

impl Watch {
    /// The next namespace change, resolved back to a full namespace.
    ///
    /// Resolution is the point: the relay sends a *suffix*, and a relay that
    /// sent whole namespaces instead would decode cleanly and produce the wrong
    /// name here.
    pub async fn next(&mut self) -> Announced {
        let frame = within("a namespace announcement", self.frames.expect()).await;
        match frame.message_type {
            MessageType::Namespace => {
                let message = Namespace::decode(&mut frame.body.clone()).expect("decodable");
                Announced::Available(
                    message
                        .resolve(&self.prefix)
                        .expect("a suffix that fits the prefix"),
                )
            }
            MessageType::NamespaceDone => {
                let message = NamespaceDone::decode(&mut frame.body.clone()).expect("decodable");
                Announced::Gone(
                    message
                        .resolve(&self.prefix)
                        .expect("a suffix that fits the prefix"),
                )
            }
            other => panic!("unexpected {other:?} on a namespace watch"),
        }
    }
}

/// Reads length-delimited control messages, as the relay's own reader does.
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

    async fn expect(&mut self) -> ControlFrame {
        self.next()
            .await
            .expect("a complete control message rather than a closed stream")
    }

    /// The next frame, or `None` if the stream ended first.
    ///
    /// Distinguished from `expect` because a stream that ends before answering
    /// is a real outcome rather than only a failure: a session the relay refuses
    /// gets a connection close instead of a reply, and the caller needs to be
    /// able to go and read why.
    async fn next(&mut self) -> Option<ControlFrame> {
        loop {
            let mut cursor = &self.buffer[..];
            match ControlFrame::decode(&mut cursor) {
                Ok(frame) => {
                    let consumed = self.buffer.len() - cursor.remaining();
                    self.buffer.advance(consumed);
                    return Some(frame);
                }
                Err(DecodeError::Short { .. }) => {}
                Err(e) => panic!("undecodable control frame: {e}"),
            }

            let mut chunk = [0u8; 4096];
            match self.stream.read(&mut chunk).await {
                Ok(Some(0) | None) | Err(_) => return None,
                Ok(Some(n)) => self.buffer.extend_from_slice(&chunk[..n]),
            }
        }
    }
}

async fn write<M: MessageBody>(stream: &mut SendStream, message: &M) {
    let mut buf = BytesMut::new();
    write_message(&mut buf, message).expect("a message that fits a frame");
    stream.write_all(&buf).await.expect("writing a message");
}

/// Trusts exactly one certificate, by comparing its bytes.
///
/// A self-signed end-entity certificate cannot be a webpki trust anchor, so the
/// alternatives were this or accepting anything. Pinning is both closer to what
/// a client actually does with a development relay and a real assertion: a test
/// that accepted any certificate would pass against a relay presenting the wrong
/// one.
#[derive(Debug)]
struct PinnedCertificate(rustls::pki_types::CertificateDer<'static>);

impl rustls::client::danger::ServerCertVerifier for PinnedCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.0.as_ref() {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }
        Err(rustls::Error::General(
            "certificate is not the pinned one".into(),
        ))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // QUIC is TLS 1.3 only, so reaching this is a misconfiguration.
        Err(rustls::Error::General(
            "TLS 1.2 is not used over QUIC".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn install_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// A namespace from string fields.
pub fn namespace(fields: &[&str]) -> TrackNamespace {
    TrackNamespace::from_parts(fields).expect("a valid namespace")
}

/// A full track name from a namespace and a name.
pub fn track(fields: &[&str], name: &str) -> FullTrackName {
    FullTrackName::new(namespace(fields), Bytes::copy_from_slice(name.as_bytes()))
        .expect("a valid track name")
}
