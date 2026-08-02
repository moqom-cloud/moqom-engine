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
    ControlFrame, DoneReason, Fetch, FetchKind, FetchOk, MessageBody, MessageType, Namespace,
    NamespaceDone, PublishDone, PublishNamespace, RequestId, RequestIdGenerator, Role, Setup,
    Subscribe, SubscribeNamespace, SubscribeOk, write_message,
};
use moqom_proto::data::{
    FetchHeader, FetchReader, FetchRecord, GroupOrder, SubgroupHeader, SubgroupSource,
};
use moqom_proto::error::DecodeError;
use moqom_proto::model::{FullTrackName, GroupId, Location, TrackAlias, TrackNamespace};
use moqom_relay::admin::Surface;
use moqom_relay::{Authenticator, Cache, Fabric, Governor, Limits, Metrics, Quotas, Session};
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

/// The value of a single unlabelled metric in an exposition.
pub fn value(scrape: &str, metric: &str) -> u64 {
    for line in scrape.lines() {
        if let Some(rest) = line.strip_prefix(metric) {
            // Guard against a prefix match: `moqom_relay_sessions` must not read
            // `moqom_relay_sessions_accepted_total`.
            if let Some(number) = rest.strip_prefix(' ') {
                return number.trim().parse().expect("a metric value");
            }
        }
    }
    panic!("no metric {metric} in:\n{scrape}");
}

/// The value of one series of a labelled metric.
pub fn series(scrape: &str, metric: &str, label: &str, label_value: &str) -> u64 {
    let needle = format!("{metric}{{{label}=\"{label_value}\"}} ");
    for line in scrape.lines() {
        if let Some(number) = line.strip_prefix(&needle) {
            return number.trim().parse().expect("a metric value");
        }
    }
    panic!("no series {needle} in:\n{scrape}");
}

/// Poll until `check` passes, so a test does not race the relay's bookkeeping.
pub async fn eventually(what: &str, relay: &Relay, check: impl Fn(&str) -> bool) -> String {
    within(what, async {
        loop {
            let scrape = relay.scrape();
            if check(&scrape) {
                return scrape;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
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

    /// Start a relay that verifies tokens, and therefore authorises requests.
    ///
    /// The distinction the rest of the harness cannot make. Every other relay
    /// here has no keys, so every session is anonymous and unrestricted, which
    /// is right for testing forwarding and useless for testing who may forward
    /// what.
    pub fn authenticating() -> Self {
        Self::assembled(
            Limits::default(),
            Governor::disabled(),
            tokens::authenticator(),
        )
    }

    /// Start a relay that verifies tokens against keys from somewhere else.
    ///
    /// For `interop_link.rs`, where the keys are the running control plane's and
    /// the tokens are ones it minted. Everything else here trusts a key this
    /// harness holds, which cannot tell whether the two implementations agree.
    pub fn verifying(authenticator: Authenticator) -> Self {
        Self::assembled(Limits::default(), Governor::disabled(), authenticator)
    }

    fn build(limits: Limits, governor: Governor) -> Self {
        Self::assembled(limits, governor, Authenticator::disabled())
    }

    fn assembled(limits: Limits, governor: Governor, authenticator: Authenticator) -> Self {
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
        let fabric = Fabric::observed(Cache::new(limits), metrics.clone())
            .governed(governor)
            .authenticated(authenticator);
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

/// How much this client's connection will hold for it.
enum Link {
    /// Whatever QUIC's defaults allow, which on loopback is everything.
    Ordinary,
    /// Barely anything. See [`Client::connect_congested`].
    Congested,
}

impl Client {
    /// Go away without saying anything.
    ///
    /// Models the peer that stops existing: a battery that dies, an app the
    /// system kills, a phone that goes into a tunnel and never comes out. What
    /// makes it different from every other teardown here is what it does *not*
    /// do — no stream is finished, so nothing is withdrawn, and the relay learns
    /// about it from the transport rather than from a message.
    pub fn vanish(&self) {
        self.session.close(0, b"vanished");
    }

    /// Connect to `relay` over raw QUIC and exchange SETUP.
    pub async fn connect(relay: &Relay) -> Self {
        Self::try_connect(relay)
            .await
            .unwrap_or_else(|closed| panic!("the relay refused the session: {closed:?}"))
    }

    /// Connect presenting `token` as a session credential.
    pub async fn connect_as(relay: &Relay, token: &str) -> Self {
        Self::establish(relay, Some(token), Link::Ordinary)
            .await
            .unwrap_or_else(|closed| panic!("the relay refused the session: {closed:?}"))
    }

    /// Connect presenting `token`, tolerating a relay that refuses.
    ///
    /// What a banned client sees: the credential verifies and the relay hangs up
    /// anyway, which is a different outcome from a token that did not verify and
    /// has to be observable separately.
    pub async fn try_connect_as(relay: &Relay, token: &str) -> Result<Self, Closed> {
        Self::establish(relay, Some(token), Link::Ordinary).await
    }

    /// Connect, tolerating a relay that refuses before answering.
    ///
    /// A session the limiter turns away never receives a SETUP: the relay
    /// refuses before answering rather than after, so there is no moment where
    /// it has said yes and then hung up. That is the right behaviour and it
    /// means the ordinary [`Client::connect`] cannot observe it.
    pub async fn try_connect(relay: &Relay) -> Result<Self, Closed> {
        Self::establish(relay, None, Link::Ordinary).await
    }

    /// Connect as a subscriber whose connection cannot take much.
    ///
    /// A few kilobytes of unread data is all it will accept before its flow
    /// control stops the sender, which is a phone on a bad train connection
    /// with the constants scaled down until a test can finish. Modelling it
    /// this way rather than by simply not reading matters: the relay must be
    /// blocked by the transport, exactly as it would be in the real case, and
    /// not merely be writing into a buffer nobody drains.
    pub async fn connect_congested(relay: &Relay) -> Self {
        Self::establish(relay, None, Link::Congested)
            .await
            .unwrap_or_else(|closed| panic!("the relay refused the session: {closed:?}"))
    }

    async fn establish(relay: &Relay, token: Option<&str>, link: Link) -> Result<Self, Closed> {
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
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        if let Link::Congested = link {
            let mut transport = quinn::TransportConfig::default();
            transport.receive_window(quinn::VarInt::from_u32(8 * 1024));
            transport.stream_receive_window(quinn::VarInt::from_u32(4 * 1024));
            config.transport_config(Arc::new(transport));
        }
        endpoint.set_default_client_config(config);

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
        if let Some(token) = token {
            ours.options
                .set_bytes(
                    moqom_proto::control::setup::option_type::AUTHORIZATION_TOKEN,
                    Bytes::copy_from_slice(token.as_bytes()),
                )
                .expect("a token within the option's size");
        }
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

    /// Announce, expecting the relay to refuse.
    ///
    /// A separate call rather than a `Result` from [`Client::announce`],
    /// because an announcement that succeeds is answered with silence: the
    /// stream stays open and *is* the announcement. Only the refusal has
    /// something to read, so only the refusal can be awaited.
    pub async fn announce_refused(&mut self, namespace: &TrackNamespace) -> u64 {
        let (mut send, recv) = self
            .session
            .open_bi()
            .await
            .expect("opening a request stream");
        let request = PublishNamespace::new(self.next_request(), namespace.clone());
        write(&mut send, &request).await;

        let mut frames = Frames::new(recv);
        let frame = within("a refusal of PUBLISH_NAMESPACE", frames.expect()).await;
        assert_eq!(
            frame.message_type,
            MessageType::RequestError,
            "expected the announcement to be refused"
        );
        moqom_proto::control::RequestError::decode(&mut frame.body.clone())
            .expect("a decodable error")
            .code
            .get()
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

    /// Watch, expecting the relay to refuse.
    ///
    /// Same asymmetry as [`Client::announce_refused`]: a permitted watch
    /// answers with the namespaces that already match, which may be none, so
    /// there is nothing to distinguish it from silence.
    pub async fn watch_refused(&mut self, prefix: &TrackNamespace) -> u64 {
        let mut watch = self.watch(prefix).await;
        let frame = within("a refusal of SUBSCRIBE_NAMESPACE", watch.frames.expect()).await;
        assert_eq!(
            frame.message_type,
            MessageType::RequestError,
            "expected the watch to be refused"
        );
        moqom_proto::control::RequestError::decode(&mut frame.body.clone())
            .expect("a decodable error")
            .code
            .get()
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
                    frames,
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
            frames,
        }
    }

    /// Answer a SUBSCRIBE if one arrives, and say so if none does.
    ///
    /// For the cases where either answer is correct and the test must not
    /// assume which. A viewer arriving as another leaves may join the pull that
    /// is still there or open a new one, depending on which of the two the
    /// relay sees first, and both are right; what matters is that objects reach
    /// it either way. The window is short because a subscriber is blocked on
    /// this: if the relay meant to ask, it has asked by now.
    pub async fn answer_subscription_if_asked(&self, alias: TrackAlias) -> Option<Served> {
        let window = std::time::Duration::from_millis(300);
        let accepted = tokio::time::timeout(window, self.session.accept_bi()).await;
        let (mut send, recv) = accepted.ok()?.expect("the relay opens a request stream");

        let mut frames = Frames::new(recv);
        let frame = within("a SUBSCRIBE", frames.expect()).await;
        assert_eq!(frame.message_type, MessageType::Subscribe);
        let request = Subscribe::decode(&mut frame.body.clone()).expect("a decodable SUBSCRIBE");

        write(&mut send, &SubscribeOk::new(alias)).await;
        Some(Served {
            track: request.track,
            _send: send,
            frames,
        })
    }

    /// Assert the relay asks this publisher for nothing further.
    ///
    /// The claim deduplication makes is a negative — a SUBSCRIBE that does
    /// *not* happen — and a negative can only be waited for. Short, because the
    /// wait is spent on every passing run, and long enough that the request
    /// would have arrived: everything else in these tests is loopback and
    /// answered in microseconds.
    pub async fn asked_nothing_further(&self) {
        let quiet = std::time::Duration::from_millis(300);
        if tokio::time::timeout(quiet, self.session.accept_bi())
            .await
            .is_ok()
        {
            panic!("the relay opened a second request stream to the publisher");
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

    /// Take the next forwarded subgroup and report whether the relay abandoned
    /// it rather than completing it.
    ///
    /// The distinction is the point of shedding: a reset stream tells the
    /// subscriber this subgroup is not coming, where a stream left to dangle
    /// would have it waiting for objects nobody intends to send.
    pub async fn subgroup_was_abandoned(&self) -> bool {
        let mut recv = within("a forwarded subgroup", self.session.accept_uni())
            .await
            .expect("the relay opens a data stream");
        recv.read_to_end(1024 * 1024).await.is_err()
    }

    /// Read one forwarded subgroup: its header, and every payload on it.
    pub async fn read_subgroup(&self) -> (SubgroupHeader, Vec<Bytes>) {
        let recv = within("a forwarded subgroup", self.session.accept_uni())
            .await
            .expect("the relay opens a data stream");

        // A megabyte, which is a bound against a runaway test rather than a
        // statement about subgroups. The congestion tests deliberately send
        // more than a comfortable amount.
        let bytes = within("the subgroup body", async move {
            let mut recv = recv;
            recv.read_to_end(1024 * 1024)
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
    frames: Frames,
}

impl Subscription {
    /// Wait for the relay to say the track has ended.
    ///
    /// A subscriber cannot infer this: objects stopping is what a stalled
    /// network looks like too, and the two want opposite responses — wait, or
    /// tear the tile down and say why. `PUBLISH_DONE` is the difference.
    pub async fn ended(&mut self) -> PublishDone {
        let frame = within("the track to be declared over", self.frames.expect()).await;
        assert_eq!(frame.message_type, MessageType::PublishDone);
        PublishDone::decode(&mut frame.body.clone()).expect("a decodable PUBLISH_DONE")
    }
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
    frames: Frames,
}

impl Served {
    /// Wait for the relay to stop wanting this track.
    ///
    /// Unsubscribing is a stream reset in this protocol, so what the publisher
    /// sees is its request stream failing rather than a message arriving. That
    /// makes the assertion indirect and worth stating plainly: a relay that
    /// forgot to let go looks exactly like one whose subscribers are all still
    /// watching, and the difference is a phone uploading video to nobody.
    pub async fn released(&mut self) {
        within("the relay to stop pulling", async {
            match self.frames.next().await {
                None => (),
                Some(frame) => panic!(
                    "unexpected {:?} on a served subscription",
                    frame.message_type
                ),
            }
        })
        .await;
    }

    /// Assert the relay keeps this subscription for a little while yet.
    ///
    /// The negative half of [`released`](Self::released), and the one that
    /// catches over-eagerness: a relay that let go the moment *any* viewer left
    /// would pass every test above and cut the broadcast off for everyone who
    /// stayed.
    pub async fn kept(&mut self) {
        let quiet = std::time::Duration::from_millis(300);
        if tokio::time::timeout(quiet, self.frames.next())
            .await
            .is_ok()
        {
            panic!("the relay dropped a subscription that still has viewers");
        }
    }
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
    /// A namespace went away, and why the relay said it did.
    Gone(TrackNamespace, Option<DoneReason>),
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
                    message.reason,
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

/// Session credentials, minted the way the Go control plane mints them.
///
/// Written out here rather than imported from the relay's own test module for
/// the reason the client is: a token this harness produced with the relay's
/// own code would prove the two agree with each other and nothing about the
/// format. `tests/interop_tokens.rs` is what pins the format against Go; this
/// is what puts a token through a socket.
pub mod tokens {
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use moqom_relay::{Authenticator, VerificationKey};

    const KID: &str = "test-key";
    const ISSUER: &str = "https://api.moqom.cloud";

    /// A thumbprint whose first sixteen characters are the device field a
    /// client announces under. The relay derives one from the other, so these
    /// two constants are one fact and have to be written as one.
    const THUMBPRINT: &str = "OuXpLpEHW7dCPqjKWm8Zq1TfBb2nQ4Zt";
    pub const DEVICE: &str = "OuXpLpEHW7dCPqjK";

    /// A deterministic key, so a failing test fails the same way twice.
    fn signer() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).expect("a valid Ed25519 seed")
    }

    /// An authenticator that trusts [`signer`] and nothing else.
    pub fn authenticator() -> Authenticator {
        Authenticator::new(
            ISSUER,
            vec![VerificationKey {
                id: KID.to_owned(),
                bytes: signer().public_key().as_ref().to_vec(),
            }],
        )
    }

    /// What a token says its holder may do.
    ///
    /// Mirrors the `moqt` claim rather than the relay's parsed form, because
    /// what these tests need to vary is the thing on the wire.
    pub struct Grant {
        pub user: &'static str,
        pub room: Option<&'static str>,
        /// Audio and video, as the bitmask the control plane mints.
        pub publish: u8,
        pub capabilities: u32,
        pub owner: bool,
        pub backstage: bool,
    }

    impl Default for Grant {
        /// A cohost: on stage in `room-42`, with a camera and stage powers.
        fn default() -> Self {
            Self {
                user: "ada",
                room: Some("room-42"),
                publish: 0b11,
                capabilities: 0x0000_7F00,
                owner: false,
                backstage: false,
            }
        }
    }

    impl Grant {
        /// Somebody with nothing but a seat in the room.
        pub fn viewer() -> Self {
            Self {
                publish: 0,
                capabilities: 0,
                ..Self::default()
            }
        }

        /// The token itself, valid for ten minutes from now.
        pub fn token(&self) -> String {
            let issued = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("after the epoch")
                .as_secs();
            let claims = serde_json::json!({
                "iss": ISSUER,
                "sub": self.user,
                "aud": "acme",
                "iat": issued,
                "exp": issued + 600,
                "cnf": { "jkt": THUMBPRINT },
                "moqt": {
                    "room": self.room.unwrap_or_default(),
                    "pub": self.publish,
                    "cap": self.capabilities,
                    "own": self.owner,
                    "bs": self.backstage,
                },
            });
            mint(
                &serde_json::json!({ "alg": "EdDSA", "typ": "MOQT", "kid": KID }),
                &claims,
            )
        }
    }

    fn mint(header: &serde_json::Value, claims: &serde_json::Value) -> String {
        let segment = |value: &serde_json::Value| {
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("serialisable"))
        };
        let signing = format!("{}.{}", segment(header), segment(claims));
        let signature = signer().sign(signing.as_bytes());
        format!("{signing}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
    }
}
