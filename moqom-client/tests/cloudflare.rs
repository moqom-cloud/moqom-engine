//! The draft-16 subscriber, against a scripted relay and, when asked, against
//! Cloudflare's.
//!
//! The scripted relay is written from the draft rather than from the client,
//! so the two cannot share a framing mistake. The live test is `#[ignore]`d:
//! it needs the network and a token, which comes from `MOQOM_CF_DEMO_TOKEN`
//! and is never written anywhere.
//!
//! ```text
//! MOQOM_CF_DEMO_TOKEN=... cargo test -p moqom-client --test cloudflare -- --ignored
//! ```

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use moqom_client::cloudflare::{DEMO_HOST, DEMO_PORT, Session};
use moqom_client::{FullTrackName, TrackNamespace};
use moqom_proto::Draft;
use moqom_proto::control::d16::{Filter, Message, param, setup_param};
use moqom_proto::control::{Parameter, Parameters, Properties, ReasonPhrase};
use moqom_proto::data::{SubgroupHeader, SubgroupObject, SubgroupSource, SubgroupWriter};
use moqom_proto::error::DecodeError;
use moqom_proto::model::{GroupId, Location, ObjectId, TrackAlias};
use moqom_proto::varint::VarInt;

const PATIENCE: Duration = Duration::from_secs(10);

async fn within<F: Future>(what: &str, future: F) -> F::Output {
    tokio::time::timeout(PATIENCE, future)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}

fn track(name: &str) -> FullTrackName {
    FullTrackName::new(
        TrackNamespace::from_parts(["bbb"]).unwrap(),
        Bytes::copy_from_slice(name.as_bytes()),
    )
    .unwrap()
}

/// The relay's end of the control stream.
struct Control {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    buffer: BytesMut,
}

impl Control {
    async fn read(&mut self) -> Message {
        loop {
            let mut cursor = &self.buffer[..];
            match Message::decode(Draft::D16, &mut cursor) {
                Ok(message) => {
                    let consumed = self.buffer.len() - cursor.len();
                    let _ = self.buffer.split_to(consumed);
                    return message;
                }
                Err(DecodeError::Short { .. }) => {}
                Err(e) => panic!("the client sent an undecodable message: {e}"),
            }
            let chunk = within("a control message", self.recv.read_chunk(4096, true))
                .await
                .expect("reading the control stream")
                .expect("the client keeps the control stream open");
            self.buffer.extend_from_slice(&chunk.bytes);
        }
    }

    async fn write(&mut self, message: &Message) {
        let bytes = message.to_bytes(Draft::D16).unwrap();
        self.send.write_all(&bytes).await.unwrap();
    }
}

/// A draft-16 relay that does what the test says, one step at a time.
struct Scripted {
    addr: SocketAddr,
    certificate: rustls::pki_types::CertificateDer<'static>,
    endpoint: quinn::Endpoint,
}

impl Scripted {
    fn start() -> Self {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let certificate = generated.cert.der().clone();
        let key = rustls::pki_types::PrivateKeyDer::try_from(generated.signing_key.serialize_der())
            .unwrap();
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key)
            .unwrap();
        tls.alpn_protocols = vec![b"moqt-16".to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        let endpoint =
            quinn::Endpoint::server(config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        Self {
            addr: endpoint.local_addr().unwrap(),
            certificate,
            endpoint,
        }
    }

    /// Accept the client and take its `CLIENT_SETUP`, answering with
    /// `MAX_REQUEST_ID` = `limit`.
    async fn accept(&self, limit: u32) -> (quinn::Connection, Control, Parameters) {
        let incoming = within("a connection", self.endpoint.accept())
            .await
            .unwrap();
        let connection = incoming.await.unwrap();
        let (send, recv) = within("the control stream", connection.accept_bi())
            .await
            .unwrap();
        let mut control = Control {
            send,
            recv,
            buffer: BytesMut::new(),
        };
        let Message::ClientSetup(parameters) = control.read().await else {
            panic!("the client must open with CLIENT_SETUP");
        };
        let mut ours = Parameters::new();
        ours.push(Parameter::varint(setup_param::MAX_REQUEST_ID, VarInt::from_u32(limit)).unwrap());
        control.write(&Message::ServerSetup(ours)).await;
        (connection, control, parameters)
    }
}

async fn publish_subgroup(
    connection: &quinn::Connection,
    alias: u32,
    group: u32,
    payloads: &[&[u8]],
) {
    let bytes = Draft::D16.scope(|| {
        let header = SubgroupHeader::new(
            TrackAlias::new(VarInt::from_u32(alias)),
            GroupId::new(VarInt::from_u32(group)),
            SubgroupSource::Zero,
        );
        let mut buf = Vec::new();
        header.encode(&mut buf);
        let mut writer = SubgroupWriter::new(&header);
        for (id, payload) in payloads.iter().enumerate() {
            writer
                .write(
                    &mut buf,
                    &SubgroupObject::new(id as u32, Bytes::copy_from_slice(payload)),
                )
                .unwrap();
        }
        buf
    });
    let mut stream = connection.open_uni().await.unwrap();
    stream.write_all(&bytes).await.unwrap();
    stream.finish().unwrap();
}

#[tokio::test]
async fn setup_carries_the_token_as_the_path_and_nothing_private() {
    let relay = Scripted::start();
    let connecting = Session::connect_to(
        relay.addr,
        "localhost",
        moqom_client::tls::pinned(relay.certificate.clone()),
        "header.claims.signature",
    );
    let (session, (_connection, _control, setup)) = tokio::join!(connecting, relay.accept(0));
    session.expect("the session is established");

    let bytes = |t| setup.get(t).and_then(Parameter::as_bytes).cloned();
    assert_eq!(
        bytes(setup_param::PATH),
        Some(Bytes::from_static(b"/header.claims.signature"))
    );
    assert_eq!(
        bytes(setup_param::AUTHORITY),
        Some(Bytes::from_static(b"localhost"))
    );
    assert_eq!(
        setup
            .get(setup_param::MAX_REQUEST_ID)
            .and_then(Parameter::as_varint),
        Some(VarInt::from_u32(0)),
        "the relay may not make requests of a subscriber"
    );
    for parameter in setup.as_slice() {
        assert!(
            [
                setup_param::PATH,
                setup_param::MAX_REQUEST_ID,
                setup_param::AUTHORITY,
                setup_param::MOQT_IMPLEMENTATION
            ]
            .contains(&parameter.type_value()),
            "no MOQOM option goes to a draft-16 relay, found {:#x}",
            parameter.type_value()
        );
    }
}

#[tokio::test]
async fn a_subscription_receives_objects_until_publish_done() {
    let relay = Scripted::start();
    let connecting = Session::connect_to(
        relay.addr,
        "localhost",
        moqom_client::tls::pinned(relay.certificate.clone()),
        "t",
    );
    let (session, (connection, mut control, _)) = tokio::join!(connecting, relay.accept(10));
    let session = session.unwrap();

    let relay_side = async {
        let Message::Subscribe(request) = control.read().await else {
            panic!("expected SUBSCRIBE");
        };
        assert_eq!(
            request.request_id.get(),
            0,
            "a client's first request ID is 0"
        );
        assert_eq!(request.track, track("1.m4s"));
        assert_eq!(
            request
                .parameters
                .get(param::SUBSCRIPTION_FILTER)
                .and_then(Parameter::as_bytes)
                .map(|b| Filter::decode(b).unwrap()),
            Some(Filter::LargestObject)
        );
        let mut location = Vec::new();
        Draft::D16.scope(|| {
            Location::new(GroupId::new(VarInt::from_u32(3)), ObjectId::ZERO).encode(&mut location);
        });
        let mut ok = Parameters::new();
        ok.push(Parameter::bytes(param::LARGEST_OBJECT, location).unwrap());
        control
            .write(&Message::SubscribeOk {
                request_id: request.request_id,
                track_alias: TrackAlias::new(VarInt::from_u32(9)),
                parameters: ok,
                extensions: Properties::new(),
            })
            .await;
        request.request_id
    };
    let (subscription, request_id) = tokio::join!(
        session.subscribe(track("1.m4s"), Some(Filter::LargestObject)),
        relay_side
    );
    let mut subscription = subscription.expect("subscribed");
    assert_eq!(
        subscription.largest,
        Some(Location::new(
            GroupId::new(VarInt::from_u32(3)),
            ObjectId::ZERO
        ))
    );

    publish_subgroup(&connection, 9, 4, &[b"moof", b"mdat"]).await;
    let first = within("the first object", subscription.next_object())
        .await
        .unwrap()
        .expect("an object");
    let second = within("the second object", subscription.next_object())
        .await
        .unwrap()
        .expect("an object");
    assert_eq!((first.group.get(), first.object), (4, 0));
    assert_eq!(&second.payload[..], b"mdat");

    control
        .write(&Message::PublishDone {
            request_id,
            status: VarInt::from_u32(2),
            stream_count: VarInt::from_u32(1),
            reason: ReasonPhrase::truncating("track ended"),
        })
        .await;
    assert!(
        within("the end", subscription.next_object())
            .await
            .unwrap()
            .is_none()
    );
    let ended = subscription.ended().expect("PUBLISH_DONE recorded");
    assert_eq!((ended.status, ended.reason.as_str()), (2, "track ended"));
}

#[tokio::test]
async fn a_client_at_the_request_limit_says_so_and_waits() {
    let relay = Scripted::start();
    let connecting = Session::connect_to(
        relay.addr,
        "localhost",
        moqom_client::tls::pinned(relay.certificate.clone()),
        "t",
    );
    // Room for one request: ID 0.
    let (session, (_connection, mut control, _)) = tokio::join!(connecting, relay.accept(1));
    let session = session.unwrap();

    let relay_side = async {
        let mut answered = Vec::new();
        for _ in 0..2 {
            let mut message = control.read().await;
            if let Message::RequestsBlocked(at) = message {
                assert_eq!(at.get(), 1, "blocked on the limit the relay set");
                control
                    .write(&Message::MaxRequestId(VarInt::from_u32(3)))
                    .await;
                message = control.read().await;
            }
            let Message::Subscribe(request) = message else {
                panic!("expected SUBSCRIBE, got {message:?}");
            };
            answered.push(request.request_id.get());
            control
                .write(&Message::SubscribeOk {
                    request_id: request.request_id,
                    track_alias: TrackAlias::new(VarInt::from_u32(answered.len() as u32)),
                    parameters: Parameters::new(),
                    extensions: Properties::new(),
                })
                .await;
        }
        // Dropping a subscription unsubscribes it.
        let unsubscribed = control.read().await;
        (answered, unsubscribed)
    };
    let client_side = async {
        let first = session.subscribe(track("0.mp4"), None).await.unwrap();
        let second = session.subscribe(track("1.m4s"), None).await.unwrap();
        drop(first);
        second
    };
    let (_second, (answered, unsubscribed)) = tokio::join!(client_side, relay_side);
    assert_eq!(
        answered,
        vec![0, 2],
        "even IDs, the second after the limit rose"
    );
    assert!(matches!(
        unsubscribed,
        Message::Unsubscribe { request_id } if request_id.get() == 0
    ));
}

/// Against Cloudflare's relay, for real. The demo broadcast `bbb` is
/// moq-pub's layout: `0.mp4` is the init segment, `<track id>.m4s` the media.
#[tokio::test]
#[ignore = "needs the network and MOQOM_CF_DEMO_TOKEN"]
async fn live_cloudflare_demo() {
    let token = std::env::var("MOQOM_CF_DEMO_TOKEN").expect("MOQOM_CF_DEMO_TOKEN is set");
    let session = within(
        "connecting to Cloudflare",
        Session::connect(DEMO_HOST, DEMO_PORT, &token),
    )
    .await
    .expect("Cloudflare accepts the session");

    let mut init = within(
        "subscribing to 0.mp4",
        session.subscribe(track("0.mp4"), None),
    )
    .await
    .expect("Cloudflare accepts the subscription");
    let mut media = within(
        "subscribing to 1.m4s",
        session.subscribe(track("1.m4s"), Some(Filter::LargestObject)),
    )
    .await
    .expect("Cloudflare accepts the subscription");
    eprintln!(
        "0.mp4: alias {}, largest {:?}; 1.m4s: alias {}, largest {:?}",
        init.alias, init.largest, media.alias, media.largest
    );

    let object = tokio::time::timeout(Duration::from_secs(20), media.next_object())
        .await
        .expect("an object within 20 s")
        .expect("decodable")
        .expect("the subscription is live");
    eprintln!(
        "1.m4s: group {} object {}, {} bytes",
        object.group,
        object.object,
        object.payload.len()
    );
    assert!(!object.payload.is_empty());

    // The init segment is published once, so it may or may not be sent to
    // a late subscriber; report rather than require it.
    match tokio::time::timeout(Duration::from_secs(3), init.next_object()).await {
        Ok(Ok(Some(object))) => eprintln!(
            "0.mp4: group {} object {}, {} bytes, starts {:?}",
            object.group,
            object.object,
            object.payload.len(),
            String::from_utf8_lossy(&object.payload[4..8.min(object.payload.len())])
        ),
        other => eprintln!("0.mp4: nothing within 3 s ({other:?})"),
    }
    session.close();
}
