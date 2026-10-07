//! A live subscribe through a real relay, using only this crate's public API
//! on the client side.
//!
//! The relay is started from the library (`Server` + `Session::serve`), not
//! from the relay crate's test harness, so the sequence under test is the one
//! a recorder would run.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use bytes::Bytes;
use moqom_client::{
    FullTrackName, Metadata, ObjectProperties, OutgoingObject, Session, TrackNamespace,
};
use moqom_relay::{Cache, Fabric, Limits, Session as RelaySession};
use moqom_transport::{Server, server::with_moqt_alpn};

const PATIENCE: Duration = Duration::from_secs(10);

struct Relay {
    addr: SocketAddr,
    fabric: Fabric,
    certificate: rustls::pki_types::CertificateDer<'static>,
    accept: tokio::task::JoinHandle<()>,
}

impl Relay {
    fn start() -> Self {
        Self::offering(moqom_transport::alpn::OFFERED)
    }

    /// A relay whose TLS offers only `alpns`, as one that predates draft-22
    /// would.
    fn offering(alpns: &[&[u8]]) -> Self {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generating a certificate");
        let certificate = generated.cert.der().clone();
        let key = rustls::pki_types::PrivateKeyDer::try_from(generated.signing_key.serialize_der())
            .expect("generated key is usable");
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key)
            .expect("certificate and key agree");

        let mut tls = with_moqt_alpn(tls);
        tls.alpn_protocols = alpns.iter().map(|alpn| alpn.to_vec()).collect();
        let server = Server::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), tls)
            .expect("binding a loopback port");
        let addr = server.local_addr().expect("bound address");
        let fabric = Fabric::with_cache(Cache::new(Limits::default()));
        let accept = tokio::spawn({
            let fabric = fabric.clone();
            async move {
                while let Some(incoming) = server.accept().await {
                    let fabric = fabric.clone();
                    tokio::spawn(async move {
                        let Ok((session, negotiated)) = incoming.establish().await else {
                            return;
                        };
                        let _ = RelaySession::serve(session, negotiated.carrier, fabric).await;
                    });
                }
            }
        });

        Self {
            addr,
            fabric,
            certificate,
            accept,
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

async fn within<F: Future>(what: &str, future: F) -> F::Output {
    tokio::time::timeout(PATIENCE, future)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}

/// Objects published on one session come out of another, with the payload
/// untouched. This is the claim a recorder depends on.
#[tokio::test]
async fn objects_round_trip_through_a_relay() {
    let relay = Relay::start();
    let tls = moqom_client::tls::pinned(relay.certificate.clone());

    let mut publisher = within(
        "publisher connect",
        Session::connect(relay.addr, "localhost", tls.clone(), None),
    )
    .await
    .expect("publisher connects");
    let mut subscriber = within(
        "subscriber connect",
        Session::connect(relay.addr, "localhost", tls, None),
    )
    .await
    .expect("subscriber connects");

    let namespace = TrackNamespace::from_parts(["acme", "room-42"]).expect("a valid namespace");
    let track = FullTrackName::new(namespace.clone(), Bytes::from_static(b"video"))
        .expect("a valid track name");

    let announcement = within("announce", publisher.announce(namespace))
        .await
        .expect("the relay accepts the announcement");
    within("the announcement to register", async {
        while relay.fabric.namespaces().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await;

    let mut subscription = within("subscribe", subscriber.subscribe(track))
        .await
        .expect("the relay accepts the subscription");
    within("the relay to pull the publisher", announcement.subscribed()).await;

    let alias = announcement.alias();
    assert_ne!(
        subscription.alias, alias,
        "the downstream alias must be the relay's own"
    );

    within(
        "publish",
        publisher.publish_group(alias, 0, &[b"first", b"second"]),
    )
    .await
    .expect("the publisher writes a subgroup");

    let first = within("first object", subscription.next_object())
        .await
        .expect("the first object decodes")
        .expect("the first object arrives");
    let second = within("second object", subscription.next_object())
        .await
        .expect("the second object decodes")
        .expect("the second object arrives");

    assert_eq!(first.group.get(), 0);
    assert_eq!(first.object, 0);
    assert_eq!(&first.payload[..], b"first");
    assert_eq!(second.object, 1);
    assert_eq!(&second.payload[..], b"second");

    // Nothing said, so nothing arrives: the header's properties_present flag is
    // off for a publisher that only sends bytes, and an empty set on the far side
    // is what proves it rather than a set of defaults.
    assert!(first.properties.is_empty());
}

/// What a publisher says about each object arrives with it, through the relay.
///
/// The claim a latency measurement rests on. A capture time inferred from arrival
/// order measures the receiver's scheduler; this one is the publisher's clock,
/// carried on the object, and the relay forwards it without understanding it.
#[tokio::test]
async fn object_properties_survive_the_relay() {
    let relay = Relay::start();
    let tls = moqom_client::tls::pinned(relay.certificate.clone());

    let mut publisher = within(
        "publisher connect",
        Session::connect(relay.addr, "localhost", tls.clone(), None),
    )
    .await
    .expect("publisher connects");
    let mut subscriber = within(
        "subscriber connect",
        Session::connect(relay.addr, "localhost", tls, None),
    )
    .await
    .expect("subscriber connects");

    let namespace = TrackNamespace::from_parts(["acme", "room-42"]).expect("a valid namespace");
    let track = FullTrackName::new(namespace.clone(), Bytes::from_static(b"video"))
        .expect("a valid track name");

    let announcement = within("announce", publisher.announce(namespace))
        .await
        .expect("the relay accepts the announcement");
    within("the announcement to register", async {
        while relay.fabric.namespaces().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    let mut subscription = within("subscribe", subscriber.subscribe(track))
        .await
        .expect("the relay accepts the subscription");
    within("the relay to pull the publisher", announcement.subscribed()).await;

    // A keyframe and the frame after it, tagged the way a video publisher tags
    // them: the group opener carries the parameter sets, both carry a capture
    // time, and the second is on the enhancement layer a relay may drop.
    let opener = ObjectProperties::default()
        .captured_at_micros(1_000_000)
        .opening(Bytes::from_static(b"sps/pps"));
    let follower = ObjectProperties {
        capture_time_micros: Some(1_033_333),
        temporal_layer: Some(1),
        ..ObjectProperties::default()
    };
    within(
        "publish",
        publisher.publish_objects(
            announcement.alias(),
            7,
            &[
                OutgoingObject::tagged(b"keyframe", opener.clone()),
                OutgoingObject::tagged(b"delta", follower.clone()),
            ],
        ),
    )
    .await
    .expect("the publisher writes a tagged subgroup");

    let first = within("first object", subscription.next_object())
        .await
        .expect("the first object decodes")
        .expect("the first object arrives");
    let second = within("second object", subscription.next_object())
        .await
        .expect("the second object decodes")
        .expect("the second object arrives");

    assert_eq!(first.properties, opener);
    assert_eq!(second.properties, follower);
    assert_eq!(&first.payload[..], b"keyframe");
    assert_eq!(&second.payload[..], b"delta");
    assert_eq!(first.group.get(), 7);
}

/// A frame arrives before the group it is in has finished.
///
/// The whole reason [`Session::open_group`] exists. A group is a group of
/// pictures, so a publisher that hands over a complete one has already held its
/// keyframe for the length of a GOP -- and because the capture times ride on the
/// objects, that delay would show up in the measurement as though the network had
/// caused it. This asserts the frames come out one at a time, while the group is
/// still open.
#[tokio::test]
async fn a_frame_arrives_before_its_group_is_finished() {
    let relay = Relay::start();
    let tls = moqom_client::tls::pinned(relay.certificate.clone());

    let mut publisher = within(
        "publisher connect",
        Session::connect(relay.addr, "localhost", tls.clone(), None),
    )
    .await
    .expect("publisher connects");
    let mut subscriber = within(
        "subscriber connect",
        Session::connect(relay.addr, "localhost", tls, None),
    )
    .await
    .expect("subscriber connects");

    let namespace = TrackNamespace::from_parts(["acme", "room-42"]).expect("a valid namespace");
    let track = FullTrackName::new(namespace.clone(), Bytes::from_static(b"video"))
        .expect("a valid track name");

    let announcement = within("announce", publisher.announce(namespace))
        .await
        .expect("the relay accepts the announcement");
    within("the announcement to register", async {
        while relay.fabric.namespaces().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    let mut subscription = within("subscribe", subscriber.subscribe(track))
        .await
        .expect("the relay accepts the subscription");
    within("the relay to pull the publisher", announcement.subscribed()).await;

    let mut group = within(
        "open a group",
        publisher.open_group(announcement.alias(), 3, Metadata::Present),
    )
    .await
    .expect("the publisher opens a group");

    let keyframe = ObjectProperties::default()
        .captured_at_micros(500_000)
        .opening(Bytes::from_static(b"vps/sps/pps"));
    assert_eq!(
        within(
            "write the keyframe",
            group.write(&OutgoingObject::tagged(b"keyframe", keyframe.clone())),
        )
        .await
        .expect("the keyframe is written"),
        0,
        "object IDs come from position in the group"
    );

    // Nothing has finished the group, and the frame is expected anyway.
    let first = within("the keyframe to arrive", subscription.next_object())
        .await
        .expect("the keyframe decodes")
        .expect("the keyframe arrives while the group is open");
    assert_eq!(&first.payload[..], b"keyframe");
    assert_eq!(first.properties, keyframe);
    assert_eq!(first.group.get(), 3);

    let delta = ObjectProperties::default().captured_at_micros(533_333);
    within(
        "write the delta",
        group.write(&OutgoingObject::tagged(b"delta", delta.clone())),
    )
    .await
    .expect("the delta is written");

    let second = within("the delta to arrive", subscription.next_object())
        .await
        .expect("the delta decodes")
        .expect("the delta arrives while the group is open");
    assert_eq!(&second.payload[..], b"delta");
    assert_eq!(second.properties, delta);
    assert_eq!(second.object, 1);

    assert_eq!(group.written(), 2);
    group.finish().expect("the group closes");
}

/// Whether properties are present is a header flag, so it is settled before the
/// first object. Silently dropping them would leave a latency harness reporting
/// nothing with no way to find out why.
#[tokio::test]
async fn a_group_opened_without_properties_refuses_a_tagged_object() {
    let relay = Relay::start();
    let tls = moqom_client::tls::pinned(relay.certificate.clone());

    let mut publisher = within(
        "publisher connect",
        Session::connect(relay.addr, "localhost", tls, None),
    )
    .await
    .expect("publisher connects");

    let namespace = TrackNamespace::from_parts(["acme", "room-42"]).expect("a valid namespace");
    let announcement = within("announce", publisher.announce(namespace))
        .await
        .expect("the relay accepts the announcement");

    let mut group = within(
        "open a group",
        publisher.open_group(announcement.alias(), 0, Metadata::Absent),
    )
    .await
    .expect("the publisher opens a group");

    let error = group
        .write(&OutgoingObject::tagged(
            b"frame",
            ObjectProperties::default().captured_at_micros(1),
        ))
        .await
        .expect_err("a tagged object in an untagged group is refused");
    assert!(matches!(error, moqom_client::Error::PropertiesNotDeclared));

    // An untagged object on the same group is still fine.
    within(
        "write an untagged object",
        group.write(&OutgoingObject::new(b"frame")),
    )
    .await
    .expect("an untagged object is accepted");
    group.finish().expect("the group closes");
}

/// The client prefers draft-22, and still works against a relay that only
/// speaks MOQOM's draft-19.
#[tokio::test]
async fn the_client_speaks_whichever_draft_the_relay_picks() {
    for (relay, expected) in [
        (Relay::start(), moqom_proto::Draft::D22),
        (
            Relay::offering(&[moqom_transport::alpn::MOQT_DRAFT_19]),
            moqom_proto::Draft::D19,
        ),
    ] {
        let tls = moqom_client::tls::pinned(relay.certificate.clone());
        let mut publisher = within(
            "publisher connect",
            Session::connect(relay.addr, "localhost", tls.clone(), None),
        )
        .await
        .expect("publisher connects");
        let mut subscriber = within(
            "subscriber connect",
            Session::connect(relay.addr, "localhost", tls, None),
        )
        .await
        .expect("subscriber connects");
        assert_eq!(publisher.draft(), expected);
        assert_eq!(subscriber.draft(), expected);

        let namespace = TrackNamespace::from_parts(["acme", "room"]).expect("a namespace");
        let track =
            FullTrackName::new(namespace.clone(), Bytes::from_static(b"audio")).expect("a track");
        let mut watch = within("watch", subscriber.watch(namespace.clone()))
            .await
            .expect("a watch");
        let announcement = within("announce", publisher.announce(namespace.clone()))
            .await
            .expect("announced");
        let seen = within("the namespace to be seen", watch.next())
            .await
            .expect("a decodable event");
        assert_eq!(
            seen,
            Some(moqom_client::NamespaceEvent::Available(namespace))
        );

        let mut subscription = within("subscribe", subscriber.subscribe(track))
            .await
            .expect("subscribed");
        within("the relay to pull", announcement.subscribed()).await;
        within(
            "publish",
            publisher.publish_group(announcement.alias(), 5, &[b"one"]),
        )
        .await
        .expect("published");
        let object = within("the object", subscription.next_object())
            .await
            .expect("decodes")
            .expect("arrives");
        assert_eq!(&object.payload[..], b"one");
        assert_eq!(object.group.get(), 5);
    }
}
