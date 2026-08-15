//! A live subscribe through a real relay, using only this crate's public API
//! on the client side.
//!
//! The relay is started from the library (`Server` + `Session::serve`), not
//! from the relay crate's test harness, so the sequence under test is the one
//! a recorder would run.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use bytes::Bytes;
use moqom_client::{FullTrackName, Session, TrackNamespace};
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

        let server = Server::bind(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            with_moqt_alpn(tls),
        )
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
}
