//! Two devices on a direct path, admitting each other with the relay's own check.
//!
//! Everything a direct path promises is exercised here over real sockets on the
//! loopback interface: offers sealed under the room secret and opened by their
//! addressee, a pinned mutual handshake, SETUP in both directions with a proof
//! bound to the peer's ephemeral certificate, and media published on one device
//! and read on the other. The verifier is `moqom_relay::direct::PeerCheck`, so a
//! peer admitted here is one a relay would have admitted.
//!
//! The last test adds a relay and reads one track over both paths at once, which
//! is the fallback the direct path is never allowed to be without.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use moqom_client::direct::{
    CandidateOffer, DirectConfig, DirectEndpoint, DualSubscription, Eligibility, IpExposure, Path,
    PathSettings, PeerCredentials, RoomSecret, VerifiedPeer,
};
use moqom_client::{
    Announcement, Credentials, DeviceKey, Error, FullTrackName, Session, Subscription,
    TrackNamespace,
};
use moqom_relay::direct::PeerCheck;
use moqom_relay::{Authenticator, Cache, Fabric, Limits, Session as RelaySession};
use moqom_token::{Claims, Confirmation, Grant, Signer};
use moqom_transport::{Server, server::with_moqt_alpn};

const PATIENCE: Duration = Duration::from_secs(10);
const KEY_ID: &str = "test-key";
const TENANT: &str = "acme";
const ROOM: &str = "room-42";

const ELIGIBLE: Eligibility = Eligibility {
    end_to_end_encrypted: true,
    participants: 2,
    everyone_opted_in: true,
    watchdog_required: false,
    audience: false,
    limit: moqom_client::direct::MAX_PARTICIPANTS,
};

async fn within<F: Future>(what: &str, future: F) -> F::Output {
    tokio::time::timeout(PATIENCE, Box::pin(future))
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}

fn signer() -> Signer {
    Signer::from_seed(&[7u8; 32])
        .expect("a valid ML-DSA-65 seed")
        .with_id(KEY_ID)
}

fn authenticator() -> Authenticator {
    Authenticator::new("", vec![signer().public_key()])
}

/// A token for `user` in `room`, bound to `key`, minted the way the control
/// plane mints one. `publish` is the media-kind bitmask; zero is a viewer.
fn token(user: &str, room: &str, key: &DeviceKey, publish: u32) -> Vec<u8> {
    let issued = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs()
        .cast_signed();
    signer()
        .sign(&Claims {
            iss: "https://api.moqom.cloud".to_owned(),
            sub: user.to_owned(),
            tenant: TENANT.to_owned(),
            iat: issued,
            exp: issued + 600,
            cnf: Confirmation {
                jkt: key.thumbprint(),
            },
            grant: Grant {
                room: room.to_owned(),
                publish: u8::try_from(publish).expect("a media-kind bitmask"),
                ..Grant::default()
            },
            ..Claims::default()
        })
        .expect("a complete ten-minute token")
        .into_bytes()
}

/// `user/device`, with the device derived from the key the way the relay does.
fn participant(user: &str, key: &DeviceKey) -> String {
    let thumbprint = key.thumbprint();
    format!("{user}/{}", &thumbprint[..thumbprint.len().min(16)])
}

/// One device: its key, its token, and its endpoint on loopback.
struct Device {
    me: String,
    key: DeviceKey,
    token: Vec<u8>,
    endpoint: DirectEndpoint,
    check: PeerCheck,
}

impl Device {
    async fn new(user: &str, publish: u32, room: &str) -> Self {
        Self::with_patience(user, publish, room, Duration::from_secs(5)).await
    }

    async fn with_patience(user: &str, publish: u32, room: &str, patience: Duration) -> Self {
        let (key, _) = DeviceKey::generate().expect("a device key");
        let token = token(user, room, &key, publish);
        let me = participant(user, &key);
        let mut config = DirectConfig::new(TENANT, ROOM, me.clone());
        config.bind = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        config.patience = patience;
        let endpoint = DirectEndpoint::bind(
            config,
            &ELIGIBLE,
            IpExposure::peers_will_learn_my_ip_addresses(),
        )
        .await
        .expect("binding a direct endpoint");
        let check = PeerCheck::new(authenticator(), endpoint.certificate_identity());
        Self {
            me,
            key,
            token,
            endpoint,
            check,
        }
    }

    fn verify(&self, presented: &PeerCredentials<'_>) -> Result<VerifiedPeer, String> {
        self.check
            .check(presented.token, presented.proof, SystemTime::now())
            .map(|peer| VerifiedPeer {
                tenant: peer.tenant.to_string(),
                user: peer.user.to_string(),
                device: peer.device.to_string(),
                room: peer.room.map(|room| room.to_string()),
                may_publish: peer.may_publish,
            })
            .map_err(|refusal| refusal.to_string())
    }

    async fn establish(&self, offer: &CandidateOffer) -> Result<(Session, VerifiedPeer), Error> {
        let verifier = |presented: &PeerCredentials<'_>| self.verify(presented);
        self.endpoint
            .establish(
                offer,
                &Credentials::proven(&self.token, &self.key),
                &verifier,
            )
            .await
    }
}

fn install_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Offers sealed by each side and opened by the other, as they would cross the
/// relay on the room's track.
fn exchange(ada: &Device, bob: &Device) -> (CandidateOffer, CandidateOffer) {
    let secret = RoomSecret::new(&[5u8; 32], &format!("{TENANT}/{ROOM}")).expect("a secret");
    let from_ada = ada
        .endpoint
        .offer_to(&bob.me)
        .seal(&secret)
        .expect("sealed");
    let from_bob = bob
        .endpoint
        .offer_to(&ada.me)
        .seal(&secret)
        .expect("sealed");
    (
        CandidateOffer::open(&from_bob, &secret, &ada.me).expect("ada opens bob's offer"),
        CandidateOffer::open(&from_ada, &secret, &bob.me).expect("bob opens ada's offer"),
    )
}

fn track() -> (TrackNamespace, FullTrackName) {
    let namespace =
        TrackNamespace::from_parts([TENANT, "r", ROOM, "ada"]).expect("a valid namespace");
    let track = FullTrackName::new(namespace.clone(), Bytes::from_static(b"video"))
        .expect("a valid track name");
    (namespace, track)
}

#[tokio::test]
async fn two_devices_admit_each_other_and_exchange_media_directly() {
    install_provider();
    let ada = Device::new("ada", 3, ROOM).await;
    let bob = Device::new("bob", 3, ROOM).await;
    let (for_ada, for_bob) = exchange(&ada, &bob);

    let (at_ada, at_bob) = within("both sides to establish", async {
        tokio::join!(ada.establish(&for_ada), bob.establish(&for_bob))
    })
    .await;
    let (mut ada_session, bob_seen_by_ada) = at_ada.expect("ada admits bob");
    let (mut bob_session, ada_seen_by_bob) = at_bob.expect("bob admits ada");

    assert_eq!(
        format!("{}/{}", bob_seen_by_ada.user, bob_seen_by_ada.device),
        bob.me
    );
    assert_eq!(
        format!("{}/{}", ada_seen_by_bob.user, ada_seen_by_bob.device),
        ada.me
    );
    assert_eq!(ada_seen_by_bob.room.as_deref(), Some(ROOM));

    let (namespace, track) = track();
    let announcement = within("announce", ada_session.announce(namespace))
        .await
        .expect("ada announces on the direct session");
    let mut subscription = within("subscribe", bob_session.subscribe(track))
        .await
        .expect("ada answers bob's subscription directly");
    within("ada to see the subscription", announcement.subscribed()).await;

    within(
        "publish",
        ada_session.publish_group(announcement.alias(), 0, &[b"keyframe", b"delta"]),
    )
    .await
    .expect("ada publishes");

    let first = within("first object", subscription.next_object())
        .await
        .expect("decodes")
        .expect("arrives");
    let second = within("second object", subscription.next_object())
        .await
        .expect("decodes")
        .expect("arrives");
    assert_eq!(&first.payload[..], b"keyframe");
    assert_eq!(&second.payload[..], b"delta");
    assert_eq!(second.object, 1);
}

/// A viewer's token verifies, and is still refused: a direct path would hand a
/// viewer the publisher's network address.
#[tokio::test]
async fn a_viewer_is_refused_a_direct_path() {
    install_provider();
    let ada = Device::new("ada", 3, ROOM).await;
    let viewer = Device::new("vic", 0, ROOM).await;
    let (for_ada, for_viewer) = exchange(&ada, &viewer);

    let (at_ada, at_viewer) = within("both sides to finish", async {
        tokio::join!(ada.establish(&for_ada), viewer.establish(&for_viewer))
    })
    .await;
    match at_ada {
        Err(Error::PeerUnverified(reason)) => {
            assert!(
                reason.contains("viewers never use direct paths"),
                "{reason}"
            );
        }
        Err(other) => panic!("refused for the wrong reason: {other}"),
        Ok(_) => panic!("a viewer was admitted to a direct path"),
    }
    assert!(
        at_viewer.is_err(),
        "the viewer believes it has a direct path"
    );
}

/// A token for another room is refused even though it verifies.
#[tokio::test]
async fn a_token_for_another_room_is_refused() {
    install_provider();
    let ada = Device::new("ada", 3, ROOM).await;
    let eve = Device::new("eve", 3, "room-7").await;
    let (for_ada, for_eve) = exchange(&ada, &eve);

    let (at_ada, _) = within("both sides to finish", async {
        tokio::join!(ada.establish(&for_ada), eve.establish(&for_eve))
    })
    .await;
    match at_ada {
        Err(Error::PeerUnverified(reason)) => assert!(reason.contains("another room"), "{reason}"),
        Err(other) => panic!("refused for the wrong reason: {other}"),
        Ok(_) => panic!("a token for another room was admitted"),
    }
}

/// An offer whose certificate is not the one the peer presents is never
/// connected to: the pin is what stops anybody else answering for the peer.
#[tokio::test]
async fn a_peer_presenting_another_certificate_is_never_reached() {
    install_provider();
    let ada = Device::with_patience("ada", 3, ROOM, Duration::from_millis(500)).await;
    let bob = Device::with_patience("bob", 3, ROOM, Duration::from_millis(500)).await;
    let (mut for_ada, for_bob) = exchange(&ada, &bob);
    for_ada.certificate = [0xAA; 32];

    let (at_ada, at_bob) = within("both sides to give up", async {
        tokio::join!(ada.establish(&for_ada), bob.establish(&for_bob))
    })
    .await;
    assert!(
        at_ada.is_err(),
        "ada connected to a certificate it was not offered"
    );
    assert!(
        at_bob.is_err(),
        "bob connected to a peer that refused its certificate"
    );
}

/// Refused before the network is touched, for each rule.
#[tokio::test]
async fn an_ineligible_room_binds_nothing() {
    let config = DirectConfig::new(TENANT, ROOM, "ada/dev");
    let audience = Eligibility {
        audience: true,
        ..ELIGIBLE
    };
    let refused = DirectEndpoint::bind(
        config,
        &audience,
        IpExposure::peers_will_learn_my_ip_addresses(),
    )
    .await;
    assert!(matches!(refused, Err(Error::Ineligible(_))));
}

struct Relay {
    addr: SocketAddr,
    fabric: Fabric,
    certificate: rustls::pki_types::CertificateDer<'static>,
    accept: tokio::task::JoinHandle<()>,
}

impl Relay {
    fn start() -> Self {
        install_provider();
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

/// Ada publishing `track` through the relay and Bob subscribed to it there.
async fn relayed_track(
    relay: &Relay,
    namespace: &TrackNamespace,
    track: &FullTrackName,
) -> (Session, Session, Announcement, Subscription) {
    let tls = moqom_client::tls::pinned(relay.certificate.clone());
    let mut ada = within(
        "ada connects to the relay",
        Session::connect(relay.addr, "localhost", tls.clone(), None),
    )
    .await
    .expect("connects");
    let mut bob = within(
        "bob connects to the relay",
        Session::connect(relay.addr, "localhost", tls, None),
    )
    .await
    .expect("connects");
    let announcement = within("announce on the relay", ada.announce(namespace.clone()))
        .await
        .expect("announces");
    within("the announcement to register", async {
        while relay.fabric.namespaces().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    let subscription = within("subscribe on the relay", bob.subscribe(track.clone()))
        .await
        .expect("subscribes");
    within("the relay to pull ada", announcement.subscribed()).await;
    (ada, bob, announcement, subscription)
}

/// One track over the relay and the direct path at once: each object delivered
/// once, the direct path taking over once it keeps up, and the relay copy
/// delivering what the direct path then fails to.
#[tokio::test]
async fn a_dual_subscription_moves_to_the_direct_path_and_falls_back_to_the_relay() {
    install_provider();
    let relay = Relay::start();
    let (namespace, track) = track();
    let (ada_relay, _bob_relay, relayed, relay_subscription) =
        relayed_track(&relay, &namespace, &track).await;

    let ada = Device::new("ada", 3, ROOM).await;
    let bob = Device::new("bob", 3, ROOM).await;
    let (for_ada, for_bob) = exchange(&ada, &bob);
    let (at_ada, at_bob) = within("the direct path", async {
        tokio::join!(ada.establish(&for_ada), bob.establish(&for_bob))
    })
    .await;
    let (mut ada_direct, _) = at_ada.expect("ada admits bob");
    let (mut bob_direct, _) = at_bob.expect("bob admits ada");
    let direct = within("announce directly", ada_direct.announce(namespace))
        .await
        .expect("announces");
    let direct_subscription = within("subscribe directly", bob_direct.subscribe(track))
        .await
        .expect("subscribes");
    within("ada to see bob", direct.subscribed()).await;

    let mut dual = DualSubscription::new(
        relay_subscription,
        PathSettings {
            settle: Duration::ZERO,
            stall: Duration::from_millis(150),
            held: 64,
        },
    );
    dual.attach_direct(direct_subscription);
    assert_eq!(
        dual.path(),
        Path::Relay,
        "a new direct path starts on probation"
    );

    // Group 0 on both paths, direct first.
    within(
        "publish directly",
        ada_direct.publish_group(direct.alias(), 0, &[b"g0-a", b"g0-b"]),
    )
    .await
    .expect("publishes");
    let mut seen = Vec::new();
    for _ in 0..2 {
        let delivery = within("a direct delivery", dual.next())
            .await
            .expect("no relay failure")
            .expect("not ended");
        seen.push((delivery.object.payload.clone(), delivery.path));
    }
    assert_eq!(
        seen,
        vec![
            (Bytes::from_static(b"g0-a"), Path::Direct),
            (Bytes::from_static(b"g0-b"), Path::Direct),
        ]
    );
    assert_eq!(dual.path(), Path::Direct);
    within(
        "publish on the relay",
        ada_relay.publish_group(relayed.alias(), 0, &[b"g0-a", b"g0-b"]),
    )
    .await
    .expect("publishes");

    // Group 1 on the relay only: the direct path has lost it, so the relay copy
    // is delivered once the stall bound passes, and the direct path is dropped.
    within(
        "publish on the relay",
        ada_relay.publish_group(relayed.alias(), 1, &[b"g1-a"]),
    )
    .await
    .expect("publishes");
    let recovered = within("the relay copy", dual.next())
        .await
        .expect("no relay failure")
        .expect("not ended");
    assert_eq!(
        &recovered.object.payload[..],
        b"g1-a",
        "the relay's group 0 is not repeated"
    );
    assert_eq!(recovered.path, Path::Relay);
    assert_eq!(dual.path(), Path::Relay);
    assert!(!dual.has_direct());
    assert_eq!(dual.switches(), 2);

    // And the relay carries on alone.
    within(
        "publish on the relay",
        ada_relay.publish_group(relayed.alias(), 2, &[b"g2-a"]),
    )
    .await
    .expect("publishes");
    let after = within("the next relay object", dual.next())
        .await
        .expect("no relay failure")
        .expect("not ended");
    assert_eq!(&after.object.payload[..], b"g2-a");
    assert_eq!(after.path, Path::Relay);
}
