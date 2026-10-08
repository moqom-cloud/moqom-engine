//! Direct paths in a room, from joining to falling back.
//!
//! Each participant runs a [`DirectRoom`] beside its relay session, as an app
//! would: the relay authenticates, checks proofs, issues direct tickets and
//! answers STUN, and the room's grant names that STUN server. Nothing is
//! handed to the room but the roster and the key, so the offers, the punch,
//! the peer check, the tickets, pausing the relay copy and falling back are
//! all the room's own.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use moqom_client::direct::{
    DirectConfig, DirectPolicy, DirectRoom, DirectRoomConfig, Fallback, Ineligible, IpExposure,
    OFFERS_TRACK, Path, PathSettings, PathState, PeerCredentials, RoomCredentials,
    RoomDirectPolicy, RoomPublication, RoomSubscription, RoomView, StunServer, TicketSettings,
    VerifiedPeer,
};
use moqom_client::{
    Announcement, Credentials, DeviceKey, FullTrackName, OutgoingObject, Session, TrackNamespace,
};
use moqom_relay::direct::PeerCheck;
use moqom_relay::fabric::Ticketing;
use moqom_relay::metrics::Gauges;
use moqom_relay::possession::{Enforcement, Possession};
use moqom_relay::ticket::TicketKeys;
use moqom_relay::{Authenticator, Cache, Fabric, Limits, Metrics, Session as RelaySession};
use moqom_token::{Claims, Confirmation, Grant, Signer};
use moqom_transport::{Server, server::with_moqt_alpn};

const PATIENCE: Duration = Duration::from_secs(20);
const TENANT: &str = "acme";
const ROOM: &str = "room-42";
const SECRET: [u8; 32] = [5; 32];

async fn within<F: Future>(what: &str, future: F) -> F::Output {
    tokio::time::timeout(PATIENCE, Box::pin(future))
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}

fn install_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn signer() -> Signer {
    Signer::from_seed(&[7u8; 32])
        .expect("a valid ML-DSA-65 seed")
        .with_id("test-key")
}

fn authenticator() -> Authenticator {
    Authenticator::new("", vec![signer().public_key()])
}

/// A publisher's token for the room, on stage or backstage.
fn token(user: &str, key: &DeviceKey, backstage: bool) -> Vec<u8> {
    let issued = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
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
                room: ROOM.to_owned(),
                publish: 3,
                backstage,
                ..Grant::default()
            },
            ..Claims::default()
        })
        .expect("a complete token")
        .into_bytes()
}

/// The relay's check, against whichever certificate this attempt's endpoint
/// presented.
fn verify(presented: &PeerCredentials<'_>) -> Result<VerifiedPeer, String> {
    PeerCheck::new(authenticator(), presented.local_certificate)
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

fn slot(me: &str, backstage: bool) -> TrackNamespace {
    let (user, device) = me.split_once('/').expect("user/device");
    let marker = if backstage { "bs" } else { "r" };
    TrackNamespace::from_parts([TENANT, marker, ROOM, user, device]).expect("a valid namespace")
}

/// A relay that verifies tokens and proofs, issues direct tickets, and
/// answers STUN beside it.
struct Relay {
    addr: SocketAddr,
    certificate: rustls::pki_types::CertificateDer<'static>,
    stun: SocketAddr,
    metrics: Metrics,
    accept: tokio::task::JoinHandle<()>,
    answering: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Relay {
    fn start() -> Self {
        Self::issuing(true)
    }

    fn issuing(tickets: bool) -> Self {
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

        let identity = URL_SAFE_NO_PAD.encode(
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, certificate.as_ref()).as_ref(),
        );
        let metrics = Metrics::new();
        let fabric = Fabric::observed(Cache::new(Limits::default()), metrics.clone())
            .authenticated(authenticator())
            .proving(Possession::new(Enforcement::Required, Some(identity)));
        let fabric = if tickets {
            fabric.ticketing(Ticketing {
                keys: Arc::new(TicketKeys::from_seed("ticket-test", &[11u8; 32])),
                renew: Duration::from_secs(1),
            })
        } else {
            fabric
        };
        let accept = tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                let fabric = fabric.clone();
                tokio::spawn(async move {
                    let Ok((session, negotiated)) = incoming.establish().await else {
                        return;
                    };
                    let _ = RelaySession::serve(session, negotiated.carrier, fabric).await;
                });
            }
        });

        let responder = moqom_relay::stun::Responder::bind(
            &moqom_relay::stun::Config {
                listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                limits: moqom_relay::stun::Limits::default(),
            },
            metrics.clone(),
        )
        .expect("binding STUN");
        let stun = responder.local_addr().expect("bound");
        Self {
            addr,
            certificate,
            stun,
            metrics,
            accept,
            answering: tokio::spawn(responder.serve()),
        }
    }

    /// The grant the control plane sends with each token: allowed, up to four,
    /// and this relay's STUN responder.
    fn grant(&self) -> RoomDirectPolicy {
        RoomDirectPolicy {
            allowed: true,
            max_participants: 4,
            stun: Some(StunServer::Address(self.stun)),
        }
    }

    /// Binding requests this relay's STUN responder has answered.
    fn stun_answered(&self) -> u64 {
        let exposed = self.metrics.expose(&Gauges::default());
        let prefix = r#"moqom_relay_stun_requests_total{outcome="answered"} "#;
        exposed
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .and_then(|count| count.trim().parse().ok())
            .unwrap_or(0)
    }

    async fn connect(&self, token: &[u8], key: &DeviceKey) -> Session {
        let tls = moqom_client::tls::pinned(self.certificate.clone());
        within(
            "connecting to the relay",
            Session::connect(
                self.addr,
                "localhost",
                tls,
                Some(&Credentials::proven(token, key)),
            ),
        )
        .await
        .expect("admitted")
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.accept.abort();
        self.answering.abort();
    }
}

/// One participant: a relay session publishing on its own slot, and the room.
struct Member {
    me: String,
    backstage: bool,
    key: Arc<DeviceKey>,
    room: DirectRoom,
    _slot: Announcement,
}

impl Member {
    async fn join(
        relay: &Relay,
        user: &str,
        backstage: bool,
        policy: DirectPolicy,
        grant: RoomDirectPolicy,
    ) -> Self {
        let (key, _) = DeviceKey::generate().expect("a device key");
        let key = Arc::new(key);
        let token = token(user, &key, backstage);
        let thumbprint = key.thumbprint();
        let me = format!("{user}/{}", &thumbprint[..16]);
        let mut session = relay.connect(&token, &key).await;
        let mut endpoint = DirectConfig::new(TENANT, ROOM, me.clone());
        endpoint.bind = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        endpoint.patience = Duration::from_secs(5);
        let mut config = DirectRoomConfig::new(
            endpoint,
            IpExposure::peers_will_learn_my_ip_addresses(),
            Arc::new(verify),
        );
        config.path = PathSettings {
            settle: Duration::from_millis(200),
            ..PathSettings::default()
        };
        config.tickets = TicketSettings {
            grace: Duration::from_secs(2),
            represent: Duration::from_millis(300),
            ..TicketSettings::default()
        };
        config.retry = Duration::from_millis(200);
        let room = DirectRoom::new(
            session.clone(),
            RoomCredentials {
                token,
                key: Some(Arc::clone(&key)),
            },
            policy,
            grant,
            config,
        );
        let announced = within(
            "announcing the slot",
            session.announce(slot(&me, backstage)),
        )
        .await
        .expect("a participant announces its own slot");
        Self {
            me,
            backstage,
            key,
            room,
            _slot: announced,
        }
    }

    /// The room as an honest caller sees it: encrypted, `peers` publishing
    /// beside this device and all of them opted in.
    fn view(&self, peers: &[&Self]) -> RoomView {
        let peers: BTreeSet<String> = peers.iter().map(|peer| peer.me.clone()).collect();
        RoomView {
            encrypted: true,
            publishing: true,
            backstage: self.backstage,
            watchdog: false,
            opted_in: peers.clone(),
            peers,
            members: None,
            audience: 0,
            secret: Some(SECRET.to_vec()),
        }
    }

    fn sees(&self, peers: &[&Self]) {
        self.room.update(self.view(peers));
    }

    fn media(&self) -> FullTrackName {
        FullTrackName::new(slot(&self.me, self.backstage), Bytes::from_static(b"video"))
            .expect("a valid track name")
    }

    fn credentials(&self, token: Vec<u8>) -> RoomCredentials {
        RoomCredentials {
            token,
            key: Some(Arc::clone(&self.key)),
        }
    }

    fn state(&self, peer: &Self) -> Option<PathState> {
        self.room.paths().borrow().get(&peer.me).cloned()
    }

    async fn until(&self, peer: &Self, what: &str, wanted: impl Fn(Option<&PathState>) -> bool) {
        let mut paths = self.room.paths();
        let waiting = async {
            loop {
                if wanted(paths.borrow_and_update().get(&peer.me)) {
                    return;
                }
                paths.changed().await.expect("the room is running");
            }
        };
        assert!(
            tokio::time::timeout(PATIENCE, waiting).await.is_ok(),
            "timed out waiting for {what}: {} sees {} as {:?}",
            self.me,
            peer.me,
            self.state(peer)
        );
    }

    async fn until_direct(&self, peer: &Self) {
        self.until(peer, "a direct path", |state| {
            state == Some(&PathState::Direct)
        })
        .await;
    }
}

/// Publish a group every 20 ms until dropped.
fn stream(publication: RoomPublication) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        for group in 0u64.. {
            let payload = group.to_be_bytes();
            let _ = publication
                .publish_objects(group, &[OutgoingObject::new(&payload)])
                .await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
}

async fn read(watching: &mut RoomSubscription) -> Path {
    within("an object", watching.next())
        .await
        .expect("reads")
        .expect("an object")
        .path
}

/// The whole of it for one pair: both opt in, asking the grant's STUN server,
/// meet directly, read each other there while the relay holds its copy, and
/// return to the relay, resumed, when the path ends.
#[tokio::test(flavor = "multi_thread")]
async fn a_pair_goes_direct_pauses_the_relay_and_falls_back() {
    let relay = Relay::start();
    let ada = Member::join(&relay, "ada", false, DirectPolicy::AUTOMATIC, relay.grant()).await;
    let bob = Member::join(&relay, "bob", false, DirectPolicy::AUTOMATIC, relay.grant()).await;
    assert!(ada.room.opted_in() && bob.room.opted_in());

    let publisher = stream(ada.room.publish(ada.media()).expect("publishes"));
    let mut watching = within("subscribing", bob.room.subscribe(&ada.me, ada.media()))
        .await
        .expect("bob reads ada over the relay");
    assert_eq!(read(&mut watching).await, Path::Relay);

    ada.sees(&[&bob]);
    bob.sees(&[&ada]);
    ada.until_direct(&bob).await;
    bob.until_direct(&ada).await;
    assert!(
        relay.stun_answered() >= 2,
        "each side asks the STUN server its grant names"
    );

    within("the direct path with the relay paused", async {
        while !(read(&mut watching).await == Path::Direct && watching.relay_paused()) {}
    })
    .await;
    let paused_at = watching.relay_objects();
    for _ in 0..50 {
        assert_eq!(read(&mut watching).await, Path::Direct);
    }
    let while_paused = watching.relay_objects() - paused_at;
    assert!(
        while_paused <= 3,
        "the relay sent {while_paused} objects while paused"
    );
    // A second of reads is past the ticket grace, so each side has been
    // holding the other to tickets its relay issued.
    assert_eq!(ada.state(&bob), Some(PathState::Direct));
    assert_eq!(bob.state(&ada), Some(PathState::Direct));

    // Ada's room ends; her relay publication goes on.
    ada.room.close().await;
    bob.until(&ada, "bob to lose the direct path", |state| {
        state != Some(&PathState::Direct)
    })
    .await;
    within("the relay again, resumed", async {
        while read(&mut watching).await != Path::Relay || watching.relay_paused() {}
    })
    .await;
    let resumed_at = watching.relay_objects();
    for _ in 0..10 {
        assert_eq!(read(&mut watching).await, Path::Relay);
    }
    assert!(watching.relay_objects() - resumed_at >= 10);
    publisher.abort();
}

/// A relay that will not meter a direct path issues no tickets for one, and a
/// path it cannot meter is not kept.
#[tokio::test(flavor = "multi_thread")]
async fn no_tickets_no_direct_path() {
    let relay = Relay::issuing(false);
    let ada = Member::join(&relay, "ada", false, DirectPolicy::AUTOMATIC, relay.grant()).await;
    let bob = Member::join(&relay, "bob", false, DirectPolicy::AUTOMATIC, relay.grant()).await;
    ada.sees(&[&bob]);
    bob.sees(&[&ada]);
    for (member, peer) in [(&ada, &bob), (&bob, &ada)] {
        member
            .until(peer, "the relay to refuse tickets", |state| {
                state == Some(&PathState::Relay(Fallback::TicketsUnavailable))
            })
            .await;
    }
}

/// `RelayOnly` keeps this device off, whatever its caller believes about the
/// room: it publishes no offer, asks no STUN server, and so neither does a
/// peer that counts it honestly.
#[tokio::test(flavor = "multi_thread")]
async fn relay_only_never_offers_an_address() {
    let relay = Relay::start();
    let ada = Member::join(&relay, "ada", false, DirectPolicy::RelayOnly, relay.grant()).await;
    let bob = Member::join(&relay, "bob", false, DirectPolicy::AUTOMATIC, relay.grant()).await;
    assert!(!ada.room.opted_in(), "the catalog says ada is not in");
    assert!(bob.room.opted_in());

    // Ada's caller says everyone is in; Bob's reads Ada's catalog.
    ada.sees(&[&bob]);
    bob.room.update(RoomView {
        opted_in: BTreeSet::new(),
        ..bob.view(&[&ada])
    });
    ada.until(&bob, "ada to stay on the relay", |state| {
        state == Some(&PathState::Relay(Fallback::Off))
    })
    .await;
    bob.until(&ada, "bob to see ada is not in", |state| {
        state
            == Some(&PathState::Relay(Fallback::Ineligible(
                Ineligible::NotEveryoneOptedIn,
            )))
    })
    .await;

    // Anybody in the room can read Ada's offers track. There is nothing on it.
    let (key, _) = DeviceKey::generate().expect("a device key");
    let mut cat = relay.connect(&token("cat", &key, false), &key).await;
    let offers = FullTrackName::new(
        slot(&ada.me, false),
        Bytes::from_static(OFFERS_TRACK.as_bytes()),
    )
    .expect("a valid track name");
    if let Ok(mut reading) = within("subscribing", cat.subscribe(offers)).await {
        let next = tokio::time::timeout(Duration::from_millis(2500), reading.next_object()).await;
        assert!(!matches!(next, Ok(Ok(Some(_)))), "ada offered an address");
    }
    assert_eq!(relay.stun_answered(), 0, "no STUN server was asked");
}

/// Backstage meets backstage and the stage meets the stage, because offers
/// travel on the slot each participant is in. A caller that pairs across the
/// two gets no path rather than a wrong one.
#[tokio::test(flavor = "multi_thread")]
async fn backstage_pairs_only_with_backstage() {
    let relay = Relay::start();
    let grant = relay.grant();
    let ada = Member::join(&relay, "ada", true, DirectPolicy::AUTOMATIC, grant.clone()).await;
    let bob = Member::join(&relay, "bob", true, DirectPolicy::AUTOMATIC, grant.clone()).await;
    let cat = Member::join(&relay, "cat", false, DirectPolicy::AUTOMATIC, grant.clone()).await;
    let dan = Member::join(&relay, "dan", false, DirectPolicy::AUTOMATIC, grant).await;

    ada.sees(&[&bob]);
    bob.sees(&[&ada]);
    // Cat's caller has Ada beside her on stage, which she is not.
    cat.sees(&[&dan, &ada]);
    dan.sees(&[&cat]);

    ada.until_direct(&bob).await;
    bob.until_direct(&ada).await;
    cat.until_direct(&dan).await;
    dan.until_direct(&cat).await;

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(cat.state(&ada), Some(PathState::Connecting));
    assert_eq!(ada.state(&bob), Some(PathState::Direct));
    assert_eq!(cat.state(&dan), Some(PathState::Direct));
}

/// A renewed token's grant applies at once: a lower limit or a refusal ends
/// the path, and the grant restored brings it back.
#[tokio::test(flavor = "multi_thread")]
async fn a_renewed_grant_takes_effect_mid_room() {
    let relay = Relay::start();
    let ada = Member::join(&relay, "ada", false, DirectPolicy::AUTOMATIC, relay.grant()).await;
    let bob = Member::join(&relay, "bob", false, DirectPolicy::AUTOMATIC, relay.grant()).await;

    // Three hold the room's key, though only two publish.
    let members: BTreeSet<String> = [ada.me.clone(), bob.me.clone(), "eve/0000".to_owned()].into();
    for (member, peer) in [(&ada, &bob), (&bob, &ada)] {
        let view = member.view(&[peer]);
        member.room.update(RoomView {
            opted_in: members
                .iter()
                .filter(|m| **m != member.me)
                .cloned()
                .collect(),
            members: Some(members.clone()),
            ..view
        });
    }
    ada.until_direct(&bob).await;
    bob.until_direct(&ada).await;

    let renewed = token("ada", &ada.key, false);
    ada.room.renew(
        ada.credentials(renewed.clone()),
        RoomDirectPolicy {
            max_participants: 2,
            ..relay.grant()
        },
    );
    ada.until(&bob, "the lower limit to apply", |state| {
        state
            == Some(&PathState::Relay(Fallback::Ineligible(
                Ineligible::TooManyParticipants(3),
            )))
    })
    .await;
    bob.until(&ada, "bob to lose the path", |state| {
        state != Some(&PathState::Direct)
    })
    .await;
    assert!(ada.room.opted_in(), "a limit is not a refusal");

    ada.room.renew(
        ada.credentials(renewed.clone()),
        RoomDirectPolicy {
            allowed: false,
            ..relay.grant()
        },
    );
    ada.until(&bob, "the refusal to apply", |state| {
        state == Some(&PathState::Relay(Fallback::Off))
    })
    .await;
    assert!(!ada.room.opted_in());

    ada.room.renew(ada.credentials(renewed), relay.grant());
    within("opting in again", async {
        while !ada.room.opted_in() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    ada.until_direct(&bob).await;
    bob.until_direct(&ada).await;
}
