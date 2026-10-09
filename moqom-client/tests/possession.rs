//! A session proving possession of its token, against a relay that demands it.
//!
//! The device key and the proof it signs are only worth anything if the relay's own
//! verifier accepts them, and nothing inside this crate can establish that: a proof
//! checked by code written alongside it shows that the two agree with each other
//! and not that either is right. So the relay here is the real one, configured the
//! way the development deployment is, and the token is minted the way the Go
//! control plane mints one.
//!
//! What that catches is the class of mistake this is most exposed to. Every field
//! of the proof is a hash or a canonical encoding, so getting one wrong -- a
//! reordered JWK member, a padded coordinate, a DER signature where a fixed-width
//! one belongs, a hash over the token file including its trailing newline --
//! produces something perfectly well-formed that verifies against nothing.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use moqom_client::{Credentials, DeviceKey, Session};
use moqom_relay::possession::{Enforcement, Possession};
use moqom_relay::{Authenticator, Cache, Fabric, Limits, Session as RelaySession};
use moqom_token::{Claims, Confirmation, Grant, Signer};
use moqom_transport::{Server, server::with_moqt_alpn};

const PATIENCE: Duration = Duration::from_secs(10);
const KEY_ID: &str = "test-key";

/// A relay that verifies tokens and requires a proof for each.
struct Relay {
    addr: SocketAddr,
    certificate: rustls::pki_types::CertificateDer<'static>,
    accept: tokio::task::JoinHandle<()>,
}

impl Relay {
    fn requiring_proofs() -> Self {
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

        // The relay identifies itself by the hash of the certificate it serves,
        // and the client computes the same thing from the handshake. Both sides
        // deriving it rather than sharing a constant is the point: a mismatch here
        // is exactly the bug this test is for.
        let identity = URL_SAFE_NO_PAD.encode(
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, certificate.as_ref()).as_ref(),
        );

        // An empty issuer accepts any, which is what the relay's own harness does.
        let authenticator = Authenticator::new("", vec![signer().public_key()]);
        let fabric = Fabric::with_cache(Cache::new(Limits::default()))
            .authenticated(authenticator)
            .proving(Possession::new(Enforcement::Required, Some(identity)));

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

/// The issuing key. A fixed seed, because what varies between these tests is the
/// device key and not the issuer.
fn signer() -> Signer {
    Signer::from_seed(&[7u8; 32])
        .expect("a valid ML-DSA-87 seed")
        .with_id(KEY_ID)
}

/// A token committed to `thumbprint`, shaped the way the control plane mints one.
fn token_bound_to(thumbprint: &str) -> Vec<u8> {
    token_bound_to_lasting(thumbprint, 600)
}

/// A token for `thumbprint` that expires `seconds` from now. A negative value
/// mints one, issued two seconds before that, that is already inside the clock
/// skew a relay forgives, which is how a test gets one that lapses within
/// seconds.
fn token_bound_to_lasting(thumbprint: &str, seconds: i64) -> Vec<u8> {
    let issued = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs()
        .cast_signed();
    signer()
        .sign(&Claims {
            iss: "https://api.moqom.cloud".to_owned(),
            sub: "ada".to_owned(),
            tenant: "acme".to_owned(),
            iat: if seconds > 0 {
                issued
            } else {
                issued + seconds - 2
            },
            exp: issued + seconds,
            cnf: Confirmation {
                jkt: thumbprint.to_owned(),
            },
            grant: Grant {
                room: "room-42".to_owned(),
                publish: 3,
                ..Grant::default()
            },
            ..Claims::default()
        })
        .expect("a complete token")
        .into_bytes()
}

async fn within<F: Future>(what: &str, future: F) -> F::Output {
    tokio::time::timeout(PATIENCE, future)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}

/// The claim the whole mechanism rests on: a proof this crate signs is one the
/// relay accepts. Every hash and every canonical encoding in it has to be right
/// for this to pass, and any one of them being wrong looks identical from here.
#[tokio::test]
async fn a_session_that_proves_its_token_is_admitted() {
    let relay = Relay::requiring_proofs();
    let tls = moqom_client::tls::pinned(relay.certificate.clone());

    let (key, _) = DeviceKey::generate().expect("a device key");
    let token = token_bound_to(&key.thumbprint());

    within(
        "connect with a proof",
        Session::connect(
            relay.addr,
            "localhost",
            tls,
            Some(&Credentials::proven(&token, &key)),
        ),
    )
    .await
    .expect("a proven session is admitted");
}

/// The reason proofs exist. The token is valid, it names a real device, and it is
/// refused because whoever presented it cannot show they are that device -- which
/// is what a token lifted off a machine looks like.
#[tokio::test]
async fn a_token_without_its_key_is_refused() {
    let relay = Relay::requiring_proofs();
    let tls = moqom_client::tls::pinned(relay.certificate.clone());

    let (key, _) = DeviceKey::generate().expect("a device key");
    let token = token_bound_to(&key.thumbprint());

    let Err(refused) = within(
        "connect without a proof",
        Session::connect(
            relay.addr,
            "localhost",
            tls,
            Some(&Credentials::bearer(&token)),
        ),
    )
    .await
    else {
        panic!("a relay requiring proofs admitted a bearer token");
    };

    // The reason and not merely the failure. A refusal reported as "the peer closed
    // the stream" leaves somebody holding a valid token with nothing to act on, and
    // the several ways this can fail all arrive as one error code.
    assert!(
        matches!(&refused, moqom_client::Error::Rejected { reason, .. } if !reason.is_empty()),
        "expected the relay's own reason, got {refused}"
    );
}

/// A proof from the wrong key is worse than none: it is what an attacker who has
/// the token and a key pair of their own can produce, and it must not be mistaken
/// for the device the token names.
#[tokio::test]
async fn a_proof_from_another_key_is_refused() {
    let relay = Relay::requiring_proofs();
    let tls = moqom_client::tls::pinned(relay.certificate.clone());

    let (named, _) = DeviceKey::generate().expect("the device the token names");
    let (attacker, _) = DeviceKey::generate().expect("a key of their own");
    let token = token_bound_to(&named.thumbprint());

    let Err(refused) = within(
        "connect with the wrong key",
        Session::connect(
            relay.addr,
            "localhost",
            tls,
            Some(&Credentials::proven(&token, &attacker)),
        ),
    )
    .await
    else {
        panic!("a proof from a key the token does not name was accepted");
    };
    assert!(
        matches!(&refused, moqom_client::Error::Rejected { reason, .. } if !reason.is_empty()),
        "expected the relay's own reason, got {refused}"
    );
}

/// Each connection signs a fresh proof, so two sessions from one token both work.
///
/// Worth asserting because the relay remembers every proof identifier until the
/// token expires and refuses a repeat. A client that reused a proof -- by caching
/// it, or by deriving the identifier from anything stable -- would work exactly
/// once per token and then appear to have a broken credential.
#[tokio::test]
async fn one_token_admits_two_sessions() {
    let relay = Relay::requiring_proofs();
    let tls = moqom_client::tls::pinned(relay.certificate.clone());

    let (key, _) = DeviceKey::generate().expect("a device key");
    let token = token_bound_to(&key.thumbprint());

    let first = within(
        "the first session",
        Session::connect(
            relay.addr,
            "localhost",
            tls.clone(),
            Some(&Credentials::proven(&token, &key)),
        ),
    )
    .await
    .expect("the first session is admitted");
    let second = within(
        "the second session",
        Session::connect(
            relay.addr,
            "localhost",
            tls,
            Some(&Credentials::proven(&token, &key)),
        ),
    )
    .await
    .expect("the second session is admitted with a fresh proof");

    drop((first, second));
}

/// A publisher renews on its announcement and its session outlives the token it
/// opened with. A subscription renews the same way, through the same code.
#[tokio::test]
async fn a_renewal_on_an_announcement_outlives_the_first_token() {
    let relay = Relay::requiring_proofs();
    let tls = moqom_client::tls::pinned(relay.certificate.clone());
    let (key, _) = DeviceKey::generate().expect("a device key");
    let thumbprint = key.thumbprint();

    let lapsing = token_bound_to_lasting(&thumbprint, -28);
    let mut session = within(
        "connect with a token about to lapse",
        Session::connect(
            relay.addr,
            "localhost",
            tls,
            Some(&Credentials::proven(&lapsing, &key)),
        ),
    )
    .await
    .expect("admitted inside the clock skew");

    let device = &thumbprint[..16];
    let mut announcement = within(
        "announce",
        session.announce(
            moqom_client::TrackNamespace::from_parts(["acme", "r", "room-42", "ada", device])
                .expect("a valid namespace"),
        ),
    )
    .await
    .expect("the relay accepts the announcement");

    let fresh = token_bound_to(&thumbprint);
    within(
        "renew",
        announcement.renew(&Credentials::proven(&fresh, &key)),
    )
    .await
    .expect("the renewal is written");

    tokio::time::sleep(Duration::from_secs(4)).await;
    within(
        "watch the room after the first token lapsed",
        session.watch(
            moqom_client::TrackNamespace::from_parts(["acme", "r", "room-42"])
                .expect("a valid namespace"),
        ),
    )
    .await
    .expect("the session outlived the token it opened with");
}
