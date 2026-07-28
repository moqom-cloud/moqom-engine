//! What happens to a connection nobody is speaking on.
//!
//! Shortening the idle timeout is only safe because a keep-alive holds quiet
//! connections open, and that is a claim about two settings interacting rather
//! than about either one. So both tests here run the same silence against the
//! same timeout, and differ only in whether the keep-alive is configured — the
//! first proves the connection survives, the second proves it would not have.
//!
//! Without the second, the first would pass just as happily if the timeout were
//! never applied at all.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use moqom_transport::{Liveness, Server, alpn};

/// Short enough to run in a test, in the same proportion as the real pair:
/// several keep-alives inside one timeout.
const IDLE: Duration = Duration::from_millis(400);
const KEEP_ALIVE: Duration = Duration::from_millis(100);

/// Three idle timeouts of doing nothing whatsoever.
const SILENCE: Duration = Duration::from_millis(1_200);

fn self_signed() -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key = rustls::pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
    (der, key)
}

fn server_tls(
    cert: rustls::pki_types::CertificateDer<'static>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> rustls::ServerConfig {
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .unwrap();

    moqom_transport::server::with_moqt_alpn(tls)
}

fn client_config(cert: &rustls::pki_types::CertificateDer<'static>) -> quinn::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();

    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![alpn::MOQT_DRAFT_19.to_vec()];

    // Left on quinn's default idle timeout, deliberately. The effective value
    // is the lower of the two advertised (RFC 9000 §10.1), so the server's is
    // what applies to both -- which is the property being relied on, and worth
    // exercising rather than papering over by configuring the client to match.
    quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    ))
}

/// A server whose liveness settings are chosen by the caller.
fn bare_server(
    tls: rustls::ServerConfig,
    liveness: Option<Liveness>,
) -> (Server, SocketAddr, quinn::Endpoint) {
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));

    let mut transport = quinn::TransportConfig::default();
    if let Some(liveness) = liveness {
        liveness.apply(&mut transport).unwrap();
    } else {
        // The control case: the same short timeout, and nothing to hold the
        // connection open through it.
        transport.max_idle_timeout(Some(quinn::IdleTimeout::try_from(IDLE).unwrap()));
        transport.keep_alive_interval(None);
    }
    config.transport_config(Arc::new(transport));

    let endpoint =
        quinn::Endpoint::server(config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let addr = endpoint.local_addr().unwrap();
    (Server::new(endpoint.clone()), addr, endpoint)
}

/// Connect, say nothing for [`SILENCE`], and report why the connection ended —
/// `None` if it is still up.
async fn outcome_after_silence(liveness: Option<Liveness>) -> Option<quinn::ConnectionError> {
    let (cert, key) = self_signed();
    let (server, addr, _endpoint) = bare_server(server_tls(cert.clone(), key), liveness);

    // Holds the accepted session for the duration. Dropping it would close the
    // connection from this side and the test would be measuring its own
    // teardown rather than the timeout.
    let serving = tokio::spawn(async move {
        let accepting = server.accept().await.expect("a connection");
        let (session, _) = accepting.establish().await.expect("a handshake");
        tokio::time::sleep(SILENCE * 2).await;
        drop(session);
    });

    let endpoint = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let conn = endpoint
        .connect_with(client_config(&cert), addr, "localhost")
        .unwrap()
        .await
        .expect("the handshake completes");

    // No reads, no writes, no streams. The only packets that can flow now are
    // the ones the transport decides to send on its own.
    tokio::time::sleep(SILENCE).await;

    let reason = conn.close_reason();
    conn.close(0u32.into(), b"done");
    serving.abort();
    reason
}

#[tokio::test]
async fn a_quiet_connection_is_kept_alive() {
    let reason = outcome_after_silence(Some(Liveness::new(IDLE, KEEP_ALIVE).unwrap())).await;

    assert!(
        reason.is_none(),
        "a silent connection should survive on keep-alives alone, but ended: {reason:?}"
    );
}

#[tokio::test]
async fn without_a_keep_alive_the_same_silence_ends_it() {
    let reason = outcome_after_silence(None).await;

    assert!(
        matches!(reason, Some(quinn::ConnectionError::TimedOut)),
        "the same silence without a keep-alive should time out, but got: {reason:?}"
    );
}

/// The setting the relay actually ships with, held to the rule that the
/// keep-alive has to fit several times over inside the timeout.
#[test]
fn the_shipped_pair_leaves_room_for_loss() {
    let Liveness {
        idle_timeout,
        keep_alive,
    } = Liveness::DEFAULT;

    let chances = idle_timeout.as_millis() / keep_alive.as_millis();
    assert!(
        chances >= 3,
        "only {chances} keep-alive(s) fit inside the idle timeout, so a lost \
         packet or two would disconnect a healthy peer"
    );
}
