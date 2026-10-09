//! The key exchanges a relay's device listener and its links agree on, over a
//! real handshake.
//!
//! The providers' group lists are checked in the crate. This is the claim they
//! exist for: a link negotiates ML-KEM-1024, an Apple device's hybrid share is
//! still admitted, and a peer with only classical groups gets no session.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use moqom_transport::key_exchange::{device_provider, link_provider};
use moqom_transport::{Server, alpn};
use quinn::crypto::rustls::HandshakeData;
use rustls::NamedGroup;
use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{default_provider, kx_group};

fn listener() -> (Server, rustls::pki_types::CertificateDer<'static>) {
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key = rustls::pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(device_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .unwrap();
    let server = Server::bind(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        moqom_transport::server::with_moqt_alpn(tls),
    )
    .unwrap();
    (server, der)
}

/// Connect with `provider` and return the group the handshake settled on, or
/// `None` if there was no handshake.
async fn negotiate(provider: CryptoProvider) -> Option<NamedGroup> {
    let (server, certificate) = listener();
    let addr = server.local_addr().unwrap();
    let accepting = tokio::spawn(async move {
        if let Some(incoming) = server.accept().await {
            let _ = incoming.establish().await;
        }
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![alpn::MOQT_DRAFT_19.to_vec()];
    let mut endpoint = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    )));

    let connected = endpoint.connect(addr, "localhost").unwrap().await;
    accepting.abort();
    let connection = connected.ok()?;
    let group = connection
        .handshake_data()?
        .downcast::<HandshakeData>()
        .ok()?
        .negotiated_key_exchange_group;
    Some(group)
}

fn only(groups: &[&'static dyn rustls::crypto::SupportedKxGroup]) -> CryptoProvider {
    CryptoProvider {
        kx_groups: groups.to_vec(),
        ..default_provider()
    }
}

#[tokio::test]
async fn a_relay_link_negotiates_ml_kem_1024() {
    assert_eq!(
        negotiate(link_provider()).await,
        Some(NamedGroup::MLKEM1024)
    );
}

/// What an iPhone offers: the hybrid first, with classical fallbacks the relay
/// must not take.
#[tokio::test]
async fn an_apple_device_is_admitted_on_the_hybrid() {
    let apple = only(&[
        kx_group::X25519MLKEM768,
        kx_group::X25519,
        kx_group::SECP256R1,
    ]);
    assert_eq!(negotiate(apple).await, Some(NamedGroup::X25519MLKEM768));
}

/// The listener takes the group of the share a device sent when it accepts that
/// group, rather than spending a round trip to ask for its own first choice; a
/// device that leads with ML-KEM-1024 gets it, and one that sent no share the
/// listener accepts is asked for ML-KEM-1024.
#[tokio::test]
async fn a_device_leading_with_ml_kem_1024_gets_it() {
    let both = only(&[kx_group::MLKEM1024, kx_group::X25519MLKEM768]);
    assert_eq!(negotiate(both).await, Some(NamedGroup::MLKEM1024));
    let late = only(&[
        kx_group::X25519,
        kx_group::MLKEM1024,
        kx_group::X25519MLKEM768,
    ]);
    assert_eq!(negotiate(late).await, Some(NamedGroup::MLKEM1024));
}

#[tokio::test]
async fn a_classical_only_peer_is_refused() {
    for groups in [
        &[kx_group::X25519][..],
        &[kx_group::SECP256R1],
        &[kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1],
    ] {
        assert_eq!(negotiate(only(groups)).await, None);
    }
}
