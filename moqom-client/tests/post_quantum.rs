//! Which key exchange the engine's TLS configurations actually negotiate.
//!
//! Every handshake here is real: a relay listener built by `moqom-transport`
//! and a client config from `moqom_client::tls`, or two direct sockets. The
//! group is read from quinn's handshake data after the handshake, so what is
//! asserted is what the two ends agreed on rather than what a config lists.
//!
//! The classical cases are the other half of the guarantee. Preferring the
//! hybrid must never cost a connection to a peer that does not have it.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use moqom_client::direct::socket::{DirectSocket, SocketConfig};
use moqom_relay::{Cache, Fabric, Limits, Session as RelaySession};
use moqom_transport::{Server, alpn, server::with_moqt_alpn};
use quinn::crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig};
use rustls::NamedGroup;
use rustls::crypto::aws_lc_rs::{default_provider, kx_group};
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

const PATIENCE: Duration = Duration::from_secs(10);

fn install_provider() {
    let _ = default_provider().install_default();
}

fn certificate() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generating a certificate");
    let certificate = generated.cert.der().clone();
    let key = PrivateKeyDer::try_from(generated.signing_key.serialize_der())
        .expect("generated key is usable");
    (certificate, key)
}

/// The group quinn says this connection's handshake settled on.
fn negotiated(connection: &quinn::Connection) -> NamedGroup {
    connection
        .handshake_data()
        .expect("a completed handshake")
        .downcast::<HandshakeData>()
        .expect("rustls handshake data")
        .negotiated_key_exchange_group
}

/// aws-lc-rs with only `groups`: a peer built without the hybrid, or one
/// that never learned X25519.
fn provider_with(groups: &[&'static dyn SupportedKxGroup]) -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider {
        kx_groups: groups.to_vec(),
        ..default_provider()
    })
}

const CLASSICAL: &[&dyn SupportedKxGroup] =
    &[kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1];

/// A relay listener exactly as the relay builds one: `ServerConfig::builder`
/// on the installed provider, routed through `with_moqt_alpn` and
/// `Server::bind`, serving relay sessions.
struct Relay {
    addr: SocketAddr,
    certificate: CertificateDer<'static>,
    accept: tokio::task::JoinHandle<()>,
}

impl Relay {
    fn start() -> Self {
        install_provider();
        let (certificate, key) = certificate();
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
        let accept = tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                let fabric = fabric.clone();
                tokio::spawn(async move {
                    if let Ok((session, negotiated)) = incoming.establish().await {
                        let _ = RelaySession::serve(session, negotiated.carrier, fabric).await;
                    }
                });
            }
        });
        Self {
            addr,
            certificate,
            accept,
        }
    }

    /// Complete a QUIC handshake to the listener with `tls`, offering `alpn`.
    async fn handshake(&self, mut tls: rustls::ClientConfig, alpn: &[u8]) -> quinn::Connection {
        tls.alpn_protocols = vec![alpn.to_vec()];
        let crypto = QuicClientConfig::try_from(tls).expect("a TLS 1.3 configuration");
        let mut endpoint = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("binding a client socket");
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        tokio::time::timeout(PATIENCE, async {
            endpoint
                .connect(self.addr, "localhost")
                .expect("a connectable address")
                .await
                .expect("the relay accepts the handshake")
        })
        .await
        .expect("the handshake finishes in time")
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

/// A plain QUIC server whose provider has only `groups`, standing in for a
/// relay or service that predates the hybrid.
fn classical_server(
    groups: &[&'static dyn SupportedKxGroup],
) -> (quinn::Endpoint, CertificateDer<'static>) {
    let (certificate, key) = certificate();
    let mut tls = rustls::ServerConfig::builder_with_provider(provider_with(groups))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key)
        .expect("certificate and key agree");
    tls.alpn_protocols = vec![alpn::MOQT_DRAFT_22.to_vec(), alpn::MOQT_DRAFT_19.to_vec()];
    let crypto = QuicServerConfig::try_from(tls).expect("a QUIC server configuration");
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .expect("binding a loopback port");
    (endpoint, certificate)
}

/// Dial `server` with `tls` and return both ends' views of the connection.
async fn both_ends(
    server: &quinn::Endpoint,
    tls: rustls::ClientConfig,
) -> (quinn::Connection, quinn::Connection) {
    let crypto = QuicClientConfig::try_from(tls).expect("a TLS 1.3 configuration");
    let mut client = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("binding a client socket");
    client.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let addr = server.local_addr().expect("bound address");
    tokio::time::timeout(PATIENCE, async {
        let accepted = async {
            server
                .accept()
                .await
                .expect("an incoming connection")
                .await
                .expect("the server completes the handshake")
        };
        let dialled = async {
            client
                .connect(addr, "localhost")
                .expect("a connectable address")
                .await
                .expect("the client completes the handshake")
        };
        let (accepted, dialled) = tokio::join!(accepted, dialled);
        (dialled, accepted)
    })
    .await
    .expect("the handshake finishes in time")
}

#[tokio::test]
async fn a_client_and_the_relay_listener_negotiate_the_hybrid_over_raw_quic() {
    let relay = Relay::start();
    let connection = relay
        .handshake(
            moqom_client::tls::pinned(relay.certificate.clone()),
            alpn::MOQT_DRAFT_22,
        )
        .await;
    assert_eq!(negotiated(&connection), NamedGroup::X25519MLKEM768);
}

#[tokio::test]
async fn a_client_and_the_relay_listener_negotiate_the_hybrid_over_webtransport() {
    let relay = Relay::start();
    let connection = relay
        .handshake(
            moqom_client::tls::pinned(relay.certificate.clone()),
            alpn::H3,
        )
        .await;
    assert_eq!(negotiated(&connection), NamedGroup::X25519MLKEM768);
}

#[tokio::test]
async fn the_client_session_connects_to_the_relay_with_the_hybrid_preferred() {
    // The whole client path, not only its TLS config: SETUP has to complete
    // over a connection whose first flight carried the larger hybrid share.
    let relay = Relay::start();
    let session = tokio::time::timeout(
        PATIENCE,
        moqom_client::Session::connect(
            relay.addr,
            "localhost",
            moqom_client::tls::pinned(relay.certificate.clone()),
            None,
        ),
    )
    .await
    .expect("connects in time");
    assert!(session.is_ok(), "{:?}", session.err());
}

#[tokio::test]
async fn a_classical_only_client_still_reaches_the_relay_listener() {
    let relay = Relay::start();
    let tls = rustls::ClientConfig::builder_with_provider(provider_with(CLASSICAL))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_root_certificates({
            let mut roots = rustls::RootCertStore::empty();
            roots.add(relay.certificate.clone()).expect("a usable root");
            roots
        })
        .with_no_client_auth();
    let connection = relay.handshake(tls, alpn::MOQT_DRAFT_22).await;
    assert_eq!(negotiated(&connection), NamedGroup::X25519);
}

#[tokio::test]
async fn the_client_falls_back_to_x25519_for_a_classical_server() {
    install_provider();
    let (server, certificate) = classical_server(CLASSICAL);
    let (client, accepted) = both_ends(&server, moqom_client::tls::pinned(certificate)).await;
    assert_eq!(negotiated(&client), NamedGroup::X25519);
    assert_eq!(negotiated(&accepted), NamedGroup::X25519);
}

#[tokio::test]
async fn the_client_retries_for_a_server_with_neither_share_it_sent() {
    // The client's first flight carries the hybrid share and its X25519 half.
    // A server with only P-256 has to ask again with a HelloRetryRequest.
    install_provider();
    let (server, certificate) = classical_server(&[kx_group::SECP256R1]);
    let (client, accepted) = both_ends(&server, moqom_client::tls::pinned(certificate)).await;
    assert_eq!(negotiated(&client), NamedGroup::secp256r1);
    assert_eq!(negotiated(&accepted), NamedGroup::secp256r1);
}

/// Drive a client and server `rustls` connection to completion in memory.
///
/// QUIC hides the handshake's shape from quinn's caller; plain TLS over the
/// same configs shows whether it needed a HelloRetryRequest.
fn handshake_in_memory(
    client: rustls::ClientConfig,
    server: rustls::ServerConfig,
) -> (rustls::ClientConnection, rustls::ServerConnection) {
    let mut client = rustls::ClientConnection::new(
        Arc::new(client),
        "localhost".try_into().expect("a server name"),
    )
    .expect("a client connection");
    let mut server = rustls::ServerConnection::new(Arc::new(server)).expect("a server connection");
    for _ in 0..16 {
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
        let mut buffer = Vec::new();
        client.write_tls(&mut buffer).expect("client writes");
        server
            .read_tls(&mut buffer.as_slice())
            .expect("server reads");
        server.process_new_packets().expect("server accepts");
        let mut buffer = Vec::new();
        server.write_tls(&mut buffer).expect("server writes");
        client
            .read_tls(&mut buffer.as_slice())
            .expect("client reads");
        client.process_new_packets().expect("client accepts");
    }
    assert!(!client.is_handshaking() && !server.is_handshaking());
    (client, server)
}

fn in_memory_server(
    groups: &[&'static dyn SupportedKxGroup],
    certificate: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> rustls::ServerConfig {
    rustls::ServerConfig::builder_with_provider(provider_with(groups))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .expect("certificate and key agree")
}

#[test]
fn only_a_server_without_x25519_costs_a_round_trip() {
    install_provider();
    let cases = [
        (
            default_provider().kx_groups,
            NamedGroup::X25519MLKEM768,
            rustls::HandshakeKind::Full,
        ),
        (
            CLASSICAL.to_vec(),
            NamedGroup::X25519,
            rustls::HandshakeKind::Full,
        ),
        (
            vec![kx_group::SECP256R1],
            NamedGroup::secp256r1,
            rustls::HandshakeKind::FullWithHelloRetryRequest,
        ),
    ];
    for (groups, group, kind) in cases {
        let (certificate, key) = certificate();
        let mut client = moqom_client::tls::pinned(certificate.clone());
        client.alpn_protocols.clear();
        let (client, server) =
            handshake_in_memory(client, in_memory_server(&groups, certificate, key));
        assert_eq!(
            client.negotiated_key_exchange_group().map(|g| g.name()),
            Some(group)
        );
        assert_eq!(
            server.negotiated_key_exchange_group().map(|g| g.name()),
            Some(group)
        );
        assert_eq!(client.handshake_kind(), Some(kind), "{group:?}");
    }
}

async fn direct_pair() -> (DirectSocket, DirectSocket) {
    install_provider();
    let mut config = SocketConfig::new(alpn::MOQT_DRAFT_19);
    config.bind = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let ada = DirectSocket::bind(config.clone()).await.expect("ada binds");
    let bob = DirectSocket::bind(config).await.expect("bob binds");
    (ada, bob)
}

#[tokio::test]
async fn both_ends_of_a_direct_path_negotiate_the_hybrid() {
    let (ada, bob) = direct_pair().await;
    let target = [bob.local_addr().expect("bob's address")];
    let (dialled, accepted) = tokio::join!(
        ada.dial(&target, bob.fingerprint(), PATIENCE),
        bob.accept(ada.fingerprint(), PATIENCE),
    );
    let dialled = dialled.expect("ada reaches bob");
    let accepted = accepted.expect("bob admits ada");
    assert_eq!(negotiated(&dialled), NamedGroup::X25519MLKEM768);
    assert_eq!(negotiated(&accepted), NamedGroup::X25519MLKEM768);
}
