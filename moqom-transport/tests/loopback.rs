//! Both carriers, one port, over a real socket.
//!
//! Everything else in this crate is a claim about how QUIC and WebTransport
//! converge. This is the test that makes the claim falsifiable: two clients
//! that connect in genuinely different ways, reaching one listener, and the
//! server code handling them identically once the handshake is done.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use moqom_transport::{Carrier, Dialect, Server, alpn};
use web_transport_quinn::Session;
use web_transport_quinn::proto::{ConnectRequest, ConnectResponse};

/// A certificate for `localhost`, valid only for this process.
fn self_signed() -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    // The IP SAN matters: web-transport resolves the URL's host itself, and
    // "localhost" resolves to ::1 while these tests bind IPv4. Connecting by
    // address sidesteps the mismatch, and needs the certificate to cover it.
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

/// A client that trusts only the certificate we just generated, and offers only
/// the ALPN under test. Restricting the offer is what makes each test actually
/// exercise the carrier it names rather than whichever the server prefers.
fn client_config(
    cert: &rustls::pki_types::CertificateDer<'static>,
    alpn: &[u8],
) -> quinn::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();

    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![alpn.to_vec()];

    quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    ))
}

fn client_endpoint() -> quinn::Endpoint {
    quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap()
}

/// Write on a bidirectional stream and read the echo, which is the smallest
/// exchange that proves streams work in both directions.
async fn round_trip(session: &Session, payload: &[u8]) -> Vec<u8> {
    let (mut send, mut recv) = session.open_bi().await.unwrap();
    send.write_all(payload).await.unwrap();
    send.finish().unwrap();
    recv.read_to_end(64 * 1024).await.unwrap()
}

/// Accept one session and echo one stream, then report what was negotiated.
async fn serve_one(server: Server) -> moqom_transport::Negotiated {
    let accepting = server.accept().await.expect("a connection");
    let (session, negotiated) = accepting.establish().await.unwrap();

    let (mut send, mut recv) = session.accept_bi().await.unwrap();
    let received = recv.read_to_end(64 * 1024).await.unwrap();
    send.write_all(&received).await.unwrap();
    send.finish().unwrap();

    // Without this the process can exit before the FIN is flushed, and the
    // client sees a reset instead of the echo. Not a protocol subtlety, just
    // the usual one about closing a QUIC connection too eagerly.
    session.closed().await;
    negotiated
}

#[tokio::test]
async fn raw_quic_reaches_the_same_session_type() {
    let (cert, key) = self_signed();
    let server = Server::bind(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        server_tls(cert.clone(), key),
    )
    .unwrap();
    let addr = server.local_addr().unwrap();

    let serving = tokio::spawn(serve_one(server));

    let endpoint = client_endpoint();
    let conn = endpoint
        .connect_with(client_config(&cert, alpn::MOQT_DRAFT_19), addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    // The client wraps its raw connection the same way the server does, so both
    // ends agree there is no session ID and neither writes a stream preamble.
    let session = Session::raw(
        conn,
        ConnectRequest::new(url::Url::parse("https://localhost/").unwrap()),
        ConnectResponse::OK,
    );

    assert_eq!(
        round_trip(&session, b"hello over quic").await,
        b"hello over quic"
    );
    session.close(0, b"done");

    let negotiated = serving.await.unwrap();
    assert_eq!(negotiated.carrier, Carrier::Quic);
    assert_eq!(negotiated.dialect, Some(Dialect::Draft19));
}

#[tokio::test]
async fn webtransport_reaches_the_same_session_type() {
    let (cert, key) = self_signed();
    let server = Server::bind(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        server_tls(cert.clone(), key),
    )
    .unwrap();
    let addr = server.local_addr().unwrap();

    let serving = tokio::spawn(serve_one(server));

    let client =
        web_transport_quinn::Client::new(client_endpoint(), client_config(&cert, alpn::H3));

    let url = url::Url::parse(&format!("https://127.0.0.1:{}/live", addr.port())).unwrap();
    let session = client.connect(url).await.unwrap();

    assert_eq!(
        round_trip(&session, b"hello over webtransport").await,
        b"hello over webtransport"
    );
    session.close(0, b"done");

    let negotiated = serving.await.unwrap();
    assert_eq!(negotiated.carrier, Carrier::WebTransport);
    // The dialect is not in the ALPN here; it arrives in WT-Available-Protocols
    // and is resolved a layer up.
    assert_eq!(negotiated.dialect, None);
}

/// A peer offering something we do not serve must fail at the handshake rather
/// than connecting and then finding no session. With version negotiation gone
/// from SETUP, this is the only place a mismatch can be caught.
#[tokio::test]
async fn an_unoffered_alpn_never_connects() {
    let (cert, key) = self_signed();
    let server = Server::bind(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        server_tls(cert.clone(), key),
    )
    .unwrap();
    let addr = server.local_addr().unwrap();

    // Keep accepting so the failure is the handshake's, not a closed listener's.
    tokio::spawn(async move { while server.accept().await.is_some() {} });

    let endpoint = client_endpoint();
    let result = endpoint
        .connect_with(client_config(&cert, b"moq-00"), addr, "localhost")
        .unwrap()
        .await;

    assert!(result.is_err(), "the retired ALPN must not connect");
}

/// A relay bound to `[::]` behind a dual-stack load balancer must still answer
/// IPv4 clients, as mapped addresses, on the same socket.
#[tokio::test]
async fn a_dual_stack_wildcard_answers_ipv4_clients() {
    let (cert, key) = self_signed();
    let server = Server::bind(
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        server_tls(cert.clone(), key),
    )
    .unwrap();
    let port = server.local_addr().unwrap().port();

    let serving = tokio::spawn(serve_one(server));

    let endpoint = client_endpoint();
    let conn = endpoint
        .connect_with(
            client_config(&cert, alpn::MOQT_DRAFT_19),
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            "localhost",
        )
        .unwrap()
        .await
        .unwrap();
    let session = Session::raw(
        conn,
        ConnectRequest::new(url::Url::parse("https://localhost/").unwrap()),
        ConnectResponse::OK,
    );
    assert_eq!(round_trip(&session, b"over ipv4").await, b"over ipv4");
    session.close(0, b"done");

    assert_eq!(serving.await.unwrap().carrier, Carrier::Quic);
}
