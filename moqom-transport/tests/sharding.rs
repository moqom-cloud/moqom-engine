//! Several sockets on one port, which is how a relay uses more than one core.
//!
//! The measurement this exists for is on Linux, where `SO_REUSEPORT` spreads
//! arriving connections across the sharing sockets. These tests do not assert
//! that spreading -- on the BSDs, macOS included, the option permits the bind
//! without distributing across it, and a test that demanded a particular shard
//! answer would fail there for a reason that is not a fault. What is portable,
//! and what is worth holding, is that sharding changes nothing a client can see:
//! one port, and every client served.

use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::Arc;

use moqom_transport::{Server, alpn};
use web_transport_quinn::Session;
use web_transport_quinn::proto::{ConnectRequest, ConnectResponse};

/// A certificate for `localhost`, valid only for this process.
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

    quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    ))
}

/// Echo every stream on every session this listener accepts.
async fn echo_on(server: Arc<Server>) {
    while let Some(accepting) = server.accept().await {
        tokio::spawn(async move {
            let Ok((session, _)) = accepting.establish().await else {
                return;
            };
            while let Ok((mut send, mut recv)) = session.accept_bi().await {
                let Ok(received) = recv.read_to_end(64 * 1024).await else {
                    return;
                };
                if send.write_all(&received).await.is_err() {
                    return;
                }
                let _ = send.finish();
            }
        });
    }
}

/// Connect, echo one stream, and report what came back.
async fn round_trip(
    addr: SocketAddr,
    cert: &rustls::pki_types::CertificateDer<'static>,
    payload: &[u8],
) -> Vec<u8> {
    let endpoint = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let conn = endpoint
        .connect_with(client_config(cert), addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let session = Session::raw(
        conn,
        ConnectRequest::new(url::Url::parse("https://localhost/").unwrap()),
        ConnectResponse::OK,
    );

    let (mut send, mut recv) = session.open_bi().await.unwrap();
    send.write_all(payload).await.unwrap();
    send.finish().unwrap();
    let echoed = recv.read_to_end(64 * 1024).await.unwrap();
    session.close(0, b"done");
    echoed
}

/// Asking for port zero must still put every shard on one port. Binding each
/// shard to zero would hand out several ports, of which a client could reach one
/// -- and it would look like a working relay that loses most of its traffic.
#[tokio::test]
async fn every_shard_listens_on_the_same_port() {
    let (cert, key) = self_signed();
    let shards = Server::bind_shards(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        server_tls(cert, key),
        None,
        NonZeroUsize::new(4).unwrap(),
    )
    .unwrap();

    assert_eq!(shards.len(), 4);
    let ports: Vec<u16> = shards
        .iter()
        .map(|shard| shard.local_addr().unwrap().port())
        .collect();
    assert!(
        ports.iter().all(|port| *port == ports[0]) && ports[0] != 0,
        "every shard shares one bound port: {ports:?}"
    );
}

/// The point of the caveats on `bind_shards` is that a client should not be able
/// to tell. Several clients, one address, all served.
#[tokio::test]
async fn a_sharded_listener_serves_every_client() {
    let (cert, key) = self_signed();
    let shards: Vec<Arc<Server>> = Server::bind_shards(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        server_tls(cert.clone(), key),
        None,
        NonZeroUsize::new(3).unwrap(),
    )
    .unwrap()
    .into_iter()
    .map(Arc::new)
    .collect();
    let addr = shards[0].local_addr().unwrap();

    let mut listening = Vec::new();
    for shard in &shards {
        listening.push(tokio::spawn(echo_on(Arc::clone(shard))));
    }

    for client in 0..6_u8 {
        let payload = [client; 32];
        assert_eq!(
            round_trip(addr, &cert, &payload).await,
            payload,
            "client {client} was not served"
        );
    }

    for task in listening {
        task.abort();
    }
}

/// One shard is the ordinary listener, and has to stay exactly that: the default
/// deployment takes this path and none of the sharding caveats apply to it.
#[tokio::test]
async fn one_shard_is_an_ordinary_listener() {
    let (cert, key) = self_signed();
    let mut shards = Server::bind_shards(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        server_tls(cert.clone(), key),
        None,
        NonZeroUsize::MIN,
    )
    .unwrap();

    assert_eq!(shards.len(), 1);
    let server = Arc::new(shards.pop().unwrap());
    let addr = server.local_addr().unwrap();
    let serving = tokio::spawn(echo_on(Arc::clone(&server)));

    assert_eq!(round_trip(addr, &cert, b"unsharded").await, b"unsharded");
    serving.abort();
}
