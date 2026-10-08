//! Direct sockets over IPv6, and both families on one dual-stack port.
//!
//! Loopback only: `::1` and `127.0.0.1` are on every machine that runs these,
//! and what is under test is the socket's handling of the families rather than
//! any network's routing of them.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use moqom_client::Error;
use moqom_client::direct::socket::{DirectSocket, SocketConfig, StunServer};

const PATIENCE: Duration = Duration::from_secs(10);
const ALPN: &[u8] = b"moqt-19";

fn install_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

async fn bound(bind: SocketAddr) -> DirectSocket {
    install_provider();
    let mut config = SocketConfig::new(ALPN);
    config.bind = bind;
    DirectSocket::bind(config).await.expect("binds")
}

/// A socket on the default bind, which is dual-stack wherever these run.
async fn dual() -> DirectSocket {
    let socket = bound(SocketConfig::new(ALPN).bind).await;
    assert!(
        socket.local_addr().expect("address").is_ipv6(),
        "the default bind should be one dual-stack IPv6 socket"
    );
    socket
}

fn port(socket: &DirectSocket) -> u16 {
    socket.local_addr().expect("address").port()
}

/// Dial `to` at `target` from `from` and accept there; both connections.
async fn connect(
    from: &DirectSocket,
    to: &DirectSocket,
    target: SocketAddr,
) -> (quinn::Connection, quinn::Connection) {
    let targets = [target];
    let (dialled, accepted) = tokio::join!(
        from.dial(&targets, to.fingerprint(), PATIENCE),
        to.accept(from.fingerprint(), PATIENCE),
    );
    (
        dialled.expect("the dial completes"),
        accepted.expect("the accept completes"),
    )
}

/// A one-shot STUN server answering with whatever address it saw.
fn stun_server(socket: UdpSocket) -> std::thread::JoinHandle<SocketAddr> {
    std::thread::spawn(move || {
        let mut buffer = [0u8; 576];
        let (n, from) = socket.recv_from(&mut buffer).expect("a request");
        assert!(n >= 20);
        let transaction: [u8; 12] = buffer[8..20].try_into().expect("12 bytes");
        let response = moqom_client::direct::stun::binding_response(transaction, from);
        socket.send_to(&response, from).expect("answer");
        from
    })
}

#[tokio::test]
async fn two_sockets_on_ipv6_loopback_connect() {
    let loopback = SocketAddr::from((Ipv6Addr::LOCALHOST, 0));
    let ada = bound(loopback).await;
    let bob = bound(loopback).await;
    assert_eq!(
        bob.host_candidates(),
        &[SocketAddr::from((Ipv6Addr::LOCALHOST, port(&bob)))]
    );

    let (dialled, accepted) = connect(&ada, &bob, bob.host_candidates()[0]).await;
    assert_eq!(
        dialled.remote_address(),
        SocketAddr::from((Ipv6Addr::LOCALHOST, port(&bob)))
    );
    assert_eq!(
        accepted.remote_address(),
        SocketAddr::from((Ipv6Addr::LOCALHOST, port(&ada)))
    );
}

#[tokio::test]
async fn a_dual_stack_socket_is_reached_in_both_families_on_one_port() {
    let ada = dual().await;
    let bob = dual().await;
    let (v6, _) = connect(
        &ada,
        &bob,
        SocketAddr::from((Ipv6Addr::LOCALHOST, port(&bob))),
    )
    .await;
    assert_eq!(v6.remote_address().ip(), Ipv6Addr::LOCALHOST);
    let (v4, _) = connect(
        &ada,
        &bob,
        SocketAddr::from((Ipv4Addr::LOCALHOST, port(&bob))),
    )
    .await;
    assert_eq!(v4.remote_address().ip().to_canonical(), Ipv4Addr::LOCALHOST);
}

#[tokio::test]
async fn a_dual_stack_socket_reaches_an_ipv4_only_one() {
    let ada = dual().await;
    let bob = bound(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await;
    let (dialled, accepted) = connect(&ada, &bob, bob.host_candidates()[0]).await;
    assert_eq!(
        dialled.remote_address().ip().to_canonical(),
        Ipv4Addr::LOCALHOST
    );
    // Seen from an IPv4 socket the peer is plain IPv4, not mapped.
    assert_eq!(
        accepted.remote_address(),
        SocketAddr::from((Ipv4Addr::LOCALHOST, port(&ada)))
    );
}

#[tokio::test]
async fn an_ipv4_socket_skips_ipv6_candidates_rather_than_failing_the_rest() {
    let ada = bound(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await;
    let bob = dual().await;

    let only_v6 = [SocketAddr::from((Ipv6Addr::LOCALHOST, port(&bob)))];
    let refused = ada.dial(&only_v6, bob.fingerprint(), PATIENCE).await;
    assert!(matches!(refused, Err(Error::Connect(_))), "{refused:?}");

    let (dialled, _) = {
        let mixed = [
            SocketAddr::from((Ipv6Addr::LOCALHOST, port(&bob))),
            SocketAddr::from((Ipv4Addr::LOCALHOST, port(&bob))),
        ];
        let (dialled, accepted) = tokio::join!(
            ada.dial(&mixed, bob.fingerprint(), PATIENCE),
            bob.accept(ada.fingerprint(), PATIENCE),
        );
        (
            dialled.expect("the IPv4 candidate"),
            accepted.expect("accepted"),
        )
    };
    assert_eq!(dialled.remote_address().ip(), Ipv4Addr::LOCALHOST);
}

#[tokio::test]
async fn stun_over_ipv6_reports_the_ipv6_address() {
    let server = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).expect("server");
    let server_addr = server.local_addr().expect("address");
    let answering = stun_server(server);

    install_provider();
    let mut config = SocketConfig::new(ALPN);
    config.stun = Some(StunServer::Address(server_addr));
    config.stun_timeout = Duration::from_secs(3);
    let socket = DirectSocket::bind(config).await.expect("binds");
    let seen = answering.join().expect("server thread");

    assert_eq!(seen.ip(), Ipv6Addr::LOCALHOST);
    assert_eq!(socket.reflexive(), Some(seen));
    assert_eq!(socket.reflexive_addresses(), &[seen]);
    assert_eq!(seen.port(), port(&socket));
}

#[tokio::test]
async fn stun_over_ipv4_from_a_dual_stack_socket_reports_plain_ipv4() {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("server");
    let server_addr = server.local_addr().expect("address");
    let answering = stun_server(server);

    install_provider();
    let mut config = SocketConfig::new(ALPN);
    config.stun = Some(StunServer::Address(server_addr));
    config.stun_timeout = Duration::from_secs(3);
    let socket = DirectSocket::bind(config).await.expect("binds");
    let seen = answering.join().expect("server thread");

    assert!(socket.local_addr().expect("address").is_ipv6());
    assert_eq!(seen, SocketAddr::from((Ipv4Addr::LOCALHOST, port(&socket))));
    assert_eq!(socket.reflexive(), Some(seen));
}

#[tokio::test]
async fn stun_by_name_asks_each_family_once() {
    // `localhost` resolves to both loopbacks on the machines these run on. A
    // resolver that offers only one family leaves nothing to test here.
    let resolved: Vec<SocketAddr> = std::net::ToSocketAddrs::to_socket_addrs(&("localhost", 0))
        .expect("localhost resolves")
        .collect();
    if !resolved.iter().any(SocketAddr::is_ipv4) || !resolved.iter().any(SocketAddr::is_ipv6) {
        eprintln!("localhost does not resolve to both families here: {resolved:?}");
        return;
    }

    // One port on both loopbacks, since a name has one port.
    let (v4, v6) = (0..32)
        .find_map(|_| {
            let v4 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).ok()?;
            let port = v4.local_addr().ok()?.port();
            let v6 = UdpSocket::bind((Ipv6Addr::LOCALHOST, port)).ok()?;
            Some((v4, v6))
        })
        .expect("a port free on both loopbacks");
    let stun_port = v4.local_addr().expect("address").port();
    let (answer_v4, answer_v6) = (stun_server(v4), stun_server(v6));

    install_provider();
    let mut config = SocketConfig::new(ALPN);
    config.stun = Some(StunServer::Name {
        host: "localhost".to_owned(),
        port: stun_port,
    });
    config.stun_timeout = Duration::from_secs(3);
    let socket = DirectSocket::bind(config).await.expect("binds");

    let seen_v4 = answer_v4.join().expect("IPv4 server");
    let seen_v6 = answer_v6.join().expect("IPv6 server");
    assert_eq!(
        socket.reflexive_addresses(),
        &[
            SocketAddr::from((Ipv4Addr::LOCALHOST, port(&socket))),
            SocketAddr::from((Ipv6Addr::LOCALHOST, port(&socket))),
        ]
    );
    assert_eq!(seen_v4.port(), port(&socket));
    assert_eq!(seen_v6.port(), port(&socket));
    assert_eq!(socket.reflexive(), Some(socket.reflexive_addresses()[0]));
}

#[tokio::test]
async fn probes_reach_both_families_from_the_one_port() {
    let socket = dual().await;
    let observers = [
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("IPv4 observer"),
        UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).expect("IPv6 observer"),
    ];
    let targets = observers
        .iter()
        .map(|observer| {
            observer
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("timeout");
            observer.local_addr().expect("address")
        })
        .collect();
    socket
        .punch_start(targets, Duration::from_millis(20))
        .expect("probing starts");
    for observer in &observers {
        let mut buffer = [0u8; 16];
        let (n, from) = observer.recv_from(&mut buffer).expect("a probe");
        assert_eq!(&buffer[..n], b"MQDP");
        assert_eq!(from.port(), port(&socket));
        assert_eq!(
            from.is_ipv6(),
            observer.local_addr().expect("address").is_ipv6()
        );
    }
    socket.punch_stop();
}

#[tokio::test]
async fn a_dual_stack_socket_offers_no_unusable_host_candidates() {
    let socket = dual().await;
    let candidates = socket.host_candidates();
    assert!(!candidates.is_empty());
    for candidate in candidates {
        assert_eq!(candidate.port(), port(&socket));
        assert!(!candidate.ip().is_unspecified(), "{candidate}");
        if let std::net::IpAddr::V6(ip) = candidate.ip() {
            assert!(!ip.is_unicast_link_local(), "{candidate}");
            assert!(ip.to_ipv4_mapped().is_none(), "{candidate}");
        }
    }
}
