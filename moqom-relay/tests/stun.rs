//! The relay's STUN responder, asked by the client `moqom-client` ships.
//!
//! What a device does before offering a direct path: ask, from the socket the
//! path will use, what address its requests arrive from.

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use moqom_client::direct::stun::{binding_request, reflexive, reflexive_each};
use moqom_relay::Metrics;
use moqom_relay::metrics::Gauges;
use moqom_relay::stun::{Config, Limits, Responder};

fn responder(listen: &str, limits: Limits) -> (SocketAddr, Metrics) {
    let metrics = Metrics::new();
    let config = Config {
        listen: listen.parse().expect("address"),
        limits,
    };
    let responder = Responder::bind(&config, metrics.clone()).expect("binding STUN");
    let bound = responder.local_addr().expect("bound");
    tokio::spawn(responder.serve());
    (bound, metrics)
}

async fn ask(server: SocketAddr, from: &str) -> (std::io::Result<SocketAddr>, SocketAddr) {
    let client = UdpSocket::bind(from).expect("client");
    let local = client.local_addr().expect("local");
    let seen =
        tokio::task::spawn_blocking(move || reflexive(&client, server, Duration::from_secs(3)))
            .await
            .expect("asking");
    (seen, local)
}

#[tokio::test]
async fn a_client_learns_the_address_it_asked_from() {
    let (server, metrics) = responder("127.0.0.1:0", Limits::default());
    let (seen, local) = ask(server, "127.0.0.1:0").await;
    assert_eq!(seen.expect("an answer"), local);
    assert!(
        metrics
            .expose(&Gauges::default())
            .contains(r#"moqom_relay_stun_requests_total{outcome="answered"} 1"#)
    );
}

/// The default listener is dual-stack, and answers each family with its own
/// address: an IPv4 client hears an IPv4 address, not a mapped one.
#[tokio::test]
async fn one_socket_answers_both_families() {
    let (server, _) = responder("[::]:0", Limits::default());
    let v4 = SocketAddr::from(([127, 0, 0, 1], server.port()));
    let (seen, local) = ask(v4, "127.0.0.1:0").await;
    assert_eq!(seen.expect("an IPv4 answer"), local);

    // A host with no IPv6 loopback has nothing to test here.
    if UdpSocket::bind("[::1]:0").is_ok() {
        let v6: SocketAddr = format!("[::1]:{}", server.port()).parse().expect("v6");
        let (seen, local) = ask(v6, "[::1]:0").await;
        assert_eq!(seen.expect("an IPv6 answer"), local);
    }
}

#[tokio::test]
async fn garbage_and_a_flooding_source_go_unanswered() {
    let limits = Limits {
        rate: 1.0,
        burst: 2.0,
        sources: 16,
    };
    let (server, metrics) = responder("127.0.0.1:0", limits);
    let client = UdpSocket::bind("127.0.0.1:0").expect("client");
    client
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("timeout");

    client.send_to(b"not stun at all", server).expect("send");
    let mut response = binding_request([7; 12]).to_vec();
    response[1] = 0x01;
    response[0] = 0x01;
    client.send_to(&response, server).expect("send");
    for _ in 0..5 {
        client
            .send_to(&binding_request([9; 12]), server)
            .expect("send");
    }

    let answered = tokio::task::spawn_blocking(move || {
        let mut buffer = [0u8; 576];
        let mut answered = 0;
        while client.recv_from(&mut buffer).is_ok() {
            answered += 1;
        }
        answered
    })
    .await
    .expect("reading");
    assert_eq!(answered, 2, "the burst, and nothing past it");

    let exposed = metrics.expose(&Gauges::default());
    assert!(exposed.contains(r#"moqom_relay_stun_requests_total{outcome="answered"} 2"#));
    assert!(exposed.contains(r#"moqom_relay_stun_requests_total{outcome="limited"} 3"#));
    assert!(exposed.contains(r#"moqom_relay_stun_requests_total{outcome="ignored"} 2"#));
}

/// Asking for both families at once from one dual-stack socket, as the client
/// does when it binds, gets an answer for each.
#[tokio::test]
async fn a_dual_stack_client_learns_both() {
    if UdpSocket::bind("[::1]:0").is_err() {
        return;
    }
    let (server, _) = responder("[::]:0", Limits::default());
    let client = UdpSocket::bind("[::]:0").expect("client");
    let port = client.local_addr().expect("local").port();
    let servers = [
        SocketAddr::from(([127, 0, 0, 1], server.port())),
        format!("[::1]:{}", server.port()).parse().expect("v6"),
    ];
    let seen = tokio::task::spawn_blocking(move || {
        reflexive_each(&client, &servers, Duration::from_secs(3))
    })
    .await
    .expect("asking")
    .expect("answers");
    assert_eq!(
        seen,
        vec![
            Some(SocketAddr::from(([127, 0, 0, 1], port))),
            Some(format!("[::1]:{port}").parse().expect("v6")),
        ]
    );
}
