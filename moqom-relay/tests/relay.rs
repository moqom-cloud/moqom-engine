//! The relay, over a real socket, with a peer that does not share its code.
//!
//! These are the tests that would have caught the state this crate was written
//! to fix. Before it existed the protocol implementation had never been spoken
//! between two independent parties: the codec round-tripped against itself, the
//! Swift client ran against an in-memory loopback, and the transport crate
//! accepted QUIC connections and echoed bytes. Every one of those passes while a
//! framing mistake goes unnoticed.
//!
//! So the client here is a separate implementation, in
//! [`support`](support), built directly on the codec rather than on the relay's
//! session code. A disagreement about the wire shows up as a test failure rather
//! than as two ends agreeing on the wrong thing.

mod support;

use support::{Announced, Client, Relay, namespace, track, within};

/// SETUP, both directions, over raw QUIC with the `moqt-19` ALPN.
///
/// Everything else depends on this, and `Client::connect` asserts the answer is
/// a decodable SETUP — so a connection that returns at all has already checked
/// the handshake.
#[tokio::test]
async fn a_session_is_established() {
    let relay = Relay::start();
    let client = Client::connect(&relay).await;
    drop(client);
}

/// A namespace announced before the watch starts still reaches it.
///
/// The ordering matters more than it looks: a relay that only forwarded *changes*
/// would pass a test where the watch comes first and silently break discovery for
/// every subscriber that joins an existing room.
#[tokio::test]
async fn an_existing_namespace_reaches_a_new_watcher() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let mut subscriber = Client::connect(&relay).await;

    let room = namespace(&["acme", "room-42"]);
    let _announcement = publisher.announce(&room).await;
    // The announcement has to have reached the relay before the watch starts,
    // or this tests the live-update path by accident.
    within("the announcement to register", async {
        while relay.fabric.namespaces().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await;

    let mut watch = subscriber.watch(&namespace(&["acme"])).await;
    assert_eq!(watch.next().await, Announced::Available(room));
}

/// A namespace announced after the watch starts reaches it too.
#[tokio::test]
async fn a_new_namespace_reaches_an_existing_watcher() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let mut subscriber = Client::connect(&relay).await;

    let mut watch = subscriber.watch(&namespace(&["acme"])).await;
    let room = namespace(&["acme", "room-42"]);
    let _announcement = publisher.announce(&room).await;

    assert_eq!(watch.next().await, Announced::Available(room));
}

/// Closing the announcement stream withdraws the namespace, and watchers are
/// told. There is no `UNANNOUNCE` message; the close *is* the withdrawal.
#[tokio::test]
async fn closing_an_announcement_withdraws_it() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let mut subscriber = Client::connect(&relay).await;

    let room = namespace(&["acme", "room-42"]);
    let announcement = publisher.announce(&room).await;
    let mut watch = subscriber.watch(&namespace(&["acme"])).await;
    assert_eq!(watch.next().await, Announced::Available(room.clone()));

    announcement.withdraw();
    assert_eq!(watch.next().await, Announced::Gone(room));
}

/// A watch under a different prefix hears nothing. Tuple prefixes are the reason
/// namespaces are not strings: `("acme", "room")` must not match
/// `("acme", "roomies")`.
#[tokio::test]
async fn a_watch_hears_nothing_outside_its_prefix() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let mut subscriber = Client::connect(&relay).await;

    let mut watch = subscriber.watch(&namespace(&["acme", "room"])).await;
    let _announcement = publisher.announce(&namespace(&["acme", "roomies"])).await;

    let leaked = tokio::time::timeout(
        std::time::Duration::from_millis(250),
        Box::pin(watch.next()),
    )
    .await;
    assert!(
        leaked.is_err(),
        "a sibling namespace is not under this prefix, but the relay sent {leaked:?}"
    );
}

/// Subscribing to a namespace nobody publishes is refused, with the code the
/// draft defines rather than a generic failure.
///
/// The alternative — accepting and never delivering — is the failure mode that
/// looks like a network problem and is impossible to diagnose from the client.
#[tokio::test]
async fn subscribing_to_an_unpublished_namespace_is_refused() {
    let relay = Relay::start();
    let mut subscriber = Client::connect(&relay).await;

    let outcome = subscriber
        .subscribe(&track(&["acme", "nothing"], "video"))
        .await;
    assert_eq!(
        outcome.err(),
        Some(moqom_proto::control::RequestErrorCode::DOES_NOT_EXIST.get()),
        "expected DOES_NOT_EXIST"
    );
}

/// The whole point: objects published on one session come out of another, with
/// the alias rewritten and the payload untouched.
#[tokio::test]
async fn objects_are_forwarded_with_a_rewritten_alias() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let mut subscriber = Client::connect(&relay).await;

    let room = namespace(&["acme", "room-42"]);
    let _announcement = publisher.announce(&room).await;
    within("the announcement to register", async {
        while relay.fabric.namespaces().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await;

    // An upstream alias the relay could not accidentally pass through: it hands
    // out aliases from zero, so 7 here can only appear downstream if the rewrite
    // did not happen.
    let upstream = moqom_proto::model::TrackAlias::from(7_u32);
    let video = track(&["acme", "room-42"], "video");

    // Both halves have to run concurrently: the relay does not answer the
    // subscriber until the publisher has answered it, so awaiting either one
    // first deadlocks.
    let (served, subscription) = tokio::join!(
        publisher.answer_subscription(upstream),
        subscriber.subscribe(&video),
    );
    let subscription = subscription.expect("the relay accepts the subscription");
    assert_eq!(
        served.track, video,
        "the relay asked for the track requested"
    );
    assert_ne!(
        subscription.alias, upstream,
        "the downstream alias must be the relay's own"
    );

    publisher
        .publish_subgroup(upstream, &[b"first", b"second"])
        .await;

    let (header, payloads) = subscriber.read_subgroup().await;
    assert_eq!(
        header.track_alias, subscription.alias,
        "the forwarded header must carry the alias this subscriber negotiated"
    );
    assert_eq!(
        payloads,
        vec![
            bytes::Bytes::from_static(b"first"),
            bytes::Bytes::from_static(b"second")
        ],
        "payloads must survive the relay byte for byte"
    );
}

/// Two subscribers get the same objects, each under its own alias.
///
/// Fan-out is the reason a relay exists at all, and per-session aliases mean the
/// two subscribers see *different* headers for the same subgroup. A relay that
/// forwarded one and reused its header for the other would pass a single-
/// subscriber test.
#[tokio::test]
async fn every_subscriber_gets_the_objects_under_its_own_alias() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let mut first = Client::connect(&relay).await;
    let mut second = Client::connect(&relay).await;

    let _announcement = publisher.announce(&namespace(&["acme", "room-42"])).await;
    within("the announcement to register", async {
        while relay.fabric.namespaces().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await;

    let video = track(&["acme", "room-42"], "video");
    let upstream = moqom_proto::model::TrackAlias::from(7_u32);

    // Each downstream subscription causes its own upstream SUBSCRIBE, and the
    // publisher answers both with the same alias — one track, one stream of
    // objects, as far as it is concerned.
    let (served_a, one) = tokio::join!(
        publisher.answer_subscription(upstream),
        first.subscribe(&video),
    );
    let (served_b, two) = tokio::join!(
        publisher.answer_subscription(upstream),
        second.subscribe(&video),
    );
    let one = one.expect("the first subscription is accepted");
    let two = two.expect("the second subscription is accepted");
    assert_eq!(served_a.track, video);
    assert_eq!(served_b.track, video);

    publisher.publish_subgroup(upstream, &[b"shared"]).await;

    let (header_one, payloads_one) = first.read_subgroup().await;
    let (header_two, payloads_two) = second.read_subgroup().await;

    assert_eq!(header_one.track_alias, one.alias);
    assert_eq!(header_two.track_alias, two.alias);
    // Aliases are per session, so both subscribers are on their first
    // subscription and both get the same number — which makes this the sharper
    // check: the upstream alias is 7, and neither header carries it.
    assert_ne!(one.alias, upstream);
    assert_ne!(two.alias, upstream);
    assert_eq!(payloads_one, payloads_two);
    assert_eq!(payloads_one, vec![bytes::Bytes::from_static(b"shared")]);
}
