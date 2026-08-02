//! What a relay does when one subscriber cannot take what the others can.
//!
//! Every room has one: the person on a train, on a hotel network, on a phone
//! holding one bar. The question is who pays for them. A relay that writes to
//! its subscribers in turn makes everybody pay, because a QUIC write does not
//! return until that connection's flow control allows it — so the slowest
//! viewer sets the pace for the room, and the backpressure runs all the way up
//! to the publisher's phone, which then encodes for the worst link in the
//! system.
//!
//! The alternative is not a bigger buffer. Queueing turns a bandwidth shortfall
//! into latency, delivers pictures after the moment they belonged to, and
//! reports nothing wrong. So the relay drops: whole subgroups, per subscriber,
//! with the stream reset so the loss is stated rather than inferred.
//!
//! These tests are about a *publisher* and a *healthy subscriber* remaining
//! unaffected. That is the property; the shedding is only how it is achieved.

mod support;

use moqom_proto::model::{GroupId, TrackAlias};
use support::{Client, Relay, eventually, namespace, track, value, within};

/// Wait for an announcement to reach the fabric before subscribing to it.
async fn registered(relay: &Relay) {
    within("the announcement to register", async {
        while relay.fabric.namespaces().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await;
}

/// Comfortably more than the congested subscriber's window, and more than the
/// relay will hold for it. A real subgroup is a frame or a group of them; this
/// is one sized so that a test can watch a subscriber fall behind within it.
const OBJECTS: usize = 48;
const OBJECT_SIZE: usize = 8 * 1024;

/// The one property that matters: nobody else notices.
#[tokio::test]
async fn a_subscriber_who_cannot_keep_up_does_not_slow_the_others() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let mut healthy = Client::connect(&relay).await;
    let mut struggling = Client::connect_congested(&relay).await;

    let _announcement = publisher.announce(&namespace(&["acme", "room-42"])).await;
    registered(&relay).await;

    let video = track(&["acme", "room-42"], "video");
    let upstream = TrackAlias::from(7_u32);
    let (_served, subscribed) = tokio::join!(
        publisher.answer_subscription(upstream),
        healthy.subscribe(&video),
    );
    let _healthy = subscribed.expect("the healthy subscriber");
    let _struggling = struggling.subscribe(&video).await.expect("the other one");

    let payload = vec![b'x'; OBJECT_SIZE];
    let objects: Vec<&[u8]> = vec![&payload[..]; OBJECTS];
    publisher.publish_subgroup(upstream, &objects).await;

    // The whole subgroup, at the speed the healthy connection allows. Before
    // the writes were separated this could not complete until the congested
    // subscriber had taken its copy, which it never will.
    let (_, payloads) = within("the healthy subscriber's copy", healthy.read_subgroup()).await;
    assert_eq!(payloads.len(), OBJECTS);
    assert!(payloads.iter().all(|p| p.len() == OBJECT_SIZE));

    // And the other subscriber really was stuck, rather than quietly keeping
    // up — without which the assertion above would prove nothing at all.
    eventually("the struggling subscriber to be shed", &relay, |s| {
        value(s, "moqom_relay_subgroups_shed_total") > 0
    })
    .await;
}

/// The relay stops keeping a subgroup nobody can take, and says so.
#[tokio::test]
async fn a_subgroup_is_abandoned_rather_than_queued() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let mut struggling = Client::connect_congested(&relay).await;

    let _announcement = publisher.announce(&namespace(&["acme", "room-42"])).await;
    registered(&relay).await;

    let video = track(&["acme", "room-42"], "video");
    let upstream = TrackAlias::from(7_u32);
    let (_served, subscribed) = tokio::join!(
        publisher.answer_subscription(upstream),
        struggling.subscribe(&video),
    );
    let _subscription = subscribed.expect("subscribed");

    let payload = vec![b'x'; OBJECT_SIZE];
    let objects: Vec<&[u8]> = vec![&payload[..]; OBJECTS];
    publisher.publish_subgroup(upstream, &objects).await;

    // A reset, not a stream that simply stops. The subscriber can tell that
    // this group is not coming and ask for something it can afford, which is
    // the recovery the whole mechanism is arranged around.
    assert!(
        within(
            "the abandoned subgroup",
            struggling.subgroup_was_abandoned()
        )
        .await,
        "a subgroup the subscriber could not take should be reset, not left open"
    );

    let scrape = eventually("the shed copy to be counted", &relay, |s| {
        value(s, "moqom_relay_subgroups_shed_total") > 0
    })
    .await;
    assert_eq!(
        value(&scrape, "moqom_relay_fanout_failures_total"),
        0,
        "shedding is a decision, not a write failure:\n{scrape}"
    );
}

/// Shedding a subgroup must not end the subscription.
///
/// A slow moment is a slow moment. If falling behind on one group cost the
/// viewer its subscription, the picture would not recover when the connection
/// did — and the failure would look like a relay that drops people at random.
#[tokio::test]
async fn a_subscriber_recovers_on_the_next_group() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let mut struggling = Client::connect_congested(&relay).await;

    let _announcement = publisher.announce(&namespace(&["acme", "room-42"])).await;
    registered(&relay).await;

    let video = track(&["acme", "room-42"], "video");
    let upstream = TrackAlias::from(7_u32);
    let (_served, subscribed) = tokio::join!(
        publisher.answer_subscription(upstream),
        struggling.subscribe(&video),
    );
    let subscription = subscribed.expect("subscribed");

    let payload = vec![b'x'; OBJECT_SIZE];
    let heavy: Vec<&[u8]> = vec![&payload[..]; OBJECTS];
    publisher
        .publish_group(upstream, GroupId::ZERO, &heavy)
        .await;
    assert!(
        within(
            "the abandoned subgroup",
            struggling.subgroup_was_abandoned()
        )
        .await,
        "the first group is more than this subscriber can take"
    );

    // Something it can afford, on the next group.
    publisher
        .publish_group(upstream, GroupId::from(1_u32), &[b"small"])
        .await;
    let (header, payloads) = within("the group after it", struggling.read_subgroup()).await;
    assert_eq!(header.track_alias, subscription.alias);
    assert_eq!(payloads, vec![bytes::Bytes::from_static(b"small")]);
}

/// The publisher is not held back by the room's slowest member.
///
/// The subscriber here never recovers, so a relay that waits for it waits for
/// ever: the assertion is simply that the publisher's own stream keeps being
/// read, group after group.
#[tokio::test]
async fn a_publisher_keeps_being_read_while_a_subscriber_stalls() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let mut struggling = Client::connect_congested(&relay).await;

    let _announcement = publisher.announce(&namespace(&["acme", "room-42"])).await;
    registered(&relay).await;

    let video = track(&["acme", "room-42"], "video");
    let upstream = TrackAlias::from(7_u32);
    let (_served, subscribed) = tokio::join!(
        publisher.answer_subscription(upstream),
        struggling.subscribe(&video),
    );
    let _subscription = subscribed.expect("subscribed");

    let payload = vec![b'x'; OBJECT_SIZE];
    let heavy: Vec<&[u8]> = vec![&payload[..]; OBJECTS];
    for group in 0..4_u32 {
        within(
            "the publisher's group to be taken",
            publisher.publish_group(upstream, GroupId::from(group), &heavy),
        )
        .await;
    }

    // Every group reached the relay, which is the ingress counter's job to
    // prove: a relay stalled behind a subscriber would have read the first and
    // then stopped.
    let expected = (OBJECTS * OBJECT_SIZE * 4) as u64;
    eventually("the publisher's bytes to be read", &relay, |s| {
        value(s, "moqom_relay_ingress_bytes_total") >= expected
    })
    .await;
}
