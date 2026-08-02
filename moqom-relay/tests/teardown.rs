//! What happens when somebody stops watching, and when a track stops.
//!
//! Both ends of a subscription can end it, and until now the relay noticed
//! neither. A viewer that closed its request stream left the relay pulling the
//! track anyway — a phone spending its uplink and its battery on a broadcast
//! with no audience — and a publisher that stopped left every viewer staring at
//! a tile that was indistinguishable from a stalled network.
//!
//! Neither failure is visible to the side that caused it, which is why they
//! survived this long. The tests here are written from the other side each
//! time: what the publisher sees when the last viewer leaves, and what a viewer
//! sees when the publisher goes.

mod support;

use moqom_proto::control::{PublishDoneStatus, StreamCount};
use moqom_proto::model::TrackAlias;
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

/// The saving that makes the rest of this worth having.
///
/// A room that empties should stop costing the person who left it. Without
/// this the pull runs until the publisher itself gives up, and on a phone that
/// means uploading video to an empty room until the battery or the tab dies.
#[tokio::test]
async fn the_last_viewer_leaving_stops_the_pull() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let mut viewer = Client::connect(&relay).await;

    let _announcement = publisher.announce(&namespace(&["acme", "room-42"])).await;
    registered(&relay).await;

    let video = track(&["acme", "room-42"], "video");
    let (mut served, subscribed) = tokio::join!(
        publisher.answer_subscription(TrackAlias::from(7_u32)),
        viewer.subscribe(&video),
    );
    let subscription = subscribed.expect("the subscription is accepted");

    // Closing the request stream is the whole of unsubscribing: the protocol
    // has no message for it.
    drop(subscription);

    served.released().await;
    eventually("the track to stop being pulled", &relay, |s| {
        value(s, "moqom_relay_tracks") == 0
    })
    .await;
}

/// One of several leaving is not the same as the last one leaving.
///
/// The dangerous version of the change above is a relay that hears any
/// departure as the end. Since the pull is shared, that would take the
/// broadcast away from everybody who stayed — and the viewer who caused it
/// would never know, having already left.
#[tokio::test]
async fn a_pull_outlives_a_viewer_who_is_not_the_last() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let mut leaving = Client::connect(&relay).await;
    let mut staying = Client::connect(&relay).await;

    let _announcement = publisher.announce(&namespace(&["acme", "room-42"])).await;
    registered(&relay).await;

    let video = track(&["acme", "room-42"], "video");
    let upstream = TrackAlias::from(7_u32);
    let (mut served, subscribed) = tokio::join!(
        publisher.answer_subscription(upstream),
        leaving.subscribe(&video),
    );
    let first = subscribed.expect("the first subscription is accepted");
    let _second = staying.subscribe(&video).await.expect("the second");

    drop(first);
    served.kept().await;

    // And the pull is still a working one, rather than merely a record that has
    // not been cleaned up yet.
    publisher.publish_subgroup(upstream, &[b"still here"]).await;
    let (_, payloads) = staying.read_subgroup().await;
    assert_eq!(payloads, vec![bytes::Bytes::from_static(b"still here")]);
}

/// A publisher stopping is news, and every viewer is told.
///
/// The alternative is silence, which is what a phone going through a tunnel
/// also looks like. A player waits out silence — correctly — so a track that
/// ended without saying so is a tile that never recovers and never explains
/// itself.
#[tokio::test]
async fn a_track_ending_is_announced_to_every_viewer() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let mut first = Client::connect(&relay).await;
    let mut second = Client::connect(&relay).await;

    let _announcement = publisher.announce(&namespace(&["acme", "room-42"])).await;
    registered(&relay).await;

    let video = track(&["acme", "room-42"], "video");
    let (served, subscribed) = tokio::join!(
        publisher.answer_subscription(TrackAlias::from(7_u32)),
        first.subscribe(&video),
    );
    let mut one = subscribed.expect("the first subscription is accepted");
    let mut two = second.subscribe(&video).await.expect("the second");

    // The publisher ends the track by closing the stream it was serving.
    drop(served);

    for subscription in [&mut one, &mut two] {
        let done = subscription.ended().await;
        assert_eq!(done.status, PublishDoneStatus::TRACK_ENDED);
    }
}

/// What `PUBLISH_DONE` counts is what a viewer waits for.
///
/// A subscriber reads the count to tell "everything arrived" from "one stream
/// is still in flight". A relay that reported zero, or lost count, would have
/// every viewer either tear down early or wait for a stream that was never
/// coming — so the number is asserted rather than merely its presence.
#[tokio::test]
async fn the_end_reports_how_many_streams_were_sent() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let mut viewer = Client::connect(&relay).await;

    let _announcement = publisher.announce(&namespace(&["acme", "room-42"])).await;
    registered(&relay).await;

    let video = track(&["acme", "room-42"], "video");
    let upstream = TrackAlias::from(7_u32);
    let (served, subscribed) = tokio::join!(
        publisher.answer_subscription(upstream),
        viewer.subscribe(&video),
    );
    let mut subscription = subscribed.expect("the subscription is accepted");

    for group in 0..3_u32 {
        publisher
            .publish_group(upstream, moqom_proto::model::GroupId::from(group), &[b"x"])
            .await;
        // Read before the next one, so the count under test is of streams the
        // relay opened rather than of a race between three of them.
        viewer.read_subgroup().await;
    }

    drop(served);

    let done = subscription.ended().await;
    assert_eq!(done.status, PublishDoneStatus::TRACK_ENDED);
    assert_eq!(done.stream_count, StreamCount::Exact(3));
}

/// A viewer leaving one rung must not disturb another.
///
/// Layer changes are the common case for unsubscribing — a phone moving between
/// rungs does it constantly — and they happen while another subscription to the
/// same publisher is live. Releasing by track alone, or by alias alone, would
/// take down the wrong one.
#[tokio::test]
async fn leaving_one_track_leaves_the_others_alone() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let mut viewer = Client::connect(&relay).await;

    let _announcement = publisher.announce(&namespace(&["acme", "room-42"])).await;
    registered(&relay).await;

    let high = TrackAlias::from(7_u32);
    let low = TrackAlias::from(8_u32);
    let rung_high = track(&["acme", "room-42"], "video/1080p");
    let rung_low = track(&["acme", "room-42"], "video/360p");

    let (mut serving_high, subscribed) = tokio::join!(
        publisher.answer_subscription(high),
        viewer.subscribe(&rung_high),
    );
    let dropping = subscribed.expect("the high rung");
    let (mut serving_low, subscribed) = tokio::join!(
        publisher.answer_subscription(low),
        viewer.subscribe(&rung_low),
    );
    let _keeping = subscribed.expect("the low rung");

    drop(dropping);

    serving_high.released().await;
    serving_low.kept().await;

    publisher.publish_subgroup(low, &[b"lower"]).await;
    let (_, payloads) = viewer.read_subgroup().await;
    assert_eq!(payloads, vec![bytes::Bytes::from_static(b"lower")]);
}
