//! One track, one subscription upstream, however many subscribers downstream.
//!
//! This is the arithmetic a relay is bought for. A broadcast watched by a
//! thousand people is one copy up from the phone and a thousand down from a
//! machine in a datacentre; a relay that asks the publisher once per viewer has
//! moved the fan-out onto the worst link in the system and left the phone
//! paying for it. The saving is invisible in any single-subscriber test, which
//! is why it gets a file.
//!
//! Every assertion here is about how many times the *publisher* was asked, and
//! that is deliberate. The subscribers cannot tell the difference — they get
//! their objects either way — so a test written from the viewer's side would
//! pass on a relay that had never heard of deduplication.

mod support;

use moqom_proto::model::TrackAlias;
use support::{Client, Relay, eventually, namespace, series, track, value, within};

/// Wait for an announcement to reach the fabric before subscribing to it.
async fn registered(relay: &Relay) {
    within("the announcement to register", async {
        while relay.fabric.namespaces().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await;
}

/// The ordinary case: an audience turns up one at a time and the publisher
/// notices only the first of them.
#[tokio::test]
async fn one_upstream_subscription_serves_every_viewer() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let mut first = Client::connect(&relay).await;
    let mut second = Client::connect(&relay).await;
    let mut third = Client::connect(&relay).await;

    let _announcement = publisher.announce(&namespace(&["acme", "room-42"])).await;
    registered(&relay).await;

    let video = track(&["acme", "room-42"], "video");
    let upstream = TrackAlias::from(7_u32);

    // Joined because the relay does not answer the first subscriber until the
    // publisher has answered it. The two after it need no such dance, which is
    // the point: there is nothing left to ask.
    let (_served, one) = tokio::join!(
        publisher.answer_subscription(upstream),
        first.subscribe(&video),
    );
    let one = one.expect("the first subscription is accepted");
    let two = second.subscribe(&video).await.expect("the second");
    let three = third.subscribe(&video).await.expect("the third");

    publisher.asked_nothing_further().await;

    publisher
        .publish_subgroup(upstream, &[b"one copy in"])
        .await;

    let (header_one, payloads_one) = first.read_subgroup().await;
    let (header_two, payloads_two) = second.read_subgroup().await;
    let (header_three, payloads_three) = third.read_subgroup().await;

    // Each still on its own alias. Sharing the pull upstream must not leak the
    // upstream's numbering downstream, and this is where that would show.
    assert_eq!(header_one.track_alias, one.alias);
    assert_eq!(header_two.track_alias, two.alias);
    assert_eq!(header_three.track_alias, three.alias);
    assert_eq!(payloads_one, payloads_two);
    assert_eq!(payloads_two, payloads_three);
    assert_eq!(
        payloads_one,
        vec![bytes::Bytes::from_static(b"one copy in")]
    );
}

/// Everybody arrives at once, which is what a scheduled broadcast actually
/// looks like.
///
/// The window this closes is the round trip: a subscriber that looks for an
/// existing pull *after* asking upstream finds nothing, because nothing has
/// finished yet, and four simultaneous viewers become four subscriptions. A
/// relay can therefore pass the test above and fail in production on its first
/// popular room.
#[tokio::test]
async fn viewers_arriving_together_still_pull_once() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let mut first = Client::connect(&relay).await;
    let mut second = Client::connect(&relay).await;
    let mut third = Client::connect(&relay).await;

    let _announcement = publisher.announce(&namespace(&["acme", "room-42"])).await;
    registered(&relay).await;

    let video = track(&["acme", "room-42"], "video");
    let upstream = TrackAlias::from(7_u32);

    let (_served, one, two, three) = tokio::join!(
        publisher.answer_subscription(upstream),
        first.subscribe(&video),
        second.subscribe(&video),
        third.subscribe(&video),
    );
    // Held, not merely checked: a subscription's request stream *is* the
    // subscription, so dropping these would unsubscribe all three.
    let _one = one.expect("the first subscription is accepted");
    let _two = two.expect("the second");
    let _three = three.expect("the third");

    publisher.asked_nothing_further().await;

    // And all three are actually routed, rather than two of them having been
    // answered with a subscription that goes nowhere.
    publisher.publish_subgroup(upstream, &[b"together"]).await;
    for viewer in [&mut first, &mut second, &mut third] {
        let (_, payloads) = viewer.read_subgroup().await;
        assert_eq!(payloads, vec![bytes::Bytes::from_static(b"together")]);
    }
}

/// Two rungs of one broadcast are two tracks, and collapsing them would send
/// the wrong bytes to half the room.
#[tokio::test]
async fn different_tracks_are_pulled_separately() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let mut viewer = Client::connect(&relay).await;

    let _announcement = publisher.announce(&namespace(&["acme", "room-42"])).await;
    registered(&relay).await;

    let high = TrackAlias::from(7_u32);
    let low = TrackAlias::from(8_u32);
    let rung_high = track(&["acme", "room-42"], "video/1080p");
    let rung_low = track(&["acme", "room-42"], "video/360p");

    let (served_high, subscribed) = tokio::join!(
        publisher.answer_subscription(high),
        viewer.subscribe(&rung_high),
    );
    let _high = subscribed.expect("the high rung");
    let (served_low, subscribed) = tokio::join!(
        publisher.answer_subscription(low),
        viewer.subscribe(&rung_low),
    );
    let _low = subscribed.expect("the low rung");

    assert_eq!(served_high.track.name(), b"video/1080p".as_slice());
    assert_eq!(served_low.track.name(), b"video/360p".as_slice());
}

/// A viewer leaving must not take the broadcast with it.
///
/// Before the pull was shared, a route and a subscriber were the same thing and
/// this could not go wrong. Now the last person to arrive is attached to
/// somebody else's subscription, and a relay that tore that down when its
/// originator hung up would end the broadcast for everybody who stayed.
#[tokio::test]
async fn a_viewer_leaving_does_not_end_it_for_the_others() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let mut leaving = Client::connect(&relay).await;
    let mut staying = Client::connect(&relay).await;

    let _announcement = publisher.announce(&namespace(&["acme", "room-42"])).await;
    registered(&relay).await;

    let video = track(&["acme", "room-42"], "video");
    let upstream = TrackAlias::from(7_u32);
    let (_served, first) = tokio::join!(
        publisher.answer_subscription(upstream),
        leaving.subscribe(&video),
    );
    let _first = first.expect("the first subscription is accepted");
    let _second = staying.subscribe(&video).await.expect("the second");

    // Not a polite departure: no message, the connection simply stops. This is
    // the common case — an app the system killed, a phone in a tunnel — and the
    // one where a relay is most likely to lose track of who is left.
    leaving.vanish();

    publisher.publish_subgroup(upstream, &[b"still here"]).await;
    let (_, payloads) = staying.read_subgroup().await;
    assert_eq!(payloads, vec![bytes::Bytes::from_static(b"still here")]);

    // The departure is noticed rather than merely survived. Failing to write to
    // a session that has gone is a fan-out failure, and a route left in place
    // would produce one for every subgroup from here on.
    publisher.publish_subgroup(upstream, &[b"and again"]).await;
    let (_, payloads) = staying.read_subgroup().await;
    assert_eq!(payloads, vec![bytes::Bytes::from_static(b"and again")]);
    let scrape = relay.scrape();
    assert_eq!(
        value(&scrape, "moqom_relay_fanout_failures_total"),
        0,
        "a departed subscriber should be forgotten, not written to:\n{scrape}"
    );
}

/// A track taken up again after the publisher stops is a new subscription.
///
/// The record of what is being pulled has to be cleared when the pull ends, and
/// a relay that kept it would attach every later viewer to an alias nothing
/// arrives on — a black tile that no error explains, and the failure this whole
/// mechanism most plausibly introduces.
#[tokio::test]
async fn a_track_is_pulled_again_after_its_publisher_stops() {
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
    let _first = subscribed.expect("the first subscription is accepted");

    // The publisher ends the subscription by closing the stream it was serving.
    drop(served);
    eventually("the track to be released", &relay, |s| {
        value(s, "moqom_relay_tracks") == 0
    })
    .await;

    let restarted = TrackAlias::from(9_u32);
    let (_served, subscribed) = tokio::join!(
        publisher.answer_subscription(restarted),
        second.subscribe(&video),
    );
    let second_subscription = subscribed.expect("the second subscription is accepted");

    publisher.publish_subgroup(restarted, &[b"back"]).await;
    let (header, payloads) = second.read_subgroup().await;
    assert_eq!(header.track_alias, second_subscription.alias);
    assert_eq!(payloads, vec![bytes::Bytes::from_static(b"back")]);
}

/// The saving has to be visible to whoever is paying for the bandwidth.
///
/// Counting both outcomes as "established" would leave an operator unable to
/// tell a relay that is deduplicating from one that has quietly stopped —
/// identical traffic downstream, and the only difference on a graph they do not
/// have.
#[tokio::test]
async fn sharing_is_counted_apart_from_establishing() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let mut first = Client::connect(&relay).await;
    let mut second = Client::connect(&relay).await;

    let _announcement = publisher.announce(&namespace(&["acme", "room-42"])).await;
    registered(&relay).await;

    let video = track(&["acme", "room-42"], "video");
    let (_served, subscribed) = tokio::join!(
        publisher.answer_subscription(TrackAlias::from(7_u32)),
        first.subscribe(&video),
    );
    let _first = subscribed.expect("subscribed");
    let _second = second.subscribe(&video).await.expect("subscribed");

    let scrape = eventually("the subscriptions to be counted", &relay, |s| {
        series(s, "moqom_relay_subscriptions_total", "outcome", "shared") == 1
    })
    .await;
    assert_eq!(
        series(
            &scrape,
            "moqom_relay_subscriptions_total",
            "outcome",
            "established"
        ),
        1,
        "one of the two opened a subscription upstream"
    );
}
