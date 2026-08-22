//! What a relay does when it is asked for a track it does not hold.
//!
//! One relay can only serve as many viewers as one machine's network card allows,
//! and no amount of hardware changes that for a single track: every viewer of a
//! track has to be connected to the relay holding its publisher, because that is
//! where the copies come from. An audience larger than one host is therefore not a
//! tuning problem. It needs a second tier.
//!
//! These tests are about an edge relay with a parent. The property is that a viewer
//! cannot tell: it subscribes to a track its own relay has never heard of, and gets
//! the objects. Everything the relay does for a local publisher — one pull however
//! many watchers, the cache, the latency budget — it does for a parent, because the
//! session to a parent is the same code with the handshake the other way round.
//!
//! The second property is that the arrangement cannot run away. Two relays each
//! configured with the other as a parent is a cycle, and neither can see it from its
//! own end, so a subscription carries a budget that only decreases.

mod support;

use moqom_proto::control::params::param_type;
use moqom_proto::model::{GroupId, TrackAlias};
use support::{Client, Relay, namespace, track, value, within};

/// Wait for an announcement to reach the fabric before subscribing to it.
async fn registered(relay: &Relay) {
    within("the announcement to register", async {
        while relay.fabric.namespaces().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await;
}

/// The whole point: a viewer on an edge watches a track published on the origin.
#[tokio::test]
async fn an_edge_serves_a_track_it_does_not_hold() {
    let origin = Relay::start();
    let edge = Relay::start();

    let mut publisher = Client::connect(&origin).await;
    let _announcement = publisher.announce(&namespace(&["acme", "room-42"])).await;
    registered(&origin).await;

    let _link = edge.attach_to(&origin, None).await;

    // Connected to the edge, which holds nothing and has never heard of this
    // namespace. Before there was an upstream this was answered with
    // DOES_NOT_EXIST, and the audience for a track was bounded by one host.
    let video = track(&["acme", "room-42"], "video");
    let mut viewer = Client::connect(&edge).await;

    let upstream = TrackAlias::from(7_u32);
    let (_served, subscribed) = tokio::join!(
        publisher.answer_subscription(upstream),
        viewer.subscribe(&video),
    );
    let _subscription = subscribed.expect("the edge should fetch the track from its parent");

    let payloads: Vec<&[u8]> = vec![b"a frame", b"another"];
    publisher
        .publish_group(upstream, GroupId::from(0_u32), &payloads)
        .await;

    let (_, arrived) = within("the viewer's copy", viewer.read_subgroup()).await;
    assert_eq!(
        arrived.len(),
        payloads.len(),
        "every object should cross both relays"
    );
    assert_eq!(&arrived[0][..], b"a frame");
}

/// The arithmetic that makes tiering worth doing: the origin sees one subscriber
/// however many viewers the edge has, because the edge deduplicates its own pull
/// exactly as it would for a local publisher.
#[tokio::test]
async fn many_viewers_on_an_edge_are_one_subscription_on_the_origin() {
    let origin = Relay::start();
    let edge = Relay::start();

    let mut publisher = Client::connect(&origin).await;
    let _announcement = publisher.announce(&namespace(&["acme", "room-42"])).await;
    registered(&origin).await;
    let _link = edge.attach_to(&origin, None).await;

    let video = track(&["acme", "room-42"], "video");
    let mut first = Client::connect(&edge).await;
    let mut second = Client::connect(&edge).await;
    let mut third = Client::connect(&edge).await;

    let upstream = TrackAlias::from(7_u32);
    let (_served, subscribed) = tokio::join!(
        publisher.answer_subscription(upstream),
        first.subscribe(&video),
    );
    let _first = subscribed.expect("the first viewer");
    let _second = second.subscribe(&video).await.expect("the second viewer");
    let _third = third.subscribe(&video).await.expect("the third viewer");

    // The publisher is asked once. Anything else and a tier would multiply load
    // upwards instead of dividing it, which is the opposite of the purpose.
    assert!(
        publisher
            .answer_subscription_if_asked(TrackAlias::from(8_u32))
            .await
            .is_none(),
        "the edge must not open a second upstream subscription per viewer"
    );

    let payloads: Vec<&[u8]> = vec![b"one frame"];
    publisher
        .publish_group(upstream, GroupId::from(0_u32), &payloads)
        .await;

    for (who, viewer) in [
        ("first", &mut first),
        ("second", &mut second),
        ("third", &mut third),
    ] {
        let (_, arrived) = within("a viewer's copy", viewer.read_subgroup()).await;
        assert_eq!(arrived.len(), 1, "the {who} viewer should get the object");
    }

    // One established pull on the edge, shared by the other two viewers: the same
    // account the relay keeps for a local publisher.
    let scrape = edge.scrape();
    assert_eq!(
        value(
            &scrape,
            r#"moqom_relay_subscriptions_total{outcome="established"}"#
        ),
        1,
        "the edge should establish one upstream subscription"
    );
    assert_eq!(
        value(
            &scrape,
            r#"moqom_relay_subscriptions_total{outcome="shared"}"#
        ),
        2,
        "the other two viewers should share it"
    );
}

/// A track nobody in the fleet publishes is still refused, rather than hanging while
/// an edge waits on a parent that has nothing to give it.
#[tokio::test]
async fn a_track_no_relay_holds_is_refused_through_the_tier() {
    let origin = Relay::start();
    let edge = Relay::start();
    let _link = edge.attach_to(&origin, None).await;

    let mut viewer = Client::connect(&edge).await;
    let missing = track(&["acme", "nobody-here"], "video");
    let Err(refused) = viewer.subscribe(&missing).await else {
        panic!("a track nobody publishes must be refused");
    };

    // The same answer a single relay gives, which is what makes an edge safe to put
    // in front of clients that know nothing about the topology.
    assert_eq!(refused, 0x10, "DOES_NOT_EXIST, as from one relay alone");
}

/// A subscription that has run out of hops is not forwarded, which is what stops a
/// misconfigured cycle of relays asking each other indefinitely.
#[tokio::test]
async fn a_subscription_out_of_hops_is_not_forwarded_again() {
    let origin = Relay::start();
    let edge = Relay::start();
    let _link = edge.attach_to(&origin, None).await;

    let mut viewer = Client::connect(&edge).await;
    let video = track(&["acme", "room-42"], "video");

    // What a child relay's own forwarding looks like once the budget is spent. A
    // viewer never sends this; a relay in a chain does, and the last one in the
    // chain has to stop rather than pass it on.
    let Err(refused) = viewer
        .subscribe_with(&video, &[(param_type::RELAY_HOPS, 0)])
        .await
    else {
        panic!("an exhausted budget must not be forwarded");
    };
    assert_eq!(refused, 0x10, "DOES_NOT_EXIST rather than another hop");
}

/// A parent named rather than addressed is reached whichever family answers.
///
/// The bug this pins down cost an afternoon and looked nothing like itself. A parent
/// given as `localhost:4433` resolved to the IPv6 loopback while the parent listened
/// on IPv4, and because the dialler took the first address and kept it, every attempt
/// timed out. The symptom appeared at the viewers as a track that did not exist, and
/// the tier looked broken in the forwarding path that was in fact correct.
///
/// So: dial by a name, and require the link to come up. On a host whose resolver
/// returns only one address this is a weaker test than on one that returns both, and
/// it costs nothing either way.
#[tokio::test]
async fn a_parent_named_rather_than_addressed_is_still_reached() {
    let origin = Relay::start();
    let edge = Relay::start();

    let mut publisher = Client::connect(&origin).await;
    let _announcement = publisher.announce(&namespace(&["acme", "room-42"])).await;
    registered(&origin).await;

    let _link = edge.attach_by_name("localhost", &origin).await;

    let video = track(&["acme", "room-42"], "video");
    let mut viewer = Client::connect(&edge).await;
    let (_served, subscribed) = tokio::join!(
        publisher.answer_subscription(TrackAlias::from(7_u32)),
        viewer.subscribe(&video),
    );
    subscribed.expect("a parent reached by name serves the track");
}

/// Being a relay is not a way past the door.
///
/// The dialled handshake is a second entrance to a relay, and the thing to be sure
/// of is that it is not a quieter one: an edge presenting a credential that does not
/// verify has to be turned away exactly as a phone presenting the same one would be.
/// A parent that trusted its peers because they claimed to be relays would be an open
/// proxy onto every track in the fleet, reachable by anybody who could dial it.
#[tokio::test]
async fn a_parent_refuses_an_edge_whose_credential_does_not_verify() {
    let origin = Relay::authenticating();
    let edge = Relay::start();

    let outcome = edge
        .try_attach_to(&origin, Some("not.a.token"))
        .await
        .expect_err("a parent must refuse a credential that does not verify");
    assert!(
        outcome.contains("refused") || outcome.contains("closed"),
        "the refusal should say the parent ended it: {outcome}"
    );
    assert!(
        edge.fabric.upstream().is_none(),
        "a refused link must not be left registered as a parent"
    );
}

/// And an edge that presents nothing is anonymous rather than privileged.
///
/// A parent holding keys admits an unauthenticated peer — that is deliberate and
/// predates any of this — but it admits it as nobody, with whatever an anonymous
/// session is allowed. What must not happen is a dialled session inheriting more
/// than that by virtue of which end opened it, so this checks the permission is
/// applied: the anonymous edge cannot read a namespace it has no claim to.
#[tokio::test]
async fn an_anonymous_edge_gets_no_more_than_an_anonymous_client() {
    let origin = Relay::authenticating();
    let edge = Relay::start();
    let _link = edge.attach_to(&origin, None).await;

    let mut viewer = Client::connect(&edge).await;
    let video = track(&["acme", "r", "room-42", "ada", "device"], "video");
    let Err(refused) = viewer.subscribe(&video).await else {
        panic!("an anonymous edge must not be able to read an authorised namespace");
    };
    // Whichever the parent answers, it must not be a subscription: the edge asked
    // upstream, was told no, and passed that on rather than inventing an answer.
    assert!(
        refused == 0x01 || refused == 0x10,
        "expected unauthorized or does-not-exist, got {refused:#x}"
    );
}
