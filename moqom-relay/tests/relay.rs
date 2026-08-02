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

use moqom_proto::control::{DoneReason, FetchKind};
use moqom_proto::data::FetchRecord;
use moqom_proto::model::{FetchEnd, GroupId, Location, ObjectId, TrackAlias};
use moqom_proto::varint::VarInt;
use moqom_relay::Limits;
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

    // `Stopped`, because the publisher chose to. This is the distinction a bare
    // draft-19 `NAMESPACE_DONE` cannot carry, and the reason for the extension:
    // a subscriber that cannot tell this from a dropped connection has to guess
    // whether to hold the publisher's place open, and will be wrong half the
    // time. See the next test for the other half.
    assert_eq!(
        watch.next().await,
        Announced::Gone(room, Some(DoneReason::Stopped))
    );
}

/// The other half: a publisher whose session dies without withdrawing anything.
///
/// Identical on the wire to the test above in draft-19 — same message, same
/// suffix — and the whole point of the reason is that it no longer is.
#[tokio::test]
async fn a_vanished_publisher_is_reported_as_vanished() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let mut subscriber = Client::connect(&relay).await;

    let room = namespace(&["acme", "room-42"]);
    let announcement = publisher.announce(&room).await;
    let mut watch = subscriber.watch(&namespace(&["acme"])).await;
    assert_eq!(watch.next().await, Announced::Available(room.clone()));

    // Gone without a word: the connection disappears rather than the
    // announcement stream closing. Leaked deliberately, because dropping it
    // would close the stream cleanly and produce `Stopped` — which is exactly
    // the confusion under test.
    std::mem::forget(announcement);
    publisher.vanish();

    assert_eq!(
        watch.next().await,
        Announced::Gone(room, Some(DoneReason::Vanished))
    );
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

    // One upstream SUBSCRIBE serves both: the publisher is asked once, and the
    // second subscriber joins what the first started.
    let (served, one) = tokio::join!(
        publisher.answer_subscription(upstream),
        first.subscribe(&video),
    );
    let two = second.subscribe(&video).await;
    let one = one.expect("the first subscription is accepted");
    let two = two.expect("the second subscription is accepted");
    assert_eq!(served.track, video);

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

// MARK: - Retained history

/// A publisher, a subscriber pulling its track, and some groups already gone by.
///
/// Returned in a struct because every history test needs all of it alive: drop
/// the announcement and the namespace goes, drop the subscription and the relay
/// stops pulling.
struct Broadcast {
    relay: Relay,
    publisher: Client,
    subscriber: Client,
    track: moqom_proto::model::FullTrackName,
    subscription: support::Subscription,
    _announcement: support::Announcement,
    /// The publisher's side of the relay's upstream subscription. Held because
    /// dropping it resets that request stream, which the relay reads as a
    /// cancellation and answers by tearing down the route.
    _served: support::Served,
}

/// Set up a broadcast and publish `groups` groups of two objects each.
///
/// The subscriber exists because the relay only pulls a track somebody has
/// subscribed to — with no subscriber there is no upstream subscription, no
/// forwarded objects, and so nothing to retain.
///
/// Boxed rather than `async fn` because the body holds two clients, each with a
/// QUIC endpoint, and inlining that into every caller's future makes each test a
/// twenty-kilobyte stack frame.
fn broadcast(relay: Relay, groups: u32) -> impl Future<Output = Broadcast> {
    Box::pin(setup(relay, groups))
}

async fn setup(relay: Relay, groups: u32) -> Broadcast {
    let mut publisher = Client::connect(&relay).await;
    let mut subscriber = Client::connect(&relay).await;

    let room = namespace(&["acme", "room-42"]);
    let announcement = publisher.announce(&room).await;
    within("the announcement to register", async {
        while relay.fabric.namespaces().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await;

    let video = track(&["acme", "room-42"], "video");
    let upstream = TrackAlias::from(7_u32);
    let (served, subscription) = tokio::join!(
        publisher.answer_subscription(upstream),
        subscriber.subscribe(&video),
    );
    let subscription = subscription.expect("the relay accepts the subscription");

    for group in 0..groups {
        publisher
            .publish_group(
                upstream,
                GroupId::from(group),
                &[
                    format!("g{group}o0").as_bytes(),
                    format!("g{group}o1").as_bytes(),
                ],
            )
            .await;
        // Read it downstream before publishing the next, so the relay has
        // finished parsing this group into the cache. Without this the test races
        // its own setup.
        let (_header, payloads) = subscriber.read_subgroup().await;
        assert_eq!(payloads.len(), 2, "group {group} should have forwarded");
    }

    Broadcast {
        relay,
        publisher,
        subscriber,
        track: video,
        subscription,
        _announcement: announcement,
        _served: served,
    }
}

fn location(group: u32, object: u32) -> Location {
    Location::new(GroupId::from(group), ObjectId::from(object))
}

/// The end-to-end version of the whole feature: objects that already went by are
/// fetchable from the relay, not just from the publisher.
///
/// The publisher here never answers a fetch — the harness has no code for it — so
/// a passing test can only mean the relay answered from its own history.
#[tokio::test]
async fn a_fetch_is_answered_from_retained_history() {
    let mut show = broadcast(Relay::start(), 3).await;

    let fetched = show
        .subscriber
        .fetch(FetchKind::Standalone {
            track: show.track.clone(),
            start: location(1, 0),
            end: FetchEnd::EndOfGroup(GroupId::from(1u32))
                .wire()
                .expect("representable"),
        })
        .await
        .expect("the relay serves the range");

    assert_eq!(
        fetched.payloads(),
        vec![
            bytes::Bytes::from_static(b"g1o0"),
            bytes::Bytes::from_static(b"g1o1")
        ]
    );
    assert_eq!(fetched.locations(), vec![location(1, 0), location(1, 1)]);
    // The reported end is the last object delivered plus one, which is what lets
    // a client tell a clipped range from a complete one.
    assert_eq!(fetched.end, location(1, 2));
}

/// A fetch spanning several groups comes back as one stream, in order.
#[tokio::test]
async fn a_fetch_can_span_groups() {
    let mut show = broadcast(Relay::start(), 3).await;

    let fetched = show
        .subscriber
        .fetch(FetchKind::Standalone {
            track: show.track.clone(),
            start: Location::ZERO,
            end: FetchEnd::EndOfGroup(GroupId::from(2u32))
                .wire()
                .expect("representable"),
        })
        .await
        .expect("the relay serves the range");

    assert_eq!(fetched.payloads().len(), 6);
    assert_eq!(
        fetched.locations(),
        vec![
            location(0, 0),
            location(0, 1),
            location(1, 0),
            location(1, 1),
            location(2, 0),
            location(2, 1),
        ],
        "groups ascend and objects ascend within them"
    );
}

/// The reconnection case, which is what all of this is for: a client that was
/// away asks for everything since where it stopped and gets what is still held.
#[tokio::test]
async fn a_client_that_missed_objects_can_ask_for_them() {
    // Deliberately tighter than the broadcast, so the answer has to be clipped
    // to retention rather than to the request.
    let relay = Relay::retaining(Limits {
        groups_per_track: 2,
        ..Limits::default()
    });
    let mut show = broadcast(relay, 4).await;

    let fetched = show
        .subscriber
        .fetch(FetchKind::Standalone {
            track: show.track.clone(),
            // From the start of the broadcast, most of which is long gone.
            start: Location::ZERO,
            end: FetchEnd::EndOfGroup(GroupId::from(3u32))
                .wire()
                .expect("representable"),
        })
        .await
        .expect("the relay serves what it still has");

    assert_eq!(
        fetched.locations(),
        vec![
            location(2, 0),
            location(2, 1),
            location(3, 0),
            location(3, 1),
        ],
        "the answer starts where retention does, not where the client asked"
    );
    // And it says so: the end reported is the end delivered, so a client can see
    // its request was clipped rather than assume it received everything.
    assert_eq!(fetched.end, location(3, 2));
}

/// A joining fetch names a subscription rather than a track, and the relay
/// derives the range from it. This is what a client actually sends on subscribing:
/// it is the warm start that makes a joined stream show a picture immediately.
#[tokio::test]
async fn a_joining_fetch_resolves_its_subscription() {
    let mut show = broadcast(Relay::start(), 3).await;

    let fetched = show
        .subscriber
        .fetch(FetchKind::RelativeJoining {
            request_id: show.subscription.request_id,
            preceding_groups: VarInt::from(1u32),
        })
        .await
        .expect("the relay resolves the subscription");

    // One group back from the live edge, through the edge itself.
    assert_eq!(
        fetched.locations(),
        vec![
            location(1, 0),
            location(1, 1),
            location(2, 0),
            location(2, 1),
        ]
    );
}

/// A joining fetch naming a subscription that does not exist is refused rather
/// than answered from whatever track happened to be handy.
#[tokio::test]
async fn a_joining_fetch_for_an_unknown_subscription_is_refused() {
    let mut show = broadcast(Relay::start(), 2).await;

    let outcome = show
        .subscriber
        .fetch(FetchKind::RelativeJoining {
            // A client-allocated ID this session never used for a subscription.
            request_id: moqom_proto::control::RequestId::new(4242).unwrap(),
            preceding_groups: VarInt::from(1u32),
        })
        .await;

    assert_eq!(
        outcome.err(),
        Some(moqom_proto::control::RequestErrorCode::DOES_NOT_EXIST.get())
    );
}

/// A range the relay holds nothing for is refused, not answered with an empty
/// stream. An empty stream reads as "these objects do not exist", which would
/// stop a client asking anyone who does have them.
#[tokio::test]
async fn a_range_with_no_history_is_refused() {
    let mut show = broadcast(Relay::start(), 2).await;

    let outcome = show
        .subscriber
        .fetch(FetchKind::Standalone {
            track: show.track.clone(),
            start: location(900, 0),
            end: FetchEnd::EndOfGroup(GroupId::from(901u32))
                .wire()
                .expect("representable"),
        })
        .await;

    assert_eq!(
        outcome.err(),
        Some(moqom_proto::control::RequestErrorCode::DOES_NOT_EXIST.get())
    );
}

/// A fetch for a track nobody ever published is refused.
#[tokio::test]
async fn a_fetch_for_an_unknown_track_is_refused() {
    let relay = Relay::start();
    let mut client = Client::connect(&relay).await;

    let outcome = client
        .fetch(FetchKind::Standalone {
            track: track(&["acme", "nothing"], "video"),
            start: Location::ZERO,
            end: FetchEnd::EndOfGroup(GroupId::ZERO)
                .wire()
                .expect("representable"),
        })
        .await;

    assert_eq!(
        outcome.err(),
        Some(moqom_proto::control::RequestErrorCode::DOES_NOT_EXIST.get())
    );
}

/// Retention is bounded, and the bound is enforced on the real path rather than
/// only in the cache's own tests.
#[tokio::test]
async fn retention_is_bounded_on_the_wire() {
    let relay = Relay::retaining(Limits {
        groups_per_track: 2,
        ..Limits::default()
    });
    let show = broadcast(relay, 5).await;

    let stats = show.relay.fabric.cache().stats();
    assert_eq!(stats.groups, 2, "only the last two groups are kept");
    assert_eq!(stats.objects, 4);
}

/// A relay configured to retain nothing refuses every fetch, and forwarding still
/// works. Operators who cannot store media at all need this to be a supported
/// configuration rather than a broken one.
#[tokio::test]
async fn a_relay_can_retain_nothing() {
    let relay = Relay::retaining(Limits::none());
    let mut show = broadcast(relay, 2).await;

    assert_eq!(show.relay.fabric.cache().stats().objects, 0);
    let outcome = show
        .subscriber
        .fetch(FetchKind::Standalone {
            track: show.track.clone(),
            start: Location::ZERO,
            end: FetchEnd::EndOfGroup(GroupId::from(1u32))
                .wire()
                .expect("representable"),
        })
        .await;
    assert!(outcome.is_err(), "nothing was retained to serve");
}

/// A hole in what the relay holds comes back as a marker saying so, rather than
/// as a stream that quietly skips it. The distinction is what tells a client
/// whether to ask somebody else.
#[tokio::test]
async fn a_gap_is_reported_rather_than_skipped() {
    let mut show = broadcast(Relay::start(), 1).await;

    // A second subgroup in the same group, with a hole where objects 2 and 3
    // would be. Published directly rather than through the helper because the
    // helper always starts at object zero.
    let upstream = TrackAlias::from(7_u32);
    show.publisher
        .publish_objects(upstream, GroupId::ZERO, &[(4, b"late")])
        .await;
    let (_header, payloads) = show.subscriber.read_subgroup().await;
    assert_eq!(payloads.len(), 1);

    let fetched = show
        .subscriber
        .fetch(FetchKind::Standalone {
            track: show.track.clone(),
            start: Location::ZERO,
            end: FetchEnd::EndOfGroup(GroupId::ZERO)
                .wire()
                .expect("representable"),
        })
        .await
        .expect("the relay serves what it has");

    assert!(
        fetched
            .records
            .iter()
            .any(|record| matches!(record, FetchRecord::EndOfUnknownRange(_))),
        "expected a gap marker covering the missing objects, got {:?}",
        fetched.records
    );
    assert_eq!(
        fetched.payloads(),
        vec![
            bytes::Bytes::from_static(b"g0o0"),
            bytes::Bytes::from_static(b"g0o1"),
            bytes::Bytes::from_static(b"late"),
        ]
    );
}
