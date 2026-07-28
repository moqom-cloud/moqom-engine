//! What the relay reports about itself, measured against a real socket.
//!
//! The unit tests in `metrics` prove the arithmetic and the ones in `admin` prove
//! the exposition parses. Neither can prove the *call sites* are right, and that
//! is where instrumentation actually goes wrong: a counter incremented on the
//! wrong branch, a gauge that never comes back down, a session that stays in the
//! live set after its connection has gone. Those only show up with a peer on the
//! other end of a wire.
//!
//! So every assertion here is driven by real traffic and read back through the
//! same endpoint a scraper would use.

mod support;

use moqom_proto::control::FetchKind;
use moqom_proto::model::{FetchEnd, GroupId, Location, ObjectId, TrackAlias};
use support::{Client, Relay, namespace, track, within};

/// The value of a single unlabelled metric in an exposition.
fn value(scrape: &str, metric: &str) -> u64 {
    for line in scrape.lines() {
        if let Some(rest) = line.strip_prefix(metric) {
            // Guard against a prefix match: `moqom_relay_sessions` must not read
            // `moqom_relay_sessions_accepted_total`.
            if let Some(number) = rest.strip_prefix(' ') {
                return number.trim().parse().expect("a metric value");
            }
        }
    }
    panic!("no metric {metric} in:\n{scrape}");
}

/// The value of one series of a labelled metric.
fn series(scrape: &str, metric: &str, label: &str, label_value: &str) -> u64 {
    let needle = format!("{metric}{{{label}=\"{label_value}\"}} ");
    for line in scrape.lines() {
        if let Some(number) = line.strip_prefix(&needle) {
            return number.trim().parse().expect("a metric value");
        }
    }
    panic!("no series {needle} in:\n{scrape}");
}

/// Poll until `check` passes, so a test does not race the relay's bookkeeping.
async fn eventually(what: &str, relay: &Relay, check: impl Fn(&str) -> bool) -> String {
    within(what, async {
        loop {
            let scrape = relay.scrape();
            if check(&scrape) {
                return scrape;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
}

/// The `/tracks` body a diagnostic request would return right now.
fn tracks(relay: &Relay) -> String {
    relay.surface.respond("/tracks").body
}

/// Wait for an announcement to reach the fabric before asserting on it.
async fn registered(relay: &Relay) {
    within("the announcement to register", async {
        while relay.fabric.namespaces().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await;
}

#[tokio::test]
async fn a_connected_session_is_counted_and_described() {
    let relay = Relay::start();
    let client = Client::connect(&relay).await;

    let scrape = eventually("the session to be counted", &relay, |s| {
        value(s, "moqom_relay_sessions") == 1
    })
    .await;
    assert_eq!(
        series(
            &scrape,
            "moqom_relay_sessions_accepted_total",
            "carrier",
            "quic"
        ),
        1
    );
    assert_eq!(
        series(
            &scrape,
            "moqom_relay_sessions_accepted_total",
            "carrier",
            "webtransport"
        ),
        0
    );

    // The diagnostic endpoint is where the unbounded detail lives, and the peer
    // address is the only identity an unauthenticated relay has.
    let sessions = relay.surface.respond("/sessions").body;
    assert!(sessions.contains(r#""carrier":"quic""#), "{sessions}");
    assert!(sessions.contains("127.0.0.1:"), "{sessions}");
    assert!(sessions.contains(r#""count":1"#), "{sessions}");

    drop(client);
}

/// The gauge that would otherwise leak. A session removed from the live set only
/// on the happy path leaves a relay that reports thousands of connections it does
/// not have, and there is no way to tell that from real load.
#[tokio::test]
async fn a_disconnected_session_leaves_the_live_set() {
    let relay = Relay::start();
    let client = Client::connect(&relay).await;
    eventually("the session to appear", &relay, |s| {
        value(s, "moqom_relay_sessions") == 1
    })
    .await;

    drop(client);

    let scrape = eventually("the session to be reaped", &relay, |s| {
        value(s, "moqom_relay_sessions") == 0
    })
    .await;

    // Which reason it ended with depends on whether the client's close capsule
    // arrived before its connection went away, and both are honest answers. That
    // it was classified at all is the property worth asserting.
    let clean = series(
        &scrape,
        "moqom_relay_sessions_ended_total",
        "reason",
        "clean",
    );
    let transport = series(
        &scrape,
        "moqom_relay_sessions_ended_total",
        "reason",
        "transport",
    );
    assert_eq!(clean + transport, 1, "exactly one session ended: {scrape}");
    assert_eq!(
        series(
            &scrape,
            "moqom_relay_sessions_ended_total",
            "reason",
            "protocol"
        ),
        0,
        "a client that simply disconnects has not violated anything"
    );
    assert_eq!(
        value(&scrape, "moqom_relay_session_duration_seconds_count"),
        1
    );

    let sessions = relay.surface.respond("/sessions").body;
    assert!(sessions.contains(r#""count":0"#), "{sessions}");
}

/// Fan-out amplification, which is the number a relay exists to produce. One copy
/// in, two copies out: an egress counter that matched ingress would mean the
/// per-destination write was being counted once for the whole loop.
#[tokio::test]
async fn egress_exceeds_ingress_by_the_fan_out_ratio() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let mut first = Client::connect(&relay).await;
    let mut second = Client::connect(&relay).await;

    let _announcement = publisher.announce(&namespace(&["acme", "room-42"])).await;
    registered(&relay).await;

    let video = track(&["acme", "room-42"], "video");
    let upstream = TrackAlias::from(7_u32);
    let (_served_a, one) = tokio::join!(
        publisher.answer_subscription(upstream),
        first.subscribe(&video),
    );
    let (_served_b, two) = tokio::join!(
        publisher.answer_subscription(upstream),
        second.subscribe(&video),
    );
    let _one = one.expect("subscribed");
    let _two = two.expect("subscribed");

    publisher
        .publish_subgroup(upstream, &[b"shared payload"])
        .await;
    first.read_subgroup().await;
    second.read_subgroup().await;

    let scrape = eventually("the bytes to be accounted", &relay, |s| {
        value(s, "moqom_relay_ingress_bytes_total") > 0
            && value(s, "moqom_relay_egress_bytes_total") > 0
    })
    .await;

    let ingress = value(&scrape, "moqom_relay_ingress_bytes_total");
    let egress = value(&scrape, "moqom_relay_egress_bytes_total");
    assert_eq!(
        egress,
        ingress * 2,
        "one subgroup to two subscribers is twice the bytes out"
    );
    assert_eq!(
        series(
            &scrape,
            "moqom_relay_subgroups_total",
            "disposition",
            "forwarded"
        ),
        1
    );
    assert_eq!(
        series(
            &scrape,
            "moqom_relay_subgroups_total",
            "disposition",
            "dropped"
        ),
        0
    );
    assert_eq!(
        series(
            &scrape,
            "moqom_relay_subscriptions_total",
            "outcome",
            "established"
        ),
        2
    );
}

/// The case no transport signal can reach: the publisher is connected, the
/// connection is healthy, and the media has stopped.
///
/// This is the whole justification for tracking silence per track. Everything
/// else the relay reports about that publisher looks correct, because it *is*
/// correct — the session is live, the RTT is fine, the announcement stands — and
/// a viewer is looking at a frozen picture. So the assertions here are as much
/// about what stays healthy as about what goes stale.
#[tokio::test]
async fn a_publisher_that_stops_sending_shows_up_as_a_silent_track() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let mut subscriber = Client::connect(&relay).await;

    let _announcement = publisher.announce(&namespace(&["acme", "room-42"])).await;
    registered(&relay).await;

    let video = track(&["acme", "room-42"], "video");
    let upstream = TrackAlias::from(7_u32);
    let (_served, feed) = tokio::join!(
        publisher.answer_subscription(upstream),
        subscriber.subscribe(&video),
    );
    let _feed = feed.expect("subscribed");

    // Nothing has been published yet, so the track exists and has carried
    // nothing. That must already read as silent: a publisher that never starts
    // is the same problem as one that stops, and wants the same alert.
    let scrape = eventually("the track to be counted", &relay, |s| {
        value(s, "moqom_relay_tracks") == 1
    })
    .await;
    for bound in ["1", "5", "30"] {
        assert_eq!(
            series(&scrape, "moqom_relay_tracks_silent", "ge", bound),
            0,
            "nothing has been silent for {bound}s yet"
        );
    }

    let before = tracks(&relay);
    assert!(
        before.contains(r#""carried":false"#),
        "a track that has carried nothing says so: {before}"
    );

    publisher
        .publish_subgroup(upstream, &[b"a frame, and then nothing"])
        .await;
    subscriber.read_subgroup().await;

    // Silence resets on arrival, which is the half that would make the gauge
    // useless if it were wrong: without it every busy track reads as stalled.
    let flowing = within("the track to report bytes", async {
        loop {
            let body = tracks(&relay);
            if body.contains(r#""carried":true"#) {
                return body;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(flowing.contains(r#""name":"video""#), "{flowing}");
    assert!(flowing.contains(r#""subgroups":1"#), "{flowing}");

    // And now the publisher simply stops. No withdrawal, no disconnect: it holds
    // the connection open and sends nothing, which is what a frozen camera does.
    let quiet = within("the silence to be measurable", async {
        loop {
            let body = tracks(&relay);
            if !body.contains(r#""silent_ms":0"#) {
                return body;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;

    // The session is still perfectly healthy, which is exactly why the track
    // needed its own signal.
    let scrape = relay.scrape();
    assert_eq!(value(&scrape, "moqom_relay_sessions"), 2);
    assert_eq!(
        series(
            &scrape,
            "moqom_relay_sessions_ended_total",
            "reason",
            "clean"
        ),
        0,
        "nobody has gone anywhere: {quiet}"
    );
}

/// The other direction: the row goes when the pull does, rather than
/// accumulating into a list of tracks that stopped hours ago.
///
/// It matters more than tidiness. A row that never leaves is permanently and
/// increasingly silent, so the gauge these feed climbs on its own — and a gauge
/// that reports stalled publishers where there are none is worse than no gauge,
/// because the alert built on it gets muted.
#[tokio::test]
async fn a_track_stops_being_reported_when_the_pull_ends() {
    let relay = Relay::start();
    let mut publisher = Client::connect(&relay).await;
    let mut subscriber = Client::connect(&relay).await;

    let _announcement = publisher.announce(&namespace(&["acme", "room-42"])).await;
    registered(&relay).await;

    let video = track(&["acme", "room-42"], "video");
    let upstream = TrackAlias::from(7_u32);
    let (served, feed) = tokio::join!(
        publisher.answer_subscription(upstream),
        subscriber.subscribe(&video),
    );
    let _feed = feed.expect("subscribed");

    eventually("the track to be counted", &relay, |s| {
        value(s, "moqom_relay_tracks") == 1
    })
    .await;

    // The publisher ends the subscription it was serving, which closes the
    // stream the relay was pulling on.
    drop(served);

    let scrape = eventually("the track to be released", &relay, |s| {
        value(s, "moqom_relay_tracks") == 0
    })
    .await;
    assert_eq!(value(&scrape, "moqom_relay_tracks"), 0);
    let body = tracks(&relay);
    assert!(body.contains(r#""count":0"#), "{body}");
}

/// A subgroup nobody wants is a different event from one that was forwarded, and
/// collapsing the two hides a publisher broadcasting into an empty room — which
/// is bandwidth being paid for and not used.
#[tokio::test]
async fn a_subgroup_with_no_subscribers_is_counted_as_dropped() {
    // Retention off, so nothing keeps the stream alive for the cache's sake.
    let relay = Relay::retaining(moqom_relay::Limits::none());
    let mut publisher = Client::connect(&relay).await;
    let _announcement = publisher.announce(&namespace(&["acme", "room-42"])).await;
    registered(&relay).await;

    publisher
        .publish_subgroup(TrackAlias::from(3_u32), &[b"into the void"])
        .await;

    let scrape = eventually("the drop to be counted", &relay, |s| {
        series(s, "moqom_relay_subgroups_total", "disposition", "dropped") == 1
    })
    .await;
    assert_eq!(
        series(
            &scrape,
            "moqom_relay_subgroups_total",
            "disposition",
            "forwarded"
        ),
        0
    );
    assert_eq!(value(&scrape, "moqom_relay_egress_bytes_total"), 0);
}

/// Outcomes have to be separable. "Subscriptions are failing" and "subscriptions
/// are failing because nothing is publishing" are different incidents with
/// different responders.
#[tokio::test]
async fn a_subscription_with_no_publisher_is_counted_apart_from_a_refusal() {
    let relay = Relay::start();
    let mut subscriber = Client::connect(&relay).await;

    let result = subscriber
        .subscribe(&track(&["acme", "nothing"], "video"))
        .await;
    assert!(result.is_err(), "there is no publisher");

    let scrape = eventually("the refusal to be counted", &relay, |s| {
        series(
            s,
            "moqom_relay_subscriptions_total",
            "outcome",
            "no_publisher",
        ) == 1
    })
    .await;
    assert_eq!(
        series(
            &scrape,
            "moqom_relay_subscriptions_total",
            "outcome",
            "established"
        ),
        0
    );
    assert_eq!(
        series(
            &scrape,
            "moqom_relay_subscriptions_total",
            "outcome",
            "refused"
        ),
        0
    );
}

#[tokio::test]
async fn fetch_outcomes_are_counted_separately() {
    let relay = Relay::start();
    let mut client = Client::connect(&relay).await;

    // A track nothing has ever published cannot be resolved at all.
    let refused = client
        .fetch(FetchKind::Standalone {
            track: track(&["acme", "ghost"], "video"),
            start: Location::new(GroupId::ZERO, ObjectId::ZERO),
            end: FetchEnd::EndOfGroup(GroupId::ZERO)
                .wire()
                .expect("representable"),
        })
        .await;
    assert!(refused.is_err(), "there is no history for that track");

    let scrape = eventually("the fetch to be counted", &relay, |s| {
        series(s, "moqom_relay_fetches_total", "outcome", "no_history") == 1
    })
    .await;
    assert_eq!(
        series(&scrape, "moqom_relay_fetches_total", "outcome", "served"),
        0
    );
    assert_eq!(value(&scrape, "moqom_relay_fetch_records_total"), 0);
}

/// Room occupancy from namespaces alone. Nothing asks a client what room it is
/// in, because the client whose connection is under investigation is the last
/// party whose account of it should be trusted.
#[tokio::test]
async fn rooms_and_participants_are_derived_from_what_is_announced() {
    let relay = Relay::start();
    let mut host = Client::connect(&relay).await;
    let mut guest = Client::connect(&relay).await;
    let mut waiting = Client::connect(&relay).await;

    let _a = host
        .announce(&namespace(&["acme", "r", "room-42", "ada", "phone"]))
        .await;
    let _b = guest
        .announce(&namespace(&["acme", "r", "room-42", "grace", "mac"]))
        .await;
    // Backstage is a separate namespace family so viewers cannot reach it, but
    // the same room.
    let _c = waiting
        .announce(&namespace(&["acme", "bs", "room-42", "alan", "phone"]))
        .await;

    let scrape = eventually("the room to fill", &relay, |s| {
        value(s, "moqom_relay_participants") == 3
    })
    .await;
    assert_eq!(value(&scrape, "moqom_relay_rooms"), 1, "{scrape}");
    assert_eq!(value(&scrape, "moqom_relay_namespaces"), 3);
    assert_eq!(value(&scrape, "moqom_relay_announcements_total"), 3);

    let rooms = relay.surface.respond("/rooms").body;
    assert!(rooms.contains(r#""room":"room-42""#), "{rooms}");
    assert!(rooms.contains(r#""username":"ada""#), "{rooms}");
    assert!(rooms.contains(r#""stage":"backstage""#), "{rooms}");
    assert!(
        rooms.contains(r#""count":3"#),
        "three participants: {rooms}"
    );
}

/// A withdrawn announcement has to empty the room, or occupancy only ever grows.
#[tokio::test]
async fn a_room_empties_when_its_publishers_leave() {
    let relay = Relay::start();
    let mut host = Client::connect(&relay).await;
    let announcement = host
        .announce(&namespace(&["acme", "r", "room-42", "ada", "phone"]))
        .await;

    eventually("the room to fill", &relay, |s| {
        value(s, "moqom_relay_rooms") == 1
    })
    .await;

    // Dropping the stream withdraws the announcement, which is the protocol's
    // own mechanism rather than a convenience of the harness.
    drop(announcement);

    let scrape = eventually("the room to empty", &relay, |s| {
        value(s, "moqom_relay_rooms") == 0
    })
    .await;
    assert_eq!(value(&scrape, "moqom_relay_participants"), 0);
    assert_eq!(
        value(&scrape, "moqom_relay_announcements_total"),
        1,
        "the counter of announcements ever made does not go down"
    );
}

/// The sampler, which is the one piece that cannot be checked without letting
/// time pass: it reads the live QUIC connection rather than being told anything.
/// A wrong `Deref` target here would compile and report zero forever.
#[tokio::test]
async fn connection_quality_is_sampled_from_the_live_transport() {
    let relay = Relay::start();
    let _client = Client::connect(&relay).await;

    // One sample interval, plus room for a loaded machine. This is the slowest
    // test in the suite by design; the alternative is not testing the sampler.
    let scrape = eventually("an RTT sample", &relay, |s| {
        value(s, "moqom_relay_connection_rtt_seconds_count") > 0
    })
    .await;

    assert!(
        value(&scrape, "moqom_relay_udp_rx_bytes_total") > 0,
        "a handshake moved bytes: {scrape}"
    );

    let sessions = relay.surface.respond("/sessions").body;
    assert!(
        !sessions.contains(r#""rtt_ms":0.0"#),
        "a loopback RTT is small but not zero: {sessions}"
    );
    assert!(
        !sessions.contains(r#""mtu":0"#),
        "the path has an MTU: {sessions}"
    );
    assert!(
        !sessions.contains(r#""cwnd_bytes":0"#),
        "a live connection has a congestion window: {sessions}"
    );
}

/// Health and readiness answer different questions, and conflating them makes a
/// drain either impossible or indistinguishable from a crash.
#[tokio::test]
async fn readiness_drops_before_liveness_on_a_drain() {
    let relay = Relay::start();
    assert_eq!(relay.surface.respond("/healthz").status, 200);
    assert_eq!(relay.surface.respond("/readyz").status, 200);

    relay.surface.draining();
    assert_eq!(relay.surface.respond("/readyz").status, 503);
    assert_eq!(
        relay.surface.respond("/healthz").status,
        200,
        "a draining relay is still serving the sessions it has"
    );
}
