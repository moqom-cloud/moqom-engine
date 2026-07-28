//! The rate limiter, over a real socket.
//!
//! The unit tests in `quota` prove the arithmetic. What they cannot prove is
//! that the arithmetic is reached: a limiter wired to nothing passes every one
//! of them. These check that a client which asks for too much is actually told
//! so, in a message it can act on, and that the rest of its connection keeps
//! working — which is the property that separates a rate limit from a
//! disconnection.
//!
//! Every client here is unauthenticated and comes from loopback, so they all
//! share one address-tier bucket. That is deliberate: it is both the simplest
//! thing to test and the exact configuration of a relay behind a load balancer
//! that does not preserve the client address.

mod support;

use moqom_proto::control::{FetchKind, RequestErrorCode};
use moqom_proto::model::{FetchEnd, GroupId, Location, TrackAlias};
use moqom_proto::varint::VarInt;
use moqom_relay::quota::{Allowance, Quota, Quotas, Tier};
use support::{Client, Relay, namespace, track, within};

/// Quotas where one resource is scarce and nothing else gets in the way.
fn only(resource: &str, quota: Quota) -> Quotas {
    let open = Quota::new(f64::INFINITY, f64::INFINITY, 0);
    let mut allowance = Allowance {
        session: open,
        subscription: open,
        announcement: open,
        watch: open,
        fetch: open,
    };
    match resource {
        "session" => allowance.session = quota,
        "subscription" => allowance.subscription = quota,
        "announcement" => allowance.announcement = quota,
        "watch" => allowance.watch = quota,
        "fetch" => allowance.fetch = quota,
        other => panic!("no such resource {other}"),
    }
    Quotas {
        device: allowance,
        user: allowance,
        address: allowance,
        principals: 1_000,
    }
}

#[tokio::test]
async fn a_subscription_over_the_limit_is_refused_with_a_retry_after() {
    // Two subscriptions at once, and nothing refills within the test.
    let relay = Relay::governed(only("subscription", Quota::new(0.01, 2.0, 8)));
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

    let one = track(&["acme", "room-42"], "video");
    let two = track(&["acme", "room-42"], "audio");
    let three = track(&["acme", "room-42"], "screen");

    let (first, _) = tokio::join!(
        subscriber.try_subscribe(&one),
        publisher.answer_subscription(TrackAlias::from(1u32)),
    );
    first.expect("the first is within the burst");
    let (second, _) = tokio::join!(
        subscriber.try_subscribe(&two),
        publisher.answer_subscription(TrackAlias::from(2u32)),
    );
    second.expect("the second is within the burst");

    // The third never reaches the publisher, so there is nothing to answer.
    let Err(refused) = subscriber.try_subscribe(&three).await else {
        panic!("the burst is spent, so the third subscription should be refused");
    };

    assert_eq!(refused.code, RequestErrorCode::EXCESSIVE_LOAD);
    // The part a client acts on. A refusal with no retry-after leaves a client
    // to guess, and clients guess by retrying immediately.
    let wait = refused
        .retry_after_ms()
        .expect("a rate limit says when to come back");
    assert!(wait > 0, "retry-after was {wait}ms");
}

#[tokio::test]
async fn a_refusal_leaves_the_rest_of_the_connection_working() {
    let relay = Relay::governed(only("fetch", Quota::new(0.01, 1.0, 4)));
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

    let video = track(&["acme", "room-42"], "video");
    let range = FetchKind::Standalone {
        track: video.clone(),
        start: Location::ZERO,
        end: FetchEnd::EndOfGroup(GroupId::from(1u32))
            .wire()
            .expect("representable"),
    };

    // Spend the fetch allowance. Both of these fail for their own reasons --
    // there is no history -- and what matters is that the second is refused by
    // the limiter rather than by the cache.
    let _ = subscriber.fetch(range.clone()).await;
    let Err(refused) = subscriber.fetch(range).await else {
        panic!("the fetch allowance is spent, so this should be refused");
    };
    assert_eq!(refused, RequestErrorCode::EXCESSIVE_LOAD.get());

    // The session is still usable for everything else, which is the whole point
    // of refusing a request instead of closing a connection: one greedy fetch
    // loop must not take a viewer's video with it.
    let (subscription, _) = tokio::join!(
        subscriber.try_subscribe(&video),
        publisher.answer_subscription(TrackAlias::from(1u32)),
    );
    subscription.expect("subscribing still works");
}

#[tokio::test]
async fn an_announcement_over_the_limit_does_not_reach_the_fabric() {
    let relay = Relay::governed(only("announcement", Quota::new(0.01, 1.0, 1)));
    let mut publisher = Client::connect(&relay).await;

    let first = namespace(&["acme", "room-1"]);
    let _held = publisher.announce(&first).await;
    within("the first announcement to register", async {
        while relay.fabric.namespaces().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await;

    // A refused announcement must not be registered. If it were, a client could
    // hold namespaces it was refused, and the refusal would be advisory -- which
    // is the failure mode where a limit exists in the metrics and nowhere else.
    let _second = publisher.announce(&namespace(&["acme", "room-2"])).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        relay.fabric.namespaces().len(),
        1,
        "the second announcement was registered despite being over the limit"
    );
}

#[tokio::test]
async fn a_released_slot_can_be_taken_again() {
    let relay = Relay::governed(only("announcement", Quota::new(1_000.0, 1_000.0, 1)));
    let mut publisher = Client::connect(&relay).await;

    let first = publisher.announce(&namespace(&["acme", "room-1"])).await;
    within("the first announcement to register", async {
        while relay.fabric.namespaces().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await;

    // Withdrawing ends the stream, which is both how the announcement is
    // withdrawn and how the quota slot is released -- the two are the same
    // event, which is what makes it impossible to leak one without the other.
    first.withdraw();
    within("the withdrawal to land", async {
        while !relay.fabric.namespaces().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await;

    let _second = publisher.announce(&namespace(&["acme", "room-2"])).await;
    within("the second announcement to register", async {
        while relay.fabric.namespaces().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await;
}

#[tokio::test]
async fn a_session_over_the_limit_is_closed_with_a_reason_it_can_act_on() {
    // One session at a time from this address.
    let relay = Relay::governed(only("session", Quota::new(1_000.0, 1_000.0, 1)));
    let _first = Client::connect(&relay).await;

    // Refused before SETUP is answered rather than after. The identity comes out
    // of the peer's own SETUP, so the charge can happen between reading theirs
    // and writing ours -- which means there is never a moment where the relay
    // has said the session is established and then taken it away.
    let closed = Client::try_connect(&relay)
        .await
        .err()
        .expect("the second session is over the limit");

    // A distinct code from an authentication failure, because the client's
    // correct response differs: a rejected credential should stop it trying, and
    // a limit should make it wait. A client that cannot tell them apart
    // reconnects immediately in both cases, which turns a rate limit into a
    // reconnect storm.
    assert_eq!(closed.code, 0x04, "closed with {closed:?}");
    assert!(
        closed.reason.contains("retry_after_ms="),
        "a session-level refusal has nowhere else to put the retry-after: {closed:?}"
    );
}

#[tokio::test]
async fn refusals_are_counted_by_resource_and_tier_and_not_by_identity() {
    let relay = Relay::governed(only("fetch", Quota::new(0.01, 1.0, 4)));
    let mut subscriber = Client::connect(&relay).await;

    let range = FetchKind::Standalone {
        track: track(&["acme", "room-42"], "video"),
        start: Location::ZERO,
        end: FetchEnd::EndOfGroup(GroupId::from(1u32))
            .wire()
            .expect("representable"),
    };
    let _ = subscriber.fetch(range.clone()).await;
    let _ = subscriber.fetch(range).await;

    let scrape = relay.scrape();
    assert!(
        scrape.contains(r#"moqom_relay_requests_refused_total{resource="fetch",tier="address"} 1"#),
        "{scrape}"
    );
    assert!(
        scrape.contains(r#"moqom_relay_refusals_total{reason="too_fast"} 1"#),
        "{scrape}"
    );

    // Never the identity. A label per user is unbounded cardinality that anyone
    // who can connect could grow, and it publishes who is being throttled to
    // everyone who can reach the scrape endpoint.
    assert!(!scrape.contains("127.0.0.1"), "{scrape}");
    assert!(!scrape.contains("username"), "{scrape}");

    // And the tiers that were not the binding constraint stay at zero, so the
    // metric can actually answer "which allowance ran out".
    for tier in [Tier::User, Tier::Device] {
        assert!(
            scrape.contains(&format!(
                r#"moqom_relay_requests_refused_total{{resource="fetch",tier="{}"}} 0"#,
                tier.name()
            )),
            "{scrape}"
        );
    }
}

#[tokio::test]
async fn an_ungoverned_relay_admits_everything() {
    // The default a test or an embedder gets. A library that silently throttles
    // produces failures that look like bugs in the caller, so `Relay::start`
    // must not limit -- and this is the test that would fail if the default ever
    // quietly changed.
    let relay = Relay::start();
    let mut subscriber = Client::connect(&relay).await;

    let range = FetchKind::Standalone {
        track: track(&["acme", "room-42"], "video"),
        start: Location::ZERO,
        end: FetchEnd::EndOfGroup(GroupId::from(1u32))
            .wire()
            .expect("representable"),
    };
    for _ in 0..40 {
        let outcome = subscriber.fetch(range.clone()).await;
        // Refused for want of history, never for want of allowance.
        if let Err(code) = outcome {
            assert_ne!(code, RequestErrorCode::EXCESSIVE_LOAD.get());
        }
    }

    let _ = VarInt::new(0);
}
