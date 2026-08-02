//! What a token permits, over a real socket.
//!
//! The policy itself is unit tested in `scope.rs`, exhaustively and in
//! microseconds. What cannot be tested there is whether the relay ever asks:
//! every check here would still pass with the calls removed from `session.rs`,
//! and a permission system that is never consulted is the failure this file
//! exists to catch.
//!
//! So each test is written against an effect rather than an answer. An
//! announcement that should have been refused is checked by having somebody
//! else fail to find it, because a relay that answered "no" and registered the
//! namespace anyway has done the damage regardless of what it said.

mod support;

use moqom_proto::control::FetchKind;
use moqom_proto::model::{FetchEnd, GroupId, Location, TrackNamespace};
use support::tokens::{DEVICE, Grant};
use support::{Announced, Client, Relay, namespace, track};

/// The one code every denial reports, whatever the reason. See `Denial::code`.
const UNAUTHORIZED: u64 = 0x01;

/// What a subscriber gets for a namespace nobody publishes.
const DOES_NOT_EXIST: u64 = 0x10;

/// The namespace a client announces for its own slot on stage, matching
/// `MoqomNamespaces.participant` in the client SDK.
fn slot(user: &str) -> TrackNamespace {
    namespace(&["acme", "r", "room-42", user, DEVICE])
}

#[tokio::test]
async fn a_participant_publishes_as_themselves() {
    let relay = Relay::authenticating();
    let mut ada = Client::connect_as(&relay, &Grant::default().token()).await;

    let _announcement = ada.announce(&slot("ada")).await;

    // Visible to somebody else in the room, which is what makes this an
    // announcement that took effect rather than one that was merely not
    // refused.
    let mut bea = Client::connect_as(
        &relay,
        &Grant {
            user: "bea",
            ..Grant::viewer()
        }
        .token(),
    )
    .await;
    let mut watch = bea.watch(&namespace(&["acme", "r", "room-42"])).await;
    assert_eq!(watch.next().await, Announced::Available(slot("ada")));
}

/// The hole this was written to close: a valid token was a licence to publish
/// under any name at all.
#[tokio::test]
async fn nobody_publishes_as_somebody_else() {
    let relay = Relay::authenticating();
    let mut ada = Client::connect_as(&relay, &Grant::default().token()).await;

    assert_eq!(ada.announce_refused(&slot("bea")).await, UNAUTHORIZED);

    // And the impersonation did not happen quietly behind the refusal. A
    // subscriber looking for bea must find nothing, rather than find ada.
    let mut viewer = Client::connect_as(&relay, &Grant::viewer().token()).await;
    let outcome = viewer
        .subscribe(&track(&["acme", "r", "room-42", "bea", DEVICE], "video"))
        .await;
    let Err(code) = outcome else {
        panic!("bea's namespace must not exist");
    };
    assert_eq!(code, DOES_NOT_EXIST);
}

#[tokio::test]
async fn nobody_publishes_into_another_tenant() {
    let relay = Relay::authenticating();
    let mut ada = Client::connect_as(&relay, &Grant::default().token()).await;

    let theirs = namespace(&["globex", "r", "room-42", "ada", DEVICE]);
    assert_eq!(ada.announce_refused(&theirs).await, UNAUTHORIZED);
}

#[tokio::test]
async fn a_token_for_one_room_does_not_reach_another() {
    let relay = Relay::authenticating();
    let mut ada = Client::connect_as(&relay, &Grant::default().token()).await;

    let elsewhere = namespace(&["acme", "r", "room-7", "ada", DEVICE]);
    assert_eq!(ada.announce_refused(&elsewhere).await, UNAUTHORIZED);
    assert_eq!(
        ada.watch_refused(&namespace(&["acme", "r", "room-7"]))
            .await,
        UNAUTHORIZED
    );
}

/// A watch is how a client learns who is in a room. A prefix above the room
/// would answer with every room the customer is running.
#[tokio::test]
async fn a_watch_cannot_enumerate_the_tenant() {
    let relay = Relay::authenticating();
    let mut ada = Client::connect_as(&relay, &Grant::default().token()).await;

    assert_eq!(ada.watch_refused(&namespace(&["acme"])).await, UNAUTHORIZED);
}

#[tokio::test]
async fn a_viewer_may_watch_and_may_not_publish() {
    let relay = Relay::authenticating();
    let mut viewer = Client::connect_as(&relay, &Grant::viewer().token()).await;

    assert_eq!(viewer.announce_refused(&slot("ada")).await, UNAUTHORIZED);
    // The same client's watch is fine, so the refusal above is about the grant
    // rather than about the session having been soured by a bad request.
    let _watch = viewer.watch(&namespace(&["acme", "r", "room-42"])).await;
}

/// Backstage sits outside the room prefix so that a viewer's watch cannot
/// reach it, and the relay is where that has to be true.
#[tokio::test]
async fn backstage_is_not_visible_to_the_audience() {
    let relay = Relay::authenticating();
    let backstage = namespace(&["acme", "bs", "room-42"]);

    let mut viewer = Client::connect_as(&relay, &Grant::viewer().token()).await;
    assert_eq!(viewer.watch_refused(&backstage).await, UNAUTHORIZED);

    // A cohost holds stage powers, which is what running a queue is.
    let mut cohost = Client::connect_as(&relay, &Grant::default().token()).await;
    let _watch = cohost.watch(&backstage).await;
}

#[tokio::test]
async fn a_guest_waiting_to_go_live_publishes_backstage_only() {
    let relay = Relay::authenticating();
    let waiting = Grant {
        backstage: true,
        capabilities: 0,
        ..Grant::default()
    };
    let mut guest = Client::connect_as(&relay, &waiting.token()).await;

    let _announcement = guest
        .announce(&namespace(&["acme", "bs", "room-42", "ada", DEVICE]))
        .await;
    // Going live is a promotion, which is a new token. Without this the queue
    // would be advisory: any guest could put themselves on stage by announcing
    // one namespace instead of another.
    assert_eq!(guest.announce_refused(&slot("ada")).await, UNAUTHORIZED);
}

/// The room's own namespace carries its control log — the roster, the grants,
/// who was removed — so publishing it is running the room.
#[tokio::test]
async fn the_control_log_belongs_to_whoever_runs_the_room() {
    let relay = Relay::authenticating();
    let room = namespace(&["acme", "r", "room-42"]);

    let mut viewer = Client::connect_as(&relay, &Grant::viewer().token()).await;
    assert_eq!(viewer.announce_refused(&room).await, UNAUTHORIZED);

    let mut owner = Client::connect_as(
        &relay,
        &Grant {
            owner: true,
            ..Grant::viewer()
        }
        .token(),
    )
    .await;
    let _announcement = owner.announce(&room).await;
}

/// History is cached across every room on the relay, so a fetch that skipped
/// the check would be a way to read another room's objects by naming them.
#[tokio::test]
async fn a_fetch_cannot_reach_another_room() {
    let relay = Relay::authenticating();
    let mut ada = Client::connect_as(&relay, &Grant::default().token()).await;

    let outcome = ada
        .fetch(FetchKind::Standalone {
            track: track(&["acme", "r", "room-7", "bea", DEVICE], "video"),
            start: Location::ZERO,
            end: FetchEnd::EndOfGroup(GroupId::from(1u32))
                .wire()
                .expect("representable"),
        })
        .await;
    let Err(code) = outcome else {
        panic!("another room's history must not be readable");
    };
    assert_eq!(code, UNAUTHORIZED);
}

/// Denials are counted, because the series is the one worth alerting on: a
/// token that fails to verify is usually an expiry, and a token that verifies
/// and then reaches for another room is either a broken client or somebody
/// looking around.
#[tokio::test]
async fn a_denial_is_counted_without_naming_anybody() {
    let relay = Relay::authenticating();
    let mut ada = Client::connect_as(&relay, &Grant::default().token()).await;
    ada.announce_refused(&slot("bea")).await;

    let scrape = relay.scrape();
    assert!(
        scrape.contains(r#"moqom_relay_requests_denied_total{reason="identity"} 1"#),
        "expected an identity denial in:\n{scrape}"
    );
    assert!(
        !scrape.contains("bea"),
        "a metric label must not carry a username:\n{scrape}"
    );
}

/// The mode the benches and the two-phone rig run in. A relay with no keys has
/// no verified tenant to compare a namespace against, so it authorises nothing
/// — and this test is here so that changing that is a decision somebody makes
/// on purpose rather than a default that drifts.
#[tokio::test]
async fn a_relay_without_keys_authorises_nothing() {
    let relay = Relay::start();
    let mut anyone = Client::connect(&relay).await;

    let elsewhere = namespace(&["globex", "r", "someone-elses-room", "mallory", "d"]);
    let _announcement = anyone.announce(&elsewhere).await;

    let mut watcher = Client::connect(&relay).await;
    let mut watch = watcher.watch(&namespace(&["globex"])).await;
    assert_eq!(watch.next().await, Announced::Available(elsewhere));
}
