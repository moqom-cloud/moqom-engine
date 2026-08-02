//! Moderation, over a real socket.
//!
//! The control-plane link is unit tested against a real gRPC server in
//! `link.rs`, with sessions that are records rather than connections. What that
//! cannot show is the half that matters most: whether deciding to eject somebody
//! actually closes a QUIC connection, and whether a ban is consulted on the path
//! a phone takes to join.
//!
//! So there is no control plane here at all. Each test puts the policy in the
//! state a directive would have left it in, and then asks a real client what
//! happened to it — because a relay that recorded the ban perfectly and served
//! the session anyway would pass every test written the other way round.

mod support;

use std::time::Duration;

use moqom_relay::policy::{Ban, Banned, Rules};
use moqom_relay::roster::Departure;
use support::tokens::{DEVICE, Grant};
use support::{Client, Relay, within};

/// What the relay closes a session with when it will not have it. See
/// `session::code`.
const UNAUTHORIZED: u64 = 0x03;

fn room() -> (std::sync::Arc<str>, std::sync::Arc<str>) {
    ("acme".into(), "room-42".into())
}

/// Wait for the roster to catch up with a handshake that has completed.
async fn enrolled(relay: &Relay, count: usize) {
    within("the roster to record the session", async {
        while relay.fabric.roster().count() != count {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
}

#[tokio::test]
async fn a_session_that_completes_a_handshake_can_be_named() {
    let relay = Relay::authenticating();
    let _ada = Client::connect_as(&relay, &Grant::default().token()).await;
    enrolled(&relay, 1).await;

    let everybody = relay.fabric.roster().everybody();
    let ada = everybody.first().expect("ada on the roster");
    assert_eq!(&*ada.tenant, "acme");
    assert_eq!(&*ada.room, "room-42");
    assert_eq!(&*ada.user, "ada");
    // Derived from the token's thumbprint, and the same string the client
    // announces under: a ban keyed on one and a session keyed on the other
    // would be two names for one device.
    assert_eq!(&*ada.device, DEVICE);
    assert!(ada.address.is_loopback());
}

/// A relay with no keys knows nothing about anybody, and says nothing about
/// them either.
#[tokio::test]
async fn an_unauthenticated_session_is_not_reported() {
    let relay = Relay::start();
    let _peer = Client::connect(&relay).await;

    // Nothing to wait for, so wait a moment and confirm nothing arrived.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(relay.fabric.roster().count(), 0);
}

/// The property the whole link exists for: a decision made elsewhere closes a
/// connection here.
#[tokio::test]
async fn ejecting_somebody_closes_their_connection() {
    let relay = Relay::authenticating();
    let ada = Client::connect_as(&relay, &Grant::default().token()).await;
    let bea = Client::connect_as(
        &relay,
        &Grant {
            user: "bea",
            ..Grant::viewer()
        }
        .token(),
    )
    .await;
    enrolled(&relay, 2).await;

    let everybody = relay.fabric.roster().everybody();
    let target = everybody
        .iter()
        .find(|presence| &*presence.user == "ada")
        .expect("ada on the roster");
    target.eject(UNAUTHORIZED as u32, "moderation_code_harassment");

    let closed = ada.closed().await;
    assert_eq!(closed.code, UNAUTHORIZED);
    // The code travels in the reason so the app can say something true before
    // the picture goes dark.
    assert_eq!(closed.reason, "moderation_code_harassment");

    // And nobody else was touched, which is the failure that would be invisible
    // from the ejected client's side.
    assert_eq!(relay.fabric.roster().count(), 1);
    let left = relay.fabric.roster().everybody();
    assert_eq!(&*left[0].user, "bea");
    drop(bea);
}

/// An ejection must not be reported as a network failure. The control plane
/// holds a place open for somebody who dropped off a train and does not hold one
/// for somebody it threw out, and both arrive here as a closed connection.
#[tokio::test]
async fn an_ejection_is_reported_as_an_ejection() {
    let relay = Relay::authenticating();
    let mut notes = relay.fabric.roster().listen();
    let ada = Client::connect_as(&relay, &Grant::default().token()).await;

    let arrival = within("the arrival", notes.recv()).await;
    assert!(matches!(
        arrival,
        Some(moqom_relay::roster::Note::Arrived(_))
    ));

    relay.fabric.roster().everybody()[0].eject(UNAUTHORIZED as u32, "banned");
    ada.closed().await;

    let departure = within("the departure", notes.recv()).await;
    match departure {
        Some(moqom_relay::roster::Note::Left { why, .. }) => {
            assert_eq!(why, Departure::Ejected);
        }
        other => panic!("expected a departure, got {other:?}"),
    }
}

#[tokio::test]
async fn a_banned_person_cannot_join() {
    let relay = Relay::authenticating();
    relay.fabric.policy().revise(
        room(),
        Ban {
            who: Banned::User("ada".into()),
            until: None,
        },
        true,
    );

    let refused = Client::try_connect_as(&relay, &Grant::default().token())
        .await
        .err()
        .expect("a banned session must be refused");
    assert_eq!(refused.code, UNAUTHORIZED);
    assert_eq!(refused.reason, "banned from this room");

    // Somebody else with the same shape of token still gets in, so the refusal
    // is the ban rather than the relay having stopped admitting anybody.
    let _bea = Client::connect_as(
        &relay,
        &Grant {
            user: "bea",
            ..Grant::default()
        }
        .token(),
    )
    .await;
}

#[tokio::test]
async fn a_lifted_ban_lets_them_back_in() {
    let relay = Relay::authenticating();
    let ban = Ban {
        who: Banned::User("ada".into()),
        until: None,
    };
    relay.fabric.policy().revise(room(), ban.clone(), true);
    assert!(
        Client::try_connect_as(&relay, &Grant::default().token())
            .await
            .is_err()
    );

    relay.fabric.policy().revise(room(), ban, false);
    let _ada = Client::connect_as(&relay, &Grant::default().token()).await;
}

#[tokio::test]
async fn a_closed_room_refuses_new_sessions() {
    let relay = Relay::authenticating();
    relay.fabric.policy().close(room(), true);

    let refused = Client::try_connect_as(&relay, &Grant::default().token())
        .await
        .err()
        .expect("a closed room admits nobody");
    assert_eq!(refused.reason, "this room is closed");
}

#[tokio::test]
async fn a_full_room_refuses_the_next_one_and_never_the_owner() {
    let relay = Relay::authenticating();
    relay.fabric.policy().describe(
        room(),
        Rules {
            ceiling: 1,
            ..Rules::default()
        },
    );

    let _ada = Client::connect_as(&relay, &Grant::default().token()).await;
    enrolled(&relay, 1).await;

    let refused = Client::try_connect_as(
        &relay,
        &Grant {
            user: "bea",
            ..Grant::default()
        }
        .token(),
    )
    .await
    .err()
    .expect("the ceiling to hold");
    assert_eq!(refused.reason, "this room is full");

    // The host is not kept out of their own room by a ceiling: a room whose
    // owner cannot rejoin after a dropped connection is a room nobody can
    // moderate.
    let _host = Client::connect_as(
        &relay,
        &Grant {
            user: "cy",
            owner: true,
            ..Grant::default()
        }
        .token(),
    )
    .await;
}

/// Refusing a session must refuse it, rather than answer no and serve it.
#[tokio::test]
async fn a_refused_session_is_not_quietly_on_the_roster() {
    let relay = Relay::authenticating();
    relay.fabric.policy().close(room(), true);

    let _refused = Client::try_connect_as(&relay, &Grant::default().token()).await;

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(relay.fabric.roster().count(), 0);
}
