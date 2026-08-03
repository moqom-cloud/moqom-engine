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

use bytes::Bytes;
use moqom_proto::model::{FullTrackName, TrackAlias, TrackNamespace};
use moqom_relay::media::Kinds;
use moqom_relay::policy::{Ban, Banned, Mute, Rules};
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

/// The whole of a force-mute, over a socket: the publisher is told, the track
/// stops being carried, and nobody is disconnected.
#[tokio::test]
async fn a_force_mute_reaches_the_phone_and_stops_the_track() {
    let relay = Relay::authenticating();
    let mut ada = Client::connect_as(&relay, &Grant::default().token()).await;
    let mut bea = Client::connect_as(
        &relay,
        &Grant {
            user: "bea",
            ..Grant::viewer()
        }
        .token(),
    )
    .await;
    enrolled(&relay, 2).await;

    let slot = TrackNamespace::from_parts([
        b"acme".as_slice(),
        b"r",
        b"room-42",
        b"ada",
        DEVICE.as_bytes(),
    ])
    .expect("a namespace");
    let camera =
        FullTrackName::new(slot.clone(), Bytes::from_static(b"video/720p")).expect("a track");
    let microphone = FullTrackName::new(slot, Bytes::from_static(b"audio")).expect("a track");
    // Held: dropping an announcement withdraws it.
    let _slot = ada.announce(&camera.namespace().clone()).await;

    // Before the mute: bea can watch the camera, and the relay pulls it.
    let watching = {
        let subscribing = bea.subscribe(&camera);
        let answering = ada.answer_subscription(TrackAlias::new(
            moqom_proto::varint::VarInt::from_u32(7),
        ));
        let (subscribed, _served) = tokio::join!(subscribing, answering);
        subscribed.expect("a viewer may watch an unmuted camera")
    };

    // The moderator stops the camera. This is what the control-plane link does
    // when an ApplyMute arrives, written out so the test needs no control plane.
    relay.fabric.policy().mute(
        room(),
        Mute {
            user: "ada".into(),
            device: String::new(),
            media: Kinds::VIDEO,
            audience_only: false,
            until: None,
        },
        true,
    );
    let present = relay.fabric.roster().everybody();
    let target = present
        .iter()
        .find(|presence| &*presence.user == "ada")
        .expect("ada on the roster");
    assert!(target.restrict(relay.fabric.policy().silenced(
        &room(),
        &target.user,
        &target.device
    )));

    // Ada's phone is told, by name and by number, which is what lets it stop
    // the capture device rather than merely stop encoding.
    let (track, payloads) = ada.accept_publish().await;
    assert_eq!(track.name().as_ref(), b".policy");
    assert_eq!(track.namespace(), camera.namespace());
    let said = String::from_utf8(payloads.concat()).expect("text");
    assert!(
        said.contains("\"mutedForEveryone\":2") && said.contains("\"mutedForAudience\":0"),
        "the object must say what is muted: {said}"
    );

    // The camera stops being carried, and a new subscription to it is refused
    // the way a track nobody publishes is -- so a viewer cannot tell a mute
    // from an absence and read the room's moderation history by guessing.
    assert_eq!(
        bea.subscribe(&camera).await.err(),
        Some(moqom_proto::control::RequestErrorCode::DOES_NOT_EXIST.get())
    );
    drop(watching);

    // The microphone was not muted and is unaffected: a mute names media, and
    // muting the camera must not take the room's audio with it.
    let listening = {
        let subscribing = bea.subscribe(&microphone);
        let answering = ada.answer_subscription(TrackAlias::new(
            moqom_proto::varint::VarInt::from_u32(9),
        ));
        let (subscribed, _served) = tokio::join!(subscribing, answering);
        subscribed.expect("a mute on the camera must not stop the microphone")
    };
    drop(listening);

    // And nobody was thrown out. A muted host is still in the room, and still
    // able to moderate it.
    assert_eq!(relay.fabric.roster().count(), 2);
}

/// Lifting is not resuming. The relay stops enforcing and tells the phone; what
/// it must not do is put the camera back on, because only the person holding it
/// may do that.
#[tokio::test]
async fn lifting_a_mute_permits_the_track_without_resuming_it() {
    let relay = Relay::authenticating();
    let ada = Client::connect_as(&relay, &Grant::default().token()).await;
    enrolled(&relay, 1).await;

    let mute = Mute {
        user: "ada".into(),
        device: String::new(),
        media: Kinds::AUDIO,
        audience_only: false,
        until: None,
    };
    relay.fabric.policy().mute(room(), mute.clone(), true);
    let present = relay.fabric.roster().everybody();
    let target = present.first().expect("ada on the roster");
    target.restrict(relay.fabric.policy().silenced(&room(), &target.user, &target.device));
    let (_, muted) = ada.accept_publish().await;
    assert!(String::from_utf8_lossy(&muted.concat()).contains("\"mutedForEveryone\":1"));

    relay.fabric.policy().mute(room(), mute, false);
    target.restrict(relay.fabric.policy().silenced(&room(), &target.user, &target.device));

    let (track, lifted) = ada.accept_publish().await;
    assert_eq!(track.name().as_ref(), b".policy");
    let said = String::from_utf8(lifted.concat()).expect("text");
    assert!(
        said.contains("\"mutedForEveryone\":0"),
        "a lift says nothing is muted, and nothing more: {said}"
    );
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
