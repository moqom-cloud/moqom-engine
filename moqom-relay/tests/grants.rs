//! Grants that change on a live session, over a real socket.
//!
//! A viewer promoted to guest, or a guest returned to the audience, stays on
//! the connection they are watching on. The backend mints a token for the new
//! role and the client presents it; or, for a demotion that cannot wait for the
//! client to cooperate, the control plane sets a ceiling and the relay narrows
//! the session to it. Either way nothing reconnects, and these tests say so by
//! checking that the session the relay holds is the one it held before.
//!
//! The rules for what a renewal may change are unit tested in `scope.rs`. What
//! is tested here is that the relay acts on them: that an announcement allowed a
//! moment ago is withdrawn, that subscribers are told, and that the ways round a
//! demotion — an old token, a different room, no proof — do not work.

mod support;

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use moqom_proto::control::{DoneReason, PublishDoneStatus};
use moqom_proto::model::{FullTrackName, TrackAlias, TrackNamespace};
use moqom_proto::varint::VarInt;
use moqom_relay::media::Kinds;
use moqom_relay::policy::{Mute, Override};
use moqom_relay::scope::Ceiling;
use moqom_relay::session::GRANTS_CHANGED;
use moqom_relay::{Presence, Publish};
use support::tokens::{Grant, device};
use support::{Announced, Client, Relay, namespace, within};

/// The code every authorisation refusal reports. See `Denial::code`.
const UNAUTHORIZED: u64 = 0x01;

/// What a subscriber gets for a track nobody may give it.
const DOES_NOT_EXIST: u64 = 0x10;

fn room() -> (Arc<str>, Arc<str>) {
    (Arc::from("acme"), Arc::from("room-42"))
}

/// The slot a client holding the harness's device key announces on stage.
fn stage(user: &str) -> TrackNamespace {
    namespace(&["acme", "r", "room-42", user, &device::id()])
}

/// The same participant's slot in the queue.
fn backstage(user: &str) -> TrackNamespace {
    namespace(&["acme", "bs", "room-42", user, &device::id()])
}

fn the_room() -> TrackNamespace {
    namespace(&["acme", "r", "room-42"])
}

fn track(namespace: &TrackNamespace, name: &'static str) -> FullTrackName {
    FullTrackName::new(namespace.clone(), Bytes::from_static(name.as_bytes())).expect("a track")
}

fn alias(n: u32) -> TrackAlias {
    TrackAlias::new(VarInt::from_u32(n))
}

/// A guest: on stage with a camera and a microphone, and no powers.
fn guest() -> Grant {
    Grant {
        capabilities: 0,
        ..Grant::default()
    }
}

/// A token bound to the harness's device key and a fresh proof for it.
fn credential(relay: &Relay, grant: &Grant, id: &str) -> (String, String) {
    let token = grant.token_bound_to_device();
    let proof = device::prove(&token, &relay.certificate_identity(), id);
    (token, proof)
}

async fn join(relay: &Relay, grant: &Grant, id: &str) -> Client {
    let (token, proof) = credential(relay, grant, id);
    Client::connect_proving(relay, &token, &proof).await
}

/// Somebody else who watches, so that what they see is independent of the
/// session whose grants are changing.
async fn audience(relay: &Relay, user: &'static str) -> Client {
    let viewer = Grant {
        user,
        ..Grant::viewer()
    };
    join(relay, &viewer, &format!("{user}-setup")).await
}

fn presence(relay: &Relay, user: &str) -> Option<Arc<Presence>> {
    relay
        .fabric
        .roster()
        .everybody()
        .into_iter()
        .find(|presence| &*presence.user == user)
}

/// Wait until the relay's record of `user` satisfies `check`.
///
/// A renewal is answered with silence, so the only way to know it has landed
/// is to look at what the relay now believes.
async fn until_held(relay: &Relay, user: &str, what: &str, check: impl Fn(&Presence) -> bool) {
    within(what, async {
        while !presence(relay, user).is_some_and(|presence| check(&presence)) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
}

/// Give a renewal the relay is expected to ignore long enough to have landed.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(200)).await;
}

/// The headline: a viewer becomes a guest on the connection they are watching
/// on, and can publish at once.
#[tokio::test]
async fn a_viewer_is_promoted_without_reconnecting() {
    let relay = Relay::proving();
    let mut ada = join(&relay, &Grant::viewer(), "ada-setup").await;
    let mut watch = ada.watch(&the_room()).await;
    let mut bea = audience(&relay, "bea").await;
    let mut seen = bea.watch(&the_room()).await;
    until_held(&relay, "bea", "both on the roster", |_| true).await;
    let before = presence(&relay, "ada").expect("ada on the roster").id;

    assert_eq!(ada.announce_refused(&stage("ada")).await, UNAUTHORIZED);

    let (token, proof) = credential(&relay, &guest(), "ada-promoted");
    watch.renew_proving(&token, &proof).await;
    until_held(&relay, "ada", "the promotion", |p| !p.publish.is_none()).await;

    let _live = ada.announce(&stage("ada")).await;
    assert_eq!(seen.next().await, Announced::Available(stage("ada")));

    // The same session, not a new one that happened to arrive: no departure,
    // no arrival, and the room's roster never had a gap in it.
    assert_eq!(presence(&relay, "ada").expect("still here").id, before);
    assert_eq!(relay.fabric.roster().count(), 2);
    assert!(
        relay
            .scrape()
            .contains(r#"moqom_relay_grants_changed_total{change="promotion"} 1"#),
        "{}",
        relay.scrape()
    );
}

/// The reverse, and the half that has to work without the client's help once
/// it has been asked: the announcement goes, subscribers are told, and the
/// phone stops being asked for media. Watching carries on.
#[tokio::test]
async fn a_demotion_withdraws_publishing_and_keeps_the_session() {
    let relay = Relay::proving();
    let mut ada = join(&relay, &guest(), "ada-setup").await;
    let mut announcement = ada.announce(&stage("ada")).await;
    let mut bea = audience(&relay, "bea").await;
    let mut seen = bea.watch(&the_room()).await;
    assert_eq!(seen.next().await, Announced::Available(stage("ada")));

    let camera = track(&stage("ada"), "video");
    let (watching, served) =
        tokio::join!(bea.subscribe(&camera), ada.answer_subscription(alias(3)));
    let mut watching = watching.expect("bea may watch a guest");
    let mut served = served;
    let before = presence(&relay, "ada").expect("ada on the roster").id;

    // On the announcement's own stream, which is the stream a publisher has.
    let (token, proof) = credential(&relay, &Grant::viewer(), "ada-demoted");
    announcement.renew_proving(&token, &proof).await;

    let ended = announcement.ended().await;
    assert_eq!(ended.code, UNAUTHORIZED);
    assert!(ended.reason.starts_with(GRANTS_CHANGED), "{ended:?}");

    // The audience is told the guest has gone rather than left holding a tile.
    match seen.next().await {
        Announced::Gone(gone, Some(reason)) => {
            assert_eq!(gone, stage("ada"));
            assert!(!reason.may_return(), "{reason:?}");
        }
        other => panic!("expected the guest to leave the stage, got {other:?}"),
    }
    // Their subscription ends with news rather than with silence.
    let done = watching.ended().await;
    assert_eq!(done.status, PublishDoneStatus::TRACK_ENDED);
    // And the phone is no longer asked for the camera, whatever it does next.
    served.released().await;

    // Still connected, still the same session, and still able to watch.
    assert_eq!(presence(&relay, "ada").expect("still here").id, before);
    let _still_watching = ada.watch(&the_room()).await;
    assert_eq!(ada.announce_refused(&stage("ada")).await, UNAUTHORIZED);
    let scrape = relay.scrape();
    assert!(
        scrape.contains(r#"moqom_relay_grants_changed_total{change="demotion"} 1"#)
            && scrape.contains(r#"moqom_relay_grant_revocations_total{request="announcement"} 1"#),
        "{scrape}"
    );
}

/// A renewal is not a way to become somebody else, and that does not change
/// now that it can change what somebody may do.
#[tokio::test]
async fn a_promotion_for_somebody_else_is_ignored() {
    let relay = Relay::proving();
    let mut ada = join(&relay, &Grant::viewer(), "ada-setup").await;
    let mut watch = ada.watch(&the_room()).await;

    let (token, proof) = credential(
        &relay,
        &Grant {
            user: "bea",
            ..guest()
        },
        "bea-borrowed",
    );
    watch.renew_proving(&token, &proof).await;
    settle().await;

    assert_eq!(ada.announce_refused(&stage("ada")).await, UNAUTHORIZED);
    assert_eq!(ada.announce_refused(&stage("bea")).await, UNAUTHORIZED);
    assert!(
        relay
            .scrape()
            .contains(r#"moqom_relay_grant_changes_refused_total{reason="holder"} 1"#)
    );
}

/// Moving rooms changes what the session was admitted to — its roster entry,
/// the bans it was checked against — so it is a new session's work.
#[tokio::test]
async fn a_promotion_into_another_room_is_ignored() {
    let relay = Relay::proving();
    let mut ada = join(&relay, &Grant::viewer(), "ada-setup").await;
    let mut watch = ada.watch(&the_room()).await;

    let (token, proof) = credential(
        &relay,
        &Grant {
            room: Some("room-7"),
            ..guest()
        },
        "ada-elsewhere",
    );
    watch.renew_proving(&token, &proof).await;
    settle().await;

    assert_eq!(ada.announce_refused(&stage("ada")).await, UNAUTHORIZED);
    let elsewhere = namespace(&["acme", "r", "room-7", "ada", &device::id()]);
    assert_eq!(ada.announce_refused(&elsewhere).await, UNAUTHORIZED);
    assert!(
        relay
            .scrape()
            .contains(r#"moqom_relay_grant_changes_refused_total{reason="room"} 1"#)
    );
}

/// The way round a demotion that the ordering closes: keep the old token and
/// hand it back afterwards. It verifies, it has not expired, and it is provably
/// the client's own; it is also superseded.
#[tokio::test]
async fn a_superseded_token_cannot_undo_a_demotion() {
    let relay = Relay::proving();
    let kept = guest().token_bound_to_device_minted(60);
    let mut ada = join(&relay, &Grant::viewer(), "ada-setup").await;
    let mut watch = ada.watch(&the_room()).await;

    let proof = device::prove(&kept, &relay.certificate_identity(), "ada-kept");
    watch.renew_proving(&kept, &proof).await;
    settle().await;

    assert_eq!(ada.announce_refused(&stage("ada")).await, UNAUTHORIZED);
    assert!(
        relay
            .scrape()
            .contains(r#"moqom_relay_grant_changes_refused_total{reason="stale"} 1"#)
    );
}

/// A renewal that hands a live connection new powers must prove the device
/// asking holds the key — including on a relay that would admit a session
/// without one. On a bearer relay nothing is checked, so nothing can satisfy
/// that, and grants there change by reconnecting.
#[tokio::test]
async fn an_unproven_promotion_is_ignored() {
    let relay = Relay::authenticating();
    let mut ada = Client::connect_as(&relay, &Grant::viewer().token()).await;
    let mut watch = ada.watch(&the_room()).await;

    watch.renew(&guest().token()).await;
    settle().await;

    let slot = namespace(&["acme", "r", "room-42", "ada", support::tokens::DEVICE]);
    assert_eq!(ada.announce_refused(&slot).await, UNAUTHORIZED);
    assert!(
        relay
            .scrape()
            .contains(r#"moqom_relay_grant_changes_refused_total{reason="unproven"} 1"#)
    );
}

/// A mute imposed in the queue holds on stage. Mutes are kept against the
/// person rather than against the namespace, so the stage slot is muted the
/// moment it exists — and the phone hears it again under its new `.policy`
/// name, before it starts the microphone the promotion is about to unlock.
#[tokio::test]
async fn a_mute_survives_going_on_stage() {
    let relay = Relay::proving();
    let waiting = Grant {
        backstage: true,
        ..guest()
    };
    let mut ada = join(&relay, &waiting, "ada-setup").await;
    let mut queue = ada.announce(&backstage("ada")).await;
    until_held(&relay, "ada", "ada on the roster", |_| true).await;

    relay.fabric.policy().mute(
        room(),
        Mute {
            user: "ada".into(),
            device: String::new(),
            media: Kinds::AUDIO,
            audience_only: false,
            until: None,
        },
        true,
    );
    let target = presence(&relay, "ada").expect("ada on the roster");
    target.restrict(
        relay
            .fabric
            .policy()
            .silenced(&room(), &target.user, &target.device),
    );
    let (told, _) = ada.accept_publish().await;
    assert_eq!(told.namespace(), &backstage("ada"));

    let (token, proof) = credential(&relay, &guest(), "ada-on-stage");
    queue.renew_proving(&token, &proof).await;

    // The queue slot is not where a guest on stage publishes, so it goes.
    assert_eq!(queue.ended().await.code, UNAUTHORIZED);
    // Told again, on the name a client on stage listens to.
    let (told, payloads) = ada.accept_publish().await;
    assert_eq!(told.namespace(), &stage("ada"));
    let said = String::from_utf8(payloads.concat()).expect("text");
    assert!(said.contains("\"mutedForEveryone\":1"), "{said}");

    let _live = ada.announce(&stage("ada")).await;
    let mut bea = audience(&relay, "bea").await;
    assert_eq!(
        bea.subscribe(&track(&stage("ada"), "audio")).await.err(),
        Some(DOES_NOT_EXIST),
        "the microphone muted in the queue must stay muted on stage"
    );
    let video = track(&stage("ada"), "video");
    let (camera, _served) = tokio::join!(bea.subscribe(&video), ada.answer_subscription(alias(5)));
    assert!(camera.is_ok(), "the camera was never muted");
}

/// A demotion must not wait for the client to present a token, because a
/// client that did not want to be demoted would simply not renew. The control
/// plane's ceiling lands at once, and holds against the token the client
/// already has, on renewal and on reconnection alike.
#[tokio::test]
async fn a_directive_demotes_at_once_and_an_old_token_cannot_undo_it() {
    let relay = Relay::proving();
    let host = Grant::default();
    let mut ada = join(&relay, &host, "ada-setup").await;
    let mut announcement = ada.announce(&stage("ada")).await;
    let mut queue_watch = ada.watch(&namespace(&["acme", "bs", "room-42"])).await;
    let mut room_watch = ada.watch(&the_room()).await;
    // Announcements are answered with silence, so seeing it is the only way to
    // know it was taken before the directive rather than refused after it.
    assert_eq!(room_watch.next().await, Announced::Available(stage("ada")));
    let before = presence(&relay, "ada").expect("ada on the roster").id;

    // What the link does when an ApplyGrants arrives, written out so that the
    // test needs no control plane. The link's own handling is tested in
    // `link.rs`.
    let ceiling = Ceiling {
        publish: Publish::NONE,
        capabilities: 0,
    };
    relay.fabric.policy().regrant(
        room(),
        Override {
            user: "ada".into(),
            device: String::new(),
            ceiling,
        },
    );
    assert!(presence(&relay, "ada").expect("ada").regrant(ceiling));

    let ended = announcement.ended().await;
    assert!(ended.reason.starts_with(GRANTS_CHANGED), "{ended:?}");
    // A host returned to the audience no longer sees the queue...
    assert_eq!(queue_watch.ended().await.code, UNAUTHORIZED);
    // ...and goes on seeing the room: their own slot leaving it, and then the
    // guest who arrives next, which is proof the feed is still live.
    assert_eq!(
        room_watch.next().await,
        Announced::Gone(stage("ada"), Some(DoneReason::Stopped))
    );
    let mut bea = join(
        &relay,
        &Grant {
            user: "bea",
            ..guest()
        },
        "bea-setup",
    )
    .await;
    let _bea_live = bea.announce(&stage("bea")).await;
    assert_eq!(room_watch.next().await, Announced::Available(stage("bea")));

    // Handing the host token back — a fresh one, even, minted after the
    // directive — is capped by the ceiling.
    let (token, proof) = credential(&relay, &host, "ada-again");
    room_watch.renew_proving(&token, &proof).await;
    settle().await;
    assert_eq!(ada.announce_refused(&stage("ada")).await, UNAUTHORIZED);
    assert_eq!(presence(&relay, "ada").expect("still here").id, before);

    // And so is dialling back in with it.
    drop(ada);
    let mut again = join(&relay, &host, "ada-reconnect").await;
    assert_eq!(again.announce_refused(&stage("ada")).await, UNAUTHORIZED);
}

/// Lifting a ceiling does not promote anybody. The promotion is the token; the
/// directive only gets out of its way.
#[tokio::test]
async fn lifting_a_ceiling_waits_for_a_token() {
    let relay = Relay::proving();
    let none = Ceiling {
        publish: Publish::NONE,
        capabilities: 0,
    };
    relay.fabric.policy().regrant(
        room(),
        Override {
            user: "ada".into(),
            device: String::new(),
            ceiling: none,
        },
    );
    let mut ada = join(&relay, &guest(), "ada-setup").await;
    let mut watch = ada.watch(&the_room()).await;
    assert_eq!(ada.announce_refused(&stage("ada")).await, UNAUTHORIZED);

    let lifted = Ceiling {
        publish: Publish::from_bits(0b11),
        capabilities: 0,
    };
    relay.fabric.policy().regrant(
        room(),
        Override {
            user: "ada".into(),
            device: String::new(),
            ceiling: lifted,
        },
    );
    presence(&relay, "ada").expect("ada").regrant(lifted);
    settle().await;
    assert_eq!(
        ada.announce_refused(&stage("ada")).await,
        UNAUTHORIZED,
        "a directive must never widen a session"
    );

    let (token, proof) = credential(&relay, &guest(), "ada-promoted");
    watch.renew_proving(&token, &proof).await;
    until_held(&relay, "ada", "the promotion", |p| !p.publish.is_none()).await;
    let mut live = ada.announce(&stage("ada")).await;
    live.kept().await;
}
