//! An edge's per-room links to a parent that requires proof of possession.
//!
//! The parent here is [`Relay::proving`]: it verifies tokens and refuses a session
//! that cannot prove its token is its own, exactly as production does. The edge
//! is a plain relay with an [`Edge`] linking it, and its credentials come from a
//! scripted [`Minter`] standing in for the control plane, so each test decides
//! what the control plane says and when.

mod support;

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use moqom_proto::control::RequestErrorCode;
use moqom_proto::model::{TrackAlias, TrackNamespace};
use moqom_relay::edge::{Credential, Edge, Holder, MintError, Minter, Minting, Timing};
use moqom_relay::fabric::{LinkState, RoomKey};
use moqom_relay::upstream::{self, Introduction};
use support::tokens::Grant;
use support::{Client, Relay, namespace, series, track, within};

type Answer = dyn Fn(usize, &RoomKey, &str) -> Result<Credential, MintError> + Send + Sync;

/// The control plane, as a script: `answer` is told how many credentials it has
/// minted before, for which room, and for which key.
#[derive(Clone)]
struct Scripted {
    asked: Arc<Mutex<Vec<(RoomKey, String)>>>,
    answer: Arc<Answer>,
}

impl Scripted {
    fn new(
        answer: impl Fn(usize, &RoomKey, &str) -> Result<Credential, MintError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            asked: Arc::default(),
            answer: Arc::new(answer),
        }
    }

    fn asked(&self) -> Vec<(RoomKey, String)> {
        self.asked.lock().expect("unpoisoned").clone()
    }

    fn rooms(&self) -> Vec<String> {
        let mut rooms: Vec<String> = self
            .asked()
            .into_iter()
            .map(|(room, _)| room.room)
            .collect();
        rooms.sort();
        rooms.dedup();
        rooms
    }
}

impl Minter for Scripted {
    fn mint<'a>(&'a self, room: &'a RoomKey, holder: Holder<'a>) -> Minting<'a> {
        let before = {
            let mut asked = self.asked.lock().expect("unpoisoned");
            asked.push((room.clone(), holder.thumbprint.to_owned()));
            asked.len() - 1
        };
        let answer = (self.answer)(before, room, holder.thumbprint);
        Box::pin(async move { answer })
    }
}

/// A link credential for `room`, as the control plane mints one: the relay
/// grant, that room, bound to `thumbprint`, issued and expiring the given
/// number of seconds from now, and the mint response saying the same.
fn link_token(room: &RoomKey, thumbprint: &str, issued: i64, expires: i64) -> Credential {
    let room = match room.room.as_str() {
        "room-42" => "room-42",
        "room-7" => "room-7",
        other => panic!("no grant for {other}"),
    };
    let token = Grant {
        room: Some(room),
        ..Grant::relay_link()
    }
    .token_for(thumbprint, issued, expires);
    let from_now = |seconds: i64| {
        let now = SystemTime::now();
        let by = Duration::from_secs(seconds.unsigned_abs());
        if seconds < 0 { now - by } else { now + by }
    };
    Credential {
        token,
        issued: from_now(issued),
        expires: from_now(expires),
    }
}

/// A credential the parent still accepts, inside its clock skew, but whose
/// session it closes four seconds from now unless it is renewed.
fn nearly_lapsed(room: &RoomKey, thumbprint: &str) -> Credential {
    link_token(room, thumbprint, -34, -26)
}

fn fresh(room: &RoomKey, thumbprint: &str) -> Credential {
    link_token(room, thumbprint, 0, 600)
}

fn room(name: &str) -> RoomKey {
    RoomKey {
        tenant: "acme".to_owned(),
        room: name.to_owned(),
    }
}

fn quick() -> Timing {
    Timing {
        first_retry: Duration::from_millis(100),
        longest_retry: Duration::from_millis(500),
        ..Timing::default()
    }
}

/// A relay linking to `parent` per room on credentials from `minter`.
fn edge_of(parent: &Relay, minter: Scripted, timing: Timing) -> (Relay, String) {
    let edge = Relay::start();
    let linking = Edge::new(
        parent.dialer(),
        parent.as_parent(),
        edge.fabric.clone(),
        minter,
        timing,
    )
    .expect("a device key");
    let thumbprint = linking.thumbprint().to_owned();
    drop(linking.start());
    (edge, thumbprint)
}

/// Where a proving publisher called `user` sits in `room`.
fn slot(room: &str, user: &str) -> TrackNamespace {
    namespace(&["acme", "r", room, user, &support::tokens::device::id()])
}

/// A publisher on `relay`, proving its credential, announcing its slot in `room`.
async fn publisher(relay: &Relay, room: &'static str, id: &str) -> (Client, support::Announcement) {
    let token = Grant {
        room: Some(room),
        ..Grant::default()
    }
    .token_bound_to_device();
    let proof = support::tokens::device::prove(&token, &relay.certificate_identity(), id);
    let mut client = Client::connect_proving(relay, &token, &proof).await;
    let announcement = client.announce(&slot(room, "ada")).await;
    (client, announcement)
}

fn refusals(relay: &Relay, cause: &str) -> u64 {
    let scrape = relay.scrape();
    let metric = "moqom_relay_tokens_refused_total";
    if scrape.contains(&format!("{metric}{{cause=\"{cause}\"}}")) {
        series(&scrape, metric, "cause", cause)
    } else {
        0
    }
}

async fn eventually_link(edge: &Relay, room: &RoomKey, what: &str, wanted: fn(&LinkState) -> bool) {
    within(what, async {
        while !edge.fabric.link(room).as_ref().is_some_and(wanted) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
}

/// The edge mints a credential for the room, links with a proof, serves the
/// parent's track, and renews before the parent would close the link: the first
/// credential here lapses four seconds in, and the link is still carrying well
/// after that.
#[tokio::test]
async fn an_edge_fetches_its_link_credential_and_renews_it() {
    let parent = Relay::proving();
    let (ada, _announced) = publisher(&parent, "room-42", "ada-1").await;
    let minter = Scripted::new(|before, room, thumbprint| {
        Ok(if before == 0 {
            nearly_lapsed(room, thumbprint)
        } else {
            fresh(room, thumbprint)
        })
    });
    let (edge, thumbprint) = edge_of(&parent, minter.clone(), quick());

    let mut viewer = Client::connect(&edge).await;
    let video = track(
        &[
            "acme",
            "r",
            "room-42",
            "ada",
            &support::tokens::device::id(),
        ],
        "video",
    );
    let (_served, subscribed) = tokio::join!(
        ada.answer_subscription(TrackAlias::from(1_u32)),
        viewer.subscribe(&video),
    );
    let _video = subscribed.expect("a linked edge serves the parent's track");

    within("the credential to be renewed", async {
        while minter.asked().len() < 2 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert!(
        matches!(edge.fabric.link(&room("room-42")), Some(LinkState::Up(_))),
        "the renewed link outlives its first credential"
    );
    let audio = track(
        &[
            "acme",
            "r",
            "room-42",
            "ada",
            &support::tokens::device::id(),
        ],
        "audio",
    );
    let (_served, subscribed) = tokio::join!(
        ada.answer_subscription(TrackAlias::from(2_u32)),
        viewer.subscribe(&audio),
    );
    let _audio = subscribed.expect("and still carries new subscriptions");

    for (asked, key) in minter.asked() {
        assert_eq!(asked, room("room-42"));
        assert_eq!(
            key, thumbprint,
            "every credential is bound to the edge's key"
        );
    }
    assert_eq!(refusals(&parent, "expired"), 0);
}

/// One link, and one credential, per room. A viewer in a second room makes a
/// second link scoped to that room alone; a personal channel, which no room
/// link can carry, is refused without asking the control plane.
#[tokio::test]
async fn each_room_gets_a_link_and_a_credential_of_its_own() {
    let parent = Relay::proving();
    let (ada, _a) = publisher(&parent, "room-42", "ada-1").await;
    let (bea, _b) = publisher(&parent, "room-7", "bea-1").await;
    let minter = Scripted::new(|_, room, thumbprint| Ok(fresh(room, thumbprint)));
    let (edge, _) = edge_of(&parent, minter.clone(), quick());
    let mut viewer = Client::connect(&edge).await;

    let id = support::tokens::device::id();
    let (video_42, video_7) = (
        track(&["acme", "r", "room-42", "ada", &id], "video"),
        track(&["acme", "r", "room-7", "ada", &id], "video"),
    );
    let (_served, in_42) = tokio::join!(
        ada.answer_subscription(TrackAlias::from(1_u32)),
        viewer.subscribe(&video_42),
    );
    let (_served, in_7) = tokio::join!(
        bea.answer_subscription(TrackAlias::from(1_u32)),
        viewer.subscribe(&video_7),
    );
    let (_in_42, _in_7) = (in_42.expect("room-42"), in_7.expect("room-7"));
    assert_eq!(minter.rooms(), ["room-42", "room-7"]);
    for name in ["room-42", "room-7"] {
        assert!(matches!(
            edge.fabric.link(&room(name)),
            Some(LinkState::Up(_))
        ));
    }

    let personal = track(&["acme", "u", "ada", &id], "video");
    assert!(viewer.subscribe(&personal).await.is_err());
    assert_eq!(
        minter.rooms(),
        ["room-42", "room-7"],
        "no credential for a personal channel"
    );
}

/// The parent refuses whatever a link asks outside the room its credential
/// names, and the refusal reaches the viewer; the room it does name is served
/// on the same link.
#[tokio::test]
async fn a_link_is_refused_a_request_for_another_room() {
    let parent = Relay::proving();
    let (ada, _a) = publisher(&parent, "room-42", "ada-1").await;
    let (bea, _b) = publisher(&parent, "room-7", "bea-1").await;
    let edge = Relay::start();
    let token = Grant::relay_link().token_bound_to_device();
    let proof = support::tokens::device::prove(&token, &parent.certificate_identity(), "link-1");
    let _link = attach(&edge, &parent, Some(&token), Some(&proof))
        .await
        .expect("a proven room-42 link is admitted");

    let id = support::tokens::device::id();
    let mut viewer = Client::connect(&edge).await;
    let refused = viewer
        .subscribe(&track(&["acme", "r", "room-7", "ada", &id], "video"))
        .await
        .err()
        .expect("room-7 is not this link's room");
    assert_eq!(refused, RequestErrorCode::UNAUTHORIZED.get());
    bea.asked_nothing_further().await;

    let video_42 = track(&["acme", "r", "room-42", "ada", &id], "video");
    let (_served, subscribed) = tokio::join!(
        ada.answer_subscription(TrackAlias::from(1_u32)),
        viewer.subscribe(&video_42),
    );
    subscribed.expect("room-42 is");
}

/// A credential past its expiry, beyond the parent's skew, gets no link.
#[tokio::test]
async fn an_expired_link_credential_is_refused() {
    let parent = Relay::proving();
    let (_ada, _a) = publisher(&parent, "room-42", "ada-1").await;
    let minter = Scripted::new(|_, room, thumbprint| Ok(link_token(room, thumbprint, -700, -120)));
    let (edge, _) = edge_of(&parent, minter, quick());

    let mut viewer = Client::connect(&edge).await;
    let video = track(
        &[
            "acme",
            "r",
            "room-42",
            "ada",
            &support::tokens::device::id(),
        ],
        "video",
    );
    assert!(viewer.subscribe(&video).await.is_err());
    assert!(refusals(&parent, "expired") >= 1);
    assert!(!matches!(
        edge.fabric.link(&room("room-42")),
        Some(LinkState::Up(_))
    ));
}

/// The control plane refusing to mint — the room ended, the account was
/// withdrawn — marks the room refused, and the edge does not keep asking.
#[tokio::test]
async fn a_revoked_room_gets_no_link() {
    let parent = Relay::proving();
    let minter =
        Scripted::new(|_, _, _| Err(MintError::Revoked("410 Gone: room is closed".to_owned())));
    let (edge, _) = edge_of(&parent, minter.clone(), quick());

    let mut viewer = Client::connect(&edge).await;
    let video = track(
        &[
            "acme",
            "r",
            "room-42",
            "ada",
            &support::tokens::device::id(),
        ],
        "video",
    );
    assert!(viewer.subscribe(&video).await.is_err());
    assert!(matches!(
        edge.fabric.link(&room("room-42")),
        Some(LinkState::Refused)
    ));
    assert!(viewer.subscribe(&video).await.is_err());
    assert_eq!(
        minter.asked().len(),
        1,
        "a refused room is not asked about again at once"
    );
}

/// Revoked after the link is up: the edge stops renewing, the link serves on the
/// credential it has, and when that lapses the parent closes it and the room is
/// refused.
#[tokio::test]
async fn a_link_revoked_while_up_ends_with_its_credential() {
    let parent = Relay::proving();
    let (ada, _a) = publisher(&parent, "room-42", "ada-1").await;
    let minter = Scripted::new(|before, room, thumbprint| {
        if before == 0 {
            Ok(nearly_lapsed(room, thumbprint))
        } else {
            Err(MintError::Revoked("410 Gone: room is closed".to_owned()))
        }
    });
    let (edge, _) = edge_of(&parent, minter, quick());

    let mut viewer = Client::connect(&edge).await;
    let video = track(
        &[
            "acme",
            "r",
            "room-42",
            "ada",
            &support::tokens::device::id(),
        ],
        "video",
    );
    let (_served, subscribed) = tokio::join!(
        ada.answer_subscription(TrackAlias::from(1_u32)),
        viewer.subscribe(&video),
    );
    let _video = subscribed.expect("served until the credential lapses");

    eventually_link(
        &edge,
        &room("room-42"),
        "the link to end and the room to be refused",
        |state| matches!(state, LinkState::Refused),
    )
    .await;
}

/// Dial `parent` from `edge` and attach as its single link, presenting `token`
/// and `proof`. The link's task, or why it failed.
async fn attach(
    edge: &Relay,
    parent: &Relay,
    token: Option<&str>,
    proof: Option<&str>,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let dialer = parent.dialer();
    let connection = upstream::connect(&dialer, &parent.as_parent())
        .await
        .map_err(|e| e.to_string())?;
    let introduction = Introduction {
        token: token.map(|token| token.as_bytes().to_vec()),
        proof: proof.map(|proof| proof.as_bytes().to_vec()),
        ..Introduction::default()
    };
    let fabric = edge.fabric.clone();
    let mut running = tokio::spawn(async move {
        let _dialer = dialer;
        upstream::attach_over(connection, fabric, introduction)
            .await
            .map_err(|e| e.to_string())
    });
    let fabric = edge.fabric.clone();
    let up = async move {
        while fabric.upstream().is_none() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::select! {
        () = up => Ok(tokio::spawn(async move { let _ = running.await; })),
        outcome = &mut running => Err(match outcome {
            Ok(Err(e)) => e,
            Ok(Ok(())) => "closed without attaching".to_owned(),
            Err(e) => e.to_string(),
        }),
    }
}

#[tokio::test]
async fn a_link_without_a_proof_is_refused() {
    let parent = Relay::proving();
    let edge = Relay::start();
    let token = Grant::relay_link().token_bound_to_device();
    assert!(attach(&edge, &parent, Some(&token), None).await.is_err());
    assert_eq!(refusals(&parent, "proof_missing"), 1);
}

#[tokio::test]
async fn a_link_proof_made_for_another_relay_is_refused() {
    let parent = Relay::proving();
    let elsewhere = Relay::proving();
    let edge = Relay::start();
    let token = Grant::relay_link().token_bound_to_device();
    let proof = support::tokens::device::prove(&token, &elsewhere.certificate_identity(), "link-1");
    assert!(
        attach(&edge, &parent, Some(&token), Some(&proof))
            .await
            .is_err()
    );
    assert_eq!(refusals(&parent, "proof_wrong_relay"), 1);
}

#[tokio::test]
async fn a_replayed_link_proof_is_refused() {
    let parent = Relay::proving();
    let token = Grant::relay_link().token_bound_to_device();
    let proof = support::tokens::device::prove(&token, &parent.certificate_identity(), "link-1");

    let first = Relay::start();
    let _link = attach(&first, &parent, Some(&token), Some(&proof))
        .await
        .expect("the proof's first use is admitted");
    let second = Relay::start();
    assert!(
        attach(&second, &parent, Some(&token), Some(&proof))
            .await
            .is_err()
    );
    assert_eq!(refusals(&parent, "proof_replayed"), 1);
}

/// A link nothing is pulled over ends, and the room is forgotten so the next
/// subscription in it links again.
#[tokio::test]
async fn an_idle_link_closes() {
    let parent = Relay::proving();
    let (ada, _a) = publisher(&parent, "room-42", "ada-1").await;
    let minter = Scripted::new(|_, room, thumbprint| Ok(fresh(room, thumbprint)));
    let (edge, _) = edge_of(
        &parent,
        minter.clone(),
        Timing {
            idle: Duration::from_millis(300),
            ..quick()
        },
    );

    let mut viewer = Client::connect(&edge).await;
    let video = track(
        &[
            "acme",
            "r",
            "room-42",
            "ada",
            &support::tokens::device::id(),
        ],
        "video",
    );
    let (_served, subscribed) = tokio::join!(
        ada.answer_subscription(TrackAlias::from(1_u32)),
        viewer.subscribe(&video),
    );
    drop(subscribed.expect("served"));

    within("the idle link to close", async {
        while edge.fabric.link(&room("room-42")).is_some() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
}
