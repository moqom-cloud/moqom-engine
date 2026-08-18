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
///
/// A *request* error, which is what a refused announce or subscribe answers with
/// on the stream that asked. Not to be confused with [`SESSION_UNAUTHORIZED`]
/// below: they mean the same thing at two different scopes and are numbered in
/// separate registries, so the two are easy to swap and the symptom is a passing
/// assertion about the wrong layer.
const UNAUTHORIZED: u64 = 0x01;

/// What the relay closes a whole session with when the credential is the problem.
///
/// The session-level counterpart of [`UNAUTHORIZED`], reported in the QUIC close
/// rather than on a stream, because a session that never established an identity
/// has no request to answer.
const SESSION_UNAUTHORIZED: u64 = 0x03;

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

/// A token's lifetime used to bound the act of joining and nothing after it.
/// `exp` was checked once, at SETUP, and then discarded — so a ten-minute token
/// admitted a session that lasted as long as the connection did, and since these
/// are bearer credentials whose short life is the only thing limiting a stolen
/// one, the mitigation was being applied to the wrong event.
#[tokio::test]
async fn a_session_does_not_outlive_its_credential() {
    let relay = Relay::authenticating();
    // Admitted, because the relay allows a clock-skew window past `exp`, and
    // then out of time almost at once. A realistic token would make this test
    // take ten minutes to say the same thing.
    let expiring = Grant::default().token_lasting(-28);
    let ada = Client::connect_as(&relay, &expiring).await;

    let closed = ada.closed().await;
    assert_eq!(
        closed.code, SESSION_UNAUTHORIZED,
        "expiry closes as unauthorized"
    );
    // The reason phrase is the only thing distinguishing this from a credential
    // that never verified, and the two call for different things from a client:
    // reconnecting with the same token cannot fix this one.
    assert!(
        closed.reason.contains("renew"),
        "the close reason must tell a client to renew: {:?}",
        closed.reason
    );
}

/// The other half, and neither is any use alone: enforcing an expiry without a
/// way to renew would end every call at the token's lifetime.
#[tokio::test]
async fn a_renewed_credential_extends_the_session() {
    let relay = Relay::authenticating();
    let grant = Grant::default();
    let mut ada = Client::connect_as(&relay, &grant.token_lasting(-28)).await;

    // On the namespace watch, which is the stream a real client is likeliest to
    // have: it is how anybody learns who else is in the room.
    let mut watch = ada.watch(&namespace(&["acme", "r", "room-42"])).await;
    watch.renew(&grant.token()).await;

    // Long enough that the original deadline is well past. Asserting the session
    // is *still* here is the only way to check this: a renewal is answered with
    // silence, exactly like an accepted announcement.
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    let _announcement = ada.announce(&slot("ada")).await;
    let mut bea = Client::connect_as(
        &relay,
        &Grant {
            user: "bea",
            ..Grant::viewer()
        }
        .token(),
    )
    .await;
    let mut watching = bea.watch(&namespace(&["acme", "r", "room-42"])).await;
    assert_eq!(watching.next().await, Announced::Available(slot("ada")));
}

/// A renewal is not a way to become somebody else. The principal is what a rate
/// limit is charged against and the scope is what every request is checked
/// against, so a token that disagreed with either could not take effect even if
/// it were accepted — it would leave the relay enforcing one credential while
/// holding another.
#[tokio::test]
async fn a_renewal_cannot_change_who_you_are() {
    let relay = Relay::authenticating();
    let ada = Grant::default();
    let mut client = Client::connect_as(&relay, &ada.token_lasting(-28)).await;

    let mut watch = client.watch(&namespace(&["acme", "r", "room-42"])).await;
    watch
        .renew(
            &Grant {
                user: "bea",
                ..Grant::default()
            }
            .token(),
        )
        .await;

    // Ignored rather than obeyed, so the session still runs out on ada's
    // credential. It is also not closed early over it: the stream the renewal
    // arrived on is a roster feed, and tearing that down because a token was
    // wrong would turn a client mistake into everybody losing the room.
    let closed = client.closed().await;
    assert_eq!(closed.code, SESSION_UNAUTHORIZED);
    assert!(closed.reason.contains("expired"), "{:?}", closed.reason);
}

/// The namespace a client holding the harness's device key announces under.
///
/// Derived from the key rather than written down, because that is the whole
/// point: a session on a relay requiring proof of possession publishes under the
/// device its token names, and its token names the key it holds.
fn proven_slot(user: &str) -> TrackNamespace {
    namespace(&["acme", "r", "room-42", user, &support::tokens::device::id()])
}

/// The credential a proving client presents: a token bound to the device key,
/// and a proof made with it, identified by `id`.
fn presenting(relay: &Relay, grant: &Grant, id: &str) -> (String, String) {
    let token = grant.token_bound_to_device();
    let proof = support::tokens::device::prove(&token, &relay.certificate_identity(), id);
    (token, proof)
}

#[tokio::test]
async fn a_session_that_proves_its_credential_is_admitted() {
    let relay = Relay::proving();
    let (token, proof) = presenting(&relay, &Grant::default(), "ada-1");
    let mut ada = Client::connect_proving(&relay, &token, &proof).await;

    // Announcing is what shows the proof was accepted *and* that the identity it
    // established is the one being enforced: this namespace is derived from the
    // device key, so it could only be announced by the holder of that key.
    let _announcement = ada.announce(&proven_slot("ada")).await;

    let (viewing, viewers_proof) = presenting(
        &relay,
        &Grant {
            user: "bea",
            ..Grant::viewer()
        },
        "bea-1",
    );
    let mut bea = Client::connect_proving(&relay, &viewing, &viewers_proof).await;
    let mut watch = bea.watch(&namespace(&["acme", "r", "room-42"])).await;
    assert_eq!(watch.next().await, Announced::Available(proven_slot("ada")));
}

/// The hole this whole mechanism exists to close: a token lifted from a Keychain,
/// a log, or a pasted shell variable.
///
/// The thief has a credential that verifies perfectly and names somebody real.
/// What they do not have is the key it was issued to, so they cannot make a proof
/// — and on a relay that requires one, a token they cannot prove is worth nothing.
#[tokio::test]
async fn a_stolen_token_is_worthless_without_the_key() {
    let relay = Relay::proving();
    let stolen = Grant::default().token_bound_to_device();

    let refused = Client::refused_proving(&relay, &stolen, "").await;
    assert_eq!(refused.code, SESSION_UNAUTHORIZED);

    // And a proof the thief made with a key of their own is no better, which is
    // the check that makes the rest of it mean anything: anybody can generate a
    // key pair and sign with it, so the question is never whether a proof
    // verifies but whether the token was issued to the key that made it.
    let forged = support::tokens::device::prove(&stolen, &relay.certificate_identity(), "mallory");
    let mut mallory = forged.into_bytes();
    // Corrupting the key in the header, which is the closest a thief can come:
    // they must present a key whose thumbprint the token commits to, and they do
    // not have one.
    let at = mallory.len() / 3;
    mallory[at] = if mallory[at] == b'A' { b'B' } else { b'A' };
    let refused = Client::refused_proving(
        &relay,
        &stolen,
        &String::from_utf8(mallory).expect("still ASCII"),
    )
    .await;
    assert_eq!(refused.code, SESSION_UNAUTHORIZED);
}

/// Freshness, which this design gets from the token's own uniqueness rather than
/// from a server nonce or a clock. A proof is spent when it is used.
#[tokio::test]
async fn a_proof_cannot_be_used_twice() {
    let relay = Relay::proving();
    let (token, proof) = presenting(&relay, &Grant::default(), "ada-once");

    let _ada = Client::connect_proving(&relay, &token, &proof).await;
    let refused = Client::refused_proving(&relay, &token, &proof).await;
    assert_eq!(refused.code, SESSION_UNAUTHORIZED);
}

/// A renewal must carry its own proof. The proof presented at setup commits to
/// the token it accompanied, so accepting a renewal without one would be a way to
/// trade a proven credential for an unproven one — the guarantee undone by the
/// mechanism that keeps sessions alive.
#[tokio::test]
async fn a_renewal_carries_its_own_proof() {
    let relay = Relay::proving();
    let grant = Grant::default();
    let token = grant.token_bound_to_device_lasting(-28);
    let proof = support::tokens::device::prove(&token, &relay.certificate_identity(), "ada-setup");
    let mut ada = Client::connect_proving(&relay, &token, &proof).await;
    let mut watch = ada.watch(&namespace(&["acme", "r", "room-42"])).await;

    // Renewed with a token that verifies, and no proof that it is ours. Refused,
    // so the session still runs out on the credential it was admitted with.
    watch.renew(&grant.token_bound_to_device()).await;

    let closed = ada.closed().await;
    assert_eq!(closed.code, SESSION_UNAUTHORIZED);
    assert!(closed.reason.contains("expired"), "{:?}", closed.reason);
}

/// And the proven renewal works, which is the half that makes the refusal above
/// something other than a session that can never be kept alive.
#[tokio::test]
async fn a_proven_renewal_extends_the_session() {
    let relay = Relay::proving();
    let grant = Grant::default();
    let token = grant.token_bound_to_device_lasting(-28);
    let proof = support::tokens::device::prove(&token, &relay.certificate_identity(), "ada-setup");
    let mut ada = Client::connect_proving(&relay, &token, &proof).await;
    let mut watch = ada.watch(&namespace(&["acme", "r", "room-42"])).await;

    let fresh = grant.token_bound_to_device();
    let renewing = support::tokens::device::prove(&fresh, &relay.certificate_identity(), "ada-2");
    watch.renew_proving(&fresh, &renewing).await;

    // Well past the original deadline. Still here, and still able to act, which
    // is the only way to observe an accepted renewal: it is answered with
    // silence.
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    let _announcement = ada.announce(&proven_slot("ada")).await;
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
