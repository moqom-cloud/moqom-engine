//! Direct tickets, from a client's side of a relay session.
//!
//! A ticket is how direct time becomes something a relay can see: the
//! participant subscribes to its own `.direct/{peer}` track, the relay answers
//! with a signed ticket and a fresh one every renewal, and the peer on the
//! other end of the direct path refuses to stay there without one.

mod support;

use std::time::{Duration, SystemTime};

use moqom_proto::control::RequestErrorCode;
use moqom_relay::Usage;
use moqom_relay::ticket::{Expected, TicketError, TicketKeys, verify};
use support::tokens::{DEVICE, Grant, ticket_keys};
use support::{Client, Relay, track};

const PEER: &str = "bob/0123456789abcdef";

fn own_ticket_track(peer: &str) -> moqom_proto::model::FullTrackName {
    track(
        &["acme", "r", "room-42", "ada", DEVICE],
        &format!(".direct/{peer}"),
    )
}

fn holder() -> String {
    format!("ada/{DEVICE}")
}

fn expected(holder: &str) -> Expected<'_> {
    Expected {
        tenant: "acme",
        room: "room-42",
        holder,
        peer: PEER,
    }
}

/// One ticket object: the ticket and the keys it is checked against.
fn read_ticket(payload: &[u8]) -> (String, Vec<moqom_relay::VerificationKey>) {
    let object: serde_json::Value = serde_json::from_slice(payload).expect("a JSON ticket object");
    assert_eq!(object["version"], 1);
    let keys = serde_json::to_string(&object["keys"]).expect("keys");
    (
        object["ticket"].as_str().expect("a ticket").to_owned(),
        moqom_relay::VerificationKey::parse_set(&keys).expect("a JWK set"),
    )
}

#[tokio::test]
async fn a_participant_is_issued_a_ticket_and_a_fresh_one_every_renewal() {
    let relay = Relay::ticketing(Usage::disabled(), Duration::from_millis(200));
    let mut client = Client::connect_as(&relay, &Grant::default().token()).await;

    let _subscription = client
        .subscribe(&own_ticket_track(PEER))
        .await
        .expect("a participant may hold tickets on its own slot");

    let ada = holder();
    let (first_header, first) = client.read_subgroup().await;
    let (ticket, keys) = read_ticket(&first[0]);
    assert_eq!(
        keys,
        ticket_keys().verification_keys(),
        "the relay publishes the keys its tickets verify against"
    );
    let claims = verify(&keys, ticket.as_bytes(), expected(&ada), SystemTime::now())
        .expect("a ticket the peer accepts");
    assert_eq!(claims.peer, PEER);

    let (second_header, second) = client.read_subgroup().await;
    let (renewed, _) = read_ticket(&second[0]);
    assert!(
        second_header.group > first_header.group,
        "each ticket on its own group"
    );
    verify(&keys, renewed.as_bytes(), expected(&ada), SystemTime::now())
        .expect("the renewal verifies too");
}

/// What a modified app could make for itself: a ticket in the right shape,
/// signed by a key that is not the relay's. The peer checks it against the
/// keys from its own relay session and refuses it.
#[tokio::test]
async fn a_forged_ticket_is_refused_by_the_peers_check() {
    let relay = Relay::ticketing(Usage::disabled(), Duration::from_mins(1));
    let mut client = Client::connect_as(&relay, &Grant::default().token()).await;
    let _subscription = client
        .subscribe(&own_ticket_track(PEER))
        .await
        .expect("issued");
    let (_, payloads) = client.read_subgroup().await;
    let (_, keys) = read_ticket(&payloads[0]);

    let ada = holder();
    let forger = TicketKeys::from_seed("ticket-test", &[12u8; 32]);
    let counterfeit = forger.issue(&moqom_relay::ticket::Claims::new(
        "acme",
        "room-42",
        "ada",
        DEVICE,
        PEER,
        SystemTime::now(),
    ));
    assert_eq!(
        verify(
            &keys,
            counterfeit.as_bytes(),
            expected(&ada),
            SystemTime::now()
        ),
        Err(TicketError::BadSignature)
    );
}

#[tokio::test]
async fn a_viewer_cannot_get_a_ticket() {
    let relay = Relay::ticketing(Usage::disabled(), Duration::from_mins(1));
    let mut viewer = Client::connect_as(&relay, &Grant::viewer().token()).await;
    assert_eq!(
        viewer.subscribe(&own_ticket_track(PEER)).await.err(),
        Some(RequestErrorCode::UNAUTHORIZED.get())
    );
}

#[tokio::test]
async fn tickets_are_only_issued_on_ones_own_slot_and_for_somebody_else() {
    let relay = Relay::ticketing(Usage::disabled(), Duration::from_mins(1));
    let mut client = Client::connect_as(&relay, &Grant::default().token()).await;

    let someone_elses = track(
        &["acme", "r", "room-42", "bob", "0123456789abcdef"],
        ".direct/ada/OuXpLpEHW7dCPqjK",
    );
    assert_eq!(
        client.subscribe(&someone_elses).await.err(),
        Some(RequestErrorCode::UNAUTHORIZED.get())
    );
    assert_eq!(
        client.subscribe(&own_ticket_track(&holder())).await.err(),
        Some(RequestErrorCode::UNAUTHORIZED.get()),
        "a direct path to oneself"
    );
    assert_eq!(
        client.subscribe(&own_ticket_track("nobody")).await.err(),
        Some(RequestErrorCode::UNAUTHORIZED.get()),
        "a peer that is not a participant name"
    );
}

#[tokio::test]
async fn a_relay_without_ticket_keys_issues_none() {
    let relay = Relay::metering(Usage::disabled());
    let mut client = Client::connect_as(&relay, &Grant::default().token()).await;
    assert_eq!(
        client.subscribe(&own_ticket_track(PEER)).await.err(),
        Some(RequestErrorCode::NOT_SUPPORTED.get())
    );
}
