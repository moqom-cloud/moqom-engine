//! The Rust verifier against tokens the Go control plane actually minted.
//!
//! Everything else about authentication is tested against tokens this crate
//! signed itself, which proves the verifier is self-consistent and nothing at
//! all about whether it agrees with the minter. Two implementations written
//! from one description agree on everything except the detail that matters, and
//! here the candidates are specific: which claim carries the tenant, how many
//! characters of the thumbprint become a device, and whether the signature
//! covers the segments as sent or as re-encoded.
//!
//! The fixture is committed rather than generated, so this runs on a machine
//! with no Go toolchain. `go test ./internal/token -run TestInteropFixture`
//! checks it still verifies on that side, and `MOQOM_WRITE_FIXTURES=1` rebuilds
//! it — a diff there is a protocol change and should be read as one.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, UNIX_EPOCH};

use moqom_relay::{Authenticator, Principal, VerificationKey};

#[derive(serde::Deserialize)]
struct Fixture {
    issuer: String,
    now: u64,
    jwks: String,
    cases: Vec<Case>,
}

#[derive(serde::Deserialize)]
struct Case {
    name: String,
    token: String,
    tenant: String,
    username: String,
    device: String,
    /// Who brought this holder, where the control plane said. Absent for the
    /// cases that arrived alone.
    #[serde(default)]
    arrived_via: Option<String>,
}

fn fixture() -> Fixture {
    let raw = include_str!("testdata/tokens.json");
    serde_json::from_str(raw).expect("the committed fixture parses")
}

fn peer() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4))
}

#[test]
fn tokens_minted_by_the_control_plane_verify_here() {
    let fixture = fixture();
    let keys = VerificationKey::parse_set(&fixture.jwks).expect("the Go JWK renders as a JWK set");
    let authenticator = Authenticator::new(&fixture.issuer, keys);
    let now = UNIX_EPOCH + Duration::from_secs(fixture.now);

    assert!(
        !fixture.cases.is_empty(),
        "a fixture with no cases proves nothing"
    );
    for case in &fixture.cases {
        let admitted = authenticator
            .admit([case.token.as_bytes()], peer(), now)
            .unwrap_or_else(|e| panic!("{}: {e}", case.name));

        assert_eq!(
            admitted.who,
            Principal::verified(&case.tenant, &case.username, &case.device),
            "{}: the two sides disagree about who this is",
            case.name
        );
        // Provenance decides which cohost's audience a viewer counts towards, so
        // a disagreement here is a cohort that reads as organic on one side and
        // attributed on the other -- silent, and eventually a revenue dispute.
        assert_eq!(
            admitted.via.as_deref(),
            case.arrived_via.as_deref(),
            "{}: the two sides disagree about who brought this holder",
            case.name
        );
    }

    assert!(
        fixture.cases.iter().any(|case| case.arrived_via.is_some()),
        "no case carries provenance, so this proves only that both sides ignore it"
    );
}

#[test]
fn the_control_planes_expiry_is_read_the_same_way() {
    let fixture = fixture();
    let keys = VerificationKey::parse_set(&fixture.jwks).expect("valid JWK set");
    let authenticator = Authenticator::new(&fixture.issuer, keys);
    let token = fixture.cases[0].token.as_bytes();

    // Ten minutes was the lifetime, and thirty seconds is the skew both sides
    // pin. A disagreement about either would show up as a relay that refuses
    // fresh tokens or honours stale ones, and only one of those is noticed.
    let expires_at = UNIX_EPOCH + Duration::from_secs(fixture.now + 600 + 30);
    authenticator
        .identify([token], peer(), expires_at)
        .expect("inside the lifetime plus the skew");
    assert!(
        authenticator
            .identify([token], peer(), expires_at + Duration::from_secs(2))
            .is_err(),
        "past the lifetime plus the skew, this must be refused"
    );
}

#[test]
fn a_token_from_the_fixture_does_not_verify_under_a_different_key() {
    let fixture = fixture();
    // Same shape, different key material: the check has to be the signature and
    // not the fact that the token parses.
    let other = moqom_token::Signer::from_seed(&[0u8; 32])
        .expect("a valid ML-DSA-87 seed")
        .with_id("_oEsEvOrTOY")
        .public_key()
        .jwk();
    let keys = VerificationKey::parse_set(&format!("[{other}]")).expect("valid JWK set");
    let authenticator = Authenticator::new(&fixture.issuer, keys);
    let now = UNIX_EPOCH + Duration::from_secs(fixture.now);

    assert!(
        authenticator
            .identify([fixture.cases[0].token.as_bytes()], peer(), now)
            .is_err()
    );
}
