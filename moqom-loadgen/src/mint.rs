//! Tokens for the identities a run needs, and the key set a relay verifies them
//! with.
//!
//! # Why this mints rather than asking the control plane
//!
//! A run needs a few hundred distinct identities within a few seconds, and the
//! control plane deliberately refuses that: `/join` allows thirty a minute per
//! credential, described in its own source as a brake so a leaked credential
//! cannot spend the control plane's CPU. Relaxing that to run a load test would
//! be loosening a control on the one endpoint that faces the internet.
//!
//! So the harness carries the signing half itself and the relay under test is
//! told to trust it, which also means a fan-out measurement needs no Postgres and
//! no control plane running at all. The cost is that these identities are minted
//! rather than issued, so nothing here exercises the control plane's own minting
//! path. That is a separate measurement and wants a different tool.
//!
//! # Why the signing key comes from a seed
//!
//! Reproducibility, and because the alternative is worse. A fresh key each run
//! means rewriting the relay's key set and restarting it between runs, which
//! turns a measurement into a two-step dance and invites the mistake it is
//! trying to avoid: measuring against a relay still trusting the previous key.
//!
//! The key is therefore *public*, which is a property to state loudly rather
//! than a weakness to note quietly. Anyone reading this file can mint tokens the
//! relay trusts, so `jwks` prints a warning beside the key set. The failure worth
//! preventing is an operator pasting it into a relay that is not a test relay.

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use aws_lc_rs::{digest, error};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The issuer the minted tokens name, and what a relay must be told to expect.
pub const ISSUER: &str = "https://loadgen.moqom.invalid";

/// The key identifier, present because a relay matches `kid` before verifying.
pub const KEY_ID: &str = "loadgen";

/// How much of a thumbprint becomes the device field of a namespace.
///
/// Sixteen characters, matching what the control plane truncates to and what the
/// relay compares against. Any other number produces names the relay reads as
/// somebody else's slot, and its refusal names the shape rather than the length.
const DEVICE_ID_LENGTH: usize = 16;

/// The signing half of a run's identities.
pub struct Mint {
    pair: Ed25519KeyPair,
}

impl Mint {
    /// Derive the signer from `seed`.
    ///
    /// # Errors
    /// A seed the curve will not accept.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, error::KeyRejected> {
        Ok(Self {
            pair: Ed25519KeyPair::from_seed_unchecked(seed)?,
        })
    }

    /// The key set a relay needs in order to verify what this mints, as the JSON
    /// document `MOQOM_RELAY_JWKS` reads.
    #[must_use]
    pub fn jwks(&self) -> String {
        let x = URL_SAFE_NO_PAD.encode(self.pair.public_key().as_ref());
        format!(r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","kid":"{KEY_ID}","x":"{x}"}}]}}"#)
    }

    /// A token for one identity, valid for `seconds`.
    ///
    /// `publish` is the media-kind bitmask: non-empty for the publisher, zero for
    /// a viewer. That is the difference between a session that may announce its
    /// own slot and one that may only watch.
    #[must_use]
    pub fn token(&self, who: &Identity, publish: u8, seconds: u64) -> String {
        let issued = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after the epoch")
            .as_secs();
        let claims = serde_json::json!({
            "iss": ISSUER,
            "sub": who.user,
            "aud": who.tenant,
            "iat": issued,
            "exp": issued + seconds,
            "cnf": { "jkt": who.thumbprint },
            "moqt": {
                "room": who.room,
                "pub": publish,
                "cap": 0,
                "own": false,
                "bs": false,
            },
        });
        let header = serde_json::json!({ "alg": "EdDSA", "typ": "MOQT", "kid": KEY_ID });
        self.sign(&header, &claims)
    }

    /// Compact JWS over `header` and `claims`.
    fn sign(&self, header: &serde_json::Value, claims: &serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(header.to_string());
        let claims = URL_SAFE_NO_PAD.encode(claims.to_string());
        let signing = format!("{header}.{claims}");
        let signature = URL_SAFE_NO_PAD.encode(self.pair.sign(signing.as_bytes()).as_ref());
        format!("{signing}.{signature}")
    }
}

/// Who one session claims to be.
///
/// Every subscriber gets its own, which is a requirement rather than a nicety.
/// The relay charges a verified peer against its device and its user, so
/// identities shared across sessions would meet a per-device ceiling of eight
/// concurrent sessions and the run would be measuring the limiter. An
/// unauthenticated peer is charged by address instead, where the ceiling is four
/// for the whole machine — which is why this harness presents tokens even to a
/// relay that would admit it without one.
pub struct Identity {
    /// The customer, which a token carries as `aud`.
    pub tenant: String,
    /// The person, which a token carries as `sub`.
    pub user: String,
    /// The room they were admitted to.
    pub room: String,
    /// Stands in for the RFC 7638 thumbprint of a device key.
    ///
    /// A real client's is the hash of a key it holds. Nothing here holds one,
    /// because a relay only insists on that under
    /// `MOQOM_RELAY_POSSESSION=required` and this measures fan-out rather than
    /// admission. What matters is that it is distinct per session, and shaped
    /// like the real thing so that truncating it produces a legal device field.
    pub thumbprint: String,
}

impl Identity {
    /// The publisher: one person, on stage, in `room`.
    #[must_use]
    pub fn publisher(tenant: &str, room: &str) -> Self {
        Self::new(tenant, room, "publisher")
    }

    /// Viewer number `n`, distinct from every other viewer in both name and
    /// device so that each is charged its own allowance.
    #[must_use]
    pub fn viewer(tenant: &str, room: &str, n: usize) -> Self {
        Self::new(tenant, room, &format!("viewer-{n}"))
    }

    /// An edge relay pulling the room from its parent.
    ///
    /// Named apart from the viewers so a parent's logs distinguish a tier's own
    /// link from the audience behind it, and so its sessions are charged their own
    /// allowance rather than colliding with a viewer of the same number.
    #[must_use]
    pub fn relay(tenant: &str, room: &str) -> Self {
        Self::new(tenant, room, "edge-relay")
    }

    fn new(tenant: &str, room: &str, user: &str) -> Self {
        // A hash, so it is the length and alphabet of a real thumbprint, and
        // deterministic, so a name in a log points at the same session on a
        // rerun.
        let hash = digest::digest(&digest::SHA256, user.as_bytes());
        Self {
            tenant: tenant.to_owned(),
            user: user.to_owned(),
            room: room.to_owned(),
            thumbprint: URL_SAFE_NO_PAD.encode(hash.as_ref()),
        }
    }

    /// The device field a namespace of this identity's carries.
    #[must_use]
    pub fn device(&self) -> &str {
        &self.thumbprint[..DEVICE_ID_LENGTH]
    }

    /// This identity's slot on stage: `tenant/r/room/user/device`.
    ///
    /// One of the five shapes a relay holding keys recognises. A name outside
    /// them is refused rather than forwarded, and the refusal names the shape,
    /// which is not much help when the mistake is a missing `r`.
    #[must_use]
    pub fn slot(&self) -> String {
        let (tenant, room, user, device) = (&self.tenant, &self.room, &self.user, self.device());
        format!("{tenant}/r/{room}/{user}/{device}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mint() -> Mint {
        Mint::from_seed(&[3u8; 32]).expect("a valid seed")
    }

    /// The shape the relay's grammar insists on, since getting it wrong is
    /// refused with a message that names the shape and not the mistake.
    #[test]
    fn a_slot_is_one_of_the_shapes_a_relay_recognises() {
        let who = Identity::viewer("acme", "room-42", 7);
        let slot = who.slot();
        let fields: Vec<&str> = slot.split('/').collect();
        assert_eq!(fields.len(), 5, "a participant's slot has five fields");
        assert_eq!(fields[0], "acme");
        assert_eq!(fields[1], "r", "the marker that says this is a room");
        assert_eq!(fields[2], "room-42");
        assert_eq!(fields[3], "viewer-7");
        assert_eq!(fields[4].len(), DEVICE_ID_LENGTH);
    }

    /// Two viewers must not share a device, or the relay charges them the same
    /// allowance and the run measures the rate limiter rather than the fan-out.
    #[test]
    fn viewers_are_distinct_in_both_name_and_device() {
        let first = Identity::viewer("acme", "room-42", 1);
        let second = Identity::viewer("acme", "room-42", 2);
        assert_ne!(first.user, second.user);
        assert_ne!(first.device(), second.device());
    }

    #[test]
    fn a_token_is_three_base64_parts_a_relay_can_split() {
        let who = Identity::publisher("acme", "room-42");
        let token = mint().token(&who, 0b11, 600);
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let claims = URL_SAFE_NO_PAD.decode(parts[1]).expect("base64url claims");
        let claims: serde_json::Value =
            serde_json::from_slice(&claims).expect("the claims are JSON");
        assert_eq!(claims["aud"], "acme");
        assert_eq!(claims["sub"], "publisher");
        assert_eq!(claims["moqt"]["room"], "room-42");
        assert_eq!(claims["moqt"]["pub"], 0b11);
        assert_eq!(
            claims["cnf"]["jkt"], who.thumbprint,
            "the token has to commit to the device its namespace names"
        );
    }

    /// The device field is a prefix of what the token commits to, which is the
    /// relation the relay checks rather than one this crate is free to choose.
    #[test]
    fn the_device_is_the_thumbprint_the_token_carries_truncated() {
        let who = Identity::publisher("acme", "room-42");
        assert!(who.thumbprint.starts_with(who.device()));
    }

    #[test]
    fn the_key_set_names_the_algorithm_the_relay_expects() {
        let jwks: serde_json::Value = serde_json::from_str(&mint().jwks()).expect("valid JSON");
        assert_eq!(jwks["keys"][0]["crv"], "Ed25519");
        assert_eq!(jwks["keys"][0]["kid"], KEY_ID);
    }
}
