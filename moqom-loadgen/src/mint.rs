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
//!
//! The device keys the tokens are bound to are derived the same way, from each
//! identity's name, and are just as public. Derived rather than generated because
//! the publisher's namespace is its thumbprint, and the hosts of a run agree on
//! it without talking to each other.

use std::sync::Arc;

use aws_lc_rs::digest;
use moqom_client::DeviceKey;
use moqom_token::{Claims, Confirmation, Grant, Signer};

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
    signer: Signer,
}

impl Mint {
    /// Derive the signer from `seed`.
    ///
    /// # Errors
    /// A seed ML-DSA-65 will not accept.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, moqom_token::KeyError> {
        Ok(Self {
            signer: Signer::from_seed(seed)?.with_id(KEY_ID),
        })
    }

    /// The key set a relay needs in order to verify what this mints, as the JSON
    /// document `MOQOM_RELAY_JWKS` reads.
    #[must_use]
    pub fn jwks(&self) -> String {
        serde_json::json!({ "keys": [self.signer.public_key().jwk()] }).to_string()
    }

    /// A token for one identity, valid for `seconds`.
    ///
    /// `publish` is the media-kind bitmask: non-empty for the publisher, zero for
    /// a viewer. That is the difference between a session that may announce its
    /// own slot and one that may only watch.
    ///
    /// # Errors
    /// [`moqom_token::Error::Lifetime`] for `seconds` beyond the fifteen minutes
    /// a relay accepts, which is refused here rather than at the relay.
    pub fn token(
        &self,
        who: &Identity,
        publish: u8,
        seconds: u64,
    ) -> Result<String, moqom_token::Error> {
        let issued = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after the epoch")
            .as_secs();
        let issued = i64::try_from(issued).expect("a representable clock");
        self.signer.sign(&Claims {
            iss: ISSUER.to_owned(),
            sub: who.user.clone(),
            tenant: who.tenant.clone(),
            iat: issued,
            exp: issued.saturating_add(i64::try_from(seconds).unwrap_or(i64::MAX)),
            cnf: Confirmation {
                jkt: who.thumbprint.clone(),
            },
            grant: Grant {
                room: who.room.clone(),
                publish,
                ..Grant::default()
            },
            ..Claims::default()
        })
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
#[derive(Clone)]
pub struct Identity {
    /// The customer, which a token carries as `aud`.
    pub tenant: String,
    /// The person, which a token carries as `sub`.
    pub user: String,
    /// The room they were admitted to.
    pub room: String,
    /// The device key the token is bound to, which every session proves.
    pub key: Arc<DeviceKey>,
    /// The RFC 7638 thumbprint of `key`, which the token commits to as `cnf`.
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
        let key = Self::key(user);
        Self {
            tenant: tenant.to_owned(),
            user: user.to_owned(),
            room: room.to_owned(),
            thumbprint: key.thumbprint(),
            key: Arc::new(key),
        }
    }

    /// The ML-DSA-65 key for `user`, its seed a hash of the name, so a run and
    /// the relay it targets agree on every device without exchanging keys.
    fn key(user: &str) -> DeviceKey {
        let mut seed = b"moqom-loadgen device key ".to_vec();
        seed.extend_from_slice(user.as_bytes());
        DeviceKey::from_seed(digest::digest(&digest::SHA256, &seed).as_ref())
            .expect("a SHA-256 digest is a 32-byte seed")
    }

    /// The PKCS#8 ML-DSA-65 private key for `user`, the one [`Self::key`] makes.
    #[must_use]
    pub fn pkcs8(user: &str) -> Vec<u8> {
        Self::key(user)
            .to_pkcs8()
            .expect("an ML-DSA-65 key serialises")
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
        let token = mint()
            .token(&who, 0b11, 600)
            .expect("ten minutes is allowed");
        let keys = moqom_token::PublicKey::parse_set(&mint().jwks()).expect("a key set");
        let claims = moqom_token::Verifier::new(ISSUER, keys)
            .verify(token.as_bytes(), std::time::SystemTime::now())
            .expect("the relay's verifier accepts it");
        assert_eq!(claims.tenant, "acme");
        assert_eq!(claims.sub, "publisher");
        assert_eq!(claims.grant.room, "room-42");
        assert_eq!(claims.grant.publish, 0b11);
        assert_eq!(
            claims.cnf.jkt, who.thumbprint,
            "the token has to commit to the device its namespace names"
        );
    }

    /// Longer than a relay accepts is refused here, where the flag was given,
    /// rather than as an authentication failure at the relay.
    #[test]
    fn a_token_longer_than_a_relay_accepts_is_refused() {
        let who = Identity::publisher("acme", "room-42");
        assert_eq!(
            mint().token(&who, 0, 3600),
            Err(moqom_token::Error::Lifetime)
        );
    }

    /// The device field is a prefix of what the token commits to, which is the
    /// relation the relay checks rather than one this crate is free to choose.
    #[test]
    fn the_device_is_the_thumbprint_the_token_carries_truncated() {
        let who = Identity::publisher("acme", "room-42");
        assert!(who.thumbprint.starts_with(who.device()));
    }

    /// Every host derives the same key for the same name, which is what lets
    /// them agree on the publisher's namespace.
    #[test]
    fn a_name_always_derives_the_same_device_key() {
        let one = Identity::publisher("acme", "room-42");
        let two = Identity::publisher("acme", "room-42");
        assert_eq!(one.thumbprint, two.thumbprint);
        assert_eq!(one.thumbprint, one.key.thumbprint());
        assert_eq!(one.thumbprint.len(), 43, "base64url of a SHA-256");
    }

    #[test]
    fn the_key_set_names_the_algorithm_the_relay_expects() {
        let jwks: serde_json::Value = serde_json::from_str(&mint().jwks()).expect("valid JSON");
        assert_eq!(jwks["keys"][0]["kty"], "AKP");
        assert_eq!(jwks["keys"][0]["alg"], "ML-DSA-65");
        assert_eq!(jwks["keys"][0]["kid"], KEY_ID);
    }
}
