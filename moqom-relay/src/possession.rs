//! Proving that a session holds the key its token was issued to.
//!
//! # What this is for
//!
//! A token names a device in its `cnf.jkt` claim, and until this module existed
//! that was a note rather than a check: the relay recorded the thumbprint and
//! admitted whoever presented the token. Such a token is a bearer credential —
//! possession is authorisation — so a copy lifted from a Keychain, a log, a
//! pasted shell variable or a compromised backend worked from anywhere until it
//! expired. Short lifetimes bounded the damage and were the only thing that did.
//!
//! What closes that is a signature, made at connect time by a key the token
//! commits to and the device cannot export. The thief gets the token and not the
//! key, so the token stops being worth stealing.
//!
//! # Why one proof per session, and not one per request
//!
//! The obvious reading of `DPoP` is per-request, because that is how RFC 9449
//! works over HTTP, and this codebase said so in a comment for a while. It does
//! not transfer. HTTP is stateless, so every request must carry its own evidence;
//! a session here establishes who the peer is once and pins it — see the
//! write-once principal and permission on [`crate::session::Session`] — and
//! every later announce or subscribe is checked against *that*, not against the
//! token again. A per-request proof would therefore prove possession to a relay
//! that had already stopped asking, at the cost of a secure-element signature per
//! subscribe.
//!
//! So possession is proven where identity is established: at SETUP, and again on
//! renewal, because a renewal presents a different token and a proof is bound to
//! one token. Anything else would let a proven credential be traded for an
//! unproven one.
//!
//! # Freshness without a nonce, a clock, or a round trip
//!
//! The awkward part of proving possession here is that the client speaks first.
//! It opens the control stream and sends SETUP, so there is no earlier moment at
//! which the relay could have handed out a challenge — a server nonce would mean
//! a second round trip on every connection and a session state that is admitted
//! but not yet allowed to do anything.
//!
//! None is needed, because the token already carries the uniqueness a nonce would
//! have supplied. A proof commits to its token by hash (its `ath`), so it is usable
//! with that token and no other; the token expires in minutes; and a proof's own
//! identifier is accepted exactly once, remembered for as long as the token it
//! names could still be presented. Replay therefore requires a proof that was
//! captured but never delivered, for a token that has not expired, at the relay
//! it was made for. Capturing one at all means reading it out of QUIC, and an
//! attacker who can do that can read the token beside it and has no need of any
//! of this.
//!
//! The residual is worth stating rather than implying: a relay that restarts
//! forgets which proofs it has seen, so a captured-and-undelivered proof could be
//! replayed within its token's remaining lifetime. Persisting the set across
//! restarts would trade that for a write on the connect path and a new way for a
//! relay to fail, which is not a good trade for an attack that begins with
//! breaking TLS.
//!
//! # The algorithm is not negotiable and not the fastest one
//!
//! `ES256`, because the point of this module is a key that cannot be extracted
//! and on the devices that matter that means the Secure Enclave, which does
//! P-256 and nothing else. Ed25519 verifies about twice as quickly and `CryptoKit`
//! offers it, in software, with the private key in ordinary memory — where it can
//! be dumped alongside the token by exactly the attacker this exists to stop. A
//! faster check of a weaker claim is not a saving.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

/// The one algorithm accepted, pinned for the reason the module note gives.
const ALGORITHM: &str = "ES256";

/// The proof type, so that a JWS minted for something else — including a token
/// from this same deployment — cannot be presented as one.
const PROOF_TYPE: &str = "MOQT-POP";

/// A proof may not be larger than this.
///
/// Bounded before any parsing, like the token limit beside it: the work below is
/// proportional to the input, and a peer that can hand over a megabyte of base64
/// per connection attempt has found something cheaper than the attack the rate
/// limiter is watching. A real proof is around three hundred bytes.
const MAX_PROOF_BYTES: usize = 2048;

/// How many proof identifiers to remember at once.
///
/// Generous, because the honest ceiling is one entry per session established in a
/// token's lifetime and each entry is a few dozen bytes; a hundred thousand is
/// far past what a relay this size serves and still under ten megabytes. It
/// exists so that the set has *a* bound, not because the bound is expected to be
/// approached, and reaching it is reported as the fault it would be.
const MAX_REMEMBERED: usize = 100_000;

/// Why a proof of possession was not accepted.
///
/// Separate from [`crate::identity::AuthError`] and folded into it at the edge,
/// because these mean different things to whoever reads the logs: a malformed
/// proof is a client that has the format wrong, a thumbprint mismatch is a client
/// whose token and key disagree — the ordinary consequence of a token minted for
/// somebody else's device — and a replay is the one worth alerting on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProofError {
    /// Required by this relay, and the peer sent none.
    #[error("no proof of possession was presented")]
    Missing,
    /// Not a well-formed proof.
    #[error("proof is malformed: {0}")]
    Malformed(&'static str),
    /// Signed with something other than `ES256`, or not a proof at all.
    #[error("proof algorithm or type is not supported")]
    Unsupported,
    /// The signature does not verify under the key the proof carries.
    #[error("proof signature does not verify")]
    BadSignature,
    /// It verified, but under a different key than the token was issued to.
    #[error("proof is signed by a key the token was not issued to")]
    WrongKey,
    /// It verified, but commits to a different token.
    #[error("proof was made for a different token")]
    WrongToken,
    /// It verified, but was made for a different relay.
    #[error("proof was made for another relay")]
    WrongRelay,
    /// Already used. See the module note on freshness.
    #[error("proof has already been presented")]
    Replayed,
    /// Too many unexpired proofs to remember another. Fails closed.
    #[error("this relay is tracking too many proofs to accept another")]
    Overloaded,
}

impl ProofError {
    /// A stable, low-cardinality name for metrics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Missing => "proof_missing",
            Self::Malformed(_) => "proof_malformed",
            Self::Unsupported => "proof_unsupported",
            Self::BadSignature => "proof_bad_signature",
            Self::WrongKey => "proof_wrong_key",
            Self::WrongToken => "proof_wrong_token",
            Self::WrongRelay => "proof_wrong_relay",
            Self::Replayed => "proof_replayed",
            Self::Overloaded => "proof_overloaded",
        }
    }
}

/// How strictly a relay holds sessions to proving possession: completely.
///
/// One mode. A token is bound to the device key its `cnf.jkt` names, and a
/// session that cannot prove it holds that key is refused, on every relay. The
/// `bearer` and `observed` modes that once let a deployment migrate are gone:
/// every MOQOM SDK signs a proof, and a credential that works from any device
/// is not one a zero-trust platform issues.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Enforcement {
    /// A token without a valid proof admits nobody.
    #[default]
    Required,
}

impl Enforcement {
    /// Read the mode from its configured name, which can only be `required`.
    ///
    /// `bearer` and `observed` are errors rather than silently upgraded, so a
    /// deployment still configured for them finds out at startup.
    ///
    /// # Errors
    /// What was wrong, for the person who wrote the configuration.
    pub fn parse(name: &str) -> Result<Self, String> {
        match name.trim().to_ascii_lowercase().as_str() {
            "required" => Ok(Self::Required),
            "bearer" | "observed" => Err(format!(
                "possession mode {:?} has been removed: every session must prove its device key",
                name.trim()
            )),
            other => Err(format!(
                "unknown possession mode {other:?}: expected required"
            )),
        }
    }
}

/// Checks proofs of possession, and remembers which have been used.
///
/// One per relay, shared by every session, because the set of spent proofs has to
/// be: a proof accepted on one connection must not be accepted on the next.
#[derive(Debug)]
pub struct Possession {
    mode: Enforcement,

    /// This relay's certificate hash, base64url of its SHA-256.
    ///
    /// What a proof is bound to, so that one made for this relay is refused by
    /// any other. The attack that motivates it is a relay rather than a network
    /// eavesdropper: in a deployment of several, a compromised one is handed
    /// perfectly good credentials by every session that connects to it, and
    /// without this binding it could turn round and use them on its neighbours.
    /// Requiring a proof would otherwise have moved the confused deputy rather
    /// than removed it.
    ///
    /// `None` where the relay does not know its own certificate, which is an
    /// in-process test harness rather than anything deployed. A proof's binding
    /// is then unchecked — the relay has nothing to compare it against — and that
    /// is a property of the deployment and not something a peer can select.
    relay: Option<String>,

    /// Proof identifiers already spent, against the moment each may be forgotten.
    ///
    /// Keyed by the identifier and valued by the expiry of the token the proof
    /// named, which is exactly how long it needs to be remembered: after that the
    /// token is refused on its own account and a proof for it is worthless.
    spent: Mutex<HashMap<String, SystemTime>>,
}

/// A proof's header. The key travels with it, which is what makes the thumbprint
/// check meaningful: the relay compares a key it was given against a commitment
/// the control plane signed, rather than looking one up.
#[derive(Deserialize)]
struct Header {
    alg: String,
    typ: String,
    jwk: Jwk,
}

/// The public half of the device's key, as a JWK.
#[derive(Deserialize)]
struct Jwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
}

/// A proof's claims.
///
/// Three fields and no timestamps, which is the module note's point about
/// freshness: a proof inherits its lifetime from the token it commits to, so it
/// has no clock of its own to disagree with anybody about.
#[derive(Deserialize)]
struct Claims {
    /// Base64url SHA-256 of the token this proof is for, named as RFC 9449 names
    /// it.
    ///
    /// Over the encoded token rather than over any part of its contents, so that
    /// this cannot be satisfied by a different token that happens to name the
    /// same device — a renewal is a new token and needs a new proof.
    #[serde(default)]
    ath: String,
    /// This proof's own identifier, accepted once.
    #[serde(default)]
    jti: String,
    /// Base64url SHA-256 of the certificate of the relay this proof is for.
    #[serde(default)]
    rel: String,
}

impl Possession {
    /// A checker in the given mode, for a relay identified by `certificate`.
    ///
    /// `certificate` is the SHA-256 of the relay's certificate in base64url, the
    /// same digest the client pins. `None` disables the relay binding; see the
    /// note on the `relay` field.
    #[must_use]
    pub fn new(mode: Enforcement, certificate: Option<String>) -> Self {
        Self {
            mode,
            relay: certificate,
            spent: Mutex::new(HashMap::new()),
        }
    }

    /// The mode in force.
    #[must_use]
    pub const fn mode(&self) -> Enforcement {
        self.mode
    }

    /// Whether a session's `token` is accompanied by proof that it holds the key
    /// `thumbprint` names.
    ///
    /// `expires` is the token's own expiry, which sets how long the proof's
    /// identifier is remembered. `now` is passed rather than read so that the
    /// caller's notion of the time is the one used throughout a single admission.
    ///
    /// A proof is consumed by a successful check and not by a failed one, which
    /// is the only order that works: burning the identifier first would let
    /// anybody who could make the relay fail the check — by corrupting a byte in
    /// flight — spend a legitimate client's proof for it.
    ///
    /// # Errors
    /// [`ProofError`], which the caller reports as an authentication failure,
    /// [`ProofError::Missing`] included.
    pub fn check(
        &self,
        token: &[u8],
        proof: Option<&[u8]>,
        thumbprint: &str,
        expires: SystemTime,
        now: SystemTime,
    ) -> Result<(), ProofError> {
        let Some(proof) = proof else {
            return Err(ProofError::Missing);
        };

        let (header, claims, signed, signature) = split(proof)?;
        let header: Header = decode_segment(&header, "header")?;
        if header.alg != ALGORITHM || header.typ != PROOF_TYPE {
            return Err(ProofError::Unsupported);
        }

        // The signature is checked before any claim is read, for the reason the
        // token verifier gives: a verifier that acts on unverified claims, even
        // to produce a better error, is a parser an attacker can reach.
        let key = public_key(&header.jwk)?;
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.as_slice())
            .verify(&signed, &signature)
            .map_err(|_| ProofError::BadSignature)?;

        // A signature that verifies proves the sender holds *some* key. This is
        // the line that makes it the right one, and without it the whole module
        // would be theatre: anybody could generate a key pair, sign a proof with
        // it, and present it beside a stolen token.
        if !constant_time_eq(
            thumbprint.as_bytes(),
            jwk_thumbprint(&header.jwk)?.as_bytes(),
        ) {
            return Err(ProofError::WrongKey);
        }

        let claims: Claims = decode_segment(&claims, "claims")?;
        if !constant_time_eq(claims.ath.as_bytes(), sha256_base64url(token).as_bytes()) {
            return Err(ProofError::WrongToken);
        }
        if self
            .relay
            .as_ref()
            .is_some_and(|relay| !constant_time_eq(claims.rel.as_bytes(), relay.as_bytes()))
        {
            return Err(ProofError::WrongRelay);
        }
        if claims.jti.is_empty() {
            return Err(ProofError::Malformed("no identifier to spend"));
        }

        self.spend(claims.jti, expires, now)
    }

    /// Record an identifier as used, refusing one already there.
    fn spend(&self, id: String, expires: SystemTime, now: SystemTime) -> Result<(), ProofError> {
        let mut spent = self
            .spent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Swept here rather than on a timer. The set only grows when a proof is
        // accepted, so the moment of insertion is the only moment it can need
        // clearing, and a relay sitting idle should not be waking up to tidy an
        // empty map.
        if spent.len() >= MAX_REMEMBERED {
            spent.retain(|_, until| *until > now);
        }
        if spent.len() >= MAX_REMEMBERED {
            // Fails closed. Evicting something to make room would be choosing
            // which proof becomes replayable, and refusing new sessions is the
            // lesser failure — it is loud, it is temporary, and it does not
            // quietly undo the guarantee this module exists to provide.
            return Err(ProofError::Overloaded);
        }

        match spent.entry(id) {
            std::collections::hash_map::Entry::Occupied(_) => Err(ProofError::Replayed),
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(expires);
                Ok(())
            }
        }
    }

    /// How many spent identifiers are being remembered, for tests and metrics.
    #[must_use]
    pub fn remembered(&self) -> usize {
        self.spent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

/// Split a compact JWS into its parts, returning the signed bytes with them.
///
/// The signed message has to be taken from the original bytes rather than
/// rebuilt from the decoded segments: a round trip through base64 and JSON does
/// not reproduce them byte for byte, and the signature is over bytes.
type Split = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

fn split(proof: &[u8]) -> Result<Split, ProofError> {
    if proof.is_empty() || proof.len() > MAX_PROOF_BYTES {
        return Err(ProofError::Malformed("proof length is out of range"));
    }

    let mut segments = proof.splitn(3, |&byte| byte == b'.');
    let (Some(header), Some(claims), Some(signature)) =
        (segments.next(), segments.next(), segments.next())
    else {
        return Err(ProofError::Malformed("expected three segments"));
    };
    if claims.contains(&b'.') || signature.contains(&b'.') {
        return Err(ProofError::Malformed("expected three segments"));
    }

    let signed = proof[..header.len() + 1 + claims.len()].to_vec();
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| ProofError::Malformed("signature is not base64url"))?;
    Ok((header.to_vec(), claims.to_vec(), signed, signature))
}

fn decode_segment<T: for<'de> Deserialize<'de>>(
    segment: &[u8],
    what: &'static str,
) -> Result<T, ProofError> {
    let decoded = URL_SAFE_NO_PAD.decode(segment).map_err(|_| {
        ProofError::Malformed(if what == "header" {
            "header is not base64url"
        } else {
            "claims are not base64url"
        })
    })?;
    serde_json::from_slice(&decoded).map_err(|_| {
        ProofError::Malformed(if what == "header" {
            "header is not JSON, or carries no key"
        } else {
            "claims are not JSON"
        })
    })
}

/// The uncompressed point `0x04 || x || y` that the verifier wants.
fn public_key(jwk: &Jwk) -> Result<Vec<u8>, ProofError> {
    if jwk.kty != "EC" || jwk.crv != "P-256" {
        return Err(ProofError::Unsupported);
    }
    let x = coordinate(&jwk.x)?;
    let y = coordinate(&jwk.y)?;

    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    Ok(point)
}

/// One coordinate, which must be exactly the curve's field size.
///
/// The length check is not pedantry. Base64url would happily decode a shorter
/// value, and a coordinate silently left-padded or truncated is a different point
/// — so this would compute a thumbprint that matched the token while verifying
/// under a key nobody holds, or fail in a way that looked like a signature bug.
fn coordinate(value: &str) -> Result<[u8; 32], ProofError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ProofError::Malformed("key coordinate is not base64url"))?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| ProofError::Malformed("key coordinate is not 32 bytes"))
}

/// The RFC 7638 thumbprint of an EC public key.
///
/// The specification is exact about the input and every part of it matters: the
/// four required members and no others, ordered lexicographically, no whitespace,
/// and the coordinates re-encoded from what was decoded rather than copied from
/// the wire. Copying them would let a peer pad its base64 and produce a different
/// thumbprint for the same key, which is a way to claim a device the token does
/// not name.
fn jwk_thumbprint(jwk: &Jwk) -> Result<String, ProofError> {
    let x = URL_SAFE_NO_PAD.encode(coordinate(&jwk.x)?);
    let y = URL_SAFE_NO_PAD.encode(coordinate(&jwk.y)?);
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    Ok(sha256_base64url(canonical.as_bytes()))
}

fn sha256_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(digest(&SHA256, bytes).as_ref())
}

/// Compare without leaking where two values first differ.
///
/// Applied to a thumbprint and a token hash, neither of which is secret, so this
/// is a habit rather than a fix for a known leak — the habit being that a
/// comparison guarding an authentication decision does not become a way to
/// discover the value it is guarding, whatever gets compared here later.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (l, r)| difference | (l ^ r))
        == 0
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

    use super::*;

    const RELAY: &str = "cGludGhpc3JlbGF5c2NlcnRpZmljYXRlaGFzaA";

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    /// A device key, and the thumbprint a token would commit to.
    struct Device {
        pair: EcdsaKeyPair,
    }

    impl Device {
        fn new() -> Self {
            let rng = aws_lc_rs::rand::SystemRandom::new();
            let document =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
            let pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, document.as_ref())
                    .unwrap();
            Self { pair }
        }

        /// The public key as a JWK, which is what a proof carries.
        fn jwk(&self) -> Jwk {
            // Uncompressed point: 0x04, then the two coordinates.
            let point = self.pair.public_key().as_ref();
            Jwk {
                kty: "EC".into(),
                crv: "P-256".into(),
                x: URL_SAFE_NO_PAD.encode(&point[1..33]),
                y: URL_SAFE_NO_PAD.encode(&point[33..65]),
            }
        }

        fn thumbprint(&self) -> String {
            jwk_thumbprint(&self.jwk()).unwrap()
        }

        /// A proof over `token`, as the client builds one.
        fn prove(&self, token: &[u8], id: &str, relay: &str) -> Vec<u8> {
            let jwk = self.jwk();
            let header = format!(
                r#"{{"alg":"ES256","typ":"MOQT-POP","jwk":{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"}}}}"#,
                jwk.x, jwk.y
            );
            let claims = format!(
                r#"{{"ath":"{}","jti":"{id}","rel":"{relay}"}}"#,
                sha256_base64url(token)
            );
            let signing_input = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(header),
                URL_SAFE_NO_PAD.encode(claims)
            );

            let rng = aws_lc_rs::rand::SystemRandom::new();
            let signature = self.pair.sign(&rng, signing_input.as_bytes()).unwrap();
            format!(
                "{signing_input}.{}",
                URL_SAFE_NO_PAD.encode(signature.as_ref())
            )
            .into_bytes()
        }
    }

    fn checker() -> Possession {
        Possession::new(Enforcement::Required, Some(RELAY.to_owned()))
    }

    fn expires() -> SystemTime {
        now() + Duration::from_mins(10)
    }

    #[test]
    fn a_proof_from_the_right_key_for_the_right_token_is_accepted() {
        let device = Device::new();
        let token = b"a.token";
        let proof = device.prove(token, "one", RELAY);

        assert_eq!(
            checker().check(token, Some(&proof), &device.thumbprint(), expires(), now()),
            Ok(())
        );
    }

    /// The check the module exists for. Anybody can make a key pair and sign
    /// with it; the question is whether the token was issued to that key.
    #[test]
    fn a_proof_from_a_key_the_token_does_not_name_is_refused() {
        let thief = Device::new();
        let token = b"a.token";
        let proof = thief.prove(token, "one", RELAY);

        assert_eq!(
            checker().check(
                token,
                Some(&proof),
                &Device::new().thumbprint(),
                expires(),
                now()
            ),
            Err(ProofError::WrongKey),
            "a self-signed proof passed for a token issued to another device"
        );
    }

    #[test]
    fn a_proof_for_another_token_is_refused() {
        let device = Device::new();
        let proof = device.prove(b"one.token", "one", RELAY);

        assert_eq!(
            checker().check(
                b"another.token",
                Some(&proof),
                &device.thumbprint(),
                expires(),
                now()
            ),
            Err(ProofError::WrongToken),
            "a proof must not carry over to the next token, or renewal would launder it"
        );
    }

    #[test]
    fn a_proof_for_another_relay_is_refused() {
        let device = Device::new();
        let token = b"a.token";
        let proof = device.prove(token, "one", "c29tZW90aGVycmVsYXlzY2VydA");

        assert_eq!(
            checker().check(token, Some(&proof), &device.thumbprint(), expires(), now()),
            Err(ProofError::WrongRelay),
            "a compromised relay could pass its sessions' credentials to a neighbour"
        );
    }

    #[test]
    fn a_proof_is_accepted_once() {
        let device = Device::new();
        let token = b"a.token";
        let proof = device.prove(token, "one", RELAY);
        let checker = checker();

        assert_eq!(
            checker.check(token, Some(&proof), &device.thumbprint(), expires(), now()),
            Ok(())
        );
        assert_eq!(
            checker.check(token, Some(&proof), &device.thumbprint(), expires(), now()),
            Err(ProofError::Replayed),
            "this is the freshness the design has instead of a nonce"
        );
    }

    /// A tampered signature must not spend the identifier it names, or anybody
    /// able to corrupt a byte in flight could burn a legitimate proof.
    #[test]
    fn a_failed_check_does_not_spend_the_identifier() {
        let device = Device::new();
        let token = b"a.token";
        let good = device.prove(token, "one", RELAY);
        let mut bad = good.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        let checker = checker();

        assert!(
            checker
                .check(token, Some(&bad), &device.thumbprint(), expires(), now())
                .is_err()
        );
        assert_eq!(checker.remembered(), 0, "a refusal must leave no trace");
        assert_eq!(
            checker.check(token, Some(&good), &device.thumbprint(), expires(), now()),
            Ok(())
        );
    }

    #[test]
    fn a_missing_proof_is_refused() {
        let token = b"a.token";
        let device = Device::new();
        assert_eq!(
            checker().check(token, None, &device.thumbprint(), expires(), now()),
            Err(ProofError::Missing)
        );
        assert_eq!(
            Possession::new(Enforcement::default(), None).check(
                token,
                None,
                &device.thumbprint(),
                expires(),
                now()
            ),
            Err(ProofError::Missing),
            "a checker with no relay binding still demands a proof"
        );
    }

    /// Identifiers are forgotten once the token they name has expired, which is
    /// what keeps the set bounded by the token lifetime rather than by uptime.
    #[test]
    fn spent_identifiers_are_forgotten_once_their_token_expires() {
        let checker = checker();
        let device = Device::new();

        for n in 0..MAX_REMEMBERED {
            checker
                .spend(format!("old-{n}"), now(), now())
                .expect("room for another");
        }
        assert_eq!(checker.remembered(), MAX_REMEMBERED);

        // The next one sweeps, and everything above expired at `now`.
        let token = b"a.token";
        assert_eq!(
            checker.check(
                token,
                Some(&device.prove(token, "fresh", RELAY)),
                &device.thumbprint(),
                expires(),
                now() + Duration::from_secs(1)
            ),
            Ok(())
        );
        assert_eq!(checker.remembered(), 1, "the swept entries are still held");
    }

    #[test]
    fn a_full_set_of_unexpired_identifiers_fails_closed() {
        let checker = checker();
        for n in 0..MAX_REMEMBERED {
            checker
                .spend(format!("live-{n}"), expires(), now())
                .expect("room for another");
        }
        assert_eq!(
            checker.spend("one-more".into(), expires(), now()),
            Err(ProofError::Overloaded),
            "evicting would be choosing which proof becomes replayable"
        );
    }

    #[test]
    fn garbage_is_refused_without_panicking() {
        let device = Device::new();
        let token = b"a.token";
        let thumbprint = device.thumbprint();
        let checker = checker();

        for rubbish in [
            &b""[..],
            b"...",
            b"one.two",
            b"one.two.three.four",
            b"!!!.!!!.!!!",
            &[0xFF; 64],
            &vec![b'a'; MAX_PROOF_BYTES + 1],
        ] {
            assert!(
                checker
                    .check(token, Some(rubbish), &thumbprint, expires(), now())
                    .is_err(),
                "accepted {rubbish:?}"
            );
        }
        assert_eq!(checker.remembered(), 0);
    }

    /// A proof whose header carries a key of the wrong shape must be refused
    /// before any of it reaches the verifier.
    #[test]
    fn a_key_of_the_wrong_shape_is_refused() {
        let short = Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: URL_SAFE_NO_PAD.encode([1u8; 31]),
            y: URL_SAFE_NO_PAD.encode([2u8; 32]),
        };
        assert_eq!(
            public_key(&short),
            Err(ProofError::Malformed("key coordinate is not 32 bytes"))
        );

        let wrong_curve = Jwk {
            kty: "EC".into(),
            crv: "P-384".into(),
            x: URL_SAFE_NO_PAD.encode([1u8; 32]),
            y: URL_SAFE_NO_PAD.encode([2u8; 32]),
        };
        assert_eq!(public_key(&wrong_curve), Err(ProofError::Unsupported));
    }

    /// Pinned against the worked example in RFC 7638 §3.1, which is the only way
    /// to know this agrees with every other implementation rather than merely
    /// with itself. The RFC's example is an RSA key; this is the EC key from
    /// RFC 7517 §A.1 with the thumbprint computed over the canonical form the
    /// specification prescribes.
    #[test]
    fn the_thumbprint_follows_rfc_7638() {
        let jwk = Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4".into(),
            y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM".into(),
        };

        // SHA-256 of {"crv":"P-256","kty":"EC","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}
        assert_eq!(
            jwk_thumbprint(&jwk).unwrap(),
            "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s"
        );
    }

    /// Padding the coordinates must not produce a second thumbprint for one key,
    /// or a peer could pick which device a token appears to name.
    #[test]
    fn the_thumbprint_is_canonical_rather_than_copied() {
        let device = Device::new();
        let jwk = device.jwk();
        let padded = Jwk {
            kty: jwk.kty.clone(),
            crv: jwk.crv.clone(),
            x: format!("{}=", jwk.x),
            y: jwk.y.clone(),
        };

        assert!(
            jwk_thumbprint(&padded).is_err(),
            "padded base64url must not decode to a second spelling of one key"
        );
    }

    #[test]
    fn only_required_is_read_from_configuration() {
        assert_eq!(Enforcement::parse(" Required "), Ok(Enforcement::Required));
        for removed in ["bearer", "observed", "yes"] {
            assert!(Enforcement::parse(removed).is_err(), "{removed}");
        }
    }

    /// The proofs above are made by the same code that checks them, which is the
    /// one thing this module's tests cannot establish on their own: a mistake
    /// shared by the builder and the verifier passes every test in this file and
    /// fails against the only client that exists.
    ///
    /// So these read what `moqom-swift` writes. The fixture is committed here
    /// rather than generated on demand — no Swift toolchain is needed to run
    /// them, so they run wherever `cargo test` does, which is the property that
    /// makes them worth having. Regenerate it with `MOQOM_WRITE_FIXTURES=1 swift
    /// test --filter ProofInteropTests` in that repository.
    mod interop {
        use super::*;

        const FIXTURE: &str = include_str!("../tests/testdata/possession.json");

        #[derive(Deserialize)]
        struct Fixture {
            relay: String,
            keys: Vec<KeyCase>,
            proofs: Vec<ProofCase>,
        }

        #[derive(Deserialize)]
        struct KeyCase {
            name: String,
            jwk: Jwk,
            thumbprint: String,
        }

        #[derive(Deserialize)]
        struct ProofCase {
            name: String,
            token: String,
            thumbprint: String,
            proof: String,
        }

        fn fixture() -> Fixture {
            serde_json::from_str(FIXTURE).expect("the committed fixture parses")
        }

        /// `include_str!` rather than a runtime read, so a fixture deleted or
        /// moved fails the build instead of skipping the check.
        #[test]
        fn the_fixture_is_not_empty() {
            let read = fixture();
            assert!(!read.keys.is_empty(), "no thumbprint vectors");
            assert!(!read.proofs.is_empty(), "no proofs");
        }

        /// The half of the fixture both sides compute deterministically, so it is
        /// compared rather than merely recomputed. A vector this build no longer
        /// reproduces means every token already minted against the old value
        /// names a device this relay would refuse.
        #[test]
        fn thumbprints_agree_with_the_swift_client() {
            for case in fixture().keys {
                assert_eq!(
                    jwk_thumbprint(&case.jwk).expect("a well-formed vector"),
                    case.thumbprint,
                    "{}: the client and this relay disagree about RFC 7638",
                    case.name
                );
            }
        }

        /// Every proof the client produced is one this relay accepts.
        ///
        /// A fresh checker per case, because a shared one would spend the
        /// identifiers and the second half of the loop would be testing the
        /// replay cache instead of the format.
        #[test]
        fn every_proof_the_client_makes_is_accepted() {
            let read = fixture();
            for case in &read.proofs {
                let checker = Possession::new(Enforcement::Required, Some(read.relay.clone()));
                assert_eq!(
                    checker.check(
                        case.token.as_bytes(),
                        Some(case.proof.as_bytes()),
                        &case.thumbprint,
                        expires(),
                        now(),
                    ),
                    Ok(()),
                    "{}: the client's proof was refused",
                    case.name
                );
            }
        }

        /// The relay binding, checked against a proof made elsewhere rather than
        /// one this file built — the case where a client that omitted `rel`, or
        /// spelled it differently, would otherwise look correct.
        #[test]
        fn a_clients_proof_does_not_travel_to_another_relay() {
            let read = fixture();
            let case = &read.proofs[0];
            let elsewhere =
                Possession::new(Enforcement::Required, Some("c29tZW9uZWVsc2U".to_owned()));

            assert_eq!(
                elsewhere.check(
                    case.token.as_bytes(),
                    Some(case.proof.as_bytes()),
                    &case.thumbprint,
                    expires(),
                    now(),
                ),
                Err(ProofError::WrongRelay)
            );
        }

        /// Two proofs over one token are two sessions, not a replay. An
        /// implementation that remembered tokens rather than identifiers would
        /// pass everything above and refuse every second connection.
        #[test]
        fn two_proofs_over_one_token_are_both_accepted() {
            let read = fixture();
            let checker = Possession::new(Enforcement::Required, Some(read.relay.clone()));

            let over_one_token: Vec<&ProofCase> = read
                .proofs
                .iter()
                .filter(|case| case.token == read.proofs[0].token)
                .collect();
            assert!(
                over_one_token.len() > 1,
                "the fixture no longer carries two proofs for one token"
            );

            for case in over_one_token {
                assert_eq!(
                    checker.check(
                        case.token.as_bytes(),
                        Some(case.proof.as_bytes()),
                        &case.thumbprint,
                        expires(),
                        now(),
                    ),
                    Ok(()),
                    "{}: refused as a replay of another proof for the same token",
                    case.name
                );
            }
        }
    }
}
