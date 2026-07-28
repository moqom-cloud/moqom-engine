//! Establishing who a peer is, so that a limit can be charged to them.
//!
//! # This is authentication, and deliberately not authorisation
//!
//! What this module answers is "who signed this session's token", and nothing
//! else. It does not check that the holder may publish under the namespace they
//! announce, that they belong to the room they name, or that they have not been
//! banned. Those are authorisation, they are still missing, and this module
//! landing must not be read as their having arrived — a relay running this is
//! still one where anyone with any valid token can publish under any namespace.
//!
//! The distinction is worth keeping sharp because the two are usually built
//! together. They are separated here because rate limiting needs exactly the
//! first half: to charge a limit to a person you must know which person, and
//! you need not yet know what they are allowed to do.
//!
//! # Why a claimed identity is not usable and a verified one is
//!
//! The token arrives in a Setup Option, which is to say from the peer, which is
//! to say from an attacker in the case that matters. Reading `sub` out of it
//! and keying a rate limit on that would build two holes at once: a new name
//! per request escapes every limit, and *somebody else's* name aims their limit
//! at them. So the signature is checked before the name is used for anything,
//! and where there is no key configured to check it with, the name is not used
//! at all — [`Authenticator::disabled`] returns an anonymous principal charged
//! by address rather than a principal that takes the peer's word.
//!
//! # The format
//!
//! Ed25519 over JSON claims in the compact JWS serialisation, minted by the Go
//! control plane's `token` package. The full design target is CAT/CWT with
//! COSE and `DPoP`; this is the subset that exists on both sides today, and the
//! gap that matters here is that a token is still a bearer credential — the
//! `cnf.jkt` thumbprint records the device it was issued to but nothing proves
//! the holder has that device's key. Short lifetimes are the mitigation, and
//! for rate limiting specifically the consequence is mild: a stolen token lets
//! the thief spend the victim's allowance, which is a nuisance rather than a
//! bypass, and the theft is bounded by the token's few remaining minutes.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

use crate::quota::Principal;

/// The one algorithm accepted.
///
/// Pinned rather than read from the token, which is the whole defence against
/// algorithm confusion: a verifier that dispatches on the token's own `alg` can
/// be told to use `none`, or to verify an HMAC using the public key as the
/// shared secret. Both produce forgeries that validate. The Go minter pins the
/// same string for the same reason.
const ALGORITHM: &str = "EdDSA";

/// The token type, so a JWS minted for something else cannot be replayed here.
const TOKEN_TYPE: &str = "MOQT";

/// How much clock disagreement between minting and verifying is tolerated.
///
/// One-directional, matching the control plane: a token from slightly in the
/// future is a clock, but an expired one is a security boundary and is not
/// extended.
const CLOCK_SKEW: Duration = Duration::from_secs(30);

/// How much of the thumbprint becomes the device identifier.
///
/// Must match `control.DeviceIDLength` in Go and `DeviceID(thumbprint:)` in
/// `MoqomKit`. A limit keyed on one derivation and a ban keyed on another would
/// be two names for one device, and the ban would be the one that missed.
const DEVICE_ID_LENGTH: usize = 16;

/// A token may not be larger than this.
///
/// Checked before anything is decoded, because the work below is proportional
/// to the input and a peer that can hand us a megabyte of base64 to parse per
/// connection attempt has found a cheaper attack than the one the rate limiter
/// is watching for. Real tokens are around four hundred bytes.
const MAX_TOKEN_BYTES: usize = 4096;

/// Why a token was not accepted.
///
/// Distinguished because they mean different things operationally: malformed is
/// a client bug, expired is routine and self-correcting, and a bad signature is
/// the one worth alerting on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// Not a well-formed token.
    #[error("token is malformed: {0}")]
    Malformed(&'static str),
    /// Signed with something other than Ed25519, or not a MOQT token.
    #[error("token algorithm or type is not supported")]
    Unsupported,
    /// Signed by a key this relay does not have.
    #[error("token was signed by an unknown key")]
    UnknownKey,
    /// The signature does not verify.
    #[error("token signature does not verify")]
    BadSignature,
    /// Past its expiry.
    #[error("token has expired")]
    Expired,
    /// Issued in the future by more than the tolerated skew.
    #[error("token is not valid yet")]
    NotYetValid,
    /// Issued by a different deployment.
    #[error("token was issued by another deployment")]
    WrongIssuer,
    /// Verified, but does not name a tenant, user, and device.
    #[error("token does not name a complete identity")]
    Incomplete,
}

impl AuthError {
    /// The MOQT code to report.
    ///
    /// Expiry gets its own code because it is the one failure a client can fix
    /// by itself, and telling it apart from a malformed token is the difference
    /// between refreshing and giving up.
    #[must_use]
    pub const fn code(self) -> moqom_proto::control::RequestErrorCode {
        use moqom_proto::control::RequestErrorCode as Code;
        match self {
            Self::Expired | Self::NotYetValid => Code::EXPIRED_AUTH_TOKEN,
            Self::Malformed(_) | Self::Unsupported | Self::Incomplete => Code::MALFORMED_AUTH_TOKEN,
            Self::UnknownKey | Self::BadSignature | Self::WrongIssuer => Code::UNAUTHORIZED,
        }
    }

    /// A stable, low-cardinality name for metrics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Malformed(_) => "malformed",
            Self::Unsupported => "unsupported",
            Self::UnknownKey => "unknown_key",
            Self::BadSignature => "bad_signature",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::WrongIssuer => "wrong_issuer",
            Self::Incomplete => "incomplete",
        }
    }
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}

/// The claims this relay reads.
///
/// A subset. Unknown fields are ignored rather than refused, which is the
/// opposite of what the Go verifier does, and the difference is deliberate:
/// there, the claims decide what somebody may do, so a claim the build does not
/// understand may be withholding something and guessing is unsafe. Here they
/// decide only *who* somebody is, and no unrecognised field can make the
/// subject or the thumbprint wrong.
///
/// That reasoning expires the moment this struct is used for authorisation. If
/// a scope field is ever read from here to decide a permission, this must
/// become strict at the same time.
#[derive(Deserialize)]
struct Claims {
    #[serde(default)]
    iss: String,
    #[serde(default)]
    sub: String,
    /// The tenant. Named `aud` because the tenant is who the token is *for*, and
    /// the control plane mints it into the audience claim.
    #[serde(default)]
    aud: String,
    #[serde(default)]
    iat: i64,
    #[serde(default)]
    exp: i64,
    #[serde(default)]
    cnf: Confirmation,
}

#[derive(Deserialize, Default)]
struct Confirmation {
    #[serde(default)]
    jkt: String,
}

/// A public key this relay will accept tokens from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationKey {
    /// The `kid` naming it.
    pub id: String,
    /// Raw Ed25519 public key bytes.
    pub bytes: Vec<u8>,
}

impl VerificationKey {
    /// Read keys from the JWK set the control plane serves.
    ///
    /// Accepts either a bare array of JWKs or the `{"keys": [...]}` wrapper, so
    /// an operator can paste either shape.
    ///
    /// # Errors
    /// A string describing what was wrong with the document, since this runs at
    /// startup and the only useful audience is the person who wrote the config.
    pub fn parse_set(document: &str) -> Result<Vec<Self>, String> {
        #[derive(Deserialize)]
        struct Jwk {
            kty: String,
            crv: String,
            kid: String,
            x: String,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Document {
            Wrapped { keys: Vec<Jwk> },
            Bare(Vec<Jwk>),
        }

        let parsed: Document =
            serde_json::from_str(document).map_err(|e| format!("not a JWK set: {e}"))?;
        let jwks = match parsed {
            Document::Wrapped { keys } | Document::Bare(keys) => keys,
        };

        jwks.into_iter()
            .map(|jwk| {
                if jwk.kty != "OKP" || jwk.crv != "Ed25519" {
                    return Err(format!(
                        "key {}: only OKP/Ed25519 is supported, got {}/{}",
                        jwk.kid, jwk.kty, jwk.crv
                    ));
                }
                let bytes = URL_SAFE_NO_PAD
                    .decode(jwk.x.as_bytes())
                    .map_err(|e| format!("key {}: x is not base64url: {e}", jwk.kid))?;
                if bytes.len() != 32 {
                    return Err(format!(
                        "key {}: an Ed25519 public key is 32 bytes, got {}",
                        jwk.kid,
                        bytes.len()
                    ));
                }
                Ok(Self { id: jwk.kid, bytes })
            })
            .collect()
    }
}

/// Checks the credential a session presents.
///
/// Holds a set of keys rather than one, because rotation needs an overlap: the
/// new key is published, minting moves to it, and the old one stays verifiable
/// until the last token it signed has expired. With a single key that sequence
/// has a window in which every session fails.
#[derive(Clone)]
pub struct Authenticator {
    inner: Option<Arc<Keys>>,
}

struct Keys {
    issuer: String,
    by_id: HashMap<String, Vec<u8>>,
}

impl std::fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.inner {
            None => f.write_str("Authenticator(disabled)"),
            Some(keys) => f
                .debug_struct("Authenticator")
                .field("issuer", &keys.issuer)
                .field("keys", &keys.by_id.len())
                .finish(),
        }
    }
}

impl Authenticator {
    /// An authenticator that accepts tokens from `keys`, issued by `issuer`.
    ///
    /// An empty issuer accepts any, which is for tests. A deployment that does
    /// not pin the issuer will accept a token minted by any other deployment
    /// that happens to share a key identifier.
    #[must_use]
    pub fn new(issuer: impl Into<String>, keys: Vec<VerificationKey>) -> Self {
        Self {
            inner: Some(Arc::new(Keys {
                issuer: issuer.into(),
                by_id: keys.into_iter().map(|key| (key.id, key.bytes)).collect(),
            })),
        }
    }

    /// An authenticator with no keys, which verifies nothing.
    ///
    /// Every session is anonymous and charged by address. This is the default
    /// because a relay with no control plane to fetch keys from must still run
    /// for a test harness, and because the alternative — trusting the token
    /// unverified — is the failure mode this whole module exists to prevent.
    #[must_use]
    pub const fn disabled() -> Self {
        Self { inner: None }
    }

    /// Whether tokens are checked at all.
    #[must_use]
    pub const fn is_verifying(&self) -> bool {
        self.inner.is_some()
    }

    /// Who this peer is.
    ///
    /// `tokens` is every `AUTHORIZATION_TOKEN` Setup Option, in the order sent;
    /// the option is defined to repeat. The first one that verifies wins, which
    /// is the behaviour a client needs when it is mid-rotation and sends both
    /// an old and a new credential.
    ///
    /// A peer that offers nothing is anonymous rather than rejected. Refusing
    /// it here would make authentication mandatory, which is a policy decision
    /// that belongs to the deployment: the address tier exists precisely so an
    /// unauthenticated peer can be allowed in on a short leash.
    ///
    /// # Errors
    /// [`AuthError`] when tokens were offered and none of them verified. The
    /// error describes the *last* failure, since with a single token — the
    /// normal case — that is the only one.
    pub fn identify<'a>(
        &self,
        tokens: impl IntoIterator<Item = &'a [u8]>,
        address: std::net::IpAddr,
        now: SystemTime,
    ) -> Result<Principal, AuthError> {
        let Some(keys) = &self.inner else {
            return Ok(Principal::anonymous(address));
        };

        let mut last = None;
        for token in tokens {
            match keys.verify(token, now) {
                Ok(principal) => return Ok(principal),
                Err(e) => last = Some(e),
            }
        }
        match last {
            Some(e) => Err(e),
            None => Ok(Principal::anonymous(address)),
        }
    }
}

impl Keys {
    fn verify(&self, token: &[u8], now: SystemTime) -> Result<Principal, AuthError> {
        if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
            return Err(AuthError::Malformed("token length is out of range"));
        }

        // Split before decoding anything. The signed message is the first two
        // segments verbatim, so it has to be taken from the original bytes
        // rather than re-encoded from parsed values — a round trip through a
        // JSON parser and back would not reproduce them byte for byte, and the
        // signature is over bytes.
        let mut segments = token.splitn(3, |&byte| byte == b'.');
        let (Some(header_segment), Some(claims_segment), Some(signature_segment)) =
            (segments.next(), segments.next(), segments.next())
        else {
            return Err(AuthError::Malformed("expected three segments"));
        };
        if claims_segment.contains(&b'.') || signature_segment.contains(&b'.') {
            return Err(AuthError::Malformed("expected three segments"));
        }

        let header: Header = decode_segment(header_segment, "header")?;
        if header.alg != ALGORITHM || header.typ != TOKEN_TYPE {
            return Err(AuthError::Unsupported);
        }
        let Some(public) = self.by_id.get(&header.kid) else {
            return Err(AuthError::UnknownKey);
        };

        let signature = URL_SAFE_NO_PAD
            .decode(signature_segment)
            .map_err(|_| AuthError::Malformed("signature is not base64url"))?;

        // The signed message is `header.claims`, which is everything before the
        // final separator.
        let signed = &token[..header_segment.len() + 1 + claims_segment.len()];
        UnparsedPublicKey::new(&ED25519, public.as_slice())
            .verify(signed, &signature)
            .map_err(|_| AuthError::BadSignature)?;

        // Only now are the claims worth reading. Parsing them earlier and
        // acting on the result — even to produce a better error message — is
        // how a verifier becomes a parser an attacker can reach.
        let claims: Claims = decode_segment(claims_segment, "claims")?;

        if !self.issuer.is_empty() && claims.iss != self.issuer {
            return Err(AuthError::WrongIssuer);
        }
        if claims.exp == 0 {
            return Err(AuthError::Malformed("no expiry"));
        }
        let expires = unix(claims.exp);
        if now.saturating_sub(CLOCK_SKEW) > expires {
            return Err(AuthError::Expired);
        }
        if claims.iat != 0 {
            let issued = unix(claims.iat);
            if now + CLOCK_SKEW < issued {
                return Err(AuthError::NotYetValid);
            }
        }

        let device = device_from(&claims.cnf.jkt);
        if claims.aud.is_empty() || claims.sub.is_empty() || device.is_empty() {
            return Err(AuthError::Incomplete);
        }
        Ok(Principal::verified(&claims.aud, &claims.sub, device))
    }
}

fn decode_segment<T: for<'de> Deserialize<'de>>(
    segment: &[u8],
    what: &'static str,
) -> Result<T, AuthError> {
    let decoded = URL_SAFE_NO_PAD.decode(segment).map_err(|_| {
        AuthError::Malformed(if what == "header" {
            "header is not base64url"
        } else {
            "claims are not base64url"
        })
    })?;
    serde_json::from_slice(&decoded).map_err(|_| {
        AuthError::Malformed(if what == "header" {
            "header is not JSON"
        } else {
            "claims are not JSON"
        })
    })
}

/// The device identifier a thumbprint implies.
///
/// Truncated on a byte boundary, and the thumbprint is base64url so every byte
/// is one ASCII character — this cannot split a multi-byte sequence. Matching
/// the Go derivation exactly matters more than the length being any particular
/// number.
fn device_from(thumbprint: &str) -> &str {
    if thumbprint.len() <= DEVICE_ID_LENGTH {
        thumbprint
    } else {
        &thumbprint[..DEVICE_ID_LENGTH]
    }
}

fn unix(seconds: i64) -> SystemTime {
    if seconds < 0 {
        UNIX_EPOCH - Duration::from_secs(seconds.unsigned_abs())
    } else {
        UNIX_EPOCH + Duration::from_secs(seconds.unsigned_abs())
    }
}

/// `SystemTime` has no saturating subtraction and the naive one panics on
/// underflow, which a clock set before 1970 would reach.
trait SaturatingSub {
    fn saturating_sub(self, amount: Duration) -> Self;
}

impl SaturatingSub for SystemTime {
    fn saturating_sub(self, amount: Duration) -> Self {
        self.checked_sub(amount).unwrap_or(UNIX_EPOCH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
    use std::net::{IpAddr, Ipv4Addr};

    const KID: &str = "test-key";

    fn peer() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4))
    }

    /// A deterministic key, so a failing test fails the same way twice.
    fn signer() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).expect("seed is a valid Ed25519 key")
    }

    fn authenticator() -> Authenticator {
        Authenticator::new(
            "https://api.moqom.cloud",
            vec![VerificationKey {
                id: KID.to_owned(),
                bytes: signer().public_key().as_ref().to_vec(),
            }],
        )
    }

    fn segment(value: &serde_json::Value) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("serialisable"))
    }

    /// Mint a token the way the Go control plane does.
    fn mint(header: &serde_json::Value, claims: &serde_json::Value) -> String {
        let signing = format!("{}.{}", segment(header), segment(claims));
        let signature = signer().sign(signing.as_bytes());
        format!(
            "{signing}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        )
    }

    fn header() -> serde_json::Value {
        serde_json::json!({ "alg": "EdDSA", "typ": "MOQT", "kid": KID })
    }

    fn claims(now: SystemTime) -> serde_json::Value {
        let issued = now
            .duration_since(UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs();
        serde_json::json!({
            "iss": "https://api.moqom.cloud",
            "sub": "ada",
            "aud": "acme",
            "jti": "abc",
            "iat": issued,
            "exp": issued + 600,
            "cnf": { "jkt": "OuXpLpEHW7dCPqjKWm8Zq1TfBb2nQ4Zt" },
            "moqt": { "room": "r1", "pub": 3, "cap": 0 },
        })
    }

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_800_000_000 + seconds)
    }

    #[test]
    fn a_signed_token_names_its_holder() {
        let now = at(0);
        let token = mint(&header(), &claims(now));
        let who = authenticator()
            .identify([token.as_bytes()], peer(), now)
            .expect("verifies");

        assert!(who.is_verified());
        // The device is the thumbprint truncated exactly as the control plane
        // truncates it, or a ban and a limit would name different devices.
        assert_eq!(who, Principal::verified("acme", "ada", "OuXpLpEHW7dCPqjK"));
    }

    #[test]
    fn a_tampered_claim_does_not_verify() {
        let now = at(0);
        let mut altered = claims(now);
        altered["sub"] = serde_json::json!("root");
        let signing = format!("{}.{}", segment(&header()), segment(&altered));
        // The signature from the honest token, over the altered claims. This is
        // the attack the whole exercise is for: changing who you are.
        let honest = mint(&header(), &claims(now));
        let signature = honest.rsplit('.').next().expect("three segments");

        let forged = format!("{signing}.{signature}");
        assert_eq!(
            authenticator().identify([forged.as_bytes()], peer(), now),
            Err(AuthError::BadSignature)
        );
    }

    #[test]
    fn an_unsigned_token_is_refused_however_it_asks() {
        let now = at(0);
        // Algorithm confusion, in both of its usual shapes: `none`, and naming
        // a symmetric algorithm in the hope the verifier will use the public
        // key as an HMAC secret. Neither reaches a signature check, because the
        // algorithm is pinned rather than read.
        for alg in ["none", "HS256", "EdDSA "] {
            let header = serde_json::json!({ "alg": alg, "typ": "MOQT", "kid": KID });
            let signing = format!("{}.{}", segment(&header), segment(&claims(now)));
            let token = format!("{signing}.");
            assert_eq!(
                authenticator().identify([token.as_bytes()], peer(), now),
                Err(AuthError::Unsupported),
                "alg {alg} should not be accepted"
            );
        }
    }

    #[test]
    fn a_token_for_something_else_is_not_replayable_here() {
        let now = at(0);
        let header = serde_json::json!({ "alg": "EdDSA", "typ": "JWT", "kid": KID });
        let token = mint(&header, &claims(now));
        assert_eq!(
            authenticator().identify([token.as_bytes()], peer(), now),
            Err(AuthError::Unsupported)
        );
    }

    #[test]
    fn expiry_is_enforced_and_the_skew_is_one_directional() {
        let now = at(0);
        let token = mint(&header(), &claims(now));
        let authenticator = authenticator();

        // Ten minutes, plus the thirty seconds of tolerated skew.
        authenticator
            .identify([token.as_bytes()], peer(), at(600))
            .expect("still inside the skew");
        assert_eq!(
            authenticator.identify([token.as_bytes()], peer(), at(631)),
            Err(AuthError::Expired)
        );

        // A token minted well in the future is refused, but the same skew is
        // tolerated in that direction — a clock is a clock.
        let ahead = mint(&header(), &claims(at(1_000)));
        authenticator
            .identify([ahead.as_bytes()], peer(), at(980))
            .expect("within the skew");
        assert_eq!(
            authenticator.identify([ahead.as_bytes()], peer(), at(960)),
            Err(AuthError::NotYetValid)
        );
    }

    #[test]
    fn another_deployments_token_is_refused() {
        let now = at(0);
        let mut theirs = claims(now);
        theirs["iss"] = serde_json::json!("https://api.example.test");
        let token = mint(&header(), &theirs);
        assert_eq!(
            authenticator().identify([token.as_bytes()], peer(), now),
            Err(AuthError::WrongIssuer)
        );
    }

    #[test]
    fn a_key_we_do_not_hold_is_refused_before_the_signature_is_checked() {
        let now = at(0);
        let header = serde_json::json!({ "alg": "EdDSA", "typ": "MOQT", "kid": "rotated-away" });
        let token = mint(&header, &claims(now));
        assert_eq!(
            authenticator().identify([token.as_bytes()], peer(), now),
            Err(AuthError::UnknownKey)
        );
    }

    #[test]
    fn a_token_with_no_device_names_no_identity() {
        let now = at(0);
        let mut anonymousish = claims(now);
        anonymousish["cnf"] = serde_json::json!({});
        let token = mint(&header(), &anonymousish);
        // Refused rather than accepted with an empty device, because an empty
        // device would put every device that person owns in one bucket and
        // silently merge them.
        assert_eq!(
            authenticator().identify([token.as_bytes()], peer(), now),
            Err(AuthError::Incomplete)
        );
    }

    #[test]
    fn a_claim_this_build_does_not_know_is_ignored() {
        let now = at(0);
        let mut newer = claims(now);
        newer["something_added_later"] = serde_json::json!({ "nested": true });
        let token = mint(&header(), &newer);

        // Ignored rather than refused, because these claims decide only who the
        // holder is and no unknown field can make the subject wrong. This must
        // become strict the day a scope is read from here.
        let who = authenticator()
            .identify([token.as_bytes()], peer(), now)
            .expect("an unfamiliar claim does not break identity");
        assert_eq!(who, Principal::verified("acme", "ada", "OuXpLpEHW7dCPqjK"));
    }

    #[test]
    fn the_first_token_that_verifies_wins() {
        let now = at(0);
        let stale = mint(&header(), &claims(at(0).saturating_sub(Duration::from_hours(1))));
        let fresh = mint(&header(), &claims(now));

        // A client mid-rotation sends both. The option is defined to repeat
        // precisely so this works, and refusing the pair because one of them
        // has expired would break the rotation it exists for.
        let who = authenticator()
            .identify([stale.as_bytes(), fresh.as_bytes()], peer(), now)
            .expect("the good one is found");
        assert!(who.is_verified());
    }

    #[test]
    fn offering_nothing_is_anonymous_and_offering_rubbish_is_an_error() {
        let now = at(0);
        let authenticator = authenticator();

        // No token is not a failure: the deployment decides whether an
        // unauthenticated peer may do anything, by way of the address tier.
        assert_eq!(
            authenticator.identify([], peer(), now),
            Ok(Principal::anonymous(peer()))
        );

        // But a token that was offered and did not verify must not quietly
        // become an anonymous session, or presenting deliberate rubbish would
        // be a way to choose the tier you are limited under.
        for rubbish in [&b""[..], b"...", b"one.two", b"a.b.c", b"\xff\xfe.x.y"] {
            assert!(
                authenticator.identify([rubbish], peer(), now).is_err(),
                "{rubbish:?} should not pass"
            );
        }
    }

    #[test]
    fn an_enormous_token_is_rejected_before_it_is_parsed() {
        let now = at(0);
        let huge = vec![b'A'; MAX_TOKEN_BYTES + 1];
        assert_eq!(
            authenticator().identify([huge.as_slice()], peer(), now),
            Err(AuthError::Malformed("token length is out of range"))
        );
    }

    #[test]
    fn a_disabled_authenticator_never_believes_a_token() {
        let now = at(0);
        let token = mint(&header(), &claims(now));
        let authenticator = Authenticator::disabled();
        assert!(!authenticator.is_verifying());

        // The failure this rules out is the tempting one: with no keys
        // configured, read the claims anyway and use them "for rate limiting
        // only". That is a limiter keyed on an attacker-chosen string.
        assert_eq!(
            authenticator.identify([token.as_bytes()], peer(), now),
            Ok(Principal::anonymous(peer()))
        );
    }

    #[test]
    fn a_jwk_set_is_read_in_either_shape() {
        let x = URL_SAFE_NO_PAD.encode(signer().public_key().as_ref());
        let bare = format!(r#"[{{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"{x}"}}]"#);
        let wrapped = format!(r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"{x}"}}]}}"#);

        for document in [&bare, &wrapped] {
            let keys = VerificationKey::parse_set(document).expect("parses");
            assert_eq!(keys.len(), 1);
            assert_eq!(keys[0].id, "k1");
            assert_eq!(keys[0].bytes.len(), 32);
        }
    }

    #[test]
    fn a_key_of_the_wrong_kind_or_size_is_refused_at_startup() {
        // Refused loudly when the config is read rather than silently at the
        // first session, because a relay that starts with no usable keys and
        // discovers it under load is a relay that authenticates nobody during
        // an incident.
        let short = URL_SAFE_NO_PAD.encode([1u8; 16]);
        for document in [
            format!(r#"[{{"kty":"RSA","crv":"Ed25519","kid":"k","x":"{short}"}}]"#),
            format!(r#"[{{"kty":"OKP","crv":"P-256","kid":"k","x":"{short}"}}]"#),
            format!(r#"[{{"kty":"OKP","crv":"Ed25519","kid":"k","x":"{short}"}}]"#),
            r#"["not an object"]"#.to_owned(),
        ] {
            assert!(
                VerificationKey::parse_set(&document).is_err(),
                "{document} should be refused"
            );
        }
    }

    #[test]
    fn the_error_a_client_can_act_on_is_distinguishable_on_the_wire() {
        use moqom_proto::control::RequestErrorCode as Code;
        // A client that can tell "refresh your token" from "your token is
        // nonsense" recovers from the first and stops retrying on the second.
        assert_eq!(AuthError::Expired.code(), Code::EXPIRED_AUTH_TOKEN);
        assert_eq!(AuthError::Unsupported.code(), Code::MALFORMED_AUTH_TOKEN);
        assert_eq!(AuthError::BadSignature.code(), Code::UNAUTHORIZED);
    }
}
