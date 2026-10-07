//! Direct tickets: the relay's signed statement that a participant is still
//! connected to it, metered, while it holds a direct path to one peer.
//!
//! Direct media never touches a relay, so a relay cannot count it. What it can
//! count is the participant asking it, about once a minute, for a ticket naming
//! the peer it is on a direct path with, and each peer refuses to stay on a
//! direct path with somebody who stops presenting one. A modified app that drops
//! its relay session therefore loses its direct path too, and direct time is
//! billable because it is ticket time, which the relay sees.
//!
//! # Not a token
//!
//! A ticket is a compact JWS like a MOQOM token and is verified the same way,
//! against an ML-DSA-65 JWK by `kid`, but nothing about it can be mistaken for
//! one. Its `typ` is [`TICKET_TYPE`], which a token verifier refuses, and it is
//! signed by a key in a separate set: a relay holds the private half of a
//! ticket key, and a relay holding a key that verified tokens could mint them.
//!
//! The public half reaches peers on the ticket objects themselves. Each peer
//! takes the ticket keys from its own relay session, which is MOQOM's relay
//! over pinned TLS, so a peer never trusts a key the other peer handed it.
//! That works across relays only because the fleet shares its ticket keys,
//! which is why the configuration is a set and why every key in it is
//! published: rotation is a new key added, then signing moved, then the old one
//! removed once its tickets have expired.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::{KeyPair, ML_DSA_65_SIGNING, PqdsaKeyPair};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::identity::{KeyAlgorithm, VerificationKey};

/// The JWS `typ` every ticket carries and a token never does.
pub const TICKET_TYPE: &str = "moqom-direct-ticket";

/// How often a ticket is reissued while its subscription is open.
pub const RENEW: Duration = Duration::from_mins(1);

/// How long a ticket is good for. Longer than [`RENEW`] by enough to cover a
/// late renewal and a peer's clock, and short enough that a participant who
/// stops renewing loses its direct path within a minute and a half.
pub const LIFETIME: Duration = Duration::from_secs(90);

/// Clock skew allowed between the relay that signed a ticket and the peer
/// checking it. The same allowance a token gets.
pub const CLOCK_SKEW: Duration = Duration::from_secs(30);

/// Longest ticket a peer reads. A real one is about 4.7 kilobytes, nearly all of
/// it the 3,309-byte ML-DSA-65 signature in base64.
const LONGEST: usize = 8192;

/// The ticket keys a relay signs with and publishes.
pub struct TicketKeys {
    signer: PqdsaKeyPair,
    kid: String,
    published: Vec<VerificationKey>,
}

impl std::fmt::Debug for TicketKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TicketKeys")
            .field("kid", &self.kid)
            .field("published", &self.published.len())
            .finish_non_exhaustive()
    }
}

impl TicketKeys {
    /// Read a JWK set. The first ML-DSA-65 key (`AKP`) with a private seed
    /// (`priv`) signs; every key's public half is published, including Ed25519
    /// (`OKP`) keys, which only verify tickets issued before the move.
    ///
    /// # Errors
    /// What is wrong with the document, for the operator who wrote it.
    pub fn parse(document: &str) -> Result<Self, String> {
        #[derive(Deserialize)]
        struct Jwk {
            kty: String,
            #[serde(default)]
            crv: String,
            #[serde(default)]
            alg: String,
            kid: String,
            #[serde(default)]
            x: String,
            #[serde(default, rename = "pub")]
            public: String,
            #[serde(default, rename = "priv")]
            private: Option<String>,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Document {
            Wrapped { keys: Vec<Jwk> },
            Bare(Vec<Jwk>),
        }

        let parsed: Document =
            serde_json::from_str(document).map_err(|e| format!("not a JWK set: {e}"))?;
        let (Document::Wrapped { keys } | Document::Bare(keys)) = parsed;

        let mut signer = None;
        let mut published = Vec::with_capacity(keys.len());
        for jwk in keys {
            match (jwk.kty.as_str(), jwk.crv.as_str()) {
                ("AKP", _) if jwk.alg == "ML-DSA-65" => {
                    let public = URL_SAFE_NO_PAD
                        .decode(&jwk.public)
                        .map_err(|_| format!("ticket key {}: bad pub", jwk.kid))?;
                    if let (Some(private), None) = (&jwk.private, &signer) {
                        let seed = decode_32(private)
                            .ok_or_else(|| format!("ticket key {}: bad priv", jwk.kid))?;
                        let pair = PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, &seed)
                            .map_err(|_| format!("ticket key {}: bad priv", jwk.kid))?;
                        if pair.public_key().as_ref() != public.as_slice() {
                            return Err(format!(
                                "ticket key {}: priv and pub are not one key",
                                jwk.kid
                            ));
                        }
                        signer = Some((pair, jwk.kid.clone()));
                    }
                    published.push(VerificationKey::ml_dsa_65(jwk.kid, public));
                }
                ("OKP", "Ed25519") => {
                    let public = decode_32(&jwk.x)
                        .ok_or_else(|| format!("ticket key {}: bad x", jwk.kid))?;
                    published.push(VerificationKey::ed25519(jwk.kid, public.to_vec()));
                }
                _ => {
                    return Err(format!(
                        "ticket key {}: only AKP/ML-DSA-65 and OKP/Ed25519 are supported",
                        jwk.kid
                    ));
                }
            }
        }
        let (signer, kid) =
            signer.ok_or("no ML-DSA-65 ticket key has a private seed (priv) to sign with")?;
        Ok(Self {
            signer,
            kid,
            published,
        })
    }

    /// One ML-DSA-65 key, from its FIPS 204 seed. For tests and for embedders
    /// that hold their own.
    ///
    /// # Panics
    /// Never for a 32-byte seed.
    #[must_use]
    pub fn from_seed(kid: impl Into<String>, seed: &[u8; 32]) -> Self {
        let signer =
            PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, seed).expect("any 32 bytes are a seed");
        let kid = kid.into();
        let published = vec![VerificationKey::ml_dsa_65(
            kid.clone(),
            signer.public_key().as_ref().to_vec(),
        )];
        Self {
            signer,
            kid,
            published,
        }
    }

    /// Every public key, as JWKs, for the ticket objects.
    #[must_use]
    pub fn public_jwks(&self) -> Vec<serde_json::Value> {
        self.published.iter().map(VerificationKey::jwk).collect()
    }

    /// Every public key, for verifying.
    #[must_use]
    pub fn verification_keys(&self) -> &[VerificationKey] {
        &self.published
    }

    /// Sign `claims`.
    ///
    /// # Panics
    /// Never: the claims are plain strings and integers.
    #[must_use]
    pub fn issue(&self, claims: &Claims) -> String {
        let header = serde_json::json!({
            "alg": KeyAlgorithm::MlDsa65.jose(), "typ": TICKET_TYPE, "kid": self.kid,
        });
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("a JSON object"));
        let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("a JSON object"));
        let signed = format!("{header}.{body}");
        let mut signature = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
        let written = self
            .signer
            .sign(signed.as_bytes(), &mut signature)
            .expect("ML-DSA-65 signs any message");
        signature.truncate(written);
        format!("{signed}.{}", URL_SAFE_NO_PAD.encode(&signature))
    }
}

fn decode_32(text: &str) -> Option<[u8; 32]> {
    URL_SAFE_NO_PAD.decode(text).ok()?.try_into().ok()
}

/// What a ticket says.
///
/// Short claim names, like a token's, because it crosses the network once a
/// minute per direct pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    /// The tenant.
    pub ten: String,
    /// The room.
    pub room: String,
    /// The holder's user.
    pub sub: String,
    /// The holder's device: the first sixteen characters of its key thumbprint,
    /// as in every participant name.
    pub dev: String,
    /// The peer it is for, as `user/device`.
    pub peer: String,
    /// Issued at, in seconds since the epoch.
    pub iat: u64,
    /// Expires at, in seconds since the epoch.
    pub exp: u64,
}

impl Claims {
    /// A ticket for `holder` (`tenant`, `room`, `user`, `device`) on a direct
    /// path to `peer`, issued `now` and lasting [`LIFETIME`].
    #[must_use]
    pub fn new(
        tenant: &str,
        room: &str,
        user: &str,
        device: &str,
        peer: &str,
        now: SystemTime,
    ) -> Self {
        let iat = unix(now);
        Self {
            ten: tenant.to_owned(),
            room: room.to_owned(),
            sub: user.to_owned(),
            dev: device.to_owned(),
            peer: peer.to_owned(),
            iat,
            exp: iat + LIFETIME.as_secs(),
        }
    }

    /// The holder, as `user/device`.
    #[must_use]
    pub fn holder(&self) -> String {
        format!("{}/{}", self.sub, self.dev)
    }
}

fn unix(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Why a peer's ticket was refused. Each one ends the direct path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TicketError {
    /// Not a compact JWS this verifier reads.
    #[error("the ticket is malformed")]
    Malformed,
    /// Signed with another algorithm, or not a ticket.
    #[error("not a direct ticket")]
    Unsupported,
    /// Signed by a key outside the ticket set.
    #[error("the ticket's key is not a ticket key")]
    UnknownKey,
    /// The signature does not verify.
    #[error("the ticket's signature does not verify")]
    BadSignature,
    /// Past its expiry, allowing for skew.
    #[error("the ticket has expired")]
    Expired,
    /// Issued in the future, allowing for skew.
    #[error("the ticket is not valid yet")]
    NotYetValid,
    /// For another tenant, room or holder than the peer verified at setup.
    #[error("the ticket names somebody other than the peer")]
    WrongHolder,
    /// For a direct path to somebody else.
    #[error("the ticket is for a direct path to somebody else")]
    WrongPeer,
}

/// Who the checking side verified at setup, and who it is.
#[derive(Clone, Copy, Debug)]
pub struct Expected<'a> {
    /// The peer's tenant.
    pub tenant: &'a str,
    /// The peer's room.
    pub room: &'a str,
    /// The peer, as `user/device`.
    pub holder: &'a str,
    /// The checking side, as `user/device`.
    pub peer: &'a str,
}

/// Check a peer's ticket.
///
/// # Errors
/// [`TicketError`], every one of which ends the direct path.
pub fn verify(
    keys: &[VerificationKey],
    ticket: &[u8],
    expected: Expected<'_>,
    now: SystemTime,
) -> Result<Claims, TicketError> {
    #[derive(Deserialize)]
    struct Header {
        alg: String,
        typ: String,
        kid: String,
    }

    if ticket.len() > LONGEST {
        return Err(TicketError::Malformed);
    }
    let mut segments = ticket.split(|&byte| byte == b'.');
    let (Some(header), Some(body), Some(signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(TicketError::Malformed);
    };
    let decode = |segment: &[u8]| {
        URL_SAFE_NO_PAD
            .decode(segment)
            .map_err(|_| TicketError::Malformed)
    };
    let parsed: Header =
        serde_json::from_slice(&decode(header)?).map_err(|_| TicketError::Malformed)?;
    if parsed.typ != TICKET_TYPE {
        return Err(TicketError::Unsupported);
    }
    let key = keys
        .iter()
        .find(|key| key.id == parsed.kid)
        .ok_or(TicketError::UnknownKey)?;
    if parsed.alg != key.algorithm.jose() {
        return Err(TicketError::Unsupported);
    }
    if !key.verifies(
        &ticket[..header.len() + 1 + body.len()],
        &decode(signature)?,
    ) {
        return Err(TicketError::BadSignature);
    }

    let claims: Claims =
        serde_json::from_slice(&decode(body)?).map_err(|_| TicketError::Malformed)?;
    let now = unix(now);
    if now > claims.exp + CLOCK_SKEW.as_secs() {
        return Err(TicketError::Expired);
    }
    if now + CLOCK_SKEW.as_secs() < claims.iat {
        return Err(TicketError::NotYetValid);
    }
    if claims.ten != expected.tenant
        || claims.room != expected.room
        || claims.holder() != expected.holder
    {
        return Err(TicketError::WrongHolder);
    }
    if claims.peer != expected.peer {
        return Err(TicketError::WrongPeer);
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED: Expected<'static> = Expected {
        tenant: "acme",
        room: "room-42",
        holder: "ada/OuXpLpEHW7dCPqjK",
        peer: "bob/0123456789abcdef",
    };

    fn keys() -> TicketKeys {
        TicketKeys::from_seed("ticket-1", &[3u8; 32])
    }

    fn claims(now: SystemTime) -> Claims {
        Claims::new(
            "acme",
            "room-42",
            "ada",
            "OuXpLpEHW7dCPqjK",
            "bob/0123456789abcdef",
            now,
        )
    }

    #[test]
    fn a_ticket_verifies_against_the_published_keys() {
        let keys = keys();
        let now = SystemTime::now();
        let ticket = keys.issue(&claims(now));
        let read = verify(keys.verification_keys(), ticket.as_bytes(), EXPECTED, now)
            .expect("a fresh ticket");
        assert_eq!(read.exp - read.iat, LIFETIME.as_secs());
    }

    #[test]
    fn a_forged_ticket_is_refused() {
        let now = SystemTime::now();
        let forger = TicketKeys::from_seed("ticket-1", &[4u8; 32]);
        let ticket = forger.issue(&claims(now));
        assert_eq!(
            verify(keys().verification_keys(), ticket.as_bytes(), EXPECTED, now),
            Err(TicketError::BadSignature)
        );

        let mut tampered = keys().issue(&claims(now)).into_bytes();
        let body = tampered.iter().position(|&b| b == b'.').expect("a header") + 3;
        tampered[body] ^= 1;
        assert!(verify(keys().verification_keys(), &tampered, EXPECTED, now).is_err());
    }

    #[test]
    fn an_expired_ticket_is_refused_after_the_skew() {
        let keys = keys();
        let then = SystemTime::now();
        let ticket = keys.issue(&claims(then));
        let at = |seconds: u64| then + Duration::from_secs(seconds);
        let lasts = LIFETIME.as_secs() + CLOCK_SKEW.as_secs();
        assert!(
            verify(
                keys.verification_keys(),
                ticket.as_bytes(),
                EXPECTED,
                at(lasts)
            )
            .is_ok()
        );
        assert_eq!(
            verify(
                keys.verification_keys(),
                ticket.as_bytes(),
                EXPECTED,
                at(lasts + 2)
            ),
            Err(TicketError::Expired)
        );
    }

    #[test]
    fn a_ticket_is_bound_to_its_holder_room_and_peer() {
        let keys = keys();
        let now = SystemTime::now();
        let ticket = keys.issue(&claims(now));
        let check = |expected| verify(keys.verification_keys(), ticket.as_bytes(), expected, now);
        assert_eq!(
            check(Expected {
                room: "room-43",
                ..EXPECTED
            }),
            Err(TicketError::WrongHolder)
        );
        assert_eq!(
            check(Expected {
                tenant: "other",
                ..EXPECTED
            }),
            Err(TicketError::WrongHolder)
        );
        assert_eq!(
            check(Expected {
                holder: "eve/OuXpLpEHW7dCPqjK",
                ..EXPECTED
            }),
            Err(TicketError::WrongHolder)
        );
        assert_eq!(
            check(Expected {
                peer: "carol/0123456789abcdef",
                ..EXPECTED
            }),
            Err(TicketError::WrongPeer)
        );
    }

    /// A token is never a ticket, even one signed by a ticket key.
    #[test]
    fn a_token_shaped_jws_is_not_a_ticket() {
        let keys = keys();
        let header =
            URL_SAFE_NO_PAD.encode(br#"{"alg":"ML-DSA-65","typ":"MOQT","kid":"ticket-1"}"#);
        let body =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims(SystemTime::now())).expect("claims"));
        let signed = format!("{header}.{body}");
        let mut signature = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
        let written = keys
            .signer
            .sign(signed.as_bytes(), &mut signature)
            .expect("signs");
        signature.truncate(written);
        let jws = format!("{signed}.{}", URL_SAFE_NO_PAD.encode(&signature));
        assert_eq!(
            verify(
                keys.verification_keys(),
                jws.as_bytes(),
                EXPECTED,
                SystemTime::now()
            ),
            Err(TicketError::Unsupported)
        );
    }

    #[test]
    fn a_key_set_signs_with_its_first_private_key_and_publishes_all() {
        let seed = [5u8; 32];
        let pair = PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, &seed).expect("seed");
        let public = URL_SAFE_NO_PAD.encode(pair.public_key().as_ref());
        let private = URL_SAFE_NO_PAD.encode(seed);
        let other = PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, &[6u8; 32]).expect("seed");
        let other = URL_SAFE_NO_PAD.encode(other.public_key().as_ref());
        let old = URL_SAFE_NO_PAD.encode([9u8; 32]);
        let document = format!(
            r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","kid":"old","x":"{old}"}},
                {{"kty":"AKP","alg":"ML-DSA-65","kid":"new","pub":"{public}","priv":"{private}"}}]}}"#
        );
        let keys = TicketKeys::parse(&document).expect("a set");
        assert_eq!(keys.kid, "new");
        assert_eq!(keys.public_jwks().len(), 2);
        assert!(
            keys.public_jwks()
                .iter()
                .all(|jwk| jwk.get("priv").is_none())
        );

        let mismatched = document.replace(&public, &other);
        assert!(TicketKeys::parse(&mismatched).is_err());
        assert!(TicketKeys::parse(&document.replace(r#","priv":""#, r#","e":""#)).is_err());
    }

    /// An Ed25519 ticket key only verifies: a set with no ML-DSA-65 key to
    /// sign with is refused.
    #[test]
    fn an_ed25519_ticket_key_never_signs() {
        let seed = URL_SAFE_NO_PAD.encode([5u8; 32]);
        let x = URL_SAFE_NO_PAD.encode(
            aws_lc_rs::signature::Ed25519KeyPair::from_seed_unchecked(&[5u8; 32])
                .expect("seed")
                .public_key()
                .as_ref(),
        );
        let document =
            format!(r#"[{{"kty":"OKP","crv":"Ed25519","kid":"old","x":"{x}","d":"{seed}"}}]"#);
        assert!(TicketKeys::parse(&document).is_err());
    }
}
