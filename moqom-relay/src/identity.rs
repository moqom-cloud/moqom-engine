//! Establishing who a peer is, so that a limit can be charged to them and a
//! permission decided for them.
//!
//! # This is authentication, and the line to authorisation runs through here
//!
//! What this module answers is "who signed this session's token". Whether that
//! holder may publish under the namespace they announce is a separate question,
//! asked and answered in [`scope`] — this module's part is to
//! hand it a [`Permission`] built from a signature that verified, and never
//! from anything a peer merely claimed.
//!
//! The distinction is worth keeping sharp because the two are usually built as
//! one thing. Rate limiting needs only the first half: to charge a limit to a
//! person you must know which person, and you need not know what they may do.
//! Keeping them apart is also what lets a relay run with limits and without
//! authorisation, which is what a relay with no keys configured is.
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
//! ML-DSA-65 (FIPS 204) over JSON claims in the compact JWS serialisation,
//! minted by the Go control plane's `token` package. Ed25519 keys are still read,
//! so tokens signed before the move to ML-DSA verify until they expire. The full
//! design target is CAT/CWT with COSE; this is the subset that exists on both
//! sides today.
//!
//! The `cnf.jkt` thumbprint names the device the token was issued to, and
//! [`crate::possession`] turns naming into proving: every session shows a
//! signature from that device, so a copied token is worth nothing.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::{ED25519, ML_DSA_65, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

use crate::possession::Possession;
use crate::quota::Principal;
use crate::scope::{self, Permission, Publish, capability};

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
/// is watching for. Real tokens are about five kilobytes, nearly all of it the
/// 3,309-byte ML-DSA-65 signature in base64.
const MAX_TOKEN_BYTES: usize = 8192;

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
    /// Not a MOQT token, or naming an algorithm other than its key's.
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
    /// Verified, but for a tenant this relay does not serve. Only a relay
    /// pinned to one tenant -- a customer's own, enrolled for their tenant --
    /// says this.
    #[error("token is for another tenant")]
    WrongTenant,
    /// Verified, but does not name a tenant, user, and device.
    #[error("token does not name a complete identity")]
    Incomplete,
    /// The token verified, but the holder did not prove it is theirs.
    ///
    /// A separate category from the failures above, because everything above is
    /// a statement about the token and this is a statement about who is holding
    /// it. A token that reaches here is perfectly good; it is being presented by
    /// somebody who cannot show the key it was issued to.
    #[error("{0}")]
    Unproven(#[from] crate::possession::ProofError),
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
            // `Unproven` belongs here rather than with the malformed cases, even
            // when the proof itself is what was malformed: the token is fine, and
            // a client told its token was malformed goes and fetches another one,
            // which will not help it.
            Self::UnknownKey
            | Self::BadSignature
            | Self::WrongIssuer
            | Self::WrongTenant
            | Self::Unproven(_) => Code::UNAUTHORIZED,
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
            Self::WrongTenant => "wrong_tenant",
            Self::Incomplete => "incomplete",
            Self::Unproven(e) => e.name(),
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
/// A subset, and unknown top-level fields are ignored rather than refused. That
/// was once safe because these claims decided only *who* somebody is, and it is
/// no longer the whole story: [`Claims::moqt`] now decides what they may do. So
/// the strictness lives where the decision does — see [`Scope`], which refuses
/// a field or a capability bit it does not recognise. A claim beside it that
/// this build has never heard of still cannot make the subject wrong, and
/// refusing those would mean a control plane could not add one without
/// upgrading every relay first.
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
    /// The username whose following brought this session in, if any.
    ///
    /// Read here and not acted on here. It exists so that the relay can report
    /// which audience a session belongs to, and later attribute per-track egress
    /// to it -- when two cohosts bring their own followings to one room, whose
    /// bandwidth B's media is when it reaches A's viewers is a question only the
    /// party forwarding the bytes can answer.
    ///
    /// Deliberately not part of the lax-parsing caveat above: this decides
    /// nothing about what anybody may do, so a token that omits it is a session
    /// nobody brought rather than a session with unknown rights.
    #[serde(default)]
    via: String,

    /// What the holder may do. See [`Scope`].
    ///
    /// Defaulted rather than required, and the default is the least permission
    /// there is: no room, nothing publishable, no powers. A token minted before
    /// this claim existed therefore reaches its holder's own personal channel
    /// and nothing else, which is the failure a missing grant should have.
    #[serde(default)]
    moqt: Scope,
}

#[derive(Deserialize, Default)]
struct Confirmation {
    #[serde(default)]
    jkt: String,
}

/// The `moqt` claim, as the Go control plane mints it.
///
/// Strict, unlike the claims around it, and this is the struct the note there
/// refers to. Two rules, both fail-closed and both matching the minter:
///
/// - An unrecognised **capability bit** is refused, exactly as `Scope.Grants`
///   does in Go. Dropping it would mean a token from a newer control plane
///   quietly granting less than it says, which presents as a moderator whose
///   buttons stopped working and no error anywhere.
/// - An unrecognised **field** is refused too, which Go does not do. The
///   asymmetry is deliberate: this is the enforcement point, and a field added
///   later is at least as likely to narrow a grant as to widen one. Ignoring a
///   narrowing is the failure that matters, so a scope this build cannot fully
///   read is not one it will act on. The cost is an ordering constraint on
///   rollouts — relays learn a new field before the control plane mints it —
///   which the capability rule already imposed.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // the claim's shape, which the minter decides
struct Scope {
    #[serde(default)]
    room: String,
    /// Media kinds, as a bitmask. See [`scope::Publish`](crate::scope::Publish).
    #[serde(default, rename = "pub")]
    publish: u8,
    #[serde(default)]
    cap: u32,
    #[serde(default)]
    own: bool,
    #[serde(default)]
    bs: bool,
    /// Whether the holder passed an age check.
    ///
    /// Declared so the claim parses — the struct refuses fields it does not
    /// know — and deliberately not read. An age gate is a decision about
    /// whether to admit somebody to a room at all, and the control plane makes
    /// it when it mints the token; by the time a session is announcing
    /// namespaces the question has already been answered.
    #[serde(default)]
    #[allow(dead_code)]
    age: bool,
    /// Whether the holder is another relay's link to this one. See
    /// [`scope::Scope::relay`](crate::scope::Scope::relay).
    #[serde(default)]
    rly: bool,
}

/// What a [`VerificationKey`] verifies with.
///
/// A property of the key rather than of the token, which is the whole defence
/// against algorithm confusion: a verifier that dispatches on the token's own
/// `alg` can be told to use `none`, or to verify an HMAC using the public key
/// as the shared secret. A token here must name its key's algorithm, and is
/// verified with that algorithm and no other. The Go minter does the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// ML-DSA-65, which every token and ticket is signed with.
    MlDsa65,
    /// Ed25519, read only to verify what was signed before ML-DSA.
    Ed25519,
}

impl KeyAlgorithm {
    /// The JOSE `alg` a token signed with this key carries.
    #[must_use]
    pub const fn jose(self) -> &'static str {
        match self {
            Self::MlDsa65 => "ML-DSA-65",
            Self::Ed25519 => "EdDSA",
        }
    }

    const fn public_key_bytes(self) -> usize {
        match self {
            Self::MlDsa65 => 1952,
            Self::Ed25519 => 32,
        }
    }
}

/// A public key this relay will accept tokens from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationKey {
    /// The `kid` naming it.
    pub id: String,
    /// What it verifies with.
    pub algorithm: KeyAlgorithm,
    /// The raw public key.
    pub bytes: Vec<u8>,
}

impl VerificationKey {
    /// An ML-DSA-65 key from its 1,952-byte encoding.
    #[must_use]
    pub fn ml_dsa_65(id: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            id: id.into(),
            algorithm: KeyAlgorithm::MlDsa65,
            bytes,
        }
    }

    /// A legacy Ed25519 key from its 32 bytes.
    #[must_use]
    pub fn ed25519(id: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            id: id.into(),
            algorithm: KeyAlgorithm::Ed25519,
            bytes,
        }
    }

    /// Whether `signature` is this key's over `message`, by this key's own
    /// algorithm.
    #[must_use]
    pub fn verifies(&self, message: &[u8], signature: &[u8]) -> bool {
        let algorithm: &dyn aws_lc_rs::signature::VerificationAlgorithm = match self.algorithm {
            KeyAlgorithm::MlDsa65 => &ML_DSA_65,
            KeyAlgorithm::Ed25519 => &ED25519,
        };
        UnparsedPublicKey::new(algorithm, self.bytes.as_slice())
            .verify(message, signature)
            .is_ok()
    }

    /// The key as a JWK, in the shape [`Self::parse_set`] reads.
    #[must_use]
    pub fn jwk(&self) -> serde_json::Value {
        let encoded = URL_SAFE_NO_PAD.encode(&self.bytes);
        match self.algorithm {
            KeyAlgorithm::MlDsa65 => serde_json::json!({
                "kty": "AKP", "alg": "ML-DSA-65", "kid": self.id, "pub": encoded,
            }),
            KeyAlgorithm::Ed25519 => serde_json::json!({
                "kty": "OKP", "crv": "Ed25519", "kid": self.id, "x": encoded,
            }),
        }
    }

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
            #[serde(default)]
            crv: String,
            #[serde(default)]
            alg: String,
            kid: String,
            #[serde(default)]
            x: String,
            #[serde(default, rename = "pub")]
            public: String,
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
                let (algorithm, field, name) = match (jwk.kty.as_str(), jwk.crv.as_str()) {
                    ("AKP", _) if jwk.alg == "ML-DSA-65" => {
                        (KeyAlgorithm::MlDsa65, &jwk.public, "pub")
                    }
                    ("OKP", "Ed25519") => (KeyAlgorithm::Ed25519, &jwk.x, "x"),
                    _ => {
                        return Err(format!(
                            "key {}: only AKP/ML-DSA-65 and OKP/Ed25519 are supported, got {}/{}{}",
                            jwk.kid, jwk.kty, jwk.alg, jwk.crv
                        ));
                    }
                };
                let bytes = URL_SAFE_NO_PAD
                    .decode(field.as_bytes())
                    .map_err(|e| format!("key {}: {name} is not base64url: {e}", jwk.kid))?;
                if bytes.len() != algorithm.public_key_bytes() {
                    return Err(format!(
                        "key {}: an {} public key is {} bytes, got {}",
                        jwk.kid,
                        algorithm.jose(),
                        algorithm.public_key_bytes(),
                        bytes.len()
                    ));
                }
                Ok(Self {
                    id: jwk.kid,
                    algorithm,
                    bytes,
                })
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
///
/// # Why the set can change while the relay runs
///
/// A relay is given keys two ways, and they answer different problems. What an
/// operator puts in `MOQOM_RELAY_JWKS` is fixed for the life of the process: it
/// is an explicit statement, and the only keys a relay with no control plane
/// has. What the control plane pushes over its link arrives later and again on
/// every rotation, which is the half that cannot be a startup constant — a
/// relay that could not follow a rotation would keep working only until the
/// retiring key was withdrawn, and then refuse every session at once.
///
/// So the effective set is the union, recomputed when a push arrives, and a
/// push cannot remove what the operator configured. Sessions read it through a
/// lock rather than holding a copy, because a rotation has to reach the
/// sessions that already exist and not only the next one.
///
/// The push is trusted exactly as far as the link it arrives on, and that link
/// authenticates the relay to the control plane and not the other way around.
/// Anything that can impersonate the control plane's address can therefore
/// publish its own keys — but it can already close sessions and rewrite a
/// room's membership over the same stream, so this widens no door that is not
/// already open. Closing it properly means mutual TLS on the link.
#[derive(Clone)]
pub struct Authenticator {
    inner: Arc<Shared>,
}

struct Shared {
    /// What the operator configured, kept apart so that a push cannot drop it.
    configured: HashMap<String, VerificationKey>,
    /// The union of the above and the most recent push, which is what verifies.
    effective: RwLock<Arc<Keys>>,
}

struct Keys {
    issuer: String,
    /// The one tenant this relay serves, or empty for any.
    tenant: String,
    by_id: HashMap<String, VerificationKey>,
}

impl std::fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keys = self.keys();
        if keys.by_id.is_empty() {
            return f.write_str("Authenticator(no keys)");
        }
        f.debug_struct("Authenticator")
            .field("issuer", &keys.issuer)
            .field("keys", &keys.by_id.len())
            .finish()
    }
}

impl Authenticator {
    /// An authenticator that accepts tokens from `keys`, issued by `issuer`.
    ///
    /// An empty issuer accepts any, which is for tests. A deployment that does
    /// not pin the issuer will accept a token minted by any other deployment
    /// that happens to share a key identifier.
    ///
    /// An empty `keys` is not the same as [`Self::disabled`] even though it
    /// verifies nothing yet: it remembers the issuer, so keys arriving later
    /// from the control plane are checked against the right one.
    #[must_use]
    pub fn new(issuer: impl Into<String>, keys: Vec<VerificationKey>) -> Self {
        let configured: HashMap<_, _> = keys.into_iter().map(|key| (key.id.clone(), key)).collect();
        Self {
            inner: Arc::new(Shared {
                effective: RwLock::new(Arc::new(Keys {
                    issuer: issuer.into(),
                    tenant: String::new(),
                    by_id: configured.clone(),
                })),
                configured,
            }),
        }
    }

    /// The same, refusing every token not issued for `tenant`.
    ///
    /// For a relay a customer runs and enrolled for their own tenant. The
    /// control plane already refuses to tell such a relay about anybody else's
    /// rooms; this is the relay declining to serve them in the first place,
    /// with keys that would otherwise verify every tenant's tokens. Empty is
    /// the same as [`Self::new`].
    #[must_use]
    pub fn for_tenant(
        issuer: impl Into<String>,
        tenant: impl Into<String>,
        keys: Vec<VerificationKey>,
    ) -> Self {
        let authenticator = Self::new(issuer, keys);
        let tenant = tenant.into();
        {
            let mut effective = authenticator
                .inner
                .effective
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *effective = Arc::new(Keys {
                issuer: effective.issuer.clone(),
                tenant,
                by_id: effective.by_id.clone(),
            });
        }
        authenticator
    }

    /// An authenticator with no keys, which verifies nothing.
    ///
    /// Every session is anonymous and charged by address. This is the default
    /// because a relay with no control plane to fetch keys from must still run
    /// for a test harness, and because the alternative — trusting the token
    /// unverified — is the failure mode this whole module exists to prevent.
    #[must_use]
    pub fn disabled() -> Self {
        Self::new("", Vec::new())
    }

    /// Take the keys the control plane published, replacing any earlier push.
    ///
    /// Wholesale rather than additive, because a rotation that retires a key
    /// has to be able to withdraw it: merging every push would leave a relay
    /// trusting a key long after the control plane stopped publishing it, and
    /// the whole point of a retirement is that it eventually takes effect.
    ///
    /// Returns how many keys now verify, which is the union with whatever the
    /// operator configured and so may be larger than what was pushed.
    #[must_use]
    pub fn accept(&self, pushed: Vec<VerificationKey>) -> usize {
        let mut by_id = self.inner.configured.clone();
        by_id.extend(pushed.into_iter().map(|key| (key.id.clone(), key)));
        let count = by_id.len();

        let mut effective = self
            .inner
            .effective
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *effective = Arc::new(Keys {
            issuer: effective.issuer.clone(),
            tenant: effective.tenant.clone(),
            by_id,
        });
        count
    }

    /// The set in force right now.
    fn keys(&self) -> Arc<Keys> {
        Arc::clone(
            &self
                .inner
                .effective
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Whether tokens are checked at all.
    #[must_use]
    pub fn is_verifying(&self) -> bool {
        !self.keys().by_id.is_empty()
    }

    /// Whether this relay checks credentials at all.
    ///
    /// Read by the session to decide what an unauthenticated request means: on
    /// a relay with keys it is a request to deny, and on one without it is the
    /// only kind of request there is.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.is_verifying()
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
    /// The leash is the point. On a relay with keys such a peer is admitted and
    /// may do nothing at all, because a namespace it announced would have no
    /// verified tenant to be checked against. On a relay without keys it is
    /// unrestricted, because there is nothing to check against anywhere and a
    /// relay that refused would be unable to relay.
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
        self.admit(tokens, address, now)
            .map(|admitted| admitted.who)
    }

    /// Who this peer is, and whether it can show that the credential is its own.
    ///
    /// The entry point a session uses. [`Self::admit`] beside it checks the
    /// token and nothing else, which is what a rate limit needs and not what an
    /// admission decision needs; the two are separate so that this one can be the
    /// only thing on the connect path.
    ///
    /// `proof` is the accompanying `AUTHORIZATION_PROOF`, and it decides between
    /// tokens as well as validating one. A client mid-rotation offers an old
    /// credential and a new one, so several may verify, and a proof commits to
    /// exactly one of them — so a token is accepted here when its signature is
    /// good *and* the proof is for that token. Checking the proof against only
    /// the first token that verified would refuse a rotation that was entirely
    /// correct.
    ///
    /// Nothing is proven where there is nothing to prove: a relay holding no keys
    /// admits everybody anonymously without reaching this, and a peer that
    /// offered no token has nothing for a proof to be bound to and is admitted
    /// with the permission to do nothing.
    ///
    /// # Errors
    /// As [`Self::admit`], plus [`AuthError::Unproven`] when a token verified but
    /// its holder could not show the key it names. The distinction matters to
    /// whoever reads the log: the credential was genuine and the session was
    /// still refused.
    pub fn admit_presented(
        &self,
        tokens: &[&[u8]],
        proof: Option<&[u8]>,
        possession: &Possession,
        address: std::net::IpAddr,
        now: SystemTime,
    ) -> Result<Admission, AuthError> {
        let keys = self.keys();
        if keys.by_id.is_empty() {
            return Ok(Admission::anonymous(address));
        }

        let mut last = None;
        for token in tokens {
            let admitted = match keys.verify(token, now) {
                Ok(admitted) => admitted,
                Err(e) => {
                    last = Some(e);
                    continue;
                }
            };

            // A verified token always names a device and always has an expiry —
            // `Keys::verify` refuses one that does not — so the fallbacks here
            // are unreachable rather than lenient. They are written as fallbacks
            // because the alternative is an `expect` on the connect path, and a
            // relay that panics on a malformed credential is a relay anybody can
            // stop.
            let thumbprint = admitted.thumbprint.as_deref().unwrap_or_default();
            let expires = admitted.expires.unwrap_or(now);
            match possession.check(token, proof, thumbprint, expires, now) {
                Ok(()) => return Ok(admitted),
                Err(e) => last = Some(AuthError::Unproven(e)),
            }
        }
        match last {
            Some(e) => Err(e),
            None => Ok(Admission::unauthorised(address)),
        }
    }

    /// The same check, keeping what the token said beyond who it names.
    ///
    /// Separate from [`Self::identify`] rather than replacing it because the two
    /// answer different questions and only one of them may reach a quota key. A
    /// [`Principal`] is what a request is charged against, and it is compared for
    /// equality to find the bucket -- so folding provenance into it would make
    /// two sessions of one user distinct whenever they arrived by different
    /// routes, which is a rate limit anybody could escape by joining twice.
    ///
    /// Checks the token and not its holder, which is the right amount for
    /// charging a limit: the worst a stolen token does to a quota is spend
    /// somebody else's allowance. An admission decision needs more, and belongs
    /// in [`Self::admit_presented`].
    ///
    /// # Errors
    /// As [`Self::identify`].
    pub fn admit<'a>(
        &self,
        tokens: impl IntoIterator<Item = &'a [u8]>,
        address: std::net::IpAddr,
        now: SystemTime,
    ) -> Result<Admission, AuthError> {
        let keys = self.keys();
        if keys.by_id.is_empty() {
            return Ok(Admission::anonymous(address));
        }

        let mut last = None;
        for token in tokens {
            match keys.verify(token, now) {
                Ok(admitted) => return Ok(admitted),
                Err(e) => last = Some(e),
            }
        }
        match last {
            Some(e) => Err(e),
            // Offered nothing, on a relay that can check. Admitted, and
            // permitted nothing: granting the unrestricted permission here
            // would mean that saying nothing bought more than saying something
            // unverifiable, and a relay is easier to use with no token than
            // with a stolen one.
            None => Ok(Admission::unauthorised(address)),
        }
    }
}

/// What a verified token said: who the holder is, what they may do, and who
/// brought them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admission {
    /// Who they are, and the only part of this a limit or a ban may read.
    pub who: Principal,

    /// What they may publish and reach. See [`crate::scope`].
    pub permission: Permission,

    /// The username whose following brought them, from the `via` claim.
    ///
    /// `None` for a session nobody brought, which is the ordinary case rather
    /// than missing information -- a viewer who found the room themselves is a
    /// cohort of their own, and the size of it is how a cohost's contribution is
    /// judged.
    pub via: Option<Arc<str>>,

    /// When the credential stops being valid, from the `exp` claim.
    ///
    /// Kept rather than discarded once checked, which it used to be. A token's
    /// expiry was verified at setup and then forgotten, so a lifetime capped at
    /// minutes bounded only the act of joining: the session it admitted ran for
    /// as long as the connection did. Since a token here is a bearer credential
    /// whose short life is the only thing limiting a stolen one, that made the
    /// mitigation apply to the wrong event.
    ///
    /// `None` where there is nothing to enforce, which is a relay holding no
    /// keys — see [`Self::anonymous`].
    pub expires: Option<SystemTime>,

    /// When the token was minted, from the `iat` claim.
    ///
    /// What orders two credentials for the same person. A renewal that changes
    /// grants must not be older than the credential it replaces, or a client
    /// that kept its host token could hand it back after being demoted and be a
    /// host again — the token is genuine, unexpired and provably theirs, and the
    /// only thing wrong with it is that it has been superseded.
    ///
    /// `None` where the token did not say, or where there was no token.
    pub issued: Option<SystemTime>,

    /// The device key this token was issued to, from `cnf.jkt`, untruncated.
    ///
    /// Distinct from the device in [`Self::who`], which is the first sixteen
    /// characters and is what a ban and a namespace are keyed on. The whole
    /// thumbprint is kept because a proof of possession is checked against it,
    /// and comparing a proof's key to a truncated commitment would leave a peer
    /// free to present any key whose thumbprint shared a prefix — ninety-six
    /// bits is ample to tell one person's phones apart and is not a value to
    /// hang a signature check on.
    ///
    /// `None` where no token said, which is an anonymous or unauthorised
    /// session.
    pub thumbprint: Option<Arc<str>>,
}

impl Admission {
    /// An unauthenticated peer, who by definition arrived through nobody: there
    /// is no signed claim, and an unsigned one is worth less than nothing here.
    ///
    /// Unrestricted, because there is no verified tenant or room to compare a
    /// namespace against and nothing anywhere on this relay to compare it with.
    /// Only reached on a relay with no keys, which is documented, and logs at
    /// startup, as one that authorises nothing.
    #[must_use]
    pub const fn anonymous(address: std::net::IpAddr) -> Self {
        Self {
            who: Principal::anonymous(address),
            permission: Permission::Unrestricted,
            via: None,
            expires: None,
            issued: None,
            thumbprint: None,
        }
    }

    /// The same peer on a relay that does have keys: admitted, and permitted
    /// nothing until it presents one.
    ///
    /// The distinction from [`Self::anonymous`] is the whole of the difference
    /// between a relay that authorises and one that does not, and it used to be
    /// missing -- a peer that offered no token at all was handed the
    /// unrestricted permission on a relay whose entire purpose was to check.
    /// Sending a token that failed to verify ended the session; sending none
    /// bought everything.
    #[must_use]
    pub const fn unauthorised(address: std::net::IpAddr) -> Self {
        Self {
            who: Principal::anonymous(address),
            permission: Permission::Nothing,
            via: None,
            expires: None,
            issued: None,
            thumbprint: None,
        }
    }

    /// The instant a session admitted on this credential must be closed.
    ///
    /// [`Self::expires`] plus the same `CLOCK_SKEW` the verifier allows, and
    /// the tolerance is not optional. Admission accepts a token up to that far
    /// past its `exp`, so enforcing the bare claim would close a session the
    /// handshake had just let in — and the symptom would be a client that
    /// connects and is dropped instantly whenever the relay's clock happens to
    /// run ahead of the minter's.
    ///
    /// `None` where there is nothing to enforce, and that has to stay
    /// distinguishable from a deadline in the past: a relay with no keys admits
    /// everybody, and turning "no expiry" into "expired" would close every
    /// session on it at once.
    #[must_use]
    pub fn deadline(&self) -> Option<SystemTime> {
        self.expires.map(|expires| expires + CLOCK_SKEW)
    }
}

impl Keys {
    fn verify(&self, token: &[u8], now: SystemTime) -> Result<Admission, AuthError> {
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
        if header.typ != TOKEN_TYPE {
            return Err(AuthError::Unsupported);
        }
        let Some(key) = self.by_id.get(&header.kid) else {
            return Err(AuthError::UnknownKey);
        };
        if header.alg != key.algorithm.jose() {
            return Err(AuthError::Unsupported);
        }

        let signature = URL_SAFE_NO_PAD
            .decode(signature_segment)
            .map_err(|_| AuthError::Malformed("signature is not base64url"))?;

        // The signed message is `header.claims`, which is everything before the
        // final separator.
        let signed = &token[..header_segment.len() + 1 + claims_segment.len()];
        if !key.verifies(signed, &signature) {
            return Err(AuthError::BadSignature);
        }

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
        let issued = (claims.iat != 0).then(|| unix(claims.iat));
        if issued.is_some_and(|issued| now + CLOCK_SKEW < issued) {
            return Err(AuthError::NotYetValid);
        }

        let device = device_from(&claims.cnf.jkt);
        if claims.aud.is_empty() || claims.sub.is_empty() || device.is_empty() {
            return Err(AuthError::Incomplete);
        }
        if !self.tenant.is_empty() && claims.aud != self.tenant {
            return Err(AuthError::WrongTenant);
        }
        // A token attributed to its own subject is dropped rather than refused.
        // The control plane will not mint one, so this is defence against a bug
        // rather than an attack, and rejecting the session over it would turn a
        // miscounted audience into somebody unable to watch.
        let via = Some(claims.via)
            .filter(|via| !via.is_empty() && *via != claims.sub)
            .map(Arc::from);

        // Refused rather than masked, matching the Go minter bit for bit. A
        // relay that dropped the bits it did not know would enforce a narrower
        // grant than the one that was issued, silently.
        if claims.moqt.cap & !capability::KNOWN != 0 {
            return Err(AuthError::Unsupported);
        }
        // A relay link reads and does nothing else, and is not metered. A link
        // claim beside any power would be an unmetered session that can
        // publish or moderate, which the control plane never mints, so it is
        // refused rather than given either half.
        //
        // And it names a room. A link is minted per room so that a parent can
        // refuse whatever the edge asks for outside it; one naming none would
        // be an unmetered read of the whole tenant.
        let m = &claims.moqt;
        if m.rly && (m.publish != 0 || m.cap != 0 || m.own || m.bs || m.room.is_empty()) {
            return Err(AuthError::Unsupported);
        }
        let permission = Permission::scoped(scope::Scope {
            tenant: Arc::from(claims.aud.as_str()),
            user: Arc::from(claims.sub.as_str()),
            device: Arc::from(device),
            room: Some(claims.moqt.room)
                .filter(|room| !room.is_empty())
                .map(Arc::from),
            publish: Publish::from_bits(claims.moqt.publish),
            capabilities: claims.moqt.cap,
            owner: claims.moqt.own,
            backstage: claims.moqt.bs,
            relay: claims.moqt.rly,
        });

        Ok(Admission {
            who: Principal::verified(&claims.aud, &claims.sub, device),
            permission,
            via,
            expires: Some(expires),
            issued,
            thumbprint: Some(Arc::from(claims.cnf.jkt.as_str())),
        })
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
            vec![VerificationKey::ed25519(
                KID.to_owned(),
                signer().public_key().as_ref().to_vec(),
            )],
        )
    }

    fn segment(value: &serde_json::Value) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("serialisable"))
    }

    /// Mint a token the way the Go control plane does.
    fn mint(header: &serde_json::Value, claims: &serde_json::Value) -> String {
        let signing = format!("{}.{}", segment(header), segment(claims));
        let signature = signer().sign(signing.as_bytes());
        format!("{signing}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
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
    fn a_token_says_who_brought_its_holder() {
        let now = at(0);
        let mut brought = claims(now);
        brought["via"] = serde_json::json!("bea");
        let token = mint(&header(), &brought);

        let admitted = authenticator()
            .admit([token.as_bytes()], peer(), now)
            .expect("verifies");

        assert_eq!(admitted.via.as_deref(), Some("bea"));
        // And the identity is untouched by it.
        assert_eq!(
            admitted.who,
            Principal::verified("acme", "ada", "OuXpLpEHW7dCPqjK")
        );
    }

    #[test]
    fn provenance_stays_out_of_the_quota_key() {
        // The reason `Admission` exists rather than a field on `Principal`. A
        // principal is compared for equality to find the bucket a request is
        // charged against, so if provenance were part of it, one user could have
        // as many buckets as there are routes into a room -- and shed a rate
        // limit by joining through a different link.
        let now = at(0);
        let mut brought = claims(now);
        brought["via"] = serde_json::json!("bea");
        let mut otherwise = claims(now);
        otherwise["via"] = serde_json::json!("ana");

        let one = authenticator()
            .admit([mint(&header(), &brought).as_bytes()], peer(), now)
            .expect("verifies");
        let two = authenticator()
            .admit([mint(&header(), &otherwise).as_bytes()], peer(), now)
            .expect("verifies");

        assert_ne!(one.via, two.via);
        assert_eq!(one.who, two.who, "the same user, however they arrived");
    }

    #[test]
    fn a_token_nobody_brought_is_ordinary() {
        let now = at(0);
        let admitted = authenticator()
            .admit([mint(&header(), &claims(now)).as_bytes()], peer(), now)
            .expect("verifies");

        // Absent rather than empty, so "arrived alone" is a value and not a
        // string somebody has to remember to check the length of.
        assert_eq!(admitted.via, None);
    }

    #[test]
    fn a_token_attributed_to_itself_is_ignored_not_refused() {
        // The control plane will not mint one, so this is a bug rather than an
        // attack -- and refusing the session over a miscounted audience would
        // stop somebody watching for no good reason.
        let now = at(0);
        let mut itself = claims(now);
        itself["via"] = serde_json::json!("ada");

        let admitted = authenticator()
            .admit([mint(&header(), &itself).as_bytes()], peer(), now)
            .expect("verifies despite the nonsense");

        assert_eq!(admitted.via, None);
        assert!(admitted.who.is_verified());
    }

    #[test]
    fn provenance_cannot_be_rewritten_by_its_holder() {
        // What makes it worth carrying in the token at all: these counts divide
        // money between cohosts.
        let now = at(0);
        let mut brought = claims(now);
        brought["via"] = serde_json::json!("bea");
        let token = mint(&header(), &brought);

        let mut forged = claims(now);
        forged["via"] = serde_json::json!("ana");
        let (head, _) = token.split_once('.').expect("three segments");
        let tail = token.rsplit('.').next().expect("a signature");
        let rewritten = format!("{head}.{}.{tail}", segment(&forged));

        assert_eq!(
            authenticator().admit([rewritten.as_bytes()], peer(), now),
            Err(AuthError::BadSignature)
        );
    }

    #[test]
    fn a_relay_link_is_a_signed_grant_and_only_a_read_only_one() {
        let now = at(0);
        let link = |moqt: serde_json::Value| {
            let mut claims = claims(now);
            claims["moqt"] = moqt;
            authenticator().admit([mint(&header(), &claims).as_bytes()], peer(), now)
        };
        let relay = |admitted: Result<Admission, AuthError>| match &admitted
            .expect("verifies")
            .permission
        {
            Permission::Scoped(scope) => scope.relay,
            other => panic!("expected a scope, got {other:?}"),
        };

        assert!(relay(link(
            serde_json::json!({ "room": "r1", "pub": 0, "cap": 0, "rly": true })
        )));
        assert!(!relay(link(
            serde_json::json!({ "room": "r1", "pub": 0, "cap": 0 })
        )));
        for powers in [
            serde_json::json!({ "pub": 0, "cap": 0, "rly": true }),
            serde_json::json!({ "room": "", "pub": 0, "cap": 0, "rly": true }),
            serde_json::json!({ "pub": 3, "cap": 0, "rly": true }),
            serde_json::json!({ "pub": 0, "cap": 0x100, "rly": true }),
            serde_json::json!({ "pub": 0, "cap": 0, "own": true, "rly": true }),
            serde_json::json!({ "pub": 0, "cap": 0, "bs": true, "rly": true }),
        ] {
            assert_eq!(
                link(powers.clone()).err(),
                Some(AuthError::Unsupported),
                "{powers}"
            );
        }

        // Claimed by its holder rather than granted, it does not verify.
        let token = mint(&header(), &claims(now));
        let mut claimed = claims(now);
        claimed["moqt"]["pub"] = serde_json::json!(0);
        claimed["moqt"]["rly"] = serde_json::json!(true);
        let (head, _) = token.split_once('.').expect("three segments");
        let tail = token.rsplit('.').next().expect("a signature");
        let rewritten = format!("{head}.{}.{tail}", segment(&claimed));
        assert_eq!(
            authenticator()
                .admit([rewritten.as_bytes()], peer(), now)
                .err(),
            Some(AuthError::BadSignature)
        );
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

    fn pinned(tenant: &str) -> Authenticator {
        Authenticator::for_tenant(
            "https://api.moqom.cloud",
            tenant,
            vec![VerificationKey::ed25519(
                KID.to_owned(),
                signer().public_key().as_ref().to_vec(),
            )],
        )
    }

    #[test]
    fn a_relay_pinned_to_a_tenant_refuses_every_other_tenant() {
        let now = at(0);
        let mut theirs = claims(now);
        theirs["aud"] = serde_json::json!("globex");
        let token = mint(&header(), &theirs);
        let error = pinned("acme").identify([token.as_bytes()], peer(), now);
        assert_eq!(error, Err(AuthError::WrongTenant));
        assert_eq!(AuthError::WrongTenant.name(), "wrong_tenant");
        assert_eq!(
            AuthError::WrongTenant.code(),
            moqom_proto::control::RequestErrorCode::UNAUTHORIZED
        );
    }

    #[test]
    fn a_relay_pinned_to_a_tenant_serves_that_tenant() {
        let now = at(0);
        let token = mint(&header(), &claims(now));
        pinned("acme")
            .identify([token.as_bytes()], peer(), now)
            .expect("its own tenant's token");
    }

    #[test]
    fn the_tenant_pin_survives_a_key_push() {
        // Keys arrive over the link and replace the set wholesale; the pin is
        // the operator's and must not go with them.
        let now = at(0);
        let authenticator = pinned("acme");
        let count = authenticator.accept(vec![VerificationKey::ed25519(
            KID.to_owned(),
            signer().public_key().as_ref().to_vec(),
        )]);
        assert_eq!(count, 1);
        let mut theirs = claims(now);
        theirs["aud"] = serde_json::json!("globex");
        assert_eq!(
            authenticator.identify([mint(&header(), &theirs).as_bytes()], peer(), now),
            Err(AuthError::WrongTenant)
        );
    }

    #[test]
    fn an_empty_pin_is_no_pin() {
        let now = at(0);
        let mut theirs = claims(now);
        theirs["aud"] = serde_json::json!("globex");
        pinned("")
            .identify([mint(&header(), &theirs).as_bytes()], peer(), now)
            .expect("any tenant");
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
        let stale = mint(
            &header(),
            &claims(at(0).saturating_sub(Duration::from_hours(1))),
        );
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
    fn offering_no_token_to_a_relay_with_keys_buys_nothing() {
        // The hole this closes: a peer that said nothing used to be handed the
        // unrestricted permission, on a relay whose whole purpose was to check.
        // Presenting a forged token ended the session, and presenting none was
        // better than presenting a real one.
        let admitted = authenticator()
            .admit(std::iter::empty(), peer(), at(0))
            .expect("a peer that claims nothing is admitted, not refused");

        assert_eq!(admitted.who, Principal::anonymous(peer()));
        assert_eq!(admitted.permission, Permission::Nothing);
    }

    #[test]
    fn a_relay_without_keys_still_relays() {
        // The other half of the same decision. With nothing to check against,
        // refusing would leave the relay unable to do the one thing it is for,
        // and this is the mode a test harness and a laptop run in.
        let admitted = Authenticator::disabled()
            .admit(std::iter::empty(), peer(), at(0))
            .expect("admitted");

        assert_eq!(admitted.permission, Permission::Unrestricted);
    }

    #[test]
    fn keys_pushed_by_the_control_plane_start_verifying_sessions() {
        let now = at(0);
        let token = mint(&header(), &claims(now));

        // A relay as it is deployed: an issuer, and no keys until the link
        // brings them.
        let authenticator = Authenticator::new("https://api.moqom.cloud", Vec::new());
        assert!(!authenticator.is_verifying());
        assert_eq!(
            authenticator.identify([token.as_bytes()], peer(), now),
            Ok(Principal::anonymous(peer())),
            "before any key arrives the token is not read, only ignored"
        );

        let pushed = authenticator.accept(vec![VerificationKey::ed25519(
            KID.to_owned(),
            signer().public_key().as_ref().to_vec(),
        )]);

        assert_eq!(pushed, 1);
        assert!(authenticator.is_verifying());
        assert_eq!(
            authenticator.identify([token.as_bytes()], peer(), now),
            Ok(Principal::verified("acme", "ada", "OuXpLpEHW7dCPqjK")),
            "the same token now names its holder"
        );
    }

    #[test]
    fn a_push_cannot_withdraw_what_the_operator_configured() {
        // The two sources answer different problems and only one of them is an
        // explicit statement. A control plane that publishes an empty set, or a
        // different set, must not be able to strip a relay of the keys its
        // operator wrote down -- otherwise the operator's copy is decoration.
        let now = at(0);
        let token = mint(&header(), &claims(now));
        let authenticator = authenticator();

        let _ = authenticator.accept(vec![VerificationKey::ed25519(
            "some-other-key".to_owned(),
            vec![7u8; 32],
        )]);

        assert_eq!(
            authenticator.identify([token.as_bytes()], peer(), now),
            Ok(Principal::verified("acme", "ada", "OuXpLpEHW7dCPqjK"))
        );
    }

    #[test]
    fn a_later_push_replaces_an_earlier_one() {
        // Rotation has to be able to retire a key. If pushes accumulated, a
        // relay would go on trusting a withdrawn key until it restarted, which
        // is the one guarantee a retirement is supposed to make.
        let now = at(0);
        let token = mint(&header(), &claims(now));
        let real =
            VerificationKey::ed25519(KID.to_owned(), signer().public_key().as_ref().to_vec());

        let authenticator = Authenticator::new("https://api.moqom.cloud", Vec::new());
        let _ = authenticator.accept(vec![real]);
        assert!(
            authenticator
                .identify([token.as_bytes()], peer(), now)
                .is_ok()
        );

        let _ = authenticator.accept(vec![VerificationKey::ed25519(
            "the-only-key-now".to_owned(),
            vec![9u8; 32],
        )]);

        assert!(
            authenticator
                .identify([token.as_bytes()], peer(), now)
                .is_err(),
            "a token signed by the retired key is refused once it is withdrawn"
        );
    }

    #[test]
    fn a_jwk_set_is_read_in_either_shape() {
        let x = URL_SAFE_NO_PAD.encode(signer().public_key().as_ref());
        let bare = format!(r#"[{{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"{x}"}}]"#);
        let wrapped =
            format!(r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"{x}"}}]}}"#);

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

    fn ml_dsa_signer() -> aws_lc_rs::signature::PqdsaKeyPair {
        aws_lc_rs::signature::PqdsaKeyPair::from_seed(
            &aws_lc_rs::signature::ML_DSA_65_SIGNING,
            &[8u8; 32],
        )
        .expect("a valid ML-DSA-65 seed")
    }

    fn ml_dsa_mint(alg: &str, kid: &str, claims: &serde_json::Value) -> String {
        let header = serde_json::json!({ "alg": alg, "typ": "MOQT", "kid": kid });
        let signing = format!("{}.{}", segment(&header), segment(claims));
        let mut signature = vec![0u8; aws_lc_rs::signature::ML_DSA_65_SIGNING.signature_len()];
        let written = ml_dsa_signer()
            .sign(signing.as_bytes(), &mut signature)
            .expect("signs");
        signature.truncate(written);
        format!("{signing}.{}", URL_SAFE_NO_PAD.encode(&signature))
    }

    /// Both kinds of key at once, as during the move from Ed25519.
    fn rollover() -> Authenticator {
        Authenticator::new(
            "https://api.moqom.cloud",
            vec![
                VerificationKey::ml_dsa_65("pq", ml_dsa_signer().public_key().as_ref().to_vec()),
                VerificationKey::ed25519(KID, signer().public_key().as_ref().to_vec()),
            ],
        )
    }

    #[test]
    fn an_ml_dsa_token_verifies_beside_a_legacy_ed25519_one() {
        let now = SystemTime::now();
        let authenticator = rollover();
        let pq = ml_dsa_mint("ML-DSA-65", "pq", &claims(now));
        assert!(pq.len() > 4096 && pq.len() < MAX_TOKEN_BYTES);
        assert!(authenticator.identify([pq.as_bytes()], peer(), now).is_ok());
        let legacy = mint(&header(), &claims(now));
        assert!(
            authenticator
                .identify([legacy.as_bytes()], peer(), now)
                .is_ok()
        );
    }

    /// The algorithm belongs to the key, so neither kind of key can be made
    /// to verify with the other's algorithm by what a token's header says.
    #[test]
    fn a_token_naming_another_algorithm_than_its_keys_is_refused() {
        let now = SystemTime::now();
        let authenticator = rollover();
        let claims = claims(now);

        let pq_as_eddsa = ml_dsa_mint("EdDSA", "pq", &claims);
        assert_eq!(
            authenticator
                .identify([pq_as_eddsa.as_bytes()], peer(), now)
                .err(),
            Some(AuthError::Unsupported)
        );
        let legacy_as_pq = mint(
            &serde_json::json!({ "alg": "ML-DSA-65", "typ": "MOQT", "kid": KID }),
            &claims,
        );
        assert_eq!(
            authenticator
                .identify([legacy_as_pq.as_bytes()], peer(), now)
                .err(),
            Some(AuthError::Unsupported)
        );
    }

    #[test]
    fn an_akp_key_is_read_from_a_set() {
        let key = VerificationKey::ml_dsa_65("pq", ml_dsa_signer().public_key().as_ref().to_vec());
        let document = serde_json::json!({ "keys": [key.jwk()] }).to_string();
        assert_eq!(VerificationKey::parse_set(&document), Ok(vec![key]));

        let short = r#"[{"kty":"AKP","alg":"ML-DSA-65","kid":"k","pub":"AAAA"}]"#;
        assert!(VerificationKey::parse_set(short).is_err());
        let other = r#"[{"kty":"AKP","alg":"ML-DSA-44","kid":"k","pub":"AAAA"}]"#;
        assert!(VerificationKey::parse_set(other).is_err());
    }
}
