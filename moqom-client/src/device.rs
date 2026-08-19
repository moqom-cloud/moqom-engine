//! A device key, and the proof of possession it signs.
//!
//! A token on its own is a bearer credential: whoever holds the bytes can use
//! them, so one lifted off a device works from anywhere until it expires. Binding
//! it to a key fixes that. The control plane mints a token committed to a
//! particular public key — as `cnf.jkt`, the RFC 7638 thumbprint — and the relay
//! admits the session only if it also arrives with a signature from the matching
//! private key. A stolen token then buys nothing without the key, and the key does
//! not travel.
//!
//! This is the Rust side of what `MoqomKit`'s `DeviceKey` does on iOS, where the
//! private key lives in the Secure Enclave and cannot be extracted at all. There
//! is no equivalent here: a CLI on a server has a file, and a file can be copied.
//! What it still buys is that the token and the key are separate things to steal,
//! and only one of them is handed out by an API.
//!
//! # What is signed
//!
//! A compact JWS, `ES256`, typed `MOQT-POP` so a JWS minted for anything else --
//! including a token from the same deployment -- cannot be presented as one. Three
//! claims, and each is load-bearing:
//!
//! * `ath`, the hash of the token, which ties this proof to that token and no
//!   other;
//! * `rel`, the hash of the relay's own certificate, which stops a proof gathered
//!   by one relay being replayed against another;
//! * `jti`, a fresh identifier, which a relay accepts once.
//!
//! Together those are why no challenge from the relay is needed, which matters
//! because the client speaks first: SETUP carries the proof, and there is nothing
//! before it to carry a nonce.
//!
//! # On matching the verifier byte for byte
//!
//! The JSON here is assembled by hand rather than serialised. That looks like the
//! wrong instinct and is not: the signature covers the exact bytes of the encoded
//! segments, so a serialiser that reorders a map, adds a space, or pads its base64
//! produces a proof that verifies against nothing. The relay's verifier and the
//! Swift client both hand-assemble for the same reason, and
//! `moqom-relay/tests/testdata/possession.json` is what keeps all three honest.

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Why a device key could not be loaded, or a proof could not be made.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DeviceKeyError {
    /// The bytes are not a PKCS#8 P-256 private key.
    #[error("not a PKCS#8 P-256 private key")]
    Malformed,

    /// A key could not be generated, or its private half could not be serialised.
    #[error("the platform's key store refused: {0}")]
    Unavailable(String),

    /// Signing failed, or the system random source did.
    #[error("signing the proof failed")]
    Signing,
}

/// A P-256 key pair identifying one device.
///
/// The thumbprint is what a token commits to, so this key is the device's name as
/// far as authorisation is concerned: revoking it revokes the machine, which is
/// the property that makes a stolen laptop something an operator can act on.
pub struct DeviceKey {
    pair: EcdsaKeyPair,
    /// Base64url `x` and `y`, decoded once and kept, since every proof needs them
    /// and they cannot change.
    x: String,
    y: String,
}

impl DeviceKey {
    /// Generate a key, returning it with the PKCS#8 bytes to store it as.
    ///
    /// The private bytes come back to the caller rather than being written here,
    /// because where a key belongs is a decision this module should not be making
    /// -- a keyring on one platform, a file with the right mode on another.
    ///
    /// # Errors
    /// The platform's random source or key generation refusing.
    pub fn generate() -> Result<(Self, Vec<u8>), DeviceKeyError> {
        let random = SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &random)
            .map_err(|error| DeviceKeyError::Unavailable(error.to_string()))?;
        let pkcs8 = document.as_ref().to_vec();
        Ok((Self::from_pkcs8(&pkcs8)?, pkcs8))
    }

    /// Load a key from PKCS#8 bytes.
    ///
    /// # Errors
    /// Bytes that are not a PKCS#8 P-256 private key.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, DeviceKeyError> {
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8)
            .map_err(|_| DeviceKeyError::Malformed)?;

        // An uncompressed point: the 0x04 tag, then the two coordinates at the
        // curve's field size. Split by length rather than searched, because both
        // halves are fixed width and a coordinate read at the wrong offset is a
        // different point that fails as a signature bug much later.
        let point = pair.public_key().as_ref();
        if point.len() != 65 || point[0] != 0x04 {
            return Err(DeviceKeyError::Malformed);
        }

        Ok(Self {
            x: URL_SAFE_NO_PAD.encode(&point[1..33]),
            y: URL_SAFE_NO_PAD.encode(&point[33..65]),
            pair,
        })
    }

    /// The public key as a JWK, in the exact form a proof header carries.
    #[must_use]
    pub fn public_key_jwk(&self) -> String {
        format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            self.x, self.y
        )
    }

    /// The RFC 7638 thumbprint, which is what a token's `cnf.jkt` names.
    ///
    /// This is the value to hand whoever mints the token. Without it the token
    /// commits to nothing and the proof has nothing to match.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        // The specification is exact and every part of it matters: the required
        // members and no others, ordered lexicographically, and no whitespace. The
        // JWK above is already in that order, which is why it is written that way
        // and not in the order the fields are declared.
        sha256_base64url(self.public_key_jwk().as_bytes())
    }

    /// Sign a proof that this key holds `token`, for the relay identified by
    /// `relay`.
    ///
    /// `relay` is the base64url SHA-256 of the relay's leaf certificate, which
    /// [`crate::Session::connect`] reads from the completed handshake. A proof
    /// made for one relay is refused by any other.
    ///
    /// # Errors
    /// The system random source or the signature failing.
    pub fn prove(&self, token: &[u8], relay: &str) -> Result<Vec<u8>, DeviceKeyError> {
        let header = format!(
            r#"{{"alg":"ES256","typ":"MOQT-POP","jwk":{}}}"#,
            self.public_key_jwk()
        );
        let claims = format!(
            r#"{{"ath":"{}","jti":"{}","rel":"{relay}"}}"#,
            sha256_base64url(token),
            identifier()?
        );

        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(claims)
        );
        let signature = self
            .pair
            .sign(&SystemRandom::new(), signing_input.as_bytes())
            .map_err(|_| DeviceKeyError::Signing)?;

        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        )
        .into_bytes())
    }
}

impl std::fmt::Debug for DeviceKey {
    /// Prints the thumbprint and nothing else.
    ///
    /// Derived would print the key pair. `EcdsaKeyPair`'s own `Debug` does not
    /// expose the private scalar, so this is a precaution rather than a fix, and
    /// the thumbprint is the useful half in a log anyway.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceKey")
            .field("thumbprint", &self.thumbprint())
            .finish_non_exhaustive()
    }
}

/// What a session presents to be admitted.
///
/// The key is optional because a relay may be running as `bearer` or `observed`,
/// and because a token that commits to no device cannot be proven for. Offering a
/// key the token does not name is worse than offering none where the relay is
/// checking: `observed` admits a session with no proof and refuses one whose proof
/// does not verify.
#[derive(Debug)]
pub struct Credentials<'a> {
    /// The token, exactly as it was issued. The hash in the proof covers these
    /// bytes, so a trailing newline from a shell redirect is a different token.
    pub token: &'a [u8],
    /// The key the token is bound to, if it is bound to one.
    pub key: Option<&'a DeviceKey>,
}

impl<'a> Credentials<'a> {
    /// A bearer token, with no key to prove it.
    #[must_use]
    pub const fn bearer(token: &'a [u8]) -> Self {
        Self { token, key: None }
    }

    /// A token and the key it is bound to.
    #[must_use]
    pub const fn proven(token: &'a [u8], key: &'a DeviceKey) -> Self {
        Self {
            token,
            key: Some(key),
        }
    }
}

/// A fresh proof identifier, which the relay accepts once.
///
/// 128 bits from the system source. Not a counter and not a timestamp: a relay
/// remembers these until the token expires, so two sessions started from one
/// token in the same second must not collide, and the second would be refused as
/// a replay if they did.
fn identifier() -> Result<String, DeviceKeyError> {
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| DeviceKeyError::Signing)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn sha256_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(digest(&SHA256, bytes).as_ref())
}

/// The relay's identity for the `rel` claim: base64url SHA-256 of its leaf
/// certificate, as the DER the handshake presented.
///
/// The leaf and not the chain, and the certificate and not the public key, because
/// the relay computes the same thing over its own configured certificate and the
/// two have to agree exactly.
#[must_use]
pub(crate) fn certificate_identity(der: &[u8]) -> String {
    sha256_base64url(der)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vector from RFC 7517 §A.1, thumbprinted per RFC 7638. The same
    /// assertion exists in the relay's verifier and in the Swift client, and it is
    /// the cheapest way to catch a canonicalisation that has drifted -- a
    /// reordered member or a padded coordinate changes the thumbprint and nothing
    /// else, so the failure would otherwise surface as a token that names a device
    /// nobody is.
    #[test]
    fn the_thumbprint_follows_rfc_7638() {
        let jwk = r#"{"crv":"P-256","kty":"EC","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}"#;
        assert_eq!(
            sha256_base64url(jwk.as_bytes()),
            "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s"
        );
    }

    #[test]
    fn a_key_survives_a_round_trip_through_pkcs8() {
        let (key, pkcs8) = DeviceKey::generate().expect("a key");
        let reloaded = DeviceKey::from_pkcs8(&pkcs8).expect("the same key back");
        assert_eq!(key.thumbprint(), reloaded.thumbprint());
        assert_eq!(key.public_key_jwk(), reloaded.public_key_jwk());
    }

    #[test]
    fn two_keys_are_two_devices() {
        let (first, _) = DeviceKey::generate().expect("a key");
        let (second, _) = DeviceKey::generate().expect("another key");
        assert_ne!(first.thumbprint(), second.thumbprint());
    }

    #[test]
    fn rubbish_is_not_a_key() {
        assert!(matches!(
            DeviceKey::from_pkcs8(b"not a key"),
            Err(DeviceKeyError::Malformed)
        ));
    }

    /// Two proofs over one token must differ, or the second session is refused as
    /// a replay of the first.
    #[test]
    fn every_proof_carries_a_fresh_identifier() {
        let (key, _) = DeviceKey::generate().expect("a key");
        let first = key.prove(b"token", "relay").expect("a proof");
        let second = key.prove(b"token", "relay").expect("another proof");
        assert_ne!(first, second);
    }

    /// The proof is a compact JWS whose header and claims say what the relay
    /// checks. Asserted structurally rather than against a fixed string, since the
    /// signature over a fresh key is different every time.
    #[test]
    fn a_proof_is_a_typed_jws_over_the_token_and_the_relay() {
        let (key, _) = DeviceKey::generate().expect("a key");
        let proof = key.prove(b"token", "the-relay").expect("a proof");
        let proof = String::from_utf8(proof).expect("a proof is ASCII");

        let segments: Vec<&str> = proof.split('.').collect();
        assert_eq!(segments.len(), 3, "header, claims, signature");

        let decode = |segment: &str| {
            String::from_utf8(URL_SAFE_NO_PAD.decode(segment).expect("base64url"))
                .expect("json is utf-8")
        };
        let header = decode(segments[0]);
        assert!(header.contains(r#""alg":"ES256""#), "{header}");
        assert!(header.contains(r#""typ":"MOQT-POP""#), "{header}");
        assert!(header.contains(&key.public_key_jwk()), "{header}");

        let claims = decode(segments[1]);
        assert!(
            claims.contains(&format!(r#""ath":"{}""#, sha256_base64url(b"token"))),
            "{claims}"
        );
        assert!(claims.contains(r#""rel":"the-relay""#), "{claims}");

        // Fixed width, r then s. A DER signature would be about seventy bytes and
        // would fail verification rather than parsing, which is a hard failure to
        // read.
        let signature = URL_SAFE_NO_PAD.decode(segments[2]).expect("base64url");
        assert_eq!(signature.len(), 64);
    }
}
