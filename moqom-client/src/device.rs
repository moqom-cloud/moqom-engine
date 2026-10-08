//! A device key, and the proof of possession it signs.
//!
//! A token on its own is a bearer credential: whoever holds the bytes can use
//! them, so one lifted off a device works from anywhere until it expires. Binding
//! it to a key fixes that. The control plane mints a token committed to a
//! particular public key — as `cnf.jkt`, its JWK thumbprint — and the relay
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
//! A `moqom-proof` proof: a compact JWS typed `MOQT-POP`, `ML-DSA-65` for a key
//! made here and `ES256` for a P-256 key loaded from before the move, with four
//! claims:
//!
//! * `ath`, the hash of the token, which ties this proof to that token and no
//!   other;
//! * `rel`, the hash of the relay's own certificate, which stops a proof gathered
//!   by one relay being replayed against another;
//! * `iat`, when it was made, which a relay holds to a few minutes either way;
//! * `jti`, a fresh identifier, which a relay accepts once.
//!
//! Together those are why no challenge from the relay is needed, which matters
//! because the client speaks first: SETUP carries the proof, and there is nothing
//! before it to carry a nonce.

use std::time::SystemTime;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use moqom_proof::{Algorithm, Prover};

/// Why a device key could not be loaded, or a proof could not be made.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DeviceKeyError {
    /// The bytes are not a PKCS#8 ML-DSA-65 or P-256 private key.
    #[error("not a PKCS#8 ML-DSA-65 or P-256 private key")]
    Malformed,

    /// A key could not be generated, or its private half could not be serialised.
    #[error("the platform's key store refused: {0}")]
    Unavailable(String),

    /// Signing failed, or the system random source did.
    #[error("signing the proof failed")]
    Signing,

    /// The relay's certificate identity is not base64url.
    #[error("the relay's certificate identity is not base64url")]
    Relay,
}

/// A key pair identifying one device: ML-DSA-65 when made here, P-256 when
/// loaded from a key made before proofs moved to ML-DSA.
///
/// The thumbprint is what a token commits to, so this key is the device's name as
/// far as authorisation is concerned: revoking it revokes the machine, which is
/// the property that makes a stolen laptop something an operator can act on.
pub struct DeviceKey {
    prover: Prover,
}

impl DeviceKey {
    /// Generate an ML-DSA-65 key, returning it with the PKCS#8 bytes to store it
    /// as.
    ///
    /// The private bytes come back to the caller rather than being written here,
    /// because where a key belongs is a decision this module should not be making
    /// -- a keyring on one platform, a file with the right mode on another.
    ///
    /// # Errors
    /// The platform's random source or key generation refusing.
    pub fn generate() -> Result<(Self, Vec<u8>), DeviceKeyError> {
        let prover = Prover::generate(Algorithm::MlDsa65)
            .map_err(|error| DeviceKeyError::Unavailable(error.to_string()))?;
        let pkcs8 = prover
            .to_pkcs8()
            .map_err(|error| DeviceKeyError::Unavailable(error.to_string()))?;
        Ok((Self { prover }, pkcs8))
    }

    /// Load a key from PKCS#8 bytes, ML-DSA-65 or P-256.
    ///
    /// # Errors
    /// Bytes that are neither.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, DeviceKeyError> {
        Ok(Self {
            prover: Prover::from_pkcs8(pkcs8).map_err(|_| DeviceKeyError::Malformed)?,
        })
    }

    /// The algorithm this key proves with.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.prover.algorithm()
    }

    /// The public key as a JWK, in the canonical form a proof header carries
    /// and `/join` receives.
    #[must_use]
    pub fn public_key_jwk(&self) -> String {
        self.prover.jwk_json().to_owned()
    }

    /// The JWK thumbprint, which is what a token's `cnf.jkt` names.
    ///
    /// This is the value to hand whoever mints the token. Without it the token
    /// commits to nothing and the proof has nothing to match.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        self.prover.thumbprint().to_owned()
    }

    /// Sign a proof that this key holds `token`, for the relay identified by
    /// `relay`.
    ///
    /// `relay` is the base64url SHA-256 of the relay's leaf certificate, which
    /// [`crate::Session::connect`] reads from the completed handshake. A proof
    /// made for one relay is refused by any other.
    ///
    /// # Errors
    /// A `relay` that is not base64url, or the system random source or the
    /// signature failing.
    pub fn prove(&self, token: &[u8], relay: &str) -> Result<Vec<u8>, DeviceKeyError> {
        let certificate = URL_SAFE_NO_PAD
            .decode(relay)
            .map_err(|_| DeviceKeyError::Relay)?;
        let nonce = moqom_proof::nonce().map_err(|_| DeviceKeyError::Signing)?;
        self.prover
            .prove(token, &certificate, &nonce, SystemTime::now())
            .map_err(|_| DeviceKeyError::Signing)
    }
}

impl std::fmt::Debug for DeviceKey {
    /// Prints the algorithm and thumbprint and nothing else.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceKey")
            .field("algorithm", &self.algorithm())
            .field("thumbprint", &self.prover.thumbprint())
            .finish_non_exhaustive()
    }
}

/// What a session presents to be admitted.
///
/// The key is optional because a token that commits to no device cannot be
/// proven for. Offering a key the token does not name is worse than offering
/// none: a relay refuses a proof that does not verify.
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

/// The relay's identity for the `rel` claim: base64url SHA-256 of its leaf
/// certificate, as the DER the handshake presented.
///
/// The leaf and not the chain, and the certificate and not the public key, because
/// the relay computes the same thing over its own configured certificate and the
/// two have to agree exactly.
#[must_use]
pub(crate) fn certificate_identity(der: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, der).as_ref())
}

#[cfg(test)]
mod tests {
    use moqom_proof::{Checker, MemoryNonceStore};

    use super::*;

    const RELAY: &str = "cGludGhpc3JlbGF5c2NlcnRpZmljYXRlaGFzaA";

    #[test]
    fn a_new_key_is_ml_dsa_65() {
        let (key, _) = DeviceKey::generate().expect("a key");
        assert_eq!(key.algorithm(), Algorithm::MlDsa65);
        assert!(key.public_key_jwk().contains(r#""kty":"AKP""#));
    }

    #[test]
    fn a_key_survives_a_round_trip_through_pkcs8() {
        let (key, pkcs8) = DeviceKey::generate().expect("a key");
        let reloaded = DeviceKey::from_pkcs8(&pkcs8).expect("the same key back");
        assert_eq!(key.thumbprint(), reloaded.thumbprint());
        assert_eq!(key.public_key_jwk(), reloaded.public_key_jwk());
    }

    /// A machine that made its key before the move keeps its identity.
    #[test]
    fn a_p256_key_from_before_the_move_still_loads_and_proves() {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let pkcs8 = aws_lc_rs::signature::EcdsaKeyPair::generate_pkcs8(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .expect("a P-256 key");
        let key = DeviceKey::from_pkcs8(pkcs8.as_ref()).expect("loads");
        assert_eq!(key.algorithm(), Algorithm::Es256);
        let proof = key.prove(b"token", RELAY).expect("a proof");
        assert_eq!(checked(&key, &proof, b"token"), Ok(()));
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
        let first = key.prove(b"token", RELAY).expect("a proof");
        let second = key.prove(b"token", RELAY).expect("another proof");
        assert_ne!(first, second);
        assert_eq!(checked(&key, &first, b"token"), Ok(()));
        assert_eq!(checked(&key, &second, b"token"), Ok(()));
    }

    #[test]
    fn a_proof_names_its_token_and_its_relay() {
        let (key, _) = DeviceKey::generate().expect("a key");
        let proof = key.prove(b"token", RELAY).expect("a proof");
        assert_eq!(checked(&key, &proof, b"token"), Ok(()));
        assert_eq!(
            checked(&key, &proof, b"another"),
            Err(moqom_proof::Error::WrongToken)
        );
        assert!(matches!(
            key.prove(b"token", "not base64url!"),
            Err(DeviceKeyError::Relay)
        ));
    }

    fn checked(key: &DeviceKey, proof: &[u8], token: &[u8]) -> Result<(), moqom_proof::Error> {
        let now = SystemTime::now();
        Checker::new(MemoryNonceStore::default()).check(
            proof,
            token,
            Some(&URL_SAFE_NO_PAD.decode(RELAY).expect("base64url")),
            &key.thumbprint(),
            now,
            now + std::time::Duration::from_mins(10),
        )
    }
}
