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
//! # Freshness without a server nonce or a round trip
//!
//! The awkward part of proving possession here is that the client speaks first.
//! It opens the control stream and sends SETUP, so there is no earlier moment at
//! which the relay could have handed out a challenge — a server nonce would mean
//! a second round trip on every connection and a session state that is admitted
//! but not yet allowed to do anything.
//!
//! None is needed, because the token already carries the uniqueness a nonce would
//! have supplied. A proof commits to its token by hash (its `ath`), so it is usable
//! with that token and no other; the token expires in minutes; a proof's `iat`
//! must be within a few minutes of this relay's clock; and a proof's own
//! identifier is accepted exactly once, remembered for as long as the token it
//! names could still be presented. Replay therefore requires a proof that was
//! captured but never delivered, for a token that has not expired, at the relay
//! it was made for, within minutes of its making. Capturing one at all means
//! reading it out of QUIC, and an attacker who can do that can read the token
//! beside it and has no need of any of this.
//!
//! The residual is worth stating rather than implying: a relay that restarts
//! forgets which proofs it has seen, so a captured-and-undelivered proof could be
//! replayed within its window. Persisting the set across restarts would trade
//! that for a write on the connect path and a new way for a relay to fail, which
//! is not a good trade for an attack that begins with breaking TLS.
//!
//! # The algorithms
//!
//! `ML-DSA-65` and nothing else, because the point of this module is a key that
//! cannot be extracted and the Secure Enclave holds ML-DSA-65 keys from iOS 26
//! and macOS 26. `ES256`, which the enclave held before, is refused: a P-256
//! device key is a signature a quantum adversary could forge later, against a
//! credential that names the key forever. Ed25519 is not accepted either:
//! `CryptoKit` offers it only in software, with the private key in ordinary
//! memory — where it can be dumped alongside the token by exactly the attacker
//! this exists to stop.
//!
//! The list is this module's rather than `moqom-proof`'s, so that the library
//! still knowing an algorithm cannot widen what the relay admits.
//!
//! The format and the check are `moqom-proof`'s, shared with the clients and
//! the control plane; this module adds the relay's policy, its spent set and its
//! names for the failures.

use std::time::SystemTime;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use moqom_proof::{Algorithm, Checker, MemoryNonceStore};

/// What a device key may be. See the module docs.
const ALGORITHMS: &[Algorithm] = &[Algorithm::MlDsa65];

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
    /// Signed with an algorithm this relay does not accept, or not a proof at
    /// all.
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
    /// It verified, and was made too long ago to be fresh.
    #[error("proof was made too long ago")]
    Expired,
    /// It verified, and claims to have been made in the future.
    #[error("proof is dated in the future")]
    NotYetValid,
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
            Self::Expired => "proof_expired",
            Self::NotYetValid => "proof_not_yet_valid",
            Self::Replayed => "proof_replayed",
            Self::Overloaded => "proof_overloaded",
        }
    }
}

impl From<moqom_proof::Error> for ProofError {
    fn from(error: moqom_proof::Error) -> Self {
        use moqom_proof::Error as E;
        match error {
            E::Malformed(why) => Self::Malformed(why),
            E::BadSignature => Self::BadSignature,
            E::WrongKey => Self::WrongKey,
            E::WrongToken => Self::WrongToken,
            E::WrongCertificate => Self::WrongRelay,
            E::Expired => Self::Expired,
            E::NotYetValid => Self::NotYetValid,
            E::Replayed => Self::Replayed,
            E::Overloaded => Self::Overloaded,
            _ => Self::Unsupported,
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

    /// The check, and the proof identifiers already spent, each remembered until
    /// the token its proof named expires: after that the token is refused on its
    /// own account and a proof for it is worthless.
    checker: Checker<MemoryNonceStore>,
}

impl Possession {
    /// A checker in the given mode, for a relay identified by `certificate`.
    ///
    /// `certificate` is the SHA-256 of the relay's certificate in base64url, the
    /// same digest the client pins. `None` disables the relay binding; see the
    /// note on the `relay` field.
    ///
    /// # Panics
    /// Never: the algorithm list is a constant and not empty.
    #[must_use]
    pub fn new(mode: Enforcement, certificate: Option<String>) -> Self {
        Self {
            mode,
            relay: certificate,
            checker: Checker::new(MemoryNonceStore::default())
                .with_algorithms(ALGORITHMS)
                .expect("the list is not empty"),
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
        // An identity that does not decode can match no proof, so it refuses
        // every one rather than falling back to checking none.
        let certificate = match &self.relay {
            Some(relay) => Some(
                URL_SAFE_NO_PAD
                    .decode(relay)
                    .map_err(|_| ProofError::WrongRelay)?,
            ),
            None => None,
        };
        self.checker
            .check(
                proof,
                token,
                certificate.as_deref(),
                thumbprint,
                now,
                expires,
            )
            .map_err(ProofError::from)
    }

    /// How many spent identifiers are being remembered, for tests and metrics.
    #[must_use]
    pub fn remembered(&self) -> usize {
        self.checker.store().remembered()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use moqom_proof::{Jwk, NonceStore as _, Prover};
    use serde::Deserialize;

    use super::*;

    const RELAY: &str = "cGludGhpc3JlbGF5c2NlcnRpZmljYXRlaGFzaA";

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    fn relay_hash(relay: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD.decode(relay).expect("base64url")
    }

    /// A device key, and the thumbprint a token would commit to.
    struct Device {
        prover: Prover,
    }

    impl Device {
        fn new() -> Self {
            Self {
                prover: Prover::generate(Algorithm::MlDsa65).expect("a key"),
            }
        }

        fn thumbprint(&self) -> String {
            self.prover.thumbprint().to_owned()
        }

        /// A proof over `token`, as the client builds one.
        fn prove(&self, token: &[u8], id: &str, relay: &str) -> Vec<u8> {
            self.prover
                .prove(token, &relay_hash(relay), id, now())
                .expect("a proof")
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
    fn a_stale_proof_is_refused() {
        let device = Device::new();
        let token = b"a.token";
        let proof = device.prove(token, "one", RELAY);

        assert_eq!(
            checker().check(
                token,
                Some(&proof),
                &device.thumbprint(),
                expires(),
                now() + Duration::from_mins(6)
            ),
            Err(ProofError::Expired)
        );
        assert_eq!(
            checker().check(
                token,
                Some(&proof),
                &device.thumbprint(),
                expires(),
                now() - Duration::from_mins(6)
            ),
            Err(ProofError::NotYetValid)
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
        let middle = bad.len() - 10;
        bad[middle] = if bad[middle] == b'A' { b'B' } else { b'A' };
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

        for n in 0..moqom_proof::DEFAULT_CAPACITY {
            checker
                .checker
                .store()
                .spend(&format!("old-{n}"), now(), now())
                .expect("room for another");
        }
        assert_eq!(checker.remembered(), moqom_proof::DEFAULT_CAPACITY);

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
        let device = Device::new();
        for n in 0..moqom_proof::DEFAULT_CAPACITY {
            checker
                .checker
                .store()
                .spend(&format!("live-{n}"), expires(), now())
                .expect("room for another");
        }
        let token = b"a.token";
        assert_eq!(
            checker.check(
                token,
                Some(&device.prove(token, "one-more", RELAY)),
                &device.thumbprint(),
                expires(),
                now()
            ),
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
            &vec![b'a'; moqom_proof::MAX_PROOF_BYTES + 1],
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

    /// An identity this relay was configured with that is not base64url can
    /// match no proof, and must not fall back to checking no binding.
    #[test]
    fn an_identity_that_does_not_decode_refuses_every_proof() {
        let device = Device::new();
        let token = b"a.token";
        let proof = device.prove(token, "one", "");
        let broken = Possession::new(Enforcement::Required, Some("not base64url!".to_owned()));
        assert_eq!(
            broken.check(token, Some(&proof), &device.thumbprint(), expires(), now()),
            Err(ProofError::WrongRelay)
        );
    }

    #[test]
    fn only_required_is_read_from_configuration() {
        assert_eq!(Enforcement::parse(" Required "), Ok(Enforcement::Required));
        for removed in ["bearer", "observed", "yes"] {
            assert!(Enforcement::parse(removed).is_err(), "{removed}");
        }
    }

    /// The proofs above are made by the same library that checks them, which is
    /// the one thing this module's tests cannot establish on their own: a
    /// mistake shared by the builder and the verifier passes every test in this
    /// file and fails against the only client that exists.
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
            /// When the proofs were made, which their `iat` says.
            now: u64,
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

        fn made(read: &Fixture) -> SystemTime {
            SystemTime::UNIX_EPOCH + Duration::from_secs(read.now)
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
                    case.jwk.thumbprint().expect("a well-formed vector"),
                    case.thumbprint,
                    "{}: the client and this relay disagree about the thumbprint",
                    case.name
                );
            }
        }

        /// Every proof the client produced is one this relay accepts, and every
        /// one is ML-DSA-65: a fixture still carrying another algorithm is a
        /// client still making it.
        ///
        /// A fresh checker per case, because a shared one would spend the
        /// identifiers and the second half of the loop would be testing the
        /// replay cache instead of the format.
        #[test]
        fn every_proof_the_client_makes_is_accepted() {
            let read = fixture();
            let mut algorithms = std::collections::HashSet::new();
            for case in &read.proofs {
                let checker = Possession::new(Enforcement::Required, Some(read.relay.clone()));
                assert_eq!(
                    checker.check(
                        case.token.as_bytes(),
                        Some(case.proof.as_bytes()),
                        &case.thumbprint,
                        made(&read) + Duration::from_mins(10),
                        made(&read),
                    ),
                    Ok(()),
                    "{}: the client's proof was refused",
                    case.name
                );
                let header = case.proof.split('.').next().unwrap_or_default();
                let header: serde_json::Value =
                    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).expect("base64url"))
                        .expect("a JSON header");
                algorithms.insert(header["alg"].as_str().unwrap_or_default().to_owned());
            }
            assert_eq!(
                algorithms,
                ["ML-DSA-65".to_owned()].into(),
                "the client makes ML-DSA-65 proofs and nothing else"
            );
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
                    made(&read) + Duration::from_mins(10),
                    made(&read),
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
                        made(&read) + Duration::from_mins(10),
                        made(&read),
                    ),
                    Ok(()),
                    "{}: refused as a replay of another proof for the same token",
                    case.name
                );
            }
        }
    }
}
