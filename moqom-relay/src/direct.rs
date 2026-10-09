//! The relay's admission check, for a peer on a direct path.
//!
//! A direct (peer-to-peer) session in a small end-to-end encrypted room skips
//! the relay for media, and must not skip its checks: each device admits the
//! other on what a relay signed about it. This is that check, built from the
//! same [`ticket::verify`] and [`Possession`] the relay runs, so there is one
//! verifier and not two that might drift.
//!
//! # A ticket, not a token
//!
//! A peer is admitted on its direct ticket, presented in the direct SETUP as
//! `AUTHORIZATION_TOKEN`, with a proof of possession over the ticket's bytes in
//! `AUTHORIZATION_PROOF`. It passes when:
//!
//! - the ticket is signed by a ticket key from this side's own relay session —
//!   never a key the peer supplied — and is unexpired, allowing for skew;
//! - it is for this side's tenant and room, issued to the participant whose
//!   offer was accepted, and names this side as its `peer`;
//! - the proof is by the key the ticket's `jkt` names, over these ticket bytes,
//!   bound to the accepting side's own certificate, and not seen before. Its
//!   identifier is remembered until the ticket expires.
//!
//! What a peer learns of the other — who it is, which device, whether it may
//! publish — is the ticket's (`sub`, `dev`, `pub`), so a MOQOM token never
//! crosses a direct path. It may be sealed, and only a relay may read it.
//!
//! What differs from a relay's admission:
//!
//! - A proof of possession is **required**, never observed or bearer. A direct
//!   peer is a device, and a device that cannot prove its ticket is its own is
//!   not one this device should hand its network address to.
//! - A peer with no ticket is refused rather than admitted with no permission.
//!   A relay admits such a peer because it can then refuse each request; a
//!   direct path has no later point at which to refuse anything.
//! - The binding a proof commits to is the accepting device's own ephemeral
//!   certificate rather than a relay's.
//!
//! `moqom-client` asks for this through its `PeerVerifier` trait rather than
//! depending on this crate, which keeps the client Apache-licensed.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::identity::VerificationKey;
use crate::possession::{Enforcement, Possession, ProofError};
use crate::ticket::{self, Expected, TicketError};

/// Who a direct peer's verified ticket names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    /// The customer.
    pub tenant: Arc<str>,
    /// The person.
    pub user: Arc<str>,
    /// The device, derived from the peer's key thumbprint.
    pub device: Arc<str>,
    /// The room the ticket is for.
    pub room: Option<Arc<str>>,
    /// Whether the peer's token grants any publishing. A viewer's does not.
    pub may_publish: bool,
}

/// Why a direct peer was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The ticket did not pass: forged, expired, or for somebody or somewhere
    /// else.
    #[error("{0}")]
    Ticket(#[from] TicketError),
    /// The ticket passed and its holder could not show the key it names.
    #[error("{0}")]
    Unproven(#[from] ProofError),
    /// This side has no ticket keys yet, so no ticket can be verified, and a
    /// direct path is never opened to somebody unverified.
    #[error("no ticket keys to verify the peer's ticket with")]
    Unverifiable,
    /// The peer offered no ticket at all.
    #[error("a direct session needs a direct ticket")]
    Anonymous,
}

/// What a peer presented, and what this side expects of it.
#[derive(Clone, Copy, Debug)]
pub struct Presented<'a> {
    /// The peer's `AUTHORIZATION_TOKEN`: its direct ticket.
    pub ticket: &'a [u8],
    /// The peer's `AUTHORIZATION_PROOF`, over the ticket.
    pub proof: Option<&'a [u8]>,
    /// The ticket keys from this side's own relay session.
    pub keys: &'a [VerificationKey],
    /// Who the ticket must be issued to, and for.
    pub expected: Expected<'a>,
}

/// Admits peers to one direct endpoint.
///
/// One per endpoint, because a proof names the endpoint's certificate and the
/// spent-proof set is per binding.
#[derive(Debug)]
pub struct PeerCheck {
    possession: Possession,
}

impl PeerCheck {
    /// A check for the endpoint whose certificate identity is
    /// `local_certificate` (base64url SHA-256 of its leaf certificate).
    #[must_use]
    pub fn new(local_certificate: impl Into<String>) -> Self {
        Self {
            possession: Possession::new(Enforcement::Required, Some(local_certificate.into())),
        }
    }

    /// Check a peer's ticket and the proof over it.
    ///
    /// # Errors
    /// [`Refusal`]: what the ticket check or the possession check refused,
    /// plus the two cases a relay admits with no permission and a direct path
    /// cannot.
    pub fn check(&self, presented: Presented<'_>, now: SystemTime) -> Result<Peer, Refusal> {
        if presented.keys.is_empty() {
            return Err(Refusal::Unverifiable);
        }
        if presented.ticket.is_empty() {
            return Err(Refusal::Anonymous);
        }
        let claims = ticket::verify(presented.keys, presented.ticket, presented.expected, now)?;
        // Remembered past `exp` by the skew a late ticket is still accepted
        // with, so a proof cannot be replayed in that window either.
        let until = UNIX_EPOCH + Duration::from_secs(claims.exp) + ticket::CLOCK_SKEW;
        self.possession
            .check(presented.ticket, presented.proof, &claims.jkt, until, now)?;
        Ok(Peer {
            tenant: claims.ten.into(),
            user: claims.sub.into(),
            device: claims.dev.into(),
            room: Some(claims.room.into()),
            may_publish: claims.publish != 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use moqom_proof::{Algorithm, Prover};

    use super::*;
    use crate::ticket::{Claims, Holder, TicketKeys};

    const LOCAL: &str = "cGludGhpc3JlbGF5c2NlcnRpZmljYXRlaGFzaA";

    const EXPECTED: Expected<'static> = Expected {
        tenant: "acme",
        room: "room-42",
        holder: "ada/OuXpLpEHW7dCPqjK",
        peer: "bob/0123456789abcdef",
    };

    fn keys() -> TicketKeys {
        TicketKeys::from_seed("ticket-1", &[3u8; 32])
    }

    fn ticket(keys: &TicketKeys, jkt: &str, publish: u8, now: SystemTime) -> String {
        keys.issue(&Claims::new(
            Holder {
                tenant: "acme",
                room: "room-42",
                user: "ada",
                device: "OuXpLpEHW7dCPqjK",
                jkt,
                publish,
            },
            "bob/0123456789abcdef",
            now,
        ))
    }

    fn prove(device: &Prover, over: &str, certificate: &str) -> Vec<u8> {
        device
            .prove(
                over.as_bytes(),
                &URL_SAFE_NO_PAD.decode(certificate).expect("base64url"),
                &moqom_proof::nonce().expect("a nonce"),
                SystemTime::now(),
            )
            .expect("a proof")
    }

    fn device() -> Prover {
        Prover::generate(Algorithm::MlDsa87).expect("a key")
    }

    fn presented<'a>(
        ticket: &'a str,
        proof: Option<&'a [u8]>,
        keys: &'a [VerificationKey],
    ) -> Presented<'a> {
        Presented {
            ticket: ticket.as_bytes(),
            proof,
            keys,
            expected: EXPECTED,
        }
    }

    #[test]
    fn a_relay_signed_ticket_proven_by_its_key_is_admitted() {
        let keys = keys();
        let ada = device();
        let now = SystemTime::now();
        let ticket = ticket(&keys, ada.thumbprint(), 3, now);
        let proof = prove(&ada, &ticket, LOCAL);

        let check = PeerCheck::new(LOCAL);
        let peer = check
            .check(
                presented(&ticket, Some(&proof), keys.verification_keys()),
                now,
            )
            .expect("admitted");
        assert_eq!(
            peer,
            Peer {
                tenant: "acme".into(),
                user: "ada".into(),
                device: "OuXpLpEHW7dCPqjK".into(),
                room: Some("room-42".into()),
                may_publish: true,
            }
        );
        assert_eq!(
            check.check(
                presented(&ticket, Some(&proof), keys.verification_keys()),
                now
            ),
            Err(Refusal::Unproven(ProofError::Replayed))
        );
    }

    #[test]
    fn the_publish_bits_come_from_the_ticket() {
        let keys = keys();
        let ada = device();
        let now = SystemTime::now();
        let ticket = ticket(&keys, ada.thumbprint(), 0, now);
        let proof = prove(&ada, &ticket, LOCAL);
        let peer = PeerCheck::new(LOCAL)
            .check(
                presented(&ticket, Some(&proof), keys.verification_keys()),
                now,
            )
            .expect("admitted");
        assert!(!peer.may_publish);
    }

    /// A copied ticket is worth nothing without the key it names.
    #[test]
    fn a_ticket_proven_by_another_key_is_refused() {
        let keys = keys();
        let now = SystemTime::now();
        let ticket = ticket(&keys, device().thumbprint(), 3, now);
        let proof = prove(&device(), &ticket, LOCAL);
        assert_eq!(
            PeerCheck::new(LOCAL).check(
                presented(&ticket, Some(&proof), keys.verification_keys()),
                now
            ),
            Err(Refusal::Unproven(ProofError::WrongKey))
        );
        assert_eq!(
            PeerCheck::new(LOCAL).check(presented(&ticket, None, keys.verification_keys()), now),
            Err(Refusal::Unproven(ProofError::Missing))
        );
    }

    #[test]
    fn a_proof_for_another_endpoint_or_ticket_is_refused() {
        let keys = keys();
        let ada = device();
        let now = SystemTime::now();
        let ticket = ticket(&keys, ada.thumbprint(), 3, now);
        let elsewhere = prove(&ada, &ticket, "c29tZW90aGVycmVsYXlzY2VydA");
        assert_eq!(
            PeerCheck::new(LOCAL).check(
                presented(&ticket, Some(&elsewhere), keys.verification_keys()),
                now
            ),
            Err(Refusal::Unproven(ProofError::WrongRelay))
        );
        let other = self::ticket(&keys, ada.thumbprint(), 1, now);
        let over_other = prove(&ada, &other, LOCAL);
        assert_eq!(
            PeerCheck::new(LOCAL).check(
                presented(&ticket, Some(&over_other), keys.verification_keys()),
                now
            ),
            Err(Refusal::Unproven(ProofError::WrongToken))
        );
    }

    #[test]
    fn a_ticket_this_sides_relay_did_not_sign_or_for_somebody_else_is_refused() {
        let ada = device();
        let now = SystemTime::now();
        let forged = ticket(
            &TicketKeys::from_seed("ticket-1", &[4u8; 32]),
            ada.thumbprint(),
            3,
            now,
        );
        let proof = prove(&ada, &forged, LOCAL);
        assert_eq!(
            PeerCheck::new(LOCAL).check(
                presented(&forged, Some(&proof), keys().verification_keys()),
                now
            ),
            Err(Refusal::Ticket(TicketError::BadSignature))
        );

        let keys = keys();
        let ticket = ticket(&keys, ada.thumbprint(), 3, now);
        let proof = prove(&ada, &ticket, LOCAL);
        let for_carol = Presented {
            expected: Expected {
                peer: "carol/0123456789abcdef",
                ..EXPECTED
            },
            ..presented(&ticket, Some(&proof), keys.verification_keys())
        };
        assert_eq!(
            PeerCheck::new(LOCAL).check(for_carol, now),
            Err(Refusal::Ticket(TicketError::WrongPeer))
        );
        let lapsed = now + ticket::LIFETIME + ticket::CLOCK_SKEW + Duration::from_secs(2);
        assert_eq!(
            PeerCheck::new(LOCAL).check(
                presented(&ticket, Some(&proof), keys.verification_keys()),
                lapsed
            ),
            Err(Refusal::Ticket(TicketError::Expired))
        );
    }

    #[test]
    fn no_keys_verify_nobody_and_no_ticket_is_anonymous() {
        let check = PeerCheck::new(LOCAL);
        assert_eq!(
            check.check(presented("anything", None, &[]), SystemTime::now()),
            Err(Refusal::Unverifiable)
        );
        assert_eq!(
            check.check(
                presented("", None, keys().verification_keys()),
                SystemTime::now()
            ),
            Err(Refusal::Anonymous)
        );
    }
}
