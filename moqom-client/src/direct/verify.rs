//! Checking a peer's credentials on a direct path.
//!
//! A peer is admitted on its direct ticket, not its MOQOM token. The ticket is
//! what the peer's relay signed about it for this path — tenant, room, who it
//! is, the key its token is bound to (`jkt`) and its publish bits (`pub`),
//! naming this side as the `peer` — and it comes with a proof of possession over
//! the ticket's bytes, by that key, bound to this side's certificate. So the
//! token never leaves the holder's relay session: it may be sealed, and a peer
//! has no business reading it.
//!
//! The check itself is the relay's: its ticket verification and its possession
//! check. This crate does not contain the second — it is Apache-licensed and the
//! verifier is part of the relay — so it asks through [`PeerVerifier`], and
//! `moqom_relay::direct::PeerCheck` is the implementation. What this crate adds
//! on top is the part that is specific to a direct path: the peer must be in
//! this room, must be the participant whose offer was accepted, and must not be
//! a viewer.

use moqom_token::PublicKey;

/// What a peer presented in its SETUP, and what this side expects of it.
#[derive(Debug, Clone, Copy)]
pub struct PeerCredentials<'a> {
    /// The peer's `AUTHORIZATION_TOKEN`, which on a direct path is its current
    /// direct ticket naming this side.
    pub ticket: &'a [u8],
    /// The peer's `AUTHORIZATION_PROOF`, over the ticket, if it sent one.
    pub proof: Option<&'a [u8]>,
    /// The identity of this side's own certificate, which the proof must name.
    ///
    /// Base64url SHA-256 of the leaf certificate this endpoint presented, which
    /// is the same value a relay checks a proof against.
    pub local_certificate: &'a str,
    /// The ticket keys from this side's own relay, which the ticket must be
    /// signed by. Never keys the peer supplied.
    pub ticket_keys: &'a [PublicKey],
    /// This side's tenant.
    pub tenant: &'a str,
    /// This side's room.
    pub room: &'a str,
    /// Who the accepted offer came from, as `user/device`: who the ticket must
    /// be issued to.
    pub holder: &'a str,
    /// This side, as `user/device`: who the ticket must name as its peer.
    pub me: &'a str,
}

/// Who a verified ticket says the peer is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPeer {
    /// The customer.
    pub tenant: String,
    /// The person.
    pub user: String,
    /// The device, as the relay derives it from the token's key thumbprint.
    pub device: String,
    /// The room the ticket is for.
    pub room: Option<String>,
    /// Whether the peer's token grants publishing, as the ticket's `pub` says.
    pub may_publish: bool,
}

/// Checks a peer's ticket and proof of possession.
///
/// Implemented for closures, so a caller holding the relay's verifier can adapt
/// it in a line without this crate depending on the relay.
pub trait PeerVerifier: Send + Sync {
    /// Verify `presented`, returning who the ticket names.
    ///
    /// # Errors
    /// A sentence saying why the credentials were refused. It is sent to the
    /// peer as the close reason, so it must not say more than the relay's own
    /// refusals do.
    fn verify(&self, presented: &PeerCredentials<'_>) -> Result<VerifiedPeer, String>;
}

impl<F> PeerVerifier for F
where
    F: Fn(&PeerCredentials<'_>) -> Result<VerifiedPeer, String> + Send + Sync,
{
    fn verify(&self, presented: &PeerCredentials<'_>) -> Result<VerifiedPeer, String> {
        self(presented)
    }
}

/// The direct-path rules on top of a ticket that verified.
///
/// `participant` is `user/device` from the accepted offer, and `room` and
/// `tenant` are this side's own. A verifier that checked the ticket against
/// [`PeerCredentials`] has already refused most of this; checked again here
/// because a verifier is the caller's to write.
pub(crate) fn admissible(
    peer: &VerifiedPeer,
    tenant: &str,
    room: &str,
    participant: &str,
) -> Result<(), String> {
    if peer.tenant != tenant || peer.room.as_deref() != Some(room) {
        return Err("the peer's ticket is for another room".to_owned());
    }
    if !peer.may_publish {
        return Err("viewers never use direct paths".to_owned());
    }
    if format!("{}/{}", peer.user, peer.device) != participant {
        return Err("the peer's ticket names a different participant than its offer".to_owned());
    }
    Ok(())
}
