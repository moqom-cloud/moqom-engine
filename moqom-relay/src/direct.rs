//! The relay's admission check, for a peer on a direct path.
//!
//! A direct (peer-to-peer) session in a small end-to-end encrypted room skips
//! the relay for media, and must not skip its checks: each device admits the
//! other exactly as a relay would, with MOQOM-issued credentials. This is that
//! check, built from the same [`Authenticator`] and [`Possession`] the relay
//! runs at SETUP, so there is one verifier and not two that might drift.
//!
//! What differs from a relay's admission:
//!
//! - A proof of possession is **required**, never observed or bearer. A direct
//!   peer is a device, and a device that cannot prove its token is its own is
//!   not one this device should hand its network address to.
//! - A peer with no verified token is refused rather than admitted with no
//!   permission. A relay admits such a peer because it can then refuse each
//!   request; a direct path has no later point at which to refuse anything.
//! - The binding a proof commits to is the accepting device's own ephemeral
//!   certificate rather than a relay's.
//!
//! `moqom-client` asks for this through its `PeerVerifier` trait rather than
//! depending on this crate, which keeps the client Apache-licensed.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::SystemTime;

use crate::identity::{AuthError, Authenticator};
use crate::possession::{Enforcement, Possession};
use crate::scope::Permission;

/// Who a direct peer's verified token names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    /// The customer.
    pub tenant: Arc<str>,
    /// The person.
    pub user: Arc<str>,
    /// The device, derived from the token's key thumbprint.
    pub device: Arc<str>,
    /// The room the token admits them to.
    pub room: Option<Arc<str>>,
    /// Whether the token grants any publishing. A viewer's does not.
    pub may_publish: bool,
}

/// Why a direct peer was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The token or its proof did not pass the relay's checks.
    #[error("{0}")]
    Credentials(#[from] AuthError),
    /// No verification keys are configured, so nobody can be verified, and a
    /// direct path is never opened to somebody unverified.
    #[error("no keys to verify the peer's token with")]
    Unverifiable,
    /// The peer offered no token at all.
    #[error("a direct session needs a MOQOM token")]
    Anonymous,
}

/// Admits peers to one direct endpoint.
///
/// One per endpoint, because a proof names the endpoint's certificate and the
/// spent-proof set is per binding. Shares the relay's key set, so a key rotation
/// pushed by the control plane reaches direct paths too.
#[derive(Debug)]
pub struct PeerCheck {
    authenticator: Authenticator,
    possession: Possession,
}

impl PeerCheck {
    /// A check for the endpoint whose certificate identity is
    /// `local_certificate` (base64url SHA-256 of its leaf certificate).
    #[must_use]
    pub fn new(authenticator: Authenticator, local_certificate: impl Into<String>) -> Self {
        Self {
            authenticator,
            possession: Possession::new(Enforcement::Required, Some(local_certificate.into())),
        }
    }

    /// Check a peer's token and proof.
    ///
    /// # Errors
    /// [`Refusal`]: what the relay would have refused, plus the two cases a
    /// relay admits with no permission and a direct path cannot.
    pub fn check(
        &self,
        token: &[u8],
        proof: Option<&[u8]>,
        now: SystemTime,
    ) -> Result<Peer, Refusal> {
        if !self.authenticator.is_verifying() {
            return Err(Refusal::Unverifiable);
        }
        if token.is_empty() {
            return Err(Refusal::Anonymous);
        }
        let admission = self.authenticator.admit_presented(
            &[token],
            proof,
            &self.possession,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            now,
        )?;
        match admission.permission {
            Permission::Scoped(scope) => Ok(Peer {
                tenant: scope.tenant,
                user: scope.user,
                device: scope.device,
                room: scope.room,
                may_publish: !scope.publish.is_none(),
            }),
            Permission::Unrestricted | Permission::Nothing => Err(Refusal::Anonymous),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::VerificationKey;

    #[test]
    fn a_relay_without_keys_verifies_nobody_for_a_direct_path() {
        let check = PeerCheck::new(Authenticator::disabled(), "cert");
        assert_eq!(
            check.check(b"anything", None, SystemTime::now()),
            Err(Refusal::Unverifiable)
        );
    }

    #[test]
    fn an_empty_token_is_anonymous() {
        let check = PeerCheck::new(
            Authenticator::new(
                "",
                vec![VerificationKey::ed25519("k".to_owned(), vec![0u8; 32])],
            ),
            "cert",
        );
        assert_eq!(
            check.check(b"", None, SystemTime::now()),
            Err(Refusal::Anonymous)
        );
    }
}
