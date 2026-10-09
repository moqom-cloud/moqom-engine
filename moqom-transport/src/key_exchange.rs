//! Which TLS key exchanges a MOQOM server offers.
//!
//! Two sets, because there are two kinds of peer:
//!
//! - **Links**: a relay dialling another MOQOM server — its parent, the control
//!   plane, the usage and link-credential endpoints. Both ends are ours, so
//!   both can be held to the strongest group there is, and they are: pure
//!   `MLKEM1024` and nothing else. A server that cannot do it is not one a
//!   relay should be talking to, and a downgrade to anything weaker is exactly
//!   what an attacker in the path would arrange.
//! - **Devices**: the relay's QUIC listener. `MLKEM1024` first, then the hybrid
//!   `X25519MLKEM768`, which is what Apple's TLS stack offers and the only
//!   post-quantum group most phones have. Nothing classical: a device that
//!   offers only X25519 or P-256 fails the handshake, because a session key a
//!   future quantum computer can recover from a recording is a session that
//!   was never private.
//!
//! The provider is aws-lc-rs's, so the cipher suites and signature algorithms
//! are its defaults; only the groups differ.

use rustls::NamedGroup;
use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{default_provider, kx_group};

/// What a relay offers when it dials another MOQOM server.
pub const LINK_GROUPS: &[NamedGroup] = &[NamedGroup::MLKEM1024];

/// What the relay's device listener accepts, most preferred first.
pub const DEVICE_GROUPS: &[NamedGroup] = &[NamedGroup::MLKEM1024, NamedGroup::X25519MLKEM768];

/// The provider for a relay's client configurations: [`LINK_GROUPS`] only.
#[must_use]
pub fn link_provider() -> CryptoProvider {
    CryptoProvider {
        kx_groups: vec![kx_group::MLKEM1024],
        ..default_provider()
    }
}

/// The provider for the relay's device listener: [`DEVICE_GROUPS`], in order.
#[must_use]
pub fn device_provider() -> CryptoProvider {
    CryptoProvider {
        kx_groups: vec![kx_group::MLKEM1024, kx_group::X25519MLKEM768],
        ..default_provider()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn groups(provider: &CryptoProvider) -> Vec<NamedGroup> {
        provider
            .kx_groups
            .iter()
            .map(|group| group.name())
            .collect()
    }

    #[test]
    fn the_providers_offer_what_their_constants_say() {
        assert_eq!(groups(&link_provider()), LINK_GROUPS);
        assert_eq!(groups(&device_provider()), DEVICE_GROUPS);
    }
}
