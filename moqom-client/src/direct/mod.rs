//! Direct (peer-to-peer) media for small end-to-end encrypted rooms.
//!
//! An upgrade to a session that already works through the relay, never a
//! replacement for one. The sequence, and the type that owns each step:
//!
//! 1. Join through the relay as usual. Nothing here runs until that has
//!    happened, and nothing here changes it.
//! 2. Check the room allows it: [`Eligibility::check`]. Every participant opted
//!    in, the room is end-to-end encrypted, at most [`MAX_PARTICIPANTS`], no
//!    watchdog required, and this session is not part of an audience.
//! 3. Bind a [`DirectEndpoint`], which needs an [`IpExposure`] acknowledgement:
//!    a direct path tells the peer this device's network addresses, and that is
//!    a decision the person holding the device has to have made.
//! 4. Exchange [`CandidateOffer`]s over the room, sealed under a [`RoomSecret`]
//!    so the relay carries them without being able to read them.
//! 5. [`DirectEndpoint::establish`] opens the path through both NATs and speaks
//!    MOQT over it. Each side checks the other's MOQOM credentials through a
//!    [`PeerVerifier`] before a single object moves.
//! 6. Read media through a [`DualSubscription`], which keeps the relay
//!    subscription open as the fallback, moves to the direct path once it has
//!    delivered for a while, and returns to the relay without a gap when the
//!    direct path stalls or closes.
//!
//! # What the relay still does
//!
//! Admission, tokens, keys, room state, and every participant this room has
//! beyond the direct pair. The relay subscription stays open throughout, so the
//! relay keeps forwarding the same objects while the direct path is in use. That
//! is what makes falling back gapless, and it is also why a direct path does not
//! yet save relay egress: pausing the relay copy needs the relay to honour a
//! paused subscription, which it does not do yet.
//!
//! # Only the socket
//!
//! [`socket::DirectSocket`] is the layer beneath [`DirectEndpoint`]: binding,
//! STUN, probing, and pinned mutual-TLS QUIC, with no MOQT and no admission.
//! It is public for SDKs that do those steps themselves and need only the
//! part that has to share one UDP port, which is what `moqom-direct-ffi`
//! exports to Swift.

mod link;
mod offer;
mod path;
mod punch;
pub mod socket;
pub mod stun;
mod verify;

pub use link::{DirectConfig, DirectEndpoint};
pub use offer::{CandidateOffer, RoomSecret};
pub use path::{Delivery, DualSubscription, Path, PathSettings};
pub use verify::{PeerCredentials, PeerVerifier, VerifiedPeer};

/// The most participants a room may have and still use direct paths.
///
/// Each extra peer costs every publisher a full upload of their media, so the
/// upload grows with the room while the relay's fan-out does not.
pub const MAX_PARTICIPANTS: usize = 4;

/// What the room and this session are, as far as direct mode is concerned.
///
/// Stated by the caller, who has the room's policy, and checked here so every
/// SDK refuses the same cases for the same reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct Eligibility {
    /// The room's media is end-to-end encrypted.
    pub end_to_end_encrypted: bool,
    /// How many participants are in the room, including this one.
    pub participants: usize,
    /// Every participant has opted in, not only this one.
    pub everyone_opted_in: bool,
    /// The room requires a recorder or safety watchdog to see its media.
    pub watchdog_required: bool,
    /// This session is a viewer in an audience rather than a participant.
    pub audience: bool,
    /// The room's own limit on participants, from its policy
    /// ([`RoomDirectPolicy::max_participants`]). Never above
    /// [`MAX_PARTICIPANTS`].
    pub limit: usize,
}

/// Why a room or session may not use a direct path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Ineligible {
    /// The room's media is not end-to-end encrypted.
    ///
    /// Direct paths remove server-side recording and moderation. In an encrypted
    /// room those are already off, so nothing is lost that was not already gone.
    #[error("the room is not end-to-end encrypted")]
    NotEncrypted,
    /// More participants than the room's limit, or [`MAX_PARTICIPANTS`].
    #[error("{0} participants is more than direct mode allows in this room")]
    TooManyParticipants(usize),
    /// Fewer than two, so there is nobody to connect to.
    #[error("there is no other participant")]
    Alone,
    /// Somebody in the room has not opted in.
    #[error("not every participant has opted in")]
    NotEveryoneOptedIn,
    /// The room requires a watchdog, which a direct path would bypass.
    #[error("the room requires a watchdog")]
    WatchdogRequired,
    /// This session is a viewer. Direct paths would hand a viewer the
    /// publisher's network address.
    #[error("viewers never use direct paths")]
    Audience,
}

impl Eligibility {
    /// Whether a direct path is allowed.
    ///
    /// # Errors
    /// The first reason it is not, checked in the order a product would want to
    /// explain them: who is asking, then what the room is.
    pub const fn check(&self) -> Result<(), Ineligible> {
        if self.audience {
            return Err(Ineligible::Audience);
        }
        if !self.end_to_end_encrypted {
            return Err(Ineligible::NotEncrypted);
        }
        if self.watchdog_required {
            return Err(Ineligible::WatchdogRequired);
        }
        if self.participants < 2 {
            return Err(Ineligible::Alone);
        }
        let limit = if self.limit < MAX_PARTICIPANTS {
            self.limit
        } else {
            MAX_PARTICIPANTS
        };
        if self.participants > limit {
            return Err(Ineligible::TooManyParticipants(self.participants));
        }
        if !self.everyone_opted_in {
            return Err(Ineligible::NotEveryoneOptedIn);
        }
        Ok(())
    }
}

/// Whether this device's rooms use direct paths, as `DirectPolicy` is in
/// `MoqomKit`.
///
/// One participant not opting in keeps the whole room on the relay, so a device
/// on [`DirectPolicy::RelayOnly`] keeps everyone's addresses private from
/// everyone else in its rooms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DirectPolicy {
    /// Direct paths wherever the room qualifies, with the relay as the fallback.
    /// Choosing it accepts, on the user's behalf, that the other participants of
    /// a qualifying room learn this device's IP addresses.
    #[default]
    Automatic,
    /// Every participant's media through the relay, and this device's addresses
    /// never offered.
    RelayOnly,
}

/// What the control plane allows of direct paths in a room, as stated with each
/// token (`MintClientTokenResponse.direct`, or `direct` from the join endpoint).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoomDirectPolicy {
    /// The room may use direct paths at all.
    pub allowed: bool,
    /// The most participants the room may have and still use them.
    pub max_participants: usize,
}

impl Default for RoomDirectPolicy {
    /// What a control plane that says nothing means: allowed, up to
    /// [`MAX_PARTICIPANTS`].
    fn default() -> Self {
        Self {
            allowed: true,
            max_participants: MAX_PARTICIPANTS,
        }
    }
}

impl DirectPolicy {
    /// Whether this device opts in to direct paths in a room with `room`'s
    /// policy, and if so the room's limit for [`Eligibility::limit`].
    #[must_use]
    pub fn opt_in(self, room: RoomDirectPolicy) -> Option<usize> {
        let limit = room.max_participants.min(MAX_PARTICIPANTS);
        (self == Self::Automatic && room.allowed && limit >= 2).then_some(limit)
    }
}

/// Acknowledgement that a direct path reveals this device's IP addresses to the
/// peer.
///
/// A type rather than a boolean so it cannot be passed by accident: the only way
/// to get one is to call a constructor whose name says what it means. Products
/// should construct it from an explicit user choice, after saying so in their UI.
#[derive(Debug, Clone, Copy)]
pub struct IpExposure(());

impl IpExposure {
    /// The person using this device has agreed that the other participants will
    /// learn its public and local IP addresses.
    #[must_use]
    pub const fn peers_will_learn_my_ip_addresses() -> Self {
        Self(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALLOWED: Eligibility = Eligibility {
        end_to_end_encrypted: true,
        participants: 2,
        everyone_opted_in: true,
        watchdog_required: false,
        audience: false,
        limit: MAX_PARTICIPANTS,
    };

    #[test]
    fn the_room_policy_decides_whether_and_how_many() {
        assert_eq!(
            DirectPolicy::default().opt_in(RoomDirectPolicy::default()),
            Some(4)
        );
        assert_eq!(
            DirectPolicy::RelayOnly.opt_in(RoomDirectPolicy::default()),
            None
        );
        let relay_only = RoomDirectPolicy {
            allowed: false,
            ..RoomDirectPolicy::default()
        };
        assert_eq!(DirectPolicy::Automatic.opt_in(relay_only), None);
        let pair = RoomDirectPolicy {
            allowed: true,
            max_participants: 2,
        };
        assert_eq!(DirectPolicy::Automatic.opt_in(pair), Some(2));
        let three = Eligibility {
            participants: 3,
            limit: 2,
            ..ALLOWED
        };
        assert_eq!(three.check(), Err(Ineligible::TooManyParticipants(3)));
        let generous = Eligibility {
            participants: 5,
            limit: 40,
            ..ALLOWED
        };
        assert_eq!(generous.check(), Err(Ineligible::TooManyParticipants(5)));
    }

    #[test]
    fn a_one_to_one_encrypted_call_where_both_opted_in_is_allowed() {
        assert_eq!(ALLOWED.check(), Ok(()));
        let four = Eligibility {
            participants: 4,
            ..ALLOWED
        };
        assert_eq!(four.check(), Ok(()));
    }

    #[test]
    fn each_rule_refuses_on_its_own() {
        let cases = [
            (
                Eligibility {
                    audience: true,
                    ..ALLOWED
                },
                Ineligible::Audience,
            ),
            (
                Eligibility {
                    end_to_end_encrypted: false,
                    ..ALLOWED
                },
                Ineligible::NotEncrypted,
            ),
            (
                Eligibility {
                    watchdog_required: true,
                    ..ALLOWED
                },
                Ineligible::WatchdogRequired,
            ),
            (
                Eligibility {
                    participants: 5,
                    ..ALLOWED
                },
                Ineligible::TooManyParticipants(5),
            ),
            (
                Eligibility {
                    participants: 1,
                    ..ALLOWED
                },
                Ineligible::Alone,
            ),
            (
                Eligibility {
                    everyone_opted_in: false,
                    ..ALLOWED
                },
                Ineligible::NotEveryoneOptedIn,
            ),
        ];
        for (eligibility, expected) in cases {
            assert_eq!(eligibility.check(), Err(expected), "{eligibility:?}");
        }
    }
}
