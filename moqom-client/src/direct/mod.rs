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
pub use socket::StunServer;
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectPolicy {
    /// Direct paths wherever the room qualifies, with the relay as the fallback.
    /// Choosing it accepts, on the user's behalf, that the other participants of
    /// a qualifying room learn this device's IP addresses.
    Automatic {
        /// Where to learn this device's public address. `None`, the default,
        /// asks the STUN server the token's room names
        /// ([`RoomDirectPolicy::stun`]): a MOQOM relay's.
        stun: Option<StunServer>,
    },
    /// Every participant's media through the relay, this device's addresses
    /// never offered, and no STUN server asked.
    RelayOnly,
}

impl Default for DirectPolicy {
    fn default() -> Self {
        Self::AUTOMATIC
    }
}

/// What the control plane allows of direct paths in a room, as stated with each
/// token (`MintClientTokenResponse.direct`, or `direct` from the join endpoint).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomDirectPolicy {
    /// The room may use direct paths at all.
    pub allowed: bool,
    /// The most participants the room may have and still use them.
    pub max_participants: usize,
    /// The relays' STUN responder, as the grant names it (`direct.stun`).
    pub stun: Option<StunServer>,
}

impl Default for RoomDirectPolicy {
    /// What a control plane that says nothing means: allowed, up to
    /// [`MAX_PARTICIPANTS`], with no STUN server named.
    fn default() -> Self {
        Self {
            allowed: true,
            max_participants: MAX_PARTICIPANTS,
            stun: None,
        }
    }
}

/// What [`DirectPolicy::opt_in`] decided for a room: the limit for
/// [`Eligibility::limit`], and the STUN server for [`DirectConfig::stun`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptIn {
    /// The room's limit on participants, never above [`MAX_PARTICIPANTS`].
    pub limit: usize,
    /// Where to learn this device's public address, if anywhere. Without one
    /// only interface addresses are offered, which cross no NAT.
    pub stun: Option<StunServer>,
}

impl DirectPolicy {
    /// [`Self::Automatic`], asking the STUN server the room names.
    pub const AUTOMATIC: Self = Self::Automatic { stun: None };

    /// Whether this device opts in to direct paths in a room with `room`'s
    /// policy, and if so with what limit and which STUN server. A STUN server
    /// given to [`Self::Automatic`] wins over the room's.
    #[must_use]
    pub fn opt_in(&self, room: &RoomDirectPolicy) -> Option<OptIn> {
        let Self::Automatic { stun } = self else {
            return None;
        };
        let limit = room.max_participants.min(MAX_PARTICIPANTS);
        (room.allowed && limit >= 2).then(|| OptIn {
            limit,
            stun: stun.clone().or_else(|| room.stun.clone()),
        })
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
        let limit = |policy: &DirectPolicy, room: &RoomDirectPolicy| {
            policy.opt_in(room).map(|opted| opted.limit)
        };
        assert_eq!(
            limit(&DirectPolicy::default(), &RoomDirectPolicy::default()),
            Some(4)
        );
        assert_eq!(
            limit(&DirectPolicy::RelayOnly, &RoomDirectPolicy::default()),
            None
        );
        let relay_only = RoomDirectPolicy {
            allowed: false,
            ..RoomDirectPolicy::default()
        };
        assert_eq!(limit(&DirectPolicy::AUTOMATIC, &relay_only), None);
        let pair = RoomDirectPolicy {
            max_participants: 2,
            ..RoomDirectPolicy::default()
        };
        assert_eq!(limit(&DirectPolicy::AUTOMATIC, &pair), Some(2));
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

    /// Automatic asks the relays' STUN server unless the application named its
    /// own, and relay-only asks none.
    #[test]
    fn the_stun_server_is_the_rooms_unless_one_was_named() {
        let relays = StunServer::Name {
            host: "relay.moqom.cloud".to_owned(),
            port: 3478,
        };
        let own = StunServer::Address("192.0.2.1:3478".parse().expect("address"));
        let room = RoomDirectPolicy {
            stun: Some(relays.clone()),
            ..RoomDirectPolicy::default()
        };
        let stun = |policy: &DirectPolicy, room: &RoomDirectPolicy| {
            policy.opt_in(room).and_then(|opted| opted.stun)
        };

        assert_eq!(stun(&DirectPolicy::AUTOMATIC, &room), Some(relays));
        let named = DirectPolicy::Automatic {
            stun: Some(own.clone()),
        };
        assert_eq!(stun(&named, &room), Some(own.clone()));
        assert_eq!(stun(&named, &RoomDirectPolicy::default()), Some(own));
        assert_eq!(
            stun(&DirectPolicy::AUTOMATIC, &RoomDirectPolicy::default()),
            None
        );
        assert_eq!(DirectPolicy::RelayOnly.opt_in(&room), None);
        let closed = RoomDirectPolicy {
            allowed: false,
            ..room
        };
        assert_eq!(named.opt_in(&closed), None);
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
