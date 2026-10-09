//! What a verified token permits.
//!
//! [`identity`](crate::identity) answers who a peer is. This answers what that
//! person may do, which is the half that was missing: until it existed, anyone
//! holding any valid token could publish under any namespace, including one
//! naming somebody else in another tenant's room.
//!
//! # Why names are the whole of the enforcement surface
//!
//! A relay forwards objects it cannot read — that is the property that keeps it
//! compatible with end-to-end encryption, and it is not negotiable. So the only
//! thing available to decide a permission is the name a request asks for, and
//! the names are structured for exactly this. `MoqomNamespaces` in the client
//! SDK builds five shapes and no others:
//!
//! ```text
//! (tenant, "u",  user, device)          a personal channel
//! (tenant, "r",  room)                  the room itself, whose track is its control log
//! (tenant, "r",  room, user, device)    one participant on stage
//! (tenant, "bs", room)                  backstage, outside what a viewer can watch
//! (tenant, "bs", room, user, device)    one participant waiting to go live
//! ```
//!
//! A token names a tenant (`aud`), a user (`sub`), a device (`cnf.jkt`), and a
//! room (`moqt.room`). Lay those against the shapes above and every question
//! this module answers becomes a comparison of fields: publishing means naming
//! *your own* slot, in *your own* room, in *your own* tenant, and reading means
//! naming something inside the room you were admitted to.
//!
//! The consequence worth being explicit about is that a relay with keys
//! configured is a MOQOM relay rather than a general one. A namespace that does
//! not fit the grammar is refused rather than forwarded, because the alternative
//! — forwarding names it cannot reason about — is the hole this module closes,
//! reopened for anything that declines to use the shapes.
//!
//! # Why the media kind is not checked, although the token carries it
//!
//! `moqt.pub` distinguishes audio from video from screen share, and this module
//! only asks whether it is empty. That is deliberate. A publisher announces a
//! namespace, not a list of tracks; the track names appear later, chosen by the
//! publisher, and nothing stops a peer that may publish audio from sending video
//! bytes in a track called `audio`. Enforcing the finer grant would therefore
//! mean checking a label the same party invents, which reads as security and is
//! not. The namespace is the boundary the relay can actually hold, and whether
//! somebody may publish here at all is the question it can answer honestly.
//!
//! Stage moderation — promoting a guest, forcing a mute — is where those bits
//! become enforceable, because there the relay is being asked to change what it
//! forwards rather than to trust a name.
//!
//! # A relay with no keys permits everything
//!
//! [`Permission::Unrestricted`] is what a session gets when no authenticator is
//! configured, and it is a real decision rather than an oversight. Without keys
//! there is no verified tenant, user, or room, so there is nothing to compare a
//! namespace against; the only fail-closed alternative is a relay that refuses
//! every request, which would leave the keyless mode — tests, benches, the
//! two-phone rig — with no relay at all. The mode is already documented as
//! unsafe to expose, and the binary says so at startup. What must never happen
//! is the reverse: a relay *with* keys treating a missing scope as permission.

use std::sync::Arc;

use moqom_proto::control::RequestErrorCode;
use moqom_proto::model::TrackNamespace;

/// The field that says which shape a namespace is.
///
/// Short because they are on the wire in every announcement, and matched as
/// bytes because that is what a namespace field is.
const PERSONAL: &[u8] = b"u";
const ROOM: &[u8] = b"r";
const BACKSTAGE: &[u8] = b"bs";

/// Moderation capability bits, as the control plane mints them.
///
/// The positions are protocol: the same numbers appear in `control.Capability`
/// in Go and in `Capability` in `MoqomKit`, and the gaps between the groups are
/// deliberate so a power added later takes an unused bit in its own range
/// instead of shifting everything after it. Only the ranges matter here, since
/// what this module asks is which *kind* of power a holder has rather than
/// which particular one.
pub mod capability {
    /// Chat, enforced in the control plane because chat does not pass through
    /// a relay.
    pub const CHAT: u32 = 0x0000_001F;
    /// Stage: promote, demote, force mute, spotlight, manage the queue.
    pub const STAGE: u32 = 0x0000_7F00;
    /// The room: kick, ban, close, change policy, manage watchdogs.
    pub const ROOM: u32 = 0x003F_0000;
    /// Appointing moderators, reading the log, handling appeals.
    pub const META: u32 = 0x0700_0000;

    /// Every bit that means something.
    pub const KNOWN: u32 = CHAT | STAGE | ROOM | META;
}

/// Whose slot a namespace names, for the questions that are about the
/// *publisher* rather than about the token asking.
///
/// A mute is the case this exists for. Enforcing one means recognising the
/// muted person's tracks in a subscription made by somebody else entirely, so
/// the name has to be read on its own terms rather than compared against the
/// scope of whoever is asking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot<'a> {
    /// The customer.
    pub tenant: &'a [u8],
    /// The room, whether the slot is on stage or backstage.
    pub room: &'a [u8],
    /// The person.
    pub user: &'a [u8],
    /// Which of their devices.
    pub device: &'a [u8],
}

/// Read a participant's slot out of a namespace.
///
/// `None` for anything else, including the room's own namespace and a personal
/// channel: neither belongs to one participant in one room, which is the only
/// thing a mute can name.
#[must_use]
pub fn slot(namespace: &TrackNamespace) -> Option<Slot<'_>> {
    match namespace.fields() {
        [tenant, marker, room, user, device] if marker.as_ref() == ROOM || marker == BACKSTAGE => {
            Some(Slot {
                tenant,
                room,
                user,
                device,
            })
        }
        _ => None,
    }
}

/// Media kinds a holder may publish.
///
/// A bitmask rather than a set because it is read on every announcement and the
/// bit positions are shared with Go and Swift. Unknown bits are kept rather than
/// refused, which is the opposite of the rule for capabilities and matches what
/// the Go verifier does: a capability the relay does not understand may be a
/// power it is failing to grant, while a media kind it does not understand is
/// one it will never be asked about.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Publish(u8);

impl Publish {
    /// A viewer, who publishes nothing.
    pub const NONE: Self = Self(0);
    /// A microphone.
    pub const AUDIO: Self = Self(1 << 0);
    /// A camera.
    pub const VIDEO: Self = Self(1 << 1);
    /// A screen share, which is separate from a camera because a room may allow
    /// one and not the other.
    pub const SCREEN: Self = Self(1 << 2);
    /// Application data tracks.
    pub const DATA: Self = Self(1 << 3);

    /// The kinds a token's `pub` claim names.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// The raw bits, as the token's `moqt.pub` carried them.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Whether the holder may publish nothing at all, which is an ordinary
    /// viewer rather than a broken token.
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.0 == 0
    }

    /// Whether every kind in `other` is present.
    #[must_use]
    pub const fn has(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// The kinds present in both.
    #[must_use]
    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}

/// The subject every hosted recorder token carries.
///
/// The control plane's `RecorderSubject`. It is reserved there: `MintClientToken`
/// refuses it, so a signed token naming it was minted by the recording link and
/// by nothing a customer can reach.
pub const RECORDER_SUBJECT: &str = "moqom-recorder";

/// Whether a verified session with these rights is the hosted recorder.
///
/// The subject alone would do, since only the control plane can sign it; the
/// rights are checked as well so that a recorder token minted with anything
/// beyond viewing -- which the control plane never does -- is held to the
/// ceiling like anybody else rather than given a seat the room cannot see.
/// `elevated` is owning the room, being backstage, or being a relay link.
#[must_use]
pub fn is_recorder(user: &str, publish: Publish, capabilities: u32, elevated: bool) -> bool {
    user == RECORDER_SUBJECT && publish.is_none() && capabilities == 0 && !elevated
}

/// The most the control plane says somebody holds in a room right now.
///
/// A ceiling rather than a grant, and the difference is the rule this whole
/// mechanism rests on: the relay only ever *narrows* with one. Widening is
/// what a token is for, because a token is signed and bound to a device key,
/// and a directive is a message on a link. A relay that widened on a
/// directive would let anybody who could forge or replay one hand out powers;
/// a relay that only narrows on one can at worst be told to take powers away,
/// which a moderator could have done by ejecting the session anyway.
///
/// Ownership is not here because it cannot be granted or taken. The room's
/// owner is a fact about the room, not a power somebody was handed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ceiling {
    /// The media kinds they may publish, at most.
    pub publish: Publish,
    /// The moderation powers they may hold, at most.
    pub capabilities: u32,
}

impl Ceiling {
    /// The lower of two ceilings, for somebody named by more than one.
    #[must_use]
    pub const fn meet(self, other: Self) -> Self {
        Self {
            publish: self.publish.intersect(other.publish),
            capabilities: self.capabilities & other.capabilities,
        }
    }
}

/// Which way a change of grants moved somebody.
///
/// For the counter and the log line, which are how an operator tells "the
/// stage is being run" from "something is demoting everybody".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Regrade {
    /// Gained something and lost nothing. Going on stage from backstage counts.
    Promotion,
    /// Lost something and gained nothing. Going backstage from the stage counts.
    Demotion,
    /// Gained one thing and lost another: a cohost who became a guest with a
    /// screen share, say.
    Lateral,
}

impl Regrade {
    /// A stable, low-cardinality name for metrics and logs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Promotion => "promotion",
            Self::Demotion => "demotion",
            Self::Lateral => "lateral",
        }
    }
}

/// What a token said its holder may do.
///
/// Built by [`identity`](crate::identity) from a signature that verified, and
/// never from anything a peer merely claimed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope {
    /// The customer, from `aud`. Every name this session touches begins here.
    pub tenant: Arc<str>,
    /// The person, from `sub`.
    pub user: Arc<str>,
    /// The device, derived from the `cnf.jkt` thumbprint the same way the
    /// client derives the field it announces under.
    pub device: Arc<str>,
    /// The room they were admitted to, if any. A token with no room can still
    /// reach personal channels, which is how a viewer follows somebody outside
    /// a call.
    pub room: Option<Arc<str>>,
    /// Which media kinds they may publish. Empty for a viewer.
    pub publish: Publish,
    /// Moderation powers, as a bitmask. See [`capability`].
    pub capabilities: u32,
    /// Whether they own the room, which is not a capability and cannot be
    /// granted or taken.
    pub owner: bool,
    /// Whether this session is backstage — waiting to go live rather than on
    /// stage.
    pub backstage: bool,
    /// Whether this is another relay's link to this one rather than a person.
    ///
    /// A signed grant like the rest, which the control plane mints only for
    /// relay service accounts, and the only thing it changes is that the
    /// session is not metered: the relay at the other end meters the people it
    /// serves, and metering the link too would bill them twice. Read-only by
    /// construction — [`identity`](crate::identity) refuses it beside any
    /// publish right or power.
    pub relay: bool,
}

impl Scope {
    /// Whether this holder runs the room rather than merely appearing in it.
    ///
    /// Stage and room powers count; chat powers do not, because chat is
    /// enforced in the control plane and a chat moderator has no business
    /// writing the room's control log.
    #[must_use]
    const fn runs_the_room(&self) -> bool {
        self.owner || self.capabilities & (capability::STAGE | capability::ROOM) != 0
    }

    /// Whether this is the hosted recorder rather than a person.
    ///
    /// See [`is_recorder`]. The recorder is a viewer the room is told about by
    /// its watchdog, not a participant, so the room's ceiling does not count it.
    #[must_use]
    pub fn is_recorder(&self) -> bool {
        is_recorder(
            &self.user,
            self.publish,
            self.capabilities,
            self.owner || self.backstage || self.relay,
        )
    }

    /// Whether the tenant field of a namespace is this holder's tenant.
    fn is_own_tenant(&self, field: &[u8]) -> bool {
        field == self.tenant.as_bytes()
    }

    fn is_own_room(&self, field: &[u8]) -> bool {
        self.room
            .as_ref()
            .is_some_and(|room| field == room.as_bytes())
    }

    fn is_own_slot(&self, user: &[u8], device: &[u8]) -> bool {
        user == self.user.as_bytes() && device == self.device.as_bytes()
    }

    /// Whether `other` is the same person, on the same device, in the same
    /// room — the parts of a scope a renewal may not change.
    ///
    /// Who they are is a quota key and the device is what a proof binds to, so
    /// either changing would be a different session wearing this one's
    /// connection. The room is here because a move between rooms changes
    /// everything the session has already been admitted to: its roster entry,
    /// the bans and the ceiling it was checked against, and every name its
    /// open requests were authorised under. That is a new session's work.
    /// Ownership is here because it is not a grant; see [`Ceiling`]. Being a
    /// relay link is here because it decides whether the session is metered,
    /// which is fixed when the session opens.
    #[must_use]
    pub fn same_seat(&self, other: &Self) -> bool {
        self.tenant == other.tenant
            && self.user == other.user
            && self.device == other.device
            && self.room == other.room
            && self.owner == other.owner
            && self.relay == other.relay
    }

    /// This scope with nothing above `ceiling`.
    #[must_use]
    pub fn capped(&self, ceiling: Ceiling) -> Self {
        Self {
            publish: self.publish.intersect(ceiling.publish),
            capabilities: self.capabilities & ceiling.capabilities,
            ..self.clone()
        }
    }

    /// How going from this scope to `to` moved somebody, or `None` if it did
    /// not move them at all.
    ///
    /// Only the parts a grant change can touch are compared. Callers have
    /// already established [`Self::same_seat`].
    #[must_use]
    pub fn regrade(&self, to: &Self) -> Option<Regrade> {
        let gained = to.publish.0 & !self.publish.0 != 0
            || to.capabilities & !self.capabilities != 0
            || (self.backstage && !to.backstage);
        let lost = self.publish.0 & !to.publish.0 != 0
            || self.capabilities & !to.capabilities != 0
            || (!self.backstage && to.backstage);
        match (gained, lost) {
            (false, false) => None,
            (true, false) => Some(Regrade::Promotion),
            (false, true) => Some(Regrade::Demotion),
            (true, true) => Some(Regrade::Lateral),
        }
    }
}

/// Why a request was not allowed.
///
/// Separated by cause because they call for different responses. Naming
/// somebody else's slot is an attack or a badly broken client; naming a room
/// the token does not cover is routine, and happens whenever a client keeps
/// using a token minted for the room it just left.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Denial {
    /// The name belongs to another customer.
    #[error("that namespace belongs to another tenant")]
    Tenant,
    /// The name belongs to a room this token does not cover.
    #[error("that namespace belongs to another room")]
    Room,
    /// The name is somebody else's slot.
    #[error("that namespace belongs to another participant")]
    Identity,
    /// Not a namespace this relay's grammar recognises.
    #[error("that namespace is not one this relay recognises")]
    Shape,
    /// The holder may not publish.
    #[error("this session was not granted publishing")]
    Publishing,
    /// Backstage, without having been put there.
    #[error("this session is not backstage")]
    Backstage,
    /// The room's own track, without the standing to write it.
    #[error("this session does not run this room")]
    Authority,
    /// No verified token on a relay that requires one.
    #[error("this session has not been authenticated")]
    Unauthenticated,
}

impl Denial {
    /// The MOQT code to report.
    ///
    /// All one code, and deliberately: the distinctions above are for the
    /// relay's operator, and telling a peer which of them applied would let it
    /// map out the rooms and participants it cannot see by reading the errors.
    /// The reason phrase carries the difference, which is enough for a
    /// developer holding the token and useless to anyone else.
    #[must_use]
    pub const fn code(self) -> RequestErrorCode {
        RequestErrorCode::UNAUTHORIZED
    }

    /// A stable, low-cardinality name for metrics and logs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Tenant => "tenant",
            Self::Room => "room",
            Self::Identity => "identity",
            Self::Shape => "shape",
            Self::Publishing => "publishing",
            Self::Backstage => "backstage",
            Self::Authority => "authority",
            Self::Unauthenticated => "unauthenticated",
        }
    }
}

/// What a session is allowed to ask for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Permission {
    /// No authenticator is configured, so there is nothing to check against.
    /// See the note at the top of this module.
    Unrestricted,
    /// A verified token, and the only mode that enforces anything.
    Scoped(Box<Scope>),
    /// Nothing at all.
    ///
    /// What a session holds on a relay that verifies tokens before its own has
    /// been verified. The window should not exist — a session serves no request
    /// until SETUP has completed — and this is what makes the ordering a
    /// property of the code rather than of the reading of it. Denying is the
    /// only safe answer to "who is this" when the answer is not known yet.
    Nothing,
}

impl Permission {
    /// A permission from a verified scope.
    #[must_use]
    pub fn scoped(scope: Scope) -> Self {
        Self::Scoped(Box::new(scope))
    }

    /// Whether this session may announce `namespace`.
    ///
    /// Announcing is the strict direction: the name must be *exactly* one of
    /// the holder's own slots, with no room for a prefix to stand in for the
    /// thing under it. A publisher that could announce a room prefix would own
    /// every participant name beneath it, and a subscriber asking for any of
    /// them would be routed to whoever got there first.
    ///
    /// # Errors
    /// [`Denial`] naming which part of the token the namespace disagreed with.
    pub fn may_announce(&self, namespace: &TrackNamespace) -> Result<(), Denial> {
        let scope = match self {
            Self::Unrestricted => return Ok(()),
            Self::Nothing => return Err(Denial::Unauthenticated),
            Self::Scoped(scope) => scope,
        };
        // A relay link reads, and is not metered for it; publishing on one
        // would be media nobody is billed for.
        if scope.relay {
            return Err(Denial::Publishing);
        }
        let fields = namespace.fields();
        let [tenant, marker, rest @ ..] = fields else {
            return Err(Denial::Shape);
        };
        if !scope.is_own_tenant(tenant) {
            return Err(Denial::Tenant);
        }

        match (marker.as_ref(), rest) {
            // A personal channel needs no room and no grant: it is the holder's
            // own name, and publishing to it is what a broadcaster outside a
            // call is doing.
            (PERSONAL, [user, device]) => {
                if scope.is_own_slot(user, device) {
                    Ok(())
                } else {
                    Err(Denial::Identity)
                }
            }
            // The room's own track is its control log — the roster, the grants,
            // who was kicked. Writing it is running the room.
            (ROOM, [room]) => {
                if !scope.is_own_room(room) {
                    Err(Denial::Room)
                } else if scope.runs_the_room() {
                    Ok(())
                } else {
                    Err(Denial::Authority)
                }
            }
            (ROOM, [room, user, device]) => {
                scope.may_take_slot(room, user, device)?;
                if scope.backstage {
                    // On stage while the control plane put this session
                    // backstage. Going live is a promotion, and a promotion is a
                    // new token: letting a backstage session announce on stage
                    // would make the queue advisory.
                    return Err(Denial::Backstage);
                }
                Ok(())
            }
            (BACKSTAGE, [room, user, device]) => {
                scope.may_take_slot(room, user, device)?;
                if scope.backstage {
                    Ok(())
                } else {
                    Err(Denial::Backstage)
                }
            }
            _ => Err(Denial::Shape),
        }
    }

    /// Whether this session may subscribe to, fetch, or watch under `name`.
    ///
    /// One question for all three because they are one question: each is a way
    /// of learning what exists under a name and receiving what flows there, and
    /// a rule that let a client watch a prefix it could not subscribe under
    /// would leak the roster of a room it cannot join.
    ///
    /// Prefixes are why this is looser than [`Self::may_announce`] in shape and
    /// no looser in reach. A watch names a prefix and a subscribe names a full
    /// track namespace, so the depth varies; what does not vary is that the
    /// name must sit inside an area this token was admitted to. In particular a
    /// prefix of `(tenant)` or `(tenant, "r")` is refused, since answering it
    /// would enumerate every room the customer is running.
    ///
    /// # Errors
    /// [`Denial`] naming which part of the token the name disagreed with.
    pub fn may_read(&self, name: &TrackNamespace) -> Result<(), Denial> {
        let scope = match self {
            Self::Unrestricted => return Ok(()),
            Self::Nothing => return Err(Denial::Unauthenticated),
            Self::Scoped(scope) => scope,
        };
        let fields = name.fields();
        let [tenant, marker, area, ..] = fields else {
            return Err(Denial::Shape);
        };
        if !scope.is_own_tenant(tenant) {
            return Err(Denial::Tenant);
        }

        match marker.as_ref() {
            // Anyone in the tenant may follow a named person's own channel. It
            // is deliberately not a room, so there is no membership to check —
            // and the name has to be complete enough to name somebody, or this
            // would be a way to list the customer's users. Not on a relay link,
            // which is minted for one room and reads nothing outside it.
            PERSONAL if scope.relay => Err(Denial::Room),
            PERSONAL => Ok(()),
            ROOM => {
                if scope.is_own_room(area) {
                    Ok(())
                } else {
                    Err(Denial::Room)
                }
            }
            // Backstage is outside the room prefix precisely so a viewer cannot
            // reach it. Hosts running the queue can, and so can whoever is
            // waiting in it.
            BACKSTAGE => {
                if !scope.is_own_room(area) {
                    Err(Denial::Room)
                } else if scope.runs_the_room() || scope.backstage {
                    Ok(())
                } else {
                    Err(Denial::Backstage)
                }
            }
            _ => Err(Denial::Shape),
        }
    }
}

impl Scope {
    /// The checks shared by both participant shapes: right room, own name, and
    /// something to publish.
    fn may_take_slot(&self, room: &[u8], user: &[u8], device: &[u8]) -> Result<(), Denial> {
        if !self.is_own_room(room) {
            return Err(Denial::Room);
        }
        if !self.is_own_slot(user, device) {
            return Err(Denial::Identity);
        }
        if self.publish.is_none() {
            return Err(Denial::Publishing);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn namespace(fields: &[&str]) -> TrackNamespace {
        TrackNamespace::from_parts(fields).expect("valid namespace")
    }

    /// A cohost: on stage, in room-42, with a camera and stage powers.
    fn cohost() -> Scope {
        Scope {
            tenant: Arc::from("acme"),
            user: Arc::from("ada"),
            device: Arc::from("device-1"),
            room: Some(Arc::from("room-42")),
            publish: Publish::from_bits(Publish::AUDIO.0 | Publish::VIDEO.0),
            capabilities: capability::STAGE,
            owner: false,
            backstage: false,
            relay: false,
        }
    }

    /// A viewer in the same room: no publishing, no powers.
    fn viewer() -> Scope {
        Scope {
            publish: Publish::NONE,
            capabilities: 0,
            ..cohost()
        }
    }

    fn permission(scope: Scope) -> Permission {
        Permission::scoped(scope)
    }

    #[test]
    fn a_renewal_cannot_turn_a_session_into_a_relay_link_or_back() {
        let link = Scope {
            relay: true,
            ..viewer()
        };
        assert!(!viewer().same_seat(&link));
        assert!(!link.same_seat(&viewer()));
        assert!(link.same_seat(&link.clone()));
    }

    /// A link is minted for one room: it reads that room and nothing else, not
    /// even the personal channels any viewer in the tenant may follow, and it
    /// announces nothing, not even its own personal channel.
    #[test]
    fn a_relay_link_reads_its_room_and_nothing_else() {
        let link = permission(Scope {
            user: Arc::from("moqom-relay"),
            relay: true,
            ..viewer()
        });
        assert_eq!(
            link.may_read(&namespace(&["acme", "r", "room-42", "ada", "device-1"])),
            Ok(())
        );
        assert_eq!(
            link.may_read(&namespace(&["acme", "r", "room-7"])),
            Err(Denial::Room)
        );
        assert_eq!(
            link.may_read(&namespace(&["acme", "u", "ada", "device-1"])),
            Err(Denial::Room)
        );
        assert_eq!(
            permission(viewer()).may_read(&namespace(&["acme", "u", "ada", "device-1"])),
            Ok(()),
            "a viewer still follows personal channels"
        );
        assert_eq!(
            link.may_announce(&namespace(&["acme", "u", "moqom-relay", "device-1"])),
            Err(Denial::Publishing)
        );
    }

    #[test]
    fn a_participant_may_announce_their_own_slot() {
        assert_eq!(
            permission(cohost())
                .may_announce(&namespace(&["acme", "r", "room-42", "ada", "device-1"])),
            Ok(())
        );
    }

    /// The hole this module was written to close.
    #[test]
    fn nobody_publishes_into_another_tenant() {
        assert_eq!(
            permission(cohost())
                .may_announce(&namespace(&["globex", "r", "room-42", "ada", "device-1"])),
            Err(Denial::Tenant)
        );
        assert_eq!(
            permission(cohost()).may_read(&namespace(&["globex", "r", "room-42"])),
            Err(Denial::Tenant)
        );
    }

    #[test]
    fn nobody_publishes_as_somebody_else() {
        assert_eq!(
            permission(cohost())
                .may_announce(&namespace(&["acme", "r", "room-42", "bea", "device-1"])),
            Err(Denial::Identity)
        );
        // Same person, another device. Refused for the same reason: the tile
        // that appears is one this device is not producing frames for, and the
        // subscription lands on whichever session claimed the name.
        assert_eq!(
            permission(cohost())
                .may_announce(&namespace(&["acme", "r", "room-42", "ada", "device-2"])),
            Err(Denial::Identity)
        );
    }

    #[test]
    fn a_token_for_one_room_does_not_reach_another() {
        assert_eq!(
            permission(cohost())
                .may_announce(&namespace(&["acme", "r", "room-7", "ada", "device-1"])),
            Err(Denial::Room)
        );
        assert_eq!(
            permission(cohost()).may_read(&namespace(&["acme", "r", "room-7", "bea", "device-9"])),
            Err(Denial::Room)
        );
    }

    #[test]
    fn a_viewer_may_watch_and_may_not_publish() {
        assert_eq!(
            permission(viewer()).may_read(&namespace(&["acme", "r", "room-42"])),
            Ok(())
        );
        assert_eq!(
            permission(viewer())
                .may_announce(&namespace(&["acme", "r", "room-42", "ada", "device-1"])),
            Err(Denial::Publishing)
        );
    }

    /// A prefix that would answer with every room the customer is running.
    #[test]
    fn a_watch_cannot_enumerate_the_tenant() {
        assert_eq!(
            permission(viewer()).may_read(&namespace(&["acme"])),
            Err(Denial::Shape)
        );
        assert_eq!(
            permission(viewer()).may_read(&namespace(&["acme", "r"])),
            Err(Denial::Shape)
        );
        assert_eq!(
            permission(viewer()).may_read(&namespace(&[])),
            Err(Denial::Shape)
        );
    }

    #[test]
    fn backstage_is_reachable_by_the_people_running_it() {
        let backstage = namespace(&["acme", "bs", "room-42"]);
        // A cohost holds stage powers, which is what managing a queue is.
        assert_eq!(permission(cohost()).may_read(&backstage), Ok(()));
        // A viewer does not, and backstage sits outside the room prefix
        // precisely so that this is the answer.
        assert_eq!(
            permission(viewer()).may_read(&backstage),
            Err(Denial::Backstage)
        );
        // A guest waiting in it can see it.
        let waiting = Scope {
            backstage: true,
            ..viewer()
        };
        assert_eq!(permission(waiting).may_read(&backstage), Ok(()));
    }

    #[test]
    fn a_backstage_guest_publishes_backstage_and_not_on_stage() {
        let guest = Scope {
            backstage: true,
            ..cohost()
        };
        assert_eq!(
            permission(guest.clone())
                .may_announce(&namespace(&["acme", "bs", "room-42", "ada", "device-1"])),
            Ok(())
        );
        // Going live is a new token rather than a different namespace, so this
        // is what stops the queue from being advisory.
        assert_eq!(
            permission(guest)
                .may_announce(&namespace(&["acme", "r", "room-42", "ada", "device-1"])),
            Err(Denial::Backstage)
        );
        // And the reverse: somebody on stage cannot occupy a backstage slot.
        assert_eq!(
            permission(cohost())
                .may_announce(&namespace(&["acme", "bs", "room-42", "ada", "device-1"])),
            Err(Denial::Backstage)
        );
    }

    /// The room's own namespace carries the control log, which is the roster,
    /// the grants, and who was removed.
    #[test]
    fn the_control_log_belongs_to_whoever_runs_the_room() {
        let room = namespace(&["acme", "r", "room-42"]);
        assert_eq!(permission(cohost()).may_announce(&room), Ok(()));
        assert_eq!(
            permission(viewer()).may_announce(&room),
            Err(Denial::Authority)
        );

        let owner = Scope {
            owner: true,
            capabilities: 0,
            ..viewer()
        };
        assert_eq!(permission(owner).may_announce(&room), Ok(()));

        // Chat powers are not room powers. Chat never reaches a relay, so a
        // chat moderator holding the room's control track would be a grant
        // nobody meant to make.
        let chat = Scope {
            capabilities: capability::CHAT,
            ..viewer()
        };
        assert_eq!(permission(chat).may_announce(&room), Err(Denial::Authority));
    }

    #[test]
    fn a_personal_channel_belongs_to_its_owner_and_is_public_to_the_tenant() {
        let mine = namespace(&["acme", "u", "ada", "device-1"]);
        let theirs = namespace(&["acme", "u", "bea", "device-3"]);

        // No room needed: this is what a broadcaster outside a call publishes.
        let roomless = Scope {
            room: None,
            ..cohost()
        };
        assert_eq!(permission(roomless).may_announce(&mine), Ok(()));
        assert_eq!(
            permission(cohost()).may_announce(&theirs),
            Err(Denial::Identity)
        );
        // Following somebody is reading their channel, and needs no membership.
        assert_eq!(permission(cohost()).may_read(&theirs), Ok(()));
    }

    /// A token with no room reaches personal channels and nothing else, which
    /// is what a client that has left a room is holding.
    #[test]
    fn a_token_naming_no_room_reaches_no_room() {
        let roomless = Scope {
            room: None,
            ..cohost()
        };
        assert_eq!(
            permission(roomless.clone()).may_read(&namespace(&["acme", "r", "room-42"])),
            Err(Denial::Room)
        );
        assert_eq!(
            permission(roomless)
                .may_announce(&namespace(&["acme", "r", "room-42", "ada", "device-1"])),
            Err(Denial::Room)
        );
    }

    /// Names outside the grammar are refused rather than forwarded. See the
    /// note at the top of this module: a relay with keys is a MOQOM relay.
    #[test]
    fn an_unrecognised_shape_is_refused() {
        assert_eq!(
            permission(cohost()).may_announce(&namespace(&["acme", "x", "something"])),
            Err(Denial::Shape)
        );
        assert_eq!(
            permission(cohost()).may_read(&namespace(&["acme", "x", "something"])),
            Err(Denial::Shape)
        );
        // The right marker with the wrong depth is equally unrecognised: a
        // sub-track under a participant is not a slot anybody may claim.
        assert_eq!(
            permission(cohost()).may_announce(&namespace(&[
                "acme", "r", "room-42", "ada", "device-1", "extra"
            ])),
            Err(Denial::Shape)
        );
    }

    /// Reading deeper than a slot is fine, because a subscription names a full
    /// track namespace and applications may nest below it.
    #[test]
    fn reading_below_a_slot_stays_inside_the_room() {
        assert_eq!(
            permission(viewer()).may_read(&namespace(&[
                "acme", "r", "room-42", "bea", "device-3", "whatever"
            ])),
            Ok(())
        );
    }

    /// What may change on a live session and what may not. A grant is the
    /// first kind; the person, the device, the room and ownership are the
    /// second, because each of them is part of what the session was admitted as.
    #[test]
    fn a_seat_is_who_where_and_whose_room_and_not_what_they_may_do() {
        assert!(viewer().same_seat(&cohost()));
        let waiting = Scope {
            backstage: true,
            ..viewer()
        };
        assert!(waiting.same_seat(&cohost()));

        for moved in [
            Scope {
                user: Arc::from("bea"),
                ..cohost()
            },
            Scope {
                device: Arc::from("device-2"),
                ..cohost()
            },
            Scope {
                room: Some(Arc::from("room-7")),
                ..cohost()
            },
            Scope {
                room: None,
                ..cohost()
            },
            Scope {
                tenant: Arc::from("globex"),
                ..cohost()
            },
            Scope {
                owner: true,
                ..cohost()
            },
        ] {
            assert!(!viewer().same_seat(&moved), "{moved:?}");
        }
    }

    #[test]
    fn a_regrade_says_which_way_somebody_moved() {
        assert_eq!(viewer().regrade(&cohost()), Some(Regrade::Promotion));
        assert_eq!(cohost().regrade(&viewer()), Some(Regrade::Demotion));
        assert_eq!(cohost().regrade(&cohost()), None);

        // Leaving the queue for the stage is a promotion although no bit moved,
        // and the reverse is a demotion: it is the difference between being
        // seen by the audience and not.
        let waiting = Scope {
            backstage: true,
            ..cohost()
        };
        assert_eq!(waiting.regrade(&cohost()), Some(Regrade::Promotion));
        assert_eq!(cohost().regrade(&waiting), Some(Regrade::Demotion));

        let screen_guest = Scope {
            publish: Publish::SCREEN,
            capabilities: 0,
            ..cohost()
        };
        assert_eq!(cohost().regrade(&screen_guest), Some(Regrade::Lateral));
    }

    /// A ceiling only takes away. Applying the most generous one there is to a
    /// viewer leaves a viewer.
    #[test]
    fn a_ceiling_narrows_and_never_widens() {
        let demoted = cohost().capped(Ceiling {
            publish: Publish::AUDIO,
            capabilities: 0,
        });
        assert_eq!(demoted.publish, Publish::AUDIO);
        assert_eq!(demoted.capabilities, 0);
        assert!(demoted.same_seat(&cohost()));

        let generous = Ceiling {
            publish: Publish::from_bits(0xFF),
            capabilities: capability::KNOWN,
        };
        assert_eq!(viewer().capped(generous), viewer());

        let both = generous.meet(Ceiling {
            publish: Publish::VIDEO,
            capabilities: capability::CHAT,
        });
        assert_eq!(both.publish, Publish::VIDEO);
        assert_eq!(both.capabilities, capability::CHAT);
    }

    #[test]
    fn an_unrestricted_relay_permits_everything() {
        assert_eq!(
            Permission::Unrestricted.may_announce(&namespace(&["anything", "at", "all"])),
            Ok(())
        );
        assert_eq!(Permission::Unrestricted.may_read(&namespace(&[])), Ok(()));
    }
}
