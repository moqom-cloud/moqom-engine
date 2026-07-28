//! What MOQOM's namespace tuples mean.
//!
//! This mirrors `MoqomNamespaces` in `MoqomCore/Identity.swift` and must keep
//! mirroring it. The Swift side *builds* these tuples, because a client knows
//! the tenant, the room, and its own identity. This side *reads* them, because
//! a relay is handed namespaces by strangers and has to decide what it is
//! looking at.
//!
//! The layouts, which are the whole of the convention:
//!
//! | Shape | Meaning |
//! |---|---|
//! | `(tenant, "u", username, device)` | a personal channel, independent of any room |
//! | `(tenant, "r", room)` | the prefix a viewer subscribes to for a whole room |
//! | `(tenant, "r", room, username, device)` | one participant on stage |
//! | `(tenant, "bs", room)` | backstage, deliberately outside the room prefix |
//! | `(tenant, "bs", room, username, device)` | one participant backstage |
//!
//! # Why the relay parses these at all
//!
//! Forwarding does not need them: a relay matches prefixes bytewise and never
//! has to know that field 2 is a room. Observability does. "How many rooms are
//! live", "which participants are on this session", and "who was publishing
//! when this went wrong" are unanswerable from an opaque tuple, and answering
//! them by having clients *report* their own room would mean trusting the party
//! whose connection is the thing under investigation.
//!
//! # Why parsing is strict
//!
//! A shape this does not recognise returns `None` rather than a best guess.
//! That matters most for the participant forms: something one field deeper than
//! a participant slot — a sub-track, or whatever a later draft adds — must not
//! be read as a participant and counted as one. The Swift side takes the same
//! position by requiring exactly two trailing fields.

use super::name::TrackNamespace;

/// Which of MOQOM's three namespace families a tuple belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A user's own channel: `(tenant, "u", …)`.
    Personal,
    /// A room's stage, which viewers may subscribe to: `(tenant, "r", …)`.
    Stage,
    /// A room's backstage, which they may not: `(tenant, "bs", …)`.
    Backstage,
}

impl Kind {
    /// The field-1 discriminator this kind is written as.
    #[must_use]
    pub const fn tag(self) -> &'static [u8] {
        match self {
            Self::Personal => b"u",
            Self::Stage => b"r",
            Self::Backstage => b"bs",
        }
    }

    fn from_tag(tag: &[u8]) -> Option<Self> {
        match tag {
            b"u" => Some(Self::Personal),
            b"r" => Some(Self::Stage),
            b"bs" => Some(Self::Backstage),
            _ => None,
        }
    }

    /// Whether this kind names a room rather than a personal channel.
    #[must_use]
    pub const fn is_room(self) -> bool {
        matches!(self, Self::Stage | Self::Backstage)
    }
}

/// One participant's device, as the trailing two fields of a slot namespace.
///
/// Both fields together are the identity: the same person on a phone and a
/// laptop is two participants, publishing two tracks, and a relay that
/// collapsed them would report one of them as having disappeared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Participant<'a> {
    /// The account name, which is the user-facing identifier.
    pub username: &'a [u8],
    /// Which of that account's devices this is.
    pub device: &'a [u8],
}

/// What a namespace refers to.
///
/// Borrows from the namespace rather than copying: this is built on the
/// forwarding path's data at log and scrape time, and the fields are only ever
/// read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Scope<'a> {
    /// The tenant, which is always field 0.
    pub tenant: &'a [u8],
    /// Which family of namespace this is.
    pub kind: Kind,
    /// The room, for [`Kind::Stage`] and [`Kind::Backstage`].
    ///
    /// `None` for a personal channel, and for the bare `(tenant, "r")` prefix
    /// that a tenant-wide watcher subscribes to.
    pub room: Option<&'a [u8]>,
    /// The participant, when this is a slot rather than a prefix.
    pub participant: Option<Participant<'a>>,
}

impl<'a> Scope<'a> {
    /// Interpret `namespace`, or `None` if it is not a shape MOQOM builds.
    #[must_use]
    pub fn of(namespace: &'a TrackNamespace) -> Option<Self> {
        let fields = namespace.fields();
        // Field 1 is the discriminator, so nothing shorter carries a meaning —
        // including the empty namespace, which is a legal prefix and not a
        // scope.
        let [tenant, tag, rest @ ..] = fields else {
            return None;
        };
        let kind = Kind::from_tag(tag)?;
        let tenant = &tenant[..];

        let (room, participant) = match (kind.is_room(), rest) {
            // `(tenant, "u")` and `(tenant, "r")`: a prefix naming everything
            // of that kind in the tenant.
            (_, []) => (None, None),

            // `(tenant, "u", username, device)`.
            (false, [username, device]) => (None, Some(Participant { username, device })),

            // `(tenant, "r"|"bs", room)`.
            (true, [room]) => (Some(&room[..]), None),

            // `(tenant, "r"|"bs", room, username, device)`.
            (true, [room, username, device]) => {
                (Some(&room[..]), Some(Participant { username, device }))
            }

            // Everything else: a personal channel missing its device, a room
            // slot missing one, or anything deeper than a slot. Guessing here
            // is how a sub-track becomes a phantom participant.
            _ => return None,
        };

        Some(Self {
            tenant,
            kind,
            room,
            participant,
        })
    }

    /// The room this belongs to, as a tenant and room pair.
    ///
    /// `None` for a personal channel or a tenant-wide prefix. Stage and
    /// backstage collapse to the same room deliberately: they are two halves of
    /// one room, and counting them separately would report every room with a
    /// guest waiting as two.
    #[must_use]
    pub fn room_key(&self) -> Option<(&'a [u8], &'a [u8])> {
        self.room.map(|room| (self.tenant, room))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(fields: &[&str]) -> TrackNamespace {
        TrackNamespace::from_parts(fields).expect("valid namespace")
    }

    #[test]
    fn a_participant_slot_yields_its_room_and_identity() {
        let namespace = ns(&["acme", "r", "room-42", "ada", "phone"]);
        let scope = Scope::of(&namespace).expect("a known shape");
        assert_eq!(scope.tenant, b"acme");
        assert_eq!(scope.kind, Kind::Stage);
        assert_eq!(scope.room, Some(&b"room-42"[..]));
        assert_eq!(
            scope.participant,
            Some(Participant {
                username: b"ada",
                device: b"phone"
            })
        );
    }

    #[test]
    fn a_room_prefix_has_no_participant() {
        let namespace = ns(&["acme", "r", "room-42"]);
        let scope = Scope::of(&namespace).expect("a known shape");
        assert_eq!(scope.room, Some(&b"room-42"[..]));
        assert_eq!(scope.participant, None);
    }

    #[test]
    fn a_personal_channel_has_no_room() {
        let namespace = ns(&["acme", "u", "ada", "phone"]);
        let scope = Scope::of(&namespace).expect("a known shape");
        assert_eq!(scope.kind, Kind::Personal);
        assert_eq!(scope.room, None);
        assert_eq!(scope.room_key(), None);
        assert_eq!(scope.participant.map(|p| p.username), Some(&b"ada"[..]));
    }

    /// Backstage is a different namespace family so that a viewer's prefix
    /// subscription cannot reach it, but it is the *same room*. Reporting two
    /// rooms for one would double every room with a guest waiting to go on.
    #[test]
    fn backstage_belongs_to_the_same_room_as_the_stage() {
        let stage = ns(&["acme", "r", "room-42", "ada", "phone"]);
        let backstage = ns(&["acme", "bs", "room-42", "grace", "phone"]);

        let stage = Scope::of(&stage).expect("a known shape");
        let backstage = Scope::of(&backstage).expect("a known shape");

        assert_eq!(stage.kind, Kind::Stage);
        assert_eq!(backstage.kind, Kind::Backstage);
        assert_eq!(stage.room_key(), backstage.room_key());
    }

    /// The strictness that matters: one field deeper than a slot is not a slot.
    /// Reading it as one would put a phantom participant in every count.
    #[test]
    fn something_deeper_than_a_slot_is_not_a_slot() {
        assert_eq!(
            Scope::of(&ns(&["acme", "r", "room-42", "ada", "phone", "extra"])),
            None
        );
        assert_eq!(
            Scope::of(&ns(&["acme", "u", "ada", "phone", "extra"])),
            None
        );
    }

    /// A slot missing its device field is not a participant. Treating it as one
    /// would attribute every device to whichever arrived first.
    #[test]
    fn a_slot_missing_its_device_is_not_a_participant() {
        assert_eq!(Scope::of(&ns(&["acme", "r", "room-42", "ada"])), None);
        assert_eq!(Scope::of(&ns(&["acme", "u", "ada"])), None);
    }

    #[test]
    fn an_unknown_discriminator_is_not_a_scope() {
        assert_eq!(Scope::of(&ns(&["acme", "zz", "room-42"])), None);
    }

    /// The empty namespace is a legal prefix — it matches everything — but it
    /// names nothing, and a metric attributed to it would be attributed to the
    /// whole relay.
    #[test]
    fn a_namespace_too_short_to_have_a_kind_is_not_a_scope() {
        assert_eq!(Scope::of(&ns(&[])), None);
        assert_eq!(Scope::of(&ns(&["acme"])), None);
    }

    /// Namespaces are bytes and the specification imposes no encoding, so
    /// parsing must not assume UTF-8. Anything that wants to *display* these
    /// has to handle that itself.
    #[test]
    fn a_non_utf8_room_still_parses() {
        let namespace =
            TrackNamespace::from_parts([b"acme".as_slice(), b"r", &[0xff, 0xfe], b"ada", b"phone"])
                .expect("bytes are legal namespace fields");
        let scope = Scope::of(&namespace).expect("a known shape");
        assert_eq!(scope.room, Some(&[0xff, 0xfe][..]));
    }

    /// The tags are the wire contract with the Swift builder, so a typo here is
    /// a silent interoperability break rather than a compile error.
    #[test]
    fn the_tags_match_the_swift_builder() {
        assert_eq!(Kind::Personal.tag(), b"u");
        assert_eq!(Kind::Stage.tag(), b"r");
        assert_eq!(Kind::Backstage.tag(), b"bs");
    }
}
