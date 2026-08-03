//! Which media a track name carries.
//!
//! A relay cannot read an object — that is the property that keeps it
//! compatible with end-to-end encryption, and it is why the module docs for
//! [`crate::link`] used to say that mutes were unenforceable here. That
//! reasoning had a hole in it. Stopping somebody's camera does not require
//! reading a frame; it requires knowing which tracks are the camera, and a
//! track's kind is in its *name*, which is the one thing a relay always reads.
//!
//! The names are the client SDK's, and they are already shaped for this:
//!
//! ```text
//! audio            the microphone
//! video/720p       one rung of the camera ladder
//! screen/1080p     one rung of a screen share
//! .catalog         what this participant is offering
//! .control         the room's log
//! .policy          what the relay will let this participant publish
//! ```
//!
//! # Why an unrecognised name is media
//!
//! A track that classifies as nothing is still stopped by a mute that names
//! every kind, and that is deliberate. "Mute them" during an incident has to
//! mean *everything*, including a track this build has never heard of, because
//! the alternative is a moderator watching a stream they were told they had
//! stopped. Only the reserved names — the ones beginning with a dot, which
//! carry no media at all — are exempt, and they are exempt by name rather than
//! by failing to match: `.policy` in particular is how the relay tells a muted
//! participant they are muted, and muting the channel that says so would be a
//! fine way to make the feature untestable.

use std::fmt;

/// A set of media kinds.
///
/// The bit positions are shared with Go's `control.MediaKind` and Swift's
/// `MediaKind`, so a mute crosses three languages as a number rather than as a
/// translation. [`crate::scope::Publish`] is the same idea for what a *token*
/// permits and is deliberately a different type: one says what a person was
/// granted, the other what a moderator has taken away, and a mute that could
/// be compared to a grant by accident is a bug waiting for a busy evening.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Kinds(u32);

impl Kinds {
    /// Nothing is muted.
    pub const NONE: Self = Self(0);
    /// The microphone.
    pub const AUDIO: Self = Self(1 << 0);
    /// The camera.
    pub const VIDEO: Self = Self(1 << 1);
    /// A screen share, which a room may allow when it allows no camera.
    pub const SCREEN: Self = Self(1 << 2);
    /// Every kind this relay knows the name of.
    pub const ALL: Self = Self(0b111);

    /// The kinds a directive's bitmask names.
    ///
    /// Bits this build does not know are dropped rather than kept. Unlike a
    /// capability, where an unknown bit may be a power being withheld, an
    /// unknown media bit cannot name a track: the classifier below produces
    /// only the three, so a fourth could never match anything and keeping it
    /// would only make `ALL` unreachable by equality.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits & Self::ALL.0)
    }

    /// The bitmask, for reporting back the way it arrived.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether this is nothing at all.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Whether every kind in `other` is present.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether any kind is in both.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Both sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// This set without `other`.
    #[must_use]
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

/// The kinds by name, for a log line a person has to read at 3am.
impl fmt::Display for Kinds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("nothing");
        }
        let mut first = true;
        for (kind, name) in [
            (Self::AUDIO, "audio"),
            (Self::VIDEO, "video"),
            (Self::SCREEN, "screen"),
        ] {
            if self.contains(kind) {
                if !first {
                    f.write_str("+")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        Ok(())
    }
}

/// What a track called `name` carries.
///
/// `None` for the reserved tracks, which carry no media and are never muted.
/// Everything else is media, classified by its prefix where the prefix is one
/// this relay knows and treated as unknown media where it is not — see the
/// module docs for why that is the safe direction.
#[must_use]
pub fn classify(name: &[u8]) -> Option<Kinds> {
    // A reserved name, which is metadata about the participant rather than
    // anything they are broadcasting.
    if name.first() == Some(&b'.') {
        return None;
    }

    let head = match name.iter().position(|byte| *byte == b'/') {
        Some(slash) => &name[..slash],
        None => name,
    };

    Some(match head {
        b"audio" => Kinds::AUDIO,
        b"video" => Kinds::VIDEO,
        b"screen" | b"screenshare" => Kinds::SCREEN,
        // Unknown media. Caught by a mute that names every kind and by nothing
        // narrower, which is the most a relay can honestly do with a name it
        // does not recognise.
        _ => Kinds::ALL,
    })
}

/// Whether a mute of `muted` stops the track called `name`.
///
/// The unknown-media case is what makes this more than a bitwise test: a track
/// this relay cannot classify is stopped only by a mute that covers
/// everything, so a moderator muting one kind cannot accidentally take down a
/// data track, and a moderator muting all of it cannot be evaded by inventing
/// a track name.
#[must_use]
pub fn stopped(name: &[u8], muted: Kinds) -> bool {
    match classify(name) {
        None => false,
        Some(kinds) if kinds == Kinds::ALL => muted.contains(Kinds::ALL),
        Some(kinds) => muted.intersects(kinds),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_says_what_it_carries() {
        assert_eq!(classify(b"audio"), Some(Kinds::AUDIO));
        assert_eq!(classify(b"video/720p"), Some(Kinds::VIDEO));
        assert_eq!(classify(b"video"), Some(Kinds::VIDEO));
        assert_eq!(classify(b"screen/1080p"), Some(Kinds::SCREEN));
        assert_eq!(classify(b"screenshare/1080p"), Some(Kinds::SCREEN));
    }

    #[test]
    fn the_reserved_tracks_carry_no_media() {
        assert_eq!(classify(b".catalog"), None);
        assert_eq!(classify(b".control"), None);
        assert_eq!(classify(b".policy"), None);

        // And are never stopped, whatever is muted -- including by the mute
        // that stops everything, since that is how the muted participant finds
        // out they are muted.
        assert!(!stopped(b".policy", Kinds::ALL));
        assert!(!stopped(b".catalog", Kinds::ALL));
    }

    #[test]
    fn an_unrecognised_track_is_stopped_only_by_a_total_mute() {
        assert!(!stopped(b"telemetry", Kinds::VIDEO));
        assert!(!stopped(b"telemetry", Kinds::AUDIO.union(Kinds::VIDEO)));
        assert!(stopped(b"telemetry", Kinds::ALL));
    }

    #[test]
    fn a_mute_of_one_kind_leaves_the_others_alone() {
        assert!(stopped(b"video/180p", Kinds::VIDEO));
        assert!(!stopped(b"audio", Kinds::VIDEO));
        assert!(stopped(b"audio", Kinds::AUDIO.union(Kinds::VIDEO)));
        assert!(!stopped(b"video/180p", Kinds::NONE));
    }

    #[test]
    fn the_bitmask_matches_what_go_and_swift_send() {
        assert_eq!(Kinds::AUDIO.bits(), 1);
        assert_eq!(Kinds::VIDEO.bits(), 2);
        assert_eq!(Kinds::SCREEN.bits(), 4);
        assert_eq!(Kinds::from_bits(0b1111), Kinds::ALL);
        assert_eq!(Kinds::from_bits(0), Kinds::NONE);
    }

    #[test]
    fn kinds_read_as_words() {
        assert_eq!(Kinds::NONE.to_string(), "nothing");
        assert_eq!(Kinds::AUDIO.to_string(), "audio");
        assert_eq!(Kinds::ALL.to_string(), "audio+video+screen");
        assert_eq!(Kinds::ALL.without(Kinds::VIDEO).to_string(), "audio+screen");
    }
}
