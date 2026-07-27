//! What an object carries, shared by datagrams and subgroup streams.

use crate::error::DecodeError;
use crate::model::ObjectStatus;

/// A status that marks the end of a range rather than carrying media.
///
/// Split out from [`ObjectStatus`] because the draft attaches two rules to
/// non-normal statuses — no payload (§11.2.1.1) and no properties (§11.2.1.2) —
/// and a type that cannot hold either enforces both without a runtime check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TerminalStatus {
    /// No object in this group has an Object ID at or above this one.
    EndOfGroup,
    /// No object in this track has a Location at or above this one.
    EndOfTrack,
}

impl TerminalStatus {
    /// The equivalent [`ObjectStatus`].
    #[must_use]
    pub const fn as_status(self) -> ObjectStatus {
        match self {
            Self::EndOfGroup => ObjectStatus::EndOfGroup,
            Self::EndOfTrack => ObjectStatus::EndOfTrack,
        }
    }
}

impl TryFrom<ObjectStatus> for TerminalStatus {
    type Error = DecodeError;

    fn try_from(status: ObjectStatus) -> Result<Self, Self::Error> {
        match status {
            ObjectStatus::EndOfGroup => Ok(Self::EndOfGroup),
            ObjectStatus::EndOfTrack => Ok(Self::EndOfTrack),
            ObjectStatus::Normal => Err(DecodeError::Invalid(
                "normal status is not a terminal marker",
            )),
        }
    }
}

impl std::fmt::Display for TerminalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_status().fmt(f)
    }
}
