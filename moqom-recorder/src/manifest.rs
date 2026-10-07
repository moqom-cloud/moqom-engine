//! The index written beside a recording's files.
//!
//! One per attempt, written last, so its presence says that attempt finished
//! cleanly; an attempt cut short by a crash leaves archives without one, and
//! those archives are still readable to their last whole record. A reader
//! wanting the whole recording takes every manifest under the prefix in attempt
//! order.

use serde::{Deserialize, Serialize};

/// What a file is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    /// A lossless object archive (`.mqa`).
    Archive,
    /// A CMAF track file: initialisation segment, then fragments.
    Cmaf,
    /// This manifest.
    Manifest,
}

impl ArtifactKind {
    /// The name the control plane's API uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Archive => "archive",
            Self::Cmaf => "cmaf",
            Self::Manifest => "manifest",
        }
    }

    /// The `Content-Type` it is stored with.
    #[must_use]
    pub const fn content_type(self) -> &'static str {
        match self {
            Self::Archive => "application/octet-stream",
            Self::Cmaf => "video/mp4",
            Self::Manifest => "application/json",
        }
    }
}

/// One finished file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    /// The object name, relative to the recording's prefix.
    pub name: String,
    /// What it is.
    pub kind: ArtifactKind,
    /// The track, as `user/device/track`.
    pub track: String,
    /// Its length.
    pub bytes: u64,
    /// Its CRC-32C, as GCS reports it.
    pub crc32c: u32,
    /// Microseconds since the Unix epoch of the first object in it.
    pub first_micros: Option<u64>,
    /// And of the last.
    pub last_micros: Option<u64>,
}

/// One track as the manifest describes it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TrackEntry {
    /// `user/device/track`.
    pub track: String,
    /// The catalog's kind, if the track was listed in one.
    pub kind: Option<String>,
    /// The catalog's codec string.
    pub codec: Option<String>,
    /// Objects archived.
    pub objects: u64,
    /// Objects received again after a reconnect and not archived twice.
    pub duplicates: u64,
    /// Why no CMAF was written for this track, if none was.
    pub cmaf_skipped: Option<String>,
    /// Where each session's recording of this track began. Absent from
    /// manifests written before recorders caught up on joining.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub joins: Vec<Join>,
}

/// How a recording of one track began, in one session.
///
/// A subscription starts at the next group, so a recorder that joins while a
/// group is in flight fetches that group from the relay to begin at its first
/// object. This says whether it did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Join {
    /// The session, as numbered by the archive's `session` records.
    pub session: u32,
    /// How it began.
    pub from: JoinFrom,
    /// The first group recorded contiguously from here, when known.
    pub group: Option<u64>,
    /// And the first object in it: zero is a clean group boundary.
    pub object: Option<u64>,
    /// Why it did not catch up, when it did not.
    pub reason: Option<String>,
}

/// See [`Join`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinFrom {
    /// The track began after the recorder subscribed: nothing was missed.
    TrackStart,
    /// The group in flight was fetched from its first object.
    CaughtUp,
    /// The group in flight could not be fetched, so recording begins at the
    /// start of the next one and the rest of the group in flight is not in it.
    NextGroup,
    /// Recording begins part-way through a group: the relay held only part of
    /// it, or the subscription itself started mid-group and the start could
    /// not be fetched.
    MidGroup,
}

/// The manifest.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    /// Always `moqom-recording`.
    pub format: String,
    /// Bumped on an incompatible change.
    pub version: u32,
    /// The recording.
    pub recording: String,
    /// The tenant.
    pub tenant: String,
    /// The room.
    pub room: String,
    /// Which attempt this is. A recorder that crashed and was replaced writes
    /// its files under a new attempt number, so two never write the same name.
    pub attempt: u32,
    /// Whether the room's media was end-to-end encrypted, in which case every
    /// archived payload is ciphertext and no CMAF exists.
    pub encrypted: bool,
    /// Microseconds since the Unix epoch.
    pub started_micros: u64,
    /// And the end.
    pub ended_micros: u64,
    /// How many times the recorder had to reconnect.
    pub reconnects: u32,
    /// The tracks.
    pub tracks: Vec<TrackEntry>,
    /// The files, the manifest itself excluded.
    pub artifacts: Vec<Artifact>,
    /// Why the attempt ended early, if it did.
    pub error: Option<String>,
}

impl Manifest {
    /// The object name a manifest for `attempt` is stored under.
    #[must_use]
    pub fn name(attempt: u32) -> String {
        format!("manifest-a{attempt}.json")
    }
}
