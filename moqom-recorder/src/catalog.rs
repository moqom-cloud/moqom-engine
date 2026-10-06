//! Reading a participant's `.catalog`, and following it as it changes.
//!
//! The catalog is the one document a recorder can read in an encrypted room:
//! catalogs are never encrypted, so a third party can learn what is offered
//! without anyone's keys. Every version is a whole document, so following one
//! is a diff against the last version applied, and a version that cannot be
//! parsed leaves the previous one in force -- dropping tracks because one
//! document was malformed would stop recording media that is still arriving.
//!
//! Only the fields the recorder acts on are typed. The rest of the document is
//! kept as it arrived, in the archive of the `.catalog` track itself.

use std::collections::BTreeMap;

use serde::Deserialize;

/// The catalog track's name within a participant's namespace.
pub const TRACK_NAME: &str = ".catalog";

/// The newest format version this build reads.
pub const CURRENT_VERSION: u64 = 1;

/// What one track carries, as far as recording needs to know.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Track {
    /// The track's name within the participant's namespace.
    pub name: String,
    /// `video`, `audio`, `screen` or `data`.
    pub kind: Kind,
    /// MIME-style: `video/hevc`, `video/h264`, `audio/opus`.
    #[serde(default)]
    pub codec: String,
    /// Hex. Length-prefixed parameter sets for video, the identification header
    /// for Opus.
    #[serde(default)]
    pub decoder_configuration: Option<String>,
    /// Pixels.
    #[serde(default)]
    pub width: Option<u32>,
    /// Pixels.
    #[serde(default)]
    pub height: Option<u32>,
    /// Frames per second, used for timing only when objects carry no capture time.
    #[serde(default)]
    pub frame_rate: Option<f64>,
    /// Hertz.
    #[serde(default)]
    pub sample_rate: Option<u32>,
    /// Audio channels.
    #[serde(default)]
    pub channels: Option<u32>,
}

/// What kind of media a track is.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A camera rung.
    Video,
    /// The microphone.
    Audio,
    /// A screen share rung.
    Screen,
    /// Anything the SDK does not interpret.
    #[serde(other)]
    Data,
}

/// A catalog, reduced to what recording acts on.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Catalog {
    /// Format version.
    pub version: u64,
    /// The `SFrame` key ID protecting this publisher's media, if any. Present
    /// means the payloads are ciphertext, whatever the room's policy says.
    #[serde(default, rename = "keyID")]
    pub key_id: Option<u64>,
    /// What is on offer.
    pub tracks: Vec<Track>,
}

/// Why a payload is not a catalog this build will act on.
#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    /// Not JSON, or not this shape.
    #[error("not a catalog: {0}")]
    Malformed(#[from] serde_json::Error),
    /// A newer format than this build reads. Refused rather than partly
    /// applied, because a field read wrong becomes a file muxed wrong.
    #[error("catalog version {0} is newer than {CURRENT_VERSION}")]
    UnsupportedVersion(u64),
}

impl Catalog {
    /// Parse one `.catalog` object.
    ///
    /// # Errors
    /// [`CatalogError`] for anything that is not a version-1 catalog.
    pub fn parse(payload: &[u8]) -> Result<Self, CatalogError> {
        let catalog: Self = serde_json::from_slice(payload)?;
        if catalog.version > CURRENT_VERSION {
            return Err(CatalogError::UnsupportedVersion(catalog.version));
        }
        Ok(catalog)
    }

    /// Whether this publisher's media is end-to-end encrypted.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.key_id.is_some()
    }
}

/// The difference one catalog version makes.
#[derive(Debug, Default, PartialEq)]
pub struct Changes {
    /// Tracks to start recording.
    pub added: Vec<Track>,
    /// Tracks the publisher has stopped offering.
    pub removed: Vec<String>,
    /// Tracks still offered whose description changed, such as a new geometry.
    pub changed: Vec<Track>,
}

impl Changes {
    /// Whether this version changed nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

/// One participant's catalog, followed across versions.
#[derive(Debug, Default)]
pub struct Follower {
    tracks: BTreeMap<String, Track>,
    encrypted: bool,
    applied: u64,
    rejected: u64,
}

impl Follower {
    /// A follower that has seen nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one `.catalog` object, returning what changed.
    ///
    /// Reserved names -- those beginning with a dot -- are never offered as
    /// media, so a catalog that lists one does not make the recorder subscribe
    /// to the relay's own channels.
    ///
    /// # Errors
    /// [`CatalogError`], in which case the previous version stays in force.
    pub fn apply(&mut self, payload: &[u8]) -> Result<Changes, CatalogError> {
        let catalog = match Catalog::parse(payload) {
            Ok(catalog) => catalog,
            Err(error) => {
                self.rejected += 1;
                return Err(error);
            }
        };
        self.applied += 1;
        self.encrypted = catalog.is_encrypted();

        let mut next = BTreeMap::new();
        for track in catalog.tracks {
            if track.name.is_empty() || track.name.starts_with('.') {
                continue;
            }
            next.insert(track.name.clone(), track);
        }

        let mut changes = Changes::default();
        for (name, track) in &next {
            match self.tracks.get(name) {
                None => changes.added.push(track.clone()),
                Some(previous) if previous != track => changes.changed.push(track.clone()),
                Some(_) => {}
            }
        }
        for name in self.tracks.keys() {
            if !next.contains_key(name) {
                changes.removed.push(name.clone());
            }
        }
        self.tracks = next;
        Ok(changes)
    }

    /// The current description of `name`, if it is offered.
    #[must_use]
    pub fn track(&self, name: &str) -> Option<&Track> {
        self.tracks.get(name)
    }

    /// Every track currently offered, which is what a reconnect resubscribes to.
    pub fn tracks(&self) -> impl Iterator<Item = &Track> {
        self.tracks.values()
    }

    /// Whether the latest version applied names a key.
    #[must_use]
    pub const fn encrypted(&self) -> bool {
        self.encrypted
    }

    /// Versions applied and refused.
    #[must_use]
    pub const fn counts(&self) -> (u64, u64) {
        (self.applied, self.rejected)
    }
}

/// Decode a catalog's hex `decoderConfiguration`.
#[must_use]
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIRST: &[u8] = br#"{"version":1,"muted":0,"interrupted":0,"tracks":[
        {"name":"video/360p","kind":"video","codec":"video/hevc","width":640,"height":360,"rung":0,"isPrimary":false},
        {"name":"video/720p","kind":"video","codec":"video/hevc","width":1280,"height":720,"rung":1,"isPrimary":true},
        {"name":"audio","kind":"audio","codec":"audio/opus","sampleRate":48000,"channels":1,"isPrimary":false}
    ]}"#;

    #[test]
    fn the_first_version_adds_every_track() {
        let mut follower = Follower::new();
        let changes = follower.apply(FIRST).expect("a catalog");
        let names: Vec<_> = changes.added.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["audio", "video/360p", "video/720p"]);
        assert!(changes.removed.is_empty());
        assert!(!follower.encrypted());
        assert_eq!(
            follower.track("video/720p").and_then(|t| t.width),
            Some(1280)
        );
    }

    #[test]
    fn a_later_version_is_a_diff() {
        let mut follower = Follower::new();
        follower.apply(FIRST).expect("a catalog");
        let next = br#"{"version":1,"keyID":7,"tracks":[
            {"name":"video/720p","kind":"video","codec":"video/hevc","width":720,"height":1280,"rung":1,"isPrimary":true},
            {"name":"audio","kind":"audio","codec":"audio/opus","sampleRate":48000,"channels":1,"isPrimary":false},
            {"name":"screen/1080p","kind":"screen","codec":"video/h264","width":1920,"height":1080}
        ]}"#;
        let changes = follower.apply(next).expect("a catalog");
        assert_eq!(changes.added.len(), 1);
        assert_eq!(changes.added[0].name, "screen/1080p");
        assert_eq!(changes.added[0].kind, Kind::Screen);
        assert_eq!(changes.removed, ["video/360p"]);
        assert_eq!(changes.changed.len(), 1, "the 720p rung turned portrait");
        assert!(follower.encrypted());

        assert!(follower.apply(next).expect("the same again").is_empty());
    }

    #[test]
    fn a_bad_version_leaves_the_last_good_one() {
        let mut follower = Follower::new();
        follower.apply(FIRST).expect("a catalog");
        assert!(follower.apply(b"not json").is_err());
        assert!(matches!(
            follower.apply(br#"{"version":2,"tracks":[]}"#),
            Err(CatalogError::UnsupportedVersion(2))
        ));
        assert!(follower.track("audio").is_some());
        assert_eq!(follower.counts(), (1, 2));
    }

    #[test]
    fn reserved_names_and_unknown_kinds() {
        let mut follower = Follower::new();
        let changes = follower
            .apply(
                br#"{"version":1,"tracks":[
                {"name":".policy","kind":"data","codec":""},
                {"name":"telemetry","kind":"hologram","codec":"application/x"}
            ]}"#,
            )
            .expect("a catalog");
        assert_eq!(changes.added.len(), 1);
        assert_eq!(changes.added[0].kind, Kind::Data);
    }

    #[test]
    fn hex_round_trips() {
        assert_eq!(unhex("00ff10"), Some(vec![0, 255, 16]));
        assert_eq!(unhex("0"), None);
        assert_eq!(unhex("zz"), None);
    }
}
