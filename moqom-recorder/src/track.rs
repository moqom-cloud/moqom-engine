//! Writing one track down.
//!
//! A [`TrackWriter`] outlives the sessions that feed it. When the recorder
//! reconnects it resubscribes and keeps writing into the same writer, so a
//! reconnect is a [`session`](TrackWriter::session) marker in the archive, not
//! a new file, and an object the relay delivers twice across the gap -- it
//! will, for the group in flight -- is archived once.
//!
//! Files rotate at a group boundary once they pass a size, so no one file
//! grows without bound and each finished file can be uploaded while the next
//! is written. A finished file goes onto the upload queue as a path; nothing
//! here holds media in memory beyond the write buffer and, for CMAF, the group
//! being assembled.

use std::collections::{HashSet, VecDeque};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use moqom_client::Object;
use tokio::sync::mpsc;

use crate::archive::{self, Archived, Header};
use crate::catalog::Track;
use crate::crc32c::Crc32c;
use crate::fmp4::{Muxer, Output, Reorder};
use crate::manifest::{Artifact, ArtifactKind, Join, JoinFrom, TrackEntry};

/// Groups remembered for recognising redelivery. A reconnect replays at most
/// the group in flight, so a handful would do; this many covers a relay that
/// replays from its cache after a long gap.
const DEDUPE_GROUPS: usize = 64;

/// Write buffer per open file.
const BUFFER: usize = 256 << 10;

/// Microseconds since the Unix epoch.
#[must_use]
pub fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
        })
}

/// A file ready for the store.
#[derive(Debug)]
pub struct Finished {
    /// Where it is on local disk.
    pub path: PathBuf,
    /// What it is.
    pub artifact: Artifact,
}

/// What a writer needs to know.
#[derive(Clone, Debug)]
pub struct TrackConfig {
    /// The recording.
    pub recording: String,
    /// Which attempt this recorder is.
    pub attempt: u32,
    /// The publisher's full namespace.
    pub namespace: Vec<String>,
    /// The track name.
    pub track: String,
    /// `user/device/track`, which is also where its files go.
    pub relative: String,
    /// The local spool directory.
    pub spool: PathBuf,
    /// Rotate a file at the next group boundary past this many bytes.
    pub segment_bytes: u64,
    /// Whether payloads are ciphertext.
    pub encrypted: bool,
}

struct OpenArchive {
    writer: archive::Writer<BufWriter<File>>,
    path: PathBuf,
    name: String,
    first: Option<u64>,
    last: Option<u64>,
}

struct OpenCmaf {
    file: BufWriter<File>,
    path: PathBuf,
    name: String,
    crc: Crc32c,
    bytes: u64,
    first: Option<u64>,
    last: Option<u64>,
}

/// Which `(group, object)` pairs have been archived recently.
#[derive(Default)]
struct Dedupe {
    groups: VecDeque<(u64, HashSet<u64>)>,
}

impl Dedupe {
    /// Record the pair, returning whether it is new.
    fn insert(&mut self, group: u64, object: u64) -> bool {
        if let Some((_, seen)) = self.groups.iter_mut().find(|(id, _)| *id == group) {
            return seen.insert(object);
        }
        if self.groups.len() == DEDUPE_GROUPS {
            self.groups.pop_front();
        }
        self.groups.push_back((group, HashSet::from([object])));
        true
    }
}

/// One track's files.
pub struct TrackWriter {
    config: TrackConfig,
    finished: mpsc::UnboundedSender<Finished>,
    archive: Option<OpenArchive>,
    segment: u32,
    session: Option<(u32, u64)>,
    muxer: Option<Reorder>,
    cmaf: Option<OpenCmaf>,
    init: Option<Vec<u8>>,
    part: u32,
    cmaf_skipped: Option<String>,
    catalog: Option<Track>,
    dedupe: Dedupe,
    objects: u64,
    duplicates: u64,
    joins: Vec<Join>,
}

impl TrackWriter {
    /// A writer for one track. `track` is its catalog entry, absent for the
    /// catalog track itself; `remux` is whether CMAF may be written at all.
    #[must_use]
    pub fn new(
        config: TrackConfig,
        track: Option<&Track>,
        remux: Result<(), String>,
        finished: mpsc::UnboundedSender<Finished>,
    ) -> Self {
        let (muxer, cmaf_skipped) = match (remux, track) {
            (Err(reason), _) => (None, Some(reason)),
            (Ok(()), None) => (None, None),
            (Ok(()), Some(track)) => match Muxer::for_track(track) {
                Some(muxer) => (Some(Reorder::new(muxer)), None),
                None => (
                    None,
                    Some(format!(
                        "{} cannot be carried in CMAF without transcoding",
                        track.codec
                    )),
                ),
            },
        };
        Self {
            config,
            finished,
            archive: None,
            segment: 0,
            session: None,
            muxer,
            cmaf: None,
            init: None,
            part: 0,
            cmaf_skipped,
            catalog: track.cloned(),
            dedupe: Dedupe::default(),
            objects: 0,
            duplicates: 0,
            joins: Vec::new(),
        }
    }

    /// The track's place, `user/device/track`.
    #[must_use]
    pub fn relative(&self) -> &str {
        &self.config.relative
    }

    /// A new session started feeding this writer.
    ///
    /// # Errors
    /// Writing the marker.
    pub fn session(&mut self, ordinal: u32) -> io::Result<()> {
        let at = now_micros();
        self.session = Some((ordinal, at));
        if let Some(open) = self.archive.as_mut() {
            open.writer.session(ordinal, at)?;
        }
        Ok(())
    }

    /// Say how this session's recording of the track began. See [`Join`].
    pub fn joined(&mut self, from: JoinFrom, at: Option<(u64, u64)>, reason: Option<String>) {
        let session = self.session.map_or(0, |(ordinal, _)| ordinal);
        if let Some(reason) = &reason {
            tracing::info!(track = %self.config.relative, session, ?from, %reason, "the group in flight was not caught up");
        }
        self.joins.push(Join {
            session,
            from,
            group: at.map(|(group, _)| group),
            object: at.map(|(_, object)| object),
            reason,
        });
    }

    /// The catalog restated this track, possibly differently.
    pub fn describe(&mut self, track: &Track) {
        if let Some(muxer) = self.muxer.as_mut() {
            muxer.describe(track);
        }
        self.catalog = Some(track.clone());
    }

    /// Archive one received object, and mux it if this track is muxed.
    ///
    /// Returns whether it was new.
    ///
    /// # Errors
    /// Writing the spool.
    pub fn object(&mut self, object: &Object) -> io::Result<bool> {
        let group = object.group.get();
        if !self.dedupe.insert(group, object.object) {
            self.duplicates += 1;
            return Ok(false);
        }
        let received = now_micros();

        if object.object == 0
            && self
                .archive
                .as_ref()
                .is_some_and(|open| open.writer.bytes() >= self.config.segment_bytes)
        {
            self.close_archive(received)?;
        }
        if self.archive.is_none() {
            self.open_archive(received)?;
        }

        let archived = Archived {
            group,
            object: object.object,
            received_micros: received,
            properties: object.properties.clone(),
            payload: object.payload.clone(),
        };
        if let Some(open) = self.archive.as_mut() {
            open.writer.object(&archived)?;
            open.first.get_or_insert(received);
            open.last = Some(received);
        }
        self.objects += 1;

        let outputs = self
            .muxer
            .as_mut()
            .map(|muxer| muxer.push(&archived))
            .unwrap_or_default();
        for output in outputs {
            self.cmaf_output(output, received)?;
        }
        Ok(true)
    }

    /// The publisher left. The open files are finished; if it comes back, the
    /// next object opens new ones.
    ///
    /// # Errors
    /// Writing or closing the spool.
    pub fn departed(&mut self) -> io::Result<()> {
        let at = now_micros();
        if let Some(open) = self.archive.as_mut() {
            open.writer.departed(at)?;
        }
        self.close(at)
    }

    /// Finish whatever is open.
    ///
    /// # Errors
    /// Closing the spool.
    pub fn close(&mut self, at: u64) -> io::Result<()> {
        self.close_archive(at)?;
        for output in self.muxer.as_mut().map(Reorder::finish).unwrap_or_default() {
            self.cmaf_output(output, at)?;
        }
        self.close_cmaf()
    }

    /// How the manifest describes this track.
    #[must_use]
    pub fn entry(&self) -> TrackEntry {
        TrackEntry {
            track: self.config.relative.clone(),
            kind: self
                .catalog
                .as_ref()
                .map(|track| format!("{:?}", track.kind).to_lowercase()),
            codec: self.catalog.as_ref().map(|track| track.codec.clone()),
            objects: self.objects,
            duplicates: self.duplicates,
            cmaf_skipped: self.cmaf_skipped.clone(),
            joins: self.joins.clone(),
        }
    }

    fn open_archive(&mut self, at: u64) -> io::Result<()> {
        let name = format!(
            "{}/a{}-s{:05}.mqa",
            self.config.relative, self.config.attempt, self.segment
        );
        self.segment += 1;
        let path = self.config.spool.join(&name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut header = Header::new(
            &self.config.recording,
            self.config.namespace.clone(),
            &self.config.track,
        );
        header.attempt = self.config.attempt;
        header.segment = self.segment - 1;
        header.encrypted = self.config.encrypted;
        header.opened_micros = at;
        let file = BufWriter::with_capacity(BUFFER, File::create(&path)?);
        let mut writer = archive::Writer::create(file, &header)?;
        if let Some((ordinal, at)) = self.session {
            writer.session(ordinal, at)?;
        }
        self.archive = Some(OpenArchive {
            writer,
            path,
            name,
            first: None,
            last: None,
        });
        Ok(())
    }

    fn close_archive(&mut self, at: u64) -> io::Result<()> {
        let Some(open) = self.archive.take() else {
            return Ok(());
        };
        let finished = open.writer.finish(at)?;
        let file = finished
            .inner
            .into_inner()
            .map_err(io::IntoInnerError::into_error)?;
        file.sync_all()?;
        self.ship(
            open.path,
            open.name,
            ArtifactKind::Archive,
            finished.bytes,
            finished.crc32c,
            open.first,
            open.last,
        );
        Ok(())
    }

    fn cmaf_output(&mut self, output: Output, at: u64) -> io::Result<()> {
        match output {
            Output::Init(init) => {
                self.close_cmaf()?;
                self.open_cmaf(&init)?;
                self.init = Some(init);
            }
            Output::Fragment(fragment) => {
                if self
                    .cmaf
                    .as_ref()
                    .is_some_and(|open| open.bytes >= self.config.segment_bytes)
                {
                    self.close_cmaf()?;
                }
                if self.cmaf.is_none() {
                    let Some(init) = self.init.clone() else {
                        return Ok(());
                    };
                    self.open_cmaf(&init)?;
                }
                if let Some(open) = self.cmaf.as_mut() {
                    open.file.write_all(&fragment)?;
                    open.crc.update(&fragment);
                    open.bytes += fragment.len() as u64;
                    open.first.get_or_insert(at);
                    open.last = Some(at);
                }
            }
        }
        Ok(())
    }

    fn open_cmaf(&mut self, init: &[u8]) -> io::Result<()> {
        let rendition = self.muxer.as_ref().map_or(0, Reorder::renditions);
        let name = format!(
            "{}/a{}-r{}-p{:05}.mp4",
            self.config.relative, self.config.attempt, rendition, self.part
        );
        self.part += 1;
        let path = self.config.spool.join(&name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = BufWriter::with_capacity(BUFFER, File::create(&path)?);
        file.write_all(init)?;
        let mut crc = Crc32c::new();
        crc.update(init);
        self.cmaf = Some(OpenCmaf {
            file,
            path,
            name,
            crc,
            bytes: init.len() as u64,
            first: None,
            last: None,
        });
        Ok(())
    }

    fn close_cmaf(&mut self) -> io::Result<()> {
        let Some(open) = self.cmaf.take() else {
            return Ok(());
        };
        let file = open
            .file
            .into_inner()
            .map_err(io::IntoInnerError::into_error)?;
        file.sync_all()?;
        self.ship(
            open.path,
            open.name,
            ArtifactKind::Cmaf,
            open.bytes,
            open.crc.value(),
            open.first,
            open.last,
        );
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn ship(
        &self,
        path: PathBuf,
        name: String,
        kind: ArtifactKind,
        bytes: u64,
        crc32c: u32,
        first: Option<u64>,
        last: Option<u64>,
    ) {
        // The receiver is gone only once the recorder has stopped uploading,
        // and then the file stays in the spool, which is where a rerun finds it.
        let _ = self.finished.send(Finished {
            path,
            artifact: Artifact {
                name,
                kind,
                track: self.config.relative.clone(),
                bytes,
                crc32c,
                first_micros: first,
                last_micros: last,
            },
        });
    }
}

/// A path component that cannot climb out of, or split, the recording's prefix.
#[must_use]
pub fn component(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let cleaned: String = text
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    match cleaned.as_str() {
        "" => "_".to_owned(),
        "." | ".." => cleaned.replace('.', "_"),
        _ => cleaned,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use moqom_client::{GroupId, ObjectProperties};

    fn config(spool: &std::path::Path, segment_bytes: u64) -> TrackConfig {
        TrackConfig {
            recording: "rec_1".into(),
            attempt: 2,
            namespace: vec![
                "acme".into(),
                "r".into(),
                "standup".into(),
                "ada".into(),
                "phone".into(),
            ],
            track: "video".into(),
            relative: "ada/phone/video".into(),
            spool: spool.to_path_buf(),
            segment_bytes,
            encrypted: true,
        }
    }

    fn object(group: u32, object: u64, payload: &'static [u8]) -> Object {
        Object {
            group: GroupId::from(group),
            object,
            payload: Bytes::from_static(payload),
            properties: ObjectProperties::default(),
        }
    }

    fn spool(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("moqom-recorder-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        path
    }

    #[test]
    fn redelivery_is_archived_once_and_a_reconnect_is_marked() {
        let dir = spool("dedupe");
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut writer =
            TrackWriter::new(config(&dir, u64::MAX), None, Err("encrypted".into()), tx);
        writer.session(1).unwrap();
        assert!(writer.object(&object(5, 0, b"key")).unwrap());
        assert!(writer.object(&object(5, 1, b"delta")).unwrap());
        writer.session(2).unwrap();
        assert!(
            !writer.object(&object(5, 1, b"delta")).unwrap(),
            "the replayed object is skipped"
        );
        assert!(writer.object(&object(5, 2, b"delta")).unwrap());
        writer.close(now_micros()).unwrap();

        let finished = rx.try_recv().unwrap();
        assert_eq!(finished.artifact.name, "ada/phone/video/a2-s00000.mqa");
        assert_eq!(finished.artifact.kind, ArtifactKind::Archive);
        let bytes = std::fs::read(&finished.path).unwrap();
        assert_eq!(crate::crc32c::checksum(&bytes), finished.artifact.crc32c);

        let mut reader = archive::Reader::open(bytes.as_slice()).unwrap();
        assert!(reader.header().encrypted);
        assert_eq!(reader.header().attempt, 2);
        let mut kinds = Vec::new();
        while let Some(record) = reader.next_record().unwrap() {
            kinds.push(match record {
                archive::Record::Object(object) => format!("o{}.{}", object.group, object.object),
                archive::Record::Session { ordinal, .. } => format!("s{ordinal}"),
                archive::Record::Departed { .. } => "d".into(),
                archive::Record::End { objects, .. } => format!("end{objects}"),
            });
        }
        assert_eq!(kinds, ["s1", "o5.0", "o5.1", "s2", "o5.2", "end3"]);
        assert_eq!(writer.entry().duplicates, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn files_rotate_at_a_group_boundary() {
        let dir = spool("rotate");
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut writer = TrackWriter::new(config(&dir, 1), None, Ok(()), tx);
        writer.object(&object(1, 0, b"a")).unwrap();
        writer.object(&object(1, 1, b"b")).unwrap();
        assert!(rx.try_recv().is_err(), "not mid-group");
        writer.object(&object(2, 0, b"c")).unwrap();
        assert_eq!(
            rx.try_recv().unwrap().artifact.name,
            "ada/phone/video/a2-s00000.mqa"
        );
        writer.departed().unwrap();
        assert_eq!(
            rx.try_recv().unwrap().artifact.name,
            "ada/phone/video/a2-s00001.mqa"
        );
        writer.object(&object(3, 0, b"d")).unwrap();
        writer.close(now_micros()).unwrap();
        assert_eq!(
            rx.try_recv().unwrap().artifact.name,
            "ada/phone/video/a2-s00002.mqa"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn components_stay_inside_the_prefix() {
        assert_eq!(component(b".."), "__");
        assert_eq!(component(b"a/b"), "a_b");
        assert_eq!(component(b""), "_");
        assert_eq!(component(b"720p.hevc"), "720p.hevc");
    }
}
