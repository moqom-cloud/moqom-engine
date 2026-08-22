//! A real coded video, read once and published on a loop.
//!
//! Synthetic frames measure a relay against traffic no encoder produces. Every
//! frame the same size means every group the same shape, a constant number of
//! chunks per read, and a queue that never has to absorb anything. Real video is
//! lumpy in exactly the places that cost a relay something: a keyframe is often
//! twenty times the size of the frames after it, so it arrives as a burst of
//! chunks that has to be copied to every subscriber at once, and group boundaries
//! fall where the encoder put them rather than on a round count.
//!
//! Deliberately deterministic. Both roles read the same file, so a subscriber can
//! still say precisely what it missed without a channel back to the publisher --
//! which is the property that lets the two run on different machines. What is
//! shared is the file, not a message.

use std::path::Path;

use moqom_media::annexb::{AccessUnit, Codec, access_units};

/// A parsed clip, ready to publish repeatedly.
pub struct Film {
    /// Frames in encoder order, beginning at the first keyframe.
    units: Vec<AccessUnit>,
    /// How many frames each group holds, in order.
    gops: Vec<u64>,
    /// Total payload bytes of one pass, for reporting the bitrate.
    bytes: u64,
}

impl Film {
    /// Read and parse a clip.
    ///
    /// Frames before the first keyframe are discarded rather than published.
    /// Nothing can decode them -- they refer backwards to pictures that are not
    /// in the file -- and keeping them would put a partial group at group zero,
    /// which is the one group a subscriber cannot tell from a late join.
    pub fn load(path: &Path, codec: Codec) -> Result<Self, String> {
        let stream = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let all = access_units(&stream, codec);
        if all.is_empty() {
            return Err(format!(
                "{}: no access units; is it an Annex B elementary stream, and the right codec?",
                path.display()
            ));
        }

        let Some(first) = all.iter().position(|unit| unit.is_keyframe) else {
            return Err(format!(
                "{}: no keyframe, so nothing a subscriber could join on",
                path.display()
            ));
        };
        let units: Vec<AccessUnit> = all.into_iter().skip(first).collect();

        let mut gops: Vec<u64> = Vec::new();
        let mut bytes = 0_u64;
        for unit in &units {
            if unit.is_keyframe {
                gops.push(0);
            }
            if let Some(current) = gops.last_mut() {
                *current = current.saturating_add(1);
            }
            bytes = bytes.saturating_add(unit.payload.len() as u64);
        }

        Ok(Self { units, gops, bytes })
    }

    /// The frames, in order, beginning at a keyframe.
    pub fn units(&self) -> &[AccessUnit] {
        &self.units
    }

    /// How many groups one pass through the clip publishes.
    pub fn groups(&self) -> usize {
        self.gops.len()
    }

    /// How many frames each group holds, in order.
    ///
    /// Group N of a run is group `N % groups()` of the clip, because publishing
    /// loops the file to fill a run longer than it. That is what makes an exact
    /// expectation available to a subscriber that only has the same file.
    pub fn gops(&self) -> &[u64] {
        &self.gops
    }

    /// What one pass would take at a given frame rate, in seconds.
    ///
    /// Counts become `f64` only to be reported. An `f64` is exact to 2^53, which
    /// is more frames than any clip anyone would drive a load test with.
    #[allow(clippy::cast_precision_loss)]
    pub fn seconds(&self, fps: f64) -> f64 {
        if fps <= 0.0 {
            return 0.0;
        }
        self.units.len() as f64 / fps
    }

    /// Bits per second this clip represents at a given frame rate.
    ///
    /// Reported rather than assumed, because the frame rate is the operator's
    /// claim about a file that carries no timing of its own: an elementary stream
    /// says what the pictures are and nothing about when to show them. A figure
    /// well away from the clip's real bitrate is the sign that `--fps` is wrong.
    #[allow(clippy::cast_precision_loss)]
    pub fn bits_per_second(&self, fps: f64) -> f64 {
        let seconds = self.seconds(fps);
        if seconds <= 0.0 {
            return 0.0;
        }
        self.bytes.saturating_mul(8) as f64 / seconds
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    /// An H.264 slice NAL that begins a picture.
    ///
    /// `first_mb_in_slice` is zero, which exp-Golomb encodes as a single set bit,
    /// so the byte after the header has its top bit set. That is the bit the
    /// parser reads to decide a picture starts here.
    fn slice(keyframe: bool) -> Vec<u8> {
        let header = if keyframe { 0x65 } else { 0x41 };
        vec![0, 0, 0, 1, header, 0x88, 0x84, 0x21]
    }

    fn parameter_sets() -> Vec<u8> {
        let mut bytes = vec![0, 0, 0, 1, 0x67, 0x42, 0xC0, 0x28];
        bytes.extend_from_slice(&[0, 0, 0, 1, 0x68, 0xCE, 0x3C, 0x80]);
        bytes
    }

    /// Write a stream to a file, since `Film` reads a path.
    ///
    /// Numbered as well as named for the process, because these tests run as
    /// threads of one binary and a shared path would have them overwrite each
    /// other's clip.
    fn film_of(stream: &[u8]) -> Result<Film, String> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let ordinal = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "moqom-load-film-{}-{ordinal}.h264",
            std::process::id()
        ));
        let mut file = std::fs::File::create(&path).expect("a temporary file");
        file.write_all(stream).expect("writing the stream");
        let film = Film::load(&path, Codec::H264);
        let _ = std::fs::remove_file(&path);
        film
    }

    #[test]
    fn a_group_is_a_keyframe_and_the_frames_that_depend_on_it() {
        let mut stream = parameter_sets();
        for gop in [3, 2] {
            stream.extend_from_slice(&slice(true));
            for _ in 1..gop {
                stream.extend_from_slice(&slice(false));
            }
        }
        let film = film_of(&stream).expect("a readable clip");
        assert_eq!(film.gops(), [3, 2], "groups run keyframe to keyframe");
        assert_eq!(film.units().len(), 5);
        assert_eq!(film.groups(), 2);
    }

    /// Frames before the first keyframe refer backwards to pictures that are not
    /// in the file, so publishing them would put an undecodable partial group at
    /// group zero -- the one group a subscriber cannot tell from a late join.
    #[test]
    fn frames_before_the_first_keyframe_are_not_published() {
        let mut stream = parameter_sets();
        stream.extend_from_slice(&slice(false));
        stream.extend_from_slice(&slice(false));
        stream.extend_from_slice(&slice(true));
        stream.extend_from_slice(&slice(false));

        let film = film_of(&stream).expect("a readable clip");
        assert_eq!(film.units().len(), 2, "the clip starts at the keyframe");
        assert!(film.units()[0].is_keyframe);
        assert_eq!(film.gops(), [2]);
    }

    #[test]
    fn a_clip_with_nothing_to_join_on_is_refused() {
        let mut stream = parameter_sets();
        stream.extend_from_slice(&slice(false));
        // Matched rather than unwrapped: a `Film` holds a whole clip, and
        // `expect_err` would want to print one.
        let Err(refused) = film_of(&stream) else {
            panic!("a clip with no keyframe should be refused");
        };
        assert!(refused.contains("keyframe"), "{refused}");

        let Err(empty) = film_of(&[]) else {
            panic!("an empty file should be refused");
        };
        assert!(empty.contains("no access units"), "{empty}");
    }

    /// The frame rate is the operator's claim about a file that carries no timing,
    /// so the reported bitrate is what tells them the claim was wrong.
    #[test]
    fn the_bitrate_follows_the_frame_rate_it_is_played_at() {
        let mut stream = parameter_sets();
        for _ in 0..10 {
            stream.extend_from_slice(&slice(true));
        }
        let film = film_of(&stream).expect("a readable clip");
        assert!((film.seconds(10.0) - 1.0).abs() < f64::EPSILON);
        let fast = film.bits_per_second(20.0);
        let slow = film.bits_per_second(10.0);
        assert!(
            (fast - slow * 2.0).abs() < 1.0,
            "twice the rate is twice the bitrate: {fast} against {slow}"
        );
        assert!(film.bits_per_second(0.0).abs() < f64::EPSILON);
    }
}
