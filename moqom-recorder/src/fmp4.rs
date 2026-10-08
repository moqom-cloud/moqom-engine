//! CMAF (fragmented MP4) from a track's objects, without transcoding.
//!
//! Possible only because of how MOQOM frames media, which is already the shape
//! an MP4 sample has (see `moqom-media`):
//!
//! * video objects are one access unit each, as four-byte length-prefixed NAL
//!   units with the parameter sets kept out -- byte for byte an `avc1`/`hvc1`
//!   sample;
//! * the parameter sets travel as the `configuration` property on the object
//!   that opens each group, which is what an `avcC`/`hvcC` is built from;
//! * Opus objects are one packet each, which is an `Opus` sample;
//! * every object carries its capture time, which becomes its decode time.
//!
//! Anything else is not muxed and stays in the archive only: PCM, data tracks,
//! codecs this does not know, and every track whose payloads are ciphertext.
//!
//! One fragment per group for video, so every fragment starts on a keyframe and
//! a player can seek to any of them; audio is cut about once a second. Objects
//! after a gap in a group are dropped until the next keyframe, because a frame
//! whose reference never arrived decodes to garbage rather than to nothing.
//! A change of parameter sets mid-track -- a publisher changing geometry --
//! starts a new rendition with its own initialisation segment, since one `stsd`
//! cannot describe both.

use bytes::Bytes;

use crate::archive::Archived;
use crate::catalog::{self, Kind, Track};

/// Pending sample bytes above which a fragment is cut early. A GOP is normally
/// a few megabytes; this bounds what one pathological group can hold.
const MAX_PENDING_BYTES: usize = 32 << 20;

/// Audio fragment length, in microseconds.
const AUDIO_FRAGMENT_MICROS: u64 = 1_000_000;

/// Which codec, and what its sample entry needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Codec {
    /// H.264, `avc1` with `avcC`.
    H264,
    /// HEVC, `hvc1` with `hvcC`.
    Hevc,
    /// Opus, `Opus` with `dOps`.
    Opus,
}

impl Codec {
    /// The codec a catalog track names, if it can be remuxed.
    #[must_use]
    pub fn of(track: &Track) -> Option<Self> {
        let codec = track.codec.to_ascii_lowercase();
        let name = codec.rsplit('/').next().unwrap_or(&codec);
        match (track.kind, name) {
            (Kind::Video | Kind::Screen, "h264" | "avc" | "avc1") => Some(Self::H264),
            (Kind::Video | Kind::Screen, "hevc" | "h265" | "hvc1" | "hev1") => Some(Self::Hevc),
            (Kind::Audio, "opus") => Some(Self::Opus),
            _ => None,
        }
    }

    const fn is_video(self) -> bool {
        matches!(self, Self::H264 | Self::Hevc)
    }

    const fn timescale(self) -> u32 {
        match self {
            Self::H264 | Self::Hevc => 90_000,
            Self::Opus => 48_000,
        }
    }
}

/// What the muxer produced from one object.
#[derive(Debug, PartialEq, Eq)]
pub enum Output {
    /// An initialisation segment. Starts a rendition: every fragment until the
    /// next one belongs with it.
    Init(Vec<u8>),
    /// A `moof` and its `mdat`.
    Fragment(Vec<u8>),
}

struct Sample {
    payload: Bytes,
    micros: u64,
    sync: bool,
}

/// Turns one track's objects into CMAF.
pub struct Muxer {
    codec: Codec,
    width: u32,
    height: u32,
    channels: u32,
    sample_rate: u32,
    default_micros: u64,
    /// The configuration the current rendition was initialised with.
    configuration: Option<Bytes>,
    /// From the catalog, until a keyframe brings its own.
    catalog_configuration: Option<Bytes>,
    pending: Vec<Sample>,
    pending_bytes: usize,
    sequence: u32,
    origin: Option<u64>,
    last_micros: Option<u64>,
    group: Option<u64>,
    next_object: u64,
    waiting_for_keyframe: bool,
    renditions: u32,
}

impl Muxer {
    /// A muxer for `track`, or `None` if its codec cannot be remuxed.
    #[must_use]
    pub fn for_track(track: &Track) -> Option<Self> {
        let codec = Codec::of(track)?;
        let default_micros = match codec {
            Codec::Opus => 20_000,
            _ => track
                .frame_rate
                .filter(|rate| *rate >= 1.0)
                // Positive and at most a million, by the filter.
                .map_or(33_333, |rate| {
                    #[allow(clippy::cast_sign_loss)]
                    let micros = (1_000_000.0 / rate) as u64;
                    micros
                }),
        };
        Some(Self {
            codec,
            width: track.width.unwrap_or(0),
            height: track.height.unwrap_or(0),
            channels: track.channels.unwrap_or(1).max(1),
            sample_rate: track.sample_rate.unwrap_or(48_000),
            default_micros,
            configuration: None,
            catalog_configuration: track
                .decoder_configuration
                .as_deref()
                .and_then(catalog::unhex)
                .map(Bytes::from),
            pending: Vec::new(),
            pending_bytes: 0,
            sequence: 0,
            origin: None,
            last_micros: None,
            group: None,
            next_object: 0,
            waiting_for_keyframe: true,
            renditions: 0,
        })
    }

    /// The codec being written.
    #[must_use]
    pub const fn codec(&self) -> Codec {
        self.codec
    }

    /// Renditions started so far.
    #[must_use]
    pub const fn renditions(&self) -> u32 {
        self.renditions
    }

    /// Take the catalog's newer description, such as a changed geometry.
    pub fn describe(&mut self, track: &Track) {
        if let Some(width) = track.width {
            self.width = width;
        }
        if let Some(height) = track.height {
            self.height = height;
        }
        if let Some(configuration) = track
            .decoder_configuration
            .as_deref()
            .and_then(catalog::unhex)
        {
            self.catalog_configuration = Some(Bytes::from(configuration));
        }
    }

    /// Feed one object, in order. See [`Reorder`] for objects as they arrive.
    pub fn push(&mut self, object: &Archived) -> Vec<Output> {
        let mut out = Vec::new();
        if self.group.is_some_and(|current| object.group < current) {
            // Decode time only moves forward, so a group that arrives after a
            // later one has started cannot be placed. The archive has it.
            return out;
        }
        let new_group = self.group != Some(object.group);
        let in_order = !new_group && object.object == self.next_object;
        let opens_group = object.object == 0;

        if self.codec.is_video() {
            if new_group || !in_order {
                // A group is a GOP, so its end is a fragment boundary; an
                // object out of sequence is a gap, and nothing after it can be
                // decoded until the next keyframe.
                self.flush(&mut out, object.properties.capture_time_micros);
                self.waiting_for_keyframe = !opens_group;
            }
            if self.waiting_for_keyframe {
                self.group = Some(object.group);
                self.next_object = object.object + 1;
                return out;
            }
        } else if new_group
            && !self.pending.is_empty()
            && self.pending_span() >= AUDIO_FRAGMENT_MICROS
        {
            self.flush(&mut out, object.properties.capture_time_micros);
        }
        self.group = Some(object.group);
        self.next_object = object.object + 1;

        let sync = !self.codec.is_video() || opens_group;
        if sync && self.codec.is_video() {
            let configuration = object
                .properties
                .configuration
                .clone()
                .or_else(|| self.configuration.clone())
                .or_else(|| self.catalog_configuration.clone());
            let Some(configuration) = configuration else {
                // A keyframe with nothing to configure a decoder from. Wait
                // for one that says.
                self.waiting_for_keyframe = true;
                return out;
            };
            if self.configuration.as_ref() != Some(&configuration) {
                let Some(init) = self.init(&configuration) else {
                    self.waiting_for_keyframe = true;
                    return out;
                };
                self.flush(&mut out, None);
                self.configuration = Some(configuration);
                self.renditions += 1;
                out.push(Output::Init(init));
            }
        } else if self.configuration.is_none() && !self.codec.is_video() {
            let configuration = self.catalog_configuration.clone().unwrap_or_default();
            let Some(init) = self.init(&configuration) else {
                return out;
            };
            self.configuration = Some(configuration);
            self.renditions += 1;
            out.push(Output::Init(init));
        }

        let micros = self.time_of(object);
        if self.pending_bytes + object.payload.len() > MAX_PENDING_BYTES {
            self.flush(&mut out, Some(micros));
        }
        self.pending_bytes += object.payload.len();
        self.pending.push(Sample {
            payload: object.payload.clone(),
            micros,
            sync,
        });
        out
    }

    /// Emit whatever is pending. The last sample's duration is the one before
    /// it, there being no next sample to measure against.
    pub fn finish(&mut self) -> Option<Output> {
        let mut out = Vec::new();
        self.flush(&mut out, None);
        out.pop()
    }

    fn pending_span(&self) -> u64 {
        match (self.pending.first(), self.pending.last()) {
            (Some(first), Some(last)) => last.micros.saturating_sub(first.micros),
            _ => 0,
        }
    }

    fn time_of(&mut self, object: &Archived) -> u64 {
        let micros = match (object.properties.capture_time_micros, self.last_micros) {
            // Monotonic, because a decode time that goes backwards is refused by
            // every player. Capture times are presentation times and MOQOM
            // publishers do not reorder frames, so this only bites a publisher
            // whose clock stepped.
            (Some(captured), Some(last)) => captured.max(last + 1),
            (Some(captured), None) => captured,
            (None, Some(last)) => last + self.default_micros,
            (None, None) => object.received_micros,
        };
        self.origin.get_or_insert(micros);
        self.last_micros = Some(micros);
        micros
    }

    fn ticks(&self, micros: u64) -> u64 {
        let since = micros.saturating_sub(self.origin.unwrap_or(micros));
        (u128::from(since) * u128::from(self.codec.timescale()) / 1_000_000) as u64
    }

    fn flush(&mut self, out: &mut Vec<Output>, next_micros: Option<u64>) {
        if self.pending.is_empty() {
            return;
        }
        let samples = std::mem::take(&mut self.pending);
        self.pending_bytes = 0;
        self.sequence += 1;

        let times: Vec<u64> = samples.iter().map(|s| self.ticks(s.micros)).collect();
        let fallback = self
            .ticks(self.origin.unwrap_or(0) + self.default_micros)
            .max(1);
        let mut durations = Vec::with_capacity(samples.len());
        for index in 0..samples.len() {
            let next = times
                .get(index + 1)
                .copied()
                .or_else(|| next_micros.map(|micros| self.ticks(micros)));
            let duration = match next {
                Some(next) => next.saturating_sub(times[index]),
                None if index > 0 => times[index] - times[index - 1],
                None => fallback,
            };
            durations.push(u32::try_from(duration.max(1)).unwrap_or(u32::MAX));
        }
        out.push(Output::Fragment(fragment(
            self.sequence,
            times[0],
            &samples,
            &durations,
        )));
    }

    fn init(&self, configuration: &[u8]) -> Option<Vec<u8>> {
        let entry = match self.codec {
            Codec::H264 => avc_entry(configuration, self.width, self.height)?,
            Codec::Hevc => hevc_entry(configuration, self.width, self.height)?,
            Codec::Opus => opus_entry(configuration, self.channels, self.sample_rate),
        };
        Some(init_segment(self.codec, self.width, self.height, &entry))
    }
}

// --- Boxes ------------------------------------------------------------------

fn mp4_box(out: &mut Vec<u8>, kind: [u8; 4], content: impl FnOnce(&mut Vec<u8>)) {
    let start = out.len();
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&kind);
    content(out);
    let size = u32::try_from(out.len() - start).unwrap_or(u32::MAX);
    out[start..start + 4].copy_from_slice(&size.to_be_bytes());
}

fn full_box(
    out: &mut Vec<u8>,
    kind: [u8; 4],
    version: u8,
    flags: u32,
    content: impl FnOnce(&mut Vec<u8>),
) {
    mp4_box(out, kind, |out| {
        out.push(version);
        out.extend_from_slice(&flags.to_be_bytes()[1..]);
        content(out);
    });
}

fn u16be(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn u32be(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// Groups held back for reordering.
///
/// Each group travels on its own QUIC stream, so the start of one and the end
/// of the one before routinely arrive interleaved. Holding a few groups and
/// releasing the oldest whole puts them back in order at a cost of a few
/// seconds of delay, which a recording does not mind.
const REORDER_GROUPS: usize = 3;

/// Held bytes above which the oldest group is released early, so a stalled
/// stream cannot make this hold a track's whole output.
const REORDER_BYTES: usize = 64 << 20;

/// A [`Muxer`] fed in `(group, object)` order, whatever order objects arrive in.
pub struct Reorder {
    muxer: Muxer,
    held: std::collections::BTreeMap<u64, std::collections::BTreeMap<u64, Archived>>,
    bytes: usize,
}

impl Reorder {
    /// Reordering in front of `muxer`.
    #[must_use]
    pub const fn new(muxer: Muxer) -> Self {
        Self {
            muxer,
            held: std::collections::BTreeMap::new(),
            bytes: 0,
        }
    }

    /// Renditions started so far.
    #[must_use]
    pub const fn renditions(&self) -> u32 {
        self.muxer.renditions()
    }

    /// Take the catalog's newer description.
    pub fn describe(&mut self, track: &Track) {
        self.muxer.describe(track);
    }

    /// Feed one object as it arrived.
    pub fn push(&mut self, object: &Archived) -> Vec<Output> {
        self.bytes += object.payload.len();
        self.held
            .entry(object.group)
            .or_default()
            .insert(object.object, object.clone());
        let mut out = Vec::new();
        while self.held.len() > REORDER_GROUPS
            || (self.bytes > REORDER_BYTES && !self.held.is_empty())
        {
            self.release(&mut out);
        }
        out
    }

    /// Release everything held and close the last fragment.
    pub fn finish(&mut self) -> Vec<Output> {
        let mut out = Vec::new();
        while !self.held.is_empty() {
            self.release(&mut out);
        }
        out.extend(self.muxer.finish());
        out
    }

    fn release(&mut self, out: &mut Vec<Output>) {
        if let Some((_, objects)) = self.held.pop_first() {
            for object in objects.into_values() {
                self.bytes -= object.payload.len();
                out.extend(self.muxer.push(&object));
            }
        }
    }
}

const MATRIX: [u32; 9] = [0x0001_0000, 0, 0, 0, 0x0001_0000, 0, 0, 0, 0x4000_0000];

fn init_segment(codec: Codec, width: u32, height: u32, entry: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    mp4_box(&mut out, *b"ftyp", |out| {
        out.extend_from_slice(b"cmfc");
        u32be(out, 0);
        for brand in [b"cmfc", b"iso6", b"mp41"] {
            out.extend_from_slice(brand);
        }
    });
    mp4_box(&mut out, *b"moov", |out| {
        full_box(out, *b"mvhd", 0, 0, |out| {
            u32be(out, 0);
            u32be(out, 0);
            u32be(out, 1000);
            u32be(out, 0);
            u32be(out, 0x0001_0000);
            u16be(out, 0x0100);
            out.extend_from_slice(&[0; 10]);
            for value in MATRIX {
                u32be(out, value);
            }
            out.extend_from_slice(&[0; 24]);
            u32be(out, 2);
        });
        mp4_box(out, *b"trak", |out| {
            full_box(out, *b"tkhd", 0, 0x3, |out| {
                u32be(out, 0);
                u32be(out, 0);
                u32be(out, 1);
                u32be(out, 0);
                u32be(out, 0);
                out.extend_from_slice(&[0; 8]);
                u16be(out, 0);
                u16be(out, 0);
                u16be(out, if codec.is_video() { 0 } else { 0x0100 });
                u16be(out, 0);
                for value in MATRIX {
                    u32be(out, value);
                }
                u32be(out, if codec.is_video() { width << 16 } else { 0 });
                u32be(out, if codec.is_video() { height << 16 } else { 0 });
            });
            mp4_box(out, *b"mdia", |out| {
                full_box(out, *b"mdhd", 0, 0, |out| {
                    u32be(out, 0);
                    u32be(out, 0);
                    u32be(out, codec.timescale());
                    u32be(out, 0);
                    u16be(out, 0x55C4);
                    u16be(out, 0);
                });
                full_box(out, *b"hdlr", 0, 0, |out| {
                    u32be(out, 0);
                    out.extend_from_slice(if codec.is_video() { b"vide" } else { b"soun" });
                    out.extend_from_slice(&[0; 12]);
                    out.extend_from_slice(b"moqom\0");
                });
                mp4_box(out, *b"minf", |out| {
                    if codec.is_video() {
                        full_box(out, *b"vmhd", 0, 1, |out| out.extend_from_slice(&[0; 8]));
                    } else {
                        full_box(out, *b"smhd", 0, 0, |out| out.extend_from_slice(&[0; 4]));
                    }
                    mp4_box(out, *b"dinf", |out| {
                        full_box(out, *b"dref", 0, 0, |out| {
                            u32be(out, 1);
                            full_box(out, *b"url ", 0, 1, |_| {});
                        });
                    });
                    mp4_box(out, *b"stbl", |out| {
                        full_box(out, *b"stsd", 0, 0, |out| {
                            u32be(out, 1);
                            out.extend_from_slice(entry);
                        });
                        for kind in [*b"stts", *b"stsc", *b"stco"] {
                            full_box(out, kind, 0, 0, |out| u32be(out, 0));
                        }
                        full_box(out, *b"stsz", 0, 0, |out| {
                            u32be(out, 0);
                            u32be(out, 0);
                        });
                    });
                });
            });
        });
        mp4_box(out, *b"mvex", |out| {
            full_box(out, *b"trex", 0, 0, |out| {
                u32be(out, 1);
                u32be(out, 1);
                u32be(out, 0);
                u32be(out, 0);
                u32be(out, 0);
            });
        });
    });
    out
}

const SYNC: u32 = 0x0200_0000;
const NON_SYNC: u32 = 0x0101_0000;

fn fragment(sequence: u32, decode_time: u64, samples: &[Sample], durations: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut offset_at = 0;
    mp4_box(&mut out, *b"moof", |out| {
        full_box(out, *b"mfhd", 0, 0, |out| u32be(out, sequence));
        mp4_box(out, *b"traf", |out| {
            // default-base-is-moof, so data offsets are relative to this moof.
            full_box(out, *b"tfhd", 0, 0x02_0000, |out| u32be(out, 1));
            full_box(out, *b"tfdt", 1, 0, |out| {
                out.extend_from_slice(&decode_time.to_be_bytes());
            });
            // data-offset, sample duration, size and flags present.
            full_box(out, *b"trun", 0, 0x0701, |out| {
                u32be(out, u32::try_from(samples.len()).unwrap_or(u32::MAX));
                offset_at = out.len();
                u32be(out, 0);
                for (sample, duration) in samples.iter().zip(durations) {
                    u32be(out, *duration);
                    u32be(out, u32::try_from(sample.payload.len()).unwrap_or(u32::MAX));
                    u32be(out, if sample.sync { SYNC } else { NON_SYNC });
                }
            });
        });
    });
    let data_offset = u32::try_from(out.len() + 8).unwrap_or(u32::MAX);
    out[offset_at..offset_at + 4].copy_from_slice(&data_offset.to_be_bytes());
    let mdat_len: usize = samples.iter().map(|s| s.payload.len()).sum();
    out.reserve(mdat_len + 8);
    u32be(&mut out, u32::try_from(mdat_len + 8).unwrap_or(u32::MAX));
    out.extend_from_slice(b"mdat");
    for sample in samples {
        out.extend_from_slice(&sample.payload);
    }
    out
}

fn visual_entry(
    kind: [u8; 4],
    width: u32,
    height: u32,
    config_kind: [u8; 4],
    config: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    mp4_box(&mut out, kind, |out| {
        out.extend_from_slice(&[0; 6]);
        u16be(out, 1);
        out.extend_from_slice(&[0; 16]);
        u16be(out, u16::try_from(width).unwrap_or(u16::MAX));
        u16be(out, u16::try_from(height).unwrap_or(u16::MAX));
        u32be(out, 0x0048_0000);
        u32be(out, 0x0048_0000);
        u32be(out, 0);
        u16be(out, 1);
        out.extend_from_slice(&[0; 32]);
        u16be(out, 0x0018);
        u16be(out, 0xFFFF);
        mp4_box(out, config_kind, |out| out.extend_from_slice(config));
    });
    out
}

/// Split a length-prefixed parameter-set buffer, as the `configuration`
/// property and the catalog both carry it.
#[must_use]
pub fn parameter_sets(buffer: &[u8]) -> Option<Vec<&[u8]>> {
    let mut sets = Vec::new();
    let mut rest = buffer;
    while !rest.is_empty() {
        let (len, tail) = rest.split_first_chunk::<4>()?;
        let len = u32::from_be_bytes(*len) as usize;
        if len == 0 || tail.len() < len {
            return None;
        }
        sets.push(&tail[..len]);
        rest = &tail[len..];
    }
    Some(sets)
}

fn push_sets(out: &mut Vec<u8>, sets: &[&[u8]]) {
    for set in sets {
        u16be(out, u16::try_from(set.len()).unwrap_or(u16::MAX));
        out.extend_from_slice(set);
    }
}

fn avc_entry(configuration: &[u8], width: u32, height: u32) -> Option<Vec<u8>> {
    let sets = parameter_sets(configuration)?;
    let sps: Vec<&[u8]> = sets.iter().copied().filter(|s| s[0] & 0x1F == 7).collect();
    let pps: Vec<&[u8]> = sets.iter().copied().filter(|s| s[0] & 0x1F == 8).collect();
    let first = sps.first().filter(|s| s.len() >= 4)?;
    if pps.is_empty() {
        return None;
    }
    let mut avcc = vec![1, first[1], first[2], first[3], 0xFF];
    avcc.push(0xE0 | u8::try_from(sps.len()).ok()?.min(31));
    push_sets(&mut avcc, &sps);
    avcc.push(u8::try_from(pps.len()).ok()?);
    push_sets(&mut avcc, &pps);
    Some(visual_entry(*b"avc1", width, height, *b"avcC", &avcc))
}

/// Remove emulation-prevention bytes, which sit inside the profile fields an
/// `hvcC` copies.
fn unescape(nal: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nal.len());
    let mut zeros = 0;
    for &byte in nal {
        if zeros >= 2 && byte == 3 {
            zeros = 0;
            continue;
        }
        zeros = if byte == 0 { zeros + 1 } else { 0 };
        out.push(byte);
    }
    out
}

fn hevc_entry(configuration: &[u8], width: u32, height: u32) -> Option<Vec<u8>> {
    let sets = parameter_sets(configuration)?;
    let kind = |set: &&[u8]| (set[0] >> 1) & 0x3F;
    let sps = sets.iter().find(|set| kind(set) == 33)?;
    // Header (2), then vps id / max sub layers / nesting (1), then the twelve
    // bytes of general profile, tier and level the hvcC repeats.
    let rbsp = unescape(sps);
    let ptl = rbsp.get(3..15)?;
    let sub_layers = (rbsp[2] >> 1) & 0x07;
    let nested = rbsp[2] & 0x01;

    let mut hvcc = vec![1];
    hvcc.extend_from_slice(ptl);
    // Segmentation and parallelism unknown; 4:2:0, 8-bit. Decoders configure
    // from the parameter sets themselves, which follow.
    hvcc.extend_from_slice(&[0xF0, 0x00, 0xFC, 0xFD, 0xF8, 0xF8, 0x00, 0x00]);
    hvcc.push(((sub_layers + 1) << 3) | (nested << 2) | 0x03);

    let mut arrays: Vec<(u8, Vec<&[u8]>)> = Vec::new();
    for set in &sets {
        let nal_type = kind(set);
        match arrays.iter_mut().find(|(t, _)| *t == nal_type) {
            Some((_, list)) => list.push(set),
            None => arrays.push((nal_type, vec![set])),
        }
    }
    hvcc.push(u8::try_from(arrays.len()).ok()?);
    for (nal_type, list) in arrays {
        hvcc.push(0x80 | nal_type);
        u16be(&mut hvcc, u16::try_from(list.len()).ok()?);
        push_sets(&mut hvcc, &list);
    }
    Some(visual_entry(*b"hvc1", width, height, *b"hvcC", &hvcc))
}

/// An `Opus` sample entry. The catalog's configuration for Opus is the
/// `OpusHead` identification header when the publisher states one; otherwise
/// the channel count and rate come from the catalog and the pre-skip is the
/// libopus default.
fn opus_entry(configuration: &[u8], channels: u32, sample_rate: u32) -> Vec<u8> {
    let (channels, pre_skip, rate, gain) = match configuration {
        [
            b'O',
            b'p',
            b'u',
            b's',
            b'H',
            b'e',
            b'a',
            b'd',
            _,
            ch,
            ps0,
            ps1,
            r0,
            r1,
            r2,
            r3,
            g0,
            g1,
            ..,
        ] => (
            *ch,
            u16::from_le_bytes([*ps0, *ps1]),
            u32::from_le_bytes([*r0, *r1, *r2, *r3]),
            i16::from_le_bytes([*g0, *g1]),
        ),
        _ => (u8::try_from(channels).unwrap_or(2), 312, sample_rate, 0),
    };
    let mut out = Vec::new();
    mp4_box(&mut out, *b"Opus", |out| {
        out.extend_from_slice(&[0; 6]);
        u16be(out, 1);
        out.extend_from_slice(&[0; 8]);
        u16be(out, u16::from(channels));
        u16be(out, 16);
        u32be(out, 0);
        u32be(out, 48_000 << 16);
        mp4_box(out, *b"dOps", |out| {
            out.push(0);
            out.push(channels);
            u16be(out, pre_skip);
            u32be(out, rate);
            out.extend_from_slice(&gain.to_be_bytes());
            out.push(0);
        });
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use moqom_client::ObjectProperties;

    fn track(name: &str, kind: Kind, codec: &str) -> Track {
        Track {
            name: name.to_owned(),
            kind,
            codec: codec.to_owned(),
            decoder_configuration: None,
            width: Some(1280),
            height: Some(720),
            frame_rate: Some(30.0),
            sample_rate: Some(48_000),
            channels: Some(1),
        }
    }

    fn prefixed(sets: &[&[u8]]) -> Bytes {
        let mut out = Vec::new();
        for set in sets {
            out.extend_from_slice(&(set.len() as u32).to_be_bytes());
            out.extend_from_slice(set);
        }
        Bytes::from(out)
    }

    const SPS: &[u8] = &[0x67, 0x42, 0xC0, 0x1F, 0xDA, 0x01];
    const PPS: &[u8] = &[0x68, 0xCE, 0x3C, 0x80];

    fn frame(group: u64, object: u64, micros: u64, configuration: Option<Bytes>) -> Archived {
        let mut properties = ObjectProperties::default().captured_at_micros(micros);
        properties.configuration = configuration;
        Archived {
            group,
            object,
            received_micros: micros + 50_000,
            properties,
            payload: Bytes::from(vec![0, 0, 0, 2, 0x65, object as u8]),
        }
    }

    /// Walk top-level boxes, returning their types.
    fn boxes(bytes: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        let mut at = 0;
        while at + 8 <= bytes.len() {
            let size = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
            out.push(String::from_utf8_lossy(&bytes[at + 4..at + 8]).into_owned());
            assert!(
                size >= 8 && at + size <= bytes.len(),
                "a box overruns its parent"
            );
            at += size;
        }
        assert_eq!(at, bytes.len(), "boxes tile the buffer exactly");
        out
    }

    fn find(bytes: &[u8], kind: [u8; 4]) -> Option<&[u8]> {
        bytes
            .windows(4)
            .position(|w| w == kind)
            .map(|at| &bytes[at - 4..])
    }

    /// Two groups interleaved on arrival, as two QUIC streams deliver them,
    /// come out as two fragments in decode order.
    #[test]
    fn interleaved_groups_are_put_back_in_order() {
        let config = prefixed(&[SPS, PPS]);
        let mut reorder =
            Reorder::new(Muxer::for_track(&track("video", Kind::Video, "video/h264")).unwrap());
        let mut out = Vec::new();
        for object in [
            frame(1, 0, 1_100_000, Some(config.clone())),
            frame(0, 0, 1_000_000, Some(config.clone())),
            frame(1, 1, 1_133_333, None),
            frame(0, 1, 1_033_333, None),
        ] {
            out.extend(reorder.push(&object));
        }
        assert!(out.is_empty(), "held until enough groups have arrived");
        out.extend(reorder.finish());
        let fragments: Vec<&Vec<u8>> = out
            .iter()
            .filter_map(|output| match output {
                Output::Fragment(bytes) => Some(bytes),
                Output::Init(_) => None,
            })
            .collect();
        assert_eq!(fragments.len(), 2);
        let decode_time = |fragment: &[u8]| {
            let tfdt = find(fragment, *b"tfdt").unwrap();
            u64::from_be_bytes(tfdt[12..20].try_into().unwrap())
        };
        assert_eq!(decode_time(fragments[0]), 0);
        assert_eq!(decode_time(fragments[1]), 9000);

        // And a group that turns up after a later one has been muxed is left
        // to the archive.
        let mut muxer = Muxer::for_track(&track("video", Kind::Video, "video/h264")).unwrap();
        muxer.push(&frame(5, 0, 1_000_000, Some(config.clone())));
        assert!(muxer.push(&frame(4, 0, 900_000, Some(config))).is_empty());
    }

    #[test]
    fn codecs_from_the_catalog() {
        assert_eq!(
            Codec::of(&track("video/720p", Kind::Video, "video/hevc")),
            Some(Codec::Hevc)
        );
        assert_eq!(
            Codec::of(&track("screen/1080p", Kind::Screen, "video/h264")),
            Some(Codec::H264)
        );
        assert_eq!(
            Codec::of(&track("audio", Kind::Audio, "audio/opus")),
            Some(Codec::Opus)
        );
        assert_eq!(Codec::of(&track("audio", Kind::Audio, "audio/pcm")), None);
        assert_eq!(Codec::of(&track("t", Kind::Data, "video/h264")), None);
    }

    #[test]
    fn a_gop_becomes_an_init_and_a_fragment() {
        let mut muxer = Muxer::for_track(&track("video/720p", Kind::Video, "video/h264")).unwrap();
        let config = prefixed(&[SPS, PPS]);

        let out = muxer.push(&frame(0, 0, 1_000_000, Some(config.clone())));
        let [Output::Init(init)] = out.as_slice() else {
            panic!("an init first: {out:?}")
        };
        assert_eq!(boxes(init), ["ftyp", "moov"]);
        let avcc = find(init, *b"avcC").expect("an avcC");
        assert_eq!(
            &avcc[8..12],
            &[1, 0x42, 0xC0, 0x1F],
            "profile and level from the SPS"
        );

        assert!(muxer.push(&frame(0, 1, 1_033_333, None)).is_empty());
        assert!(muxer.push(&frame(0, 2, 1_066_666, None)).is_empty());

        let out = muxer.push(&frame(1, 0, 1_100_000, Some(config)));
        let [Output::Fragment(fragment)] = out.as_slice() else {
            panic!("a fragment: {out:?}")
        };
        assert_eq!(boxes(fragment), ["moof", "mdat"]);
        let trun = find(fragment, *b"trun").unwrap();
        assert_eq!(
            u32::from_be_bytes(trun[12..16].try_into().unwrap()),
            3,
            "three samples"
        );
        // First duration: 33,333 µs at 90 kHz.
        assert_eq!(u32::from_be_bytes(trun[20..24].try_into().unwrap()), 2_999);
        assert_eq!(u32::from_be_bytes(trun[28..32].try_into().unwrap()), SYNC);
        assert_eq!(
            u32::from_be_bytes(trun[40..44].try_into().unwrap()),
            NON_SYNC
        );

        let Some(Output::Fragment(last)) = muxer.finish() else {
            panic!("the last group")
        };
        let tfdt = find(&last, *b"tfdt").unwrap();
        assert_eq!(
            u64::from_be_bytes(tfdt[12..20].try_into().unwrap()),
            9_000,
            "100 ms in"
        );
    }

    #[test]
    fn objects_before_the_first_keyframe_and_after_a_gap_are_dropped() {
        let mut muxer = Muxer::for_track(&track("video/720p", Kind::Video, "video/h264")).unwrap();
        let config = prefixed(&[SPS, PPS]);
        assert!(
            muxer.push(&frame(3, 4, 0, None)).is_empty(),
            "joined mid-group"
        );
        assert_eq!(muxer.push(&frame(4, 0, 100, Some(config.clone()))).len(), 1);
        muxer.push(&frame(4, 1, 200, None));
        // Object 2 lost: 3 and 4 have no reference.
        let out = muxer.push(&frame(4, 3, 400, None));
        assert!(matches!(out.as_slice(), [Output::Fragment(_)]));
        assert!(muxer.push(&frame(4, 4, 500, None)).is_empty());
        assert!(muxer.finish().is_none(), "nothing decodable was pending");
    }

    #[test]
    fn a_new_geometry_is_a_new_rendition() {
        let mut muxer = Muxer::for_track(&track("video/720p", Kind::Video, "video/h264")).unwrap();
        muxer.push(&frame(0, 0, 0, Some(prefixed(&[SPS, PPS]))));
        let other_sps: &[u8] = &[0x67, 0x64, 0x00, 0x28, 0xAC];
        let out = muxer.push(&frame(1, 0, 33_333, Some(prefixed(&[other_sps, PPS]))));
        assert!(
            matches!(out.as_slice(), [Output::Fragment(_), Output::Init(_)]),
            "{out:?}"
        );
        assert_eq!(muxer.renditions(), 2);
    }

    #[test]
    fn hevc_profile_fields_come_from_the_sps() {
        let vps: &[u8] = &[0x40, 0x01, 0x0C];
        // NAL header 0x42 0x01, then vps id 0, one sub-layer, nested; then a
        // profile-tier-level with an emulation-prevention byte in it.
        let sps: &[u8] = &[
            0x42, 0x01, 0x01, 0x01, 0x60, 0x00, 0x00, 0x03, 0x00, 0x90, 0x00, 0x00, 0x03, 0x00,
            0x00, 0x03, 0x00, 0x5D,
        ];
        let pps: &[u8] = &[0x44, 0x01, 0xC1];
        let entry = hevc_entry(&prefixed(&[vps, sps, pps]), 1280, 720).expect("an hvc1 entry");
        let hvcc = find(&entry, *b"hvcC").unwrap();
        assert_eq!(hvcc[8], 1, "configurationVersion");
        assert_eq!(hvcc[9], 0x01, "Main profile");
        assert_eq!(
            &hvcc[10..14],
            &[0x60, 0x00, 0x00, 0x00],
            "compatibility flags, unescaped"
        );
        assert_eq!(hvcc[20], 0x5D, "level 3.1");
        assert_eq!(hvcc[30], 3, "three arrays: VPS, SPS, PPS");
    }

    #[test]
    fn opus_is_cut_about_once_a_second() {
        let mut muxer = Muxer::for_track(&track("audio", Kind::Audio, "audio/opus")).unwrap();
        let mut fragments = 0;
        let mut inits = 0;
        for index in 0..150u64 {
            for output in muxer.push(&frame(index / 10, index % 10, index * 20_000, None)) {
                match output {
                    Output::Init(init) => {
                        inits += 1;
                        assert!(find(&init, *b"dOps").is_some());
                    }
                    Output::Fragment(_) => fragments += 1,
                }
            }
        }
        assert_eq!(inits, 1);
        assert_eq!(
            fragments, 2,
            "three seconds, cut at group boundaries past a second"
        );
        assert!(muxer.finish().is_some());
    }

    #[test]
    fn a_truncated_configuration_is_not_parsed() {
        assert!(parameter_sets(&[0, 0, 0, 9, 1, 2]).is_none());
        assert_eq!(parameter_sets(&[0, 0, 0, 1, 7]).unwrap(), [&[7u8][..]]);
    }
}
