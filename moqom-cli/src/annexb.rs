//! Reading an Annex B elementary stream the way MOQOM publishes one.
//!
//! Deterministic input is the point. A camera gives a different stream every run,
//! which makes a latency number unrepeatable and a regression unprovable; a file
//! gives the same frames, at the same sizes, in the same order, on every machine
//! that runs it. `ffmpeg -i x.mp4 -c:v copy -bsf:v hevc_mp4toannexb out.h265`
//! produces one.
//!
//! What comes out here is shaped by what a MOQOM viewer expects, which is what
//! `VideoToolbox` produces and `MoqomKit`'s depacketiser reads:
//!
//! * one object per access unit, not per NAL unit — a frame is several NALs and a
//!   viewer decodes frames;
//! * payloads as four-byte big-endian length-prefixed NALs rather than start
//!   codes, matching the `nalUnitHeaderLength: 4` the Apple decoder is built
//!   with;
//! * parameter sets kept out of the payload and carried as the group's
//!   `configuration` property, because that is where a decoder is configured
//!   from and because a group that repeats them is a group that can be joined.
//!
//! Only the framing is read. Nothing here parses a slice header beyond the one
//! bit that says whether a picture starts, and nothing decodes.

use bytes::{BufMut, Bytes, BytesMut};

/// Which codec's NAL headers to read.
///
/// Named rather than sniffed. The two layouts are one bit apart — H.264 puts the
/// type in the low five bits of one byte, HEVC in six bits of the first of two —
/// so a wrong guess does not fail, it silently reads every NAL as the wrong kind
/// and publishes a stream that arrives intact and decodes to nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Codec {
    /// H.264, one-byte NAL header.
    H264,
    /// HEVC, two-byte NAL header.
    Hevc,
}

/// One access unit: a frame, and what it needs to be decodable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessUnit {
    /// Four-byte length-prefixed NAL units, parameter sets excluded.
    pub payload: Bytes,
    /// Whether this frame can be decoded without any before it.
    pub is_keyframe: bool,
    /// Temporal layer, when the stream says and it is not the base one.
    ///
    /// `None` covers both "the base layer" and "not stated": HEVC carries the ID
    /// in every NAL header, H.264 does not carry it at all outside SVC, and a
    /// single-layer stream would otherwise spend two bytes on every frame
    /// announcing the default. What a relay does with this is drop it, so only a
    /// layer that can be dropped is worth naming.
    pub temporal_layer: Option<u64>,
    /// The parameter sets in force, on keyframes only.
    ///
    /// Concatenated and length-prefixed the same way, ready to be the
    /// `configuration` property. Empty on a frame that is not opening a group,
    /// where repeating them would be per-frame overhead for nothing.
    pub configuration: Bytes,
}

/// What a NAL unit is, to the extent that framing cares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// A parameter set: VPS, SPS or PPS.
    ParameterSet,
    /// Part of a coded picture.
    Slice {
        /// This slice begins a new picture.
        starts_picture: bool,
        /// This picture is decodable on its own.
        keyframe: bool,
        /// Temporal layer, if the header carries one and it is not the base.
        temporal_layer: Option<u64>,
    },
    /// A non-VCL unit that introduces the picture after it: a delimiter, or a
    /// prefix SEI. Held back and emitted with that picture, because an SEI
    /// describing a picture has to precede it to be of any use.
    Prefix,
    /// A non-VCL unit that trails the picture before it: a suffix SEI, filler, an
    /// end-of-sequence marker. Kept with the picture it came after.
    ///
    /// The distinction from [`Self::Prefix`] is the whole reason this enum is not
    /// one "other" case. Putting a prefix SEI on the preceding picture moves it
    /// past the frame it describes, and putting a suffix SEI on the following one
    /// moves it past the end of the stream if it was the last thing in the file.
    Suffix,
}

/// Split an Annex B stream into access units.
///
/// Bytes that are not preceded by a start code are ignored rather than refused,
/// which is what makes this safe to point at a file with a few junk bytes at the
/// front. A stream with no start codes at all yields nothing, and the caller
/// reports that rather than publishing silence.
#[must_use]
pub fn access_units(stream: &[u8], codec: Codec) -> Vec<AccessUnit> {
    // In encoder order, and de-duplicated by kind rather than accumulated: a
    // stream that repeats its parameter sets before every keyframe -- which is
    // what a stream meant for broadcast does -- would otherwise grow the
    // configuration blob without bound.
    let mut parameter_sets: Vec<(u8, Bytes)> = Vec::new();
    let mut units = Vec::new();
    let mut pending = BytesMut::new();
    let mut open: Option<Open> = None;

    for nal in nal_units(stream) {
        let Some(&first) = nal.first() else { continue };
        match kind(nal, codec) {
            Kind::ParameterSet => {
                let type_code = nal_type(first, codec);
                let set = Bytes::copy_from_slice(nal);
                match parameter_sets
                    .iter_mut()
                    .find(|(code, _)| *code == type_code)
                {
                    Some(existing) => existing.1 = set,
                    None => parameter_sets.push((type_code, set)),
                }
            }
            Kind::Slice {
                starts_picture,
                keyframe,
                temporal_layer,
            } => {
                if starts_picture {
                    if let Some(unit) = open.take() {
                        units.push(unit.finish(&parameter_sets));
                    }
                    let mut body = std::mem::take(&mut pending);
                    append_length_prefixed(&mut body, nal);
                    open = Some(Open {
                        body,
                        keyframe,
                        temporal_layer,
                    });
                } else if let Some(unit) = open.as_mut() {
                    // A second slice of the same picture. Keyframe-ness is a
                    // property of the picture, so one intra slice makes the frame
                    // one; a stream with mixed slice types is not a keyframe
                    // unless every slice says so, and this errs towards the frame
                    // being one because the alternative -- an IRAP that opens no
                    // group -- leaves a viewer unable to join at all.
                    unit.keyframe |= keyframe;
                    append_length_prefixed(&mut unit.body, nal);
                }
                // A slice arriving before any picture has started is a stream
                // beginning mid-frame, and there is nothing to attach it to.
            }
            // Held for the picture that has not arrived yet. If none ever does --
            // a file ending on a delimiter -- these bytes are dropped, which is
            // the right end for a prefix with nothing to prefix.
            Kind::Prefix => append_length_prefixed(&mut pending, nal),
            Kind::Suffix => match open.as_mut() {
                Some(unit) => append_length_prefixed(&mut unit.body, nal),
                // Before any picture, so there is nothing to trail. Treated as a
                // prefix rather than discarded: a stream opening with filler
                // should not lose it.
                None => append_length_prefixed(&mut pending, nal),
            },
        }
    }

    if let Some(unit) = open.take() {
        units.push(unit.finish(&parameter_sets));
    }
    units
}

/// An access unit being accumulated.
struct Open {
    body: BytesMut,
    keyframe: bool,
    temporal_layer: Option<u64>,
}

impl Open {
    fn finish(self, parameter_sets: &[(u8, Bytes)]) -> AccessUnit {
        let configuration = if self.keyframe {
            let mut blob = BytesMut::new();
            for (_, set) in parameter_sets {
                append_length_prefixed(&mut blob, set);
            }
            blob.freeze()
        } else {
            Bytes::new()
        };
        AccessUnit {
            payload: self.body.freeze(),
            is_keyframe: self.keyframe,
            temporal_layer: self.temporal_layer,
            configuration,
        }
    }
}

/// Every NAL unit in the stream, without its start code.
///
/// Three-byte and four-byte start codes both count, and a trailing zero byte
/// before the next start code is left on the NAL: it is legal padding, a decoder
/// ignores it, and trimming it would be this reader editing the bytes it was
/// asked to carry.
fn nal_units(stream: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut starts = Vec::new();
    let mut index = 0;
    while index + 3 <= stream.len() {
        if stream[index] == 0 && stream[index + 1] == 0 && stream[index + 2] == 1 {
            starts.push(index + 3);
            index += 3;
        } else {
            index += 1;
        }
    }

    let ends = starts
        .iter()
        .skip(1)
        .map(|next| {
            // Back off the start code itself, and the extra zero of a four-byte
            // one, so the NAL before it ends where it actually ends.
            let mut end = next - 3;
            if end > 0 && stream[end - 1] == 0 {
                end -= 1;
            }
            end
        })
        .chain(std::iter::once(stream.len()));

    starts
        .clone()
        .into_iter()
        .zip(ends)
        .filter(|(start, end)| end > start)
        .map(|(start, end)| &stream[start..end])
        .collect::<Vec<_>>()
        .into_iter()
}

/// The NAL type code.
fn nal_type(first: u8, codec: Codec) -> u8 {
    match codec {
        Codec::H264 => first & 0x1F,
        Codec::Hevc => (first >> 1) & 0x3F,
    }
}

fn kind(nal: &[u8], codec: Codec) -> Kind {
    let Some(&first) = nal.first() else {
        return Kind::Suffix;
    };
    let type_code = nal_type(first, codec);
    match codec {
        Codec::H264 => match type_code {
            // 7 SPS, 8 PPS.
            7 | 8 => Kind::ParameterSet,
            // 1 non-IDR, 5 IDR. The first field of a slice header is
            // `first_mb_in_slice`, an exp-Golomb value, and zero is encoded as a
            // single set bit -- so the top bit of the byte after the header says
            // whether this slice starts the picture.
            1 | 5 => Kind::Slice {
                starts_picture: nal.get(1).is_some_and(|byte| byte & 0x80 != 0),
                keyframe: type_code == 5,
                // H.264 puts the temporal ID in an SVC prefix NAL rather than in
                // the header, so a plain stream does not say.
                temporal_layer: None,
            },
            // 6 SEI and 9 access unit delimiter both introduce a picture.
            6 | 9 => Kind::Prefix,
            _ => Kind::Suffix,
        },
        Codec::Hevc => match type_code {
            // 32 VPS, 33 SPS, 34 PPS.
            32..=34 => Kind::ParameterSet,
            // 0..=21 are slice segments; 16..=23 are the IRAP range, which is
            // what a viewer can join on. `first_slice_segment_in_pic_flag` is the
            // first bit of the slice header, after the two-byte NAL header.
            0..=21 => Kind::Slice {
                starts_picture: nal.get(2).is_some_and(|byte| byte & 0x80 != 0),
                keyframe: (16..=23).contains(&type_code),
                // nuh_temporal_id_plus1 is the low three bits of the second
                // header byte, biased by one. Only a layer above the base is
                // named; see the field this ends up in.
                temporal_layer: nal
                    .get(1)
                    .map(|byte| u64::from(byte & 0x07).saturating_sub(1))
                    .filter(|layer| *layer > 0),
            },
            // 35 access unit delimiter and 39 prefix SEI introduce a picture. 40
            // is the suffix SEI, and everything else here -- end of sequence, end
            // of bitstream, filler -- trails one.
            35 | 39 => Kind::Prefix,
            _ => Kind::Suffix,
        },
    }
}

fn append_length_prefixed(buf: &mut BytesMut, nal: &[u8]) {
    // Truncation would produce a length that disagrees with the bytes after it,
    // which is a stream that decodes as garbage rather than failing, so an
    // impossible NAL is dropped instead.
    if let Ok(length) = u32::try_from(nal.len()) {
        buf.put_u32(length);
        buf.put_slice(nal);
    }
}

/// Turn length-prefixed NAL units back into an Annex B stream.
///
/// The other direction, for `subscribe --out`: what arrives is what a decoder
/// wants and what a file wants is start codes, so a saved stream is playable
/// rather than being a debugging artefact. Four-byte start codes throughout, so a
/// round trip through a three-byte-coded file is equal frame for frame and not
/// byte for byte.
///
/// A buffer whose lengths do not add up is written out as far as it parses and no
/// further, the caller having already been told how many bytes arrived.
pub fn to_annex_b(payload: &[u8], out: &mut Vec<u8>) {
    let mut index = 0;
    while index + 4 <= payload.len() {
        let length = u32::from_be_bytes([
            payload[index],
            payload[index + 1],
            payload[index + 2],
            payload[index + 3],
        ]) as usize;
        index += 4;
        let end = index.saturating_add(length);
        if length == 0 || end > payload.len() {
            return;
        }
        out.extend_from_slice(&[0, 0, 0, 1]);
        out.extend_from_slice(&payload[index..end]);
        index = end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An HEVC NAL header for `type_code`, with the layer and temporal ID a
    /// single-layer encoder writes.
    fn hevc(type_code: u8, rest: &[u8]) -> Vec<u8> {
        let mut nal = vec![type_code << 1, 0x01];
        nal.extend_from_slice(rest);
        nal
    }

    fn annex_b(nals: &[Vec<u8>]) -> Vec<u8> {
        let mut stream = Vec::new();
        for nal in nals {
            stream.extend_from_slice(&[0, 0, 0, 1]);
            stream.extend_from_slice(nal);
        }
        stream
    }

    #[test]
    fn a_frame_is_one_object_however_many_nals_it_took() {
        let stream = annex_b(&[
            hevc(32, &[0xAA]),
            hevc(33, &[0xBB]),
            hevc(34, &[0xCC]),
            // One picture in two slices: the second does not start it.
            hevc(19, &[0x80, 0x01]),
            hevc(19, &[0x00, 0x02]),
        ]);

        let units = access_units(&stream, Codec::Hevc);
        assert_eq!(units.len(), 1, "two slices of one picture are one object");
        assert!(units[0].is_keyframe);

        // Both slices, and neither parameter set.
        let mut annex = Vec::new();
        to_annex_b(&units[0].payload, &mut annex);
        assert_eq!(
            annex,
            annex_b(&[hevc(19, &[0x80, 0x01]), hevc(19, &[0x00, 0x02])])
        );
    }

    /// The sets travel in the configuration property, so they are in the group's
    /// metadata rather than in the frame, and only on the frame that opens one.
    #[test]
    fn parameter_sets_leave_the_payload_and_arrive_as_configuration() {
        let stream = annex_b(&[
            hevc(32, &[0xAA]),
            hevc(33, &[0xBB]),
            hevc(19, &[0x80]),
            hevc(1, &[0x80]),
        ]);

        let units = access_units(&stream, Codec::Hevc);
        assert_eq!(units.len(), 2);

        let mut sets = Vec::new();
        to_annex_b(&units[0].configuration, &mut sets);
        assert_eq!(sets, annex_b(&[hevc(32, &[0xAA]), hevc(33, &[0xBB])]));

        assert!(!units[1].is_keyframe);
        assert!(
            units[1].configuration.is_empty(),
            "repeating the sets on every frame is per-frame overhead for nothing"
        );
    }

    /// A broadcast stream repeats its parameter sets before every keyframe. The
    /// configuration has to stay the size of one set of them.
    #[test]
    fn repeated_parameter_sets_replace_rather_than_accumulate() {
        let stream = annex_b(&[
            hevc(33, &[0xBB]),
            hevc(19, &[0x80]),
            hevc(33, &[0xBB]),
            hevc(19, &[0x80]),
        ]);

        let units = access_units(&stream, Codec::Hevc);
        assert_eq!(units.len(), 2);
        assert_eq!(units[0].configuration, units[1].configuration);
        assert_eq!(units[1].configuration.len(), 4 + 3);
    }

    /// An SEI describes the picture that follows it, so it has to travel with
    /// that picture and not with the one before.
    #[test]
    fn a_prefix_nal_belongs_to_the_picture_after_it() {
        let stream = annex_b(&[
            hevc(19, &[0x80]),
            // 39 is a prefix SEI.
            hevc(39, &[0xEE]),
            hevc(1, &[0x80]),
        ]);

        let units = access_units(&stream, Codec::Hevc);
        assert_eq!(units.len(), 2);

        let mut second = Vec::new();
        to_annex_b(&units[1].payload, &mut second);
        assert_eq!(second, annex_b(&[hevc(39, &[0xEE]), hevc(1, &[0x80])]));
    }

    /// The other half of the same rule, and the half that would go unnoticed: a
    /// suffix SEI held for the next picture rides one frame late, and if it was
    /// the last thing in the file it is lost outright.
    #[test]
    fn a_suffix_nal_belongs_to_the_picture_before_it() {
        let stream = annex_b(&[
            hevc(19, &[0x80]),
            // 40 is a suffix SEI.
            hevc(40, &[0xEE]),
        ]);

        let units = access_units(&stream, Codec::Hevc);
        assert_eq!(units.len(), 1);

        let mut only = Vec::new();
        to_annex_b(&units[0].payload, &mut only);
        assert_eq!(only, annex_b(&[hevc(19, &[0x80]), hevc(40, &[0xEE])]));
    }

    #[test]
    fn three_byte_start_codes_are_read_too() {
        let mut stream = vec![0, 0, 1];
        stream.extend_from_slice(&hevc(19, &[0x80, 0x11]));
        stream.extend_from_slice(&[0, 0, 1]);
        stream.extend_from_slice(&hevc(1, &[0x80, 0x22]));

        let units = access_units(&stream, Codec::Hevc);
        assert_eq!(units.len(), 2);
        assert!(units[0].is_keyframe);
    }

    #[test]
    fn h264_reads_its_own_header_layout() {
        // 0x67 SPS, 0x68 PPS, 0x65 IDR, 0x41 non-IDR. The byte after the header
        // carries first_mb_in_slice, and 0x80 is that value being zero.
        let stream = annex_b(&[
            vec![0x67, 0xAA],
            vec![0x68, 0xBB],
            vec![0x65, 0x80],
            vec![0x41, 0x80],
        ]);

        let units = access_units(&stream, Codec::H264);
        assert_eq!(units.len(), 2);
        assert!(units[0].is_keyframe);
        assert!(!units[1].is_keyframe);
        assert_eq!(units[0].configuration.len(), (4 + 2) * 2);
    }

    /// Reading HEVC as H.264 is the mistake the codec flag exists to prevent, and
    /// this is what it costs: no frames at all rather than wrong ones, which is at
    /// least a failure somebody notices.
    #[test]
    fn the_wrong_codec_finds_nothing_rather_than_something_wrong() {
        let stream = annex_b(&[hevc(33, &[0xBB]), hevc(19, &[0x80])]);
        assert!(access_units(&stream, Codec::H264).is_empty());
    }

    /// What a relay drops when it needs to shed bitrate, so it has to be on the
    /// object rather than inside the payload. The base layer is left unstated: it
    /// cannot be dropped, and naming it on every frame of a single-layer stream
    /// costs bytes to say nothing.
    #[test]
    fn an_enhancement_layer_is_named_and_the_base_is_not() {
        // Second header byte carries nuh_temporal_id_plus1 in its low three bits.
        let base = annex_b(&[vec![19 << 1, 0x01, 0x80]]);
        assert_eq!(access_units(&base, Codec::Hevc)[0].temporal_layer, None);

        let higher = annex_b(&[vec![1 << 1, 0x03, 0x80]]);
        assert_eq!(
            access_units(&higher, Codec::Hevc)[0].temporal_layer,
            Some(2)
        );
    }

    #[test]
    fn a_stream_with_no_start_codes_yields_nothing() {
        assert!(access_units(b"not a video file", Codec::Hevc).is_empty());
    }

    /// Lengths that do not add up stop the conversion rather than reading past
    /// the end or emitting a NAL that is partly the next one's length.
    #[test]
    fn a_truncated_payload_stops_where_it_stops() {
        let mut out = Vec::new();
        to_annex_b(&[0, 0, 0, 9, 1, 2, 3], &mut out);
        assert!(out.is_empty());

        out.clear();
        to_annex_b(&[0, 0, 0, 2, 0xAA, 0xBB, 0, 0, 0, 5, 1], &mut out);
        assert_eq!(out, vec![0, 0, 0, 1, 0xAA, 0xBB]);
    }
}
