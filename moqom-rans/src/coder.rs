//! The entropy coder: quantised probability tables, bypass coding, and the
//! encode and decode drivers.
//!
//! Ported from `msrtc_rans/EntropyCoder.cpp`. The layer above [`crate::rans`]
//! answers two questions that the raw algorithm does not: which distribution a
//! given symbol is drawn from, and what to do about a value the distribution
//! does not cover.
//!
//! # How the tables are laid out
//!
//! A model has thousands of distributions — one per (channel, quantisation
//! index) pair — and they are handed over as three flat arrays rather than as a
//! nested structure, because they come from a tensor:
//!
//! - `pmf_lengths[i]` — how many symbols distribution `i` has.
//! - `pmf_offsets[i]` — where zero sits within it, since latents are signed and
//!   symbol indices are not.
//! - `pmf_table` — every distribution's frequencies, concatenated.
//!
//! The last symbol of each distribution is not a value. It is the sentinel that
//! means "what follows is a bypass-coded value", and it carries the tail mass of
//! the distribution — the probability the model assigns to everything it did not
//! give an explicit symbol.
//!
//! # Why bypass coding exists
//!
//! A learned model predicts a narrow range and is occasionally wrong. Widening
//! every distribution to cover the rare large residual would cost bits on every
//! symbol; bypass instead spends the sentinel plus a handful of uniform digits,
//! but only when it happens. The comment in the reference is blunter — bypass
//! "adds a lot of overhead" — and that is the trade: rare and expensive beats
//! common and cheap.
//!
//! Bypass digits are written most significant first so that the decoder, reading
//! in the opposite order, recovers them least significant first. If that
//! sentence looks backwards, re-read the LIFO note in [`crate::rans`].

use crate::Error;
use crate::rans::{EncSymbol, MAX_SCALE_BITS, RansDecoder, RansEncoder};

/// Largest number of bypass digits a `u32` can need.
///
/// `bypass_bits` is at least two, so a 32-bit value never splits into more than
/// sixteen digits. The reference sizes its stack buffer with the same reasoning.
const MAX_BYPASS_DIGITS: usize = 16;

/// One distribution's position and shape.
#[derive(Clone, Copy, Debug)]
struct Distribution {
    /// Added to a value on the way in, subtracted on the way out.
    value_offset: i32,
    /// Index of the sentinel symbol, and so also the count of real values.
    bypass_sentinel: u32,
    /// Where this distribution starts in the owner's derived table.
    table_offset: usize,
}

/// Validate the table shape and locate each distribution within it.
///
/// `extra_per_distribution` is what makes this shared: the encoder's derived
/// table has one entry per symbol, and the decoder's has one more per
/// distribution for the closing cumulative total. Everything else about the
/// walk is identical, and a second copy of it would be a second place for the
/// two sides to drift apart.
fn distributions(
    pmf_lengths: &[i32],
    pmf_offsets: &[i32],
    pmf_table_len: usize,
    extra_per_distribution: usize,
) -> Result<Vec<Distribution>, Error> {
    if pmf_offsets.len() != pmf_lengths.len() {
        return Err(Error::InvalidPmf);
    }

    let mut descs = Vec::with_capacity(pmf_lengths.len());
    let mut symbols_seen = 0usize;
    let mut table_offset = 0usize;

    for (&length, &value_offset) in pmf_lengths.iter().zip(pmf_offsets) {
        // Two symbols is the minimum that means anything: one value and the
        // sentinel. A length of one would be a distribution that can only say
        // "bypass", and a length of zero has no sentinel at all.
        if length <= 1 {
            return Err(Error::InvalidPmf);
        }
        let length = usize::try_from(length).map_err(|_| Error::InvalidPmf)?;
        if pmf_table_len - symbols_seen < length {
            return Err(Error::InvalidPmf);
        }

        // Every value this distribution can produce directly must fit in `i32`.
        // Checked once here rather than per symbol in the decode loop, which is
        // both faster and a better place to fail: an offset that makes the
        // distribution unrepresentable is a property of the tables, so it should
        // be refused when they are supplied rather than when a frame arrives.
        // Bypass values are still checked in the loop, because those come from
        // the stream rather than from the tables.
        let sentinel = length as i64 - 1;
        if i32::try_from(-i64::from(value_offset)).is_err()
            || i32::try_from(sentinel - i64::from(value_offset)).is_err()
        {
            return Err(Error::InvalidPmf);
        }

        descs.push(Distribution {
            value_offset,
            bypass_sentinel: (length - 1) as u32,
            table_offset,
        });

        symbols_seen += length;
        table_offset += length + extra_per_distribution;
    }

    // Exactly consumed, not merely not-overrun. A table with trailing
    // frequencies means the caller and the model disagree about the shape of
    // something, and every symbol after the disagreement would be drawn from
    // the wrong distribution.
    if symbols_seen != pmf_table_len {
        return Err(Error::InvalidPmf);
    }
    Ok(descs)
}

/// Check a bit width against what this rANS variant can carry.
fn check_bits(bits: i32) -> Result<u32, Error> {
    let bits = u32::try_from(bits).map_err(|_| Error::InvalidParams)?;
    if !(2..=MAX_SCALE_BITS).contains(&bits) {
        return Err(Error::InvalidParams);
    }
    Ok(bits)
}

/// Shared configuration for both directions.
#[derive(Clone, Copy, Debug)]
struct Config {
    symbol_bits: u32,
    bypass_bits: u32,
    bypass_max: u32,
}

impl Config {
    fn new(symbol_bits: i32, bypass_bits: i32) -> Result<Self, Error> {
        let symbol_bits = check_bits(symbol_bits)?;
        let bypass_bits = check_bits(bypass_bits)?;
        Ok(Self {
            symbol_bits,
            bypass_bits,
            bypass_max: (1u32 << bypass_bits) - 1,
        })
    }
}

/// Turns quantised latents into a bitstream.
///
/// Holds a precomputed reciprocal per symbol, so construction is the expensive
/// part and encoding a frame is a walk. Build one per model and keep it: MLVC's
/// tables run to millions of symbols, and rebuilding them per frame would cost
/// more than the frame.
#[derive(Debug)]
pub struct Encoder {
    config: Config,
    descs: Vec<Distribution>,
    symbols: Vec<EncSymbol>,
}

impl Encoder {
    /// Build an encoder from a model's quantised probability tables.
    ///
    /// `symbol_bits` and `bypass_bits` are the scales the tables were quantised
    /// against; MLVC uses 16 and 2. They are part of the format, not a tuning
    /// knob — a decoder built with different ones will not decode this stream.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidParams`] for an unusable bit width, [`Error::InvalidPmf`]
    /// for tables whose shape or frequencies are inconsistent.
    pub fn new(
        pmf_lengths: &[i32],
        pmf_offsets: &[i32],
        pmf_table: &[i32],
        symbol_bits: i32,
        bypass_bits: i32,
    ) -> Result<Self, Error> {
        let config = Config::new(symbol_bits, bypass_bits)?;
        let descs = distributions(pmf_lengths, pmf_offsets, pmf_table.len(), 0)?;

        let max_freq = 1i64 << config.symbol_bits;
        let mut symbols = Vec::with_capacity(pmf_table.len());
        let mut cursor = 0usize;

        for desc in &descs {
            let mut start = 0i64;
            for _ in 0..=desc.bypass_sentinel {
                let freq = i64::from(pmf_table[cursor]);
                cursor += 1;
                // The cumulative total may not exceed the scale. This is the
                // check that makes every later state update provably fit in 31
                // bits, which is why it is here and not merely asserted.
                if freq <= 0 || freq > max_freq - start {
                    return Err(Error::InvalidPmf);
                }
                symbols.push(EncSymbol::new(
                    start as u32,
                    freq as u32,
                    config.symbol_bits,
                )?);
                start += freq;
            }
        }

        Ok(Self {
            config,
            descs,
            symbols,
        })
    }

    /// Encode one block, returning its bitstream.
    ///
    /// # Errors
    ///
    /// See [`Encoder::encode_into`].
    pub fn encode(&self, indices: &[i32], values: &[i32]) -> Result<Vec<u8>, Error> {
        let mut rans = RansEncoder::with_capacity(indices.len() / 2 + 8);
        self.encode_into(&mut rans, indices, values)?;
        Ok(rans.finish())
    }

    /// Encode one block into a shared stream, without flushing it.
    ///
    /// MLVC uses this form: a frame's latents arrive as several tensors, and
    /// they share one rANS stream because each flush costs four bytes of state
    /// and a keyframe has enough tensors for that to matter.
    ///
    /// Note that blocks must be *decoded* in the reverse of the order they were
    /// encoded. That is not a quirk of this API; it is what LIFO means.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidParams`] if `indices` and `values` differ in length, and
    /// [`Error::ValueOutOfRange`] for a value whose bypass form does not fit in
    /// 32 bits and so could not be decoded back.
    pub fn encode_into(
        &self,
        rans: &mut RansEncoder,
        indices: &[i32],
        values: &[i32],
    ) -> Result<(), Error> {
        if indices.len() != values.len() {
            return Err(Error::InvalidParams);
        }
        if self.descs.is_empty() {
            return Err(Error::InvalidState);
        }
        let last = (self.descs.len() - 1) as i32;

        // Reverse, because the decoder reads forwards.
        for (&index, &raw) in indices.iter().zip(values).rev() {
            if index < 0 {
                // A negative index marks a position the model did not code at
                // all — masked out by the spatial prior. The decoder writes zero
                // there without consuming any bits.
                continue;
            }
            let desc = &self.descs[index.min(last) as usize];

            // Widened before offsetting. In `i32` this addition can overflow for
            // a pathological latent, which in the reference is undefined and
            // here would panic in a debug build.
            let value = i64::from(raw) + i64::from(desc.value_offset);
            let sentinel = i64::from(desc.bypass_sentinel);

            let symbol = if (0..sentinel).contains(&value) {
                value
            } else {
                // Fold the sign into the low bit: negatives odd, overshoots
                // even. One bypass value therefore covers both directions
                // without a sign flag.
                let bypass = if value < 0 {
                    2 * -value - 1
                } else {
                    2 * (value - sentinel)
                };
                let bypass = u32::try_from(bypass).map_err(|_| Error::ValueOutOfRange)?;
                self.encode_bypass(rans, bypass);
                sentinel
            };

            // In range by construction: `symbol` is either below the sentinel or
            // equal to it, and the table has `sentinel + 1` entries.
            rans.put_symbol(&self.symbols[desc.table_offset + symbol as usize]);
        }
        Ok(())
    }

    /// Write a bypass value as uniform digits, followed by its own length.
    ///
    /// The length is written last and so read first, which is the only way the
    /// decoder can know how many digits to expect.
    fn encode_bypass(&self, rans: &mut RansEncoder, bypass: u32) {
        let mut digits = [0u32; MAX_BYPASS_DIGITS];
        let mut count = 0usize;
        let mut remaining = bypass;
        while remaining != 0 {
            digits[count] = remaining & self.config.bypass_max;
            count += 1;
            remaining >>= self.config.bypass_bits;
        }

        // Most significant first.
        for &digit in digits[..count].iter().rev() {
            rans.put(digit, 1, self.config.bypass_bits);
        }

        // The count itself is coded in the same digits, as however many
        // saturated digits it takes plus a remainder. A count of exactly
        // `bypass_max` becomes one saturated digit and a zero remainder, which
        // is what stops the decoder's loop.
        let mut remainder = count as u32;
        let mut saturated = 0u32;
        while remainder >= self.config.bypass_max {
            remainder -= self.config.bypass_max;
            saturated += 1;
        }
        rans.put(remainder, 1, self.config.bypass_bits);
        for _ in 0..saturated {
            rans.put(self.config.bypass_max, 1, self.config.bypass_bits);
        }
    }
}

/// Turns a bitstream back into quantised latents.
///
/// Holds cumulative frequencies rather than reciprocals, because decoding needs
/// a search rather than a division: the stream gives a point in `[0, 1 <<
/// symbol_bits)` and the symbol is whichever interval contains it.
#[derive(Debug)]
pub struct Decoder {
    config: Config,
    descs: Vec<Distribution>,
    /// Cumulative frequencies, with a closing total per distribution so that
    /// every symbol can be read as a `[start, next)` pair without a bounds test
    /// in the hot loop.
    cdf: Vec<u32>,
}

impl Decoder {
    /// Build a decoder from the same tables the encoder was built from.
    ///
    /// # Errors
    ///
    /// As [`Encoder::new`].
    pub fn new(
        pmf_lengths: &[i32],
        pmf_offsets: &[i32],
        pmf_table: &[i32],
        symbol_bits: i32,
        bypass_bits: i32,
    ) -> Result<Self, Error> {
        let config = Config::new(symbol_bits, bypass_bits)?;
        let descs = distributions(pmf_lengths, pmf_offsets, pmf_table.len(), 1)?;

        let max_freq = 1i64 << config.symbol_bits;
        let mut cdf = vec![0u32; pmf_table.len() + descs.len()];
        let mut cursor = 0usize;

        for desc in &descs {
            let mut start = 0i64;
            let mut out = desc.table_offset;
            for _ in 0..=desc.bypass_sentinel {
                let freq = i64::from(pmf_table[cursor]);
                cursor += 1;
                if freq <= 0 || freq > max_freq - start {
                    return Err(Error::InvalidPmf);
                }
                cdf[out] = start as u32;
                out += 1;
                start += freq;
            }
            // The closing total. Without it the last symbol would have no upper
            // bound to subtract, and the search would need a special case.
            cdf[out] = start as u32;
        }

        Ok(Self { config, descs, cdf })
    }

    /// Decode one block from a complete bitstream.
    ///
    /// Requires the stream to be exactly consumed, which is the check that turns
    /// a corrupt frame into an error rather than into plausible-looking noise.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidStream`] if the stream is malformed, truncated, or has
    /// bytes left over; otherwise as [`Decoder::decode_from`].
    pub fn decode(&self, values: &mut [i32], indices: &[i32], stream: &[u8]) -> Result<(), Error> {
        let mut rans = RansDecoder::new(stream)?;
        self.decode_from(values, indices, &mut rans)?;
        if !rans.is_finished() {
            return Err(Error::InvalidStream);
        }
        Ok(())
    }

    /// Decode one block from a shared stream, leaving it open.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidParams`] if `values` and `indices` differ in length, and
    /// [`Error::InvalidStream`] for any stream that does not decode — including
    /// the cases the reference leaves undefined.
    pub fn decode_from(
        &self,
        values: &mut [i32],
        indices: &[i32],
        rans: &mut RansDecoder<'_>,
    ) -> Result<(), Error> {
        if values.len() != indices.len() {
            return Err(Error::InvalidParams);
        }
        if self.descs.is_empty() {
            return Err(Error::InvalidState);
        }
        let last = (self.descs.len() - 1) as i32;

        for (out, &index) in values.iter_mut().zip(indices) {
            if index < 0 {
                *out = 0;
                continue;
            }
            let desc = &self.descs[index.min(last) as usize];
            let base = desc.table_offset;
            let sentinel = desc.bypass_sentinel as usize;

            let point = rans.peek(self.config.symbol_bits);

            // This distribution's cumulative frequencies, taken as one slice so
            // that the loads below need no further bounds check: the length is
            // `sentinel + 2`, the search cannot return more than `sentinel`, and
            // the optimiser can see both facts.
            let window = &self.cdf[base..base + sentinel + 2];

            // Which interval contains `point`. The search covers entries 1
            // through `sentinel`; entry 0 is always zero and so always a
            // candidate, and running off the end lands on the sentinel, which is
            // correct — that is the interval carrying the tail mass.
            let symbol = window[1..=sentinel].partition_point(|&cf| cf <= point);

            let start = window[symbol];
            let end = window[symbol + 1];
            rans.advance(start, end - start, self.config.symbol_bits)?;

            if symbol == sentinel {
                let bypass = i64::from(self.decode_bypass(rans)?);
                let value = if bypass & 1 == 1 {
                    -(bypass >> 1) - 1
                } else {
                    (bypass >> 1) + sentinel as i64
                };
                // Checked, because a hostile stream can name a bypass value
                // whose latent does not fit in `i32`. The reference wraps and
                // returns it, which would put a nonsense sample into the model's
                // state and from there into the next frame.
                *out = i32::try_from(value - i64::from(desc.value_offset))
                    .map_err(|_| Error::InvalidStream)?;
            } else {
                // The common path, and `i32` throughout: the range every direct
                // symbol can produce was proven to fit when the tables were
                // accepted, so there is nothing left to check per symbol.
                *out = symbol as i32 - desc.value_offset;
            }
        }
        Ok(())
    }

    /// Read a bypass value: its digit count, then its digits.
    fn decode_bypass(&self, rans: &mut RansDecoder<'_>) -> Result<u32, Error> {
        let bits = self.config.bypass_bits;

        let mut digit = self.read_digit(rans)?;
        let mut count = digit;
        while digit == self.config.bypass_max {
            digit = self.read_digit(rans)?;
            count += digit;
            // The reference's own bound, kept because it is part of what a valid
            // stream may say.
            if count > u32::BITS {
                return Err(Error::InvalidStream);
            }
        }

        let mut value = 0u32;
        let mut shift = 0u32;
        // `count * bits` can exceed 32 for a stream that claims more digits than
        // a `u32` holds — the reference then shifts by more than the width of the
        // type, which is undefined. Bounding the shift is the fix, and no valid
        // stream reaches it: a real bypass value of 32 bits needs at most
        // `32 / bits` digits.
        let total = count * bits;
        while shift < total {
            if shift >= u32::BITS {
                return Err(Error::InvalidStream);
            }
            value |= self.read_digit(rans)? << shift;
            shift += bits;
        }
        Ok(value)
    }

    /// Read one uniform digit.
    fn read_digit(&self, rans: &mut RansDecoder<'_>) -> Result<u32, Error> {
        let digit = rans.peek(self.config.bypass_bits);
        rans.advance(digit, 1, self.config.bypass_bits)?;
        Ok(digit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small but non-trivial table: three distributions, different lengths,
    /// different zero points, frequencies summing to exactly the scale.
    fn tables() -> (Vec<i32>, Vec<i32>, Vec<i32>) {
        let symbol_scale = 1 << 16;
        // Distribution 0: 4 symbols (3 values + sentinel), zero at index 1.
        let d0 = [40000, 20000, 5000, symbol_scale - 65000];
        // Distribution 1: 6 symbols, zero at index 2.
        let d1 = [1000, 30000, 25000, 8000, 1000, symbol_scale - 65000];
        // Distribution 2: 2 symbols — the minimum: one value and the sentinel.
        let d2 = [60000, symbol_scale - 60000];

        let lengths = vec![d0.len() as i32, d1.len() as i32, d2.len() as i32];
        let offsets = vec![1, 2, 0];
        let mut table = Vec::new();
        table.extend_from_slice(&d0);
        table.extend_from_slice(&d1);
        table.extend_from_slice(&d2);
        (lengths, offsets, table)
    }

    fn coder() -> (Encoder, Decoder) {
        let (lengths, offsets, table) = tables();
        (
            Encoder::new(&lengths, &offsets, &table, 16, 2).expect("valid tables"),
            Decoder::new(&lengths, &offsets, &table, 16, 2).expect("valid tables"),
        )
    }

    fn round_trip(indices: &[i32], values: &[i32]) {
        let (encoder, decoder) = coder();
        let stream = encoder.encode(indices, values).expect("encodable");
        let mut decoded = vec![0i32; values.len()];
        decoder
            .decode(&mut decoded, indices, &stream)
            .expect("decodable");
        assert_eq!(decoded, values, "indices {indices:?}");
    }

    #[test]
    fn values_inside_every_distribution_round_trip() {
        // Distribution 0 has zero at index 1, so values -1, 0 are in range and
        // 1 is the sentinel. Distribution 1 has zero at 2: -2 through 2.
        round_trip(&[0, 0, 1, 1, 1, 2, 2], &[-1, 0, -2, 0, 1, 0, 0]);
    }

    #[test]
    fn a_value_past_the_sentinel_goes_through_bypass() {
        round_trip(&[0, 0, 0], &[7, 100, 30000]);
    }

    #[test]
    fn a_value_below_the_offset_goes_through_bypass() {
        round_trip(&[0, 1, 2], &[-9, -400, -70000]);
    }

    /// The sentinel index itself must take the bypass path.
    ///
    /// Easy to get wrong: the symbol exists in the table, so a `<=` where a `<`
    /// belongs encodes it directly and the decoder then reads a bypass value
    /// that was never written. The stream stays plausible and the frame is
    /// silently wrong, which is why this has its own test.
    #[test]
    fn the_sentinel_value_is_bypassed_not_coded_directly() {
        // Distribution 0: sentinel index is 3, zero at 1, so raw value 2.
        round_trip(&[0], &[2]);
    }

    #[test]
    fn a_negative_index_codes_nothing_and_decodes_to_zero() {
        let (encoder, decoder) = coder();
        let indices = [0, -1, 1, -1, 2];
        let values = [0, 0, 1, 0, 0];

        let stream = encoder.encode(&indices, &values).expect("encodable");
        let mut decoded = vec![99i32; values.len()];
        decoder
            .decode(&mut decoded, &indices, &stream)
            .expect("decodable");
        assert_eq!(decoded, values);

        // And it really costs nothing: the same three coded values with the
        // masked positions removed produce the same stream.
        let dense = encoder.encode(&[0, 1, 2], &[0, 1, 0]).expect("encodable");
        assert_eq!(stream, dense, "a masked position should occupy no bits");
    }

    #[test]
    fn an_index_past_the_end_is_clamped_to_the_last_distribution() {
        let (encoder, decoder) = coder();
        // Index 99 does not exist; both sides clamp to 2 and so still agree.
        let stream = encoder.encode(&[99], &[0]).expect("encodable");
        let mut decoded = [0i32];
        decoder
            .decode(&mut decoded, &[99], &stream)
            .expect("decodable");
        assert_eq!(decoded, [0]);
    }

    /// A long mixed run, which is what actually catches renormalisation bugs.
    #[test]
    fn a_long_mixed_run_round_trips() {
        let mut indices = Vec::new();
        let mut values = Vec::new();
        let mut state = 0x1234_5678u32;
        for i in 0..4000 {
            // xorshift, so the sequence is fixed but not patterned.
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;

            match i % 11 {
                0 => {
                    indices.push(-1);
                    values.push(0);
                }
                1 => {
                    // Occasional large residual, forcing bypass.
                    indices.push((state % 3) as i32);
                    values.push((state as i32) / 1000);
                }
                _ => {
                    indices.push((state % 3) as i32);
                    // Small values, mostly in range.
                    values.push((state % 5) as i32 - 2);
                }
            }
        }
        round_trip(&indices, &values);
    }

    #[test]
    fn several_blocks_share_one_stream_and_come_back_in_reverse() {
        let (encoder, decoder) = coder();

        let first = ([0i32, 1, 2], [0i32, 1, 0]);
        let second = ([1i32, 1], [-1i32, 2]);

        let mut rans = RansEncoder::new();
        encoder
            .encode_into(&mut rans, &first.0, &first.1)
            .expect("encodable");
        encoder
            .encode_into(&mut rans, &second.0, &second.1)
            .expect("encodable");
        let stream = rans.finish();

        // Encoded first, second; so decoded second, first.
        let mut rans = RansDecoder::new(&stream).expect("well formed");
        let mut got_second = [0i32; 2];
        decoder
            .decode_from(&mut got_second, &second.0, &mut rans)
            .expect("decodable");
        let mut got_first = [0i32; 3];
        decoder
            .decode_from(&mut got_first, &first.0, &mut rans)
            .expect("decodable");

        assert_eq!(got_second, second.1);
        assert_eq!(got_first, first.1);
        assert!(rans.is_finished());
    }

    #[test]
    fn one_flush_is_cheaper_than_two() {
        let (encoder, _) = coder();
        let block = ([0i32, 1, 2], [0i32, 1, 0]);

        let mut shared = RansEncoder::new();
        encoder
            .encode_into(&mut shared, &block.0, &block.1)
            .expect("encodable");
        encoder
            .encode_into(&mut shared, &block.0, &block.1)
            .expect("encodable");
        let shared = shared.finish();

        let separate = encoder.encode(&block.0, &block.1).expect("encodable").len()
            + encoder.encode(&block.0, &block.1).expect("encodable").len();

        assert!(
            shared.len() < separate,
            "sharing a stream should save a flush: {} vs {separate}",
            shared.len()
        );
    }

    // ----- table validation

    #[test]
    fn mismatched_table_lengths_are_refused() {
        let (lengths, _, table) = tables();
        assert!(matches!(
            Encoder::new(&lengths, &[1, 2], &table, 16, 2),
            Err(Error::InvalidPmf)
        ));
    }

    #[test]
    fn a_distribution_with_no_room_for_a_sentinel_is_refused() {
        assert!(matches!(
            Encoder::new(&[1], &[0], &[65536], 16, 2),
            Err(Error::InvalidPmf)
        ));
        assert!(matches!(
            Encoder::new(&[0], &[0], &[], 16, 2),
            Err(Error::InvalidPmf)
        ));
    }

    #[test]
    fn a_table_that_is_not_exactly_consumed_is_refused() {
        // Two symbols claimed, three supplied.
        assert!(matches!(
            Encoder::new(&[2], &[0], &[1000, 2000, 3000], 16, 2),
            Err(Error::InvalidPmf)
        ));
        // Three claimed, two supplied.
        assert!(matches!(
            Encoder::new(&[3], &[0], &[1000, 2000], 16, 2),
            Err(Error::InvalidPmf)
        ));
    }

    #[test]
    fn a_zero_or_negative_frequency_is_refused() {
        assert!(matches!(
            Encoder::new(&[2], &[0], &[0, 65536], 16, 2),
            Err(Error::InvalidPmf)
        ));
        assert!(matches!(
            Decoder::new(&[2], &[0], &[-5, 65536], 16, 2),
            Err(Error::InvalidPmf)
        ));
    }

    #[test]
    fn frequencies_summing_past_the_scale_are_refused() {
        assert!(matches!(
            Encoder::new(&[2], &[0], &[60000, 60000], 16, 2),
            Err(Error::InvalidPmf)
        ));
        assert!(matches!(
            Decoder::new(&[2], &[0], &[60000, 60000], 16, 2),
            Err(Error::InvalidPmf)
        ));
    }

    /// Frequencies summing to *less* than the scale are allowed.
    ///
    /// Surprising, and worth pinning: it means part of the code space maps to no
    /// symbol. The reference tolerates it, and a decoder handed such a point
    /// lands on the sentinel rather than reading out of bounds — so it stays
    /// well defined, just wasteful.
    #[test]
    fn frequencies_summing_below_the_scale_are_allowed() {
        let lengths = [2];
        let offsets = [0];
        let table = [1000, 1000];
        let encoder = Encoder::new(&lengths, &offsets, &table, 16, 2).expect("permitted");
        let decoder = Decoder::new(&lengths, &offsets, &table, 16, 2).expect("permitted");

        let stream = encoder.encode(&[0, 0], &[0, 0]).expect("encodable");
        let mut decoded = [9i32; 2];
        decoder
            .decode(&mut decoded, &[0, 0], &stream)
            .expect("decodable");
        assert_eq!(decoded, [0, 0]);
    }

    #[test]
    fn an_unusable_bit_width_is_refused() {
        let (lengths, offsets, table) = tables();
        // 24 through 30 are the range the reference nominally allows but cannot
        // decode; see MAX_SCALE_BITS.
        for bits in [-1, 0, 1, 24, 30, 31, 32, 64] {
            assert!(
                matches!(
                    Encoder::new(&lengths, &offsets, &table, bits, 2),
                    Err(Error::InvalidParams)
                ),
                "symbol_bits {bits} should be refused"
            );
            assert!(
                matches!(
                    Encoder::new(&lengths, &offsets, &table, 16, bits),
                    Err(Error::InvalidParams)
                ),
                "bypass_bits {bits} should be refused"
            );
        }
    }

    #[test]
    fn mismatched_input_lengths_are_refused() {
        let (encoder, decoder) = coder();
        assert!(matches!(
            encoder.encode(&[0, 1], &[0]),
            Err(Error::InvalidParams)
        ));
        let stream = encoder.encode(&[0], &[0]).expect("encodable");
        let mut decoded = [0i32; 2];
        assert!(matches!(
            decoder.decode(&mut decoded, &[0], &stream),
            Err(Error::InvalidParams)
        ));
    }

    // ----- hostile input

    #[test]
    fn a_truncated_stream_is_refused() {
        let (encoder, decoder) = coder();
        let indices = vec![0i32; 500];
        let values = vec![0i32; 500];
        let stream = encoder.encode(&indices, &values).expect("encodable");

        for cut in [1, 2, 3, 4, 8, stream.len() / 2, stream.len() - 1] {
            let mut decoded = vec![0i32; 500];
            assert!(
                decoder
                    .decode(&mut decoded, &indices, &stream[..cut])
                    .is_err(),
                "a stream cut to {cut} bytes should not decode"
            );
        }
    }

    #[test]
    fn a_stream_with_bytes_left_over_is_refused() {
        let (encoder, decoder) = coder();
        let mut stream = encoder.encode(&[0], &[0]).expect("encodable");
        stream.push(0);
        let mut decoded = [0i32; 1];
        assert!(matches!(
            decoder.decode(&mut decoded, &[0], &stream),
            Err(Error::InvalidStream)
        ));
    }

    /// Arbitrary bytes must produce an error or a value, never a panic.
    ///
    /// The property that matters for shipping this into a client: the stream
    /// comes from another participant, and under end-to-end encryption no relay
    /// has looked at it. The reference has real undefined behaviour on some of
    /// these inputs — a shift wider than the type, reachable by claiming more
    /// bypass digits than a `u32` can hold.
    #[test]
    fn arbitrary_bytes_never_panic() {
        let (_, decoder) = coder();
        let mut state = 0xdead_beefu32;

        for length in [4usize, 5, 6, 8, 16, 64, 256] {
            for _ in 0..200 {
                let stream: Vec<u8> = (0..length)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 17;
                        state ^= state << 5;
                        (state >> 7) as u8
                    })
                    .collect();

                for count in [1usize, 4, 64] {
                    let indices: Vec<i32> = (0..count).map(|i| (i % 3) as i32).collect();
                    let mut decoded = vec![0i32; count];
                    // Either outcome is fine. Not crashing is the test.
                    let _ = decoder.decode(&mut decoded, &indices, &stream);
                }
            }
        }
    }

    /// A stream that claims an impossible number of bypass digits.
    ///
    /// Constructed rather than stumbled upon, because this is precisely the
    /// input that makes the reference shift a `u32` by up to 62 bits.
    #[test]
    fn a_bypass_count_wider_than_the_value_is_refused() {
        let (_, decoder) = coder();

        // With bypass_bits = 2 the saturated digit is 3, and a run of them adds
        // three to the claimed digit count each time. Enough of them and the
        // count exceeds what a u32 can hold.
        let mut encoder = RansEncoder::new();
        // Encoder side, in decode order: sentinel symbol first, then a long run
        // of saturated count digits. Encoded in reverse of that.
        for _ in 0..20 {
            encoder.put(3, 1, 2);
        }
        // The sentinel of distribution 2, which is symbol index 1.
        let table_start = 60000;
        encoder.put(table_start, 65536 - table_start, 16);
        let stream = encoder.finish();

        let mut decoded = [0i32; 1];
        // Must report, not panic and not silently succeed.
        assert!(decoder.decode(&mut decoded, &[2], &stream).is_err());
    }
}
