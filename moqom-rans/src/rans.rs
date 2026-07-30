//! Raw rANS primitives: state, renormalisation, and symbol coding.
//!
//! A direct port of the `rans_byte` variant in `msrtc_rans/rans.h`, which is the
//! only variant MLVC's models construct. Every expression here is integer, so
//! "port" means what it sounds like: the same arithmetic in the same order
//! produces the same bytes, on every target, with no rounding to argue about.
//! That is the entire reason this could be moved to Rust at all — see the crate
//! documentation.
//!
//! # The one thing to understand before editing
//!
//! rANS is last-in first-out. The encoder consumes symbols in reverse and emits
//! bytes from the end of the buffer backwards; the decoder reads forwards and
//! recovers symbols in the original order. So the order of `put` calls in the
//! encoder is the *reverse* of the order of `advance` calls in the decoder, and
//! any change to one has to be mirrored backwards in the other. Nothing here
//! will catch that mistake for you except the round-trip tests.
//!
//! # Why the state is a `u32` that never exceeds 31 bits
//!
//! The variant is defined by two numbers: a 32-bit state of which only 31 bits
//! are used, and 8-bit output units. The unused top bit is not waste — the
//! reciprocal of an `n`-bit integer needs `n + 1` bits, so giving up one bit of
//! state is what allows division by a symbol frequency to be a multiply.

use crate::Error;

/// Bits of the state actually used. One short of 32, deliberately; see above.
const STATE_BITS: u32 = 31;

/// Bits emitted per output unit. Bytes, which is why this format has no
/// endianness: the reference reinterprets its buffer as an array of units, so a
/// wider unit would serialise in host order. With `u8` there is nothing to
/// disagree about.
const UNIT_BITS: u32 = 8;

/// Largest `scale_bits` any distribution may use.
///
/// The reference computes `min(STATE_BITS - 1, 32)`, which is 30 here, and that
/// is too high to work. rANS requires the scale to divide the lower bound of the
/// normalisation interval — `M | l`, in the paper's notation — because the
/// renormalisation threshold is `freq * (l / M) * 2^UNIT_BITS` and that
/// expression is only a valid threshold when `l / M` is a whole number. With
/// `l = 1 << 23` the scale therefore cannot exceed 23 bits.
///
/// Above it the coder does not fail loudly; it produces streams that neither
/// implementation can decode. Encoding a low-frequency symbol renormalises the
/// state down past the interval, the update leaves it there, and the flushed
/// state no longer describes anything. The reference's own round trip breaks at
/// `symbol_bits = 24` for exactly this reason — verified, not deduced.
///
/// This is the one place the port deliberately accepts less than the reference
/// claims to, and it costs nothing: every stream in the range being refused is
/// one the reference could not have decoded either. MLVC uses 16.
///
/// Strictly, the bound is conservative rather than tight. A table above it whose
/// every frequency is at least `1 << (scale_bits - 23)` would still work, since
/// the threshold only degenerates for small frequencies. Enforcing the tight
/// version would mean a validity rule that depends on every entry in the table,
/// and a configuration that silently produces undecodable output for some tables
/// and not others is worse than one that is simply unavailable.
pub(crate) const MAX_SCALE_BITS: u32 = STATE_BITS - UNIT_BITS;

/// Lower bound of the normalisation interval — `l` in Duda's paper.
///
/// The state is kept in `[LOWER_BOUND, LOWER_BOUND << UNIT_BITS)`. Both coders
/// start here, and a decoder that ends anywhere else has been fed a stream that
/// does not correspond to any encoding.
const LOWER_BOUND: u32 = 1 << (STATE_BITS - UNIT_BITS);

/// A symbol with its division-by-frequency precomputed.
///
/// Building one costs two 64-bit divisions; using one costs a multiply. Since a
/// frame encodes hundreds of thousands of symbols drawn from a few thousand
/// distributions, the table is built once at initialisation and the hot loop
/// never divides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncSymbol {
    /// Renormalisation threshold, pre-shifted.
    x_max: u32,
    /// Fixed-point reciprocal of the frequency.
    freq_rcp: u32,
    /// Right shift that turns the reciprocal product into a quotient.
    freq_rcp_shift: u32,
    /// `scale - freq`, which is what the substituted update actually needs.
    freq_cmpl: u32,
    /// `start`, except for the `freq == 1` case that folds a correction in.
    bias: u32,
}

impl EncSymbol {
    /// Precompute the symbol occupying `[start, start + freq)` of `1 << scale_bits`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPmf`] if the range does not fit the scale, and
    /// [`Error::InvalidParams`] for a scale this variant cannot represent.
    /// Rejecting rather than asserting is the point: these bounds are what keep
    /// every later operation inside 31 bits, so a caller that violates them must
    /// not get a symbol back.
    pub fn new(start: u32, freq: u32, scale_bits: u32) -> Result<Self, Error> {
        if !(2..=MAX_SCALE_BITS).contains(&scale_bits) {
            return Err(Error::InvalidParams);
        }
        let scale = 1u32 << scale_bits;
        if freq == 0 || start >= scale || freq > scale - start {
            return Err(Error::InvalidPmf);
        }

        // High bits of the renormalisation threshold. The reference stores this
        // shifted by `31 - scale_bits` and restores the low bits at use time for
        // the 64-bit variant; for this one the stored value is already final.
        let x_max = freq << (STATE_BITS - scale_bits);

        // The plain encoder update is
        //   x = (x / freq) * scale + start + (x % freq)
        // and the fast one substitutes the remainder away to
        //   x = x + (x / freq) * (scale - freq) + start
        // which needs only a quotient. Alverson's reciprocal supplies that.
        let (freq_rcp, mut freq_rcp_shift, bias) = if freq > 1 {
            // shift = ceil(log2(freq))
            let mut shift = 1u32;
            while freq > (1u32 << shift) {
                shift += 1;
            }
            // ((1 << (shift + 31)) + freq - 1) / freq, rounded up so the
            // quotient is never short by one.
            let nominator = (1u64 << (shift + STATE_BITS)) + u64::from(freq) - 1;
            (
                u32::try_from(nominator / u64::from(freq)).map_err(|_| Error::InvalidPmf)?,
                shift - 1,
                start,
            )
        } else {
            // freq == 1 has no useful reciprocal, since 1/1 is 1 and the
            // multiply would be a no-op. The next best thing is `~0`, for which
            // `mul_hi(x, ~0) == x - 1` whenever `x >= 1`, and the bias absorbs
            // the resulting off-by-one: with bias = start + scale - 1 the
            // update collapses to `x * scale + start`, which is what a symbol of
            // frequency one should cost.
            (u32::MAX, 0, start + scale - 1)
        };

        // The quotient is taken from the high half of a 64-bit product, so the
        // shift has to skip that half. The 64-bit variant uses a widening
        // multiply-high instead and omits this.
        freq_rcp_shift += 32;

        Ok(Self {
            x_max,
            freq_rcp,
            freq_rcp_shift,
            freq_cmpl: scale - freq,
            bias,
        })
    }
}

/// rANS encoder over a growable byte buffer.
///
/// Bytes are pushed in emission order and reversed once at [`finish`]. The
/// reference instead writes backwards into a buffer it reallocates and copies
/// when it runs out of room; the result is identical, and this way the buffer
/// grows by the ordinary amortised doubling rather than by a hand-rolled scheme.
///
/// [`finish`]: Self::finish
#[derive(Debug)]
pub struct RansEncoder {
    state: u32,
    /// Emission order, so the last byte pushed is the first byte of the output.
    emitted: Vec<u8>,
}

impl Default for RansEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RansEncoder {
    /// A fresh encoder with the state at the bottom of the normalisation interval.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: LOWER_BOUND,
            emitted: Vec::new(),
        }
    }

    /// A fresh encoder with room for `capacity` bytes of output reserved.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            state: LOWER_BOUND,
            emitted: Vec::with_capacity(capacity),
        }
    }

    /// Bytes emitted so far, not counting the state still held in registers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.emitted.len()
    }

    /// Whether nothing has been emitted yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.emitted.is_empty()
    }

    /// Push output units until the state is low enough to absorb a symbol.
    fn renormalise(&mut self, x_max: u32) {
        while self.state >= x_max {
            self.emitted.push(self.state as u8);
            self.state >>= UNIT_BITS;
        }
    }

    /// Encode a precomputed symbol.
    pub fn put_symbol(&mut self, symbol: &EncSymbol) {
        self.renormalise(symbol.x_max);

        // Quotient via the high half of a 64-bit product. The narrowing cast is
        // exact: the shift has already discarded everything above 32 bits.
        let quotient =
            ((u64::from(self.state) * u64::from(symbol.freq_rcp)) >> symbol.freq_rcp_shift) as u32;

        // Cannot exceed 31 bits, because `EncSymbol::new` rejected any symbol
        // with `start + freq > scale`, and that is exactly the condition that
        // bounds this sum. Wrapping is used anyway so that a future change to
        // that validation degrades to wrong output rather than to a panic in a
        // client that is decoding someone else's stream.
        self.state = self
            .state
            .wrapping_add(quotient.wrapping_mul(symbol.freq_cmpl))
            .wrapping_add(symbol.bias);
    }

    /// Encode a symbol without a precomputed reciprocal, using a division.
    ///
    /// Used for bypass digits, which are uniform — every digit has frequency
    /// one, so there are only `1 << bypass_bits` distinct symbols and building a
    /// table for them would cost more than the occasional divide.
    ///
    /// # Panics
    ///
    /// Never for `start + freq <= 1 << scale_bits` with `scale_bits` in range,
    /// which every caller in this crate satisfies by construction.
    pub fn put(&mut self, start: u32, freq: u32, scale_bits: u32) {
        debug_assert!((2..=MAX_SCALE_BITS).contains(&scale_bits));
        debug_assert!(freq > 0 && start < (1 << scale_bits) && freq <= (1 << scale_bits) - start);

        self.renormalise(freq << (STATE_BITS - scale_bits));
        self.state = ((self.state / freq) << scale_bits) + start + (self.state % freq);
    }

    /// Flush the state and return the stream.
    ///
    /// The four state bytes are emitted most significant first, which — because
    /// the output is reversed — puts the least significant first in the stream,
    /// matching the order [`RansDecoder::new`] reads them back.
    #[must_use]
    pub fn finish(mut self) -> Vec<u8> {
        for i in (1..(u32::BITS / UNIT_BITS)).rev() {
            self.emitted.push((self.state >> (i * UNIT_BITS)) as u8);
        }
        self.emitted.push(self.state as u8);
        self.emitted.reverse();
        self.emitted
    }
}

/// rANS decoder over a borrowed stream.
///
/// Borrowed rather than owned so that a caller can decode straight out of a
/// received buffer without a copy, which for video is the difference between
/// nothing and a memcpy per frame.
#[derive(Debug)]
pub struct RansDecoder<'a> {
    state: u32,
    stream: &'a [u8],
    cursor: usize,
}

impl<'a> RansDecoder<'a> {
    /// Open a stream, consuming the four bytes of initial state.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidStream`] if the stream is too short, or if the recovered
    /// state is outside the normalisation interval.
    ///
    /// The upper check is hardening the reference does not do. A state at or
    /// above 31 bits cannot be produced by any encoding, and rejecting it here
    /// is what keeps every later multiply inside 32 bits — the reference instead
    /// carries on and relies on unsigned wraparound.
    pub fn new(stream: &'a [u8]) -> Result<Self, Error> {
        let units = (u32::BITS / UNIT_BITS) as usize;
        if stream.len() < units {
            return Err(Error::InvalidStream);
        }

        let mut state = 0u32;
        for (i, &unit) in stream[..units].iter().enumerate() {
            state |= u32::from(unit) << (i as u32 * UNIT_BITS);
        }
        if !(LOWER_BOUND..(1 << STATE_BITS)).contains(&state) {
            return Err(Error::InvalidStream);
        }

        Ok(Self {
            state,
            stream,
            cursor: units,
        })
    }

    /// The scaled cumulative frequency of the next symbol, without consuming it.
    ///
    /// Returned rather than resolved because only the caller knows which
    /// distribution to look it up in.
    #[must_use]
    pub fn peek(&self, scale_bits: u32) -> u32 {
        debug_assert!((2..=MAX_SCALE_BITS).contains(&scale_bits));
        self.state & ((1 << scale_bits) - 1)
    }

    /// Consume the symbol occupying `[start, start + freq)`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidStream`] if renormalisation runs off the end of the
    /// stream, which is how a truncated or fabricated bitstream shows up.
    pub fn advance(&mut self, start: u32, freq: u32, scale_bits: u32) -> Result<(), Error> {
        debug_assert!((2..=MAX_SCALE_BITS).contains(&scale_bits));
        debug_assert!(freq > 0);

        let scale = 1u32 << scale_bits;
        let value = self.state & (scale - 1);

        // `value >= start` holds because the caller found `start` by searching
        // for the last cumulative frequency not exceeding `value`. Wrapping
        // matches the reference's unsigned arithmetic exactly, so a stream that
        // somehow violates it produces the same nonsense here as there — and
        // then fails the end-of-stream check — instead of panicking.
        self.state = freq
            .wrapping_mul(self.state >> scale_bits)
            .wrapping_add(value)
            .wrapping_sub(start);

        while self.state < LOWER_BOUND {
            let &unit = self.stream.get(self.cursor).ok_or(Error::InvalidStream)?;
            self.cursor += 1;
            self.state = (self.state << UNIT_BITS) | u32::from(unit);
        }
        Ok(())
    }

    /// Whether every byte has been consumed and the state has returned to rest.
    ///
    /// Both halves matter. A stream with bytes left over decoded fewer symbols
    /// than it contains, and a state that is not exactly at the lower bound
    /// decoded a different sequence than was encoded. Either means the caller
    /// and the producer disagree about the shape of the data, which for a video
    /// frame is worth rejecting rather than rendering.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.cursor == self.stream.len() && self.state == LOWER_BOUND
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published constants for this variant, spelled out.
    ///
    /// Not a tautology: these four numbers define the wire format, and a stream
    /// written with a different lower bound decodes to garbage rather than to an
    /// error. Pinning them means a well-meaning edit to `STATE_BITS` fails here
    /// instead of in the field.
    #[test]
    fn the_variant_constants_are_the_rans_byte_ones() {
        assert_eq!(STATE_BITS, 31);
        assert_eq!(UNIT_BITS, 8);
        assert_eq!(LOWER_BOUND, 1 << 23);
        // The scale must divide the lower bound; see the constant's own note.
        assert_eq!(MAX_SCALE_BITS, 23);
        assert_eq!(LOWER_BOUND % (1 << MAX_SCALE_BITS), 0);
    }

    /// The state stays inside the normalisation interval at the largest scale.
    ///
    /// This is the property that fails above [`MAX_SCALE_BITS`], and it fails
    /// silently — so check it directly rather than trusting the round trip,
    /// which would also pass for a coder that happened to be wrong in both
    /// directions. The worst case is the lowest possible frequency, since that
    /// is what renormalises the state furthest down.
    #[test]
    fn the_state_stays_in_the_interval_at_the_largest_usable_scale() {
        for scale_bits in 2..=MAX_SCALE_BITS {
            let symbol = EncSymbol::new(0, 1, scale_bits).expect("a valid symbol");
            let mut encoder = RansEncoder::new();
            for _ in 0..64 {
                encoder.put_symbol(&symbol);
                assert!(
                    encoder.state >= LOWER_BOUND && encoder.state < (1 << STATE_BITS),
                    "scale_bits {scale_bits}: state {} left the interval",
                    encoder.state
                );
            }
        }
    }

    #[test]
    fn a_symbol_of_frequency_one_gets_the_corrected_bias() {
        let symbol = EncSymbol::new(5, 1, 16).expect("a valid symbol");
        assert_eq!(symbol.freq_rcp, u32::MAX);
        assert_eq!(symbol.freq_rcp_shift, 32);
        assert_eq!(symbol.bias, 5 + (1 << 16) - 1);
    }

    /// The reciprocal has to be exact for every frequency, not nearly exact.
    ///
    /// A quotient one too low silently shifts the symbol's interval, and the
    /// decoder then recovers a neighbouring symbol — visible as corruption
    /// rather than as an error. So this checks the reciprocal against real
    /// division across the whole state range for each frequency, which is the
    /// property the Alverson construction is supposed to guarantee.
    #[test]
    fn the_reciprocal_agrees_with_division_over_the_state_range() {
        for freq in [1u32, 2, 3, 5, 7, 255, 256, 1000, 4095, 4096, 65535, 65536] {
            let scale_bits = 16;
            if freq > (1 << scale_bits) {
                continue;
            }
            let symbol = EncSymbol::new(0, freq, scale_bits).expect("a valid symbol");
            if freq == 1 {
                continue; // handled by its own bias, checked above
            }

            let x_max = freq << (STATE_BITS - scale_bits);
            for x in [
                LOWER_BOUND,
                LOWER_BOUND + 1,
                x_max / 2,
                x_max.saturating_sub(2),
                x_max - 1,
            ] {
                if x < LOWER_BOUND || x >= x_max {
                    continue;
                }
                let quotient =
                    ((u64::from(x) * u64::from(symbol.freq_rcp)) >> symbol.freq_rcp_shift) as u32;
                assert_eq!(quotient, x / freq, "freq {freq}, x {x}");
            }
        }
    }

    /// Scales the algorithm cannot carry are refused, including the range the
    /// reference nominally allows but cannot actually code.
    #[test]
    fn a_scale_this_variant_cannot_represent_is_refused() {
        for scale_bits in [0, 1, 24, 25, 30, 31, 32, 64] {
            assert!(
                matches!(EncSymbol::new(0, 1, scale_bits), Err(Error::InvalidParams)),
                "scale_bits {scale_bits} should be refused"
            );
        }
        assert!(EncSymbol::new(0, 1, 23).is_ok());
    }

    #[test]
    fn a_symbol_that_overflows_its_scale_is_refused() {
        assert!(matches!(
            EncSymbol::new(1 << 15, (1 << 15) + 1, 16),
            Err(Error::InvalidPmf)
        ));
        assert!(matches!(EncSymbol::new(0, 0, 16), Err(Error::InvalidPmf)));
    }

    /// Encode a known symbol sequence and decode it back.
    ///
    /// Deliberately uses a skewed distribution: a uniform one exercises none of
    /// the renormalisation edges, because every symbol costs the same number of
    /// bits and the state never approaches its bounds unevenly.
    #[test]
    fn a_sequence_round_trips_through_a_skewed_distribution() {
        let scale_bits = 16;
        // Frequencies summing to exactly 1 << 16, heavily skewed.
        let freqs = [60000u32, 5000, 400, 100, 36];
        let mut starts = [0u32; 5];
        let mut cumulative = 0;
        for (i, &freq) in freqs.iter().enumerate() {
            starts[i] = cumulative;
            cumulative += freq;
        }
        assert_eq!(cumulative, 1 << scale_bits);

        let symbols: Vec<EncSymbol> = freqs
            .iter()
            .zip(starts.iter())
            .map(|(&freq, &start)| EncSymbol::new(start, freq, scale_bits).expect("valid"))
            .collect();

        let sequence = [0usize, 0, 1, 4, 2, 0, 3, 0, 0, 1, 4, 4, 2, 0];

        let mut encoder = RansEncoder::new();
        for &index in sequence.iter().rev() {
            encoder.put_symbol(&symbols[index]);
        }
        let stream = encoder.finish();

        let mut decoder = RansDecoder::new(&stream).expect("a well-formed stream");
        let mut decoded = Vec::new();
        for _ in 0..sequence.len() {
            let cumulative_freq = decoder.peek(scale_bits);
            let index = starts
                .iter()
                .rposition(|&start| start <= cumulative_freq)
                .expect("a symbol covering every cumulative frequency");
            decoder
                .advance(starts[index], freqs[index], scale_bits)
                .expect("a stream long enough for the sequence");
            decoded.push(index);
        }

        assert_eq!(decoded, sequence);
        assert!(
            decoder.is_finished(),
            "state and stream should both be spent"
        );
    }

    #[test]
    fn a_stream_shorter_than_the_state_is_refused() {
        assert!(matches!(RansDecoder::new(&[]), Err(Error::InvalidStream)));
        assert!(matches!(
            RansDecoder::new(&[1, 2, 3]),
            Err(Error::InvalidStream)
        ));
    }

    #[test]
    fn a_state_outside_the_normalisation_interval_is_refused() {
        // Below the lower bound.
        assert!(matches!(
            RansDecoder::new(&[0, 0, 0, 0]),
            Err(Error::InvalidStream)
        ));
        // At or above 31 bits, which no encoding can produce.
        assert!(matches!(
            RansDecoder::new(&[0, 0, 0, 0x80]),
            Err(Error::InvalidStream)
        ));
    }

    /// A truncated stream must report, not panic.
    ///
    /// This is the case that motivated the port: the bytes come from another
    /// participant, and under end-to-end encryption the relay cannot have
    /// checked them.
    #[test]
    fn a_truncated_stream_reports_rather_than_reading_past_the_end() {
        let symbol = EncSymbol::new(0, 1000, 16).expect("valid");
        let mut encoder = RansEncoder::new();
        for _ in 0..64 {
            encoder.put_symbol(&symbol);
        }
        let stream = encoder.finish();

        let truncated = &stream[..stream.len() / 2];
        let mut decoder = RansDecoder::new(truncated).expect("a plausible header");
        let mut error = None;
        for _ in 0..64 {
            if let Err(e) = decoder.advance(0, 1000, 16) {
                error = Some(e);
                break;
            }
        }
        assert!(matches!(error, Some(Error::InvalidStream)));
    }
}
