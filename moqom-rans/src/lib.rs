//! rANS entropy coding for MLVC bitstreams.
//!
//! A port of Microsoft's `msrtc_rans` from C++ to Rust, bit-exact with the
//! reference for every stream either can produce. It is the CPU half of a
//! learned video codec: the neural network turns pixels into quantised latents
//! and a probability for each, and this turns those into bytes. Nothing here
//! knows anything about video.
//!
//! # Why this is a port and not a binding
//!
//! Normally you would not retype an entropy coder. One differing bit
//! desynchronises the decoder and every subsequent frame is garbage, so the
//! reference implementation is usually worth keeping whatever language it is in.
//!
//! What makes this case different is that the reference contains no floating
//! point. Not in the coder, not in the table construction — the probabilities
//! arrive already quantised to integers. Integer arithmetic is exactly specified
//! and identical in both languages, so a port that computes the same expressions
//! in the same order produces the same bytes by construction, with no libm
//! rounding, `-ffast-math`, or FMA contraction to argue about. The differential
//! tests against the reference then confirm it rather than hoping for it.
//!
//! Given that, Rust wins on the things that actually cost us:
//!
//! - **Hostile input.** The decoder parses bytes produced by another
//!   participant, and under end-to-end encryption no relay has been able to look
//!   at them. A bad index is a bounds check here and memory corruption there.
//!   The reference also has genuine undefined behaviour reachable from a
//!   malformed stream — a shift wider than its type, from a bypass length that
//!   claims more digits than a `u32` holds — which this rejects.
//! - **Portability.** The reference's 64-bit multiply-high is three
//!   `#if`-guarded implementations ending in `#error Unknown/unsupported
//!   compiler!`. This variant needs no such thing, and where the reference
//!   reinterprets a byte buffer as wider units — host-endian, and unaligned —
//!   this reads bytes.
//! - **One implementation.** The same crate serves the relay, the iOS and
//!   Android SDKs through a C ABI, and eventually WebAssembly. The C++ route
//!   needs a per-platform toolchain story, including an Android NDK C++ runtime
//!   choice that conflicts with other libraries in the same process.
//!
//! Speed is a wash and is not a reason to prefer either. Both go through LLVM,
//! and the hot loop is scalar integer work with a table lookup — the reference
//! contains no SIMD and no intrinsics beyond the multiply-high.
//!
//! # What is not here
//!
//! Only the `rans_byte` variant: a 32-bit state and byte-sized output units.
//! That is what MLVC's models construct, and byte units mean the format has no
//! endianness. The reference's 64-bit variant is not implemented, and its
//! parameter range is not fully usable anyway — at a 32-bit scale it shifts a
//! `u32` by 32 and by `-1`.
//!
//! Within this variant the usable scale stops at 23 bits, not the 30 the
//! reference advertises. Above 23 the reference produces streams it cannot
//! decode itself, so nothing is lost by refusing them; the reasoning is in the
//! `MAX_SCALE_BITS` note in the `rans` module. MLVC uses 16.
//!
//! # Usage
//!
//! Build the coders once from the model's tables and keep them; construction
//! precomputes a reciprocal per symbol, and MLVC's tables run to millions of
//! symbols.
//!
//! ```
//! use moqom_rans::{Decoder, Encoder};
//!
//! // Two distributions of three symbols each: two values and a sentinel.
//! let lengths = [3, 3];
//! let offsets = [1, 1];
//! let table = [30_000, 30_000, 5_536, 20_000, 40_000, 5_536];
//!
//! let encoder = Encoder::new(&lengths, &offsets, &table, 16, 2)?;
//! let decoder = Decoder::new(&lengths, &offsets, &table, 16, 2)?;
//!
//! // Which distribution each symbol is drawn from, and the values themselves.
//! let indices = [0, 1, 0, 1];
//! let values = [-1, 0, 0, -1];
//!
//! let stream = encoder.encode(&indices, &values)?;
//!
//! let mut decoded = [0i32; 4];
//! decoder.decode(&mut decoded, &indices, &stream)?;
//! assert_eq!(decoded, values);
//! # Ok::<(), moqom_rans::Error>(())
//! ```

#![forbid(unsafe_code)]
// The workspace already allows `cast_possible_truncation` for the wire codec, on
// the grounds that a codec is mostly deliberate numeric conversion with locally
// proven bounds and that the lint buries the real findings. That reasoning
// applies here more than anywhere: the whole crate exists to reproduce one
// specific sequence of integer operations, and every conversion in it sits
// directly below the validation that bounds it. Sign loss is only ever reachable
// through a `usize` cast of a value the preceding line has established is not
// negative.
#![allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
// `start`, `state`, `stream`, `scale`; `value`, `values`; `descs`, `cdf`. This is
// the reference's vocabulary, and renaming for the linter would make the port
// harder to read against the C++ it has to match.
#![allow(clippy::similar_names)]

mod coder;
mod rans;

pub use coder::{Decoder, Encoder};
pub use rans::{EncSymbol, RansDecoder, RansEncoder};

/// What can go wrong.
///
/// The distinction that matters operationally is between the first three, which
/// mean this build is misconfigured and no stream will ever decode, and
/// [`Error::InvalidStream`], which means one frame from one participant was bad
/// and the room should carry on without it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Probability tables whose shape or frequencies are inconsistent.
    #[error("probability tables are inconsistent")]
    InvalidPmf,

    /// A parameter outside the range this variant can represent.
    #[error("parameter outside the supported range")]
    InvalidParams,

    /// A coder used before it holds usable tables.
    #[error("coder has no distributions")]
    InvalidState,

    /// A bitstream that does not correspond to any encoding.
    ///
    /// Covers truncation, trailing bytes, a state outside the normalisation
    /// interval, and the malformed-bypass cases the reference leaves undefined.
    /// Deliberately one variant: telling a caller *how* a hostile stream was
    /// wrong invites treating some kinds as recoverable, and none of them are.
    #[error("bitstream is malformed")]
    InvalidStream,

    /// A value whose bypass form does not fit in 32 bits.
    ///
    /// Cannot arise from a model's latents; it means a caller supplied something
    /// that could not have been decoded back, so it is refused rather than
    /// written.
    #[error("value cannot be represented")]
    ValueOutOfRange,
}
