//! C ABI for [`moqom_rans`], so Swift and Kotlin can call it.
//!
//! A separate crate for one reason: `moqom-rans` declares `forbid(unsafe_code)`
//! and that is worth keeping literally true. Reconstructing a slice from a
//! caller's pointer and length is unavoidably unsafe, so it lives here, where the
//! unsafe surface is small enough to read in one sitting and consists entirely of
//! the same two operations.
//!
//! # The contract
//!
//! Every pointer is borrowed for the duration of the call and never retained.
//! Buffers are caller-owned; nothing here allocates on the caller's behalf except
//! the two coder handles, which are freed explicitly. That makes the Swift side a
//! `final class` with a `deinit` and no lifetime cleverness.
//!
//! Errors are negative return values rather than out-parameters, because a Swift
//! wrapper turns them into a thrown error and an out-parameter would just be a
//! second thing to check.
//!
//! # Panics
//!
//! The decoder is not supposed to panic on any input — that is most of why the
//! coder was ported — and 19 million fuzzed inputs support it. Even so, every
//! entry point catches unwinding and converts it to [`STATUS_PANIC`], because the
//! alternative on a client is terminating someone's app because another
//! participant sent a bad frame. Under a `panic = "abort"` profile the catch
//! cannot fire, which is a reason to build the client library with unwinding.

// The entire purpose of this crate. Confined to `slice_from` and `slice_mut_from`
// below, which every entry point goes through rather than dereferencing directly.
#![allow(unsafe_code)]

use std::panic::{AssertUnwindSafe, catch_unwind};

use moqom_rans::{Decoder, Encoder, Error};

/// Success.
pub const STATUS_OK: i32 = 0;
/// A required pointer was null.
pub const STATUS_NULL: i32 = -1;
/// Probability tables were inconsistent.
pub const STATUS_INVALID_PMF: i32 = -2;
/// A parameter was outside the supported range.
pub const STATUS_INVALID_PARAMS: i32 = -3;
/// The coder held no usable tables.
pub const STATUS_INVALID_STATE: i32 = -4;
/// The bitstream did not correspond to any encoding.
pub const STATUS_INVALID_STREAM: i32 = -5;
/// A value could not be represented.
pub const STATUS_VALUE_OUT_OF_RANGE: i32 = -6;
/// The caller's output buffer was too small.
pub const STATUS_BUFFER_TOO_SMALL: i32 = -7;
/// A panic was caught at the boundary. Always a bug in this library.
pub const STATUS_PANIC: i32 = -8;

// The catch-all repeats `InvalidParams`'s body, which clippy reads as a mistake. It
// is load-bearing: `Error` is `non_exhaustive`, and collapsing the two would mean a
// variant added upstream stops compiling here instead of degrading to a status a C
// caller can already handle.
#[allow(clippy::match_same_arms)]
fn status_of(error: Error) -> i32 {
    match error {
        Error::InvalidPmf => STATUS_INVALID_PMF,
        Error::InvalidParams => STATUS_INVALID_PARAMS,
        Error::InvalidState => STATUS_INVALID_STATE,
        Error::InvalidStream => STATUS_INVALID_STREAM,
        Error::ValueOutOfRange => STATUS_VALUE_OUT_OF_RANGE,
        _ => STATUS_INVALID_PARAMS,
    }
}

/// A human-readable description of a status, for logs and test failures.
///
/// Returns a static, NUL-terminated string that the caller must not free. Static
/// rather than allocated so there is no matching free function to get wrong.
#[unsafe(no_mangle)]
pub extern "C" fn moqom_rans_status_message(status: i32) -> *const std::ffi::c_char {
    let text: &'static str = match status {
        STATUS_OK => "ok\0",
        STATUS_NULL => "a required pointer was null\0",
        STATUS_INVALID_PMF => "probability tables are inconsistent\0",
        STATUS_INVALID_PARAMS => "parameter outside the supported range\0",
        STATUS_INVALID_STATE => "coder has no distributions\0",
        STATUS_INVALID_STREAM => "bitstream is malformed\0",
        STATUS_VALUE_OUT_OF_RANGE => "value cannot be represented\0",
        STATUS_BUFFER_TOO_SMALL => "output buffer is too small\0",
        STATUS_PANIC => "internal error\0",
        _ => "unknown status\0",
    };
    text.as_ptr().cast()
}

/// Borrow a caller's array as a slice.
///
/// # Safety
///
/// `ptr` must point to `len` initialised `T` for the duration of the call, or
/// `len` must be zero. A null pointer with a zero length is accepted and yields
/// an empty slice, because a caller with nothing to encode should not have to
/// invent an address — and because `from_raw_parts` on null is undefined even at
/// length zero, so it must be handled rather than passed through.
unsafe fn slice_from<'a, T>(ptr: *const T, len: usize) -> Option<&'a [T]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Borrow a caller's array as a mutable slice.
///
/// # Safety
///
/// As [`slice_from`], and additionally `ptr` must not alias anything else the
/// call touches. Callers pass a distinct output array; the encode and decode
/// entry points never write through a pointer they also read.
unsafe fn slice_mut_from<'a, T>(ptr: *mut T, len: usize) -> Option<&'a mut [T]> {
    if len == 0 {
        return Some(&mut []);
    }
    if ptr.is_null() {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts_mut(ptr, len) })
}

/// Run `body`, converting a panic into [`STATUS_PANIC`].
fn guarded(body: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(STATUS_PANIC)
}

/// Opaque encoder handle.
pub struct MoqomRansEncoder(Encoder);

/// Opaque decoder handle.
pub struct MoqomRansDecoder(Decoder);

/// Build an encoder from a model's quantised probability tables.
///
/// Writes the handle to `out` and returns [`STATUS_OK`], or leaves `out` untouched
/// and returns a negative status.
///
/// # Safety
///
/// The three table pointers must be valid for their stated lengths, and `out`
/// must be a valid place to write one pointer. Tables are copied into the
/// encoder, so the caller may free them as soon as this returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_rans_encoder_new(
    pmf_lengths: *const i32,
    pmf_offsets: *const i32,
    distributions: usize,
    pmf_table: *const i32,
    table_len: usize,
    symbol_bits: i32,
    bypass_bits: i32,
    out: *mut *mut MoqomRansEncoder,
) -> i32 {
    guarded(|| {
        if out.is_null() {
            return STATUS_NULL;
        }
        let tables = unsafe {
            (
                slice_from(pmf_lengths, distributions),
                slice_from(pmf_offsets, distributions),
                slice_from(pmf_table, table_len),
            )
        };
        let (Some(lengths), Some(offsets), Some(table)) = tables else {
            return STATUS_NULL;
        };

        match Encoder::new(lengths, offsets, table, symbol_bits, bypass_bits) {
            Ok(encoder) => {
                let handle = Box::into_raw(Box::new(MoqomRansEncoder(encoder)));
                unsafe { out.write(handle) };
                STATUS_OK
            }
            Err(e) => status_of(e),
        }
    })
}

/// Release an encoder. Null is accepted and ignored.
///
/// # Safety
///
/// `encoder` must have come from [`moqom_rans_encoder_new`] and must not have
/// been freed already.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_rans_encoder_free(encoder: *mut MoqomRansEncoder) {
    if !encoder.is_null() {
        drop(unsafe { Box::from_raw(encoder) });
    }
}

/// Upper bound on the bytes [`moqom_rans_encode`] can produce for `count` symbols.
///
/// Exists so a caller can size a buffer once and reuse it, rather than retrying
/// after [`STATUS_BUFFER_TOO_SMALL`]. Generous on purpose: the worst case is every
/// symbol taking the bypass path, which spends its digits plus a length, and four
/// bytes of flushed state on top.
#[unsafe(no_mangle)]
pub extern "C" fn moqom_rans_encode_bound(count: usize) -> usize {
    // Sixteen bypass digits and a length, at two bits each, is at most five bytes
    // per symbol; eight is comfortable and still linear.
    count.saturating_mul(8).saturating_add(64)
}

/// Encode `count` values into `out`.
///
/// Returns the number of bytes written, or a negative status. A caller that wants
/// to size `out` exactly can call [`moqom_rans_encode_bound`] first.
///
/// # Safety
///
/// `encoder` must be live. `indices` and `values` must each be valid for `count`
/// elements, and `out` for `out_capacity` bytes, and `out` must not overlap them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_rans_encode(
    encoder: *const MoqomRansEncoder,
    indices: *const i32,
    values: *const i32,
    count: usize,
    out: *mut u8,
    out_capacity: usize,
) -> i64 {
    let status = guarded(|| {
        let handle = unsafe { encoder.as_ref() };
        let Some(encoder) = handle else {
            return STATUS_NULL;
        };
        let borrowed = unsafe {
            (
                slice_from(indices, count),
                slice_from(values, count),
                slice_mut_from(out, out_capacity),
            )
        };
        let (Some(indices), Some(values), Some(out)) = borrowed else {
            return STATUS_NULL;
        };

        match encoder.0.encode(indices, values) {
            Ok(stream) => {
                if stream.len() > out.len() {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                out[..stream.len()].copy_from_slice(&stream);
                // Positive, so the caller reads it as a length. Bounded by
                // `out_capacity`, so it cannot collide with a status.
                i32::try_from(stream.len()).unwrap_or(i32::MAX)
            }
            Err(e) => status_of(e),
        }
    });

    // Widened only here, so the guarded body can keep returning `i32` like every
    // other entry point. A length above `i32::MAX` is not reachable: a stream
    // that long would need a quarter of a billion symbols in one call.
    i64::from(status)
}

/// Build a decoder from the same tables the encoder was built from.
///
/// # Safety
///
/// As [`moqom_rans_encoder_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_rans_decoder_new(
    pmf_lengths: *const i32,
    pmf_offsets: *const i32,
    distributions: usize,
    pmf_table: *const i32,
    table_len: usize,
    symbol_bits: i32,
    bypass_bits: i32,
    out: *mut *mut MoqomRansDecoder,
) -> i32 {
    guarded(|| {
        if out.is_null() {
            return STATUS_NULL;
        }
        let tables = unsafe {
            (
                slice_from(pmf_lengths, distributions),
                slice_from(pmf_offsets, distributions),
                slice_from(pmf_table, table_len),
            )
        };
        let (Some(lengths), Some(offsets), Some(table)) = tables else {
            return STATUS_NULL;
        };

        match Decoder::new(lengths, offsets, table, symbol_bits, bypass_bits) {
            Ok(decoder) => {
                let handle = Box::into_raw(Box::new(MoqomRansDecoder(decoder)));
                unsafe { out.write(handle) };
                STATUS_OK
            }
            Err(e) => status_of(e),
        }
    })
}

/// Release a decoder. Null is accepted and ignored.
///
/// # Safety
///
/// `decoder` must have come from [`moqom_rans_decoder_new`] and must not have
/// been freed already.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_rans_decoder_free(decoder: *mut MoqomRansDecoder) {
    if !decoder.is_null() {
        drop(unsafe { Box::from_raw(decoder) });
    }
}

/// Decode `count` values from `stream` into `values`.
///
/// The stream must be exactly consumed; a truncated one, or one with bytes left
/// over, is [`STATUS_INVALID_STREAM`]. On any error `values` may have been
/// partially written and should be treated as meaningless rather than as a
/// partial result.
///
/// # Safety
///
/// `decoder` must be live. `values` must be valid for `count` writable elements,
/// `indices` for `count` readable ones, and `stream` for `stream_len` bytes;
/// `values` must not overlap the others.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_rans_decode(
    decoder: *const MoqomRansDecoder,
    values: *mut i32,
    indices: *const i32,
    count: usize,
    stream: *const u8,
    stream_len: usize,
) -> i32 {
    guarded(|| {
        let handle = unsafe { decoder.as_ref() };
        let Some(decoder) = handle else {
            return STATUS_NULL;
        };
        let borrowed = unsafe {
            (
                slice_mut_from(values, count),
                slice_from(indices, count),
                slice_from(stream, stream_len),
            )
        };
        let (Some(values), Some(indices), Some(stream)) = borrowed else {
            return STATUS_NULL;
        };

        match decoder.0.decode(values, indices, stream) {
            Ok(()) => STATUS_OK,
            Err(e) => status_of(e),
        }
    })
}

#[cfg(test)]
// These tests speak C's vocabulary: counts arrive as the signed integers the ABI
// declares and are indexed with after a check, and `values`/`decoded` sit beside
// each other in a round trip because that is what a round trip compares.
#[allow(clippy::cast_sign_loss, clippy::similar_names)]
mod tests {
    use super::*;

    /// Tables with two distributions of three symbols, as in the crate docs.
    const LENGTHS: [i32; 2] = [3, 3];
    const OFFSETS: [i32; 2] = [1, 1];
    const TABLE: [i32; 6] = [30_000, 30_000, 5_536, 20_000, 40_000, 5_536];

    fn encoder() -> *mut MoqomRansEncoder {
        let mut handle = std::ptr::null_mut();
        let status = unsafe {
            moqom_rans_encoder_new(
                LENGTHS.as_ptr(),
                OFFSETS.as_ptr(),
                LENGTHS.len(),
                TABLE.as_ptr(),
                TABLE.len(),
                16,
                2,
                &raw mut handle,
            )
        };
        assert_eq!(status, STATUS_OK);
        assert!(!handle.is_null());
        handle
    }

    fn decoder() -> *mut MoqomRansDecoder {
        let mut handle = std::ptr::null_mut();
        let status = unsafe {
            moqom_rans_decoder_new(
                LENGTHS.as_ptr(),
                OFFSETS.as_ptr(),
                LENGTHS.len(),
                TABLE.as_ptr(),
                TABLE.len(),
                16,
                2,
                &raw mut handle,
            )
        };
        assert_eq!(status, STATUS_OK);
        handle
    }

    #[test]
    fn a_round_trip_across_the_boundary() {
        let encoder = encoder();
        let decoder = decoder();

        let indices = [0i32, 1, 0, 1, 0];
        let values = [-1i32, 0, 0, -1, 7];

        let mut buffer = vec![0u8; moqom_rans_encode_bound(indices.len())];
        let written = unsafe {
            moqom_rans_encode(
                encoder,
                indices.as_ptr(),
                values.as_ptr(),
                indices.len(),
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };
        assert!(written > 0, "status {written}");
        let written = written as usize;

        let mut decoded = vec![0i32; values.len()];
        let status = unsafe {
            moqom_rans_decode(
                decoder,
                decoded.as_mut_ptr(),
                indices.as_ptr(),
                indices.len(),
                buffer.as_ptr(),
                written,
            )
        };
        assert_eq!(status, STATUS_OK, "status {status}");
        assert_eq!(decoded, values);

        unsafe {
            moqom_rans_encoder_free(encoder);
            moqom_rans_decoder_free(decoder);
        }
    }

    /// The bound has to actually bound, or a caller sizing a buffer from it will
    /// see spurious failures on the frames that bypass most.
    #[test]
    fn the_encode_bound_holds_for_all_bypass() {
        let encoder = encoder();
        // Every value far outside its distribution, so every one takes bypass.
        let count = 512;
        let indices: Vec<i32> = (0..count).map(|i| i % 2).collect();
        let values: Vec<i32> = (0..count).map(|i| 1_000_000 + i * 7919).collect();

        let mut buffer = vec![0u8; moqom_rans_encode_bound(count as usize)];
        let written = unsafe {
            moqom_rans_encode(
                encoder,
                indices.as_ptr(),
                values.as_ptr(),
                count as usize,
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };
        assert!(written > 0, "status {written}");
        unsafe { moqom_rans_encoder_free(encoder) };
    }

    #[test]
    fn a_short_buffer_is_reported_rather_than_overrun() {
        let encoder = encoder();
        let indices = [0i32; 64];
        let values = [0i32; 64];
        let mut buffer = [0u8; 2];
        let written = unsafe {
            moqom_rans_encode(
                encoder,
                indices.as_ptr(),
                values.as_ptr(),
                indices.len(),
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };
        assert_eq!(written, i64::from(STATUS_BUFFER_TOO_SMALL));
        unsafe { moqom_rans_encoder_free(encoder) };
    }

    #[test]
    fn null_pointers_are_reported_rather_than_dereferenced() {
        let mut handle = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                moqom_rans_encoder_new(
                    std::ptr::null(),
                    OFFSETS.as_ptr(),
                    LENGTHS.len(),
                    TABLE.as_ptr(),
                    TABLE.len(),
                    16,
                    2,
                    &raw mut handle,
                )
            },
            STATUS_NULL
        );

        // A null output pointer, which would otherwise be written through.
        assert_eq!(
            unsafe {
                moqom_rans_encoder_new(
                    LENGTHS.as_ptr(),
                    OFFSETS.as_ptr(),
                    LENGTHS.len(),
                    TABLE.as_ptr(),
                    TABLE.len(),
                    16,
                    2,
                    std::ptr::null_mut(),
                )
            },
            STATUS_NULL
        );

        // A null coder handle.
        assert_eq!(
            unsafe {
                moqom_rans_decode(
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                )
            },
            STATUS_NULL
        );
    }

    /// Freeing null must be safe, because a Swift `deinit` will do it after a
    /// failed initialiser.
    #[test]
    fn freeing_null_is_harmless() {
        unsafe {
            moqom_rans_encoder_free(std::ptr::null_mut());
            moqom_rans_decoder_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn a_malformed_stream_is_reported() {
        let decoder = decoder();
        let indices = [0i32, 1, 0];
        let mut decoded = [0i32; 3];
        let stream = [0xffu8; 6];
        let status = unsafe {
            moqom_rans_decode(
                decoder,
                decoded.as_mut_ptr(),
                indices.as_ptr(),
                indices.len(),
                stream.as_ptr(),
                stream.len(),
            )
        };
        assert_eq!(status, STATUS_INVALID_STREAM);
        unsafe { moqom_rans_decoder_free(decoder) };
    }

    #[test]
    fn every_status_has_a_message() {
        for status in [
            STATUS_OK,
            STATUS_NULL,
            STATUS_INVALID_PMF,
            STATUS_INVALID_PARAMS,
            STATUS_INVALID_STATE,
            STATUS_INVALID_STREAM,
            STATUS_VALUE_OUT_OF_RANGE,
            STATUS_BUFFER_TOO_SMALL,
            STATUS_PANIC,
        ] {
            let message = moqom_rans_status_message(status);
            assert!(!message.is_null());
            let text = unsafe { std::ffi::CStr::from_ptr(message) }
                .to_str()
                .expect("utf-8");
            assert!(!text.is_empty(), "status {status} has an empty message");
            assert_ne!(text, "unknown status", "status {status} has no message");
        }
    }
}
