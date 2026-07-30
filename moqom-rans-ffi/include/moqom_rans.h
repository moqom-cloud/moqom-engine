// rANS entropy coding for MLVC bitstreams.
//
// Hand-written rather than generated, because the API is nine functions and a
// generator would be a build dependency plus a step to forget. The Rust side is
// moqom-rans-ffi/src/lib.rs; if you change one, change both, and the round-trip
// test there will not catch a mismatched signature — the linker will, loudly.
//
// Threading: a coder is immutable once built and holds no per-call state, so one
// handle may be shared across threads and used concurrently. Freeing is not
// concurrent with use.
//
// Lifetimes: every pointer is borrowed for the duration of the call and never
// retained. Tables are copied into the coder, so they may be freed as soon as the
// constructor returns.

#ifndef MOQOM_RANS_H
#define MOQOM_RANS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Status codes. Zero is success and everything else is negative, so a function
// returning a length can return a status in the same value.
#define MOQOM_RANS_OK 0
#define MOQOM_RANS_NULL (-1)
#define MOQOM_RANS_INVALID_PMF (-2)
#define MOQOM_RANS_INVALID_PARAMS (-3)
#define MOQOM_RANS_INVALID_STATE (-4)
#define MOQOM_RANS_INVALID_STREAM (-5)
#define MOQOM_RANS_VALUE_OUT_OF_RANGE (-6)
#define MOQOM_RANS_BUFFER_TOO_SMALL (-7)
#define MOQOM_RANS_PANIC (-8)

typedef struct MoqomRansEncoder MoqomRansEncoder;
typedef struct MoqomRansDecoder MoqomRansDecoder;

// A static description of a status. Never null; must not be freed.
const char *moqom_rans_status_message(int32_t status);

// Build an encoder from a model's quantised probability tables.
//
// `pmf_lengths` and `pmf_offsets` each hold `distributions` entries: how many
// symbols each distribution has, and where zero sits within it. `pmf_table` holds
// every distribution's frequencies concatenated, and its length must equal the sum
// of the lengths exactly.
//
// The last symbol of each distribution is the bypass sentinel rather than a value,
// so a length of two means one codeable value. `symbol_bits` and `bypass_bits` are
// the scales the tables were quantised against; MLVC uses 16 and 2. They are part
// of the format, so a decoder built with different ones will not read this stream.
//
// Writes the handle to `*out` and returns MOQOM_RANS_OK, or returns a negative
// status and leaves `*out` untouched.
int32_t moqom_rans_encoder_new(const int32_t *pmf_lengths,
                               const int32_t *pmf_offsets,
                               size_t distributions,
                               const int32_t *pmf_table,
                               size_t table_len,
                               int32_t symbol_bits,
                               int32_t bypass_bits,
                               MoqomRansEncoder **out);

// Release an encoder. Null is accepted and ignored.
void moqom_rans_encoder_free(MoqomRansEncoder *encoder);

// An upper bound on the bytes `moqom_rans_encode` can produce for `count`
// symbols, so a buffer can be sized once and reused rather than grown on failure.
size_t moqom_rans_encode_bound(size_t count);

// Encode `count` values into `out`.
//
// `indices` says which distribution each value is drawn from. A negative index
// means the position was masked out by the model: it costs no bits and decodes
// back to zero.
//
// Returns the number of bytes written, or a negative status. In particular
// MOQOM_RANS_BUFFER_TOO_SMALL if `out_capacity` was insufficient — nothing is
// written in that case.
int64_t moqom_rans_encode(const MoqomRansEncoder *encoder,
                          const int32_t *indices,
                          const int32_t *values,
                          size_t count,
                          uint8_t *out,
                          size_t out_capacity);

// Build a decoder from the same tables the encoder was built from.
int32_t moqom_rans_decoder_new(const int32_t *pmf_lengths,
                               const int32_t *pmf_offsets,
                               size_t distributions,
                               const int32_t *pmf_table,
                               size_t table_len,
                               int32_t symbol_bits,
                               int32_t bypass_bits,
                               MoqomRansDecoder **out);

// Release a decoder. Null is accepted and ignored.
void moqom_rans_decoder_free(MoqomRansDecoder *decoder);

// Decode `count` values from `stream` into `values`.
//
// The stream must be exactly consumed: truncated, or with bytes left over, is
// MOQOM_RANS_INVALID_STREAM. On any error `values` may have been partly written,
// and should be discarded rather than treated as a partial result.
//
// This is the function that parses bytes from another participant, on the device
// of someone who only joined to watch. It is designed to be safe to call on
// arbitrary input: malformed streams are reported, never acted on.
int32_t moqom_rans_decode(const MoqomRansDecoder *decoder,
                          int32_t *values,
                          const int32_t *indices,
                          size_t count,
                          const uint8_t *stream,
                          size_t stream_len);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // MOQOM_RANS_H
