// Direct (peer-to-peer) QUIC paths for the client SDKs, from Rust.
//
// The narrow half of the direct path: one UDP socket that does STUN, sends NAT
// probes, and carries QUIC, all from the same port. Network.framework cannot
// share a port between a QUIC listener and plain UDP flows without the flows
// stealing the listener's packets, so the Swift SDK's own backend can only probe
// in a short burst. This one probes for as long as an establishment lasts.
//
// Everything above QUIC stays in the SDK that links this: MOQT SETUP, peer
// verification, admission, and the merging of relay and direct paths. This
// library hands back a mutually authenticated, certificate-pinned QUIC
// connection and its streams, and nothing more.
//
// Hand-written rather than generated, like moqom_rans.h. The Rust side is
// moqom-direct-ffi/src/lib.rs; change both together.
//
// THREADING. Every function may be called from any thread. Asynchronous
// operations take a callback and an opaque `context`; the callback is invoked
// exactly once, on a thread owned by this library, and possibly before the
// starting function has returned. A callback must not block for long and must
// not call `*_free` on the handle whose operation it is completing.
//
// LIFETIMES. Pointers passed in are borrowed for the duration of the call and
// never retained; data to write is copied before the call returns. Pointers
// passed to a callback (bytes, messages) are valid only until the callback
// returns. Handles are owned by the caller and released with their `*_free`.
//
// CANCELLATION. Freeing a handle, or closing an endpoint or connection,
// completes every operation still pending on it with MOQOM_DIRECT_CANCELLED or
// MOQOM_DIRECT_CLOSED. A callback for a pending operation can therefore still
// arrive after `*_free` has returned; keep `context` alive until it does.
//
// PANICS. A panic inside the library is caught at the boundary and reported as
// MOQOM_DIRECT_PANIC rather than unwinding into the caller.

#ifndef MOQOM_DIRECT_H
#define MOQOM_DIRECT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// The version of this interface. Bumped on any incompatible change; the SDK
// checks it before using anything else.
#define MOQOM_DIRECT_ABI_VERSION 1

// Status codes. Zero is success, MOQOM_DIRECT_END marks the end of a stream,
// and every failure is negative.
#define MOQOM_DIRECT_OK 0
#define MOQOM_DIRECT_END 1
#define MOQOM_DIRECT_NULL (-1)        // a required pointer was null
#define MOQOM_DIRECT_INVALID (-2)     // an argument was out of range or malformed
#define MOQOM_DIRECT_IO (-3)          // the socket failed: bind, send, receive
#define MOQOM_DIRECT_TLS (-4)         // certificate generation or TLS setup failed
#define MOQOM_DIRECT_TIMEOUT (-5)     // the operation's deadline passed
#define MOQOM_DIRECT_HANDSHAKE (-6)   // every candidate failed the QUIC handshake
#define MOQOM_DIRECT_CLOSED (-7)      // the connection or endpoint closed
#define MOQOM_DIRECT_RESET (-8)       // the peer reset the stream; see `code`
#define MOQOM_DIRECT_STOPPED (-9)     // the peer stopped reading; see `code`
#define MOQOM_DIRECT_CANCELLED (-10)  // the handle was freed or closed first
#define MOQOM_DIRECT_UNSUPPORTED (-11)// e.g. a datagram where the peer allows none
#define MOQOM_DIRECT_TOO_LARGE (-12)  // a datagram larger than the path carries
#define MOQOM_DIRECT_BUSY (-13)       // an establishment is already under way
#define MOQOM_DIRECT_NOT_FOUND (-14)  // nothing to report, e.g. no STUN answer
#define MOQOM_DIRECT_PANIC (-15)      // a bug in the library, caught at the boundary

typedef struct MoqomDirectEndpoint MoqomDirectEndpoint;
typedef struct MoqomDirectConnection MoqomDirectConnection;
typedef struct MoqomDirectSendStream MoqomDirectSendStream;
typedef struct MoqomDirectRecvStream MoqomDirectRecvStream;

// A UDP address. `family` is 4 or 6; for IPv4 only the first four bytes of
// `address` are used. Network byte order throughout, as the bytes appear on the
// wire; `port` is a host-order integer.
typedef struct MoqomDirectAddress {
    uint8_t family;
    uint8_t address[16];
    uint16_t port;
} MoqomDirectAddress;

// How to bind an endpoint.
typedef struct MoqomDirectEndpointConfig {
    // The UDP port to bind on every interface. Zero picks one.
    uint16_t port;
    // The single ALPN to offer and accept, e.g. "moqt-19". Required.
    const char *alpn;
    // How long a connection may be silent before it is declared dead. Keep-alives
    // go out at a third of this, which also keeps both NAT mappings open.
    uint32_t idle_timeout_ms;
    // Whether to offer QUIC datagrams. A peer that offers none gets none.
    uint8_t datagrams;
    // A STUN server to ask for this socket's public address, from the same
    // socket, during bind. Null for none. A name is resolved; a server that does
    // not answer within `stun_timeout_ms` is not an error.
    const char *stun_host;
    uint16_t stun_port;
    uint32_t stun_timeout_ms;
} MoqomDirectEndpointConfig;

// A static description of a status. Never null; must not be freed.
const char *moqom_direct_status_message(int32_t status);

// MOQOM_DIRECT_ABI_VERSION as this library was built.
uint32_t moqom_direct_abi_version(void);

// ---------------------------------------------------------------------------
// Endpoints: one socket, one certificate, one peer.

typedef void (*moqom_direct_endpoint_callback)(void *context, int32_t status,
                                               MoqomDirectEndpoint *endpoint,
                                               const char *message);

// Bind a socket, generate a self-signed certificate, and ask the STUN server if
// one is configured. On success the callback receives a new endpoint the caller
// owns; on failure, a null endpoint and a message.
void moqom_direct_endpoint_bind(const MoqomDirectEndpointConfig *config, void *context,
                                moqom_direct_endpoint_callback callback);

// The bound port, never zero.
uint16_t moqom_direct_endpoint_port(const MoqomDirectEndpoint *endpoint);

// This endpoint's DER leaf certificate, borrowed for the endpoint's lifetime.
// The SDK offers its SHA-256 to the peer and names it in proofs of possession.
int32_t moqom_direct_endpoint_certificate(const MoqomDirectEndpoint *endpoint,
                                          const uint8_t **der, size_t *length);

// The public address the STUN server reported during bind.
// MOQOM_DIRECT_NOT_FOUND if none was configured or none answered.
int32_t moqom_direct_endpoint_reflexive(const MoqomDirectEndpoint *endpoint,
                                        MoqomDirectAddress *out);

// Send a small probe to every candidate from the endpoint's own socket every
// `interval_ms`, until moqom_direct_endpoint_punch_stop or the endpoint closes.
// Starting again replaces the targets. The probe is the four bytes "MQDP",
// which QUIC discards.
int32_t moqom_direct_endpoint_punch_start(MoqomDirectEndpoint *endpoint,
                                          const MoqomDirectAddress *candidates, size_t count,
                                          uint32_t interval_ms);
void moqom_direct_endpoint_punch_stop(MoqomDirectEndpoint *endpoint);

typedef void (*moqom_direct_connection_callback)(void *context, int32_t status,
                                                 MoqomDirectConnection *connection,
                                                 const char *message);

// Dial every candidate at once. The first handshake to complete with a peer
// presenting the certificate whose SHA-256 is `pin` wins, and the rest are
// abandoned. Fails with MOQOM_DIRECT_TIMEOUT after `timeout_ms`, or
// MOQOM_DIRECT_HANDSHAKE if every candidate failed first. TLS is mutual: this
// endpoint presents its own certificate.
void moqom_direct_endpoint_dial(MoqomDirectEndpoint *endpoint,
                                const MoqomDirectAddress *candidates, size_t count,
                                const uint8_t pin[32], uint32_t timeout_ms, void *context,
                                moqom_direct_connection_callback callback);

// Wait for the peer presenting the certificate whose SHA-256 is `pin` to
// connect. Handshakes from anyone else fail and are ignored; the wait goes on.
// Fails with MOQOM_DIRECT_TIMEOUT after `timeout_ms`. The endpoint accepts
// nothing outside this call.
void moqom_direct_endpoint_accept(MoqomDirectEndpoint *endpoint, const uint8_t pin[32],
                                  uint32_t timeout_ms, void *context,
                                  moqom_direct_connection_callback callback);

// Stop probing, refuse new connections, and complete pending dials and accepts
// with MOQOM_DIRECT_CANCELLED. Connections already returned are unaffected.
void moqom_direct_endpoint_close(MoqomDirectEndpoint *endpoint);

// Close (as above) and release. Null is accepted and ignored.
void moqom_direct_endpoint_free(MoqomDirectEndpoint *endpoint);

// ---------------------------------------------------------------------------
// Connections.

// The negotiated ALPN, NUL-terminated, borrowed for the connection's lifetime.
const char *moqom_direct_connection_alpn(const MoqomDirectConnection *connection);

// SHA-256 of the peer's DER leaf certificate.
int32_t moqom_direct_connection_peer_certificate(const MoqomDirectConnection *connection,
                                                 uint8_t out[32]);

// The largest datagram payload the path carries now, or zero if the peer
// allows none.
size_t moqom_direct_connection_max_datagram_size(const MoqomDirectConnection *connection);

// The address the peer is reached at.
int32_t moqom_direct_connection_remote(const MoqomDirectConnection *connection,
                                       MoqomDirectAddress *out);

typedef void (*moqom_direct_bi_callback)(void *context, int32_t status,
                                         MoqomDirectSendStream *send,
                                         MoqomDirectRecvStream *recv);
typedef void (*moqom_direct_uni_send_callback)(void *context, int32_t status,
                                               MoqomDirectSendStream *send);
typedef void (*moqom_direct_uni_recv_callback)(void *context, int32_t status,
                                               MoqomDirectRecvStream *recv);

// Open a stream. Completes once flow control allows it.
void moqom_direct_connection_open_bi(MoqomDirectConnection *connection, void *context,
                                     moqom_direct_bi_callback callback);
void moqom_direct_connection_open_uni(MoqomDirectConnection *connection, void *context,
                                      moqom_direct_uni_send_callback callback);

// The next stream the peer opened. Call again for the one after. Completes
// with MOQOM_DIRECT_CLOSED once the connection is gone.
void moqom_direct_connection_accept_bi(MoqomDirectConnection *connection, void *context,
                                       moqom_direct_bi_callback callback);
void moqom_direct_connection_accept_uni(MoqomDirectConnection *connection, void *context,
                                        moqom_direct_uni_recv_callback callback);

// Send a datagram now, or fail: MOQOM_DIRECT_UNSUPPORTED, MOQOM_DIRECT_TOO_LARGE
// or MOQOM_DIRECT_CLOSED. Datagrams are unreliable, so there is no completion.
int32_t moqom_direct_connection_send_datagram(MoqomDirectConnection *connection,
                                              const uint8_t *data, size_t length);

typedef void (*moqom_direct_bytes_callback)(void *context, int32_t status,
                                            const uint8_t *data, size_t length,
                                            uint64_t code);

// The next datagram. Call again for the one after.
void moqom_direct_connection_read_datagram(MoqomDirectConnection *connection, void *context,
                                           moqom_direct_bytes_callback callback);

typedef void (*moqom_direct_closed_callback)(void *context, int32_t status, uint64_t code,
                                             const char *reason);

// Completes once, when the connection ends for any reason, including
// moqom_direct_connection_close. `status` is MOQOM_DIRECT_CLOSED with the
// application `code` and `reason` if either side closed it, MOQOM_DIRECT_TIMEOUT
// if it went idle, or MOQOM_DIRECT_IO for anything else.
void moqom_direct_connection_closed(MoqomDirectConnection *connection, void *context,
                                    moqom_direct_closed_callback callback);

// Close with an application error code and a reason, immediately.
void moqom_direct_connection_close(MoqomDirectConnection *connection, uint64_t code,
                                   const char *reason);

// Release the handle. The connection closes, with code 0, when this and every
// stream handle from it are released. Null is accepted and ignored.
void moqom_direct_connection_free(MoqomDirectConnection *connection);

// ---------------------------------------------------------------------------
// Streams.

typedef void (*moqom_direct_status_callback)(void *context, int32_t status, uint64_t code);

// Write all of `data`, copied before this returns. Completes once flow control
// has taken it, or with MOQOM_DIRECT_STOPPED and the peer's code.
void moqom_direct_send_write(MoqomDirectSendStream *stream, const uint8_t *data, size_t length,
                             void *context, moqom_direct_status_callback callback);

// End the stream cleanly after what has been written.
int32_t moqom_direct_send_finish(MoqomDirectSendStream *stream);

// Abandon the stream; the peer sees a reset with `code`.
int32_t moqom_direct_send_reset(MoqomDirectSendStream *stream, uint64_t code);

void moqom_direct_send_free(MoqomDirectSendStream *stream);

// Up to `max_length` of the next bytes. The callback receives MOQOM_DIRECT_OK
// with data, MOQOM_DIRECT_END with none at the end of the stream, or
// MOQOM_DIRECT_RESET with the peer's code.
void moqom_direct_recv_read(MoqomDirectRecvStream *stream, size_t max_length, void *context,
                            moqom_direct_bytes_callback callback);

// Tell the peer to stop sending, with `code`.
int32_t moqom_direct_recv_stop(MoqomDirectRecvStream *stream, uint64_t code);

void moqom_direct_recv_free(MoqomDirectRecvStream *stream);

#ifdef __cplusplus
}
#endif

#endif
