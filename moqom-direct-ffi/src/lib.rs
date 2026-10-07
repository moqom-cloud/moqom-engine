//! C ABI for [`moqom_client::direct::socket`], so the Swift SDK can use it.
//!
//! The Swift SDK's own direct path is built on Network.framework, which cannot
//! share one UDP port between a QUIC listener and plain UDP flows: a flow to
//! the peer's address takes the listener's packets. So it can only send NAT
//! probes in a short burst before it starts listening. The Rust socket does
//! STUN, probing, and QUIC on one port for as long as an establishment takes,
//! and this crate hands exactly that layer across: bind and STUN, probing,
//! pinned mutual-TLS dial and accept, streams, and datagrams. MOQT SETUP, peer
//! verification, and admission stay in Swift, which already has them.
//!
//! The header is `include/moqom_direct.h`, written by hand and authoritative.
//! Its comments are the contract; this file implements it.
//!
//! # How an asynchronous call works
//!
//! The library owns one multi-threaded Tokio runtime, created on first use and
//! never shut down, so a callback can always still arrive. Every asynchronous
//! entry point validates its arguments, then spawns a task that awaits the
//! operation and invokes the callback exactly once. Arguments that fail
//! validation invoke the callback at once, before the entry point returns.
//!
//! "Exactly once" holds under panics too. The callback travels inside a
//! [`Once`], which fires [`STATUS_PANIC`] if it is dropped unfired, and a
//! panicking task drops everything it holds.
//!
//! # Cancellation
//!
//! Every handle owns a [`watch`] sender that its pending operations select
//! against. Closing an endpoint sets it; freeing any handle drops it, which
//! the receivers see the same way. So freeing is cancellation, with no
//! registry of pending operations to keep in step.
//!
//! Streams are served by one task each, fed through a queue, so writes and
//! reads complete in the order they were issued even when the caller does not
//! wait for one before issuing the next. Finishing goes through the same
//! queue, after the writes before it; resetting and stopping act at once.
//!
//! # Lifetimes the header leaves to the implementation
//!
//! - A successful [`moqom_direct_endpoint_bind`] or dial or accept passes a
//!   null `message`.
//! - Freeing an endpoint does not close connections it produced: QUIC keeps
//!   the socket alive until the last of them ends.
//! - A dial can succeed with a connection that closes at once. In TLS 1.3 the
//!   client completes its handshake before the server has checked the
//!   client's certificate, so a peer pinning some other certificate refuses
//!   the dialler only after the dial has returned. The SDK's SETUP over the
//!   connection fails on the close, as it would on any other.
//! - Datagrams off is off both ways: quinn sends none from a connection that
//!   offered none, and reports a maximum datagram size of zero for it.
//! - Freeing a send stream with writes still pending cancels them and resets
//!   the stream with code 0, so the peer never sees a truncated stream as a
//!   complete one. A send stream freed with nothing pending and never finished
//!   is finished, as QUIC does on drop.
//!
//! # Panics
//!
//! Every entry point catches unwinding and converts it to [`STATUS_PANIC`],
//! for the same reason as `moqom-rans-ffi`: terminating someone's app is the
//! worst available outcome. That needs a build with `panic = "unwind"`, which
//! `build-apple.sh` sets.

// The entire purpose of this crate: borrowing the caller's pointers and handing
// out raw handles. Each dereference is next to the null check that guards it.
#![allow(unsafe_code)]

use std::borrow::Cow;
use std::convert::Infallible;
use std::ffi::{CStr, CString, c_char, c_void};
use std::fmt::Display;
use std::future::{Future, poll_fn};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use moqom_client::Error;
use moqom_client::direct::socket::{DirectSocket, SocketConfig, StunServer};
use quinn::VarInt;
use tokio::sync::{mpsc, watch};

/// `MOQOM_DIRECT_ABI_VERSION`.
pub const ABI_VERSION: u32 = 1;

/// Success.
pub const STATUS_OK: i32 = 0;
/// The end of a stream.
pub const STATUS_END: i32 = 1;
/// A required pointer was null.
pub const STATUS_NULL: i32 = -1;
/// An argument was out of range or malformed.
pub const STATUS_INVALID: i32 = -2;
/// The socket failed: bind, send, receive.
pub const STATUS_IO: i32 = -3;
/// Certificate generation or TLS setup failed.
pub const STATUS_TLS: i32 = -4;
/// The operation's deadline passed.
pub const STATUS_TIMEOUT: i32 = -5;
/// Every candidate failed the QUIC handshake.
pub const STATUS_HANDSHAKE: i32 = -6;
/// The connection or endpoint closed.
pub const STATUS_CLOSED: i32 = -7;
/// The peer reset the stream.
pub const STATUS_RESET: i32 = -8;
/// The peer stopped reading.
pub const STATUS_STOPPED: i32 = -9;
/// The handle was freed or closed first.
pub const STATUS_CANCELLED: i32 = -10;
/// A datagram where the peer allows none.
pub const STATUS_UNSUPPORTED: i32 = -11;
/// A datagram larger than the path carries.
pub const STATUS_TOO_LARGE: i32 = -12;
/// An establishment is already under way.
pub const STATUS_BUSY: i32 = -13;
/// Nothing to report.
pub const STATUS_NOT_FOUND: i32 = -14;
/// A panic was caught at the boundary. Always a bug in this library.
pub const STATUS_PANIC: i32 = -15;

/// The most a single read allocates, whatever the caller asks for. A Swift
/// caller passing `Int.max` should get a large read, not an abort.
const MAX_READ: usize = 1 << 20;

/// Each status's description, NUL-terminated so the C side can borrow it.
fn status_text(status: i32) -> &'static str {
    match status {
        STATUS_OK => "ok\0",
        STATUS_END => "end of stream\0",
        STATUS_NULL => "a required pointer was null\0",
        STATUS_INVALID => "an argument was out of range or malformed\0",
        STATUS_IO => "the socket failed\0",
        STATUS_TLS => "certificate generation or TLS setup failed\0",
        STATUS_TIMEOUT => "the deadline passed\0",
        STATUS_HANDSHAKE => "every candidate failed the QUIC handshake\0",
        STATUS_CLOSED => "the connection or endpoint closed\0",
        STATUS_RESET => "the peer reset the stream\0",
        STATUS_STOPPED => "the peer stopped reading\0",
        STATUS_CANCELLED => "the handle was freed or closed first\0",
        STATUS_UNSUPPORTED => "the peer does not accept this\0",
        STATUS_TOO_LARGE => "the datagram is larger than the path carries\0",
        STATUS_BUSY => "an establishment is already under way\0",
        STATUS_NOT_FOUND => "nothing to report\0",
        STATUS_PANIC => "internal error\0",
        _ => "unknown status\0",
    }
}

/// A static description of a status. Never null; must not be freed.
#[unsafe(no_mangle)]
pub extern "C" fn moqom_direct_status_message(status: i32) -> *const c_char {
    status_text(status).as_ptr().cast()
}

/// [`ABI_VERSION`] as this library was built.
#[unsafe(no_mangle)]
pub extern "C" fn moqom_direct_abi_version() -> u32 {
    ABI_VERSION
}

// ---------------------------------------------------------------------------
// The machinery every entry point shares.

/// The runtime every task and QUIC endpoint runs on.
///
/// Two workers: a phone has one or two direct connections at a time, and each
/// is mostly waiting. Never shut down, so a pending callback always arrives.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("moqom-direct")
            .enable_all()
            .build()
            .expect("the direct-path runtime could not start")
    })
}

/// The caller's opaque `context`, which this library never dereferences.
///
/// Raw pointers are neither `Send` nor `Sync`, but this one is only ever
/// handed back to the caller's own callback; the header makes keeping what it
/// points to alive, and safe to use from our threads, the caller's job.
#[derive(Clone, Copy)]
struct Context(*mut c_void);

// SAFETY: see the type's documentation.
unsafe impl Send for Context {}
// SAFETY: as above; the pointer is copied, never dereferenced.
unsafe impl Sync for Context {}

/// Why an operation did not succeed, as the callback reports it.
#[derive(Debug)]
struct Failure {
    status: i32,
    /// The peer's code for [`STATUS_RESET`], [`STATUS_STOPPED`] and
    /// [`STATUS_CLOSED`]; zero otherwise.
    code: u64,
    message: Cow<'static, str>,
}

impl Failure {
    fn new(status: i32) -> Self {
        let text = status_text(status);
        Self {
            status,
            code: 0,
            message: Cow::Borrowed(&text[..text.len() - 1]),
        }
    }

    fn with(status: i32, detail: impl Display) -> Self {
        Self {
            status,
            code: 0,
            message: Cow::Owned(detail.to_string()),
        }
    }

    fn coded(status: i32, code: u64, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    fn c_message(&self) -> CString {
        c_string(&self.message)
    }
}

/// `text` as a C string, with any interior NUL replaced rather than truncating
/// at it or failing.
fn c_string(text: &str) -> CString {
    CString::new(text.replace('\0', " ")).unwrap_or_default()
}

type Outcome<T> = Result<T, Failure>;

/// An operation, boxed so it borrows nothing from the handle that began it.
type Work<T> = std::pin::Pin<Box<dyn Future<Output = Outcome<T>> + Send>>;

/// One kind of callback, and how an outcome is passed to it.
trait Completion: Send + 'static {
    type Value: Send + 'static;
    fn complete(self, outcome: Outcome<Self::Value>);
}

/// A callback that fires at most once, and fires [`STATUS_PANIC`] if the last
/// reference to it is dropped without having fired.
///
/// Shared, so the entry point can keep a reference to report a validation
/// failure or a panic of its own while a task holds another.
struct Once<C: Completion>(Arc<Slot<C>>);

struct Slot<C: Completion>(Mutex<Option<C>>);

impl<C: Completion> Once<C> {
    fn new(completion: C) -> Self {
        Self(Arc::new(Slot(Mutex::new(Some(completion)))))
    }

    fn complete(&self, outcome: Outcome<C::Value>) {
        let taken = lock(&self.0.0).take();
        if let Some(completion) = taken {
            completion.complete(outcome);
        }
    }
}

impl<C: Completion> Clone for Once<C> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<C: Completion> Drop for Slot<C> {
    fn drop(&mut self) {
        let taken = self
            .0
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(completion) = taken {
            completion.complete(Err(Failure::new(STATUS_PANIC)));
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic while holding one of these is caught and reported; the data
    // behind it is a quinn handle that stays coherent, so carry on.
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Run `body` with the callback, completing it with the body's failure or a
/// caught panic. A body that succeeds has handed the callback on.
fn begin<C: Completion>(completion: C, body: impl FnOnce(&Once<C>) -> Result<(), Failure>) {
    let once = Once::new(completion);
    match catch_unwind(AssertUnwindSafe(|| body(&once))) {
        Ok(Ok(())) => {}
        Ok(Err(failure)) => once.complete(Err(failure)),
        Err(_) => once.complete(Err(Failure::new(STATUS_PANIC))),
    }
}

/// [`begin`], for an operation that is one future: `start` validates and
/// returns it, and a task awaits it and completes the callback.
fn launch<C, F>(completion: C, start: impl FnOnce() -> Result<F, Failure>)
where
    C: Completion,
    F: Future<Output = Outcome<C::Value>> + Send + 'static,
{
    begin(completion, |once| {
        let work = start()?;
        let once = once.clone();
        runtime().spawn(async move {
            let outcome = work.await;
            once.complete(outcome);
        });
        Ok(())
    });
}

/// Run a synchronous entry point, converting a panic into `on_panic`.
fn guarded<T>(on_panic: T, body: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(on_panic)
}

/// A synchronous entry point returning a status.
fn status(body: impl FnOnce() -> Result<(), Failure>) -> i32 {
    guarded(STATUS_PANIC, || match body() {
        Ok(()) => STATUS_OK,
        Err(failure) => failure.status,
    })
}

/// Resolves once `cancel` is set to true or its sender is dropped.
async fn cancelled(mut cancel: watch::Receiver<bool>) {
    let _ = cancel.wait_for(|set| *set).await;
}

/// Borrow `count` elements, as `moqom-rans-ffi` does: null is fine for zero.
///
/// # Safety
/// `pointer` must be valid for `count` elements for the call, or `count` zero.
unsafe fn slice_from<'a, T>(pointer: *const T, count: usize) -> Option<&'a [T]> {
    if count == 0 {
        return Some(&[]);
    }
    if pointer.is_null() {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(pointer, count) })
}

/// Read a 32-byte pin.
///
/// # Safety
/// `pin` must be null or valid for 32 bytes.
unsafe fn pin_from(pin: *const u8) -> Result<[u8; 32], Failure> {
    let bytes = unsafe { slice_from(pin, 32) }.ok_or_else(|| Failure::new(STATUS_NULL))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// A borrowed C string, as UTF-8.
///
/// # Safety
/// `text` must be null or a NUL-terminated string valid for the call.
unsafe fn str_from<'a>(text: *const c_char) -> Result<Option<&'a str>, Failure> {
    if text.is_null() {
        return Ok(None);
    }
    unsafe { CStr::from_ptr(text) }
        .to_str()
        .map(Some)
        .map_err(|_| Failure::with(STATUS_INVALID, "a string was not UTF-8"))
}

fn duration(milliseconds: u32, what: &str) -> Result<Duration, Failure> {
    if milliseconds == 0 {
        return Err(Failure::with(
            STATUS_INVALID,
            format!("{what} must not be zero"),
        ));
    }
    Ok(Duration::from_millis(u64::from(milliseconds)))
}

fn varint(code: u64) -> Result<VarInt, Failure> {
    VarInt::from_u64(code).map_err(|_| Failure::with(STATUS_INVALID, "a code above 2^62 - 1"))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

// ---------------------------------------------------------------------------
// Addresses.

/// A UDP address. `family` is 4 or 6; for IPv4 only the first four bytes of
/// `address` are used. Network byte order as on the wire; `port` is a host
/// integer.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoqomDirectAddress {
    /// 4 or 6.
    pub family: u8,
    /// The address bytes; IPv4 in the first four.
    pub address: [u8; 16],
    /// The UDP port.
    pub port: u16,
}

impl MoqomDirectAddress {
    /// The address this describes, or `None` for an unknown family.
    #[must_use]
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        let ip = match self.family {
            4 => IpAddr::V4(Ipv4Addr::new(
                self.address[0],
                self.address[1],
                self.address[2],
                self.address[3],
            )),
            6 => IpAddr::V6(Ipv6Addr::from(self.address)),
            _ => return None,
        };
        Some(SocketAddr::new(ip, self.port))
    }
}

impl From<SocketAddr> for MoqomDirectAddress {
    /// IPv4-mapped IPv6 addresses come out as IPv4, which is what they are.
    fn from(address: SocketAddr) -> Self {
        let mut bytes = [0u8; 16];
        let family = match address.ip().to_canonical() {
            IpAddr::V4(ip) => {
                bytes[..4].copy_from_slice(&ip.octets());
                4
            }
            IpAddr::V6(ip) => {
                bytes = ip.octets();
                6
            }
        };
        Self {
            family,
            address: bytes,
            port: address.port(),
        }
    }
}

/// # Safety
/// As [`slice_from`].
unsafe fn addresses_from(
    candidates: *const MoqomDirectAddress,
    count: usize,
) -> Result<Vec<SocketAddr>, Failure> {
    let candidates =
        unsafe { slice_from(candidates, count) }.ok_or_else(|| Failure::new(STATUS_NULL))?;
    candidates
        .iter()
        .map(MoqomDirectAddress::to_socket_addr)
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| Failure::with(STATUS_INVALID, "an address family other than 4 or 6"))
}

/// # Safety
/// `out` must be null or valid to write one address.
unsafe fn write_address(out: *mut MoqomDirectAddress, address: SocketAddr) -> Result<(), Failure> {
    if out.is_null() {
        return Err(Failure::new(STATUS_NULL));
    }
    unsafe { out.write(address.into()) };
    Ok(())
}

// ---------------------------------------------------------------------------
// Endpoints.

/// How to bind an endpoint. See the header for each field.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MoqomDirectEndpointConfig {
    /// The UDP port to bind on every interface. Zero picks one.
    pub port: u16,
    /// The single ALPN to offer and accept. Required.
    pub alpn: *const c_char,
    /// How long a connection may be silent before it is declared dead.
    pub idle_timeout_ms: u32,
    /// Nonzero to offer QUIC datagrams.
    pub datagrams: u8,
    /// A STUN server, by name or address literal. Null for none.
    pub stun_host: *const c_char,
    /// The STUN server's port.
    pub stun_port: u16,
    /// How long the STUN server has to answer.
    pub stun_timeout_ms: u32,
}

/// One socket, one certificate, one peer at a time.
pub struct MoqomDirectEndpoint {
    socket: Arc<DirectSocket>,
    port: u16,
    /// True once closed; dropped on free. Pending dials and accepts watch it.
    closed: watch::Sender<bool>,
    /// Whether a dial or accept is pending.
    busy: Arc<AtomicBool>,
}

impl MoqomDirectEndpoint {
    fn close(&self) {
        self.closed.send_replace(true);
        self.socket.punch_stop();
    }

    fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }

    /// Claim the one establishment slot, or fail with [`STATUS_BUSY`].
    fn claim(&self) -> Result<Busy, Failure> {
        if self.is_closed() {
            return Err(Failure::new(STATUS_CLOSED));
        }
        self.busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Busy(Arc::clone(&self.busy)))
            .map_err(|_| Failure::new(STATUS_BUSY))
    }
}

/// Holds the establishment slot; releases it when the operation ends, however.
struct Busy(Arc<AtomicBool>);

impl Drop for Busy {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// `void (*)(void *context, int32_t status, MoqomDirectEndpoint *, const char *message)`.
pub type EndpointCallback =
    extern "C" fn(*mut c_void, i32, *mut MoqomDirectEndpoint, *const c_char);

struct EndpointReply(EndpointCallback, Context);

impl Completion for EndpointReply {
    type Value = Box<MoqomDirectEndpoint>;
    fn complete(self, outcome: Outcome<Self::Value>) {
        let Self(callback, context) = self;
        match outcome {
            Ok(endpoint) => callback(
                context.0,
                STATUS_OK,
                Box::into_raw(endpoint),
                std::ptr::null(),
            ),
            Err(failure) => callback(
                context.0,
                failure.status,
                std::ptr::null_mut(),
                failure.c_message().as_ptr(),
            ),
        }
    }
}

/// Why an establishment or bind failed, as a status.
#[allow(clippy::match_same_arms)] // `Error` is non_exhaustive; see moqom-rans-ffi.
fn failure_of(error: &Error) -> Failure {
    let status = match error {
        Error::Unreachable(_) => STATUS_TIMEOUT,
        Error::Handshake(_) | Error::Connect(_) => STATUS_HANDSHAKE,
        Error::Tls(_) => STATUS_TLS,
        Error::Closed => STATUS_CLOSED,
        Error::Io(_) => STATUS_IO,
        _ => STATUS_IO,
    };
    Failure::with(status, error)
}

/// # Safety
/// `config` must be null or valid, with its strings null or NUL-terminated.
unsafe fn socket_config(config: *const MoqomDirectEndpointConfig) -> Result<SocketConfig, Failure> {
    let config = unsafe { config.as_ref() }.ok_or_else(|| Failure::new(STATUS_NULL))?;
    let alpn = unsafe { str_from(config.alpn) }?.ok_or_else(|| Failure::new(STATUS_NULL))?;
    if alpn.is_empty() || alpn.len() > 255 {
        return Err(Failure::with(
            STATUS_INVALID,
            "an ALPN must be 1 to 255 bytes",
        ));
    }
    let mut socket = SocketConfig::new(alpn.as_bytes());
    socket.bind = SocketAddr::from((Ipv4Addr::UNSPECIFIED, config.port));
    socket.idle_timeout = duration(config.idle_timeout_ms, "idle_timeout_ms")?;
    socket.datagrams = config.datagrams != 0;
    if let Some(host) = unsafe { str_from(config.stun_host) }? {
        if host.is_empty() || config.stun_port == 0 {
            return Err(Failure::with(
                STATUS_INVALID,
                "a STUN server needs a host and a port",
            ));
        }
        socket.stun = Some(match host.parse() {
            Ok(ip) => StunServer::Address(SocketAddr::new(ip, config.stun_port)),
            Err(_) => StunServer::Name {
                host: host.to_owned(),
                port: config.stun_port,
            },
        });
        socket.stun_timeout = duration(config.stun_timeout_ms, "stun_timeout_ms")?;
    }
    Ok(socket)
}

/// Bind a socket, generate a certificate, and ask STUN if configured.
///
/// # Safety
/// `config` must be valid for the call, as the header describes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_endpoint_bind(
    config: *const MoqomDirectEndpointConfig,
    context: *mut c_void,
    callback: Option<EndpointCallback>,
) {
    let Some(callback) = callback else { return };
    launch(EndpointReply(callback, Context(context)), || {
        let config = unsafe { socket_config(config) }?;
        Ok(async move {
            let socket = DirectSocket::bind(config)
                .await
                .map_err(|error| failure_of(&error))?;
            let port = socket
                .local_addr()
                .map_err(|error| Failure::with(STATUS_IO, error))?
                .port();
            Ok(Box::new(MoqomDirectEndpoint {
                socket: Arc::new(socket),
                port,
                closed: watch::Sender::new(false),
                busy: Arc::new(AtomicBool::new(false)),
            }))
        })
    });
}

/// The bound port, or zero for a null endpoint.
///
/// # Safety
/// `endpoint` must be null or live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_endpoint_port(endpoint: *const MoqomDirectEndpoint) -> u16 {
    guarded(0, || {
        unsafe { endpoint.as_ref() }.map_or(0, |endpoint| endpoint.port)
    })
}

/// This endpoint's DER certificate, borrowed for the endpoint's lifetime.
///
/// # Safety
/// `endpoint` must be null or live; `der` and `length` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_endpoint_certificate(
    endpoint: *const MoqomDirectEndpoint,
    der: *mut *const u8,
    length: *mut usize,
) -> i32 {
    status(|| {
        let endpoint = unsafe { endpoint.as_ref() }.ok_or_else(|| Failure::new(STATUS_NULL))?;
        if der.is_null() || length.is_null() {
            return Err(Failure::new(STATUS_NULL));
        }
        let certificate = endpoint.socket.certificate().as_ref();
        unsafe {
            der.write(certificate.as_ptr());
            length.write(certificate.len());
        }
        Ok(())
    })
}

/// The public address STUN reported, or [`STATUS_NOT_FOUND`].
///
/// # Safety
/// `endpoint` must be null or live; `out` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_endpoint_reflexive(
    endpoint: *const MoqomDirectEndpoint,
    out: *mut MoqomDirectAddress,
) -> i32 {
    status(|| {
        let endpoint = unsafe { endpoint.as_ref() }.ok_or_else(|| Failure::new(STATUS_NULL))?;
        let reflexive = endpoint
            .socket
            .reflexive()
            .ok_or_else(|| Failure::new(STATUS_NOT_FOUND))?;
        unsafe { write_address(out, reflexive) }
    })
}

/// Probe every candidate every `interval_ms`, replacing earlier targets.
///
/// # Safety
/// `endpoint` must be null or live; `candidates` valid for `count`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_endpoint_punch_start(
    endpoint: *mut MoqomDirectEndpoint,
    candidates: *const MoqomDirectAddress,
    count: usize,
    interval_ms: u32,
) -> i32 {
    status(|| {
        let endpoint = unsafe { endpoint.as_ref() }.ok_or_else(|| Failure::new(STATUS_NULL))?;
        let targets = unsafe { addresses_from(candidates, count) }?;
        let interval = duration(interval_ms, "interval_ms")?;
        if endpoint.is_closed() {
            return Err(Failure::new(STATUS_CLOSED));
        }
        endpoint
            .socket
            .punch_start(targets, interval)
            .map_err(|error| Failure::with(STATUS_IO, error))
    })
}

/// Stop probing.
///
/// # Safety
/// `endpoint` must be null or live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_endpoint_punch_stop(endpoint: *mut MoqomDirectEndpoint) {
    guarded((), || {
        if let Some(endpoint) = unsafe { endpoint.as_ref() } {
            endpoint.socket.punch_stop();
        }
    });
}

/// `void (*)(void *context, int32_t status, MoqomDirectConnection *, const char *message)`.
pub type ConnectionCallback =
    extern "C" fn(*mut c_void, i32, *mut MoqomDirectConnection, *const c_char);

struct ConnectionReply(ConnectionCallback, Context);

impl Completion for ConnectionReply {
    type Value = MoqomDirectConnection;
    fn complete(self, outcome: Outcome<Self::Value>) {
        let Self(callback, context) = self;
        match outcome {
            Ok(connection) => callback(
                context.0,
                STATUS_OK,
                Box::into_raw(Box::new(connection)),
                std::ptr::null(),
            ),
            Err(failure) => callback(
                context.0,
                failure.status,
                std::ptr::null_mut(),
                failure.c_message().as_ptr(),
            ),
        }
    }
}

/// Run an establishment: hold the slot, and give way to closing the endpoint.
fn establish<F>(
    endpoint: &MoqomDirectEndpoint,
    attempt: impl FnOnce(Arc<DirectSocket>) -> F,
) -> Result<Work<MoqomDirectConnection>, Failure>
where
    F: Future<Output = Result<quinn::Connection, Error>> + Send + 'static,
{
    let busy = endpoint.claim()?;
    let cancel = endpoint.closed.subscribe();
    let datagrams = endpoint.socket.datagrams();
    let attempt = attempt(Arc::clone(&endpoint.socket));
    Ok(Box::pin(async move {
        let _busy = busy;
        tokio::select! {
            biased;
            () = cancelled(cancel) => Err(Failure::new(STATUS_CANCELLED)),
            result = attempt => result
                .map(|connection| MoqomDirectConnection::new(connection, datagrams))
                .map_err(|error| failure_of(&error)),
        }
    }))
}

/// Dial every candidate at once; the first pinned handshake wins.
///
/// # Safety
/// `endpoint` must be null or live; `candidates` valid for `count`; `pin`
/// null or valid for 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_endpoint_dial(
    endpoint: *mut MoqomDirectEndpoint,
    candidates: *const MoqomDirectAddress,
    count: usize,
    pin: *const u8,
    timeout_ms: u32,
    context: *mut c_void,
    callback: Option<ConnectionCallback>,
) {
    let Some(callback) = callback else { return };
    launch(ConnectionReply(callback, Context(context)), || {
        let endpoint = unsafe { endpoint.as_ref() }.ok_or_else(|| Failure::new(STATUS_NULL))?;
        let targets = unsafe { addresses_from(candidates, count) }?;
        let pin = unsafe { pin_from(pin) }?;
        let timeout = duration(timeout_ms, "timeout_ms")?;
        if targets.is_empty() {
            return Err(Failure::with(STATUS_INVALID, "no candidates to dial"));
        }
        establish(endpoint, move |socket| async move {
            socket.dial(&targets, pin, timeout).await
        })
    });
}

/// Wait for the pinned peer to connect.
///
/// # Safety
/// `endpoint` must be null or live; `pin` null or valid for 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_endpoint_accept(
    endpoint: *mut MoqomDirectEndpoint,
    pin: *const u8,
    timeout_ms: u32,
    context: *mut c_void,
    callback: Option<ConnectionCallback>,
) {
    let Some(callback) = callback else { return };
    launch(ConnectionReply(callback, Context(context)), || {
        let endpoint = unsafe { endpoint.as_ref() }.ok_or_else(|| Failure::new(STATUS_NULL))?;
        let pin = unsafe { pin_from(pin) }?;
        let timeout = duration(timeout_ms, "timeout_ms")?;
        establish(endpoint, move |socket| async move {
            socket.accept(pin, timeout).await
        })
    });
}

/// Stop probing, refuse new connections, and cancel pending establishments.
///
/// # Safety
/// `endpoint` must be null or live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_endpoint_close(endpoint: *mut MoqomDirectEndpoint) {
    guarded((), || {
        if let Some(endpoint) = unsafe { endpoint.as_ref() } {
            endpoint.close();
        }
    });
}

/// Close and release. Null is accepted and ignored.
///
/// # Safety
/// `endpoint` must be null or from [`moqom_direct_endpoint_bind`], not freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_endpoint_free(endpoint: *mut MoqomDirectEndpoint) {
    guarded((), || {
        if !endpoint.is_null() {
            let endpoint = unsafe { Box::from_raw(endpoint) };
            endpoint.close();
        }
    });
}

// ---------------------------------------------------------------------------
// Connections.

/// A pinned QUIC connection to the peer.
pub struct MoqomDirectConnection {
    connection: quinn::Connection,
    alpn: CString,
    peer: Option<[u8; 32]>,
    /// Whether this side enabled datagrams. quinn sends none when it did not,
    /// whatever the peer offers.
    datagrams: bool,
    /// Dropped on free, which cancels this handle's pending operations.
    cancel: watch::Sender<bool>,
    /// The code and reason this side closed with, which quinn reports only as
    /// "locally closed".
    closing: Arc<Mutex<Option<(u64, String)>>>,
}

impl MoqomDirectConnection {
    fn new(connection: quinn::Connection, datagrams: bool) -> Self {
        let alpn = connection
            .handshake_data()
            .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|data| data.protocol)
            .map(|protocol| c_string(&String::from_utf8_lossy(&protocol)))
            .unwrap_or_default();
        let peer = connection
            .peer_identity()
            .and_then(|identity| {
                identity
                    .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                    .ok()
            })
            .and_then(|chain| chain.first().map(|leaf| sha256(leaf.as_ref())));
        Self {
            connection,
            alpn,
            peer,
            datagrams,
            cancel: watch::Sender::new(false),
            closing: Arc::new(Mutex::new(None)),
        }
    }
}

/// How a lost connection reads as a status.
fn lost(error: &quinn::ConnectionError) -> Failure {
    use quinn::ConnectionError as E;
    let status = match error {
        E::ApplicationClosed(_) | E::ConnectionClosed(_) | E::LocallyClosed => STATUS_CLOSED,
        E::TimedOut => STATUS_TIMEOUT,
        _ => STATUS_IO,
    };
    Failure::with(status, error)
}

/// The negotiated ALPN, borrowed for the connection's lifetime; null for a
/// null connection.
///
/// # Safety
/// `connection` must be null or live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_connection_alpn(
    connection: *const MoqomDirectConnection,
) -> *const c_char {
    guarded(std::ptr::null(), || {
        unsafe { connection.as_ref() }.map_or(std::ptr::null(), |handle| handle.alpn.as_ptr())
    })
}

/// SHA-256 of the peer's DER leaf certificate.
///
/// # Safety
/// `connection` must be null or live; `out` null or valid for 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_connection_peer_certificate(
    connection: *const MoqomDirectConnection,
    out: *mut u8,
) -> i32 {
    status(|| {
        let handle = unsafe { connection.as_ref() }.ok_or_else(|| Failure::new(STATUS_NULL))?;
        if out.is_null() {
            return Err(Failure::new(STATUS_NULL));
        }
        let peer = handle.peer.ok_or_else(|| Failure::new(STATUS_NOT_FOUND))?;
        unsafe { std::ptr::copy_nonoverlapping(peer.as_ptr(), out, peer.len()) };
        Ok(())
    })
}

/// The largest datagram payload the path carries now; zero if the peer allows
/// none, or this endpoint was bound without datagrams.
///
/// # Safety
/// `connection` must be null or live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_connection_max_datagram_size(
    connection: *const MoqomDirectConnection,
) -> usize {
    guarded(0, || {
        unsafe { connection.as_ref() }
            .filter(|handle| handle.datagrams)
            .and_then(|handle| handle.connection.max_datagram_size())
            .unwrap_or(0)
    })
}

/// The address the peer is reached at.
///
/// # Safety
/// `connection` must be null or live; `out` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_connection_remote(
    connection: *const MoqomDirectConnection,
    out: *mut MoqomDirectAddress,
) -> i32 {
    status(|| {
        let handle = unsafe { connection.as_ref() }.ok_or_else(|| Failure::new(STATUS_NULL))?;
        unsafe { write_address(out, handle.connection.remote_address()) }
    })
}

/// `void (*)(void *context, int32_t status, MoqomDirectSendStream *, MoqomDirectRecvStream *)`.
pub type BiCallback =
    extern "C" fn(*mut c_void, i32, *mut MoqomDirectSendStream, *mut MoqomDirectRecvStream);
/// `void (*)(void *context, int32_t status, MoqomDirectSendStream *)`.
pub type UniSendCallback = extern "C" fn(*mut c_void, i32, *mut MoqomDirectSendStream);
/// `void (*)(void *context, int32_t status, MoqomDirectRecvStream *)`.
pub type UniRecvCallback = extern "C" fn(*mut c_void, i32, *mut MoqomDirectRecvStream);

struct BiReply(BiCallback, Context);

impl Completion for BiReply {
    type Value = (MoqomDirectSendStream, MoqomDirectRecvStream);
    fn complete(self, outcome: Outcome<Self::Value>) {
        let Self(callback, context) = self;
        match outcome {
            Ok((send, recv)) => callback(
                context.0,
                STATUS_OK,
                Box::into_raw(Box::new(send)),
                Box::into_raw(Box::new(recv)),
            ),
            Err(failure) => callback(
                context.0,
                failure.status,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ),
        }
    }
}

struct UniSendReply(UniSendCallback, Context);

impl Completion for UniSendReply {
    type Value = MoqomDirectSendStream;
    fn complete(self, outcome: Outcome<Self::Value>) {
        let Self(callback, context) = self;
        match outcome {
            Ok(send) => callback(context.0, STATUS_OK, Box::into_raw(Box::new(send))),
            Err(failure) => callback(context.0, failure.status, std::ptr::null_mut()),
        }
    }
}

struct UniRecvReply(UniRecvCallback, Context);

impl Completion for UniRecvReply {
    type Value = MoqomDirectRecvStream;
    fn complete(self, outcome: Outcome<Self::Value>) {
        let Self(callback, context) = self;
        match outcome {
            Ok(recv) => callback(context.0, STATUS_OK, Box::into_raw(Box::new(recv))),
            Err(failure) => callback(context.0, failure.status, std::ptr::null_mut()),
        }
    }
}

/// Run `operation` on a connection, giving way to the handle being freed.
///
/// # Safety
/// `connection` must be null or live.
unsafe fn on_connection<T, F>(
    connection: *const MoqomDirectConnection,
    operation: impl FnOnce(quinn::Connection) -> F,
) -> Result<Work<T>, Failure>
where
    T: Send + 'static,
    F: Future<Output = Result<T, quinn::ConnectionError>> + Send + 'static,
{
    let handle = unsafe { connection.as_ref() }.ok_or_else(|| Failure::new(STATUS_NULL))?;
    let cancel = handle.cancel.subscribe();
    let operation = operation(handle.connection.clone());
    Ok(Box::pin(async move {
        tokio::select! {
            biased;
            () = cancelled(cancel) => Err(Failure::new(STATUS_CANCELLED)),
            result = operation => result.map_err(|error| lost(&error)),
        }
    }))
}

/// Open a bidirectional stream.
///
/// # Safety
/// `connection` must be null or live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_connection_open_bi(
    connection: *mut MoqomDirectConnection,
    context: *mut c_void,
    callback: Option<BiCallback>,
) {
    let Some(callback) = callback else { return };
    launch(BiReply(callback, Context(context)), || {
        let work = unsafe {
            on_connection(connection, |connection| async move {
                connection.open_bi().await
            })
        }?;
        Ok(async move {
            work.await
                .map(|(send, recv)| (send_stream(send), recv_stream(recv)))
        })
    });
}

/// Open a unidirectional stream.
///
/// # Safety
/// `connection` must be null or live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_connection_open_uni(
    connection: *mut MoqomDirectConnection,
    context: *mut c_void,
    callback: Option<UniSendCallback>,
) {
    let Some(callback) = callback else { return };
    launch(UniSendReply(callback, Context(context)), || {
        let work = unsafe {
            on_connection(connection, |connection| async move {
                connection.open_uni().await
            })
        }?;
        Ok(async move { work.await.map(send_stream) })
    });
}

/// The next bidirectional stream the peer opened.
///
/// # Safety
/// `connection` must be null or live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_connection_accept_bi(
    connection: *mut MoqomDirectConnection,
    context: *mut c_void,
    callback: Option<BiCallback>,
) {
    let Some(callback) = callback else { return };
    launch(BiReply(callback, Context(context)), || {
        let work = unsafe {
            on_connection(connection, |connection| async move {
                connection.accept_bi().await
            })
        }?;
        Ok(async move {
            work.await
                .map(|(send, recv)| (send_stream(send), recv_stream(recv)))
        })
    });
}

/// The next unidirectional stream the peer opened.
///
/// # Safety
/// `connection` must be null or live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_connection_accept_uni(
    connection: *mut MoqomDirectConnection,
    context: *mut c_void,
    callback: Option<UniRecvCallback>,
) {
    let Some(callback) = callback else { return };
    launch(UniRecvReply(callback, Context(context)), || {
        let work = unsafe {
            on_connection(connection, |connection| async move {
                connection.accept_uni().await
            })
        }?;
        Ok(async move { work.await.map(recv_stream) })
    });
}

/// Send a datagram now, or fail.
///
/// # Safety
/// `connection` must be null or live; `data` valid for `length`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_connection_send_datagram(
    connection: *mut MoqomDirectConnection,
    data: *const u8,
    length: usize,
) -> i32 {
    status(|| {
        use quinn::SendDatagramError as E;
        let handle = unsafe { connection.as_ref() }.ok_or_else(|| Failure::new(STATUS_NULL))?;
        let data = unsafe { slice_from(data, length) }.ok_or_else(|| Failure::new(STATUS_NULL))?;
        handle
            .connection
            .send_datagram(data.to_vec().into())
            .map_err(|error| match error {
                E::UnsupportedByPeer | E::Disabled => Failure::new(STATUS_UNSUPPORTED),
                E::TooLarge => Failure::new(STATUS_TOO_LARGE),
                E::ConnectionLost(error) => lost(&error),
            })
    })
}

/// `void (*)(void *context, int32_t status, const uint8_t *data, size_t length, uint64_t code)`.
pub type BytesCallback = extern "C" fn(*mut c_void, i32, *const u8, usize, u64);

/// What a read produced.
enum Read {
    Data(Vec<u8>),
    End,
}

struct BytesReply(BytesCallback, Context);

impl Completion for BytesReply {
    type Value = Read;
    fn complete(self, outcome: Outcome<Self::Value>) {
        let Self(callback, context) = self;
        match outcome {
            Ok(Read::Data(data)) => callback(context.0, STATUS_OK, data.as_ptr(), data.len(), 0),
            Ok(Read::End) => callback(context.0, STATUS_END, std::ptr::null(), 0, 0),
            Err(failure) => {
                callback(context.0, failure.status, std::ptr::null(), 0, failure.code);
            }
        }
    }
}

/// The next datagram.
///
/// # Safety
/// `connection` must be null or live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_connection_read_datagram(
    connection: *mut MoqomDirectConnection,
    context: *mut c_void,
    callback: Option<BytesCallback>,
) {
    let Some(callback) = callback else { return };
    launch(BytesReply(callback, Context(context)), || {
        let work = unsafe {
            on_connection(connection, |connection| async move {
                connection.read_datagram().await
            })
        }?;
        Ok(async move { work.await.map(|datagram| Read::Data(datagram.to_vec())) })
    });
}

/// `void (*)(void *context, int32_t status, uint64_t code, const char *reason)`.
pub type ClosedCallback = extern "C" fn(*mut c_void, i32, u64, *const c_char);

struct ClosedReply(ClosedCallback, Context);

impl Completion for ClosedReply {
    type Value = Infallible;
    fn complete(self, outcome: Outcome<Self::Value>) {
        let Self(callback, context) = self;
        let Err(failure) = outcome;
        callback(
            context.0,
            failure.status,
            failure.code,
            failure.c_message().as_ptr(),
        );
    }
}

/// Why a connection ended, with the application's code and reason when it
/// was an application close on either side.
fn ending(error: &quinn::ConnectionError, closing: &Mutex<Option<(u64, String)>>) -> Failure {
    use quinn::ConnectionError as E;
    match error {
        E::ApplicationClosed(close) => Failure::coded(
            STATUS_CLOSED,
            close.error_code.into_inner(),
            String::from_utf8_lossy(&close.reason).into_owned(),
        ),
        E::LocallyClosed => match lock(closing).clone() {
            Some((code, reason)) => Failure::coded(STATUS_CLOSED, code, reason),
            None => Failure::with(STATUS_CLOSED, error),
        },
        _ => lost(error),
    }
}

/// Completes once, when the connection ends for any reason.
///
/// # Safety
/// `connection` must be null or live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_connection_closed(
    connection: *mut MoqomDirectConnection,
    context: *mut c_void,
    callback: Option<ClosedCallback>,
) {
    let Some(callback) = callback else { return };
    launch(ClosedReply(callback, Context(context)), || {
        let handle = unsafe { connection.as_ref() }.ok_or_else(|| Failure::new(STATUS_NULL))?;
        let connection = handle.connection.clone();
        let closing = Arc::clone(&handle.closing);
        let cancel = handle.cancel.subscribe();
        Ok(async move {
            // The close first: closing and then freeing at once should still
            // report the close, which quinn has already recorded.
            tokio::select! {
                biased;
                error = connection.closed() => Err(ending(&error, &closing)),
                () = cancelled(cancel) => Err(Failure::new(STATUS_CANCELLED)),
            }
        })
    });
}

/// Close with an application code and reason, immediately.
///
/// # Safety
/// `connection` must be null or live; `reason` null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_connection_close(
    connection: *mut MoqomDirectConnection,
    code: u64,
    reason: *const c_char,
) {
    guarded((), || {
        let Some(handle) = (unsafe { connection.as_ref() }) else {
            return;
        };
        let reason = if reason.is_null() {
            Vec::new()
        } else {
            unsafe { CStr::from_ptr(reason) }.to_bytes().to_vec()
        };
        // The header has no status to return, so an out-of-range code is
        // clamped rather than refused: the close must still happen.
        let code = VarInt::from_u64(code).unwrap_or(VarInt::MAX);
        *lock(&handle.closing) = Some((
            code.into_inner(),
            String::from_utf8_lossy(&reason).into_owned(),
        ));
        handle.connection.close(code, &reason);
    });
}

/// Release the handle, cancelling its pending operations.
///
/// # Safety
/// `connection` must be null or from a dial or accept, not freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_connection_free(connection: *mut MoqomDirectConnection) {
    guarded((), || {
        if !connection.is_null() {
            drop(unsafe { Box::from_raw(connection) });
        }
    });
}

// ---------------------------------------------------------------------------
// Streams.

/// The sending half of a stream.
pub struct MoqomDirectSendStream {
    shared: Arc<SendShared>,
    queue: mpsc::UnboundedSender<SendOp>,
    /// Dropped on free, which cancels pending writes.
    _cancel: watch::Sender<bool>,
}

struct SendShared {
    /// Locked only within a poll, never across an await, so a reset can act
    /// while a write is waiting on flow control.
    stream: Mutex<quinn::SendStream>,
    finished: AtomicBool,
    reset: AtomicBool,
}

enum SendOp {
    Write(Vec<u8>, Once<StatusReply>),
    Finish,
}

/// `void (*)(void *context, int32_t status, uint64_t code)`.
pub type StatusCallback = extern "C" fn(*mut c_void, i32, u64);

struct StatusReply(StatusCallback, Context);

impl Completion for StatusReply {
    type Value = ();
    fn complete(self, outcome: Outcome<Self::Value>) {
        let Self(callback, context) = self;
        match outcome {
            Ok(()) => callback(context.0, STATUS_OK, 0),
            Err(failure) => callback(context.0, failure.status, failure.code),
        }
    }
}

fn send_stream(stream: quinn::SendStream) -> MoqomDirectSendStream {
    let shared = Arc::new(SendShared {
        stream: Mutex::new(stream),
        finished: AtomicBool::new(false),
        reset: AtomicBool::new(false),
    });
    let (queue, ops) = mpsc::unbounded_channel();
    let (cancel, freed) = watch::channel(false);
    runtime().spawn(writer(Arc::clone(&shared), ops, freed));
    MoqomDirectSendStream {
        shared,
        queue,
        _cancel: cancel,
    }
}

/// Serves one send stream's queue in order until the handle is freed.
async fn writer(
    shared: Arc<SendShared>,
    mut ops: mpsc::UnboundedReceiver<SendOp>,
    freed: watch::Receiver<bool>,
) {
    let mut abandoned = false;
    while let Some(op) = ops.recv().await {
        match op {
            SendOp::Write(data, reply) => {
                if freed.has_changed().is_err() {
                    abandoned = true;
                    reply.complete(Err(Failure::new(STATUS_CANCELLED)));
                    continue;
                }
                let outcome = tokio::select! {
                    biased;
                    () = cancelled(freed.clone()) => {
                        abandoned = true;
                        Err(Failure::new(STATUS_CANCELLED))
                    }
                    result = write_all(&shared.stream, &data) => result.map_err(|error| written(&error)),
                };
                reply.complete(outcome);
            }
            SendOp::Finish => {
                if !abandoned {
                    let _ = lock(&shared.stream).finish();
                }
            }
        }
    }
    if abandoned && !shared.reset.swap(true, Ordering::AcqRel) {
        let _ = lock(&shared.stream).reset(VarInt::from_u32(0));
    }
}

async fn write_all(
    stream: &Mutex<quinn::SendStream>,
    data: &[u8],
) -> Result<(), quinn::WriteError> {
    let mut sent = 0;
    while sent < data.len() {
        sent += poll_fn(|cx| std::pin::Pin::new(&mut *lock(stream)).poll_write(cx, &data[sent..]))
            .await?;
    }
    Ok(())
}

fn written(error: &quinn::WriteError) -> Failure {
    use quinn::WriteError as E;
    match error {
        E::Stopped(code) => Failure::coded(STATUS_STOPPED, code.into_inner(), error.to_string()),
        E::ConnectionLost(lost_by) => lost(lost_by),
        // Reset or finished here first.
        E::ClosedStream => Failure::new(STATUS_CANCELLED),
        E::ZeroRttRejected => Failure::with(STATUS_IO, error),
    }
}

/// Write all of `data`, copied before this returns.
///
/// # Safety
/// `stream` must be null or live; `data` valid for `length`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_send_write(
    stream: *mut MoqomDirectSendStream,
    data: *const u8,
    length: usize,
    context: *mut c_void,
    callback: Option<StatusCallback>,
) {
    let Some(callback) = callback else { return };
    begin(StatusReply(callback, Context(context)), |once| {
        let handle = unsafe { stream.as_ref() }.ok_or_else(|| Failure::new(STATUS_NULL))?;
        let data = unsafe { slice_from(data, length) }.ok_or_else(|| Failure::new(STATUS_NULL))?;
        if handle.shared.finished.load(Ordering::Acquire)
            || handle.shared.reset.load(Ordering::Acquire)
        {
            return Err(Failure::with(
                STATUS_CLOSED,
                "the stream was finished or reset",
            ));
        }
        handle
            .queue
            .send(SendOp::Write(data.to_vec(), once.clone()))
            .map_err(|_| Failure::new(STATUS_CLOSED))
    });
}

/// End the stream cleanly after what has been written.
///
/// # Safety
/// `stream` must be null or live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_send_finish(stream: *mut MoqomDirectSendStream) -> i32 {
    status(|| {
        let handle = unsafe { stream.as_ref() }.ok_or_else(|| Failure::new(STATUS_NULL))?;
        if handle.shared.reset.load(Ordering::Acquire)
            || handle.shared.finished.swap(true, Ordering::AcqRel)
        {
            return Err(Failure::new(STATUS_CLOSED));
        }
        handle
            .queue
            .send(SendOp::Finish)
            .map_err(|_| Failure::new(STATUS_CLOSED))
    })
}

/// Abandon the stream; the peer sees a reset with `code`.
///
/// # Safety
/// `stream` must be null or live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_send_reset(
    stream: *mut MoqomDirectSendStream,
    code: u64,
) -> i32 {
    status(|| {
        let handle = unsafe { stream.as_ref() }.ok_or_else(|| Failure::new(STATUS_NULL))?;
        let code = varint(code)?;
        if handle.shared.reset.swap(true, Ordering::AcqRel) {
            return Err(Failure::new(STATUS_CLOSED));
        }
        lock(&handle.shared.stream)
            .reset(code)
            .map_err(|_| Failure::new(STATUS_CLOSED))
    })
}

/// Release a send stream.
///
/// # Safety
/// `stream` must be null or from this library, not freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_send_free(stream: *mut MoqomDirectSendStream) {
    guarded((), || {
        if !stream.is_null() {
            drop(unsafe { Box::from_raw(stream) });
        }
    });
}

/// The receiving half of a stream.
pub struct MoqomDirectRecvStream {
    shared: Arc<RecvShared>,
    queue: mpsc::UnboundedSender<(usize, Once<BytesReply>)>,
    /// Dropped on free, which cancels pending reads.
    _cancel: watch::Sender<bool>,
}

struct RecvShared {
    /// As [`SendShared::stream`], so a stop can act while a read waits.
    stream: Mutex<quinn::RecvStream>,
    stopped: AtomicBool,
}

fn recv_stream(stream: quinn::RecvStream) -> MoqomDirectRecvStream {
    let shared = Arc::new(RecvShared {
        stream: Mutex::new(stream),
        stopped: AtomicBool::new(false),
    });
    let (queue, ops) = mpsc::unbounded_channel();
    let (cancel, freed) = watch::channel(false);
    runtime().spawn(reader(Arc::clone(&shared), ops, freed));
    MoqomDirectRecvStream {
        shared,
        queue,
        _cancel: cancel,
    }
}

/// Serves one receive stream's reads in order until the handle is freed.
async fn reader(
    shared: Arc<RecvShared>,
    mut ops: mpsc::UnboundedReceiver<(usize, Once<BytesReply>)>,
    freed: watch::Receiver<bool>,
) {
    while let Some((max, reply)) = ops.recv().await {
        if freed.has_changed().is_err() {
            reply.complete(Err(Failure::new(STATUS_CANCELLED)));
            continue;
        }
        let outcome = tokio::select! {
            biased;
            () = cancelled(freed.clone()) => Err(Failure::new(STATUS_CANCELLED)),
            result = read(&shared.stream, max) => result,
        };
        reply.complete(outcome);
    }
}

async fn read(stream: &Mutex<quinn::RecvStream>, max: usize) -> Outcome<Read> {
    use quinn::ReadError as E;
    let mut buffer = vec![0u8; max.min(MAX_READ)];
    match poll_fn(|cx| lock(stream).poll_read(cx, &mut buffer)).await {
        Ok(0) => Ok(Read::End),
        Ok(n) => {
            buffer.truncate(n);
            Ok(Read::Data(buffer))
        }
        Err(E::Reset(code)) => Err(Failure::coded(STATUS_RESET, code.into_inner(), "reset")),
        Err(E::ConnectionLost(error)) => Err(lost(&error)),
        // Stopped here first, or already read to the end.
        Err(E::ClosedStream) => Err(Failure::new(STATUS_CANCELLED)),
        Err(error) => Err(Failure::with(STATUS_IO, error)),
    }
}

/// Up to `max_length` of the next bytes.
///
/// # Safety
/// `stream` must be null or live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_recv_read(
    stream: *mut MoqomDirectRecvStream,
    max_length: usize,
    context: *mut c_void,
    callback: Option<BytesCallback>,
) {
    let Some(callback) = callback else { return };
    begin(BytesReply(callback, Context(context)), |once| {
        let handle = unsafe { stream.as_ref() }.ok_or_else(|| Failure::new(STATUS_NULL))?;
        if max_length == 0 {
            return Err(Failure::with(STATUS_INVALID, "max_length must not be zero"));
        }
        if handle.shared.stopped.load(Ordering::Acquire) {
            return Err(Failure::new(STATUS_CLOSED));
        }
        handle
            .queue
            .send((max_length, once.clone()))
            .map_err(|_| Failure::new(STATUS_CLOSED))
    });
}

/// Tell the peer to stop sending, with `code`.
///
/// # Safety
/// `stream` must be null or live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_recv_stop(
    stream: *mut MoqomDirectRecvStream,
    code: u64,
) -> i32 {
    status(|| {
        let handle = unsafe { stream.as_ref() }.ok_or_else(|| Failure::new(STATUS_NULL))?;
        let code = varint(code)?;
        if handle.shared.stopped.swap(true, Ordering::AcqRel) {
            return Err(Failure::new(STATUS_CLOSED));
        }
        lock(&handle.shared.stream)
            .stop(code)
            .map_err(|_| Failure::new(STATUS_CLOSED))
    })
}

/// Release a receive stream.
///
/// # Safety
/// `stream` must be null or from this library, not freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn moqom_direct_recv_free(stream: *mut MoqomDirectRecvStream) {
    guarded((), || {
        if !stream.is_null() {
            drop(unsafe { Box::from_raw(stream) });
        }
    });
}
