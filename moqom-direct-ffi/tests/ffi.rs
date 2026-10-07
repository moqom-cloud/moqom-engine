//! The direct-path ABI, driven only through its `extern "C"` functions.
//!
//! Each callback's `context` is a channel sender, so a test waits for an
//! operation the way the Swift SDK does: by being called back, on a thread it
//! does not own. Two endpoints on loopback stand in for two devices; what
//! cannot be proven over loopback -- crossing real NATs -- is what the probe
//! and STUN tests reduce to the parts that can.

#![allow(unsafe_code)]
// A dial and what it dialled, an accept and what it accepted: the pairs are
// named for each other because that is what each test compares.
#![allow(clippy::similar_names)]

use std::ffi::{CStr, CString, c_char, c_void};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

use moqom_direct_ffi::*;

const PATIENCE: Duration = Duration::from_secs(10);
const ALPN: &CStr = c"moqt-19";

/// A raw pointer that may cross to the test thread. The tests own every
/// handle and free each exactly once.
struct Handle<T>(*mut T);
// SAFETY: only moved to the thread that waits on it, never shared.
unsafe impl<T> Send for Handle<T> {}

/// A channel whose sender is the callback's context. Boxed so the address
/// handed across stays put however the waiter moves.
struct Waiter<T> {
    tx: Box<Sender<T>>,
    rx: Receiver<T>,
}

impl<T> Waiter<T> {
    fn new() -> Self {
        let (tx, rx) = channel();
        Self {
            tx: Box::new(tx),
            rx,
        }
    }

    fn context(&self) -> *mut c_void {
        std::ptr::from_ref::<Sender<T>>(&self.tx).cast_mut().cast()
    }

    fn wait(&self, what: &str) -> T {
        self.rx
            .recv_timeout(PATIENCE)
            .unwrap_or_else(|_| panic!("no callback for {what}"))
    }
}

/// The sender a callback's context points to.
///
/// # Safety
/// `context` must come from [`Waiter::context`] on a live waiter.
unsafe fn sender<'a, T>(context: *mut c_void) -> &'a Sender<T> {
    unsafe { &*context.cast::<Sender<T>>() }
}

fn text(message: *const c_char) -> String {
    if message.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(message) }
            .to_string_lossy()
            .into_owned()
    }
}

type EndpointEvent = (i32, Handle<MoqomDirectEndpoint>, String);
type ConnectionEvent = (i32, Handle<MoqomDirectConnection>, String);
type BiEvent = (
    i32,
    Handle<MoqomDirectSendStream>,
    Handle<MoqomDirectRecvStream>,
);
type SendEvent = (i32, Handle<MoqomDirectSendStream>);
type RecvEvent = (i32, Handle<MoqomDirectRecvStream>);
type BytesEvent = (i32, Vec<u8>, u64);
type StatusEvent = (i32, u64);
type ClosedEvent = (i32, u64, String);

extern "C" fn on_endpoint(
    context: *mut c_void,
    status: i32,
    endpoint: *mut MoqomDirectEndpoint,
    message: *const c_char,
) {
    let _ =
        unsafe { sender::<EndpointEvent>(context) }.send((status, Handle(endpoint), text(message)));
}

extern "C" fn on_connection(
    context: *mut c_void,
    status: i32,
    connection: *mut MoqomDirectConnection,
    message: *const c_char,
) {
    let _ = unsafe { sender::<ConnectionEvent>(context) }.send((
        status,
        Handle(connection),
        text(message),
    ));
}

extern "C" fn on_bi(
    context: *mut c_void,
    status: i32,
    send: *mut MoqomDirectSendStream,
    recv: *mut MoqomDirectRecvStream,
) {
    let _ = unsafe { sender::<BiEvent>(context) }.send((status, Handle(send), Handle(recv)));
}

extern "C" fn on_send(context: *mut c_void, status: i32, send: *mut MoqomDirectSendStream) {
    let _ = unsafe { sender::<SendEvent>(context) }.send((status, Handle(send)));
}

extern "C" fn on_recv(context: *mut c_void, status: i32, recv: *mut MoqomDirectRecvStream) {
    let _ = unsafe { sender::<RecvEvent>(context) }.send((status, Handle(recv)));
}

extern "C" fn on_bytes(
    context: *mut c_void,
    status: i32,
    data: *const u8,
    length: usize,
    code: u64,
) {
    let bytes = if data.is_null() {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, length) }.to_vec()
    };
    let _ = unsafe { sender::<BytesEvent>(context) }.send((status, bytes, code));
}

extern "C" fn on_status(context: *mut c_void, status: i32, code: u64) {
    let _ = unsafe { sender::<StatusEvent>(context) }.send((status, code));
}

extern "C" fn on_closed(context: *mut c_void, status: i32, code: u64, reason: *const c_char) {
    let _ = unsafe { sender::<ClosedEvent>(context) }.send((status, code, text(reason)));
}

/// An endpoint config for loopback, optionally asking a STUN server.
struct Config {
    datagrams: bool,
    stun: Option<(CString, u16)>,
}

impl Config {
    fn plain() -> Self {
        Self {
            datagrams: true,
            stun: None,
        }
    }

    fn raw(&self) -> MoqomDirectEndpointConfig {
        MoqomDirectEndpointConfig {
            port: 0,
            alpn: ALPN.as_ptr(),
            idle_timeout_ms: 3_000,
            datagrams: u8::from(self.datagrams),
            stun_host: self
                .stun
                .as_ref()
                .map_or(std::ptr::null(), |(host, _)| host.as_ptr()),
            stun_port: self.stun.as_ref().map_or(0, |(_, port)| *port),
            stun_timeout_ms: 1_000,
        }
    }
}

fn bind(config: &Config) -> *mut MoqomDirectEndpoint {
    let waiter = Waiter::<EndpointEvent>::new();
    let raw = config.raw();
    unsafe { moqom_direct_endpoint_bind(&raw const raw, waiter.context(), Some(on_endpoint)) };
    let (status, endpoint, message) = waiter.wait("bind");
    assert_eq!(status, STATUS_OK, "bind: {message}");
    assert!(!endpoint.0.is_null());
    endpoint.0
}

fn fingerprint(endpoint: *const MoqomDirectEndpoint) -> [u8; 32] {
    let mut der = std::ptr::null();
    let mut length = 0;
    let status =
        unsafe { moqom_direct_endpoint_certificate(endpoint, &raw mut der, &raw mut length) };
    assert_eq!(status, STATUS_OK);
    let der = unsafe { std::slice::from_raw_parts(der, length) };
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, der);
    digest.as_ref().try_into().expect("32 bytes")
}

fn loopback(endpoint: *const MoqomDirectEndpoint) -> MoqomDirectAddress {
    let port = unsafe { moqom_direct_endpoint_port(endpoint) };
    assert_ne!(port, 0);
    SocketAddr::from((Ipv4Addr::LOCALHOST, port)).into()
}

/// Start an accept on `acceptor` for `dialler` and a dial the other way, and
/// return both outcomes: (dialled, accepted).
fn race(
    dialler: *mut MoqomDirectEndpoint,
    dial_pin: [u8; 32],
    acceptor: *mut MoqomDirectEndpoint,
    accept_pin: [u8; 32],
    timeout_ms: u32,
) -> (ConnectionEvent, ConnectionEvent) {
    race_to(
        loopback(acceptor),
        dialler,
        dial_pin,
        acceptor,
        accept_pin,
        timeout_ms,
    )
}

/// [`race`], dialling the acceptor at `target`.
fn race_to(
    target: MoqomDirectAddress,
    dialler: *mut MoqomDirectEndpoint,
    dial_pin: [u8; 32],
    acceptor: *mut MoqomDirectEndpoint,
    accept_pin: [u8; 32],
    timeout_ms: u32,
) -> (ConnectionEvent, ConnectionEvent) {
    let accepted = Waiter::<ConnectionEvent>::new();
    let dialled = Waiter::<ConnectionEvent>::new();
    let target = [target];
    unsafe {
        moqom_direct_endpoint_accept(
            acceptor,
            accept_pin.as_ptr(),
            timeout_ms,
            accepted.context(),
            Some(on_connection),
        );
        moqom_direct_endpoint_dial(
            dialler,
            target.as_ptr(),
            target.len(),
            dial_pin.as_ptr(),
            timeout_ms,
            dialled.context(),
            Some(on_connection),
        );
    }
    (dialled.wait("dial"), accepted.wait("accept"))
}

/// Two endpoints and the connection between them: (dialler side, acceptor side).
struct Pair {
    endpoints: [*mut MoqomDirectEndpoint; 2],
    dialler: *mut MoqomDirectConnection,
    acceptor: *mut MoqomDirectConnection,
}

impl Pair {
    fn new(dialler: &Config, acceptor: &Config) -> Self {
        let a = bind(dialler);
        let b = bind(acceptor);
        let ((dial, dialled, why), (accept, accepted, how)) =
            race(a, fingerprint(b), b, fingerprint(a), 5_000);
        assert_eq!(dial, STATUS_OK, "dial: {why}");
        assert_eq!(accept, STATUS_OK, "accept: {how}");
        Self {
            endpoints: [a, b],
            dialler: dialled.0,
            acceptor: accepted.0,
        }
    }
}

impl Drop for Pair {
    fn drop(&mut self) {
        unsafe {
            moqom_direct_connection_free(self.dialler);
            moqom_direct_connection_free(self.acceptor);
            for endpoint in self.endpoints {
                moqom_direct_endpoint_free(endpoint);
            }
        }
    }
}

fn open_bi(
    connection: *mut MoqomDirectConnection,
) -> (*mut MoqomDirectSendStream, *mut MoqomDirectRecvStream) {
    let waiter = Waiter::<BiEvent>::new();
    unsafe { moqom_direct_connection_open_bi(connection, waiter.context(), Some(on_bi)) };
    let (status, send, recv) = waiter.wait("open_bi");
    assert_eq!(status, STATUS_OK);
    (send.0, recv.0)
}

fn accept_bi(
    connection: *mut MoqomDirectConnection,
) -> (*mut MoqomDirectSendStream, *mut MoqomDirectRecvStream) {
    let waiter = Waiter::<BiEvent>::new();
    unsafe { moqom_direct_connection_accept_bi(connection, waiter.context(), Some(on_bi)) };
    let (status, send, recv) = waiter.wait("accept_bi");
    assert_eq!(status, STATUS_OK);
    (send.0, recv.0)
}

fn open_uni(connection: *mut MoqomDirectConnection) -> *mut MoqomDirectSendStream {
    let waiter = Waiter::<SendEvent>::new();
    unsafe { moqom_direct_connection_open_uni(connection, waiter.context(), Some(on_send)) };
    let (status, send) = waiter.wait("open_uni");
    assert_eq!(status, STATUS_OK);
    send.0
}

fn accept_uni(connection: *mut MoqomDirectConnection) -> *mut MoqomDirectRecvStream {
    let waiter = Waiter::<RecvEvent>::new();
    unsafe { moqom_direct_connection_accept_uni(connection, waiter.context(), Some(on_recv)) };
    let (status, recv) = waiter.wait("accept_uni");
    assert_eq!(status, STATUS_OK);
    recv.0
}

fn write(stream: *mut MoqomDirectSendStream, data: &[u8]) -> StatusEvent {
    let waiter = Waiter::<StatusEvent>::new();
    unsafe {
        moqom_direct_send_write(
            stream,
            data.as_ptr(),
            data.len(),
            waiter.context(),
            Some(on_status),
        );
    }
    waiter.wait("write")
}

fn read(stream: *mut MoqomDirectRecvStream, max: usize) -> BytesEvent {
    let waiter = Waiter::<BytesEvent>::new();
    unsafe { moqom_direct_recv_read(stream, max, waiter.context(), Some(on_bytes)) };
    waiter.wait("read")
}

/// Everything up to the end of the stream, or the failure that ended it
/// first: (bytes, final status, code).
fn read_to_end(stream: *mut MoqomDirectRecvStream) -> (Vec<u8>, i32, u64) {
    let mut all = Vec::new();
    loop {
        let (status, data, code) = read(stream, 7);
        if status != STATUS_OK {
            return (all, status, code);
        }
        all.extend_from_slice(&data);
    }
}

#[test]
fn the_version_and_every_status_have_answers() {
    assert_eq!(moqom_direct_abi_version(), 1);
    for status in [
        STATUS_OK,
        STATUS_END,
        STATUS_NULL,
        STATUS_INVALID,
        STATUS_IO,
        STATUS_TLS,
        STATUS_TIMEOUT,
        STATUS_HANDSHAKE,
        STATUS_CLOSED,
        STATUS_RESET,
        STATUS_STOPPED,
        STATUS_CANCELLED,
        STATUS_UNSUPPORTED,
        STATUS_TOO_LARGE,
        STATUS_BUSY,
        STATUS_NOT_FOUND,
        STATUS_PANIC,
    ] {
        let message = text(moqom_direct_status_message(status));
        assert!(!message.is_empty());
        assert_ne!(message, "unknown status", "status {status}");
    }
    assert_eq!(text(moqom_direct_status_message(-99)), "unknown status");
}

#[test]
fn null_pointers_are_reported_rather_than_dereferenced() {
    let null_endpoint = std::ptr::null_mut::<MoqomDirectEndpoint>();
    let null_connection = std::ptr::null_mut::<MoqomDirectConnection>();

    let bound = Waiter::<EndpointEvent>::new();
    unsafe { moqom_direct_endpoint_bind(std::ptr::null(), bound.context(), Some(on_endpoint)) };
    let (status, endpoint, _) = bound.wait("bind");
    assert_eq!(status, STATUS_NULL);
    assert!(endpoint.0.is_null());

    // A config without its required ALPN.
    let raw = MoqomDirectEndpointConfig {
        alpn: std::ptr::null(),
        ..Config::plain().raw()
    };
    unsafe { moqom_direct_endpoint_bind(&raw const raw, bound.context(), Some(on_endpoint)) };
    assert_eq!(bound.wait("bind").0, STATUS_NULL);

    let dialled = Waiter::<ConnectionEvent>::new();
    let pin = [0u8; 32];
    unsafe {
        moqom_direct_endpoint_dial(
            null_endpoint,
            std::ptr::null(),
            0,
            pin.as_ptr(),
            1_000,
            dialled.context(),
            Some(on_connection),
        );
    }
    assert_eq!(dialled.wait("dial").0, STATUS_NULL);

    let bytes = Waiter::<BytesEvent>::new();
    unsafe {
        moqom_direct_connection_read_datagram(null_connection, bytes.context(), Some(on_bytes));
        moqom_direct_recv_read(std::ptr::null_mut(), 16, bytes.context(), Some(on_bytes));
    }
    assert_eq!(bytes.wait("read_datagram").0, STATUS_NULL);
    assert_eq!(bytes.wait("read").0, STATUS_NULL);

    let mut address = MoqomDirectAddress::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 1)));
    let mut out = [0u8; 32];
    unsafe {
        assert_eq!(moqom_direct_endpoint_port(null_endpoint), 0);
        assert_eq!(
            moqom_direct_endpoint_reflexive(null_endpoint, &raw mut address),
            STATUS_NULL
        );
        assert_eq!(
            moqom_direct_endpoint_certificate(
                null_endpoint,
                std::ptr::null_mut(),
                std::ptr::null_mut()
            ),
            STATUS_NULL
        );
        assert_eq!(
            moqom_direct_endpoint_punch_start(null_endpoint, std::ptr::null(), 0, 10),
            STATUS_NULL
        );
        assert!(moqom_direct_connection_alpn(null_connection).is_null());
        assert_eq!(
            moqom_direct_connection_peer_certificate(null_connection, out.as_mut_ptr()),
            STATUS_NULL
        );
        assert_eq!(
            moqom_direct_connection_max_datagram_size(null_connection),
            0
        );
        assert_eq!(
            moqom_direct_connection_remote(null_connection, &raw mut address),
            STATUS_NULL
        );
        assert_eq!(
            moqom_direct_connection_send_datagram(null_connection, std::ptr::null(), 0),
            STATUS_NULL
        );
        assert_eq!(moqom_direct_send_finish(std::ptr::null_mut()), STATUS_NULL);
        assert_eq!(
            moqom_direct_send_reset(std::ptr::null_mut(), 0),
            STATUS_NULL
        );
        assert_eq!(moqom_direct_recv_stop(std::ptr::null_mut(), 0), STATUS_NULL);

        // No callback: nothing to call, and nothing to crash.
        moqom_direct_endpoint_bind(std::ptr::null(), std::ptr::null_mut(), None);

        // Every operation that takes a handle without a result accepts null.
        moqom_direct_endpoint_punch_stop(null_endpoint);
        moqom_direct_endpoint_close(null_endpoint);
        moqom_direct_connection_close(null_connection, 0, std::ptr::null());
        moqom_direct_endpoint_free(null_endpoint);
        moqom_direct_connection_free(null_connection);
        moqom_direct_send_free(std::ptr::null_mut());
        moqom_direct_recv_free(std::ptr::null_mut());
    }
}

#[test]
fn malformed_arguments_are_invalid() {
    let raw = MoqomDirectEndpointConfig {
        idle_timeout_ms: 0,
        ..Config::plain().raw()
    };
    let bound = Waiter::<EndpointEvent>::new();
    unsafe { moqom_direct_endpoint_bind(&raw const raw, bound.context(), Some(on_endpoint)) };
    let (status, _, message) = bound.wait("bind");
    assert_eq!(status, STATUS_INVALID);
    assert!(message.contains("idle_timeout_ms"), "{message}");

    let endpoint = bind(&Config::plain());
    let bad = MoqomDirectAddress {
        family: 5,
        address: [0; 16],
        port: 1,
    };
    assert_eq!(
        unsafe { moqom_direct_endpoint_punch_start(endpoint, &raw const bad, 1, 10) },
        STATUS_INVALID
    );
    let dialled = Waiter::<ConnectionEvent>::new();
    let pin = [0u8; 32];
    unsafe {
        moqom_direct_endpoint_dial(
            endpoint,
            std::ptr::null(),
            0,
            pin.as_ptr(),
            1_000,
            dialled.context(),
            Some(on_connection),
        );
    }
    assert_eq!(dialled.wait("dial").0, STATUS_INVALID);
    unsafe { moqom_direct_endpoint_free(endpoint) };
}

#[test]
fn addresses_convert_for_both_families() {
    for text in ["198.51.100.7:50000", "[2001:db8::7]:443"] {
        let address: SocketAddr = text.parse().expect("address");
        let raw = MoqomDirectAddress::from(address);
        assert_eq!(raw.family, if address.is_ipv4() { 4 } else { 6 });
        assert_eq!(raw.to_socket_addr(), Some(address));
    }
    let mapped: SocketAddr = "[::ffff:192.0.2.1]:9".parse().expect("address");
    assert_eq!(MoqomDirectAddress::from(mapped).family, 4);
}

#[test]
fn pinned_peers_connect_and_see_each_other() {
    let pair = Pair::new(&Config::plain(), &Config::plain());
    let [a, b] = pair.endpoints;
    let mut peer = [0u8; 32];
    unsafe {
        assert_eq!(
            moqom_direct_connection_peer_certificate(pair.dialler, peer.as_mut_ptr()),
            STATUS_OK
        );
        assert_eq!(peer, fingerprint(b));
        assert_eq!(
            moqom_direct_connection_peer_certificate(pair.acceptor, peer.as_mut_ptr()),
            STATUS_OK
        );
        assert_eq!(peer, fingerprint(a));
        assert_eq!(text(moqom_direct_connection_alpn(pair.dialler)), "moqt-19");
        assert_eq!(text(moqom_direct_connection_alpn(pair.acceptor)), "moqt-19");

        let mut remote = MoqomDirectAddress::from(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
        assert_eq!(
            moqom_direct_connection_remote(pair.dialler, &raw mut remote),
            STATUS_OK
        );
        assert_eq!(remote, loopback(b));
    }
}

#[test]
fn a_wrong_pin_is_refused_in_either_direction() {
    let a = bind(&Config::plain());
    let b = bind(&Config::plain());
    let stranger = [0xAB; 32];

    // The dialler expects someone else: it refuses the acceptor's certificate,
    // and the acceptor never sees its peer.
    let ((dial, connection, _), (accept, _, _)) = race(a, stranger, b, fingerprint(a), 800);
    assert!(
        dial == STATUS_HANDSHAKE || dial == STATUS_TIMEOUT,
        "dial status {dial}"
    );
    assert!(connection.0.is_null());
    assert_eq!(accept, STATUS_TIMEOUT);

    // The acceptor expects someone else: the dialler's certificate is refused,
    // and the accept waits on until its deadline. In TLS 1.3 the client
    // finishes before the server has judged its certificate, so the dial may
    // briefly succeed -- but only with a connection the acceptor closes at once.
    let ((dial, dialled, _), (accept, connection, _)) = race(a, fingerprint(b), b, stranger, 800);
    match dial {
        STATUS_OK => {
            let closed = Waiter::<ClosedEvent>::new();
            unsafe { moqom_direct_connection_closed(dialled.0, closed.context(), Some(on_closed)) };
            let (status, _, reason) = closed.wait("the refused connection closing");
            assert_eq!(status, STATUS_CLOSED, "{reason}");
            unsafe { moqom_direct_connection_free(dialled.0) };
        }
        STATUS_HANDSHAKE | STATUS_TIMEOUT => {}
        other => panic!("dial status {other}"),
    }
    assert_eq!(accept, STATUS_TIMEOUT);
    assert!(connection.0.is_null());

    unsafe {
        moqom_direct_endpoint_free(a);
        moqom_direct_endpoint_free(b);
    }
}

#[test]
fn bidirectional_streams_carry_bytes_both_ways_to_the_end() {
    let pair = Pair::new(&Config::plain(), &Config::plain());

    let (send, recv) = open_bi(pair.dialler);
    assert_eq!(write(send, b"hello, "), (STATUS_OK, 0));
    assert_eq!(write(send, b"acceptor"), (STATUS_OK, 0));
    assert_eq!(unsafe { moqom_direct_send_finish(send) }, STATUS_OK);
    assert_eq!(unsafe { moqom_direct_send_finish(send) }, STATUS_CLOSED);

    let (their_send, their_recv) = accept_bi(pair.acceptor);
    assert_eq!(
        read_to_end(their_recv),
        (b"hello, acceptor".to_vec(), STATUS_END, 0)
    );
    assert_eq!(write(their_send, b"hello, dialler"), (STATUS_OK, 0));
    assert_eq!(unsafe { moqom_direct_send_finish(their_send) }, STATUS_OK);
    assert_eq!(
        read_to_end(recv),
        (b"hello, dialler".to_vec(), STATUS_END, 0)
    );

    unsafe {
        moqom_direct_send_free(send);
        moqom_direct_recv_free(recv);
        moqom_direct_send_free(their_send);
        moqom_direct_recv_free(their_recv);
    }
}

#[test]
fn unidirectional_streams_work_from_either_side() {
    let pair = Pair::new(&Config::plain(), &Config::plain());
    for (from, to) in [(pair.dialler, pair.acceptor), (pair.acceptor, pair.dialler)] {
        let send = open_uni(from);
        // Several writes issued without waiting, which must arrive in order.
        let waiter = Waiter::<StatusEvent>::new();
        for chunk in [&b"one "[..], b"two ", b"three"] {
            unsafe {
                moqom_direct_send_write(
                    send,
                    chunk.as_ptr(),
                    chunk.len(),
                    waiter.context(),
                    Some(on_status),
                );
            }
        }
        assert_eq!(unsafe { moqom_direct_send_finish(send) }, STATUS_OK);
        for _ in 0..3 {
            assert_eq!(waiter.wait("write"), (STATUS_OK, 0));
        }
        let recv = accept_uni(to);
        assert_eq!(
            read_to_end(recv),
            (b"one two three".to_vec(), STATUS_END, 0)
        );
        unsafe {
            moqom_direct_send_free(send);
            moqom_direct_recv_free(recv);
        }
    }
}

#[test]
fn a_reset_and_a_stop_carry_their_codes() {
    let pair = Pair::new(&Config::plain(), &Config::plain());

    let send = open_uni(pair.dialler);
    assert_eq!(write(send, b"partial"), (STATUS_OK, 0));
    assert_eq!(unsafe { moqom_direct_send_reset(send, 42) }, STATUS_OK);
    assert_eq!(unsafe { moqom_direct_send_reset(send, 42) }, STATUS_CLOSED);
    let recv = accept_uni(pair.acceptor);
    let (_, status, code) = read_to_end(recv);
    assert_eq!((status, code), (STATUS_RESET, 42));
    unsafe {
        moqom_direct_send_free(send);
        moqom_direct_recv_free(recv);
    }

    let (send, recv) = open_bi(pair.dialler);
    assert_eq!(write(send, b"x"), (STATUS_OK, 0));
    let (their_send, their_recv) = accept_bi(pair.acceptor);
    assert_eq!(unsafe { moqom_direct_recv_stop(their_recv, 7) }, STATUS_OK);
    // The stop takes a round trip to arrive; write until it has.
    let chunk = vec![0u8; 4096];
    let stopped = (0..1_000).find_map(|_| {
        let outcome = write(send, &chunk);
        (outcome.0 != STATUS_OK).then_some(outcome)
    });
    assert_eq!(stopped, Some((STATUS_STOPPED, 7)));
    unsafe {
        moqom_direct_send_free(send);
        moqom_direct_recv_free(recv);
        moqom_direct_send_free(their_send);
        moqom_direct_recv_free(their_recv);
    }
}

#[test]
fn freeing_a_stream_cancels_its_pending_operations() {
    let pair = Pair::new(&Config::plain(), &Config::plain());

    // Far more than the peer's flow-control window, so the write must wait.
    let send = open_uni(pair.dialler);
    let blocked = Waiter::<StatusEvent>::new();
    let huge = vec![0u8; 64 << 20];
    unsafe {
        moqom_direct_send_write(
            send,
            huge.as_ptr(),
            huge.len(),
            blocked.context(),
            Some(on_status),
        );
    }
    let recv = accept_uni(pair.acceptor);
    assert_eq!(read(recv, 16).0, STATUS_OK);
    unsafe { moqom_direct_send_free(send) };
    assert_eq!(blocked.wait("the blocked write").0, STATUS_CANCELLED);
    // Truncated, so reset rather than finished.
    let (_, status, code) = read_to_end(recv);
    assert_eq!((status, code), (STATUS_RESET, 0));
    unsafe { moqom_direct_recv_free(recv) };

    let (send, recv) = open_bi(pair.dialler);
    let pending = Waiter::<BytesEvent>::new();
    unsafe {
        moqom_direct_recv_read(recv, 16, pending.context(), Some(on_bytes));
        moqom_direct_recv_free(recv);
    }
    assert_eq!(pending.wait("the pending read").0, STATUS_CANCELLED);
    unsafe { moqom_direct_send_free(send) };
}

#[test]
fn datagrams_cross_both_ways_when_both_offer_them() {
    let pair = Pair::new(&Config::plain(), &Config::plain());
    for (from, to) in [(pair.dialler, pair.acceptor), (pair.acceptor, pair.dialler)] {
        assert!(unsafe { moqom_direct_connection_max_datagram_size(from) } > 0);
        let waiter = Waiter::<BytesEvent>::new();
        unsafe { moqom_direct_connection_read_datagram(to, waiter.context(), Some(on_bytes)) };
        // Unreliable even on loopback in principle, so a few tries.
        let mut received = None;
        for _ in 0..20 {
            let payload = b"ping";
            assert_eq!(
                unsafe {
                    moqom_direct_connection_send_datagram(from, payload.as_ptr(), payload.len())
                },
                STATUS_OK
            );
            if let Ok(event) = waiter.rx.recv_timeout(Duration::from_millis(250)) {
                received = Some(event);
                break;
            }
        }
        assert_eq!(received, Some((STATUS_OK, b"ping".to_vec(), 0)));

        let huge = vec![0u8; 64 * 1024];
        assert_eq!(
            unsafe { moqom_direct_connection_send_datagram(from, huge.as_ptr(), huge.len()) },
            STATUS_TOO_LARGE
        );
    }
}

#[test]
fn a_peer_that_offers_no_datagrams_gets_none() {
    let refuses = Config {
        datagrams: false,
        stun: None,
    };
    let pair = Pair::new(&Config::plain(), &refuses);
    let payload = b"ping";
    unsafe {
        assert_eq!(moqom_direct_connection_max_datagram_size(pair.dialler), 0);
        assert_eq!(
            moqom_direct_connection_send_datagram(pair.dialler, payload.as_ptr(), payload.len()),
            STATUS_UNSUPPORTED
        );
        // Nor the other way: off is off in both directions.
        assert_eq!(moqom_direct_connection_max_datagram_size(pair.acceptor), 0);
        assert_eq!(
            moqom_direct_connection_send_datagram(pair.acceptor, payload.as_ptr(), payload.len()),
            STATUS_UNSUPPORTED
        );
    }
}

#[test]
fn closing_reports_the_code_and_reason_on_both_sides() {
    let pair = Pair::new(&Config::plain(), &Config::plain());
    let theirs = Waiter::<ClosedEvent>::new();
    let ours = Waiter::<ClosedEvent>::new();
    let pending = Waiter::<BiEvent>::new();
    unsafe {
        moqom_direct_connection_closed(pair.acceptor, theirs.context(), Some(on_closed));
        moqom_direct_connection_closed(pair.dialler, ours.context(), Some(on_closed));
        moqom_direct_connection_accept_bi(pair.acceptor, pending.context(), Some(on_bi));
        moqom_direct_connection_close(pair.dialler, 9, c"bye".as_ptr());
    }
    assert_eq!(
        theirs.wait("their close"),
        (STATUS_CLOSED, 9, "bye".to_owned())
    );
    assert_eq!(ours.wait("our close"), (STATUS_CLOSED, 9, "bye".to_owned()));
    assert_eq!(pending.wait("pending accept_bi").0, STATUS_CLOSED);

    // Operations after the close fail rather than hang.
    let payload = b"late";
    assert_eq!(
        unsafe {
            moqom_direct_connection_send_datagram(pair.dialler, payload.as_ptr(), payload.len())
        },
        STATUS_CLOSED
    );
}

#[test]
fn freeing_a_connection_cancels_what_is_pending_on_it() {
    let mut pair = Pair::new(&Config::plain(), &Config::plain());
    let pending = Waiter::<RecvEvent>::new();
    let closed = Waiter::<ClosedEvent>::new();
    let theirs = Waiter::<ClosedEvent>::new();
    unsafe {
        moqom_direct_connection_accept_uni(pair.acceptor, pending.context(), Some(on_recv));
        moqom_direct_connection_closed(pair.acceptor, closed.context(), Some(on_closed));
        moqom_direct_connection_closed(pair.dialler, theirs.context(), Some(on_closed));
        moqom_direct_connection_free(pair.acceptor);
    }
    pair.acceptor = std::ptr::null_mut();
    assert_eq!(pending.wait("accept_uni").0, STATUS_CANCELLED);
    assert_eq!(closed.wait("closed").0, STATUS_CANCELLED);
    // With no handle left, the connection closes with code 0.
    assert_eq!(theirs.wait("their close").0, STATUS_CLOSED);
    assert_eq!(theirs.rx.try_recv().ok(), None);
}

#[test]
fn connections_outlive_the_endpoints_that_made_them() {
    let mut pair = Pair::new(&Config::plain(), &Config::plain());
    for endpoint in &mut pair.endpoints {
        unsafe { moqom_direct_endpoint_free(*endpoint) };
        *endpoint = std::ptr::null_mut();
    }
    let send = open_uni(pair.dialler);
    assert_eq!(write(send, b"still here"), (STATUS_OK, 0));
    assert_eq!(unsafe { moqom_direct_send_finish(send) }, STATUS_OK);
    let recv = accept_uni(pair.acceptor);
    assert_eq!(read_to_end(recv), (b"still here".to_vec(), STATUS_END, 0));
    unsafe {
        moqom_direct_send_free(send);
        moqom_direct_recv_free(recv);
    }
}

#[test]
fn closing_an_endpoint_cancels_a_pending_accept_and_refuses_more() {
    let endpoint = bind(&Config::plain());
    let accepted = Waiter::<ConnectionEvent>::new();
    let busy = Waiter::<ConnectionEvent>::new();
    let pin = [1u8; 32];
    let target = [loopback(endpoint)];
    unsafe {
        moqom_direct_endpoint_accept(
            endpoint,
            pin.as_ptr(),
            30_000,
            accepted.context(),
            Some(on_connection),
        );
        // One establishment at a time.
        moqom_direct_endpoint_dial(
            endpoint,
            target.as_ptr(),
            1,
            pin.as_ptr(),
            1_000,
            busy.context(),
            Some(on_connection),
        );
    }
    assert_eq!(busy.wait("dial").0, STATUS_BUSY);

    unsafe { moqom_direct_endpoint_close(endpoint) };
    let (status, connection, _) = accepted.wait("accept");
    assert_eq!(status, STATUS_CANCELLED);
    assert!(connection.0.is_null());

    unsafe {
        moqom_direct_endpoint_accept(
            endpoint,
            pin.as_ptr(),
            1_000,
            accepted.context(),
            Some(on_connection),
        );
    }
    assert_eq!(accepted.wait("accept after close").0, STATUS_CLOSED);
    assert_eq!(
        unsafe { moqom_direct_endpoint_punch_start(endpoint, target.as_ptr(), 1, 10) },
        STATUS_CLOSED
    );

    // Freeing an endpoint cancels too.
    let other = bind(&Config::plain());
    unsafe {
        moqom_direct_endpoint_accept(
            other,
            pin.as_ptr(),
            30_000,
            accepted.context(),
            Some(on_connection),
        );
        moqom_direct_endpoint_free(other);
        moqom_direct_endpoint_free(endpoint);
    }
    assert_eq!(
        accepted.wait("accept on a freed endpoint").0,
        STATUS_CANCELLED
    );
}

#[test]
fn stun_reports_the_address_the_server_saw() {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("server");
    let port = server.local_addr().expect("addr").port();
    let answering = std::thread::spawn(move || {
        let mut buffer = [0u8; 576];
        let (n, from) = server.recv_from(&mut buffer).expect("a request");
        assert!(n >= 20);
        let transaction: [u8; 12] = buffer[8..20].try_into().expect("12 bytes");
        let response = moqom_client::direct::stun::binding_response(transaction, from);
        server.send_to(&response, from).expect("answer");
        from
    });

    // By name, so the resolver is exercised; the endpoint takes the IPv4
    // address, being an IPv4 socket.
    let config = Config {
        datagrams: true,
        stun: Some((c"localhost".to_owned(), port)),
    };
    let endpoint = bind(&config);
    let from = answering.join().expect("server thread");
    let mut reflexive = MoqomDirectAddress::from(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
    unsafe {
        assert_eq!(
            moqom_direct_endpoint_reflexive(endpoint, &raw mut reflexive),
            STATUS_OK
        );
        assert_eq!(reflexive.to_socket_addr(), Some(from));
        assert_eq!(reflexive.port, moqom_direct_endpoint_port(endpoint));
        moqom_direct_endpoint_free(endpoint);
    }

    let silent = bind(&Config::plain());
    unsafe {
        assert_eq!(
            moqom_direct_endpoint_reflexive(silent, &raw mut reflexive),
            STATUS_NOT_FOUND
        );
        moqom_direct_endpoint_free(silent);
    }
}

#[test]
fn a_silent_stun_server_is_not_an_error() {
    // Bound and never read, so it never answers.
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("server");
    let config = Config {
        datagrams: true,
        stun: Some((
            c"127.0.0.1".to_owned(),
            server.local_addr().expect("addr").port(),
        )),
    };
    let endpoint = bind(&config);
    let mut reflexive = MoqomDirectAddress::from(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
    unsafe {
        assert_eq!(
            moqom_direct_endpoint_reflexive(endpoint, &raw mut reflexive),
            STATUS_NOT_FOUND
        );
        moqom_direct_endpoint_free(endpoint);
    }
}

#[test]
fn probes_go_out_from_the_endpoint_port_until_stopped() {
    let endpoint = bind(&Config::plain());
    let port = unsafe { moqom_direct_endpoint_port(endpoint) };
    let observers = [
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("observer"),
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("observer"),
    ];
    for observer in &observers {
        observer
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("timeout");
    }
    let address = |socket: &UdpSocket| MoqomDirectAddress::from(socket.local_addr().expect("addr"));

    let first = [address(&observers[0])];
    assert_eq!(
        unsafe { moqom_direct_endpoint_punch_start(endpoint, first.as_ptr(), 1, 20) },
        STATUS_OK
    );
    let mut buffer = [0u8; 64];
    for _ in 0..3 {
        let (n, from) = observers[0].recv_from(&mut buffer).expect("a probe");
        assert_eq!(&buffer[..n], b"MQDP");
        assert_eq!(from.port(), port);
    }

    // Starting again replaces the targets.
    let second = [address(&observers[1])];
    assert_eq!(
        unsafe { moqom_direct_endpoint_punch_start(endpoint, second.as_ptr(), 1, 20) },
        STATUS_OK
    );
    let (n, _) = observers[1].recv_from(&mut buffer).expect("a probe");
    assert_eq!(&buffer[..n], b"MQDP");
    while observers[0].recv_from(&mut buffer).is_ok() {}

    unsafe { moqom_direct_endpoint_punch_stop(endpoint) };
    std::thread::sleep(Duration::from_millis(50));
    observers[1]
        .set_read_timeout(Some(Duration::from_millis(10)))
        .expect("timeout");
    while observers[1].recv_from(&mut buffer).is_ok() {}
    observers[1]
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("timeout");
    assert!(
        observers[1].recv_from(&mut buffer).is_err(),
        "a probe after punch_stop"
    );
    unsafe { moqom_direct_endpoint_free(endpoint) };
}

#[test]
fn endpoints_connect_over_ipv6_on_the_port_they_report() {
    // The bind is dual-stack, so the one port the header reports takes IPv6
    // as well as IPv4, and an address of family 6 dials it.
    let a = bind(&Config::plain());
    let b = bind(&Config::plain());
    let port = unsafe { moqom_direct_endpoint_port(b) };
    let target = MoqomDirectAddress::from(SocketAddr::from((Ipv6Addr::LOCALHOST, port)));
    assert_eq!(target.family, 6);

    let ((dial, dialled, why), (accept, accepted, how)) =
        race_to(target, a, fingerprint(b), b, fingerprint(a), 5_000);
    assert_eq!(dial, STATUS_OK, "dial: {why}");
    assert_eq!(accept, STATUS_OK, "accept: {how}");
    unsafe {
        let mut remote = MoqomDirectAddress::from(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
        assert_eq!(
            moqom_direct_connection_remote(dialled.0, &raw mut remote),
            STATUS_OK
        );
        assert_eq!(remote, target);
        assert_eq!(
            moqom_direct_connection_remote(accepted.0, &raw mut remote),
            STATUS_OK
        );
        assert_eq!(remote.family, 6);
        assert_eq!(remote.port, moqom_direct_endpoint_port(a));
        moqom_direct_connection_free(dialled.0);
        moqom_direct_connection_free(accepted.0);
        moqom_direct_endpoint_free(a);
        moqom_direct_endpoint_free(b);
    }
}
