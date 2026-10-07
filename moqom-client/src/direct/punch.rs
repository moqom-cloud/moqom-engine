//! Opening a NAT from the inside, so the peer's first packets are let in.
//!
//! Most home NATs admit a datagram from outside only if the inside host has
//! recently sent one to that same address. Two devices behind such NATs can
//! therefore never reach each other by one dialling: the dialler's packets are
//! dropped at the far NAT, which has never seen the far device send anything to
//! it. Both sending at once fixes that. Each side's outbound packets open its
//! own NAT to the other, and the QUIC handshake then passes through both.
//!
//! The probes go out on the same socket QUIC uses, through a clone of its file
//! descriptor, because a NAT's permission is per internal socket. They are four
//! bytes, which QUIC cannot parse as a packet and discards without answering.

use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

/// What a probe says, in case anybody is reading a packet capture.
pub(crate) const PROBE: &[u8] = b"MQDP";

/// Probes `targets` from `socket` every `interval` until dropped.
pub(crate) struct Puncher {
    /// Never sent on. Dropping it wakes the thread out of its wait at once, so
    /// a replaced puncher stops before its successor's first round rather than
    /// up to an interval later.
    _stop: mpsc::Sender<()>,
}

impl Puncher {
    pub(crate) fn start(socket: UdpSocket, targets: Vec<SocketAddr>, interval: Duration) -> Self {
        let (stop, stopped) = mpsc::channel::<()>();
        // A thread rather than a task, since the socket is a plain std one
        // shared with QUIC and registering a second handle to it with the
        // runtime's reactor would be asking for confusion over readiness.
        std::thread::spawn(move || {
            loop {
                for target in &targets {
                    // Unreachable targets are expected -- a candidate on a
                    // network this device is not on -- and say nothing about
                    // the others, so every error is ignored.
                    let _ = socket.send_to(PROBE, target);
                }
                match stopped.recv_timeout(interval) {
                    Err(RecvTimeoutError::Timeout) => {}
                    Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
                }
            }
        });
        Self { _stop: stop }
    }
}
