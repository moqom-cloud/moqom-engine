//! Does a codepoint set on the socket reach the wire?
//!
//! The question is not whether `setsockopt` succeeds — it does, and did before any of this, while
//! every datagram left with a codepoint of zero. `quinn-udp` attaches an `IP_TOS` control message
//! to each send carrying the ECN bits, and a control message sets the whole byte, so the socket's
//! configuration was overwritten on the way out. That is invisible from the sending side: the
//! option reads back exactly as it was set. It is only visible to whoever receives the packet.
//!
//! So the receiver is the test. See `vendor/quinn/VENDORED.md` for the patch this pins, and
//! delete both together when upstream carries it.

#![cfg(unix)]

use std::mem;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;

use quinn_udp::{EcnCodepoint, Transmit, UdpSocketState};

/// AF41, which is what an access point reads as interactive video.
const DSCP: u8 = 34;

/// The receiver's view of one datagram's type-of-service byte.
fn tos_of_next_datagram(socket: &UdpSocket) -> u8 {
    let mut payload = [0u8; 64];
    let mut control = [0u8; 128];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
    hdr.msg_iov = &raw mut iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = control.as_mut_ptr().cast();
    hdr.msg_controllen = control.len() as _;

    let read = unsafe { libc::recvmsg(socket.as_raw_fd(), &raw mut hdr, 0) };
    assert!(
        read > 0,
        "no datagram arrived: {}",
        std::io::Error::last_os_error()
    );

    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const hdr) };
    while !cmsg.is_null() {
        let header = unsafe { &*cmsg };
        if header.cmsg_level == libc::IPPROTO_IP
            && (header.cmsg_type == libc::IP_TOS || header.cmsg_type == libc::IP_RECVTOS)
        {
            return unsafe { *libc::CMSG_DATA(cmsg) };
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(&raw const hdr, cmsg) };
    }
    panic!("the datagram arrived without a type-of-service control message");
}

/// A socket that will report the type-of-service byte of what it receives.
fn listening() -> UdpSocket {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("binding a receiver");
    let on: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_RECVTOS,
            (&raw const on).cast(),
            mem::size_of::<libc::c_int>() as _,
        )
    };
    assert_eq!(rc, 0, "asking for the type-of-service byte");
    socket
}

/// Send one datagram from a socket carrying `dscp`, and report what arrived.
fn arrives_with(dscp: Option<u8>) -> u8 {
    let receiver = listening();
    let to: SocketAddr = receiver.local_addr().expect("the receiver's address");

    let sender = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .expect("a sending socket");
    if let Some(dscp) = dscp {
        sender
            .set_tos_v4(u32::from(dscp) << 2)
            .expect("setting the codepoint");
    }
    sender
        .bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())
        .expect("binding the sender");

    let state = UdpSocketState::new((&sender).into()).expect("wrapping the sender");
    state
        .send(
            (&sender).into(),
            &Transmit {
                destination: to,
                ecn: Some(EcnCodepoint::Ect0),
                contents: b"one datagram",
                segment_size: None,
                src_ip: None,
            },
        )
        .expect("sending");

    tos_of_next_datagram(&receiver)
}

#[test]
fn a_codepoint_set_on_the_socket_reaches_the_wire() {
    let tos = arrives_with(Some(DSCP));

    assert_eq!(
        tos >> 2,
        DSCP,
        "the codepoint was replaced on the way out; it arrived as {tos:#04x}"
    );

    // And the transport still owns the two bits underneath it. Marking is not allowed to cost
    // congestion signalling, which is the thing the byte was already being used for.
    assert_eq!(tos & 0b11, EcnCodepoint::Ect0 as u8, "ECN was overwritten");
}

#[test]
fn an_unmarked_socket_is_left_alone() {
    let tos = arrives_with(None);

    assert_eq!(tos >> 2, 0, "a socket nobody marked acquired a codepoint");
    assert_eq!(tos & 0b11, EcnCodepoint::Ect0 as u8);
}
