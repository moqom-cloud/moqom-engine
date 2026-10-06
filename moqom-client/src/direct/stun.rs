//! The smallest STUN client that finds this socket's public address.
//!
//! A NAT rewrites the source address of everything leaving a home network, so
//! the address a device sees on its own interface is not the one a peer
//! elsewhere must send to. A STUN Binding request (RFC 8489) asks a server what
//! address the request arrived from, which is that public address.
//!
//! It has to be asked from the very socket the direct path will use, because a
//! NAT maps each internal socket separately. So this runs before the socket is
//! handed to QUIC: afterwards QUIC owns every datagram that arrives on it, and
//! would discard the answer as a packet it could not parse.
//!
//! Only the Binding exchange, without authentication or `FINGERPRINT`. The
//! server is chosen by the caller; any public STUN server works, and a relay
//! could answer the same request later.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use aws_lc_rs::rand::{SecureRandom, SystemRandom};

const MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const MAPPED_ADDRESS: u16 = 0x0001;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// A Binding request with transaction ID `transaction`.
#[must_use]
pub fn binding_request(transaction: [u8; 12]) -> [u8; 20] {
    let mut out = [0u8; 20];
    out[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    // Length 0: no attributes.
    out[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out[8..20].copy_from_slice(&transaction);
    out
}

/// A Binding success response telling the requester it came from `from`.
///
/// For a test server, or a relay answering the same question.
#[must_use]
pub fn binding_response(transaction: [u8; 12], from: SocketAddr) -> Vec<u8> {
    let mut value = vec![0u8];
    let port = from.port() ^ (MAGIC_COOKIE >> 16) as u16;
    match from.ip() {
        IpAddr::V4(ip) => {
            value.push(0x01);
            value.extend_from_slice(&port.to_be_bytes());
            value.extend_from_slice(&(u32::from(ip) ^ MAGIC_COOKIE).to_be_bytes());
        }
        IpAddr::V6(ip) => {
            value.push(0x02);
            value.extend_from_slice(&port.to_be_bytes());
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(&transaction);
            value.extend(ip.octets().iter().zip(mask).map(|(a, b)| a ^ b));
        }
    }

    let mut out = Vec::with_capacity(20 + 4 + value.len());
    out.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
    out.extend_from_slice(&((4 + value.len()) as u16).to_be_bytes());
    out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(&transaction);
    out.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(&value);
    out
}

/// The address a Binding success response for `transaction` reports, if
/// `datagram` is one.
#[must_use]
pub fn parse_binding_response(datagram: &[u8], transaction: [u8; 12]) -> Option<SocketAddr> {
    if datagram.len() < 20
        || u16::from_be_bytes([datagram[0], datagram[1]]) != BINDING_SUCCESS
        || u32::from_be_bytes(datagram[4..8].try_into().ok()?) != MAGIC_COOKIE
        || datagram[8..20] != transaction
    {
        return None;
    }
    let length = u16::from_be_bytes([datagram[2], datagram[3]]) as usize;
    let mut attributes = datagram.get(20..20 + length)?;

    let mut plain = None;
    while attributes.len() >= 4 {
        let kind = u16::from_be_bytes([attributes[0], attributes[1]]);
        let len = u16::from_be_bytes([attributes[2], attributes[3]]) as usize;
        let value = attributes.get(4..4 + len)?;
        match kind {
            XOR_MAPPED_ADDRESS => return address(value, Some(transaction)),
            MAPPED_ADDRESS => plain = address(value, None),
            _ => {}
        }
        let padded = (len + 3) & !3;
        attributes = attributes.get(4 + padded..).unwrap_or_default();
    }
    plain
}

/// Decode a (XOR-)MAPPED-ADDRESS value. `xor` carries the transaction ID when
/// the value is obfuscated.
fn address(value: &[u8], xor: Option<[u8; 12]>) -> Option<SocketAddr> {
    let family = *value.get(1)?;
    let mut port = u16::from_be_bytes([*value.get(2)?, *value.get(3)?]);
    let mut mask = [0u8; 16];
    if let Some(transaction) = xor {
        port ^= (MAGIC_COOKIE >> 16) as u16;
        mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        mask[4..].copy_from_slice(&transaction);
    }
    let ip = match family {
        0x01 => {
            let raw: [u8; 4] = value.get(4..8)?.try_into().ok()?;
            let octets: Vec<u8> = raw.iter().zip(&mask[..4]).map(|(a, b)| a ^ b).collect();
            IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
        }
        0x02 => {
            let raw: [u8; 16] = value.get(4..20)?.try_into().ok()?;
            let mut octets = [0u8; 16];
            for (i, byte) in octets.iter_mut().enumerate() {
                *byte = raw[i] ^ mask[i];
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// Ask `server` for `socket`'s public address.
///
/// Blocking, and restores the socket's read timeout afterwards. Three attempts,
/// each waiting a third of `patience`, since a lost request is the common
/// failure and a single long wait would spend all of it on one.
///
/// # Errors
/// No answer within `patience`, or the socket refusing.
pub fn reflexive(socket: &UdpSocket, server: SocketAddr, patience: Duration) -> io::Result<SocketAddr> {
    let mut transaction = [0u8; 12];
    SystemRandom::new()
        .fill(&mut transaction)
        .map_err(|_| io::Error::other("the random source failed"))?;
    let request = binding_request(transaction);

    let previous = socket.read_timeout()?;
    let attempt = (patience / 3).max(Duration::from_millis(10));
    socket.set_read_timeout(Some(attempt))?;
    let result = (|| {
        let mut buffer = [0u8; 576];
        for _ in 0..3 {
            socket.send_to(&request, server)?;
            let deadline = std::time::Instant::now() + attempt;
            while std::time::Instant::now() < deadline {
                match socket.recv_from(&mut buffer) {
                    Ok((n, from)) if from == server => {
                        if let Some(address) = parse_binding_response(&buffer[..n], transaction) {
                            return Ok(address);
                        }
                    }
                    Ok(_) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "the STUN server did not answer",
        ))
    })();
    socket.set_read_timeout(previous)?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5769 §2.2, the IPv4 sample response, with `MESSAGE-INTEGRITY`
    /// zeroed: this client does not check it, and the address is what matters.
    #[test]
    fn the_rfc_5769_ipv4_vector_decodes() {
        let transaction = [
            0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
        ];
        let mut vector = vec![0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42];
        vector.extend_from_slice(&transaction);
        vector.extend_from_slice(&[0x80, 0x22, 0x00, 0x0b]);
        vector.extend_from_slice(b"test vector ");
        vector.extend_from_slice(&[0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47]);
        vector.extend_from_slice(&[0xe1, 0x12, 0xa6, 0x43]);
        vector.extend_from_slice(&[0x00, 0x08, 0x00, 0x14]);
        vector.extend_from_slice(&[0u8; 20]);
        vector.extend_from_slice(&[0x80, 0x28, 0x00, 0x04, 0xc0, 0x7d, 0x4c, 0x96]);

        assert_eq!(
            parse_binding_response(&vector, transaction),
            Some("192.0.2.1:32853".parse().expect("address"))
        );
    }

    #[test]
    fn a_response_round_trips_for_both_families() {
        let transaction = [3u8; 12];
        for from in ["198.51.100.7:50000", "[2001:db8::7]:50000"] {
            let from: SocketAddr = from.parse().expect("address");
            let response = binding_response(transaction, from);
            assert_eq!(parse_binding_response(&response, transaction), Some(from));
            assert_eq!(parse_binding_response(&response, [4u8; 12]), None);
        }
    }

    #[test]
    fn a_socket_learns_the_address_a_server_saw() {
        let server = UdpSocket::bind("127.0.0.1:0").expect("server");
        let server_addr = server.local_addr().expect("addr");
        std::thread::spawn(move || {
            let mut buffer = [0u8; 576];
            if let Ok((n, from)) = server.recv_from(&mut buffer) {
                let transaction: [u8; 12] = buffer[8..20].try_into().expect("12 bytes");
                if n >= 20 {
                    let _ = server.send_to(&binding_response(transaction, from), from);
                }
            }
        });

        let client = UdpSocket::bind("127.0.0.1:0").expect("client");
        let seen = reflexive(&client, server_addr, Duration::from_secs(3)).expect("an answer");
        assert_eq!(seen, client.local_addr().expect("addr"));
    }
}
