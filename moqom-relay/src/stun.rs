//! A STUN Binding responder, so a device can learn its public address from the
//! relay it already talks to.
//!
//! A direct path between two devices behind NATs needs each to know the address
//! its NAT gives it, and only something outside the NAT can say what that is.
//! That is the whole of a STUN Binding exchange (RFC 8489): the device sends a
//! request, and the answer carries the address the request arrived from. Without
//! a server to ask, a device can offer only its own interface addresses, which
//! reach a peer on the same network and nothing else.
//!
//! # The subset
//!
//! Binding requests only, answered with `XOR-MAPPED-ADDRESS` and `FINGERPRINT`
//! and nothing more, so a response is 40 bytes for IPv4 and 52 for IPv6. No
//! authentication, no `SOFTWARE`, no TURN, and no error responses: anything that
//! is not a well-formed Binding request is dropped unanswered, which is what a
//! port open to the internet should do with a datagram it has no use for. That
//! includes a request carrying an attribute a server must understand to answer
//! (any type below `0x8000`, such as `MESSAGE-INTEGRITY` or `CHANGE-REQUEST`),
//! which RFC 8489 would answer with an error this does not send.
//!
//! # Its own socket
//!
//! Not the QUIC port. A Binding request is told apart from QUIC by its first
//! bits, so the two could share one, but that would put a parser in front of
//! every media datagram and tie STUN's availability to the QUIC endpoint's. A
//! port of its own (3478 by convention) costs one firewall rule.
//!
//! Behind a passthrough load balancer the request arrives addressed to the
//! balancer's address rather than the machine's, so the answer is sent from
//! whichever address the request was sent to. A reply from anywhere else is one
//! a careful client drops, since it did not ask that address.
//!
//! # Abuse
//!
//! A forged source address turns any UDP responder into a reflector. The answer
//! here is at most 2.6 times the smallest request, which is little to amplify,
//! and every source is held to a token bucket ([`Limits`]), so a victim receives
//! at most that rate from each relay however many forged requests are sent.

use std::collections::HashMap;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Instant;

use crate::metrics::{Metrics, Stun};

/// The port STUN is served on unless configured otherwise.
pub const DEFAULT_PORT: u16 = 3478;

/// The fixed header every STUN message starts with.
const HEADER: usize = 20;

const MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const FINGERPRINT: u16 = 0x8028;
/// What the CRC is combined with, so a CRC over a non-STUN payload that happens to
/// carry one does not read as a fingerprint (RFC 8489 §14.7).
const FINGERPRINT_XOR: u32 = 0x5354_554E;

/// The largest request read. A Binding request needs no attributes at all, and
/// one this size is either a mistake or somebody seeing what a bigger datagram
/// buys.
pub const MAX_REQUEST: usize = 548;

/// The largest response: the header, an IPv6 `XOR-MAPPED-ADDRESS`, and a
/// `FINGERPRINT`.
pub const MAX_RESPONSE: usize = HEADER + 4 + 20 + 4 + 4;

/// Why a datagram is not a Binding request this answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Malformed {
    /// Shorter than a header, or longer than [`MAX_REQUEST`].
    Size,
    /// Not a STUN message, or a STUN message that is not a Binding request.
    NotBindingRequest,
    /// No magic cookie: an RFC 3489 client, or not STUN at all.
    Cookie,
    /// The length field disagrees with the datagram, or is not a multiple of
    /// four.
    Length,
    /// An attribute runs past the end of the message.
    Attribute,
    /// A `FINGERPRINT` that is wrong, the wrong size, or not last.
    Fingerprint,
    /// An attribute a server must understand to answer, of this type.
    Unsupported(u16),
}

/// The transaction ID of `datagram`, if it is a well-formed Binding request.
///
/// # Errors
/// What is wrong with it.
pub fn binding_request(datagram: &[u8]) -> Result<[u8; 12], Malformed> {
    if datagram.len() < HEADER || datagram.len() > MAX_REQUEST {
        return Err(Malformed::Size);
    }
    // The top two bits of every STUN message are zero, and the type names the
    // method and the class together.
    if u16::from_be_bytes([datagram[0], datagram[1]]) != BINDING_REQUEST {
        return Err(Malformed::NotBindingRequest);
    }
    if u32::from_be_bytes([datagram[4], datagram[5], datagram[6], datagram[7]]) != MAGIC_COOKIE {
        return Err(Malformed::Cookie);
    }
    let length = usize::from(u16::from_be_bytes([datagram[2], datagram[3]]));
    if length % 4 != 0 || HEADER + length != datagram.len() {
        return Err(Malformed::Length);
    }

    let mut at = HEADER;
    while at < datagram.len() {
        let header = datagram.get(at..at + 4).ok_or(Malformed::Attribute)?;
        let kind = u16::from_be_bytes([header[0], header[1]]);
        let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let end = at + 4 + len.next_multiple_of(4);
        if end > datagram.len() {
            return Err(Malformed::Attribute);
        }
        if kind == FINGERPRINT {
            if len != 4 || end != datagram.len() || !fingerprint_matches(datagram) {
                return Err(Malformed::Fingerprint);
            }
        } else if kind < 0x8000 {
            return Err(Malformed::Unsupported(kind));
        }
        at = end;
    }

    let mut transaction = [0u8; 12];
    transaction.copy_from_slice(&datagram[8..HEADER]);
    Ok(transaction)
}

/// A Binding success response, ready to send.
#[derive(Debug, Clone, Copy)]
pub struct Response {
    bytes: [u8; MAX_RESPONSE],
    len: usize,
}

impl AsRef<[u8]> for Response {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// The success response to request `transaction`, telling the requester it came
/// from `mapped`.
///
/// An IPv4-mapped IPv6 address, which is how a dual-stack socket sees an IPv4
/// peer, is reported as the IPv4 address it is.
#[must_use]
pub fn binding_success(transaction: [u8; 12], mapped: SocketAddr) -> Response {
    let mut bytes = [0u8; MAX_RESPONSE];
    bytes[0..2].copy_from_slice(&BINDING_SUCCESS.to_be_bytes());
    bytes[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    bytes[8..HEADER].copy_from_slice(&transaction);

    let address = xor_mapped_address(transaction, mapped);
    let mut len = HEADER;
    bytes[len..len + address.len()].copy_from_slice(&address);
    len += address.len();

    // The length counts the fingerprint, which is computed over everything
    // before it with the length already saying so.
    let attributes = len - HEADER + 8;
    bytes[2..4].copy_from_slice(&u16::try_from(attributes).unwrap_or(0).to_be_bytes());
    let crc = crc32(&bytes[..len]) ^ FINGERPRINT_XOR;
    bytes[len..len + 2].copy_from_slice(&FINGERPRINT.to_be_bytes());
    bytes[len + 2..len + 4].copy_from_slice(&4u16.to_be_bytes());
    bytes[len + 4..len + 8].copy_from_slice(&crc.to_be_bytes());
    len += 8;

    Response { bytes, len }
}

/// The answer to `datagram` from `from`, if it is a Binding request.
#[must_use]
pub fn answer(datagram: &[u8], from: SocketAddr) -> Option<Response> {
    binding_request(datagram)
        .ok()
        .map(|transaction| binding_success(transaction, from))
}

/// An `XOR-MAPPED-ADDRESS` attribute, header included, for `mapped`.
fn xor_mapped_address(transaction: [u8; 12], mapped: SocketAddr) -> Vec<u8> {
    let port = mapped.port() ^ (MAGIC_COOKIE >> 16) as u16;
    let mut mask = [0u8; 16];
    mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    mask[4..].copy_from_slice(&transaction);

    let (family, octets): (u8, Vec<u8>) = match mapped.ip().to_canonical() {
        IpAddr::V4(ip) => (0x01, ip.octets().to_vec()),
        IpAddr::V6(ip) => (0x02, ip.octets().to_vec()),
    };
    let value_len = 4 + octets.len();
    let mut out = Vec::with_capacity(4 + value_len);
    out.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
    out.extend_from_slice(&u16::try_from(value_len).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(&[0, family]);
    out.extend_from_slice(&port.to_be_bytes());
    out.extend(octets.iter().zip(mask).map(|(a, b)| a ^ b));
    out
}

/// Whether `message`, whose last attribute is a `FINGERPRINT`, carries the
/// right one.
fn fingerprint_matches(message: &[u8]) -> bool {
    let Some(split) = message.len().checked_sub(8) else {
        return false;
    };
    let carried = u32::from_be_bytes([
        message[split + 4],
        message[split + 5],
        message[split + 6],
        message[split + 7],
    ]);
    crc32(&message[..split]) ^ FINGERPRINT_XOR == carried
}

/// CRC-32 as ISO-HDLC and zlib compute it, which is the one `FINGERPRINT`
/// names. Bitwise rather than by table: it runs over a few dozen bytes per
/// request.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// How many answers each source may have.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Limits {
    /// Answers per second each source earns.
    pub rate: f64,
    /// The most a source may have at once, which is also where a new one
    /// starts. A device asks up to three times per address family each time it
    /// prepares a direct path, and a carrier-grade NAT puts many devices behind
    /// one address.
    pub burst: f64,
    /// How many sources are tracked. One more is answered only once a source
    /// that has been quiet long enough to be full again is forgotten.
    pub sources: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            rate: 20.0,
            burst: 40.0,
            sources: 65_536,
        }
    }
}

/// A token bucket per source address.
///
/// IPv6 sources are counted by their /64, the smallest block a network is
/// assigned, so a host cannot earn a fresh allowance by changing address.
#[derive(Debug)]
pub struct Limiter {
    limits: Limits,
    buckets: HashMap<IpAddr, Bucket>,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Limiter {
    /// A limiter enforcing `limits`.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            buckets: HashMap::new(),
        }
    }

    /// Whether `source` may have an answer at `now`, spending one if so.
    pub fn permit(&mut self, source: IpAddr, now: Instant) -> bool {
        let key = Self::key(source);
        if !self.buckets.contains_key(&key) && self.buckets.len() >= self.limits.sources {
            self.forget_full(now);
            if self.buckets.len() >= self.limits.sources {
                return false;
            }
        }
        let limits = self.limits;
        let bucket = self.buckets.entry(key).or_insert(Bucket {
            tokens: limits.burst,
            at: now,
        });
        let earned = now.saturating_duration_since(bucket.at).as_secs_f64() * limits.rate;
        bucket.tokens = (bucket.tokens + earned).min(limits.burst);
        bucket.at = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// How many sources are tracked.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.buckets.len()
    }

    /// Drop every source whose bucket has refilled, which is the same as never
    /// having seen it.
    fn forget_full(&mut self, now: Instant) {
        let Limits { rate, burst, .. } = self.limits;
        self.buckets.retain(|_, bucket| {
            bucket.tokens + now.saturating_duration_since(bucket.at).as_secs_f64() * rate < burst
        });
    }

    fn key(source: IpAddr) -> IpAddr {
        match source.to_canonical() {
            IpAddr::V6(ip) => {
                let mut octets = ip.octets();
                octets[8..].fill(0);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            v4 @ IpAddr::V4(_) => v4,
        }
    }
}

/// Where to answer STUN, and how much.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Config {
    /// The address to bind. An unspecified IPv6 address serves both families.
    pub listen: SocketAddr,
    /// Each source's allowance.
    pub limits: Limits,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from((Ipv6Addr::UNSPECIFIED, DEFAULT_PORT)),
            limits: Limits::default(),
        }
    }
}

/// A bound STUN socket and the state to answer on it.
#[derive(Debug)]
pub struct Responder {
    socket: tokio::net::UdpSocket,
    state: quinn_udp::UdpSocketState,
    limiter: Limiter,
    metrics: Metrics,
}

impl Responder {
    /// Bind `config.listen`. Must be called inside a Tokio runtime.
    ///
    /// # Errors
    /// The address being taken or refused.
    pub fn bind(config: &Config, metrics: Metrics) -> io::Result<Self> {
        let domain = socket2::Domain::for_address(config.listen);
        let socket =
            socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        if let SocketAddr::V6(v6) = config.listen
            && v6.ip().is_unspecified()
        {
            // Explicitly, because the platform default varies and an IPv6-only
            // socket would ignore every IPv4 device, which is most of them.
            socket.set_only_v6(false)?;
        }
        socket.bind(&config.listen.into())?;
        socket.set_nonblocking(true)?;
        let socket = tokio::net::UdpSocket::from_std(socket.into())?;
        let state = quinn_udp::UdpSocketState::new((&socket).into())?;
        Ok(Self {
            socket,
            state,
            limiter: Limiter::new(config.limits),
            metrics,
        })
    }

    /// The address actually bound.
    ///
    /// # Errors
    /// The socket refusing to say.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Answer requests until the socket fails.
    ///
    /// # Errors
    /// The socket becoming unreadable. A read that fails for one datagram, and
    /// every send, is not an error: the client asks again.
    pub async fn serve(mut self) -> io::Result<()> {
        // Big enough for a coalesced batch where the platform coalesces, of
        // which only the first `MAX_REQUEST` bytes of each are ever looked at.
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            self.socket.readable().await?;
            let mut meta = [quinn_udp::RecvMeta::default()];
            let received = self.socket.try_io(tokio::io::Interest::READABLE, || {
                self.state.recv(
                    (&self.socket).into(),
                    &mut [IoSliceMut::new(&mut buffer)],
                    &mut meta,
                )
            });
            match received {
                Ok(0) => continue,
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => {
                    tracing::debug!(%error, "STUN read failed");
                    continue;
                }
            }
            let [meta] = meta;
            let stride = meta.stride.max(1);
            for datagram in buffer[..meta.len.min(buffer.len())].chunks(stride) {
                self.handle(datagram, meta.addr, meta.dst_ip);
            }
        }
    }

    fn handle(&mut self, datagram: &[u8], from: SocketAddr, to: Option<IpAddr>) {
        let Some(response) = answer(datagram, from) else {
            self.metrics.stun(Stun::Ignored);
            return;
        };
        if !self.limiter.permit(from.ip(), Instant::now()) {
            self.metrics.stun(Stun::Limited);
            return;
        }
        let transmit = quinn_udp::Transmit {
            destination: from,
            ecn: None,
            contents: response.as_ref(),
            segment_size: None,
            src_ip: to,
        };
        // Once, without waiting: a full send buffer is congestion, and the
        // client's retry is the right response to it.
        let _ = self.socket.try_io(tokio::io::Interest::WRITABLE, || {
            self.state.try_send((&self.socket).into(), &transmit)
        });
        self.metrics.stun(Stun::Answered);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    const TRANSACTION: [u8; 12] = [
        0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
    ];

    /// RFC 5769 §2.1.
    const SAMPLE_REQUEST: &[u8] = b"\x00\x01\x00\x58\x21\x12\xa4\x42\
        \xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae\
        \x80\x22\x00\x10STUN test client\
        \x00\x24\x00\x04\x6e\x00\x01\xff\
        \x80\x29\x00\x08\x93\x2f\xf9\xb1\x51\x26\x3b\x36\
        \x00\x06\x00\x09\x65\x76\x74\x6a\x3a\x68\x36\x76\x59\x20\x20\x20\
        \x00\x08\x00\x14\x9a\xea\xa7\x0c\xbf\xd8\xcb\x56\x78\x1e\xf2\xb5\
        \xb2\xd3\xf2\x49\xc1\xb5\x71\xa2\
        \x80\x28\x00\x04\xe5\x7a\x3b\xcf";

    /// RFC 5769 §2.2.
    const SAMPLE_IPV4_RESPONSE: &[u8] = b"\x01\x01\x00\x3c\x21\x12\xa4\x42\
        \xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae\
        \x80\x22\x00\x0b\x74\x65\x73\x74\x20\x76\x65\x63\x74\x6f\x72\x20\
        \x00\x20\x00\x08\x00\x01\xa1\x47\xe1\x12\xa6\x43\
        \x00\x08\x00\x14\x2b\x91\xf5\x99\xfd\x9e\x90\xc3\x8c\x74\x89\xf9\
        \x2a\xf9\xba\x53\xf0\x6b\xe7\xd7\
        \x80\x28\x00\x04\xc0\x7d\x4c\x96";

    /// RFC 5769 §2.3.
    const SAMPLE_IPV6_RESPONSE: &[u8] = b"\x01\x01\x00\x48\x21\x12\xa4\x42\
        \xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae\
        \x80\x22\x00\x0b\x74\x65\x73\x74\x20\x76\x65\x63\x74\x6f\x72\x20\
        \x00\x20\x00\x14\x00\x02\xa1\x47\
        \x01\x13\xa9\xfa\xa5\xd3\xf1\x79\xbc\x25\xf4\xb5\xbe\xd2\xb9\xd9\
        \x00\x08\x00\x14\xa3\x82\x95\x4e\x4b\xe6\x7b\xf1\x17\x84\xc9\x7c\
        \x82\x92\xc2\x75\xbf\xe3\xed\x41\
        \x80\x28\x00\x04\xc8\xfb\x0b\x4c";

    /// A bare Binding request, as the MOQOM clients send it.
    fn bare(transaction: [u8; 12]) -> Vec<u8> {
        let mut request = vec![0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42];
        request.extend_from_slice(&transaction);
        request
    }

    /// `message` with a correct `FINGERPRINT` appended and its length updated.
    fn fingerprinted(mut message: Vec<u8>) -> Vec<u8> {
        let length = u16::try_from(message.len() - HEADER + 8).expect("short");
        message[2..4].copy_from_slice(&length.to_be_bytes());
        let crc = crc32(&message) ^ FINGERPRINT_XOR;
        message.extend_from_slice(&[0x80, 0x28, 0x00, 0x04]);
        message.extend_from_slice(&crc.to_be_bytes());
        message
    }

    #[test]
    fn crc32_is_the_zlib_one() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn the_rfc_5769_fingerprints_verify() {
        for vector in [SAMPLE_REQUEST, SAMPLE_IPV4_RESPONSE, SAMPLE_IPV6_RESPONSE] {
            assert!(fingerprint_matches(vector));
            let mut wrong = vector.to_vec();
            *wrong.last_mut().expect("bytes") ^= 1;
            assert!(!fingerprint_matches(&wrong));
        }
    }

    /// The ICE sample carries `PRIORITY`, `USERNAME` and `MESSAGE-INTEGRITY`,
    /// which ask for an authenticated connectivity check this is not.
    #[test]
    fn the_rfc_5769_request_is_not_one_this_answers() {
        assert_eq!(
            binding_request(SAMPLE_REQUEST),
            Err(Malformed::Unsupported(0x0024))
        );
    }

    /// The vector's `XOR-MAPPED-ADDRESS` bytes, for both families.
    #[test]
    fn the_address_encodes_as_the_rfc_5769_vectors_do() {
        let v4 = xor_mapped_address(TRANSACTION, "192.0.2.1:32853".parse().expect("v4"));
        assert_eq!(v4, SAMPLE_IPV4_RESPONSE[36..48]);
        let v6 = xor_mapped_address(
            TRANSACTION,
            "[2001:db8:1234:5678:11:2233:4455:6677]:32853"
                .parse()
                .expect("v6"),
        );
        assert_eq!(v6, SAMPLE_IPV6_RESPONSE[36..60]);
    }

    #[test]
    fn a_response_is_only_as_long_as_it_has_to_be() {
        let v4 = binding_success(TRANSACTION, "192.0.2.1:32853".parse().expect("v4"));
        assert_eq!(v4.as_ref().len(), 40);
        assert_eq!(&v4.as_ref()[2..4], &[0x00, 0x14]);
        assert!(fingerprint_matches(v4.as_ref()));
        let v6 = binding_success(TRANSACTION, "[2001:db8::1]:9".parse().expect("v6"));
        assert_eq!(v6.as_ref().len(), MAX_RESPONSE);
        assert!(fingerprint_matches(v6.as_ref()));
    }

    /// What the client in `moqom-client` reads back is the address answered.
    #[test]
    fn the_client_reads_the_response() {
        use moqom_client::direct::stun::parse_binding_response;
        for from in ["198.51.100.7:50000", "[2001:db8::7]:50000"] {
            let from: SocketAddr = from.parse().expect("address");
            let response = answer(&bare(TRANSACTION), from).expect("answered");
            assert_eq!(
                parse_binding_response(response.as_ref(), TRANSACTION),
                Some(from)
            );
        }
        let mapped: SocketAddr = "[::ffff:198.51.100.7]:50000".parse().expect("mapped");
        let response = answer(&bare(TRANSACTION), mapped).expect("answered");
        assert_eq!(
            parse_binding_response(response.as_ref(), TRANSACTION),
            Some("198.51.100.7:50000".parse().expect("v4"))
        );
    }

    #[test]
    fn requests_with_optional_attributes_and_a_fingerprint_are_answered() {
        let mut request = bare(TRANSACTION);
        request.extend_from_slice(&[0x80, 0x22, 0x00, 0x03, b'a', b'b', b'c', 0]);
        request[2..4].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(binding_request(&request), Ok(TRANSACTION));
        assert_eq!(binding_request(&fingerprinted(request)), Ok(TRANSACTION));
        assert_eq!(
            binding_request(&fingerprinted(bare(TRANSACTION))),
            Ok(TRANSACTION)
        );
    }

    #[test]
    fn anything_else_is_dropped() {
        let request = bare(TRANSACTION);
        let mut cases: Vec<(Vec<u8>, Malformed)> = vec![(request[..19].to_vec(), Malformed::Size)];
        let mut huge = request.clone();
        huge.resize(MAX_REQUEST + 4, 0);
        cases.push((huge, Malformed::Size));

        // A response, an indication, and QUIC's long header.
        for first in [[0x01, 0x01], [0x00, 0x11], [0xc0, 0x00]] {
            let mut other = request.clone();
            other[..2].copy_from_slice(&first);
            cases.push((other, Malformed::NotBindingRequest));
        }
        let mut classic = request.clone();
        classic[4] = 0;
        cases.push((classic, Malformed::Cookie));

        let mut long = request.clone();
        long[3] = 4;
        cases.push((long, Malformed::Length));
        let mut unaligned = request.clone();
        unaligned.extend_from_slice(&[0, 0]);
        unaligned[3] = 2;
        cases.push((unaligned, Malformed::Length));

        let mut overrun = request.clone();
        overrun.extend_from_slice(&[0x80, 0x22, 0x00, 0x08, 0, 0, 0, 0]);
        overrun[3] = 8;
        cases.push((overrun, Malformed::Attribute));

        let mut bad_crc = fingerprinted(request.clone());
        *bad_crc.last_mut().expect("bytes") ^= 0xff;
        cases.push((bad_crc, Malformed::Fingerprint));
        let mut not_last = fingerprinted(request.clone());
        not_last.extend_from_slice(&[0x80, 0x22, 0x00, 0x00]);
        let length = u16::try_from(not_last.len() - HEADER).expect("short");
        not_last[2..4].copy_from_slice(&length.to_be_bytes());
        cases.push((not_last, Malformed::Fingerprint));

        let mut change = request.clone();
        change.extend_from_slice(&[0x00, 0x03, 0x00, 0x04, 0, 0, 0, 6]);
        change[3] = 8;
        cases.push((change, Malformed::Unsupported(0x0003)));

        for (datagram, why) in cases {
            assert_eq!(binding_request(&datagram), Err(why), "{datagram:02x?}");
            assert!(answer(&datagram, "192.0.2.1:1".parse().expect("addr")).is_none());
        }
    }

    #[test]
    fn each_source_has_a_bucket() {
        let limits = Limits {
            rate: 2.0,
            burst: 3.0,
            sources: 2,
        };
        let mut limiter = Limiter::new(limits);
        let start = Instant::now();
        let a: IpAddr = "192.0.2.1".parse().expect("a");
        let b: IpAddr = "192.0.2.2".parse().expect("b");

        for _ in 0..3 {
            assert!(limiter.permit(a, start));
        }
        assert!(!limiter.permit(a, start));
        for _ in 0..3 {
            assert!(limiter.permit(b, start), "another source is unaffected");
        }
        assert!(limiter.permit(a, start + Duration::from_millis(500)));
        assert!(!limiter.permit(a, start + Duration::from_millis(500)));

        // Two tracked and both busy, so a third waits.
        let c: IpAddr = "192.0.2.3".parse().expect("c");
        assert!(!limiter.permit(c, start + Duration::from_millis(500)));
        // Once the others have refilled they are forgotten and it is answered.
        assert!(limiter.permit(c, start + Duration::from_secs(5)));
        assert_eq!(limiter.tracked(), 1);
    }

    #[test]
    fn ipv6_sources_share_their_64() {
        let mut limiter = Limiter::new(Limits {
            rate: 1.0,
            burst: 1.0,
            sources: 8,
        });
        let now = Instant::now();
        assert!(limiter.permit("2001:db8:1:2::1".parse().expect("v6"), now));
        assert!(!limiter.permit("2001:db8:1:2::ffff".parse().expect("v6"), now));
        assert!(limiter.permit("2001:db8:1:3::1".parse().expect("v6"), now));
        // A mapped IPv4 address is the IPv4 address.
        assert!(limiter.permit("192.0.2.9".parse().expect("v4"), now));
        assert!(!limiter.permit("::ffff:192.0.2.9".parse().expect("mapped"), now));
    }
}
