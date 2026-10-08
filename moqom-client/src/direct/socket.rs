//! The direct path below MOQT: one UDP socket, one certificate, pinned QUIC.
//!
//! [`DirectEndpoint`](super::DirectEndpoint) is this plus a MOQT session and
//! the checks that admit a peer to it. This half is separate so an SDK that
//! does its own SETUP and verification -- the Swift SDK, through
//! `moqom-direct-ffi` -- can still have the part that is hard to get right
//! anywhere else.
//!
//! # One socket for everything
//!
//! A NAT maps each internal socket separately, so the STUN query, the probes,
//! and QUIC must all leave from the same one or the address learned and the
//! hole opened belong to a socket QUIC never uses. The order matters too:
//!
//! 1. A plain std socket is bound and asks STUN for its public address, while
//!    nothing else is reading it.
//! 2. A clone of its descriptor is kept for probes, which are sent with plain
//!    `send_to` from a thread of their own; see [`Puncher`].
//! 3. The socket itself is handed to quinn, which from then on owns every
//!    datagram that arrives on it.
//!
//! # Both address families, one port
//!
//! The default bind is `[::]` with `IPV6_V6ONLY` off: one dual-stack socket,
//! so IPv4 and IPv6 share the port and everything above still holds for both.
//! IPv4 peers are reached through their IPv4-mapped addresses, which quinn
//! does on its own and the probes and STUN do here. Where the platform will not
//! make a dual-stack socket, or has no IPv6 at all, the socket is IPv4 alone,
//! which is what it always was.
//!
//! # Pinned, mutual TLS
//!
//! Each socket generates an ephemeral self-signed certificate. A peer learns
//! its SHA-256 from an offer that arrived some other way, and both directions
//! of the handshake check the other's certificate against exactly that digest:
//! nothing else is trusted, and no certificate authority is involved.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

use super::punch::Puncher;
use crate::Error;
use crate::tls::install_crypto_provider;

/// The name in each endpoint's certificate. Nothing checks it -- both sides pin
/// the certificate itself -- but TLS needs a server name to send.
const SERVER_NAME: &str = "moqom-direct";

/// Where to ask for this socket's public address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StunServer {
    /// An address, used as given.
    Address(SocketAddr),
    /// A name, resolved through the system resolver when the socket is bound.
    ///
    /// The first address of each family the socket can use is asked: a
    /// dual-stack socket learns its public IPv4 and IPv6 addresses together,
    /// and an IPv4 socket asks only the IPv4 one. Asking from a different
    /// socket would learn a mapping nobody uses.
    Name {
        /// The host name, or an address literal.
        host: String,
        /// The UDP port, usually 3478.
        port: u16,
    },
}

impl StunServer {
    /// The addresses to ask from a socket of `stack`.
    fn resolve(&self, stack: Stack) -> io::Result<Vec<SocketAddr>> {
        match self {
            Self::Address(address) => Ok(vec![*address]),
            Self::Name { host, port } => {
                let resolved: Vec<SocketAddr> = (host.as_str(), *port).to_socket_addrs()?.collect();
                let servers = pick_servers(&resolved, stack);
                if servers.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "the STUN server has no address of this socket's family",
                    ));
                }
                Ok(servers)
            }
        }
    }
}

/// The first resolved address of each family `stack` reaches, IPv4 first.
fn pick_servers(resolved: &[SocketAddr], stack: Stack) -> Vec<SocketAddr> {
    let v4 = resolved
        .iter()
        .find(|address| address.ip().to_canonical().is_ipv4());
    let v6 = resolved
        .iter()
        .find(|address| address.ip().to_canonical().is_ipv6());
    [v4, v6]
        .into_iter()
        .flatten()
        .filter(|address| stack.reaches(**address))
        .copied()
        .collect()
}

/// Which families a bound socket can send to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stack {
    /// An IPv4 socket.
    V4,
    /// An IPv6 socket bound to one address, or with `IPV6_V6ONLY` on.
    V6,
    /// An IPv6 socket on every interface with `IPV6_V6ONLY` off.
    Dual,
}

impl Stack {
    fn reaches(self, target: SocketAddr) -> bool {
        let v4 = target.ip().to_canonical().is_ipv4();
        match self {
            Self::V4 => v4,
            Self::V6 => !v4,
            Self::Dual => true,
        }
    }
}

/// Bind `address`, making an unspecified IPv6 one dual-stack.
///
/// A dual-stack socket that cannot be made -- no IPv6 in the kernel, or a
/// platform that insists on `IPV6_V6ONLY` -- falls back to IPv4 on the same
/// port, since an IPv6-only socket would quietly drop every IPv4 peer, which
/// is most of them.
fn bind_udp(address: SocketAddr) -> io::Result<(UdpSocket, Stack)> {
    let SocketAddr::V6(v6) = address else {
        return Ok((UdpSocket::bind(address)?, Stack::V4));
    };
    if !v6.ip().is_unspecified() {
        return Ok((UdpSocket::bind(address)?, Stack::V6));
    }
    let dual = || -> io::Result<UdpSocket> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket.set_only_v6(false)?;
        socket.bind(&address.into())?;
        Ok(socket.into())
    };
    match dual() {
        Ok(socket) => Ok((socket, Stack::Dual)),
        Err(_) => Ok((
            UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, address.port())))?,
            Stack::V4,
        )),
    }
}

/// How to bind a [`DirectSocket`].
#[derive(Debug, Clone)]
pub struct SocketConfig {
    /// Where to bind. The default, `[::]` on an ephemeral port, is every
    /// interface in both families on one dual-stack socket, or every IPv4
    /// interface where that cannot be made. An IPv4 address binds IPv4 alone,
    /// and a specific IPv6 one IPv6 alone.
    pub bind: SocketAddr,
    /// A STUN server to learn the public address from, if any.
    pub stun: Option<StunServer>,
    /// How long the STUN server has to answer, over three attempts. A server
    /// that does not answer in time is not an error; the socket simply has no
    /// [`reflexive`](DirectSocket::reflexive) address.
    pub stun_timeout: Duration,
    /// How long a connection may be silent before QUIC declares it dead.
    /// Keep-alives go out at a third of it, which also keeps both NAT mappings
    /// open.
    pub idle_timeout: Duration,
    /// Whether to use QUIC datagrams. Off means the transport parameter is
    /// not sent, so the peer cannot send any, and quinn refuses to send them
    /// too: off is off in both directions.
    pub datagrams: bool,
    /// The one ALPN offered when dialling and accepted when accepting.
    pub alpn: Vec<u8>,
}

impl SocketConfig {
    /// Defaults for a socket speaking `alpn`.
    #[must_use]
    pub fn new(alpn: impl Into<Vec<u8>>) -> Self {
        Self {
            bind: SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
            stun: None,
            stun_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(3),
            datagrams: true,
            alpn: alpn.into(),
        }
    }
}

/// A UDP socket that does STUN, sends NAT probes, and carries pinned QUIC.
///
/// One peer at a time: [`dial`](Self::dial) and [`accept`](Self::accept) are
/// not meant to run concurrently on one socket, since a server config set for
/// one accept would also admit a handshake meant for another.
pub struct DirectSocket {
    /// A second handle on the socket QUIC owns, for the probes.
    probes: UdpSocket,
    endpoint: quinn::Endpoint,
    certificate: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    fingerprint: [u8; 32],
    host_candidates: Vec<SocketAddr>,
    /// IPv4 first, then IPv6, each present only if a server of that family
    /// answered.
    reflexive: Vec<SocketAddr>,
    stack: Stack,
    alpn: Vec<u8>,
    datagrams: bool,
    transport: Arc<quinn::TransportConfig>,
    punching: Mutex<Option<Puncher>>,
}

impl std::fmt::Debug for DirectSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectSocket")
            .field("local", &self.endpoint.local_addr().ok())
            .field("host_candidates", &self.host_candidates)
            .field("reflexive", &self.reflexive)
            .finish_non_exhaustive()
    }
}

impl DirectSocket {
    /// Bind a socket, ask STUN for its public address if configured, generate a
    /// certificate, and start QUIC on the socket.
    ///
    /// Must run inside a Tokio runtime, which the QUIC endpoint is driven by.
    ///
    /// # Errors
    /// Binding, certificate generation, or QUIC configuration failing, or an
    /// ALPN that is empty or longer than TLS allows. A STUN server that cannot
    /// be resolved or does not answer is not an error.
    pub async fn bind(config: SocketConfig) -> Result<Self, Error> {
        install_crypto_provider();
        if config.alpn.is_empty() || config.alpn.len() > 255 {
            return Err(Error::Tls("an ALPN must be 1 to 255 bytes".to_owned()));
        }

        let (socket, stack) = bind_udp(config.bind)?;
        let host_candidates = host_candidates(&socket, stack)?;
        let mut reflexive = Vec::new();
        if let Some(stun) = config.stun {
            let probe = socket.try_clone()?;
            let patience = config.stun_timeout;
            // Blocking twice over: the resolver, and STUN's own timed reads.
            let answer = tokio::task::spawn_blocking(move || {
                let servers = stun.resolve(stack)?;
                super::stun::reflexive_each(&probe, &servers, patience)
            })
            .await
            .map_err(|error| Error::Io(io::Error::other(error)))?;
            if let Ok(answers) = answer {
                for address in answers.into_iter().flatten() {
                    if !reflexive.contains(&address) {
                        reflexive.push(address);
                    }
                }
                reflexive.sort_by_key(|address: &SocketAddr| address.is_ipv6());
            }
        }

        let generated =
            rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_owned()]).map_err(Error::tls)?;
        let certificate = generated.cert.der().clone();
        let key =
            PrivateKeyDer::try_from(generated.signing_key.serialize_der()).map_err(Error::tls)?;
        let fingerprint = sha256(certificate.as_ref());

        let probes = socket.try_clone()?;
        let runtime = quinn::default_runtime()
            .ok_or_else(|| Error::Io(io::Error::other("no async runtime")))?;
        let endpoint =
            quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)?;

        Ok(Self {
            probes,
            endpoint,
            certificate,
            key,
            fingerprint,
            host_candidates,
            reflexive,
            stack,
            alpn: config.alpn,
            datagrams: config.datagrams,
            transport: transport(config.idle_timeout, config.datagrams),
            punching: Mutex::new(None),
        })
    }

    /// The local address the socket is bound to.
    ///
    /// # Errors
    /// The socket refusing to say.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// This socket's DER leaf certificate.
    #[must_use]
    pub fn certificate(&self) -> &CertificateDer<'static> {
        &self.certificate
    }

    /// SHA-256 of [`certificate`](Self::certificate): what a peer pins.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// This device's own addresses for the socket, for a peer on the same
    /// network.
    #[must_use]
    pub fn host_candidates(&self) -> &[SocketAddr] {
        &self.host_candidates
    }

    /// The public address the STUN server reported, if one was asked and
    /// answered: the IPv4 one when both families answered, since that is the
    /// one behind a NAT.
    #[must_use]
    pub fn reflexive(&self) -> Option<SocketAddr> {
        self.reflexive.first().copied()
    }

    /// Every public address STUN reported, IPv4 first. A dual-stack socket
    /// asked by name can have one of each.
    #[must_use]
    pub fn reflexive_addresses(&self) -> &[SocketAddr] {
        &self.reflexive
    }

    /// Whether connections from this socket use datagrams; see
    /// [`SocketConfig::datagrams`].
    #[must_use]
    pub fn datagrams(&self) -> bool {
        self.datagrams
    }

    /// The QUIC endpoint on the socket.
    #[must_use]
    pub fn endpoint(&self) -> &quinn::Endpoint {
        &self.endpoint
    }

    /// Probe `targets` every `interval` from this socket until
    /// [`punch_stop`](Self::punch_stop) or the socket is dropped. Starting
    /// again replaces the targets.
    ///
    /// # Errors
    /// The socket's descriptor could not be cloned.
    pub fn punch_start(&self, targets: Vec<SocketAddr>, interval: Duration) -> io::Result<()> {
        let puncher = self.puncher(targets, interval)?;
        // The previous puncher, if any, is dropped here and stops at once.
        *self.punching.lock().unwrap_or_else(PoisonError::into_inner) = Some(puncher);
        Ok(())
    }

    /// Stop probing. Harmless if nothing was.
    pub fn punch_stop(&self) {
        *self.punching.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// A puncher whose lifetime is the caller's rather than the socket's.
    pub(crate) fn puncher(
        &self,
        targets: Vec<SocketAddr>,
        interval: Duration,
    ) -> io::Result<Puncher> {
        Ok(Puncher::start(self.probes.try_clone()?, targets, interval))
    }

    /// Dial every candidate at once and return the first connection whose
    /// handshake completes with the peer presenting the certificate `pin`
    /// names. The rest are dropped, which closes them.
    ///
    /// A candidate this socket cannot reach at all -- IPv6 from an IPv4
    /// socket, IPv4 from one bound to a single IPv6 address -- is skipped
    /// rather than failing the others, as is one quinn refuses.
    ///
    /// # Errors
    /// [`Error::Unreachable`] after `timeout`, [`Error::Handshake`] with the
    /// last failure if every candidate failed first, [`Error::Connect`] if no
    /// candidate could even be dialled.
    pub async fn dial(
        &self,
        candidates: &[SocketAddr],
        pin: [u8; 32],
        timeout: Duration,
    ) -> Result<quinn::Connection, Error> {
        let mut tls = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Pinned(pin)))
            .with_client_auth_cert(vec![self.certificate.clone()], self.key.clone_key())
            .map_err(Error::tls)?;
        tls.alpn_protocols = vec![self.alpn.clone()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(Error::tls)?;
        let mut client = quinn::ClientConfig::new(Arc::new(crypto));
        client.transport_config(Arc::clone(&self.transport));

        let mut attempts = tokio::task::JoinSet::new();
        let mut refused = None;
        for candidate in candidates {
            let candidate = super::stun::canonical(*candidate);
            if !self.stack.reaches(candidate) {
                refused = Some(quinn::ConnectError::InvalidRemoteAddress(candidate));
                continue;
            }
            match self
                .endpoint
                .connect_with(client.clone(), candidate, SERVER_NAME)
            {
                Ok(connecting) => {
                    attempts.spawn(connecting);
                }
                Err(error) => refused = Some(error),
            }
        }
        if attempts.is_empty()
            && let Some(error) = refused
        {
            return Err(Error::Connect(error));
        }

        let race = async move {
            let mut last = None;
            loop {
                match attempts.join_next().await {
                    Some(Ok(Ok(connection))) => return Ok(connection),
                    Some(Ok(Err(error))) => last = Some(error),
                    Some(Err(_)) => {}
                    None => {
                        return Err(match last {
                            Some(error) => Error::Handshake(error),
                            None => Error::Unreachable(timeout),
                        });
                    }
                }
            }
        };
        tokio::time::timeout(timeout, race)
            .await
            .map_err(|_| Error::Unreachable(timeout))?
    }

    /// Wait for the peer presenting the certificate `pin` names to connect.
    ///
    /// The socket accepts connections only while this runs. Handshakes from
    /// anyone else fail and are ignored; the wait goes on for the one that
    /// matters.
    ///
    /// # Errors
    /// [`Error::Unreachable`] after `timeout`, or [`Error::Closed`] if the QUIC
    /// endpoint closed.
    pub async fn accept(
        &self,
        pin: [u8; 32],
        timeout: Duration,
    ) -> Result<quinn::Connection, Error> {
        let mut tls = rustls::ServerConfig::builder()
            .with_client_cert_verifier(Arc::new(Pinned(pin)))
            .with_single_cert(vec![self.certificate.clone()], self.key.clone_key())
            .map_err(Error::tls)?;
        tls.alpn_protocols = vec![self.alpn.clone()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(Error::tls)?;
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        server.transport_config(Arc::clone(&self.transport));
        self.endpoint.set_server_config(Some(server));
        let _listening = Listening(&self.endpoint);

        let wait = async {
            loop {
                let incoming = self.endpoint.accept().await.ok_or(Error::Closed)?;
                if let Ok(connection) = incoming.await {
                    return Ok(connection);
                }
            }
        };
        tokio::time::timeout(timeout, wait)
            .await
            .map_err(|_| Error::Unreachable(timeout))?
    }
}

/// Withdraws the server config when an accept ends, however it ends, so the
/// socket never admits a handshake nobody is waiting for.
struct Listening<'a>(&'a quinn::Endpoint);

impl Drop for Listening<'_> {
    fn drop(&mut self) {
        self.0.set_server_config(None);
    }
}

fn transport(idle_timeout: Duration, datagrams: bool) -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    if let Ok(idle) = quinn::IdleTimeout::try_from(idle_timeout) {
        transport.max_idle_timeout(Some(idle));
    }
    transport.keep_alive_interval(Some(idle_timeout / 3));
    // A hole-punched path is usually short, and the default initial RTT of a
    // third of a second would make the first retransmission -- the one that
    // crosses once the far NAT has opened -- wait far longer than the path
    // needs.
    transport.initial_rtt(Duration::from_millis(50));
    if !datagrams {
        transport.datagram_receive_buffer_size(None);
    }
    Arc::new(transport)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// This socket's own addresses, for a peer on the same network, IPv4 first.
///
/// A socket bound to every interface reports `0.0.0.0` or `::`, which is no
/// use to a peer, so the address the default route of each family leaves from
/// is asked for instead: a UDP `connect` picks it without sending anything. A
/// family with no default route contributes nothing, and an IPv6 link-local
/// address is never offered, since it means nothing without the interface it
/// belongs to.
fn host_candidates(socket: &UdpSocket, stack: Stack) -> io::Result<Vec<SocketAddr>> {
    let bound = socket.local_addr()?;
    if !bound.ip().is_unspecified() {
        return Ok(vec![super::stun::canonical(bound)]);
    }
    let mut candidates = Vec::new();
    if stack != Stack::V6 {
        // TEST-NET-1: never routed, so nothing is sent, but the kernel still
        // picks the interface it would use for the internet.
        if let Some(ip) = route_source(
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 9)),
        ) {
            candidates.push(SocketAddr::new(ip, bound.port()));
        }
    }
    if stack != Stack::V4 {
        // The IPv6 documentation prefix, for the same reason.
        if let Some(IpAddr::V6(ip)) = route_source(
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
            SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 9)),
        ) && !ip.is_unicast_link_local()
            && ip.to_ipv4_mapped().is_none()
        {
            candidates.push(SocketAddr::new(IpAddr::V6(ip), bound.port()));
        }
    }
    if candidates.is_empty() {
        let loopback = if stack == Stack::V6 {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        };
        candidates.push(SocketAddr::new(loopback, bound.port()));
    }
    Ok(candidates)
}

/// The local address the kernel would send to `target` from, if it has a
/// route there at all.
fn route_source(bind: SocketAddr, target: SocketAddr) -> Option<IpAddr> {
    let probe = UdpSocket::bind(bind).ok()?;
    probe.connect(target).ok()?;
    let local = probe.local_addr().ok()?.ip();
    (!local.is_unspecified() && !local.is_loopback()).then_some(local)
}

/// Trusts exactly the certificate whose SHA-256 is pinned, in either direction.
#[derive(Debug)]
struct Pinned([u8; 32]);

impl Pinned {
    fn matches(&self, end_entity: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        if sha256(end_entity.as_ref()) == self.0 {
            Ok(())
        } else {
            Err(rustls::Error::General(
                "certificate is not the one the peer's offer named".into(),
            ))
        }
    }

    fn verify_signature(
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn schemes() -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl rustls::client::danger::ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.matches(end_entity)?;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General(
            "TLS 1.2 is not used over QUIC".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Self::verify_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        Self::schemes()
    }
}

impl rustls::server::danger::ClientCertVerifier for Pinned {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        self.matches(end_entity)?;
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General(
            "TLS 1.2 is not used over QUIC".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Self::verify_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        Self::schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(text: &str) -> SocketAddr {
        text.parse().expect("an address")
    }

    #[test]
    fn each_stack_reaches_its_own_families() {
        let v4 = address("192.0.2.1:9");
        let mapped = address("[::ffff:192.0.2.1]:9");
        let v6 = address("[2001:db8::1]:9");
        assert!(Stack::V4.reaches(v4) && Stack::V4.reaches(mapped) && !Stack::V4.reaches(v6));
        assert!(!Stack::V6.reaches(v4) && !Stack::V6.reaches(mapped) && Stack::V6.reaches(v6));
        assert!(Stack::Dual.reaches(v4) && Stack::Dual.reaches(mapped) && Stack::Dual.reaches(v6));
    }

    #[test]
    fn a_name_is_asked_once_per_family_the_socket_reaches() {
        let resolved = [
            address("[2001:db8::1]:3478"),
            address("192.0.2.1:3478"),
            address("[2001:db8::2]:3478"),
            address("192.0.2.2:3478"),
        ];
        let v4 = address("192.0.2.1:3478");
        let v6 = address("[2001:db8::1]:3478");
        assert_eq!(pick_servers(&resolved, Stack::Dual), vec![v4, v6]);
        assert_eq!(pick_servers(&resolved, Stack::V4), vec![v4]);
        assert_eq!(pick_servers(&resolved, Stack::V6), vec![v6]);
        assert!(pick_servers(&resolved[..1], Stack::V4).is_empty());
    }

    #[test]
    fn the_default_bind_is_dual_stack_and_an_ipv4_bind_is_not() {
        let (socket, stack) = bind_udp(SocketConfig::new(b"x".to_vec()).bind).expect("binds");
        assert_eq!(stack, Stack::Dual);
        assert!(socket.local_addr().expect("address").is_ipv6());
        let (_, stack) = bind_udp(address("127.0.0.1:0")).expect("binds");
        assert_eq!(stack, Stack::V4);
        let (_, stack) = bind_udp(address("[::1]:0")).expect("binds");
        assert_eq!(stack, Stack::V6);
    }
}
