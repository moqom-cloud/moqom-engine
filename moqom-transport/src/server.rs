//! Accepting sessions over both carriers on one UDP port.

use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;

use web_transport_quinn::proto::ConnectResponse;

use crate::{Carrier, Dialect, Liveness, Session, alpn};

/// Why a session could not be established.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AcceptError {
    /// The QUIC handshake did not complete.
    #[error("QUIC handshake failed: {0}")]
    Connect(#[from] quinn::ConnectionError),

    /// The WebTransport `CONNECT` exchange did not complete.
    #[error("WebTransport handshake failed: {0}")]
    WebTransport(#[from] web_transport_quinn::ServerError),

    /// The handshake produced no ALPN, or one that is not ours.
    ///
    /// Should be unreachable: `rustls` fails the handshake when no offered
    /// protocol matches. Reachable only if the endpoint was built with an ALPN
    /// list that disagrees with [`alpn::OFFERED`], which is a configuration bug
    /// rather than anything a peer can cause.
    #[error("handshake settled on an unusable protocol")]
    UnexpectedAlpn,
}

/// A listener that serves MOQT over QUIC and WebTransport on the same socket.
///
/// One port for both is not a convenience. A relay is reached through a UDP
/// load balancer and an anycast address, and splitting the carriers across
/// ports would double that plumbing and force clients to know which they are
/// about to use before they have connected.
pub struct Server {
    endpoint: quinn::Endpoint,
}

impl Server {
    /// Wrap an endpoint that is already configured.
    ///
    /// Its ALPN list must be [`alpn::OFFERED`]; nothing here can check that,
    /// and a mismatch surfaces as [`AcceptError::UnexpectedAlpn`] on the first
    /// connection.
    #[must_use]
    pub const fn new(endpoint: quinn::Endpoint) -> Self {
        Self { endpoint }
    }

    /// Bind a socket with the given TLS configuration.
    ///
    /// Uses [`Liveness::DEFAULT`]. See [`Server::bind_with`] to choose.
    ///
    /// # Errors
    /// If the address cannot be bound, or the TLS configuration is not usable
    /// for QUIC.
    pub fn bind(addr: SocketAddr, tls: rustls::ServerConfig) -> io::Result<Self> {
        Self::bind_with(addr, tls, Liveness::DEFAULT)
    }

    /// Bind a socket, choosing how long a silent peer has.
    ///
    /// # Errors
    /// If the address cannot be bound, the TLS configuration is not usable for
    /// QUIC, or the liveness timings cannot be encoded.
    pub fn bind_with(
        addr: SocketAddr,
        tls: rustls::ServerConfig,
        liveness: Liveness,
    ) -> io::Result<Self> {
        Self::bound(addr, tls, liveness, None)
    }

    /// Bind a socket that asks the network for a class of service.
    ///
    /// The codepoint is the top six bits of the IP header's second byte, and its whole purpose is
    /// the last hop rather than the internet: a home access point reads it to choose a WMM queue,
    /// and an unmarked flow shares the queue and the contention backoff of a background download.
    /// Marking the client's uplink was measured to be worth 15.6ms at the 95th percentile of link
    /// latency and 8.2ms of glass-to-glass, and this is the other direction of the same hop --
    /// every frame crosses it twice and only one crossing was marked.
    ///
    /// Expect it to be rewritten. Codepoints are routinely cleared or remapped in transit, so
    /// whether one set here reaches a phone is a question about a particular path on a particular
    /// day, and has to be measured rather than assumed. It was, from a relay in GCP to a home
    /// network, and the answer there was no: the byte arrived as zero on every sample while the
    /// relay was demonstrably setting it. Measure before believing a deployment is getting
    /// anything from this.
    ///
    /// # Errors
    /// As [`Server::bind_with`], and if the codepoint cannot be set on the socket.
    pub fn bind_marked(
        addr: SocketAddr,
        tls: rustls::ServerConfig,
        dscp: Option<u8>,
    ) -> io::Result<Self> {
        Self::bound(addr, tls, Liveness::DEFAULT, dscp)
    }

    /// Bind several sockets on one port, so that one thread is not the ceiling.
    ///
    /// A `quinn::Endpoint` owns one UDP socket and drives it from one task. Every
    /// packet arriving for every connection on that endpoint is demultiplexed
    /// there, and every packet leaving is a send on that one socket -- which the
    /// kernel serialises per socket. Both are fine at hundreds of connections and
    /// neither divides across cores: a relay measured at 3,500 subscribers on four
    /// vCPUs never got past 3.4 of them, and collapsed rather than saturating the
    /// link. Several sockets on the same port, which `SO_REUSEPORT` allows, give
    /// each shard its own driver and its own send lock, and the kernel spreads
    /// arriving connections across them by a hash of the four-tuple.
    ///
    /// Every returned `Server` is a peer of the others: each needs its own accept
    /// loop, and they share nothing but the port.
    ///
    /// Two things to know before turning this on:
    ///
    /// * **Migration.** The kernel steers by four-tuple, so a client that changes
    ///   address or port -- a phone moving from wifi to cellular -- can be steered
    ///   to a shard that has never heard of its connection ID, which ends the
    ///   connection that [`Server::bound`]'s `migration(true)` exists to preserve.
    ///   Safe for a fixed fleet of subscribers and for a load test; not safe in
    ///   front of mobile clients until the steering is done by connection ID with
    ///   an eBPF `SO_REUSEPORT` program instead of by four-tuple.
    /// * **Linux.** `SO_REUSEPORT` load-balances on Linux. On the BSDs, including
    ///   macOS, it permits the bind without distributing across it, so asking for
    ///   shards there binds successfully and measures nothing.
    ///
    /// One shard takes the ordinary single-socket path exactly, so the default
    /// deployment is not affected by any of the above.
    ///
    /// # Errors
    /// As [`Server::bind_marked`], and if `SO_REUSEPORT` cannot be set.
    pub fn bind_shards(
        addr: SocketAddr,
        tls: rustls::ServerConfig,
        dscp: Option<u8>,
        shards: NonZeroUsize,
    ) -> io::Result<Vec<Self>> {
        let config = Self::configured(tls, Liveness::DEFAULT)?;
        if shards.get() == 1 {
            return Ok(vec![Self::new(Self::endpoint(addr, config, dscp, false)?)]);
        }

        // The first shard's bound address rather than the requested one, so that
        // asking for port zero still puts every shard on one port. Binding each to
        // port zero would hand out several ports, of which clients could reach one.
        let first = Self::new(Self::endpoint(addr, config.clone(), dscp, true)?);
        let port = first.local_addr()?;
        let mut servers = vec![first];
        for _ in 1..shards.get() {
            servers.push(Self::new(Self::endpoint(
                port,
                config.clone(),
                dscp,
                true,
            )?));
        }
        Ok(servers)
    }

    fn bound(
        addr: SocketAddr,
        tls: rustls::ServerConfig,
        liveness: Liveness,
        dscp: Option<u8>,
    ) -> io::Result<Self> {
        let config = Self::configured(tls, liveness)?;
        Ok(Self::new(Self::endpoint(addr, config, dscp, false)?))
    }

    /// The QUIC server configuration a listener is built from.
    fn configured(
        tls: rustls::ServerConfig,
        liveness: Liveness,
    ) -> io::Result<quinn::ServerConfig> {
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));

        let mut transport = quinn::TransportConfig::default();
        liveness
            .apply(&mut transport)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        Self::size_windows(&mut transport);
        config.transport_config(Arc::new(transport));

        // Already the default, and set anyway because of what it does here. A
        // phone moving from wifi to cellular keeps its QUIC connection: the
        // path changes underneath and the connection ID does not, so the
        // session survives what would end a TCP one. Turning this off would
        // convert every handover into a disconnection, a reconnection, and a
        // gap in somebody's broadcast -- and it would do so silently, which is
        // why it is written down rather than inherited.
        config.migration(true);
        Ok(config)
    }

    /// One endpoint, on a socket configured the way this deployment needs.
    fn endpoint(
        addr: SocketAddr,
        config: quinn::ServerConfig,
        dscp: Option<u8>,
        share_port: bool,
    ) -> io::Result<quinn::Endpoint> {
        if dscp.is_none() && !share_port {
            return quinn::Endpoint::server(config, addr);
        }

        // Bound here rather than by `Endpoint::server`, which binds its own and offers no way to
        // configure it first. The codepoint has to be on the socket before the endpoint wraps it,
        // because `quinn-udp` reads it once and carries it into the control message it attaches
        // to every datagram -- see the note in `vendor/quinn/VENDORED.md`. `SO_REUSEPORT` has to
        // be set before the bind for the same reason every sharing socket must set it: the kernel
        // decides at bind time whether the address is already taken.
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        if share_port {
            socket.set_reuse_port(true)?;
        }
        if let Some(dscp) = dscp {
            // Shifted into the top six bits: the value names a codepoint, and the two bits below
            // it are ECN's, which belong to the transport.
            let tos = u32::from(dscp) << 2;
            if addr.is_ipv6() {
                socket.set_tclass_v6(tos)?;
            } else {
                socket.set_tos_v4(tos)?;
            }
        }
        socket.bind(&addr.into())?;

        let runtime =
            quinn::default_runtime().ok_or_else(|| io::Error::other("no async runtime found"))?;
        quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(config),
            socket.into(),
            runtime,
        )
    }

    /// Per-stream credit large enough that a media stream never needs a refill,
    /// and a connection-wide cap to replace the unlimited default.
    ///
    /// The per-stream number is not about throughput. `quinn` sends
    /// `MAX_STREAM_DATA` once a stream has been read past an eighth of its
    /// window, which at the default 1.25 MB is every 160 KB — two or three times
    /// a second for one 720p track. That is legal and ordinarily harmless, but a
    /// subgroup stream *ends* at every group boundary, so sooner or later a
    /// refill is in flight when the publisher finishes the stream and frees it.
    /// RFC 9000 § 3.1 anticipates exactly this and says the sender "can safely
    /// ignore" credit for a stream in `Data Sent`. Apple's stack does not: it
    /// answers with `STREAM_STATE_ERROR` and takes the whole connection down,
    /// which on a phone is the call ending mid-sentence roughly every fifteen
    /// seconds. Sizing the window past what any group carries means the frame is
    /// never sent, and the race has nothing to lose.
    ///
    /// The connection cap is the safety this trades against. `quinn` defaults
    /// `receive_window` to unlimited, which with a window this large would let a
    /// peer opening many streams at once buffer without bound; the cap is what
    /// bounds it, and it is per connection rather than per stream because the
    /// relay reads promptly and no single track legitimately needs more.
    fn size_windows(transport: &mut quinn::TransportConfig) {
        const STREAM_WINDOW: u32 = 16 * 1024 * 1024;
        const CONNECTION_WINDOW: u32 = 64 * 1024 * 1024;

        transport.stream_receive_window(STREAM_WINDOW.into());
        transport.receive_window(CONNECTION_WINDOW.into());
    }

    /// The address actually bound, which differs from the requested one when
    /// port 0 was asked for.
    ///
    /// # Errors
    /// If the socket cannot report its address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Wait for the next incoming connection.
    ///
    /// Returns as soon as a packet arrives, *before* the handshake runs. The
    /// caller is expected to spawn [`Accepting::establish`] rather than await
    /// it here, and the split exists to make that the obvious thing to do: a
    /// single accept loop that awaited each handshake in turn would let one
    /// slow or hostile peer stall every connection behind it. That is a trivial
    /// denial of service against a public relay, and it is the default
    /// behaviour of the obvious API.
    ///
    /// `None` once the endpoint is closed.
    pub async fn accept(&self) -> Option<Accepting> {
        self.endpoint.accept().await.map(Accepting)
    }

    /// Stop accepting, and wait for existing connections to drain.
    pub async fn shutdown(&self) {
        self.endpoint.close(0u32.into(), b"shutting down");
        self.endpoint.wait_idle().await;
    }
}

/// An inbound connection whose handshake has not run yet.
pub struct Accepting(quinn::Incoming);

impl Accepting {
    /// The peer's address, available before the handshake.
    #[must_use]
    pub fn remote_address(&self) -> SocketAddr {
        self.0.remote_address()
    }

    /// Refuse the connection without completing a handshake.
    ///
    /// Cheaper than accepting and closing, and the right response to an address
    /// that is already rate limited — the point is to not do the asymmetric
    /// work an attacker is trying to make us do.
    pub fn refuse(self) {
        self.0.refuse();
    }

    /// Complete the handshake and establish a session.
    ///
    /// The carrier is decided here, by whichever ALPN the TLS handshake settled
    /// on, and this is the only place in the codebase that branches on it.
    ///
    /// # Errors
    /// [`AcceptError`] if either handshake fails, or if the negotiated protocol
    /// is not one this build understands.
    pub async fn establish(self) -> Result<(Session, Negotiated), AcceptError> {
        let conn = self.0.await?;
        let negotiated = Negotiated::from_connection(&conn).ok_or(AcceptError::UnexpectedAlpn)?;

        let session = match negotiated.carrier {
            Carrier::WebTransport => {
                web_transport_quinn::Request::accept(conn)
                    .await?
                    .ok()
                    .await?
            }

            // No CONNECT to exchange, so the session begins immediately. The
            // URL is a placeholder: on raw QUIC the authority and path arrive
            // later in Setup Options (draft-19 3.1.5), and nothing below this
            // point reads it.
            Carrier::Quic => Session::raw(conn, placeholder_url(), ConnectResponse::OK),
        };

        Ok((session, negotiated))
    }
}

/// What the handshake settled on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Negotiated {
    /// What is moving the bytes.
    pub carrier: Carrier,
    /// Which message grammar to speak.
    ///
    /// `None` over WebTransport, where the dialect comes from the
    /// `WT-Available-Protocols` header rather than the ALPN, and so is not
    /// known at this layer yet.
    pub dialect: Option<Dialect>,
}

impl Negotiated {
    fn from_connection(conn: &quinn::Connection) -> Option<Self> {
        let data = conn.handshake_data()?;
        let handshake = data
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .ok()?;
        let protocol = handshake.protocol?;

        Some(Self {
            carrier: Carrier::from_alpn(&protocol)?,
            dialect: Dialect::from_token(&protocol),
        })
    }
}

impl std::fmt::Display for Negotiated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.dialect {
            Some(dialect) => write!(f, "{}/{dialect}", self.carrier),
            None => write!(f, "{}", self.carrier),
        }
    }
}

/// Stands in for the `CONNECT` URL a raw QUIC session never had.
fn placeholder_url() -> web_transport_quinn::proto::ConnectRequest {
    let url = url::Url::parse("https://moqt.invalid/").expect("a constant, valid URL");
    web_transport_quinn::proto::ConnectRequest::new(url)
}

/// A TLS configuration that offers both carriers.
///
/// Setting the ALPN list correctly is the single thing that makes dual-carrier
/// work, and getting it wrong produces a server that silently serves only one.
/// Callers that build their own `rustls::ServerConfig` should route it through
/// here rather than setting `alpn_protocols` by hand.
#[must_use]
pub fn with_moqt_alpn(mut tls: rustls::ServerConfig) -> rustls::ServerConfig {
    tls.alpn_protocols = alpn::OFFERED.iter().map(|p| p.to_vec()).collect();
    tls
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_alpn_helper_offers_exactly_what_we_advertise() {
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new()));

        let tls = with_moqt_alpn(tls);
        let offered: Vec<&[u8]> = tls.alpn_protocols.iter().map(Vec::as_slice).collect();
        assert_eq!(offered, alpn::OFFERED);
    }
}
