//! Accepting sessions over both carriers on one UDP port.

use std::io;
use std::net::SocketAddr;
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

        Ok(Self::new(quinn::Endpoint::server(config, addr)?))
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
