//! Attaching a relay to a parent, so it can serve tracks it does not hold.
//!
//! This is the half of fan-out that one machine cannot do. A relay copies one
//! publisher's objects to everybody watching, and that arithmetic is what makes a
//! room cheap — but it bounds an audience by one host's network card, because every
//! viewer of a track has to be connected to the relay that holds its publisher.
//! There is no sharding a single track around that: the copies have to come from
//! somewhere, and the publisher is only in one place.
//!
//! An edge with a parent removes the bound. It asks the parent for a track no local
//! session publishes, and from then on it is an ordinary publisher as far as its own
//! viewers are concerned — one copy uphill and as many downhill as it can write. The
//! tiers multiply, so audiences that need a hundred machines need a tier of a
//! hundred edges above which a single interior relay is barely working.
//!
//! What arrives here is deliberately not a new data path. The session to a parent is
//! the relay's own [`Session`], dialled instead of accepted, so an
//! object from a parent is forwarded by the same code that forwards an object from a
//! phone: the same deduplication, the same cache, the same latency budget, the same
//! counters. The alternative — a client library feeding a second forwarding
//! implementation — would have been two of everything, and the second one would be
//! the one without the bug fixes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::fabric::Fabric;
use crate::session::Session;

/// How long to wait before dialling a parent again after the link fails.
///
/// Fixed rather than exponential, and short. A parent is a sibling inside one
/// fleet, reached over a network this deployment owns, so a failure is a restart or
/// a deploy rather than congestion to back away from — and every second an edge
/// spends detached is a room its viewers cannot join. Backoff protects a service
/// from its clients, and an edge is not a stranger to its parent.
const RETRY: Duration = Duration::from_secs(1);

/// How long one address gets to complete a handshake before the next is tried.
///
/// Short, because a parent is inside the fleet and the point of the budget is to
/// move on. A name that resolves to both address families is the common case —
/// `localhost` does, and so does any internal record with an AAAA — and only one of
/// them may have a listener. Waiting out QUIC's own handshake timeout on the wrong
/// one would leave an edge detached for ten seconds at a time while an answer was
/// available on the other.
const DIAL: Duration = Duration::from_secs(3);

/// The drafts a link offers its parent, most preferred first.
pub const LINK_ALPN: [&[u8]; 2] = [
    moqom_transport::alpn::MOQT_DRAFT_22,
    moqom_transport::alpn::MOQT_DRAFT_19,
];

/// Where a relay's parent is, and how to introduce itself.
#[derive(Debug, Clone)]
pub struct Parent {
    /// The parent's host and port, resolved afresh for each attempt.
    ///
    /// A name rather than an address, because a parent behind a record that moves
    /// is the normal deployment: resolving once at startup would have an edge dial
    /// a decommissioned host forever, and the log would say "timed out" while DNS
    /// had the answer all along.
    pub host: String,
    /// The port the parent listens on.
    pub port: u16,
    /// The name to verify its certificate against.
    pub server_name: String,
    /// This relay's own credential, if the parent requires one.
    ///
    /// A relay in a fleet is authenticated like anything else. Being a relay is
    /// not a way past the door, and an unauthenticated interior tier would be an
    /// open proxy for every track the fleet carries.
    pub token: Option<String>,
}

impl std::fmt::Display for Parent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// Could not attach to the parent.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The name does not resolve, so there is nothing to dial.
    #[error("could not resolve the parent relay {parent}: {source}")]
    Unresolvable {
        /// The name that failed to resolve.
        parent: String,
        /// What the resolver said about it.
        #[source]
        source: std::io::Error,
    },
    /// Every address the name resolved to refused or ignored the connection.
    ///
    /// Carries each attempt, because the interesting failure is usually one
    /// address of several: a name with an AAAA and an A record where only the A
    /// has a listener reads as a timeout on the first and a working link on the
    /// second, and a message naming only one of them sends the reader to the
    /// wrong side of the fleet.
    #[error("could not reach the parent relay {parent}: {}", tried.join("; "))]
    Unreachable {
        /// The name this relay was trying to reach.
        parent: String,
        /// What each address said, in the order they were tried.
        tried: Vec<String>,
    },
    /// The session was established and then ended, or the parent turned it away.
    #[error("the parent relay refused or ended the session: {0}")]
    Refused(#[from] crate::session::SessionError),
}

/// Dial the parent and serve the session until it ends.
///
/// Returns when the link closes, which for a healthy fleet is when the process is
/// shutting down or the parent restarted. Callers wanting it to stay up should use
/// [`keep_attached`].
///
/// # Errors
/// [`Error`] if the parent cannot be reached, or if the session ends in a fault.
pub async fn attach(dialer: &Dialer, parent: &Parent, fabric: Fabric) -> Result<(), Error> {
    let addresses = tokio::net::lookup_host((parent.host.as_str(), parent.port))
        .await
        .map_err(|source| Error::Unresolvable {
            parent: parent.to_string(),
            source,
        })?;

    let mut tried = Vec::new();
    let mut established = None;
    for addr in addresses {
        match dialer.dial(addr, &parent.server_name).await {
            Ok(connection) => {
                established = Some(connection);
                break;
            }
            Err(failure) => tried.push(format!("{addr}: {failure}")),
        }
    }
    let Some(connection) = established else {
        return Err(Error::Unreachable {
            parent: parent.to_string(),
            tried,
        });
    };

    let transport = moqom_transport::Session::raw(
        connection,
        web_transport_quinn::proto::ConnectRequest::new(placeholder_url()),
        web_transport_quinn::proto::ConnectResponse::OK,
    );

    Session::attach(
        transport,
        fabric,
        parent.token.as_deref().map(str::as_bytes),
    )
    .await
    .map_err(Error::from)
}

/// Keep a parent attached, reconnecting when the link fails.
///
/// Never returns. Intended to be spawned beside the accept loop.
///
/// Failures are logged rather than propagated because there is nobody to propagate
/// them to: an edge whose parent is briefly gone should still serve the tracks it
/// already holds and the local publishers it already has, and should pick the link
/// up again when it comes back. What it must not do is pretend to have a parent
/// while it does not, which is why the session withdraws itself from the fabric on
/// the way out and a subscription in the gap is refused.
pub async fn keep_attached(dialer: Dialer, parent: Parent, fabric: Fabric) {
    loop {
        match attach(&dialer, &parent, fabric.clone()).await {
            Ok(()) => tracing::info!(%parent, "upstream link closed; reattaching"),
            Err(e) => tracing::warn!(%parent, error = %e, "upstream link failed"),
        }
        tokio::time::sleep(RETRY).await;
    }
}

/// Outgoing sockets for dialling a parent, trusting `tls`.
///
/// One per address family, because a socket cannot reach an address of the other
/// one and the family a parent's name resolves to is not this relay's choice.
/// Holding both is what lets [`attach`] work through the candidates a name gives
/// it; holding one would make half of them unreachable for a reason that appears in
/// the log as a timeout.
pub struct Dialer {
    v4: quinn::Endpoint,
    v6: Option<quinn::Endpoint>,
}

impl Dialer {
    /// Bind the outgoing sockets.
    ///
    /// Bound to arbitrary local ports on the unspecified address, because these are
    /// outgoing sockets: the relay's own listener is elsewhere and a parent never
    /// dials back.
    ///
    /// Offers draft-22 ahead of draft-19 whatever `tls` offered, because only a
    /// draft-22 link negotiates `HOP_LIMIT`; a parent that speaks only draft-19
    /// still gets a link, carrying the budget in `RELAY_HOPS`.
    ///
    /// # Errors
    /// [`std::io::Error`] if no socket can be bound, or the TLS configuration is
    /// not usable for QUIC.
    pub fn new(mut tls: rustls::ClientConfig) -> std::io::Result<Self> {
        tls.alpn_protocols = LINK_ALPN.iter().map(|alpn| alpn.to_vec()).collect();
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|e| std::io::Error::other(format!("TLS 1.3 is required for QUIC: {e}")))?;
        let config = quinn::ClientConfig::new(Arc::new(crypto));

        let bind = |addr: SocketAddr| -> std::io::Result<quinn::Endpoint> {
            let mut endpoint = quinn::Endpoint::client(addr)?;
            endpoint.set_default_client_config(config.clone());
            Ok(endpoint)
        };

        let v4 = bind(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)))?;
        // A host without IPv6 is ordinary, and refusing to start over it would take
        // out an edge whose parent is reachable over IPv4.
        let v6 = bind(SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))).ok();
        Ok(Self { v4, v6 })
    }

    /// Connect to one address, giving it [`DIAL`] to finish the handshake.
    async fn dial(
        &self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<quinn::Connection, Box<dyn std::error::Error + Send + Sync>> {
        let endpoint = match addr {
            SocketAddr::V4(_) => Some(&self.v4),
            SocketAddr::V6(_) => self.v6.as_ref(),
        };
        let Some(endpoint) = endpoint else {
            return Err("this host has no socket of that address family".into());
        };

        let connecting = endpoint.connect(addr, server_name)?;
        match tokio::time::timeout(DIAL, connecting).await {
            Ok(connection) => Ok(connection?),
            Err(_) => Err(format!("no handshake within {DIAL:?}").into()),
        }
    }
}

fn placeholder_url() -> url::Url {
    // A raw QUIC session has no CONNECT URL; the wrapper still wants one.
    "https://localhost/"
        .parse()
        .unwrap_or_else(|_| unreachable!("constant URL"))
}
