//! Session establishment for MOQT over QUIC and WebTransport.
//!
//! MOQT does not care which of the two carries it — it needs a bidirectional
//! control stream, more bidirectional and unidirectional streams on demand, and
//! datagrams. Both provide exactly that, and the difference is confined to how
//! a session is opened. This crate is that confinement: everything above it
//! sees one [`Session`] regardless of how the peer connected.
//!
//! That matters because the two are not alternatives to choose between. A
//! browser can only reach us over WebTransport, and a native client should not
//! pay for HTTP/3 to do it. Both have to work, on the same port, at the same
//! time — so the choice is the peer's, made during the handshake, and the relay
//! finds out after the fact rather than being configured for one or the other.
//!
//! # How the two paths converge
//!
//! The obvious design is a trait with a QUIC implementation and a WebTransport
//! one, and it is the wrong one. WebTransport streams carry a session-ID
//! preamble that raw QUIC streams do not, so the two are not interchangeable at
//! the stream level, and a trait would push that difference up into every
//! caller — or hide it behind `dyn` dispatch on the hot path.
//!
//! `web_transport_quinn::Session::raw` removes the problem. It wraps a plain
//! `quinn::Connection` as a `Session` with no session ID, which means no
//! preamble is written and the streams are byte-for-byte raw QUIC. Upstream
//! calls it a hack. It is the right one: both protocols become the same
//! concrete type, the relay above never branches on which is in use, and the
//! only place the distinction survives is the accept path in this crate.
//!
//! [`Session`] is that type. Nothing above this crate should learn how a peer
//! connected — if something needs to, that is a signal the abstraction leaked
//! rather than a reason to expose [`Protocol`].
//!
//! # Status
//!
//! Scaffolding. The types below fix the shape of the boundary; the
//! implementations land next.

#![forbid(unsafe_code)]

/// A MOQT session, however the peer reached us.
///
/// One concrete type for both protocols — see the module docs for why this is
/// not a trait.
pub type Session = web_transport_quinn::Session;

/// How a peer connected.
///
/// Determined by ALPN during the handshake, so it is only knowable once the
/// handshake completes. Exposed for logging and metrics; behaviour above this
/// crate should not depend on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// Raw MOQT over QUIC. No HTTP layer, no stream preamble.
    Moq,
    /// WebTransport over HTTP/3, which is all a browser can offer.
    WebTransport,
}

impl Protocol {
    /// Identify a protocol from the ALPN the handshake settled on.
    #[must_use]
    pub fn from_alpn(alpn: &[u8]) -> Option<Self> {
        match alpn {
            alpn::MOQ => Some(Self::Moq),
            alpn::H3 => Some(Self::WebTransport),
            _ => None,
        }
    }

    /// The ALPN identifier.
    #[must_use]
    pub const fn alpn(self) -> &'static [u8] {
        match self {
            Self::Moq => alpn::MOQ,
            Self::WebTransport => alpn::H3,
        }
    }
}

/// The negotiated ALPN protocols.
///
/// Offered together on one endpoint. `h3` gets WebTransport a browser can
/// reach; the MOQT identifier gets a native client a direct QUIC connection
/// with no HTTP layer in the way. Which one a peer picks is discoverable only
/// after the TLS handshake completes, which is why dispatch happens there
/// rather than at listener setup.
pub mod alpn {
    /// Raw MOQT over QUIC, per draft-19 §3.2.
    pub const MOQ: &[u8] = b"moq-00";

    /// HTTP/3, which carries WebTransport.
    pub const H3: &[u8] = b"h3";

    /// Both, in preference order. A peer that understands MOQT directly should
    /// use it; the HTTP/3 fallback exists for peers that have no choice.
    pub const ALL: &[&[u8]] = &[MOQ, H3];
}

#[cfg(test)]
mod tests {
    /// The vendored `quinn` is only worth having if it is the one actually
    /// linked. A `[patch.crates-io]` entry that silently fails to apply --
    /// because a version requirement stopped matching, say -- would leave us
    /// building against the registry copy while `vendor/quinn` sat unused and
    /// unnoticed.
    ///
    /// `vendor/verify-quinn.sh` checks this properly, by asking cargo where the
    /// crate resolved from. This is the cheap version: if the patch is not
    /// applied, `quinn` is absent or a different version, and the build fails
    /// before the test runs.
    #[test]
    fn quinn_is_linked() {
        let _ = quinn::VarInt::from_u32(0);
    }

    /// Every ALPN we offer must map to a protocol, and back. A mismatch here
    /// would mean advertising something the accept path then refuses to
    /// dispatch — a handshake that succeeds and a session that never starts.
    #[test]
    fn every_offered_alpn_round_trips() {
        for alpn in super::alpn::ALL {
            let protocol = super::Protocol::from_alpn(alpn)
                .unwrap_or_else(|| panic!("unmapped ALPN {alpn:?}"));
            assert_eq!(protocol.alpn(), *alpn);
        }
        assert_eq!(super::Protocol::from_alpn(b"h2"), None);
    }
}
