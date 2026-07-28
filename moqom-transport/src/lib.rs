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
//! calls it a hack. It is the right one: both carriers become the same concrete
//! type, the relay above never branches on which is in use, and the only place
//! the distinction survives is the accept path in this crate.
//!
//! # Status
//!
//! Scaffolding. The types below fix the shape of the boundary; the endpoint and
//! accept path land next.

#![forbid(unsafe_code)]

/// A MOQT session, however the peer reached us.
///
/// One concrete type for both carriers — see the module docs for why this is
/// not a trait.
pub type Session = web_transport_quinn::Session;

pub mod liveness;
pub mod server;

pub use liveness::{Liveness, LivenessError};
pub use server::{AcceptError, Accepting, Negotiated, Server};

/// Protocol identifiers offered during the handshake.
///
/// Draft-15 moved version negotiation out of `SETUP` and into these entirely
/// (§3.1.3). There is no in-band fallback any more: if the identifiers do not
/// agree, the connection fails at the TLS handshake and no MOQT message is ever
/// exchanged. Supporting two dialects therefore means offering two identifiers
/// and dispatching on the result, which is the whole reason [`Dialect`] exists
/// as a value rather than a compile-time constant.
pub mod alpn {
    /// MOQT as specified by `draft-ietf-moq-transport-19`.
    ///
    /// Draft ALPNs append the draft number to `moqt-`. This one is temporary by
    /// construction: every draft revision changes it, which is exactly the
    /// point — an implementation cannot accidentally speak -19 grammar to a -20
    /// peer, because they will not complete a handshake.
    pub const MOQT_DRAFT_19: &[u8] = b"moqt-19";

    /// MOQT as it will be once the specification is published.
    ///
    /// Deliberately **not** offered. Claiming it before the RFC exists would
    /// mean asserting conformance to a document that can still change, and the
    /// cost of being wrong is a peer that connects successfully and then
    /// misparses. It is here so the constant is in one place when the time
    /// comes.
    pub const MOQT_FINAL: &[u8] = b"moqt";

    /// HTTP/3, which carries WebTransport.
    pub const H3: &[u8] = b"h3";

    /// What we offer, in preference order.
    ///
    /// MOQT first: a peer that can speak it directly should, since HTTP/3 buys
    /// nothing but overhead for a client that is not a browser.
    pub const OFFERED: &[&[u8]] = &[MOQT_DRAFT_19, H3];
}

/// Which version of the MOQT message grammar a session speaks.
///
/// Independent of [`Carrier`]. A browser over WebTransport and a native client
/// over QUIC can speak the same dialect, and two native clients can speak
/// different ones — which is why these are two types rather than one flattened
/// enum of the combinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Dialect {
    /// `draft-ietf-moq-transport-19`.
    Draft19,
}

impl Dialect {
    /// Every dialect this build understands, newest first.
    ///
    /// The offered ALPN list is checked against this, so adding a dialect and
    /// forgetting to offer it is a test failure rather than a peer that
    /// mysteriously cannot connect.
    pub const ALL: &'static [Self] = &[Self::Draft19];

    /// The identifier this dialect is negotiated under.
    ///
    /// The same token in both places: an ALPN on raw QUIC, and an entry in the
    /// `WT-Available-Protocols` header on WebTransport.
    #[must_use]
    pub const fn token(self) -> &'static [u8] {
        match self {
            Self::Draft19 => alpn::MOQT_DRAFT_19,
        }
    }

    /// Identify a dialect from a negotiated token, or `None` if unsupported.
    #[must_use]
    pub fn from_token(token: &[u8]) -> Option<Self> {
        match token {
            alpn::MOQT_DRAFT_19 => Some(Self::Draft19),
            _ => None,
        }
    }
}

impl std::fmt::Display for Dialect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Draft19 => "moqt-19",
        })
    }
}

/// What is moving the bytes.
///
/// Affects nothing above this crate. Exposed for logging and metrics — if
/// something upstream starts branching on it, the abstraction has leaked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Carrier {
    /// Raw MOQT over QUIC. No HTTP layer and no stream preamble.
    ///
    /// The connection URL's authority, path, and query arrive later, in Setup
    /// Options, because a QUIC handshake has nowhere to put them (draft-19
    /// §3.1.5).
    Quic,

    /// WebTransport over HTTP/3, which is all a browser can offer.
    ///
    /// Here the same authority and path come from the extended `CONNECT` URL,
    /// and the `PATH` Setup Option is forbidden — a server that receives one
    /// answers `INVALID_PATH`.
    WebTransport,
}

impl Carrier {
    /// Which carrier an ALPN selects, or `None` for one we did not offer.
    #[must_use]
    pub fn from_alpn(alpn: &[u8]) -> Option<Self> {
        match alpn {
            alpn::H3 => Some(Self::WebTransport),
            other if Dialect::from_token(other).is_some() => Some(Self::Quic),
            _ => None,
        }
    }
}

impl std::fmt::Display for Carrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Quic => "quic",
            Self::WebTransport => "webtransport",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Carrier, Dialect, alpn};

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

    /// Every identifier we offer must resolve to a carrier. One that does not
    /// would complete a TLS handshake and then have nowhere to go -- a
    /// connection that succeeds and a session that never starts.
    #[test]
    fn every_offered_alpn_resolves() {
        for token in alpn::OFFERED {
            assert!(
                Carrier::from_alpn(token).is_some(),
                "offered {token:?} with no carrier"
            );
        }
        assert_eq!(Carrier::from_alpn(b"h2"), None);
    }

    /// Offering the unversioned `moqt` would claim conformance to a
    /// specification that does not exist yet, and the failure mode is a peer
    /// that connects and then misparses rather than one that fails to connect.
    #[test]
    fn the_final_alpn_is_not_offered_yet() {
        assert!(!alpn::OFFERED.contains(&alpn::MOQT_FINAL));
        assert_eq!(Dialect::from_token(alpn::MOQT_FINAL), None);
    }

    /// Pre-draft-15 used `moq-00` and negotiated the version inside SETUP.
    /// Accepting it now would mean completing a handshake with a peer whose
    /// message grammar we cannot read, since that in-band negotiation is gone.
    #[test]
    fn the_retired_alpn_is_rejected() {
        assert_eq!(Carrier::from_alpn(b"moq-00"), None);
        assert_eq!(Dialect::from_token(b"moq-00"), None);
    }

    #[test]
    fn dialect_tokens_round_trip() {
        for &dialect in Dialect::ALL {
            assert_eq!(Dialect::from_token(dialect.token()), Some(dialect));
            assert_eq!(dialect.to_string().as_bytes(), dialect.token());
        }
    }

    /// A dialect we can parse but never advertise is unreachable, and the
    /// symptom is a peer that fails to connect for no visible reason.
    #[test]
    fn every_dialect_is_offered() {
        for &dialect in Dialect::ALL {
            assert!(
                alpn::OFFERED.contains(&dialect.token()),
                "{dialect} is supported but not offered"
            );
        }
    }

    /// A MOQT ALPN means raw QUIC; h3 means WebTransport. Getting this backwards
    /// would wrap a raw connection in stream preambles the peer is not reading.
    #[test]
    fn alpn_selects_the_carrier() {
        assert_eq!(Carrier::from_alpn(b"moqt-19"), Some(Carrier::Quic));
        assert_eq!(Carrier::from_alpn(b"h3"), Some(Carrier::WebTransport));
    }
}
