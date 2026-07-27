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
//! # Status
//!
//! Scaffolding. The types below fix the shape of the boundary; the
//! implementations land next.

#![forbid(unsafe_code)]

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
}
