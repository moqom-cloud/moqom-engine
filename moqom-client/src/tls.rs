//! TLS helpers for talking to a MOQT relay.
//!
//! [`Session::connect`](crate::Session::connect) takes a `rustls::ClientConfig`
//! so a caller can bring their own roots. These constructors set the MOQT
//! ALPNs; `connect` sets them again, so a config built here cannot silently
//! speak the wrong protocol.

use std::sync::{Arc, Once};

use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

/// A client config that trusts the webpki root program.
#[must_use]
pub fn native() -> rustls::ClientConfig {
    install_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    apply_alpn(&mut tls);
    tls
}

/// A client config that accepts any certificate.
///
/// For a self-signed development relay, where the alternative is pinning a
/// hash that has to travel out of band. Do not use this against the internet.
#[must_use]
pub fn insecure() -> rustls::ClientConfig {
    install_crypto_provider();
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    apply_alpn(&mut tls);
    tls
}

/// A client config that trusts exactly one certificate, by comparing its bytes.
///
/// A self-signed end-entity cannot be a webpki trust anchor, so the
/// alternatives were this or [`insecure`]. Pinning is what a test (and a
/// client that was handed the relay's cert) actually does.
#[must_use]
pub fn pinned(certificate: CertificateDer<'static>) -> rustls::ClientConfig {
    install_crypto_provider();
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCertificate(certificate)))
        .with_no_client_auth();
    apply_alpn(&mut tls);
    tls
}

/// Offer draft-22 first, then MOQOM's draft-19.
///
/// The order is the preference; the relay picks. Draft-16 is not offered: it
/// is only spoken to a relay known to want it.
pub(crate) fn apply_alpn(tls: &mut rustls::ClientConfig) {
    tls.alpn_protocols = vec![
        moqom_transport::alpn::MOQT_DRAFT_22.to_vec(),
        moqom_transport::alpn::MOQT_DRAFT_19.to_vec(),
    ];
}

pub(crate) fn install_crypto_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Trusts every certificate. See [`insecure`].
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
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
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Trusts exactly one certificate, by comparing its bytes.
#[derive(Debug)]
struct PinnedCertificate(CertificateDer<'static>);

impl rustls::client::danger::ServerCertVerifier for PinnedCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.0.as_ref() {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }
        Err(rustls::Error::General(
            "certificate is not the pinned one".into(),
        ))
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
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
