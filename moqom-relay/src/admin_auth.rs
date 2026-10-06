//! Who may read the admin port.
//!
//! The admin port answers two kinds of question. `/healthz` and `/readyz` say one
//! bit each about the process, and the things that ask them -- a load balancer's
//! prober, an orchestrator -- cannot hold a credential. Everything else names
//! people: `/sessions` lists peer addresses, `/rooms` lists usernames, `/tracks`
//! lists what each of them is publishing, and `/metrics` is the shape of the
//! traffic. Those need a credential.
//!
//! # The mechanisms
//!
//! Two, and either or both may be configured. When both are, both must pass.
//!
//! - A **bearer token**, compared in constant time. What a scraper on the same
//!   private network can be given with the least machinery.
//! - **Mutual TLS** against an operator authority. The listener speaks TLS, and
//!   a protected path needs a client certificate that authority issued. Probes
//!   still work without one, so a prober that does TLS but holds no certificate
//!   can keep asking whether the relay is well.
//!
//! A third setting, `probes-only`, serves the two probes and refuses everything
//! else. It is what a deployment uses when it needs the port for health checks
//! and has not issued an admin credential yet.
//!
//! # The rule about addresses
//!
//! A listener with none of the above is open, and an open listener may only
//! bind a loopback address. That is checked before binding rather than
//! documented: a relay given `0.0.0.0` and no credential refuses to start, which
//! is louder than serving its participant list to the VPC.

use std::net::SocketAddr;
use std::sync::Arc;

use aws_lc_rs::digest;

/// The shortest bearer token accepted.
///
/// Thirty-two characters is 192 bits of base64 or 128 of hex, which is past the
/// point where guessing is the attack worth worrying about. A shorter one is
/// almost always a placeholder that reached production.
pub const MIN_TOKEN_LEN: usize = 32;

/// Why an admin configuration was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GuardError {
    /// An open listener was asked to bind somewhere other than loopback.
    #[error(
        "refusing to serve the admin port on {0} without authentication: set \
         MOQOM_RELAY_ADMIN_TOKEN_FILE or MOQOM_RELAY_ADMIN_CLIENT_CA, set \
         MOQOM_RELAY_ADMIN_AUTH=probes-only, or bind a loopback address"
    )]
    OpenOnNetwork(SocketAddr),
    /// The bearer token is too short to be a credential.
    #[error("the admin token is {0} characters; at least {MIN_TOKEN_LEN} are required")]
    WeakToken(usize),
    /// `probes-only` was combined with a credential, which would mean nothing.
    #[error("MOQOM_RELAY_ADMIN_AUTH=probes-only cannot be combined with an admin credential")]
    ProbesOnlyWithCredential,
    /// A certificate, key or authority could not be used.
    #[error("admin TLS: {0}")]
    Tls(String),
}

/// What a request is answered with, before any endpoint runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Serve it.
    Allow,
    /// 401: a bearer token was required and the right one was not presented.
    Unauthenticated,
    /// 403: no credential this request could present would be enough, either
    /// because the listener serves only probes or because the TLS connection
    /// carried no client certificate.
    Forbidden,
}

/// The policy one admin listener enforces.
///
/// Holds a digest of the token rather than the token, so the comparison is
/// between two fixed-length values and takes the same time whatever was sent.
#[derive(Clone, Default)]
pub struct Guard {
    bearer: Option<[u8; 32]>,
    client_certificates: bool,
    probes_only: bool,
}

impl std::fmt::Debug for Guard {
    // Hand-written so a debug print of the configuration cannot leak the digest,
    // which is not the token but is a value an attacker could test guesses
    // against offline.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Guard")
            .field("bearer", &self.bearer.is_some())
            .field("client_certificates", &self.client_certificates)
            .field("probes_only", &self.probes_only)
            .finish()
    }
}

impl Guard {
    /// No credential at all. Only permitted on loopback; see [`Guard::permits_bind`].
    #[must_use]
    pub fn open() -> Self {
        Self::default()
    }

    /// Serve `/healthz` and `/readyz` to anyone and nothing else to anybody.
    #[must_use]
    pub fn probes_only() -> Self {
        Self {
            probes_only: true,
            ..Self::default()
        }
    }

    /// Require `Authorization: Bearer <token>` on protected paths.
    ///
    /// Surrounding whitespace is trimmed, because the token usually arrives from
    /// a file and a trailing newline is not part of anybody's secret.
    ///
    /// # Errors
    /// [`GuardError::WeakToken`] for a token shorter than [`MIN_TOKEN_LEN`], and
    /// [`GuardError::ProbesOnlyWithCredential`] on a probes-only guard.
    pub fn with_bearer(mut self, token: &str) -> Result<Self, GuardError> {
        if self.probes_only {
            return Err(GuardError::ProbesOnlyWithCredential);
        }
        let token = token.trim();
        if token.len() < MIN_TOKEN_LEN {
            return Err(GuardError::WeakToken(token.len()));
        }
        self.bearer = Some(sha256(token.as_bytes()));
        Ok(self)
    }

    /// Require a verified client certificate on protected paths.
    ///
    /// The verification itself happens in the TLS handshake, configured by
    /// [`tls_config`]; this records that its outcome is required.
    ///
    /// # Errors
    /// [`GuardError::ProbesOnlyWithCredential`] on a probes-only guard.
    pub fn with_client_certificates(mut self) -> Result<Self, GuardError> {
        if self.probes_only {
            return Err(GuardError::ProbesOnlyWithCredential);
        }
        self.client_certificates = true;
        Ok(self)
    }

    /// Whether this guard admits anybody to the protected paths.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.bearer.is_none() && !self.client_certificates && !self.probes_only
    }

    /// Whether a TLS listener is needed to enforce this guard.
    #[must_use]
    pub fn needs_tls(&self) -> bool {
        self.client_certificates
    }

    /// Check the guard against the address it is about to bind.
    ///
    /// # Errors
    /// [`GuardError::OpenOnNetwork`] for an open guard on any address that is not
    /// loopback, including the unspecified address and IPv4-mapped forms of a
    /// public one.
    pub fn permits_bind(&self, addr: SocketAddr) -> Result<(), GuardError> {
        if self.is_open() && !addr.ip().to_canonical().is_loopback() {
            return Err(GuardError::OpenOnNetwork(addr));
        }
        Ok(())
    }

    /// Decide a request.
    ///
    /// `authorization` is the raw `Authorization` header value, if any, and
    /// `client_certificate` is whether the TLS handshake verified one. A
    /// certificate that failed verification never gets this far: the handshake
    /// refuses it.
    #[must_use]
    pub fn judge(&self, path: &str, authorization: Option<&str>, client_certificate: bool) -> Verdict {
        if is_probe(path) {
            return Verdict::Allow;
        }
        if self.probes_only {
            return Verdict::Forbidden;
        }
        if self.client_certificates && !client_certificate {
            return Verdict::Forbidden;
        }
        if let Some(expected) = &self.bearer {
            let presented = authorization.and_then(bearer_token);
            match presented {
                Some(token) if same_secret(token.as_bytes(), expected) => {}
                _ => return Verdict::Unauthenticated,
            }
        }
        Verdict::Allow
    }
}

/// Whether a path is one of the two that are always served.
///
/// Matched on the path alone, ignoring a query string, the same way the router
/// does, so `/healthz?x` cannot be exempt here and routed somewhere else there.
#[must_use]
pub fn is_probe(target: &str) -> bool {
    let path = target.split(['?', '#']).next().unwrap_or(target);
    matches!(path, "/healthz" | "/readyz")
}

/// The token from an `Authorization` header, if it uses the bearer scheme.
///
/// The scheme name is case-insensitive per RFC 9110; the token is not.
fn bearer_token(header: &str) -> Option<&str> {
    let header = header.trim();
    let (scheme, token) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then_some(token)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest::digest(&digest::SHA256, bytes).as_ref());
    out
}

/// Compare a presented secret against a stored digest in constant time.
///
/// Hashing first means the comparison is always over 32 bytes, so neither the
/// length of the presented value nor the position of its first wrong byte
/// changes how long this takes.
fn same_secret(presented: &[u8], expected: &[u8; 32]) -> bool {
    let presented = sha256(presented);
    let mut difference = 0u8;
    for (a, b) in presented.iter().zip(expected) {
        difference |= a ^ b;
    }
    std::hint::black_box(difference) == 0
}

/// Build the admin listener's TLS configuration.
///
/// Client certificates are verified against `client_ca_pem` and are optional at
/// the handshake, because the probes must still work without one. A certificate
/// that is presented and does not verify fails the handshake; one that is absent
/// leaves the connection able to reach the probes and nothing else (see
/// [`Guard::judge`]).
///
/// # Errors
/// [`GuardError::Tls`] if any PEM is unreadable or empty, or the key does not
/// match the certificate.
pub fn tls_config(
    server_cert_pem: &[u8],
    server_key_pem: &[u8],
    client_ca_pem: &[u8],
) -> Result<Arc<rustls::ServerConfig>, GuardError> {
    let tls = |e: &dyn std::fmt::Display| GuardError::Tls(e.to_string());

    let certs = rustls_pemfile::certs(&mut &server_cert_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| tls(&e))?;
    if certs.is_empty() {
        return Err(GuardError::Tls("no certificate in the admin certificate file".into()));
    }
    let key = rustls_pemfile::private_key(&mut &server_key_pem[..])
        .map_err(|e| tls(&e))?
        .ok_or_else(|| GuardError::Tls("no private key in the admin key file".into()))?;

    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut &client_ca_pem[..]) {
        roots.add(certificate.map_err(|e| tls(&e))?).map_err(|e| tls(&e))?;
    }
    if roots.is_empty() {
        return Err(GuardError::Tls("the operator authority file holds no certificates".into()));
    }

    // Explicit provider, as everywhere else in the relay: more than one is
    // compiled into this binary, and relying on a process default would make
    // this fail in a test that never installed one.
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::clone(&provider),
    )
    .allow_unauthenticated()
    .build()
    .map_err(|e| tls(&e))?;

    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| tls(&e))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| tls(&e))?;
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("address")
    }

    #[test]
    fn an_open_guard_binds_loopback_only() {
        let open = Guard::open();
        assert!(open.permits_bind(addr("127.0.0.1:9090")).is_ok());
        assert!(open.permits_bind(addr("[::1]:9090")).is_ok());
        assert!(open.permits_bind(addr("[::ffff:127.0.0.1]:9090")).is_ok());

        for refused in ["0.0.0.0:9090", "[::]:9090", "10.0.0.4:9090", "[::ffff:10.0.0.4]:9090"] {
            assert_eq!(
                open.permits_bind(addr(refused)),
                Err(GuardError::OpenOnNetwork(addr(refused))),
                "{refused}"
            );
        }
    }

    #[test]
    fn any_configured_mechanism_permits_a_network_bind() {
        let everywhere = addr("0.0.0.0:9090");
        assert!(Guard::probes_only().permits_bind(everywhere).is_ok());
        assert!(Guard::open().with_bearer(TOKEN).unwrap().permits_bind(everywhere).is_ok());
        assert!(
            Guard::open()
                .with_client_certificates()
                .unwrap()
                .permits_bind(everywhere)
                .is_ok()
        );
    }

    #[test]
    fn a_short_token_is_refused() {
        assert_eq!(Guard::open().with_bearer("hunter2").unwrap_err(), GuardError::WeakToken(7));
        assert_eq!(
            Guard::open().with_bearer(&format!("  {}\n", &TOKEN[..31])).unwrap_err(),
            GuardError::WeakToken(31),
            "whitespace does not count towards the length"
        );
    }

    #[test]
    fn probes_only_cannot_also_carry_a_credential() {
        assert_eq!(
            Guard::probes_only().with_bearer(TOKEN).unwrap_err(),
            GuardError::ProbesOnlyWithCredential
        );
        assert_eq!(
            Guard::probes_only().with_client_certificates().unwrap_err(),
            GuardError::ProbesOnlyWithCredential
        );
    }

    #[test]
    fn probes_are_always_answered() {
        let guard = Guard::open()
            .with_bearer(TOKEN)
            .unwrap()
            .with_client_certificates()
            .unwrap();
        for probe in ["/healthz", "/readyz", "/readyz?verbose"] {
            assert_eq!(guard.judge(probe, None, false), Verdict::Allow, "{probe}");
        }
        assert_eq!(Guard::probes_only().judge("/healthz", None, false), Verdict::Allow);
    }

    #[test]
    fn probes_only_refuses_everything_else() {
        let guard = Guard::probes_only();
        for path in ["/metrics", "/sessions", "/rooms", "/tracks", "/", "/healthz/../sessions"] {
            assert_eq!(guard.judge(path, Some(&format!("Bearer {TOKEN}")), true), Verdict::Forbidden);
        }
    }

    #[test]
    fn the_bearer_token_is_checked() {
        let guard = Guard::open().with_bearer(TOKEN).unwrap();
        assert_eq!(guard.judge("/sessions", None, false), Verdict::Unauthenticated);
        assert_eq!(guard.judge("/sessions", Some("Bearer wrong"), false), Verdict::Unauthenticated);
        assert_eq!(
            guard.judge("/sessions", Some(&format!("Bearer {TOKEN}x")), false),
            Verdict::Unauthenticated,
            "a longer value that starts with the token is a different token"
        );
        assert_eq!(
            guard.judge("/sessions", Some(&format!("Basic {TOKEN}")), false),
            Verdict::Unauthenticated
        );
        assert_eq!(guard.judge("/sessions", Some(&format!("Bearer {TOKEN}")), false), Verdict::Allow);
        assert_eq!(guard.judge("/metrics", Some(&format!("bearer  {TOKEN} ")), false), Verdict::Allow);
    }

    #[test]
    fn a_client_certificate_is_required_when_configured() {
        let guard = Guard::open().with_client_certificates().unwrap();
        assert_eq!(guard.judge("/sessions", None, false), Verdict::Forbidden);
        assert_eq!(guard.judge("/sessions", None, true), Verdict::Allow);
    }

    #[test]
    fn both_mechanisms_must_pass_when_both_are_configured() {
        let guard = Guard::open()
            .with_bearer(TOKEN)
            .unwrap()
            .with_client_certificates()
            .unwrap();
        let header = format!("Bearer {TOKEN}");
        assert_eq!(guard.judge("/rooms", Some(&header), false), Verdict::Forbidden);
        assert_eq!(guard.judge("/rooms", None, true), Verdict::Unauthenticated);
        assert_eq!(guard.judge("/rooms", Some(&header), true), Verdict::Allow);
    }

    #[test]
    fn the_debug_form_does_not_print_the_digest() {
        let printed = format!("{:?}", Guard::open().with_bearer(TOKEN).unwrap());
        assert!(printed.contains("bearer: true"), "{printed}");
        assert!(!printed.contains('['), "{printed}");
    }

    #[test]
    fn a_ca_with_no_certificates_is_refused() {
        let leaf = rcgen::generate_simple_self_signed(vec!["relay.internal".to_owned()]).unwrap();
        let err = tls_config(
            leaf.cert.pem().as_bytes(),
            leaf.signing_key.serialize_pem().as_bytes(),
            b"",
        )
        .unwrap_err();
        assert!(matches!(err, GuardError::Tls(_)), "{err}");
    }
}
