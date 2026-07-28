//! The relay server.
//!
//! Reads its configuration from the environment rather than flags, because the
//! two places this runs are a container and a test harness, and neither wants to
//! build an argument vector:
//!
//! - `MOQOM_RELAY_ADDR` — address to bind. Default `[::]:4443`.
//! - `MOQOM_RELAY_CERT`, `MOQOM_RELAY_KEY` — PEM paths. Both or neither; with
//!   neither, a self-signed certificate is generated for the names in
//!   `MOQOM_RELAY_NAMES` (default `localhost`).
//! - `MOQOM_RELAY_CACHE_GROUPS` — groups of history retained per track, which is
//!   what a reconnecting client can ask for. `0` retains nothing and refuses
//!   every fetch. Default 8.
//! - `MOQOM_RELAY_CACHE_MB` — megabytes of history retained across all tracks.
//!   Default 512.
//! - `MOQOM_RELAY_ADMIN_ADDR` — address for the metrics and diagnostics
//!   endpoints. Unset means no admin listener and no metrics collection at all,
//!   which is the default because an observability port that appears without
//!   being asked for is one that gets exposed by accident. See
//!   [`moqom_relay::admin`] for what it serves and why it is a separate port.
//! - `MOQOM_RELAY_LIMITS` — `off` disables per-user and per-device limits
//!   entirely. On otherwise, which is the default.
//! - `MOQOM_RELAY_LIMIT_SCALE` — multiply every allowance by this. Default 1.
//! - `MOQOM_RELAY_MAX_PRINCIPALS` — how many identities each tier tracks before
//!   it refuses new ones. Default 100000. See [`moqom_relay::quota`].
//! - `MOQOM_RELAY_JWKS` — path to the control plane's verification keys. Unset
//!   means no session is authenticated and every one is charged to its address,
//!   which is a much smaller allowance.
//! - `MOQOM_RELAY_ISSUER` — the issuer tokens must name. Unset accepts any,
//!   which is for tests.
//!
//! # A caveat about the address tier
//!
//! Unauthenticated peers are limited by IP, and that is the address the relay
//! sees. Behind a load balancer that does not preserve the client address, that
//! is one address for everybody, so the address tier becomes a single global
//! limit and legitimate clients starve each other. Either preserve the client
//! address at the balancer, or configure `MOQOM_RELAY_JWKS` so sessions are
//! identified by who they are rather than where they came from.
//!
//! A generated certificate prints its SPKI hash to stdout as
//! `certificate-hash: <base64>`, which is what a client needs to trust it. That
//! line, and the `listening: <addr>` line before it, are the machine-readable
//! part of this program's output; everything else goes to stderr as tracing.
//!
//! # On the self-signed default
//!
//! Convenience, not policy. A relay reachable from the internet must be given a
//! real certificate: the generated one is trusted by pinning its hash, and
//! pinning is only meaningful when the hash travels out of band. Two processes
//! on one machine can do that through stdout. Nothing else can.

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;

use base64::Engine as _;
use moqom_relay::admin::Surface;
use moqom_relay::{
    Authenticator, Cache, Fabric, Governor, Limits, Metrics, Quotas, Session, VerificationKey,
};
use moqom_transport::{Server, server::with_moqt_alpn};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Logs to stderr, so the two machine-readable lines on stdout stay clean.
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "moqom_relay=info".into()),
        )
        .init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Installed once, before any TLS configuration is built. `rustls` will
    // otherwise refuse to pick a provider when more than one is compiled in.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let addr: SocketAddr = env("MOQOM_RELAY_ADDR")
        .unwrap_or_else(|| "[::]:4443".to_owned())
        .parse()?;

    let tls = match (env_path("MOQOM_RELAY_CERT"), env_path("MOQOM_RELAY_KEY")) {
        (Some(cert), Some(key)) => tls_from_pem(&cert, &key)?,
        (None, None) => {
            let names: Vec<String> = env("MOQOM_RELAY_NAMES")
                .unwrap_or_else(|| "localhost".to_owned())
                .split(',')
                .map(str::to_owned)
                .collect();
            let (tls, hash) = self_signed(&names)?;
            println!("certificate-hash: {hash}");
            tls
        }
        _ => {
            return Err(
                "MOQOM_RELAY_CERT and MOQOM_RELAY_KEY must be set together or not at all".into(),
            );
        }
    };

    let server = Server::bind(addr, with_moqt_alpn(tls))?;
    let bound = server.local_addr()?;
    // Printed before the first accept so a harness can wait on this line rather
    // than poll the port, and flushed because stdout to a pipe is block
    // buffered — a harness reading line by line would otherwise wait forever.
    println!("listening: {bound}");
    io::Write::flush(&mut io::stdout())?;
    tracing::info!(%bound, "relay listening");

    let limits = cache_limits()?;
    tracing::info!(
        groups = limits.groups_per_track,
        megabytes = limits.bytes_total / (1024 * 1024),
        "retaining history"
    );
    // Metrics exist only when something can read them. A registry nobody scrapes
    // is a per-object atomic add that no query will ever run against.
    let admin_addr = match env("MOQOM_RELAY_ADMIN_ADDR") {
        Some(value) => Some(value.parse::<SocketAddr>()?),
        None => None,
    };
    let metrics = if admin_addr.is_some() {
        Metrics::new()
    } else {
        tracing::info!("no MOQOM_RELAY_ADMIN_ADDR, so metrics are off");
        Metrics::disabled()
    };

    let fabric = Fabric::observed(Cache::new(limits), metrics.clone())
        .governed(governor()?)
        .authenticated(authenticator()?);
    let surface = Surface::new(metrics, fabric.clone());
    if let Some(addr) = admin_addr {
        let serving = surface.clone();
        tokio::spawn(async move {
            if let Err(e) = serving.serve(addr).await {
                // Not fatal to the relay: losing the metrics endpoint is worth
                // reporting loudly and is not worth dropping live broadcasts
                // over.
                tracing::error!(%addr, error = %e, "admin listener failed");
            }
        });
    }

    loop {
        tokio::select! {
            () = shutdown() => {
                tracing::info!("draining");
                // Readiness drops before the drain begins, so a load balancer
                // stops sending new connections while the existing ones finish.
                // Doing it the other way round refuses traffic it was still
                // capable of serving.
                surface.draining();
                server.shutdown().await;
                return Ok(());
            }

            incoming = server.accept() => {
                let Some(incoming) = incoming else { return Ok(()) };
                let fabric = fabric.clone();
                // Spawned rather than awaited: the handshake happens inside, and
                // awaiting it here would let one slow peer hold up every other
                // connection. See `Server::accept`.
                tokio::spawn(async move {
                    let peer = incoming.remote_address();
                    match incoming.establish().await {
                        Err(e) => {
                            fabric.metrics().handshake_failed();
                            tracing::debug!(%peer, error = %e, "handshake failed");
                        }
                        Ok((session, negotiated)) => {
                            if let Err(e) =
                                Session::serve(session, negotiated.carrier, fabric).await
                            {
                                tracing::debug!(%peer, error = %e, "session ended badly");
                            }
                        }
                    }
                });
            }
        }
    }
}

/// Resolve once either signal arrives.
///
/// `SIGTERM` is what a container orchestrator sends, and ignoring it means every
/// deploy kills sessions that could have been drained. `SIGINT` is for a human
/// at a terminal.
async fn shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        // No SIGTERM handler means no graceful drain, but it does not mean the
        // relay should refuse to run — so wait forever on this arm instead.
        let Ok(mut term) = signal(SignalKind::terminate()) else {
            return std::future::pending().await;
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// How much history to retain, from the environment.
///
/// The per-track byte budget is derived rather than configured separately: one
/// track should not be able to fill the process on its own, and a quarter of the
/// total is a defensible share without adding a third knob nobody would tune.
fn cache_limits() -> Result<Limits, Box<dyn std::error::Error>> {
    let defaults = Limits::default();
    let groups = match env("MOQOM_RELAY_CACHE_GROUPS") {
        Some(value) => value
            .parse()
            .map_err(|e| format!("MOQOM_RELAY_CACHE_GROUPS is not a count: {e}"))?,
        None => defaults.groups_per_track,
    };
    let total = match env("MOQOM_RELAY_CACHE_MB") {
        Some(value) => {
            value
                .parse::<usize>()
                .map_err(|e| format!("MOQOM_RELAY_CACHE_MB is not a count: {e}"))?
                * 1024
                * 1024
        }
        None => defaults.bytes_total,
    };

    Ok(Limits {
        groups_per_track: groups,
        bytes_per_track: (total / 4).max(1),
        bytes_total: total,
    })
}

/// The limits every session is held to, from the environment.
///
/// On by default, which is the opposite of the library's default and the
/// difference is deliberate. `Fabric::default()` is what tests and embedders
/// build and it limits nothing, because a library that silently throttles
/// produces failures that look like bugs in the caller. This is the deployment,
/// and a defence that ships off is a defence nobody turns on.
fn governor() -> Result<Governor, Box<dyn std::error::Error>> {
    if env("MOQOM_RELAY_LIMITS").as_deref() == Some("off") {
        tracing::warn!("MOQOM_RELAY_LIMITS=off, so no per-user or per-device limits are enforced");
        return Ok(Governor::disabled());
    }

    let scale = match env("MOQOM_RELAY_LIMIT_SCALE") {
        Some(value) => value
            .parse::<f64>()
            .map_err(|e| format!("MOQOM_RELAY_LIMIT_SCALE is not a number: {e}"))?,
        None => 1.0,
    };
    if !scale.is_finite() || scale <= 0.0 {
        return Err("MOQOM_RELAY_LIMIT_SCALE must be a positive number".into());
    }

    let defaults = Quotas::default();
    let principals = match env("MOQOM_RELAY_MAX_PRINCIPALS") {
        Some(value) => value
            .parse()
            .map_err(|e| format!("MOQOM_RELAY_MAX_PRINCIPALS is not a count: {e}"))?,
        None => defaults.principals,
    };

    // One factor across all three tiers rather than a knob per resource. The
    // ratios between them are the design -- a user gets more than a device, an
    // address less -- and an operator who needs to move them all is usually
    // sizing for a bigger or smaller relay, not rebalancing them.
    let quotas = Quotas {
        device: defaults.device.scaled(scale),
        user: defaults.user.scaled(scale),
        address: defaults.address.scaled(scale),
        principals,
    };
    tracing::info!(
        scale,
        principals,
        "limiting requests per device, per user, and per address"
    );
    Ok(Governor::new(quotas))
}

/// How session credentials are checked, from the environment.
///
/// Off by default, and this one really is the safe choice rather than the
/// convenient one: with no keys there is no verified identity, so every session
/// lands on the address tier and is limited hard. Turning it on is what lets a
/// client earn the larger per-user and per-device allowances.
///
/// The failure worth avoiding is the middle position — reading the token and
/// believing it without a key — which would key every limit on a string the
/// peer chose.
fn authenticator() -> Result<Authenticator, Box<dyn std::error::Error>> {
    let Some(path) = env_path("MOQOM_RELAY_JWKS") else {
        tracing::warn!(
            "no MOQOM_RELAY_JWKS, so no session is authenticated and every one is \
             limited by address"
        );
        return Ok(Authenticator::disabled());
    };

    let document = std::fs::read_to_string(&path)
        .map_err(|e| format!("reading MOQOM_RELAY_JWKS {}: {e}", path.display()))?;
    let keys = VerificationKey::parse_set(&document)
        .map_err(|e| format!("MOQOM_RELAY_JWKS {}: {e}", path.display()))?;
    if keys.is_empty() {
        return Err(format!("MOQOM_RELAY_JWKS {} has no keys", path.display()).into());
    }

    // An unpinned issuer accepts a token minted by any deployment that happens
    // to share a key identifier, which is a real hazard when identifiers are
    // derived from the key and two environments restore the same secret.
    let issuer = env("MOQOM_RELAY_ISSUER").unwrap_or_default();
    if issuer.is_empty() {
        tracing::warn!("no MOQOM_RELAY_ISSUER, so tokens from any issuer are accepted");
    }
    tracing::info!(keys = keys.len(), %issuer, "verifying session credentials");
    Ok(Authenticator::new(issuer, keys))
}

fn env_path(key: &str) -> Option<PathBuf> {
    env(key).map(PathBuf::from)
}

fn tls_from_pem(
    cert: &PathBuf,
    key: &PathBuf,
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error>> {
    let certs = rustls_pemfile::certs(&mut io::BufReader::new(std::fs::File::open(cert)?))
        .collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut io::BufReader::new(std::fs::File::open(key)?))?
        .ok_or("no private key in the key file")?;

    Ok(rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?)
}

/// A certificate for `names`, and the hash a client pins it by.
///
/// The hash covers the whole DER certificate, which is what WebTransport's
/// `serverCertificateHashes` is defined against. Hashing the public key instead
/// produces a value of the right shape and the wrong content, and the symptom is
/// a handshake that fails with no indication of which side is wrong.
fn self_signed(
    names: &[String],
) -> Result<(rustls::ServerConfig, String), Box<dyn std::error::Error>> {
    let generated = rcgen::generate_simple_self_signed(names.to_vec())?;
    let der = generated.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::try_from(generated.signing_key.serialize_der())
        .map_err(|e| format!("generated key is unusable: {e}"))?;

    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, der.as_ref());
    let hash = base64::engine::general_purpose::STANDARD.encode(digest.as_ref());

    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![der], key)?;
    Ok((tls, hash))
}
