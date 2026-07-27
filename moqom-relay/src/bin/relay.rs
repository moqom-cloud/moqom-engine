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
use moqom_relay::{Fabric, Session};
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

    let fabric = Fabric::new();
    loop {
        tokio::select! {
            () = shutdown() => {
                tracing::info!("draining");
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
                        Err(e) => tracing::debug!(%peer, error = %e, "handshake failed"),
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
