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
//!   Without one of the three settings below it is open, and an open admin port
//!   refuses to bind anything but a loopback address: the relay will not start.
//! - `MOQOM_RELAY_ADMIN_TOKEN_FILE` — a file holding the bearer token every
//!   admin path but `/healthz` and `/readyz` requires. At least 32 characters.
//! - `MOQOM_RELAY_ADMIN_CLIENT_CA` — a PEM of the operator authority. Set, the
//!   admin port speaks TLS and those same paths require a client certificate it
//!   issued. The port's own certificate is `MOQOM_RELAY_ADMIN_CERT` and
//!   `MOQOM_RELAY_ADMIN_KEY`, defaulting to the relay's. With the token as well,
//!   both are required.
//! - `MOQOM_RELAY_ADMIN_AUTH` — `probes-only` serves the two probes and refuses
//!   everything else, for a port that exists for a load balancer's health check.
//!   See [`moqom_relay::admin_auth`].
//! - `MOQOM_RELAY_ADMIN_LOCAL_ADDR` — a second admin listener, serving the
//!   whole surface with no authentication, on a loopback address only (any
//!   other refuses to start). For an `OpenZiti` tunneler beside the relay to host
//!   as a dark service, so the network-facing port can be `probes-only`. It
//!   shares state with the first: readiness and metrics are the same.
//! - `MOQOM_RELAY_TENANT` — serve this one tenant: every token issued for
//!   another is refused (`wrong_tenant`). For a relay a customer runs and
//!   enrolled for their tenant. Unset serves every tenant the keys verify.
//! - `MOQOM_RELAY_LIMITS` — `off` disables per-user and per-device limits
//!   entirely. On otherwise, which is the default.
//! - `MOQOM_RELAY_LIMIT_SCALE` — multiply every allowance by this. Default 1.
//! - `MOQOM_RELAY_MAX_PRINCIPALS` — how many identities each tier tracks before
//!   it refuses new ones. Default 100000. See [`moqom_relay::quota`].
//! - `MOQOM_RELAY_JWKS` — path to verification keys this relay must always
//!   accept. Usually unset: a relay attached to a control plane is sent the
//!   current keys over the link and follows every rotation, and a file is for
//!   the relay that has no control plane to be sent them by. Until either
//!   happens no session is authenticated and every one is charged to its
//!   address, which is a much smaller allowance.
//! - `MOQOM_RELAY_ISSUER` — the issuer tokens must name. Required whenever the
//!   relay can verify tokens (`MOQOM_RELAY_JWKS` or `MOQOM_CONTROL_ENDPOINT` is
//!   set): the relay will not start without it unless
//!   `MOQOM_RELAY_ALLOW_ANY_ISSUER=true`, which accepts any issuer and is for
//!   tests.
//! - `MOQOM_RELAY_POSSESSION` — whether a session must prove that the credential
//!   it presents is its own: `required` (the default), `observed` or `bearer`.
//!   Weaker modes log a warning at startup and on every session admitted
//!   without a proof. Without keys this decides nothing, since there is no token to be the
//!   owner of.
//! - `MOQOM_RELAY_UPSTREAM` — a parent relay, as `HOST:PORT`, to fetch tracks this
//!   one does not hold. Unset is a single-tier relay, which serves what its own
//!   publishers announce and refuses the rest. Set, this relay becomes an edge: a
//!   subscription for a namespace nobody here publishes is asked of the parent, and
//!   the audience for one track stops being bounded by one machine's network card.
//!   See [`crate::upstream`](moqom_relay::upstream).
//! - `MOQOM_RELAY_UPSTREAM_CA` — a PEM of certificate authorities to trust for that
//!   link, in addition to the public roots. What a fleet on internal names needs,
//!   since no public authority will certify them. Verification cannot be turned off.
//! - `MOQOM_RELAY_UPSTREAM_TOKEN` — this relay's own credential for that parent.
//!   Being a relay is not a way past a parent's door, so against a parent that
//!   verifies credentials an edge without this is anonymous and will not be able to
//!   read the tracks it exists to serve.
//! - `MOQOM_RELAY_UPSTREAM_KEY` — a PKCS#8 P-256 file holding the device key that
//!   token is bound to. Required with the token: every parent requires proof of
//!   possession, so this relay proves the token on each link, against the
//!   certificate the parent presented.
//! - `MOQOM_RELAY_LINK_URL` — the control plane's `/relay/link`, on its join
//!   listener. Set beside `MOQOM_RELAY_UPSTREAM`, this edge links to its parent
//!   once per room instead of once, each link on a short-lived credential minted
//!   for that room alone, bound to a key this process generates and proved to the
//!   parent like a client's, and renewed before it lapses. The request is
//!   authenticated with `MOQOM_CONTROL_CREDENTIAL`, which must be a relay
//!   service account's; `MOQOM_RELAY_UPSTREAM_TOKEN` is then unused. See
//!   [`crate::edge`](moqom_relay::edge).
//! - `MOQOM_RELAY_LINK_CA` — a PEM of authorities to trust for that URL as well
//!   as the public roots.
//! - `MOQOM_RELAY_MAX_HOP_LIMIT` — how many relays a subscription may be
//!   forwarded through, the hop-limit draft's `MAX_HOP_LIMIT`: the budget a
//!   request with none starts with and the most honoured on one that names more.
//!   Defaults to 3. See [`crate::hops`](moqom_relay::hops).
//! - `MOQOM_CONTROL_ENDPOINT` — the control plane's URL. Unset means no
//!   moderation reaches this relay: it enforces what tokens say and nothing
//!   else, which is the mode the benches run in and not one to expose.
//! - `MOQOM_CONTROL_CREDENTIAL` — the relay service account's bearer token.
//! - `MOQOM_CONTROL_CA`, `MOQOM_CONTROL_CLIENT_CERT`, `MOQOM_CONTROL_CLIENT_KEY`
//!   — the link's certificates, all three or none. The credential above proves
//!   this relay to the control plane; the authority proves the control plane to
//!   this relay, which is the direction that decides whose verification keys
//!   end up here. Unset is for a control plane on the same machine.
//! - `MOQOM_CONTROL_SERVER_NAME` — the name to verify that certificate against,
//!   defaulting to `moqom-control`. A name and not the address, because the
//!   address is a load balancer's and changes for reasons unrelated to identity.
//! - `MOQOM_RELAY_ID` — this relay's name to the control plane. Defaults to
//!   `HOSTNAME`, which in a managed instance group is the instance and is stable
//!   across its restarts.
//! - `MOQOM_RELAY_REGION` — where it is, for steering.
//! - `MOQOM_RELAY_USAGE_KEY_FILE` — a file holding this account's `mqk_` relay
//!   key. Set, the relay is self-hosted: it reports usage against the key's
//!   account, and stops admitting new sessions while the account says it is not
//!   admitting. Reread on every report, so the key can be rotated in place.
//! - `MOQOM_RELAY_USAGE_URL` — where usage goes. With a key file it defaults to
//!   `https://api.moqom.cloud/v1/usage`. Without one, setting it makes this a
//!   MOQOM-run relay that reports every tenant's usage with
//!   `MOQOM_CONTROL_CREDENTIAL`, which must belong to a relay operator account.
//!   Neither set means no usage is metered at all. A bare origin has
//!   `/v1/usage` appended.
//! - `MOQOM_RELAY_USAGE_INTERVAL` — seconds per usage record. Default 60.
//! - `MOQOM_RELAY_USAGE_QUEUE` — records held while the endpoint is unreachable
//!   before the oldest are dropped. Default 100000.
//! - `MOQOM_RELAY_USAGE_CA` — a PEM of extra authorities to trust for that URL.
//!   Usage records carry `MOQOM_RELAY_ID` in their ids, so two relays reporting
//!   to one account must not share one.
//! - `MOQOM_RELAY_TICKET_KEYS` — a file holding the fleet's direct-ticket keys,
//!   a JWK set where the first ML-DSA-65 key (`AKP`) with a private seed
//!   (`priv`) signs and every public half is published to participants,
//!   including Ed25519 (`OKP`) keys, which only verify older tickets. Unset issues no
//!   tickets, which keeps every participant on this relay off direct paths.
//!   Not the token keys: see `moqom_relay::ticket`.
//! - `MOQOM_RELAY_STUN_ADDR` — where to answer STUN Binding requests, so devices
//!   behind NATs learn the public address a direct path needs. Default
//!   `[::]:3478`, both families; `off` serves none. A default that cannot be
//!   bound, such as a second relay on one machine, is logged and skipped; an
//!   address given explicitly that cannot be bound stops the relay. See
//!   [`crate::stun`](moqom_relay::stun).
//! - `MOQOM_RELAY_STUN_RATE`, `MOQOM_RELAY_STUN_BURST` — answers per second
//!   each source address (each IPv6 /64) earns, and the most it may have at
//!   once. Default 20 and 40.
//!
//! # A caveat about the address tier
//!
//! Unauthenticated peers are limited by IP, and that is the address the relay
//! sees. Behind a load balancer that does not preserve the client address, that
//! is one address for everybody, so the address tier becomes a single global
//! limit and legitimate clients starve each other. Either preserve the client
//! address at the balancer, or attach this relay to a control plane — the keys
//! it sends are what let a session be identified by who it is rather than by
//! where it came from.
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
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine as _;
use moqom_relay::admin::Surface;
use moqom_relay::admin_auth::Guard;
use moqom_relay::fabric::Ticketing;
use moqom_relay::possession::{Enforcement, Possession};
use moqom_relay::ticket::TicketKeys;
use moqom_relay::usage::report::{Credential, Endpoint, Reporter};
use moqom_relay::usage::{Config as UsageConfig, Hosting};
use moqom_relay::{
    Authenticator, Cache, Fabric, Governor, Limits, Link, Metrics, Quotas, Session, Supervisor,
    Usage, VerificationKey,
};
use moqom_relay::{edge, stun, upstream};
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

#[allow(clippy::too_many_lines)] // the startup sequence, read top to bottom
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Installed once, before any TLS configuration is built. `rustls` will
    // otherwise refuse to pick a provider when more than one is compiled in.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let addr: SocketAddr = env("MOQOM_RELAY_ADDR")
        .unwrap_or_else(|| "[::]:4443".to_owned())
        .parse()?;

    let (tls, identity) = match (env_path("MOQOM_RELAY_CERT"), env_path("MOQOM_RELAY_KEY")) {
        (Some(cert), Some(key)) => tls_from_pem(&cert, &key)?,
        (None, None) => {
            let names: Vec<String> = env("MOQOM_RELAY_NAMES")
                .unwrap_or_else(|| "localhost".to_owned())
                .split(',')
                .map(str::to_owned)
                .collect();
            let (tls, hash, identity) = self_signed(&names)?;
            println!("certificate-hash: {hash}");
            (tls, identity)
        }
        _ => {
            return Err(
                "MOQOM_RELAY_CERT and MOQOM_RELAY_KEY must be set together or not at all".into(),
            );
        }
    };

    let dscp = egress_dscp()?;
    let shards = shards()?;
    let servers: Vec<Arc<Server>> = Server::bind_shards(addr, with_moqt_alpn(tls), dscp, shards)?
        .into_iter()
        .map(Arc::new)
        .collect();
    if let Some(dscp) = dscp {
        tracing::info!(dscp, "marking egress");
    }
    if shards.get() > 1 {
        tracing::info!(shards = shards.get(), "sharing the port across sockets");
    }
    let bound = servers
        .first()
        .ok_or("no listener was bound")?
        .local_addr()?;
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
    // Decided before the first accept, so a relay told to expose an unguarded
    // admin port to the network fails at startup with the reason, rather than
    // serving media with no way to see into it.
    let admin_guard = match admin_addr {
        Some(addr) => {
            let (guard, tls) = admin_guard()?;
            guard.permits_bind(addr)?;
            Some((addr, guard, tls))
        }
        None => None,
    };
    // The full surface again, unauthenticated, on loopback only -- for the
    // overlay tunneler beside the relay to host as a dark service, so the
    // network port can stay probes-only. Open is the only guard that makes
    // sense here and the guard itself refuses it anything but loopback.
    let admin_local = match env("MOQOM_RELAY_ADMIN_LOCAL_ADDR") {
        Some(value) => {
            let addr = value.parse::<SocketAddr>()?;
            Guard::open().permits_bind(addr)?;
            Some(addr)
        }
        None => None,
    };
    let metrics = if admin_addr.is_some() || admin_local.is_some() {
        Metrics::new()
    } else {
        tracing::info!("no MOQOM_RELAY_ADMIN_ADDR, so metrics are off");
        Metrics::disabled()
    };
    serve_stun(&metrics)?;

    let (usage, reporter) = usage()?;
    let fabric = ticketing(
        Fabric::observed(Cache::new(limits), metrics.clone())
            .governed(governor()?)
            .authenticated(authenticator()?)
            .proving(possession(identity)?)
            .metered(usage)
            .with_hop_limit(max_hop_limit()?),
    )?;
    // Held for the life of the process; dropping it detaches. Before the accept
    // loop so that a relay restarting into a room with a ban in force learns
    // about it in the same second rather than after somebody rejoins.
    let _link = control_link(&fabric);

    // An edge in a tier, if this relay was given a parent. Spawned rather than
    // awaited: an edge whose parent is not up yet should still serve the publishers
    // that connect to it directly, and the link retries in the background.
    if let Some(parent) = upstream()? {
        let dialer = upstream::Dialer::new(upstream_tls()?)?;
        if let Some(minter) = link_minter()? {
            tracing::info!(%parent, "linking upstream per room");
            let edge = edge::Edge::new(
                dialer,
                parent,
                fabric.clone(),
                minter,
                edge::Timing::default(),
            )?;
            tracing::info!(key = edge.thumbprint(), "room links are bound to this key");
            drop(edge.start());
        } else {
            tracing::info!(%parent, "attaching upstream");
            tokio::spawn(upstream::keep_attached(dialer, parent, fabric.clone()));
        }
    }

    let surface = Surface::new(metrics, fabric.clone());
    if let Some((addr, guard, tls)) = admin_guard {
        let serving = surface.clone();
        tokio::spawn(async move {
            if let Err(e) = serving.serve(addr, guard, tls).await {
                // Not fatal to the relay: losing the metrics endpoint is worth
                // reporting loudly and is not worth dropping live broadcasts
                // over.
                tracing::error!(%addr, error = %e, "admin listener failed");
            }
        });
    }
    if let Some(addr) = admin_local {
        let serving = surface.clone();
        tokio::spawn(async move {
            if let Err(e) = serving.serve(addr, Guard::open(), None).await {
                tracing::error!(%addr, error = %e, "local admin listener failed");
            }
        });
    }

    // One accept loop per listener. With a single shard this is the same single
    // loop as ever, one task removed from the signal handler.
    let mut listening = tokio::task::JoinSet::new();
    for server in &servers {
        listening.spawn(accept_on(Arc::clone(server), fabric.clone()));
    }

    tokio::select! {
        () = shutdown() => {
            tracing::info!("draining");
            // Readiness drops before the drain begins, so a load balancer stops
            // sending new connections while the existing ones finish. Doing it the
            // other way round refuses traffic it was still capable of serving.
            surface.draining();
            for server in &servers {
                server.shutdown().await;
            }
        }

        // Every listener stopping means the endpoints closed underneath the relay,
        // which is not something a signal caused and not something to wait on.
        () = async { while listening.join_next().await.is_some() {} } => {
            tracing::warn!("every listener stopped");
        }
    }
    // After the listeners, so the sessions they ended are in the last report.
    stop_reporting(reporter).await;
    Ok(())
}

/// Start answering STUN, unless `MOQOM_RELAY_STUN_ADDR` is `off`.
fn serve_stun(metrics: &Metrics) -> Result<(), Box<dyn std::error::Error>> {
    let given = env("MOQOM_RELAY_STUN_ADDR");
    if given.as_deref() == Some("off") {
        tracing::info!("MOQOM_RELAY_STUN_ADDR is off, so STUN is not answered");
        return Ok(());
    }
    let mut config = stun::Config::default();
    if let Some(value) = &given {
        config.listen = value
            .parse()
            .map_err(|e| format!("MOQOM_RELAY_STUN_ADDR is not an address or `off`: {e}"))?;
    }
    for (name, field) in [
        ("MOQOM_RELAY_STUN_RATE", &mut config.limits.rate),
        ("MOQOM_RELAY_STUN_BURST", &mut config.limits.burst),
    ] {
        if let Some(value) = env(name) {
            let parsed: f64 = value
                .parse()
                .map_err(|e| format!("{name} is not a number: {e}"))?;
            if !(parsed.is_finite() && parsed >= 1.0) {
                return Err(format!("{name} must be at least 1").into());
            }
            *field = parsed;
        }
    }
    match stun::Responder::bind(&config, metrics.clone()) {
        Ok(responder) => {
            let bound = responder.local_addr()?;
            tracing::info!(%bound, "answering STUN");
            tokio::spawn(async move {
                if let Err(error) = responder.serve().await {
                    tracing::error!(%bound, %error, "STUN responder stopped");
                }
            });
            Ok(())
        }
        Err(error) if given.is_none() => {
            tracing::warn!(listen = %config.listen, %error, "STUN not answered: the default port could not be bound");
            Ok(())
        }
        Err(error) => Err(format!("MOQOM_RELAY_STUN_ADDR {}: {error}", config.listen).into()),
    }
}

/// Deliver what usage is still held, within a bound: an orchestrator's grace
/// period is bounded too, and the records that do not make it are counted and
/// logged rather than waited on.
async fn stop_reporting(reporter: Option<Reporter>) {
    if let Some(reporter) = reporter {
        reporter.shutdown(std::time::Duration::from_secs(10)).await;
    }
}

/// The fabric, issuing direct tickets if `MOQOM_RELAY_TICKET_KEYS` names keys.
///
/// # Errors
/// If the file is unreadable or holds no key to sign with: a relay told to
/// issue tickets and unable to would leave every direct path failing its
/// peer's check, which is better found at startup.
fn ticketing(fabric: Fabric) -> Result<Fabric, Box<dyn std::error::Error>> {
    let Some(path) = env_path("MOQOM_RELAY_TICKET_KEYS") else {
        tracing::info!("no MOQOM_RELAY_TICKET_KEYS, so no direct tickets are issued");
        return Ok(fabric);
    };
    let document = std::fs::read_to_string(&path)
        .map_err(|e| format!("MOQOM_RELAY_TICKET_KEYS {}: {e}", path.display()))?;
    let keys = TicketKeys::parse(&document)
        .map_err(|e| format!("MOQOM_RELAY_TICKET_KEYS {}: {e}", path.display()))?;
    tracing::info!(?keys, "issuing direct tickets");
    Ok(fabric.ticketing(Ticketing {
        keys: Arc::new(keys),
        renew: moqom_relay::ticket::RENEW,
    }))
}

/// The usage meter, and the reporter sending it, from the environment.
///
/// # Errors
/// If a value does not parse, the URL is not one, or the authority file is
/// unreadable. Usage a deployment asked for and cannot report is a billing
/// failure to fix before serving, not one to discover on the invoice.
fn usage() -> Result<(Usage, Option<Reporter>), Box<dyn std::error::Error>> {
    let key = env_path("MOQOM_RELAY_USAGE_KEY_FILE");
    let url = env("MOQOM_RELAY_USAGE_URL");
    let (hosting, url, credential) = match (key, url) {
        (Some(key), url) => (
            Hosting::SelfHosted,
            url.unwrap_or_else(|| "https://api.moqom.cloud/v1/usage".to_owned()),
            Credential::File(key),
        ),
        (None, Some(url)) => {
            let credential = env("MOQOM_CONTROL_CREDENTIAL").unwrap_or_default();
            if credential.is_empty() {
                tracing::warn!(
                    "MOQOM_RELAY_USAGE_URL is set with no MOQOM_CONTROL_CREDENTIAL; \
                     usage will be held and retried until one is configured"
                );
            }
            (Hosting::Cloud, url, Credential::Value(credential))
        }
        (None, None) => {
            tracing::info!(
                "no MOQOM_RELAY_USAGE_URL or MOQOM_RELAY_USAGE_KEY_FILE, so usage is not metered"
            );
            return Ok((Usage::disabled(), None));
        }
    };

    let relay_id = env("MOQOM_RELAY_ID")
        .or_else(|| env("HOSTNAME"))
        .unwrap_or_else(|| "relay".to_owned());
    let mut config = UsageConfig::new(relay_id, hosting);
    if let Some(value) = env("MOQOM_RELAY_USAGE_INTERVAL") {
        let seconds: u64 = value
            .parse()
            .map_err(|e| format!("MOQOM_RELAY_USAGE_INTERVAL is not a number of seconds: {e}"))?;
        if seconds == 0 {
            return Err("MOQOM_RELAY_USAGE_INTERVAL must be at least 1".into());
        }
        config.interval = std::time::Duration::from_secs(seconds);
    }
    if let Some(value) = env("MOQOM_RELAY_USAGE_QUEUE") {
        config.capacity = value
            .parse::<NonZeroUsize>()
            .map_err(|e| format!("MOQOM_RELAY_USAGE_QUEUE must be a positive count: {e}"))?
            .get();
    }

    let mut endpoint = Endpoint::new(&url, credential)?;
    if let Some(ca) = env_path("MOQOM_RELAY_USAGE_CA") {
        let pem = std::fs::read(&ca)
            .map_err(|e| format!("MOQOM_RELAY_USAGE_CA {}: {e}", ca.display()))?;
        endpoint = endpoint.trusting(&pem)?;
    }
    tracing::info!(
        url = endpoint.url(),
        relay = %config.relay_id,
        hosting = ?config.hosting,
        interval = config.interval.as_secs(),
        "metering usage"
    );
    let usage = Usage::new(config);
    let reporter = usage.report_to(endpoint);
    Ok((usage, reporter))
}

/// Accept connections on one listener until it closes.
async fn accept_on(server: Arc<Server>, fabric: Fabric) {
    while let Some(incoming) = server.accept().await {
        let fabric = fabric.clone();
        // Spawned rather than awaited: the handshake happens inside, and awaiting
        // it here would let one slow peer hold up every other connection. See
        // `Server::accept`.
        tokio::spawn(async move {
            let peer = incoming.remote_address();
            match incoming.establish().await {
                Err(e) => {
                    fabric.metrics().handshake_failed();
                    tracing::debug!(%peer, error = %e, "handshake failed");
                }
                Ok((session, negotiated)) => {
                    if let Err(e) = Session::serve(session, negotiated.carrier, fabric).await {
                        tracing::debug!(%peer, error = %e, "session ended badly");
                    }
                }
            }
        });
    }
}

/// How many sockets share the listening port.
///
/// One by default, which is the ordinary single-socket listener. More than one
/// divides packet handling across cores, and carries a caveat about clients that
/// change address mid-connection -- see [`Server::bind_shards`], and do not raise
/// this in front of mobile clients on the strength of a throughput number alone.
fn shards() -> Result<NonZeroUsize, Box<dyn std::error::Error>> {
    let Some(value) = env("MOQOM_RELAY_SHARDS") else {
        return Ok(NonZeroUsize::MIN);
    };
    match value.trim() {
        // Named rather than only numeric, because the useful number is a property
        // of the machine and a deployment should not have to restate it per size.
        "auto" => Ok(std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN)),
        digits => Ok(digits
            .parse::<NonZeroUsize>()
            .map_err(|e| format!("MOQOM_RELAY_SHARDS must be a positive number or auto: {e}"))?),
    }
}

/// Attach to the control plane, if this deployment has one.
///
/// Without one the relay still runs, and says so loudly: it enforces what tokens
/// claim and no moderation at all, which is right for a bench on a laptop and
/// wrong for anything with users on it.
fn control_link(fabric: &Fabric) -> Option<Link> {
    let Some(supervisor) = Supervisor::from_env() else {
        tracing::warn!("no MOQOM_CONTROL_ENDPOINT: this relay enforces tokens and no moderation");
        return None;
    };
    tracing::info!(
        endpoint = %supervisor.endpoint,
        relay = %supervisor.relay_id,
        region = %supervisor.region,
        "attaching to the control plane"
    );
    Some(Link::attach(supervisor, fabric.clone()))
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

/// Where per-room link credentials come from, if this edge links per room.
///
/// # Errors
/// A URL that is not one, no credential to ask with, or an unreadable CA.
fn link_minter() -> Result<Option<edge::ControlPlane>, Box<dyn std::error::Error>> {
    let Some(url) = env("MOQOM_RELAY_LINK_URL") else {
        return Ok(None);
    };
    let credential = env("MOQOM_CONTROL_CREDENTIAL")
        .ok_or("MOQOM_RELAY_LINK_URL needs MOQOM_CONTROL_CREDENTIAL to ask with")?;
    let minter = edge::ControlPlane::new(&url, Credential::Value(credential))?;
    Ok(Some(match env_path("MOQOM_RELAY_LINK_CA") {
        Some(path) => {
            let pem = std::fs::read(&path)
                .map_err(|e| format!("reading MOQOM_RELAY_LINK_CA {}: {e}", path.display()))?;
            minter.trusting(&pem)?
        }
        None => minter,
    }))
}

/// `MAX_HOP_LIMIT`, from the environment.
///
/// # Errors
/// If the value is not a number.
fn max_hop_limit() -> Result<u64, Box<dyn std::error::Error>> {
    let Some(value) = env("MOQOM_RELAY_MAX_HOP_LIMIT") else {
        return Ok(moqom_relay::hops::BUDGET);
    };
    Ok(value
        .parse()
        .map_err(|e| format!("MOQOM_RELAY_MAX_HOP_LIMIT is not a number: {e}"))?)
}

/// What class of service to ask the network for, from the environment.
///
/// Off unless asked for. A codepoint the path ignores is harmless, but one the path honours and
/// that names the wrong class is not — a flow marked as background gets treated as background —
/// so this is a deployment's decision rather than a default. AF41, 34, is the usual choice for
/// interactive video and is what a home access point maps to its video queue.
///
/// # Errors
/// If the value is not a number, or does not fit in the six bits a codepoint has.
fn egress_dscp() -> Result<Option<u8>, Box<dyn std::error::Error>> {
    let Some(value) = env("MOQOM_RELAY_DSCP") else {
        return Ok(None);
    };

    let dscp: u8 = value
        .parse()
        .map_err(|e| format!("MOQOM_RELAY_DSCP is not a codepoint: {e}"))?;
    if dscp > 63 {
        return Err("MOQOM_RELAY_DSCP is six bits, so 0 to 63".into());
    }
    Ok(Some(dscp))
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

    let age = match env("MOQOM_RELAY_CACHE_SECONDS") {
        Some(value) => std::time::Duration::from_secs(
            value
                .parse()
                .map_err(|e| format!("MOQOM_RELAY_CACHE_SECONDS is not a count: {e}"))?,
        ),
        None => defaults.max_age,
    };

    Ok(Limits {
        groups_per_track: groups,
        bytes_per_track: (total / 4).max(1),
        bytes_total: total,
        max_age: age,
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
    // An unpinned issuer accepts a token minted by any deployment that happens
    // to share a key identifier, which is a real hazard when identifiers are
    // derived from the key and two environments restore the same secret.
    //
    // So a relay that will verify anything -- keys from a file, or keys a
    // control plane will send -- refuses to start without one unless told to.
    // A relay with neither authenticates nobody and has no issuer to pin.
    let issuer = env("MOQOM_RELAY_ISSUER").unwrap_or_default();
    if issuer.is_empty() {
        let verifies =
            env_path("MOQOM_RELAY_JWKS").is_some() || env("MOQOM_CONTROL_ENDPOINT").is_some();
        let allowed = matches!(
            env("MOQOM_RELAY_ALLOW_ANY_ISSUER")
                .as_deref()
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("1" | "true" | "yes")
        );
        if verifies && !allowed {
            return Err(
                "MOQOM_RELAY_ISSUER is unset; a relay that verifies tokens pins their \
                        issuer by default. Set it, or set MOQOM_RELAY_ALLOW_ANY_ISSUER=true"
                    .into(),
            );
        }
        tracing::warn!("no MOQOM_RELAY_ISSUER, so tokens from any issuer are accepted");
    }

    let Some(path) = env_path("MOQOM_RELAY_JWKS") else {
        // Not the end of the matter, and this is the ordinary case rather than
        // a degraded one: a relay attached to a control plane is sent the keys
        // over the link and starts verifying when they arrive. What this says
        // is what is true until then, which for a relay with no control plane
        // is forever.
        tracing::warn!(
            "no MOQOM_RELAY_JWKS; until the control plane sends keys, no session is \
             authenticated and every one is limited by address"
        );
        return Ok(pinned(issuer, Vec::new()));
    };

    let document = std::fs::read_to_string(&path)
        .map_err(|e| format!("reading MOQOM_RELAY_JWKS {}: {e}", path.display()))?;
    let keys = VerificationKey::parse_set(&document)
        .map_err(|e| format!("MOQOM_RELAY_JWKS {}: {e}", path.display()))?;
    if keys.is_empty() {
        return Err(format!("MOQOM_RELAY_JWKS {} has no keys", path.display()).into());
    }

    tracing::info!(keys = keys.len(), %issuer, "verifying session credentials");
    Ok(pinned(issuer, keys))
}

/// An authenticator for `issuer`, pinned to `MOQOM_RELAY_TENANT` when that is
/// set: a customer's own relay, which serves their tenant and nobody else's.
fn pinned(issuer: String, keys: Vec<VerificationKey>) -> Authenticator {
    match env("MOQOM_RELAY_TENANT").filter(|tenant| !tenant.is_empty()) {
        Some(tenant) => {
            tracing::info!(%tenant, "serving one tenant only");
            Authenticator::for_tenant(issuer, tenant, keys)
        }
        None => Authenticator::new(issuer, keys),
    }
}

/// The parent relay this one fetches tracks from, if it has been given one.
///
/// A relay with no parent is the ordinary single-tier case and is unaffected by any
/// of this: it serves what its own publishers announce and refuses the rest, exactly
/// as it did before parents existed.
fn upstream() -> Result<Option<upstream::Parent>, Box<dyn std::error::Error>> {
    let Some(target) = env("MOQOM_RELAY_UPSTREAM") else {
        return Ok(None);
    };

    // Split rather than resolved. The name is what the parent's certificate attests
    // to, so verifying against an address would accept any host that answers on it,
    // which is the whole attack certificate verification exists to stop -- and the
    // address is looked up per attempt rather than here, so a parent that moves is
    // followed instead of dialled forever at the address it had at startup.
    let (host, port) = target
        .rsplit_once(':')
        .ok_or("MOQOM_RELAY_UPSTREAM needs a port, as HOST:PORT")?;
    let port: u16 = port
        .parse()
        .map_err(|e| format!("MOQOM_RELAY_UPSTREAM {target} has no usable port: {e}"))?;
    let host = host.trim_matches(['[', ']']).to_owned();

    let token = env("MOQOM_RELAY_UPSTREAM_TOKEN");
    let key = match env_path("MOQOM_RELAY_UPSTREAM_KEY") {
        Some(path) => {
            let pkcs8 = std::fs::read(&path)
                .map_err(|e| format!("reading MOQOM_RELAY_UPSTREAM_KEY {}: {e}", path.display()))?;
            let key = moqom_client::device::DeviceKey::from_pkcs8(&pkcs8)
                .map_err(|e| format!("MOQOM_RELAY_UPSTREAM_KEY {}: {e}", path.display()))?;
            Some(std::sync::Arc::new(key))
        }
        None => None,
    };
    let credential = match (token, key) {
        (Some(token), Some(key)) => Some(upstream::Credential { token, key }),
        (Some(_), None) => {
            return Err(
                "MOQOM_RELAY_UPSTREAM_TOKEN needs MOQOM_RELAY_UPSTREAM_KEY: \
                        a parent refuses a token its holder cannot prove"
                    .into(),
            );
        }
        (None, Some(_)) => {
            return Err(
                "MOQOM_RELAY_UPSTREAM_KEY is set without MOQOM_RELAY_UPSTREAM_TOKEN".into(),
            );
        }
        (None, None) => None,
    };
    if credential.is_none() {
        // Worth a line rather than silence: against a parent that verifies
        // credentials this relay is anonymous, and an anonymous edge can read only
        // what an anonymous client could, so the tracks it is there to serve will
        // not resolve and the symptom appears at the viewer.
        tracing::warn!("no MOQOM_RELAY_UPSTREAM_TOKEN, so this relay is anonymous to its parent");
    }

    Ok(Some(upstream::Parent {
        server_name: host.clone(),
        host,
        port,
        credential,
    }))
}

/// How to verify a parent relay's certificate.
///
/// The well-known roots, plus a private authority when one is configured, and no way
/// to turn verification off. A relay-to-relay link carries every track in the fleet,
/// so an unverified one is an interior tier that anybody able to answer on an address
/// can impersonate — and a flag to skip it would end up set in production by somebody
/// debugging a name that did not resolve.
///
/// The private authority is not a loophole in that, it is what a fleet actually needs:
/// relays inside a VPC are reached by internal names that no public authority will
/// certify, so without this the only way to run a tier would be to weaken it. The
/// control-plane link takes `MOQOM_CONTROL_CA` for the same reason.
fn upstream_tls() -> Result<rustls::ClientConfig, Box<dyn std::error::Error>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if let Some(path) = env_path("MOQOM_RELAY_UPSTREAM_CA") {
        let pem = std::fs::read(&path)
            .map_err(|e| format!("reading MOQOM_RELAY_UPSTREAM_CA {}: {e}", path.display()))?;
        let mut added = 0;
        for certificate in rustls_pemfile::certs(&mut pem.as_slice()) {
            let certificate = certificate
                .map_err(|e| format!("MOQOM_RELAY_UPSTREAM_CA {}: {e}", path.display()))?;
            roots
                .add(certificate)
                .map_err(|e| format!("MOQOM_RELAY_UPSTREAM_CA {}: {e}", path.display()))?;
            added += 1;
        }
        // An empty or wrong-format file would otherwise leave verification quietly
        // resting on the public roots, and the failure would appear later as a
        // handshake error naming the parent rather than the file.
        if added == 0 {
            return Err(format!(
                "MOQOM_RELAY_UPSTREAM_CA {} contains no certificates",
                path.display()
            )
            .into());
        }
        tracing::info!(authorities = added, path = %path.display(), "trusting a private authority for the upstream link");
    }

    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![moqom_transport::alpn::MOQT_DRAFT_19.to_vec()];
    Ok(tls)
}

fn env_path(key: &str) -> Option<PathBuf> {
    env(key).map(PathBuf::from)
}

/// The admin port's TLS, when it has any.
type AdminTls = Arc<rustls::ServerConfig>;

/// Who may read the admin port, from the environment.
///
/// Files rather than values for every secret, as with the rest of the relay's
/// credentials: a process's environment is readable by more things than its
/// files are.
fn admin_guard() -> Result<(Guard, Option<AdminTls>), Box<dyn std::error::Error>> {
    let probes_only = match env("MOQOM_RELAY_ADMIN_AUTH").as_deref() {
        None => false,
        Some("probes-only") => true,
        Some(other) => {
            return Err(format!(
                "MOQOM_RELAY_ADMIN_AUTH must be probes-only or unset, not {other:?}"
            )
            .into());
        }
    };
    let token = env_path("MOQOM_RELAY_ADMIN_TOKEN_FILE");
    let client_ca = env_path("MOQOM_RELAY_ADMIN_CLIENT_CA");

    let mut guard = if probes_only {
        Guard::probes_only()
    } else {
        Guard::open()
    };
    if let Some(path) = &token {
        let secret = std::fs::read_to_string(path).map_err(|e| {
            format!(
                "reading MOQOM_RELAY_ADMIN_TOKEN_FILE {}: {e}",
                path.display()
            )
        })?;
        guard = guard
            .with_bearer(&secret)
            .map_err(|e| format!("MOQOM_RELAY_ADMIN_TOKEN_FILE {}: {e}", path.display()))?;
    }

    let mut tls = None;
    if let Some(ca) = &client_ca {
        guard = guard.with_client_certificates()?;
        let cert = env_path("MOQOM_RELAY_ADMIN_CERT").or_else(|| env_path("MOQOM_RELAY_CERT"));
        let key = env_path("MOQOM_RELAY_ADMIN_KEY").or_else(|| env_path("MOQOM_RELAY_KEY"));
        let (Some(cert), Some(key)) = (cert, key) else {
            return Err("MOQOM_RELAY_ADMIN_CLIENT_CA needs a certificate for the admin port: \
                        MOQOM_RELAY_ADMIN_CERT and MOQOM_RELAY_ADMIN_KEY, or MOQOM_RELAY_CERT and MOQOM_RELAY_KEY"
                .into());
        };
        let read = |path: &PathBuf| {
            std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))
        };
        tls = Some(moqom_relay::admin_auth::tls_config(
            &read(&cert)?,
            &read(&key)?,
            &read(ca)?,
        )?);
    }

    if token.is_some() && tls.is_none() {
        // Worth saying, not worth refusing: on a VPC the alternative to a token
        // in the clear is usually no token at all.
        tracing::warn!(
            "the admin token travels in plaintext; set MOQOM_RELAY_ADMIN_CLIENT_CA for TLS"
        );
    }
    Ok((guard, tls))
}

/// How strictly this relay holds a session to proving its credential is its own:
/// always. A token is bound to the device key it names, and a session that
/// cannot prove it holds that key is refused. `MOQOM_RELAY_POSSESSION` may be
/// unset or `required`; the removed `bearer` and `observed` stop the relay at
/// startup rather than being quietly upgraded.
fn possession(certificate: String) -> Result<Possession, Box<dyn std::error::Error>> {
    let mode = match env("MOQOM_RELAY_POSSESSION") {
        Some(name) => {
            Enforcement::parse(&name).map_err(|e| format!("MOQOM_RELAY_POSSESSION: {e}"))?
        }
        None => Enforcement::default(),
    };
    tracing::info!("sessions must prove they hold the key their token names");
    Ok(Possession::new(mode, Some(certificate)))
}

fn tls_from_pem(
    cert: &PathBuf,
    key: &PathBuf,
) -> Result<(rustls::ServerConfig, String), Box<dyn std::error::Error>> {
    let certs = rustls_pemfile::certs(&mut io::BufReader::new(std::fs::File::open(cert)?))
        .collect::<Result<Vec<_>, _>>()?;
    let leaf = certs.first().ok_or("no certificate in the cert file")?;
    let identity = certificate_identity(leaf);
    let key = rustls_pemfile::private_key(&mut io::BufReader::new(std::fs::File::open(key)?))?
        .ok_or("no private key in the key file")?;

    Ok((
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?,
        identity,
    ))
}

/// A certificate for `names`, and the hash a client pins it by.
///
/// The hash covers the whole DER certificate, which is what WebTransport's
/// `serverCertificateHashes` is defined against. Hashing the public key instead
/// produces a value of the right shape and the wrong content, and the symptom is
/// a handshake that fails with no indication of which side is wrong.
fn self_signed(
    names: &[String],
) -> Result<(rustls::ServerConfig, String, String), Box<dyn std::error::Error>> {
    let generated = rcgen::generate_simple_self_signed(names.to_vec())?;
    let der = generated.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::try_from(generated.signing_key.serialize_der())
        .map_err(|e| format!("generated key is unusable: {e}"))?;

    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, der.as_ref());
    let hash = base64::engine::general_purpose::STANDARD.encode(digest.as_ref());
    let identity = certificate_identity(&der);

    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![der], key)?;
    Ok((tls, hash, identity))
}

/// What a proof of possession names this relay by.
///
/// The same digest of the same bytes as the pinning hash above, in base64url with
/// no padding rather than standard base64 — the spelling every other identifier in
/// a token or a proof uses, and the reason the two lines differ. Which is worth
/// saying out loud, because a value that looks like the one printed at startup but
/// is not it invites somebody to paste the wrong one.
///
/// Nobody should have to: both sides compute this from the certificate itself
/// rather than from configuration. A client takes the DER from the TLS handshake,
/// whether or not it was pinning anything, so a relay given a certificate by a
/// real authority is named here exactly as reliably as a self-signed one.
fn certificate_identity(der: &rustls::pki_types::CertificateDer<'_>) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, der.as_ref());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref())
}
