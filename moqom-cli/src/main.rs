//! The `moqom` CLI: subscribe to a track, or publish bytes onto one.
//!
//! Uses only [`moqom_client`]'s public API. A privileged path here would make
//! that API second-class; if a flag cannot be implemented through it, the
//! flag does not belong here yet.

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use moqom_client::{FullTrackName, Session, TrackNamespace};
use tokio::io::{AsyncBufReadExt, BufReader};

/// Speak MOQT as a subscriber or a publisher.
#[derive(Parser)]
#[command(
    name = "moqom",
    about = "Subscribe to a MOQT track, or publish bytes onto one"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print each object on a track.
    Subscribe(Common),
    /// Read stdin and publish each line as an object on successive groups.
    Publish(Common),
}

#[derive(clap::Args)]
struct Common {
    /// Relay address, `HOST:PORT`.
    #[arg(long)]
    relay: String,
    /// Track namespace, fields separated by `/`.
    #[arg(long)]
    namespace: String,
    /// Track name within that namespace.
    #[arg(long)]
    name: String,
    /// Path to a session token, sent as `AUTHORIZATION_TOKEN`.
    #[arg(long)]
    token: Option<PathBuf>,
    /// Skip certificate verification. For a self-signed development relay.
    #[arg(long)]
    insecure: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(error) = run().await {
        eprintln!("{error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Subscribe(common) => subscribe(common).await,
        Command::Publish(common) => publish(common).await,
    }
}

async fn subscribe(common: Common) -> Result<(), Box<dyn std::error::Error>> {
    let (mut session, track) = connect(&common).await?;
    let mut subscription = session.subscribe(track).await?;
    while let Some(object) = subscription.next_object().await? {
        print_object(&object);
    }
    Ok(())
}

async fn publish(common: Common) -> Result<(), Box<dyn std::error::Error>> {
    let (mut session, _track) = connect(&common).await?;
    let namespace = namespace(&common.namespace)?;
    let announcement = session.announce(namespace).await?;
    eprintln!("announced; waiting for a subscriber");
    announcement.subscribed().await;

    let alias = announcement.alias();
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut group = 0u64;
    while let Some(line) = lines.next_line().await? {
        session
            .publish_group(alias, group, &[line.as_bytes()])
            .await?;
        group = group.checked_add(1).ok_or("group id overflow")?;
    }
    Ok(())
}

async fn connect(common: &Common) -> Result<(Session, FullTrackName), Box<dyn std::error::Error>> {
    let (server_name, addr) = resolve(&common.relay)?;
    let tls = if common.insecure {
        moqom_client::tls::insecure()
    } else {
        moqom_client::tls::native()
    };
    let token = match &common.token {
        Some(path) => Some(std::fs::read(path)?),
        None => None,
    };
    let session = Session::connect(addr, &server_name, tls, token.as_deref()).await?;
    let track = FullTrackName::new(
        namespace(&common.namespace)?,
        common.name.as_bytes().to_vec().into(),
    )?;
    Ok((session, track))
}

fn namespace(spec: &str) -> Result<TrackNamespace, moqom_client::NameError> {
    TrackNamespace::from_parts(spec.split('/').filter(|field| !field.is_empty()))
}

fn resolve(relay: &str) -> Result<(String, SocketAddr), Box<dyn std::error::Error>> {
    let host = host_of(relay).to_owned();
    let addr = relay
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| format!("could not resolve {relay}"))?;
    Ok((host, addr))
}

fn host_of(relay: &str) -> &str {
    if let Some(rest) = relay.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(relay);
    }
    relay.rsplit_once(':').map_or(relay, |(host, _)| host)
}

fn print_object(object: &moqom_client::Object) {
    let bytes = object.payload.len();
    if bytes <= 32 {
        eprintln!(
            "group={} object={} bytes={bytes} {}",
            object.group,
            object.object,
            Hex(&object.payload)
        );
    } else {
        eprintln!(
            "group={} object={} bytes={bytes}",
            object.group, object.object
        );
    }
}

struct Hex<'a>(&'a [u8]);

impl std::fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
