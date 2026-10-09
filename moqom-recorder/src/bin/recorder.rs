//! `moqom-recorder`: record a room, run as a pool worker, or read an archive.

use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use clap::{Args, Parser, Subcommand};
use moqom_client::DeviceKey;
use moqom_recorder::archive::{Reader, Record};
use moqom_recorder::store::{self, Store};
use moqom_recorder::{Recorder, RecorderConfig, link};
use tokio::sync::watch;

/// A hosted MOQT recorder.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Record one room until interrupted.
    Record(RecordArgs),
    /// Claim recordings from the control plane and record them.
    Worker(WorkerArgs),
    /// Print an archive's records.
    Inspect {
        /// The `.mqa` file.
        file: PathBuf,
        /// Print every object, not only the summary.
        #[arg(long)]
        objects: bool,
    },
    /// Print the JWK thumbprint of a recorder key, which the control plane is
    /// configured with as `MOQOM_RECORDER_THUMBPRINT`.
    Thumbprint {
        /// The key, PKCS#8, PEM or DER.
        key: PathBuf,
        /// Generate a new key at that path first. Refuses to overwrite one.
        #[arg(long)]
        generate: bool,
    },
}

#[derive(Args)]
struct RelayArgs {
    /// The relay, as host:port.
    #[arg(long, env = "MOQOM_RELAY")]
    relay: String,
    /// The name the relay's certificate is verified against. Defaults to the
    /// host part of --relay.
    #[arg(long, env = "MOQOM_RELAY_NAME")]
    relay_name: Option<String>,
    /// Pin the relay to this certificate (PEM) instead of the system roots.
    #[arg(long, env = "MOQOM_RELAY_CERT")]
    relay_cert: Option<PathBuf>,
    /// Skip verifying the relay. Development only: the proof the recorder makes
    /// is still bound to whatever certificate the relay presented.
    #[arg(long)]
    insecure: bool,
    /// The recorder's ML-DSA-87 key, PKCS#8, PEM or DER.
    #[arg(long, env = "MOQOM_RECORDER_KEY")]
    key: PathBuf,
    /// The local spool.
    #[arg(
        long,
        env = "MOQOM_RECORDER_SPOOL",
        default_value = "/var/spool/moqom-recorder"
    )]
    spool: PathBuf,
    /// Rotate files at the next group boundary past this many MiB.
    #[arg(long, env = "MOQOM_RECORDER_SEGMENT_MIB", default_value_t = 256)]
    segment_mib: u64,
}

#[derive(Args)]
struct RecordArgs {
    #[command(flatten)]
    relay: RelayArgs,
    /// The tenant.
    #[arg(long)]
    tenant: String,
    /// The room.
    #[arg(long)]
    room: String,
    /// A name for this recording, used in file headers and names.
    #[arg(long, default_value = "local")]
    recording: String,
    /// A file holding the relay token, reread every minute so a script can
    /// keep it fresh.
    #[arg(long)]
    token_file: PathBuf,
    /// Write files here.
    #[arg(long, conflicts_with = "gcs_bucket")]
    out: Option<PathBuf>,
    /// Or to this bucket.
    #[arg(long)]
    gcs_bucket: Option<String>,
    /// The object prefix, in a directory or a bucket.
    #[arg(long, default_value = "")]
    prefix: String,
    /// The GCS endpoint, for an emulator.
    #[arg(
        long,
        env = "MOQOM_GCS_ENDPOINT",
        default_value = "https://storage.googleapis.com"
    )]
    gcs_endpoint: String,
    /// Write CMAF where the room is not end-to-end encrypted.
    #[arg(long)]
    cmaf: bool,
    /// The room requires end-to-end encryption.
    #[arg(long)]
    e2ee_required: bool,
    /// Stop after this many seconds.
    #[arg(long)]
    seconds: Option<u64>,
}

#[derive(Args)]
struct WorkerArgs {
    #[command(flatten)]
    relay: RelayArgs,
    /// The control plane's gRPC endpoint.
    #[arg(long, env = "MOQOM_CONTROL")]
    control: String,
    /// A CA bundle (PEM) for the control plane.
    #[arg(long, env = "MOQOM_CONTROL_CA")]
    control_ca: Option<PathBuf>,
    /// A client certificate (PEM) for the control plane's mutual TLS.
    #[arg(long, env = "MOQOM_CONTROL_TLS_CERT", requires = "control_key")]
    control_cert: Option<PathBuf>,
    /// The client certificate's private key (PEM).
    #[arg(long, env = "MOQOM_CONTROL_TLS_KEY", requires = "control_cert")]
    control_key: Option<PathBuf>,
    /// The name on the control plane's certificate, if not the endpoint's host.
    #[arg(long, env = "MOQOM_CONTROL_SERVER_NAME")]
    control_server_name: Option<String>,
    /// A file holding the service-account credential.
    #[arg(long, env = "MOQOM_CONTROL_CREDENTIAL_FILE")]
    credential_file: PathBuf,
    /// Stable for this process; defaults to the host name.
    #[arg(long, env = "MOQOM_WORKER_ID")]
    worker_id: Option<String>,
    /// The GCS endpoint.
    #[arg(
        long,
        env = "MOQOM_GCS_ENDPOINT",
        default_value = "https://storage.googleapis.com"
    )]
    gcs_endpoint: String,
    /// Store into this directory instead of each assignment's bucket.
    #[arg(long)]
    local_store: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "moqom_recorder=info".into()),
        )
        .init();
    // Before any TLS configuration is built. tonic's gRPC client takes the
    // installed provider and otherwise falls back to ring, which has no
    // post-quantum key exchange; aws-lc-rs sends X25519MLKEM768 first.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let result = match Cli::parse().command {
        Command::Record(args) => record(args).await,
        Command::Worker(args) => worker(args).await,
        Command::Inspect { file, objects } => inspect(&file, objects),
        Command::Thumbprint { key, generate } => thumbprint(&key, generate),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("moqom-recorder: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn read_key(path: &Path) -> Result<DeviceKey, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let der = if bytes.starts_with(b"-----BEGIN") {
        match rustls_pemfile::private_key(&mut bytes.as_slice()) {
            Ok(Some(rustls::pki_types::PrivateKeyDer::Pkcs8(key))) => {
                key.secret_pkcs8_der().to_vec()
            }
            Ok(_) => return Err(format!("{}: not a PKCS#8 private key", path.display())),
            Err(error) => return Err(format!("{}: {error}", path.display())),
        }
    } else {
        bytes
    };
    DeviceKey::from_pkcs8(&der).map_err(|error| format!("{}: {error}", path.display()))
}

fn thumbprint(path: &Path, generate: bool) -> Result<(), String> {
    if generate {
        use base64::Engine as _;
        use std::io::Write as _;
        let (_, pkcs8) = DeviceKey::generate().map_err(|error| error.to_string())?;
        let body = base64::engine::general_purpose::STANDARD.encode(&pkcs8);
        let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
        for line in body.as_bytes().chunks(64) {
            pem.push_str(&String::from_utf8_lossy(line));
            pem.push('\n');
        }
        pem.push_str("-----END PRIVATE KEY-----\n");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options
            .open(path)
            .and_then(|mut file| file.write_all(pem.as_bytes()))
            .map_err(|error| format!("{}: {error}", path.display()))?;
    }
    println!("{}", read_key(path)?.thumbprint());
    Ok(())
}

fn relay_tls(args: &RelayArgs) -> Result<rustls::ClientConfig, String> {
    if args.insecure {
        return Ok(moqom_client::tls::insecure());
    }
    let Some(path) = &args.relay_cert else {
        return Ok(moqom_client::tls::native());
    };
    let pem = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let certificate = rustls_pemfile::certs(&mut pem.as_slice())
        .next()
        .ok_or_else(|| format!("{}: no certificate", path.display()))?
        .map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(moqom_client::tls::pinned(certificate))
}

fn relay_name(args: &RelayArgs) -> String {
    args.relay_name.clone().unwrap_or_else(|| {
        args.relay
            .rsplit_once(':')
            .map_or(args.relay.as_str(), |(host, _)| host)
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned()
    })
}

fn read_token(path: &Path) -> Result<Bytes, String> {
    std::fs::read_to_string(path)
        .map(|token| Bytes::from(token.trim().to_owned()))
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// Turns true on SIGTERM or Ctrl-C. Recording then finishes its files rather
/// than leaving them for the next run to find.
fn shutdown() -> watch::Receiver<bool> {
    let (tx, rx) = watch::channel(false);
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("installing a SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("stopping: finishing files");
        let _ = tx.send(true);
        // Held so the receivers do not read a dropped sender as a second stop.
        std::future::pending::<()>().await;
    });
    rx
}

async fn record(args: RecordArgs) -> Result<(), String> {
    let key = Arc::new(read_key(&args.relay.key)?);
    let token = read_token(&args.token_file)?;
    let store = match (&args.out, &args.gcs_bucket) {
        (Some(out), None) => Store::Local(store::LocalDir::new(out.clone())),
        (None, Some(bucket)) => {
            let credentials = match std::env::var("MOQOM_GCS_TOKEN") {
                Ok(token) if !token.is_empty() => store::Credentials::Static(token),
                _ if args.gcs_endpoint.starts_with("http://") => store::Credentials::Anonymous,
                _ => store::Credentials::Metadata,
            };
            Store::Gcs(store::Gcs::new(
                bucket.clone(),
                args.gcs_endpoint.clone(),
                credentials,
            ))
        }
        _ => return Err("one of --out or --gcs-bucket".to_owned()),
    };
    let spool = match &args.out {
        Some(out) => out.join(".spool"),
        None => args.relay.spool.join(&args.recording),
    };

    let recorder = Recorder::new(RecorderConfig {
        recording: args.recording.clone(),
        tenant: args.tenant.clone(),
        room: args.room.clone(),
        attempt: 1,
        relay: args.relay.relay.clone(),
        server_name: relay_name(&args.relay),
        tls: relay_tls(&args.relay)?,
        key,
        e2ee_required: args.e2ee_required,
        remux: args.cmaf,
        spool,
        prefix: args.prefix.trim_end_matches('/').to_owned(),
        segment_bytes: args.relay.segment_mib.max(1) << 20,
    });

    let (tokens, credentials) = watch::channel(token);
    let path = args.token_file.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_mins(1)).await;
            match read_token(&path) {
                Ok(token) if token != *tokens.borrow() => {
                    let _ = tokens.send(token);
                }
                Ok(_) => {}
                Err(error) => tracing::warn!(%error, "rereading the token"),
            }
        }
    });

    let mut stop = shutdown();
    if let Some(seconds) = args.seconds {
        let (tx, rx) = watch::channel(false);
        let mut signal = stop.clone();
        tokio::spawn(async move {
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs(seconds)) => {}
                _ = signal.wait_for(|stop| *stop) => {}
            }
            let _ = tx.send(true);
            std::future::pending::<()>().await;
        });
        stop = rx;
    }

    let summary = recorder.run(Arc::new(store), credentials, stop).await;
    println!(
        "{}",
        serde_json::to_string_pretty(&summary.manifest).map_err(|error| error.to_string())?
    );
    summary.error.map_or(Ok(()), Err)
}

async fn worker(args: WorkerArgs) -> Result<(), String> {
    let credential = std::fs::read_to_string(&args.credential_file)
        .map_err(|error| format!("{}: {error}", args.credential_file.display()))?
        .trim()
        .to_owned();
    let read = |path: &PathBuf| {
        std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))
    };
    let control_ca = args.control_ca.as_ref().map(read).transpose()?;
    let control_identity = match (&args.control_cert, &args.control_key) {
        (Some(certificate), Some(key)) => Some((read(certificate)?, read(key)?)),
        _ => None,
    };
    let worker = args.worker_id.clone().unwrap_or_else(|| {
        std::env::var("HOSTNAME").unwrap_or_else(|_| format!("recorder-{}", std::process::id()))
    });
    let config = link::WorkerConfig {
        control: args.control.clone(),
        control_ca,
        control_identity,
        control_server_name: args.control_server_name.clone(),
        credential,
        worker,
        relay: args.relay.relay.clone(),
        server_name: relay_name(&args.relay),
        tls: relay_tls(&args.relay)?,
        key: Arc::new(read_key(&args.relay.key)?),
        spool: args.relay.spool.clone(),
        segment_bytes: args.relay.segment_mib.max(1) << 20,
        gcs_endpoint: args.gcs_endpoint.clone(),
        local_store: args.local_store.clone(),
    };
    link::run(config, shutdown()).await
}

fn inspect(path: &Path, objects: bool) -> Result<(), String> {
    let file = std::fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut reader = Reader::open(BufReader::new(file)).map_err(|error| error.to_string())?;
    println!(
        "{}",
        serde_json::to_string_pretty(reader.header()).map_err(|error| error.to_string())?
    );
    let (mut count, mut bytes, mut sessions) = (0u64, 0u64, 0u32);
    loop {
        match reader.next_record() {
            Ok(Some(Record::Object(object))) => {
                count += 1;
                bytes += object.payload.len() as u64;
                if objects {
                    println!(
                        "object {}.{} {} bytes at {} capture {:?}",
                        object.group,
                        object.object,
                        object.payload.len(),
                        object.received_micros,
                        object.properties.capture_time_micros
                    );
                }
            }
            Ok(Some(Record::Session { ordinal, at_micros })) => {
                sessions += 1;
                println!("session {ordinal} at {at_micros}");
            }
            Ok(Some(Record::Departed { at_micros })) => println!("departed at {at_micros}"),
            Ok(Some(Record::End {
                objects,
                payload_bytes,
                at_micros,
            })) => {
                println!("end at {at_micros}: {objects} objects, {payload_bytes} payload bytes");
            }
            Ok(None) => break,
            Err(error) => {
                println!("stopped: {error} (everything above is intact)");
                break;
            }
        }
    }
    println!("{count} objects, {bytes} payload bytes, {sessions} sessions");
    Ok(())
}
