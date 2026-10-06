//! The worker: claim a recording from the control plane, record it, report.
//!
//! Pull, with leases. A worker asks for the oldest recording nobody holds,
//! renews its lease while recording -- each renewal reports progress, and
//! collects a fresh relay token and whether to stop -- and finishes with the
//! list of what it stored. A worker that stops renewing loses the recording to
//! the next one that claims, which records under a new attempt number beside
//! whatever the first managed to store.
//!
//! A worker told to shut down (a rolling deploy, a node drained) finalises
//! what it has and hands the recording back with `requeue`, rather than
//! failing it: the room is still going, and another worker can take over.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use moqom_client::DeviceKey;
use tokio::sync::watch;

use crate::generated::moqom::recorder::v1 as pb;
use crate::recorder::{Progress, Recorder, RecorderConfig, Summary};
use crate::store::{self, Store};

type Client = pb::recorder_link_client::RecorderLinkClient<tonic::transport::Channel>;

/// How long to wait between claims when nothing is waiting.
const IDLE: Duration = Duration::from_secs(5);

/// Attempts at reporting the end of a recording.
const FINISH_ATTEMPTS: u32 = 6;

/// How a worker reaches the control plane, the relay, and storage.
#[derive(Clone)]
pub struct WorkerConfig {
    /// The control plane's gRPC endpoint.
    pub control: String,
    /// A CA bundle for the control plane, if it is not publicly trusted.
    pub control_ca: Option<Vec<u8>>,
    /// A client certificate and key (PEM), for a control plane whose gRPC port
    /// requires mutual TLS.
    pub control_identity: Option<(Vec<u8>, Vec<u8>)>,
    /// The name the control plane's certificate carries, when the endpoint is
    /// an address rather than that name.
    pub control_server_name: Option<String>,
    /// The service-account credential the control plane knows this pool by.
    pub credential: String,
    /// Stable for this process.
    pub worker: String,
    /// The relay, as `host:port`.
    pub relay: String,
    /// The relay certificate's name.
    pub server_name: String,
    /// TLS for the relay.
    pub tls: rustls::ClientConfig,
    /// The recorder key.
    pub key: Arc<DeviceKey>,
    /// The local spool.
    pub spool: PathBuf,
    /// File rotation size.
    pub segment_bytes: u64,
    /// The GCS endpoint, normally `https://storage.googleapis.com`.
    pub gcs_endpoint: String,
    /// Write to this directory instead of the assignment's bucket. For running
    /// a worker against a development control plane.
    pub local_store: Option<PathBuf>,
}

/// Claim and record until `shutdown`.
///
/// # Errors
/// The control plane's endpoint is unusable. Failures to reach it are retried.
pub async fn run(config: WorkerConfig, mut shutdown: watch::Receiver<bool>) -> Result<(), String> {
    let mut client = connect(&config)?;
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let claimed = tokio::select! {
            claimed = client.claim(request(&config, pb::ClaimRequest { worker: config.worker.clone() })) => claimed,
            _ = shutdown.wait_for(|stop| *stop) => return Ok(()),
        };
        match claimed.map(tonic::Response::into_inner) {
            Ok(pb::ClaimResponse {
                assignment: Some(assignment),
            }) => {
                record(&config, &mut client, assignment, shutdown.clone()).await;
                continue;
            }
            Ok(_) => {}
            Err(status) => tracing::warn!(%status, "claiming from the control plane"),
        }
        tokio::select! {
            () = tokio::time::sleep(IDLE) => {}
            _ = shutdown.wait_for(|stop| *stop) => return Ok(()),
        }
    }
}

fn connect(config: &WorkerConfig) -> Result<Client, String> {
    let mut endpoint = tonic::transport::Endpoint::from_shared(config.control.clone())
        .map_err(|error| format!("control endpoint: {error}"))?
        .http2_keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(20));
    if config.control.starts_with("https://") {
        let mut tls = tonic::transport::ClientTlsConfig::new().with_native_roots();
        if let Some(ca) = &config.control_ca {
            tls = tls.ca_certificate(tonic::transport::Certificate::from_pem(ca));
        }
        if let Some((certificate, key)) = &config.control_identity {
            tls = tls.identity(tonic::transport::Identity::from_pem(certificate, key));
        }
        if let Some(name) = &config.control_server_name {
            tls = tls.domain_name(name.clone());
        }
        endpoint = endpoint
            .tls_config(tls)
            .map_err(|error| format!("control-plane TLS: {error}"))?;
    }
    // Lazy: a control plane that is down at start is retried by each claim,
    // rather than keeping the pod from becoming ready.
    Ok(Client::new(endpoint.connect_lazy()))
}

fn request<T>(config: &WorkerConfig, body: T) -> tonic::Request<T> {
    let mut request = tonic::Request::new(body);
    if let Ok(bearer) = format!("Bearer {}", config.credential).parse() {
        request.metadata_mut().insert("authorization", bearer);
    }
    request
}

fn progress(progress: &Progress) -> pb::Progress {
    let narrow = |value: u64| u32::try_from(value).unwrap_or(u32::MAX);
    pb::Progress {
        objects: progress.objects.load(Ordering::Relaxed),
        bytes_received: progress.bytes_received.load(Ordering::Relaxed),
        bytes_stored: progress.bytes_stored.load(Ordering::Relaxed),
        tracks: narrow(progress.tracks.load(Ordering::Relaxed)),
        reconnects: narrow(progress.reconnects.load(Ordering::Relaxed)),
    }
}

fn until(timestamp: &prost_types::Timestamp) -> Duration {
    let at = Duration::new(
        u64::try_from(timestamp.seconds).unwrap_or(0),
        u32::try_from(timestamp.nanos).unwrap_or(0),
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    at.saturating_sub(now)
}

fn recorder_for(config: &WorkerConfig, assignment: &pb::Assignment) -> (Arc<Store>, Recorder) {
    let store = Arc::new(match &config.local_store {
        Some(root) => Store::Local(store::LocalDir::new(root.clone())),
        None => Store::Gcs(store::Gcs::new(
            assignment.storage_bucket.clone(),
            config.gcs_endpoint.clone(),
            store::Credentials::Metadata,
        )),
    });
    let recorder = Recorder::new(RecorderConfig {
        recording: assignment.recording_id.clone(),
        tenant: assignment.tenant.clone(),
        room: assignment.room.clone(),
        attempt: assignment.attempt.max(1),
        relay: config.relay.clone(),
        server_name: config.server_name.clone(),
        tls: config.tls.clone(),
        key: Arc::clone(&config.key),
        e2ee_required: assignment.e2ee_required,
        remux: assignment.remux,
        spool: config.spool.join(&assignment.recording_id),
        prefix: assignment.storage_prefix.trim_end_matches('/').to_owned(),
        segment_bytes: config.segment_bytes,
    });
    (store, recorder)
}

async fn record(
    config: &WorkerConfig,
    client: &mut Client,
    assignment: pb::Assignment,
    mut shutdown: watch::Receiver<bool>,
) {
    let id = assignment.recording_id.clone();
    let Some(credential) = assignment.credential.as_ref() else {
        tracing::error!(recording = %id, "an assignment without a credential");
        return;
    };
    tracing::info!(recording = %id, tenant = %assignment.tenant, room = %assignment.room, attempt = assignment.attempt, "recording");

    let (store, recorder) = recorder_for(config, &assignment);
    let counters = recorder.progress();
    let (tokens, credentials) = watch::channel(Bytes::from(credential.token.clone()));
    let (stop, stopping) = watch::channel(false);
    let mut running = tokio::spawn(recorder.run(store, credentials, stopping));

    let lease = Duration::from_secs(u64::from(assignment.lease_seconds.max(15)));
    let deadline = assignment
        .deadline
        .as_ref()
        .map(|at| Instant::now() + until(at));
    let mut renewed = Instant::now();
    let mut requeue = false;
    let mut lost = false;
    let summary: Summary = loop {
        let deadline_sleep = async {
            match deadline {
                Some(at) => tokio::time::sleep_until(at.into()).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            finished = &mut running => {
                match finished {
                    Ok(summary) => break summary,
                    Err(failure) => {
                        // Unreported: the lease runs out and another worker
                        // resumes under the next attempt number.
                        tracing::error!(recording = %id, %failure, "the recorder task died");
                        return;
                    }
                }
            }
            () = tokio::time::sleep(lease / 3) => {
                let renewal = pb::RenewRequest { recording_id: id.clone(), worker: config.worker.clone(), progress: Some(progress(&counters)) };
                match client.renew(request(config, renewal)).await.map(tonic::Response::into_inner) {
                    Ok(answer) => {
                        renewed = Instant::now();
                        if let Some(credential) = answer.credential
                            && !credential.token.is_empty()
                        {
                            let _ = tokens.send(Bytes::from(credential.token));
                        }
                        if answer.stop {
                            let _ = stop.send(true);
                        }
                    }
                    Err(status) if matches!(status.code(), tonic::Code::NotFound | tonic::Code::FailedPrecondition | tonic::Code::PermissionDenied) => {
                        // Another worker holds it now, or it is gone. Nothing
                        // to report to, so finish the files and walk away.
                        tracing::warn!(recording = %id, %status, "the lease is lost");
                        lost = true;
                        let _ = stop.send(true);
                    }
                    Err(status) => {
                        tracing::warn!(recording = %id, %status, "renewing the lease");
                        if renewed.elapsed() >= lease {
                            lost = true;
                            let _ = stop.send(true);
                        }
                    }
                }
            }
            () = deadline_sleep, if !*stop.borrow() => {
                tracing::info!(recording = %id, "the recording reached its maximum duration");
                let _ = stop.send(true);
            }
            _ = shutdown.wait_for(|stop| *stop), if !requeue => {
                requeue = true;
                let _ = stop.send(true);
            }
        }
    };
    if !lost {
        report(config, client, &id, &summary, &counters, requeue).await;
    }
}

/// Tell the control plane what an attempt stored, retrying while it is unreachable.
async fn report(
    config: &WorkerConfig,
    client: &mut Client,
    id: &str,
    summary: &Summary,
    counters: &Progress,
    requeue: bool,
) {
    let mut artifacts: Vec<pb::Artifact> = summary
        .manifest
        .artifacts
        .iter()
        .chain(summary.manifest_artifact.iter())
        .map(|artifact| pb::Artifact {
            name: artifact.name.clone(),
            kind: artifact.kind.as_str().to_owned(),
            track: artifact.track.clone(),
            bytes: artifact.bytes,
            crc32c: STANDARD.encode(artifact.crc32c.to_be_bytes()),
        })
        .collect();
    artifacts.sort_by(|a, b| a.name.cmp(&b.name));
    let finish = pb::FinishRequest {
        recording_id: id.to_owned(),
        worker: config.worker.clone(),
        progress: Some(progress(counters)),
        manifest: summary
            .manifest_artifact
            .as_ref()
            .map(|artifact| artifact.name.clone())
            .unwrap_or_default(),
        artifacts,
        error: summary.error.clone().unwrap_or_default(),
        requeue,
    };
    for attempt in 0..FINISH_ATTEMPTS {
        match client.finish(request(config, finish.clone())).await {
            Ok(_) => {
                tracing::info!(recording = %id, requeue, error = ?summary.error, "recording finished");
                return;
            }
            Err(status) if status.code() == tonic::Code::Unavailable => {
                tracing::warn!(recording = %id, %status, "reporting the finish");
                tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
            }
            Err(status) => {
                tracing::error!(recording = %id, %status, "the control plane refused the finish");
                return;
            }
        }
    }
}
