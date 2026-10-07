//! Sending usage records to the billing endpoint, `POST /v1/usage`.
//!
//! Two tasks, so that a report stuck on a slow endpoint never delays a cut. The
//! cutter wakes every [`SAMPLE`](super::SAMPLE) to re-sample meters and, at each
//! interval boundary, cuts every one into a record. The sender drains the
//! queue in batches and is the only thing that waits on the network; nothing
//! on the media path waits on either.
//!
//! # When the endpoint says no
//!
//! - A network error, a timeout, `429` or any `5xx`: the same batch is sent
//!   again, with the same identifiers, after a jittered exponential wait. The
//!   endpoint charges an identifier once, so a retry of a batch that was in
//!   fact recorded costs nothing. Nothing is given up on: an outage is waited
//!   out for as long as the queue can hold what accrues meanwhile.
//! - `400`, `413` or `422`: the batch is invalid and sending it again would fail
//!   again. The endpoint refuses a whole batch for one bad record, so a refused
//!   batch is split in half and each half sent, until the records it refuses
//!   are alone; those are logged and dropped. Nothing is charged for a refused
//!   batch, so the halves cannot double-charge.
//! - `401`, `403` or `404`: the credential or the URL is wrong. Logged as an
//!   error on every attempt and retried at the same backoff, keeping the
//!   batch, so that a rotated key file or a fixed deployment picks up where it
//!   left off.
//!
//! # Admission
//!
//! A self-hosted relay is told with each answer whether its tenant may admit new
//! sessions, and [`Usage::admitting`] follows it. Because that is only learned
//! by reporting, a self-hosted relay reports every interval even with nothing
//! to report: an empty batch costs one small request a minute, and without it
//! a relay that had been told no would have no sessions, so no records, so no
//! way to hear yes. Until the first answer, and whenever the endpoint cannot be
//! reached, the last answer stands — which at startup is yes, because the
//! control plane already refuses to mint tokens for a tenant that may not
//! admit, and a relay that refused everybody whenever billing was unreachable
//! would make billing an outage.

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::{Method, Request, StatusCode, Uri};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::{Hosting, Inner, Record, SAMPLE, Usage, unix_now};

/// How long one report may take, connection included.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Longest answer read. The endpoint's are a few hundred bytes of JSON.
const MOST_ANSWER: usize = 64 * 1024;

/// How long a refusal's message may be in a log line.
const MOST_LOGGED: usize = 300;

/// Where reports go, and what they are signed with.
#[derive(Debug)]
pub struct Endpoint {
    url: String,
    credential: Credential,
    authorities: Vec<rustls::pki_types::CertificateDer<'static>>,
    tls: OnceLock<Arc<rustls::ClientConfig>>,
}

/// The bearer credential a report carries.
#[derive(Debug, Clone)]
pub enum Credential {
    /// A value fixed at startup: the hosted relay's operator credential, the
    /// same one its control-plane link presents.
    Value(String),
    /// A file holding a self-hosted relay's `mqk_` relay key, reread for every
    /// report so that rotating the key needs no restart.
    File(PathBuf),
}

impl Credential {
    fn read(&self) -> Result<String, String> {
        match self {
            Self::Value(value) => Ok(value.clone()),
            Self::File(path) => std::fs::read_to_string(path)
                .map(|contents| contents.trim().to_owned())
                .map_err(|e| format!("reading {}: {e}", path.display())),
        }
    }
}

impl Endpoint {
    /// Reports to `url`, signed with `credential`.
    ///
    /// A URL with no path is the billing listener itself, and `/v1/usage` is
    /// added. `https` is verified against the public roots and any authority
    /// added with [`Self::trusting`]; plain `http` is for a test or a control
    /// plane on the same machine.
    ///
    /// # Errors
    /// If the URL is not an `http` or `https` URL with a host.
    pub fn new(url: &str, credential: Credential) -> Result<Self, String> {
        let uri: Uri = url.parse().map_err(|e| format!("usage URL {url:?}: {e}"))?;
        if !matches!(uri.scheme_str(), Some("http" | "https")) || uri.host().is_none() {
            return Err(format!(
                "usage URL {url:?} must be http:// or https:// with a host"
            ));
        }
        let url = match uri.path() {
            "" | "/" => format!("{}/v1/usage", url.trim_end_matches('/')),
            _ => url.to_owned(),
        };
        Self::at(&url, credential)
    }

    /// Posts to exactly `url`, signed with `credential`, for a caller other than
    /// the reporter. See [`Self::new`] for which schemes are allowed.
    ///
    /// # Errors
    /// If the URL is not an `http` or `https` URL with a host.
    pub fn at(url: &str, credential: Credential) -> Result<Self, String> {
        let uri: Uri = url.parse().map_err(|e| format!("URL {url:?}: {e}"))?;
        if !matches!(uri.scheme_str(), Some("http" | "https")) || uri.host().is_none() {
            return Err(format!(
                "URL {url:?} must be http:// or https:// with a host"
            ));
        }
        Ok(Self {
            url: url.to_owned(),
            credential,
            authorities: Vec::new(),
            tls: OnceLock::new(),
        })
    }

    /// POST `body` as JSON, returning the status and what came back.
    ///
    /// # Errors
    /// An unreadable credential, or a request that did not complete within the
    /// reporter's timeout.
    pub(crate) async fn post_json(&self, body: Bytes) -> Result<(StatusCode, Bytes), String> {
        let credential = self.credential.read()?;
        if credential.is_empty() {
            return Err("the credential is empty".to_owned());
        }
        tokio::time::timeout(TIMEOUT, exchange(self, &credential, body))
            .await
            .map_err(|_| "timed out".to_owned())?
    }

    /// Also trust the certificate authorities in `pem`, for an endpoint on a
    /// private network that no public authority will certify.
    ///
    /// # Errors
    /// If `pem` holds no certificates, or one that does not parse.
    pub fn trusting(mut self, pem: &[u8]) -> Result<Self, String> {
        for certificate in rustls_pemfile::certs(&mut &pem[..]) {
            self.authorities
                .push(certificate.map_err(|e| format!("usage CA: {e}"))?);
        }
        if self.authorities.is_empty() {
            return Err("usage CA contains no certificates".to_owned());
        }
        Ok(self)
    }

    /// Where reports go.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    fn tls(&self) -> Arc<rustls::ClientConfig> {
        Arc::clone(self.tls.get_or_init(|| {
            let mut roots: rustls::RootCertStore =
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
            for authority in &self.authorities {
                // Parsed at startup by `trusting`; one the store will not take
                // leaves the public roots, and the handshake says why.
                let _ = roots.add(authority.clone());
            }
            Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        }))
    }
}

/// The running reporter.
///
/// Dropping it closes every meter and leaves the sender draining the queue with
/// no deadline; [`Self::shutdown`] is the same with one, and says what was lost.
#[derive(Debug)]
pub struct Reporter {
    usage: Usage,
    closing: watch::Sender<bool>,
    cutter: JoinHandle<()>,
    sender: JoinHandle<()>,
}

impl Usage {
    /// Start cutting and sending records to `endpoint`.
    ///
    /// `None` when metering is disabled, since there would be nothing to send.
    #[must_use]
    pub fn report_to(&self, endpoint: Endpoint) -> Option<Reporter> {
        let inner = Arc::clone(self.inner.as_ref()?);
        let (closing, watching) = watch::channel(false);
        let cutter = tokio::spawn(cut(self.clone(), watching.clone()));
        let sender = tokio::spawn(send(inner, endpoint, watching));
        Some(Reporter {
            usage: self.clone(),
            closing,
            cutter,
            sender,
        })
    }
}

impl Reporter {
    /// Close every session's last interval and send what is queued, giving up
    /// after `within`.
    ///
    /// For a graceful stop, after the listeners have drained: a session still
    /// open is recorded up to now, as though it had ended, and anything still
    /// unsent when time runs out is counted as dropped and logged, since an
    /// in-memory queue does not outlive the process.
    pub async fn shutdown(self, within: Duration) {
        self.closing.send_replace(true);
        let _ = self.cutter.await;
        let mut sender = self.sender;
        if tokio::time::timeout(within, &mut sender).await.is_err() {
            sender.abort();
            let _ = sender.await;
        }
        let Some(inner) = &self.usage.inner else {
            return;
        };
        let left = {
            let mut queue = inner.lock_queue();
            let left = queue.records.len();
            queue.records.clear();
            left + usize::try_from(inner.in_flight.swap(0, Ordering::Relaxed)).unwrap_or(0)
        };
        if left > 0 {
            inner
                .counters
                .dropped_shutdown
                .fetch_add(left as u64, Ordering::Relaxed);
            tracing::error!(
                records = left,
                "stopping with usage records the billing endpoint has not accepted; they are lost"
            );
        }
    }
}

/// The next interval boundary after `now`, in seconds since the epoch.
const fn next_boundary(now: u64, interval: u64) -> u64 {
    now - now % interval + interval
}

/// Sample meters, and cut them at every boundary, until told to stop.
async fn cut(usage: Usage, mut closing: watch::Receiver<bool>) {
    let Some(interval) = usage.inner.as_ref().map(|i| i.config.interval_seconds()) else {
        return;
    };
    let mut boundary = next_boundary(unix_now(), interval);
    loop {
        let until = (UNIX_EPOCH + Duration::from_secs(boundary))
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO);
        tokio::select! {
            () = tokio::time::sleep(until.min(SAMPLE)) => {}
            _ = closing.changed() => {}
        }
        if *closing.borrow() || closing.has_changed().is_err() {
            usage.cut_all(Instant::now(), unix_now(), true);
            return;
        }
        if SystemTime::now() >= UNIX_EPOCH + Duration::from_secs(boundary) {
            usage.cut_all(Instant::now(), boundary, false);
            boundary = next_boundary(unix_now(), interval);
        } else {
            usage.sample_all();
        }
    }
}

/// What became of one report.
enum Outcome {
    /// Recorded, with what the endpoint said about it.
    Accepted(Answer),
    /// Invalid; sending it again would fail again.
    Rejected(String),
    /// The credential or the address is wrong.
    Unauthorized(String),
    /// Worth trying again.
    Failed(String),
}

#[derive(Debug, Default, Deserialize)]
struct Answer {
    #[serde(default)]
    duplicates: u64,
    #[serde(default)]
    unbilled: u64,
    #[serde(default)]
    admitted: Option<bool>,
}

#[derive(serde::Serialize)]
struct Body<'a> {
    records: &'a [Record],
}

/// Send batches until told to stop and the queue is empty.
// One loop, because what each outcome does to the batches in hand is the
// policy, and spreading it over helpers would hide how they interact.
#[allow(clippy::too_many_lines)]
async fn send(inner: Arc<Inner>, endpoint: Endpoint, closing: watch::Receiver<bool>) {
    // Batches in hand, last sent first. More than one only while a refused
    // batch is being split.
    let mut pieces: Vec<Vec<Record>> = Vec::new();
    let mut failures: u32 = 0;
    loop {
        // A dropped reporter stops too, rather than leaving `changed` to
        // return at once forever below.
        let stopping = *closing.borrow() || closing.has_changed().is_err();
        if pieces.is_empty() {
            let batch = inner.take_batch();
            let heartbeat = inner.config.hosting == Hosting::SelfHosted
                && inner.heartbeat.swap(false, Ordering::Relaxed);
            if batch.is_empty() && !heartbeat {
                inner.in_flight.store(0, Ordering::Relaxed);
                if stopping {
                    return;
                }
                let mut closing = closing.clone();
                tokio::select! {
                    () = inner.wake.notified() => {}
                    _ = closing.changed() => {}
                }
                continue;
            }
            pieces.push(batch);
        }
        let held: usize = pieces.iter().map(Vec::len).sum();
        inner.in_flight.store(held as u64, Ordering::Relaxed);
        let Some(piece) = pieces.last() else {
            continue;
        };

        let started = Instant::now();
        let outcome = post(&endpoint, piece).await;
        let took = started.elapsed();
        match outcome {
            Outcome::Accepted(answer) => {
                inner.observe_latency(took);
                let sent = pieces.pop().map_or(0, |piece| piece.len());
                inner.in_flight.fetch_sub(sent as u64, Ordering::Relaxed);
                failures = 0;
                let c = &inner.counters;
                c.reports_ok.fetch_add(1, Ordering::Relaxed);
                c.sent.fetch_add(sent as u64, Ordering::Relaxed);
                c.duplicates.fetch_add(answer.duplicates, Ordering::Relaxed);
                c.unbilled.fetch_add(answer.unbilled, Ordering::Relaxed);
                c.last_success.store(unix_now(), Ordering::Relaxed);
                tracing::debug!(
                    records = sent,
                    duplicates = answer.duplicates,
                    ?took,
                    "usage reported"
                );
                if let Some(admitted) = answer.admitted {
                    inner.admit(admitted);
                }
                continue;
            }
            Outcome::Rejected(why) => {
                inner.observe_latency(took);
                inner
                    .counters
                    .reports_rejected
                    .fetch_add(1, Ordering::Relaxed);
                let Some(mut piece) = pieces.pop() else {
                    continue;
                };
                if piece.len() > 1 {
                    let second = piece.split_off(piece.len() / 2);
                    tracing::warn!(
                        records = piece.len() + second.len(),
                        reason = %why,
                        "billing endpoint refused a usage batch; splitting it to find the bad records"
                    );
                    pieces.push(second);
                    pieces.push(piece);
                } else {
                    inner
                        .in_flight
                        .fetch_sub(piece.len() as u64, Ordering::Relaxed);
                    inner
                        .counters
                        .dropped_rejected
                        .fetch_add(piece.len() as u64, Ordering::Relaxed);
                    tracing::error!(
                        id = piece.first().map(|r| r.id.as_str()),
                        reason = %why,
                        "billing endpoint refused a usage record; dropped"
                    );
                }
                continue;
            }
            Outcome::Unauthorized(why) => {
                inner.observe_latency(took);
                inner
                    .counters
                    .reports_unauthorized
                    .fetch_add(1, Ordering::Relaxed);
                tracing::error!(
                    url = endpoint.url(),
                    reason = %why,
                    waiting = pieces.iter().map(Vec::len).sum::<usize>(),
                    "billing endpoint refused this relay's credential; usage is not being recorded"
                );
            }
            Outcome::Failed(why) => {
                inner
                    .counters
                    .reports_failed
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    url = endpoint.url(),
                    reason = %why,
                    attempt = failures + 1,
                    "usage report failed; will retry the same records"
                );
            }
        }

        failures = failures.saturating_add(1);
        let mut wait = backoff(&inner.config, failures);
        if stopping {
            // Shutdown has its own deadline, and waiting out a minute of
            // backoff inside it would spend the whole of it asleep.
            wait = wait.min(Duration::from_millis(500));
        }
        let mut closing = closing.clone();
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            _ = closing.changed(), if !stopping => {}
        }
    }
}

/// How long to wait before attempt `failures + 1`: doubling from the first
/// retry to the longest, and drawn from the upper half of that so a fleet that
/// lost the endpoint together does not return to it together.
fn backoff(config: &super::Config, failures: u32) -> Duration {
    let doubled = config
        .first_retry
        .saturating_mul(1 << failures.saturating_sub(1).min(16));
    let ceiling = doubled.min(config.longest_retry);
    let half = ceiling / 2;
    half + half.mul_f64(jitter())
}

/// A uniform draw from `[0, 1)`.
#[allow(clippy::cast_precision_loss)] // 53 bits, which is all an f64 holds
pub(crate) fn jitter() -> f64 {
    use aws_lc_rs::rand::SecureRandom as _;
    let mut bytes = [0u8; 8];
    if aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut bytes)
        .is_err()
    {
        return 0.5;
    }
    let draw = (u64::from_le_bytes(bytes) >> 11) as f64;
    draw / (1u64 << 53) as f64
}

impl Inner {
    fn admit(&self, admitted: bool) {
        let was = self.admitting.swap(admitted, Ordering::Relaxed);
        if was && !admitted {
            tracing::warn!(
                "billing says this tenant may not admit new sessions; refusing them until it says otherwise"
            );
        } else if !was && admitted {
            tracing::info!("billing admits new sessions again");
        }
    }
}

async fn post(endpoint: &Endpoint, records: &[Record]) -> Outcome {
    let credential = match endpoint.credential.read() {
        Ok(credential) if !credential.is_empty() => credential,
        Ok(_) => return Outcome::Unauthorized("the credential is empty".to_owned()),
        Err(e) => return Outcome::Unauthorized(e),
    };
    let body = match serde_json::to_vec(&Body { records }) {
        Ok(body) => Bytes::from(body),
        Err(e) => return Outcome::Rejected(format!("could not encode the batch: {e}")),
    };
    let answer = match tokio::time::timeout(TIMEOUT, exchange(endpoint, &credential, body)).await {
        Err(_) => return Outcome::Failed("timed out".to_owned()),
        Ok(Err(e)) => return Outcome::Failed(e),
        Ok(Ok(answer)) => answer,
    };
    let (status, body) = answer;
    let message = || {
        let text = String::from_utf8_lossy(&body);
        let mut text = text.trim().to_owned();
        if text.len() > MOST_LOGGED {
            let mut cut = MOST_LOGGED;
            while !text.is_char_boundary(cut) {
                cut -= 1;
            }
            text.truncate(cut);
        }
        format!("{status}: {text}")
    };
    match status {
        status if status.is_success() => {
            Outcome::Accepted(serde_json::from_slice(&body).unwrap_or_else(|e| {
                // Recorded, which is what the status says; only the detail is
                // missing, and retrying a recorded batch would be noise.
                tracing::warn!(error = %e, "billing endpoint's answer was not readable");
                Answer::default()
            }))
        }
        StatusCode::BAD_REQUEST
        | StatusCode::PAYLOAD_TOO_LARGE
        | StatusCode::UNPROCESSABLE_ENTITY => Outcome::Rejected(message()),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::NOT_FOUND => {
            Outcome::Unauthorized(message())
        }
        _ => Outcome::Failed(message()),
    }
}

/// One request on its own connection. A report a minute does not justify a
/// pool, or the connection-lifecycle state one needs.
async fn exchange(
    endpoint: &Endpoint,
    credential: &str,
    body: Bytes,
) -> Result<(StatusCode, Bytes), String> {
    let uri: Uri = endpoint.url.parse().map_err(|e| format!("{e}"))?;
    let secure = uri.scheme_str() == Some("https");
    let host = uri.host().ok_or("no host")?.to_owned();
    let port = uri.port_u16().unwrap_or(if secure { 443 } else { 80 });
    let path = uri
        .path_and_query()
        .map_or_else(|| "/".to_owned(), ToString::to_string);
    let authority = uri
        .authority()
        .map_or_else(|| host.clone(), ToString::to_string);

    let request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(http::header::HOST, authority)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::CONTENT_LENGTH, body.len())
        .header(http::header::AUTHORIZATION, format!("Bearer {credential}"))
        .body(Full::new(body))
        .map_err(|e| e.to_string())?;

    let tcp = TcpStream::connect((host.trim_matches(['[', ']']), port))
        .await
        .map_err(|e| format!("connecting: {e}"))?;
    if secure {
        let name =
            rustls::pki_types::ServerName::try_from(host.trim_matches(['[', ']']).to_owned())
                .map_err(|e| e.to_string())?;
        let stream = tokio_rustls::TlsConnector::from(endpoint.tls())
            .connect(name, tcp)
            .await
            .map_err(|e| format!("TLS: {e}"))?;
        roundtrip(TokioIo::new(stream), request).await
    } else {
        roundtrip(TokioIo::new(tcp), request).await
    }
}

async fn roundtrip<T>(io: T, request: Request<Full<Bytes>>) -> Result<(StatusCode, Bytes), String>
where
    T: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = sender
        .send_request(request)
        .await
        .map_err(|e| e.to_string())?;
    let status = response.status();
    let body = Limited::new(response.into_body(), MOST_ANSWER)
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    Ok((status, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usage::{Config, Hosting};

    #[test]
    fn backoff_doubles_to_a_ceiling_and_stays_in_its_upper_half() {
        let config = Config::new("relay", Hosting::Cloud);
        for (failures, ceiling) in [(1, 1), (2, 2), (3, 4), (6, 32), (7, 60), (40, 60)] {
            let ceiling = Duration::from_secs(ceiling);
            for _ in 0..50 {
                let wait = backoff(&config, failures);
                assert!(
                    wait >= ceiling / 2 && wait <= ceiling,
                    "{failures}: {wait:?}"
                );
            }
        }
    }

    #[test]
    fn a_bare_listener_url_gets_the_usage_path() {
        let credential = || Credential::Value("x".to_owned());
        assert_eq!(
            Endpoint::new("https://api.moqom.cloud", credential())
                .expect("url")
                .url(),
            "https://api.moqom.cloud/v1/usage"
        );
        assert_eq!(
            Endpoint::new("http://127.0.0.1:8090/", credential())
                .expect("url")
                .url(),
            "http://127.0.0.1:8090/v1/usage"
        );
        assert_eq!(
            Endpoint::new("https://billing.internal/v1/usage", credential())
                .expect("url")
                .url(),
            "https://billing.internal/v1/usage"
        );
        assert!(Endpoint::new("ftp://x", credential()).is_err());
        assert!(Endpoint::new("not a url", credential()).is_err());
    }

    #[test]
    fn boundaries_are_aligned() {
        assert_eq!(next_boundary(1_791_278_123, 60), 1_791_278_160);
        assert_eq!(next_boundary(1_791_278_160, 60), 1_791_278_220);
        assert_eq!(next_boundary(7, 1), 8);
    }
}
