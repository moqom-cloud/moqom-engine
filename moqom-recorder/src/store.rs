//! Where finished files go.
//!
//! Files are written to a local spool first and handed to a store only once
//! they are finalised, so an upload is always of a complete, checksummed file
//! and never of something still growing. What is in flight is bounded by the
//! chunk size, whatever the file's length.
//!
//! Two stores. A directory, for development and for a self-hosted recorder
//! writing to a volume. And Google Cloud Storage over its JSON API, with
//! resumable uploads -- a dropped connection resumes from what GCS says it has
//! rather than starting again -- and the CRC32C stated up front, so GCS refuses
//! an object whose bytes do not match what was written locally.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ::http::{Method, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use tokio::io::AsyncReadExt;

use crate::http::{self as web, encode_component};

/// Bytes per upload request. GCS requires a multiple of 256 KiB for every chunk
/// but the last.
const CHUNK: usize = 8 << 20;

/// Attempts at one request before the upload is given up as failed.
const ATTEMPTS: u32 = 8;

/// Why a file did not reach the store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Reading the spooled file, or writing a local destination.
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// The store answered with a status that will not improve on retry.
    #[error("the object store refused {key}: {status} {body}")]
    Refused {
        /// The object.
        key: String,
        /// The status.
        status: u16,
        /// What it said.
        body: String,
    },
    /// Retries ran out.
    #[error("the object store could not be reached for {key}: {reason}")]
    Unavailable {
        /// The object.
        key: String,
        /// The last failure.
        reason: String,
    },
    /// No credentials for the store.
    #[error("no object-store credentials: {0}")]
    Credentials(String),
}

/// Where files go.
pub enum Store {
    /// A directory.
    Local(LocalDir),
    /// A GCS bucket.
    Gcs(Gcs),
}

impl Store {
    /// Move a finalised spool file to `key`, returning its length.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn upload(
        &self,
        spooled: &Path,
        key: &str,
        crc32c: u32,
        content_type: &str,
    ) -> Result<u64, StoreError> {
        match self {
            Self::Local(local) => local.upload(spooled, key).await,
            Self::Gcs(gcs) => {
                gcs.upload(Source::File(spooled), key, crc32c, content_type)
                    .await
            }
        }
    }

    /// Write `bytes` to `key`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put(
        &self,
        key: &str,
        bytes: Bytes,
        content_type: &str,
    ) -> Result<u64, StoreError> {
        match self {
            Self::Local(local) => local.put(key, &bytes).await,
            Self::Gcs(gcs) => {
                let crc = crate::crc32c::checksum(&bytes);
                gcs.upload(Source::Bytes(bytes), key, crc, content_type)
                    .await
            }
        }
    }

    /// A URI for `key`, for logs and the manifest.
    #[must_use]
    pub fn uri(&self, key: &str) -> String {
        match self {
            Self::Local(local) => local.root.join(key).display().to_string(),
            Self::Gcs(gcs) => format!("gs://{}/{key}", gcs.bucket),
        }
    }
}

/// A directory store.
pub struct LocalDir {
    root: PathBuf,
}

impl LocalDir {
    /// A store rooted at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    async fn upload(&self, spooled: &Path, key: &str) -> Result<u64, StoreError> {
        let destination = self.root.join(key);
        if destination != spooled {
            if let Some(parent) = destination.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            if tokio::fs::rename(spooled, &destination).await.is_err() {
                tokio::fs::copy(spooled, &destination).await?;
                tokio::fs::remove_file(spooled).await?;
            }
        }
        Ok(tokio::fs::metadata(&destination).await?.len())
    }

    async fn put(&self, key: &str, bytes: &[u8]) -> Result<u64, StoreError> {
        let destination = self.root.join(key);
        if let Some(parent) = destination.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let partial = destination.with_extension("partial");
        tokio::fs::write(&partial, bytes).await?;
        tokio::fs::rename(&partial, &destination).await?;
        Ok(bytes.len() as u64)
    }
}

/// How the GCS client gets a bearer token.
pub enum Credentials {
    /// The metadata server, which is what Workload Identity provides to a pod:
    /// the pod's Kubernetes service account is bound to a Google one, and no
    /// key file exists anywhere.
    Metadata,
    /// A fixed token, for a laptop (`gcloud auth print-access-token`).
    Static(String),
    /// None, for an emulator.
    Anonymous,
}

/// A GCS bucket over the JSON API.
pub struct Gcs {
    bucket: String,
    endpoint: String,
    credentials: Credentials,
    cached: Mutex<Option<(String, Instant)>>,
}

/// What the metadata server answers.
#[derive(serde::Deserialize)]
struct MetadataToken {
    access_token: String,
    expires_in: u64,
}

enum Source<'a> {
    File(&'a Path),
    Bytes(Bytes),
}

impl Gcs {
    /// A client for `bucket` at `endpoint` (`https://storage.googleapis.com`
    /// unless an emulator is in use).
    #[must_use]
    pub fn new(
        bucket: impl Into<String>,
        endpoint: impl Into<String>,
        credentials: Credentials,
    ) -> Self {
        Self {
            bucket: bucket.into(),
            endpoint: endpoint.into().trim_end_matches('/').to_owned(),
            credentials,
            cached: Mutex::new(None),
        }
    }

    async fn authorization(&self) -> Result<Option<String>, StoreError> {
        match &self.credentials {
            Credentials::Anonymous => Ok(None),
            Credentials::Static(token) => Ok(Some(format!("Bearer {token}"))),
            Credentials::Metadata => {
                if let Some((token, until)) = self
                    .cached
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
                    && Instant::now() < until
                {
                    return Ok(Some(format!("Bearer {token}")));
                }
                let response = web::send(
                    Method::GET,
                    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                    &[("Metadata-Flavor", "Google".to_owned())],
                    Bytes::new(),
                )
                .await
                .map_err(|error| StoreError::Credentials(error.to_string()))?;
                if !response.status.is_success() {
                    return Err(StoreError::Credentials(format!(
                        "metadata server answered {}",
                        response.status
                    )));
                }
                let token: MetadataToken = serde_json::from_slice(&response.body)
                    .map_err(|error| StoreError::Credentials(error.to_string()))?;
                // Refreshed a minute early, so a token never expires mid-chunk.
                let until =
                    Instant::now() + Duration::from_secs(token.expires_in.saturating_sub(60));
                *self
                    .cached
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some((token.access_token.clone(), until));
                Ok(Some(format!("Bearer {}", token.access_token)))
            }
        }
    }

    async fn headers(
        &self,
        extra: &[(&'static str, String)],
    ) -> Result<Vec<(&'static str, String)>, StoreError> {
        let mut headers: Vec<(&'static str, String)> = extra.to_vec();
        if let Some(authorization) = self.authorization().await? {
            headers.push(("Authorization", authorization));
        }
        Ok(headers)
    }

    async fn upload(
        &self,
        source: Source<'_>,
        key: &str,
        crc32c: u32,
        content_type: &str,
    ) -> Result<u64, StoreError> {
        let total = match &source {
            Source::File(path) => tokio::fs::metadata(path).await?.len(),
            Source::Bytes(bytes) => bytes.len() as u64,
        };
        let session = self.start(key, total, crc32c, content_type).await?;

        let mut file = match &source {
            Source::File(path) => Some(tokio::fs::File::open(path).await?),
            Source::Bytes(_) => None,
        };
        let mut offset = 0u64;
        let mut chunk = Vec::with_capacity(CHUNK.min(usize::try_from(total).unwrap_or(CHUNK)));
        loop {
            chunk.clear();
            let want = usize::try_from((total - offset).min(CHUNK as u64)).unwrap_or(CHUNK);
            match (&source, file.as_mut()) {
                (Source::Bytes(bytes), _) => {
                    let start = usize::try_from(offset).unwrap_or(usize::MAX);
                    chunk.extend_from_slice(&bytes[start..start + want]);
                }
                (Source::File(_), Some(file)) => {
                    chunk.resize(want, 0);
                    file.read_exact(&mut chunk).await?;
                }
                (Source::File(_), None) => unreachable!("a file source has a file"),
            }

            let confirmed = self.put_chunk(&session, key, offset, &chunk, total).await?;
            if confirmed >= total {
                return Ok(total);
            }
            if confirmed != offset + chunk.len() as u64 {
                // GCS kept less than was sent. Resume from what it has, which
                // means rereading: seek the file back rather than hold the chunk.
                if let Some(file) = file.as_mut() {
                    use tokio::io::AsyncSeekExt;
                    file.seek(std::io::SeekFrom::Start(confirmed)).await?;
                }
            }
            offset = confirmed;
        }
    }

    async fn start(
        &self,
        key: &str,
        total: u64,
        crc32c: u32,
        content_type: &str,
    ) -> Result<String, StoreError> {
        let url = format!(
            "{}/upload/storage/v1/b/{}/o?uploadType=resumable&name={}",
            self.endpoint,
            encode_component(&self.bucket),
            encode_component(key)
        );
        let metadata = serde_json::json!({
            "name": key,
            "contentType": content_type,
            "crc32c": STANDARD.encode(crc32c.to_be_bytes()),
        });
        let body = Bytes::from(metadata.to_string());
        let mut last = String::new();
        for attempt in 0..ATTEMPTS {
            let headers = self
                .headers(&[
                    ("Content-Type", "application/json; charset=UTF-8".to_owned()),
                    ("X-Upload-Content-Type", content_type.to_owned()),
                    ("X-Upload-Content-Length", total.to_string()),
                ])
                .await?;
            match web::send(Method::POST, &url, &headers, body.clone()).await {
                Ok(response) if response.status.is_success() => {
                    return response
                        .headers
                        .get(::http::header::LOCATION)
                        .and_then(|value| value.to_str().ok())
                        .map(ToOwned::to_owned)
                        .ok_or_else(|| StoreError::Unavailable {
                            key: key.to_owned(),
                            reason: "no upload session in the answer".to_owned(),
                        });
                }
                Ok(response) if retryable(response.status) => last = response.status.to_string(),
                Ok(response) => return Err(refused(key, &response)),
                Err(error) => last = error.to_string(),
            }
            backoff(attempt).await;
        }
        Err(StoreError::Unavailable {
            key: key.to_owned(),
            reason: last,
        })
    }

    /// Send one chunk, returning how many bytes GCS now holds.
    async fn put_chunk(
        &self,
        session: &str,
        key: &str,
        offset: u64,
        chunk: &[u8],
        total: u64,
    ) -> Result<u64, StoreError> {
        let range = if total == 0 {
            "bytes */0".to_owned()
        } else {
            format!(
                "bytes {}-{}/{}",
                offset,
                offset + chunk.len() as u64 - 1,
                total
            )
        };
        let body = Bytes::copy_from_slice(chunk);
        let mut last = String::new();
        for attempt in 0..ATTEMPTS {
            let headers = self.headers(&[("Content-Range", range.clone())]).await?;
            match web::send(Method::PUT, session, &headers, body.clone()).await {
                Ok(response) if response.status.is_success() => return Ok(total),
                Ok(response) if response.status.as_u16() == 308 => return Ok(persisted(&response)),
                Ok(response) if retryable(response.status) => last = response.status.to_string(),
                Ok(response) => return Err(refused(key, &response)),
                Err(error) => last = error.to_string(),
            }
            backoff(attempt).await;
            // The chunk may have landed before the failure. Ask, and resume
            // from GCS's answer rather than resending what it already has.
            if let Ok(held) = self.status(session, total).await {
                if held >= total {
                    return Ok(total);
                }
                if held != offset {
                    return Ok(held);
                }
            }
        }
        Err(StoreError::Unavailable {
            key: key.to_owned(),
            reason: last,
        })
    }

    async fn status(&self, session: &str, total: u64) -> Result<u64, StoreError> {
        let headers = self
            .headers(&[("Content-Range", format!("bytes */{total}"))])
            .await?;
        let response = web::send(Method::PUT, session, &headers, Bytes::new())
            .await
            .map_err(|error| StoreError::Unavailable {
                key: String::new(),
                reason: error.to_string(),
            })?;
        if response.status.is_success() {
            return Ok(total);
        }
        Ok(persisted(&response))
    }
}

/// What a `308 Resume Incomplete` says GCS holds: `Range: bytes=0-N` means N+1
/// bytes, and no header means none.
fn persisted(response: &web::Response) -> u64 {
    response
        .headers
        .get("range")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit('-').next())
        .and_then(|end| end.parse::<u64>().ok())
        .map_or(0, |end| end + 1)
}

fn retryable(status: StatusCode) -> bool {
    status.is_server_error()
        || status == StatusCode::TOO_MANY_REQUESTS
        || status == StatusCode::REQUEST_TIMEOUT
}

fn refused(key: &str, response: &web::Response) -> StoreError {
    StoreError::Refused {
        key: key.to_owned(),
        status: response.status.as_u16(),
        body: String::from_utf8_lossy(&response.body)
            .chars()
            .take(400)
            .collect(),
    }
}

async fn backoff(attempt: u32) {
    let millis = 250u64.saturating_mul(1 << attempt.min(6));
    tokio::time::sleep(Duration::from_millis(millis.min(15_000))).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_308_says_how_much_is_held() {
        let mut headers = ::http::HeaderMap::new();
        headers.insert("range", "bytes=0-8388607".parse().unwrap());
        let response = web::Response {
            status: StatusCode::PERMANENT_REDIRECT,
            headers,
            body: Bytes::new(),
        };
        assert_eq!(persisted(&response), 8 << 20);
        let empty = web::Response {
            status: StatusCode::PERMANENT_REDIRECT,
            headers: ::http::HeaderMap::new(),
            body: Bytes::new(),
        };
        assert_eq!(persisted(&empty), 0);
    }

    #[tokio::test]
    async fn a_local_store_moves_files_into_place() {
        let root =
            std::env::temp_dir().join(format!("moqom-recorder-store-{}", std::process::id()));
        let spool = root.join("spool");
        let out = root.join("out");
        tokio::fs::create_dir_all(&spool).await.unwrap();
        let file = spool.join("a.mqa");
        tokio::fs::write(&file, b"archive").await.unwrap();

        let store = Store::Local(LocalDir::new(&out));
        assert_eq!(
            store.upload(&file, "acme/r1/a.mqa", 0, "x").await.unwrap(),
            7
        );
        assert!(!file.exists(), "the spool copy is gone");
        assert_eq!(
            tokio::fs::read(out.join("acme/r1/a.mqa")).await.unwrap(),
            b"archive"
        );
        assert_eq!(
            store
                .put(
                    "acme/r1/manifest.json",
                    Bytes::from_static(b"{}"),
                    "application/json"
                )
                .await
                .unwrap(),
            2
        );
        let _ = tokio::fs::remove_dir_all(&root).await;
    }
}
