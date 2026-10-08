//! Just enough HTTP/1.1 for the object store and the metadata server.
//!
//! One connection per request. The requests here are a handful per segment --
//! start an upload, send a few chunks, finish -- so pooling would save a TLS
//! handshake per eight megabytes and cost a connection-lifecycle state machine.

use std::fmt::Write as _;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Method, Request, StatusCode, Uri};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

/// Longest response body read. Object-store answers are small JSON.
const MAX_RESPONSE: usize = 1 << 20;

/// How long one request may take, connection included.
const TIMEOUT: Duration = Duration::from_mins(2);

/// A response, read whole.
#[derive(Debug)]
pub struct Response {
    /// The status.
    pub status: StatusCode,
    /// The headers.
    pub headers: HeaderMap,
    /// The body.
    pub body: Bytes,
}

/// Why a request failed before a status arrived.
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    /// The URL is not one this client can reach.
    #[error("unusable URL {0}")]
    Url(String),
    /// Connecting, TLS, or the exchange itself.
    #[error("{0}")]
    Transport(String),
    /// No answer in time.
    #[error("timed out")]
    Timeout,
}

fn transport(error: impl std::fmt::Display) -> HttpError {
    HttpError::Transport(error.to_string())
}

fn tls() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    Arc::clone(CONFIG.get_or_init(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let roots = webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned()
            .collect::<rustls::RootCertStore>();
        Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }))
}

/// Send one request and read the answer.
///
/// # Errors
/// [`HttpError`] for anything short of a status line.
pub async fn send(
    method: Method,
    url: &str,
    headers: &[(&str, String)],
    body: Bytes,
) -> Result<Response, HttpError> {
    tokio::time::timeout(TIMEOUT, exchange(method, url, headers, body))
        .await
        .map_err(|_| HttpError::Timeout)?
}

async fn exchange(
    method: Method,
    url: &str,
    headers: &[(&str, String)],
    body: Bytes,
) -> Result<Response, HttpError> {
    let uri: Uri = url.parse().map_err(|_| HttpError::Url(url.to_owned()))?;
    let secure = match uri.scheme_str() {
        Some("https") => true,
        Some("http") => false,
        _ => return Err(HttpError::Url(url.to_owned())),
    };
    let host = uri
        .host()
        .ok_or_else(|| HttpError::Url(url.to_owned()))?
        .to_owned();
    let port = uri.port_u16().unwrap_or(if secure { 443 } else { 80 });
    let path = uri
        .path_and_query()
        .map_or_else(|| "/".to_owned(), ToString::to_string);

    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(http::header::HOST, &host)
        .header(http::header::CONTENT_LENGTH, body.len());
    for (name, value) in headers {
        request = request.header(*name, value);
    }
    let request = request.body(Full::new(body)).map_err(transport)?;

    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(transport)?;
    let response = if secure {
        let name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(transport)?;
        let stream = tokio_rustls::TlsConnector::from(tls())
            .connect(name, tcp)
            .await
            .map_err(transport)?;
        roundtrip(TokioIo::new(stream), request).await?
    } else {
        roundtrip(TokioIo::new(tcp), request).await?
    };
    Ok(response)
}

async fn roundtrip<T>(io: T, request: Request<Full<Bytes>>) -> Result<Response, HttpError>
where
    T: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(transport)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = sender.send_request(request).await.map_err(transport)?;
    let (parts, body) = response.into_parts();
    let body = Limited::new(body, MAX_RESPONSE)
        .collect()
        .await
        .map_err(transport)?
        .to_bytes();
    Ok(Response {
        status: parts.status,
        headers: parts.headers,
        body,
    })
}

/// Percent-encode everything but the unreserved set, for an object name in a
/// query string.
#[must_use]
pub fn encode_component(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_names_are_encoded_whole() {
        assert_eq!(
            encode_component("acme/room 1/video/720p.mqa"),
            "acme%2Froom%201%2Fvideo%2F720p.mqa"
        );
    }
}
