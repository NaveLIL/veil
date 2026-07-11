//! Minimal tus.io 1.0.0 client targeted at veil-server's `/v1/uploads/`
//! endpoint. We deliberately keep this slim — only the operations the
//! veil clients actually use are implemented:
//!
//!   * Mint a bearer token via `POST /v1/uploads/token` (signed
//!     request handled by the caller via the existing `veil-client`
//!     signed-request layer; this crate just receives the token).
//!   * Create an upload (`POST /v1/uploads/files/`).
//!   * Stream chunks (`PATCH /v1/uploads/files/{id}` with
//!     `Upload-Offset` + `Content-Type: application/offset+octet-stream`).
//!   * Resume after disconnect (`HEAD /v1/uploads/files/{id}` to
//!     learn the server-side offset).
//!   * Download finished blobs (`GET /v1/uploads/blob/{id}`).
//!
//! tus-extension features we explicitly skip in v1: concatenation,
//! creation-with-upload, deferred length, termination. Adding them
//! later requires an explicit server-side authorization design; the
//! gateway intentionally disables tus download and concatenation routes.

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use bytes::Bytes;
use reqwest::{header, Client, StatusCode, Url};
use thiserror::Error;
use zeroize::Zeroizing;

const TUS_VERSION: &str = "1.0.0";
const DEFAULT_MAX_DOWNLOAD_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENCRYPTED_METADATA_BYTES: usize = 4 * 1024;

#[derive(Debug, Error)]
pub enum TusClientError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("server returned status {0}")]
    Status(StatusCode),
    #[error("missing header: {0}")]
    MissingHeader(&'static str),
    #[error("bad header value for {0}: {1}")]
    BadHeader(&'static str, String),
    #[error("invalid upload base URL: {0}")]
    InvalidBaseUrl(String),
    #[error("invalid upload bearer token")]
    InvalidBearer,
    #[error("invalid upload file id")]
    InvalidFileId,
    #[error("server returned an untrusted upload location")]
    UntrustedLocation,
    #[error("download exceeds the configured {0}-byte limit")]
    DownloadTooLarge(u64),
    #[error("encrypted upload metadata exceeds the {0}-byte limit")]
    MetadataTooLarge(usize),
}

/// A configured tus client tied to a single veil-server gateway.
///
/// Internally stores the bearer token the caller minted via
/// `POST /v1/uploads/token`; the token lasts however long the server
/// allows (defaults to 24 h) so a single instance covers many uploads.
#[derive(Clone)]
pub struct TusClient {
    base_url: Url,
    bearer: Zeroizing<String>,
    http: Client,
    max_download_bytes: u64,
}

impl TusClient {
    /// Build a client bound to `base_url` (e.g. `https://veil.example/`)
    /// using the bearer token returned by the gateway. The bearer is
    /// stored as-is and sent on every request.
    pub fn new(
        base_url: impl AsRef<str>,
        bearer: impl Into<String>,
    ) -> Result<Self, TusClientError> {
        Self::with_max_download_bytes(base_url, bearer, DEFAULT_MAX_DOWNLOAD_BYTES)
    }

    /// Build a client with an explicit one-shot download ceiling. Larger
    /// attachments should use a future range/stream API instead of allocating
    /// the entire ciphertext blob in memory.
    pub fn with_max_download_bytes(
        base_url: impl AsRef<str>,
        bearer: impl Into<String>,
        max_download_bytes: u64,
    ) -> Result<Self, TusClientError> {
        let base_url = validate_base_url(base_url.as_ref())?;
        let bearer = bearer.into();
        if bearer.is_empty()
            || !bearer
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'\"')
        {
            return Err(TusClientError::InvalidBearer);
        }
        if max_download_bytes == 0 {
            return Err(TusClientError::DownloadTooLarge(0));
        }
        Ok(Self {
            base_url,
            bearer: Zeroizing::new(bearer),
            http: Client::builder()
                // A redirect could move the upload bearer to another origin.
                // Location headers are validated explicitly by create_upload.
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(60))
                .build()
                .map_err(TusClientError::Http)?,
            max_download_bytes,
        })
    }

    /// Create a new upload resource on the server. Returns a handle
    /// containing the file id and absolute Location URL the server
    /// chose. `total_bytes` is the **ciphertext** length — the size of
    /// every chunk concatenated, including AEAD tags.
    pub async fn create_upload(
        &self,
        total_bytes: u64,
        metadata: &TusUploadInit<'_>,
    ) -> Result<TusUploadHandle, TusClientError> {
        let url = self.endpoint(&["v1", "uploads", "files"])?;
        let meta_header = encode_metadata(metadata)?;
        let mut request = self
            .http
            .post(url)
            .header("Tus-Resumable", TUS_VERSION)
            .header("Upload-Length", total_bytes)
            .header(header::AUTHORIZATION, self.auth_header());
        if !meta_header.is_empty() {
            request = request.header("Upload-Metadata", meta_header);
        }
        let resp = request.send().await?;
        if resp.status() != StatusCode::CREATED {
            return Err(TusClientError::Status(resp.status()));
        }
        let loc = resp
            .headers()
            .get(header::LOCATION)
            .ok_or(TusClientError::MissingHeader("Location"))?
            .to_str()
            .map_err(|e| TusClientError::BadHeader("Location", e.to_string()))?
            .to_string();
        let location = self
            .base_url
            .join(&loc)
            .map_err(|_| TusClientError::UntrustedLocation)?;
        if !same_origin(&self.base_url, &location)
            || location.query().is_some()
            || location.fragment().is_some()
        {
            return Err(TusClientError::UntrustedLocation);
        }
        let segments: Vec<_> = location
            .path_segments()
            .ok_or(TusClientError::UntrustedLocation)?
            .filter(|segment| !segment.is_empty())
            .collect();
        if segments.len() != 4 || segments[..3] != ["v1", "uploads", "files"] {
            return Err(TusClientError::UntrustedLocation);
        }
        let file_id = segments[3].to_string();
        validate_file_id(&file_id)?;
        let absolute_url = self.upload_url(&file_id)?.to_string();
        Ok(TusUploadHandle {
            file_id,
            absolute_url,
        })
    }

    /// HEAD the upload to learn the current server-side offset. Use
    /// this to resume after a disconnect: encrypt only the chunks
    /// whose end-offset is greater than the returned value.
    pub async fn current_offset(&self, handle: &TusUploadHandle) -> Result<u64, TusClientError> {
        let url = self.validate_handle(handle)?;
        let resp = self
            .http
            .head(url)
            .header("Tus-Resumable", TUS_VERSION)
            .header(header::AUTHORIZATION, self.auth_header())
            .send()
            .await?;
        if resp.status() != StatusCode::OK && resp.status() != StatusCode::NO_CONTENT {
            return Err(TusClientError::Status(resp.status()));
        }
        let raw = resp
            .headers()
            .get("Upload-Offset")
            .ok_or(TusClientError::MissingHeader("Upload-Offset"))?
            .to_str()
            .map_err(|e| TusClientError::BadHeader("Upload-Offset", e.to_string()))?;
        raw.parse::<u64>()
            .map_err(|e| TusClientError::BadHeader("Upload-Offset", e.to_string()))
    }

    /// PATCH one ciphertext chunk at `offset`. Returns the new server-
    /// side offset. The caller is responsible for ordering: tusd
    /// rejects out-of-order PATCHes (which is what we want — chunked
    /// AEAD also assumes in-order arrival).
    pub async fn write_chunk(
        &self,
        handle: &TusUploadHandle,
        offset: u64,
        chunk: Bytes,
    ) -> Result<u64, TusClientError> {
        let url = self.validate_handle(handle)?;
        let resp = self
            .http
            .patch(url)
            .header("Tus-Resumable", TUS_VERSION)
            .header("Upload-Offset", offset)
            .header(header::CONTENT_TYPE, "application/offset+octet-stream")
            .header(header::AUTHORIZATION, self.auth_header())
            .body(chunk)
            .send()
            .await?;
        if resp.status() != StatusCode::NO_CONTENT {
            return Err(TusClientError::Status(resp.status()));
        }
        let raw = resp
            .headers()
            .get("Upload-Offset")
            .ok_or(TusClientError::MissingHeader("Upload-Offset"))?
            .to_str()
            .map_err(|e| TusClientError::BadHeader("Upload-Offset", e.to_string()))?;
        raw.parse::<u64>()
            .map_err(|e| TusClientError::BadHeader("Upload-Offset", e.to_string()))
    }

    /// Download a finished blob in one shot. For very large files
    /// callers can switch to a range-stream loop later; this v1
    /// reflects the small-attachment use case (images, voice notes).
    pub async fn download_blob(&self, file_id: &str) -> Result<Vec<u8>, TusClientError> {
        validate_file_id(file_id)?;
        let url = self.endpoint(&["v1", "uploads", "blob", file_id])?;
        let mut resp = self
            .http
            .get(url)
            .header(header::AUTHORIZATION, self.auth_header())
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(TusClientError::Status(resp.status()));
        }
        if resp
            .content_length()
            .is_some_and(|length| length > self.max_download_bytes)
        {
            return Err(TusClientError::DownloadTooLarge(self.max_download_bytes));
        }
        let initial_capacity = resp
            .content_length()
            .unwrap_or_default()
            .min(self.max_download_bytes)
            .try_into()
            .unwrap_or(0);
        let mut body = Vec::with_capacity(initial_capacity);
        while let Some(chunk) = resp.chunk().await? {
            let next_len = body
                .len()
                .checked_add(chunk.len())
                .ok_or(TusClientError::DownloadTooLarge(self.max_download_bytes))?;
            if u64::try_from(next_len).unwrap_or(u64::MAX) > self.max_download_bytes {
                return Err(TusClientError::DownloadTooLarge(self.max_download_bytes));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.bearer.as_str())
    }

    fn endpoint(&self, segments: &[&str]) -> Result<Url, TusClientError> {
        let mut url = self.base_url.clone();
        let mut path = url
            .path_segments_mut()
            .map_err(|_| TusClientError::InvalidBaseUrl("URL cannot be a base".to_string()))?;
        path.clear();
        for segment in segments {
            path.push(segment);
        }
        drop(path);
        Ok(url)
    }

    fn upload_url(&self, file_id: &str) -> Result<Url, TusClientError> {
        validate_file_id(file_id)?;
        self.endpoint(&["v1", "uploads", "files", file_id])
    }

    fn validate_handle(&self, handle: &TusUploadHandle) -> Result<Url, TusClientError> {
        if handle.file_id.is_empty() {
            return Err(TusClientError::InvalidFileId);
        }
        let expected = self.upload_url(&handle.file_id)?;
        let supplied =
            Url::parse(&handle.absolute_url).map_err(|_| TusClientError::UntrustedLocation)?;
        if supplied != expected {
            return Err(TusClientError::UntrustedLocation);
        }
        Ok(expected)
    }
}

fn validate_base_url(raw: &str) -> Result<Url, TusClientError> {
    let mut url = Url::parse(raw).map_err(|e| TusClientError::InvalidBaseUrl(e.to_string()))?;
    let loopback = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if !(url.scheme() == "https" || (url.scheme() == "http" && loopback)) {
        return Err(TusClientError::InvalidBaseUrl(
            "HTTPS is required outside loopback development".to_string(),
        ));
    }
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(TusClientError::InvalidBaseUrl(
            "URL must contain only scheme and authority".to_string(),
        ));
    }
    url.set_path("/");
    Ok(url)
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn validate_file_id(file_id: &str) -> Result<(), TusClientError> {
    if file_id.len() == 32
        && file_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(TusClientError::InvalidFileId)
    }
}

/// Result of a successful create_upload: server-assigned id plus the
/// absolute URL future PATCH/HEAD requests should hit.
#[derive(Debug, Clone)]
pub struct TusUploadHandle {
    pub file_id: String,
    pub absolute_url: String,
}

/// Optional metadata already encrypted by the conversation layer. Plaintext
/// filenames and MIME types are deliberately not accepted here: base64 in a
/// tus `Upload-Metadata` header is encoding, not confidentiality.
#[derive(Debug, Clone, Default)]
pub struct TusUploadInit<'a> {
    pub encrypted_metadata: Option<&'a [u8]>,
}

fn encode_metadata(init: &TusUploadInit<'_>) -> Result<String, TusClientError> {
    let Some(metadata) = init.encrypted_metadata else {
        return Ok(String::new());
    };
    if metadata.len() > MAX_ENCRYPTED_METADATA_BYTES {
        return Err(TusClientError::MetadataTooLarge(
            MAX_ENCRYPTED_METADATA_BYTES,
        ));
    }
    Ok(format!("veilmeta {}", B64.encode(metadata)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_encoding_roundtrip() {
        let m = encode_metadata(&TusUploadInit {
            encrypted_metadata: Some(b"opaque ciphertext"),
        })
        .unwrap();
        assert!(m.starts_with("veilmeta "));
        assert!(!m.contains("ciphertext"));
    }

    #[test]
    fn metadata_handles_empty() {
        assert_eq!(encode_metadata(&TusUploadInit::default()).unwrap(), "");
        assert!(encode_metadata(&TusUploadInit {
            encrypted_metadata: Some(&vec![0u8; MAX_ENCRYPTED_METADATA_BYTES + 1]),
        })
        .is_err());
    }

    #[test]
    fn transport_is_https_except_for_loopback_development() {
        assert!(TusClient::new("https://veil.example", "token").is_ok());
        assert!(TusClient::new("http://127.0.0.1:9080", "token").is_ok());
        assert!(TusClient::new("http://[::1]:9080", "token").is_ok());
        assert!(TusClient::new("http://veil.example", "token").is_err());
        assert!(TusClient::new("https://veil.example/prefix", "token").is_err());
        assert!(TusClient::new("https://user@veil.example", "token").is_err());
    }

    #[test]
    fn file_ids_are_strict_lowercase_random_hex() {
        assert!(validate_file_id("0123456789abcdef0123456789abcdef").is_ok());
        assert!(validate_file_id("../../v1/servers/anything").is_err());
        assert!(validate_file_id("0123456789ABCDEF0123456789ABCDEF").is_err());
    }
}
