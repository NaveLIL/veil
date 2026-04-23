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
//! later is straightforward because tusd already advertises support
//! server-side.

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use bytes::Bytes;
use reqwest::{header, Client, StatusCode};
use thiserror::Error;

const TUS_VERSION: &str = "1.0.0";

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
}

/// A configured tus client tied to a single veil-server gateway.
///
/// Internally stores the bearer token the caller minted via
/// `POST /v1/uploads/token`; the token lasts however long the server
/// allows (defaults to 24 h) so a single instance covers many uploads.
#[derive(Clone)]
pub struct TusClient {
    base_url: String,
    bearer: String,
    http: Client,
}

impl TusClient {
    /// Build a client bound to `base_url` (e.g. `https://veil.example/`)
    /// using the bearer token returned by the gateway. The bearer is
    /// stored as-is and sent on every request.
    pub fn new(base_url: impl Into<String>, bearer: impl Into<String>) -> Self {
        let mut base = base_url.into();
        if base.ends_with('/') {
            base.pop();
        }
        Self {
            base_url: base,
            bearer: bearer.into(),
            http: Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .expect("reqwest client"),
        }
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
        let url = format!("{}/v1/uploads/files/", self.base_url);
        let meta_header = encode_metadata(metadata);
        let resp = self
            .http
            .post(&url)
            .header("Tus-Resumable", TUS_VERSION)
            .header("Upload-Length", total_bytes)
            .header("Upload-Metadata", meta_header)
            .header(header::AUTHORIZATION, self.auth_header())
            .send()
            .await?;
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
        // tusd returns "/v1/uploads/files/<id>" or full URL depending
        // on RespectForwardedHeaders config. Strip any scheme/host so
        // we can re-join under our base_url.
        let path = if loc.starts_with("http") {
            // Take the path component without pulling in a URL parser.
            // Find first '/' after "scheme://".
            let rest = loc.split_once("://").map(|x| x.1).unwrap_or(&loc);
            match rest.find('/') {
                Some(i) => rest[i..].to_string(),
                None => return Err(TusClientError::BadHeader("Location", loc)),
            }
        } else {
            loc
        };
        let file_id = path
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or("")
            .to_string();
        if file_id.is_empty() {
            return Err(TusClientError::BadHeader(
                "Location",
                "no file id".to_string(),
            ));
        }
        Ok(TusUploadHandle {
            file_id,
            absolute_url: format!("{}{}", self.base_url, path),
        })
    }

    /// HEAD the upload to learn the current server-side offset. Use
    /// this to resume after a disconnect: encrypt only the chunks
    /// whose end-offset is greater than the returned value.
    pub async fn current_offset(
        &self,
        handle: &TusUploadHandle,
    ) -> Result<u64, TusClientError> {
        let resp = self
            .http
            .head(&handle.absolute_url)
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
        let resp = self
            .http
            .patch(&handle.absolute_url)
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
        let url = format!("{}/v1/uploads/blob/{}", self.base_url, file_id);
        let resp = self
            .http
            .get(&url)
            .header(header::AUTHORIZATION, self.auth_header())
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(TusClientError::Status(resp.status()));
        }
        let bytes = resp.bytes().await?;
        Ok(bytes.to_vec())
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.bearer)
    }
}

/// Result of a successful create_upload: server-assigned id plus the
/// absolute URL future PATCH/HEAD requests should hit.
#[derive(Debug, Clone)]
pub struct TusUploadHandle {
    pub file_id: String,
    pub absolute_url: String,
}

/// Public client-supplied metadata. The server stores none of these
/// (it's E2EE-blind) but tusd echoes them on the .info file so the
/// uploader sees consistent values across HEAD requests during a
/// resume. Filename + filetype are NOT used as auth/identity inputs.
#[derive(Debug, Clone, Default)]
pub struct TusUploadInit<'a> {
    pub filename: Option<&'a str>,
    pub filetype: Option<&'a str>,
}

fn encode_metadata(init: &TusUploadInit<'_>) -> String {
    let mut parts = Vec::new();
    if let Some(name) = init.filename {
        parts.push(format!("filename {}", B64.encode(name.as_bytes())));
    }
    if let Some(t) = init.filetype {
        parts.push(format!("filetype {}", B64.encode(t.as_bytes())));
    }
    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_encoding_roundtrip() {
        let m = encode_metadata(&TusUploadInit {
            filename: Some("photo.jpg"),
            filetype: Some("image/jpeg"),
        });
        assert!(m.starts_with("filename "));
        assert!(m.contains("filetype "));
    }

    #[test]
    fn metadata_handles_empty() {
        assert_eq!(encode_metadata(&TusUploadInit::default()), "");
    }
}
