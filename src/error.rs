//! Error type for the whole crate.

use std::path::PathBuf;

/// Convenience alias used by every public API in this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Every failure mode of the crate.
///
/// For downloads specifically, failure of an individual depot is normally surfaced via
/// [`crate::ProgressEvent::DepotFailed`] and the final [`crate::DownloadReport`] instead of
/// aborting the whole run - this error type is what those messages are derived from.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The [`crate::DownloadRequest`] is inconsistent (missing app id, no depots, bad key hex, …).
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// A manifest file/blob could not be parsed as a Steam depot manifest.
    #[error("invalid depot manifest: {0}")]
    Manifest(String),

    /// Encrypted manifest filenames could not be decrypted (wrong depot key, corrupt data).
    #[error("failed to decrypt manifest filenames: {0}")]
    ManifestNameDecrypt(String),

    /// reqwest-level network error.
    #[error("network error: {0}")]
    Http(#[from] reqwest::Error),

    /// The CDN answered with a non-success HTTP status.
    #[error("CDN returned HTTP {status} for {url}")]
    HttpStatus { status: u16, url: String },

    /// The Steam content server directory returned no usable servers.
    #[error("Steam returned no usable CDN servers")]
    NoCdnServers,

    /// The content server directory response could not be decoded.
    #[error("failed to query Steam's content server directory: {0}")]
    CdnDirectory(String),

    /// A downloaded chunk failed to decrypt/decompress/verify.
    #[error("invalid depot chunk {chunk_id}: {reason}")]
    Chunk { chunk_id: String, reason: String },

    /// Final Adler-32 (seed 0) verification of a chunk failed.
    #[error(
        "checksum mismatch for chunk {chunk_id}: expected adler32 {expected:08x}, computed {actual:08x} (corrupt download or wrong depot key?)"
    )]
    Checksum {
        chunk_id: String,
        expected: u32,
        actual: u32,
    },

    /// Plain I/O error where no path made contextual sense.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// I/O error attached to a specific path.
    #[error("I/O error on {}: {source}", path.display())]
    IoWithPath {
        path: PathBuf,
        source: std::io::Error,
    },

    /// The download was cancelled through [`crate::DownloadHandle::cancel`].
    #[error("download cancelled")]
    Cancelled,

    /// An internal task failed before it could finish.
    #[error("download task failed: {0}")]
    TaskFailed(String),
}

impl Error {
    /// Attach path context to an I/O error.
    pub(crate) fn io_path(path: impl Into<PathBuf>) -> impl FnOnce(std::io::Error) -> Error {
        let path = path.into();
        move |source| Error::IoWithPath { path, source }
    }

    /// Should the CDN client try the next server after this error?
    ///
    /// Mirrors DepotDownloader's retry taxonomy: timeouts/connection failures/5xx rotate to the
    /// next server, while 401/403/404 are fatal for the depot (this crate cannot mint CDN auth
    /// tokens - supply a manifest file key material that works).
    pub(crate) fn rotates_cdn_server(&self) -> bool {
        match self {
            Error::Http(e) => e.is_timeout() || e.is_connect(),
            Error::HttpStatus { status, .. } => {
                matches!(status, 408 | 425 | 429 | 500..=599)
            }
            Error::Chunk { .. } | Error::Checksum { .. } => true,
            _ => false,
        }
    }

    /// Human-readable one-liner, safe to emit into UI events.
    pub(crate) fn to_user_string(&self) -> String {
        self.to_string()
    }
}
