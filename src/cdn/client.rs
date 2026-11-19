//! CDN HTTP client: chunk GETs with DepotDownloader's retry matrix (timeouts, dropped
//! connections, 5xx and corrupt chunk content rotate servers; 401/403/404 and a wrong depot
//! key are terminal for the depot).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use tokio_util::sync::CancellationToken;

use crate::cdn::CdnServer;
use crate::cdn::chunk::{ChunkFailure, ChunkFailureKind};
use crate::error::{Error, Result};

/// Decrypt failures tolerated per chunk before it is declared a wrong depot key (see
/// [`CdnClient::fetch_chunk`]).
const MAX_DECRYPT_FAILURES: u32 = 2;

/// Round-robin CDN client shared by all download tasks of a run.
pub(crate) struct CdnClient {
    http: reqwest::Client,
    servers: Vec<CdnServer>,
    cursor: Arc<AtomicUsize>,
}

impl CdnClient {
    pub(crate) fn new(http: reqwest::Client, servers: Vec<CdnServer>, app_id: u32) -> Result<Self> {
        let servers: Vec<CdnServer> = servers
            .into_iter()
            .filter(|server| server.serves_app(app_id))
            .collect();
        if servers.is_empty() {
            return Err(Error::NoCdnServers);
        }
        Ok(CdnClient {
            http,
            servers,
            cursor: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub(crate) fn server_count(&self) -> usize {
        self.servers.len()
    }

    /// Download a chunk and hand it to `process` (decrypt → decompress → verify → write),
    /// rotating through every known server once until one copy processes cleanly.
    ///
    /// Retry semantics (mirroring DepotDownloader):
    /// - timeout / connect failure / connection dropped mid-request or mid-body / HTTP
    ///   408/425/429/5xx → try next server;
    /// - HTTP 401/403/404 → fatal (`Error::HttpStatus`); this crate cannot mint CDN auth
    ///   tokens (that requires a CM session which does not exist here);
    /// - wrong length → treated as a corrupt server response → next server;
    /// - content that decrypts but does not decompress/verify → corrupt response → next server;
    /// - decryption failure → almost always a wrong depot key, which no server can fix, but a
    ///   corrupted final block looks identical: one more server is tried, a second decrypt
    ///   failure is fatal;
    /// - local (disk write) failure → fatal.
    ///
    /// Returns the number of network bytes of the copy that succeeded. Cancellation cuts short
    /// an in-flight request, never a chunk mid-write.
    pub(crate) async fn fetch_chunk<F, Fut>(
        &self,
        depot_id: u32,
        chunk_id_hex: &str,
        expected_compressed_len: u32,
        cancel: &CancellationToken,
        mut process: F,
    ) -> Result<u64>
    where
        F: FnMut(Bytes) -> Fut,
        Fut: Future<Output = std::result::Result<(), ChunkFailure>>,
    {
        let count = self.servers.len();
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) % count;
        let mut last_error: Option<Error> = None;
        let mut decrypt_failures = 0u32;

        for index in 0..count {
            if cancel.is_cancelled() {
                return Err(Error::Cancelled);
            }
            let server = &self.servers[(start + index) % count];
            let url = server.chunk_url(depot_id, chunk_id_hex);

            let fetched = tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err(Error::Cancelled),
                fetched = self.get(&url) => fetched,
            };
            let bytes = match fetched {
                Ok(bytes) => bytes,
                Err(error) if error.rotates_cdn_server() => {
                    last_error = Some(error);
                    continue;
                }
                Err(fatal) => return Err(fatal),
            };

            if expected_compressed_len != 0 && bytes.len() != expected_compressed_len as usize {
                last_error = Some(Error::Chunk {
                    chunk_id: chunk_id_hex.to_owned(),
                    reason: format!(
                        "expected {expected_compressed_len} compressed bytes, got {}",
                        bytes.len()
                    ),
                });
                continue;
            }

            let network_len = bytes.len() as u64;
            match process(bytes).await {
                Ok(()) => return Ok(network_len),
                Err(failure) => match failure.kind {
                    ChunkFailureKind::Corrupt => last_error = Some(failure.error),
                    ChunkFailureKind::Decrypt => {
                        decrypt_failures += 1;
                        if decrypt_failures >= MAX_DECRYPT_FAILURES {
                            return Err(failure.error);
                        }
                        last_error = Some(failure.error);
                    }
                    ChunkFailureKind::Local => return Err(failure.error),
                },
            }
        }

        Err(last_error.unwrap_or(Error::NoCdnServers))
    }

    async fn get(&self, url: &str) -> Result<Bytes> {
        let response = self.http.get(url).send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(Error::HttpStatus {
                status: status.as_u16(),
                url: url.to_owned(),
            });
        }
        // `Response::bytes` already hands back the body as one `Bytes`; converting it into a
        // Vec would copy the whole chunk a second time on its way to the chunk pipeline.
        Ok(response.bytes().await?)
    }
}
