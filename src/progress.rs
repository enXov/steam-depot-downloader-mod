//! Progress reporting: a channel of [`ProgressEvent`]s plus a [`DownloadHandle`] combining
//! the event stream, a cancellation token, and the final [`DownloadReport`].

use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::error::{Error, Result};

/// Everything the download engine reports while working.
///
/// Frequency note: [`ProgressEvent::ChunkCompleted`] fires once per downloaded chunk (chunks
/// are at most ~1 MiB uncompressed). UIs usually aggregate it into a progress bar; all the
/// cumulative counters needed are present on the event itself, so no extra state is required.
#[derive(Debug, Clone, serde::Serialize)]
pub enum ProgressEvent {
    /// The CDN server list is known (queried from Steam or supplied explicitly).
    ServerListLoaded { servers: usize },

    /// A depot's manifest was parsed (before filenames are decrypted / keys are checked).
    ManifestLoaded {
        depot_id: u32,
        manifest_gid: u64,
        /// Unix time the manifest was created upstream.
        creation_unix: u32,
    },

    /// Started working on a depot.
    DepotStarted {
        depot_id: u32,
        manifest_gid: u64,
        files_total: usize,
        /// Sum of uncompressed sizes of all content files in the manifest.
        bytes_total: u64,
    },

    /// An existing file is about to be re-verified chunk-by-chunk (Steam-style verify).
    FileVerifying { depot_id: u32, path: PathBuf },

    /// Started (pre-allocating or reusing) a file.
    FileStarted {
        depot_id: u32,
        path: PathBuf,
        size: u64,
    },

    /// One chunk was downloaded, decrypted, verified and written.
    ChunkCompleted {
        depot_id: u32,
        path: PathBuf,
        /// Bytes of *this file* now fully in place (including reused/verified ones).
        file_bytes_completed: u64,
        file_size: u64,
        /// This chunk's compressed network size.
        downloaded_increment: u64,
        /// This chunk's uncompressed size.
        uncompressed_increment: u64,
        /// Whole-run cumulative network bytes.
        total_downloaded: u64,
        /// Whole-run cumulative uncompressed bytes.
        total_uncompressed: u64,
    },

    /// A file is fully written (possibly with 0 network bytes if everything was reused).
    FileCompleted {
        depot_id: u32,
        path: PathBuf,
        /// Cumulative content bytes of completed files within this depot.
        depot_bytes_completed: u64,
        depot_bytes_total: u64,
    },

    /// Depot finished successfully; state has been committed.
    DepotCompleted {
        depot_id: u32,
        manifest_gid: u64,
        downloaded_bytes: u64,
    },

    /// A depot failed. Other depots continue unaffected; details are also in the final report.
    DepotFailed {
        /// `None` if failure happened before the depot id was resolved.
        depot_id: Option<u32>,
        error: String,
    },

    /// Everything is done. The same report is returned by [`DownloadHandle::join`].
    Finished { report: DownloadReport },
}

/// Summary of one depot at the end of a run.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DepotReport {
    pub depot_id: Option<u32>,
    pub manifest_gid: Option<u64>,
    /// Content files in the manifest.
    pub files: usize,
    /// Uncompressed bytes across all content files.
    pub bytes_total: u64,
    /// Bytes actually fetched from the network for this depot.
    pub downloaded_bytes: u64,
    /// `Some(message)` if the depot failed.
    pub error: Option<String>,
}

impl DepotReport {
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.error.is_none()
    }
}

/// Final outcome of a download run.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DownloadReport {
    pub app_id: u32,
    pub depots: Vec<DepotReport>,
    /// Network bytes across the whole run.
    pub downloaded_bytes: u64,
    /// Uncompressed bytes produced across the whole run.
    pub uncompressed_bytes: u64,
    pub duration: Duration,
}

impl DownloadReport {
    /// Iterate the depots that failed.
    pub fn failed(&self) -> impl Iterator<Item = &DepotReport> {
        self.depots.iter().filter(|d| d.error.is_some())
    }

    /// `true` when at least one depot failed.
    #[must_use]
    pub fn has_failures(&self) -> bool {
        self.depots.iter().any(|d| d.error.is_some())
    }

    /// `true` when every depot succeeded.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.depots.iter().all(DepotReport::is_ok)
    }
}

impl Drop for DownloadHandle {
    /// Dropping the handle cancels the download: a consumer that walks away should never leave
    /// an orphaned engine running. (After [`DownloadHandle::join`] this is a no-op.)
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Handle for a running download: event stream + cancellation + final result.
pub struct DownloadHandle {
    events: mpsc::Receiver<ProgressEvent>,
    cancel: CancellationToken,
    task: Option<tokio::task::JoinHandle<Result<DownloadReport>>>,
}

impl DownloadHandle {
    pub(crate) fn new(
        events: mpsc::Receiver<ProgressEvent>,
        cancel: CancellationToken,
        task: tokio::task::JoinHandle<Result<DownloadReport>>,
    ) -> Self {
        DownloadHandle {
            events,
            cancel,
            task: Some(task),
        }
    }

    /// Mutably borrow the event stream, e.g. `while let Some(ev) = handle.events().recv().await`.
    pub fn events(&mut self) -> &mut mpsc::Receiver<ProgressEvent> {
        &mut self.events
    }

    /// Move the event stream out - handy when a separate task should drain events while the
    /// handle stays with you for `cancel()`/`join()`.
    pub fn take_events(mut self) -> mpsc::Receiver<ProgressEvent> {
        std::mem::replace(&mut self.events, mpsc::channel(1).1)
    }

    /// Clone the cancellation token - e.g. so a UI layer can wire a cancel button from
    /// another task without holding the whole handle.
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Cancel the download. In-flight network requests stop at the next boundary and
    /// [`DownloadHandle::join`] returns [`Error::Cancelled`].
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// Wait for completion and get the final report.
    ///
    /// Failing depots are reflected in the report (`report.failed()`); `Err` is reserved for
    /// whole-run failures (cancelled, no CDN servers, …).
    pub async fn join(mut self) -> Result<DownloadReport> {
        let task = self
            .task
            .take()
            .ok_or_else(|| Error::TaskFailed("download handle was already joined".to_owned()))?;
        task.await.map_err(|e| Error::TaskFailed(e.to_string()))?
    }
}
