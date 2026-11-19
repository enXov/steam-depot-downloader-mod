//! The download orchestrator.
//!
//! Per depot: parse manifest → ids/key → plan every file → run chunk downloads under a shared
//! concurrency semaphore → commit state. Files are planned/executed concurrently (at most a
//! bounded number in flight); network concurrency is bounded by
//! [`DownloadRequest::max_downloads`].
//!
//! Where the work of a run actually goes, in the order that matters for a fast download:
//!
//! | stage                   | cost                        | treatment |
//! |-------------------------|-----------------------------|-----------|
//! | chunk fetch             | network-bound               | `max_downloads`-wide semaphore; repeated chunks of a file fetched once |
//! | decrypt + decompress    | CPU, per chunk              | thread-local scratch buffers + a retained zstd `DCtx` |
//! | chunk verify/write      | small                       | positional I/O through `Arc<File>` - no mutex |
//! | file plan (verify run)  | disk + CPU                  | one `spawn_blocking` per file, one stat per file, offset-ordered reads |
//! | chunk reuse copy        | disk, can be many GB        | skipped when offsets are unchanged; else coalesced runs, a pool of blocking tasks |
//!
//! Reuse semantics (exactly what the crate docs promise):
//!
//! | situation                                       | behavior                                      |
//! |-------------------------------------------------|-----------------------------------------------|
//! | file missing                                    | download every chunk                          |
//! | same manifest gid as installed                  | verify every chunk (Steam-style verify)       |
//! | new gid, file hash unchanged across versions    | skip without reading                          |
//! | new gid, file hash changed, reused chunks kept their offsets | verify on-disk chunks; patch only the changed ones in place |
//! | new gid, file hash changed, reused chunks moved | verify on-disk chunks; rebuild via staging    |
//! | prior install with no/unknown state             | verify against the new manifest in place      |
//!
//! Files on disk that are not listed in the manifest are never touched and never deleted.

use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

use crate::cdn::client::CdnClient;
use crate::cdn::{CdnServer, chunk, directory};
use crate::config::{DepotSpec, DownloadRequest, ManifestSource};
use crate::error::{Error, Result};
use crate::fileio;
use crate::manifest::{DepotManifest, ManifestChunk, ManifestFile};
use crate::progress::{DepotReport, DownloadReport, ProgressEvent};
use crate::state::StateStore;
use crate::util;

/// Largest single `pread`/`pwrite` used when moving a reused chunk into staging.
/// Bounded so the coalescing below keeps memory flat no matter how big a run is.
const COPY_STRIDE: u64 = 4 * 1024 * 1024;

/// How many blocking tasks may copy reused chunks into staging at once. Local disk is the
/// bottleneck there, not the CDN, so this is independent of `max_downloads` and small: an
/// update that reuses most of the old install moves real gigabytes through it.
const COPY_PARALLELISM: usize = 4;

/// How many files may be in flight (planning, holding an open handle, waiting on chunks) at
/// once, as a multiple of `max_downloads`, clamped to [`FILE_PARALLELISM_MIN`,
/// `FILE_PARALLELISM_MAX`]. Without a bound every file of the depot would plan concurrently
/// (a `spawn_blocking` storm on a 50k-file depot) and open its write handle while still
/// queued for a download permit - enough to hit the default 1024-descriptor limit and fail
/// the depot with EMFILE. The floor keeps enough small files queued to saturate the network.
const FILE_PARALLELISM_FACTOR: usize = 4;
const FILE_PARALLELISM_MIN: usize = 32;
const FILE_PARALLELISM_MAX: usize = 256;

pub(crate) struct DownloadEngine {
    http: reqwest::Client,
    request: DownloadRequest,
    events: mpsc::Sender<ProgressEvent>,
    cancel: CancellationToken,
    server_override: Option<Arc<Vec<CdnServer>>>,
    total_downloaded: Arc<AtomicU64>,
    total_uncompressed: Arc<AtomicU64>,
}

/// A depot failure that remembers how far identification got, so failure reports can name
/// the depot once its manifest has been parsed.
struct DepotFailure {
    depot_id: Option<u32>,
    manifest_gid: Option<u64>,
    error: Error,
}

/// Everything [`DownloadEngine::download_depot`] produces for bookkeeping/state.
struct DepotOutcome {
    depot_id: u32,
    manifest_gid: u64,
    files: usize,
    bytes_total: u64,
    downloaded_bytes: u64,
    manifest_bytes: Vec<u8>,
}

/// Shared, immutable-per-depot state handed to every file task.
struct DepotCtx<'a> {
    client: &'a CdnClient,
    depot_id: u32,
    key: [u8; 32],
    staging_dir: PathBuf,
    /// `true` when the requested manifest gid equals the gid recorded as installed -
    /// disables all reuse shortcuts and forces the full Steam-style chunk verification.
    same_manifest: bool,
    old_by_path: HashMap<&'a str, &'a ManifestFile>,
    depot_cancel: CancellationToken,
    depot_bytes_completed: Arc<AtomicU64>,
    depot_downloaded: Arc<AtomicU64>,
    depot_bytes_total: u64,
    downloads_sem: Arc<Semaphore>,
    /// Caps concurrent chunk-reuse copies (see [`COPY_PARALLELISM`]).
    copies_sem: Arc<Semaphore>,
    /// Caps files in flight (see [`FILE_PARALLELISM_FACTOR`]).
    files_sem: Semaphore,
}

/// How a file's bytes are sourced.
#[derive(Default)]
struct FilePlan {
    /// Chunks that must come from the network.
    downloads: Vec<ManifestChunk>,
    /// Chunks verified on disk that must be copied to a (possibly new) offset in staging.
    copies: Vec<CopyOp>,
    /// Bytes already known-good when the plan starts (drives per-file progress).
    reused_bytes: u64,
    /// Bytes of `reused_bytes` that still have to be copied into staging. Excluded from the
    /// progress seed so copied bytes are counted once, by the copy job that moves them.
    copy_bytes: u64,
    /// The file already existed on disk (drives the `FileVerifying` progress event).
    existed: bool,
    /// Nothing to do at all (content is provably identical to the previous install).
    skip: bool,
    /// Rebuild through a staging file instead of patching in place.
    staging: bool,
    /// Target does not exist yet → create + preallocate it fresh.
    fresh: bool,
}

#[derive(Clone)]
struct CopyOp {
    chunk: ManifestChunk,
    source_offset: u64,
}

/// One contiguous byte range to move out of the existing install into staging.
///
/// Adjacent [`CopyOp`]s coalesce into one of these: a delta update whose old and new
/// boundaries line up (exactly what an untouched region of a build produces) then becomes a
/// single large `pread`/`pwrite` pair rather than one syscall pair per chunk.
#[derive(Clone, Copy)]
struct CopyRun {
    source_offset: u64,
    dest_offset: u64,
    len: u64,
}

/// Turn copy ops into maximal contiguous runs (ops are chunk-ordered, i.e. ascending
/// destination offsets, so this is a single linear pass).
fn coalesce_copy_runs(ops: &[CopyOp]) -> Vec<CopyRun> {
    let mut runs: Vec<CopyRun> = Vec::new();
    for op in ops {
        if op.chunk.len_uncompressed == 0 {
            continue;
        }
        let op_len = u64::from(op.chunk.len_uncompressed);
        let op_src = op.source_offset;
        let op_dst = op.chunk.offset;
        if let Some(last) = runs.last_mut()
            && last.source_offset + last.len == op_src
            && last.dest_offset + last.len == op_dst
        {
            last.len += op_len;
        } else {
            runs.push(CopyRun {
                source_offset: op_src,
                dest_offset: op_dst,
                len: op_len,
            });
        }
    }
    runs
}

/// Group a file's download set by chunk id: each distinct chunk is fetched once, and every
/// further offset holding the same content rides along as an extra write target. Real
/// manifests repeat chunks inside a file (zero padding, repeated blocks) - 17 files of the
/// Aion 2 fixture do. Keeps the (offset-ascending) order of each id's first occurrence.
fn dedup_downloads(downloads: Vec<ManifestChunk>) -> Vec<(ManifestChunk, Vec<u64>)> {
    let mut first_by_id: HashMap<[u8; 20], usize> = HashMap::with_capacity(downloads.len());
    let mut grouped: Vec<(ManifestChunk, Vec<u64>)> = Vec::with_capacity(downloads.len());
    for chunk in downloads {
        match first_by_id.get(&chunk.id) {
            // Identical id but a different declared shape would be a corrupt manifest; never
            // guess - fetch it separately and let its own verification decide.
            Some(&index)
                if grouped[index].0.len_uncompressed == chunk.len_uncompressed
                    && grouped[index].0.adler32 == chunk.adler32 =>
            {
                grouped[index].1.push(chunk.offset);
            }
            _ => {
                first_by_id.entry(chunk.id).or_insert(grouped.len());
                grouped.push((chunk, Vec::new()));
            }
        }
    }
    grouped
}

/// Everything one chunk download needs; handed to [`DownloadEngine::download_chunk`].
struct ChunkJob {
    /// Shared, never mutable: positional writes need no lock, so one open handle serves every
    /// chunk of the file.
    file_handle: Arc<std::fs::File>,
    done_bytes: Arc<AtomicU64>,
    display_path: PathBuf,
    file_size: u64,
    chunk: ManifestChunk,
    /// Further offsets in the same file that hold this exact chunk (same id). The chunk is
    /// fetched and decompressed once and written to `chunk.offset` plus each of these.
    extra_offsets: Vec<u64>,
    /// Held for the lifetime of the future; caps global network concurrency.
    _permit: OwnedSemaphorePermit,
}

impl DownloadEngine {
    pub(crate) fn new(
        http: reqwest::Client,
        request: DownloadRequest,
        events: mpsc::Sender<ProgressEvent>,
        cancel: CancellationToken,
        server_override: Option<Arc<Vec<CdnServer>>>,
    ) -> Self {
        DownloadEngine {
            http,
            request,
            events,
            cancel,
            server_override,
            total_downloaded: Arc::new(AtomicU64::new(0)),
            total_uncompressed: Arc::new(AtomicU64::new(0)),
        }
    }

    pub(crate) async fn run(mut self) -> Result<DownloadReport> {
        let started = Instant::now();
        let app_id = self.request.app_id;

        // 1. CDN servers: explicit override (tests / LAN caches) or Steam's public directory.
        let servers = match &self.server_override {
            Some(servers) => servers.as_ref().clone(),
            None => directory::fetch_servers(&self.http).await?,
        };
        let client = CdnClient::new(self.http.clone(), servers, app_id)?;
        self.emit(ProgressEvent::ServerListLoaded {
            servers: client.server_count(),
        })
        .await;

        // 2. Output directory + state. Stale staging leftovers from a crashed run are dropped -
        //    staging content is always rebuilt from scratch.
        tokio::fs::create_dir_all(&self.request.output_dir)
            .await
            .map_err(Error::io_path(&self.request.output_dir))?;
        let mut state = StateStore::load(&self.request.output_dir);
        state.clear_staging()?;

        // 3. Depots sequentially (as in DepotDownloader); parallelism happens within a depot.
        // `depots` is moved out so each `ManifestSource` is consumed without cloning.
        let depots = std::mem::take(&mut self.request.depots);
        let mut depot_reports = Vec::with_capacity(depots.len());
        for spec in depots {
            if self.cancel.is_cancelled() {
                return Err(Error::Cancelled);
            }

            match self.download_depot(&client, &state, spec).await {
                Ok(outcome) => {
                    let error = state
                        .commit_depot(
                            outcome.depot_id,
                            outcome.manifest_gid,
                            &outcome.manifest_bytes,
                        )
                        .err()
                        .map(|e| e.to_user_string());

                    let report = DepotReport {
                        depot_id: Some(outcome.depot_id),
                        manifest_gid: Some(outcome.manifest_gid),
                        files: outcome.files,
                        bytes_total: outcome.bytes_total,
                        downloaded_bytes: outcome.downloaded_bytes,
                        error,
                    };
                    if let Some(error) = &report.error {
                        // The download itself fully succeeded; only the bookkeeping write failed.
                        self.emit(ProgressEvent::DepotFailed {
                            depot_id: report.depot_id,
                            error: error.clone(),
                        })
                        .await;
                    } else {
                        self.emit(ProgressEvent::DepotCompleted {
                            depot_id: outcome.depot_id,
                            manifest_gid: outcome.manifest_gid,
                            downloaded_bytes: outcome.downloaded_bytes,
                        })
                        .await;
                    }
                    depot_reports.push(report);
                }
                Err(failure) => {
                    if matches!(failure.error, Error::Cancelled) || self.cancel.is_cancelled() {
                        return Err(Error::Cancelled);
                    }
                    let message = failure.error.to_user_string();
                    self.emit(ProgressEvent::DepotFailed {
                        depot_id: failure.depot_id,
                        error: message.clone(),
                    })
                    .await;
                    depot_reports.push(DepotReport {
                        depot_id: failure.depot_id,
                        manifest_gid: failure.manifest_gid,
                        files: 0,
                        bytes_total: 0,
                        downloaded_bytes: 0,
                        error: Some(message),
                    });
                    // A failed depot never takes down its siblings.
                }
            }
        }

        let report = DownloadReport {
            app_id,
            depots: depot_reports,
            downloaded_bytes: self.total_downloaded.load(Ordering::Relaxed),
            uncompressed_bytes: self.total_uncompressed.load(Ordering::Relaxed),
            duration: started.elapsed(),
        };
        self.emit(ProgressEvent::Finished {
            report: report.clone(),
        })
        .await;
        Ok(report)
    }

    async fn download_depot(
        &self,
        client: &CdnClient,
        state: &StateStore,
        spec: DepotSpec,
    ) -> std::result::Result<DepotOutcome, DepotFailure> {
        let before_ids = |error: Error| DepotFailure {
            depot_id: None,
            manifest_gid: None,
            error,
        };

        // 1. Manifest bytes → parsed manifest. Owned input: nothing is cloned here.
        let manifest_bytes: Vec<u8> = match spec.manifest {
            ManifestSource::File(path) => tokio::fs::read(&path)
                .await
                .map_err(Error::io_path(&path))
                .map_err(before_ids)?,
            ManifestSource::Bytes(bytes) => bytes,
        };
        if manifest_bytes.is_empty() {
            return Err(before_ids(Error::Manifest("manifest is empty".to_owned())));
        }
        let mut manifest = DepotManifest::from_bytes(&manifest_bytes).map_err(before_ids)?;

        // Depot id and manifest gid always come from the manifest's own metadata.
        let depot_id = manifest.depot_id();
        let manifest_gid = manifest.manifest_gid();

        self.emit(ProgressEvent::ManifestLoaded {
            depot_id,
            manifest_gid,
            creation_unix: manifest.creation_unix(),
        })
        .await;

        // Everything past this point knows the depot's identity - failures carry it.
        let result: Result<DepotOutcome> = async {
            // 2. Depot key - paired with the manifest in the request (never asked from Steam).
            let key = spec.key;
            if manifest.filenames_encrypted() {
                manifest.decrypt_filenames_with(&key)?;
            }
            if self.cancel.is_cancelled() {
                return Err(Error::Cancelled);
            }

            // 3. Previous-install state drives the verify/reuse strategy.
            let installed_gid = state.installed_gid(depot_id);
            let same_manifest = installed_gid == Some(manifest_gid);
            let old_manifest: Option<DepotManifest> = if same_manifest {
                // Same gid → Steam-style verify. No cached "old" manifest is consulted, so every
                // chunk of every existing file is verified against the manifest below.
                None
            } else {
                state
                    .cached_manifest_bytes(depot_id)
                    .and_then(|(gid, bytes)| {
                        if gid == manifest_gid {
                            return None;
                        }
                        let mut old = DepotManifest::from_bytes(&bytes).ok()?;
                        if old.filenames_encrypted() {
                            old.decrypt_filenames_with(&key).ok()?;
                        }
                        Some(old)
                    })
            };
            let old_by_path: HashMap<&str, &ManifestFile> = old_manifest
                .as_ref()
                .map(|m| m.files().iter().map(|f| (f.path.as_str(), f)).collect())
                .unwrap_or_default();

            // 4. Directory entries. Created from the full file list before any content file
            // task starts, so a nested file never has to create its own parent directory.
            for file in manifest.files() {
                if !file.is_directory() {
                    continue;
                }
                if let Some(rel) = util::safe_relative_path(&file.path) {
                    let dir = self.request.output_dir.join(rel);
                    tokio::fs::create_dir_all(&dir)
                        .await
                        .map_err(Error::io_path(&dir))?;
                }
            }

            // Each content file is consumed by exactly one task, so its chunk list can be
            // *moved* into the plan instead of cloned - a large depot's chunk metadata never
            // gets duplicated just to cross a `spawn_blocking` boundary.
            let content_files: Vec<ManifestFile> = manifest
                .into_files()
                .into_iter()
                .filter(|f| !f.is_directory() && !f.is_symlink())
                .collect();
            let files_total = content_files.len();
            let bytes_total: u64 = content_files.iter().map(|f| f.size).sum();

            self.emit(ProgressEvent::DepotStarted {
                depot_id,
                manifest_gid,
                files_total,
                bytes_total,
            })
            .await;

            // 5. Files concurrently; network concurrency is capped by the semaphore.
            let copy_parallelism = self.request.max_downloads.min(COPY_PARALLELISM);
            let ctx = DepotCtx {
                client,
                depot_id,
                key,
                staging_dir: state.staging_dir(),
                same_manifest,
                old_by_path,
                depot_cancel: self.cancel.child_token(),
                depot_bytes_completed: Arc::new(AtomicU64::new(0)),
                depot_downloaded: Arc::new(AtomicU64::new(0)),
                depot_bytes_total: bytes_total,
                downloads_sem: Arc::new(Semaphore::new(self.request.max_downloads)),
                copies_sem: Arc::new(Semaphore::new(copy_parallelism)),
                files_sem: Semaphore::new(
                    self.request
                        .max_downloads
                        .saturating_mul(FILE_PARALLELISM_FACTOR)
                        .clamp(FILE_PARALLELISM_MIN, FILE_PARALLELISM_MAX),
                ),
            };

            // Each file is consumed by exactly one task, so its chunk list can be *moved*
            // into the plan instead of cloned - a large depot's chunk metadata is never
            // duplicated just to cross a `spawn_blocking` boundary.
            let mut tasks = FuturesUnordered::new();
            for file in content_files {
                tasks.push(self.execute_file(&ctx, file));
            }

            let mut first_error: Option<Error> = None;
            while let Some(result) = tasks.next().await {
                if let Err(error) = result {
                    if first_error.is_none() {
                        first_error = Some(error);
                        // Point every other file task at the exit; they observe the token at their
                        // next chunk/plan boundary and unwind quickly.
                        ctx.depot_cancel.cancel();
                    }
                    // Keep draining so all in-flight futures settle before we return.
                }
            }
            if let Some(error) = first_error {
                return Err(error);
            }

            Ok(DepotOutcome {
                depot_id,
                manifest_gid,
                files: files_total,
                bytes_total,
                downloaded_bytes: ctx.depot_downloaded.load(Ordering::Relaxed),
                manifest_bytes,
            })
        }
        .await;

        result.map_err(|error| DepotFailure {
            depot_id: Some(depot_id),
            manifest_gid: Some(manifest_gid),
            error,
        })
    }

    /// Plan + execute one content file of a depot.
    async fn execute_file(&self, ctx: &DepotCtx<'_>, mut file: ManifestFile) -> Result<()> {
        // Bounded file concurrency: planning, the open write handle and the chunk queue all
        // live under this permit. Files queued behind it that see a cancellation (another
        // file failed) leave without planning or touching the disk.
        let _file_permit = ctx
            .files_sem
            .acquire()
            .await
            .map_err(|e| Error::TaskFailed(e.to_string()))?;
        if ctx.depot_cancel.is_cancelled() || self.cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }

        let rel = util::safe_relative_path(&file.path).ok_or_else(|| {
            Error::Manifest(format!(
                "unsafe or empty file path '{}' in manifest",
                file.path
            ))
        })?;
        let final_path = self.request.output_dir.join(&rel);
        let display_path = rel.clone();

        // Look the previous version of this exact file up once; it feeds both the
        // skip decisions and the chunk-reuse plan.
        let old_entry = ctx.old_by_path.get(file.path.as_str()).copied();
        let old_entry_matches = !ctx.same_manifest
            && old_entry.is_some_and(|e| {
                e.size == file.size && e.sha_content.is_some() && e.sha_content == file.sha_content
            });

        // Plan (blocking: one stat of the target, then positional reads for chunk
        // verification). The file's own chunks are moved in, not cloned.
        let plan = {
            let plan_input = PlanInput {
                final_path: final_path.clone(),
                size: file.size,
                chunks: std::mem::take(&mut file.chunks),
                old_chunks: old_entry.map(|e| e.chunks.clone()),
                old_entry_matches,
                verify_all: ctx.same_manifest,
            };
            tokio::task::spawn_blocking(move || plan_file(plan_input))
                .await
                .map_err(|e| Error::TaskFailed(e.to_string()))??
        };

        if plan.existed {
            self.emit(ProgressEvent::FileVerifying {
                depot_id: ctx.depot_id,
                path: display_path.clone(),
            })
            .await;
        }

        self.emit(ProgressEvent::FileStarted {
            depot_id: ctx.depot_id,
            path: display_path.clone(),
            size: file.size,
        })
        .await;

        if plan.skip {
            let prev = ctx
                .depot_bytes_completed
                .fetch_add(file.size, Ordering::Relaxed);
            self.emit(ProgressEvent::FileCompleted {
                depot_id: ctx.depot_id,
                path: display_path,
                depot_bytes_completed: prev + file.size,
                depot_bytes_total: ctx.depot_bytes_total,
            })
            .await;
            return Ok(());
        }

        if ctx.depot_cancel.is_cancelled() || self.cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }

        let write_path = if plan.staging {
            ctx.staging_dir.join(staging_name(&rel))
        } else {
            final_path.clone()
        };

        // Prepare the write target (blocking).
        let file_handle: Arc<std::fs::File> = {
            let write_path = write_path.clone();
            let fresh = plan.staging || plan.fresh;
            let size = file.size;
            let opened = tokio::task::spawn_blocking(move || -> Result<std::fs::File> {
                if let Some(parent) = write_path.parent() {
                    std::fs::create_dir_all(parent).map_err(Error::io_path(parent))?;
                }
                let file = if fresh {
                    std::fs::File::create(&write_path).map_err(Error::io_path(&write_path))?
                } else {
                    std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .truncate(false)
                        .open(&write_path)
                        .map_err(Error::io_path(&write_path))?
                };
                if fresh {
                    file.set_len(size).map_err(Error::io_path(&write_path))?;
                }
                Ok(file)
            })
            .await
            .map_err(|e| Error::TaskFailed(e.to_string()))??;
            Arc::new(opened)
        };

        // Bytes that will be *copied* count as "in place" once the copy has run, so the
        // progress seed deliberately excludes them (the copy jobs below add their run length
        // as they finish). Only chunks verified on disk in place - which are never moved -
        // start out complete.
        let done_bytes = Arc::new(AtomicU64::new(plan.reused_bytes - plan.copy_bytes));

        // Copy reused chunks into staging (parallel, coalesced local IO).
        let runs = coalesce_copy_runs(&plan.copies);
        if !runs.is_empty() {
            let source_path = final_path.clone();
            let handle = Arc::clone(&file_handle);
            let staged_done = Arc::clone(&done_bytes);
            let depot_cancel = ctx.depot_cancel.clone();
            let mut copy_jobs = FuturesUnordered::new();
            for run in runs {
                if depot_cancel.is_cancelled() || self.cancel.is_cancelled() {
                    return Err(Error::Cancelled);
                }
                let permit = Arc::clone(&ctx.copies_sem)
                    .acquire_owned()
                    .await
                    .map_err(|e| Error::TaskFailed(e.to_string()))?;
                let source_path = source_path.clone();
                let handle = Arc::clone(&handle);
                let done = Arc::clone(&staged_done);
                copy_jobs.push(tokio::task::spawn_blocking(move || -> Result<()> {
                    let _permit = permit;
                    let source =
                        std::fs::File::open(&source_path).map_err(Error::io_path(&source_path))?;
                    // One buffer per run, reused across its strided reads/writes.
                    let mut buf = vec![0u8; run.len.min(COPY_STRIDE) as usize];
                    let mut remaining = run.len;
                    let mut src = run.source_offset;
                    let mut dst = run.dest_offset;
                    while remaining > 0 {
                        let stride = remaining.min(buf.len() as u64) as usize;
                        fileio::read_at(&source, &mut buf[..stride], src).map_err(Error::Io)?;
                        fileio::write_at(&handle, &buf[..stride], dst).map_err(Error::Io)?;
                        src += stride as u64;
                        dst += stride as u64;
                        remaining -= stride as u64;
                    }
                    done.fetch_add(run.len, Ordering::Relaxed);
                    Ok(())
                }));
            }
            while let Some(result) = copy_jobs.next().await {
                result.map_err(|e| Error::TaskFailed(e.to_string()))??;
            }
        }

        // Download the remaining chunks. Each future takes its network permit *itself*, when
        // it is first polled: acquiring permits up front and parking them inside futures that
        // nobody polls yet deadlocks as soon as a file has more chunks than `max_downloads`.
        // `buffer_unordered` polls up to `max_downloads` of this file's chunks at a time (more
        // would only queue on the semaphore) and starts the next one as each finishes.
        {
            let mut jobs = futures::stream::iter(dedup_downloads(plan.downloads))
                .map(|(chunk, extra_offsets)| {
                    let sem = Arc::clone(&ctx.downloads_sem);
                    let file_handle = Arc::clone(&file_handle);
                    let done_bytes = Arc::clone(&done_bytes);
                    let display_path = display_path.clone();
                    let file_size = file.size;
                    async move {
                        let permit = sem
                            .acquire_owned()
                            .await
                            .map_err(|e| Error::TaskFailed(e.to_string()))?;
                        self.download_chunk(
                            ctx,
                            ChunkJob {
                                file_handle,
                                done_bytes,
                                display_path,
                                file_size,
                                chunk,
                                extra_offsets,
                                _permit: permit,
                            },
                        )
                        .await
                    }
                })
                .buffer_unordered(self.request.max_downloads);
            while let Some(result) = jobs.next().await {
                result?;
            }
        }

        if plan.staging {
            // About to swap the staging file over the real one: a cancellation that lands
            // after even a single chunk of the new content is missing must leave the old file
            // alone, never promote a half-written staging file.
            if ctx.depot_cancel.is_cancelled() || self.cancel.is_cancelled() {
                return Err(Error::Cancelled);
            }
        }

        // Finalize (blocking): correct the length, swap staging over the final path,
        // apply executable bits.
        {
            let write_path = write_path.clone();
            let is_staging = plan.staging;
            let size = file.size;
            let exec = file.is_executable();
            let final_path = final_path.clone();
            // Every chunk and copy future has settled and dropped its share, so this task
            // holds the only reference left. Moving it (instead of cloning again) is what
            // makes the handle below close before the rename - and renaming over a handle
            // that is still open is not portable.
            let handle = file_handle;
            debug_assert_eq!(Arc::strong_count(&handle), 1);
            tokio::task::spawn_blocking(move || -> Result<()> {
                {
                    let meta = handle.metadata().map_err(Error::Io)?;
                    if meta.len() != size {
                        handle.set_len(size).map_err(Error::Io)?;
                    }
                }
                drop(handle); // close before the rename
                if is_staging {
                    if final_path.exists() {
                        std::fs::remove_file(&final_path).map_err(Error::io_path(&final_path))?;
                    }
                    std::fs::rename(&write_path, &final_path)
                        .map_err(Error::io_path(&final_path))?;
                }
                #[cfg(unix)]
                if exec {
                    use std::os::unix::fs::PermissionsExt;
                    let meta =
                        std::fs::metadata(&final_path).map_err(Error::io_path(&final_path))?;
                    let mut perms = meta.permissions();
                    perms.set_mode(perms.mode() | 0o111);
                    std::fs::set_permissions(&final_path, perms)
                        .map_err(Error::io_path(&final_path))?;
                }
                Ok(())
            })
            .await
            .map_err(|e| Error::TaskFailed(e.to_string()))??;
        }

        let prev = ctx
            .depot_bytes_completed
            .fetch_add(file.size, Ordering::Relaxed);
        self.emit(ProgressEvent::FileCompleted {
            depot_id: ctx.depot_id,
            path: display_path,
            depot_bytes_completed: prev + file.size,
            depot_bytes_total: ctx.depot_bytes_total,
        })
        .await;
        Ok(())
    }

    /// Fetch, decrypt, verify and write a single chunk.
    async fn download_chunk(&self, ctx: &DepotCtx<'_>, job: ChunkJob) -> Result<()> {
        let ChunkJob {
            file_handle,
            done_bytes,
            display_path,
            file_size,
            chunk,
            extra_offsets,
            _permit,
        } = job;

        if ctx.depot_cancel.is_cancelled() || self.cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }

        let chunk_hex = util::to_hex_lower(&chunk.id);

        // Decrypt + verify + write at the chunk's offset(s) (blocking), run by the CDN client
        // for each copy it fetches until one is good - a corrupt response from one server is
        // retried on the next instead of failing the depot. The body is moved into the
        // blocking task and handed to the chunk pipeline as a slice: no second copy of the
        // chunk, and the pipeline reuses this thread's scratch buffers.
        let key = ctx.key;
        let len_uncompressed = chunk.len_uncompressed;
        let adler32 = chunk.adler32;
        let offsets: Arc<[u64]> = std::iter::once(chunk.offset).chain(extra_offsets).collect();
        let copies = offsets.len() as u64;
        let process = |raw: bytes::Bytes| {
            let handle = Arc::clone(&file_handle);
            let offsets = Arc::clone(&offsets);
            let chunk_hex = chunk_hex.clone();
            async move {
                tokio::task::spawn_blocking(move || {
                    chunk::process_chunk_at(
                        &raw,
                        &key,
                        len_uncompressed,
                        adler32,
                        &chunk_hex,
                        &handle,
                        &offsets,
                    )
                })
                .await
                .unwrap_or_else(|e| {
                    Err(chunk::ChunkFailure {
                        kind: chunk::ChunkFailureKind::Local,
                        error: Error::TaskFailed(e.to_string()),
                    })
                })
            }
        };
        // `depot_cancel` is a child of the run's token, so it also fires on `cancel()`; the
        // client watches it during every request - a hanging CDN must never delay a
        // cancellation by the request timeout.
        let network_len = ctx
            .client
            .fetch_chunk(
                ctx.depot_id,
                &chunk_hex,
                chunk.len_compressed,
                &ctx.depot_cancel,
                process,
            )
            .await?;

        // Every placement of a deduplicated chunk is real file content, so it counts once per
        // offset towards the uncompressed totals; the network body only once.
        let written = u64::from(chunk.len_uncompressed) * copies;
        let downloaded = self
            .total_downloaded
            .fetch_add(network_len, Ordering::Relaxed)
            + network_len;
        let uncompressed = self
            .total_uncompressed
            .fetch_add(written, Ordering::Relaxed)
            + written;
        ctx.depot_downloaded
            .fetch_add(network_len, Ordering::Relaxed);
        let file_done = done_bytes.fetch_add(written, Ordering::Relaxed) + written;

        self.emit_best_effort(ProgressEvent::ChunkCompleted {
            depot_id: ctx.depot_id,
            path: display_path,
            file_bytes_completed: file_done,
            file_size,
            downloaded_increment: network_len,
            uncompressed_increment: written,
            total_downloaded: downloaded,
            total_uncompressed: uncompressed,
        });
        Ok(())
    }

    async fn emit(&self, event: ProgressEvent) {
        let _ = self.events.send(event).await;
    }

    fn emit_best_effort(&self, event: ProgressEvent) {
        let _ = self.events.try_send(event);
    }
}

/// Everything [`plan_file`] needs; owned so it can move into `spawn_blocking`.
struct PlanInput {
    final_path: PathBuf,
    size: u64,
    /// Moved in from the file entry; the plan hands the survivors on to the downloader.
    chunks: Vec<ManifestChunk>,
    old_chunks: Option<Vec<ManifestChunk>>,
    old_entry_matches: bool,
    verify_all: bool,
}

/// Decide, for one file, which chunks can be reused from disk and which must be downloaded.
///
/// Pure filesystem work - runs inside `spawn_blocking`. It also reports whether the target
/// existed, which is the single stat the caller needs to decide between `FileVerifying` and a
/// plain start (planning used to be handed to a second stat of the same file).
fn plan_file(input: PlanInput) -> Result<FilePlan> {
    let PlanInput {
        final_path,
        size,
        chunks,
        old_chunks,
        old_entry_matches,
        verify_all,
    } = input;

    let existing_len = std::fs::metadata(&final_path)
        .ok()
        .filter(|m| m.is_file())
        .map(|m| m.len());
    let existed = existing_len.is_some();

    // Empty content file: only the length differs from "nothing".
    if size == 0 || chunks.is_empty() {
        return Ok(match existing_len {
            Some(0) => FilePlan {
                existed,
                skip: true,
                ..FilePlan::default()
            },
            Some(_) => FilePlan {
                existed,
                ..FilePlan::default()
            }, // exists, wrong size → finalize truncates
            None => FilePlan {
                fresh: true,
                ..FilePlan::default()
            },
        });
    }

    let Some(existing_len) = existing_len else {
        return Ok(FilePlan {
            existed,
            downloads: chunks,
            fresh: true,
            ..FilePlan::default()
        });
    };

    // Fast path: the previous install's manifest says this file has identical content and the
    // on-disk length agrees → skip without reading a single byte.
    if old_entry_matches && existing_len == size {
        return Ok(FilePlan {
            existed,
            skip: true,
            ..FilePlan::default()
        });
    }

    // Chunk-id reuse: when we know what the previous version looked like, reuse every on-disk
    // chunk whose (id, adler) matches a chunk of the new manifest. Chunks that moved are
    // copied into a staging file; if none moved, the file is patched in place. The rest is
    // downloaded.
    if !verify_all {
        if let Some(old_chunks) = &old_chunks {
            if !old_chunks.is_empty() {
                return plan_reuse_from_old(&final_path, size, chunks, old_chunks, existing_len)
                    .map(|mut plan| {
                        plan.existed = existed;
                        plan
                    });
            }
        }
    }

    // Steam-style verification: read every chunk position and check it against the manifest.
    plan_verify_in_place(&final_path, chunks, existing_len).map(|mut plan| {
        plan.existed = existed;
        plan
    })
}

fn plan_reuse_from_old(
    final_path: &Path,
    size: u64,
    chunks: Vec<ManifestChunk>,
    old_chunks: &[ManifestChunk],
    existing_len: u64,
) -> Result<FilePlan> {
    let _ = size;
    let mut new_by_id: HashMap<[u8; 20], Vec<usize>> = HashMap::new();
    for (index, chunk) in chunks.iter().enumerate() {
        new_by_id.entry(chunk.id).or_default().push(index);
    }

    let mut covered = vec![false; chunks.len()];
    let mut copies = Vec::new();

    // A bad/unreadable existing file simply degrades to a full download.
    let Ok(source) = std::fs::File::open(final_path) else {
        return Ok(FilePlan {
            downloads: chunks,
            fresh: true,
            ..FilePlan::default()
        });
    };

    // One read buffer, reused for every chunk of this file: a file's chunks are the same size
    // in practice, so this is a single allocation instead of one per chunk.
    let mut buf: Vec<u8> = Vec::new();
    for old_chunk in old_chunks {
        let Some(indices) = new_by_id.get(&old_chunk.id) else {
            continue;
        };
        if indices.is_empty() {
            continue;
        }
        if u64::from(old_chunk.len_uncompressed) == 0
            || old_chunk.offset + u64::from(old_chunk.len_uncompressed) > existing_len
        {
            continue;
        }
        buf.clear();
        buf.resize(old_chunk.len_uncompressed as usize, 0);
        if fileio::read_at(&source, &mut buf, old_chunk.offset).is_err() {
            continue;
        }
        if util::adler32_seed0(&buf) != old_chunk.adler32 {
            continue;
        }
        // This on-disk chunk is intact and matches new chunks with the same id.
        for &index in indices {
            if covered[index] {
                continue;
            }
            copies.push(CopyOp {
                chunk: chunks[index].clone(),
                source_offset: old_chunk.offset,
            });
            covered[index] = true;
        }
        new_by_id.insert(old_chunk.id, Vec::new());
    }

    // Uncovered chunks are the download set; move the covered ones to the end in place so the
    // vector the plan returns is the same allocation `chunks` arrived in.
    let mut downloads = chunks;
    let mut write = 0usize;
    #[allow(clippy::needless_range_loop)]
    for read in 0..downloads.len() {
        if !covered[read] {
            downloads.swap(write, read);
            write += 1;
        }
    }
    downloads.truncate(write);

    let copy_bytes = copies
        .iter()
        .map(|op| u64::from(op.chunk.len_uncompressed))
        .sum();

    // Every reused chunk already sits at its new offset (an update that only changed some
    // chunks in place, or appended/truncated): there is nothing to move, so patch the file in
    // place - exactly like a verify run - instead of rebuilding the whole file through
    // staging. For a large file with a small change this turns "read + write the entire file
    // again" into "write only the changed chunks".
    if copies.iter().all(|op| op.source_offset == op.chunk.offset) {
        return Ok(FilePlan {
            downloads,
            reused_bytes: copy_bytes,
            copy_bytes: 0,
            ..FilePlan::default()
        });
    }

    // Staging path: copies arrive in old-manifest order; destination order is what
    // `coalesce_copy_runs` merges on (and what keeps the staging writes sequential).
    copies.sort_unstable_by_key(|op| (op.chunk.offset, op.source_offset));

    Ok(FilePlan {
        downloads,
        copies,
        reused_bytes: copy_bytes,
        copy_bytes,
        staging: true,
        ..FilePlan::default()
    })
}

fn plan_verify_in_place(
    final_path: &Path,
    chunks: Vec<ManifestChunk>,
    existing_len: u64,
) -> Result<FilePlan> {
    let mut chunks = chunks;
    let mut reused_bytes = 0u64;

    let source = std::fs::File::open(final_path).ok();
    // One read buffer for the whole file's verification pass.
    let mut buf: Vec<u8> = Vec::new();
    // Bad chunks are moved to the end in place, so the plan reuses the vector it was given.
    let mut write = 0usize;
    #[allow(clippy::needless_range_loop)]
    for read in 0..chunks.len() {
        let readable =
            chunks[read].offset + u64::from(chunks[read].len_uncompressed) <= existing_len;
        let ok = if let (Some(source), true) = (&source, readable) {
            buf.clear();
            buf.resize(chunks[read].len_uncompressed as usize, 0);
            fileio::read_at(source, &mut buf, chunks[read].offset).is_ok()
                && util::adler32_seed0(&buf) == chunks[read].adler32
        } else {
            false
        };
        if ok {
            reused_bytes += u64::from(chunks[read].len_uncompressed);
        } else {
            chunks.swap(write, read);
            write += 1;
        }
    }
    chunks.truncate(write);

    Ok(FilePlan {
        downloads: chunks,
        reused_bytes,
        copy_bytes: 0,
        ..FilePlan::default()
    })
}

/// Flat, collision-free staging file name for a manifest-relative path.
fn staging_name(rel: &Path) -> PathBuf {
    PathBuf::from(format!(
        "{}.tmp",
        util::to_hex_lower(&util::sha1(rel.to_string_lossy().as_bytes()))
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    //! End-to-end tests against a fake CDN ([`wiremock`]): fresh download, Steam-style verify
    //! re-run, chunk-reuse update, per-depot failure isolation, and cancellation. No Steam
    //! connectivity involved - the wire format is byte-identical to the real CDN's.

    use super::*;
    use std::time::Duration;

    use prost::Message;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::cdn::chunk::tests::{PackMode, pack_chunk};
    use crate::manifest::parse::tests::TEST_DEPOT_KEY;

    const APP_ID: u32 = 480;
    const DEPOT_ID: u32 = 481;
    const CHUNK_SIZE: usize = 128 * 1024;

    /// The fixture key as the API receives it: a 64-character hex string.
    fn test_key_hex() -> String {
        util::to_hex_lower(&TEST_DEPOT_KEY)
    }

    // ── fixture construction ─────────────────────────────────────────────────

    /// Steam's chunk encryption + compression, as served by the CDN (see [`crate::cdn::chunk`]).
    fn served_chunk(
        content: &[u8],
    ) -> (
        steam_protobuf_rs::content_manifest_payload::file_mapping::ChunkData,
        Vec<u8>,
    ) {
        use steam_protobuf_rs::content_manifest_payload::file_mapping::ChunkData;
        let body = pack_chunk(content, &TEST_DEPOT_KEY, PackMode::Zstd);
        let chunk = ChunkData {
            sha: Some(util::sha1(content).to_vec()),
            crc: Some(util::adler32_seed0(content)),
            offset: Some(0),
            cb_original: Some(content.len() as u32),
            cb_compressed: Some(body.len() as u32),
        };
        (chunk, body)
    }

    fn chunks_with_offsets(
        content: &[u8],
    ) -> Vec<(
        steam_protobuf_rs::content_manifest_payload::file_mapping::ChunkData,
        Vec<u8>,
    )> {
        let mut offset = 0u64;
        content
            .chunks(CHUNK_SIZE)
            .map(|slice| {
                let (mut chunk, body) = served_chunk(slice);
                chunk.offset = Some(offset);
                offset += u64::from(chunk.cb_original.expect("cb_original"));
                (chunk, body)
            })
            .collect()
    }

    fn build_manifest(depot_id: u32, gid: u64, files: &[(&str, Vec<u8>, u32)]) -> Vec<u8> {
        use crate::manifest::parse::{EOF_MAGIC, METADATA_MAGIC, PAYLOAD_MAGIC, SIGNATURE_MAGIC};
        use steam_protobuf_rs::content_manifest_payload::FileMapping;
        use steam_protobuf_rs::{
            ContentManifestMetadata, ContentManifestPayload, ContentManifestSignature,
        };

        let mut mappings = Vec::new();
        for (name, content, flags) in files {
            let (chunks, size) = if content.is_empty() {
                (Vec::new(), 0)
            } else {
                let pairs = chunks_with_offsets(content);
                let size = pairs
                    .iter()
                    .map(|(c, _)| u64::from(c.cb_original.expect("cb_original")))
                    .sum();
                (pairs.into_iter().map(|(c, _)| c).collect(), size)
            };
            mappings.push(FileMapping {
                filename: Some((*name).to_owned()),
                size: Some(size),
                flags: Some(*flags),
                sha_filename: Some(vec![0; 20]),
                sha_content: Some(util::sha1(content).to_vec()),
                chunks,
                linktarget: None,
            });
        }

        let payload = ContentManifestPayload { mappings };
        let metadata = ContentManifestMetadata {
            depot_id: Some(depot_id),
            gid_manifest: Some(gid),
            creation_time: Some(1_700_000_000),
            filenames_encrypted: Some(false),
            cb_disk_original: None,
            cb_disk_compressed: None,
            unique_chunks: None,
            crc_encrypted: None,
            crc_clear: None,
        };
        let signature = ContentManifestSignature {
            signature: Some(vec![9; 8]),
        };

        let mut out = Vec::new();
        let payload_bytes = payload.encode_to_vec();
        let metadata_bytes = metadata.encode_to_vec();
        let signature_bytes = signature.encode_to_vec();
        for (magic, bytes) in [
            (PAYLOAD_MAGIC, &payload_bytes),
            (METADATA_MAGIC, &metadata_bytes),
            (SIGNATURE_MAGIC, &signature_bytes),
        ] {
            out.extend_from_slice(&magic.to_le_bytes());
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(bytes);
        }
        out.extend_from_slice(&EOF_MAGIC.to_le_bytes());
        out
    }

    /// Write the manifest bytes to a real file (the public API is path-based) and download it.
    async fn run_download(
        out: &Path,
        manifest: Vec<u8>,
        key_hex: &str,
        server_addr: String,
    ) -> DownloadReport {
        let downloader = crate::DepotDownloader::builder()
            .cdn_servers(vec![CdnServer::http(&server_addr).expect("address")])
            .build()
            .expect("downloader");
        let request = DownloadRequest::builder()
            .app_id(APP_ID)
            .depots([(manifest, key_hex)])
            .output_dir(out)
            .build()
            .expect("request");
        let mut handle = downloader.download(request);
        while let Some(event) = handle.events().recv().await {
            if matches!(event, ProgressEvent::Finished { .. }) {
                break;
            }
        }
        handle.join().await.expect("join")
    }

    async fn mount_chunks(
        server: &MockServer,
        depot_id: u32,
        served: &[(
            steam_protobuf_rs::content_manifest_payload::file_mapping::ChunkData,
            Vec<u8>,
        )],
    ) {
        for (chunk, body) in served {
            let hex = util::to_hex_lower(chunk.sha.as_ref().expect("sha"));
            Mock::given(method("GET"))
                .and(path(format!("/depot/{depot_id}/chunk/{hex}")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
                .mount(server)
                .await;
        }
    }

    // ── tests ────────────────────────────────────────────────────────────────

    /// Download through an explicit, ordered server list.
    async fn run_download_servers(
        out: &Path,
        manifest: Vec<u8>,
        key_hex: &str,
        servers: &[&MockServer],
    ) -> DownloadReport {
        let downloader = crate::DepotDownloader::builder()
            .cdn_servers(
                servers
                    .iter()
                    .map(|s| CdnServer::http(&s.address().to_string()).expect("address"))
                    .collect::<Vec<_>>(),
            )
            .build()
            .expect("downloader");
        let request = DownloadRequest::builder()
            .app_id(APP_ID)
            .depots([(manifest, key_hex)])
            .output_dir(out)
            .build()
            .expect("request");
        let mut handle = downloader.download(request);
        while let Some(event) = handle.events().recv().await {
            if matches!(event, ProgressEvent::Finished { .. }) {
                break;
            }
        }
        handle.join().await.expect("join")
    }

    /// A server that returns a corrupt chunk (right length, bad content) no longer fails the
    /// depot: the chunk is retried on the next server.
    #[tokio::test]
    async fn corrupt_chunk_is_retried_on_next_server() {
        let content: Vec<u8> = (0..CHUNK_SIZE).map(|i| (i % 173) as u8).collect();
        let manifest = build_manifest(DEPOT_ID, 3400, &[("one.bin", content.clone(), 0)]);
        let served = chunks_with_offsets(&content);
        let (chunk, good_body) = served[0].clone();

        // Same length, one flipped byte mid-ciphertext: decrypts (padding intact) to garbage.
        let mut bad_body = good_body.clone();
        let mid = bad_body.len() / 2;
        bad_body[mid] ^= 0xFF;

        let bad = MockServer::start().await;
        mount_chunks(&bad, DEPOT_ID, &[(chunk.clone(), bad_body)]).await;
        let good = MockServer::start().await;
        mount_chunks(&good, DEPOT_ID, &[(chunk, good_body)]).await;

        let out = tempfile::tempdir().expect("tempdir");
        // One chunk → the round-robin cursor starts at the first (bad) server.
        let report =
            run_download_servers(out.path(), manifest, &test_key_hex(), &[&bad, &good]).await;
        assert!(report.is_ok(), "depots: {:?}", report.depots);
        assert_eq!(
            bad.received_requests().await.expect("recording").len(),
            1,
            "the bad server was tried first"
        );
        assert_eq!(
            std::fs::read(out.path().join("one.bin")).expect("one.bin"),
            content
        );
    }

    /// A wrong depot key is not "rotated away" across every server: one extra server is
    /// tried (a corrupted last block looks identical), then the depot fails.
    #[tokio::test]
    async fn wrong_key_stops_after_two_servers() {
        let content: Vec<u8> = (0..CHUNK_SIZE).map(|i| (i % 151) as u8).collect();
        let manifest = build_manifest(DEPOT_ID, 3500, &[("one.bin", content.clone(), 0)]);
        let served = chunks_with_offsets(&content);

        let mut servers = Vec::new();
        for _ in 0..4 {
            let server = MockServer::start().await;
            mount_chunks(&server, DEPOT_ID, &served).await;
            servers.push(server);
        }
        let refs: Vec<&MockServer> = servers.iter().collect();

        let out = tempfile::tempdir().expect("tempdir");
        let report = run_download_servers(out.path(), manifest, &"ab".repeat(32), &refs).await;
        assert!(!report.is_ok(), "a wrong key must fail the depot");

        let mut requests = 0;
        for server in &servers {
            requests += server.received_requests().await.expect("recording").len();
        }
        assert_eq!(
            requests, 2,
            "wrong key: exactly one retry, not a full rotation"
        );
    }

    /// Regression: a file with more chunks than `max_downloads` used to deadlock - permits
    /// were taken up front and parked inside futures that were not polled until every chunk
    /// had a permit.
    #[tokio::test]
    async fn file_with_more_chunks_than_max_downloads_completes() {
        let server = MockServer::start().await;
        let content: Vec<u8> = (0..20 * CHUNK_SIZE + 77).map(|i| (i % 241) as u8).collect();
        let v1 = build_manifest(DEPOT_ID, 3000, &[("big.bin", content.clone(), 0)]);
        mount_chunks(&server, DEPOT_ID, &chunks_with_offsets(&content)).await;

        let out = tempfile::tempdir().expect("tempdir");
        let key = test_key_hex();
        let report = tokio::time::timeout(
            Duration::from_secs(30),
            run_download(out.path(), v1, &key, server.address().to_string()),
        )
        .await
        .expect("download must not deadlock");
        assert!(report.is_ok(), "depots: {:?}", report.depots);
        assert_eq!(
            std::fs::read(out.path().join("big.bin")).expect("big.bin"),
            content
        );
    }

    /// Many files at once stay under the bounded file concurrency and all complete.
    #[tokio::test]
    async fn many_files_complete_under_bounded_file_concurrency() {
        let server = MockServer::start().await;
        let files: Vec<(String, Vec<u8>)> = (0..FILE_PARALLELISM_MAX + 50)
            .map(|n| {
                let content: Vec<u8> = (0..1024 + n).map(|i| ((i * 7 + n) % 253) as u8).collect();
                (format!("data/file_{n}.bin"), content)
            })
            .collect();
        let entries: Vec<(&str, Vec<u8>, u32)> = files
            .iter()
            .map(|(name, content)| (name.as_str(), content.clone(), 0))
            .collect();
        let manifest = build_manifest(DEPOT_ID, 3100, &entries);
        for (_, content) in &files {
            mount_chunks(&server, DEPOT_ID, &chunks_with_offsets(content)).await;
        }

        let out = tempfile::tempdir().expect("tempdir");
        let key = test_key_hex();
        let report = tokio::time::timeout(
            Duration::from_secs(60),
            run_download(out.path(), manifest, &key, server.address().to_string()),
        )
        .await
        .expect("download must finish");
        assert!(report.is_ok(), "depots: {:?}", report.depots);
        for (name, content) in &files {
            assert_eq!(
                &std::fs::read(out.path().join(name)).expect("file"),
                content
            );
        }
    }

    /// A chunk repeated inside one file is fetched from the CDN exactly once and written to
    /// every offset that holds it.
    #[tokio::test]
    async fn repeated_chunk_in_file_is_fetched_once() {
        let server = MockServer::start().await;
        let block: Vec<u8> = (0..CHUNK_SIZE).map(|i| (i % 97) as u8).collect();
        let other: Vec<u8> = (0..CHUNK_SIZE).map(|i| (i % 89) as u8).collect();
        let mut content = block.clone();
        content.extend_from_slice(&other);
        content.extend_from_slice(&block);
        content.extend_from_slice(&block);
        let v1 = build_manifest(DEPOT_ID, 3200, &[("dup.bin", content.clone(), 0)]);

        let (block_chunk, block_body) = served_chunk(&block);
        Mock::given(method("GET"))
            .and(path(format!(
                "/depot/{DEPOT_ID}/chunk/{}",
                util::to_hex_lower(block_chunk.sha.as_ref().expect("sha"))
            )))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(block_body))
            .expect(1)
            .mount(&server)
            .await;
        let (other_chunk, other_body) = served_chunk(&other);
        mount_chunks(&server, DEPOT_ID, &[(other_chunk, other_body)]).await;

        let out = tempfile::tempdir().expect("tempdir");
        let report = run_download(
            out.path(),
            v1,
            &test_key_hex(),
            server.address().to_string(),
        )
        .await;
        assert!(report.is_ok(), "depots: {:?}", report.depots);
        assert_eq!(report.uncompressed_bytes, content.len() as u64);
        assert_eq!(
            std::fs::read(out.path().join("dup.bin")).expect("dup.bin"),
            content
        );
        server.verify().await;
    }

    /// An update whose reused chunks all keep their offsets is patched in place: no staging
    /// rebuild (same inode), only the changed chunk crosses the network.
    #[cfg(unix)]
    #[tokio::test]
    async fn offset_preserving_update_patches_in_place() {
        use std::os::unix::fs::MetadataExt;

        let server1 = MockServer::start().await;
        let v1_content: Vec<u8> = (0..4 * CHUNK_SIZE).map(|i| (i % 211) as u8).collect();
        let v1 = build_manifest(DEPOT_ID, 3300, &[("pak.bin", v1_content.clone(), 0)]);
        mount_chunks(&server1, DEPOT_ID, &chunks_with_offsets(&v1_content)).await;

        let out = tempfile::tempdir().expect("tempdir");
        let report = run_download(
            out.path(),
            v1,
            &test_key_hex(),
            server1.address().to_string(),
        )
        .await;
        assert!(report.is_ok(), "depots: {:?}", report.depots);
        let inode_before = std::fs::metadata(out.path().join("pak.bin"))
            .expect("pak.bin")
            .ino();

        // v2: third chunk changed in place, plus a shorter tail (truncation).
        let mut v2_content = v1_content.clone();
        for byte in &mut v2_content[2 * CHUNK_SIZE..3 * CHUNK_SIZE] {
            *byte = byte.wrapping_add(1);
        }
        v2_content.truncate(3 * CHUNK_SIZE + 1000);
        let v2 = build_manifest(DEPOT_ID, 3301, &[("pak.bin", v2_content.clone(), 0)]);

        let server2 = MockServer::start().await;
        let v2_chunks = chunks_with_offsets(&v2_content);
        // Only the changed chunk and the new short tail are served; anything else 404s.
        mount_chunks(&server2, DEPOT_ID, &v2_chunks[2..]).await;
        let report = run_download(
            out.path(),
            v2,
            &test_key_hex(),
            server2.address().to_string(),
        )
        .await;
        assert!(report.is_ok(), "depots: {:?}", report.depots);
        let tail_and_changed: u64 = v2_chunks[2..].iter().map(|(_, b)| b.len() as u64).sum();
        assert_eq!(report.downloaded_bytes, tail_and_changed);
        assert_eq!(
            std::fs::read(out.path().join("pak.bin")).expect("pak.bin"),
            v2_content
        );
        assert_eq!(
            std::fs::metadata(out.path().join("pak.bin"))
                .expect("pak.bin")
                .ino(),
            inode_before,
            "an offset-preserving update must patch in place, not rebuild via staging"
        );
    }

    #[test]
    fn dedup_groups_identical_chunks_and_keeps_order() {
        let chunk = |id: u8, offset: u64| ManifestChunk {
            id: [id; 20],
            adler32: u32::from(id),
            offset,
            len_uncompressed: 10,
            len_compressed: 12,
        };
        let grouped = dedup_downloads(vec![chunk(1, 0), chunk(2, 10), chunk(1, 20), chunk(1, 30)]);
        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped[0].0.offset, 0);
        assert_eq!(grouped[0].1, vec![20, 30]);
        assert_eq!(grouped[1].0.offset, 10);
        assert!(grouped[1].1.is_empty());
    }

    #[tokio::test]
    async fn fresh_download_then_verify_rerun_downloads_nothing() {
        let server = MockServer::start().await;
        let content: Vec<u8> = (0..2 * CHUNK_SIZE + 12_345)
            .map(|i| (i % 251) as u8)
            .collect();
        let v1 = build_manifest(
            DEPOT_ID,
            1000,
            &[
                ("bin/game.exe", content.clone(), 32),
                ("readme.txt", Vec::new(), 0),
            ],
        );
        mount_chunks(&server, DEPOT_ID, &chunks_with_offsets(&content)).await;

        let out = tempfile::tempdir().expect("tempdir");
        let report = run_download(
            out.path(),
            v1.clone(),
            &test_key_hex(),
            server.address().to_string(),
        )
        .await;
        assert!(report.is_ok(), "depots: {:?}", report.depots);
        assert_eq!(
            std::fs::read(out.path().join("bin/game.exe")).expect("game.exe"),
            content
        );
        assert_eq!(
            std::fs::metadata(out.path().join("readme.txt"))
                .expect("readme.txt")
                .len(),
            0
        );

        let state = StateStore::load(out.path());
        assert_eq!(state.installed_gid(DEPOT_ID), Some(1000));

        // Re-run with the SAME manifest: full Steam-style verification, zero network. The new
        // server has no chunk mocks - any wrongful re-download turns into a 404 and fails.
        let server2 = MockServer::start().await;
        let report = run_download(
            out.path(),
            v1,
            &test_key_hex(),
            server2.address().to_string(),
        )
        .await;
        assert!(report.is_ok(), "depots: {:?}", report.depots);
        assert_eq!(report.downloaded_bytes, 0, "verify must not re-download");
        assert_eq!(
            std::fs::read(out.path().join("bin/game.exe")).expect("game.exe"),
            content
        );
    }

    #[tokio::test]
    async fn update_downloads_only_changed_chunks_and_keeps_foreign_files() {
        let server1 = MockServer::start().await;
        let v1_content: Vec<u8> = (0..3 * CHUNK_SIZE).map(|i| (i % 199) as u8).collect();
        let pak_content: Vec<u8> = (0..2 * CHUNK_SIZE).map(|i| (i % 61) as u8).collect();
        let v1 = build_manifest(
            DEPOT_ID,
            2000,
            &[
                ("bin/game.exe", v1_content.clone(), 32),
                ("data/pak.bin", pak_content.clone(), 0),
            ],
        );
        mount_chunks(&server1, DEPOT_ID, &chunks_with_offsets(&v1_content)).await;
        mount_chunks(&server1, DEPOT_ID, &chunks_with_offsets(&pak_content)).await;

        let out = tempfile::tempdir().expect("tempdir");
        let report = run_download(
            out.path(),
            v1,
            &test_key_hex(),
            server1.address().to_string(),
        )
        .await;
        assert!(report.is_ok(), "depots: {:?}", report.depots);

        // A file that is NOT in any manifest: must survive every download untouched.
        std::fs::create_dir_all(out.path().join("mods")).expect("mods dir");
        std::fs::write(out.path().join("mods/extra.ini"), b"keep me").expect("mods file");

        // v2: one additional chunk on game.exe; pak.bin unchanged (same SHA-1 → skipped unread).
        let mut v2_content = v1_content.clone();
        v2_content.extend((0..CHUNK_SIZE).map(|i| (i % 71) as u8));
        let v2 = build_manifest(
            DEPOT_ID,
            2001,
            &[
                ("bin/game.exe", v2_content.clone(), 32),
                ("data/pak.bin", pak_content.clone(), 0),
            ],
        );

        // Only the NEW chunk is served. Any reuse failure → 404 → depot failure → test fails.
        let server2 = MockServer::start().await;
        let v2_chunks = chunks_with_offsets(&v2_content);
        let (new_chunk, new_body) = v2_chunks.last().expect("new chunk").clone();
        mount_chunks(&server2, DEPOT_ID, &[(new_chunk, new_body)]).await;

        let report = run_download(
            out.path(),
            v2,
            &test_key_hex(),
            server2.address().to_string(),
        )
        .await;
        assert!(report.is_ok(), "depots: {:?}", report.depots);
        assert_eq!(
            std::fs::read(out.path().join("bin/game.exe")).expect("game.exe"),
            v2_content
        );
        assert_eq!(
            std::fs::read(out.path().join("data/pak.bin")).expect("pak.bin"),
            pak_content
        );
        assert_eq!(
            std::fs::read(out.path().join("mods/extra.ini")).expect("extra.ini"),
            b"keep me"
        );

        let state = StateStore::load(out.path());
        assert_eq!(state.installed_gid(DEPOT_ID), Some(2001));
    }

    /// Progress accounting for the staged-reuse path: the seeds (`FileStarted`, plus the bytes
    /// reported complete by every `ChunkCompleted`) must describe the file's real content and
    /// never exceed it, i.e. copied bytes are counted exactly once.
    #[tokio::test]
    async fn staged_reuse_reports_progress_within_file_size() {
        let server = MockServer::start().await;
        // A single chunk at the front: an update that keeps it forces a whole-file rebuild,
        // so every copied byte goes through staging.
        let v1_content: Vec<u8> = (0..2 * CHUNK_SIZE).map(|i| (i % 137) as u8).collect();
        let v1 = build_manifest(DEPOT_ID, 2100, &[("bin/game.exe", v1_content.clone(), 32)]);
        mount_chunks(&server, DEPOT_ID, &chunks_with_offsets(&v1_content)).await;

        let out = tempfile::tempdir().expect("tempdir");
        let report = run_download(
            out.path(),
            v1,
            &test_key_hex(),
            server.address().to_string(),
        )
        .await;
        assert!(report.is_ok(), "depots: {:?}", report.depots);

        // v2: a new chunk inserted at the front, so both v1 chunks are reusable but *moved* -
        // that forces the staging rebuild (an append would be patched in place).
        let mut v2_content: Vec<u8> = (0..CHUNK_SIZE).map(|i| (i % 41) as u8).collect();
        v2_content.extend_from_slice(&v1_content);
        let v2 = build_manifest(DEPOT_ID, 2101, &[("bin/game.exe", v2_content.clone(), 32)]);

        let server2 = MockServer::start().await;
        let new_chunks = chunks_with_offsets(&v2_content);
        let (_, new_body) = new_chunks.first().expect("new chunk").clone();
        mount_chunks(
            &server2,
            DEPOT_ID,
            &[(new_chunks.first().expect("c").0.clone(), new_body)],
        )
        .await;

        let events = {
            let downloader = crate::DepotDownloader::builder()
                .cdn_servers(vec![
                    CdnServer::http(server2.address().to_string().as_str()).expect("address"),
                ])
                .build()
                .expect("downloader");
            let request = DownloadRequest::builder()
                .app_id(APP_ID)
                .depots([(v2, test_key_hex())])
                .output_dir(out.path())
                .build()
                .expect("request");
            let mut handle = downloader.download(request);
            let mut seen = Vec::new();
            while let Some(event) = handle.events().recv().await {
                let stop = matches!(event, ProgressEvent::Finished { .. });
                seen.push(event);
                if stop {
                    break;
                }
            }
            handle.join().await.expect("join");
            seen
        };

        let started_size = events
            .iter()
            .find_map(|e| match e {
                ProgressEvent::FileStarted { size, .. } => Some(*size),
                _ => None,
            })
            .expect("FileStarted");
        assert_eq!(started_size, v2_content.len() as u64);

        // Every chunk's cumulative completion stays inside the file, and the reused first
        // chunk is not reported twice over.
        let mut max_completed = 0u64;
        let mut chunk_events = 0usize;
        for event in &events {
            if let ProgressEvent::ChunkCompleted {
                file_bytes_completed,
                ..
            } = event
            {
                chunk_events += 1;
                assert!(
                    *file_bytes_completed <= started_size,
                    "progress {} exceeds file size {}",
                    file_bytes_completed,
                    started_size
                );
                max_completed = max_completed.max(*file_bytes_completed);
            }
        }
        assert_eq!(chunk_events, 1, "only the new chunk is downloaded");
        // 256 KiB copied through staging + 128 KiB just downloaded.
        assert_eq!(max_completed, v2_content.len() as u64);
        assert_eq!(
            std::fs::read(out.path().join("bin/game.exe")).expect("game.exe"),
            v2_content
        );
    }

    #[tokio::test]
    async fn wrong_key_fails_only_that_depot() {
        // Two depots in one request; the second one's key is wrong. The first must still
        // succeed - per-depot failure isolation.
        let server = MockServer::start().await;
        let good_content: Vec<u8> = (0..CHUNK_SIZE).map(|i| (i % 199) as u8).collect();
        let good = build_manifest(481, 3000, &[("bin/ok.exe", good_content.clone(), 32)]);
        let bad = build_manifest(482, 3001, &[("bin/broken.exe", b"irrelevant".to_vec(), 0)]);

        mount_chunks(&server, 481, &chunks_with_offsets(&good_content)).await;
        // Depot 482's chunk URLs are unmocked → 404 → fatal for that depot only.

        let out = tempfile::tempdir().expect("tempdir");
        let downloader = crate::DepotDownloader::builder()
            .cdn_servers(vec![
                CdnServer::http(server.address().to_string().as_str()).expect("address"),
            ])
            .build()
            .expect("downloader");
        let request = DownloadRequest::builder()
            .app_id(APP_ID)
            .depots([
                (good, test_key_hex()),
                (bad, util::to_hex_lower(&[0x99; 32])), // wrong key
            ])
            .output_dir(out.path())
            .build()
            .expect("request");

        let mut handle = downloader.download(request);
        while let Some(event) = handle.events().recv().await {
            if matches!(event, ProgressEvent::Finished { .. }) {
                break;
            }
        }
        let report = handle.join().await.expect("join");

        assert_eq!(report.depots.len(), 2);
        let good_report = report
            .depots
            .iter()
            .find(|d| d.depot_id == Some(481))
            .expect("good depot reported");
        let bad_report = report
            .depots
            .iter()
            .find(|d| d.depot_id == Some(482))
            .expect("bad depot reported");
        assert!(
            good_report.is_ok(),
            "good depot must succeed: {:?}",
            good_report
        );
        assert!(bad_report.error.is_some(), "bad depot must fail");
        assert_eq!(
            std::fs::read(out.path().join("bin/ok.exe")).expect("ok.exe"),
            good_content
        );
    }

    #[tokio::test]
    async fn cancel_stops_inflight_requests() {
        let server = MockServer::start().await;
        let content: Vec<u8> = (0..CHUNK_SIZE).map(|i| (i % 251) as u8).collect();
        let v1 = build_manifest(DEPOT_ID, 4000, &[("bin/game.exe", content.clone(), 32)]);
        for (chunk, body) in chunks_with_offsets(&content) {
            let hex = util::to_hex_lower(chunk.sha.as_ref().expect("sha"));
            Mock::given(method("GET"))
                .and(path(format!("/depot/{DEPOT_ID}/chunk/{hex}")))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_bytes(body)
                        .set_delay(Duration::from_secs(120)),
                )
                .mount(&server)
                .await;
        }

        let out = tempfile::tempdir().expect("tempdir");

        let downloader = crate::DepotDownloader::builder()
            .cdn_servers(vec![
                CdnServer::http(server.address().to_string().as_str()).expect("address"),
            ])
            .build()
            .expect("downloader");
        let request = DownloadRequest::builder()
            .app_id(APP_ID)
            .depots([(v1, test_key_hex())])
            .output_dir(out.path())
            .build()
            .expect("request");

        let mut handle = downloader.download(request);
        // Wait until the engine is actually inside a chunk fetch.
        while let Some(event) = handle.events().recv().await {
            if matches!(event, ProgressEvent::FileStarted { .. }) {
                break;
            }
        }
        handle.cancel();

        let err = handle.join().await.expect_err("must be cancelled");
        assert!(matches!(err, Error::Cancelled), "was: {err}");
        let _ = content;
    }
}
