//! The download orchestrator.
//!
//! Per depot: parse manifest → ids/key → plan every file → run chunk downloads under a shared
//! concurrency semaphore → commit state. Files are planned/executed concurrently; network
//! concurrency is bounded by [`DownloadRequest::max_downloads`].
//!
//! Reuse semantics (exactly what the crate docs promise):
//!
//! | situation                                       | behavior                                      |
//! |-------------------------------------------------|-----------------------------------------------|
//! | file missing                                    | download every chunk                          |
//! | same manifest gid as installed                  | verify every chunk (Steam-style verify)       |
//! | new gid, file hash unchanged across versions    | skip without reading                          |
//! | new gid, file hash changed                      | verify on-disk chunks; reuse valid ones via staging |
//! | prior install with no/unknown state             | verify against the new manifest in place      |
//!
//! Files on disk that are not listed in the manifest are never touched and never deleted.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

use crate::cdn::client::CdnClient;
use crate::cdn::{CdnServer, chunk, directory};
use crate::config::{DepotSpec, DownloadRequest, ManifestSource};
use crate::error::{Error, Result};
use crate::manifest::{DepotManifest, ManifestChunk, ManifestFile};
use crate::progress::{DepotReport, DownloadReport, ProgressEvent};
use crate::state::StateStore;
use crate::util;

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

/// Everything one chunk download needs; handed to [`DownloadEngine::download_chunk`].
struct ChunkJob {
    file_handle: Arc<Mutex<Option<std::fs::File>>>,
    done_bytes: Arc<AtomicU64>,
    display_path: PathBuf,
    file_size: u64,
    chunk: ManifestChunk,
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

            let files = manifest.into_files();
            let content_files: Vec<&ManifestFile> = files
                .iter()
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

            // 4. Directory entries.
            for file in &files {
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

            // 5. Files concurrently; network concurrency is capped by the semaphore.
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
            };

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
    async fn execute_file(&self, ctx: &DepotCtx<'_>, file: &ManifestFile) -> Result<()> {
        let rel = util::safe_relative_path(&file.path).ok_or_else(|| {
            Error::Manifest(format!(
                "unsafe or empty file path '{}' in manifest",
                file.path
            ))
        })?;
        let final_path = self.request.output_dir.join(&rel);
        let display_path = rel.clone();

        if std::fs::metadata(&final_path).is_ok() {
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

        // Plan (blocking: reads on-disk bytes for chunk verification).
        let plan = {
            let plan_input = PlanInput {
                final_path: final_path.clone(),
                size: file.size,
                chunks: file.chunks.clone(),
                old_chunks: ctx
                    .old_by_path
                    .get(file.path.as_str())
                    .map(|e| e.chunks.clone()),
                old_entry_matches: !ctx.same_manifest
                    && ctx.old_by_path.get(file.path.as_str()).is_some_and(|e| {
                        e.size == file.size
                            && e.sha_content.is_some()
                            && e.sha_content == file.sha_content
                    }),
                verify_all: ctx.same_manifest,
            };
            tokio::task::spawn_blocking(move || plan_file(plan_input))
                .await
                .map_err(|e| Error::TaskFailed(e.to_string()))??
        };

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
        let file_handle: Arc<Mutex<Option<std::fs::File>>> = {
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
            Arc::new(Mutex::new(Some(opened)))
        };

        let done_bytes = Arc::new(AtomicU64::new(plan.reused_bytes));

        // Copy reused chunks into staging (sequential local IO).
        if !plan.copies.is_empty() {
            let copies = plan.copies.clone();
            let source_path = final_path.clone();
            let handle = Arc::clone(&file_handle);
            let done = Arc::clone(&done_bytes);
            tokio::task::spawn_blocking(move || -> Result<()> {
                let source =
                    std::fs::File::open(&source_path).map_err(Error::io_path(&source_path))?;
                for op in copies {
                    let mut buf = vec![0u8; op.chunk.len_uncompressed as usize];
                    read_at(&source, &mut buf, op.source_offset).map_err(Error::Io)?;
                    {
                        let mut guard = handle.lock().expect("file handle mutex");
                        let f = guard.as_mut().expect("file handle open");
                        write_at(f, &buf, op.chunk.offset).map_err(Error::Io)?;
                    }
                    done.fetch_add(u64::from(op.chunk.len_uncompressed), Ordering::Relaxed);
                }
                Ok(())
            })
            .await
            .map_err(|e| Error::TaskFailed(e.to_string()))??;
        }

        // Download the remaining chunks.
        let mut jobs = FuturesUnordered::new();
        for chunk in plan.downloads {
            if ctx.depot_cancel.is_cancelled() || self.cancel.is_cancelled() {
                return Err(Error::Cancelled);
            }
            let permit = Arc::clone(&ctx.downloads_sem)
                .acquire_owned()
                .await
                .map_err(|e| Error::TaskFailed(e.to_string()))?;
            jobs.push(self.download_chunk(
                ctx,
                ChunkJob {
                    file_handle: Arc::clone(&file_handle),
                    done_bytes: Arc::clone(&done_bytes),
                    display_path: display_path.clone(),
                    file_size: file.size,
                    chunk,
                    _permit: permit,
                },
            ));
        }
        while let Some(result) = jobs.next().await {
            result?;
        }

        // Finalize (blocking): correct the length, swap staging over the final path,
        // apply executable bits.
        {
            let write_path = write_path.clone();
            let handle = Arc::clone(&file_handle);
            let is_staging = plan.staging;
            let size = file.size;
            let exec = file.is_executable();
            tokio::task::spawn_blocking(move || -> Result<()> {
                {
                    let mut guard = handle.lock().expect("file handle mutex");
                    if let Some(f) = guard.as_mut() {
                        let meta = f.metadata().map_err(Error::Io)?;
                        if meta.len() != size {
                            f.set_len(size).map_err(Error::Io)?;
                        }
                    }
                    *guard = None; // close before the rename
                }
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
            _permit,
        } = job;

        if ctx.depot_cancel.is_cancelled() || self.cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }

        let chunk_hex = util::to_hex_lower(&chunk.id);
        let fetch = ctx.client.fetch_chunk(
            ctx.depot_id,
            &chunk_hex,
            chunk.len_compressed,
            &ctx.depot_cancel,
        );
        // Cancellation must also cut short an in-flight request, not just the gaps between
        // attempts - a hanging CDN must never delay a `cancel()` by the request timeout.
        let raw = tokio::select! {
            biased;
            _ = ctx.depot_cancel.cancelled() => return Err(Error::Cancelled),
            _ = self.cancel.cancelled() => return Err(Error::Cancelled),
            result = fetch => result?,
        };
        let network_len = raw.len() as u64;

        // Decrypt + verify + write (blocking).
        let key = ctx.key;
        let offset = chunk.offset;
        let handle = Arc::clone(&file_handle);
        tokio::task::spawn_blocking(move || -> Result<()> {
            let data = chunk::process_chunk(
                &raw,
                &key,
                chunk.len_uncompressed,
                chunk.adler32,
                &chunk_hex,
            )?;
            let mut guard = handle.lock().expect("file handle mutex");
            let f = guard.as_mut().expect("file handle open");
            write_at(f, &data, offset).map_err(Error::Io)?;
            Ok(())
        })
        .await
        .map_err(|e| Error::TaskFailed(e.to_string()))??;

        let downloaded = self
            .total_downloaded
            .fetch_add(network_len, Ordering::Relaxed)
            + network_len;
        let uncompressed = self
            .total_uncompressed
            .fetch_add(u64::from(chunk.len_uncompressed), Ordering::Relaxed)
            + u64::from(chunk.len_uncompressed);
        ctx.depot_downloaded
            .fetch_add(network_len, Ordering::Relaxed);
        let file_done = done_bytes.fetch_add(u64::from(chunk.len_uncompressed), Ordering::Relaxed)
            + u64::from(chunk.len_uncompressed);

        self.emit_best_effort(ProgressEvent::ChunkCompleted {
            depot_id: ctx.depot_id,
            path: display_path,
            file_bytes_completed: file_done,
            file_size,
            downloaded_increment: network_len,
            uncompressed_increment: u64::from(chunk.len_uncompressed),
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
    chunks: Vec<ManifestChunk>,
    old_chunks: Option<Vec<ManifestChunk>>,
    old_entry_matches: bool,
    verify_all: bool,
}

/// Decide, for one file, which chunks can be reused from disk and which must be downloaded.
///
/// Pure filesystem work - runs inside `spawn_blocking`.
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

    // Empty content file: only the length differs from "nothing".
    if size == 0 || chunks.is_empty() {
        return Ok(match existing_len {
            Some(0) => FilePlan {
                skip: true,
                ..FilePlan::default()
            },
            Some(_) => FilePlan::default(), // exists, wrong size → finalize truncates
            None => FilePlan {
                fresh: true,
                ..FilePlan::default()
            },
        });
    }

    let Some(existing_len) = existing_len else {
        return Ok(FilePlan {
            downloads: chunks,
            fresh: true,
            ..FilePlan::default()
        });
    };

    // Fast path: the previous install's manifest says this file has identical content and the
    // on-disk length agrees → skip without reading a single byte.
    if old_entry_matches && existing_len == size {
        return Ok(FilePlan {
            skip: true,
            ..FilePlan::default()
        });
    }

    // Chunk-id reuse: when we know what the previous version looked like, reuse every on-disk
    // chunk whose (id, adler) matches a chunk of the new manifest. Reused chunks are copied
    // into a staging file (offsets may have moved), the rest is downloaded.
    if !verify_all {
        if let Some(old_chunks) = &old_chunks {
            if !old_chunks.is_empty() {
                return plan_reuse_from_old(&final_path, size, chunks, old_chunks, existing_len);
            }
        }
    }

    // Steam-style verification: read every chunk position and check it against the manifest.
    plan_verify_in_place(&final_path, chunks, existing_len)
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
        let mut buf = vec![0u8; old_chunk.len_uncompressed as usize];
        if read_at(&source, &mut buf, old_chunk.offset).is_err() {
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

    let downloads: Vec<ManifestChunk> = chunks
        .iter()
        .enumerate()
        .filter(|(index, _)| !covered[*index])
        .map(|(_, chunk)| chunk.clone())
        .collect();
    let reused_bytes = copies
        .iter()
        .map(|op| u64::from(op.chunk.len_uncompressed))
        .sum();

    Ok(FilePlan {
        downloads,
        copies,
        reused_bytes,
        staging: true,
        ..FilePlan::default()
    })
}

fn plan_verify_in_place(
    final_path: &Path,
    chunks: Vec<ManifestChunk>,
    existing_len: u64,
) -> Result<FilePlan> {
    let mut downloads = Vec::new();
    let mut reused_bytes = 0u64;

    let source = std::fs::File::open(final_path).ok();
    for chunk in chunks {
        let readable =
            source.is_some() && chunk.offset + u64::from(chunk.len_uncompressed) <= existing_len;
        let ok = if let (Some(source), true) = (&source, readable) {
            let mut buf = vec![0u8; chunk.len_uncompressed as usize];
            read_at(source, &mut buf, chunk.offset).is_ok()
                && util::adler32_seed0(&buf) == chunk.adler32
        } else {
            false
        };
        if ok {
            reused_bytes += u64::from(chunk.len_uncompressed);
        } else {
            downloads.push(chunk);
        }
    }

    Ok(FilePlan {
        downloads,
        reused_bytes,
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

/// Positional read, mirroring SteamKit's `FileStream.Seek + Read` usage.
#[cfg(unix)]
fn read_at(file: &std::fs::File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

#[cfg(windows)]
fn read_at(file: &std::fs::File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut read = 0usize;
    while read < buf.len() {
        let n = file.seek_read(&mut buf[read..], offset + read as u64)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "short read",
            ));
        }
        read += n;
    }
    Ok(())
}

/// Positional write, mirroring SteamKit's `FileStream.Seek + Write` usage.
#[cfg(unix)]
fn write_at(file: &mut std::fs::File, buf: &[u8], offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.write_all_at(buf, offset)
}

#[cfg(windows)]
fn write_at(file: &mut std::fs::File, buf: &[u8], offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut written = 0usize;
    while written < buf.len() {
        let n = file.seek_write(&buf[written..], offset + written as u64)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "short write",
            ));
        }
        written += n;
    }
    Ok(())
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
