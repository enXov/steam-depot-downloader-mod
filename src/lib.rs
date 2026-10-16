//! # steam-depot-downloader-mod
//!
//! A Rust library for downloading Steam depot content using **user-supplied depot keys** and
//! **manifest files** - a port of the behavior added by
//! [DepotDownloaderMod](https://github.com/enXov/DepotDownloaderMod) (itself a fork of
//! [DepotDownloader](https://github.com/SteamRE/DepotDownloader)), built on top of the
//! [`steam-protobuf-rs`](https://crates.io/crates/steam-protobuf-rs) message definitions.
//!
//! Unlike a CLI port, this crate is designed to be **embedded** - in GUI applications, CLIs,
//! services, anything that needs depot downloads without shelling out:
//!
//! - all input is typed - each depot is a `(manifest path, hex key)` pair, no argv parsing;
//! - downloads stream [`ProgressEvent`]s over a channel (forward them to your UI as you like);
//! - every download is cancellable through a [`tokio_util::sync::CancellationToken`];
//! - failed depots never take down their siblings - per-depot failures land in the final
//!   [`DownloadReport`].
//!
//! ## Behavior model (Steam-like verify / update)
//!
//! After a successful download the crate stores bookkeeping inside
//! `<output_dir>/.DepotDownloader/` (a `depots.json` state file and a copy of the installed
//! manifest). Subsequent runs are fully dynamic:
//!
//! - **same manifest again** - every file is re-verified chunk-by-chunk (Adler-32, exactly like
//!   Steam's "verify integrity of game files"); only corrupt/missing chunks are re-downloaded;
//! - **a new manifest for the same depot** → files whose SHA-1 changed (or are new) are
//!   verified chunk-by-chunk and only the differing chunks are fetched - this is how Steam
//!   updates games; unchanged files are skipped without even being read;
//! - **anything not listed in the manifest is left alone and never deleted** (Steam behaves
//!   the same way): mods, custom configs and other user files survive every download.
//!
//! Missing files (including config files wiped between versions) are simply downloaded -
//! verification is per-chunk, so "missing" and "corrupt" are the same problem.
//!
//! ## What this crate deliberately does not do
//!
//! It implements the *mod's* feature set: user-supplied depot keys + user-supplied manifest
//! files + plain HTTPS chunk downloads. It does **not** log into Steam, does not connect to a
//! CM server, does not resolve branches via PICS, does not ask Steam for depot keys, and does
//! not fetch manifests that require a manifest request code. Manifests must be supplied as
//! raw `.manifest` files (the CDN's zip wrapper is the caller's business), and keys are
//! 64-character hex strings paired with each manifest.
//!
//! ## Quick start
//!
//! ```no_run
//! use std::path::PathBuf;
//! use steam_depot_downloader_mod::{DepotDownloader, DownloadRequest, ProgressEvent};
//!
//! # async fn example() -> steam_depot_downloader_mod::Result<()> {
//! let request = DownloadRequest::builder()
//!     .app_id(730)
//!     // each depot: (raw .manifest file, that depot's 64-char hex key).
//!     // Depot id + manifest gid are read from the manifest's own metadata.
//!     .depots([(
//!         PathBuf::from("731_7617088375292372759.manifest"),
//!         "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
//!     )])
//!     .output_dir("./out")
//!     .build()?;
//!
//! let downloader = DepotDownloader::new()?;
//! let mut handle = downloader.download(request);
//!
//! while let Some(event) = handle.events().recv().await {
//!     match event {
//!         ProgressEvent::ChunkCompleted { total_downloaded, total_uncompressed, .. } => {
//!             println!("downloaded {total_downloaded} ({total_uncompressed} uncompressed)");
//!         }
//!         ProgressEvent::Finished { .. } => break,
//!         _ => {}
//!     }
//! }
//!
//! let report = handle.join().await?;
//! assert!(!report.has_failures());
//! # Ok(())
//! # }
//! ```

#![deny(rustdoc::broken_intra_doc_links)]

mod cdn;
mod config;
mod download;
mod error;
mod manifest;
mod progress;
mod state;
mod util;

pub use cdn::CdnServer;
pub use config::{DownloadRequest, DownloadRequestBuilder, ManifestSource};
pub use error::{Error, Result};
pub use manifest::{DepotManifest, ManifestChunk, ManifestFile, flags};
pub use progress::{DepotReport, DownloadHandle, DownloadReport, ProgressEvent};

use std::sync::Arc;
use tokio::sync::mpsc;

/// The public client used to run [`DownloadRequest`]s.
///
/// Owns a shared HTTP client and, optionally, an explicit CDN server list (see
/// [`DepotDownloaderBuilder::cdn_servers`] - useful for LAN caches and tests).
#[derive(Clone)]
pub struct DepotDownloader {
    http: reqwest::Client,
    cdn_server_override: Option<Arc<Vec<CdnServer>>>,
}

impl DepotDownloader {
    /// Create a downloader with the default HTTP configuration.
    pub fn new() -> Result<Self> {
        Self::builder().build()
    }

    /// Start configuring a downloader.
    pub fn builder() -> DepotDownloaderBuilder {
        DepotDownloaderBuilder {
            connect_timeout: std::time::Duration::from_secs(10),
            request_timeout: std::time::Duration::from_secs(60),
            cdn_servers: None,
        }
    }

    /// Start a download.
    ///
    /// This returns immediately; the actual work runs on the current tokio runtime. Consume
    /// progress via [`DownloadHandle::events`] and obtain the final result via
    /// [`DownloadHandle::join`].
    ///
    /// # Panics
    ///
    /// Panics if called outside of a tokio runtime context.
    pub fn download(&self, request: DownloadRequest) -> DownloadHandle {
        let (tx, rx) = mpsc::channel::<ProgressEvent>(4096);
        let cancel = tokio_util::sync::CancellationToken::new();

        let engine = download::DownloadEngine::new(
            self.http.clone(),
            request,
            tx,
            cancel.clone(),
            self.cdn_server_override.clone(),
        );
        let task = tokio::spawn(engine.run());

        DownloadHandle::new(rx, cancel, task)
    }

    /// Query Steam's public content server directory, exactly as [`DepotDownloader::download`]
    /// would.
    ///
    /// Useful for UIs that want to show connectivity up front, or to inspect the list before
    /// pinning a subset via [`DepotDownloaderBuilder::cdn_servers`].
    pub async fn cdn_servers(&self) -> Result<Vec<CdnServer>> {
        cdn::directory::fetch_servers(&self.http).await
    }
}

impl Default for DepotDownloader {
    fn default() -> Self {
        Self::new().expect("failed to initialize HTTP client")
    }
}

/// Builder for [`DepotDownloader`].
pub struct DepotDownloaderBuilder {
    connect_timeout: std::time::Duration,
    request_timeout: std::time::Duration,
    cdn_servers: Option<Vec<CdnServer>>,
}

impl DepotDownloaderBuilder {
    /// TCP connect timeout for CDN requests (SteamKit default: 10s).
    #[must_use]
    pub fn connect_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Total per-request timeout for CDN chunk requests (SteamKit default: 60s).
    #[must_use]
    pub fn request_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Use an explicit CDN server list instead of querying Steam's public directory.
    ///
    /// Servers are used in the given order. This mirrors what DepotDownloader's
    /// `-use-lancache` achieves (point it at a local cache) and is what the crate's own
    /// offline tests use.
    #[must_use]
    pub fn cdn_servers(mut self, servers: Vec<CdnServer>) -> Self {
        self.cdn_servers = Some(servers);
        self
    }

    /// Build the client.
    pub fn build(self) -> Result<DepotDownloader> {
        let http = reqwest::Client::builder()
            .connect_timeout(self.connect_timeout)
            .timeout(self.request_timeout)
            .user_agent(concat!(
                "steam-depot-downloader-mod/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()?;

        Ok(DepotDownloader {
            http,
            cdn_server_override: self.cdn_servers.map(Arc::new),
        })
    }
}
