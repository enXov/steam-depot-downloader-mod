//! Typed, validated download configuration - the library equivalent of the mod's CLI
//! parameters `-app`, `-manifestfile` + `-depotkeys` (paired), `-dir` and `-max-downloads`.
//!
//! Depot id and manifest gid do not exist as inputs: the manifest's own metadata carries both,
//! and each manifest is paired with its depot's 64-character hex key.

use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::util;

/// Where the bytes of one depot's manifest come from - the library equivalent of
/// `-manifestfile <file>`.
///
/// Construct it implicitly: an owned path becomes [`ManifestSource::File`], an owned byte
/// buffer becomes [`ManifestSource::Bytes`] - `.depots([(PathBuf::from("a.manifest"), key)])`
/// and `.depots([(manifest_bytes, key)])` both just work. Ownership is taken on purpose
/// (standard Rust API practice): the library never clones your manifest behind your back, and
/// if you need to keep a copy, cloning it in your own code makes that cost explicit. Paths
/// stay `PathBuf`-typed - the safe, validated path representation Rust gives you. The
/// manifest must be a **raw `.manifest` file**.

#[derive(Clone, Debug)]
pub enum ManifestSource {
    /// Load the manifest from a file on disk.
    File(PathBuf),
    /// Manifest bytes already in memory (e.g. received over IPC or fetched by the caller).
    Bytes(Vec<u8>),
}

impl From<PathBuf> for ManifestSource {
    fn from(path: PathBuf) -> Self {
        ManifestSource::File(path)
    }
}

impl From<Vec<u8>> for ManifestSource {
    fn from(bytes: Vec<u8>) -> Self {
        ManifestSource::Bytes(bytes)
    }
}

/// One depot download, fully resolved and validated: manifest source + raw AES-256 key bytes.
#[derive(Clone, Debug)]
pub(crate) struct DepotSpec {
    pub(crate) manifest: ManifestSource,
    pub(crate) key: [u8; 32],
}

/// A fully validated download request. Build it with [`DownloadRequest::builder`].
#[derive(Clone, Debug)]
pub struct DownloadRequest {
    pub(crate) app_id: u32,
    pub(crate) depots: Vec<DepotSpec>,
    pub(crate) output_dir: PathBuf,
    pub(crate) max_downloads: usize,
}

impl DownloadRequest {
    /// Start building a request.
    pub fn builder() -> DownloadRequestBuilder {
        DownloadRequestBuilder::default()
    }
}

/// Builder for [`DownloadRequest`].
#[derive(Default)]
pub struct DownloadRequestBuilder {
    app_id: Option<u32>,
    depots: Vec<(ManifestSource, String)>,
    output_dir: Option<PathBuf>,
    max_downloads: usize,
}

impl DownloadRequestBuilder {
    /// The owning app id (CLI: `-app <#>`). Required.
    #[must_use]
    pub fn app_id(mut self, app_id: u32) -> Self {
        self.app_id = Some(app_id);
        self
    }

    /// The depots to download: each is a `(manifest, depot_key)` pair - a raw `.manifest`
    /// (path or bytes) plus that depot's 64-character hex AES-256 key (CLI: `-manifestfile` +
    /// `-depotkeys`).
    ///
    /// Depot id and manifest gid are read from the manifest's metadata, so neither needs to be
    /// provided - and a key cannot be paired with the wrong depot by accident.
    ///
    /// ```
    /// # use std::path::PathBuf;
    /// # use steam_depot_downloader_mod::DownloadRequest;
    /// let req = DownloadRequest::builder()
    ///     .app_id(730)
    ///     .depots([
    ///         (PathBuf::from("731_7617088375292372759.manifest"), "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),
    ///         (PathBuf::from("732_123.manifest"), "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"),
    ///     ])
    ///     .output_dir("out")
    ///     .build();
    /// assert!(req.is_ok());
    /// ```
    #[must_use]
    pub fn depots(
        mut self,
        depots: impl IntoIterator<Item = (impl Into<ManifestSource>, impl Into<String>)>,
    ) -> Self {
        self.depots
            .extend(depots.into_iter().map(|(m, key)| (m.into(), key.into())));
        self
    }

    /// Where the files go (CLI: `-dir <installdir>`). Required.
    #[must_use]
    pub fn output_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.output_dir = Some(path.into());
        self
    }

    /// Max concurrent chunk downloads (CLI: `-max-downloads <#>`). Default: 8.
    #[must_use]
    pub fn max_downloads(mut self, max_downloads: usize) -> Self {
        self.max_downloads = max_downloads;
        self
    }

    /// Validate and finish.
    pub fn build(self) -> Result<DownloadRequest> {
        let app_id = self
            .app_id
            .ok_or_else(|| Error::InvalidConfig("missing app id - call .app_id(..)".to_owned()))?;

        if self.depots.is_empty() {
            return Err(Error::InvalidConfig(
                "no depots - call .depots([(manifest, key), ..])".to_owned(),
            ));
        }

        let output_dir = self.output_dir.ok_or_else(|| {
            Error::InvalidConfig("missing output directory - call .output_dir(..)".to_owned())
        })?;

        let max_downloads = if self.max_downloads == 0 {
            8
        } else {
            self.max_downloads
        };

        let depots = self
            .depots
            .into_iter()
            .map(|(manifest, key)| {
                let key = util::parse_hex_key(&key).ok_or_else(|| {
                    Error::InvalidConfig(format!(
                        "depot '{}' has an invalid depot key: expected exactly 64 hex characters",
                        match &manifest {
                            ManifestSource::File(path) => path.display().to_string(),
                            ManifestSource::Bytes(_) => "<in-memory manifest>".to_owned(),
                        }
                    ))
                })?;
                Ok(DepotSpec { manifest, key })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(DownloadRequest {
            app_id,
            depots,
            output_dir,
            max_downloads,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn builder_requires_app_depots_and_output_dir() {
        assert!(DownloadRequest::builder().build().is_err());
        assert!(DownloadRequest::builder().app_id(730).build().is_err());
        assert!(
            DownloadRequest::builder()
                .app_id(730)
                .depots([(PathBuf::from("x.manifest"), &"4".repeat(64))])
                .build()
                .is_err()
        );
        assert!(
            DownloadRequest::builder()
                .app_id(730)
                .depots([(PathBuf::from("x.manifest"), &"4".repeat(64))])
                .output_dir("out")
                .build()
                .is_ok()
        );
    }

    #[test]
    fn builder_defaults() {
        let req = DownloadRequest::builder()
            .app_id(1)
            .depots([(PathBuf::from("x.manifest"), &"4".repeat(64))])
            .output_dir("out")
            .build()
            .expect("valid");
        assert_eq!(req.max_downloads, 8);
    }

    #[test]
    fn invalid_key_names_the_offending_manifest() {
        let err = DownloadRequest::builder()
            .app_id(1)
            .depots([(PathBuf::from("my_manifest.manifest"), "tooshort")])
            .output_dir("out")
            .build()
            .expect_err("invalid key");
        let message = err.to_string();
        assert!(message.contains("my_manifest.manifest"), "{message}");
        assert!(message.contains("64 hex"), "{message}");
    }

    #[test]
    fn manifest_source_conversions() {
        assert!(matches!(
            ManifestSource::from(PathBuf::from("x.manifest")),
            ManifestSource::File(_)
        ));
        assert!(matches!(
            ManifestSource::from(vec![1, 2]),
            ManifestSource::Bytes(_)
        ));
    }
}
