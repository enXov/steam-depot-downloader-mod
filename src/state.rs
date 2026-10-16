//! `<output_dir>/.DepotDownloader/` bookkeeping.
//!
//! Layout (compatible with what DepotDownloader writes, so tools can share caches):
//!
//! ```text
//! <output>/.DepotDownloader/
//! ├── depots.json                        {"depots": {"731": {"gid": 7617…, "updated_unix": …}}}
//! ├── 731_7617088375292372759.manifest   raw Steam manifest of the installed version
//! ├── 731_7617088375292372759.manifest.sha   SHA-1 of the manifest file (DepotDownloader interop)
//! └── staging/                           in-flight files (chunk reuse downloads)
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::util;

pub(crate) const STATE_DIR_NAME: &str = ".DepotDownloader";
const STATE_FILE_NAME: &str = "depots.json";

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct StateFile {
    version: u32,
    depots: BTreeMap<String, DepotState>,
}

#[derive(Serialize, Deserialize, Clone)]
struct DepotState {
    /// Installed manifest gid.
    gid: u64,
    updated_unix: u64,
}

/// Per-output-directory state. Cheap to construct; mutations go through
/// [`StateStore::commit_depot`], which is only called after a depot fully succeeded.
pub(crate) struct StateStore {
    root: PathBuf,
    state: StateFile,
}

impl StateStore {
    /// Load existing state (a missing or corrupt state file is treated as "no state" -
    /// verification still protects the downloads, so a corrupt state file only costs
    /// performance, never correctness).
    pub(crate) fn load(output_dir: &Path) -> Self {
        let root = output_dir.join(STATE_DIR_NAME);
        let state = std::fs::read(root.join(STATE_FILE_NAME))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        StateStore { root, state }
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn staging_dir(&self) -> PathBuf {
        self.root.join("staging")
    }

    pub(crate) fn manifest_cache_path(&self, depot_id: u32, gid: u64) -> PathBuf {
        self.root.join(format!("{depot_id}_{gid}.manifest"))
    }

    /// Which manifest gid was last fully installed for this depot?
    pub(crate) fn installed_gid(&self, depot_id: u32) -> Option<u64> {
        self.state.depots.get(&depot_id.to_string()).map(|s| s.gid)
    }

    /// Load the cached manifest bytes for a depot's currently installed gid, if still on disk.
    pub(crate) fn cached_manifest_bytes(&self, depot_id: u32) -> Option<(u64, Vec<u8>)> {
        let gid = self.installed_gid(depot_id)?;
        let path = self.manifest_cache_path(depot_id, gid);
        let bytes = std::fs::read(path).ok()?;
        Some((gid, bytes))
    }

    pub(crate) fn ensure_dirs(&self) -> Result<()> {
        std::fs::create_dir_all(self.staging_dir()).map_err(Error::io_path(self.staging_dir()))
    }

    /// Wipe and recreate the staging directory. Called at the start of every run: staging
    /// content is never meaningful across runs, and a crashed run must not leave partial
    /// files behind that could ever be confused with real downloads.
    pub(crate) fn clear_staging(&self) -> Result<()> {
        if self.staging_dir().exists() {
            std::fs::remove_dir_all(self.staging_dir())
                .map_err(Error::io_path(self.staging_dir()))?;
        }
        self.ensure_dirs()
    }

    /// Record a fully completed depot: persist the manifest (plus `.sha` sidecar for
    /// DepotDownloader interop), remove stale manifests for that depot, update `depots.json`.
    ///
    /// All writes go through tmp-file + rename so a crash mid-commit cannot corrupt state;
    /// state is simply never written for failed downloads.
    pub(crate) fn commit_depot(
        &mut self,
        depot_id: u32,
        gid: u64,
        manifest_bytes: &[u8],
    ) -> Result<()> {
        self.ensure_dirs()?;

        let manifest_path = self.manifest_cache_path(depot_id, gid);
        write_atomic(&manifest_path, manifest_bytes)?;
        write_atomic(
            &manifest_path.with_extension("manifest.sha"),
            &util::sha1(manifest_bytes),
        )?;

        // Drop manifests of older installs of this same depot.
        if let Ok(entries) = std::fs::read_dir(self.root()) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                let prefix = format!("{depot_id}_");
                if name.starts_with(&prefix)
                    && name.ends_with(".manifest")
                    && entry.path() != manifest_path
                {
                    let _ = std::fs::remove_file(entry.path());
                    let _ = std::fs::remove_file(entry.path().with_extension("manifest.sha"));
                }
            }
        }

        self.state.version = 1;
        self.state.depots.insert(
            depot_id.to_string(),
            DepotState {
                gid,
                updated_unix: now_unix(),
            },
        );

        let json = serde_json::to_vec_pretty(&self.state)
            .map_err(|e| Error::TaskFailed(format!("failed to serialize state: {e}")))?;
        write_atomic(&self.root.join(STATE_FILE_NAME), &json)?;
        Ok(())
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn write_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, contents).map_err(Error::io_path(&tmp))?;
    std::fs::rename(&tmp, path).map_err(Error::io_path(path))?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = StateStore::load(dir.path());
        assert_eq!(store.installed_gid(731), None);

        store
            .commit_depot(731, 42, b"fake-manifest-bytes")
            .expect("commit");
        assert_eq!(store.installed_gid(731), Some(42));

        // Manifest file + sha sidecar exist and survive a reload.
        let reloaded = StateStore::load(dir.path());
        assert_eq!(reloaded.installed_gid(731), Some(42));
        let (gid, bytes) = reloaded
            .cached_manifest_bytes(731)
            .expect("cached manifest");
        assert_eq!(gid, 42);
        assert_eq!(bytes, b"fake-manifest-bytes");
    }

    #[test]
    fn commit_replaces_old_manifest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = StateStore::load(dir.path());
        store.commit_depot(731, 1, b"old").expect("commit old");
        store.commit_depot(731, 2, b"new").expect("commit new");

        let reloaded = StateStore::load(dir.path());
        assert_eq!(reloaded.installed_gid(731), Some(2));
        let (gid, bytes) = reloaded.cached_manifest_bytes(731).expect("cached");
        assert_eq!((gid, bytes.as_slice()), (2_u64, b"new".as_slice()));
        assert!(!reloaded.manifest_cache_path(731, 1).exists());
    }

    #[test]
    fn corrupt_state_is_tolerated() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join(STATE_DIR_NAME)).expect("mkdir");
        std::fs::write(
            dir.path().join(STATE_DIR_NAME).join(STATE_FILE_NAME),
            b"not json",
        )
        .expect("write garbage");
        let store = StateStore::load(dir.path());
        assert_eq!(store.installed_gid(731), None);
    }
}
