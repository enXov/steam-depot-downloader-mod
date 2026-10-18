//! Steam depot manifest (the binary format fed by `-manifestfile`).
//!
//! The bytes are a little-endian sequence of `[u32 magic][u32 length][protobuf payload]`
//! sections ending with an EOF magic.
//!
//! Manifests frequently ship with AES-encrypted file names - call
//! [`DepotManifest::decrypt_filenames`] with the depot key to read the real paths.

mod names;
pub(crate) mod parse;

use std::path::Path;

use crate::error::{Error, Result};
use crate::util;

/// File flag bits used in `ContentManifestPayload.FileMapping.flags` (SteamKit `EDepotFileFlag`).
pub mod flags {
    pub const USER_CONFIG: u32 = 1;
    pub const VERSIONED_USER_CONFIG: u32 = 2;
    pub const ENCRYPTED: u32 = 4;
    pub const READ_ONLY: u32 = 8;
    pub const HIDDEN: u32 = 16;
    pub const EXECUTABLE: u32 = 32;
    pub const DIRECTORY: u32 = 64;
    pub const CUSTOM_EXECUTABLE: u32 = 128;
    pub const INSTALL_SCRIPT: u32 = 256;
    pub const SYMLINK: u32 = 512;
}

/// One chunk of a file: where its (uncompressed) bytes live in the file plus the checksums
/// used to verify them (`adler32` is Steam's seed-0 Adler-32 over the uncompressed bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestChunk {
    /// Chunk id - SHA-1 of the stored (encrypted+compressed) chunk, also the CDN object name.
    pub id: [u8; 20],
    /// Seed-0 Adler-32 of the *uncompressed* content.
    pub adler32: u32,
    /// Byte offset of this chunk inside the final file.
    pub offset: u64,
    pub len_uncompressed: u32,
    pub len_compressed: u32,
}

/// One file entry of a manifest (`path` is always `/`-normalized, forward slashes).
#[derive(Clone, Debug)]
pub struct ManifestFile {
    pub path: String,
    pub size: u64,
    /// See [`flags`].
    pub flags: u32,
    /// SHA-1 of the whole file content, if present in the manifest.
    pub sha_content: Option<[u8; 20]>,
    /// Symlink target, if this is a symlink entry.
    pub link_target: Option<String>,
    pub chunks: Vec<ManifestChunk>,
}

impl ManifestFile {
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.flags & flags::DIRECTORY != 0
    }

    #[must_use]
    pub fn is_symlink(&self) -> bool {
        self.flags & flags::SYMLINK != 0
    }

    #[must_use]
    pub fn is_executable(&self) -> bool {
        self.flags & flags::EXECUTABLE != 0 || self.flags & flags::CUSTOM_EXECUTABLE != 0
    }
}

impl ManifestChunk {
    /// The chunk id as lowercase hex - this is the CDN object name of the chunk.
    #[must_use]
    pub fn id_hex(&self) -> String {
        crate::util::to_hex_lower(&self.id)
    }
}

/// A parsed depot manifest.
///
/// # Errors during parsing
///
/// `depot_id` and `manifest_gid` are required to be present in the manifest metadata - this is
/// what makes explicit `-depot`/`-manifest` arguments unnecessary
#[derive(Clone, Debug)]
pub struct DepotManifest {
    depot_id: u32,
    manifest_gid: u64,
    creation_unix: u32,
    filenames_encrypted: bool,
    total_size_uncompressed: u64,
    total_size_compressed: u64,
    files: Vec<ManifestFile>,
}

impl DepotManifest {
    /// Parse raw manifest bytes (the exact content of a `.manifest` file).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let raw = parse::parse(bytes)?;
        Self::from_sections(raw)
    }

    /// Load a manifest from a file (CLI equivalent: `-manifestfile <file>`).
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(Error::io_path(path))?;
        if bytes.is_empty() {
            return Err(Error::Manifest(format!("{} is empty", path.display())));
        }
        Self::from_bytes(&bytes)
    }

    /// Decrypt all file names in place using the depot's key, given as the 64-character hex
    /// string.
    ///
    /// No-op if `filenames_encrypted` is false. Afterwards `filenames_encrypted()` returns
    /// false and files are sorted case-insensitively (matching Steam).
    ///
    /// # Errors
    ///
    /// Fails with [`Error::ManifestNameDecrypt`] when the hex key is invalid or a name cannot
    /// be decrypted (wrong key / corrupt data).
    pub fn decrypt_filenames(&mut self, depot_key_hex: &str) -> Result<()> {
        if !self.filenames_encrypted {
            return Ok(());
        }
        let depot_key = util::parse_hex_key(depot_key_hex).ok_or_else(|| {
            Error::ManifestNameDecrypt(
                "invalid depot key: expected exactly 64 hex characters".to_owned(),
            )
        })?;
        self.decrypt_filenames_with(&depot_key)
    }

    /// Internal variant for already-parsed keys (the download engine holds `[u8; 32]`).
    pub(crate) fn decrypt_filenames_with(&mut self, depot_key: &[u8; 32]) -> Result<()> {
        if !self.filenames_encrypted {
            return Ok(());
        }
        names::decrypt_names(&mut self.files, depot_key)?;
        self.filenames_encrypted = false;
        // Steam sorts after decryption with OrdinalIgnoreCase; lowercase-ordinal is the
        // closest portable approximation.
        self.files.sort_by_key(|file| file.path.to_lowercase());
        Ok(())
    }

    #[must_use]
    pub fn depot_id(&self) -> u32 {
        self.depot_id
    }

    #[must_use]
    pub fn manifest_gid(&self) -> u64 {
        self.manifest_gid
    }

    #[must_use]
    pub fn creation_unix(&self) -> u32 {
        self.creation_unix
    }

    #[must_use]
    pub fn filenames_encrypted(&self) -> bool {
        self.filenames_encrypted
    }

    #[must_use]
    pub fn total_size_uncompressed(&self) -> u64 {
        self.total_size_uncompressed
    }

    #[must_use]
    pub fn total_size_compressed(&self) -> u64 {
        self.total_size_compressed
    }

    #[must_use]
    pub fn files(&self) -> &[ManifestFile] {
        &self.files
    }

    /// Consume into the file list.
    #[must_use]
    pub(crate) fn into_files(self) -> Vec<ManifestFile> {
        self.files
    }

    fn from_sections(raw: parse::RawSections) -> Result<Self> {
        let metadata = raw.metadata;
        let depot_id = metadata
            .depot_id
            .ok_or_else(|| Error::Manifest("metadata is missing depot_id".to_owned()))?;
        let manifest_gid = metadata
            .gid_manifest
            .ok_or_else(|| Error::Manifest("metadata is missing gid_manifest".to_owned()))?;

        let mut files = Vec::with_capacity(raw.payload.mappings.len());
        for mapping in raw.payload.mappings {
            let filename = mapping
                .filename
                .ok_or_else(|| Error::Manifest("file entry is missing a filename".to_owned()))?;

            let mut chunks = Vec::with_capacity(mapping.chunks.len());
            for chunk in mapping.chunks {
                let sha = chunk.sha.ok_or_else(|| {
                    Error::Manifest(format!("chunk of '{filename}' is missing sha"))
                })?;
                let id: [u8; 20] = sha.as_slice().try_into().map_err(|_| {
                    Error::Manifest(format!(
                        "chunk of '{filename}' has a {}-byte sha",
                        sha.len()
                    ))
                })?;
                chunks.push(ManifestChunk {
                    id,
                    adler32: chunk.crc.unwrap_or(0),
                    offset: chunk.offset.unwrap_or(0),
                    len_uncompressed: chunk.cb_original.unwrap_or(0),
                    len_compressed: chunk.cb_compressed.unwrap_or(0),
                });
            }

            let sha_content = match mapping.sha_content {
                Some(bytes) => Some(bytes.as_slice().try_into().map_err(|_| {
                    Error::Manifest(format!(
                        "file '{filename}' has a {}-byte content hash",
                        bytes.len()
                    ))
                })?),
                None => None,
            };

            files.push(ManifestFile {
                // Plaintext names keep their original separators here; encrypted names are
                // normalized during decryption. Both are normalized below or in names.rs.
                path: filename.replace('\\', "/"),
                size: mapping.size.unwrap_or(0),
                flags: mapping.flags.unwrap_or(0),
                sha_content,
                link_target: mapping.linktarget.filter(|target| !target.is_empty()),
                chunks,
            });
        }

        Ok(DepotManifest {
            depot_id,
            manifest_gid,
            creation_unix: metadata.creation_time.unwrap_or(0),
            filenames_encrypted: metadata.filenames_encrypted.unwrap_or(false),
            total_size_uncompressed: metadata.cb_disk_original.unwrap_or(0),
            total_size_compressed: metadata.cb_disk_compressed.unwrap_or(0),
            files,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use parse::tests::fixture_section_stream;

    #[test]
    fn parses_synthetic_manifest() {
        let bytes = fixture_section_stream(731, 7617, false);
        let manifest = DepotManifest::from_bytes(&bytes).expect("parse");
        assert_eq!(manifest.depot_id(), 731);
        assert_eq!(manifest.manifest_gid(), 7617);
        assert!(!manifest.filenames_encrypted());
        assert_eq!(manifest.files().len(), 2);
        assert_eq!(manifest.files()[0].path, "bin/game.exe");
        assert_eq!(manifest.files()[0].chunks[0].len_uncompressed, 3);
    }

    #[test]
    fn rejects_garbage() {
        assert!(DepotManifest::from_bytes(b"nonsense").is_err());
        assert!(DepotManifest::from_bytes(b"").is_err());
    }

    #[test]
    fn normalization_of_backslashes() {
        let bytes = fixture_section_stream(1, 1, false);
        let manifest = DepotManifest::from_bytes(&bytes).expect("parse");
        assert!(manifest.files().iter().all(|f| !f.path.contains('\\')));
    }

    #[test]
    fn parses_real_plaintext_fixture() {
        // Spacewar depot 481 manifest captured from Steam (plaintext names).
        let bytes = include_bytes!("../../tests/fixtures/space war, decrypted filenames.manifest");
        let manifest = DepotManifest::from_bytes(bytes).expect("real manifest parses");
        assert_eq!(manifest.depot_id(), 481);
        assert_eq!(manifest.manifest_gid(), 3_183_503_801_510_301_321);
        assert!(!manifest.filenames_encrypted());
        assert!(
            manifest
                .files()
                .iter()
                .any(|f| f.path.ends_with("controller.vdf"))
        );
    }

    #[test]
    fn parses_real_encrypted_fixture_and_decrypts() {
        // Aion 2 (free game) manifest captured via the Steam console - filenames encrypted,
        // depot key captured alongside. This guards decryption against real-world data:
        // Steam wraps long base64 names across lines, which .NET tolerates and strict
        // base64 decoders do not.
        let bytes = include_bytes!("../../tests/fixtures/aion 2, encrypted filenames.manifest");
        let manifest = DepotManifest::from_bytes(bytes).expect("real manifest parses");
        assert_eq!(manifest.depot_id(), 3_393_111);
        assert_eq!(manifest.manifest_gid(), 9_124_639_090_373_514_581);
        assert!(manifest.filenames_encrypted());
        assert_eq!(manifest.files().len(), 1375);
        // Encrypted names are base64 - only the base64 alphabet plus the line-wrapping
        // whitespace Steam embeds (`/` IS part of the base64 alphabet).
        assert!(
            manifest
                .files()
                .iter()
                .all(|f| f.path.chars().all(|c| c.is_ascii_alphanumeric()
                    || c.is_ascii_whitespace()
                    || matches!(c, '+' | '/' | '=')))
        );

        let mut manifest = manifest;
        manifest
            .decrypt_filenames(include_str!("../../tests/fixtures/aion 2 key.txt"))
            .expect("decrypts real-world names");
        assert!(!manifest.filenames_encrypted());
        assert!(manifest.files().iter().all(|f| !f.path.is_empty()));
        // Real paths are readable now (nested game files).
        assert!(
            manifest
                .files()
                .iter()
                .any(|f| f.path.contains('/') || f.path.contains('.'))
        );
    }
}
