//! The same pipeline as the rest of this suite, but against Steam's **live** CDN.
//!
//! Every test in `src/` is offline on purpose: it mocks the wire format so it can never fail
//! because of a network hiccup or a Steam outage. That means nothing has ever confirmed the
//! crate works against the real thing - the manifest framing, the chunk URLs, the AES-256
//! container, the depot key. These tests are that confirmation.
//!
//! They only succeed with the live CDN, so they are `#[ignore]`d: on demand, never in CI.
//!
//! ```sh
//! cargo test --release --test live_download -- --ignored
//! ```
//!
//! Each test owns its own temp directory, so they are independent and can run in any order.

use std::path::{Path, PathBuf};

use steam_depot_downloader_mod::{DepotDownloader, DepotManifest, DownloadRequest, ProgressEvent};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// Spacewar - Steam's own Steamworks example app. 8 files, ~1.9 MiB uncompressed: small
/// enough that pulling it in full is a few seconds.
const APP_ID: u32 = 480;
const DEPOT_ID: u32 = 481;

/// The one fixture pair this crate ships: the raw `.manifest` and its depot key.
fn fixture() -> (PathBuf, String) {
    let manifest = Path::new(FIXTURES).join("space war, decrypted filenames.manifest");
    let key = std::fs::read_to_string(Path::new(FIXTURES).join("space war key.txt"))
        .expect("fixture depot key")
        .trim()
        .to_owned();
    assert!(manifest.exists(), "fixture manifest missing");
    (manifest, key)
}

/// A directory that is unique per test run, so repeated runs do not inherit each other's
/// files (and with them each other's state, which would defeat the "fresh download" pass).
/// The tag keeps two `#[tokio::test]`s in the same binary - same PID - in their own trees.
fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sddm-live-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Download the fixture depot, collecting its report.
async fn download(out_dir: &Path) -> steam_depot_downloader_mod::DownloadReport {
    let (manifest, key) = fixture();
    let request = DownloadRequest::builder()
        .app_id(APP_ID)
        .depots([(manifest, key)])
        .output_dir(out_dir)
        .build()
        .expect("request builds");

    let downloader = DepotDownloader::new().expect("downloader");
    let mut handle = downloader.download(request);
    while let Some(event) = handle.events().recv().await {
        if let ProgressEvent::DepotFailed { depot_id, error } = event {
            panic!("depot {depot_id:?} failed: {error}");
        }
        if matches!(event, ProgressEvent::Finished { .. }) {
            break;
        }
    }
    handle.join().await.expect("run completes")
}

/// Every content file the manifest lists, as it should end up on disk.
fn expected_files(manifest: &DepotManifest) -> Vec<(String, u64)> {
    manifest
        .files()
        .iter()
        .filter(|f| !f.is_directory() && !f.is_symlink())
        .map(|f| (f.path.replace('\\', "/"), f.size))
        .collect()
}

/// Parse the fixture manifest - the ground truth for what a correct download produces.
fn manifest() -> DepotManifest {
    let (path, _) = fixture();
    DepotManifest::from_bytes(&std::fs::read(path).expect("manifest bytes"))
        .expect("fixture manifest parses")
}

#[tokio::test]
#[ignore = "downloads from Steam's live CDN"]
async fn fresh_download_then_verify_downloads_nothing() {
    let out = scratch_dir("fresh");
    let manifest = manifest();
    let expected = expected_files(&manifest);

    // 1. Fresh: every chunk comes over the wire.
    let fresh = download(&out).await;
    assert!(!fresh.has_failures(), "{fresh:?}");
    assert_eq!(fresh.depots.len(), 1);
    let depot = &fresh.depots[0];
    assert_eq!(depot.depot_id, Some(DEPOT_ID));
    assert_eq!(depot.manifest_gid, Some(manifest.manifest_gid()));
    assert_eq!(depot.files, expected.len());
    assert_eq!(fresh.uncompressed_bytes, manifest.total_size_uncompressed());
    // Something actually arrived, and it is the depot's whole compressed body.
    assert!(depot.downloaded_bytes > 0);
    assert_eq!(fresh.downloaded_bytes, manifest.total_size_compressed());

    // The tree matches the manifest: same files, same sizes.
    for (path, size) in &expected {
        let on_disk = std::fs::metadata(out.join(path))
            .unwrap_or_else(|e| panic!("{} missing: {e}", path))
            .len();
        assert_eq!(
            on_disk, *size,
            "{} is {} bytes, manifest says {size}",
            path, on_disk
        );
    }

    // 2. Same manifest again: every chunk is read back and Adler-32 checked, so the second
    //    run must cost nothing over the wire.
    let again = download(&out).await;
    assert!(!again.has_failures(), "{again:?}");
    assert_eq!(
        again.downloaded_bytes, 0,
        "re-verifying an intact install re-downloaded {} bytes",
        again.downloaded_bytes
    );
}

#[tokio::test]
#[ignore = "downloads from Steam's live CDN"]
async fn re_verifying_a_corrupted_chunk_fetches_only_that_chunk() {
    let out = scratch_dir("repair");
    let manifest = manifest();

    // Populate the tree first.
    let fresh = download(&out).await;
    assert!(!fresh.has_failures(), "{fresh:?}");

    // Corrupt one chunk of one file in place.
    let target = manifest
        .files()
        .iter()
        .find(|f| !f.is_directory() && !f.is_symlink() && f.chunks.len() == 1 && f.size > 1024)
        .expect("a single-chunk file to corrupt");
    let chunk = target.chunks.first().expect("one chunk");
    let path = out.join(target.path.replace('\\', "/"));
    let intact = std::fs::read(&path).expect("downloaded file");
    let mut damaged = intact.clone();
    for byte in &mut damaged
        [chunk.offset as usize..(chunk.offset + u64::from(chunk.len_uncompressed)) as usize]
    {
        *byte ^= 0xFF;
    }
    std::fs::write(&path, &damaged).expect("corrupted file");

    // The repair is chunk-granular: only the damaged chunk's compressed body comes back,
    // and the file ends up byte-identical to the first download.
    let repaired = download(&out).await;
    assert!(!repaired.has_failures(), "{repaired:?}");
    assert!(
        repaired.downloaded_bytes > 0,
        "a corrupted chunk was not re-downloaded"
    );
    assert!(
        repaired.downloaded_bytes < fresh.downloaded_bytes,
        "repairing one chunk re-downloaded {} bytes, more than the whole depot ({})",
        repaired.downloaded_bytes,
        fresh.downloaded_bytes
    );
    assert_eq!(
        std::fs::read(&path).expect("repaired file"),
        intact,
        "the repaired file is not byte-identical to the original download"
    );

    // And with the file healthy again, another run is free.
    let after = download(&out).await;
    assert!(!after.has_failures(), "{after:?}");
    assert_eq!(after.downloaded_bytes, 0);
}
