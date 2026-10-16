# steam-depot-downloader-mod

A Rust library for downloading Steam depot content using **user-supplied depot keys** and
**manifest files** - a library-first port of
[DepotDownloaderMod](https://github.com/enXov/DepotDownloaderMod) (itself a fork of
[SteamRE's DepotDownloader](https://github.com/SteamRE/DepotDownloader)), built on
[steam-protobuf-rs](https://crates.io/crates/steam-protobuf-rs).

DepotDownloader projects ship as CLI apps. That is fine for a terminal, but embedding them in a
GUI means shelling out to a process (and, for the `.dll` builds, installing a .NET runtime on
the target machine). This crate is the alternative: the same workflow as the mod, as a **native
Rust library** you call directly - no runtime, no subprocess, no console window.

## Install

```sh
cargo add steam-depot-downloader-mod
```

## Quick start

```rust,no_run
use std::path::PathBuf;
use steam_depot_downloader_mod::{DepotDownloader, DownloadRequest, ProgressEvent};

# async fn example() -> steam_depot_downloader_mod::Result<()> {
let request = DownloadRequest::builder()
    .app_id(730)
    // each depot is a (raw .manifest file, 64-char hex key) pair; the depot id and
    // manifest gid are read from the manifest's own metadata
    .depots([(
        PathBuf::from("731_7617088375292372759.manifest"),
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    )])
    .output_dir("./cs2")
    .build()?;

let downloader = DepotDownloader::new()?;
let mut handle = downloader.download(request);

while let Some(event) = handle.events().recv().await {
    match event {
        ProgressEvent::ChunkCompleted { total_downloaded, total_uncompressed, .. } => {
            println!("{total_downloaded} bytes ({total_uncompressed} uncompressed)");
        }
        ProgressEvent::Finished { .. } => break,
        _ => {}
    }
}

handle.cancel(); // anytime; or just let it run to completion
let report = handle.join().await?;
assert!(!report.has_failures());
# Ok(())
# }
```

## What this crate deliberately does not do

It implements the mod's feature set and nothing more:

- no Steam login / CM connection (anonymous or otherwise);
- no PICS app info, branch resolution, or license checks;
- no fetching of depot keys from Steam (the mod exists precisely to use external keys);
- no fetching of manifests that require a manifest request code - supply the manifest file yourself, which is the mod's own requirement.

## Testing

The test suite is fully offline: manifests, chunks and container formats (VZip/LZMA,
VZstd/zstd, zip) are exercised with round-trip fixtures byte-compatible with SteamKit, and the
entire download pipeline (including verify, update-reuse, failure isolation and cancellation)
runs against a `wiremock` fake CDN. A real captured manifest (`tests/fixtures/`) guards the
parser against real-world bytes.

## License

GPL-2.0-only - this crate is a behavioral port of the GPL-2.0 DepotDownloader.

## Credits

- [SteamRE](https://github.com/SteamRE) - DepotDownloader & SteamKit2, the original tools.
- [steam-protobuf-rs](https://github.com/enXov/steam-protobuf-rs) - the protobuf/enums layer this crate is built on.
- [DepotDownloaderMod](https://github.com/SteamAutoCracks/DepotDownloaderMod) - DepotDownloaderMod, the mod version of DepotDownloader that this crate is based on.
