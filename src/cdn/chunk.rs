//! Depot chunk pipeline: AES-256 decrypt → compression container detect → decompress →
//! Adler-32 (seed 0) verify. Byte-compatible with SteamKit's `DepotChunk.Process`.
//!
//! Container formats (all little-endian):
//!
//! ```text
//! encrypted chunk  = AES256-ECB(key, iv) ++ AES256-CBC(key, iv, ciphertext, PKCS7)
//! decrypted chunk  = VZstd | VZip | zip
//!   VZstd = u32 "VSZa" ++ u32 crc32 ++ zstd-frame ++ u32 crc32 ++ u32 size ++ u32 ++ "zsv"
//!   VZip  = u16 "VZ" ++ u8 'a' ++ u32 crc/timestamp ++ u8 lzma-props ++ u32 dict-size
//!           ++ raw-lzma ++ u32 crc32 ++ i32 size ++ u16 "zv"
//!   zip   = regular PK zip archive with exactly one entry
//! ```

use std::cell::RefCell;
use std::io::{Cursor, Read};

use aes::cipher::{BlockDecrypt, BlockDecryptMut, KeyInit, KeyIvInit};
use cbc::cipher::block_padding::Pkcs7;

use crate::error::{Error, Result};
use crate::util;

const VZSTD_MAGIC_LE: u32 = 0x615A_5356; // bytes "VSZa"
const VZIP_FOOTER_LE: u16 = 0x767A; // bytes "zv"

/// Per-thread scratch state for [`process_chunk`].
///
/// Chunk processing runs once per chunk on `spawn_blocking` threads; without reuse, every
/// chunk of a depot would allocate and free the same multi-megabyte buffers (AES-CBC
/// plaintext, decompressed output) plus a fresh zstd decompression context. The state is
/// thread-local, so it needs no locking and consecutive chunks on the same blocking thread
/// keep their allocations, their `DCtx`, and their cache warmth.
///
/// Downsides are on purpose: it is only reachable from [`process_chunk`]'s
/// `thread_local!` access, the buffers are never `Send`, and the `DCtx` is dropped with the
/// thread that created it.
struct ChunkScratch {
    /// AES-CBC plaintext - the still container-framed payload, grown to fit and retained.
    plain: Vec<u8>,
    /// Decompressed chunk content, sized to the container's declared output length.
    out: Vec<u8>,
    /// Reusable zstd decompression context.
    dctx: zstd::bulk::Decompressor<'static>,
}

impl ChunkScratch {
    fn new() -> Self {
        ChunkScratch {
            plain: Vec::new(),
            out: Vec::new(),
            dctx: zstd::bulk::Decompressor::new().expect("zstd DCtx"),
        }
    }
}

thread_local! {
    static CHUNK_SCRATCH: RefCell<ChunkScratch> = RefCell::new(ChunkScratch::new());
}

/// Why a downloaded chunk could not be turned into file content, classified for the CDN retry
/// loop ([`super::client::CdnClient::fetch_chunk`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChunkFailureKind {
    /// The body decrypted but its content is bad (container framing, decompression, size,
    /// Adler-32): a corrupt server response - another server may well have a good copy.
    Corrupt,
    /// AES-CBC/PKCS7 decryption failed. Almost always a wrong depot key - which no server can
    /// fix - but a corrupted last block looks the same, so the retry loop allows exactly one
    /// more server before giving up.
    Decrypt,
    /// Local failure (writing the chunk to disk): never a server's fault.
    Local,
}

/// A chunk processing error plus its retry classification.
#[derive(Debug)]
pub(crate) struct ChunkFailure {
    pub(crate) kind: ChunkFailureKind,
    pub(crate) error: Error,
}

impl From<Error> for ChunkFailure {
    /// Content errors (the default inside [`process_into`]) are server-side corruption.
    fn from(error: Error) -> Self {
        ChunkFailure {
            kind: ChunkFailureKind::Corrupt,
            error,
        }
    }
}

/// Convenience wrapper that returns the decompressed chunk instead of writing it to a file.
///
/// Convenient for round-trip fixtures (and for callers that want the chunk in memory); the
/// download engine itself uses [`process_chunk_at`], which skips this copy entirely.
#[cfg(test)]
pub(crate) fn process_chunk(
    raw: &[u8],
    depot_key: &[u8; 32],
    expected_len: u32,
    expected_adler32: u32,
    chunk_id_hex: &str,
) -> Result<Vec<u8>> {
    CHUNK_SCRATCH.with(|scratch| {
        let mut scratch = scratch.borrow_mut();
        process_into(
            &mut scratch,
            raw,
            depot_key,
            expected_len,
            expected_adler32,
            chunk_id_hex,
        )
        .map_err(|failure| failure.error)?;
        // The scratch buffer is sized exactly right from the container, so this is the last
        // allocation its capacity ever pays for.
        Ok(scratch.out.clone())
    })
}

/// Process a chunk and write it straight to its final offset(s) in `file`.
///
/// This is the engine's hot path: compared to [`process_chunk`], it skips the copy of the
/// decompressed output out of the scratch buffer, so a chunk is decrypted, decompressed and
/// written with no allocation beyond its network body. A chunk that occurs several times in
/// the same file is processed once and written to every offset in `offsets`.
pub(crate) fn process_chunk_at(
    raw: &[u8],
    depot_key: &[u8; 32],
    expected_len: u32,
    expected_adler32: u32,
    chunk_id_hex: &str,
    file: &std::fs::File,
    offsets: &[u64],
) -> std::result::Result<(), ChunkFailure> {
    CHUNK_SCRATCH.with(|scratch| {
        let mut scratch = scratch.borrow_mut();
        process_into(
            &mut scratch,
            raw,
            depot_key,
            expected_len,
            expected_adler32,
            chunk_id_hex,
        )?;
        for &offset in offsets {
            crate::fileio::write_at(file, &scratch.out, offset).map_err(|e| ChunkFailure {
                kind: ChunkFailureKind::Local,
                error: Error::Io(e),
            })?;
        }
        Ok(())
    })
}

/// The shared body of [`process_chunk`] and [`process_chunk_at`]: decrypt, decompress and
/// verify, leaving the decompressed chunk in `scratch.out`.
fn process_into(
    scratch: &mut ChunkScratch,
    raw: &[u8],
    depot_key: &[u8; 32],
    expected_len: u32,
    expected_adler32: u32,
    chunk_id_hex: &str,
) -> std::result::Result<(), ChunkFailure> {
    let chunk_err = |reason: String| Error::Chunk {
        chunk_id: chunk_id_hex.to_owned(),
        reason,
    };

    if raw.len() < 32 || (raw.len() - 16) % 16 != 0 {
        return Err(chunk_err(format!(
            "downloaded {} bytes; not a valid encrypted chunk",
            raw.len()
        ))
        .into());
    }

    // 1. Decrypt: first 16 bytes are the ECB-encrypted IV, remainder is CBC/PKCS7.
    let cipher = aes::Aes256::new_from_slice(depot_key).expect("32-byte key enforced by type");
    let mut iv: [u8; 16] = raw[..16].try_into().expect("16-byte slice");
    cipher.decrypt_block((&mut iv).into());

    // The body is decrypted in place into the retained scratch buffer. `clear` + `extend`
    // keeps the capacity without the redundant zero-fill a `resize` would pay for.
    let plain = &mut scratch.plain;
    plain.clear();
    plain.extend_from_slice(&raw[16..]);
    let decrypted_len = cbc::Decryptor::<aes::Aes256>::new_from_slices(depot_key, &iv)
        .expect("key/iv sizes")
        .decrypt_padded_mut::<Pkcs7>(plain)
        .map_err(|_| ChunkFailure {
            kind: ChunkFailureKind::Decrypt,
            error: chunk_err("CBC decrypt failed (wrong depot key?)".to_owned()),
        })?
        .len();
    let decrypted = &plain[..decrypted_len];

    // 2. Decompress by container magic, into the retained output buffer.
    let out = &mut scratch.out;
    if decrypted.starts_with(b"VSZa") {
        decompress_vzstd(decrypted, out, &mut scratch.dctx, &chunk_err)?
    } else if decrypted.starts_with(b"VZa") {
        decompress_vzip(decrypted, out, &chunk_err)?
    } else if decrypted.starts_with(b"PK\x03\x04") {
        decompress_zip(decrypted, out, &chunk_err)?
    } else {
        // No known container: the plaintext is garbage. With a wrong key, PKCS7 padding
        // happens to validate about 1 time in 256 and lands here - so classify it like a
        // decrypt failure, not as plain server corruption.
        let reason = if decrypted.len() >= 4 {
            format!(
                "unexpected compression magic 0x{} (wrong depot key?)",
                util::to_hex_lower(&decrypted[..4])
            )
        } else {
            format!("only {} bytes after decrypt", decrypted.len())
        };
        return Err(ChunkFailure {
            kind: ChunkFailureKind::Decrypt,
            error: chunk_err(reason),
        });
    }

    // 3. Verify against the manifest's expectations.
    if out.len() != expected_len as usize {
        return Err(chunk_err(format!(
            "decompressed to {} bytes, expected {expected_len}",
            out.len()
        ))
        .into());
    }
    let actual = crate::util::adler32_seed0(out);
    if actual != expected_adler32 {
        return Err(Error::Checksum {
            chunk_id: chunk_id_hex.to_owned(),
            expected: expected_adler32,
            actual,
        }
        .into());
    }
    Ok(())
}

fn decompress_vzstd(
    data: &[u8],
    out: &mut Vec<u8>,
    dctx: &mut zstd::bulk::Decompressor<'_>,
    err: &dyn Fn(String) -> Error,
) -> Result<()> {
    // header(8) + frame(≥1) + footer(15)
    if data.len() < 8 + 15 + 1 {
        return Err(err("VZstd data too short".to_owned()));
    }
    if u32::from_le_bytes(data[0..4].try_into().expect("4 bytes")) != VZSTD_MAGIC_LE {
        return Err(err("missing VZstd header".to_owned()));
    }
    let total = data.len();
    if !data.ends_with(b"zsv") {
        return Err(err("missing VZstd footer".to_owned()));
    }
    let frame = &data[8..total - 15];
    let size_decompressed =
        u32::from_le_bytes(data[total - 11..total - 7].try_into().expect("4 bytes")) as usize;

    // The footer declares the exact output size, so the destination is reserved to it once
    // instead of grown by doubling through an 8 KiB `io::copy` loop - measured 1.6x faster
    // per MiB. zstd sees `capacity`, not `len`, so a cleared buffer is reused as-is.
    out.clear();
    if out.capacity() < size_decompressed {
        out.reserve(size_decompressed);
    }
    let written = dctx
        .decompress_to_buffer(frame, &mut *out)
        .map_err(|e| err(format!("zstd decompress failed: {e}")))?;
    if written != size_decompressed {
        return Err(err(format!(
            "zstd produced {written} bytes, footer says {size_decompressed}"
        )));
    }
    Ok(())
}

fn decompress_vzip(data: &[u8], out: &mut Vec<u8>, err: &dyn Fn(String) -> Error) -> Result<()> {
    // header(7) + props(5) + lzma(≥1) + footer(10)
    if data.len() < 7 + 5 + 1 + 10 {
        return Err(err("VZip data too short".to_owned()));
    }
    if &data[0..2] != b"VZ" || data[2] != b'a' {
        return Err(err("missing VZip header".to_owned()));
    }
    // data[3..7] = creation timestamp or secondary CRC - meaning varies, never needed.

    // 5 bytes of LZMA properties: one packed lc/lp/pb byte + u32 dictionary size.
    let props_byte = data[7];
    let lc = u32::from(props_byte % 9);
    let remainder = u32::from(props_byte / 9);
    let lp = remainder % 5;
    let pb = remainder / 5;
    let dict_size = u32::from_le_bytes(data[8..12].try_into().expect("4 bytes")).max(4096);

    let total = data.len();
    if u16::from_le_bytes(data[total - 2..].try_into().expect("2 bytes")) != VZIP_FOOTER_LE {
        return Err(err("missing VZip footer".to_owned()));
    }
    // Footer (10 bytes from the end): crc32 ++ i32 size ++ "zv".
    let size_decompressed =
        i32::from_le_bytes(data[total - 6..total - 2].try_into().expect("4 bytes"));
    if size_decompressed < 0 {
        return Err(err("VZip declares a negative output size".to_owned()));
    }
    let size_decompressed = size_decompressed as u64;
    let lzma_payload = &data[12..total - 10];

    use lzma_rs::decompress::raw::{LzmaDecoder, LzmaParams, LzmaProperties};
    let params = LzmaParams::new(
        LzmaProperties { lc, lp, pb },
        dict_size,
        Some(size_decompressed),
    );
    let mut decoder =
        LzmaDecoder::new(params, None).map_err(|e| err(format!("lzma init failed: {e}")))?;

    // Appends from offset 0 through `Write`, so the retained capacity is reused for free.
    // `&[u8]` is already a `BufRead`; wrapping it in a `BufReader` would only add a copy.
    out.clear();
    // Reserve the declared size up front (capped: the footer is not yet verified, and real
    // chunks are ~1 MiB) so the decoder does not grow the buffer by doubling.
    out.reserve((size_decompressed as usize).min(16 * 1024 * 1024));
    let mut input = lzma_payload;
    decoder
        .decompress(&mut input, out)
        .map_err(|e| err(format!("lzma decompress failed: {e}")))?;
    if out.len() as u64 != size_decompressed {
        return Err(err(format!(
            "lzma produced {} bytes, footer says {size_decompressed}",
            out.len()
        )));
    }
    Ok(())
}

fn decompress_zip(data: &[u8], out: &mut Vec<u8>, err: &dyn Fn(String) -> Error) -> Result<()> {
    let mut archive = zip::ZipArchive::new(Cursor::new(data))
        .map_err(|e| err(format!("zip container corrupt: {e}")))?;
    if archive.len() != 1 {
        return Err(err(format!(
            "zip chunk contains {} entries, expected 1",
            archive.len()
        )));
    }
    out.clear();
    archive
        .by_index(0)
        .map_err(|e| err(format!("zip container corrupt: {e}")))?
        .read_to_end(out)
        .map_err(|e| err(format!("zip container corrupt: {e}")))?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    //! Round-trip fixtures: compress + encrypt data exactly the way Steam serves it, then make
    //! sure [`process_chunk`] comes back to the original bytes - for all three containers.

    use super::*;
    use aes::cipher::BlockEncrypt;
    use cbc::cipher::BlockEncryptMut;
    use lzma_rs::compress::{Options as LzmaOptions, UnpackedSize};

    #[derive(Clone, Copy)]
    pub(crate) enum PackMode {
        Zstd,
        Lzma,
        Zip,
    }

    fn crc32(data: &[u8]) -> u32 {
        crc32fast::hash(data)
    }

    fn vzstd_pack(content: &[u8]) -> Vec<u8> {
        let frame = zstd::encode_all(content, 3).expect("zstd encode");
        let crc = crc32(content);
        let size = (content.len() as u32).to_le_bytes();
        let mut out = Vec::with_capacity(frame.len() + 23);
        out.extend_from_slice(&VZSTD_MAGIC_LE.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&frame);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size);
        out.extend_from_slice(&[0; 4]); // third footer word, never read by decoders
        out.extend_from_slice(b"zsv");
        out
    }

    fn vzip_pack(content: &[u8]) -> Vec<u8> {
        // Produce a proper .lzma stream and reuse its 13-byte header fields, then strip the
        // header to get the raw LZMA bitstream VZip expects.
        let mut full = Vec::new();
        lzma_rs::lzma_compress_with_options(
            &mut &content[..],
            &mut full,
            &LzmaOptions {
                unpacked_size: UnpackedSize::WriteToHeader(Some(content.len() as u64)),
            },
        )
        .expect("lzma encode");
        let props_byte = full[0];
        let dict_size = &full[1..5];
        let raw_lzma = &full[13..];

        let mut out = Vec::new();
        out.extend_from_slice(b"VZ");
        out.push(b'a');
        out.extend_from_slice(&crc32(content).to_le_bytes());
        out.push(props_byte);
        out.extend_from_slice(dict_size);
        out.extend_from_slice(raw_lzma);
        out.extend_from_slice(&crc32(content).to_le_bytes());
        out.extend_from_slice(&(content.len() as u32).to_le_bytes());
        out.extend_from_slice(&VZIP_FOOTER_LE.to_le_bytes());
        out
    }

    fn zip_pack(content: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut zipped = Vec::new();
        {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut zipped));
            writer
                .start_file::<_, ()>("chunk", zip::write::FileOptions::default())
                .expect("zip entry");
            writer.write_all(content).expect("zip write");
            writer.finish().expect("zip finish");
        }
        zipped
    }

    /// AES-encrypt `data` exactly like Steam's chunk store: ECB-encrypted IV prefix, then
    /// CBC/PKCS7.
    pub(crate) fn encrypt_steam_style(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
        let iv: [u8; 16] = [0x24; 16];
        let mut encrypted_iv = iv;
        aes::Aes256::new_from_slice(key)
            .expect("key size")
            .encrypt_block((&mut encrypted_iv).into());

        let encrypted = cbc::Encryptor::<aes::Aes256>::new_from_slices(key, &iv)
            .expect("key/iv sizes")
            .encrypt_padded_vec_mut::<Pkcs7>(data);

        let mut out = encrypted_iv.to_vec();
        out.extend_from_slice(&encrypted);
        out
    }

    /// Full round-trip helper: pick a container, compress, encrypt.
    pub(crate) fn pack_chunk(content: &[u8], key: &[u8; 32], mode: PackMode) -> Vec<u8> {
        let compressed = match mode {
            PackMode::Zstd => vzstd_pack(content),
            PackMode::Lzma => vzip_pack(content),
            PackMode::Zip => zip_pack(content),
        };
        encrypt_steam_style(&compressed, key)
    }

    #[test]
    fn roundtrip_all_containers() {
        let key = [0x42; 32];
        let content: Vec<u8> = (0..50_000u32).map(|i| (i % 250) as u8).collect();
        let adler = crate::util::adler32_seed0(&content);

        for mode in [PackMode::Zstd, PackMode::Lzma, PackMode::Zip] {
            let packed = pack_chunk(&content, &key, mode);
            let out = process_chunk(&packed, &key, content.len() as u32, adler, "test")
                .expect("roundtrip");
            assert_eq!(out, content);
        }
    }

    #[test]
    fn wrong_key_fails() {
        let content = b"hello steam".to_vec();
        let adler = crate::util::adler32_seed0(&content);
        let packed = pack_chunk(&content, &[0x42; 32], PackMode::Zstd);
        assert!(process_chunk(&packed, &[0x11; 32], content.len() as u32, adler, "x").is_err());
    }

    #[test]
    fn corrupt_checksum_fails_with_checksum_error() {
        let key = [0x42; 32];
        let content = b"checksumme".to_vec();
        let packed = pack_chunk(&content, &key, PackMode::Zip);
        // Correct size, wrong adler.
        let err = process_chunk(&packed, &key, content.len() as u32, 0xDEADBEEF, "c")
            .expect_err("checksum must fail");
        assert!(matches!(err, Error::Checksum { .. }));
    }
}
