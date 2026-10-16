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

use std::io::{BufReader, Cursor, Read};

use aes::cipher::{BlockDecrypt, BlockDecryptMut, KeyInit, KeyIvInit};
use cbc::cipher::block_padding::Pkcs7;

use crate::error::{Error, Result};
use crate::util;

const VZSTD_MAGIC_LE: u32 = 0x615A_5356; // bytes "VSZa"
const VZIP_FOOTER_LE: u16 = 0x767A; // bytes "zv"

/// Fully process a downloaded chunk: decrypt with `depot_key`, decompress, and verify against
/// `expected_len`/`expected_adler32`.
///
/// Both error kinds ([`Error::Chunk`]/[`Error::Checksum`]) are classified as
/// retryable-on-another-server by the CDN retry taxonomy.
pub(crate) fn process_chunk(
    raw: &[u8],
    depot_key: &[u8; 32],
    expected_len: u32,
    expected_adler32: u32,
    chunk_id_hex: &str,
) -> Result<Vec<u8>> {
    let chunk_err = |reason: String| Error::Chunk {
        chunk_id: chunk_id_hex.to_owned(),
        reason,
    };

    if raw.len() < 32 || (raw.len() - 16) % 16 != 0 {
        return Err(chunk_err(format!(
            "downloaded {} bytes; not a valid encrypted chunk",
            raw.len()
        )));
    }

    // 1. Decrypt: first 16 bytes are the ECB-encrypted IV, remainder is CBC/PKCS7.
    let cipher = aes::Aes256::new_from_slice(depot_key).expect("32-byte key enforced by type");
    let mut iv: [u8; 16] = raw[..16].try_into().expect("16-byte slice");
    cipher.decrypt_block((&mut iv).into());

    let decrypted = cbc::Decryptor::<aes::Aes256>::new_from_slices(depot_key, &iv)
        .expect("key/iv sizes")
        .decrypt_padded_vec_mut::<Pkcs7>(&raw[16..])
        .map_err(|_| chunk_err("CBC decrypt failed (wrong depot key?)".to_owned()))?;

    // 2. Decompress by container magic.
    let out = if decrypted.starts_with(b"VSZa") {
        decompress_vzstd(&decrypted, &chunk_err)?
    } else if decrypted.starts_with(b"VZa") {
        decompress_vzip(&decrypted, &chunk_err)?
    } else if decrypted.starts_with(b"PK\x03\x04") {
        decompress_zip(&decrypted, &chunk_err)?
    } else if decrypted.len() >= 4 {
        return Err(chunk_err(format!(
            "unexpected compression magic 0x{}",
            util::to_hex_lower(&decrypted[..4])
        )));
    } else {
        return Err(chunk_err(format!(
            "only {} bytes after decrypt",
            decrypted.len()
        )));
    };

    // 3. Verify against the manifest's expectations.
    if out.len() != expected_len as usize {
        return Err(chunk_err(format!(
            "decompressed to {} bytes, expected {expected_len}",
            out.len()
        )));
    }
    let actual = util::adler32_seed0(&out);
    if actual != expected_adler32 {
        return Err(Error::Checksum {
            chunk_id: chunk_id_hex.to_owned(),
            expected: expected_adler32,
            actual,
        });
    }
    Ok(out)
}

fn decompress_vzstd(data: &[u8], err: &dyn Fn(String) -> Error) -> Result<Vec<u8>> {
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

    let out = zstd::decode_all(frame).map_err(|e| err(format!("zstd decompress failed: {e}")))?;
    if out.len() != size_decompressed {
        return Err(err(format!(
            "zstd produced {} bytes, footer says {size_decompressed}",
            out.len()
        )));
    }
    Ok(out)
}

fn decompress_vzip(data: &[u8], err: &dyn Fn(String) -> Error) -> Result<Vec<u8>> {
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

    let mut input = BufReader::new(lzma_payload);
    let mut out = Vec::with_capacity(size_decompressed as usize);
    decoder
        .decompress(&mut input, &mut out)
        .map_err(|e| err(format!("lzma decompress failed: {e}")))?;
    if out.len() as u64 != size_decompressed {
        return Err(err(format!(
            "lzma produced {} bytes, footer says {size_decompressed}",
            out.len()
        )));
    }
    Ok(out)
}

fn decompress_zip(data: &[u8], err: &dyn Fn(String) -> Error) -> Result<Vec<u8>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(data))
        .map_err(|e| err(format!("zip container corrupt: {e}")))?;
    if archive.len() != 1 {
        return Err(err(format!(
            "zip chunk contains {} entries, expected 1",
            archive.len()
        )));
    }
    let mut out = Vec::new();
    archive
        .by_index(0)
        .map_err(|e| err(format!("zip container corrupt: {e}")))?
        .read_to_end(&mut out)
        .map_err(|e| err(format!("zip container corrupt: {e}")))?;
    Ok(out)
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
        let adler = util::adler32_seed0(&content);

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
        let adler = util::adler32_seed0(&content);
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
