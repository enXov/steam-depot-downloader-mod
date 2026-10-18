//! Binary framing of the on-disk `.manifest` format.

use prost::Message;
use steam_protobuf_rs::{ContentManifestMetadata, ContentManifestPayload};

use crate::error::{Error, Result};

pub(crate) const PAYLOAD_MAGIC: u32 = 0x71F6_17D0;
pub(crate) const METADATA_MAGIC: u32 = 0x1F48_12BE;
pub(crate) const SIGNATURE_MAGIC: u32 = 0x1B81_B817;
pub(crate) const EOF_MAGIC: u32 = 0x32C4_15AB;
/// Very old depotcache manifests; intentionally unsupported (Steam has served v5 protobuf
/// manifests since 2017 and every reasonably recent manifest file is one).
const LEGACY_V4_MAGIC: u32 = 0x1634_9781;

/// The sections we care about. The manifest signature section is parsed past but ignored -
/// it is never needed for downloads (SteamKit skips signature verification too).
pub(crate) struct RawSections {
    pub payload: ContentManifestPayload,
    pub metadata: ContentManifestMetadata,
}

/// Parse the bytes of a raw `.manifest` file.
pub(crate) fn parse(data: &[u8]) -> Result<RawSections> {
    let mut cursor = 0usize;
    let mut payload = None;
    let mut metadata = None;

    loop {
        let magic = read_u32(data, &mut cursor)?;
        if magic == EOF_MAGIC {
            break;
        }
        if magic == LEGACY_V4_MAGIC {
            return Err(Error::Manifest(
                "legacy (pre-2017) binary manifests are not supported".to_owned(),
            ));
        }

        let len = read_u32(data, &mut cursor)? as usize;
        let section = data.get(cursor..cursor + len).ok_or_else(|| {
            Error::Manifest(format!(
                "section with magic {magic:#010x} extends past end of file"
            ))
        })?;
        cursor += len;

        match magic {
            PAYLOAD_MAGIC => {
                payload = Some(
                    ContentManifestPayload::decode(section)
                        .map_err(|e| Error::Manifest(format!("payload protobuf corrupt: {e}")))?,
                );
            }
            METADATA_MAGIC => {
                metadata = Some(
                    ContentManifestMetadata::decode(section)
                        .map_err(|e| Error::Manifest(format!("metadata protobuf corrupt: {e}")))?,
                );
            }
            SIGNATURE_MAGIC => {
                // Content never used for downloading (see RawSections docs).
            }
            other => {
                return Err(Error::Manifest(format!(
                    "unrecognized section magic {other:#010x} - is this a raw .manifest file, not a zip?"
                )));
            }
        }
    }

    match (payload, metadata) {
        (Some(payload), Some(metadata)) => Ok(RawSections { payload, metadata }),
        _ => Err(Error::Manifest(
            "manifest is missing its payload or metadata section".to_owned(),
        )),
    }
}

fn read_u32(data: &[u8], cursor: &mut usize) -> Result<u32> {
    let raw = data.get(*cursor..*cursor + 4).ok_or_else(|| {
        Error::Manifest("unexpected end of manifest (missing EOF marker?)".to_owned())
    })?;
    *cursor += 4;
    Ok(u32::from_le_bytes(raw.try_into().expect("4-byte slice")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use super::*;
    use steam_protobuf_rs::ContentManifestSignature;
    use steam_protobuf_rs::content_manifest_payload::{FileMapping, file_mapping::ChunkData};

    /// Fixed key used by every encrypted-name/chunk fixture in this crate's tests.
    pub(crate) const TEST_DEPOT_KEY: [u8; 32] = [0x42; 32];

    /// AES-256-encrypts `name` the way Steam does for manifests with encrypted filenames
    /// (ECB-encrypted IV prefix + CBC/PKCS7, NUL-terminated), then base64s it.
    pub(crate) fn encrypt_fixture_name(name: &str, key: &[u8; 32]) -> String {
        use aes::cipher::{BlockEncrypt, KeyInit, KeyIvInit};
        use base64::Engine;
        use cbc::cipher::BlockEncryptMut;

        let cipher = aes::Aes256::new_from_slice(key).expect("32-byte key");

        // NUL terminator, then PKCS7 pads to a block boundary.
        let mut plain = name.as_bytes().to_vec();
        plain.push(0);

        let iv: [u8; 16] = [0x24; 16];
        let encrypted = cbc::Encryptor::<aes::Aes256>::new_from_slices(key, &iv)
            .expect("key/iv sizes")
            .encrypt_padded_vec_mut::<cbc::cipher::block_padding::Pkcs7>(&plain);

        let mut encrypted_iv = iv;
        cipher.encrypt_block((&mut encrypted_iv).into());

        let mut blob = encrypted_iv.to_vec();
        blob.extend_from_slice(&encrypted);
        base64::engine::general_purpose::STANDARD.encode(blob)
    }

    fn write_section(magic: u32, message: &impl Message, out: &mut Vec<u8>) {
        out.extend_from_slice(&magic.to_le_bytes());
        let bytes = message.encode_to_vec();
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&bytes);
    }

    /// A small but complete synthetic manifest: `bin\game.exe` (one 3-byte chunk) + empty
    /// `readme.txt`. When `encrypted`, names are Steam-style encrypted with [`TEST_DEPOT_KEY`].
    pub(crate) fn fixture_section_stream(depot_id: u32, gid: u64, encrypted: bool) -> Vec<u8> {
        let entry = |name: &str, size, flags, chunks| FileMapping {
            filename: Some(if encrypted {
                encrypt_fixture_name(name, &TEST_DEPOT_KEY)
            } else {
                name.to_owned()
            }),
            size: Some(size),
            flags: Some(flags),
            sha_filename: Some(vec![0; 20]),
            sha_content: Some(vec![1; 20]),
            chunks,
            linktarget: None,
        };

        let payload = ContentManifestPayload {
            mappings: vec![
                entry(
                    "bin\\game.exe",
                    3,
                    32,
                    vec![ChunkData {
                        sha: Some(vec![2; 20]),
                        crc: Some(crate::util::adler32_seed0(b"abc")),
                        offset: Some(0),
                        cb_original: Some(3),
                        cb_compressed: Some(0),
                    }],
                ),
                entry("readme.txt", 0, 0, vec![]),
            ],
        };
        let metadata = ContentManifestMetadata {
            depot_id: Some(depot_id),
            gid_manifest: Some(gid),
            creation_time: Some(1_700_000_000),
            filenames_encrypted: Some(encrypted),
            cb_disk_original: Some(3),
            cb_disk_compressed: Some(0),
            unique_chunks: Some(1),
            crc_encrypted: None,
            crc_clear: None,
        };
        let signature = ContentManifestSignature {
            signature: Some(vec![9; 8]),
        };

        let mut out = Vec::new();
        write_section(PAYLOAD_MAGIC, &payload, &mut out);
        write_section(METADATA_MAGIC, &metadata, &mut out);
        write_section(SIGNATURE_MAGIC, &signature, &mut out);
        out.extend_from_slice(&EOF_MAGIC.to_le_bytes());
        out
    }

    #[test]
    fn parses_sections_and_ignores_signature() {
        let bytes = fixture_section_stream(731, 42, false);
        let raw = parse(&bytes).expect("parse");
        assert_eq!(raw.metadata.depot_id, Some(731));
        assert_eq!(raw.payload.mappings.len(), 2);
    }

    #[test]
    fn detects_legacy_and_garbage() {
        let mut legacy = LEGACY_V4_MAGIC.to_le_bytes().to_vec();
        legacy.extend_from_slice(&[0; 32]);
        assert!(parse(&legacy).is_err());
        assert!(parse(&[0xDE, 0xAD]).is_err());
    }
}
