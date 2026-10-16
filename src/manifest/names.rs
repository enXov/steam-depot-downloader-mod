//! Decryption of manifest file names (AES-256 with the depot key).
//!
//! Wire format per name: base64 of `AES256-ECB(key, iv) ++ AES256-CBC(key, iv, name\0, PKCS7)`.

use aes::cipher::{BlockDecrypt, BlockDecryptMut, KeyInit, KeyIvInit};
use base64::Engine;
use cbc::cipher::block_padding::Pkcs7;

use crate::error::{Error, Result};
use crate::manifest::ManifestFile;

pub(super) fn decrypt_names(files: &mut [ManifestFile], key: &[u8; 32]) -> Result<()> {
    for file in files.iter_mut() {
        file.path = decrypt_one(key, &file.path)?;

        if let Some(target) = file.link_target.take() {
            file.link_target = Some(decrypt_one(key, &target)?);
        }
    }
    Ok(())
}

fn decrypt_one(key: &[u8; 32], encoded: &str) -> Result<String> {
    // .NET's base64 converter (what Steam uses) silently ignores embedded whitespace -
    // Steam wraps long encrypted names across lines. Mirror that before decoding.
    let cleaned: String = encoded
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();

    let blob = base64::engine::general_purpose::STANDARD
        .decode(cleaned.as_bytes())
        .map_err(|e| Error::ManifestNameDecrypt(format!("'{encoded}' is not valid base64: {e}")))?;

    if blob.len() < 32 || blob.len() % 16 != 0 {
        return Err(Error::ManifestNameDecrypt(format!(
            "encrypted name has invalid length {} (need a multiple of 16 with a 16-byte IV prefix)",
            blob.len()
        )));
    }

    // First block: the CBC IV, itself AES-ECB-encrypted.
    let cipher = aes::Aes256::new_from_slice(key).expect("key length is enforced by type");
    let mut iv: [u8; 16] = blob[..16].try_into().expect("16-byte slice");
    cipher.decrypt_block((&mut iv).into());

    // Remainder: AES-256-CBC with PKCS7 padding.
    let mut plaintext = cbc::Decryptor::<aes::Aes256>::new_from_slices(key, &iv)
        .expect("key/iv sizes")
        .decrypt_padded_vec_mut::<Pkcs7>(&blob[16..])
        .map_err(|e| Error::ManifestNameDecrypt(format!("CBC/PKCS7 decrypt failed: {e}")))?;

    // Steam NUL-terminates the name.
    while plaintext.last() == Some(&0) {
        plaintext.pop();
    }

    // FromUTF8-lossy mirrors C#'s (utf8, replacement chars) behavior; separator canonicalization
    // happens here once, so every later consumer can treat `/` as the only separator.
    let name = String::from_utf8_lossy(&plaintext).replace('\\', "/");
    Ok(name)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::manifest::DepotManifest;
    use crate::manifest::parse::tests::{TEST_DEPOT_KEY, fixture_section_stream};
    use crate::util;

    #[test]
    fn roundtrips_pair() {
        let name = "common/media/logo.png";
        let encrypted = encrypt_fixture_name_passthrough(name);
        let decrypted = decrypt_one(&TEST_DEPOT_KEY, &encrypted).expect("decrypts");
        assert_eq!(decrypted, name);
    }

    #[test]
    fn decrypts_full_manifest() {
        let bytes = fixture_section_stream(731, 99, true);
        let mut manifest = DepotManifest::from_bytes(&bytes).expect("parse");

        // Names are base64 gibberish before decryption.
        assert_ne!(manifest.files()[0].path, "bin/game.exe");

        manifest
            .decrypt_filenames(&hex_test_key())
            .expect("decrypt names");
        assert_eq!(manifest.files()[0].path, "bin/game.exe");
        assert!(!manifest.filenames_encrypted());
    }

    #[test]
    fn wrong_key_fails_cleanly() {
        // Right key works and clears the encrypted flag…
        let bytes = fixture_section_stream(731, 99, true);
        let mut manifest = DepotManifest::from_bytes(&bytes).expect("parse");
        assert!(manifest.decrypt_filenames(&hex_test_key()).is_ok());
        assert!(!manifest.filenames_encrypted());

        // …so a fresh manifest is needed to prove the wrong key errors out.
        let bytes = fixture_section_stream(731, 99, true);
        let mut manifest = DepotManifest::from_bytes(&bytes).expect("parse");
        let wrong_hex = util::to_hex_lower(&[0x11; 32]);
        assert!(manifest.decrypt_filenames(&wrong_hex).is_err());

        // Garbage hex is rejected up front, before any crypto runs.
        assert!(manifest.decrypt_filenames("not-hex").is_err());
    }

    fn hex_test_key() -> String {
        util::to_hex_lower(&TEST_DEPOT_KEY)
    }

    #[test]
    fn sorted_after_decrypt() {
        let bytes = fixture_section_stream(731, 99, true);
        let mut manifest = DepotManifest::from_bytes(&bytes).expect("parse");
        manifest
            .decrypt_filenames(&hex_test_key())
            .expect("decrypt");
        // "bin/game.exe" < "readme.txt" case-insensitively.
        assert_eq!(manifest.files()[0].path, "bin/game.exe");
        assert_eq!(manifest.files()[1].path, "readme.txt");
    }

    /// Local re-export to keep the test self-explanatory.
    fn encrypt_fixture_name_passthrough(name: &str) -> String {
        crate::manifest::parse::tests::encrypt_fixture_name(name, &TEST_DEPOT_KEY)
    }
}
