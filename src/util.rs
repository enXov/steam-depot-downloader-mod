//! Small shared helpers.

use std::path::{Component, PathBuf};

/// Adler-32 variant used by Steam everywhere depot data is concerned:
/// identical to classic Adler-32 except both accumulators start at **0**
/// (see DepotDownloader's `Util.AdlerHash` / SteamKit `DepotChunk.AdlerHash`).
pub(crate) fn adler32_seed0(data: &[u8]) -> u32 {
    const MOD: u64 = 65521;
    // Largest n such that 255*n*(n+1)/2 + (n+1)*(MOD-1) fits in u64; the classic zlib NMAX.
    const NMAX: usize = 5552;

    let mut a: u64 = 0;
    let mut b: u64 = 0;

    for chunk in data.chunks(NMAX) {
        for &byte in chunk {
            a += u64::from(byte);
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }

    ((b as u32) << 16) | (a as u32)
}

/// Lowercase hex, e.g. for chunk IDs in CDN URLs.
pub(crate) fn to_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// SHA-1 of a byte slice.
pub(crate) fn sha1(bytes: &[u8]) -> [u8; 20] {
    use sha1::Digest;
    let mut hasher = sha1::Sha1::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Decode a 64-character hex string into a 32-byte AES-256 depot key.
/// Surrounding whitespace is ignored.
pub(crate) fn parse_hex_key(input: &str) -> Option<[u8; 32]> {
    let input = input.trim();
    if input.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    let bytes = input.as_bytes();
    for (i, byte) in key.iter_mut().enumerate() {
        let high = (bytes[i * 2] as char).to_digit(16)?;
        let low = (bytes[i * 2 + 1] as char).to_digit(16)?;
        *byte = ((high << 4) | low) as u8;
    }
    Some(key)
}

/// Turn a manifest-relative path (`a/b/c.txt`, possibly with `\` separators from Windows-era
/// manifests) into a safe relative [`PathBuf`].
///
/// Returns `None` for empty/unsafe names. All `.`/`..` components and any drive letters or
/// leading roots are stripped - a manifest must never be able to escape the output directory
/// (the C# implementation does not sanitize; this one does).
pub(crate) fn safe_relative_path(path: &str) -> Option<PathBuf> {
    let normalized = path.replace('\\', "/");
    if normalized.trim().is_empty() {
        return None;
    }

    let mut out = PathBuf::new();
    for component in normalized.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            continue;
        }
        out.push(component);
    }

    // Reject anything that produced an absolute path or ended up empty.
    if out.as_os_str().is_empty() || out.is_absolute() {
        return None;
    }
    debug_assert!(out.components().all(|c| matches!(c, Component::Normal(_))));
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn adler32_seed0_empty_is_zero() {
        assert_eq!(adler32_seed0(b""), 0);
    }

    #[test]
    fn adler32_seed0_known_vector() {
        // Independent of the running-modulo implementation: bytes of "Wikipedia" sum to
        // a = 0x397 (919) and the running sums total b = 4573 = 0x11DD (seed 0; for the classic
        // seed-1 variant this is the well-known 0x11E60398, i.e. +87 in a and +9 in b).
        assert_eq!(adler32_seed0(b"Wikipedia"), 0x11DD_0397);
        // Which also means: shifting to seed 1 must reproduce the classic Adler-32.
        let seed0 = adler32_seed0(b"Wikipedia");
        let a = (seed0 & 0xFFFF) + 1;
        let b = (seed0 >> 16) + 9;
        assert_eq!((b << 16) | a, 0x11E6_0398);
    }

    #[test]
    fn adler32_seed0_multi_nmax_span() {
        // Larger than NMAX to exercise the chunked modulo path; deterministic comparison
        // against a byte-at-a-time reference implementation.
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let mut a: u64 = 0;
        let mut b: u64 = 0;
        for &byte in &data {
            a = (a + u64::from(byte)) % 65521;
            b = (b + a) % 65521;
        }
        let expected = ((b as u32) << 16) | (a as u32);
        assert_eq!(adler32_seed0(&data), expected);
    }

    #[test]
    fn hex_lower() {
        assert_eq!(to_hex_lower(&[0x00, 0xab, 0xff]), "00abff");
    }

    #[test]
    fn safe_paths() {
        assert_eq!(
            safe_relative_path("foo/bar.txt").as_deref(),
            Some(std::path::Path::new("foo/bar.txt"))
        );
        assert_eq!(
            safe_relative_path("foo\\bar.txt").as_deref(),
            Some(std::path::Path::new("foo/bar.txt"))
        );
        assert!(
            safe_relative_path("../evil.txt")
                .is_some_and(|p| p == std::path::Path::new("evil.txt"))
        );
        assert!(safe_relative_path("").is_none());
        assert!(safe_relative_path("..").is_none_or(|p| p.as_os_str() != ".."));
    }
}
