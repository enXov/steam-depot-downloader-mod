//! Positional file I/O, the way SteamKit's `FileStream.Seek + Read/Write` is used here.
//!
//! Both directions go through pread/pwrite, so a single open file handle can be shared by
//! every task writing into it - no mutex, no seek, and no ordering requirement between
//! concurrent writes to distinct offsets.
//!
//! `read_at`/`write_at` take `&File` (not `&mut`) because both platforms' positional APIs do,
//! which is what makes the shared [`std::sync::Arc`]<[`std::fs::File`]> in the engine legal.

/// Positional read, mirroring SteamKit's `FileStream.Seek + Read` usage.
#[cfg(unix)]
pub(crate) fn read_at(file: &std::fs::File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

#[cfg(windows)]
pub(crate) fn read_at(file: &std::fs::File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut read = 0usize;
    while read < buf.len() {
        let n = file.seek_read(&mut buf[read..], offset + read as u64)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "short read",
            ));
        }
        read += n;
    }
    Ok(())
}

/// Positional write, mirroring SteamKit's `FileStream.Seek + Write` usage.
#[cfg(unix)]
pub(crate) fn write_at(file: &std::fs::File, buf: &[u8], offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.write_all_at(buf, offset)
}

#[cfg(windows)]
pub(crate) fn write_at(file: &std::fs::File, buf: &[u8], offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut written = 0usize;
    while written < buf.len() {
        let n = file.seek_write(&buf[written..], offset + written as u64)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "short write",
            ));
        }
        written += n;
    }
    Ok(())
}
