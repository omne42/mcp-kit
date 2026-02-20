use std::path::{Path, PathBuf};

use anyhow::Context;

#[cfg(unix)]
fn describe_file_type(meta: &std::fs::Metadata) -> &'static str {
    use std::os::unix::fs::FileTypeExt;

    let file_type = meta.file_type();
    if file_type.is_file() {
        "regular file"
    } else if file_type.is_dir() {
        "directory"
    } else if file_type.is_symlink() {
        "symlink"
    } else if file_type.is_block_device() {
        "block device"
    } else if file_type.is_char_device() {
        "character device"
    } else if file_type.is_fifo() {
        "fifo"
    } else if file_type.is_socket() {
        "socket"
    } else {
        "special file"
    }
}

#[cfg(not(unix))]
fn describe_file_type(meta: &std::fs::Metadata) -> &'static str {
    let file_type = meta.file_type();
    if file_type.is_file() {
        "regular file"
    } else if file_type.is_dir() {
        "directory"
    } else if file_type.is_symlink() {
        "symlink"
    } else {
        "special file"
    }
}

async fn read_to_string_limited_inner(
    path: &Path,
    missing_ok: bool,
) -> anyhow::Result<Option<String>> {
    let meta = match tokio::fs::symlink_metadata(path).await {
        Ok(meta) => meta,
        Err(err) if missing_ok && err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("stat {}", path.display())),
    };
    if !meta.file_type().is_file() {
        let kind = describe_file_type(&meta);
        anyhow::bail!(
            "mcp config must be a regular file (got {kind}): {}",
            path.display()
        );
    }

    let mut options = tokio::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        // Best-effort: avoid following reparse points (including symlinks) on open.
        // This mitigates TOCTOU risks where the config path could be replaced between checks.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }

    use tokio::io::AsyncReadExt;

    let file = match options.open(path).await {
        Ok(file) => file,
        Err(err) if missing_ok && err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
    };
    let file_meta = file
        .metadata()
        .await
        .with_context(|| format!("stat {}", path.display()))?;
    if !file_meta.file_type().is_file() {
        let kind = describe_file_type(&file_meta);
        anyhow::bail!(
            "mcp config must be a regular file (got {kind}): {}",
            path.display()
        );
    }
    if file_meta.len() > super::super::MAX_CONFIG_BYTES {
        anyhow::bail!(
            "mcp config too large: {} bytes (max {}): {}",
            file_meta.len(),
            super::super::MAX_CONFIG_BYTES,
            path.display()
        );
    }

    let reserve = usize::try_from(file_meta.len())
        .unwrap_or(usize::MAX)
        .min((super::super::MAX_CONFIG_BYTES + 1) as usize);
    let mut buf = Vec::with_capacity(reserve);
    file.take(super::super::MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut buf)
        .await
        .with_context(|| format!("read {}", path.display()))?;
    if buf.len() as u64 > super::super::MAX_CONFIG_BYTES {
        anyhow::bail!(
            "mcp config too large: {} bytes (max {}): {}",
            buf.len(),
            super::super::MAX_CONFIG_BYTES,
            path.display()
        );
    }

    let contents = String::from_utf8(buf)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
        .with_context(|| format!("read {}", path.display()))?;
    Ok(Some(contents))
}

pub(super) async fn try_read_to_string_limited(path: &Path) -> anyhow::Result<Option<String>> {
    read_to_string_limited_inner(path, true).await
}

pub(super) async fn read_to_string_limited(path: &Path) -> anyhow::Result<String> {
    match read_to_string_limited_inner(path, false).await? {
        Some(contents) => Ok(contents),
        None => unreachable!("missing_ok=false should never return None"),
    }
}

pub(super) async fn canonicalize_in_root(
    canonical_root: &Path,
    path: &Path,
) -> anyhow::Result<PathBuf> {
    let canonical_path = tokio::fs::canonicalize(path)
        .await
        .with_context(|| format!("canonicalize {}", path.display()))?;
    if !canonical_path.starts_with(canonical_root) {
        anyhow::bail!(
            "path escapes root: {} (root={})",
            canonical_path.display(),
            canonical_root.display()
        );
    }
    Ok(canonical_path)
}
