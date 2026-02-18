use std::path::{Path, PathBuf};

use tokio::io::AsyncWriteExt;

use crate::StdoutLog;

async fn ensure_stdout_log_path_has_no_symlink(path: &Path) -> Result<(), std::io::Error> {
    use std::path::Component;

    let skip_last_component_symlink_check = cfg!(unix);
    let mut components = path.components().peekable();
    let mut current = PathBuf::new();
    while let Some(component) = components.next() {
        let is_last = components.peek().is_none();
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                current.pop();
            }
            Component::Normal(part) => {
                current.push(part);
                if is_last && skip_last_component_symlink_check {
                    // Do not pre-check the final path component. On unix we open with `O_NOFOLLOW`
                    // to prevent TOCTOU symlink replacement.
                    continue;
                }
                match tokio::fs::symlink_metadata(&current).await {
                    Ok(metadata) => {
                        if metadata.file_type().is_symlink() {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::PermissionDenied,
                                format!(
                                    "stdout_log path contains symlink component: {}",
                                    current.display()
                                ),
                            ));
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => break,
                    Err(err) => return Err(err),
                }
            }
        }
    }
    Ok(())
}

async fn open_stdout_log_append(path: &Path) -> Result<tokio::fs::File, std::io::Error> {
    ensure_stdout_log_path_has_no_symlink(path).await?;

    let mut options = tokio::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        // Best-effort: ensure new log files are not world-readable. Existing files keep their
        // original permissions.
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;

        // Best-effort: avoid following reparse points (including symlinks) on open.
        // This mitigates TOCTOU risks where the log path could be replaced between checks.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }

    options.open(path).await
}

pub(crate) struct LogState {
    base_path: PathBuf,
    max_bytes_per_part: u64,
    max_parts: Option<u32>,
    file: tokio::fs::File,
    current_len: u64,
    next_part: u32,
}

impl LogState {
    pub(crate) async fn new(opts: StdoutLog) -> Result<Self, std::io::Error> {
        let base_path = opts.path;
        let max_bytes_per_part = opts.max_bytes_per_part.max(1);
        let max_parts = opts.max_parts.filter(|v| *v > 0);

        ensure_stdout_log_path_has_no_symlink(&base_path).await?;
        if let Some(parent) = base_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let file = open_stdout_log_append(&base_path).await?;
        let current_len = file.metadata().await.map(|m| m.len()).unwrap_or(0);
        let next_part = next_rotating_log_part(&base_path).await.unwrap_or(1);
        if let Some(max_parts) = max_parts {
            let _ = prune_rotating_log_parts(&base_path, max_parts).await;
        }

        Ok(Self {
            base_path,
            max_bytes_per_part,
            max_parts,
            file,
            current_len,
            next_part,
        })
    }

    pub(crate) async fn write_line_bytes(&mut self, line: &[u8]) -> Result<(), std::io::Error> {
        self.write_bytes_with_rotation(line).await?;
        if !line.ends_with(b"\n") {
            self.write_bytes_with_rotation(b"\n").await?;
        }

        Ok(())
    }

    async fn write_bytes_with_rotation(&mut self, bytes: &[u8]) -> Result<(), std::io::Error> {
        let mut offset = 0usize;
        while offset < bytes.len() {
            let remaining = self.max_bytes_per_part.saturating_sub(self.current_len);
            if remaining == 0 {
                self.file.flush().await?;
                self.next_part = rotate_log_file(&self.base_path, self.next_part).await?;
                if let Some(max_parts) = self.max_parts {
                    let _ = prune_rotating_log_parts(&self.base_path, max_parts).await;
                }
                self.file = open_stdout_log_append(&self.base_path).await?;
                self.current_len = 0;
                continue;
            }

            let take = usize::try_from(remaining.min((bytes.len() - offset) as u64))
                .unwrap_or(bytes.len() - offset);
            self.file.write_all(&bytes[offset..(offset + take)]).await?;
            self.current_len = self.current_len.saturating_add(take as u64);
            offset = offset.saturating_add(take);
        }
        Ok(())
    }
}

async fn next_rotating_log_part(base_path: &Path) -> Result<u32, std::io::Error> {
    let Some(parent) = base_path.parent() else {
        return Ok(1);
    };
    let Some(stem) = base_path.file_stem().and_then(|s| s.to_str()) else {
        return Ok(1);
    };

    let mut read_dir = match tokio::fs::read_dir(parent).await {
        Ok(read_dir) => read_dir,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(1),
        Err(err) => return Err(err),
    };

    let prefix = format!("{stem}.segment-");
    let mut max_part = 0u32;
    while let Some(entry) = read_dir.next_entry().await? {
        let ty = entry.file_type().await?;
        if !ty.is_file() {
            continue;
        }
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Some(rest) = name.strip_prefix(&prefix) else {
            continue;
        };
        let Some(part_str) = rest.strip_suffix(".log") else {
            continue;
        };
        let Ok(part) = part_str.parse::<u32>() else {
            continue;
        };
        max_part = max_part.max(part);
    }

    Ok(max_part.saturating_add(1).max(1))
}

async fn rotate_log_file(base_path: &Path, mut part: u32) -> Result<u32, std::io::Error> {
    let Some(parent) = base_path.parent() else {
        return Ok(part);
    };
    let Some(stem) = base_path.file_stem().and_then(|s| s.to_str()) else {
        return Ok(part);
    };

    loop {
        let rotated = parent.join(format!("{stem}.segment-{part:04}.log"));
        match tokio::fs::rename(base_path, &rotated).await {
            Ok(()) => return Ok(part.saturating_add(1)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(part),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                part = part.saturating_add(1);
            }
            Err(err) => {
                return Err(err);
            }
        }
    }
}

pub(crate) async fn list_rotating_log_parts(
    base_path: &Path,
) -> Result<Vec<(u32, PathBuf)>, std::io::Error> {
    let Some(parent) = base_path.parent() else {
        return Ok(Vec::new());
    };
    let Some(stem) = base_path.file_stem().and_then(|s| s.to_str()) else {
        return Ok(Vec::new());
    };

    let mut read_dir = match tokio::fs::read_dir(parent).await {
        Ok(read_dir) => read_dir,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };

    let prefix = format!("{stem}.segment-");
    let mut parts = Vec::new();
    while let Some(entry) = read_dir.next_entry().await? {
        let ty = entry.file_type().await?;
        if !ty.is_file() {
            continue;
        }
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Some(rest) = name.strip_prefix(&prefix) else {
            continue;
        };
        let Some(part_str) = rest.strip_suffix(".log") else {
            continue;
        };
        let Ok(part) = part_str.parse::<u32>() else {
            continue;
        };

        parts.push((part, entry.path()));
    }

    Ok(parts)
}

pub(crate) async fn prune_rotating_log_parts(
    base_path: &Path,
    max_parts: u32,
) -> Result<(), std::io::Error> {
    if max_parts == 0 {
        return Ok(());
    }
    let mut parts = list_rotating_log_parts(base_path).await?;
    parts.sort_by_key(|(part, _)| *part);

    let keep = max_parts as usize;
    if parts.len() <= keep {
        return Ok(());
    }

    let remove = parts.len().saturating_sub(keep);
    for (_part, path) in parts.into_iter().take(remove) {
        let _ = tokio::fs::remove_file(path).await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn prune_rotating_log_parts_keeps_latest_n() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("server.stdout.log");

        for part in 1..=5u32 {
            let path = dir
                .path()
                .join(format!("server.stdout.segment-{part:04}.log"));
            tokio::fs::write(&path, format!("part-{part}\n"))
                .await
                .unwrap();
        }

        prune_rotating_log_parts(&base, 2).await.unwrap();
        let mut parts = list_rotating_log_parts(&base).await.unwrap();
        parts.sort_by_key(|(part, _)| *part);
        assert_eq!(
            parts.iter().map(|(p, _)| *p).collect::<Vec<_>>(),
            vec![4, 5]
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stdout_log_rejects_symlink_target() {
        let base = std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
        let dir = tempfile::tempdir_in(base).unwrap();
        let target = dir.path().join("target.log");
        tokio::fs::write(&target, b"ok\n").await.unwrap();

        let link = dir.path().join("link.log");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = LogState::new(StdoutLog {
            path: link,
            max_bytes_per_part: 1024,
            max_parts: None,
        })
        .await
        .err()
        .expect("should reject symlink stdout_log path");

        assert_eq!(err.raw_os_error(), Some(libc::ELOOP));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stdout_log_rejects_symlink_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let real_dir = dir.path().join("real");
        tokio::fs::create_dir_all(&real_dir).await.unwrap();

        let link_dir = dir.path().join("link");
        std::os::unix::fs::symlink(&real_dir, &link_dir).unwrap();

        let err = LogState::new(StdoutLog {
            path: link_dir.join("server.stdout.log"),
            max_bytes_per_part: 1024,
            max_parts: None,
        })
        .await
        .err()
        .expect("should reject symlink stdout_log parent dir");

        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            err.to_string()
                .contains("stdout_log path contains symlink component")
        );
    }

    #[tokio::test]
    async fn write_line_bytes_rotates_large_line_without_extra_newline()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let base = dir.path().join("server.stdout.log");

        let mut state = LogState::new(StdoutLog {
            path: base.clone(),
            max_bytes_per_part: 4,
            max_parts: None,
        })
        .await?;
        state.write_line_bytes(b"abcdef").await?;
        drop(state);

        let mut parts = list_rotating_log_parts(&base).await?;
        parts.sort_by_key(|(part, _)| *part);

        let mut combined = Vec::new();
        for (_part, path) in parts {
            combined.extend_from_slice(&tokio::fs::read(path).await?);
        }
        combined.extend_from_slice(&tokio::fs::read(&base).await?);

        assert_eq!(combined, b"abcdef\n");
        Ok(())
    }
}
