use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use anyhow::Context;
use serde_json::Value;

use super::file_format::{ConfigFile, ExternalCommandConfigFile, ExternalServerConfigFile};
use super::{ClientConfig, Config, ServerConfig, StdoutLogConfig, Transport};
use crate::ServerName;

const MCP_CONFIG_VERSION: u32 = 1;
const DEFAULT_CONFIG_CANDIDATES: [&str; 2] = [".mcp.json", "mcp.json"];

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

async fn read_to_string_limited(path: &Path) -> anyhow::Result<String> {
    let meta = tokio::fs::symlink_metadata(path)
        .await
        .with_context(|| format!("stat {}", path.display()))?;
    if !meta.file_type().is_file() {
        let kind = describe_file_type(&meta);
        anyhow::bail!(
            "mcp config must be a regular file (got {kind}): {}",
            path.display()
        );
    }

    let mut buf = Vec::new();
    let mut options = tokio::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }

    use tokio::io::AsyncReadExt;

    let file = options
        .open(path)
        .await
        .with_context(|| format!("read {}", path.display()))?;
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
    if file_meta.len() > super::MAX_CONFIG_BYTES {
        anyhow::bail!(
            "mcp config too large: {} bytes (max {}): {}",
            file_meta.len(),
            super::MAX_CONFIG_BYTES,
            path.display()
        );
    }

    file.take(super::MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut buf)
        .await
        .with_context(|| format!("read {}", path.display()))?;
    if buf.len() as u64 > super::MAX_CONFIG_BYTES {
        anyhow::bail!(
            "mcp config too large: {} bytes (max {}): {}",
            buf.len(),
            super::MAX_CONFIG_BYTES,
            path.display()
        );
    }

    String::from_utf8(buf)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
        .with_context(|| format!("read {}", path.display()))
}

async fn try_read_to_string_limited(path: &Path) -> anyhow::Result<Option<String>> {
    let meta = match tokio::fs::symlink_metadata(path).await {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
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

    use tokio::io::AsyncReadExt;

    let mut buf = Vec::new();
    let file = match options.open(path).await {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
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
    if file_meta.len() > super::MAX_CONFIG_BYTES {
        anyhow::bail!(
            "mcp config too large: {} bytes (max {}): {}",
            file_meta.len(),
            super::MAX_CONFIG_BYTES,
            path.display()
        );
    }

    file.take(super::MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut buf)
        .await
        .with_context(|| format!("read {}", path.display()))?;
    if buf.len() as u64 > super::MAX_CONFIG_BYTES {
        anyhow::bail!(
            "mcp config too large: {} bytes (max {}): {}",
            buf.len(),
            super::MAX_CONFIG_BYTES,
            path.display()
        );
    }
    let contents = String::from_utf8(buf)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
        .with_context(|| format!("read {}", path.display()))?;
    Ok(Some(contents))
}

async fn canonicalize_in_root(canonical_root: &Path, path: &Path) -> anyhow::Result<PathBuf> {
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

impl Config {
    /// Load `mcp.json` (v1), but fail if no config file is found.
    ///
    /// Unlike `Config::load`, this does not treat missing config as "empty config".
    pub async fn load_required(
        thread_root: &Path,
        override_path: Option<PathBuf>,
    ) -> anyhow::Result<Self> {
        let cfg = Self::load(thread_root, override_path).await?;
        if cfg.path().is_none() {
            anyhow::bail!(
                "mcp config not found under root {} (tried: {})",
                thread_root.display(),
                DEFAULT_CONFIG_CANDIDATES.join(", ")
            );
        }
        Ok(cfg)
    }

    pub async fn load(thread_root: &Path, override_path: Option<PathBuf>) -> anyhow::Result<Self> {
        let (path, contents) = match override_path {
            Some(path) => {
                let path = if path.is_absolute() {
                    path
                } else {
                    thread_root.join(path)
                };
                let contents = read_to_string_limited(&path).await?;
                (Some(path), contents)
            }
            None => {
                let mut found = None::<(PathBuf, String)>;
                for candidate in DEFAULT_CONFIG_CANDIDATES {
                    let candidate_path = thread_root.join(candidate);
                    match try_read_to_string_limited(&candidate_path).await? {
                        Some(contents) => {
                            found = Some((candidate_path, contents));
                            break;
                        }
                        None => continue,
                    }
                }

                match found {
                    Some((path, contents)) => (Some(path), contents),
                    None => {
                        return Ok(Self {
                            path: None,
                            client: ClientConfig::default(),
                            servers: BTreeMap::new(),
                        });
                    }
                }
            }
        };

        let mut path = path;
        let mut contents = contents;
        let canonical_root = tokio::fs::canonicalize(thread_root)
            .await
            .with_context(|| format!("canonicalize {}", thread_root.display()))?;

        let cfg: ConfigFile = {
            let mut hops = 0usize;
            loop {
                let parse_ctx = match &path {
                    Some(path) => format!("parse {}", path.display()),
                    None => "parse mcp config".to_string(),
                };

                let json: Value =
                    serde_json::from_str(&contents).with_context(|| parse_ctx.clone())?;

                match json {
                    Value::Object(mut root) => {
                        if let Some(mcp_servers) = root.remove("mcpServers") {
                            match mcp_servers {
                                Value::Object(servers) => {
                                    return Self::load_external_servers(thread_root, path, servers);
                                }
                                Value::String(mcp_path) => {
                                    hops += 1;
                                    if hops > 16 {
                                        anyhow::bail!(
                                            "mcpServers path indirection too deep (possible cycle)"
                                        );
                                    }

                                    let mcp_path = PathBuf::from(mcp_path);
                                    if mcp_path.as_os_str().is_empty() {
                                        anyhow::bail!(
                                            "unsupported mcpServers format: path must not be empty"
                                        );
                                    }
                                    if mcp_path.is_absolute()
                                        || mcp_path
                                            .components()
                                            .any(|c| matches!(c, Component::ParentDir))
                                    {
                                        anyhow::bail!(
                                            "unsupported mcpServers format: path must be relative and must not contain `..` segments"
                                        );
                                    }

                                    let base_dir = path
                                        .as_ref()
                                        .and_then(|p| p.parent())
                                        .unwrap_or(thread_root);
                                    let next_path = base_dir.join(&mcp_path);
                                    let canonical_next_path =
                                        canonicalize_in_root(&canonical_root, &next_path)
                                            .await
                                            .context("resolve mcpServers path")?;
                                    contents = read_to_string_limited(&canonical_next_path).await?;
                                    path = Some(next_path);
                                    continue;
                                }
                                _ => {
                                    anyhow::bail!(
                                        "unsupported mcpServers format: `mcpServers` must be an object or a string path"
                                    );
                                }
                            }
                        }

                        if matches!(root.get("version"), Some(Value::Number(_))) {
                            break serde_json::from_value(Value::Object(root))
                                .with_context(|| parse_ctx.clone())?;
                        }

                        if root.contains_key("servers") {
                            anyhow::bail!(
                                "unsupported mcp.json format: missing `version` (expected v{MCP_CONFIG_VERSION})"
                            );
                        }

                        return Self::load_external_servers(thread_root, path, root);
                    }
                    _ => anyhow::bail!("invalid mcp config: expected a JSON object"),
                }
            }
        };
        if cfg.version != MCP_CONFIG_VERSION {
            anyhow::bail!(
                "unsupported mcp.json version {} (expected {})",
                cfg.version,
                MCP_CONFIG_VERSION
            );
        }

        let client = match cfg.client {
            Some(client) => {
                if let Some(protocol_version) = &client.protocol_version {
                    if protocol_version.trim().is_empty() {
                        anyhow::bail!("mcp.json client.protocol_version must not be empty");
                    }
                }
                if let Some(capabilities) = &client.capabilities {
                    if !capabilities.is_object() {
                        anyhow::bail!("mcp.json client.capabilities must be a JSON object");
                    }
                }
                if let Some(roots) = &client.roots {
                    for (idx, root) in roots.iter().enumerate() {
                        if root.uri.trim().is_empty() {
                            anyhow::bail!("mcp.json client.roots[{idx}].uri must not be empty");
                        }
                        if let Some(name) = &root.name {
                            if name.trim().is_empty() {
                                anyhow::bail!(
                                    "mcp.json client.roots[{idx}].name must not be empty"
                                );
                            }
                        }
                    }
                }
                ClientConfig {
                    protocol_version: client.protocol_version,
                    capabilities: client.capabilities,
                    roots: client.roots,
                }
            }
            None => ClientConfig::default(),
        };

        let mut servers = BTreeMap::<ServerName, ServerConfig>::new();
        for (name, server) in cfg.servers {
            let server_name = ServerName::parse(&name)
                .map_err(|_| anyhow::anyhow!("invalid mcp server name: {name}"))?;

            let stdout_log = match server.stdout_log {
                Some(log) => {
                    if log.path.as_os_str().is_empty() {
                        anyhow::bail!("mcp server {name}: stdout_log.path must not be empty");
                    }
                    if log
                        .path
                        .components()
                        .any(|c| matches!(c, Component::ParentDir))
                    {
                        anyhow::bail!(
                            "mcp server {name}: stdout_log.path must not contain `..` segments"
                        );
                    }
                    let path = if log.path.is_absolute() {
                        log.path
                    } else {
                        thread_root.join(log.path)
                    };
                    let max_bytes_per_part = log
                        .max_bytes_per_part
                        .unwrap_or(super::DEFAULT_STDOUT_LOG_MAX_BYTES_PER_PART)
                        .max(1);
                    let max_parts = log.max_parts.unwrap_or(super::DEFAULT_STDOUT_LOG_MAX_PARTS);
                    let max_parts = if max_parts == 0 {
                        None
                    } else {
                        Some(max_parts.max(1))
                    };
                    Some(StdoutLogConfig {
                        path,
                        max_bytes_per_part,
                        max_parts,
                    })
                }
                None => None,
            };

            let inherit_env = match server.transport {
                Transport::Stdio => server.inherit_env.unwrap_or(false),
                _ => {
                    if server.inherit_env.is_some() {
                        anyhow::bail!(
                            "mcp server {name}: inherit_env is only valid for transport=stdio"
                        );
                    }
                    true
                }
            };

            let (argv, unix_path) = match server.transport {
                Transport::Stdio => {
                    if server.unix_path.is_some() {
                        anyhow::bail!(
                            "mcp server {name}: unix_path is only valid for transport=unix"
                        );
                    }
                    if server.url.is_some() {
                        anyhow::bail!(
                            "mcp server {name}: url is only valid for transport=streamable_http"
                        );
                    }
                    if server.sse_url.is_some() || server.http_url.is_some() {
                        anyhow::bail!(
                            "mcp server {name}: sse_url/http_url are only valid for transport=streamable_http"
                        );
                    }
                    if server.bearer_token_env_var.is_some()
                        || !server.http_headers.is_empty()
                        || !server.env_http_headers.is_empty()
                    {
                        anyhow::bail!(
                            "mcp server {name}: http auth/headers are only valid for transport=streamable_http"
                        );
                    }
                    let argv = server.argv.ok_or_else(|| {
                        anyhow::anyhow!("mcp server {name}: argv must not be empty")
                    })?;
                    if argv.is_empty() {
                        anyhow::bail!("mcp server {name}: argv must not be empty");
                    }
                    for (idx, arg) in argv.iter().enumerate() {
                        if arg.trim().is_empty() {
                            anyhow::bail!("mcp server {name}: argv[{idx}] must not be empty");
                        }
                    }
                    (argv, None)
                }
                Transport::Unix => {
                    if server.argv.is_some() {
                        anyhow::bail!("mcp server {name}: argv is not allowed for transport=unix");
                    }
                    if server.url.is_some() {
                        anyhow::bail!(
                            "mcp server {name}: url is only valid for transport=streamable_http"
                        );
                    }
                    if server.sse_url.is_some() || server.http_url.is_some() {
                        anyhow::bail!(
                            "mcp server {name}: sse_url/http_url are only valid for transport=streamable_http"
                        );
                    }
                    if server.bearer_token_env_var.is_some()
                        || !server.http_headers.is_empty()
                        || !server.env_http_headers.is_empty()
                    {
                        anyhow::bail!(
                            "mcp server {name}: http auth/headers are only valid for transport=streamable_http"
                        );
                    }
                    if !server.env.is_empty() {
                        anyhow::bail!("mcp server {name}: env is not supported for transport=unix");
                    }
                    if stdout_log.is_some() {
                        anyhow::bail!(
                            "mcp server {name}: stdout_log is not supported for transport=unix"
                        );
                    }
                    let unix_path = server.unix_path.ok_or_else(|| {
                        anyhow::anyhow!(
                            "mcp server {name}: unix_path is required for transport=unix"
                        )
                    })?;
                    if unix_path.as_os_str().is_empty() {
                        anyhow::bail!("mcp server {name}: unix_path must not be empty");
                    }
                    let unix_path = if unix_path.is_absolute() {
                        unix_path
                    } else {
                        thread_root.join(unix_path)
                    };
                    (Vec::new(), Some(unix_path))
                }
                Transport::StreamableHttp => {
                    if server.argv.is_some() {
                        anyhow::bail!(
                            "mcp server {name}: argv is not allowed for transport=streamable_http"
                        );
                    }
                    if server.unix_path.is_some() {
                        anyhow::bail!(
                            "mcp server {name}: unix_path is not allowed for transport=streamable_http"
                        );
                    }
                    if !server.env.is_empty() {
                        anyhow::bail!(
                            "mcp server {name}: env is not supported for transport=streamable_http"
                        );
                    }
                    if stdout_log.is_some() {
                        anyhow::bail!(
                            "mcp server {name}: stdout_log is not supported for transport=streamable_http"
                        );
                    }
                    let (url, sse_url, http_url) = match (
                        server.url,
                        server.sse_url,
                        server.http_url,
                    ) {
                        (Some(url), None, None) => {
                            if url.trim().is_empty() {
                                anyhow::bail!("mcp server {name}: url must not be empty");
                            }
                            (Some(url), None, None)
                        }
                        (None, Some(sse_url), Some(http_url)) => {
                            if sse_url.trim().is_empty() {
                                anyhow::bail!("mcp server {name}: sse_url must not be empty");
                            }
                            if http_url.trim().is_empty() {
                                anyhow::bail!("mcp server {name}: http_url must not be empty");
                            }
                            (None, Some(sse_url), Some(http_url))
                        }
                        (None, None, None) => {
                            anyhow::bail!(
                                "mcp server {name}: url (or sse_url + http_url) is required for transport=streamable_http"
                            );
                        }
                        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
                            anyhow::bail!(
                                "mcp server {name}: set either url or (sse_url + http_url), not both"
                            );
                        }
                        (None, Some(_), None) | (None, None, Some(_)) => {
                            anyhow::bail!(
                                "mcp server {name}: sse_url and http_url must both be set for transport=streamable_http"
                            );
                        }
                    };

                    if let Some(env_var) = &server.bearer_token_env_var {
                        if env_var.trim().is_empty() {
                            anyhow::bail!(
                                "mcp server {name}: bearer_token_env_var must not be empty"
                            );
                        }
                    }

                    for (header, value) in server.http_headers.iter() {
                        if header.trim().is_empty() {
                            anyhow::bail!("mcp server {name}: http_headers key must not be empty");
                        }
                        if value.trim().is_empty() {
                            anyhow::bail!(
                                "mcp server {name}: http_headers[{header}] must not be empty"
                            );
                        }
                    }
                    for (header, env_var) in server.env_http_headers.iter() {
                        if header.trim().is_empty() {
                            anyhow::bail!(
                                "mcp server {name}: env_http_headers key must not be empty"
                            );
                        }
                        if env_var.trim().is_empty() {
                            anyhow::bail!(
                                "mcp server {name}: env_http_headers[{header}] must not be empty"
                            );
                        }
                    }

                    servers.insert(
                        server_name,
                        ServerConfig {
                            transport: Transport::StreamableHttp,
                            argv: Vec::new(),
                            inherit_env: true,
                            unix_path: None,
                            url,
                            sse_url,
                            http_url,
                            bearer_token_env_var: server.bearer_token_env_var,
                            http_headers: server.http_headers,
                            env_http_headers: server.env_http_headers,
                            env: BTreeMap::new(),
                            stdout_log: None,
                        },
                    );
                    continue;
                }
            };

            servers.insert(
                server_name,
                ServerConfig {
                    transport: server.transport,
                    argv,
                    inherit_env,
                    unix_path,
                    url: None,
                    sse_url: None,
                    http_url: None,
                    bearer_token_env_var: None,
                    http_headers: BTreeMap::new(),
                    env_http_headers: BTreeMap::new(),
                    env: server.env,
                    stdout_log,
                },
            );
        }

        Ok(Self {
            path,
            client,
            servers,
        })
    }

    fn load_external_servers(
        thread_root: &Path,
        path: Option<PathBuf>,
        servers_value: serde_json::Map<String, Value>,
    ) -> anyhow::Result<Self> {
        let client = ClientConfig::default();
        let mut servers = BTreeMap::<ServerName, ServerConfig>::new();

        for (name, server_value) in servers_value {
            if name == "$schema" {
                continue;
            }
            let server_name = ServerName::parse(&name)
                .map_err(|_| anyhow::anyhow!("invalid mcp server name: {name}"))?;

            let server: ExternalServerConfigFile = serde_json::from_value(server_value)
                .with_context(|| {
                    if let Some(path) = &path {
                        format!("parse {} servers.{name}", path.display())
                    } else {
                        format!("parse mcp config servers.{name}")
                    }
                })?;

            // Intentionally ignored: kept for compatibility with external MCP config formats.
            // Touch them to satisfy dead-code analysis without `allow`.
            let _ = (&server.description, &server.extra);

            if matches!(server.enabled, Some(false)) {
                continue;
            }

            let transport = match server.transport {
                Some(transport) => transport,
                None => {
                    if server.command.is_some()
                        || server.argv.is_some()
                        || server.args.as_ref().is_some_and(|args| !args.is_empty())
                    {
                        Transport::Stdio
                    } else if server.unix_path.is_some() {
                        Transport::Unix
                    } else if server.url.is_some()
                        || server.sse_url.is_some()
                        || server.http_url.is_some()
                        || server.server_type.is_some()
                    {
                        Transport::StreamableHttp
                    } else {
                        anyhow::bail!(
                            "mcp server {name}: missing transport (expected command/argv, unix_path, or url)"
                        );
                    }
                }
            };

            if let Some(server_type) = server.server_type.as_deref().map(str::trim) {
                if !server_type.is_empty() {
                    if server_type.eq_ignore_ascii_case("http")
                        || server_type.eq_ignore_ascii_case("sse")
                        || server_type.eq_ignore_ascii_case("streamable_http")
                    {
                        if transport != Transport::StreamableHttp {
                            anyhow::bail!(
                                "mcp server {name}: type={server_type} conflicts with transport={transport:?}"
                            );
                        }
                    } else {
                        anyhow::bail!("mcp server {name}: unsupported type: {server_type}");
                    }
                }
            }

            let stdout_log = match server.stdout_log {
                Some(log) => {
                    if log.path.as_os_str().is_empty() {
                        anyhow::bail!("mcp server {name}: stdout_log.path must not be empty");
                    }
                    if log
                        .path
                        .components()
                        .any(|c| matches!(c, Component::ParentDir))
                    {
                        anyhow::bail!(
                            "mcp server {name}: stdout_log.path must not contain `..` segments"
                        );
                    }
                    let path = if log.path.is_absolute() {
                        log.path
                    } else {
                        thread_root.join(log.path)
                    };
                    let max_bytes_per_part = log
                        .max_bytes_per_part
                        .unwrap_or(super::DEFAULT_STDOUT_LOG_MAX_BYTES_PER_PART)
                        .max(1);
                    let max_parts = log.max_parts.unwrap_or(super::DEFAULT_STDOUT_LOG_MAX_PARTS);
                    let max_parts = if max_parts == 0 {
                        None
                    } else {
                        Some(max_parts.max(1))
                    };
                    Some(StdoutLogConfig {
                        path,
                        max_bytes_per_part,
                        max_parts,
                    })
                }
                None => None,
            };

            let inherit_env = match transport {
                Transport::Stdio => server.inherit_env.unwrap_or(false),
                _ => {
                    if server.inherit_env.is_some() {
                        anyhow::bail!(
                            "mcp server {name}: inherit_env is only valid for transport=stdio"
                        );
                    }
                    true
                }
            };

            match transport {
                Transport::Stdio => {
                    if server.unix_path.is_some() {
                        anyhow::bail!(
                            "mcp server {name}: unix_path is only valid for transport=unix"
                        );
                    }
                    if server.url.is_some() || server.sse_url.is_some() || server.http_url.is_some()
                    {
                        anyhow::bail!(
                            "mcp server {name}: url/sse_url/http_url are only valid for transport=streamable_http"
                        );
                    }
                    if server.bearer_token_env_var.is_some()
                        || !server.http_headers.is_empty()
                        || !server.env_http_headers.is_empty()
                    {
                        anyhow::bail!(
                            "mcp server {name}: http headers/auth are only valid for transport=streamable_http"
                        );
                    }

                    let argv = match (server.argv, server.command) {
                        (Some(argv), _) => argv,
                        (None, Some(command)) => {
                            let mut argv = match command {
                                ExternalCommandConfigFile::String(cmd) => vec![cmd],
                                ExternalCommandConfigFile::Array(cmd) => cmd,
                            };
                            if let Some(args) = server.args {
                                argv.extend(args);
                            }
                            argv
                        }
                        (None, None) => Vec::new(),
                    };
                    if argv.is_empty() {
                        anyhow::bail!("mcp server {name}: argv must not be empty");
                    }
                    for (idx, arg) in argv.iter().enumerate() {
                        if arg.trim().is_empty() {
                            anyhow::bail!("mcp server {name}: argv[{idx}] must not be empty");
                        }
                    }

                    let mut env = server.env;
                    for (k, v) in server.environment {
                        env.insert(k, v);
                    }
                    for (key, value) in env.iter() {
                        if key.trim().is_empty() {
                            anyhow::bail!("mcp server {name}: env key must not be empty");
                        }
                        if value.trim().is_empty() {
                            anyhow::bail!("mcp server {name}: env[{key}] must not be empty");
                        }
                    }

                    servers.insert(
                        server_name,
                        ServerConfig {
                            transport: Transport::Stdio,
                            argv,
                            inherit_env,
                            unix_path: None,
                            url: None,
                            sse_url: None,
                            http_url: None,
                            bearer_token_env_var: None,
                            http_headers: BTreeMap::new(),
                            env_http_headers: BTreeMap::new(),
                            env,
                            stdout_log,
                        },
                    );
                }
                Transport::Unix => {
                    if server.command.is_some() || server.argv.is_some() || server.args.is_some() {
                        anyhow::bail!(
                            "mcp server {name}: command/args/argv are only valid for transport=stdio"
                        );
                    }
                    if server.url.is_some() || server.sse_url.is_some() || server.http_url.is_some()
                    {
                        anyhow::bail!(
                            "mcp server {name}: url/sse_url/http_url are only valid for transport=streamable_http"
                        );
                    }
                    if !server.env.is_empty()
                        || !server.environment.is_empty()
                        || stdout_log.is_some()
                    {
                        anyhow::bail!(
                            "mcp server {name}: env/stdout_log are not supported for transport=unix"
                        );
                    }
                    if server.bearer_token_env_var.is_some()
                        || !server.http_headers.is_empty()
                        || !server.env_http_headers.is_empty()
                    {
                        anyhow::bail!(
                            "mcp server {name}: http headers/auth are only valid for transport=streamable_http"
                        );
                    }

                    let unix_path = server.unix_path.ok_or_else(|| {
                        anyhow::anyhow!(
                            "mcp server {name}: unix_path is required for transport=unix"
                        )
                    })?;
                    if unix_path.as_os_str().is_empty() {
                        anyhow::bail!("mcp server {name}: unix_path must not be empty");
                    }
                    let unix_path = if unix_path.is_absolute() {
                        unix_path
                    } else {
                        thread_root.join(unix_path)
                    };

                    servers.insert(
                        server_name,
                        ServerConfig {
                            transport: Transport::Unix,
                            argv: Vec::new(),
                            inherit_env: true,
                            unix_path: Some(unix_path),
                            url: None,
                            sse_url: None,
                            http_url: None,
                            bearer_token_env_var: None,
                            http_headers: BTreeMap::new(),
                            env_http_headers: BTreeMap::new(),
                            env: BTreeMap::new(),
                            stdout_log: None,
                        },
                    );
                }
                Transport::StreamableHttp => {
                    if server.command.is_some() || server.argv.is_some() || server.args.is_some() {
                        anyhow::bail!(
                            "mcp server {name}: command/args/argv are only valid for transport=stdio"
                        );
                    }
                    if server.unix_path.is_some() {
                        anyhow::bail!(
                            "mcp server {name}: unix_path is only valid for transport=unix"
                        );
                    }
                    if !server.env.is_empty() || !server.environment.is_empty() {
                        anyhow::bail!(
                            "mcp server {name}: env is not supported for transport=streamable_http"
                        );
                    }
                    if stdout_log.is_some() {
                        anyhow::bail!(
                            "mcp server {name}: stdout_log is not supported for transport=streamable_http"
                        );
                    }

                    let (url, sse_url, http_url) = match (
                        server.url,
                        server.sse_url,
                        server.http_url,
                    ) {
                        (Some(url), None, None) => {
                            if url.trim().is_empty() {
                                anyhow::bail!("mcp server {name}: url must not be empty");
                            }
                            (Some(url), None, None)
                        }
                        (None, Some(sse_url), Some(http_url)) => {
                            if sse_url.trim().is_empty() {
                                anyhow::bail!("mcp server {name}: sse_url must not be empty");
                            }
                            if http_url.trim().is_empty() {
                                anyhow::bail!("mcp server {name}: http_url must not be empty");
                            }
                            (None, Some(sse_url), Some(http_url))
                        }
                        (None, Some(_), None) => {
                            anyhow::bail!(
                                "mcp server {name}: set either url or (sse_url + http_url), not sse_url alone"
                            );
                        }
                        (None, None, Some(_)) => {
                            anyhow::bail!(
                                "mcp server {name}: set either url or (sse_url + http_url), not http_url alone"
                            );
                        }
                        (None, None, None) => {
                            anyhow::bail!(
                                "mcp server {name}: url (or sse_url + http_url) is required for transport=streamable_http"
                            );
                        }
                        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
                            anyhow::bail!(
                                "mcp server {name}: set either url or (sse_url + http_url), not both"
                            );
                        }
                    };

                    if let Some(env_var) = &server.bearer_token_env_var {
                        if env_var.trim().is_empty() {
                            anyhow::bail!(
                                "mcp server {name}: bearer_token_env_var must not be empty"
                            );
                        }
                    }

                    for (header, value) in server.http_headers.iter() {
                        if header.trim().is_empty() {
                            anyhow::bail!("mcp server {name}: http_headers key must not be empty");
                        }
                        if value.trim().is_empty() {
                            anyhow::bail!(
                                "mcp server {name}: http_headers[{header}] must not be empty"
                            );
                        }
                    }
                    for (header, env_var) in server.env_http_headers.iter() {
                        if header.trim().is_empty() {
                            anyhow::bail!(
                                "mcp server {name}: env_http_headers key must not be empty"
                            );
                        }
                        if env_var.trim().is_empty() {
                            anyhow::bail!(
                                "mcp server {name}: env_http_headers[{header}] must not be empty"
                            );
                        }
                    }

                    servers.insert(
                        server_name,
                        ServerConfig {
                            transport: Transport::StreamableHttp,
                            argv: Vec::new(),
                            inherit_env: true,
                            unix_path: None,
                            url,
                            sse_url,
                            http_url,
                            bearer_token_env_var: server.bearer_token_env_var,
                            http_headers: server.http_headers,
                            env_http_headers: server.env_http_headers,
                            env: BTreeMap::new(),
                            stdout_log: None,
                        },
                    );
                }
            }
        }

        Ok(Self {
            path,
            client,
            servers,
        })
    }
}
