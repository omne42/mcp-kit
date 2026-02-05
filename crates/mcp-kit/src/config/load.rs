use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use anyhow::Context;
use serde_json::Value;

use super::file_format::{
    ConfigFile, ExternalCommandConfigFile, ExternalServerConfigFile, StdoutLogConfigFile,
};
use super::{ClientConfig, Config, ServerConfig, StdoutLogConfig, Transport};
use crate::ServerName;

const MCP_CONFIG_VERSION: u32 = 1;
const DEFAULT_CONFIG_CANDIDATES: [&str; 2] = [".mcp.json", "mcp.json"];

mod fs;

enum ParsedConfig {
    V1 {
        path: Option<PathBuf>,
        cfg: ConfigFile,
    },
    External(Config),
}

async fn load_initial_path_and_contents(
    thread_root: &Path,
    override_path: Option<PathBuf>,
) -> anyhow::Result<Option<(PathBuf, String)>> {
    match override_path {
        Some(path) => {
            let path = if path.is_absolute() {
                path
            } else {
                thread_root.join(path)
            };
            let contents = fs::read_to_string_limited(&path).await?;
            Ok(Some((path, contents)))
        }
        None => {
            for candidate in DEFAULT_CONFIG_CANDIDATES {
                let candidate_path = thread_root.join(candidate);
                match fs::try_read_to_string_limited(&candidate_path).await? {
                    Some(contents) => return Ok(Some((candidate_path, contents))),
                    None => continue,
                }
            }
            Ok(None)
        }
    }
}

async fn parse_config_or_external(
    thread_root: &Path,
    canonical_root: &Path,
    mut path: Option<PathBuf>,
    mut contents: String,
) -> anyhow::Result<ParsedConfig> {
    let mut hops = 0usize;
    loop {
        let parse_ctx = match &path {
            Some(path) => format!("parse {}", path.display()),
            None => "parse mcp config".to_string(),
        };

        let json: Value = serde_json::from_str(&contents).with_context(|| parse_ctx.clone())?;

        match json {
            Value::Object(mut root) => {
                if let Some(mcp_servers) = root.remove("mcpServers") {
                    match mcp_servers {
                        Value::Object(servers) => {
                            return Ok(ParsedConfig::External(Config::load_external_servers(
                                thread_root,
                                path,
                                servers,
                            )?));
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
                                fs::canonicalize_in_root(canonical_root, &next_path)
                                    .await
                                    .context("resolve mcpServers path")?;
                            contents = fs::read_to_string_limited(&canonical_next_path).await?;
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
                    let cfg: ConfigFile = serde_json::from_value(Value::Object(root))
                        .with_context(|| parse_ctx.clone())?;
                    return Ok(ParsedConfig::V1 { path, cfg });
                }

                if root.contains_key("servers") {
                    anyhow::bail!(
                        "unsupported mcp.json format: missing `version` (expected v{MCP_CONFIG_VERSION})"
                    );
                }

                return Ok(ParsedConfig::External(Config::load_external_servers(
                    thread_root,
                    path,
                    root,
                )?));
            }
            _ => anyhow::bail!("invalid mcp config: expected a JSON object"),
        }
    }
}

fn resolve_inherit_env(
    name: &str,
    transport: Transport,
    inherit_env: Option<bool>,
) -> anyhow::Result<bool> {
    match transport {
        Transport::Stdio => Ok(inherit_env.unwrap_or(false)),
        _ => {
            if inherit_env.is_some() {
                anyhow::bail!("mcp server {name}: inherit_env is only valid for transport=stdio");
            }
            Ok(true)
        }
    }
}

fn ensure_unix_path_only_for_unix(name: &str, unix_path_present: bool) -> anyhow::Result<()> {
    if unix_path_present {
        anyhow::bail!("mcp server {name}: unix_path is only valid for transport=unix");
    }
    Ok(())
}

fn ensure_url_fields_only_for_streamable_http(
    name: &str,
    has_url_fields: bool,
) -> anyhow::Result<()> {
    if has_url_fields {
        anyhow::bail!(
            "mcp server {name}: url/sse_url/http_url are only valid for transport=streamable_http"
        );
    }
    Ok(())
}

fn ensure_http_headers_auth_only_for_streamable_http(
    name: &str,
    has_auth_fields: bool,
) -> anyhow::Result<()> {
    if has_auth_fields {
        anyhow::bail!(
            "mcp server {name}: http headers/auth are only valid for transport=streamable_http"
        );
    }
    Ok(())
}

fn ensure_env_empty(name: &str, transport: Transport, env_nonempty: bool) -> anyhow::Result<()> {
    if !env_nonempty {
        return Ok(());
    }
    match transport {
        Transport::Unix => {
            anyhow::bail!("mcp server {name}: env is not supported for transport=unix")
        }
        Transport::StreamableHttp => {
            anyhow::bail!("mcp server {name}: env is not supported for transport=streamable_http")
        }
        Transport::Stdio => Ok(()),
    }
}

fn ensure_stdout_log_supported(
    name: &str,
    transport: Transport,
    stdout_log_present: bool,
) -> anyhow::Result<()> {
    if !stdout_log_present {
        return Ok(());
    }
    match transport {
        Transport::Unix => {
            anyhow::bail!("mcp server {name}: stdout_log is not supported for transport=unix")
        }
        Transport::StreamableHttp => anyhow::bail!(
            "mcp server {name}: stdout_log is not supported for transport=streamable_http"
        ),
        Transport::Stdio => Ok(()),
    }
}

fn ensure_command_args_argv_only_for_stdio(
    name: &str,
    has_command_args_argv: bool,
) -> anyhow::Result<()> {
    if has_command_args_argv {
        anyhow::bail!("mcp server {name}: command/args/argv are only valid for transport=stdio");
    }
    Ok(())
}

fn build_v1_config(
    thread_root: &Path,
    path: Option<PathBuf>,
    cfg: ConfigFile,
) -> anyhow::Result<Config> {
    if cfg.version != MCP_CONFIG_VERSION {
        anyhow::bail!(
            "unsupported mcp.json version {} (expected {})",
            cfg.version,
            MCP_CONFIG_VERSION
        );
    }

    let client = match cfg.client {
        Some(client) => ClientConfig {
            protocol_version: client.protocol_version,
            capabilities: client.capabilities,
            roots: client.roots,
        },
        None => ClientConfig::default(),
    };
    client.validate().map_err(|err| {
        let msg = format!("invalid mcp.json client config: {err}");
        err.context(msg)
    })?;

    let mut servers = BTreeMap::<ServerName, ServerConfig>::new();
    for (name, server) in cfg.servers {
        let server_name_key = ServerName::parse(&name)
            .with_context(|| format!("invalid mcp server name {name:?}"))?;

        if matches!(
            server.transport,
            Transport::Unix | Transport::StreamableHttp
        ) && server.argv.is_some()
        {
            match server.transport {
                Transport::Unix => {
                    anyhow::bail!("mcp server {name}: argv is not allowed for transport=unix")
                }
                Transport::StreamableHttp => anyhow::bail!(
                    "mcp server {name}: argv is not allowed for transport=streamable_http"
                ),
                Transport::Stdio => unreachable!("matches! guard excludes stdio"),
            }
        }

        let stdout_log = match server.transport {
            Transport::Stdio => server
                .stdout_log
                .map(|log| parse_stdout_log_config(thread_root, &name, log))
                .transpose()?,
            Transport::Unix => {
                ensure_stdout_log_supported(&name, Transport::Unix, server.stdout_log.is_some())?;
                None
            }
            Transport::StreamableHttp => {
                ensure_stdout_log_supported(
                    &name,
                    Transport::StreamableHttp,
                    server.stdout_log.is_some(),
                )?;
                None
            }
        };

        let inherit_env = resolve_inherit_env(&name, server.transport, server.inherit_env)?;

        let argv = match server.transport {
            Transport::Stdio => server.argv.unwrap_or_default(),
            _ => Vec::new(),
        };
        let unix_path = match server.transport {
            Transport::Unix => server.unix_path.map(|unix_path| {
                if unix_path.is_absolute() {
                    unix_path
                } else {
                    thread_root.join(unix_path)
                }
            }),
            _ => server.unix_path,
        };

        let server_cfg = match server.transport {
            Transport::Stdio => {
                ensure_unix_path_only_for_unix(&name, unix_path.is_some())?;
                let has_url_fields =
                    server.url.is_some() || server.sse_url.is_some() || server.http_url.is_some();
                ensure_url_fields_only_for_streamable_http(&name, has_url_fields)?;
                let has_auth_fields = server.bearer_token_env_var.is_some()
                    || !server.http_headers.is_empty()
                    || !server.env_http_headers.is_empty();
                ensure_http_headers_auth_only_for_streamable_http(&name, has_auth_fields)?;

                let mut server_cfg = ServerConfig::stdio(argv)?;
                server_cfg.set_inherit_env(inherit_env)?;
                *server_cfg.env_mut()? = server.env;
                server_cfg.set_stdout_log(stdout_log)?;
                server_cfg
            }
            Transport::Unix => {
                let has_url_fields =
                    server.url.is_some() || server.sse_url.is_some() || server.http_url.is_some();
                ensure_url_fields_only_for_streamable_http(&name, has_url_fields)?;
                let env_nonempty = !server.env.is_empty();
                ensure_env_empty(&name, Transport::Unix, env_nonempty)?;
                let has_auth_fields = server.bearer_token_env_var.is_some()
                    || !server.http_headers.is_empty()
                    || !server.env_http_headers.is_empty();
                ensure_http_headers_auth_only_for_streamable_http(&name, has_auth_fields)?;

                let unix_path = unix_path.ok_or_else(|| {
                    anyhow::anyhow!("mcp server {name}: unix_path is required for transport=unix")
                })?;
                ServerConfig::unix(unix_path)?
            }
            Transport::StreamableHttp => {
                ensure_unix_path_only_for_unix(&name, unix_path.is_some())?;
                let env_nonempty = !server.env.is_empty();
                ensure_env_empty(&name, Transport::StreamableHttp, env_nonempty)?;

                let mut server_cfg = match (server.url, server.sse_url, server.http_url) {
                    (Some(url), None, None) => ServerConfig::streamable_http(url)?,
                    (None, Some(sse_url), Some(http_url)) => {
                        ServerConfig::streamable_http_split(sse_url, http_url)?
                    }
                    (None, None, None) => anyhow::bail!(
                        "mcp server {name}: url (or sse_url + http_url) is required for transport=streamable_http"
                    ),
                    (Some(_), Some(_), _) | (Some(_), _, Some(_)) => anyhow::bail!(
                        "mcp server {name}: set either url or (sse_url + http_url), not both"
                    ),
                    (None, Some(_), None) | (None, None, Some(_)) => {
                        anyhow::bail!("mcp server {name}: sse_url and http_url must both be set")
                    }
                };
                server_cfg.set_bearer_token_env_var(server.bearer_token_env_var)?;
                *server_cfg.http_headers_mut()? = server.http_headers;
                *server_cfg.env_http_headers_mut()? = server.env_http_headers;
                server_cfg
            }
        };
        server_cfg.validate().map_err(|err| {
            let msg = format!("invalid mcp server config (server={server_name_key}): {err}");
            err.context(msg)
        })?;

        servers.insert(server_name_key, server_cfg);
    }

    Ok(Config {
        path,
        client,
        servers,
    })
}

fn parse_stdout_log_config(
    thread_root: &Path,
    name: &str,
    log: StdoutLogConfigFile,
) -> anyhow::Result<StdoutLogConfig> {
    let max_bytes_per_part = log
        .max_bytes_per_part
        .unwrap_or(super::DEFAULT_STDOUT_LOG_MAX_BYTES_PER_PART);
    let max_parts = log.max_parts.unwrap_or(super::DEFAULT_STDOUT_LOG_MAX_PARTS);
    let max_parts = if max_parts == 0 {
        None
    } else {
        Some(max_parts.max(1))
    };

    let mut cfg = StdoutLogConfig {
        path: log.path,
        max_bytes_per_part,
        max_parts,
    };
    cfg.validate().map_err(|err| {
        let msg = format!("mcp server {name}: invalid stdout_log config: {err}");
        err.context(msg)
    })?;

    if !cfg.path.is_absolute() {
        cfg.path = thread_root.join(&cfg.path);
    }

    Ok(cfg)
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
        let Some((path, contents)) =
            load_initial_path_and_contents(thread_root, override_path).await?
        else {
            return Ok(Self {
                path: None,
                client: ClientConfig::default(),
                servers: BTreeMap::new(),
            });
        };
        let canonical_root = tokio::fs::canonicalize(thread_root)
            .await
            .with_context(|| format!("canonicalize {}", thread_root.display()))?;
        match parse_config_or_external(thread_root, canonical_root.as_path(), Some(path), contents)
            .await?
        {
            ParsedConfig::V1 { path, cfg } => build_v1_config(thread_root, path, cfg),
            ParsedConfig::External(cfg) => Ok(cfg),
        }
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
                .with_context(|| format!("invalid mcp server name {name:?}"))?;

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

            let inherit_env = resolve_inherit_env(&name, transport, server.inherit_env)?;

            match transport {
                Transport::Stdio => {
                    ensure_unix_path_only_for_unix(&name, server.unix_path.is_some())?;
                    let has_url_fields = server.url.is_some()
                        || server.sse_url.is_some()
                        || server.http_url.is_some();
                    ensure_url_fields_only_for_streamable_http(&name, has_url_fields)?;
                    let has_auth_fields = server.bearer_token_env_var.is_some()
                        || !server.http_headers.is_empty()
                        || !server.env_http_headers.is_empty();
                    ensure_http_headers_auth_only_for_streamable_http(&name, has_auth_fields)?;

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

                    let mut env = server.env;
                    for (k, v) in server.environment {
                        env.insert(k, v);
                    }

                    let stdout_log = server
                        .stdout_log
                        .map(|log| parse_stdout_log_config(thread_root, &name, log))
                        .transpose()?;
                    let mut server_cfg = ServerConfig::stdio(argv).map_err(|err| {
                        let msg =
                            format!("invalid mcp server config (server={server_name}): {err}");
                        err.context(msg)
                    })?;
                    server_cfg.set_inherit_env(inherit_env)?;
                    *server_cfg.env_mut()? = env;
                    server_cfg.set_stdout_log(stdout_log)?;
                    server_cfg.validate().map_err(|err| {
                        let msg =
                            format!("invalid mcp server config (server={server_name}): {err}");
                        err.context(msg)
                    })?;

                    servers.insert(server_name, server_cfg);
                }
                Transport::Unix => {
                    let has_command_args_argv =
                        server.command.is_some() || server.argv.is_some() || server.args.is_some();
                    ensure_command_args_argv_only_for_stdio(&name, has_command_args_argv)?;
                    let has_url_fields = server.url.is_some()
                        || server.sse_url.is_some()
                        || server.http_url.is_some();
                    ensure_url_fields_only_for_streamable_http(&name, has_url_fields)?;
                    let env_nonempty = !server.env.is_empty() || !server.environment.is_empty();
                    ensure_env_empty(&name, Transport::Unix, env_nonempty)?;
                    let stdout_log_present = server.stdout_log.is_some();
                    ensure_stdout_log_supported(&name, Transport::Unix, stdout_log_present)?;
                    let has_auth_fields = server.bearer_token_env_var.is_some()
                        || !server.http_headers.is_empty()
                        || !server.env_http_headers.is_empty();
                    ensure_http_headers_auth_only_for_streamable_http(&name, has_auth_fields)?;

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

                    let server_cfg = ServerConfig::unix(unix_path)?;
                    server_cfg.validate().map_err(|err| {
                        let msg =
                            format!("invalid mcp server config (server={server_name}): {err}");
                        err.context(msg)
                    })?;

                    servers.insert(server_name, server_cfg);
                }
                Transport::StreamableHttp => {
                    let has_command_args_argv =
                        server.command.is_some() || server.argv.is_some() || server.args.is_some();
                    ensure_command_args_argv_only_for_stdio(&name, has_command_args_argv)?;
                    ensure_unix_path_only_for_unix(&name, server.unix_path.is_some())?;
                    let env_nonempty = !server.env.is_empty() || !server.environment.is_empty();
                    ensure_env_empty(&name, Transport::StreamableHttp, env_nonempty)?;
                    let stdout_log_present = server.stdout_log.is_some();
                    ensure_stdout_log_supported(
                        &name,
                        Transport::StreamableHttp,
                        stdout_log_present,
                    )?;

                    let mut server_cfg = match (server.url, server.sse_url, server.http_url) {
                        (Some(url), None, None) => ServerConfig::streamable_http(url)?,
                        (None, Some(sse_url), Some(http_url)) => {
                            ServerConfig::streamable_http_split(sse_url, http_url)?
                        }
                        (None, None, None) => anyhow::bail!(
                            "mcp server {name}: url (or sse_url + http_url) is required for transport=streamable_http"
                        ),
                        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => anyhow::bail!(
                            "mcp server {name}: set either url or (sse_url + http_url), not both"
                        ),
                        (None, Some(_), None) | (None, None, Some(_)) => anyhow::bail!(
                            "mcp server {name}: sse_url and http_url must both be set"
                        ),
                    };
                    server_cfg.set_bearer_token_env_var(server.bearer_token_env_var)?;
                    *server_cfg.http_headers_mut()? = server.http_headers;
                    *server_cfg.env_http_headers_mut()? = server.env_http_headers;
                    server_cfg.validate().map_err(|err| {
                        let msg =
                            format!("invalid mcp server config (server={server_name}): {err}");
                        err.context(msg)
                    })?;

                    servers.insert(server_name, server_cfg);
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
