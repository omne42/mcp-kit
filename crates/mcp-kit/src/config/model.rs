use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use reqwest::header::{HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ServerName;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Stdio,
    Unix,
    StreamableHttp,
}

#[derive(Debug, Clone, Default)]
pub struct ClientConfig {
    pub protocol_version: Option<String>,
    pub capabilities: Option<Value>,
    pub roots: Option<Vec<Root>>,
}

impl ClientConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if let Some(protocol_version) = self.protocol_version.as_deref() {
            if protocol_version.trim().is_empty() {
                anyhow::bail!("mcp client.protocol_version must not be empty");
            }
        }
        if let Some(capabilities) = self.capabilities.as_ref() {
            if !capabilities.is_object() {
                anyhow::bail!("mcp client.capabilities must be a JSON object");
            }
        }
        if let Some(roots) = self.roots.as_ref() {
            for (idx, root) in roots.iter().enumerate() {
                if root.uri.trim().is_empty() {
                    anyhow::bail!("mcp client.roots[{idx}].uri must not be empty");
                }
                if let Some(name) = root.name.as_deref() {
                    if name.trim().is_empty() {
                        anyhow::bail!("mcp client.roots[{idx}].name must not be empty");
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Root {
    pub uri: String,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StdoutLogConfig {
    pub path: PathBuf,
    pub max_bytes_per_part: u64,
    pub max_parts: Option<u32>,
}

impl StdoutLogConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.path.as_os_str().is_empty() {
            anyhow::bail!("mcp stdout_log.path must not be empty");
        }
        if self
            .path
            .components()
            .any(|c| matches!(c, Component::ParentDir))
        {
            anyhow::bail!("mcp stdout_log.path must not contain `..` segments");
        }
        if self.max_bytes_per_part == 0 {
            anyhow::bail!("mcp stdout_log.max_bytes_per_part must be >= 1");
        }
        if matches!(self.max_parts, Some(0)) {
            anyhow::bail!("mcp stdout_log.max_parts must be >= 1 (or None for unlimited)");
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub(super) path: Option<PathBuf>,
    pub(super) client: ClientConfig,
    pub(super) servers: BTreeMap<ServerName, ServerConfig>,
}

#[derive(Debug, Clone)]
pub enum ServerConfig {
    Stdio(StdioServerConfig),
    Unix(UnixServerConfig),
    StreamableHttp(StreamableHttpServerConfig),
}

#[derive(Debug, Clone)]
pub struct StdioServerConfig {
    argv: Vec<String>,
    /// When true, inherit the current process environment when spawning a
    /// `transport=stdio` server.
    ///
    /// Default: `false` for `transport=stdio` (safer-by-default).
    ///
    /// When false, the child environment is cleared and only a small set of
    /// non-secret baseline variables are propagated (plus any `env` entries).
    inherit_env: bool,
    env: BTreeMap<String, String>,
    stdout_log: Option<StdoutLogConfig>,
}

#[derive(Debug, Clone)]
pub struct UnixServerConfig {
    unix_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct StreamableHttpServerConfig {
    urls: StreamableHttpUrls,
    bearer_token_env_var: Option<String>,
    http_headers: BTreeMap<String, String>,
    env_http_headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
enum StreamableHttpUrls {
    Single { url: String },
    Split { sse_url: String, http_url: String },
}

fn empty_kv_map() -> &'static BTreeMap<String, String> {
    static EMPTY: std::sync::OnceLock<BTreeMap<String, String>> = std::sync::OnceLock::new();
    EMPTY.get_or_init(BTreeMap::new)
}

impl ServerConfig {
    pub fn stdio(argv: Vec<String>) -> anyhow::Result<Self> {
        validate_argv(Transport::Stdio, &argv)?;
        Ok(Self::Stdio(StdioServerConfig {
            argv,
            inherit_env: false,
            env: BTreeMap::new(),
            stdout_log: None,
        }))
    }

    pub fn unix(unix_path: PathBuf) -> anyhow::Result<Self> {
        if unix_path.as_os_str().is_empty() {
            anyhow::bail!("mcp server transport=unix: unix_path must not be empty");
        }
        Ok(Self::Unix(UnixServerConfig { unix_path }))
    }

    pub fn streamable_http(url: impl Into<String>) -> anyhow::Result<Self> {
        let url = url.into();
        if url.trim().is_empty() {
            anyhow::bail!("mcp server transport=streamable_http: url must not be empty");
        }
        Ok(Self::StreamableHttp(StreamableHttpServerConfig {
            urls: StreamableHttpUrls::Single { url },
            bearer_token_env_var: None,
            http_headers: BTreeMap::new(),
            env_http_headers: BTreeMap::new(),
        }))
    }

    pub fn streamable_http_split(
        sse_url: impl Into<String>,
        http_url: impl Into<String>,
    ) -> anyhow::Result<Self> {
        let sse_url = sse_url.into();
        let http_url = http_url.into();
        if sse_url.trim().is_empty() {
            anyhow::bail!("mcp server transport=streamable_http: sse_url must not be empty");
        }
        if http_url.trim().is_empty() {
            anyhow::bail!("mcp server transport=streamable_http: http_url must not be empty");
        }
        Ok(Self::StreamableHttp(StreamableHttpServerConfig {
            urls: StreamableHttpUrls::Split { sse_url, http_url },
            bearer_token_env_var: None,
            http_headers: BTreeMap::new(),
            env_http_headers: BTreeMap::new(),
        }))
    }

    pub fn transport(&self) -> Transport {
        match self {
            Self::Stdio(_) => Transport::Stdio,
            Self::Unix(_) => Transport::Unix,
            Self::StreamableHttp(_) => Transport::StreamableHttp,
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        match self {
            Self::Stdio(cfg) => {
                validate_argv(Transport::Stdio, &cfg.argv)?;
                for (key, value) in cfg.env.iter() {
                    if key.trim().is_empty() {
                        anyhow::bail!("mcp server transport=stdio: env key must not be empty");
                    }
                    if value.trim().is_empty() {
                        anyhow::bail!("mcp server transport=stdio: env[{key}] must not be empty");
                    }
                }
                if let Some(log) = cfg.stdout_log.as_ref() {
                    log.validate()?;
                }
            }
            Self::Unix(cfg) => {
                if cfg.unix_path.as_os_str().is_empty() {
                    anyhow::bail!("mcp server transport=unix: unix_path must not be empty");
                }
            }
            Self::StreamableHttp(cfg) => {
                match &cfg.urls {
                    StreamableHttpUrls::Single { url } => {
                        if url.trim().is_empty() {
                            anyhow::bail!(
                                "mcp server transport=streamable_http: url must not be empty"
                            );
                        }
                    }
                    StreamableHttpUrls::Split { sse_url, http_url } => {
                        if sse_url.trim().is_empty() {
                            anyhow::bail!(
                                "mcp server transport=streamable_http: sse_url must not be empty"
                            );
                        }
                        if http_url.trim().is_empty() {
                            anyhow::bail!(
                                "mcp server transport=streamable_http: http_url must not be empty"
                            );
                        }
                    }
                }

                if let Some(env_var) = cfg.bearer_token_env_var.as_deref() {
                    if env_var.trim().is_empty() {
                        anyhow::bail!(
                            "mcp server transport=streamable_http: bearer_token_env_var must not be empty"
                        );
                    }
                }

                for (header, value) in cfg.http_headers.iter() {
                    if header.trim().is_empty() {
                        anyhow::bail!(
                            "mcp server transport=streamable_http: http_headers key must not be empty"
                        );
                    }
                    HeaderName::from_bytes(header.as_bytes()).map_err(|_| {
                        anyhow::anyhow!(
                            "mcp server transport=streamable_http: invalid http_headers key: {header}"
                        )
                    })?;
                    if value.trim().is_empty() {
                        anyhow::bail!(
                            "mcp server transport=streamable_http: http_headers[{header}] must not be empty"
                        );
                    }
                    HeaderValue::from_str(value).map_err(|_| {
                        anyhow::anyhow!(
                            "mcp server transport=streamable_http: invalid http_headers[{header}] value"
                        )
                    })?;
                }
                for (header, env_var) in cfg.env_http_headers.iter() {
                    if header.trim().is_empty() {
                        anyhow::bail!(
                            "mcp server transport=streamable_http: env_http_headers key must not be empty"
                        );
                    }
                    HeaderName::from_bytes(header.as_bytes()).map_err(|_| {
                        anyhow::anyhow!(
                            "mcp server transport=streamable_http: invalid env_http_headers key: {header}"
                        )
                    })?;
                    if env_var.trim().is_empty() {
                        anyhow::bail!(
                            "mcp server transport=streamable_http: env_http_headers[{header}] must not be empty"
                        );
                    }
                }
            }
        };

        Ok(())
    }

    pub fn argv(&self) -> &[String] {
        match self {
            Self::Stdio(cfg) => &cfg.argv,
            _ => &[],
        }
    }

    pub fn inherit_env(&self) -> bool {
        match self {
            Self::Stdio(cfg) => cfg.inherit_env,
            _ => true,
        }
    }

    pub fn unix_path(&self) -> Option<&Path> {
        match self {
            Self::Unix(cfg) => Some(cfg.unix_path.as_path()),
            _ => None,
        }
    }

    pub(crate) fn unix_path_required(&self) -> &Path {
        match self {
            Self::Unix(cfg) => cfg.unix_path.as_path(),
            _ => unreachable!("unix_path_required called for non-unix transport"),
        }
    }

    pub fn url(&self) -> Option<&str> {
        match self {
            Self::StreamableHttp(cfg) => match &cfg.urls {
                StreamableHttpUrls::Single { url } => Some(url.as_str()),
                StreamableHttpUrls::Split { .. } => None,
            },
            _ => None,
        }
    }

    pub fn sse_url(&self) -> Option<&str> {
        match self {
            Self::StreamableHttp(cfg) => match &cfg.urls {
                StreamableHttpUrls::Single { .. } => None,
                StreamableHttpUrls::Split { sse_url, .. } => Some(sse_url.as_str()),
            },
            _ => None,
        }
    }

    pub fn http_url(&self) -> Option<&str> {
        match self {
            Self::StreamableHttp(cfg) => match &cfg.urls {
                StreamableHttpUrls::Single { .. } => None,
                StreamableHttpUrls::Split { http_url, .. } => Some(http_url.as_str()),
            },
            _ => None,
        }
    }

    pub fn bearer_token_env_var(&self) -> Option<&str> {
        match self {
            Self::StreamableHttp(cfg) => cfg.bearer_token_env_var.as_deref(),
            _ => None,
        }
    }

    pub fn http_headers(&self) -> &BTreeMap<String, String> {
        match self {
            Self::StreamableHttp(cfg) => &cfg.http_headers,
            _ => empty_kv_map(),
        }
    }

    pub fn env_http_headers(&self) -> &BTreeMap<String, String> {
        match self {
            Self::StreamableHttp(cfg) => &cfg.env_http_headers,
            _ => empty_kv_map(),
        }
    }

    pub fn env(&self) -> &BTreeMap<String, String> {
        match self {
            Self::Stdio(cfg) => &cfg.env,
            _ => empty_kv_map(),
        }
    }

    pub fn stdout_log(&self) -> Option<&StdoutLogConfig> {
        match self {
            Self::Stdio(cfg) => cfg.stdout_log.as_ref(),
            _ => None,
        }
    }

    pub fn set_inherit_env(&mut self, inherit_env: bool) -> anyhow::Result<()> {
        match self {
            Self::Stdio(cfg) => {
                cfg.inherit_env = inherit_env;
            }
            Self::Unix(_) => {
                if !inherit_env {
                    anyhow::bail!("mcp server transport=unix: inherit_env must be true");
                }
            }
            Self::StreamableHttp(_) => {
                if !inherit_env {
                    anyhow::bail!("mcp server transport=streamable_http: inherit_env must be true");
                }
            }
        }
        Ok(())
    }

    pub fn set_bearer_token_env_var(
        &mut self,
        bearer_token_env_var: Option<String>,
    ) -> anyhow::Result<()> {
        match self {
            Self::StreamableHttp(cfg) => {
                cfg.bearer_token_env_var = bearer_token_env_var;
                Ok(())
            }
            _ => {
                if bearer_token_env_var.is_some() {
                    anyhow::bail!(
                        "mcp server transport={}: bearer_token_env_var is not allowed",
                        transport_tag(self.transport())
                    );
                }
                Ok(())
            }
        }
    }

    pub fn env_mut(&mut self) -> anyhow::Result<&mut BTreeMap<String, String>> {
        match self {
            Self::Stdio(cfg) => Ok(&mut cfg.env),
            _ => anyhow::bail!(
                "mcp server transport={}: env is not allowed",
                transport_tag(self.transport())
            ),
        }
    }

    pub fn http_headers_mut(&mut self) -> anyhow::Result<&mut BTreeMap<String, String>> {
        match self {
            Self::StreamableHttp(cfg) => Ok(&mut cfg.http_headers),
            _ => anyhow::bail!(
                "mcp server transport={}: http_headers are not allowed",
                transport_tag(self.transport())
            ),
        }
    }

    pub fn env_http_headers_mut(&mut self) -> anyhow::Result<&mut BTreeMap<String, String>> {
        match self {
            Self::StreamableHttp(cfg) => Ok(&mut cfg.env_http_headers),
            _ => anyhow::bail!(
                "mcp server transport={}: env_http_headers are not allowed",
                transport_tag(self.transport())
            ),
        }
    }

    pub fn set_stdout_log(&mut self, stdout_log: Option<StdoutLogConfig>) -> anyhow::Result<()> {
        match self {
            Self::Stdio(cfg) => {
                cfg.stdout_log = stdout_log;
                Ok(())
            }
            _ => {
                if stdout_log.is_some() {
                    anyhow::bail!(
                        "mcp server transport={}: stdout_log is not allowed",
                        transport_tag(self.transport())
                    );
                }
                Ok(())
            }
        }
    }
}

fn validate_argv(transport: Transport, argv: &[String]) -> anyhow::Result<()> {
    if argv.is_empty() {
        anyhow::bail!(
            "mcp server transport={}: argv must not be empty",
            transport_tag(transport)
        );
    }
    for (idx, arg) in argv.iter().enumerate() {
        if arg.trim().is_empty() {
            anyhow::bail!(
                "mcp server transport={}: argv[{idx}] must not be empty",
                transport_tag(transport)
            );
        }
    }
    Ok(())
}

fn transport_tag(transport: Transport) -> &'static str {
    match transport {
        Transport::Stdio => "stdio",
        Transport::Unix => "unix",
        Transport::StreamableHttp => "streamable_http",
    }
}

impl Config {
    pub fn new(client: ClientConfig, servers: BTreeMap<ServerName, ServerConfig>) -> Self {
        Self {
            path: None,
            client,
            servers,
        }
    }

    pub fn with_path(mut self, path: PathBuf) -> Self {
        self.path = Some(path);
        self
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn client(&self) -> &ClientConfig {
        &self.client
    }

    pub fn servers(&self) -> &BTreeMap<ServerName, ServerConfig> {
        &self.servers
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        self.client.validate().map_err(|err| {
            let msg = format!("invalid mcp client config: {err}");
            err.context(msg)
        })?;
        for (name, server) in self.servers.iter() {
            server.validate().map_err(|err| {
                let msg = format!("invalid mcp server config (server={name}): {err}");
                err.context(msg)
            })?;
        }
        Ok(())
    }

    pub fn server(&self, name: &str) -> Option<&ServerConfig> {
        self.servers.get(name)
    }

    pub fn server_named(&self, name: &ServerName) -> Option<&ServerConfig> {
        self.servers.get(name)
    }
}
