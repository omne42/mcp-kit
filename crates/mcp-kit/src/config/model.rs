use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

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
pub struct ServerConfig {
    pub(super) transport: Transport,
    pub(super) argv: Vec<String>,
    /// When true, inherit the current process environment when spawning a
    /// `transport=stdio` server.
    ///
    /// Default: `false` for `transport=stdio` (safer-by-default).
    ///
    /// When false, the child environment is cleared and only a small set of
    /// non-secret baseline variables are propagated (plus any `env` entries).
    pub(super) inherit_env: bool,
    pub(super) unix_path: Option<PathBuf>,
    pub(super) url: Option<String>,
    pub(super) sse_url: Option<String>,
    pub(super) http_url: Option<String>,
    pub(super) bearer_token_env_var: Option<String>,
    pub(super) http_headers: BTreeMap<String, String>,
    pub(super) env_http_headers: BTreeMap<String, String>,
    pub(super) env: BTreeMap<String, String>,
    pub(super) stdout_log: Option<StdoutLogConfig>,
}

impl ServerConfig {
    pub fn stdio(argv: Vec<String>) -> anyhow::Result<Self> {
        if argv.is_empty() {
            anyhow::bail!("mcp server transport=stdio: argv must not be empty");
        }
        for (idx, arg) in argv.iter().enumerate() {
            if arg.trim().is_empty() {
                anyhow::bail!("mcp server transport=stdio: argv[{idx}] must not be empty");
            }
        }
        Ok(Self {
            transport: Transport::Stdio,
            argv,
            inherit_env: false,
            unix_path: None,
            url: None,
            sse_url: None,
            http_url: None,
            bearer_token_env_var: None,
            http_headers: BTreeMap::new(),
            env_http_headers: BTreeMap::new(),
            env: BTreeMap::new(),
            stdout_log: None,
        })
    }

    pub fn unix(unix_path: PathBuf) -> anyhow::Result<Self> {
        if unix_path.as_os_str().is_empty() {
            anyhow::bail!("mcp server transport=unix: unix_path must not be empty");
        }
        Ok(Self {
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
        })
    }

    pub fn streamable_http(url: impl Into<String>) -> anyhow::Result<Self> {
        let url = url.into();
        if url.trim().is_empty() {
            anyhow::bail!("mcp server transport=streamable_http: url must not be empty");
        }
        Ok(Self {
            transport: Transport::StreamableHttp,
            argv: Vec::new(),
            inherit_env: true,
            unix_path: None,
            url: Some(url),
            sse_url: None,
            http_url: None,
            bearer_token_env_var: None,
            http_headers: BTreeMap::new(),
            env_http_headers: BTreeMap::new(),
            env: BTreeMap::new(),
            stdout_log: None,
        })
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
        Ok(Self {
            transport: Transport::StreamableHttp,
            argv: Vec::new(),
            inherit_env: true,
            unix_path: None,
            url: None,
            sse_url: Some(sse_url),
            http_url: Some(http_url),
            bearer_token_env_var: None,
            http_headers: BTreeMap::new(),
            env_http_headers: BTreeMap::new(),
            env: BTreeMap::new(),
            stdout_log: None,
        })
    }

    pub fn transport(&self) -> Transport {
        self.transport
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        match self.transport {
            Transport::Stdio => {
                if self.argv.is_empty() {
                    anyhow::bail!("mcp server transport=stdio: argv must not be empty");
                }
                for (idx, arg) in self.argv.iter().enumerate() {
                    if arg.trim().is_empty() {
                        anyhow::bail!("mcp server transport=stdio: argv[{idx}] must not be empty");
                    }
                }
                if self.unix_path.is_some() {
                    anyhow::bail!("mcp server transport=stdio: unix_path is not allowed");
                }
                if self.url.is_some() || self.sse_url.is_some() || self.http_url.is_some() {
                    anyhow::bail!(
                        "mcp server transport=stdio: url/sse_url/http_url are not allowed"
                    );
                }
                if self.bearer_token_env_var.is_some()
                    || !self.http_headers.is_empty()
                    || !self.env_http_headers.is_empty()
                {
                    anyhow::bail!("mcp server transport=stdio: http auth/headers are not allowed");
                }
                for (key, value) in self.env.iter() {
                    if key.trim().is_empty() {
                        anyhow::bail!("mcp server transport=stdio: env key must not be empty");
                    }
                    if value.trim().is_empty() {
                        anyhow::bail!("mcp server transport=stdio: env[{key}] must not be empty");
                    }
                }
                if let Some(log) = self.stdout_log.as_ref() {
                    log.validate()?;
                }
            }
            Transport::Unix => {
                if !self.argv.is_empty() {
                    anyhow::bail!("mcp server transport=unix: argv is not allowed");
                }
                if !self.inherit_env {
                    anyhow::bail!("mcp server transport=unix: inherit_env must be true");
                }
                let Some(unix_path) = self.unix_path.as_deref() else {
                    anyhow::bail!("mcp server transport=unix: unix_path must be set");
                };
                if unix_path.as_os_str().is_empty() {
                    anyhow::bail!("mcp server transport=unix: unix_path must not be empty");
                }
                if self.url.is_some() || self.sse_url.is_some() || self.http_url.is_some() {
                    anyhow::bail!(
                        "mcp server transport=unix: url/sse_url/http_url are not allowed"
                    );
                }
                if !self.env.is_empty() {
                    anyhow::bail!("mcp server transport=unix: env is not allowed");
                }
                if self.stdout_log.is_some() {
                    anyhow::bail!("mcp server transport=unix: stdout_log is not allowed");
                }
                if self.bearer_token_env_var.is_some()
                    || !self.http_headers.is_empty()
                    || !self.env_http_headers.is_empty()
                {
                    anyhow::bail!("mcp server transport=unix: http auth/headers are not allowed");
                }
            }
            Transport::StreamableHttp => {
                if !self.argv.is_empty() {
                    anyhow::bail!("mcp server transport=streamable_http: argv is not allowed");
                }
                if !self.inherit_env {
                    anyhow::bail!("mcp server transport=streamable_http: inherit_env must be true");
                }
                if self.unix_path.is_some() {
                    anyhow::bail!("mcp server transport=streamable_http: unix_path is not allowed");
                }
                if !self.env.is_empty() {
                    anyhow::bail!("mcp server transport=streamable_http: env is not supported");
                }
                if self.stdout_log.is_some() {
                    anyhow::bail!(
                        "mcp server transport=streamable_http: stdout_log is not supported"
                    );
                }

                match (
                    self.url.as_deref(),
                    self.sse_url.as_deref(),
                    self.http_url.as_deref(),
                ) {
                    (Some(url), None, None) => {
                        if url.trim().is_empty() {
                            anyhow::bail!(
                                "mcp server transport=streamable_http: url must not be empty"
                            );
                        }
                    }
                    (None, Some(sse_url), Some(http_url)) => {
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
                    (None, None, None) => {
                        anyhow::bail!(
                            "mcp server transport=streamable_http: url (or sse_url + http_url) is required"
                        )
                    }
                    (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
                        anyhow::bail!(
                            "mcp server transport=streamable_http: set either url or (sse_url + http_url), not both"
                        )
                    }
                    (None, Some(_), None) | (None, None, Some(_)) => {
                        anyhow::bail!(
                            "mcp server transport=streamable_http: sse_url and http_url must both be set"
                        )
                    }
                }

                if let Some(env_var) = self.bearer_token_env_var.as_deref() {
                    if env_var.trim().is_empty() {
                        anyhow::bail!(
                            "mcp server transport=streamable_http: bearer_token_env_var must not be empty"
                        );
                    }
                }

                for (header, value) in self.http_headers.iter() {
                    if header.trim().is_empty() {
                        anyhow::bail!(
                            "mcp server transport=streamable_http: http_headers key must not be empty"
                        );
                    }
                    if value.trim().is_empty() {
                        anyhow::bail!(
                            "mcp server transport=streamable_http: http_headers[{header}] must not be empty"
                        );
                    }
                }
                for (header, env_var) in self.env_http_headers.iter() {
                    if header.trim().is_empty() {
                        anyhow::bail!(
                            "mcp server transport=streamable_http: env_http_headers key must not be empty"
                        );
                    }
                    if env_var.trim().is_empty() {
                        anyhow::bail!(
                            "mcp server transport=streamable_http: env_http_headers[{header}] must not be empty"
                        );
                    }
                }
            }
        }

        Ok(())
    }

    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    pub fn inherit_env(&self) -> bool {
        self.inherit_env
    }

    pub fn unix_path(&self) -> Option<&Path> {
        self.unix_path.as_deref()
    }

    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    pub fn sse_url(&self) -> Option<&str> {
        self.sse_url.as_deref()
    }

    pub fn http_url(&self) -> Option<&str> {
        self.http_url.as_deref()
    }

    pub fn bearer_token_env_var(&self) -> Option<&str> {
        self.bearer_token_env_var.as_deref()
    }

    pub fn http_headers(&self) -> &BTreeMap<String, String> {
        &self.http_headers
    }

    pub fn env_http_headers(&self) -> &BTreeMap<String, String> {
        &self.env_http_headers
    }

    pub fn env(&self) -> &BTreeMap<String, String> {
        &self.env
    }

    pub fn stdout_log(&self) -> Option<&StdoutLogConfig> {
        self.stdout_log.as_ref()
    }

    pub fn set_inherit_env(&mut self, inherit_env: bool) {
        self.inherit_env = inherit_env;
    }

    pub fn set_bearer_token_env_var(&mut self, bearer_token_env_var: Option<String>) {
        self.bearer_token_env_var = bearer_token_env_var;
    }

    pub fn env_mut(&mut self) -> &mut BTreeMap<String, String> {
        &mut self.env
    }

    pub fn http_headers_mut(&mut self) -> &mut BTreeMap<String, String> {
        &mut self.http_headers
    }

    pub fn env_http_headers_mut(&mut self) -> &mut BTreeMap<String, String> {
        &mut self.env_http_headers
    }

    pub fn set_stdout_log(&mut self, stdout_log: Option<StdoutLogConfig>) {
        self.stdout_log = stdout_log;
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
