//! Connection cache + MCP initialize + request helpers.

use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::process::{Child, Command};

use crate::{
    Config, MCP_PROTOCOL_VERSION, McpNotification, McpRequest, Root, ServerConfig, ServerName,
    Session, Transport, TrustMode, UntrustedStreamableHttpPolicy,
};

mod placeholders;
mod streamable_http_validation;

use placeholders::{apply_stdio_baseline_env, expand_placeholders_trusted};
use streamable_http_validation::{
    should_disconnect_after_jsonrpc_error, validate_streamable_http_config,
    validate_streamable_http_url_untrusted_dns,
};

#[cfg(test)]
use streamable_http_validation::validate_streamable_http_url_untrusted;

const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

fn parse_server_name_anyhow(server_name: &str) -> anyhow::Result<ServerName> {
    ServerName::parse(server_name)
        .map_err(|err| anyhow::anyhow!("invalid mcp server name {server_name:?}: {err}"))
}

pub enum ServerRequestOutcome {
    Ok(Value),
    Error {
        code: i64,
        message: String,
        data: Option<Value>,
    },
    MethodNotFound,
}

pub struct ServerRequestContext {
    pub server_name: ServerName,
    pub method: String,
    pub params: Option<Value>,
}

pub type ServerRequestHandler =
    Arc<dyn Fn(ServerRequestContext) -> BoxFuture<ServerRequestOutcome> + Send + Sync>;

pub struct ServerNotificationContext {
    pub server_name: ServerName,
    pub method: String,
    pub params: Option<Value>,
}

pub type ServerNotificationHandler =
    Arc<dyn Fn(ServerNotificationContext) -> BoxFuture<()> + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProtocolVersionCheck {
    /// Fail closed (default): reject servers whose `initialize` result includes a different
    /// `protocolVersion`.
    #[default]
    Strict,
    /// Allow mismatches but record them in `Manager::protocol_version_mismatches`.
    Warn,
    /// Allow mismatches without recording.
    Ignore,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolVersionMismatch {
    pub server_name: ServerName,
    pub client_protocol_version: String,
    pub server_protocol_version: String,
}

pub struct Manager {
    conns: HashMap<ServerName, Connection>,
    init_results: HashMap<ServerName, Value>,
    client_name: String,
    client_version: String,
    protocol_version: String,
    protocol_version_check: ProtocolVersionCheck,
    protocol_version_mismatches: Vec<ProtocolVersionMismatch>,
    server_handler_timeout_counts: Arc<Mutex<HashMap<ServerName, u64>>>,
    capabilities: Value,
    roots: Option<Arc<Vec<Root>>>,
    trust_mode: TrustMode,
    untrusted_streamable_http_policy: UntrustedStreamableHttpPolicy,
    allow_stdout_log_outside_root: bool,
    request_timeout: Duration,
    server_handler_concurrency: usize,
    server_handler_timeout: Option<Duration>,
    server_request_handler: ServerRequestHandler,
    server_notification_handler: ServerNotificationHandler,
}

pub struct Connection {
    child: Option<Child>,
    client: mcp_jsonrpc::Client,
    handler_tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Connection {
    pub fn client(&self) -> &mcp_jsonrpc::Client {
        &self.client
    }

    pub fn client_mut(&mut self) -> &mut mcp_jsonrpc::Client {
        &mut self.client
    }

    pub fn child_id(&self) -> Option<u32> {
        self.child.as_ref().and_then(|child| child.id())
    }

    pub fn take_child(&mut self) -> Option<Child> {
        self.child.take()
    }

    /// Closes the JSON-RPC client and (if present) waits for the underlying child process to exit.
    ///
    /// Note: this can hang indefinitely if the child process does not exit. Prefer
    /// `Connection::wait_with_timeout` if you need an upper bound.
    pub async fn wait(mut self) -> anyhow::Result<Option<std::process::ExitStatus>> {
        let status = self.client.wait().await.context("close jsonrpc client")?;
        let status = match status {
            Some(status) => Some(status),
            None => match &mut self.child {
                Some(child) => Some(child.wait().await?),
                None => None,
            },
        };

        let handler_tasks = std::mem::take(&mut self.handler_tasks);
        for task in handler_tasks {
            if let Err(err) = task.await {
                if err.is_panic() {
                    anyhow::bail!("server handler task panicked");
                }
                anyhow::bail!("server handler task failed: {err}");
            }
        }

        Ok(status)
    }

    /// Closes the JSON-RPC client and waits for the underlying child process to exit, up to
    /// `timeout`.
    pub async fn wait_with_timeout(
        mut self,
        timeout: Duration,
        on_timeout: mcp_jsonrpc::WaitOnTimeout,
    ) -> anyhow::Result<Option<std::process::ExitStatus>> {
        let status = self
            .client
            .wait_with_timeout(timeout, on_timeout)
            .await
            .context("close jsonrpc client")?;
        let status = match status {
            Some(status) => Some(status),
            None => match &mut self.child {
                Some(child) => match tokio::time::timeout(timeout, child.wait()).await {
                    Ok(status) => Some(status?),
                    Err(_) => match on_timeout {
                        mcp_jsonrpc::WaitOnTimeout::ReturnError => {
                            anyhow::bail!("wait timed out after {timeout:?}")
                        }
                        mcp_jsonrpc::WaitOnTimeout::Kill { kill_timeout } => {
                            let child_id = child.id();
                            if let Err(err) = child.start_kill() {
                                match child.try_wait() {
                                    Ok(Some(status)) => return Ok(Some(status)),
                                    Ok(None) => {
                                        anyhow::bail!(
                                            "wait timed out after {timeout:?}; failed to kill child (id={child_id:?}): {err}"
                                        )
                                    }
                                    Err(try_wait_err) => {
                                        anyhow::bail!(
                                            "wait timed out after {timeout:?}; failed to kill child (id={child_id:?}): {err}; try_wait failed: {try_wait_err}"
                                        )
                                    }
                                }
                            }

                            match tokio::time::timeout(kill_timeout, child.wait()).await {
                                Ok(status) => Some(status?),
                                Err(_) => anyhow::bail!(
                                    "wait timed out after {timeout:?}; killed child (id={child_id:?}) but it did not exit within {kill_timeout:?}"
                                ),
                            }
                        }
                    },
                },
                None => None,
            },
        };

        let handler_tasks = std::mem::take(&mut self.handler_tasks);
        for task in handler_tasks {
            if let Err(err) = task.await {
                if err.is_panic() {
                    anyhow::bail!("server handler task panicked");
                }
                anyhow::bail!("server handler task failed: {err}");
            }
        }

        Ok(status)
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        for task in self.handler_tasks.drain(..) {
            task.abort();
        }
    }
}

impl Default for Manager {
    fn default() -> Self {
        Self::new(
            "mcp-kit",
            env!("CARGO_PKG_VERSION"),
            Duration::from_secs(30),
        )
    }
}

impl Manager {
    pub fn from_config(
        config: &Config,
        client_name: impl Into<String>,
        client_version: impl Into<String>,
        timeout: Duration,
    ) -> Self {
        let mut manager = Self::new(client_name, client_version, timeout);
        if let Some(protocol_version) = config.client().protocol_version.clone() {
            manager = manager.with_protocol_version(protocol_version);
        }
        if let Some(capabilities) = config.client().capabilities.clone() {
            manager = manager.with_capabilities(capabilities);
        }
        if let Some(roots) = config.client().roots.clone() {
            manager = manager.with_roots(roots);
        }
        manager
    }

    pub fn new(
        client_name: impl Into<String>,
        client_version: impl Into<String>,
        timeout: Duration,
    ) -> Self {
        let server_request_handler: ServerRequestHandler =
            Arc::new(|_| Box::pin(async { ServerRequestOutcome::MethodNotFound }));
        let server_notification_handler: ServerNotificationHandler =
            Arc::new(|_| Box::pin(async {}));

        Self {
            conns: HashMap::new(),
            init_results: HashMap::new(),
            client_name: client_name.into(),
            client_version: client_version.into(),
            protocol_version: MCP_PROTOCOL_VERSION.to_string(),
            protocol_version_check: ProtocolVersionCheck::Strict,
            protocol_version_mismatches: Vec::new(),
            server_handler_timeout_counts: Arc::new(Mutex::new(HashMap::new())),
            capabilities: Value::Object(serde_json::Map::new()),
            roots: None,
            trust_mode: TrustMode::Untrusted,
            untrusted_streamable_http_policy: UntrustedStreamableHttpPolicy::default(),
            allow_stdout_log_outside_root: false,
            request_timeout: timeout,
            server_handler_concurrency: 1,
            server_handler_timeout: None,
            server_request_handler,
            server_notification_handler,
        }
    }

    pub fn with_trust_mode(mut self, trust_mode: TrustMode) -> Self {
        self.trust_mode = trust_mode;
        self
    }

    pub fn with_untrusted_streamable_http_policy(
        mut self,
        policy: UntrustedStreamableHttpPolicy,
    ) -> Self {
        self.untrusted_streamable_http_policy = policy;
        self
    }

    pub fn with_allow_stdout_log_outside_root(mut self, allow: bool) -> Self {
        self.allow_stdout_log_outside_root = allow;
        self
    }

    pub fn trust_mode(&self) -> TrustMode {
        self.trust_mode
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    pub fn with_protocol_version(mut self, protocol_version: impl Into<String>) -> Self {
        self.protocol_version = protocol_version.into();
        self
    }

    pub fn with_protocol_version_check(mut self, check: ProtocolVersionCheck) -> Self {
        self.protocol_version_check = check;
        self
    }

    pub fn protocol_version_mismatches(&self) -> &[ProtocolVersionMismatch] {
        &self.protocol_version_mismatches
    }

    pub fn take_protocol_version_mismatches(&mut self) -> Vec<ProtocolVersionMismatch> {
        std::mem::take(&mut self.protocol_version_mismatches)
    }

    /// Returns the number of server→client handler timeouts observed for `server_name`.
    ///
    /// This increments when a server→client request/notification handler exceeds
    /// `Manager::with_server_handler_timeout(...)`.
    pub fn server_handler_timeout_count(&self, server_name: &str) -> u64 {
        let counts = self
            .server_handler_timeout_counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        counts.get(server_name).copied().unwrap_or(0)
    }

    /// Returns a snapshot of timeout counts for all servers.
    pub fn server_handler_timeout_counts(&self) -> HashMap<ServerName, u64> {
        let counts = self
            .server_handler_timeout_counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        counts.clone()
    }

    /// Takes (and clears) the timeout counts map.
    pub fn take_server_handler_timeout_counts(&mut self) -> HashMap<ServerName, u64> {
        let mut counts = self
            .server_handler_timeout_counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::mem::take(&mut *counts)
    }

    pub fn with_capabilities(mut self, capabilities: Value) -> Self {
        self.capabilities = capabilities;
        if self.roots.is_some() {
            ensure_roots_capability(&mut self.capabilities);
        }
        self
    }

    pub fn with_roots(mut self, roots: Vec<Root>) -> Self {
        self.roots = Some(Arc::new(roots));
        ensure_roots_capability(&mut self.capabilities);
        self
    }

    pub fn with_server_request_handler(mut self, handler: ServerRequestHandler) -> Self {
        self.server_request_handler = handler;
        self
    }

    pub fn with_server_notification_handler(mut self, handler: ServerNotificationHandler) -> Self {
        self.server_notification_handler = handler;
        self
    }

    /// Set the maximum number of in-flight server→client handler calls per connection.
    ///
    /// Default: 1 (sequential handling).
    pub fn with_server_handler_concurrency(mut self, concurrency: usize) -> Self {
        self.server_handler_concurrency = concurrency.max(1);
        self
    }

    /// Set a per-message timeout for server→client request/notification handlers.
    ///
    /// Default: no timeout.
    pub fn with_server_handler_timeout(mut self, timeout: Duration) -> Self {
        self.server_handler_timeout = Some(timeout);
        self
    }

    pub fn without_server_handler_timeout(mut self) -> Self {
        self.server_handler_timeout = None;
        self
    }

    pub fn is_connected(&mut self, server_name: &str) -> bool {
        self.is_connected_and_alive(server_name)
    }

    pub fn is_connected_named(&mut self, server_name: &ServerName) -> bool {
        self.is_connected(server_name.as_str())
    }

    pub fn connected_server_names(&mut self) -> Vec<ServerName> {
        let names = self.conns.keys().cloned().collect::<Vec<_>>();
        names
            .into_iter()
            .filter(|name| self.is_connected_and_alive(name))
            .collect()
    }

    pub fn initialize_result(&self, server_name: &str) -> Option<&Value> {
        self.init_results.get(server_name)
    }

    pub fn initialize_result_named(&self, server_name: &ServerName) -> Option<&Value> {
        self.initialize_result(server_name.as_str())
    }

    pub async fn connect(
        &mut self,
        server_name: &str,
        server_cfg: &ServerConfig,
        cwd: &Path,
    ) -> anyhow::Result<()> {
        self.connect_with_builder(server_name, server_cfg, cwd, || {
            parse_server_name_anyhow(server_name)
        })
        .await
    }

    async fn connect_with_builder<F>(
        &mut self,
        server_name: &str,
        server_cfg: &ServerConfig,
        cwd: &Path,
        build_server_name: F,
    ) -> anyhow::Result<()>
    where
        F: FnOnce() -> anyhow::Result<ServerName>,
    {
        if self.is_connected_and_alive(server_name) {
            return Ok(());
        }

        let server_name_key = build_server_name()?;

        let (client, child) = match server_cfg.transport() {
            Transport::Stdio => {
                if self.trust_mode == TrustMode::Untrusted {
                    anyhow::bail!(
                        "refusing to spawn mcp server in untrusted mode: {server_name} (set Manager::with_trust_mode(TrustMode::Trusted) to override)"
                    );
                }
                if server_cfg.argv().is_empty() {
                    anyhow::bail!("mcp server argv must not be empty");
                }

                let expanded_argv = server_cfg
                    .argv()
                    .iter()
                    .enumerate()
                    .map(|(idx, arg)| {
                        let expanded = expand_placeholders_trusted(arg, cwd).with_context(|| {
                            format!(
                                "expand argv placeholder (server={server_name} argv[{idx}] redacted)"
                            )
                        })?;
                        Ok::<_, anyhow::Error>(std::ffi::OsString::from(expanded))
                    })
                    .collect::<anyhow::Result<Vec<std::ffi::OsString>>>()?;

                let mut cmd = Command::new(&expanded_argv[0]);
                cmd.args(expanded_argv.iter().skip(1));
                cmd.current_dir(cwd);
                cmd.stdin(Stdio::piped());
                cmd.stdout(Stdio::piped());
                cmd.stderr(Stdio::inherit());
                if !server_cfg.inherit_env() {
                    cmd.env_clear();
                    apply_stdio_baseline_env(&mut cmd);
                }
                for (key, value) in server_cfg.env().iter() {
                    let value = expand_placeholders_trusted(value, cwd)
                        .with_context(|| format!("expand env placeholder: {key}"))?;
                    cmd.env(key, value);
                }
                cmd.kill_on_drop(true);

                let stdout_log = server_cfg.stdout_log().map(|log| {
                    if !self.allow_stdout_log_outside_root && !log.path.starts_with(cwd) {
                        anyhow::bail!(
                            "mcp server {server_name}: stdout_log.path must be within root (set Manager::with_allow_stdout_log_outside_root(true) to override): {}",
                            log.path.display()
                        );
                    }
                    Ok::<_, anyhow::Error>(mcp_jsonrpc::StdoutLog {
                        path: log.path.clone(),
                        max_bytes_per_part: log.max_bytes_per_part,
                        max_parts: log.max_parts,
                    })
                });
                let stdout_log = stdout_log.transpose()?;
                let mut client = mcp_jsonrpc::Client::spawn_command_with_options(
                    cmd,
                    mcp_jsonrpc::SpawnOptions {
                        stdout_log,
                        ..Default::default()
                    },
                )
                .await
                .with_context(|| {
                    format!(
                        "spawn mcp server (server={server_name}) argv redacted (argc={})",
                        server_cfg.argv().len()
                    )
                })?;
                let child = client.take_child();
                (client, child)
            }
            Transport::Unix => {
                if self.trust_mode == TrustMode::Untrusted {
                    anyhow::bail!(
                        "refusing to connect unix mcp server in untrusted mode: {server_name} (set Manager::with_trust_mode(TrustMode::Trusted) to override)"
                    );
                }
                let unix_path = server_cfg
                    .unix_path()
                    .ok_or_else(|| anyhow::anyhow!("mcp server unix_path must be set"))?;
                let client = mcp_jsonrpc::Client::connect_unix(unix_path)
                    .await
                    .with_context(|| {
                        format!("connect unix mcp server path={}", unix_path.display())
                    })?;
                (client, None)
            }
            Transport::StreamableHttp => {
                let (sse_url_raw, post_url_raw) = match (
                    server_cfg.url(),
                    server_cfg.sse_url(),
                    server_cfg.http_url(),
                ) {
                    (Some(url), None, None) => (url, url),
                    (None, Some(sse_url), Some(http_url)) => (sse_url, http_url),
                    _ => {
                        anyhow::bail!(
                            "mcp server {server_name}: set url or (sse_url + http_url) for transport=streamable_http"
                        )
                    }
                };

                let (sse_url_field, post_url_field) = if server_cfg.url().is_some() {
                    ("url", "url")
                } else {
                    ("sse_url", "http_url")
                };

                let sse_url = if self.trust_mode == TrustMode::Trusted {
                    expand_placeholders_trusted(sse_url_raw, cwd)
                        .with_context(|| {
                            format!(
                                "expand url placeholder (server={server_name} field={sse_url_field}) (url redacted)"
                            )
                        })?
                } else {
                    sse_url_raw.to_string()
                };
                let post_url = if self.trust_mode == TrustMode::Trusted {
                    expand_placeholders_trusted(post_url_raw, cwd)
                        .with_context(|| {
                            format!(
                                "expand url placeholder (server={server_name} field={post_url_field}) (url redacted)"
                            )
                        })?
                } else {
                    post_url_raw.to_string()
                };

                validate_streamable_http_config(
                    self.trust_mode,
                    &self.untrusted_streamable_http_policy,
                    server_name,
                    sse_url_field,
                    &sse_url,
                    server_cfg,
                )?;
                if post_url != sse_url {
                    validate_streamable_http_config(
                        self.trust_mode,
                        &self.untrusted_streamable_http_policy,
                        server_name,
                        post_url_field,
                        &post_url,
                        server_cfg,
                    )?;
                }
                if self.trust_mode != TrustMode::Trusted {
                    validate_streamable_http_url_untrusted_dns(
                        &self.untrusted_streamable_http_policy,
                        server_name,
                        sse_url_field,
                        &sse_url,
                    )
                    .await?;
                    if post_url != sse_url {
                        validate_streamable_http_url_untrusted_dns(
                            &self.untrusted_streamable_http_policy,
                            server_name,
                            post_url_field,
                            &post_url,
                        )
                        .await?;
                    }
                }

                let mut headers: std::collections::HashMap<String, String> = server_cfg
                    .http_headers()
                    .iter()
                    .map(|(k, v)| {
                        let v = if self.trust_mode == TrustMode::Trusted {
                            expand_placeholders_trusted(v, cwd).with_context(|| {
                                format!("expand http_header placeholder: {server_name} header={k}")
                            })?
                        } else {
                            v.to_string()
                        };
                        Ok((k.to_string(), v))
                    })
                    .collect::<anyhow::Result<_>>()?;
                headers.insert(
                    "MCP-Protocol-Version".to_string(),
                    self.protocol_version.clone(),
                );

                if let Some(env_var) = server_cfg.bearer_token_env_var() {
                    if self.trust_mode == TrustMode::Untrusted {
                        anyhow::bail!(
                            "refusing to read bearer token env var in untrusted mode: {server_name} (set Manager::with_trust_mode(TrustMode::Trusted) to override)"
                        );
                    }
                    let token = std::env::var(env_var)
                        .with_context(|| format!("read bearer token env var: {env_var}"))?;
                    headers.insert("Authorization".to_string(), format!("Bearer {token}"));
                }

                if !server_cfg.env_http_headers().is_empty() {
                    if self.trust_mode == TrustMode::Untrusted {
                        anyhow::bail!(
                            "refusing to read http header env vars in untrusted mode: {server_name} (set Manager::with_trust_mode(TrustMode::Trusted) to override)"
                        );
                    }

                    for (header, env_var) in server_cfg.env_http_headers().iter() {
                        let value = std::env::var(env_var)
                            .with_context(|| format!("read http header env var: {env_var}"))?;
                        headers.insert(header.to_string(), value);
                    }
                }

                let client = mcp_jsonrpc::Client::connect_streamable_http_split_with_options(
                    &sse_url,
                    &post_url,
                    mcp_jsonrpc::StreamableHttpOptions {
                        headers,
                        request_timeout: Some(self.request_timeout),
                        ..Default::default()
                    },
                    mcp_jsonrpc::SpawnOptions::default(),
                )
                .await
                .with_context(|| {
                    if sse_url == post_url {
                        format!(
                            "connect streamable http mcp server (server={server_name} field={sse_url_field}) (url redacted)"
                        )
                    } else {
                        format!(
                            "connect streamable http mcp server (server={server_name} fields={sse_url_field},{post_url_field}) (urls redacted)"
                        )
                    }
                })?;
                (client, None)
            }
        };

        self.install_connection_parsed(server_name_key, client, child)
            .await?;
        Ok(())
    }

    /// Attach an already-connected `mcp_jsonrpc::Client` and perform MCP initialize.
    ///
    /// This requires `TrustMode::Trusted` because attaching a custom client can bypass
    /// `Untrusted`-mode safety checks (for example, by constructing a custom streamable_http
    /// client with different redirect/proxy/header behavior).
    pub async fn connect_jsonrpc(
        &mut self,
        server_name: &str,
        client: mcp_jsonrpc::Client,
    ) -> anyhow::Result<()> {
        if self.trust_mode == TrustMode::Untrusted {
            anyhow::bail!(
                "refusing to attach custom JSON-RPC client in untrusted mode: {server_name} (set Manager::with_trust_mode(TrustMode::Trusted) or use Manager::connect_jsonrpc_unchecked)"
            );
        }

        self.connect_jsonrpc_unchecked(server_name, client).await
    }

    /// Like `Manager::connect_jsonrpc`, but does not enforce `TrustMode`.
    ///
    /// This is intended for controlled environments (e.g. tests) where you explicitly accept the
    /// risk of bypassing `Untrusted`-mode safety checks.
    pub async fn connect_jsonrpc_unchecked(
        &mut self,
        server_name: &str,
        client: mcp_jsonrpc::Client,
    ) -> anyhow::Result<()> {
        self.connect_jsonrpc_with_builder(
            server_name,
            || parse_server_name_anyhow(server_name),
            client,
        )
        .await
    }

    async fn connect_jsonrpc_with_builder<F>(
        &mut self,
        server_name: &str,
        build_server_name: F,
        mut client: mcp_jsonrpc::Client,
    ) -> anyhow::Result<()>
    where
        F: FnOnce() -> anyhow::Result<ServerName>,
    {
        if self.is_connected_and_alive(server_name) {
            return Ok(());
        }

        let server_name_key = build_server_name()?;
        let child = client.take_child();
        self.install_connection_parsed(server_name_key, client, child)
            .await?;
        Ok(())
    }

    /// Attach a custom `AsyncRead + AsyncWrite` transport as a JSON-RPC connection and perform
    /// MCP initialize.
    ///
    /// This requires `TrustMode::Trusted` because attaching a custom transport can bypass
    /// `Untrusted`-mode safety checks.
    pub async fn connect_io<R, W>(
        &mut self,
        server_name: &str,
        read: R,
        write: W,
    ) -> anyhow::Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        if self.trust_mode == TrustMode::Untrusted {
            anyhow::bail!(
                "refusing to attach custom JSON-RPC IO in untrusted mode: {server_name} (set Manager::with_trust_mode(TrustMode::Trusted) or use Manager::connect_io_unchecked)"
            );
        }

        self.connect_io_unchecked(server_name, read, write).await
    }

    /// Like `Manager::connect_io`, but does not enforce `TrustMode`.
    ///
    /// This is intended for controlled environments (e.g. tests) where you explicitly accept the
    /// risk of bypassing `Untrusted`-mode safety checks.
    pub async fn connect_io_unchecked<R, W>(
        &mut self,
        server_name: &str,
        read: R,
        write: W,
    ) -> anyhow::Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        if self.is_connected_and_alive(server_name) {
            return Ok(());
        }

        let client = mcp_jsonrpc::Client::connect_io(read, write)
            .await
            .context("connect jsonrpc io")?;
        self.connect_jsonrpc_unchecked(server_name, client).await
    }

    fn is_connected_and_alive(&mut self, server_name: &str) -> bool {
        let Some(exited) = self.connection_exited(server_name) else {
            return false;
        };
        if exited {
            self.conns.remove(server_name);
            self.init_results.remove(server_name);
            return false;
        }
        true
    }

    fn connection_exited(&mut self, server_name: &str) -> Option<bool> {
        let conn = self.conns.get_mut(server_name)?;
        let exited = match &mut conn.child {
            Some(child) => {
                if child.try_wait().ok().flatten().is_some() {
                    true
                } else {
                    conn.client.handle().is_closed()
                }
            }
            None => conn.client.handle().is_closed(),
        };

        if exited {
            return Some(true);
        }

        if conn.handler_tasks.iter().any(|task| task.is_finished()) {
            return Some(true);
        }

        Some(false)
    }

    async fn install_connection_parsed(
        &mut self,
        server_name: ServerName,
        mut client: mcp_jsonrpc::Client,
        child: Option<Child>,
    ) -> anyhow::Result<()> {
        struct HandlerTasksGuard {
            tasks: Vec<tokio::task::JoinHandle<()>>,
            armed: bool,
        }

        impl HandlerTasksGuard {
            fn new(tasks: Vec<tokio::task::JoinHandle<()>>) -> Self {
                Self { tasks, armed: true }
            }

            fn disarm(mut self) -> Vec<tokio::task::JoinHandle<()>> {
                self.armed = false;
                std::mem::take(&mut self.tasks)
            }
        }

        impl Drop for HandlerTasksGuard {
            fn drop(&mut self) {
                if !self.armed {
                    return;
                }
                for task in self.tasks.drain(..) {
                    task.abort();
                }
            }
        }

        let handler_tasks = self.attach_client_handlers(server_name.clone(), &mut client);
        let handler_tasks_guard = HandlerTasksGuard::new(handler_tasks);
        let init_result = self.initialize(&server_name, &client).await?;
        let handler_tasks = handler_tasks_guard.disarm();

        self.init_results.insert(server_name.clone(), init_result);
        self.conns.insert(
            server_name,
            Connection {
                child,
                client,
                handler_tasks,
            },
        );
        Ok(())
    }

    fn attach_client_handlers(
        &self,
        server_name: ServerName,
        client: &mut mcp_jsonrpc::Client,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let mut tasks = Vec::new();
        let handler_concurrency = self.server_handler_concurrency.max(1);
        let handler_timeout = self.server_handler_timeout;
        let handler_timeout_counts = self.server_handler_timeout_counts.clone();

        struct AbortOnDrop(tokio::task::AbortHandle);

        impl Drop for AbortOnDrop {
            fn drop(&mut self) {
                self.0.abort();
            }
        }

        if let Some(mut requests_rx) = client.take_requests() {
            let handler = self.server_request_handler.clone();
            let roots = self.roots.clone();
            let server_name = server_name.clone();
            let handler_timeout_counts = handler_timeout_counts.clone();
            tasks.push(tokio::spawn(async move {
                let mut in_flight = tokio::task::JoinSet::new();

                loop {
                    tokio::select! {
                        Some(req) = requests_rx.recv(), if in_flight.len() < handler_concurrency => {
                            let handler = handler.clone();
                            let roots = roots.clone();
                            let server_name = server_name.clone();
                            let handler_timeout_counts = handler_timeout_counts.clone();
                            in_flight.spawn(async move {
                                const JSONRPC_SERVER_ERROR: i64 = -32000;

                                let method = req.method.clone();
                                let ctx = ServerRequestContext {
                                    server_name: server_name.clone(),
                                    method: method.clone(),
                                    params: req.params.clone(),
                                };

                                let mut handler_task = tokio::spawn(handler(ctx));
                                let _abort_on_drop = AbortOnDrop(handler_task.abort_handle());
                                let mut outcome = match handler_timeout {
                                    Some(timeout) => match tokio::time::timeout(timeout, &mut handler_task).await {
                                        Ok(joined) => match joined {
                                            Ok(outcome) => outcome,
                                            Err(err) if err.is_panic() => {
                                                ServerRequestOutcome::Error {
                                                    code: JSONRPC_SERVER_ERROR,
                                                    message: format!(
                                                        "server request handler panicked: {method}"
                                                    ),
                                                    data: None,
                                                }
                                            }
                                            Err(_) => ServerRequestOutcome::Error {
                                                code: JSONRPC_SERVER_ERROR,
                                                message: format!(
                                                    "server request handler cancelled: {method}"
                                                ),
                                                data: None,
                                            },
                                        },
                                        Err(_) => {
                                            handler_task.abort();
                                            {
                                                let mut counts = handler_timeout_counts
                                                    .lock()
                                                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                                                *counts.entry(server_name.clone()).or_insert(0) += 1;
                                            }
                                            ServerRequestOutcome::Error {
                                                code: JSONRPC_SERVER_ERROR,
                                                message: format!(
                                                    "server request handler timed out after {timeout:?}: {method}"
                                                ),
                                                data: None,
                                            }
                                        }
                                    },
                                    None => match handler_task.await {
                                        Ok(outcome) => outcome,
                                        Err(err) if err.is_panic() => {
                                            ServerRequestOutcome::Error {
                                                code: JSONRPC_SERVER_ERROR,
                                                message: format!(
                                                    "server request handler panicked: {method}"
                                                ),
                                                data: None,
                                            }
                                        }
                                        Err(_) => ServerRequestOutcome::Error {
                                            code: JSONRPC_SERVER_ERROR,
                                            message: format!(
                                                "server request handler cancelled: {method}"
                                            ),
                                            data: None,
                                        },
                                    },
                                };

                                if matches!(outcome, ServerRequestOutcome::MethodNotFound) {
                                    if let Some(result) =
                                        try_handle_built_in_request(&method, roots.as_ref())
                                    {
                                        outcome = ServerRequestOutcome::Ok(result);
                                    }
                                }

                                match outcome {
                                    ServerRequestOutcome::Ok(result) => {
                                        let _ = req.respond_ok(result).await;
                                    }
                                    ServerRequestOutcome::Error { code, message, data } => {
                                        let _ = req.respond_error(code, message, data).await;
                                    }
                                    ServerRequestOutcome::MethodNotFound => {
                                        let _ = req
                                            .respond_error(
                                                JSONRPC_METHOD_NOT_FOUND,
                                                format!("method not found: {}", method.as_str()),
                                                None,
                                            )
                                            .await;
                                    }
                                }
                            });
                        }
                        Some(outcome) = in_flight.join_next(), if !in_flight.is_empty() => {
                            match outcome {
                                Ok(()) => {}
                                Err(err) if err.is_panic() => return,
                                Err(_) => {}
                            }
                        }
                        else => break,
                    }
                }

                while let Some(outcome) = in_flight.join_next().await {
                    match outcome {
                        Ok(()) => {}
                        Err(err) if err.is_panic() => return,
                        Err(_) => {}
                    }
                }
            }));
        }

        if let Some(mut notifications_rx) = client.take_notifications() {
            let handler = self.server_notification_handler.clone();
            let server_name = server_name.clone();
            let handler_timeout_counts = handler_timeout_counts.clone();
            tasks.push(tokio::spawn(async move {
                let mut in_flight = tokio::task::JoinSet::new();

                loop {
                    tokio::select! {
                        Some(note) = notifications_rx.recv(), if in_flight.len() < handler_concurrency => {
                            let handler = handler.clone();
                            let server_name = server_name.clone();
                            let handler_timeout_counts = handler_timeout_counts.clone();
                            in_flight.spawn(async move {
                                let ctx = ServerNotificationContext {
                                    server_name: server_name.clone(),
                                    method: note.method,
                                    params: note.params,
                                };

                                let mut handler_task = tokio::spawn(handler(ctx));
                                let _abort_on_drop = AbortOnDrop(handler_task.abort_handle());
                                match handler_timeout {
                                    Some(timeout) => match tokio::time::timeout(timeout, &mut handler_task).await {
                                        Ok(joined) => match joined {
                                            Ok(()) => {}
                                            Err(err) if err.is_panic() => {}
                                            Err(_) => {}
                                        },
                                        Err(_) => {
                                            handler_task.abort();
                                            let mut counts = handler_timeout_counts
                                                .lock()
                                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                                            *counts.entry(server_name).or_insert(0) += 1;
                                        }
                                    },
                                    None => match handler_task.await {
                                        Ok(()) => {}
                                        Err(err) if err.is_panic() => {}
                                        Err(_) => {}
                                    },
                                }
                            });
                        }
                        Some(outcome) = in_flight.join_next(), if !in_flight.is_empty() => {
                            match outcome {
                                Ok(()) => {}
                                Err(err) if err.is_panic() => return,
                                Err(_) => {}
                            }
                        }
                        else => break,
                    }
                }

                while let Some(outcome) = in_flight.join_next().await {
                    match outcome {
                        Ok(()) => {}
                        Err(err) if err.is_panic() => return,
                        Err(_) => {}
                    }
                }
            }));
        }

        tasks
    }

    pub async fn get_or_connect(
        &mut self,
        config: &Config,
        server_name: &str,
        cwd: &Path,
    ) -> anyhow::Result<()> {
        let server_cfg = config
            .server(server_name)
            .ok_or_else(|| anyhow::anyhow!("unknown mcp server: {server_name}"))?;
        self.connect(server_name, server_cfg, cwd).await
    }

    pub async fn get_or_connect_named(
        &mut self,
        config: &Config,
        server_name: &ServerName,
        cwd: &Path,
    ) -> anyhow::Result<()> {
        let server_cfg = config
            .server_named(server_name)
            .ok_or_else(|| anyhow::anyhow!("unknown mcp server: {server_name}"))?;
        self.connect_named(server_name, server_cfg, cwd).await
    }

    pub async fn get_or_connect_session(
        &mut self,
        config: &Config,
        server_name: &str,
        cwd: &Path,
    ) -> anyhow::Result<Session> {
        self.get_or_connect(config, server_name, cwd).await?;
        self.take_session(server_name)
            .ok_or_else(|| anyhow::anyhow!("mcp server not connected: {server_name}"))
    }

    pub async fn get_or_connect_session_named(
        &mut self,
        config: &Config,
        server_name: &ServerName,
        cwd: &Path,
    ) -> anyhow::Result<Session> {
        self.get_or_connect_named(config, server_name, cwd).await?;
        self.take_session_named(server_name)
            .ok_or_else(|| anyhow::anyhow!("mcp server not connected: {server_name}"))
    }

    pub async fn connect_named(
        &mut self,
        server_name: &ServerName,
        server_cfg: &ServerConfig,
        cwd: &Path,
    ) -> anyhow::Result<()> {
        let server_name_key = server_name.clone();
        self.connect_with_builder(server_name.as_str(), server_cfg, cwd, || {
            Ok(server_name_key)
        })
        .await
    }

    /// Remove a cached connection (if any) without waiting for shutdown.
    ///
    /// This is best-effort and may leave a child process running/zombied if you drop it without
    /// an explicit `wait*` call. Prefer `Manager::disconnect_and_wait` (or `take_connection` +
    /// `Connection::wait_with_timeout`) when you own the lifecycle.
    pub fn disconnect(&mut self, server_name: &str) -> bool {
        self.init_results.remove(server_name);
        self.conns.remove(server_name).is_some()
    }

    pub fn disconnect_named(&mut self, server_name: &ServerName) -> bool {
        self.disconnect(server_name.as_str())
    }

    pub async fn disconnect_and_wait(
        &mut self,
        server_name: &str,
        timeout: Duration,
        on_timeout: mcp_jsonrpc::WaitOnTimeout,
    ) -> anyhow::Result<Option<std::process::ExitStatus>> {
        let Some(conn) = self.take_connection(server_name) else {
            return Ok(None);
        };

        conn.wait_with_timeout(timeout, on_timeout)
            .await
            .with_context(|| format!("disconnect mcp server: {server_name}"))
    }

    pub async fn disconnect_and_wait_named(
        &mut self,
        server_name: &ServerName,
        timeout: Duration,
        on_timeout: mcp_jsonrpc::WaitOnTimeout,
    ) -> anyhow::Result<Option<std::process::ExitStatus>> {
        self.disconnect_and_wait(server_name.as_str(), timeout, on_timeout)
            .await
    }

    /// Take ownership of a cached connection (if any).
    ///
    /// After calling this, the caller owns the connection lifecycle. In particular, if the
    /// connection was created via `transport=stdio`, prefer an explicit `Connection::wait*` call
    /// to avoid leaving a child process running/zombied.
    pub fn take_connection(&mut self, server_name: &str) -> Option<Connection> {
        self.init_results.remove(server_name);
        self.conns.remove(server_name)
    }

    pub fn take_connection_named(&mut self, server_name: &ServerName) -> Option<Connection> {
        self.take_connection(server_name.as_str())
    }

    /// Take ownership of a cached session (if any).
    ///
    /// After calling this, the caller owns the session lifecycle. Prefer calling
    /// `Session::wait_with_timeout` (or converting into a `Connection` and calling `wait*`) to
    /// ensure any associated stdio child process is reaped.
    pub fn take_session(&mut self, server_name: &str) -> Option<Session> {
        let Some((server_name, connection)) = self.conns.remove_entry(server_name) else {
            self.init_results.remove(server_name);
            return None;
        };
        let initialize_result = self.init_results.remove(&server_name)?;
        Some(Session::new(
            server_name,
            connection,
            initialize_result,
            self.request_timeout,
        ))
    }

    pub fn take_session_named(&mut self, server_name: &ServerName) -> Option<Session> {
        self.take_session(server_name.as_str())
    }

    pub async fn connect_session(
        &mut self,
        server_name: &str,
        server_cfg: &ServerConfig,
        cwd: &Path,
    ) -> anyhow::Result<Session> {
        self.connect(server_name, server_cfg, cwd).await?;
        self.take_session(server_name)
            .ok_or_else(|| anyhow::anyhow!("mcp server not connected: {server_name}"))
    }

    pub async fn connect_session_named(
        &mut self,
        server_name: &ServerName,
        server_cfg: &ServerConfig,
        cwd: &Path,
    ) -> anyhow::Result<Session> {
        self.connect_named(server_name, server_cfg, cwd).await?;
        self.take_session_named(server_name)
            .ok_or_else(|| anyhow::anyhow!("mcp server not connected: {server_name}"))
    }

    pub async fn connect_jsonrpc_session(
        &mut self,
        server_name: &str,
        client: mcp_jsonrpc::Client,
    ) -> anyhow::Result<Session> {
        self.connect_jsonrpc(server_name, client).await?;
        self.take_session(server_name)
            .ok_or_else(|| anyhow::anyhow!("mcp server not connected: {server_name}"))
    }

    pub async fn connect_jsonrpc_session_named(
        &mut self,
        server_name: &ServerName,
        client: mcp_jsonrpc::Client,
    ) -> anyhow::Result<Session> {
        self.connect_jsonrpc(server_name.as_str(), client).await?;
        self.take_session_named(server_name)
            .ok_or_else(|| anyhow::anyhow!("mcp server not connected: {server_name}"))
    }

    pub async fn connect_io_session<R, W>(
        &mut self,
        server_name: &str,
        read: R,
        write: W,
    ) -> anyhow::Result<Session>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        self.connect_io(server_name, read, write).await?;
        self.take_session(server_name)
            .ok_or_else(|| anyhow::anyhow!("mcp server not connected: {server_name}"))
    }

    pub async fn connect_io_session_named<R, W>(
        &mut self,
        server_name: &ServerName,
        read: R,
        write: W,
    ) -> anyhow::Result<Session>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        self.connect_io(server_name.as_str(), read, write).await?;
        self.take_session_named(server_name)
            .ok_or_else(|| anyhow::anyhow!("mcp server not connected: {server_name}"))
    }

    pub async fn request(
        &mut self,
        config: &Config,
        server_name: &str,
        method: &str,
        params: Option<Value>,
        cwd: &Path,
    ) -> anyhow::Result<Value> {
        self.get_or_connect(config, server_name, cwd).await?;
        let result = self.request_connected(server_name, method, params).await;
        if let Err(err) = &result {
            if should_disconnect_after_jsonrpc_error(err) {
                self.disconnect(server_name);
            }
        }
        result
    }

    pub async fn request_named(
        &mut self,
        config: &Config,
        server_name: &ServerName,
        method: &str,
        params: Option<Value>,
        cwd: &Path,
    ) -> anyhow::Result<Value> {
        self.request(config, server_name.as_str(), method, params, cwd)
            .await
    }

    pub async fn request_server(
        &mut self,
        server_name: &str,
        server_cfg: &ServerConfig,
        method: &str,
        params: Option<Value>,
        cwd: &Path,
    ) -> anyhow::Result<Value> {
        self.connect(server_name, server_cfg, cwd).await?;
        let result = self.request_connected(server_name, method, params).await;
        if let Err(err) = &result {
            if should_disconnect_after_jsonrpc_error(err) {
                self.disconnect(server_name);
            }
        }
        result
    }

    pub async fn request_typed<R: McpRequest>(
        &mut self,
        config: &Config,
        server_name: &str,
        params: Option<R::Params>,
        cwd: &Path,
    ) -> anyhow::Result<R::Result> {
        let params = match params {
            Some(params) => Some(serde_json::to_value(params).with_context(|| {
                format!("serialize MCP params: {} (server={server_name})", R::METHOD)
            })?),
            None => None,
        };
        let result = self
            .request(config, server_name, R::METHOD, params, cwd)
            .await?;
        serde_json::from_value(result).with_context(|| {
            format!(
                "deserialize MCP result: {} (server={server_name})",
                R::METHOD
            )
        })
    }

    pub async fn request_typed_connected<R: McpRequest>(
        &mut self,
        server_name: &str,
        params: Option<R::Params>,
    ) -> anyhow::Result<R::Result> {
        let params = match params {
            Some(params) => Some(serde_json::to_value(params).with_context(|| {
                format!("serialize MCP params: {} (server={server_name})", R::METHOD)
            })?),
            None => None,
        };
        let result = self
            .request_connected(server_name, R::METHOD, params)
            .await?;
        serde_json::from_value(result).with_context(|| {
            format!(
                "deserialize MCP result: {} (server={server_name})",
                R::METHOD
            )
        })
    }

    pub async fn notify(
        &mut self,
        config: &Config,
        server_name: &str,
        method: &str,
        params: Option<Value>,
        cwd: &Path,
    ) -> anyhow::Result<()> {
        self.get_or_connect(config, server_name, cwd).await?;
        let result = self.notify_connected(server_name, method, params).await;
        if let Err(err) = &result {
            if should_disconnect_after_jsonrpc_error(err) {
                self.disconnect(server_name);
            }
        }
        result
    }

    pub async fn notify_server(
        &mut self,
        server_name: &str,
        server_cfg: &ServerConfig,
        method: &str,
        params: Option<Value>,
        cwd: &Path,
    ) -> anyhow::Result<()> {
        self.connect(server_name, server_cfg, cwd).await?;
        let result = self.notify_connected(server_name, method, params).await;
        if let Err(err) = &result {
            if should_disconnect_after_jsonrpc_error(err) {
                self.disconnect(server_name);
            }
        }
        result
    }

    pub async fn notify_typed<N: McpNotification>(
        &mut self,
        config: &Config,
        server_name: &str,
        params: Option<N::Params>,
        cwd: &Path,
    ) -> anyhow::Result<()> {
        let params = match params {
            Some(params) => Some(serde_json::to_value(params).with_context(|| {
                format!("serialize MCP params: {} (server={server_name})", N::METHOD)
            })?),
            None => None,
        };
        self.notify(config, server_name, N::METHOD, params, cwd)
            .await
    }

    pub async fn notify_typed_connected<N: McpNotification>(
        &mut self,
        server_name: &str,
        params: Option<N::Params>,
    ) -> anyhow::Result<()> {
        let params = match params {
            Some(params) => Some(serde_json::to_value(params).with_context(|| {
                format!("serialize MCP params: {} (server={server_name})", N::METHOD)
            })?),
            None => None,
        };
        self.notify_connected(server_name, N::METHOD, params).await
    }

    pub async fn list_tools(
        &mut self,
        config: &Config,
        server_name: &str,
        cwd: &Path,
    ) -> anyhow::Result<Value> {
        self.request(config, server_name, "tools/list", None, cwd)
            .await
    }

    pub async fn list_resources(
        &mut self,
        config: &Config,
        server_name: &str,
        cwd: &Path,
    ) -> anyhow::Result<Value> {
        self.request(config, server_name, "resources/list", None, cwd)
            .await
    }

    pub async fn list_resource_templates(
        &mut self,
        config: &Config,
        server_name: &str,
        cwd: &Path,
    ) -> anyhow::Result<Value> {
        self.request(config, server_name, "resources/templates/list", None, cwd)
            .await
    }

    pub async fn read_resource(
        &mut self,
        config: &Config,
        server_name: &str,
        uri: &str,
        cwd: &Path,
    ) -> anyhow::Result<Value> {
        let params = serde_json::json!({ "uri": uri });
        self.request(config, server_name, "resources/read", Some(params), cwd)
            .await
    }

    pub async fn subscribe_resource(
        &mut self,
        config: &Config,
        server_name: &str,
        uri: &str,
        cwd: &Path,
    ) -> anyhow::Result<Value> {
        let params = serde_json::json!({ "uri": uri });
        self.request(
            config,
            server_name,
            "resources/subscribe",
            Some(params),
            cwd,
        )
        .await
    }

    pub async fn unsubscribe_resource(
        &mut self,
        config: &Config,
        server_name: &str,
        uri: &str,
        cwd: &Path,
    ) -> anyhow::Result<Value> {
        let params = serde_json::json!({ "uri": uri });
        self.request(
            config,
            server_name,
            "resources/unsubscribe",
            Some(params),
            cwd,
        )
        .await
    }

    pub async fn list_prompts(
        &mut self,
        config: &Config,
        server_name: &str,
        cwd: &Path,
    ) -> anyhow::Result<Value> {
        self.request(config, server_name, "prompts/list", None, cwd)
            .await
    }

    pub async fn get_prompt(
        &mut self,
        config: &Config,
        server_name: &str,
        prompt: &str,
        arguments: Option<Value>,
        cwd: &Path,
    ) -> anyhow::Result<Value> {
        let mut params = serde_json::json!({ "name": prompt });
        if let Some(arguments) = arguments {
            params["arguments"] = arguments;
        }
        self.request(config, server_name, "prompts/get", Some(params), cwd)
            .await
    }

    pub async fn call_tool(
        &mut self,
        config: &Config,
        server_name: &str,
        tool: &str,
        arguments: Option<Value>,
        cwd: &Path,
    ) -> anyhow::Result<Value> {
        let mut params = serde_json::json!({ "name": tool });
        if let Some(arguments) = arguments {
            params["arguments"] = arguments;
        }
        self.request(config, server_name, "tools/call", Some(params), cwd)
            .await
    }

    pub async fn ping(
        &mut self,
        config: &Config,
        server_name: &str,
        cwd: &Path,
    ) -> anyhow::Result<Value> {
        self.request(config, server_name, "ping", None, cwd).await
    }

    pub async fn set_logging_level(
        &mut self,
        config: &Config,
        server_name: &str,
        level: &str,
        cwd: &Path,
    ) -> anyhow::Result<Value> {
        let params = serde_json::json!({ "level": level });
        self.request(config, server_name, "logging/setLevel", Some(params), cwd)
            .await
    }

    pub async fn complete(
        &mut self,
        config: &Config,
        server_name: &str,
        params: Value,
        cwd: &Path,
    ) -> anyhow::Result<Value> {
        self.request(
            config,
            server_name,
            "completion/complete",
            Some(params),
            cwd,
        )
        .await
    }

    pub async fn list_tools_connected(&mut self, server_name: &str) -> anyhow::Result<Value> {
        self.request_connected(server_name, "tools/list", None)
            .await
    }

    pub async fn list_resources_connected(&mut self, server_name: &str) -> anyhow::Result<Value> {
        self.request_connected(server_name, "resources/list", None)
            .await
    }

    pub async fn list_resource_templates_connected(
        &mut self,
        server_name: &str,
    ) -> anyhow::Result<Value> {
        self.request_connected(server_name, "resources/templates/list", None)
            .await
    }

    pub async fn read_resource_connected(
        &mut self,
        server_name: &str,
        uri: &str,
    ) -> anyhow::Result<Value> {
        let params = serde_json::json!({ "uri": uri });
        self.request_connected(server_name, "resources/read", Some(params))
            .await
    }

    pub async fn subscribe_resource_connected(
        &mut self,
        server_name: &str,
        uri: &str,
    ) -> anyhow::Result<Value> {
        let params = serde_json::json!({ "uri": uri });
        self.request_connected(server_name, "resources/subscribe", Some(params))
            .await
    }

    pub async fn unsubscribe_resource_connected(
        &mut self,
        server_name: &str,
        uri: &str,
    ) -> anyhow::Result<Value> {
        let params = serde_json::json!({ "uri": uri });
        self.request_connected(server_name, "resources/unsubscribe", Some(params))
            .await
    }

    pub async fn list_prompts_connected(&mut self, server_name: &str) -> anyhow::Result<Value> {
        self.request_connected(server_name, "prompts/list", None)
            .await
    }

    pub async fn get_prompt_connected(
        &mut self,
        server_name: &str,
        prompt: &str,
        arguments: Option<Value>,
    ) -> anyhow::Result<Value> {
        let mut params = serde_json::json!({ "name": prompt });
        if let Some(arguments) = arguments {
            params["arguments"] = arguments;
        }
        self.request_connected(server_name, "prompts/get", Some(params))
            .await
    }

    pub async fn ping_connected(&mut self, server_name: &str) -> anyhow::Result<Value> {
        self.request_connected(server_name, "ping", None).await
    }

    pub async fn set_logging_level_connected(
        &mut self,
        server_name: &str,
        level: &str,
    ) -> anyhow::Result<Value> {
        let params = serde_json::json!({ "level": level });
        self.request_connected(server_name, "logging/setLevel", Some(params))
            .await
    }

    pub async fn complete_connected(
        &mut self,
        server_name: &str,
        params: Value,
    ) -> anyhow::Result<Value> {
        self.request_connected(server_name, "completion/complete", Some(params))
            .await
    }

    pub async fn request_connected(
        &mut self,
        server_name: &str,
        method: &str,
        params: Option<Value>,
    ) -> anyhow::Result<Value> {
        if !self.is_connected_and_alive(server_name) {
            anyhow::bail!("mcp server not connected: {server_name}");
        }

        let timeout = self.request_timeout;
        let result = {
            let conn = self
                .conns
                .get(server_name)
                .ok_or_else(|| anyhow::anyhow!("mcp server not connected: {server_name}"))?;
            Self::request_raw(timeout, server_name, &conn.client, method, params).await
        };

        if let Err(err) = &result {
            if should_disconnect_after_jsonrpc_error(err) {
                self.disconnect(server_name);
            }
        }

        result
    }

    pub async fn request_connected_named(
        &mut self,
        server_name: &ServerName,
        method: &str,
        params: Option<Value>,
    ) -> anyhow::Result<Value> {
        self.request_connected(server_name.as_str(), method, params)
            .await
    }

    pub async fn notify_connected(
        &mut self,
        server_name: &str,
        method: &str,
        params: Option<Value>,
    ) -> anyhow::Result<()> {
        if !self.is_connected_and_alive(server_name) {
            anyhow::bail!("mcp server not connected: {server_name}");
        }

        let timeout = self.request_timeout;
        let result = {
            let conn = self
                .conns
                .get(server_name)
                .ok_or_else(|| anyhow::anyhow!("mcp server not connected: {server_name}"))?;
            Self::notify_raw(timeout, server_name, &conn.client, method, params).await
        };

        if let Err(err) = &result {
            if should_disconnect_after_jsonrpc_error(err) {
                self.disconnect(server_name);
            }
        }

        result
    }

    pub async fn notify_connected_named(
        &mut self,
        server_name: &ServerName,
        method: &str,
        params: Option<Value>,
    ) -> anyhow::Result<()> {
        self.notify_connected(server_name.as_str(), method, params)
            .await
    }

    async fn initialize(
        &mut self,
        server_name: &ServerName,
        client: &mcp_jsonrpc::Client,
    ) -> anyhow::Result<Value> {
        if self.protocol_version.trim().is_empty() {
            anyhow::bail!("mcp protocol version must not be empty");
        }
        if !self.capabilities.is_object() {
            anyhow::bail!("mcp client capabilities must be a JSON object");
        }

        let initialize_params = serde_json::json!({
            "protocolVersion": &self.protocol_version,
            "clientInfo": {
                "name": &self.client_name,
                "version": &self.client_version,
            },
            "capabilities": &self.capabilities,
        });

        let timeout = self.request_timeout;
        let outcome =
            tokio::time::timeout(timeout, client.request("initialize", initialize_params)).await;
        let result = outcome
            .with_context(|| {
                format!(
                    "mcp initialize timed out after {timeout:?} (server={})",
                    server_name.as_str()
                )
            })?
            .with_context(|| format!("mcp initialize failed (server={})", server_name.as_str()))?;

        if let Some(server_protocol_version) =
            result.get("protocolVersion").and_then(|v| v.as_str())
        {
            if server_protocol_version != self.protocol_version {
                match self.protocol_version_check {
                    ProtocolVersionCheck::Strict => {
                        anyhow::bail!(
                            "mcp initialize protocolVersion mismatch (server={}): client={}, server={}",
                            server_name.as_str(),
                            self.protocol_version,
                            server_protocol_version
                        );
                    }
                    ProtocolVersionCheck::Warn => {
                        let mismatch = ProtocolVersionMismatch {
                            server_name: server_name.clone(),
                            client_protocol_version: self.protocol_version.clone(),
                            server_protocol_version: server_protocol_version.to_string(),
                        };

                        if let Some(existing) = self
                            .protocol_version_mismatches
                            .iter_mut()
                            .find(|m| m.server_name == *server_name)
                        {
                            *existing = mismatch;
                        } else {
                            self.protocol_version_mismatches.push(mismatch);
                        }
                    }
                    ProtocolVersionCheck::Ignore => {}
                }
            }
        }

        Self::notify_raw(
            timeout,
            server_name.as_str(),
            client,
            "notifications/initialized",
            None,
        )
        .await
        .with_context(|| {
            format!(
                "mcp initialized notification failed (server={})",
                server_name.as_str()
            )
        })?;
        Ok(result)
    }

    async fn request_raw(
        timeout: Duration,
        server_name: &str,
        client: &mcp_jsonrpc::Client,
        method: &str,
        params: Option<Value>,
    ) -> anyhow::Result<Value> {
        let outcome = tokio::time::timeout(timeout, client.request_optional(method, params)).await;
        outcome
            .with_context(|| {
                format!("mcp request timed out after {timeout:?}: {method} (server={server_name})")
            })?
            .with_context(|| format!("mcp request failed: {method} (server={server_name})"))
    }

    async fn notify_raw(
        timeout: Duration,
        server_name: &str,
        client: &mcp_jsonrpc::Client,
        method: &str,
        params: Option<Value>,
    ) -> anyhow::Result<()> {
        let outcome = tokio::time::timeout(timeout, client.notify(method, params)).await;
        outcome
            .with_context(|| {
                format!(
                    "mcp notification timed out after {timeout:?}: {method} (server={server_name})"
                )
            })?
            .with_context(|| format!("mcp notification failed: {method} (server={server_name})"))
    }
}

fn ensure_roots_capability(capabilities: &mut Value) {
    let Value::Object(map) = capabilities else {
        return;
    };
    match map.get_mut("roots") {
        Some(Value::Object(_)) => {}
        _ => {
            map.insert("roots".to_string(), Value::Object(serde_json::Map::new()));
        }
    }
}

fn try_handle_built_in_request(method: &str, roots: Option<&Arc<Vec<Root>>>) -> Option<Value> {
    match method {
        "roots/list" => {
            let roots = roots?;
            Some(serde_json::json!({ "roots": roots.as_ref() }))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests;
