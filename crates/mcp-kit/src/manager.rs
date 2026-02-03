use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::process::{Child, Command};

use crate::{
    Config, MCP_PROTOCOL_VERSION, McpNotification, McpRequest, Root, ServerConfig, Session,
    Transport, TrustMode, UntrustedStreamableHttpPolicy,
};

pub type ServerName = String;

const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;
const STDIO_BASELINE_ENV_VARS: [&str; 8] = [
    "PATH",
    "HOME",
    "USERPROFILE",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SystemRoot",
    "SYSTEMROOT",
];

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

fn apply_stdio_baseline_env(cmd: &mut Command) {
    for key in STDIO_BASELINE_ENV_VARS {
        if let Some(value) = std::env::var_os(key) {
            cmd.env(key, value);
        }
    }
}

fn is_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn expand_placeholders_trusted(template: &str, cwd: &Path) -> anyhow::Result<String> {
    if !template.contains("${") {
        return Ok(template.to_string());
    }

    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| anyhow::anyhow!("unterminated placeholder (missing `}}`)"))?;
        let name = &after[..end];
        if !is_env_var_name(name) {
            anyhow::bail!("invalid placeholder name: {name}");
        }
        let value = match name {
            "CLAUDE_PLUGIN_ROOT" | "MCP_ROOT" => cwd.display().to_string(),
            _ => std::env::var(name).with_context(|| format!("read env var: {name}"))?,
        };
        out.push_str(&value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
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

pub struct Manager {
    conns: HashMap<ServerName, Connection>,
    init_results: HashMap<ServerName, Value>,
    client_name: String,
    client_version: String,
    protocol_version: String,
    capabilities: Value,
    roots: Option<Arc<Vec<Root>>>,
    trust_mode: TrustMode,
    untrusted_streamable_http_policy: UntrustedStreamableHttpPolicy,
    allow_stdout_log_outside_root: bool,
    request_timeout: Duration,
    server_request_handler: ServerRequestHandler,
    server_notification_handler: ServerNotificationHandler,
}

pub struct Connection {
    pub child: Option<Child>,
    pub client: mcp_jsonrpc::Client,
}

impl Connection {
    /// Closes the JSON-RPC client and (if present) waits for the underlying child process to exit.
    ///
    /// Note: this can hang indefinitely if the child process does not exit. Prefer
    /// `Connection::wait_with_timeout` if you need an upper bound.
    pub async fn wait(mut self) -> anyhow::Result<Option<std::process::ExitStatus>> {
        let status = self.client.wait().await.context("close jsonrpc client")?;
        if status.is_some() {
            return Ok(status);
        }

        match &mut self.child {
            Some(child) => Ok(Some(child.wait().await?)),
            None => Ok(None),
        }
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
        if status.is_some() {
            return Ok(status);
        }

        let Some(child) = &mut self.child else {
            return Ok(None);
        };

        match tokio::time::timeout(timeout, child.wait()).await {
            Ok(status) => Ok(Some(status?)),
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
                        Ok(status) => Ok(Some(status?)),
                        Err(_) => anyhow::bail!(
                            "wait timed out after {timeout:?}; killed child (id={child_id:?}) but it did not exit within {kill_timeout:?}"
                        ),
                    }
                }
            },
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
        if let Some(protocol_version) = config.client.protocol_version.clone() {
            manager = manager.with_protocol_version(protocol_version);
        }
        if let Some(capabilities) = config.client.capabilities.clone() {
            manager = manager.with_capabilities(capabilities);
        }
        if let Some(roots) = config.client.roots.clone() {
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
            capabilities: Value::Object(serde_json::Map::new()),
            roots: None,
            trust_mode: TrustMode::Untrusted,
            untrusted_streamable_http_policy: UntrustedStreamableHttpPolicy::default(),
            allow_stdout_log_outside_root: false,
            request_timeout: timeout,
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

    pub fn is_connected(&mut self, server_name: &str) -> bool {
        self.is_connected_and_alive(server_name)
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

    pub async fn connect(
        &mut self,
        server_name: &str,
        server_cfg: &ServerConfig,
        cwd: &Path,
    ) -> anyhow::Result<()> {
        if self.is_connected_and_alive(server_name) {
            return Ok(());
        }

        let (client, child) = match server_cfg.transport {
            Transport::Stdio => {
                if self.trust_mode == TrustMode::Untrusted {
                    anyhow::bail!(
                        "refusing to spawn mcp server in untrusted mode: {server_name} (set Manager::with_trust_mode(TrustMode::Trusted) to override)"
                    );
                }
                if server_cfg.argv.is_empty() {
                    anyhow::bail!("mcp server argv must not be empty");
                }

                let expanded_argv = server_cfg
                    .argv
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
                if !server_cfg.inherit_env {
                    cmd.env_clear();
                    apply_stdio_baseline_env(&mut cmd);
                }
                for (key, value) in server_cfg.env.iter() {
                    let value = expand_placeholders_trusted(value, cwd)
                        .with_context(|| format!("expand env placeholder: {key}"))?;
                    cmd.env(key, value);
                }
                cmd.kill_on_drop(true);

                let stdout_log = server_cfg.stdout_log.as_ref().map(|log| {
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
                        server_cfg.argv.len()
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
                    .unix_path
                    .as_ref()
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
                    server_cfg.url.as_deref(),
                    server_cfg.sse_url.as_deref(),
                    server_cfg.http_url.as_deref(),
                ) {
                    (Some(url), None, None) => (url, url),
                    (None, Some(sse_url), Some(http_url)) => (sse_url, http_url),
                    _ => {
                        anyhow::bail!(
                            "mcp server {server_name}: set url or (sse_url + http_url) for transport=streamable_http"
                        )
                    }
                };

                let (sse_url_field, post_url_field) = if server_cfg.url.is_some() {
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
                    .http_headers
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

                if let Some(env_var) = server_cfg.bearer_token_env_var.as_deref() {
                    if self.trust_mode == TrustMode::Untrusted {
                        anyhow::bail!(
                            "refusing to read bearer token env var in untrusted mode: {server_name} (set Manager::with_trust_mode(TrustMode::Trusted) to override)"
                        );
                    }
                    let token = std::env::var(env_var)
                        .with_context(|| format!("read bearer token env var: {env_var}"))?;
                    headers.insert("Authorization".to_string(), format!("Bearer {token}"));
                }

                if !server_cfg.env_http_headers.is_empty() {
                    if self.trust_mode == TrustMode::Untrusted {
                        anyhow::bail!(
                            "refusing to read http header env vars in untrusted mode: {server_name} (set Manager::with_trust_mode(TrustMode::Trusted) to override)"
                        );
                    }

                    for (header, env_var) in server_cfg.env_http_headers.iter() {
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

        self.install_connection(server_name, client, child).await?;
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
        mut client: mcp_jsonrpc::Client,
    ) -> anyhow::Result<()> {
        if self.is_connected_and_alive(server_name) {
            return Ok(());
        }

        let child = client.take_child();
        self.install_connection(server_name, client, child).await?;
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
        Some(match &mut conn.child {
            Some(child) => {
                if child.try_wait().ok().flatten().is_some() {
                    true
                } else {
                    conn.client.handle().is_closed()
                }
            }
            None => conn.client.handle().is_closed(),
        })
    }

    async fn install_connection(
        &mut self,
        server_name: &str,
        mut client: mcp_jsonrpc::Client,
        child: Option<Child>,
    ) -> anyhow::Result<()> {
        self.attach_client_handlers(server_name, &mut client);
        let init_result = self.initialize(server_name, &client).await?;

        self.init_results
            .insert(server_name.to_string(), init_result);
        self.conns
            .insert(server_name.to_string(), Connection { child, client });
        Ok(())
    }

    fn attach_client_handlers(&self, server_name: &str, client: &mut mcp_jsonrpc::Client) {
        if let Some(mut requests_rx) = client.take_requests() {
            let handler = self.server_request_handler.clone();
            let roots = self.roots.clone();
            let server_name = server_name.to_string();
            tokio::spawn(async move {
                while let Some(req) = requests_rx.recv().await {
                    let ctx = ServerRequestContext {
                        server_name: server_name.clone(),
                        method: req.method.clone(),
                        params: req.params.clone(),
                    };

                    let mut outcome = handler(ctx).await;
                    if matches!(outcome, ServerRequestOutcome::MethodNotFound) {
                        if let Some(result) =
                            try_handle_built_in_request(&req.method, roots.as_ref())
                        {
                            outcome = ServerRequestOutcome::Ok(result);
                        }
                    }

                    match outcome {
                        ServerRequestOutcome::Ok(result) => {
                            let _ = req.respond_ok(result).await;
                        }
                        ServerRequestOutcome::Error {
                            code,
                            message,
                            data,
                        } => {
                            let _ = req.respond_error(code, message, data).await;
                        }
                        ServerRequestOutcome::MethodNotFound => {
                            let _ = req
                                .respond_error(
                                    JSONRPC_METHOD_NOT_FOUND,
                                    format!("method not found: {}", req.method.as_str()),
                                    None,
                                )
                                .await;
                        }
                    }
                }
            });
        }

        if let Some(mut notifications_rx) = client.take_notifications() {
            let handler = self.server_notification_handler.clone();
            let server_name = server_name.to_string();
            tokio::spawn(async move {
                while let Some(note) = notifications_rx.recv().await {
                    let ctx = ServerNotificationContext {
                        server_name: server_name.clone(),
                        method: note.method,
                        params: note.params,
                    };
                    handler(ctx).await;
                }
            });
        }
    }

    pub async fn get_or_connect(
        &mut self,
        config: &Config,
        server_name: &str,
        cwd: &Path,
    ) -> anyhow::Result<()> {
        let server_cfg = config
            .servers
            .get(server_name)
            .ok_or_else(|| anyhow::anyhow!("unknown mcp server: {server_name}"))?;
        self.connect(server_name, server_cfg, cwd).await
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

    pub fn disconnect(&mut self, server_name: &str) -> bool {
        self.init_results.remove(server_name);
        self.conns.remove(server_name).is_some()
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

    pub fn take_connection(&mut self, server_name: &str) -> Option<Connection> {
        self.init_results.remove(server_name);
        self.conns.remove(server_name)
    }

    pub fn take_session(&mut self, server_name: &str) -> Option<Session> {
        let connection = self.conns.remove(server_name)?;
        let initialize_result = self.init_results.remove(server_name).unwrap_or(Value::Null);
        Some(Session::new(
            server_name.to_string(),
            connection,
            initialize_result,
            self.request_timeout,
        ))
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

    pub async fn connect_jsonrpc_session(
        &mut self,
        server_name: &str,
        client: mcp_jsonrpc::Client,
    ) -> anyhow::Result<Session> {
        self.connect_jsonrpc(server_name, client).await?;
        self.take_session(server_name)
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

    async fn initialize(
        &self,
        server_name: &str,
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

        let outcome = tokio::time::timeout(
            self.request_timeout,
            client.request("initialize", initialize_params),
        )
        .await;
        let result = outcome
            .context("mcp initialize timed out")?
            .with_context(|| format!("mcp initialize failed (server={server_name})"))?;

        if let Some(server_protocol_version) =
            result.get("protocolVersion").and_then(|v| v.as_str())
        {
            if server_protocol_version != self.protocol_version {
                anyhow::bail!(
                    "mcp initialize protocolVersion mismatch (server={server_name}): client={}, server={}",
                    self.protocol_version,
                    server_protocol_version
                );
            }
        }

        Self::notify_raw(
            self.request_timeout,
            server_name,
            client,
            "notifications/initialized",
            None,
        )
        .await
        .with_context(|| format!("mcp initialized notification failed (server={server_name})"))?;
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
            .with_context(|| format!("mcp request timed out: {method} (server={server_name})"))?
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
                format!("mcp notification timed out: {method} (server={server_name})")
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

fn validate_streamable_http_config(
    trust_mode: TrustMode,
    policy: &UntrustedStreamableHttpPolicy,
    server_name: &str,
    url_field: &str,
    url: &str,
    server_cfg: &ServerConfig,
) -> anyhow::Result<()> {
    if trust_mode == TrustMode::Trusted {
        return Ok(());
    }

    validate_streamable_http_url_untrusted(policy, server_name, url_field, url)?;

    for header in server_cfg.http_headers.keys() {
        if is_untrusted_sensitive_http_header(header) {
            anyhow::bail!(
                "refusing to send sensitive http header in untrusted mode: {server_name} header={header} (set Manager::with_trust_mode(TrustMode::Trusted) to override)"
            );
        }
    }

    Ok(())
}

fn validate_streamable_http_url_untrusted(
    policy: &UntrustedStreamableHttpPolicy,
    server_name: &str,
    url_field: &str,
    url: &str,
) -> anyhow::Result<()> {
    let parsed = reqwest::Url::parse(url).with_context(|| {
        format!(
            "invalid streamable http url (server={server_name} field={url_field}) (url redacted)"
        )
    })?;

    if !parsed.username().is_empty() || parsed.password().is_some() {
        anyhow::bail!(
            "refusing to use url credentials in untrusted mode: {server_name} field={url_field} (set Manager::with_trust_mode(TrustMode::Trusted) to override)"
        );
    }

    match parsed.scheme() {
        "https" => {}
        "http" if !policy.require_https => {}
        _ => {
            anyhow::bail!(
                "refusing to connect non-https streamable http url in untrusted mode: {server_name} field={url_field} (set Manager::with_trust_mode(TrustMode::Trusted) to override)"
            );
        }
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("streamable http url must include a host (server={server_name} field={url_field}) (url redacted)"))?;
    let host = host.trim_end_matches('.');
    let host_for_ip = host.trim_start_matches('[').trim_end_matches(']');
    if !policy.allow_localhost {
        let host_lc = host.to_ascii_lowercase();
        let is_ip_literal = host_for_ip.parse::<IpAddr>().is_ok();
        let is_single_label = !is_ip_literal && !host_lc.contains('.');
        if host_lc == "localhost"
            || host_lc == "localhost.localdomain"
            || host_lc.ends_with(".localhost")
            || host_lc.ends_with(".local")
            || host_lc.ends_with(".localdomain")
            || is_single_label
        {
            anyhow::bail!(
                "refusing to connect localhost/local/single-label domain in untrusted mode: {server_name} host={host} (set Manager::with_trust_mode(TrustMode::Trusted) to override)"
            );
        }
    }

    if !policy.allowed_hosts.is_empty()
        && !policy
            .allowed_hosts
            .iter()
            .any(|allowed| host_matches_allowlist(host, allowed))
    {
        anyhow::bail!(
            "refusing to connect streamable http host not in allowlist in untrusted mode: {server_name} host={host} (set Manager::with_trust_mode(TrustMode::Trusted) to override)"
        );
    }

    if let Ok(ip) = host_for_ip.parse::<IpAddr>() {
        let ip = normalize_ip(ip);
        if is_untrusted_always_disallowed_ip(ip)
            || (!policy.allow_private_ips && is_untrusted_non_global_ip(ip))
        {
            anyhow::bail!(
                "refusing to connect non-global ip in untrusted mode: {server_name} host={host} (set Manager::with_trust_mode(TrustMode::Trusted) to override)"
            );
        }
    }

    Ok(())
}

async fn validate_streamable_http_url_untrusted_dns(
    policy: &UntrustedStreamableHttpPolicy,
    server_name: &str,
    url_field: &str,
    url: &str,
) -> anyhow::Result<()> {
    if !policy.dns_check || policy.allow_private_ips {
        return Ok(());
    }

    let parsed = reqwest::Url::parse(url).with_context(|| {
        format!(
            "invalid streamable http url (server={server_name} field={url_field}) (url redacted)"
        )
    })?;

    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("streamable http url must include a host (server={server_name} field={url_field}) (url redacted)"))?;
    let host = host.trim_end_matches('.');
    let host_for_ip = host.trim_start_matches('[').trim_end_matches(']');
    if host_for_ip.parse::<IpAddr>().is_ok() {
        return Ok(());
    }

    let port = parsed.port_or_known_default().ok_or_else(|| {
        anyhow::anyhow!(
            "streamable http url must include a port or known scheme (server={server_name} field={url_field}) (url redacted)"
        )
    })?;

    let addrs = match tokio::time::timeout(
        policy.dns_timeout,
        tokio::net::lookup_host((host_for_ip, port)),
    )
    .await
    {
        Ok(Ok(addrs)) => addrs,
        Ok(Err(err)) => {
            if policy.dns_fail_open {
                return Ok(());
            }
            anyhow::bail!(
                "refusing to connect hostname with failed dns lookup in untrusted mode: {server_name} host={host} err={err}"
            );
        }
        Err(_) => {
            if policy.dns_fail_open {
                return Ok(());
            }
            anyhow::bail!(
                "refusing to connect hostname with timed out dns lookup in untrusted mode: {server_name} host={host}"
            );
        }
    };

    for addr in addrs {
        let ip = normalize_ip(addr.ip());
        if is_untrusted_always_disallowed_ip(ip) || is_untrusted_non_global_ip(ip) {
            anyhow::bail!(
                "refusing to connect hostname that resolves to non-global ip in untrusted mode: {server_name} host={host} ip={ip} (set Manager::with_trust_mode(TrustMode::Trusted) or allow_private_ips to override)"
            );
        }
    }

    Ok(())
}

fn host_matches_allowlist(host: &str, allowed: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let allowed = allowed.trim().trim_end_matches('.').to_ascii_lowercase();
    if allowed.is_empty() {
        return false;
    }
    if host == allowed {
        return true;
    }
    host.strip_suffix(&allowed)
        .is_some_and(|rest| rest.ends_with('.'))
}

fn is_untrusted_sensitive_http_header(header: &str) -> bool {
    let header = header.trim().to_ascii_lowercase();
    matches!(
        header.as_str(),
        "authorization" | "proxy-authorization" | "cookie"
    )
}

fn should_disconnect_after_jsonrpc_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<mcp_jsonrpc::Error>()
            .is_some_and(|err| {
                matches!(
                    err,
                    mcp_jsonrpc::Error::Io(_) | mcp_jsonrpc::Error::Protocol(_)
                )
            })
    })
}

fn is_untrusted_always_disallowed_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_multicast() || ip.is_broadcast() || ip.is_unspecified(),
        IpAddr::V6(ip) => ip.is_multicast() || ip.is_unspecified(),
    }
}

fn is_untrusted_non_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_untrusted_non_global_ipv4(ip),
        IpAddr::V6(ip) => is_untrusted_non_global_ipv6(ip),
    }
}

fn is_untrusted_non_global_ipv4(ip: Ipv4Addr) -> bool {
    if ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_documentation()
    {
        return true;
    }

    let [a, b, c, _d] = ip.octets();

    // 0.0.0.0/8
    if a == 0 {
        return true;
    }

    // 100.64.0.0/10 (shared address space / carrier-grade NAT)
    if a == 100 && (64..=127).contains(&b) {
        return true;
    }

    // 192.0.0.0/24 (IETF Protocol Assignments)
    if a == 192 && b == 0 && c == 0 {
        return true;
    }

    // 198.18.0.0/15 (benchmarking)
    if a == 198 && (18..=19).contains(&b) {
        return true;
    }

    // 240.0.0.0/4 (reserved)
    if a >= 240 {
        return true;
    }

    false
}

fn is_untrusted_non_global_ipv6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || ip.is_multicast()
        || ip.is_unspecified()
    {
        return true;
    }

    // 2001:db8::/32 (documentation)
    let segments = ip.segments();
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return true;
    }

    false
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4().map(IpAddr::V4).unwrap_or(IpAddr::V6(ip)),
        IpAddr::V4(ip) => IpAddr::V4(ip),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    #[test]
    fn roots_capability_is_inserted() {
        let mut capabilities = serde_json::json!({});
        ensure_roots_capability(&mut capabilities);
        assert!(capabilities.get("roots").is_some());
        assert!(capabilities.get("roots").unwrap().is_object());
    }

    #[test]
    fn roots_capability_overwrites_non_object() {
        let mut capabilities = serde_json::json!({ "roots": true });
        ensure_roots_capability(&mut capabilities);
        assert!(capabilities.get("roots").unwrap().is_object());
    }

    #[test]
    fn built_in_roots_list_requires_roots() {
        assert!(try_handle_built_in_request("roots/list", None).is_none());
    }

    #[test]
    fn built_in_roots_list_returns_expected_shape() {
        let roots = Arc::new(vec![Root {
            uri: "file:///tmp".to_string(),
            name: Some("tmp".to_string()),
        }]);

        let result = try_handle_built_in_request("roots/list", Some(&roots)).expect("result");
        assert_eq!(
            result,
            serde_json::json!({
                "roots": [{ "uri": "file:///tmp", "name": "tmp" }]
            })
        );
    }

    #[test]
    fn expand_placeholders_supports_claude_plugin_root() {
        let cwd = Path::new("/tmp/plugin");
        let expanded =
            expand_placeholders_trusted("${CLAUDE_PLUGIN_ROOT}/servers/mcp", cwd).unwrap();
        assert_eq!(expanded, "/tmp/plugin/servers/mcp");
    }

    #[test]
    fn expand_placeholders_supports_env_vars() {
        let Ok(path) = std::env::var("PATH") else {
            return;
        };
        let cwd = Path::new("/tmp/plugin");
        let expanded = expand_placeholders_trusted("prefix-${PATH}-suffix", cwd).unwrap();
        assert_eq!(expanded, format!("prefix-{path}-suffix"));
    }

    #[test]
    fn expand_placeholders_rejects_invalid_name() {
        let cwd = Path::new("/tmp/plugin");
        let err = expand_placeholders_trusted("${BAD-NAME}", cwd).unwrap_err();
        assert!(err.to_string().contains("invalid placeholder name"));
    }

    #[tokio::test]
    async fn connect_io_performs_initialize_and_exposes_result() {
        let (client_stream, server_stream) = tokio::io::duplex(1024);
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (server_read, mut server_write) = tokio::io::split(server_stream);

        let server_task = tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(server_read).lines();

            let init_line = lines.next_line().await.unwrap().unwrap();
            let init_value: Value = serde_json::from_str(&init_line).unwrap();
            assert_eq!(init_value["jsonrpc"], "2.0");
            assert_eq!(init_value["method"], "initialize");
            let id = init_value["id"].clone();

            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "hello": "world" },
            });
            let mut response_line = serde_json::to_string(&response).unwrap();
            response_line.push('\n');
            server_write
                .write_all(response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let note_line = lines.next_line().await.unwrap().unwrap();
            let note_value: Value = serde_json::from_str(&note_line).unwrap();
            assert_eq!(note_value["jsonrpc"], "2.0");
            assert_eq!(note_value["method"], "notifications/initialized");
        });

        let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
            .with_trust_mode(TrustMode::Trusted);
        manager
            .connect_io("srv", client_read, client_write)
            .await
            .unwrap();

        assert!(manager.is_connected("srv"));
        assert_eq!(
            manager.initialize_result("srv").unwrap(),
            &serde_json::json!({ "hello": "world" })
        );

        server_task.await.unwrap();

        let conn = manager.take_connection("srv");
        assert!(conn.is_some());
        assert!(!manager.is_connected("srv"));
        assert!(manager.initialize_result("srv").is_none());
    }

    #[tokio::test]
    async fn request_connected_disconnects_after_protocol_error() {
        let (client_stream, server_stream) = tokio::io::duplex(1024);
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (server_read, mut server_write) = tokio::io::split(server_stream);

        let server_task = tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(server_read).lines();

            let init_line = lines.next_line().await.unwrap().unwrap();
            let init_value: Value = serde_json::from_str(&init_line).unwrap();
            assert_eq!(init_value["jsonrpc"], "2.0");
            assert_eq!(init_value["method"], "initialize");
            let init_id = init_value["id"].clone();

            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": init_id,
                "result": { "hello": "world" },
            });
            let mut response_line = serde_json::to_string(&response).unwrap();
            response_line.push('\n');
            server_write
                .write_all(response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let note_line = lines.next_line().await.unwrap().unwrap();
            let note_value: Value = serde_json::from_str(&note_line).unwrap();
            assert_eq!(note_value["jsonrpc"], "2.0");
            assert_eq!(note_value["method"], "notifications/initialized");

            let ping_line = lines.next_line().await.unwrap().unwrap();
            let ping_value: Value = serde_json::from_str(&ping_line).unwrap();
            assert_eq!(ping_value["jsonrpc"], "2.0");
            assert_eq!(ping_value["method"], "ping");
            let ping_id = ping_value["id"].clone();

            // Send an intentionally malformed JSON-RPC response (wrong jsonrpc version)
            // to trigger a protocol error without necessarily closing the transport.
            let response = serde_json::json!({
                "jsonrpc": "1.0",
                "id": ping_id,
                "result": { "ok": true },
            });
            let mut response_line = serde_json::to_string(&response).unwrap();
            response_line.push('\n');
            server_write
                .write_all(response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();
        });

        let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(1))
            .with_trust_mode(TrustMode::Trusted);
        manager
            .connect_io("srv", client_read, client_write)
            .await
            .unwrap();

        let err = manager
            .request_connected("srv", "ping", None)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("mcp request failed: ping (server=srv)")
        );

        // Connection is dropped after Protocol/Io errors to avoid keeping a stale/broken client.
        assert!(!manager.is_connected("srv"));
        assert!(manager.initialize_result("srv").is_none());

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn connect_io_session_returns_session_and_supports_requests() {
        let (client_stream, server_stream) = tokio::io::duplex(1024);
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (server_read, mut server_write) = tokio::io::split(server_stream);

        let server_task = tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(server_read).lines();

            let init_line = lines.next_line().await.unwrap().unwrap();
            let init_value: Value = serde_json::from_str(&init_line).unwrap();
            assert_eq!(init_value["jsonrpc"], "2.0");
            assert_eq!(init_value["method"], "initialize");
            let id = init_value["id"].clone();

            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "hello": "world" },
            });
            let mut response_line = serde_json::to_string(&response).unwrap();
            response_line.push('\n');
            server_write
                .write_all(response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let note_line = lines.next_line().await.unwrap().unwrap();
            let note_value: Value = serde_json::from_str(&note_line).unwrap();
            assert_eq!(note_value["jsonrpc"], "2.0");
            assert_eq!(note_value["method"], "notifications/initialized");
            assert!(note_value.get("params").is_none());

            let ping_line = lines.next_line().await.unwrap().unwrap();
            let ping_value: Value = serde_json::from_str(&ping_line).unwrap();
            assert_eq!(ping_value["jsonrpc"], "2.0");
            assert_eq!(ping_value["method"], "ping");
            assert!(ping_value.get("params").is_none());
            let ping_id = ping_value["id"].clone();

            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": ping_id,
                "result": { "ok": true },
            });
            let mut response_line = serde_json::to_string(&response).unwrap();
            response_line.push('\n');
            server_write
                .write_all(response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();
        });

        let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
            .with_trust_mode(TrustMode::Trusted);
        let session = manager
            .connect_io_session("srv", client_read, client_write)
            .await
            .unwrap();

        assert!(!manager.is_connected("srv"));
        assert_eq!(
            session.initialize_result(),
            &serde_json::json!({ "hello": "world" })
        );
        assert_eq!(
            session
                .request_typed::<crate::mcp::PingRequest>(None)
                .await
                .unwrap(),
            serde_json::json!({ "ok": true })
        );

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn connect_io_rejects_initialize_protocol_version_mismatch() {
        let (client_stream, server_stream) = tokio::io::duplex(1024);
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (server_read, mut server_write) = tokio::io::split(server_stream);

        let server_task = tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(server_read).lines();

            let init_line = lines.next_line().await.unwrap().unwrap();
            let init_value: Value = serde_json::from_str(&init_line).unwrap();
            assert_eq!(init_value["jsonrpc"], "2.0");
            assert_eq!(init_value["method"], "initialize");
            let id = init_value["id"].clone();

            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "protocolVersion": "1900-01-01" },
            });
            let mut response_line = serde_json::to_string(&response).unwrap();
            response_line.push('\n');
            server_write
                .write_all(response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();
        });

        let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
            .with_trust_mode(TrustMode::Trusted);
        let err = match manager
            .connect_io_session("srv", client_read, client_write)
            .await
        {
            Ok(_) => panic!("expected protocolVersion mismatch"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("protocolVersion mismatch"));

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn connect_io_reconnects_when_existing_connection_is_closed() {
        let (client_stream, server_stream) = tokio::io::duplex(1024);
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (server_read, mut server_write) = tokio::io::split(server_stream);

        let server_task = tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(server_read).lines();

            let init_line = lines.next_line().await.unwrap().unwrap();
            let init_value: Value = serde_json::from_str(&init_line).unwrap();
            assert_eq!(init_value["jsonrpc"], "2.0");
            assert_eq!(init_value["method"], "initialize");
            let id = init_value["id"].clone();

            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "hello": "world" },
            });
            let mut response_line = serde_json::to_string(&response).unwrap();
            response_line.push('\n');
            server_write
                .write_all(response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let note_line = lines.next_line().await.unwrap().unwrap();
            let note_value: Value = serde_json::from_str(&note_line).unwrap();
            assert_eq!(note_value["jsonrpc"], "2.0");
            assert_eq!(note_value["method"], "notifications/initialized");
        });

        let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
            .with_trust_mode(TrustMode::Trusted);
        manager
            .connect_io("srv", client_read, client_write)
            .await
            .unwrap();

        server_task.await.unwrap();

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if manager
                    .conns
                    .get("srv")
                    .expect("srv conn exists")
                    .client
                    .handle()
                    .is_closed()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("client marked closed");

        let (client_stream, server_stream) = tokio::io::duplex(1024);
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (server_read, mut server_write) = tokio::io::split(server_stream);

        let server_task = tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(server_read).lines();

            let init_line = lines.next_line().await.unwrap().unwrap();
            let init_value: Value = serde_json::from_str(&init_line).unwrap();
            assert_eq!(init_value["jsonrpc"], "2.0");
            assert_eq!(init_value["method"], "initialize");
            let id = init_value["id"].clone();

            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "hello": "world" },
            });
            let mut response_line = serde_json::to_string(&response).unwrap();
            response_line.push('\n');
            server_write
                .write_all(response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let note_line = lines.next_line().await.unwrap().unwrap();
            let note_value: Value = serde_json::from_str(&note_line).unwrap();
            assert_eq!(note_value["jsonrpc"], "2.0");
            assert_eq!(note_value["method"], "notifications/initialized");
        });

        manager
            .connect_io("srv", client_read, client_write)
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(1), server_task)
            .await
            .expect("server task completed")
            .expect("server task ok");
    }

    #[tokio::test]
    async fn untrusted_manager_refuses_stdio_spawn() {
        let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
        assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

        let server_cfg = ServerConfig {
            transport: Transport::Stdio,
            argv: vec!["mcp-server".to_string()],
            inherit_env: true,
            unix_path: None,
            url: None,
            sse_url: None,
            http_url: None,
            bearer_token_env_var: None,
            http_headers: BTreeMap::new(),
            env_http_headers: BTreeMap::new(),
            env: BTreeMap::new(),
            stdout_log: None,
        };

        let err = manager
            .connect("srv", &server_cfg, Path::new("."))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("untrusted mode"));
    }

    #[tokio::test]
    async fn untrusted_manager_refuses_custom_jsonrpc_attachments() {
        let (client_stream, _server_stream) = tokio::io::duplex(1024);
        let (client_read, client_write) = tokio::io::split(client_stream);

        let client = mcp_jsonrpc::Client::connect_io(client_read, client_write)
            .await
            .unwrap();

        let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
        assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

        let err = manager
            .connect_jsonrpc("srv", client)
            .await
            .expect_err("should refuse in untrusted mode");
        assert!(err.to_string().contains("untrusted mode"));
        assert!(err.to_string().contains("connect_jsonrpc_unchecked"));

        let (client_stream, _server_stream) = tokio::io::duplex(1024);
        let (client_read, client_write) = tokio::io::split(client_stream);
        let err = manager
            .connect_io("srv2", client_read, client_write)
            .await
            .expect_err("should refuse in untrusted mode");
        assert!(err.to_string().contains("untrusted mode"));
        assert!(err.to_string().contains("connect_io_unchecked"));
    }

    #[tokio::test]
    async fn untrusted_manager_refuses_unix_connect() {
        let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
        assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

        let server_cfg = ServerConfig {
            transport: Transport::Unix,
            argv: Vec::new(),
            inherit_env: true,
            unix_path: Some(PathBuf::from("/tmp/mcp.sock")),
            url: None,
            sse_url: None,
            http_url: None,
            bearer_token_env_var: None,
            http_headers: BTreeMap::new(),
            env_http_headers: BTreeMap::new(),
            env: BTreeMap::new(),
            stdout_log: None,
        };

        let err = manager
            .connect("srv", &server_cfg, Path::new("."))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("untrusted mode"));
    }

    #[tokio::test]
    async fn untrusted_manager_refuses_streamable_http_env_secrets() {
        let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
        assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

        let server_cfg = ServerConfig {
            transport: Transport::StreamableHttp,
            argv: Vec::new(),
            inherit_env: true,
            unix_path: None,
            url: Some("https://example.com/mcp".to_string()),
            sse_url: None,
            http_url: None,
            bearer_token_env_var: Some("MCP_TOKEN".to_string()),
            http_headers: BTreeMap::new(),
            env_http_headers: BTreeMap::new(),
            env: BTreeMap::new(),
            stdout_log: None,
        };

        let err = manager
            .connect("srv", &server_cfg, Path::new("."))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("bearer token env var"));
    }

    #[tokio::test]
    async fn untrusted_manager_refuses_streamable_http_non_https_urls() {
        let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
        assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

        let server_cfg = ServerConfig {
            transport: Transport::StreamableHttp,
            argv: Vec::new(),
            inherit_env: true,
            unix_path: None,
            url: Some("http://example.com/mcp".to_string()),
            sse_url: None,
            http_url: None,
            bearer_token_env_var: None,
            http_headers: BTreeMap::new(),
            env_http_headers: BTreeMap::new(),
            env: BTreeMap::new(),
            stdout_log: None,
        };

        let err = manager
            .connect("srv", &server_cfg, Path::new("."))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("non-https"));
    }

    #[tokio::test]
    async fn untrusted_manager_refuses_streamable_http_localhost() {
        let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
        assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

        let server_cfg = ServerConfig {
            transport: Transport::StreamableHttp,
            argv: Vec::new(),
            inherit_env: true,
            unix_path: None,
            url: Some("https://localhost/mcp".to_string()),
            sse_url: None,
            http_url: None,
            bearer_token_env_var: None,
            http_headers: BTreeMap::new(),
            env_http_headers: BTreeMap::new(),
            env: BTreeMap::new(),
            stdout_log: None,
        };

        let err = manager
            .connect("srv", &server_cfg, Path::new("."))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("localhost"));
    }

    #[tokio::test]
    async fn untrusted_manager_refuses_streamable_http_localdomain() {
        let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
        assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

        let server_cfg = ServerConfig {
            transport: Transport::StreamableHttp,
            argv: Vec::new(),
            inherit_env: true,
            unix_path: None,
            url: Some("https://localhost.localdomain/mcp".to_string()),
            sse_url: None,
            http_url: None,
            bearer_token_env_var: None,
            http_headers: BTreeMap::new(),
            env_http_headers: BTreeMap::new(),
            env: BTreeMap::new(),
            stdout_log: None,
        };

        let err = manager
            .connect("srv", &server_cfg, Path::new("."))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("localdomain"));
    }

    #[tokio::test]
    async fn untrusted_manager_refuses_streamable_http_single_label_hosts() {
        let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
        assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

        let server_cfg = ServerConfig {
            transport: Transport::StreamableHttp,
            argv: Vec::new(),
            inherit_env: true,
            unix_path: None,
            url: Some("https://example/mcp".to_string()),
            sse_url: None,
            http_url: None,
            bearer_token_env_var: None,
            http_headers: BTreeMap::new(),
            env_http_headers: BTreeMap::new(),
            env: BTreeMap::new(),
            stdout_log: None,
        };

        let err = manager
            .connect("srv", &server_cfg, Path::new("."))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("single-label"));
    }

    #[tokio::test]
    async fn untrusted_manager_refuses_streamable_http_private_ip() {
        let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
        assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

        let server_cfg = ServerConfig {
            transport: Transport::StreamableHttp,
            argv: Vec::new(),
            inherit_env: true,
            unix_path: None,
            url: Some("https://192.168.0.10/mcp".to_string()),
            sse_url: None,
            http_url: None,
            bearer_token_env_var: None,
            http_headers: BTreeMap::new(),
            env_http_headers: BTreeMap::new(),
            env: BTreeMap::new(),
            stdout_log: None,
        };

        let err = manager
            .connect("srv", &server_cfg, Path::new("."))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("non-global ip"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn untrusted_manager_refuses_streamable_http_ipv4_mapped_ipv6_loopback() {
        let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
        assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

        let server_cfg = ServerConfig {
            transport: Transport::StreamableHttp,
            argv: Vec::new(),
            inherit_env: true,
            unix_path: None,
            url: Some("https://[::ffff:127.0.0.1]/mcp".to_string()),
            sse_url: None,
            http_url: None,
            bearer_token_env_var: None,
            http_headers: BTreeMap::new(),
            env_http_headers: BTreeMap::new(),
            env: BTreeMap::new(),
            stdout_log: None,
        };

        let err = manager
            .connect("srv", &server_cfg, Path::new("."))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("non-global ip"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn untrusted_manager_refuses_streamable_http_url_credentials() {
        let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
        assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

        let server_cfg = ServerConfig {
            transport: Transport::StreamableHttp,
            argv: Vec::new(),
            inherit_env: true,
            unix_path: None,
            url: Some("https://user:pass@example.com/mcp".to_string()),
            sse_url: None,
            http_url: None,
            bearer_token_env_var: None,
            http_headers: BTreeMap::new(),
            env_http_headers: BTreeMap::new(),
            env: BTreeMap::new(),
            stdout_log: None,
        };

        let err = manager
            .connect("srv", &server_cfg, Path::new("."))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("url credentials"));
    }

    #[tokio::test]
    async fn untrusted_manager_refuses_streamable_http_sensitive_headers() {
        let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
        assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

        let mut http_headers = BTreeMap::new();
        http_headers.insert(
            "Authorization".to_string(),
            "Bearer local-secret".to_string(),
        );

        let server_cfg = ServerConfig {
            transport: Transport::StreamableHttp,
            argv: Vec::new(),
            inherit_env: true,
            unix_path: None,
            url: Some("https://example.com/mcp".to_string()),
            sse_url: None,
            http_url: None,
            bearer_token_env_var: None,
            http_headers,
            env_http_headers: BTreeMap::new(),
            env: BTreeMap::new(),
            stdout_log: None,
        };

        let err = manager
            .connect("srv", &server_cfg, Path::new("."))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("sensitive http header"));
    }

    #[test]
    fn untrusted_policy_allows_http_when_configured() {
        let policy = UntrustedStreamableHttpPolicy {
            require_https: false,
            ..Default::default()
        };

        validate_streamable_http_url_untrusted(&policy, "srv", "url", "http://example.com/mcp")
            .unwrap();
    }

    #[test]
    fn untrusted_policy_allows_private_ip_when_configured() {
        let policy = UntrustedStreamableHttpPolicy {
            allow_private_ips: true,
            ..Default::default()
        };

        validate_streamable_http_url_untrusted(&policy, "srv", "url", "https://192.168.0.10/mcp")
            .unwrap();
    }

    #[test]
    fn untrusted_policy_enforces_allowlist_when_set() {
        let policy = UntrustedStreamableHttpPolicy {
            allowed_hosts: vec!["example.com".to_string()],
            ..Default::default()
        };

        validate_streamable_http_url_untrusted(&policy, "srv", "url", "https://example.com/mcp")
            .unwrap();
        validate_streamable_http_url_untrusted(
            &policy,
            "srv",
            "url",
            "https://api.example.com/mcp",
        )
        .unwrap();

        let err =
            validate_streamable_http_url_untrusted(&policy, "srv", "url", "https://evil.com/mcp")
                .unwrap_err();
        assert!(err.to_string().contains("allowlist"));
    }

    #[tokio::test]
    async fn untrusted_policy_dns_check_blocks_localhost_without_allow_private_ip() {
        let policy = UntrustedStreamableHttpPolicy {
            allow_localhost: true,
            dns_check: true,
            ..Default::default()
        };

        validate_streamable_http_url_untrusted(&policy, "srv", "url", "https://localhost/mcp")
            .unwrap();
        let err = validate_streamable_http_url_untrusted_dns(
            &policy,
            "srv",
            "url",
            "https://localhost/mcp",
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("resolves to non-global ip"));
    }

    #[tokio::test]
    async fn untrusted_policy_dns_check_allows_localhost_with_allow_private_ip() {
        let policy = UntrustedStreamableHttpPolicy {
            allow_localhost: true,
            allow_private_ips: true,
            dns_check: true,
            ..Default::default()
        };

        validate_streamable_http_url_untrusted(&policy, "srv", "url", "https://localhost/mcp")
            .unwrap();
        validate_streamable_http_url_untrusted_dns(&policy, "srv", "url", "https://localhost/mcp")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn untrusted_policy_dns_check_fails_closed_on_lookup_error() {
        let policy = UntrustedStreamableHttpPolicy {
            dns_check: true,
            ..Default::default()
        };

        validate_streamable_http_url_untrusted(
            &policy,
            "srv",
            "url",
            "https://does-not-exist.invalid/mcp",
        )
        .unwrap();
        let err = validate_streamable_http_url_untrusted_dns(
            &policy,
            "srv",
            "url",
            "https://does-not-exist.invalid/mcp",
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("dns"), "err={err}");
    }

    #[tokio::test]
    async fn untrusted_policy_dns_check_can_fail_open_on_lookup_error() {
        let policy = UntrustedStreamableHttpPolicy {
            dns_check: true,
            dns_fail_open: true,
            ..Default::default()
        };

        validate_streamable_http_url_untrusted(
            &policy,
            "srv",
            "url",
            "https://does-not-exist.invalid/mcp",
        )
        .unwrap();
        validate_streamable_http_url_untrusted_dns(
            &policy,
            "srv",
            "url",
            "https://does-not-exist.invalid/mcp",
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn argv_placeholder_errors_do_not_leak_plain_argv() {
        let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
            .with_trust_mode(TrustMode::Trusted);

        let server_cfg = ServerConfig {
            transport: Transport::Stdio,
            argv: vec![
                "mcp-server-bin".to_string(),
                "--auth=Bearer SECRET_TOKEN-${BAD-NAME}".to_string(),
            ],
            inherit_env: true,
            unix_path: None,
            url: None,
            sse_url: None,
            http_url: None,
            bearer_token_env_var: None,
            http_headers: BTreeMap::new(),
            env_http_headers: BTreeMap::new(),
            env: BTreeMap::new(),
            stdout_log: None,
        };

        let err = manager
            .connect("srv", &server_cfg, Path::new("."))
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("expand argv placeholder"),
            "expected redacted argv context; err={err:#}"
        );
        assert!(
            !msg.contains("SECRET_TOKEN"),
            "argv secret leaked in error chain; err={err:#}"
        );
    }

    #[test]
    fn url_validation_errors_do_not_leak_plain_url() {
        let policy = UntrustedStreamableHttpPolicy::default();

        let err = validate_streamable_http_url_untrusted(
            &policy,
            "srv",
            "url",
            "https://user:pass@example.com/mcp?token=SECRET_TOKEN",
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("url credentials"),
            "expected url credential error; err={err:#}"
        );
        assert!(
            !msg.contains("SECRET_TOKEN"),
            "url secret leaked in error chain; err={err:#}"
        );
        assert!(
            !msg.contains("user:pass"),
            "url userinfo leaked in error chain; err={err:#}"
        );
    }

    #[tokio::test]
    async fn url_placeholder_errors_do_not_leak_plain_url() {
        let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
            .with_trust_mode(TrustMode::Trusted);

        let server_cfg = ServerConfig {
            transport: Transport::StreamableHttp,
            argv: Vec::new(),
            inherit_env: true,
            unix_path: None,
            url: Some("https://example.com/mcp?token=SECRET_TOKEN_${BAD-NAME}".to_string()),
            sse_url: None,
            http_url: None,
            bearer_token_env_var: None,
            http_headers: BTreeMap::new(),
            env_http_headers: BTreeMap::new(),
            env: BTreeMap::new(),
            stdout_log: None,
        };

        let err = manager
            .connect("srv", &server_cfg, Path::new("."))
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("expand url placeholder"),
            "expected redacted url context; err={err:#}"
        );
        assert!(
            !msg.contains("SECRET_TOKEN"),
            "url secret leaked in error chain; err={err:#}"
        );
    }
}
