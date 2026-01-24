use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::Context;
use serde_json::Value;
use tokio::process::{Child, Command};

use crate::{Config, ServerConfig, Transport};

pub type ServerName = String;

const MCP_PROTOCOL_VERSION: &str = "2025-06-18";

pub struct Manager {
    pub conns: HashMap<ServerName, Connection>,
    client_name: String,
    client_version: String,
    request_timeout: Duration,
}

pub struct Connection {
    pub child: Child,
    pub client: pm_jsonrpc::Client,
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
    pub fn new(
        client_name: impl Into<String>,
        client_version: impl Into<String>,
        timeout: Duration,
    ) -> Self {
        Self {
            conns: HashMap::new(),
            client_name: client_name.into(),
            client_version: client_version.into(),
            request_timeout: timeout,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    pub async fn connect(
        &mut self,
        server_name: &str,
        server_cfg: &ServerConfig,
        cwd: &Path,
    ) -> anyhow::Result<()> {
        if self.conns.contains_key(server_name) {
            return Ok(());
        }

        if !matches!(server_cfg.transport, Transport::Stdio) {
            anyhow::bail!("unsupported mcp transport (expected stdio)");
        }
        if server_cfg.argv.is_empty() {
            anyhow::bail!("mcp server argv must not be empty");
        }

        let mut cmd = Command::new(&server_cfg.argv[0]);
        cmd.args(server_cfg.argv.iter().skip(1));
        cmd.current_dir(cwd);
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::inherit());
        cmd.envs(server_cfg.env.iter());
        cmd.kill_on_drop(true);

        let mut client = pm_jsonrpc::Client::spawn_command(cmd)
            .await
            .with_context(|| format!("spawn mcp server {:?}", server_cfg.argv))?;
        let _ = client.take_notifications();
        let child = client
            .take_child()
            .ok_or_else(|| anyhow::anyhow!("mcp transport does not expose a child process"))?;

        self.initialize(server_name, &mut client).await?;

        self.conns
            .insert(server_name.to_string(), Connection { child, client });
        Ok(())
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

    pub async fn list_tools(
        &mut self,
        config: &Config,
        server_name: &str,
        cwd: &Path,
    ) -> anyhow::Result<Value> {
        self.get_or_connect(config, server_name, cwd).await?;
        let timeout = self.request_timeout;
        let conn = self.conns.get_mut(server_name).expect("connected");
        Self::request(timeout, &mut conn.client, "tools/list", None).await
    }

    pub async fn list_resources(
        &mut self,
        config: &Config,
        server_name: &str,
        cwd: &Path,
    ) -> anyhow::Result<Value> {
        self.get_or_connect(config, server_name, cwd).await?;
        let timeout = self.request_timeout;
        let conn = self.conns.get_mut(server_name).expect("connected");
        Self::request(timeout, &mut conn.client, "resources/list", None).await
    }

    pub async fn list_prompts(
        &mut self,
        config: &Config,
        server_name: &str,
        cwd: &Path,
    ) -> anyhow::Result<Value> {
        self.get_or_connect(config, server_name, cwd).await?;
        let timeout = self.request_timeout;
        let conn = self.conns.get_mut(server_name).expect("connected");
        Self::request(timeout, &mut conn.client, "prompts/list", None).await
    }

    pub async fn call_tool(
        &mut self,
        config: &Config,
        server_name: &str,
        tool: &str,
        arguments: Option<Value>,
        cwd: &Path,
    ) -> anyhow::Result<Value> {
        self.get_or_connect(config, server_name, cwd).await?;
        let timeout = self.request_timeout;
        let conn = self.conns.get_mut(server_name).expect("connected");
        let mut params = serde_json::json!({ "name": tool });
        if let Some(arguments) = arguments {
            params["arguments"] = arguments;
        }
        Self::request(timeout, &mut conn.client, "tools/call", Some(params)).await
    }

    async fn initialize(
        &self,
        server_name: &str,
        client: &mut pm_jsonrpc::Client,
    ) -> anyhow::Result<()> {
        let initialize_params = serde_json::json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "clientInfo": {
                "name": &self.client_name,
                "version": &self.client_version,
            },
            "capabilities": {},
        });

        let outcome = tokio::time::timeout(
            self.request_timeout,
            client.request("initialize", initialize_params),
        )
        .await;
        let _ = outcome
            .context("mcp initialize timed out")?
            .with_context(|| format!("mcp initialize failed (server={server_name})"))?;

        client
            .notify("notifications/initialized", None)
            .await
            .with_context(|| {
                format!("mcp initialized notification failed (server={server_name})")
            })?;
        Ok(())
    }

    async fn request(
        timeout: Duration,
        client: &mut pm_jsonrpc::Client,
        method: &str,
        params: Option<Value>,
    ) -> anyhow::Result<Value> {
        let params = params.unwrap_or(Value::Null);
        let outcome = tokio::time::timeout(timeout, client.request(method, params)).await;
        outcome
            .with_context(|| format!("mcp request timed out: {method}"))?
            .with_context(|| format!("mcp request failed: {method}"))
    }
}
