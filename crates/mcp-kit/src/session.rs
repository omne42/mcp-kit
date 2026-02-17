use std::time::Duration;

use anyhow::Context;
use serde_json::Value;

use crate::{Connection, McpNotification, McpRequest, ServerName};

pub struct Session {
    server_name: ServerName,
    initialize_result: Value,
    connection: Connection,
    request_timeout: Duration,
}

impl Session {
    pub fn new(
        server_name: ServerName,
        connection: Connection,
        initialize_result: Value,
        request_timeout: Duration,
    ) -> Self {
        Self {
            server_name,
            initialize_result,
            connection,
            request_timeout,
        }
    }

    pub fn server_name(&self) -> &str {
        self.server_name.as_str()
    }

    pub fn server_name_named(&self) -> &ServerName {
        &self.server_name
    }

    pub fn initialize_result(&self) -> &Value {
        &self.initialize_result
    }

    /// Returns the underlying connection.
    ///
    /// This is an escape hatch for advanced use cases. Prefer `Session::{request,notify}` unless
    /// you specifically need access to the underlying JSON-RPC client or child process handle.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Returns the underlying connection (mutable).
    ///
    /// Warning: mutating the underlying client can bypass `Session`'s timeout wrappers and can
    /// make lifecycle/ownership less clear. If you take over lifecycle control, you are
    /// responsible for closing and waiting for any associated child process.
    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }

    /// Consumes this session and returns the underlying connection.
    ///
    /// After calling this, the caller owns the connection lifecycle. In particular, if the
    /// connection was created via a `transport=stdio` server, you should call
    /// `Connection::wait_with_timeout` (or equivalent) to avoid leaving a child process running.
    pub fn into_connection(self) -> Connection {
        self.connection
    }

    /// Closes this session and (if present) waits for the underlying child process to exit.
    ///
    /// Note: this can hang indefinitely if the child does not exit. Prefer
    /// `Session::wait_with_timeout` if you need an upper bound.
    pub async fn wait(self) -> anyhow::Result<Option<std::process::ExitStatus>> {
        let Session {
            server_name,
            connection,
            ..
        } = self;
        connection
            .wait()
            .await
            .with_context(|| format!("close session (server={server_name})"))
    }

    /// Closes this session and waits for the underlying child process to exit, up to `timeout`.
    pub async fn wait_with_timeout(
        self,
        timeout: Duration,
        on_timeout: mcp_jsonrpc::WaitOnTimeout,
    ) -> anyhow::Result<Option<std::process::ExitStatus>> {
        let Session {
            server_name,
            connection,
            ..
        } = self;
        connection
            .wait_with_timeout(timeout, on_timeout)
            .await
            .with_context(|| format!("close session (server={server_name})"))
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    pub async fn request(&self, method: &str, params: Option<Value>) -> anyhow::Result<Value> {
        let result = self
            .connection
            .client()
            .request_optional_with_timeout(method, params, self.request_timeout)
            .await;
        match result {
            Ok(value) => Ok(value),
            Err(err) if err.is_wait_timeout() => Err(anyhow::Error::new(err).context(format!(
                "mcp request timed out after {:?}: {method} (server={})",
                self.request_timeout, self.server_name
            ))),
            Err(err) => Err(anyhow::Error::new(err).context(format!(
                "mcp request failed: {method} (server={})",
                self.server_name
            ))),
        }
    }

    pub async fn notify(&self, method: &str, params: Option<Value>) -> anyhow::Result<()> {
        let timeout = self.request_timeout;
        let outcome = tokio::time::timeout(
            self.request_timeout,
            self.connection.client().notify(method, params),
        )
        .await;
        match outcome {
            Ok(result) => result.with_context(|| {
                format!(
                    "mcp notification failed: {method} (server={})",
                    self.server_name
                )
            }),
            Err(_) => {
                const CLOSE_ON_TIMEOUT_BUDGET: Duration = Duration::from_millis(50);
                let timeout_message = format!(
                    "mcp notification timed out after {timeout:?}: {method} (server={})",
                    self.server_name
                );

                // Best-effort close: bound close-path wait to avoid hanging the timeout caller.
                if tokio::time::timeout(
                    CLOSE_ON_TIMEOUT_BUDGET,
                    self.connection.client().close(timeout_message.clone()),
                )
                .await
                .is_err()
                {
                    // Close-path timeout is non-fatal here; the caller already gets timeout.
                }
                Err(anyhow::Error::new(mcp_jsonrpc::Error::protocol(
                    mcp_jsonrpc::ProtocolErrorKind::WaitTimeout,
                    timeout_message,
                )))
            }
        }
    }

    pub async fn request_typed<R: McpRequest>(
        &self,
        params: Option<R::Params>,
    ) -> anyhow::Result<R::Result> {
        let params = match params {
            Some(params) => Some(serde_json::to_value(params).with_context(|| {
                format!(
                    "serialize MCP params: {} (server={})",
                    R::METHOD,
                    self.server_name
                )
            })?),
            None => None,
        };
        let result = self.request(R::METHOD, params).await?;
        serde_json::from_value(result).with_context(|| {
            format!(
                "deserialize MCP result: {} (server={})",
                R::METHOD,
                self.server_name
            )
        })
    }

    pub async fn notify_typed<N: McpNotification>(
        &self,
        params: Option<N::Params>,
    ) -> anyhow::Result<()> {
        let params = match params {
            Some(params) => Some(serde_json::to_value(params).with_context(|| {
                format!(
                    "serialize MCP params: {} (server={})",
                    N::METHOD,
                    self.server_name
                )
            })?),
            None => None,
        };
        self.notify(N::METHOD, params).await
    }

    pub async fn ping(&self) -> anyhow::Result<Value> {
        self.request("ping", None).await
    }

    pub async fn list_tools(&self) -> anyhow::Result<Value> {
        self.request("tools/list", None).await
    }

    pub async fn list_resources(&self) -> anyhow::Result<Value> {
        self.request("resources/list", None).await
    }

    pub async fn list_resource_templates(&self) -> anyhow::Result<Value> {
        self.request("resources/templates/list", None).await
    }

    pub async fn read_resource(&self, uri: &str) -> anyhow::Result<Value> {
        let params = serde_json::json!({ "uri": uri });
        self.request("resources/read", Some(params)).await
    }

    pub async fn subscribe_resource(&self, uri: &str) -> anyhow::Result<Value> {
        let params = serde_json::json!({ "uri": uri });
        self.request("resources/subscribe", Some(params)).await
    }

    pub async fn unsubscribe_resource(&self, uri: &str) -> anyhow::Result<Value> {
        let params = serde_json::json!({ "uri": uri });
        self.request("resources/unsubscribe", Some(params)).await
    }

    pub async fn list_prompts(&self) -> anyhow::Result<Value> {
        self.request("prompts/list", None).await
    }

    pub async fn get_prompt(
        &self,
        prompt: &str,
        arguments: Option<Value>,
    ) -> anyhow::Result<Value> {
        let mut params = serde_json::json!({ "name": prompt });
        if let Some(arguments) = arguments {
            params["arguments"] = arguments;
        }
        self.request("prompts/get", Some(params)).await
    }

    pub async fn call_tool(&self, tool: &str, arguments: Option<Value>) -> anyhow::Result<Value> {
        let mut params = serde_json::json!({ "name": tool });
        if let Some(arguments) = arguments {
            params["arguments"] = arguments;
        }
        self.request("tools/call", Some(params)).await
    }

    pub async fn set_logging_level(&self, level: &str) -> anyhow::Result<Value> {
        let params = serde_json::json!({ "level": level });
        self.request("logging/setLevel", Some(params)).await
    }

    pub async fn complete(&self, params: Value) -> anyhow::Result<Value> {
        self.request("completion/complete", Some(params)).await
    }
}
