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
        server_name: impl Into<ServerName>,
        connection: Connection,
        initialize_result: Value,
        request_timeout: Duration,
    ) -> Self {
        Self {
            server_name: server_name.into(),
            initialize_result,
            connection,
            request_timeout,
        }
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    pub fn initialize_result(&self) -> &Value {
        &self.initialize_result
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }

    pub fn into_connection(self) -> Connection {
        self.connection
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    pub async fn request(&self, method: &str, params: Option<Value>) -> anyhow::Result<Value> {
        let params = params.unwrap_or(Value::Null);
        let outcome = tokio::time::timeout(
            self.request_timeout,
            self.connection.client.request(method, params),
        )
        .await;
        outcome
            .with_context(|| {
                format!(
                    "mcp request timed out: {method} (server={})",
                    self.server_name
                )
            })?
            .with_context(|| format!("mcp request failed: {method} (server={})", self.server_name))
    }

    pub async fn notify(&self, method: &str, params: Option<Value>) -> anyhow::Result<()> {
        let outcome = tokio::time::timeout(
            self.request_timeout,
            self.connection.client.notify(method, params),
        )
        .await;
        outcome
            .with_context(|| {
                format!(
                    "mcp notification timed out: {method} (server={})",
                    self.server_name
                )
            })?
            .with_context(|| {
                format!(
                    "mcp notification failed: {method} (server={})",
                    self.server_name
                )
            })
    }

    pub async fn request_typed<R: McpRequest>(
        &self,
        params: Option<R::Params>,
    ) -> anyhow::Result<R::Result> {
        let params = match params {
            Some(params) => Some(serde_json::to_value(params).context("serialize MCP params")?),
            None => None,
        };
        let result = self.request(R::METHOD, params).await?;
        serde_json::from_value(result).context("deserialize MCP result")
    }

    pub async fn notify_typed<N: McpNotification>(
        &self,
        params: Option<N::Params>,
    ) -> anyhow::Result<()> {
        let params = match params {
            Some(params) => Some(serde_json::to_value(params).context("serialize MCP params")?),
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
