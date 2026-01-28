//! Minimal, dependency-light typed wrappers for common MCP methods.
//!
//! These types are intentionally a *subset* of the full MCP schema and are designed
//! to provide ergonomic, strongly-typed method names + params for clients.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{McpNotification, McpRequest, Root};

pub type Result = Value;

pub enum PingRequest {}

impl McpRequest for PingRequest {
    const METHOD: &'static str = "ping";
    type Params = Option<Value>;
    type Result = Result;
}

pub enum ListRootsRequest {}

impl McpRequest for ListRootsRequest {
    const METHOD: &'static str = "roots/list";
    type Params = Option<Value>;
    type Result = ListRootsResult;
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ListRootsResult {
    pub roots: Vec<Root>,
}

pub enum ListToolsRequest {}

impl McpRequest for ListToolsRequest {
    const METHOD: &'static str = "tools/list";
    type Params = Option<ListToolsRequestParams>;
    type Result = ListToolsResult;
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
pub struct ListToolsRequestParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ListToolsResult {
    #[serde(
        rename = "nextCursor",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub next_cursor: Option<String>,
    pub tools: Vec<Tool>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Tool {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<ToolAnnotations>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "inputSchema")]
    pub input_schema: ToolInputSchema,
    pub name: String,
    #[serde(
        rename = "outputSchema",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub output_schema: Option<ToolOutputSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ToolInputSchema {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
    #[serde(default = "json_schema_object_type_default")]
    pub r#type: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ToolOutputSchema {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
    #[serde(default = "json_schema_object_type_default")]
    pub r#type: String,
}

fn json_schema_object_type_default() -> String {
    "object".to_string()
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ToolAnnotations {
    #[serde(
        rename = "destructiveHint",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub destructive_hint: Option<bool>,
    #[serde(
        rename = "idempotentHint",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub idempotent_hint: Option<bool>,
    #[serde(
        rename = "openWorldHint",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub open_world_hint: Option<bool>,
    #[serde(
        rename = "readOnlyHint",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub read_only_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

pub enum CallToolRequest {}

impl McpRequest for CallToolRequest {
    const METHOD: &'static str = "tools/call";
    type Params = CallToolRequestParams;
    type Result = CallToolResult;
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct CallToolRequestParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct CallToolResult {
    pub content: Vec<Value>,
    #[serde(rename = "isError", default, skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
    #[serde(
        rename = "structuredContent",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub structured_content: Option<Value>,
}

pub enum ListResourcesRequest {}

impl McpRequest for ListResourcesRequest {
    const METHOD: &'static str = "resources/list";
    type Params = Option<ListResourcesRequestParams>;
    type Result = ListResourcesResult;
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
pub struct ListResourcesRequestParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ListResourcesResult {
    #[serde(
        rename = "nextCursor",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub next_cursor: Option<String>,
    pub resources: Vec<Resource>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Resource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Annotations>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "mimeType", default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub uri: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Annotations {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<Vec<Role>>,
    #[serde(
        rename = "lastModified",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_modified: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub enum Role {
    #[serde(rename = "assistant")]
    Assistant,
    #[serde(rename = "user")]
    User,
}

pub enum ListResourceTemplatesRequest {}

impl McpRequest for ListResourceTemplatesRequest {
    const METHOD: &'static str = "resources/templates/list";
    type Params = Option<ListResourceTemplatesRequestParams>;
    type Result = ListResourceTemplatesResult;
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
pub struct ListResourceTemplatesRequestParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ListResourceTemplatesResult {
    #[serde(
        rename = "nextCursor",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub next_cursor: Option<String>,
    #[serde(rename = "resourceTemplates")]
    pub resource_templates: Vec<ResourceTemplate>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ResourceTemplate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Annotations>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "mimeType", default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(rename = "uriTemplate")]
    pub uri_template: String,
}

pub enum ReadResourceRequest {}

impl McpRequest for ReadResourceRequest {
    const METHOD: &'static str = "resources/read";
    type Params = ReadResourceRequestParams;
    type Result = ReadResourceResult;
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ReadResourceRequestParams {
    pub uri: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ReadResourceResult {
    pub contents: Vec<ReadResourceResultContents>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ReadResourceResultContents {
    TextResourceContents(TextResourceContents),
    BlobResourceContents(BlobResourceContents),
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct TextResourceContents {
    #[serde(rename = "mimeType", default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    pub text: String,
    pub uri: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct BlobResourceContents {
    pub blob: String,
    #[serde(rename = "mimeType", default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    pub uri: String,
}

pub enum SubscribeRequest {}

impl McpRequest for SubscribeRequest {
    const METHOD: &'static str = "resources/subscribe";
    type Params = SubscribeRequestParams;
    type Result = Result;
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct SubscribeRequestParams {
    pub uri: String,
}

pub enum UnsubscribeRequest {}

impl McpRequest for UnsubscribeRequest {
    const METHOD: &'static str = "resources/unsubscribe";
    type Params = UnsubscribeRequestParams;
    type Result = Result;
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct UnsubscribeRequestParams {
    pub uri: String,
}

pub enum ListPromptsRequest {}

impl McpRequest for ListPromptsRequest {
    const METHOD: &'static str = "prompts/list";
    type Params = Option<ListPromptsRequestParams>;
    type Result = ListPromptsResult;
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
pub struct ListPromptsRequestParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ListPromptsResult {
    #[serde(
        rename = "nextCursor",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub next_cursor: Option<String>,
    pub prompts: Vec<Prompt>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Prompt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<PromptArgument>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct PromptArgument {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

pub enum GetPromptRequest {}

impl McpRequest for GetPromptRequest {
    const METHOD: &'static str = "prompts/get";
    type Params = GetPromptRequestParams;
    type Result = GetPromptResult;
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct GetPromptRequestParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct GetPromptResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub messages: Vec<PromptMessage>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct PromptMessage {
    pub content: Value,
    pub role: Role,
}

pub enum SetLevelRequest {}

impl McpRequest for SetLevelRequest {
    const METHOD: &'static str = "logging/setLevel";
    type Params = SetLevelRequestParams;
    type Result = Result;
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct SetLevelRequestParams {
    pub level: String,
}

pub enum CompleteRequest {}

impl McpRequest for CompleteRequest {
    const METHOD: &'static str = "completion/complete";
    type Params = Value;
    type Result = Result;
}

pub enum InitializedNotification {}

impl McpNotification for InitializedNotification {
    const METHOD: &'static str = "notifications/initialized";
    type Params = Option<Value>;
}

pub enum RootsListChangedNotification {}

impl McpNotification for RootsListChangedNotification {
    const METHOD: &'static str = "notifications/roots/list_changed";
    type Params = Option<Value>;
}

pub enum ToolsListChangedNotification {}

impl McpNotification for ToolsListChangedNotification {
    const METHOD: &'static str = "notifications/tools/list_changed";
    type Params = Option<Value>;
}

pub enum PromptsListChangedNotification {}

impl McpNotification for PromptsListChangedNotification {
    const METHOD: &'static str = "notifications/prompts/list_changed";
    type Params = Option<Value>;
}

pub enum ResourcesListChangedNotification {}

impl McpNotification for ResourcesListChangedNotification {
    const METHOD: &'static str = "notifications/resources/list_changed";
    type Params = Option<Value>;
}
