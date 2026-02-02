use serde::Serialize;
use serde::de::DeserializeOwned;

/// MCP protocol version used during `initialize`.
///
/// This matches the MCP schema version used by the upstream MCP specification.
pub const MCP_PROTOCOL_VERSION: &str = "2025-06-18";

/// Typed MCP request (method + params + result).
///
/// This is a lightweight, schema-agnostic abstraction inspired by common MCP typed wrappers.
pub trait McpRequest {
    const METHOD: &'static str;
    type Params: Serialize;
    type Result: DeserializeOwned;
}

/// Typed MCP notification (method + params).
///
/// This is a lightweight, schema-agnostic abstraction inspired by common MCP typed wrappers.
pub trait McpNotification {
    const METHOD: &'static str;
    type Params: Serialize;
}
