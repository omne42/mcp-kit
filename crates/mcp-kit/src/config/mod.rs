//! MCP `mcp.json` loader + validation.

mod file_format;
mod load;
mod model;

#[cfg(test)]
mod tests;

pub use model::{ClientConfig, Config, Root, ServerConfig, StdoutLogConfig, Transport};

pub(crate) const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
pub(crate) const DEFAULT_STDOUT_LOG_MAX_BYTES_PER_PART: u64 = 1024 * 1024;
pub(crate) const DEFAULT_STDOUT_LOG_MAX_PARTS: u32 = 32;
