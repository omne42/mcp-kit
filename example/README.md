# Examples

This repository is a Rust workspace. Runnable examples are located under the crate that owns them:

- `crates/mcp-kit/examples/` (MCP client examples built on `mcp_kit::{Config, Manager, Session}`)

See also:

- `docs/examples.md` (runnable examples + copy/paste snippets)

## Runnable examples (`mcp-kit`)

From the repo root:

```bash
# Minimal config-driven client (default: Untrusted + streamable_http only)
cargo run -p mcp-kit --example minimal_client -- <server>

# Like minimal_client, but exposes --trust and Untrusted egress policy flags
cargo run -p mcp-kit --example client_with_policy -- [flags] <server>

# No external server: in-memory duplex IO + server→client request handling
cargo run -p mcp-kit --example in_memory_duplex

# No external server: demonstrate taking a `Session` and using it independently
cargo run -p mcp-kit --example session_handoff

# Requires a real MCP server: split SSE + POST URLs for streamable_http
cargo run -p mcp-kit --example streamable_http_split -- <sse_url> <http_url>

# Requires a real MCP server: customize StreamableHttpOptions (connect timeout, request timeout, redirects)
cargo run -p mcp-kit --example streamable_http_custom_options -- [flags] <sse_url> [http_url]
```
