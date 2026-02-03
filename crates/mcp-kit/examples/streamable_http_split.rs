use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result};
use mcp_kit::{Manager, ServerConfig, Transport, mcp};

fn print_help() {
    eprintln!("Usage:");
    eprintln!("  cargo run -p mcp-kit --example streamable_http_split -- <sse_url> <http_url>");
    eprintln!();
    eprintln!("Notes:");
    eprintln!("  - This example requires a real MCP server (transport=streamable_http).");
    eprintln!("  - Use https:// URLs by default (Untrusted mode enforces HTTPS).");
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let sse_url = match args.next() {
        Some(v) => v,
        None => {
            print_help();
            return Ok(());
        }
    };
    let http_url = match args.next() {
        Some(v) => v,
        None => {
            print_help();
            return Ok(());
        }
    };

    let cwd = std::env::current_dir()?;

    let server_cfg = ServerConfig {
        transport: Transport::StreamableHttp,
        argv: Vec::new(),
        unix_path: None,
        url: None,
        sse_url: Some(sse_url),
        http_url: Some(http_url),
        bearer_token_env_var: None,
        http_headers: BTreeMap::new(),
        env_http_headers: BTreeMap::new(),
        env: BTreeMap::new(),
        stdout_log: None,
    };

    let mut manager = Manager::new(
        "streamable-http-split",
        env!("CARGO_PKG_VERSION"),
        Duration::from_secs(30),
    );
    manager
        .connect("remote", &server_cfg, &cwd)
        .await
        .context("connect streamable_http (split urls)")?;

    let tools = manager
        .request_typed_connected::<mcp::ListToolsRequest>(
            "remote",
            Some(mcp::ListToolsRequestParams::default()),
        )
        .await
        .context("tools/list")?;

    println!("{}", serde_json::to_string_pretty(&tools)?);
    Ok(())
}
