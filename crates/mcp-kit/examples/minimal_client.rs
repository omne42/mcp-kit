use std::time::Duration;

use anyhow::Result;
use mcp_kit::{Config, Manager, Transport, mcp};

#[tokio::main]
async fn main() -> Result<()> {
    let root = std::env::current_dir()?;
    let config = Config::load(&root, None).await?;

    let server_name = match std::env::args().nth(1) {
        Some(name) => name,
        None => {
            eprintln!("usage: cargo run -p mcp-kit --example minimal_client -- <server>");
            eprintln!("available servers:");
            for name in config.servers().keys() {
                eprintln!("  {name}");
            }
            return Ok(());
        }
    };

    let Some(server_cfg) = config.server(&server_name) else {
        eprintln!("unknown server: {server_name}");
        eprintln!("available servers:");
        for name in config.servers().keys() {
            eprintln!("  {name}");
        }
        return Ok(());
    };

    if server_cfg.transport() != Transport::StreamableHttp {
        eprintln!(
            "note: minimal_client runs in Untrusted mode by default and only supports transport=streamable_http."
        );
        eprintln!("for stdio/unix, try:");
        eprintln!("  cargo run -p mcp-kit --example client_with_policy -- --trust {server_name}");
        eprintln!(
            "  cargo run -p mcp-kit --features cli --bin mcpctl -- --trust --yes-trust list-tools {server_name}"
        );
        return Ok(());
    }

    let mut manager = Manager::from_config(
        &config,
        "minimal-client",
        env!("CARGO_PKG_VERSION"),
        Duration::from_secs(30),
    );
    let tools = manager
        .request_typed::<mcp::ListToolsRequest>(&config, &server_name, None, &root)
        .await?;

    println!("{}", serde_json::to_string_pretty(&tools)?);
    Ok(())
}
