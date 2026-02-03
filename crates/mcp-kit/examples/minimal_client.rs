use std::time::Duration;

use anyhow::Result;
use mcp_kit::{Config, Manager, mcp};

#[tokio::main]
async fn main() -> Result<()> {
    let root = std::env::current_dir()?;
    let config = Config::load(&root, None).await?;

    let server_name = match std::env::args().nth(1) {
        Some(name) => name,
        None => {
            eprintln!("usage: cargo run -p mcp-kit --example minimal_client -- <server>");
            eprintln!("available servers:");
            for name in config.servers.keys() {
                eprintln!("  {name}");
            }
            return Ok(());
        }
    };

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
