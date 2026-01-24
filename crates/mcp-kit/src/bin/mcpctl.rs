use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use clap::{Parser, Subcommand};
use serde_json::Value;

#[derive(Parser)]
#[command(name = "mcpctl")]
#[command(about = "MCP client/runner (stdio, config-driven)")]
struct Cli {
    /// Workspace root used for relative config paths and as MCP server working directory.
    #[arg(long)]
    root: Option<PathBuf>,

    /// Override config path (absolute or relative to --root).
    #[arg(long)]
    config: Option<PathBuf>,

    /// JSON output (default: pretty JSON).
    #[arg(long, default_value_t = false)]
    json: bool,

    /// Per-request timeout in milliseconds.
    #[arg(long, default_value_t = 30_000)]
    timeout_ms: u64,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List configured MCP servers from `mcp.json`.
    ListServers,
    /// List tools exposed by an MCP server.
    ListTools { server: String },
    /// List resources exposed by an MCP server.
    ListResources { server: String },
    /// List prompts exposed by an MCP server.
    ListPrompts { server: String },
    /// Call a tool exposed by an MCP server.
    Call {
        server: String,
        tool: String,
        #[arg(long)]
        arguments_json: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let root = cli
        .root
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let config = pm_mcp_kit::Config::load(&root, cli.config.clone()).await?;

    let timeout = Duration::from_millis(cli.timeout_ms);
    let mut manager = pm_mcp_kit::Manager::new("mcpctl", env!("CARGO_PKG_VERSION"), timeout);

    let result = match cli.command {
        Command::ListServers => {
            let servers = config
                .servers
                .iter()
                .map(|(name, cfg)| {
                    serde_json::json!({
                        "name": name,
                        "transport": cfg.transport,
                        "argv": &cfg.argv,
                        "env_keys": cfg.env.keys().cloned().collect::<Vec<_>>(),
                    })
                })
                .collect::<Vec<_>>();

            serde_json::json!({
                "config_path": config.path.as_ref().map(|p| p.display().to_string()),
                "servers": servers,
            })
        }
        Command::ListTools { server } => manager
            .list_tools(&config, &server, &root)
            .await
            .with_context(|| format!("list-tools server={server}"))?,
        Command::ListResources { server } => manager
            .list_resources(&config, &server, &root)
            .await
            .with_context(|| format!("list-resources server={server}"))?,
        Command::ListPrompts { server } => manager
            .list_prompts(&config, &server, &root)
            .await
            .with_context(|| format!("list-prompts server={server}"))?,
        Command::Call {
            server,
            tool,
            arguments_json,
        } => {
            let arguments = match arguments_json {
                Some(raw) => {
                    Some(serde_json::from_str::<Value>(&raw).context("parse --arguments-json")?)
                }
                None => None,
            };
            manager
                .call_tool(&config, &server, &tool, arguments, &root)
                .await
                .with_context(|| format!("call server={server} tool={tool}"))?
        }
    };

    let text = if cli.json {
        serde_json::to_string(&result)?
    } else {
        serde_json::to_string_pretty(&result)?
    };
    println!("{text}");
    Ok(())
}
