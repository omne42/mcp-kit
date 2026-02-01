use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use clap::{Parser, Subcommand};
use serde_json::Value;

#[derive(Parser)]
#[command(name = "mcpctl")]
#[command(about = "MCP client/runner (config-driven; stdio/unix/streamable_http)")]
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

    /// Fully trust `mcp.json` (allows spawning processes / connecting unix sockets).
    ///
    /// WARNING: Only use this with trusted repositories and trusted server binaries.
    #[arg(long, default_value_t = false)]
    trust: bool,

    /// Allow connecting to `http://` streamable_http URLs in untrusted mode.
    ///
    /// WARNING: This weakens the default SSRF/safety protections.
    #[arg(long, default_value_t = false)]
    allow_http: bool,

    /// Allow connecting to `localhost` / `*.localhost` / `*.local` in untrusted mode.
    ///
    /// WARNING: This weakens the default SSRF/safety protections.
    #[arg(long, default_value_t = false)]
    allow_localhost: bool,

    /// Allow connecting to private/loopback/link-local IP literals in untrusted mode.
    ///
    /// WARNING: This weakens the default SSRF/safety protections.
    #[arg(long, default_value_t = false)]
    allow_private_ip: bool,

    /// Allowlist hostnames for streamable_http in untrusted mode (repeatable).
    ///
    /// When set, only these hosts (or their subdomains) are allowed unless `--trust` is used.
    #[arg(long)]
    allow_host: Vec<String>,

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
    /// Send a raw JSON-RPC request to an MCP server.
    Request {
        server: String,
        method: String,
        #[arg(long)]
        params_json: Option<String>,
    },
    /// Send a raw JSON-RPC notification to an MCP server.
    Notify {
        server: String,
        method: String,
        #[arg(long)]
        params_json: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let root = cli
        .root
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let config = mcp_kit::Config::load(&root, cli.config.clone()).await?;

    let timeout = Duration::from_millis(cli.timeout_ms);
    let mut manager =
        mcp_kit::Manager::from_config(&config, "mcpctl", env!("CARGO_PKG_VERSION"), timeout);

    if !cli.trust
        && (cli.allow_http
            || cli.allow_localhost
            || cli.allow_private_ip
            || !cli.allow_host.is_empty())
    {
        let mut policy = mcp_kit::UntrustedStreamableHttpPolicy::default();
        if cli.allow_http {
            policy.require_https = false;
        }
        if cli.allow_localhost {
            policy.allow_localhost = true;
        }
        if cli.allow_private_ip {
            policy.allow_private_ips = true;
        }
        if !cli.allow_host.is_empty() {
            policy.allowed_hosts = cli.allow_host.clone();
        }
        manager = manager.with_untrusted_streamable_http_policy(policy);
    }

    if cli.trust {
        manager = manager.with_trust_mode(mcp_kit::TrustMode::Trusted);
    }

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
                        "unix_path": cfg.unix_path.as_ref().map(|p| p.display().to_string()),
                        "url": cfg.url.as_deref(),
                        "bearer_token_env_var": cfg.bearer_token_env_var.as_deref(),
                        "env_keys": cfg.env.keys().cloned().collect::<Vec<_>>(),
                        "http_header_keys": cfg.http_headers.keys().cloned().collect::<Vec<_>>(),
                        "env_http_header_keys": cfg.env_http_headers.keys().cloned().collect::<Vec<_>>(),
                        "stdout_log": cfg.stdout_log.as_ref().map(|log| serde_json::json!({
                            "path": log.path.display().to_string(),
                            "max_bytes_per_part": log.max_bytes_per_part,
                            "max_parts": log.max_parts,
                        })),
                    })
                })
                .collect::<Vec<_>>();

            serde_json::json!({
                "config_path": config.path.as_ref().map(|p| p.display().to_string()),
                "client": {
                    "protocol_version": config.client.protocol_version,
                    "capabilities": config.client.capabilities,
                },
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
        Command::Request {
            server,
            method,
            params_json,
        } => {
            let params = match params_json {
                Some(raw) => {
                    Some(serde_json::from_str::<Value>(&raw).context("parse --params-json")?)
                }
                None => None,
            };
            manager
                .request(&config, &server, &method, params, &root)
                .await
                .with_context(|| format!("request server={server} method={method}"))?
        }
        Command::Notify {
            server,
            method,
            params_json,
        } => {
            let params = match params_json {
                Some(raw) => {
                    Some(serde_json::from_str::<Value>(&raw).context("parse --params-json")?)
                }
                None => None,
            };
            manager
                .notify(&config, &server, &method, params, &root)
                .await
                .with_context(|| format!("notify server={server} method={method}"))?;
            serde_json::json!({ "ok": true })
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
