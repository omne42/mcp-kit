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

    /// Allow `--config` to point outside `--root`.
    ///
    /// WARNING: This can read config from outside the workspace. Only use this with trusted
    /// paths.
    #[arg(long, default_value_t = false)]
    allow_config_outside_root: bool,

    /// JSON output (default: pretty JSON).
    #[arg(long, default_value_t = false)]
    json: bool,

    /// Per-request timeout in milliseconds.
    #[arg(long, default_value_t = 30_000)]
    timeout_ms: u64,

    /// Fully trust `mcp.json` (allows spawning processes / connecting unix sockets).
    ///
    /// WARNING: Only use this with trusted repositories and trusted server binaries.
    #[arg(long, default_value_t = false, requires = "yes_trust")]
    trust: bool,

    /// Acknowledge the risks of `--trust` (required when `--trust` is set).
    #[arg(long, default_value_t = false)]
    yes_trust: bool,

    /// Allow stdout_log.path to point outside --root.
    ///
    /// WARNING: This can cause writes outside the workspace. Only use this with trusted configs.
    #[arg(long, default_value_t = false)]
    allow_stdout_log_outside_root: bool,

    /// Show configured stdio argv in `list-servers` output.
    ///
    /// WARNING: This may leak secrets if you put tokens/keys in argv.
    #[arg(long, default_value_t = false)]
    show_argv: bool,

    /// Allow connecting to `http://` streamable_http URLs in untrusted mode.
    ///
    /// WARNING: This weakens the default SSRF/safety protections.
    #[arg(long, default_value_t = false)]
    allow_http: bool,

    /// Allow connecting to `localhost` / `*.localhost` / `*.local` / `*.localdomain`, and
    /// single-label hosts (no dots) in untrusted mode.
    ///
    /// WARNING: This weakens the default SSRF/safety protections.
    #[arg(long, default_value_t = false)]
    allow_localhost: bool,

    /// Allow connecting to private/loopback/link-local IP literals in untrusted mode.
    ///
    /// WARNING: This weakens the default SSRF/safety protections.
    #[arg(long, default_value_t = false)]
    allow_private_ip: bool,

    /// Enable DNS checks for streamable_http hostnames in untrusted mode.
    ///
    /// Deprecated compatibility flag: DNS checks are already enabled by default.
    ///
    /// When enabled, hostnames that resolve to non-global IPs are rejected unless
    /// `--allow-private-ip` is also set.
    ///
    /// DNS lookup failures/timeouts are treated as errors (fail-closed) unless
    /// `--dns-fail-open` is set.
    #[arg(long, default_value_t = false)]
    dns_check: bool,

    /// Disable DNS checks (enabled by default).
    ///
    /// WARNING: This can re-introduce SSRF risk via hostnames resolving to non-global IPs.
    #[arg(long, default_value_t = false, conflicts_with = "dns_check")]
    no_dns_check: bool,

    /// DNS lookup timeout in milliseconds.
    ///
    /// Default: 2000.
    #[arg(long, conflicts_with = "no_dns_check")]
    dns_timeout_ms: Option<u64>,

    /// When set, ignore DNS lookup failures/timeouts (fail-open).
    ///
    /// Default: fail-closed.
    #[arg(long, default_value_t = false, conflicts_with = "no_dns_check")]
    dns_fail_open: bool,

    /// Allowlist hostnames for streamable_http in untrusted mode (repeatable).
    ///
    /// When set, only these hosts (or their subdomains) are allowed unless `--trust` is used.
    ///
    /// Note: this does not override the localhost/localdomain/single-label host restriction;
    /// use `--allow-localhost` or `--trust` for that.
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

    if let Some(path) = cli.config.as_ref() {
        let resolved = if path.is_absolute() {
            path.clone()
        } else {
            root.join(path)
        };

        let canonical_root = tokio::fs::canonicalize(&root)
            .await
            .unwrap_or_else(|_| root.clone());
        if let Ok(canonical_config) = tokio::fs::canonicalize(&resolved).await {
            if !canonical_config.starts_with(&canonical_root) {
                if !cli.allow_config_outside_root {
                    anyhow::bail!(
                        "--config must be within --root (pass --allow-config-outside-root to override): {}",
                        resolved.display()
                    );
                }
                eprintln!(
                    "WARNING: --config points outside --root: {}",
                    resolved.display()
                );
            }
        }
    }

    let config = mcp_kit::Config::load(&root, cli.config.clone()).await?;

    let effective_dns_check = !cli.no_dns_check;

    if !cli.trust && cli.dns_check {
        eprintln!(
            "NOTE: --dns-check is already the default in untrusted mode; the flag is kept for compatibility."
        );
    }

    if cli.trust {
        eprintln!("WARNING: --trust disables the default safety restrictions.");
        eprintln!("  - Allows spawning local processes / connecting unix sockets from config.");
        eprintln!("  - Allows reading env secrets for remote auth headers.");
        eprintln!("Only use this with trusted repositories and trusted server binaries.");

        let risky_stdio = config
            .servers()
            .iter()
            .filter(|(_, cfg)| cfg.transport() == mcp_kit::Transport::Stdio && cfg.inherit_env())
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>();
        if !risky_stdio.is_empty() {
            eprintln!(
                "WARNING: stdio servers with inherit_env=true may inherit host secrets: {}",
                risky_stdio.join(", ")
            );
            eprintln!(
                "Consider setting servers.<name>.inherit_env=false and passing only required vars via servers.<name>.env."
            );
        }

        let has_stdout_log = config
            .servers()
            .values()
            .any(|cfg| cfg.transport() == mcp_kit::Transport::Stdio && cfg.stdout_log().is_some());
        if has_stdout_log {
            eprintln!("WARNING: stdout_log writes protocol data to disk and may contain secrets.");
        }
    } else if cli.no_dns_check {
        eprintln!("WARNING: DNS checks are disabled (--no-dns-check).");
        if !cli.allow_private_ip {
            eprintln!("This can re-introduce SSRF risk via hostnames resolving to non-global IPs.");
        }
        if !cli.allow_host.is_empty() && !cli.allow_private_ip {
            eprintln!("WARNING: --allow-host is set with DNS checks disabled (--no-dns-check).");
        }
    }

    let timeout = Duration::from_millis(cli.timeout_ms);
    let mut manager =
        mcp_kit::Manager::from_config(&config, "mcpctl", env!("CARGO_PKG_VERSION"), timeout);

    if cli.allow_stdout_log_outside_root {
        manager = manager.with_allow_stdout_log_outside_root(true);
    }

    if !cli.trust
        && (cli.allow_http
            || cli.allow_localhost
            || cli.allow_private_ip
            || cli.no_dns_check
            || cli.dns_timeout_ms.is_some()
            || cli.dns_fail_open
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
        if cli.no_dns_check {
            policy.dns_check = false;
        }
        if effective_dns_check {
            policy.dns_check = true;
            if let Some(timeout_ms) = cli.dns_timeout_ms {
                policy.dns_timeout = Duration::from_millis(timeout_ms);
            }
            if cli.dns_fail_open {
                policy.dns_fail_open = true;
            }
        }
        if !cli.allow_host.is_empty() {
            policy.allowed_hosts.clone_from(&cli.allow_host);
        }
        manager = manager.with_untrusted_streamable_http_policy(policy);
    }

    if cli.trust {
        manager = manager.with_trust_mode(mcp_kit::TrustMode::Trusted);
    }

    let result = match cli.command {
        Command::ListServers => {
            let servers = config
                .servers()
                .iter()
                .map(|(name, cfg)| {
                    let mut server = serde_json::json!({
                        "name": name,
                        "transport": cfg.transport(),
                        "argv_program": cfg.argv().first(),
                        "argv_argc": cfg.argv().len(),
                        "inherit_env": cfg.inherit_env(),
                        "unix_path": cfg.unix_path().map(|p| p.display().to_string()),
                        "url": cfg.url(),
                        "sse_url": cfg.sse_url(),
                        "http_url": cfg.http_url(),
                        "bearer_token_env_var": cfg.bearer_token_env_var(),
                        "env_keys": cfg.env().keys().cloned().collect::<Vec<_>>(),
                        "http_header_keys": cfg.http_headers().keys().cloned().collect::<Vec<_>>(),
                        "env_http_header_keys": cfg.env_http_headers().keys().cloned().collect::<Vec<_>>(),
                        "stdout_log": cfg.stdout_log().map(|log| serde_json::json!({
                            "path": log.path.display().to_string(),
                            "max_bytes_per_part": log.max_bytes_per_part,
                            "max_parts": log.max_parts,
                        })),
                    });
                    if cli.show_argv {
                        server["argv"] = serde_json::json!(cfg.argv());
                    }
                    server
                })
                .collect::<Vec<_>>();

            serde_json::json!({
                "config_path": config.path().map(|p| p.display().to_string()),
                "client": {
                    "protocol_version": config.client().protocol_version.clone(),
                    "capabilities": config.client().capabilities.clone(),
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
