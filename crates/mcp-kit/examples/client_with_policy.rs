use std::time::Duration;

use anyhow::{Context, Result};
use mcp_kit::{Config, Manager, TrustMode, UntrustedStreamableHttpPolicy, mcp};

#[derive(Debug, Default)]
struct Args {
    trust: bool,
    policy: UntrustedStreamableHttpPolicy,
    server_name: Option<String>,
}

impl Args {
    fn parse() -> Result<Self> {
        let mut args = std::env::args().skip(1);

        let mut parsed = Args {
            trust: false,
            policy: UntrustedStreamableHttpPolicy::default(),
            server_name: None,
        };

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                "--trust" => {
                    parsed.trust = true;
                }
                "--allow-http" => {
                    parsed.policy.require_https = false;
                }
                "--allow-localhost" => {
                    parsed.policy.allow_localhost = true;
                }
                "--allow-private-ip" => {
                    parsed.policy.allow_private_ips = true;
                }
                "--dns-check" => {
                    parsed.policy.dns_check = true;
                }
                "--allow-host" => {
                    let host = args
                        .next()
                        .with_context(|| "missing value for --allow-host <host>")?;
                    parsed.policy.allowed_hosts.push(host);
                }
                _ if arg.starts_with('-') => {
                    anyhow::bail!("unknown flag: {arg} (try --help)");
                }
                _ => {
                    parsed.server_name = Some(arg);
                    break;
                }
            }
        }

        Ok(parsed)
    }
}

fn print_help() {
    eprintln!("Usage:");
    eprintln!("  cargo run -p mcp-kit --example client_with_policy -- [flags] <server>");
    eprintln!();
    eprintln!("Flags (only affect transport=streamable_http in Untrusted mode):");
    eprintln!(
        "  --trust              Fully trust local mcp.json (allows stdio/unix, auth headers, env secrets)"
    );
    eprintln!("  --allow-http         Allow http:// in Untrusted mode");
    eprintln!(
        "  --allow-localhost    Allow localhost/*.localhost/*.local/*.localdomain and single-label hosts in Untrusted mode"
    );
    eprintln!("  --allow-private-ip   Allow private/loopback IP literals in Untrusted mode");
    eprintln!("  --dns-check          Best-effort DNS check for hostnames in Untrusted mode");
    eprintln!("  --allow-host <host>  Host allowlist (repeatable), e.g. --allow-host example.com");
    eprintln!("  --help, -h           Print this help");
}

#[tokio::main]
async fn main() -> Result<()> {
    let root = std::env::current_dir()?;
    let config = Config::load(&root, None).await?;

    let args = Args::parse()?;

    let server_name = match args.server_name {
        Some(name) => name,
        None => {
            print_help();
            if config.servers.is_empty() {
                eprintln!();
                eprintln!("No servers found in mcp.json.");
                return Ok(());
            }
            eprintln!();
            eprintln!("Available servers from mcp.json:");
            for name in config.servers.keys() {
                eprintln!("  {name}");
            }
            return Ok(());
        }
    };

    let mut manager = Manager::from_config(
        &config,
        "client-with-policy",
        env!("CARGO_PKG_VERSION"),
        Duration::from_secs(30),
    )
    .with_untrusted_streamable_http_policy(args.policy);
    if args.trust {
        manager = manager.with_trust_mode(TrustMode::Trusted);
    }

    let tools = manager
        .request_typed::<mcp::ListToolsRequest>(&config, &server_name, None, &root)
        .await?;

    println!("{}", serde_json::to_string_pretty(&tools)?);
    Ok(())
}
