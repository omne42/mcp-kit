use std::time::Duration;

use anyhow::{Context, Result};
use mcp_kit::{Manager, mcp};

#[derive(Debug, Default)]
struct Args {
    connect_timeout_ms: Option<u64>,
    request_timeout_ms: Option<u64>,
    follow_redirects: bool,
    sse_url: Option<String>,
    http_url: Option<String>,
}

impl Args {
    fn parse() -> Result<Self> {
        let mut args = std::env::args().skip(1);

        let mut parsed = Args::default();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                "--connect-timeout-ms" => {
                    let value = args
                        .next()
                        .with_context(|| "missing value for --connect-timeout-ms <ms>")?;
                    let ms = value
                        .parse::<u64>()
                        .with_context(|| format!("invalid --connect-timeout-ms: {value}"))?;
                    parsed.connect_timeout_ms = Some(ms);
                }
                "--request-timeout-ms" => {
                    let value = args
                        .next()
                        .with_context(|| "missing value for --request-timeout-ms <ms>")?;
                    let ms = value
                        .parse::<u64>()
                        .with_context(|| format!("invalid --request-timeout-ms: {value}"))?;
                    parsed.request_timeout_ms = Some(ms);
                }
                "--follow-redirects" => {
                    parsed.follow_redirects = true;
                }
                _ if arg.starts_with('-') => {
                    anyhow::bail!("unknown flag: {arg} (try --help)");
                }
                _ => {
                    if parsed.sse_url.is_none() {
                        parsed.sse_url = Some(arg);
                    } else if parsed.http_url.is_none() {
                        parsed.http_url = Some(arg);
                    } else {
                        anyhow::bail!("unexpected extra argument: {arg}");
                    }
                }
            }
        }

        Ok(parsed)
    }
}

fn print_help() {
    eprintln!("Usage:");
    eprintln!(
        "  cargo run -p mcp-kit --example streamable_http_custom_options -- [flags] <sse_url> [http_url]"
    );
    eprintln!();
    eprintln!("Flags:");
    eprintln!("  --connect-timeout-ms <ms>  Timeout for establishing SSE connection");
    eprintln!("  --request-timeout-ms <ms>  Timeout for HTTP POST response bodies");
    eprintln!("  --follow-redirects         Follow HTTP redirects (unsafe by default)");
    eprintln!("  --help, -h                 Print this help");
    eprintln!();
    eprintln!("Notes:");
    eprintln!("  - This example requires a real MCP server (transport=streamable_http).");
    eprintln!("  - If http_url is omitted, it defaults to sse_url.");
    eprintln!(
        "  - This demonstrates custom mcp-jsonrpc StreamableHttpOptions + Manager::connect_jsonrpc."
    );
    eprintln!(
        "  - Safety: this example explicitly uses TrustMode::Trusted because building the HTTP client yourself bypasses Manager's Untrusted streamable_http policy checks."
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse()?;

    let sse_url = match args.sse_url {
        Some(v) => v,
        None => {
            print_help();
            return Ok(());
        }
    };
    let http_url = args.http_url.unwrap_or_else(|| sse_url.clone());

    let mut http_options = mcp_jsonrpc::StreamableHttpOptions::default();
    if let Some(ms) = args.connect_timeout_ms {
        http_options.connect_timeout = Some(Duration::from_millis(ms));
    }
    if let Some(ms) = args.request_timeout_ms {
        http_options.request_timeout = Some(Duration::from_millis(ms));
    }
    if args.follow_redirects {
        http_options.follow_redirects = true;
    }

    let client = mcp_jsonrpc::Client::connect_streamable_http_split_with_options(
        &sse_url,
        &http_url,
        http_options,
        mcp_jsonrpc::SpawnOptions::default(),
    )
    .await
    .with_context(|| {
        if sse_url == http_url {
            format!("connect streamable_http url={sse_url}")
        } else {
            format!("connect streamable_http sse_url={sse_url} http_url={http_url}")
        }
    })?;

    let mut manager = Manager::new(
        "streamable-http-custom-options",
        env!("CARGO_PKG_VERSION"),
        Duration::from_secs(30),
    )
    .with_trust_mode(mcp_kit::TrustMode::Trusted);
    manager.connect_jsonrpc("remote", client).await?;

    let tools = manager
        .request_typed_connected::<mcp::ListToolsRequest>("remote", None)
        .await
        .context("tools/list")?;
    println!("{}", serde_json::to_string_pretty(&tools)?);
    Ok(())
}
