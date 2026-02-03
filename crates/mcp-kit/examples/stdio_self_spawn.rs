use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result};
use mcp_kit::{MCP_PROTOCOL_VERSION, Manager, ServerConfig, Transport, TrustMode, mcp};

fn print_help() {
    eprintln!("Usage:");
    eprintln!("  cargo run -p mcp-kit --example stdio_self_spawn");
    eprintln!();
    eprintln!("Notes:");
    eprintln!("  - This example is self-contained: it spawns itself as an MCP server over stdio.");
    eprintln!("  - The child process is started with an internal flag: --server");
}

fn is_server_mode() -> bool {
    std::env::args().any(|arg| arg == "--server")
}

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        return Ok(());
    }

    if is_server_mode() {
        return server_main().await;
    }
    client_main().await
}

async fn client_main() -> Result<()> {
    let cwd = std::env::current_dir()?;
    let exe = std::env::current_exe().context("resolve current executable path")?;
    let argv = vec![exe.to_string_lossy().to_string(), "--server".to_string()];

    let server_cfg = ServerConfig {
        transport: Transport::Stdio,
        argv,
        inherit_env: true,
        unix_path: None,
        url: None,
        sse_url: None,
        http_url: None,
        bearer_token_env_var: None,
        http_headers: BTreeMap::new(),
        env_http_headers: BTreeMap::new(),
        env: BTreeMap::new(),
        stdout_log: None,
    };

    let mut manager = Manager::new(
        "stdio-self-spawn-client",
        env!("CARGO_PKG_VERSION"),
        Duration::from_secs(10),
    )
    .with_trust_mode(TrustMode::Trusted);
    manager
        .connect("self", &server_cfg, &cwd)
        .await
        .context("connect stdio server (self-spawn)")?;

    let tools = manager
        .request_typed_connected::<mcp::ListToolsRequest>("self", None)
        .await
        .context("tools/list")?;
    println!("tools/list result:");
    println!("{}", serde_json::to_string_pretty(&tools)?);

    let call = manager
        .request_typed_connected::<mcp::CallToolRequest>(
            "self",
            Some(mcp::CallToolRequestParams {
                name: "example.echo".to_string(),
                arguments: Some(serde_json::json!({ "message": "hello from stdio_self_spawn" })),
            }),
        )
        .await
        .context("tools/call example.echo")?;
    println!();
    println!("tools/call result:");
    println!("{}", serde_json::to_string_pretty(&call)?);

    let ping = manager
        .request_typed_connected::<mcp::PingRequest>("self", None)
        .await
        .context("ping")?;
    println!();
    println!("ping result:");
    println!("{}", serde_json::to_string_pretty(&ping)?);

    Ok(())
}

async fn server_main() -> Result<()> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let mut server = mcp_jsonrpc::Client::connect_io(stdin, stdout)
        .await
        .context("connect stdio jsonrpc peer")?;

    let mut requests = server
        .take_requests()
        .context("stdio server missing requests channel")?;
    let mut notifications = server
        .take_notifications()
        .context("stdio server missing notifications channel")?;

    loop {
        tokio::select! {
            Some(req) = requests.recv() => {
                match req.method.as_str() {
                    "initialize" => {
                        let _ = req.respond_ok(serde_json::json!({
                            "protocolVersion": MCP_PROTOCOL_VERSION,
                            "serverInfo": { "name": "stdio-self-spawn-server", "version": env!("CARGO_PKG_VERSION") },
                            "capabilities": {},
                        })).await;
                    }
                    "ping" => {
                        let _ = req.respond_ok(serde_json::json!({ "ok": true })).await;
                    }
                    "tools/list" => {
                        let _ = req.respond_ok(serde_json::json!({
                            "tools": [
                                {
                                    "name": "example.echo",
                                    "description": "Echo back the provided message",
                                    "inputSchema": {
                                        "type": "object",
                                        "properties": { "message": { "type": "string" } },
                                        "required": ["message"]
                                    }
                                }
                            ]
                        })).await;
                    }
                    "tools/call" => {
                        let tool_name = req
                            .params
                            .as_ref()
                            .and_then(|p| p.get("name"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        if tool_name != "example.echo" {
                            let _ = req.respond_ok(serde_json::json!({
                                "content": [],
                                "isError": true,
                                "structuredContent": { "error": format!("unknown tool: {tool_name}") }
                            })).await;
                            continue;
                        }

                        let message = req
                            .params
                            .as_ref()
                            .and_then(|p| p.get("arguments"))
                            .and_then(|v| v.get("message"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("");

                        let _ = req.respond_ok(serde_json::json!({
                            "content": [
                                { "type": "text", "text": message }
                            ]
                        })).await;
                    }
                    _ => {
                        let _ = req
                            .respond_error(
                                -32601,
                                format!("method not found: {}", req.method.as_str()),
                                None,
                            )
                            .await;
                    }
                }
            }
            Some(note) = notifications.recv() => {
                let _ = note;
            }
            else => break,
        }
    }

    Ok(())
}
