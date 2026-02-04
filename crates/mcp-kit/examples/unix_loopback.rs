#[cfg(unix)]
mod unix {
    use std::time::Duration;

    use anyhow::{Context, Result};
    use mcp_kit::{MCP_PROTOCOL_VERSION, Manager, ServerConfig, TrustMode, mcp};
    use tokio::net::UnixListener;

    fn print_help() {
        eprintln!("Usage:");
        eprintln!("  cargo run -p mcp-kit --example unix_loopback");
        eprintln!();
        eprintln!("Notes:");
        eprintln!(
            "  - This example is self-contained: it starts a local Unix socket server and connects to it."
        );
        eprintln!("  - transport=unix requires Trusted mode.");
    }

    pub async fn main() -> Result<()> {
        if std::env::args().any(|arg| arg == "--help" || arg == "-h") {
            print_help();
            return Ok(());
        }

        let cwd = std::env::current_dir()?;

        let tempdir = tempfile::Builder::new()
            .prefix("mcp-kit-unix-loopback-")
            .tempdir_in("/tmp")
            .context("create temp dir in /tmp")?;
        let socket_path = tempdir.path().join("mcp.sock");

        let listener = UnixListener::bind(&socket_path)
            .with_context(|| format!("bind unix socket {}", socket_path.display()))?;

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.context("accept unix connection")?;
            let (read, write) = stream.into_split();
            let server = mcp_jsonrpc::Client::connect_io(read, write)
                .await
                .context("connect unix jsonrpc peer")?;
            serve(server).await
        });

        let server_cfg = ServerConfig::unix(socket_path)?;

        let mut manager = Manager::new(
            "unix-loopback-client",
            env!("CARGO_PKG_VERSION"),
            Duration::from_secs(10),
        )
        .with_trust_mode(TrustMode::Trusted);
        manager
            .connect("unix", &server_cfg, &cwd)
            .await
            .context("connect unix server")?;

        let tools = manager
            .request_typed_connected::<mcp::ListToolsRequest>("unix", None)
            .await
            .context("tools/list")?;
        println!("tools/list result:");
        println!("{}", serde_json::to_string_pretty(&tools)?);

        let call = manager
            .request_typed_connected::<mcp::CallToolRequest>(
                "unix",
                Some(mcp::CallToolRequestParams {
                    name: "example.echo".to_string(),
                    arguments: Some(serde_json::json!({ "message": "hello from unix_loopback" })),
                }),
            )
            .await
            .context("tools/call example.echo")?;
        println!();
        println!("tools/call result:");
        println!("{}", serde_json::to_string_pretty(&call)?);

        let ping = manager
            .request_typed_connected::<mcp::PingRequest>("unix", None)
            .await
            .context("ping")?;
        println!();
        println!("ping result:");
        println!("{}", serde_json::to_string_pretty(&ping)?);

        drop(manager);
        server_task
            .await
            .context("join unix server task")?
            .context("unix server task failed")?;
        Ok(())
    }

    async fn serve(mut server: mcp_jsonrpc::Client) -> Result<()> {
        let mut requests = server
            .take_requests()
            .context("unix server missing requests channel")?;
        let mut notifications = server
            .take_notifications()
            .context("unix server missing notifications channel")?;

        loop {
            tokio::select! {
                Some(req) = requests.recv() => {
                    match req.method.as_str() {
                        "initialize" => {
                            let _ = req.respond_ok(serde_json::json!({
                                "protocolVersion": MCP_PROTOCOL_VERSION,
                                "serverInfo": { "name": "unix-loopback-server", "version": env!("CARGO_PKG_VERSION") },
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
}

#[cfg(unix)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    unix::main().await
}

#[cfg(not(unix))]
fn main() {
    eprintln!("unix_loopback example is only supported on unix.");
}
