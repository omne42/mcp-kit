use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use mcp_kit::{MCP_PROTOCOL_VERSION, Manager, Root, ServerRequestContext, ServerRequestOutcome};

fn file_uri(path: &std::path::Path) -> String {
    let path = path.to_string_lossy().replace('\\', "/");
    format!("file:///{}", path.trim_start_matches('/'))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cwd = std::env::current_dir()?;

    let (client_stream, server_stream) = tokio::io::duplex(1024 * 64);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, server_write) = tokio::io::split(server_stream);

    let mut server = mcp_jsonrpc::Client::connect_io(server_read, server_write)
        .await
        .context("connect in-memory jsonrpc peer")?;
    let server_handle = server.handle();

    let mut server_requests = server
        .take_requests()
        .context("in-memory server missing requests channel")?;
    tokio::spawn(async move {
        while let Some(req) = server_requests.recv().await {
            match req.method.as_str() {
                "initialize" => {
                    let _ = req
                        .respond_ok(serde_json::json!({
                            "protocolVersion": MCP_PROTOCOL_VERSION,
                            "serverInfo": { "name": "in-memory-server", "version": "0.0.0" },
                            "capabilities": {},
                        }))
                        .await;
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
    });

    let mut server_notifications = server
        .take_notifications()
        .context("in-memory server missing notifications channel")?;
    tokio::spawn(async move {
        while let Some(note) = server_notifications.recv().await {
            let _ = note;
        }
    });

    let handler = Arc::new(|ctx: ServerRequestContext| {
        Box::pin(async move {
            match ctx.method.as_str() {
                "example/ping" => ServerRequestOutcome::Ok(serde_json::json!({
                    "ok": true,
                    "params": ctx.params,
                })),
                _ => ServerRequestOutcome::MethodNotFound,
            }
        }) as _
    });

    let mut manager = Manager::new(
        "in-memory-client",
        env!("CARGO_PKG_VERSION"),
        Duration::from_secs(5),
    )
    .with_roots(vec![Root {
        uri: file_uri(&cwd),
        name: Some("cwd".to_string()),
    }])
    .with_server_request_handler(handler);

    manager
        .connect_io("in-memory", client_read, client_write)
        .await
        .context("manager connect_io")?;

    let roots = server_handle
        .request_optional("roots/list", None)
        .await
        .context("server->client request: roots/list")?;
    println!("roots/list response:");
    println!("{}", serde_json::to_string_pretty(&roots)?);

    let ping = server_handle
        .request_optional(
            "example/ping",
            Some(serde_json::json!({ "hello": "world" })),
        )
        .await
        .context("server->client request: example/ping")?;
    println!();
    println!("example/ping response:");
    println!("{}", serde_json::to_string_pretty(&ping)?);

    Ok(())
}
