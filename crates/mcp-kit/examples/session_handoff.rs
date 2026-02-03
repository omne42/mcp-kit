use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use mcp_kit::{MCP_PROTOCOL_VERSION, Manager, Root, ServerRequestContext, ServerRequestOutcome};

fn directory_uri(path: &std::path::Path) -> Result<String> {
    let url = reqwest::Url::from_directory_path(path).map_err(|()| {
        anyhow::anyhow!(
            "failed to convert directory path to file:// URI: {}",
            path.display()
        )
    })?;
    Ok(url.to_string())
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
                "ping" => {
                    let _ = req.respond_ok(serde_json::json!({ "ok": true })).await;
                }
                "tools/list" => {
                    let _ = req
                        .respond_ok(serde_json::json!({
                            "tools": [
                                { "name": "example.echo", "inputSchema": {} }
                            ],
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
                // Custom server→client request handler (in addition to built-in roots/list).
                "example/ping" => ServerRequestOutcome::Ok(serde_json::json!({
                    "ok": true,
                    "params": ctx.params,
                })),
                _ => ServerRequestOutcome::MethodNotFound,
            }
        }) as _
    });

    let mut manager = Manager::new(
        "session-handoff-client",
        env!("CARGO_PKG_VERSION"),
        Duration::from_secs(5),
    )
    .with_roots(vec![Root {
        uri: directory_uri(&cwd)?,
        name: Some("cwd".to_string()),
    }])
    .with_server_request_handler(handler);

    // `connect_io_session` initializes and then removes the connection from `Manager`,
    // returning an owned `Session` that can be handed to other modules.
    let session = manager
        .connect_io_session("in-memory", client_read, client_write)
        .await
        .context("manager connect_io_session")?;
    println!(
        "manager.is_connected(\"in-memory\") = {}",
        manager.is_connected("in-memory")
    );

    println!();
    println!("session.server_name = {}", session.server_name());
    println!(
        "session.initialize_result = {}",
        serde_json::to_string_pretty(session.initialize_result())?
    );

    println!();
    println!("client -> server: tools/list");
    println!(
        "{}",
        serde_json::to_string_pretty(&session.list_tools().await?)?
    );

    println!();
    println!("client -> server: ping");
    println!("{}", serde_json::to_string_pretty(&session.ping().await?)?);

    println!();
    println!("server -> client: roots/list");
    let roots = server_handle
        .request_optional("roots/list", None)
        .await
        .context("server->client request: roots/list")?;
    println!("{}", serde_json::to_string_pretty(&roots)?);

    println!();
    println!("server -> client: example/ping");
    let ping = server_handle
        .request_optional(
            "example/ping",
            Some(serde_json::json!({ "hello": "world" })),
        )
        .await
        .context("server->client request: example/ping")?;
    println!("{}", serde_json::to_string_pretty(&ping)?);

    Ok(())
}
