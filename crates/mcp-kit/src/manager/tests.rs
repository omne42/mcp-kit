use super::*;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

#[test]
fn roots_capability_is_inserted() {
    let mut capabilities = serde_json::json!({});
    ensure_roots_capability(&mut capabilities);
    assert!(capabilities.get("roots").is_some());
    assert!(capabilities.get("roots").unwrap().is_object());
}

#[test]
fn roots_capability_overwrites_non_object() {
    let mut capabilities = serde_json::json!({ "roots": true });
    ensure_roots_capability(&mut capabilities);
    assert!(capabilities.get("roots").unwrap().is_object());
}

#[test]
fn built_in_roots_list_requires_roots() {
    assert!(super::handlers::try_handle_built_in_request("roots/list", None).is_none());
}

#[test]
fn built_in_roots_list_returns_expected_shape() {
    let roots = Arc::new(vec![Root {
        uri: "file:///tmp".to_string(),
        name: Some("tmp".to_string()),
    }]);

    let result =
        super::handlers::try_handle_built_in_request("roots/list", Some(&roots)).expect("result");
    assert_eq!(
        result,
        serde_json::json!({
            "roots": [{ "uri": "file:///tmp", "name": "tmp" }]
        })
    );
}

#[test]
fn try_from_config_rejects_invalid_client_config() {
    let config = Config::new(
        crate::ClientConfig {
            capabilities: Some(serde_json::json!(1)),
            ..Default::default()
        },
        std::collections::BTreeMap::new(),
    );
    let err =
        match Manager::try_from_config(&config, "test-client", "0.0.0", Duration::from_secs(1)) {
            Ok(_) => panic!("expected error"),
            Err(err) => err,
        };
    assert!(err.to_string().contains("capabilities"), "err={err:#}");
}

#[test]
fn server_handler_timeout_counts_take_resets_counters() {
    let counts = ServerHandlerTimeoutCounts::default();
    let a = ServerName::parse("a").unwrap();
    let b = ServerName::parse("b").unwrap();

    counts
        .counter_for(&a)
        .fetch_add(2, std::sync::atomic::Ordering::Relaxed);
    counts
        .counter_for(&b)
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    assert_eq!(counts.count("a"), 2);
    assert_eq!(counts.count("b"), 1);

    let taken = counts.take_and_reset();
    assert_eq!(taken.get("a"), Some(&2));
    assert_eq!(taken.get("b"), Some(&1));

    assert_eq!(counts.count("a"), 0);
    assert_eq!(counts.count("b"), 0);

    let snap = counts.snapshot();
    assert_eq!(snap.get("a"), Some(&0));
    assert_eq!(snap.get("b"), Some(&0));
}

#[test]
fn server_handler_timeout_counts_remove_drops_entry() {
    let counts = ServerHandlerTimeoutCounts::default();
    let a = ServerName::parse("a").unwrap();
    let b = ServerName::parse("b").unwrap();

    counts
        .counter_for(&a)
        .fetch_add(2, std::sync::atomic::Ordering::Relaxed);
    counts
        .counter_for(&b)
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    counts.remove("a");

    assert_eq!(counts.count("a"), 0);
    assert_eq!(counts.count("b"), 1);

    let snap = counts.snapshot();
    assert!(!snap.contains_key("a"));
    assert_eq!(snap.get("b"), Some(&1));
}

#[test]
fn disconnect_clears_stale_timeout_counter_without_connection() {
    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted);

    let srv = ServerName::parse("srv").unwrap();
    manager
        .server_handler_timeout_counts
        .counter_for(&srv)
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(manager.server_handler_timeout_count("srv"), 1);

    assert!(!manager.disconnect("srv"));
    assert_eq!(manager.server_handler_timeout_count("srv"), 0);
    assert!(!manager.server_handler_timeout_counts().contains_key("srv"));
}

#[cfg(unix)]
#[tokio::test]
async fn disconnect_reaps_child_best_effort() {
    async fn pid_is_alive(pid: u32) -> bool {
        tokio::process::Command::new("sh")
            .arg("-c")
            .arg(format!("kill -0 {pid} 2>/dev/null"))
            .status()
            .await
            .is_ok_and(|status| status.success())
    }

    let (client_stream, _server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let client = mcp_jsonrpc::Client::connect_io(client_read, client_write)
        .await
        .unwrap();

    let mut cmd = tokio::process::Command::new("sh");
    cmd.arg("-c").arg("exec sleep 10");
    let child = cmd.spawn().unwrap();
    let child_id = child.id().expect("child id should exist");
    assert!(pid_is_alive(child_id).await);

    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted);
    let server_name = ServerName::parse("srv").unwrap();
    manager.conns.insert(
        server_name.clone(),
        Connection {
            child: Some(child),
            client,
            handler_tasks: Vec::new(),
        },
    );
    manager
        .init_results
        .insert(server_name, serde_json::json!({ "ok": true }));

    assert!(manager.disconnect("srv"));

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if !pid_is_alive(child_id).await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("disconnect should reap child process in best-effort mode");
}

#[tokio::test]
async fn disconnect_and_wait_clears_stale_timeout_counter_without_connection() {
    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted);

    let srv = ServerName::parse("srv").unwrap();
    manager
        .server_handler_timeout_counts
        .counter_for(&srv)
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(manager.server_handler_timeout_count("srv"), 1);

    let status = manager
        .disconnect_and_wait(
            "srv",
            Duration::from_millis(1),
            mcp_jsonrpc::WaitOnTimeout::ReturnError,
        )
        .await
        .unwrap();
    assert!(status.is_none());
    assert_eq!(manager.server_handler_timeout_count("srv"), 0);
    assert!(!manager.server_handler_timeout_counts().contains_key("srv"));
}

#[test]
fn disconnect_clears_stale_protocol_mismatch_without_connection() {
    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted);
    manager
        .protocol_version_mismatches
        .push(ProtocolVersionMismatch {
            server_name: ServerName::parse("srv").unwrap(),
            client_protocol_version: MCP_PROTOCOL_VERSION.to_string(),
            server_protocol_version: "1900-01-01".to_string(),
        });

    assert_eq!(manager.protocol_version_mismatches().len(), 1);
    assert!(!manager.disconnect("srv"));
    assert!(manager.protocol_version_mismatches().is_empty());
}

#[tokio::test]
async fn disconnect_and_wait_clears_stale_protocol_mismatch_without_connection() {
    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted);
    manager
        .protocol_version_mismatches
        .push(ProtocolVersionMismatch {
            server_name: ServerName::parse("srv").unwrap(),
            client_protocol_version: MCP_PROTOCOL_VERSION.to_string(),
            server_protocol_version: "1900-01-01".to_string(),
        });

    assert_eq!(manager.protocol_version_mismatches().len(), 1);
    let status = manager
        .disconnect_and_wait(
            "srv",
            Duration::from_millis(1),
            mcp_jsonrpc::WaitOnTimeout::ReturnError,
        )
        .await
        .unwrap();
    assert!(status.is_none());
    assert!(manager.protocol_version_mismatches().is_empty());
}

#[test]
fn expand_placeholders_supports_claude_plugin_root() {
    let cwd = Path::new("/tmp/plugin");
    let expanded = expand_placeholders_trusted("${CLAUDE_PLUGIN_ROOT}/servers/mcp", cwd).unwrap();
    assert_eq!(expanded, "/tmp/plugin/servers/mcp");
}

#[test]
fn expand_placeholders_supports_env_vars() {
    let Ok(path) = std::env::var("PATH") else {
        return;
    };
    let cwd = Path::new("/tmp/plugin");
    let expanded = expand_placeholders_trusted("prefix-${PATH}-suffix", cwd).unwrap();
    assert_eq!(expanded, format!("prefix-{path}-suffix"));
}

#[test]
fn expand_placeholders_rejects_invalid_name() {
    let cwd = Path::new("/tmp/plugin");
    let err = expand_placeholders_trusted("${BAD-NAME}", cwd).unwrap_err();
    assert!(err.to_string().contains("invalid placeholder name"));
}

#[tokio::test]
async fn connect_io_performs_initialize_and_exposes_result() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();

        let init_line = lines.next_line().await.unwrap().unwrap();
        let init_value: Value = serde_json::from_str(&init_line).unwrap();
        assert_eq!(init_value["jsonrpc"], "2.0");
        assert_eq!(init_value["method"], "initialize");
        let id = init_value["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "hello": "world" },
        });
        let mut response_line = serde_json::to_string(&response).unwrap();
        response_line.push('\n');
        server_write
            .write_all(response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let note_line = lines.next_line().await.unwrap().unwrap();
        let note_value: Value = serde_json::from_str(&note_line).unwrap();
        assert_eq!(note_value["jsonrpc"], "2.0");
        assert_eq!(note_value["method"], "notifications/initialized");
    });

    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted);
    manager
        .connect_io("srv", client_read, client_write)
        .await
        .unwrap();

    assert!(manager.is_connected("srv"));
    assert_eq!(
        manager.initialize_result("srv").unwrap(),
        &serde_json::json!({ "hello": "world" })
    );

    server_task.await.unwrap();

    let conn = manager.take_connection("srv");
    assert!(conn.is_some());
    assert!(!manager.is_connected("srv"));
    assert!(manager.initialize_result("srv").is_none());
}

#[tokio::test]
async fn server_request_handler_panic_is_bridged_to_error_response() {
    let (client_stream, server_stream) = tokio::io::duplex(2048);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();

        let init_line = lines.next_line().await.unwrap().unwrap();
        let init_value: Value = serde_json::from_str(&init_line).unwrap();
        assert_eq!(init_value["jsonrpc"], "2.0");
        assert_eq!(init_value["method"], "initialize");
        let id = init_value["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "hello": "world" },
        });
        let mut response_line = serde_json::to_string(&response).unwrap();
        response_line.push('\n');
        server_write
            .write_all(response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let note_line = lines.next_line().await.unwrap().unwrap();
        let note_value: Value = serde_json::from_str(&note_line).unwrap();
        assert_eq!(note_value["jsonrpc"], "2.0");
        assert_eq!(note_value["method"], "notifications/initialized");

        let sync_panic_request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 42,
            "method": "demo/boom_sync",
            "params": { "x": 1 },
        });
        let mut sync_panic_request_line = serde_json::to_string(&sync_panic_request).unwrap();
        sync_panic_request_line.push('\n');
        server_write
            .write_all(sync_panic_request_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let sync_panic_resp_line = tokio::time::timeout(Duration::from_secs(1), lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let sync_panic_resp_value: Value = serde_json::from_str(&sync_panic_resp_line).unwrap();

        assert_eq!(sync_panic_resp_value["jsonrpc"], "2.0");
        assert_eq!(sync_panic_resp_value["id"], 42);
        assert_eq!(sync_panic_resp_value["error"]["code"], -32000);
        assert!(
            sync_panic_resp_value["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains("panicked"),
            "{sync_panic_resp_value}"
        );

        let async_panic_request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 43,
            "method": "demo/boom",
            "params": { "x": 2 },
        });
        let mut async_panic_request_line = serde_json::to_string(&async_panic_request).unwrap();
        async_panic_request_line.push('\n');
        server_write
            .write_all(async_panic_request_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let async_panic_resp_line = tokio::time::timeout(Duration::from_secs(1), lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let async_panic_resp_value: Value = serde_json::from_str(&async_panic_resp_line).unwrap();

        assert_eq!(async_panic_resp_value["jsonrpc"], "2.0");
        assert_eq!(async_panic_resp_value["id"], 43);
        assert_eq!(async_panic_resp_value["error"]["code"], -32000);
        assert!(
            async_panic_resp_value["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains("panicked"),
            "{async_panic_resp_value}"
        );

        let ok_request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 44,
            "method": "demo/ok",
            "params": { "x": 3 },
        });
        let mut ok_request_line = serde_json::to_string(&ok_request).unwrap();
        ok_request_line.push('\n');
        server_write
            .write_all(ok_request_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let ok_resp_line = tokio::time::timeout(Duration::from_secs(1), lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let ok_resp_value: Value = serde_json::from_str(&ok_resp_line).unwrap();
        assert_eq!(ok_resp_value["jsonrpc"], "2.0");
        assert_eq!(ok_resp_value["id"], 44);
        assert_eq!(ok_resp_value["result"], serde_json::json!({ "ok": true }));
    });

    let handler: ServerRequestHandler = Arc::new(|ctx| {
        if ctx.method == "demo/boom_sync" {
            panic!("boom sync");
        }
        Box::pin(async move {
            match ctx.method.as_str() {
                "demo/boom" => panic!("boom"),
                "demo/ok" => ServerRequestOutcome::Ok(serde_json::json!({ "ok": true })),
                _ => ServerRequestOutcome::MethodNotFound,
            }
        })
    });

    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted)
        .with_server_request_handler(handler);
    manager
        .connect_io("srv", client_read, client_write)
        .await
        .unwrap();

    server_task.await.unwrap();
    assert!(manager.take_connection("srv").is_some());
}

#[tokio::test]
async fn request_connected_disconnects_after_protocol_error() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();

        let init_line = lines.next_line().await.unwrap().unwrap();
        let init_value: Value = serde_json::from_str(&init_line).unwrap();
        assert_eq!(init_value["jsonrpc"], "2.0");
        assert_eq!(init_value["method"], "initialize");
        let init_id = init_value["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": init_id,
            "result": { "hello": "world" },
        });
        let mut response_line = serde_json::to_string(&response).unwrap();
        response_line.push('\n');
        server_write
            .write_all(response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let note_line = lines.next_line().await.unwrap().unwrap();
        let note_value: Value = serde_json::from_str(&note_line).unwrap();
        assert_eq!(note_value["jsonrpc"], "2.0");
        assert_eq!(note_value["method"], "notifications/initialized");

        let ping_line = lines.next_line().await.unwrap().unwrap();
        let ping_value: Value = serde_json::from_str(&ping_line).unwrap();
        assert_eq!(ping_value["jsonrpc"], "2.0");
        assert_eq!(ping_value["method"], "ping");
        let ping_id = ping_value["id"].clone();

        // Send an intentionally malformed JSON-RPC response (wrong jsonrpc version)
        // to trigger a protocol error without necessarily closing the transport.
        let response = serde_json::json!({
            "jsonrpc": "1.0",
            "id": ping_id,
            "result": { "ok": true },
        });
        let mut response_line = serde_json::to_string(&response).unwrap();
        response_line.push('\n');
        server_write
            .write_all(response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();
    });

    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(1))
        .with_trust_mode(TrustMode::Trusted);
    manager
        .connect_io("srv", client_read, client_write)
        .await
        .unwrap();

    let err = manager
        .request_connected("srv", "ping", None)
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("mcp request failed: ping (server=srv)")
    );

    // Connection is dropped after Protocol/Io errors to avoid keeping a stale/broken client.
    assert!(!manager.is_connected("srv"));
    assert!(manager.initialize_result("srv").is_none());

    server_task.await.unwrap();
}

#[tokio::test]
async fn request_connected_accepts_trimmed_server_name() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();

        let init_line = lines.next_line().await.unwrap().unwrap();
        let init_value: Value = serde_json::from_str(&init_line).unwrap();
        assert_eq!(init_value["jsonrpc"], "2.0");
        assert_eq!(init_value["method"], "initialize");
        let init_id = init_value["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": init_id,
            "result": { "hello": "world" },
        });
        let mut response_line = serde_json::to_string(&response).unwrap();
        response_line.push('\n');
        server_write
            .write_all(response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let note_line = lines.next_line().await.unwrap().unwrap();
        let note_value: Value = serde_json::from_str(&note_line).unwrap();
        assert_eq!(note_value["jsonrpc"], "2.0");
        assert_eq!(note_value["method"], "notifications/initialized");

        let ping_line = lines.next_line().await.unwrap().unwrap();
        let ping_value: Value = serde_json::from_str(&ping_line).unwrap();
        assert_eq!(ping_value["jsonrpc"], "2.0");
        assert_eq!(ping_value["method"], "ping");
        let ping_id = ping_value["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": ping_id,
            "result": { "ok": true },
        });
        let mut response_line = serde_json::to_string(&response).unwrap();
        response_line.push('\n');
        server_write
            .write_all(response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let eof = lines.next_line().await.unwrap();
        assert!(eof.is_none(), "expected EOF after disconnect");
    });

    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(1))
        .with_trust_mode(TrustMode::Trusted);
    manager
        .connect_io(" srv ", client_read, client_write)
        .await
        .unwrap();

    assert!(manager.is_connected("srv"));
    assert!(manager.is_connected(" srv "));
    assert_eq!(
        manager.initialize_result(" srv ").unwrap(),
        &serde_json::json!({ "hello": "world" })
    );
    assert_eq!(
        manager
            .request_connected(" srv ", "ping", None)
            .await
            .unwrap(),
        serde_json::json!({ "ok": true })
    );

    let status = manager
        .disconnect_and_wait(
            " srv ",
            Duration::from_secs(1),
            mcp_jsonrpc::WaitOnTimeout::ReturnError,
        )
        .await
        .unwrap();
    assert!(status.is_none());

    server_task.await.unwrap();
}

#[tokio::test]
async fn request_connected_timeout_late_response_does_not_disconnect() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();

        let init_line = lines.next_line().await.unwrap().unwrap();
        let init_value: Value = serde_json::from_str(&init_line).unwrap();
        assert_eq!(init_value["jsonrpc"], "2.0");
        assert_eq!(init_value["method"], "initialize");
        let init_id = init_value["id"].clone();

        let init_response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": init_id,
            "result": { "hello": "world" },
        });
        let mut init_response_line = serde_json::to_string(&init_response).unwrap();
        init_response_line.push('\n');
        server_write
            .write_all(init_response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let note_line = lines.next_line().await.unwrap().unwrap();
        let note_value: Value = serde_json::from_str(&note_line).unwrap();
        assert_eq!(note_value["jsonrpc"], "2.0");
        assert_eq!(note_value["method"], "notifications/initialized");

        let slow_line = lines.next_line().await.unwrap().unwrap();
        let slow_value: Value = serde_json::from_str(&slow_line).unwrap();
        assert_eq!(slow_value["method"], "slow");
        let slow_id = slow_value["id"].clone();

        tokio::time::sleep(Duration::from_millis(80)).await;
        let slow_response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": slow_id,
            "result": { "slow": true },
        });
        let mut slow_response_line = serde_json::to_string(&slow_response).unwrap();
        slow_response_line.push('\n');
        server_write
            .write_all(slow_response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let fast_line = lines.next_line().await.unwrap().unwrap();
        let fast_value: Value = serde_json::from_str(&fast_line).unwrap();
        assert_eq!(fast_value["method"], "fast");
        let fast_id = fast_value["id"].clone();

        let fast_response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": fast_id,
            "result": { "ok": true },
        });
        let mut fast_response_line = serde_json::to_string(&fast_response).unwrap();
        fast_response_line.push('\n');
        server_write
            .write_all(fast_response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let eof = lines.next_line().await.unwrap();
        assert!(eof.is_none(), "expected EOF after disconnect");
    });

    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_millis(20))
        .with_trust_mode(TrustMode::Trusted);
    manager
        .connect_io("srv", client_read, client_write)
        .await
        .unwrap();

    let err = manager
        .request_connected("srv", "slow", None)
        .await
        .expect_err("slow request should time out");
    assert!(err.to_string().contains("timed out"));

    tokio::time::sleep(Duration::from_millis(120)).await;

    let fast = manager
        .request_connected("srv", "fast", None)
        .await
        .expect("connection should remain usable after late response");
    assert_eq!(fast, serde_json::json!({ "ok": true }));
    assert!(manager.is_connected("srv"));

    let status = manager
        .disconnect_and_wait(
            "srv",
            Duration::from_secs(1),
            mcp_jsonrpc::WaitOnTimeout::ReturnError,
        )
        .await
        .unwrap();
    assert!(status.is_none());

    server_task.await.unwrap();
}

#[tokio::test]
async fn connect_io_session_returns_session_and_supports_requests() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();

        let init_line = lines.next_line().await.unwrap().unwrap();
        let init_value: Value = serde_json::from_str(&init_line).unwrap();
        assert_eq!(init_value["jsonrpc"], "2.0");
        assert_eq!(init_value["method"], "initialize");
        let id = init_value["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "hello": "world" },
        });
        let mut response_line = serde_json::to_string(&response).unwrap();
        response_line.push('\n');
        server_write
            .write_all(response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let note_line = lines.next_line().await.unwrap().unwrap();
        let note_value: Value = serde_json::from_str(&note_line).unwrap();
        assert_eq!(note_value["jsonrpc"], "2.0");
        assert_eq!(note_value["method"], "notifications/initialized");
        assert!(note_value.get("params").is_none());

        let ping_line = lines.next_line().await.unwrap().unwrap();
        let ping_value: Value = serde_json::from_str(&ping_line).unwrap();
        assert_eq!(ping_value["jsonrpc"], "2.0");
        assert_eq!(ping_value["method"], "ping");
        assert!(ping_value.get("params").is_none());
        let ping_id = ping_value["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": ping_id,
            "result": { "ok": true },
        });
        let mut response_line = serde_json::to_string(&response).unwrap();
        response_line.push('\n');
        server_write
            .write_all(response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();
    });

    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted);
    let session = manager
        .connect_io_session("srv", client_read, client_write)
        .await
        .unwrap();

    assert!(!manager.is_connected("srv"));
    assert_eq!(
        session.initialize_result(),
        &serde_json::json!({ "hello": "world" })
    );
    assert_eq!(
        session
            .request_typed::<crate::mcp::PingRequest>(None)
            .await
            .unwrap(),
        serde_json::json!({ "ok": true })
    );

    server_task.await.unwrap();
}

#[tokio::test]
async fn session_notify_timeout_is_bounded_when_close_path_blocks() {
    use std::io;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll};

    struct BlockingWrite {
        entered: Arc<AtomicBool>,
    }

    impl tokio::io::AsyncWrite for BlockingWrite {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.entered.store(true, Ordering::Relaxed);
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.entered.store(true, Ordering::Relaxed);
            Poll::Pending
        }
    }

    let entered = Arc::new(AtomicBool::new(false));
    let (client_stream, _server_stream) = tokio::io::duplex(64);
    let (client_read, _client_write) = tokio::io::split(client_stream);
    let client = mcp_jsonrpc::Client::connect_io(
        client_read,
        BlockingWrite {
            entered: entered.clone(),
        },
    )
    .await
    .unwrap();

    let connection = Connection {
        child: None,
        client,
        handler_tasks: Vec::new(),
    };
    let session = crate::Session::new(
        ServerName::parse("srv").unwrap(),
        connection,
        serde_json::json!({}),
        Duration::from_millis(20),
    );

    let started = tokio::time::Instant::now();
    let err = session
        .notify("demo/notify", Some(serde_json::json!({ "x": 1 })))
        .await
        .expect_err("notify should time out");

    assert!(entered.load(Ordering::Relaxed));
    assert!(
        started.elapsed() < Duration::from_millis(200),
        "notify timeout should be bounded, elapsed={:?}",
        started.elapsed()
    );
    assert!(
        contains_wait_timeout(&err),
        "timeout should preserve structured wait-timeout error, err={err:#}"
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn session_notify_timeout_returns_without_waiting_for_close_budget() {
    use std::io;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll};

    struct BlockingWrite {
        entered: Arc<AtomicBool>,
    }

    impl tokio::io::AsyncWrite for BlockingWrite {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.entered.store(true, Ordering::Relaxed);
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.entered.store(true, Ordering::Relaxed);
            Poll::Pending
        }
    }

    let entered = Arc::new(AtomicBool::new(false));
    let (client_stream, _server_stream) = tokio::io::duplex(64);
    let (client_read, _client_write) = tokio::io::split(client_stream);
    let client = mcp_jsonrpc::Client::connect_io(
        client_read,
        BlockingWrite {
            entered: entered.clone(),
        },
    )
    .await
    .unwrap();

    let connection = Connection {
        child: None,
        client,
        handler_tasks: Vec::new(),
    };
    let session = crate::Session::new(
        ServerName::parse("srv").unwrap(),
        connection,
        serde_json::json!({}),
        Duration::from_millis(20),
    );

    let started = tokio::time::Instant::now();
    let err = session
        .notify("demo/notify", Some(serde_json::json!({ "x": 1 })))
        .await
        .expect_err("notify should time out");

    assert!(entered.load(Ordering::Relaxed));
    assert!(
        started.elapsed() < Duration::from_millis(30),
        "notify timeout should not wait for close budget, elapsed={:?}",
        started.elapsed()
    );
    assert!(
        contains_wait_timeout(&err),
        "timeout should preserve structured wait-timeout error, err={err:#}"
    );
}

#[tokio::test]
async fn connect_io_session_without_handler_timeout_does_not_track_timeout_counter() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();

        let init_line = lines.next_line().await.unwrap().unwrap();
        let init_value: Value = serde_json::from_str(&init_line).unwrap();
        assert_eq!(init_value["jsonrpc"], "2.0");
        assert_eq!(init_value["method"], "initialize");
        let id = init_value["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "protocolVersion": MCP_PROTOCOL_VERSION },
        });
        let mut response_line = serde_json::to_string(&response).unwrap();
        response_line.push('\n');
        server_write
            .write_all(response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let note_line = lines.next_line().await.unwrap().unwrap();
        let note_value: Value = serde_json::from_str(&note_line).unwrap();
        assert_eq!(note_value["jsonrpc"], "2.0");
        assert_eq!(note_value["method"], "notifications/initialized");
    });

    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted);
    let session = manager
        .connect_io_session("srv", client_read, client_write)
        .await
        .unwrap();

    assert_eq!(manager.server_handler_timeout_count("srv"), 0);
    assert!(!manager.server_handler_timeout_counts().contains_key("srv"));

    session.wait().await.unwrap();
    server_task.await.unwrap();
}

#[tokio::test]
async fn session_request_timeout_late_response_keeps_session_usable() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();

        let init_line = lines.next_line().await.unwrap().unwrap();
        let init_value: Value = serde_json::from_str(&init_line).unwrap();
        assert_eq!(init_value["jsonrpc"], "2.0");
        assert_eq!(init_value["method"], "initialize");
        let init_id = init_value["id"].clone();

        let init_response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": init_id,
            "result": { "hello": "world" },
        });
        let mut init_response_line = serde_json::to_string(&init_response).unwrap();
        init_response_line.push('\n');
        server_write
            .write_all(init_response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let note_line = lines.next_line().await.unwrap().unwrap();
        let note_value: Value = serde_json::from_str(&note_line).unwrap();
        assert_eq!(note_value["jsonrpc"], "2.0");
        assert_eq!(note_value["method"], "notifications/initialized");

        let slow_line = lines.next_line().await.unwrap().unwrap();
        let slow_value: Value = serde_json::from_str(&slow_line).unwrap();
        assert_eq!(slow_value["method"], "slow");
        let slow_id = slow_value["id"].clone();

        tokio::time::sleep(Duration::from_millis(80)).await;
        let slow_response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": slow_id,
            "result": { "slow": true },
        });
        let mut slow_response_line = serde_json::to_string(&slow_response).unwrap();
        slow_response_line.push('\n');
        server_write
            .write_all(slow_response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let fast_line = lines.next_line().await.unwrap().unwrap();
        let fast_value: Value = serde_json::from_str(&fast_line).unwrap();
        assert_eq!(fast_value["method"], "fast");
        let fast_id = fast_value["id"].clone();

        let fast_response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": fast_id,
            "result": { "ok": true },
        });
        let mut fast_response_line = serde_json::to_string(&fast_response).unwrap();
        fast_response_line.push('\n');
        server_write
            .write_all(fast_response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let eof = lines.next_line().await.unwrap();
        assert!(eof.is_none(), "expected EOF after session wait");
    });

    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted);
    let session = manager
        .connect_io_session("srv", client_read, client_write)
        .await
        .unwrap()
        .with_timeout(Duration::from_millis(20));

    let err = session
        .request("slow", None)
        .await
        .expect_err("slow session request should time out");
    assert!(err.to_string().contains("timed out"));

    tokio::time::sleep(Duration::from_millis(120)).await;

    let fast = session
        .request("fast", None)
        .await
        .expect("session should remain usable after late response");
    assert_eq!(fast, serde_json::json!({ "ok": true }));

    let status = session.wait().await.unwrap();
    assert!(status.is_none());
    server_task.await.unwrap();
}

#[tokio::test]
async fn notify_connected_timeout_disconnects_connection() {
    let (client_stream, server_stream) = tokio::io::duplex(256);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();

        let init_line = lines.next_line().await.unwrap().unwrap();
        let init_value: Value = serde_json::from_str(&init_line).unwrap();
        assert_eq!(init_value["jsonrpc"], "2.0");
        assert_eq!(init_value["method"], "initialize");
        let init_id = init_value["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": init_id,
            "result": { "protocolVersion": MCP_PROTOCOL_VERSION },
        });
        let mut response_line = serde_json::to_string(&response).unwrap();
        response_line.push('\n');
        server_write
            .write_all(response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let note_line = lines.next_line().await.unwrap().unwrap();
        let note_value: Value = serde_json::from_str(&note_line).unwrap();
        assert_eq!(note_value["jsonrpc"], "2.0");
        assert_eq!(note_value["method"], "notifications/initialized");

        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_millis(20))
        .with_trust_mode(TrustMode::Trusted);
    manager
        .connect_io("srv", client_read, client_write)
        .await
        .unwrap();

    let err = manager
        .notify_connected(
            "srv",
            "demo/notify",
            Some(serde_json::json!({ "blob": "x".repeat(256 * 1024) })),
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("timed out"),
        "unexpected error: {err:#}"
    );
    assert!(
        !manager.is_connected("srv"),
        "notification timeout should close potentially corrupted connection"
    );

    server_task.await.unwrap();
}

#[tokio::test]
async fn session_notify_timeout_closes_client() {
    let (client_stream, server_stream) = tokio::io::duplex(256);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();

        let init_line = lines.next_line().await.unwrap().unwrap();
        let init_value: Value = serde_json::from_str(&init_line).unwrap();
        assert_eq!(init_value["method"], "initialize");
        let init_id = init_value["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": init_id,
            "result": { "protocolVersion": MCP_PROTOCOL_VERSION },
        });
        let mut response_line = serde_json::to_string(&response).unwrap();
        response_line.push('\n');
        server_write
            .write_all(response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let init_note = lines.next_line().await.unwrap().unwrap();
        let init_note_value: Value = serde_json::from_str(&init_note).unwrap();
        assert_eq!(init_note_value["method"], "notifications/initialized");

        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_millis(20))
        .with_trust_mode(TrustMode::Trusted);
    let session = manager
        .connect_io_session("srv", client_read, client_write)
        .await
        .unwrap()
        .with_timeout(Duration::from_millis(20));

    let err = session
        .notify(
            "demo/notify",
            Some(serde_json::json!({ "blob": "x".repeat(256 * 1024) })),
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("timed out"),
        "unexpected error: {err:#}"
    );

    tokio::time::timeout(Duration::from_secs(1), async {
        while !session.connection().client().handle().is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    server_task.await.unwrap();
}

#[tokio::test]
async fn connect_io_rejects_initialize_protocol_version_mismatch() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();

        let init_line = lines.next_line().await.unwrap().unwrap();
        let init_value: Value = serde_json::from_str(&init_line).unwrap();
        assert_eq!(init_value["jsonrpc"], "2.0");
        assert_eq!(init_value["method"], "initialize");
        let id = init_value["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "protocolVersion": "1900-01-01" },
        });
        let mut response_line = serde_json::to_string(&response).unwrap();
        response_line.push('\n');
        server_write
            .write_all(response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();
    });

    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted);
    let err = match manager
        .connect_io_session("srv", client_read, client_write)
        .await
    {
        Ok(_) => panic!("expected protocolVersion mismatch"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("protocolVersion mismatch"));
    assert_eq!(manager.server_handler_timeout_count("srv"), 0);
    assert!(
        !manager.server_handler_timeout_counts().contains_key("srv"),
        "failed initialize should not retain timeout counter entry"
    );

    server_task.await.unwrap();
}

#[tokio::test]
async fn connect_io_allows_initialize_protocol_version_mismatch_when_configured() {
    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted)
        .with_protocol_version_check(ProtocolVersionCheck::Warn);

    {
        let (client_stream, server_stream) = tokio::io::duplex(1024);
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (server_read, mut server_write) = tokio::io::split(server_stream);

        let server_task = tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(server_read).lines();

            let init_line = lines.next_line().await.unwrap().unwrap();
            let init_value: Value = serde_json::from_str(&init_line).unwrap();
            assert_eq!(init_value["jsonrpc"], "2.0");
            assert_eq!(init_value["method"], "initialize");
            let id = init_value["id"].clone();

            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "protocolVersion": "1900-01-01", "hello": "world" },
            });
            let mut response_line = serde_json::to_string(&response).unwrap();
            response_line.push('\n');
            server_write
                .write_all(response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let note_line = lines.next_line().await.unwrap().unwrap();
            let note_value: Value = serde_json::from_str(&note_line).unwrap();
            assert_eq!(note_value["jsonrpc"], "2.0");
            assert_eq!(note_value["method"], "notifications/initialized");
        });

        let session = manager
            .connect_io_session("srv", client_read, client_write)
            .await
            .unwrap();
        assert_eq!(
            session.initialize_result(),
            &serde_json::json!({ "protocolVersion": "1900-01-01", "hello": "world" })
        );
        assert_eq!(manager.protocol_version_mismatches().len(), 1);
        assert_eq!(
            manager.protocol_version_mismatches()[0],
            ProtocolVersionMismatch {
                server_name: ServerName::parse("srv").unwrap(),
                client_protocol_version: MCP_PROTOCOL_VERSION.to_string(),
                server_protocol_version: "1900-01-01".to_string(),
            }
        );

        session.wait().await.unwrap();
        server_task.await.unwrap();
    }

    // A second connection should not grow the mismatch list unboundedly.
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();

        let init_line = lines.next_line().await.unwrap().unwrap();
        let init_value: Value = serde_json::from_str(&init_line).unwrap();
        assert_eq!(init_value["jsonrpc"], "2.0");
        assert_eq!(init_value["method"], "initialize");
        let id = init_value["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "protocolVersion": "1900-01-01", "hello": "world" },
        });
        let mut response_line = serde_json::to_string(&response).unwrap();
        response_line.push('\n');
        server_write
            .write_all(response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let note_line = lines.next_line().await.unwrap().unwrap();
        let note_value: Value = serde_json::from_str(&note_line).unwrap();
        assert_eq!(note_value["jsonrpc"], "2.0");
        assert_eq!(note_value["method"], "notifications/initialized");
    });

    let session = manager
        .connect_io_session("srv", client_read, client_write)
        .await
        .unwrap();
    assert_eq!(manager.protocol_version_mismatches().len(), 1);
    session.wait().await.unwrap();

    server_task.await.unwrap();
}

#[tokio::test]
async fn initialize_failure_clears_protocol_mismatch_state() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();

        let init_line = lines.next_line().await.unwrap().unwrap();
        let init_value: Value = serde_json::from_str(&init_line).unwrap();
        assert_eq!(init_value["jsonrpc"], "2.0");
        assert_eq!(init_value["method"], "initialize");
        let id = init_value["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "protocolVersion": "1900-01-01" },
        });
        let mut response_line = serde_json::to_string(&response).unwrap();
        response_line.push('\n');
        server_write
            .write_all(response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();
        drop(server_write);
    });

    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted)
        .with_protocol_version_check(ProtocolVersionCheck::Warn);
    let err = match manager
        .connect_io_session("srv", client_read, client_write)
        .await
    {
        Ok(_) => panic!("expected connect_io_session failure"),
        Err(err) => err,
    };
    let err_chain = format!("{err:#}");
    assert!(
        err_chain.contains("mcp initialized notification failed"),
        "unexpected error: {err_chain}"
    );
    assert!(
        manager.protocol_version_mismatches().is_empty(),
        "failed initialize should not retain mismatch state"
    );

    server_task.await.unwrap();
}

#[tokio::test]
async fn protocol_version_mismatch_is_cleared_after_matching_reconnect() {
    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted)
        .with_protocol_version_check(ProtocolVersionCheck::Warn);

    {
        let (client_stream, server_stream) = tokio::io::duplex(1024);
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (server_read, mut server_write) = tokio::io::split(server_stream);

        let server_task = tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(server_read).lines();

            let init_line = lines.next_line().await.unwrap().unwrap();
            let init_value: Value = serde_json::from_str(&init_line).unwrap();
            assert_eq!(init_value["method"], "initialize");
            let id = init_value["id"].clone();

            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "protocolVersion": "1900-01-01" },
            });
            let mut response_line = serde_json::to_string(&response).unwrap();
            response_line.push('\n');
            server_write
                .write_all(response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let note_line = lines.next_line().await.unwrap().unwrap();
            let note_value: Value = serde_json::from_str(&note_line).unwrap();
            assert_eq!(note_value["method"], "notifications/initialized");
        });

        let session = manager
            .connect_io_session("srv", client_read, client_write)
            .await
            .unwrap();
        assert_eq!(manager.protocol_version_mismatches().len(), 1);
        session.wait().await.unwrap();
        server_task.await.unwrap();
    }

    {
        let (client_stream, server_stream) = tokio::io::duplex(1024);
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (server_read, mut server_write) = tokio::io::split(server_stream);

        let server_task = tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(server_read).lines();

            let init_line = lines.next_line().await.unwrap().unwrap();
            let init_value: Value = serde_json::from_str(&init_line).unwrap();
            assert_eq!(init_value["method"], "initialize");
            let id = init_value["id"].clone();

            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "protocolVersion": MCP_PROTOCOL_VERSION },
            });
            let mut response_line = serde_json::to_string(&response).unwrap();
            response_line.push('\n');
            server_write
                .write_all(response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let note_line = lines.next_line().await.unwrap().unwrap();
            let note_value: Value = serde_json::from_str(&note_line).unwrap();
            assert_eq!(note_value["method"], "notifications/initialized");
        });

        let session = manager
            .connect_io_session("srv", client_read, client_write)
            .await
            .unwrap();
        assert!(
            manager.protocol_version_mismatches().is_empty(),
            "matching reconnect should clear stale mismatch entry"
        );
        session.wait().await.unwrap();
        server_task.await.unwrap();
    }
}

#[tokio::test]
async fn disconnect_clears_protocol_version_mismatch_entry() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();

        let init_line = lines.next_line().await.unwrap().unwrap();
        let init_value: Value = serde_json::from_str(&init_line).unwrap();
        assert_eq!(init_value["method"], "initialize");
        let id = init_value["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "protocolVersion": "1900-01-01" },
        });
        let mut response_line = serde_json::to_string(&response).unwrap();
        response_line.push('\n');
        server_write
            .write_all(response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let note_line = lines.next_line().await.unwrap().unwrap();
        let note_value: Value = serde_json::from_str(&note_line).unwrap();
        assert_eq!(note_value["method"], "notifications/initialized");

        let eof = lines.next_line().await.unwrap();
        assert!(eof.is_none(), "expected EOF after disconnect");
    });

    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted)
        .with_protocol_version_check(ProtocolVersionCheck::Warn);
    manager
        .connect_io("srv", client_read, client_write)
        .await
        .unwrap();
    assert_eq!(manager.protocol_version_mismatches().len(), 1);

    let status = manager
        .disconnect_and_wait(
            "srv",
            Duration::from_secs(1),
            mcp_jsonrpc::WaitOnTimeout::ReturnError,
        )
        .await
        .unwrap();
    assert!(status.is_none());
    assert!(
        manager.protocol_version_mismatches().is_empty(),
        "disconnect should clear mismatch entry"
    );

    server_task.await.unwrap();
}

#[tokio::test]
async fn take_connection_clears_protocol_version_mismatch_entry() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();

        let init_line = lines.next_line().await.unwrap().unwrap();
        let init_value: Value = serde_json::from_str(&init_line).unwrap();
        assert_eq!(init_value["method"], "initialize");
        let id = init_value["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "protocolVersion": "1900-01-01" },
        });
        let mut response_line = serde_json::to_string(&response).unwrap();
        response_line.push('\n');
        server_write
            .write_all(response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let note_line = lines.next_line().await.unwrap().unwrap();
        let note_value: Value = serde_json::from_str(&note_line).unwrap();
        assert_eq!(note_value["method"], "notifications/initialized");

        let eof = lines.next_line().await.unwrap();
        assert!(eof.is_none(), "expected EOF after take_connection wait");
    });

    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted)
        .with_protocol_version_check(ProtocolVersionCheck::Warn);
    manager
        .connect_io("srv", client_read, client_write)
        .await
        .unwrap();
    assert_eq!(manager.protocol_version_mismatches().len(), 1);

    let conn = manager
        .take_connection("srv")
        .expect("connection should exist");
    assert!(
        manager.protocol_version_mismatches().is_empty(),
        "take_connection should clear mismatch entry"
    );

    let status = conn.wait().await.unwrap();
    assert!(status.is_none());
    server_task.await.unwrap();
}

#[tokio::test]
async fn take_session_and_clear_state_clears_manager_state() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();

        let init_line = lines.next_line().await.unwrap().unwrap();
        let init_value: Value = serde_json::from_str(&init_line).unwrap();
        assert_eq!(init_value["method"], "initialize");
        let id = init_value["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "protocolVersion": "1900-01-01" },
        });
        let mut response_line = serde_json::to_string(&response).unwrap();
        response_line.push('\n');
        server_write
            .write_all(response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let note_line = lines.next_line().await.unwrap().unwrap();
        let note_value: Value = serde_json::from_str(&note_line).unwrap();
        assert_eq!(note_value["method"], "notifications/initialized");

        let eof = lines.next_line().await.unwrap();
        assert!(
            eof.is_none(),
            "expected EOF after take_session_and_clear_state wait"
        );
    });

    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted)
        .with_protocol_version_check(ProtocolVersionCheck::Warn);
    manager
        .connect_io("srv", client_read, client_write)
        .await
        .unwrap();
    assert_eq!(manager.protocol_version_mismatches().len(), 1);

    let srv = ServerName::parse("srv").unwrap();
    manager
        .server_handler_timeout_counts
        .counter_for(&srv)
        .fetch_add(2, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(manager.server_handler_timeout_count("srv"), 2);

    let session = manager
        .take_session_and_clear_state(" srv ")
        .expect("session should exist");
    assert!(
        manager.protocol_version_mismatches().is_empty(),
        "take_session_and_clear_state should clear mismatch entry"
    );
    assert_eq!(manager.server_handler_timeout_count("srv"), 0);
    assert!(!manager.server_handler_timeout_counts().contains_key("srv"));

    let status = session.wait().await.unwrap();
    assert!(status.is_none());
    server_task.await.unwrap();
}

#[test]
fn take_session_and_clear_state_without_connection_clears_stale_state() {
    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted);
    manager
        .protocol_version_mismatches
        .push(ProtocolVersionMismatch {
            server_name: ServerName::parse("srv").unwrap(),
            client_protocol_version: MCP_PROTOCOL_VERSION.to_string(),
            server_protocol_version: "1900-01-01".to_string(),
        });

    let srv = ServerName::parse("srv").unwrap();
    manager
        .server_handler_timeout_counts
        .counter_for(&srv)
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(manager.server_handler_timeout_count("srv"), 1);

    assert!(manager.take_session_and_clear_state("srv").is_none());
    assert!(manager.protocol_version_mismatches().is_empty());
    assert_eq!(manager.server_handler_timeout_count("srv"), 0);
    assert!(!manager.server_handler_timeout_counts().contains_key("srv"));
}

#[tokio::test]
async fn take_session_keeps_connection_when_init_result_is_missing() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();

        let init_line = lines.next_line().await.unwrap().unwrap();
        let init_value: Value = serde_json::from_str(&init_line).unwrap();
        assert_eq!(init_value["method"], "initialize");
        let id = init_value["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "protocolVersion": MCP_PROTOCOL_VERSION },
        });
        let mut response_line = serde_json::to_string(&response).unwrap();
        response_line.push('\n');
        server_write
            .write_all(response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let note_line = lines.next_line().await.unwrap().unwrap();
        let note_value: Value = serde_json::from_str(&note_line).unwrap();
        assert_eq!(note_value["method"], "notifications/initialized");

        let eof = lines.next_line().await.unwrap();
        assert!(eof.is_none(), "expected EOF after explicit connection wait");
    });

    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted);
    manager
        .connect_io("srv", client_read, client_write)
        .await
        .unwrap();
    assert!(manager.is_connected("srv"));

    manager.init_results.remove("srv");
    assert!(
        manager.take_session("srv").is_none(),
        "take_session should fail when initialize result is missing"
    );
    assert!(
        manager.is_connected("srv"),
        "connection should remain cached when initialize result is missing"
    );

    let conn = manager
        .take_connection("srv")
        .expect("connection should remain available");
    let status = conn.wait().await.unwrap();
    assert!(status.is_none());

    server_task.await.unwrap();
}

#[tokio::test]
async fn server_notification_handler_timeout_is_counted() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();

        let init_line = lines.next_line().await.unwrap().unwrap();
        let init_value: Value = serde_json::from_str(&init_line).unwrap();
        assert_eq!(init_value["jsonrpc"], "2.0");
        assert_eq!(init_value["method"], "initialize");
        let id = init_value["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "protocolVersion": MCP_PROTOCOL_VERSION },
        });
        let mut response_line = serde_json::to_string(&response).unwrap();
        response_line.push('\n');
        server_write
            .write_all(response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let note_line = lines.next_line().await.unwrap().unwrap();
        let note_value: Value = serde_json::from_str(&note_line).unwrap();
        assert_eq!(note_value["jsonrpc"], "2.0");
        assert_eq!(note_value["method"], "notifications/initialized");

        let note = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "demo/notify",
            "params": {},
        });
        let mut note_line = serde_json::to_string(&note).unwrap();
        note_line.push('\n');
        server_write.write_all(note_line.as_bytes()).await.unwrap();
        server_write.flush().await.unwrap();
    });

    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted)
        .with_server_notification_handler(Arc::new(|_ctx| {
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
            })
        }))
        .with_server_handler_timeout(Duration::from_millis(10));
    let session = manager
        .connect_io_session("srv", client_read, client_write)
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if manager.server_handler_timeout_count("srv") >= 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    session.wait().await.unwrap();
    server_task.await.unwrap();
}

#[tokio::test]
async fn connect_io_reconnects_when_existing_connection_is_closed() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();

        let init_line = lines.next_line().await.unwrap().unwrap();
        let init_value: Value = serde_json::from_str(&init_line).unwrap();
        assert_eq!(init_value["jsonrpc"], "2.0");
        assert_eq!(init_value["method"], "initialize");
        let id = init_value["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "hello": "world" },
        });
        let mut response_line = serde_json::to_string(&response).unwrap();
        response_line.push('\n');
        server_write
            .write_all(response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let note_line = lines.next_line().await.unwrap().unwrap();
        let note_value: Value = serde_json::from_str(&note_line).unwrap();
        assert_eq!(note_value["jsonrpc"], "2.0");
        assert_eq!(note_value["method"], "notifications/initialized");
    });

    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted);
    manager
        .connect_io("srv", client_read, client_write)
        .await
        .unwrap();

    server_task.await.unwrap();

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if manager
                .conns
                .get("srv")
                .expect("srv conn exists")
                .client
                .handle()
                .is_closed()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("client marked closed");

    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();

        let init_line = lines.next_line().await.unwrap().unwrap();
        let init_value: Value = serde_json::from_str(&init_line).unwrap();
        assert_eq!(init_value["jsonrpc"], "2.0");
        assert_eq!(init_value["method"], "initialize");
        let id = init_value["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "hello": "world" },
        });
        let mut response_line = serde_json::to_string(&response).unwrap();
        response_line.push('\n');
        server_write
            .write_all(response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let note_line = lines.next_line().await.unwrap().unwrap();
        let note_value: Value = serde_json::from_str(&note_line).unwrap();
        assert_eq!(note_value["jsonrpc"], "2.0");
        assert_eq!(note_value["method"], "notifications/initialized");
    });

    manager
        .connect_io("srv", client_read, client_write)
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(1), server_task)
        .await
        .expect("server task completed")
        .expect("server task ok");
}

#[tokio::test]
async fn connect_io_with_spaced_name_does_not_replace_existing_connection() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let server1_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();

        let init_line = lines.next_line().await.unwrap().unwrap();
        let init_value: Value = serde_json::from_str(&init_line).unwrap();
        assert_eq!(init_value["jsonrpc"], "2.0");
        assert_eq!(init_value["method"], "initialize");
        let id = init_value["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "protocolVersion": MCP_PROTOCOL_VERSION, "marker": 1 },
        });
        let mut response_line = serde_json::to_string(&response).unwrap();
        response_line.push('\n');
        server_write
            .write_all(response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let note_line = lines.next_line().await.unwrap().unwrap();
        let note_value: Value = serde_json::from_str(&note_line).unwrap();
        assert_eq!(note_value["jsonrpc"], "2.0");
        assert_eq!(note_value["method"], "notifications/initialized");

        let eof = lines.next_line().await.unwrap();
        assert!(eof.is_none(), "expected EOF after disconnect");
    });

    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted);
    manager
        .connect_io(" srv ", client_read, client_write)
        .await
        .unwrap();
    assert_eq!(
        manager.initialize_result("srv").unwrap()["marker"],
        serde_json::json!(1)
    );

    let (client_stream2, server_stream2) = tokio::io::duplex(1024);
    let (client_read2, client_write2) = tokio::io::split(client_stream2);
    let (server_read2, mut server_write2) = tokio::io::split(server_stream2);

    let server2_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read2).lines();
        let next = tokio::time::timeout(Duration::from_millis(500), lines.next_line()).await;
        let Ok(Ok(Some(init_line))) = next else {
            return false;
        };

        let init_value: Value = serde_json::from_str(&init_line).unwrap();
        if init_value["method"] != "initialize" {
            return false;
        }
        let id = init_value["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "protocolVersion": MCP_PROTOCOL_VERSION, "marker": 2 },
        });
        let mut response_line = serde_json::to_string(&response).unwrap();
        response_line.push('\n');
        server_write2
            .write_all(response_line.as_bytes())
            .await
            .unwrap();
        server_write2.flush().await.unwrap();

        let note_line = lines.next_line().await.unwrap().unwrap();
        let note_value: Value = serde_json::from_str(&note_line).unwrap();
        assert_eq!(note_value["method"], "notifications/initialized");
        true
    });

    manager
        .connect_io(" srv ", client_read2, client_write2)
        .await
        .unwrap();

    // The second connect should no-op against the existing normalized name.
    assert_eq!(
        manager.initialize_result("srv").unwrap()["marker"],
        serde_json::json!(1)
    );
    let saw_second_initialize = server2_task.await.unwrap();
    assert!(
        !saw_second_initialize,
        "second connection should not send initialize when normalized name is already connected"
    );

    let status = manager
        .disconnect_and_wait(
            "srv",
            Duration::from_secs(1),
            mcp_jsonrpc::WaitOnTimeout::ReturnError,
        )
        .await
        .unwrap();
    assert!(status.is_none());
    server1_task.await.unwrap();
}

#[tokio::test]
async fn connect_io_unchecked_rejects_invalid_server_name() {
    let (client_stream, _server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);

    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted);
    let err = manager
        .connect_io_unchecked(" bad name! ", client_read, client_write)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("invalid mcp server name"));
}

#[tokio::test]
async fn untrusted_manager_refuses_stdio_spawn() {
    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
    assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

    let server_cfg = ServerConfig::stdio(vec!["mcp-server".to_string()]).unwrap();

    let err = manager
        .connect("srv", &server_cfg, Path::new("."))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("untrusted mode"));
}

#[tokio::test]
async fn untrusted_manager_refuses_custom_jsonrpc_attachments() {
    let (client_stream, _server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);

    let client = mcp_jsonrpc::Client::connect_io(client_read, client_write)
        .await
        .unwrap();

    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
    assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

    let err = manager
        .connect_jsonrpc("srv", client)
        .await
        .expect_err("should refuse in untrusted mode");
    assert!(err.to_string().contains("untrusted mode"));
    assert!(err.to_string().contains("connect_jsonrpc_unchecked"));

    let (client_stream, _server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let err = manager
        .connect_io("srv2", client_read, client_write)
        .await
        .expect_err("should refuse in untrusted mode");
    assert!(err.to_string().contains("untrusted mode"));
    assert!(err.to_string().contains("connect_io_unchecked"));
}

#[tokio::test]
async fn untrusted_manager_refuses_unix_connect() {
    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
    assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

    let server_cfg = ServerConfig::unix(PathBuf::from("/tmp/mcp.sock")).unwrap();

    let err = manager
        .connect("srv", &server_cfg, Path::new("."))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("untrusted mode"));
}

#[tokio::test]
async fn untrusted_manager_refuses_streamable_http_env_secrets() {
    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
    assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

    let mut server_cfg = ServerConfig::streamable_http("https://example.com/mcp").unwrap();
    server_cfg
        .set_bearer_token_env_var(Some("MCP_TOKEN".to_string()))
        .unwrap();

    let err = manager
        .connect("srv", &server_cfg, Path::new("."))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("bearer token env var"));
}

#[tokio::test]
async fn untrusted_manager_refuses_streamable_http_env_header_secrets() {
    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
    assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

    let mut server_cfg = ServerConfig::streamable_http("https://example.com/mcp").unwrap();
    server_cfg
        .env_http_headers_mut()
        .unwrap()
        .insert("x-api-key".to_string(), "MCP_API_KEY".to_string());

    let err = manager
        .connect("srv", &server_cfg, Path::new("."))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("http header env vars"));
}

#[tokio::test]
async fn untrusted_manager_refuses_streamable_http_non_https_urls() {
    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
    assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

    let server_cfg = ServerConfig::streamable_http("http://example.com/mcp").unwrap();

    let err = manager
        .connect("srv", &server_cfg, Path::new("."))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("non-https"));
}

#[tokio::test]
async fn untrusted_manager_refuses_streamable_http_localhost() {
    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
    assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

    let server_cfg = ServerConfig::streamable_http("https://localhost/mcp").unwrap();

    let err = manager
        .connect("srv", &server_cfg, Path::new("."))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("localhost"));
}

#[tokio::test]
async fn untrusted_manager_refuses_streamable_http_localdomain() {
    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
    assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

    let server_cfg = ServerConfig::streamable_http("https://localhost.localdomain/mcp").unwrap();

    let err = manager
        .connect("srv", &server_cfg, Path::new("."))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("localdomain"));
}

#[tokio::test]
async fn untrusted_manager_refuses_streamable_http_single_label_hosts() {
    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
    assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

    let server_cfg = ServerConfig::streamable_http("https://example/mcp").unwrap();

    let err = manager
        .connect("srv", &server_cfg, Path::new("."))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("single-label"));
}

#[tokio::test]
async fn untrusted_manager_refuses_streamable_http_private_ip() {
    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
    assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

    let server_cfg = ServerConfig::streamable_http("https://192.168.0.10/mcp").unwrap();

    let err = manager
        .connect("srv", &server_cfg, Path::new("."))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("non-global ip"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn untrusted_manager_refuses_streamable_http_ipv4_mapped_ipv6_loopback() {
    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
    assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

    let server_cfg = ServerConfig::streamable_http("https://[::ffff:127.0.0.1]/mcp").unwrap();

    let err = manager
        .connect("srv", &server_cfg, Path::new("."))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("non-global ip"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn untrusted_manager_refuses_streamable_http_nat64_well_known_prefix_private_ip() {
    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
    assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

    let server_cfg = ServerConfig::streamable_http("https://[64:ff9b::c0a8:0001]/mcp").unwrap();

    let err = manager
        .connect("srv", &server_cfg, Path::new("."))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("non-global ip"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn untrusted_manager_refuses_streamable_http_6to4_private_ip() {
    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
    assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

    let server_cfg = ServerConfig::streamable_http("https://[2002:c0a8:0001::]/mcp").unwrap();

    let err = manager
        .connect("srv", &server_cfg, Path::new("."))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("non-global ip"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn untrusted_manager_refuses_streamable_http_url_credentials() {
    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
    assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

    let server_cfg = ServerConfig::streamable_http("https://user:pass@example.com/mcp").unwrap();

    let err = manager
        .connect("srv", &server_cfg, Path::new("."))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("url credentials"));
}

#[tokio::test]
async fn untrusted_manager_refuses_streamable_http_hostname_resolving_to_non_global_ip_by_default()
{
    let policy = UntrustedStreamableHttpPolicy {
        allow_localhost: true,
        ..Default::default()
    };
    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_untrusted_streamable_http_policy(policy);
    assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

    let server_cfg = ServerConfig::streamable_http("https://localhost/mcp").unwrap();

    let err = manager
        .connect("srv", &server_cfg, Path::new("."))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("resolves to non-global ip"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn untrusted_manager_refuses_streamable_http_sensitive_headers() {
    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5));
    assert_eq!(manager.trust_mode(), TrustMode::Untrusted);

    let mut server_cfg = ServerConfig::streamable_http("https://example.com/mcp").unwrap();
    server_cfg.http_headers_mut().unwrap().insert(
        "Authorization".to_string(),
        "Bearer local-secret".to_string(),
    );

    let err = manager
        .connect("srv", &server_cfg, Path::new("."))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("sensitive http header"));
}

#[test]
fn untrusted_policy_allows_http_when_configured() {
    let policy = UntrustedStreamableHttpPolicy {
        require_https: false,
        ..Default::default()
    };

    validate_streamable_http_url_untrusted(&policy, "srv", "url", "http://example.com/mcp")
        .unwrap();
}

#[test]
fn untrusted_policy_allows_private_ip_when_configured() {
    let policy = UntrustedStreamableHttpPolicy {
        allow_private_ips: true,
        ..Default::default()
    };

    validate_streamable_http_url_untrusted(&policy, "srv", "url", "https://192.168.0.10/mcp")
        .unwrap();
}

#[test]
fn untrusted_policy_allows_nat64_well_known_prefix_when_embedded_ipv4_is_public() {
    let policy = UntrustedStreamableHttpPolicy::default();

    validate_streamable_http_url_untrusted(
        &policy,
        "srv",
        "url",
        "https://[64:ff9b::0808:0808]/mcp",
    )
    .unwrap();
}

#[test]
fn untrusted_policy_allows_6to4_when_embedded_ipv4_is_public() {
    let policy = UntrustedStreamableHttpPolicy::default();

    validate_streamable_http_url_untrusted(&policy, "srv", "url", "https://[2002:0808:0808::]/mcp")
        .unwrap();
}

#[test]
fn untrusted_policy_enforces_allowlist_when_set() {
    let policy = UntrustedStreamableHttpPolicy {
        allowed_hosts: vec!["example.com".to_string()],
        ..Default::default()
    };

    validate_streamable_http_url_untrusted(&policy, "srv", "url", "https://example.com/mcp")
        .unwrap();
    validate_streamable_http_url_untrusted(&policy, "srv", "url", "https://api.example.com/mcp")
        .unwrap();

    let err = validate_streamable_http_url_untrusted(&policy, "srv", "url", "https://evil.com/mcp")
        .unwrap_err();
    assert!(err.to_string().contains("allowlist"));
}

#[tokio::test]
async fn untrusted_policy_dns_check_blocks_localhost_without_allow_private_ip() {
    let policy = UntrustedStreamableHttpPolicy {
        allow_localhost: true,
        dns_check: true,
        ..Default::default()
    };

    validate_streamable_http_url_untrusted(&policy, "srv", "url", "https://localhost/mcp").unwrap();
    let err =
        validate_streamable_http_url_untrusted_dns(&policy, "srv", "url", "https://localhost/mcp")
            .await
            .unwrap_err();
    assert!(err.to_string().contains("resolves to non-global ip"));
}

#[tokio::test]
async fn untrusted_policy_dns_check_allows_localhost_with_allow_private_ip() {
    let policy = UntrustedStreamableHttpPolicy {
        allow_localhost: true,
        allow_private_ips: true,
        dns_check: true,
        ..Default::default()
    };

    validate_streamable_http_url_untrusted(&policy, "srv", "url", "https://localhost/mcp").unwrap();
    validate_streamable_http_url_untrusted_dns(&policy, "srv", "url", "https://localhost/mcp")
        .await
        .unwrap();
}

#[tokio::test]
async fn untrusted_policy_dns_check_fails_closed_on_lookup_timeout() {
    let policy = UntrustedStreamableHttpPolicy {
        dns_check: true,
        dns_timeout: Duration::from_nanos(1),
        ..Default::default()
    };

    validate_streamable_http_url_untrusted(
        &policy,
        "srv",
        "url",
        "https://does-not-exist.invalid/mcp",
    )
    .unwrap();
    let err = validate_streamable_http_url_untrusted_dns(
        &policy,
        "srv",
        "url",
        "https://does-not-exist.invalid/mcp",
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("timed out dns lookup"),
        "err={err}"
    );
}

#[tokio::test]
async fn untrusted_policy_dns_check_can_fail_open_on_lookup_timeout() {
    let policy = UntrustedStreamableHttpPolicy {
        dns_check: true,
        dns_fail_open: true,
        dns_timeout: Duration::from_nanos(1),
        ..Default::default()
    };

    validate_streamable_http_url_untrusted(
        &policy,
        "srv",
        "url",
        "https://does-not-exist.invalid/mcp",
    )
    .unwrap();
    validate_streamable_http_url_untrusted_dns(
        &policy,
        "srv",
        "url",
        "https://does-not-exist.invalid/mcp",
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn argv_placeholder_errors_do_not_leak_plain_argv() {
    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted);

    let server_cfg = ServerConfig::stdio(vec![
        "mcp-server-bin".to_string(),
        "--auth=Bearer SECRET_TOKEN-${BAD-NAME}".to_string(),
    ])
    .unwrap();

    let err = manager
        .connect("srv", &server_cfg, Path::new("."))
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("expand argv placeholder"),
        "expected redacted argv context; err={err:#}"
    );
    assert!(
        !msg.contains("SECRET_TOKEN"),
        "argv secret leaked in error chain; err={err:#}"
    );
}

#[test]
fn url_validation_errors_do_not_leak_plain_url() {
    let policy = UntrustedStreamableHttpPolicy::default();

    let err = validate_streamable_http_url_untrusted(
        &policy,
        "srv",
        "url",
        "https://user:pass@example.com/mcp?token=SECRET_TOKEN",
    )
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("url credentials"),
        "expected url credential error; err={err:#}"
    );
    assert!(
        !msg.contains("SECRET_TOKEN"),
        "url secret leaked in error chain; err={err:#}"
    );
    assert!(
        !msg.contains("user:pass"),
        "url userinfo leaked in error chain; err={err:#}"
    );
}

#[tokio::test]
async fn url_placeholder_errors_do_not_leak_plain_url() {
    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted);

    let server_cfg =
        ServerConfig::streamable_http("https://example.com/mcp?token=SECRET_TOKEN_${BAD-NAME}")
            .unwrap();

    let err = manager
        .connect("srv", &server_cfg, Path::new("."))
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("expand url placeholder"),
        "expected redacted url context; err={err:#}"
    );
    assert!(
        !msg.contains("SECRET_TOKEN"),
        "url secret leaked in error chain; err={err:#}"
    );
}

#[tokio::test]
async fn disconnect_and_wait_clears_timeout_counter_entry() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();

        let init_line = lines.next_line().await.unwrap().unwrap();
        let init_value: Value = serde_json::from_str(&init_line).unwrap();
        assert_eq!(init_value["jsonrpc"], "2.0");
        assert_eq!(init_value["method"], "initialize");
        let id = init_value["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "protocolVersion": MCP_PROTOCOL_VERSION },
        });
        let mut response_line = serde_json::to_string(&response).unwrap();
        response_line.push('\n');
        server_write
            .write_all(response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let note_line = lines.next_line().await.unwrap().unwrap();
        let note_value: Value = serde_json::from_str(&note_line).unwrap();
        assert_eq!(note_value["jsonrpc"], "2.0");
        assert_eq!(note_value["method"], "notifications/initialized");

        let eof = lines.next_line().await.unwrap();
        assert!(eof.is_none(), "expected EOF after disconnect");
    });

    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted);
    manager
        .connect_io("srv", client_read, client_write)
        .await
        .unwrap();

    let srv = ServerName::parse("srv").unwrap();
    manager
        .server_handler_timeout_counts
        .counter_for(&srv)
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(manager.server_handler_timeout_count("srv"), 1);

    let status = manager
        .disconnect_and_wait(
            "srv",
            Duration::from_secs(1),
            mcp_jsonrpc::WaitOnTimeout::ReturnError,
        )
        .await
        .unwrap();
    assert!(status.is_none());

    assert_eq!(manager.server_handler_timeout_count("srv"), 0);
    assert!(!manager.server_handler_timeout_counts().contains_key("srv"));

    server_task.await.unwrap();
}

#[tokio::test]
async fn disconnect_and_wait_times_out_when_handler_task_hangs() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();

        let init_line = lines.next_line().await.unwrap().unwrap();
        let init_value: Value = serde_json::from_str(&init_line).unwrap();
        assert_eq!(init_value["jsonrpc"], "2.0");
        assert_eq!(init_value["method"], "initialize");
        let id = init_value["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "protocolVersion": MCP_PROTOCOL_VERSION },
        });
        let mut response_line = serde_json::to_string(&response).unwrap();
        response_line.push('\n');
        server_write
            .write_all(response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let note_line = lines.next_line().await.unwrap().unwrap();
        let note_value: Value = serde_json::from_str(&note_line).unwrap();
        assert_eq!(note_value["jsonrpc"], "2.0");
        assert_eq!(note_value["method"], "notifications/initialized");

        let notify = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "demo/notify",
            "params": {},
        });
        let mut notify_line = serde_json::to_string(&notify).unwrap();
        notify_line.push('\n');
        server_write
            .write_all(notify_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let eof = lines.next_line().await.unwrap();
        assert!(eof.is_none(), "expected EOF after disconnect");
    });

    let handler_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let started_for_handler = Arc::clone(&handler_started);
    let handler_dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let dropped_for_handler = Arc::clone(&handler_dropped);
    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted)
        .with_server_notification_handler(Arc::new(move |_ctx| {
            let started_for_handler = Arc::clone(&started_for_handler);
            let dropped_for_handler = Arc::clone(&dropped_for_handler);
            Box::pin(async move {
                struct OnDrop(std::sync::Arc<std::sync::atomic::AtomicBool>);

                impl Drop for OnDrop {
                    fn drop(&mut self) {
                        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                }

                let _on_drop = OnDrop(dropped_for_handler);
                started_for_handler.store(true, std::sync::atomic::Ordering::Relaxed);
                std::future::pending::<()>().await;
            })
        }));
    manager
        .connect_io("srv", client_read, client_write)
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(1), async {
        while !handler_started.load(std::sync::atomic::Ordering::Relaxed) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let err = manager
        .disconnect_and_wait(
            "srv",
            Duration::from_millis(20),
            mcp_jsonrpc::WaitOnTimeout::ReturnError,
        )
        .await
        .unwrap_err();
    let err_chain = format!("{err:#}");
    assert!(
        err_chain.contains("wait timed out after"),
        "unexpected error: {err_chain}"
    );

    tokio::time::timeout(Duration::from_secs(1), async {
        while !handler_dropped.load(std::sync::atomic::Ordering::Relaxed) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    server_task.await.unwrap();
}

#[tokio::test]
async fn connection_wait_aborts_remaining_handler_tasks_after_first_join_error() {
    let (client_stream, _server_stream) = tokio::io::duplex(256);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let client = mcp_jsonrpc::Client::connect_io(client_read, client_write)
        .await
        .unwrap();

    let slow_task_dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let dropped_for_task = Arc::clone(&slow_task_dropped);
    let panic_task = tokio::spawn(async move {
        panic!("boom");
    });
    let slow_task = tokio::spawn(async move {
        struct OnDrop(std::sync::Arc<std::sync::atomic::AtomicBool>);

        impl Drop for OnDrop {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }

        let _on_drop = OnDrop(dropped_for_task);
        std::future::pending::<()>().await;
    });

    let conn = Connection {
        child: None,
        client,
        handler_tasks: vec![panic_task, slow_task],
    };

    let err = conn.wait().await.unwrap_err();
    let err_chain = format!("{err:#}");
    assert!(
        err_chain.contains("server handler task panicked"),
        "unexpected error: {err_chain}"
    );

    tokio::time::timeout(Duration::from_secs(1), async {
        while !slow_task_dropped.load(std::sync::atomic::Ordering::Relaxed) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn connection_wait_with_timeout_uses_single_deadline_budget() {
    let (client_stream, _server_stream) = tokio::io::duplex(256);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let client = mcp_jsonrpc::Client::connect_io(client_read, client_write)
        .await
        .unwrap();

    let mut handler_tasks = Vec::new();
    for _ in 0..3 {
        handler_tasks.push(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }));
    }

    let conn = Connection {
        child: None,
        client,
        handler_tasks,
    };

    let started = tokio::time::Instant::now();
    let err = conn
        .wait_with_timeout(
            Duration::from_millis(100),
            mcp_jsonrpc::WaitOnTimeout::ReturnError,
        )
        .await
        .unwrap_err();
    let err_chain = format!("{err:#}");
    assert!(
        err_chain.contains("wait timed out after"),
        "unexpected error: {err_chain}"
    );
    assert!(
        started.elapsed() < Duration::from_millis(220),
        "wait exceeded global timeout budget: {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn take_connection_clears_timeout_counter_entry() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();

        let init_line = lines.next_line().await.unwrap().unwrap();
        let init_value: Value = serde_json::from_str(&init_line).unwrap();
        assert_eq!(init_value["method"], "initialize");
        let id = init_value["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "protocolVersion": MCP_PROTOCOL_VERSION },
        });
        let mut response_line = serde_json::to_string(&response).unwrap();
        response_line.push('\n');
        server_write
            .write_all(response_line.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let note_line = lines.next_line().await.unwrap().unwrap();
        let note_value: Value = serde_json::from_str(&note_line).unwrap();
        assert_eq!(note_value["method"], "notifications/initialized");

        let eof = lines.next_line().await.unwrap();
        assert!(eof.is_none(), "expected EOF after take_connection wait");
    });

    let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
        .with_trust_mode(TrustMode::Trusted);
    manager
        .connect_io("srv", client_read, client_write)
        .await
        .unwrap();

    let srv = ServerName::parse("srv").unwrap();
    manager
        .server_handler_timeout_counts
        .counter_for(&srv)
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(manager.server_handler_timeout_count("srv"), 1);

    let conn = manager
        .take_connection(" srv ")
        .expect("connection should exist");
    assert_eq!(manager.server_handler_timeout_count("srv"), 0);
    assert!(!manager.server_handler_timeout_counts().contains_key("srv"));
    assert!(!manager.is_connected("srv"));

    let status = conn.wait().await.unwrap();
    assert!(status.is_none());

    server_task.await.unwrap();
}
