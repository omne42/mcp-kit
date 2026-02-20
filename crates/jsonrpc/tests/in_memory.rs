use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use mcp_jsonrpc::Id;
use serde_json::Value;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

fn parse_line(line: &str) -> Value {
    serde_json::from_str(line).expect("valid json")
}

#[tokio::test]
async fn wait_returns_ok_none_when_client_has_no_child() {
    let (client_stream, _server_stream) = tokio::io::duplex(64);
    let (client_read, client_write) = tokio::io::split(client_stream);

    let mut client = mcp_jsonrpc::Client::connect_io(client_read, client_write)
        .await
        .expect("client connect");
    let status = client.wait().await.expect("wait ok");
    assert!(status.is_none());
}

#[tokio::test]
async fn wait_with_timeout_returns_ok_none_when_client_has_no_child() {
    let (client_stream, _server_stream) = tokio::io::duplex(64);
    let (client_read, client_write) = tokio::io::split(client_stream);

    let mut client = mcp_jsonrpc::Client::connect_io(client_read, client_write)
        .await
        .expect("client connect");
    let status = client
        .wait_with_timeout(
            Duration::from_millis(1),
            mcp_jsonrpc::WaitOnTimeout::ReturnError,
        )
        .await
        .expect("wait ok");
    assert!(status.is_none());
}

#[tokio::test]
async fn wait_with_timeout_includes_close_stage_lock_wait() {
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
            Poll::Pending
        }
    }

    let entered = Arc::new(AtomicBool::new(false));
    let writer = BlockingWrite {
        entered: entered.clone(),
    };
    let (client_stream, _server_stream) = tokio::io::duplex(64);
    let (client_read, _client_write) = tokio::io::split(client_stream);

    let mut client = mcp_jsonrpc::Client::connect_io(client_read, writer)
        .await
        .expect("client connect");
    let handle = client.handle();
    let write_task = tokio::spawn(async move {
        let _ = handle
            .notify("demo/stuck", Some(serde_json::json!({ "x": 1 })))
            .await;
    });

    tokio::time::timeout(Duration::from_secs(1), async {
        while !entered.load(Ordering::Relaxed) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("write task should enter write lock");

    let err = client
        .wait_with_timeout(
            Duration::from_millis(20),
            mcp_jsonrpc::WaitOnTimeout::ReturnError,
        )
        .await
        .expect_err("close stage should time out when write lock is held");
    assert!(err.is_wait_timeout());

    write_task.abort();
}

#[tokio::test]
async fn request_timeout_includes_write_stage_and_closes_client() {
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
            Poll::Pending
        }
    }

    let entered = Arc::new(AtomicBool::new(false));
    let writer = BlockingWrite {
        entered: entered.clone(),
    };
    let (client_stream, _server_stream) = tokio::io::duplex(64);
    let (client_read, _client_write) = tokio::io::split(client_stream);

    let client = mcp_jsonrpc::Client::connect_io(client_read, writer)
        .await
        .expect("client connect");
    let handle = client.handle();
    let started = tokio::time::Instant::now();
    let err = handle
        .request_optional_with_timeout("demo/request", None, Duration::from_millis(20))
        .await
        .expect_err("write-stage timeout should fail request");
    assert!(err.is_wait_timeout());
    assert!(
        started.elapsed() < Duration::from_millis(200),
        "request timeout should bound blocked writes"
    );
    assert!(
        entered.load(Ordering::Relaxed),
        "write stage should have been entered"
    );

    tokio::time::timeout(Duration::from_secs(1), async {
        while !handle.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("client should be closed after write-stage timeout");
}

#[tokio::test]
async fn drop_closes_write_end_even_when_handle_is_cloned() {
    let (client_stream, server_stream) = tokio::io::duplex(64);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (mut server_read, _server_write) = tokio::io::split(server_stream);

    let client = mcp_jsonrpc::Client::connect_io(client_read, client_write)
        .await
        .expect("client connect");
    let handle = client.handle();
    drop(client);

    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(1), server_read.read(&mut buf))
        .await
        .expect("server read completed")
        .expect("server read ok");
    assert_eq!(n, 0, "peer should observe EOF after client drop");

    let err = handle
        .notify("demo/notify", None)
        .await
        .expect_err("cloned handle should be closed after client drop");
    assert!(matches!(
        err,
        mcp_jsonrpc::Error::Protocol(ref protocol)
            if protocol.kind == mcp_jsonrpc::ProtocolErrorKind::Closed
    ));
}

#[tokio::test]
async fn request_roundtrip_over_duplex() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let mut server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();
        let line = lines
            .next_line()
            .await
            .expect("read ok")
            .expect("request line");

        let msg = parse_line(&line);
        assert_eq!(msg["jsonrpc"], "2.0");
        assert_eq!(msg["method"], "demo/request");
        assert_eq!(msg["params"], serde_json::json!({ "x": 1 }));
        let id = msg["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "ok": true },
        });
        let mut out = serde_json::to_string(&response).unwrap();
        out.push('\n');
        server_write.write_all(out.as_bytes()).await.unwrap();
        server_write.flush().await.unwrap();
    });

    let client = mcp_jsonrpc::Client::connect_io(client_read, client_write)
        .await
        .expect("client connect");
    let result = client
        .request("demo/request", serde_json::json!({ "x": 1 }))
        .await
        .expect("request ok");
    assert_eq!(result, serde_json::json!({ "ok": true }));

    tokio::time::timeout(Duration::from_secs(1), &mut server_task)
        .await
        .expect("server task completed")
        .expect("server task ok");
}

#[tokio::test]
async fn connect_io_clamps_zero_max_message_bytes_to_default() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let mut server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();
        let line = lines
            .next_line()
            .await
            .expect("read ok")
            .expect("request line");

        let msg = parse_line(&line);
        let id = msg["id"].clone();
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "ok": true },
        });
        let mut out = serde_json::to_string(&response).unwrap();
        out.push('\n');
        server_write.write_all(out.as_bytes()).await.unwrap();
        server_write.flush().await.unwrap();
    });

    let mut options = mcp_jsonrpc::SpawnOptions::default();
    options.limits.max_message_bytes = 0;
    let client = mcp_jsonrpc::Client::connect_io_with_options(client_read, client_write, options)
        .await
        .expect("client connect");

    let result = client
        .request("demo/request", serde_json::json!({ "x": 1 }))
        .await
        .expect("request ok");
    assert_eq!(result, serde_json::json!({ "ok": true }));

    tokio::time::timeout(Duration::from_secs(1), &mut server_task)
        .await
        .expect("server task completed")
        .expect("server task ok");
}

#[tokio::test]
async fn request_fails_when_response_id_type_mismatches_pending_request() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let mut server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();
        let line = lines
            .next_line()
            .await
            .expect("read ok")
            .expect("request line");

        let msg = parse_line(&line);
        assert_eq!(msg["jsonrpc"], "2.0");
        assert_eq!(msg["method"], "demo/request");
        let id = msg["id"].as_i64().expect("client id should be integer");

        // Send the same id with a different JSON type to trigger response-id mismatch handling.
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id.to_string(),
            "result": { "ok": true },
        });
        let mut out = serde_json::to_string(&response).unwrap();
        out.push('\n');
        server_write.write_all(out.as_bytes()).await.unwrap();
        server_write.flush().await.unwrap();
    });

    let client = mcp_jsonrpc::Client::connect_io(client_read, client_write)
        .await
        .expect("client connect");
    let err = tokio::time::timeout(
        Duration::from_secs(1),
        client.request("demo/request", serde_json::json!({ "x": 1 })),
    )
    .await
    .expect("request should not hang")
    .expect_err("request should fail on mismatched response id type");

    assert!(matches!(
        err,
        mcp_jsonrpc::Error::Protocol(ref protocol)
            if protocol.kind == mcp_jsonrpc::ProtocolErrorKind::InvalidMessage
    ));
    assert!(err.to_string().contains("type mismatch"));

    tokio::time::timeout(Duration::from_secs(1), &mut server_task)
        .await
        .expect("server task completed")
        .expect("server task ok");
}

#[tokio::test]
async fn late_response_after_caller_timeout_does_not_close_connection() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let mut server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();

        let slow_line = lines
            .next_line()
            .await
            .expect("read ok")
            .expect("slow request line");
        let slow_msg = parse_line(&slow_line);
        assert_eq!(slow_msg["method"], "demo/slow");
        let slow_id = slow_msg["id"].clone();

        tokio::time::sleep(Duration::from_millis(80)).await;
        let slow_response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": slow_id,
            "result": { "slow": true },
        });
        let mut slow_out = serde_json::to_string(&slow_response).unwrap();
        slow_out.push('\n');
        server_write.write_all(slow_out.as_bytes()).await.unwrap();
        server_write.flush().await.unwrap();

        let fast_line = lines
            .next_line()
            .await
            .expect("read ok")
            .expect("fast request line");
        let fast_msg = parse_line(&fast_line);
        assert_eq!(fast_msg["method"], "demo/fast");
        let fast_id = fast_msg["id"].clone();

        let fast_response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": fast_id,
            "result": { "ok": true },
        });
        let mut fast_out = serde_json::to_string(&fast_response).unwrap();
        fast_out.push('\n');
        server_write.write_all(fast_out.as_bytes()).await.unwrap();
        server_write.flush().await.unwrap();
    });

    let client = mcp_jsonrpc::Client::connect_io(client_read, client_write)
        .await
        .expect("client connect");
    let slow = tokio::time::timeout(
        Duration::from_millis(20),
        client.request("demo/slow", serde_json::json!({})),
    )
    .await;
    assert!(slow.is_err(), "slow request should time out at caller side");

    tokio::time::sleep(Duration::from_millis(120)).await;

    let fast = tokio::time::timeout(
        Duration::from_secs(1),
        client.request("demo/fast", serde_json::json!({})),
    )
    .await
    .expect("fast request future completed")
    .expect("fast request succeeded");
    assert_eq!(fast, serde_json::json!({ "ok": true }));

    tokio::time::timeout(Duration::from_secs(1), &mut server_task)
        .await
        .expect("server task completed")
        .expect("server task ok");
}

#[tokio::test]
async fn stale_responses_after_cancelled_id_eviction_do_not_close_connection() {
    const SLOW_REQUESTS: usize = 1050;

    let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let mut server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();
        let mut stale_ids = Vec::with_capacity(SLOW_REQUESTS);

        for _ in 0..SLOW_REQUESTS {
            let slow_line = lines
                .next_line()
                .await
                .expect("read ok")
                .expect("slow request line");
            let slow_msg = parse_line(&slow_line);
            assert_eq!(slow_msg["method"], "demo/slow");
            stale_ids.push(slow_msg["id"].clone());
        }

        // Ensure caller-side timeouts have fired before replaying stale responses.
        tokio::time::sleep(Duration::from_millis(30)).await;

        let mut stale_batch = String::new();
        for id in stale_ids {
            let stale_response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "slow": true },
            });
            stale_batch.push_str(&serde_json::to_string(&stale_response).unwrap());
            stale_batch.push('\n');
        }
        server_write
            .write_all(stale_batch.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let fast_line = lines
            .next_line()
            .await
            .expect("read ok")
            .expect("fast request line");
        let fast_msg = parse_line(&fast_line);
        assert_eq!(fast_msg["method"], "demo/fast");
        let fast_id = fast_msg["id"].clone();

        let fast_response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": fast_id,
            "result": { "ok": true },
        });
        let mut fast_out = serde_json::to_string(&fast_response).unwrap();
        fast_out.push('\n');
        server_write.write_all(fast_out.as_bytes()).await.unwrap();
        server_write.flush().await.unwrap();
    });

    let client = mcp_jsonrpc::Client::connect_io(client_read, client_write)
        .await
        .expect("client connect");

    for _ in 0..SLOW_REQUESTS {
        let slow = tokio::time::timeout(
            Duration::from_millis(1),
            client.request("demo/slow", serde_json::json!({})),
        )
        .await;
        assert!(slow.is_err(), "slow request should time out at caller side");
    }

    tokio::time::sleep(Duration::from_millis(50)).await;

    let fast = tokio::time::timeout(
        Duration::from_secs(1),
        client.request("demo/fast", serde_json::json!({})),
    )
    .await
    .expect("fast request future completed")
    .expect("fast request succeeded");
    assert_eq!(fast, serde_json::json!({ "ok": true }));

    tokio::time::timeout(Duration::from_secs(1), &mut server_task)
        .await
        .expect("server task completed")
        .expect("server task ok");
}

#[tokio::test]
async fn stale_responses_with_other_pending_do_not_close_connection() {
    const SLOW_REQUESTS: usize = 1050;

    let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let mut server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();
        let mut stale_ids = Vec::with_capacity(SLOW_REQUESTS);

        for _ in 0..SLOW_REQUESTS {
            let slow_line = lines
                .next_line()
                .await
                .expect("read ok")
                .expect("slow request line");
            let slow_msg = parse_line(&slow_line);
            assert_eq!(slow_msg["method"], "demo/slow");
            stale_ids.push(slow_msg["id"].clone());
        }

        let fast_line = lines
            .next_line()
            .await
            .expect("read ok")
            .expect("fast request line");
        let fast_msg = parse_line(&fast_line);
        assert_eq!(fast_msg["method"], "demo/fast");
        let fast_id = fast_msg["id"].clone();

        tokio::time::sleep(Duration::from_millis(30)).await;

        let mut stale_batch = String::new();
        for id in stale_ids {
            let stale_response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "slow": true },
            });
            stale_batch.push_str(&serde_json::to_string(&stale_response).unwrap());
            stale_batch.push('\n');
        }
        server_write
            .write_all(stale_batch.as_bytes())
            .await
            .unwrap();
        server_write.flush().await.unwrap();

        let fast_response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": fast_id,
            "result": { "ok": true },
        });
        let mut fast_out = serde_json::to_string(&fast_response).unwrap();
        fast_out.push('\n');
        server_write.write_all(fast_out.as_bytes()).await.unwrap();
        server_write.flush().await.unwrap();
    });

    let client = mcp_jsonrpc::Client::connect_io(client_read, client_write)
        .await
        .expect("client connect");

    for _ in 0..SLOW_REQUESTS {
        let slow = tokio::time::timeout(
            Duration::from_millis(1),
            client.request("demo/slow", serde_json::json!({})),
        )
        .await;
        assert!(slow.is_err(), "slow request should time out at caller side");
    }

    let fast = tokio::time::timeout(
        Duration::from_secs(1),
        client.request("demo/fast", serde_json::json!({})),
    )
    .await
    .expect("fast request future completed")
    .expect("fast request succeeded");
    assert_eq!(fast, serde_json::json!({ "ok": true }));

    tokio::time::timeout(Duration::from_secs(1), &mut server_task)
        .await
        .expect("server task completed")
        .expect("server task ok");
}

#[tokio::test]
async fn handles_server_to_client_request_and_responds() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let mut server_task = tokio::spawn(async move {
        // Send server->client request (string id).
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "abc",
            "method": "demo/ping",
            "params": { "n": 42 },
        });
        let mut out = serde_json::to_string(&request).unwrap();
        out.push('\n');
        server_write.write_all(out.as_bytes()).await.unwrap();
        server_write.flush().await.unwrap();

        // Read client->server response.
        let mut lines = tokio::io::BufReader::new(server_read).lines();
        let line = lines
            .next_line()
            .await
            .expect("read ok")
            .expect("response line");
        let msg = parse_line(&line);
        assert_eq!(msg["jsonrpc"], "2.0");
        assert_eq!(msg["id"], "abc");
        assert_eq!(msg["result"], serde_json::json!({ "pong": true }));
    });

    let mut client = mcp_jsonrpc::Client::connect_io(client_read, client_write)
        .await
        .expect("client connect");
    let _ = client.take_notifications();
    let mut requests = client.take_requests().expect("requests rx");

    let handler_task = tokio::spawn(async move {
        let req = requests.recv().await.expect("incoming request");
        assert_eq!(req.method, "demo/ping");
        assert_eq!(req.params, Some(serde_json::json!({ "n": 42 })));
        assert_eq!(req.id, Id::String("abc".to_string()));
        req.respond_ok(serde_json::json!({ "pong": true }))
            .await
            .expect("respond ok");
    });

    tokio::time::timeout(Duration::from_secs(1), handler_task)
        .await
        .expect("handler completed")
        .expect("handler ok");

    tokio::time::timeout(Duration::from_secs(1), &mut server_task)
        .await
        .expect("server task completed")
        .expect("server task ok");
}

#[tokio::test]
async fn responds_invalid_request_when_server_sends_invalid_id() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let mut server_task = tokio::spawn(async move {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": {},
            "method": "demo/ping",
        });
        let mut out = serde_json::to_string(&request).unwrap();
        out.push('\n');
        server_write.write_all(out.as_bytes()).await.unwrap();
        server_write.flush().await.unwrap();

        let mut lines = tokio::io::BufReader::new(server_read).lines();
        let line = lines
            .next_line()
            .await
            .expect("read ok")
            .expect("response line");

        let msg = parse_line(&line);
        assert_eq!(msg["jsonrpc"], "2.0");
        assert!(msg["id"].is_null());
        assert_eq!(msg["error"]["code"], serde_json::json!(-32600));
        assert_eq!(msg["error"]["message"], "invalid request id");
    });

    let _client = mcp_jsonrpc::Client::connect_io(client_read, client_write)
        .await
        .expect("client connect");

    tokio::time::timeout(Duration::from_secs(1), &mut server_task)
        .await
        .expect("server task completed")
        .expect("server task ok");
}

#[tokio::test]
async fn notify_omits_params_when_none() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, _server_write) = tokio::io::split(server_stream);

    let mut server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();
        let line = lines
            .next_line()
            .await
            .expect("read ok")
            .expect("notification line");

        let msg = parse_line(&line);
        assert_eq!(msg["jsonrpc"], "2.0");
        assert_eq!(msg["method"], "demo/notify");
        assert!(msg.get("id").is_none());
        assert!(msg.get("params").is_none());
    });

    let client = mcp_jsonrpc::Client::connect_io(client_read, client_write)
        .await
        .expect("client connect");
    client.notify("demo/notify", None).await.expect("notify ok");

    tokio::time::timeout(Duration::from_secs(1), &mut server_task)
        .await
        .expect("server task completed")
        .expect("server task ok");
}

#[tokio::test]
async fn notify_omits_params_when_null() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, _server_write) = tokio::io::split(server_stream);

    let mut server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();
        let line = lines
            .next_line()
            .await
            .expect("read ok")
            .expect("notification line");

        let msg = parse_line(&line);
        assert_eq!(msg["jsonrpc"], "2.0");
        assert_eq!(msg["method"], "demo/notify");
        assert!(msg.get("id").is_none());
        assert!(msg.get("params").is_none());
    });

    let client = mcp_jsonrpc::Client::connect_io(client_read, client_write)
        .await
        .expect("client connect");
    client
        .notify("demo/notify", Some(serde_json::Value::Null))
        .await
        .expect("notify ok");

    tokio::time::timeout(Duration::from_secs(1), &mut server_task)
        .await
        .expect("server task completed")
        .expect("server task ok");
}

#[tokio::test]
async fn request_optional_omits_params_when_none() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let mut server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();
        let line = lines
            .next_line()
            .await
            .expect("read ok")
            .expect("request line");

        let msg = parse_line(&line);
        assert_eq!(msg["jsonrpc"], "2.0");
        assert_eq!(msg["method"], "demo/noparams");
        assert!(msg.get("params").is_none());
        let id = msg["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "ok": true },
        });
        let mut out = serde_json::to_string(&response).unwrap();
        out.push('\n');
        server_write.write_all(out.as_bytes()).await.unwrap();
        server_write.flush().await.unwrap();
    });

    let client = mcp_jsonrpc::Client::connect_io(client_read, client_write)
        .await
        .expect("client connect");
    let result = client
        .request_optional("demo/noparams", None)
        .await
        .expect("request ok");
    assert_eq!(result, serde_json::json!({ "ok": true }));

    tokio::time::timeout(Duration::from_secs(1), &mut server_task)
        .await
        .expect("server task completed")
        .expect("server task ok");
}

#[tokio::test]
async fn request_optional_omits_params_when_null() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let mut server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();
        let line = lines
            .next_line()
            .await
            .expect("read ok")
            .expect("request line");

        let msg = parse_line(&line);
        assert_eq!(msg["jsonrpc"], "2.0");
        assert_eq!(msg["method"], "demo/noparams");
        assert!(msg.get("params").is_none());
        let id = msg["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "ok": true },
        });
        let mut out = serde_json::to_string(&response).unwrap();
        out.push('\n');
        server_write.write_all(out.as_bytes()).await.unwrap();
        server_write.flush().await.unwrap();
    });

    let client = mcp_jsonrpc::Client::connect_io(client_read, client_write)
        .await
        .expect("client connect");
    let result = client
        .request_optional("demo/noparams", Some(serde_json::Value::Null))
        .await
        .expect("request ok");
    assert_eq!(result, serde_json::json!({ "ok": true }));

    tokio::time::timeout(Duration::from_secs(1), &mut server_task)
        .await
        .expect("server task completed")
        .expect("server task ok");
}

#[tokio::test]
async fn request_roundtrip_supports_batch_responses() {
    let (client_stream, server_stream) = tokio::io::duplex(4096);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let mut server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();
        let line1 = lines
            .next_line()
            .await
            .expect("read ok")
            .expect("request line 1");
        let line2 = lines
            .next_line()
            .await
            .expect("read ok")
            .expect("request line 2");

        let msg1 = parse_line(&line1);
        let msg2 = parse_line(&line2);
        let id1 = msg1["id"].clone();
        let id2 = msg2["id"].clone();

        let batch = serde_json::json!([
            { "jsonrpc": "2.0", "id": id2, "result": { "ok": 2 } },
            { "jsonrpc": "2.0", "id": id1, "result": { "ok": 1 } }
        ]);
        let mut out = serde_json::to_string(&batch).unwrap();
        out.push('\n');
        server_write.write_all(out.as_bytes()).await.unwrap();
        server_write.flush().await.unwrap();
    });

    let client = mcp_jsonrpc::Client::connect_io(client_read, client_write)
        .await
        .expect("client connect");
    let handle = client.handle();

    let t1 = tokio::spawn(async move {
        handle
            .request("demo/one", serde_json::json!({}))
            .await
            .expect("request 1 ok")
    });

    let handle = client.handle();
    let t2 = tokio::spawn(async move {
        handle
            .request("demo/two", serde_json::json!({}))
            .await
            .expect("request 2 ok")
    });

    let r1 = tokio::time::timeout(Duration::from_secs(1), t1)
        .await
        .expect("task 1 completed")
        .expect("task 1 ok");
    let r2 = tokio::time::timeout(Duration::from_secs(1), t2)
        .await
        .expect("task 2 completed")
        .expect("task 2 ok");

    assert_eq!(r1, serde_json::json!({ "ok": 1 }));
    assert_eq!(r2, serde_json::json!({ "ok": 2 }));

    tokio::time::timeout(Duration::from_secs(1), &mut server_task)
        .await
        .expect("server task completed")
        .expect("server task ok");
}

#[tokio::test]
async fn responds_invalid_request_when_jsonrpc_is_not_2_0() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let mut server_task = tokio::spawn(async move {
        let request = serde_json::json!({
            "jsonrpc": "1.0",
            "id": 1,
            "method": "demo/ping",
        });
        let mut out = serde_json::to_string(&request).unwrap();
        out.push('\n');
        server_write.write_all(out.as_bytes()).await.unwrap();
        server_write.flush().await.unwrap();

        let mut lines = tokio::io::BufReader::new(server_read).lines();
        let line = lines
            .next_line()
            .await
            .expect("read ok")
            .expect("response line");
        let msg = parse_line(&line);
        assert_eq!(msg["jsonrpc"], "2.0");
        assert_eq!(msg["id"], 1);
        assert_eq!(msg["error"]["code"], serde_json::json!(-32600));
        assert_eq!(msg["error"]["message"], "invalid jsonrpc version");
    });

    let _client = mcp_jsonrpc::Client::connect_io(client_read, client_write)
        .await
        .expect("client connect");

    tokio::time::timeout(Duration::from_secs(1), &mut server_task)
        .await
        .expect("server task completed")
        .expect("server task ok");
}

#[tokio::test]
async fn request_rejected_when_pending_limit_reached() {
    let (client_stream, server_stream) = tokio::io::duplex(4096);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let mut options = mcp_jsonrpc::SpawnOptions::default();
    options.limits.max_pending_requests = 1;
    let client = mcp_jsonrpc::Client::connect_io_with_options(client_read, client_write, options)
        .await
        .expect("client connect");
    let handle = client.handle();

    let first_handle = handle.clone();
    let first = tokio::spawn(async move {
        first_handle
            .request("demo/one", serde_json::json!({}))
            .await
    });

    let mut lines = tokio::io::BufReader::new(server_read).lines();
    let line = lines
        .next_line()
        .await
        .expect("read ok")
        .expect("first request line");
    let msg = parse_line(&line);
    let id = msg["id"].clone();

    let err = handle
        .request("demo/two", serde_json::json!({}))
        .await
        .expect_err("second request should be rejected by pending limit");
    match err {
        mcp_jsonrpc::Error::Protocol(protocol) => {
            assert_eq!(protocol.kind, mcp_jsonrpc::ProtocolErrorKind::Other);
            assert!(protocol.message.contains("too many pending requests"));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": { "ok": true },
    });
    let mut out = serde_json::to_string(&response).unwrap();
    out.push('\n');
    server_write.write_all(out.as_bytes()).await.unwrap();
    server_write.flush().await.unwrap();

    let result = tokio::time::timeout(Duration::from_secs(1), first)
        .await
        .expect("first task completed")
        .expect("first task join ok")
        .expect("first request ok");
    assert_eq!(result, serde_json::json!({ "ok": true }));
}

#[tokio::test]
async fn server_request_with_invalid_method_type_does_not_consume_pending_request() {
    let (client_stream, server_stream) = tokio::io::duplex(4096);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let mut server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();
        let line = lines
            .next_line()
            .await
            .expect("read ok")
            .expect("request line");
        let msg = parse_line(&line);
        let id = msg["id"].clone();

        let invalid = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id.clone(),
            "method": {},
        });
        let mut out = serde_json::to_string(&invalid).unwrap();
        out.push('\n');
        server_write.write_all(out.as_bytes()).await.unwrap();
        server_write.flush().await.unwrap();

        let line = lines
            .next_line()
            .await
            .expect("read ok")
            .expect("invalid request response line");
        let msg = parse_line(&line);
        assert_eq!(msg["jsonrpc"], "2.0");
        assert_eq!(msg["id"], id);
        assert_eq!(msg["error"]["code"], serde_json::json!(-32600));
        assert_eq!(msg["error"]["message"], "invalid request method");

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "ok": true },
        });
        let mut out = serde_json::to_string(&response).unwrap();
        out.push('\n');
        server_write.write_all(out.as_bytes()).await.unwrap();
        server_write.flush().await.unwrap();
    });

    let client = mcp_jsonrpc::Client::connect_io(client_read, client_write)
        .await
        .expect("client connect");
    let result = client
        .request("demo/request", serde_json::json!({}))
        .await
        .expect("request ok");
    assert_eq!(result, serde_json::json!({ "ok": true }));

    tokio::time::timeout(Duration::from_secs(1), &mut server_task)
        .await
        .expect("server task completed")
        .expect("server task ok");
}

#[tokio::test]
async fn request_fails_when_server_sends_invalid_response_structure() {
    let (client_stream, server_stream) = tokio::io::duplex(1024);
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (server_read, mut server_write) = tokio::io::split(server_stream);

    let mut server_task = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(server_read).lines();
        let line = lines
            .next_line()
            .await
            .expect("read ok")
            .expect("request line");
        let msg = parse_line(&line);
        let id = msg["id"].clone();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "ok": true },
            "error": { "code": -32000, "message": "should not have both" }
        });
        let mut out = serde_json::to_string(&response).unwrap();
        out.push('\n');
        server_write.write_all(out.as_bytes()).await.unwrap();
        server_write.flush().await.unwrap();
    });

    let client = mcp_jsonrpc::Client::connect_io(client_read, client_write)
        .await
        .expect("client connect");
    let err = client
        .request("demo/request", serde_json::json!({}))
        .await
        .expect_err("request should fail");
    assert!(matches!(err, mcp_jsonrpc::Error::Protocol(_)));

    tokio::time::timeout(Duration::from_secs(1), &mut server_task)
        .await
        .expect("server task completed")
        .expect("server task ok");
}

#[tokio::test]
async fn reader_eof_shuts_down_client_write_end() {
    let (client_stream, server_stream) = tokio::io::duplex(64);
    let (client_read, client_write) = tokio::io::split(client_stream);

    let client = mcp_jsonrpc::Client::connect_io(client_read, client_write)
        .await
        .expect("client connect");
    let handle = client.handle();

    // Closing the peer stream should cause the client's reader task to hit EOF and close.
    drop(server_stream);
    tokio::time::timeout(Duration::from_secs(1), async {
        while !handle.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("client should close after peer EOF");

    let err = handle
        .notify("demo/notify", None)
        .await
        .expect_err("closed client should reject writes after peer EOF");
    assert!(matches!(
        err,
        mcp_jsonrpc::Error::Protocol(ref protocol)
            if protocol.kind == mcp_jsonrpc::ProtocolErrorKind::Closed
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn wait_closes_child_stdin_so_child_can_exit() {
    let mut cmd = tokio::process::Command::new("sh");
    cmd.arg("-c").arg("cat > /dev/null");

    let mut client = mcp_jsonrpc::Client::spawn_command(cmd)
        .await
        .expect("spawn client");

    let status = tokio::time::timeout(Duration::from_secs(1), client.wait())
        .await
        .expect("wait completed")
        .expect("wait ok")
        .expect("exit status");

    assert!(status.success(), "child exited unsuccessfully: {status}");
}

#[cfg(unix)]
#[tokio::test]
async fn wait_with_timeout_can_return_timeout_error() {
    let mut cmd = tokio::process::Command::new("sh");
    cmd.arg("-c").arg("exec sleep 10");

    let mut client = mcp_jsonrpc::Client::spawn_command(cmd)
        .await
        .expect("spawn client");

    let err = client
        .wait_with_timeout(
            Duration::from_millis(10),
            mcp_jsonrpc::WaitOnTimeout::ReturnError,
        )
        .await
        .expect_err("expected wait timeout error");
    assert!(err.is_wait_timeout(), "err={err:?}");

    let mut child = client.take_child().expect("child");
    child.start_kill().expect("kill");
    tokio::time::timeout(Duration::from_secs(1), child.wait())
        .await
        .expect("child wait completed")
        .expect("child wait ok");
}

#[cfg(unix)]
#[tokio::test]
async fn wait_with_timeout_can_kill_child_on_timeout() {
    let mut cmd = tokio::process::Command::new("sh");
    cmd.arg("-c").arg("exec sleep 10");

    let mut client = mcp_jsonrpc::Client::spawn_command(cmd)
        .await
        .expect("spawn client");

    let status = client
        .wait_with_timeout(
            Duration::from_millis(10),
            mcp_jsonrpc::WaitOnTimeout::Kill {
                kill_timeout: Duration::from_secs(1),
            },
        )
        .await
        .expect("wait ok")
        .expect("exit status");

    assert!(
        !status.success(),
        "expected killed child to exit unsuccessfully: {status}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn connect_io_rejects_stdout_log_symlink_path() {
    let base = std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
    let dir = tempfile::tempdir_in(base).unwrap();
    let target = dir.path().join("target.log");
    tokio::fs::write(&target, b"ok\n").await.unwrap();

    let link = dir.path().join("link.log");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let (client_stream, _server_stream) = tokio::io::duplex(64);
    let (client_read, client_write) = tokio::io::split(client_stream);

    let options = mcp_jsonrpc::SpawnOptions {
        stdout_log: Some(mcp_jsonrpc::StdoutLog {
            path: link,
            max_bytes_per_part: 1024,
            max_parts: None,
        }),
        ..Default::default()
    };

    let err = mcp_jsonrpc::Client::connect_io_with_options(client_read, client_write, options)
        .await
        .err()
        .expect("should reject stdout_log symlink");
    let mcp_jsonrpc::Error::Io(err) = err else {
        panic!("expected io error, got: {err:?}");
    };
    assert_eq!(err.raw_os_error(), Some(libc::ELOOP));
}
