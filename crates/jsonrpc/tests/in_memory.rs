use std::time::Duration;

use mcp_jsonrpc::Id;
use serde_json::Value;
use tokio::io::AsyncBufReadExt;
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
