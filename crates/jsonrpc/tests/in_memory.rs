use std::time::Duration;

use mcp_jsonrpc::Id;
use serde_json::Value;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncWriteExt;

fn parse_line(line: &str) -> Value {
    serde_json::from_str(line).expect("valid json")
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
        assert_eq!(req.params, serde_json::json!({ "n": 42 }));
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
