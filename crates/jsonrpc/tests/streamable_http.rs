use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Notify};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streamable_http_allows_initial_sse_405_and_retries_after_202() {
    #[derive(Default)]
    struct State {
        get_count: AtomicUsize,
        post_count: AtomicUsize,
        response_json: Mutex<Option<Vec<u8>>>,
        response_ready: Notify,
    }

    let state = Arc::new(State::default());
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_state = state.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            let server_state = server_state.clone();
            tokio::spawn(async move {
                let mut buf = Vec::<u8>::new();
                let header_end = loop {
                    let mut tmp = [0u8; 1024];
                    let n = match socket.read(&mut tmp).await {
                        Ok(0) => return,
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(pos) = find_double_crlf(&buf) {
                        break pos;
                    }
                    if buf.len() > 1024 * 64 {
                        return;
                    }
                };

                let headers = &buf[..header_end];
                let req = match parse_request_headers(headers) {
                    Some(parts) => parts,
                    None => return,
                };
                let ParsedRequest {
                    method,
                    path,
                    content_length,
                    ..
                } = req;

                let total_needed = header_end + 4 + content_length;
                while buf.len() < total_needed {
                    let mut tmp = vec![0u8; total_needed - buf.len()];
                    let n = match socket.read(&mut tmp).await {
                        Ok(0) => return,
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    buf.extend_from_slice(&tmp[..n]);
                }

                let body_start = header_end + 4;
                let body = &buf[body_start..body_start + content_length];

                match (method.as_str(), path.as_str()) {
                    ("GET", "/mcp") => {
                        let get_idx = server_state.get_count.fetch_add(1, Ordering::SeqCst);
                        if get_idx == 0 {
                            let _ = socket
                                .write_all(
                                    b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                )
                                .await;
                            return;
                        }

                        let _ = socket
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n",
                            )
                            .await;

                        let response = loop {
                            if let Some(response) = server_state.response_json.lock().await.clone()
                            {
                                break response;
                            }
                            server_state.response_ready.notified().await;
                        };

                        let mut sse = Vec::new();
                        sse.extend_from_slice(b"data: ");
                        sse.extend_from_slice(&response);
                        sse.extend_from_slice(b"\n\n");
                        let _ = socket.write_all(&sse).await;
                        let _ = socket.flush().await;

                        // Keep the connection open until the client closes.
                        let mut drain = [0u8; 1024];
                        let _ = tokio::time::timeout(Duration::from_secs(2), async {
                            loop {
                                match socket.read(&mut drain).await {
                                    Ok(0) => break,
                                    Ok(_) => continue,
                                    Err(_) => break,
                                }
                            }
                        })
                        .await;
                    }
                    ("POST", "/mcp") => {
                        server_state.post_count.fetch_add(1, Ordering::SeqCst);
                        let parsed: serde_json::Value = match serde_json::from_slice(body) {
                            Ok(v) => v,
                            Err(_) => return,
                        };
                        let id = parsed.get("id").cloned().unwrap_or(serde_json::Value::Null);
                        let response = serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": { "ok": true },
                        });
                        let response = serde_json::to_vec(&response).unwrap();
                        *server_state.response_json.lock().await = Some(response);
                        server_state.response_ready.notify_waiters();

                        let _ = socket
                            .write_all(
                                b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                    }
                    _ => {
                        let _ = socket
                            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                            .await;
                    }
                }
            });
        }
    });

    let url = format!("http://{}/mcp", addr);
    let client = mcp_jsonrpc::Client::connect_streamable_http(&url)
        .await
        .expect("connect streamable http");

    let result = client
        .request("ping", serde_json::json!({}))
        .await
        .expect("request should succeed");
    assert_eq!(result, serde_json::json!({ "ok": true }));

    assert_eq!(state.get_count.load(Ordering::SeqCst), 2);
    assert_eq!(state.post_count.load(Ordering::SeqCst), 1);

    drop(client);
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streamable_http_propagates_mcp_session_id_and_updates() {
    #[derive(Default)]
    struct State {
        get_count: AtomicUsize,
        post_count: AtomicUsize,
        response_json: Mutex<Option<Vec<u8>>>,
        response_ready: Notify,
        first_post_session: Mutex<Option<Option<String>>>,
        second_get_session: Mutex<Option<Option<String>>>,
        second_post_session: Mutex<Option<Option<String>>>,
        third_post_session: Mutex<Option<Option<String>>>,
    }

    let state = Arc::new(State::default());
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_state = state.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            let server_state = server_state.clone();
            tokio::spawn(async move {
                let Some((req, body)) = read_http_request(&mut socket).await else {
                    return;
                };

                match (req.method.as_str(), req.path.as_str()) {
                    ("GET", "/mcp") => {
                        let get_idx = server_state.get_count.fetch_add(1, Ordering::SeqCst);
                        if get_idx == 0 {
                            let _ = socket
                                .write_all(
                                    b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                )
                                .await;
                            return;
                        }
                        if get_idx == 1 {
                            let session = req.headers.get("mcp-session-id").cloned();
                            *server_state.second_get_session.lock().await = Some(session);
                        }

                        let _ = socket
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n",
                            )
                            .await;

                        let response = loop {
                            if let Some(response) = server_state.response_json.lock().await.clone()
                            {
                                break response;
                            }
                            server_state.response_ready.notified().await;
                        };

                        let mut sse = Vec::new();
                        sse.extend_from_slice(b"data: ");
                        sse.extend_from_slice(&response);
                        sse.extend_from_slice(b"\n\n");
                        let _ = socket.write_all(&sse).await;
                        let _ = socket.flush().await;

                        // Keep the connection open until the client closes.
                        let mut drain = [0u8; 1024];
                        let _ = tokio::time::timeout(Duration::from_secs(2), async {
                            loop {
                                match socket.read(&mut drain).await {
                                    Ok(0) => break,
                                    Ok(_) => continue,
                                    Err(_) => break,
                                }
                            }
                        })
                        .await;
                    }
                    ("POST", "/mcp") => {
                        let post_idx = server_state.post_count.fetch_add(1, Ordering::SeqCst);
                        let session = req.headers.get("mcp-session-id").cloned();

                        let parsed: serde_json::Value = match serde_json::from_slice(&body) {
                            Ok(v) => v,
                            Err(_) => return,
                        };
                        let id = parsed.get("id").cloned().unwrap_or(serde_json::Value::Null);

                        match post_idx {
                            0 => {
                                *server_state.first_post_session.lock().await = Some(session);

                                let response = serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "result": { "ok": true },
                                });
                                let response = serde_json::to_vec(&response).unwrap();
                                *server_state.response_json.lock().await = Some(response);
                                server_state.response_ready.notify_waiters();

                                let _ = socket
                                    .write_all(
                                        b"HTTP/1.1 202 Accepted\r\nmcp-session-id: abc\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                    )
                                    .await;
                            }
                            1 => {
                                *server_state.second_post_session.lock().await = Some(session);

                                let response = serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "result": { "ok": true },
                                });
                                let body = serde_json::to_vec(&response).unwrap();
                                let _ = write_http_response(
                                    &mut socket,
                                    "200 OK",
                                    &[
                                        ("Content-Type", "application/json".to_string()),
                                        ("mcp-session-id", "def".to_string()),
                                        ("Connection", "close".to_string()),
                                    ],
                                    &body,
                                )
                                .await;
                            }
                            2 => {
                                *server_state.third_post_session.lock().await = Some(session);

                                let response = serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "result": { "ok": true },
                                });
                                let body = serde_json::to_vec(&response).unwrap();
                                let _ = write_http_response(
                                    &mut socket,
                                    "200 OK",
                                    &[
                                        ("Content-Type", "application/json".to_string()),
                                        ("Connection", "close".to_string()),
                                    ],
                                    &body,
                                )
                                .await;
                            }
                            _ => {
                                let _ = socket
                                    .write_all(
                                        b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                    )
                                    .await;
                            }
                        }
                    }
                    _ => {
                        let _ = socket
                            .write_all(
                                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                    }
                }
            });
        }
    });

    let url = format!("http://{}/mcp", addr);
    let client = mcp_jsonrpc::Client::connect_streamable_http(&url)
        .await
        .expect("connect streamable http");

    for method in ["ping1", "ping2", "ping3"] {
        let result = client
            .request(method, serde_json::json!({}))
            .await
            .expect("request should succeed");
        assert_eq!(result, serde_json::json!({ "ok": true }));
    }

    assert_eq!(*state.first_post_session.lock().await, Some(None));
    assert_eq!(
        *state.second_get_session.lock().await,
        Some(Some("abc".to_string()))
    );
    assert_eq!(
        *state.second_post_session.lock().await,
        Some(Some("abc".to_string()))
    );
    assert_eq!(
        *state.third_post_session.lock().await,
        Some(Some("def".to_string()))
    );

    drop(client);
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streamable_http_clamps_zero_max_message_bytes_to_minimum() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let Some((req, body)) = read_http_request(&mut socket).await else {
                    return;
                };

                match (req.method.as_str(), req.path.as_str()) {
                    ("GET", "/mcp") => {
                        let _ = socket
                            .write_all(
                                b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                    }
                    ("POST", "/mcp") => {
                        let parsed: serde_json::Value = match serde_json::from_slice(&body) {
                            Ok(v) => v,
                            Err(_) => return,
                        };
                        let id = parsed.get("id").cloned().unwrap_or(serde_json::Value::Null);
                        let response = serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": { "ok": true },
                        });
                        let body = serde_json::to_vec(&response).unwrap();
                        let _ = write_http_response(
                            &mut socket,
                            "200 OK",
                            &[
                                ("Content-Type", "application/json".to_string()),
                                ("Connection", "close".to_string()),
                            ],
                            &body,
                        )
                        .await;
                    }
                    _ => {
                        let _ = socket
                            .write_all(
                                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                    }
                }
            });
        }
    });

    let mut options = mcp_jsonrpc::SpawnOptions::default();
    options.limits.max_message_bytes = 0;
    let url = format!("http://{}/mcp", addr);
    let client = mcp_jsonrpc::Client::connect_streamable_http_with_options(
        &url,
        mcp_jsonrpc::StreamableHttpOptions::default(),
        options,
    )
    .await
    .expect("connect streamable http");

    let result = client
        .request("ping", serde_json::json!({}))
        .await
        .expect("request should succeed");
    assert_eq!(result, serde_json::json!({ "ok": true }));

    drop(client);
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streamable_http_post_can_return_sse_and_stops_on_done() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let Some((req, body)) = read_http_request(&mut socket).await else {
                    return;
                };

                match (req.method.as_str(), req.path.as_str()) {
                    ("GET", "/mcp") => {
                        let _ = socket
                            .write_all(
                                b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                    }
                    ("POST", "/mcp") => {
                        let parsed: serde_json::Value = match serde_json::from_slice(&body) {
                            Ok(v) => v,
                            Err(_) => return,
                        };
                        let id = parsed.get("id").cloned().unwrap_or(serde_json::Value::Null);

                        let response = serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": { "ok": true },
                        });
                        let response = serde_json::to_vec(&response).unwrap();

                        let mut sse = Vec::new();
                        sse.extend_from_slice(b"data: ");
                        sse.extend_from_slice(&response);
                        sse.extend_from_slice(b"\n\n");
                        sse.extend_from_slice(b"data: [DONE]\n\n");

                        let _ = write_http_response(
                            &mut socket,
                            "200 OK",
                            &[
                                ("Content-Type", "text/event-stream".to_string()),
                                ("Connection", "close".to_string()),
                            ],
                            &sse,
                        )
                        .await;
                    }
                    _ => {
                        let _ = socket
                            .write_all(
                                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                    }
                }
            });
        }
    });

    let url = format!("http://{}/mcp", addr);
    let client = mcp_jsonrpc::Client::connect_streamable_http(&url)
        .await
        .expect("connect streamable http");

    let result = client
        .request("ping", serde_json::json!({}))
        .await
        .expect("request should succeed");
    assert_eq!(result, serde_json::json!({ "ok": true }));

    drop(client);
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streamable_http_bridges_unexpected_content_type_to_jsonrpc_error() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let Some((req, _body)) = read_http_request(&mut socket).await else {
                    return;
                };

                match (req.method.as_str(), req.path.as_str()) {
                    ("GET", "/mcp") => {
                        let _ = socket
                            .write_all(
                                b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                    }
                    ("POST", "/mcp") => {
                        let _ = write_http_response(
                            &mut socket,
                            "200 OK",
                            &[
                                ("Content-Type", "text/plain".to_string()),
                                ("Connection", "close".to_string()),
                            ],
                            b"hello",
                        )
                        .await;
                    }
                    _ => {
                        let _ = socket
                            .write_all(
                                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                    }
                }
            });
        }
    });

    let url = format!("http://{}/mcp", addr);
    let client = mcp_jsonrpc::Client::connect_streamable_http(&url)
        .await
        .expect("connect streamable http");

    let err = client
        .request("ping", serde_json::json!({}))
        .await
        .expect_err("request should fail");
    match err {
        mcp_jsonrpc::Error::Rpc { code, message, .. } => {
            assert_eq!(code, -32000);
            assert_eq!(message, "unexpected content-type for json response");
        }
        other => panic!("unexpected error: {other:?}"),
    }

    drop(client);
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streamable_http_bridges_oversized_json_body_to_jsonrpc_error() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let Some((req, body)) = read_http_request(&mut socket).await else {
                    return;
                };

                match (req.method.as_str(), req.path.as_str()) {
                    ("GET", "/mcp") => {
                        let _ = socket
                            .write_all(
                                b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                    }
                    ("POST", "/mcp") => {
                        let parsed: serde_json::Value = match serde_json::from_slice(&body) {
                            Ok(v) => v,
                            Err(_) => return,
                        };
                        let id = parsed.get("id").cloned().unwrap_or(serde_json::Value::Null);
                        let response = serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": { "payload": "x".repeat(4096) },
                        });
                        let body = serde_json::to_vec(&response).unwrap();
                        let _ = write_http_response(
                            &mut socket,
                            "200 OK",
                            &[
                                ("Content-Type", "application/json".to_string()),
                                ("Connection", "close".to_string()),
                            ],
                            &body,
                        )
                        .await;
                    }
                    _ => {
                        let _ = socket
                            .write_all(
                                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                    }
                }
            });
        }
    });

    let url = format!("http://{}/mcp", addr);
    let mut spawn_options = mcp_jsonrpc::SpawnOptions::default();
    spawn_options.limits.max_message_bytes = 256;
    let client = mcp_jsonrpc::Client::connect_streamable_http_with_options(
        &url,
        mcp_jsonrpc::StreamableHttpOptions::default(),
        spawn_options,
    )
    .await
    .expect("connect streamable http");

    let err = client
        .request("ping", serde_json::json!({}))
        .await
        .expect_err("request should fail on oversized http response body");
    match err {
        mcp_jsonrpc::Error::Rpc { code, message, .. } => {
            assert_eq!(code, -32000);
            assert_eq!(message, "http response too large");
        }
        other => panic!("unexpected error: {other:?}"),
    }

    drop(client);
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streamable_http_bridges_empty_json_body_to_jsonrpc_error() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let Some((req, _body)) = read_http_request(&mut socket).await else {
                    return;
                };

                match (req.method.as_str(), req.path.as_str()) {
                    ("GET", "/mcp") => {
                        let _ = socket
                            .write_all(
                                b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                    }
                    ("POST", "/mcp") => {
                        let _ = write_http_response(
                            &mut socket,
                            "200 OK",
                            &[
                                ("Content-Type", "application/json".to_string()),
                                ("Connection", "close".to_string()),
                            ],
                            b"",
                        )
                        .await;
                    }
                    _ => {
                        let _ = socket
                            .write_all(
                                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                    }
                }
            });
        }
    });

    let url = format!("http://{}/mcp", addr);
    let client = mcp_jsonrpc::Client::connect_streamable_http(&url)
        .await
        .expect("connect streamable http");

    let err = client
        .request("ping", serde_json::json!({}))
        .await
        .expect_err("request should fail");
    match err {
        mcp_jsonrpc::Error::Rpc { code, message, .. } => {
            assert_eq!(code, -32000);
            assert_eq!(message, "http response is empty");
        }
        other => panic!("unexpected error: {other:?}"),
    }

    drop(client);
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streamable_http_notification_post_failure_closes_client() {
    #[derive(Default)]
    struct State {
        post_count: AtomicUsize,
    }

    let state = Arc::new(State::default());
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_state = state.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            let server_state = server_state.clone();
            tokio::spawn(async move {
                let Some((req, body)) = read_http_request(&mut socket).await else {
                    return;
                };

                match (req.method.as_str(), req.path.as_str()) {
                    ("GET", "/mcp") => {
                        let _ = socket
                            .write_all(
                                b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                    }
                    ("POST", "/mcp") => {
                        server_state.post_count.fetch_add(1, Ordering::SeqCst);
                        let parsed: serde_json::Value = match serde_json::from_slice(&body) {
                            Ok(v) => v,
                            Err(_) => return,
                        };
                        assert_eq!(parsed["method"], "demo/notify");
                        assert!(parsed.get("id").is_none());

                        let _ = write_http_response(
                            &mut socket,
                            "500 Internal Server Error",
                            &[
                                ("Content-Type", "application/json".to_string()),
                                ("Connection", "close".to_string()),
                            ],
                            br#"{"error":"boom"}"#,
                        )
                        .await;
                    }
                    _ => {
                        let _ = socket
                            .write_all(
                                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                    }
                }
            });
        }
    });

    let url = format!("http://{}/mcp", addr);
    let client = mcp_jsonrpc::Client::connect_streamable_http(&url)
        .await
        .expect("connect streamable http");
    let handle = client.handle();

    client
        .notify("demo/notify", Some(serde_json::json!({ "x": 1 })))
        .await
        .expect("notify should write to bridge");

    tokio::time::timeout(Duration::from_secs(1), async {
        while !handle.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("notification transport failure should close client");

    let reason = handle.close_reason().unwrap_or_default();
    assert!(reason.contains("notification failed"));
    assert!(reason.contains("http error: 500"));
    assert_eq!(state.post_count.load(Ordering::SeqCst), 1);

    let err = client
        .request("ping", serde_json::json!({}))
        .await
        .expect_err("request should fail after close");
    assert!(matches!(
        err,
        mcp_jsonrpc::Error::Protocol(ref protocol)
            if protocol.kind == mcp_jsonrpc::ProtocolErrorKind::Closed
    ));

    drop(client);
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streamable_http_error_without_request_timeout_does_not_hang() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let Some((req, _body)) = read_http_request(&mut socket).await else {
                    return;
                };

                match (req.method.as_str(), req.path.as_str()) {
                    ("GET", "/mcp") => {
                        let _ = socket
                            .write_all(
                                b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                    }
                    ("POST", "/mcp") => {
                        let _ = socket
                            .write_all(
                                b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nConnection: keep-alive\r\n\r\n",
                            )
                            .await;
                        let _ = socket.flush().await;
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                    _ => {
                        let _ = socket
                            .write_all(
                                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                    }
                }
            });
        }
    });

    let url = format!("http://{}/mcp", addr);
    let client = mcp_jsonrpc::Client::connect_streamable_http_with_options(
        &url,
        mcp_jsonrpc::StreamableHttpOptions {
            request_timeout: None,
            ..Default::default()
        },
        mcp_jsonrpc::SpawnOptions::default(),
    )
    .await
    .expect("connect streamable http");

    let request = client.request("ping", serde_json::json!({}));
    let err = match tokio::time::timeout(Duration::from_millis(300), request).await {
        Ok(Ok(value)) => panic!("request should fail, got {value:?}"),
        Ok(Err(err)) => err,
        Err(_) => panic!("request hung on http error response without request_timeout"),
    };
    match err {
        mcp_jsonrpc::Error::Rpc { code, message, .. } => {
            assert_eq!(code, -32000);
            assert_eq!(message, "http error: 500 Internal Server Error");
        }
        other => panic!("unexpected error: {other:?}"),
    }

    drop(client);
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streamable_http_close_aborts_transport_tasks_and_closes_sse_connection() {
    let disconnected = Arc::new(AtomicBool::new(false));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let disconnected_for_server = disconnected.clone();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let Some((req, _)) = read_http_request(&mut socket).await else {
            return;
        };

        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/mcp");
        let _ = socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n",
            )
            .await;
        let _ = socket.flush().await;

        let mut buf = [0u8; 1024];
        let disconnected = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match socket.read(&mut buf).await {
                    Ok(0) => return true,
                    Ok(_) => {}
                    Err(_) => return true,
                }
            }
        })
        .await
        .unwrap_or(false);

        disconnected_for_server.store(disconnected, Ordering::SeqCst);
    });

    let url = format!("http://{}/mcp", addr);
    let client = mcp_jsonrpc::Client::connect_streamable_http(&url)
        .await
        .expect("connect streamable http");

    client.close("test close").await;

    tokio::time::timeout(Duration::from_secs(1), async {
        while !disconnected.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("sse connection should close after Client::close");

    server.await.unwrap();
    drop(client);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streamable_http_bridges_pretty_json_body() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let Some((req, body)) = read_http_request(&mut socket).await else {
                    return;
                };

                match (req.method.as_str(), req.path.as_str()) {
                    ("GET", "/mcp") => {
                        let _ = socket
                            .write_all(
                                b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                    }
                    ("POST", "/mcp") => {
                        let parsed: serde_json::Value = match serde_json::from_slice(&body) {
                            Ok(v) => v,
                            Err(_) => return,
                        };
                        let id = parsed.get("id").cloned().unwrap_or(serde_json::Value::Null);
                        let response = serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": { "ok": true },
                        });
                        let body = serde_json::to_string_pretty(&response)
                            .unwrap()
                            .into_bytes();
                        let _ = write_http_response(
                            &mut socket,
                            "200 OK",
                            &[
                                ("Content-Type", "application/json".to_string()),
                                ("Connection", "close".to_string()),
                            ],
                            &body,
                        )
                        .await;
                    }
                    _ => {
                        let _ = socket
                            .write_all(
                                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                    }
                }
            });
        }
    });

    let url = format!("http://{}/mcp", addr);
    let client = mcp_jsonrpc::Client::connect_streamable_http(&url)
        .await
        .expect("connect streamable http");

    let result = client
        .request("ping", serde_json::json!({}))
        .await
        .expect("request should succeed");
    assert_eq!(result, serde_json::json!({ "ok": true }));

    drop(client);
    server.abort();
}

#[derive(Debug)]
struct ParsedRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    content_length: usize,
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_request_headers(headers: &[u8]) -> Option<ParsedRequest> {
    let text = std::str::from_utf8(headers).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?.trim();
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    let mut content_length = 0usize;
    let mut header_map = HashMap::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse().ok()?;
        } else {
            header_map.insert(name.to_ascii_lowercase(), value.to_string());
        }
    }
    Some(ParsedRequest {
        method,
        path,
        headers: header_map,
        content_length,
    })
}

async fn read_http_request(socket: &mut TcpStream) -> Option<(ParsedRequest, Vec<u8>)> {
    let mut buf = Vec::<u8>::new();
    let header_end = loop {
        let mut tmp = [0u8; 1024];
        let n = socket.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_double_crlf(&buf) {
            break pos;
        }
        if buf.len() > 1024 * 64 {
            return None;
        }
    };

    let headers = &buf[..header_end];
    let req = parse_request_headers(headers)?;

    let total_needed = header_end + 4 + req.content_length;
    while buf.len() < total_needed {
        let mut tmp = vec![0u8; total_needed - buf.len()];
        let n = socket.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    }

    let body_start = header_end + 4;
    let body = buf[body_start..body_start + req.content_length].to_vec();
    Some((req, body))
}

async fn write_http_response(
    socket: &mut TcpStream,
    status: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> std::io::Result<()> {
    let mut out = Vec::new();
    out.extend_from_slice(format!("HTTP/1.1 {status}\r\n").as_bytes());
    out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    for (name, value) in headers {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    socket.write_all(&out).await?;
    socket.flush().await?;
    Ok(())
}
