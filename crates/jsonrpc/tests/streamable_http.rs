use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
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
                let (method, path, content_length) = match parse_request_headers(headers) {
                    Some(parts) => parts,
                    None => return,
                };

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
                                    b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n",
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
                            .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n")
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

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_request_headers(headers: &[u8]) -> Option<(String, String, usize)> {
    let text = std::str::from_utf8(headers).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?.trim();
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    let mut content_length = 0usize;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse().ok()?;
        }
    }
    Some((method, path, content_length))
}
