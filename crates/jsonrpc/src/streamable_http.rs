use std::io;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio_util::io::StreamReader;

use crate::{
    Client, ClientHandle, Error, ProtocolErrorKind, SpawnOptions, StreamableHttpOptions,
};

fn ends_with_ignore_ascii_case(haystack: &str, suffix: &str) -> bool {
    if suffix.len() > haystack.len() {
        return false;
    }
    haystack
        .get(haystack.len() - suffix.len()..)
        .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
}

fn media_type(content_type: &str) -> &str {
    content_type.trim().split(';').next().unwrap_or("").trim()
}

fn is_event_stream_content_type(content_type: &str) -> bool {
    media_type(content_type).eq_ignore_ascii_case("text/event-stream")
}

fn is_json_content_type(content_type: &str) -> bool {
    if content_type.trim().is_empty() {
        return true;
    }
    let ct = media_type(content_type);
    let Some((ty, subty)) = ct.split_once('/') else {
        return false;
    };
    if !ty.eq_ignore_ascii_case("application") {
        return false;
    }
    if subty.eq_ignore_ascii_case("json") {
        return true;
    }
    ends_with_ignore_ascii_case(subty, "+json")
}

const SSE_EVENT_BUFFER_RETAIN_BYTES: usize = 64 * 1024;

impl Client {
    pub async fn connect_streamable_http(url: &str) -> Result<Self, Error> {
        Self::connect_streamable_http_with_options(
            url,
            StreamableHttpOptions::default(),
            SpawnOptions::default(),
        )
        .await
    }

    pub async fn connect_streamable_http_with_options(
        url: &str,
        http_options: StreamableHttpOptions,
        options: SpawnOptions,
    ) -> Result<Self, Error> {
        Self::connect_streamable_http_split_with_options(url, url, http_options, options).await
    }

    pub async fn connect_streamable_http_split_with_options(
        sse_url: &str,
        post_url: &str,
        http_options: StreamableHttpOptions,
        options: SpawnOptions,
    ) -> Result<Self, Error> {
        async fn try_connect_sse(
            http_client: &reqwest::Client,
            sse_url: &str,
            connect_timeout: Option<Duration>,
            session_id: &Arc<tokio::sync::Mutex<Option<String>>>,
        ) -> Result<Option<reqwest::Response>, Error> {
            let mut req = http_client
                .get(sse_url)
                .header(reqwest::header::ACCEPT, "text/event-stream");
            {
                let guard = session_id.lock().await;
                if let Some(session) = guard.as_deref() {
                    req = req.header("mcp-session-id", session);
                }
            }

            let send = req.send();
            let resp = match connect_timeout {
                Some(timeout) => match tokio::time::timeout(timeout, send).await {
                    Ok(resp) => resp,
                    Err(_) => {
                        return Err(Error::protocol(
                            ProtocolErrorKind::StreamableHttp,
                            "connect streamable http failed: request timed out",
                        ));
                    }
                },
                None => send.await,
            }
            .map_err(|err| {
                Error::protocol(
                    ProtocolErrorKind::StreamableHttp,
                    format!(
                        "connect streamable http failed: {}",
                        redact_reqwest_error(&err)
                    ),
                )
            })?;

            if resp.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED {
                return Ok(None);
            }

            if !resp.status().is_success() {
                return Err(Error::protocol(
                    ProtocolErrorKind::StreamableHttp,
                    format!(
                        "streamable http SSE connect failed: status={}",
                        resp.status()
                    ),
                ));
            }

            let content_type = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !is_event_stream_content_type(content_type) {
                return Err(Error::protocol(
                    ProtocolErrorKind::StreamableHttp,
                    format!(
                        "streamable http SSE connect failed: expected content-type text/event-stream, got {content_type}"
                    ),
                ));
            }

            if let Some(value) = resp.headers().get("mcp-session-id") {
                if let Ok(value) = value.to_str() {
                    let mut guard = session_id.lock().await;
                    if guard.as_deref() != Some(value) {
                        *guard = Some(value.to_owned());
                    }
                }
            }

            Ok(Some(resp))
        }

        let max_message_bytes =
            crate::normalize_max_message_bytes(options.limits.max_message_bytes);
        let connect_timeout = http_options.connect_timeout;
        let request_timeout = http_options.request_timeout;
        let follow_redirects = http_options.follow_redirects;
        let error_body_preview_bytes = http_options.error_body_preview_bytes;

        let mut headers = reqwest::header::HeaderMap::new();
        for (key, value) in http_options.headers {
            let name = reqwest::header::HeaderName::from_bytes(key.as_bytes()).map_err(|_| {
                Error::protocol(
                    ProtocolErrorKind::InvalidInput,
                    format!("invalid http header name: {key}"),
                )
            })?;
            let value = reqwest::header::HeaderValue::from_str(&value).map_err(|_| {
                Error::protocol(
                    ProtocolErrorKind::InvalidInput,
                    format!("invalid http header value: {key}"),
                )
            })?;
            headers.insert(name, value);
        }

        let mut http_builder = reqwest::Client::builder()
            // Avoid automatic proxy environment variable loading by default.
            .no_proxy()
            .redirect(if follow_redirects {
                reqwest::redirect::Policy::limited(10)
            } else {
                reqwest::redirect::Policy::none()
            })
            .default_headers(headers);
        if let Some(timeout) = connect_timeout {
            http_builder = http_builder.connect_timeout(timeout);
        }
        let http_client = http_builder.build().map_err(|err| {
            Error::protocol(
                ProtocolErrorKind::InvalidInput,
                format!("build http client failed: {err}"),
            )
        })?;

        let (client_stream, bridge_stream) = tokio::io::duplex(1024 * 64);
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (bridge_read, bridge_write) = tokio::io::split(bridge_stream);

        let mut client = Self::connect_io_with_options(client_read, client_write, options).await?;
        let transport_handle = client.handle.clone();

        let writer: Arc<tokio::sync::Mutex<_>> = Arc::new(tokio::sync::Mutex::new(bridge_write));
        let session_id: Arc<tokio::sync::Mutex<Option<String>>> =
            Arc::new(tokio::sync::Mutex::new(None));

        let (sse_wake_tx, sse_wake_rx) = mpsc::channel::<()>(1);
        let sse_resp = try_connect_sse(&http_client, sse_url, connect_timeout, &session_id).await?;

        let post_url = post_url.to_string();
        let http_client_post = http_client.clone();
        let writer_post = writer.clone();
        let session_id_post = session_id.clone();
        let sse_wake_post = sse_wake_tx.clone();
        let request_timeout_post = request_timeout;
        let error_body_preview_bytes_post = error_body_preview_bytes;
        let handle_post = transport_handle.clone();
        let post_task = tokio::spawn(async move {
            HttpPostBridge {
                bridge_read,
                writer: writer_post,
                handle: handle_post,
                http_client: http_client_post,
                post_url,
                session_id: session_id_post,
                sse_wake: sse_wake_post,
                max_message_bytes,
                request_timeout: request_timeout_post,
                error_body_preview_bytes: error_body_preview_bytes_post,
            }
            .run()
            .await;
        });

        let writer_sse = writer.clone();
        let session_id_sse = session_id.clone();
        let sse_url = sse_url.to_string();
        let http_client_sse = http_client.clone();
        let handle_sse = transport_handle;
        let sse_task = tokio::spawn(async move {
            let Some(resp) = sse_resp else {
                let mut wake_rx = sse_wake_rx;
                while wake_rx.recv().await.is_some() {
                    match try_connect_sse(
                        &http_client_sse,
                        &sse_url,
                        connect_timeout,
                        &session_id_sse,
                    )
                    .await
                    {
                        Ok(Some(resp)) => {
                            pump_sse(
                                resp,
                                writer_sse.clone(),
                                max_message_bytes,
                                handle_sse.clone(),
                            )
                            .await;
                            return;
                        }
                        Ok(None) => {}
                        Err(err) => {
                            handle_sse
                                .close_with_reason(format!(
                                    "streamable http SSE connection failed: {err}"
                                ))
                                .await;
                            let mut writer = writer_sse.lock().await;
                            let _ = writer.shutdown().await;
                            return;
                        }
                    }
                }
                return;
            };

            let _ = sse_wake_rx;
            pump_sse(resp, writer_sse.clone(), max_message_bytes, handle_sse).await;
        });

        client.transport_tasks.push(post_task);
        client.transport_tasks.push(sse_task);
        Ok(client)
    }
}

struct HttpPostBridge {
    bridge_read: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    writer: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<tokio::io::DuplexStream>>>,
    handle: ClientHandle,
    http_client: reqwest::Client,
    post_url: String,
    session_id: Arc<tokio::sync::Mutex<Option<String>>>,
    sse_wake: mpsc::Sender<()>,
    max_message_bytes: usize,
    request_timeout: Option<Duration>,
    error_body_preview_bytes: usize,
}

impl HttpPostBridge {
    async fn run(self) {
        const HTTP_TRANSPORT_ERROR: i64 = -32000;

        let Self {
            bridge_read,
            writer,
            handle,
            http_client,
            post_url,
            session_id,
            sse_wake,
            max_message_bytes,
            request_timeout,
            error_body_preview_bytes,
        } = self;

        let mut reader = tokio::io::BufReader::new(bridge_read);
        loop {
            let line = match crate::read_line_limited(&mut reader, max_message_bytes).await {
                Ok(Some(line)) => line,
                Ok(None) => return,
                Err(err) => {
                    close_post_bridge(
                        &writer,
                        &handle,
                        format!("streamable http POST bridge failed: {err}"),
                    )
                    .await;
                    return;
                }
            };

            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }

            let parsed: Value = match serde_json::from_slice(&line) {
                Ok(v) => v,
                Err(err) => {
                    close_post_bridge(
                        &writer,
                        &handle,
                        format!(
                            "streamable http POST bridge received invalid JSON from client: {err}"
                        ),
                    )
                    .await;
                    return;
                }
            };
            let id = parsed.get("id").cloned();

            let mut req = http_client
                .post(&post_url)
                .header(
                    reqwest::header::ACCEPT,
                    "application/json, text/event-stream",
                )
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(line);

            {
                let guard = session_id.lock().await;
                if let Some(session) = guard.as_deref() {
                    req = req.header("mcp-session-id", session);
                }
            }

            let send = req.send();
            let resp = match request_timeout {
                Some(timeout) => match tokio::time::timeout(timeout, send).await {
                    Ok(resp) => resp,
                    Err(_) => {
                        if !emit_post_bridge_error(
                            &writer,
                            &handle,
                            id,
                            HTTP_TRANSPORT_ERROR,
                            "http request timed out".to_string(),
                            None,
                        )
                        .await
                        {
                            return;
                        }
                        continue;
                    }
                },
                None => send.await,
            };
            let resp = match resp {
                Ok(resp) => resp,
                Err(err) => {
                    if !emit_post_bridge_error(
                        &writer,
                        &handle,
                        id,
                        HTTP_TRANSPORT_ERROR,
                        format!("http request failed: {}", redact_reqwest_error(&err)),
                        None,
                    )
                    .await
                    {
                        return;
                    }
                    continue;
                }
            };

            let mut should_wake_sse = resp.status() == reqwest::StatusCode::ACCEPTED;
            if let Some(value) = resp.headers().get("mcp-session-id") {
                if let Ok(value) = value.to_str() {
                    let mut guard = session_id.lock().await;
                    let was_none = guard.is_none();
                    if guard.as_deref() != Some(value) {
                        *guard = Some(value.to_owned());
                    }
                    if was_none {
                        should_wake_sse = true;
                    }
                }
            }
            if should_wake_sse {
                let _ = sse_wake.try_send(());
            }

            let status = resp.status();
            if status.is_success() {
                let content_type = resp
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");

                if is_event_stream_content_type(content_type) {
                    let stream = resp
                        .bytes_stream()
                        .map(|chunk| chunk.map_err(io::Error::other));
                    let reader = StreamReader::new(stream);
                    let mut reader = tokio::io::BufReader::new(reader);
                    let pump = sse_pump_to_writer(&mut reader, &writer, max_message_bytes, true);
                    let pump = match request_timeout {
                        Some(timeout) => match tokio::time::timeout(timeout, pump).await {
                            Ok(result) => result,
                            Err(_) => Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "http response stream timed out",
                            )),
                        },
                        None => pump.await,
                    };
                    if pump.is_err()
                        && !emit_post_bridge_error(
                            &writer,
                            &handle,
                            id,
                            HTTP_TRANSPORT_ERROR,
                            "http response stream failed".to_string(),
                            None,
                        )
                        .await
                    {
                        return;
                    }
                    continue;
                }

                if !is_json_content_type(content_type) {
                    if !emit_post_bridge_error(
                        &writer,
                        &handle,
                        id,
                        HTTP_TRANSPORT_ERROR,
                        "unexpected content-type for json response".to_string(),
                        Some(serde_json::json!({ "content_type": content_type })),
                    )
                    .await
                    {
                        return;
                    }
                    continue;
                }

                let body = match request_timeout {
                    Some(timeout) => {
                        match tokio::time::timeout(
                            timeout,
                            read_response_body_limited(resp, max_message_bytes),
                        )
                        .await
                        {
                            Ok(body) => body,
                            Err(_) => {
                                if !emit_post_bridge_error(
                                    &writer,
                                    &handle,
                                    id,
                                    HTTP_TRANSPORT_ERROR,
                                    "http response timed out".to_string(),
                                    None,
                                )
                                .await
                                {
                                    return;
                                }
                                continue;
                            }
                        }
                    }
                    None => read_response_body_limited(resp, max_message_bytes).await,
                };
                match body {
                    Err(ReadBodyError::TooLarge { actual_bytes }) => {
                        if !emit_post_bridge_error(
                            &writer,
                            &handle,
                            id,
                            HTTP_TRANSPORT_ERROR,
                            "http response too large".to_string(),
                            Some(serde_json::json!({
                                "max_bytes": max_message_bytes,
                                "actual_bytes": actual_bytes,
                            })),
                        )
                        .await
                        {
                            return;
                        }
                        continue;
                    }
                    Err(ReadBodyError::Http(err)) => {
                        if !emit_post_bridge_error(
                            &writer,
                            &handle,
                            id,
                            HTTP_TRANSPORT_ERROR,
                            format!("http response read failed: {}", redact_reqwest_error(&err)),
                            None,
                        )
                        .await
                        {
                            return;
                        }
                    }
                    Ok(body) if !body.is_empty() => {
                        // The JSON-RPC bridge is line-delimited. Re-serialize only when the HTTP
                        // body contains literal newlines so pretty-printed JSON remains valid.
                        if body.iter().any(|b| *b == b'\n' || *b == b'\r') {
                            let parsed_json: Value = match serde_json::from_slice(&body) {
                                Ok(json) => json,
                                Err(_) => {
                                    let data = if error_body_preview_bytes > 0 {
                                        let body_preview =
                                            String::from_utf8_lossy(&body).into_owned();
                                        let preview =
                                            truncate_string(body_preview, error_body_preview_bytes);
                                        Some(serde_json::json!({ "body": preview }))
                                    } else {
                                        None
                                    };
                                    if !emit_post_bridge_error(
                                        &writer,
                                        &handle,
                                        id,
                                        HTTP_TRANSPORT_ERROR,
                                        "http response is not valid json".to_string(),
                                        data,
                                    )
                                    .await
                                    {
                                        return;
                                    }
                                    continue;
                                }
                            };
                            let compact = match serde_json::to_vec(&parsed_json) {
                                Ok(compact) => compact,
                                Err(err) => {
                                    if !emit_post_bridge_error(
                                        &writer,
                                        &handle,
                                        id,
                                        HTTP_TRANSPORT_ERROR,
                                        format!("http response json re-serialize failed: {err}"),
                                        None,
                                    )
                                    .await
                                    {
                                        return;
                                    }
                                    continue;
                                }
                            };
                            if let Err(err) = write_json_line(&writer, &compact).await {
                                close_post_bridge(
                                    &writer,
                                    &handle,
                                    format!(
                                        "streamable http POST bridge failed writing response: {err}"
                                    ),
                                )
                                .await;
                                return;
                            }
                        } else {
                            if serde_json::from_slice::<serde::de::IgnoredAny>(&body).is_err() {
                                let data = if error_body_preview_bytes > 0 {
                                    let body_preview = String::from_utf8_lossy(&body).into_owned();
                                    let preview =
                                        truncate_string(body_preview, error_body_preview_bytes);
                                    Some(serde_json::json!({ "body": preview }))
                                } else {
                                    None
                                };
                                if !emit_post_bridge_error(
                                    &writer,
                                    &handle,
                                    id,
                                    HTTP_TRANSPORT_ERROR,
                                    "http response is not valid json".to_string(),
                                    data,
                                )
                                .await
                                {
                                    return;
                                }
                                continue;
                            }
                            if let Err(err) = write_json_line(&writer, &body).await {
                                close_post_bridge(
                                    &writer,
                                    &handle,
                                    format!(
                                        "streamable http POST bridge failed writing response: {err}"
                                    ),
                                )
                                .await;
                                return;
                            }
                        }
                    }
                    Ok(body) if body.is_empty() => {
                        if status != reqwest::StatusCode::ACCEPTED
                            && !emit_post_bridge_error(
                                &writer,
                                &handle,
                                id,
                                HTTP_TRANSPORT_ERROR,
                                "http response is empty".to_string(),
                                None,
                            )
                            .await
                        {
                            return;
                        }
                    }
                    _ => {}
                }
                continue;
            }

            let body_text = if error_body_preview_bytes == 0 {
                let drain = drain_response_body(resp);
                match request_timeout {
                    Some(timeout) => {
                        let _ = tokio::time::timeout(timeout, drain).await; // pre-commit: allow-let-underscore
                    }
                    None => drain.await,
                }
                None
            } else {
                let read = read_response_body_preview_text(resp, error_body_preview_bytes);
                match request_timeout {
                    Some(timeout) => tokio::time::timeout(timeout, read)
                        .await
                        .unwrap_or_default(),
                    None => read.await,
                }
            };
            if !emit_post_bridge_error(
                &writer,
                &handle,
                id,
                HTTP_TRANSPORT_ERROR,
                format!("http error: {status}"),
                body_text.map(|body| serde_json::json!({ "body": body })),
            )
            .await
            {
                return;
            }
        }
    }
}

async fn close_post_bridge(
    writer: &Arc<tokio::sync::Mutex<tokio::io::WriteHalf<tokio::io::DuplexStream>>>,
    handle: &ClientHandle,
    reason: impl Into<String>,
) {
    handle.close_with_reason(reason.into()).await;
    let mut writer = writer.lock().await;
    let _ = writer.shutdown().await; // pre-commit: allow-let-underscore
}

async fn emit_post_bridge_error(
    writer: &Arc<tokio::sync::Mutex<tokio::io::WriteHalf<tokio::io::DuplexStream>>>,
    handle: &ClientHandle,
    id: Option<Value>,
    code: i64,
    message: String,
    data: Option<Value>,
) -> bool {
    if let Some(id) = id {
        if let Err(err) = write_error_response(writer, id, code, message, data).await {
            close_post_bridge(
                writer,
                handle,
                format!("streamable http POST bridge failed writing error response: {err}"),
            )
            .await;
            return false;
        }
        return true;
    }

    close_post_bridge(
        writer,
        handle,
        format!("streamable http notification failed: {message}"),
    )
    .await;
    false
}

enum ReadBodyError {
    Http(reqwest::Error),
    TooLarge { actual_bytes: usize },
}

async fn read_response_body_limited(
    resp: reqwest::Response,
    max_message_bytes: usize,
) -> Result<Vec<u8>, ReadBodyError> {
    let mut out = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(ReadBodyError::Http)?;
        let next_len = out.len().saturating_add(chunk.len());
        if next_len > max_message_bytes {
            return Err(ReadBodyError::TooLarge {
                actual_bytes: next_len,
            });
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

async fn drain_response_body(resp: reqwest::Response) {
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        if chunk.is_err() {
            break;
        }
    }
}

async fn read_response_body_preview_text(
    resp: reqwest::Response,
    max_bytes: usize,
) -> Option<String> {
    if max_bytes == 0 {
        return None;
    }

    let mut out = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.ok()?;

        let remaining = max_bytes.saturating_add(1).saturating_sub(out.len());
        if remaining == 0 {
            break;
        }

        let take = remaining.min(chunk.len());
        out.extend_from_slice(&chunk[..take]);
        if out.len() >= max_bytes {
            break;
        }
    }

    if out.is_empty() {
        return None;
    }

    let preview = String::from_utf8_lossy(&out).into_owned();
    Some(truncate_string(preview, max_bytes))
}

fn redact_reqwest_error(err: &reqwest::Error) -> String {
    let mut msg = err.to_string();
    let Some(url) = err.url() else {
        return msg;
    };

    let full = url.as_str();
    let redacted = redact_url_for_error(url);
    msg = msg.replace(full, &redacted);
    msg
}

fn redact_url_for_error(url: &reqwest::Url) -> String {
    let mut url = url.clone();
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_path("/");
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

async fn pump_sse(
    resp: reqwest::Response,
    writer: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<tokio::io::DuplexStream>>>,
    max_message_bytes: usize,
    handle: ClientHandle,
) {
    let stream = resp
        .bytes_stream()
        .map(|chunk| chunk.map_err(io::Error::other));
    let reader = StreamReader::new(stream);
    let mut reader = tokio::io::BufReader::new(reader);
    let result = sse_pump_to_writer(&mut reader, &writer, max_message_bytes, false).await;
    match result {
        Ok(()) => {
            handle
                .close_with_reason("streamable http SSE connection closed".to_string())
                .await;
        }
        Err(err) => {
            handle
                .close_with_reason(format!("streamable http SSE connection failed: {err}"))
                .await;
        }
    }
    let mut writer = writer.lock().await;
    let _ = writer.shutdown().await;
}

async fn sse_pump_to_writer<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    writer: &Arc<tokio::sync::Mutex<tokio::io::WriteHalf<tokio::io::DuplexStream>>>,
    max_message_bytes: usize,
    stop_on_done: bool,
) -> Result<(), io::Error> {
    let mut data = Vec::new();

    loop {
        let line = crate::read_line_limited(reader, max_message_bytes).await?;
        let Some(line) = line else {
            return Ok(());
        };

        if line.is_empty() {
            if data.is_empty() {
                continue;
            }
            if stop_on_done && data == b"[DONE]" {
                return Ok(());
            }
            write_json_line(writer, &data).await?;
            data.clear();
            if data.capacity() > SSE_EVENT_BUFFER_RETAIN_BYTES {
                let retain = SSE_EVENT_BUFFER_RETAIN_BYTES.min(max_message_bytes);
                data = Vec::with_capacity(retain);
            }
            continue;
        }

        if let Some(rest) = line.strip_prefix(b"data:") {
            let mut rest = rest;
            while rest.first().is_some_and(u8::is_ascii_whitespace) {
                rest = &rest[1..];
            }

            if !data.is_empty() {
                data.push(b'\n');
            }
            if data.len().saturating_add(rest.len()) > max_message_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sse event too large",
                ));
            }
            data.extend_from_slice(rest);
        }
    }
}

async fn write_json_line(
    writer: &Arc<tokio::sync::Mutex<tokio::io::WriteHalf<tokio::io::DuplexStream>>>,
    line: &[u8],
) -> Result<(), io::Error> {
    let mut writer = writer.lock().await;
    writer.write_all(line).await?;
    writer.write_all(b"\n").await?;
    Ok(())
}

async fn write_error_response(
    writer: &Arc<tokio::sync::Mutex<tokio::io::WriteHalf<tokio::io::DuplexStream>>>,
    id: Value,
    code: i64,
    message: String,
    data: Option<Value>,
) -> Result<(), io::Error> {
    let mut error = serde_json::json!({
        "code": code,
        "message": message,
    });
    if let Some(data) = data {
        error["data"] = data;
    }
    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": error,
    });

    let mut out = serde_json::to_vec(&response).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("serialize error response failed: {err}"),
        )
    })?;
    out.push(b'\n');

    let mut writer = writer.lock().await;
    writer.write_all(&out).await?;
    Ok(())
}

fn truncate_string(mut s: String, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    s.truncate(end);
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn content_type_helpers_handle_common_variants() {
        assert!(is_event_stream_content_type("text/event-stream"));
        assert!(is_event_stream_content_type("Text/Event-Stream"));
        assert!(is_event_stream_content_type(
            "text/event-stream; charset=utf-8"
        ));
        assert!(!is_event_stream_content_type("application/json"));

        assert!(is_json_content_type(""));
        assert!(is_json_content_type("application/json"));
        assert!(is_json_content_type("Application/Json; charset=utf-8"));
        assert!(is_json_content_type("application/problem+json"));
        assert!(is_json_content_type(
            "application/vnd.api+json; charset=utf-8"
        ));
        assert!(!is_json_content_type("text/plain"));
        assert!(!is_json_content_type("application/xml"));
        assert!(!is_json_content_type("application/jsonp"));
        assert!(!is_json_content_type("application/notjson+jsone"));
    }

    #[tokio::test]
    async fn sse_pump_writes_data_events_as_json_lines() {
        let sse = concat!(
            "event: message\n",
            "data: {\"jsonrpc\":\"2.0\",\"method\":\"demo/notify\",\"params\":{}}\n",
            "\n",
        );

        let (mut in_write, in_read) = tokio::io::duplex(1024);
        let write_task = tokio::spawn(async move {
            in_write.write_all(sse.as_bytes()).await.unwrap();
            // Close input.
            drop(in_write);
        });
        let mut reader = tokio::io::BufReader::new(in_read);

        let (client_side, mut capture_side) = tokio::io::duplex(1024);
        let (read, write) = tokio::io::split(client_side);
        drop(read);
        let writer = Arc::new(tokio::sync::Mutex::new(write));

        sse_pump_to_writer(&mut reader, &writer, 1024, false)
            .await
            .unwrap();
        drop(writer);

        write_task.await.unwrap();

        let mut out = Vec::new();
        capture_side.read_to_end(&mut out).await.unwrap();
        assert_eq!(
            out,
            b"{\"jsonrpc\":\"2.0\",\"method\":\"demo/notify\",\"params\":{}}\n"
        );
    }
}
