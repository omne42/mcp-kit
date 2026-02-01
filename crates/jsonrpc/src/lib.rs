//! `mcp-jsonrpc` is a small JSON-RPC 2.0 client with a few MCP-friendly transports.
//!
//! Transports:
//! - stdio (spawned child process)
//! - unix domain socket (connect to an existing local server)
//! - "streamable http" (HTTP SSE + POST), commonly used by remote MCP servers
//!   - Redirects are disabled by default (opt in via `StreamableHttpOptions.follow_redirects`).
//!
//! Design goals:
//! - Minimal dependencies and low ceremony (`serde_json::Value` based)
//! - Support both notifications and server->client requests
//! - Bounded queues + per-message size limits to reduce DoS risk
//!
//! Non-goals:
//! - Implementing a JSON-RPC server
//! - Automatic reconnect
//! - Rich typed schemas beyond `serde_json::Value`

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot};
use tokio_util::io::StreamReader;

#[derive(Debug, Clone, Default)]
pub struct SpawnOptions {
    pub stdout_log: Option<StdoutLog>,
    pub limits: Limits,
}

#[derive(Debug, Clone)]
pub struct StreamableHttpOptions {
    /// Extra HTTP headers to include on all requests.
    pub headers: HashMap<String, String>,
    /// Optional timeout applied while establishing HTTP connections.
    pub connect_timeout: Option<Duration>,
    /// Optional timeout applied to individual HTTP POST request/response bodies.
    ///
    /// Note: do not use this to limit the long-lived SSE connection.
    pub request_timeout: Option<Duration>,
    /// Whether to follow HTTP redirects (default: false).
    ///
    /// For safety, the default is to disable redirects to reduce SSRF risk.
    pub follow_redirects: bool,
}

impl Default for StreamableHttpOptions {
    fn default() -> Self {
        Self {
            headers: HashMap::new(),
            connect_timeout: Some(Duration::from_secs(10)),
            request_timeout: None,
            follow_redirects: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StdoutLog {
    pub path: PathBuf,
    pub max_bytes_per_part: u64,
    /// Keep at most N rotated parts (`*.segment-XXXX.log`). When `None`, keep all.
    pub max_parts: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Limits {
    /// Maximum bytes for a single JSON-RPC message (one line).
    pub max_message_bytes: usize,
    /// Maximum buffered notifications from the server.
    pub notifications_capacity: usize,
    /// Maximum buffered server->client requests.
    pub requests_capacity: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            // Large enough for typical MCP messages, but bounded to reduce DoS risk.
            max_message_bytes: 16 * 1024 * 1024,
            notifications_capacity: 256,
            requests_capacity: 64,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("json-rpc error {code}: {message}")]
    Rpc {
        code: i64,
        message: String,
        data: Option<Value>,
    },
    #[error("protocol error: {0}")]
    Protocol(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Id {
    String(String),
    Integer(i64),
}

type PendingRequests = Arc<Mutex<HashMap<Id, oneshot::Sender<Result<Value, Error>>>>>;

#[derive(Clone)]
pub struct ClientHandle {
    write: Arc<tokio::sync::Mutex<Box<dyn AsyncWrite + Send + Unpin>>>,
    next_id: Arc<AtomicI64>,
    pending: PendingRequests,
}

impl std::fmt::Debug for ClientHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientHandle").finish_non_exhaustive()
    }
}

impl ClientHandle {
    pub async fn notify(&self, method: &str, params: Option<Value>) -> Result<(), Error> {
        let mut msg = Map::new();
        msg.insert("jsonrpc".to_string(), Value::String("2.0".to_string()));
        msg.insert("method".to_string(), Value::String(method.to_string()));
        msg.insert("params".to_string(), params.unwrap_or(Value::Null));
        let msg = Value::Object(msg);

        let mut line = serde_json::to_string(&msg)?;
        line.push('\n');
        self.write_line(&line).await?;
        Ok(())
    }

    pub async fn request(&self, method: &str, params: Value) -> Result<Value, Error> {
        let id = Id::Integer(self.next_id.fetch_add(1, Ordering::Relaxed));

        let (tx, rx) = oneshot::channel::<Result<Value, Error>>();
        {
            let mut pending = lock_pending(&self.pending);
            pending.insert(id.clone(), tx);
        }
        let mut guard = PendingRequestGuard::new(self.pending.clone(), id.clone());

        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });

        let mut line = serde_json::to_string(&req)?;
        line.push('\n');
        if let Err(err) = self.write_line(&line).await {
            let mut pending = lock_pending(&self.pending);
            pending.remove(&id);
            guard.disarm();
            return Err(err);
        }

        match rx.await {
            Ok(result) => {
                guard.disarm();
                result
            }
            Err(_) => Err(Error::Protocol("response channel closed".to_string())),
        }
    }

    pub async fn respond_ok(&self, id: Id, result: Value) -> Result<(), Error> {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
        });
        let mut line = serde_json::to_string(&response)?;
        line.push('\n');
        self.write_line(&line).await
    }

    pub async fn respond_error(
        &self,
        id: Id,
        code: i64,
        message: impl Into<String>,
        data: Option<Value>,
    ) -> Result<(), Error> {
        let mut error = serde_json::json!({
            "code": code,
            "message": message.into(),
        });
        if let Some(data) = data {
            error["data"] = data;
        }

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": error,
        });

        let mut line = serde_json::to_string(&response)?;
        line.push('\n');
        self.write_line(&line).await
    }

    async fn write_line(&self, line: &str) -> Result<(), Error> {
        let mut write = self.write.lock().await;
        write.write_all(line.as_bytes()).await?;
        write.flush().await?;
        Ok(())
    }
}

pub struct Client {
    handle: ClientHandle,
    child: Option<Child>,
    notifications_rx: Option<mpsc::Receiver<Notification>>,
    requests_rx: Option<mpsc::Receiver<IncomingRequest>>,
    task: tokio::task::JoinHandle<()>,
    transport_tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Client {
    pub async fn connect_io<R, W>(read: R, write: W) -> Result<Self, Error>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        Self::connect_io_with_options(read, write, SpawnOptions::default()).await
    }

    pub async fn connect_io_with_options<R, W>(
        read: R,
        write: W,
        options: SpawnOptions,
    ) -> Result<Self, Error>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        Self::create(read, write, None, options).await
    }

    pub async fn spawn<I, S>(program: S, args: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = OsString>,
        S: AsRef<OsStr>,
    {
        let mut cmd = Command::new(program);
        cmd.args(args);
        cmd.stderr(Stdio::inherit());
        Self::spawn_command_with_options(cmd, SpawnOptions::default()).await
    }

    pub async fn spawn_with_options<I, S>(
        program: S,
        args: I,
        options: SpawnOptions,
    ) -> Result<Self, Error>
    where
        I: IntoIterator<Item = OsString>,
        S: AsRef<OsStr>,
    {
        let mut cmd = Command::new(program);
        cmd.args(args);
        cmd.stderr(Stdio::inherit());
        Self::spawn_command_with_options(cmd, options).await
    }

    pub async fn spawn_command(cmd: Command) -> Result<Self, Error> {
        Self::spawn_command_with_options(cmd, SpawnOptions::default()).await
    }

    pub async fn spawn_command_with_options(
        mut cmd: Command,
        options: SpawnOptions,
    ) -> Result<Self, Error> {
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());

        let mut child = cmd.spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::Protocol("child stdin not captured".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::Protocol("child stdout not captured".to_string()))?;

        Self::create(stdout, stdin, Some(child), options).await
    }

    pub async fn connect_unix(path: &Path) -> Result<Self, Error> {
        #[cfg(unix)]
        {
            let stream = tokio::net::UnixStream::connect(path).await?;
            let (read, write) = stream.into_split();
            Self::create(read, write, None, SpawnOptions::default()).await
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(Error::Protocol(
                "unix socket client is only supported on unix".to_string(),
            ))
        }
    }

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
        let limits = options.limits.clone();
        let max_message_bytes = limits.max_message_bytes;
        let connect_timeout = http_options.connect_timeout;
        let request_timeout = http_options.request_timeout;
        let follow_redirects = http_options.follow_redirects;

        let mut headers = reqwest::header::HeaderMap::new();
        for (key, value) in http_options.headers {
            let name = reqwest::header::HeaderName::from_bytes(key.as_bytes())
                .map_err(|_| Error::Protocol(format!("invalid http header name: {key}")))?;
            let value = reqwest::header::HeaderValue::from_str(&value)
                .map_err(|_| Error::Protocol(format!("invalid http header value: {key}")))?;
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
        let http_client = http_builder
            .build()
            .map_err(|err| Error::Protocol(format!("build http client failed: {err}")))?;

        let (client_stream, bridge_stream) = tokio::io::duplex(1024 * 64);
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (bridge_read, bridge_write) = tokio::io::split(bridge_stream);

        let mut client = Self::connect_io_with_options(client_read, client_write, options).await?;

        let writer: Arc<tokio::sync::Mutex<_>> = Arc::new(tokio::sync::Mutex::new(bridge_write));
        let session_id: Arc<tokio::sync::Mutex<Option<String>>> =
            Arc::new(tokio::sync::Mutex::new(None));

        let sse_req = http_client
            .get(url)
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .send();
        let sse_resp = match connect_timeout {
            Some(timeout) => match tokio::time::timeout(timeout, sse_req).await {
                Ok(resp) => resp,
                Err(_) => {
                    return Err(Error::Protocol(
                        "connect streamable http failed: request timed out".to_string(),
                    ));
                }
            },
            None => sse_req.await,
        }
        .map_err(|err| Error::Protocol(format!("connect streamable http failed: {err}")))?;

        if !sse_resp.status().is_success() {
            return Err(Error::Protocol(format!(
                "streamable http SSE connect failed: status={}",
                sse_resp.status()
            )));
        }

        if let Some(value) = sse_resp.headers().get("mcp-session-id") {
            if let Ok(value) = value.to_str() {
                *session_id.lock().await = Some(value.to_string());
            }
        }

        let post_url = url.to_string();
        let http_client_post = http_client.clone();
        let writer_post = writer.clone();
        let session_id_post = session_id.clone();
        let limits_post = limits.clone();
        let request_timeout_post = request_timeout;
        let post_task = tokio::spawn(async move {
            http_post_bridge_loop(
                bridge_read,
                writer_post,
                http_client_post,
                post_url,
                session_id_post,
                limits_post,
                request_timeout_post,
            )
            .await;
        });

        let writer_sse = writer.clone();
        let session_id_sse = session_id.clone();
        let sse_task = tokio::spawn(async move {
            let resp = sse_resp;
            if let Some(value) = resp.headers().get("mcp-session-id") {
                if let Ok(value) = value.to_str() {
                    *session_id_sse.lock().await = Some(value.to_string());
                }
            }

            let stream = resp
                .bytes_stream()
                .map(|chunk| chunk.map_err(io::Error::other));
            let reader = StreamReader::new(stream);
            let mut reader = tokio::io::BufReader::new(reader);
            let _ = sse_pump_to_writer(&mut reader, writer_sse, max_message_bytes).await;
        });

        client.transport_tasks.push(post_task);
        client.transport_tasks.push(sse_task);
        Ok(client)
    }

    async fn create<R, W>(
        read: R,
        write: W,
        child: Option<Child>,
        options: SpawnOptions,
    ) -> Result<Self, Error>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let notify_cap = options.limits.notifications_capacity.max(1);
        let request_cap = options.limits.requests_capacity.max(1);
        let (notify_tx, notify_rx) = mpsc::channel::<Notification>(notify_cap);
        let (request_tx, request_rx) = mpsc::channel::<IncomingRequest>(request_cap);
        let pending: PendingRequests = Arc::new(Mutex::new(HashMap::new()));
        let write = Arc::new(tokio::sync::Mutex::new(Box::new(write) as _));
        let handle = ClientHandle {
            write,
            next_id: Arc::new(AtomicI64::new(1)),
            pending: pending.clone(),
        };
        let task = spawn_reader_task(
            read,
            pending,
            notify_tx,
            request_tx,
            handle.clone(),
            options.stdout_log,
            options.limits,
        );

        Ok(Self {
            handle,
            child,
            notifications_rx: Some(notify_rx),
            requests_rx: Some(request_rx),
            task,
            transport_tasks: Vec::new(),
        })
    }

    pub fn handle(&self) -> ClientHandle {
        self.handle.clone()
    }

    pub fn child_id(&self) -> Option<u32> {
        self.child.as_ref().and_then(|child| child.id())
    }

    pub fn take_child(&mut self) -> Option<Child> {
        self.child.take()
    }

    pub fn take_notifications(&mut self) -> Option<mpsc::Receiver<Notification>> {
        self.notifications_rx.take()
    }

    pub fn take_requests(&mut self) -> Option<mpsc::Receiver<IncomingRequest>> {
        self.requests_rx.take()
    }

    pub async fn notify(&self, method: &str, params: Option<Value>) -> Result<(), Error> {
        self.handle.notify(method, params).await
    }

    pub async fn request(&self, method: &str, params: Value) -> Result<Value, Error> {
        self.handle.request(method, params).await
    }

    pub async fn wait(&mut self) -> Result<std::process::ExitStatus, Error> {
        self.task.abort();
        for task in self.transport_tasks.drain(..) {
            task.abort();
        }
        let err = Error::Protocol("client closed".to_string());
        drain_pending(&self.handle.pending, &err);

        match &mut self.child {
            Some(child) => Ok(child.wait().await?),
            None => Err(Error::Protocol("client has no child process".to_string())),
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.task.abort();
        for task in self.transport_tasks.drain(..) {
            task.abort();
        }
        let err = Error::Protocol("client closed".to_string());
        drain_pending(&self.handle.pending, &err);
    }
}

struct PendingRequestGuard {
    pending: PendingRequests,
    id: Id,
    armed: bool,
}

impl PendingRequestGuard {
    fn new(pending: PendingRequests, id: Id) -> Self {
        Self {
            pending,
            id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingRequestGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut pending = lock_pending(&self.pending);
        pending.remove(&self.id);
    }
}

#[derive(Debug, Clone)]
pub struct Notification {
    pub method: String,
    pub params: Value,
}

#[derive(Debug, Clone)]
pub struct IncomingRequest {
    pub id: Id,
    pub method: String,
    pub params: Value,
    responder: ClientHandle,
}

impl IncomingRequest {
    pub async fn respond_ok(&self, result: Value) -> Result<(), Error> {
        self.responder.respond_ok(self.id.clone(), result).await
    }

    pub async fn respond_error(
        &self,
        code: i64,
        message: impl Into<String>,
        data: Option<Value>,
    ) -> Result<(), Error> {
        self.responder
            .respond_error(self.id.clone(), code, message, data)
            .await
    }
}

fn spawn_reader_task<R>(
    reader: R,
    pending: PendingRequests,
    notify_tx: mpsc::Sender<Notification>,
    request_tx: mpsc::Sender<IncomingRequest>,
    responder: ClientHandle,
    stdout_log: Option<StdoutLog>,
    limits: Limits,
) -> tokio::task::JoinHandle<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        const METHOD_NOT_FOUND: i64 = -32601;
        const CLIENT_OVERLOADED: i64 = -32000;
        let mut log_state = match stdout_log {
            Some(opts) => LogState::new(opts).await.ok(),
            None => None,
        };

        let max_message_bytes = limits.max_message_bytes.max(1);
        let mut reader = tokio::io::BufReader::new(reader);
        loop {
            let next = read_line_limited(&mut reader, max_message_bytes).await;
            match next {
                Ok(Some(line)) => {
                    if line.iter().all(u8::is_ascii_whitespace) {
                        continue;
                    }
                    if let Some(state) = &mut log_state {
                        if let Err(err) = state.write_line_bytes(&line).await {
                            eprintln!("jsonrpc: stdout log write failed: {err}");
                            log_state = None;
                        }
                    }
                    let value: Value = match serde_json::from_slice(&line) {
                        Ok(value) => value,
                        Err(_) => continue,
                    };

                    let Some(method) = value.get("method").and_then(|v| v.as_str()) else {
                        handle_response(&pending, value);
                        continue;
                    };

                    let params = value.get("params").cloned().unwrap_or(Value::Null);
                    if let Some(id_value) = value.get("id") {
                        let Some(id) = parse_id(id_value) else {
                            continue;
                        };
                        let request = IncomingRequest {
                            id: id.clone(),
                            method: method.to_string(),
                            params,
                            responder: responder.clone(),
                        };

                        match request_tx.try_send(request) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_request)) => {
                                let _ = responder
                                    .respond_error(id, CLIENT_OVERLOADED, "client overloaded", None)
                                    .await;
                            }
                            Err(mpsc::error::TrySendError::Closed(_request)) => {
                                let _ = responder
                                    .respond_error(
                                        id,
                                        METHOD_NOT_FOUND,
                                        "no request handler installed",
                                        None,
                                    )
                                    .await;
                            }
                        };
                        continue;
                    }

                    let _ = notify_tx.try_send(Notification {
                        method: method.to_string(),
                        params,
                    });
                }
                Ok(None) => {
                    let err = Error::Protocol("server closed connection".to_string());
                    drain_pending(&pending, &err);
                    return;
                }
                Err(err) => {
                    let err = Error::Io(err);
                    drain_pending(&pending, &err);
                    return;
                }
            }
        }
    })
}

async fn read_line_limited<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, std::io::Error> {
    let mut buf = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            break;
        }

        let newline_pos = available.iter().position(|b| *b == b'\n');
        let take = newline_pos
            .map(|idx| idx.saturating_add(1))
            .unwrap_or(available.len());
        if buf.len().saturating_add(take) > max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "jsonrpc message too large",
            ));
        }
        buf.extend_from_slice(&available[..take]);
        reader.consume(take);

        if newline_pos.is_some() {
            break;
        }
    }

    if buf.ends_with(b"\n") {
        buf.pop();
        if buf.ends_with(b"\r") {
            buf.pop();
        }
    }

    Ok(Some(buf))
}

async fn http_post_bridge_loop(
    bridge_read: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    writer: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<tokio::io::DuplexStream>>>,
    http_client: reqwest::Client,
    post_url: String,
    session_id: Arc<tokio::sync::Mutex<Option<String>>>,
    limits: Limits,
    request_timeout: Option<Duration>,
) {
    const HTTP_TRANSPORT_ERROR: i64 = -32000;

    let mut reader = tokio::io::BufReader::new(bridge_read);
    loop {
        let line = match read_line_limited(&mut reader, limits.max_message_bytes).await {
            Ok(Some(line)) => line,
            Ok(None) => return,
            Err(_) => return,
        };

        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }

        let parsed: Value = match serde_json::from_slice(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let id = parsed.get("id").cloned();

        let mut req = http_client
            .post(&post_url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(line);

        if let Some(session) = session_id.lock().await.clone() {
            req = req.header("mcp-session-id", session);
        }

        let send = req.send();
        let resp = match request_timeout {
            Some(timeout) => match tokio::time::timeout(timeout, send).await {
                Ok(resp) => resp,
                Err(_) => {
                    if let Some(id) = id {
                        let _ = write_error_response(
                            &writer,
                            id,
                            HTTP_TRANSPORT_ERROR,
                            "http request timed out".to_string(),
                            None,
                        )
                        .await;
                    }
                    continue;
                }
            },
            None => send.await,
        };
        let resp = match resp {
            Ok(resp) => resp,
            Err(err) => {
                if let Some(id) = id {
                    let _ = write_error_response(
                        &writer,
                        id,
                        HTTP_TRANSPORT_ERROR,
                        format!("http request failed: {err}"),
                        None,
                    )
                    .await;
                }
                continue;
            }
        };

        if let Some(value) = resp.headers().get("mcp-session-id") {
            if let Ok(value) = value.to_str() {
                *session_id.lock().await = Some(value.to_string());
            }
        }

        let status = resp.status();
        if status.is_success() {
            let content_type = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            if content_type.starts_with("text/event-stream") {
                let stream = resp
                    .bytes_stream()
                    .map(|chunk| chunk.map_err(io::Error::other));
                let reader = StreamReader::new(stream);
                let mut reader = tokio::io::BufReader::new(reader);
                let pump =
                    sse_pump_to_writer(&mut reader, writer.clone(), limits.max_message_bytes);
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
                if pump.is_err() {
                    if let Some(id) = id {
                        let _ = write_error_response(
                            &writer,
                            id,
                            HTTP_TRANSPORT_ERROR,
                            "http response stream failed".to_string(),
                            None,
                        )
                        .await;
                    }
                }
                continue;
            }

            let body = match request_timeout {
                Some(timeout) => match tokio::time::timeout(timeout, resp.bytes()).await {
                    Ok(body) => body,
                    Err(_) => {
                        if let Some(id) = id {
                            let _ = write_error_response(
                                &writer,
                                id,
                                HTTP_TRANSPORT_ERROR,
                                "http response timed out".to_string(),
                                None,
                            )
                            .await;
                        }
                        continue;
                    }
                },
                None => resp.bytes().await,
            };
            match body {
                Ok(body) if !body.is_empty() => {
                    if body.len() > limits.max_message_bytes {
                        continue;
                    }
                    let _ = write_json_line(&writer, &body).await;
                }
                _ => {}
            }
            continue;
        }

        if let Some(id) = id {
            let body_text = match request_timeout {
                Some(timeout) => match tokio::time::timeout(timeout, resp.text()).await {
                    Ok(body) => body.ok(),
                    Err(_) => None,
                },
                None => resp.text().await.ok(),
            }
            .map(|body| truncate_string(body, 4 * 1024));
            let _ = write_error_response(
                &writer,
                id,
                HTTP_TRANSPORT_ERROR,
                format!("http error: {status}"),
                body_text.map(|body| serde_json::json!({ "body": body })),
            )
            .await;
        }
    }
}

async fn sse_pump_to_writer<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    writer: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<tokio::io::DuplexStream>>>,
    max_message_bytes: usize,
) -> Result<(), io::Error> {
    let mut data = Vec::new();

    loop {
        let line = read_line_limited(reader, max_message_bytes).await?;
        let Some(line) = line else {
            return Ok(());
        };

        if line.is_empty() {
            if data.is_empty() {
                continue;
            }
            if data == b"[DONE]" {
                return Ok(());
            }
            write_json_line(&writer, &data).await?;
            data.clear();
            continue;
        }

        if let Some(rest) = line.strip_prefix(b"data:") {
            let mut rest = rest;
            while rest.first().is_some_and(|b| b.is_ascii_whitespace()) {
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
    writer.flush().await?;
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
    writer.flush().await?;
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

fn lock_pending<'a>(
    pending: &'a PendingRequests,
) -> std::sync::MutexGuard<'a, HashMap<Id, oneshot::Sender<Result<Value, Error>>>> {
    pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn drain_pending(pending: &PendingRequests, err: &Error) {
    let pending = {
        let mut pending = lock_pending(pending);
        std::mem::take(&mut *pending)
    };

    for (_id, tx) in pending {
        let _ = tx.send(Err(clone_error_for_drain(err)));
    }
}

fn clone_error_for_drain(err: &Error) -> Error {
    match err {
        Error::Io(err) => Error::Io(std::io::Error::new(err.kind(), err.to_string())),
        Error::Json(err) => Error::Protocol(format!("json error: {err}")),
        Error::Rpc {
            code,
            message,
            data,
        } => Error::Rpc {
            code: *code,
            message: message.clone(),
            data: data.clone(),
        },
        Error::Protocol(msg) => Error::Protocol(msg.clone()),
    }
}

fn parse_id(value: &Value) -> Option<Id> {
    match value {
        Value::String(value) => Some(Id::String(value.clone())),
        Value::Number(value) => value.as_i64().map(Id::Integer).or_else(|| {
            value
                .as_u64()
                .and_then(|v| i64::try_from(v).ok())
                .map(Id::Integer)
        }),
        _ => None,
    }
}

fn handle_response(pending: &PendingRequests, value: Value) {
    let Some(id_value) = value.get("id") else {
        return;
    };
    let Some(id) = parse_id(id_value) else {
        return;
    };

    let tx = {
        let mut pending = lock_pending(pending);
        pending.remove(&id)
    };
    let Some(tx) = tx else {
        return;
    };

    if let Some(error) = value.get("error") {
        let Some(code) = error.get("code").and_then(|v| v.as_i64()) else {
            let _ = tx.send(Err(Error::Protocol("invalid error response".to_string())));
            return;
        };
        let Some(message) = error.get("message").and_then(|v| v.as_str()) else {
            let _ = tx.send(Err(Error::Protocol("invalid error response".to_string())));
            return;
        };
        let data = error.get("data").cloned();
        let _ = tx.send(Err(Error::Rpc {
            code,
            message: message.to_string(),
            data,
        }));
        return;
    }

    let Some(result) = value.get("result").cloned() else {
        let _ = tx.send(Err(Error::Protocol("missing result".to_string())));
        return;
    };
    let _ = tx.send(Ok(result));
}

struct LogState {
    base_path: PathBuf,
    max_bytes_per_part: u64,
    max_parts: Option<u32>,
    file: tokio::fs::File,
    current_len: u64,
    next_part: u32,
}

impl LogState {
    async fn new(opts: StdoutLog) -> Result<Self, std::io::Error> {
        let base_path = opts.path;
        let max_bytes_per_part = opts.max_bytes_per_part.max(1);
        let max_parts = opts.max_parts.filter(|v| *v > 0);
        if let Some(parent) = base_path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }

        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&base_path)
            .await?;
        let current_len = file.metadata().await.map(|m| m.len()).unwrap_or(0);
        let next_part = next_rotating_log_part(&base_path).await.unwrap_or(1);
        if let Some(max_parts) = max_parts {
            let _ = prune_rotating_log_parts(&base_path, max_parts).await;
        }

        Ok(Self {
            base_path,
            max_bytes_per_part,
            max_parts,
            file,
            current_len,
            next_part,
        })
    }

    async fn write_line_bytes(&mut self, line: &[u8]) -> Result<(), std::io::Error> {
        let mut buf = Vec::with_capacity(line.len().saturating_add(1));
        buf.extend_from_slice(line);
        if !line.ends_with(b"\n") {
            buf.push(b'\n');
        }

        let mut offset = 0usize;
        while offset < buf.len() {
            let remaining = self.max_bytes_per_part.saturating_sub(self.current_len);
            if remaining == 0 {
                self.file.flush().await?;
                self.next_part = rotate_log_file(&self.base_path, self.next_part).await?;
                if let Some(max_parts) = self.max_parts {
                    let _ = prune_rotating_log_parts(&self.base_path, max_parts).await;
                }
                self.file = tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.base_path)
                    .await?;
                self.current_len = 0;
                continue;
            }

            let take = usize::try_from(remaining.min((buf.len() - offset) as u64))
                .unwrap_or(buf.len() - offset);
            self.file.write_all(&buf[offset..(offset + take)]).await?;
            self.current_len = self.current_len.saturating_add(take as u64);
            offset = offset.saturating_add(take);
        }

        Ok(())
    }
}

async fn next_rotating_log_part(base_path: &Path) -> Result<u32, std::io::Error> {
    let Some(parent) = base_path.parent() else {
        return Ok(1);
    };
    let Some(stem) = base_path.file_stem().and_then(|s| s.to_str()) else {
        return Ok(1);
    };

    let mut read_dir = match tokio::fs::read_dir(parent).await {
        Ok(read_dir) => read_dir,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(1),
        Err(err) => return Err(err),
    };

    let prefix = format!("{stem}.segment-");
    let mut max_part = 0u32;
    while let Some(entry) = read_dir.next_entry().await? {
        let ty = entry.file_type().await?;
        if !ty.is_file() {
            continue;
        }
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Some(rest) = name.strip_prefix(&prefix) else {
            continue;
        };
        let Some(part_str) = rest.strip_suffix(".log") else {
            continue;
        };
        let Ok(part) = part_str.parse::<u32>() else {
            continue;
        };
        max_part = max_part.max(part);
    }

    Ok(max_part.saturating_add(1).max(1))
}

async fn rotate_log_file(base_path: &Path, mut part: u32) -> Result<u32, std::io::Error> {
    let Some(parent) = base_path.parent() else {
        return Ok(part);
    };
    let Some(stem) = base_path.file_stem().and_then(|s| s.to_str()) else {
        return Ok(part);
    };

    loop {
        let rotated = parent.join(format!("{stem}.segment-{part:04}.log"));
        match tokio::fs::rename(base_path, &rotated).await {
            Ok(()) => return Ok(part.saturating_add(1)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(part),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                part = part.saturating_add(1);
                continue;
            }
            Err(err) => {
                return Err(err);
            }
        }
    }
}

async fn list_rotating_log_parts(base_path: &Path) -> Result<Vec<(u32, PathBuf)>, std::io::Error> {
    let Some(parent) = base_path.parent() else {
        return Ok(Vec::new());
    };
    let Some(stem) = base_path.file_stem().and_then(|s| s.to_str()) else {
        return Ok(Vec::new());
    };

    let mut read_dir = match tokio::fs::read_dir(parent).await {
        Ok(read_dir) => read_dir,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };

    let prefix = format!("{stem}.segment-");
    let mut parts = Vec::new();
    while let Some(entry) = read_dir.next_entry().await? {
        let ty = entry.file_type().await?;
        if !ty.is_file() {
            continue;
        }
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Some(rest) = name.strip_prefix(&prefix) else {
            continue;
        };
        let Some(part_str) = rest.strip_suffix(".log") else {
            continue;
        };
        let Ok(part) = part_str.parse::<u32>() else {
            continue;
        };

        parts.push((part, entry.path()));
    }

    Ok(parts)
}

async fn prune_rotating_log_parts(base_path: &Path, max_parts: u32) -> Result<(), std::io::Error> {
    if max_parts == 0 {
        return Ok(());
    }
    let mut parts = list_rotating_log_parts(base_path).await?;
    parts.sort_by_key(|(part, _)| *part);

    let keep = max_parts as usize;
    if parts.len() <= keep {
        return Ok(());
    }

    let remove = parts.len().saturating_sub(keep);
    for (_part, path) in parts.into_iter().take(remove) {
        let _ = tokio::fs::remove_file(path).await;
    }

    Ok(())
}

#[cfg(test)]
mod stdout_log_tests {
    use super::*;

    #[tokio::test]
    async fn prune_rotating_log_parts_keeps_latest_n() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("server.stdout.log");

        for part in 1..=5u32 {
            let path = dir
                .path()
                .join(format!("server.stdout.segment-{part:04}.log"));
            tokio::fs::write(&path, format!("part-{part}\n"))
                .await
                .unwrap();
        }

        prune_rotating_log_parts(&base, 2).await.unwrap();
        let mut parts = list_rotating_log_parts(&base).await.unwrap();
        parts.sort_by_key(|(part, _)| *part);
        assert_eq!(
            parts.iter().map(|(p, _)| *p).collect::<Vec<_>>(),
            vec![4, 5]
        );
    }
}

#[cfg(test)]
mod streamable_http_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

        sse_pump_to_writer(&mut reader, writer.clone(), 1024)
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
