#![forbid(unsafe_code)]

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

use std::collections::{HashMap, VecDeque};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot};

mod stdout_log;
mod streamable_http;

use stdout_log::LogState;

pub type StdoutLogRedactor = Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>;

#[derive(Clone)]
pub struct SpawnOptions {
    pub stdout_log: Option<StdoutLog>,
    /// Optional transformation applied to each captured stdout line before it is written to
    /// `stdout_log`.
    ///
    /// This can be used to redact secrets before they are written to disk.
    pub stdout_log_redactor: Option<StdoutLogRedactor>,
    pub limits: Limits,
    pub diagnostics: DiagnosticsOptions,
    /// When true (default), kill the child process if the `Client` is dropped.
    ///
    /// Note: this is best-effort and does not guarantee the child is reaped. Prefer an explicit
    /// `Client::wait*` call when you own the child lifecycle.
    pub kill_on_drop: bool,
}

impl std::fmt::Debug for SpawnOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpawnOptions")
            .field("stdout_log", &self.stdout_log)
            .field("stdout_log_redactor", &self.stdout_log_redactor.is_some())
            .field("limits", &self.limits)
            .field("diagnostics", &self.diagnostics)
            .field("kill_on_drop", &self.kill_on_drop)
            .finish()
    }
}

impl Default for SpawnOptions {
    fn default() -> Self {
        Self {
            stdout_log: None,
            stdout_log_redactor: None,
            limits: Limits::default(),
            diagnostics: DiagnosticsOptions::default(),
            kill_on_drop: true,
        }
    }
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
    /// Maximum bytes of HTTP response body to include in bridged JSON-RPC error data.
    ///
    /// Default: 0 (do not include body previews) to reduce accidental secrets exposure.
    pub error_body_preview_bytes: usize,
}

impl Default for StreamableHttpOptions {
    fn default() -> Self {
        Self {
            headers: HashMap::new(),
            connect_timeout: Some(Duration::from_secs(10)),
            request_timeout: None,
            follow_redirects: false,
            error_body_preview_bytes: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiagnosticsOptions {
    /// Capture up to N invalid JSON lines (best-effort) for debugging.
    ///
    /// Default: 0 (disabled).
    pub invalid_json_sample_lines: usize,
    /// Maximum bytes per captured invalid JSON line.
    ///
    /// Default: 256.
    pub invalid_json_sample_max_bytes: usize,
}

impl Default for DiagnosticsOptions {
    fn default() -> Self {
        Self {
            invalid_json_sample_lines: 0,
            invalid_json_sample_max_bytes: 256,
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
    Protocol(ProtocolError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtocolErrorKind {
    /// The client/transport was closed (explicitly or via drop).
    Closed,
    /// Waiting for a child process to exit timed out.
    WaitTimeout,
    /// The peer sent an invalid JSON / JSON-RPC message.
    InvalidMessage,
    /// Invalid user input (e.g. invalid header name/value).
    InvalidInput,
    /// Streamable HTTP transport error (SSE/POST bridge).
    StreamableHttp,
    /// Catch-all for internal invariants.
    Other,
}

#[derive(Debug, Clone)]
pub struct ProtocolError {
    pub kind: ProtocolErrorKind,
    pub message: String,
}

impl ProtocolError {
    pub fn new(kind: ProtocolErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(f)
    }
}

impl std::error::Error for ProtocolError {}

impl Error {
    pub fn protocol(kind: ProtocolErrorKind, message: impl Into<String>) -> Self {
        Self::Protocol(ProtocolError::new(kind, message))
    }

    /// Returns true if this error was produced by `Client::wait_with_timeout`.
    pub fn is_wait_timeout(&self) -> bool {
        matches!(self, Error::Protocol(err) if err.kind == ProtocolErrorKind::WaitTimeout)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Id {
    String(String),
    Integer(i64),
}

type PendingRequests = Arc<Mutex<HashMap<Id, oneshot::Sender<Result<Value, Error>>>>>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClientStats {
    pub invalid_json_lines: u64,
    pub dropped_notifications_full: u64,
    pub dropped_notifications_closed: u64,
}

#[derive(Debug, Default)]
struct ClientStatsInner {
    invalid_json_lines: AtomicU64,
    dropped_notifications_full: AtomicU64,
    dropped_notifications_closed: AtomicU64,
}

impl ClientStatsInner {
    fn snapshot(&self) -> ClientStats {
        ClientStats {
            invalid_json_lines: self.invalid_json_lines.load(Ordering::Relaxed),
            dropped_notifications_full: self.dropped_notifications_full.load(Ordering::Relaxed),
            dropped_notifications_closed: self.dropped_notifications_closed.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug)]
struct DiagnosticsState {
    invalid_json_samples: Mutex<VecDeque<String>>,
    invalid_json_sample_lines: usize,
    invalid_json_sample_max_bytes: usize,
}

impl DiagnosticsState {
    fn new(opts: &DiagnosticsOptions) -> Option<Arc<Self>> {
        if opts.invalid_json_sample_lines == 0 {
            return None;
        }
        Some(Arc::new(Self {
            invalid_json_samples: Mutex::new(VecDeque::new()),
            invalid_json_sample_lines: opts.invalid_json_sample_lines,
            invalid_json_sample_max_bytes: opts.invalid_json_sample_max_bytes.max(1),
        }))
    }

    fn record_invalid_json_line(&self, line: &[u8]) {
        let mut guard = self
            .invalid_json_samples
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if guard.len() >= self.invalid_json_sample_lines {
            return;
        }

        let mut s = String::from_utf8_lossy(line).into_owned();
        s = truncate_string(s, self.invalid_json_sample_max_bytes);
        guard.push_back(s);
    }

    fn invalid_json_samples(&self) -> Vec<String> {
        self.invalid_json_samples
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .cloned()
            .collect()
    }
}

#[derive(Clone)]
pub struct ClientHandle {
    write: Arc<tokio::sync::Mutex<Box<dyn AsyncWrite + Send + Unpin>>>,
    next_id: Arc<AtomicI64>,
    pending: PendingRequests,
    stats: Arc<ClientStatsInner>,
    diagnostics: Option<Arc<DiagnosticsState>>,
    closed: Arc<AtomicBool>,
    close_reason: Arc<Mutex<Option<String>>>,
}

impl std::fmt::Debug for ClientHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientHandle").finish_non_exhaustive()
    }
}

impl ClientHandle {
    pub fn stats(&self) -> ClientStats {
        self.stats.snapshot()
    }

    pub fn invalid_json_samples(&self) -> Vec<String> {
        self.diagnostics
            .as_ref()
            .map(|d| d.invalid_json_samples())
            .unwrap_or_default()
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    pub fn close_reason(&self) -> Option<String> {
        self.close_reason
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }

    fn check_closed(&self) -> Result<(), Error> {
        if !self.closed.load(Ordering::Relaxed) {
            return Ok(());
        }
        let reason = self
            .close_reason
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
            .unwrap_or_else(|| "client closed".to_string());
        Err(Error::protocol(ProtocolErrorKind::Closed, reason))
    }

    pub(crate) async fn close_with_reason(&self, reason: impl Into<String>) {
        let reason = reason.into();
        self.close_with_error(
            reason.clone(),
            Error::protocol(ProtocolErrorKind::Closed, reason),
        )
        .await;
    }

    pub(crate) async fn close_with_error(&self, reason: impl Into<String>, err: Error) {
        let reason = reason.into();

        self.closed.store(true, Ordering::Relaxed);
        if let Ok(mut guard) = self.close_reason.lock() {
            if guard.is_none() {
                *guard = Some(reason);
            }
        }

        drain_pending(&self.pending, &err);
        let mut write = self.write.lock().await;
        let _ = write.shutdown().await;
        // Many `AsyncWrite` impls (e.g. `tokio::process::ChildStdin`) only fully close on drop.
        // Replacing the writer guarantees the underlying write end is closed.
        let _ = std::mem::replace(&mut *write, Box::new(tokio::io::sink()));
    }

    pub async fn notify(&self, method: &str, params: Option<Value>) -> Result<(), Error> {
        self.check_closed()?;
        let mut msg = Map::new();
        msg.insert("jsonrpc".to_string(), Value::String("2.0".to_string()));
        msg.insert("method".to_string(), Value::String(method.to_string()));
        if let Some(params) = params.filter(|v| !v.is_null()) {
            msg.insert("params".to_string(), params);
        }
        let msg = Value::Object(msg);

        let mut line = serde_json::to_string(&msg)?;
        line.push('\n');
        self.write_line(&line).await?;
        Ok(())
    }

    pub async fn request(&self, method: &str, params: Value) -> Result<Value, Error> {
        self.request_optional(method, Some(params)).await
    }

    pub async fn request_optional(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> Result<Value, Error> {
        self.check_closed()?;
        let id = Id::Integer(self.next_id.fetch_add(1, Ordering::Relaxed));

        let (tx, rx) = oneshot::channel::<Result<Value, Error>>();
        {
            let mut pending = lock_pending(&self.pending);
            pending.insert(id.clone(), tx);
        }
        let mut guard = PendingRequestGuard::new(self.pending.clone(), id.clone());

        let mut req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
        });
        if let Some(params) = params.filter(|v| !v.is_null()) {
            req["params"] = params;
        }

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
            Err(_) => Err(Error::protocol(
                ProtocolErrorKind::Closed,
                "response channel closed",
            )),
        }
    }

    pub async fn respond_ok(&self, id: Id, result: Value) -> Result<(), Error> {
        self.check_closed()?;
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
        self.check_closed()?;
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

    pub(crate) async fn respond_error_raw_id(
        &self,
        id: Value,
        code: i64,
        message: impl Into<String>,
        data: Option<Value>,
    ) -> Result<(), Error> {
        self.check_closed()?;
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
        self.check_closed()?;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOnTimeout {
    /// Return an error if the child does not exit within the timeout.
    ///
    /// The child process is left running. Use `Client::take_child()` if you want to manage it
    /// manually.
    ReturnError,
    /// Attempt to kill the child if it does not exit within the timeout.
    ///
    /// After sending the kill signal, this waits up to `kill_timeout` for the child to exit.
    Kill { kill_timeout: Duration },
}

impl Client {
    pub fn stats(&self) -> ClientStats {
        self.handle.stats()
    }

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
        cmd.kill_on_drop(options.kill_on_drop);

        let mut child = cmd.spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::protocol(ProtocolErrorKind::Other, "child stdin not captured"))?;
        let stdout = child.stdout.take().ok_or_else(|| {
            Error::protocol(ProtocolErrorKind::Other, "child stdout not captured")
        })?;

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
            Err(Error::protocol(
                ProtocolErrorKind::InvalidInput,
                "unix socket client is only supported on unix",
            ))
        }
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
        let SpawnOptions {
            stdout_log,
            stdout_log_redactor,
            limits,
            diagnostics,
            ..
        } = options;

        let notify_cap = limits.notifications_capacity.max(1);
        let request_cap = limits.requests_capacity.max(1);
        let (notify_tx, notify_rx) = mpsc::channel::<Notification>(notify_cap);
        let (request_tx, request_rx) = mpsc::channel::<IncomingRequest>(request_cap);
        let pending: PendingRequests = Arc::new(Mutex::new(HashMap::new()));
        let stats = Arc::new(ClientStatsInner::default());
        let write = Arc::new(tokio::sync::Mutex::new(Box::new(write) as _));
        let diagnostics_state = DiagnosticsState::new(&diagnostics);
        let handle = ClientHandle {
            write,
            next_id: Arc::new(AtomicI64::new(1)),
            pending: pending.clone(),
            stats: stats.clone(),
            diagnostics: diagnostics_state.clone(),
            closed: Arc::new(AtomicBool::new(false)),
            close_reason: Arc::new(Mutex::new(None)),
        };

        let stdout_log = match stdout_log {
            Some(opts) => Some(LogState::new(opts).await?),
            None => None,
        };
        let task = spawn_reader_task(
            read,
            ReaderTaskContext {
                pending,
                stats,
                notify_tx,
                request_tx,
                responder: handle.clone(),
                stdout_log,
                stdout_log_redactor,
                diagnostics_state,
                limits,
            },
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

    pub async fn request_optional(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> Result<Value, Error> {
        self.handle.request_optional(method, params).await
    }

    /// Closes the client and (if present) waits for the underlying child process to exit.
    ///
    /// Clients created without a child process (e.g. via `connect_io`, `connect_unix`, or
    /// `connect_streamable_http*`) return `Ok(None)`.
    ///
    /// Note: this method can hang indefinitely if the child process does not exit.
    /// Prefer `Client::wait_with_timeout` if you need an upper bound.
    pub async fn wait(&mut self) -> Result<Option<std::process::ExitStatus>, Error> {
        self.task.abort();
        for task in self.transport_tasks.drain(..) {
            task.abort();
        }
        self.handle.close_with_reason("client closed").await;

        match &mut self.child {
            Some(child) => Ok(Some(child.wait().await?)),
            None => Ok(None),
        }
    }

    /// Closes the client and waits for the underlying child process to exit, up to `timeout`.
    ///
    /// If this client has no child process (e.g. created via `connect_io`, `connect_unix`, or
    /// `connect_streamable_http*`), this returns `Ok(None)` without waiting.
    ///
    /// On timeout:
    /// - `WaitOnTimeout::ReturnError` returns an `Error::Protocol` with kind
    ///   `ProtocolErrorKind::WaitTimeout` and leaves the child running.
    /// - `WaitOnTimeout::Kill { kill_timeout }` sends a kill signal, then waits up to
    ///   `kill_timeout` for the child to exit.
    pub async fn wait_with_timeout(
        &mut self,
        timeout: Duration,
        on_timeout: WaitOnTimeout,
    ) -> Result<Option<std::process::ExitStatus>, Error> {
        self.task.abort();
        for task in self.transport_tasks.drain(..) {
            task.abort();
        }
        self.handle.close_with_reason("client closed").await;

        let Some(child) = &mut self.child else {
            return Ok(None);
        };

        match tokio::time::timeout(timeout, child.wait()).await {
            Ok(status) => Ok(Some(status?)),
            Err(_) => match on_timeout {
                WaitOnTimeout::ReturnError => Err(Error::protocol(
                    ProtocolErrorKind::WaitTimeout,
                    format!("wait timed out after {timeout:?}"),
                )),
                WaitOnTimeout::Kill { kill_timeout } => {
                    let child_id = child.id();
                    if let Err(err) = child.start_kill() {
                        match child.try_wait() {
                            Ok(Some(status)) => return Ok(Some(status)),
                            Ok(None) => {
                                return Err(Error::protocol(
                                    ProtocolErrorKind::WaitTimeout,
                                    format!(
                                        "wait timed out after {timeout:?}; failed to kill child (id={child_id:?}): {err}"
                                    ),
                                ));
                            }
                            Err(try_wait_err) => {
                                return Err(Error::protocol(
                                    ProtocolErrorKind::WaitTimeout,
                                    format!(
                                        "wait timed out after {timeout:?}; failed to kill child (id={child_id:?}): {err}; try_wait failed: {try_wait_err}"
                                    ),
                                ));
                            }
                        }
                    }

                    match tokio::time::timeout(kill_timeout, child.wait()).await {
                        Ok(status) => Ok(Some(status?)),
                        Err(_) => Err(Error::protocol(
                            ProtocolErrorKind::WaitTimeout,
                            format!(
                                "wait timed out after {timeout:?}; killed child (id={child_id:?}) but it did not exit within {kill_timeout:?}"
                            ),
                        )),
                    }
                }
            },
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.handle.closed.store(true, Ordering::Relaxed);
        if let Ok(mut guard) = self.handle.close_reason.lock() {
            if guard.is_none() {
                *guard = Some("client closed".to_string());
            }
        }
        self.task.abort();
        for task in self.transport_tasks.drain(..) {
            task.abort();
        }
        let err = Error::protocol(ProtocolErrorKind::Closed, "client closed");
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
    pub params: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct IncomingRequest {
    pub id: Id,
    pub method: String,
    pub params: Option<Value>,
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

struct ReaderTaskContext {
    pending: PendingRequests,
    stats: Arc<ClientStatsInner>,
    notify_tx: mpsc::Sender<Notification>,
    request_tx: mpsc::Sender<IncomingRequest>,
    responder: ClientHandle,
    stdout_log: Option<LogState>,
    stdout_log_redactor: Option<StdoutLogRedactor>,
    diagnostics_state: Option<Arc<DiagnosticsState>>,
    limits: Limits,
}

fn spawn_reader_task<R>(reader: R, ctx: ReaderTaskContext) -> tokio::task::JoinHandle<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let ReaderTaskContext {
            pending,
            stats,
            notify_tx,
            request_tx,
            responder,
            stdout_log,
            stdout_log_redactor,
            diagnostics_state,
            limits,
        } = ctx;

        let mut log_state = stdout_log;

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
                        let write_result = match &stdout_log_redactor {
                            Some(redactor) => state.write_line_bytes(&redactor(&line)).await,
                            None => state.write_line_bytes(&line).await,
                        };
                        if let Err(err) = write_result {
                            eprintln!("jsonrpc: stdout log write failed: {err}");
                            log_state = None;
                        }
                    }
                    let value: Value = match serde_json::from_slice(&line) {
                        Ok(value) => value,
                        Err(_) => {
                            stats.invalid_json_lines.fetch_add(1, Ordering::Relaxed);
                            if let Some(diagnostics) = &diagnostics_state {
                                diagnostics.record_invalid_json_line(&line);
                            }
                            continue;
                        }
                    };
                    handle_incoming_value(
                        value,
                        &pending,
                        &stats,
                        &notify_tx,
                        &request_tx,
                        &responder,
                    )
                    .await;
                }
                Ok(None) => {
                    responder
                        .close_with_reason("server closed connection")
                        .await;
                    return;
                }
                Err(err) => {
                    let reason = format!("io error: {err}");
                    responder.close_with_error(reason, Error::Io(err)).await;
                    return;
                }
            }
        }
    })
}

async fn handle_incoming_value(
    value: Value,
    pending: &PendingRequests,
    stats: &Arc<ClientStatsInner>,
    notify_tx: &mpsc::Sender<Notification>,
    request_tx: &mpsc::Sender<IncomingRequest>,
    responder: &ClientHandle,
) {
    const INVALID_REQUEST: i64 = -32600;
    const METHOD_NOT_FOUND: i64 = -32601;
    const CLIENT_OVERLOADED: i64 = -32000;

    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            Value::Array(items) => {
                if items.is_empty() {
                    let _ = responder
                        .respond_error_raw_id(Value::Null, INVALID_REQUEST, "empty batch", None)
                        .await;
                    continue;
                }
                for item in items.into_iter().rev() {
                    stack.push(item);
                }
            }
            Value::Object(map) => {
                let jsonrpc = map.get("jsonrpc").and_then(|v| v.as_str());

                let method_value = map.get("method");
                let method = method_value.and_then(|v| v.as_str());
                if let Some(method) = method {
                    if jsonrpc != Some("2.0") {
                        if let Some(id_value) = map.get("id") {
                            let id_value =
                                parse_id(id_value).map_or(Value::Null, |_| id_value.clone());
                            let _ = responder
                                .respond_error_raw_id(
                                    id_value,
                                    INVALID_REQUEST,
                                    "invalid jsonrpc version",
                                    None,
                                )
                                .await;
                        }
                        continue;
                    }

                    let params = map.get("params").cloned();
                    if let Some(id_value) = map.get("id") {
                        let Some(id) = parse_id(id_value) else {
                            let _ = responder
                                .respond_error_raw_id(
                                    Value::Null,
                                    INVALID_REQUEST,
                                    "invalid request id",
                                    None,
                                )
                                .await;
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

                    match notify_tx.try_send(Notification {
                        method: method.to_string(),
                        params,
                    }) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            stats
                                .dropped_notifications_full
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            stats
                                .dropped_notifications_closed
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    continue;
                }
                if method_value.is_some() {
                    if let Some(id_value) = map.get("id") {
                        let id_value = parse_id(id_value).map_or(Value::Null, |_| id_value.clone());
                        let _ = responder
                            .respond_error_raw_id(
                                id_value,
                                INVALID_REQUEST,
                                "invalid request method",
                                None,
                            )
                            .await;
                    }
                    continue;
                }

                handle_response(pending, Value::Object(map));
            }
            _ => {
                // JSON-RPC messages must be objects or arrays.
                let _ = responder
                    .respond_error_raw_id(Value::Null, INVALID_REQUEST, "invalid message", None)
                    .await;
            }
        }
    }
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
        Error::Json(err) => Error::protocol(ProtocolErrorKind::Other, format!("json error: {err}")),
        Error::Rpc {
            code,
            message,
            data,
        } => Error::Rpc {
            code: *code,
            message: message.clone(),
            data: data.clone(),
        },
        Error::Protocol(err) => Error::Protocol(err.clone()),
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
    let Value::Object(map) = value else {
        return;
    };

    let Some(id_value) = map.get("id") else {
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

    if map.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
        let _ = tx.send(Err(Error::protocol(
            ProtocolErrorKind::InvalidMessage,
            "invalid response jsonrpc version",
        )));
        return;
    }

    let has_error = map.contains_key("error");
    let has_result = map.contains_key("result");
    match (has_error, has_result) {
        (true, false) => {
            let Some(error) = map.get("error") else {
                let _ = tx.send(Err(Error::protocol(
                    ProtocolErrorKind::InvalidMessage,
                    "invalid error response",
                )));
                return;
            };
            let Value::Object(error) = error else {
                let _ = tx.send(Err(Error::protocol(
                    ProtocolErrorKind::InvalidMessage,
                    "invalid error response",
                )));
                return;
            };

            let Some(code) = error.get("code").and_then(|v| v.as_i64()) else {
                let _ = tx.send(Err(Error::protocol(
                    ProtocolErrorKind::InvalidMessage,
                    "invalid error response",
                )));
                return;
            };
            let Some(message) = error.get("message").and_then(|v| v.as_str()) else {
                let _ = tx.send(Err(Error::protocol(
                    ProtocolErrorKind::InvalidMessage,
                    "invalid error response",
                )));
                return;
            };
            let data = error.get("data").cloned();
            let _ = tx.send(Err(Error::Rpc {
                code,
                message: message.to_string(),
                data,
            }));
        }
        (false, true) => {
            let Some(result) = map.get("result").cloned() else {
                let _ = tx.send(Err(Error::protocol(
                    ProtocolErrorKind::InvalidMessage,
                    "invalid result response",
                )));
                return;
            };
            let _ = tx.send(Ok(result));
        }
        _ => {
            let _ = tx.send(Err(Error::protocol(
                ProtocolErrorKind::InvalidMessage,
                "invalid response: must include exactly one of result/error",
            )));
        }
    }
}

// Streamable HTTP and stdout_log implementations live in `streamable_http.rs` and
// `stdout_log.rs`.

#[cfg(test)]
mod stats_tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn stats_tracks_invalid_json_lines() {
        let (client_stream, server_stream) = tokio::io::duplex(1024);
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (_server_read, mut server_write) = tokio::io::split(server_stream);

        let client = Client::connect_io(client_read, client_write).await.unwrap();

        server_write.write_all(b"not-json\n").await.unwrap();
        server_write.flush().await.unwrap();

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if client.stats().invalid_json_lines >= 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn stats_tracks_dropped_notifications() {
        let (client_stream, server_stream) = tokio::io::duplex(1024);
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (_server_read, mut server_write) = tokio::io::split(server_stream);

        let mut options = SpawnOptions::default();
        options.limits.notifications_capacity = 1;
        let client = Client::connect_io_with_options(client_read, client_write, options)
            .await
            .unwrap();

        let note = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "demo/notify",
            "params": {},
        });
        let mut out = serde_json::to_string(&note).unwrap();
        out.push('\n');
        server_write.write_all(out.as_bytes()).await.unwrap();
        server_write.write_all(out.as_bytes()).await.unwrap();
        server_write.flush().await.unwrap();

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if client.stats().dropped_notifications_full >= 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}
