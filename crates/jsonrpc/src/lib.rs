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
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot};

mod stdout_log;
mod streamable_http;

use stdout_log::LogState;

pub type StdoutLogRedactor = Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>;

const DEFAULT_MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const REUSABLE_LINE_BUFFER_RETAIN_BYTES: usize = 64 * 1024;

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
    /// Maximum in-flight client->server requests waiting for responses.
    pub max_pending_requests: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            // Large enough for typical MCP messages, but bounded to reduce DoS risk.
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            notifications_capacity: 256,
            requests_capacity: 64,
            max_pending_requests: 64,
        }
    }
}

pub(crate) fn normalize_max_message_bytes(max_message_bytes: usize) -> usize {
    if max_message_bytes == 0 {
        return DEFAULT_MAX_MESSAGE_BYTES;
    }
    max_message_bytes
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
type CancelledRequestIds = Arc<Mutex<CancelledRequestIdsState>>;

const CANCELLED_REQUEST_IDS_MAX: usize = 1024;

#[derive(Debug, Default)]
struct CancelledRequestIdsState {
    order: VecDeque<(u64, Id)>,
    latest: HashMap<Id, u64>,
    next_generation: u64,
}

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
            invalid_json_samples: Mutex::new(VecDeque::with_capacity(
                opts.invalid_json_sample_lines,
            )),
            invalid_json_sample_lines: opts.invalid_json_sample_lines,
            invalid_json_sample_max_bytes: opts.invalid_json_sample_max_bytes.max(1),
        }))
    }

    fn record_invalid_json_line(&self, line: &[u8]) {
        let mut guard = self
            .invalid_json_samples
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if guard.len() >= self.invalid_json_sample_lines {
            return;
        }

        let sample_len = line.len().min(self.invalid_json_sample_max_bytes);
        let mut s = String::from_utf8_lossy(&line[..sample_len]).into_owned();
        if sample_len < line.len() {
            s.push('…');
        }
        s = truncate_string(s, self.invalid_json_sample_max_bytes);
        guard.push_back(s);
    }

    fn invalid_json_samples(&self) -> Vec<String> {
        self.invalid_json_samples
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
    max_pending_requests: usize,
    cancelled_request_ids: CancelledRequestIds,
    stats: Arc<ClientStatsInner>,
    diagnostics: Option<Arc<DiagnosticsState>>,
    closed: Arc<AtomicBool>,
    close_reason: Arc<OnceLock<String>>,
    stdout_log_write_error: Arc<OnceLock<String>>,
}

impl std::fmt::Debug for ClientHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientHandle").finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct OutboundNotification<'a> {
    jsonrpc: &'static str,
    method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<&'a Value>,
}

#[derive(Serialize)]
struct OutboundRequest<'a> {
    jsonrpc: &'static str,
    id: &'a Id,
    method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<&'a Value>,
}

#[derive(Serialize)]
struct OutboundOkResponse<'a> {
    jsonrpc: &'static str,
    id: &'a Id,
    result: &'a Value,
}

#[derive(Serialize)]
struct OutboundErrorBody<'a> {
    code: i64,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<&'a Value>,
}

#[derive(Serialize)]
struct OutboundErrorResponse<'a, I> {
    jsonrpc: &'static str,
    id: &'a I,
    error: OutboundErrorBody<'a>,
}

fn serialize_json_line(value: &impl Serialize) -> Result<Vec<u8>, Error> {
    let mut line = serde_json::to_vec(value)?;
    line.push(b'\n');
    Ok(line)
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
        self.close_reason.get().cloned()
    }

    /// Returns the last stdout log write error, if any.
    ///
    /// When this is set, the client disables stdout log writes for the remainder of its
    /// lifetime. This is not treated as a fatal transport error.
    pub fn stdout_log_write_error(&self) -> Option<String> {
        self.stdout_log_write_error.get().cloned()
    }

    fn record_stdout_log_write_error(&self, err: &std::io::Error) {
        let _ = self.stdout_log_write_error.set(err.to_string());
    }

    pub async fn close(&self, reason: impl Into<String>) {
        self.close_with_reason(reason).await;
    }

    fn schedule_close_once(&self, reason: String) {
        if self
            .closed
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let _ = self.close_reason.set(reason.clone()); // pre-commit: allow-let-underscore
        let handle = self.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            drop(runtime.spawn(async move {
                handle.close_with_reason(reason).await;
            }));
            return;
        }

        // No runtime available (e.g. sync context): avoid panicking and perform best-effort close.
        let err = Error::protocol(ProtocolErrorKind::Closed, reason);
        drain_pending(&handle.pending, &err);
        if let Ok(mut write) = handle.write.try_lock() {
            drop(std::mem::replace(&mut *write, Box::new(tokio::io::sink())));
        }
    }

    fn check_closed(&self) -> Result<(), Error> {
        if !self.closed.load(Ordering::Relaxed) {
            return Ok(());
        }
        let reason = self
            .close_reason
            .get()
            .cloned()
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
        let _ = self.close_reason.set(reason);

        drain_pending(&self.pending, &err);
        let mut write = self.write.lock().await;
        let _ = write.shutdown().await;
        // Many `AsyncWrite` impls (e.g. `tokio::process::ChildStdin`) only fully close on drop.
        // Replacing the writer guarantees the underlying write end is closed.
        let _ = std::mem::replace(&mut *write, Box::new(tokio::io::sink()));
    }

    pub async fn notify(&self, method: &str, params: Option<Value>) -> Result<(), Error> {
        self.check_closed()?;
        let params = params.filter(|v| !v.is_null());
        let msg = OutboundNotification {
            jsonrpc: "2.0",
            method,
            params: params.as_ref(),
        };
        let line = serialize_json_line(&msg)?;
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
        self.request_optional_inner(method, params, None).await
    }

    pub async fn request_optional_with_timeout(
        &self,
        method: &str,
        params: Option<Value>,
        timeout: Duration,
    ) -> Result<Value, Error> {
        self.request_optional_inner(method, params, Some(timeout))
            .await
    }

    async fn request_optional_inner(
        &self,
        method: &str,
        params: Option<Value>,
        timeout: Option<Duration>,
    ) -> Result<Value, Error> {
        self.check_closed()?;
        let id = Id::Integer(self.next_id.fetch_add(1, Ordering::Relaxed));

        let (tx, rx) = oneshot::channel::<Result<Value, Error>>();
        {
            let mut pending = lock_pending(&self.pending);
            if pending.len() >= self.max_pending_requests {
                return Err(Error::protocol(
                    ProtocolErrorKind::Other,
                    format!(
                        "too many pending requests (limit: {})",
                        self.max_pending_requests
                    ),
                ));
            }
            pending.insert(id.clone(), tx);
        }
        let mut guard = PendingRequestGuard::new(
            self.pending.clone(),
            self.cancelled_request_ids.clone(),
            id.clone(),
        );

        let params = params.filter(|v| !v.is_null());
        let req = OutboundRequest {
            jsonrpc: "2.0",
            id: &id,
            method,
            params: params.as_ref(),
        };
        let line = serialize_json_line(&req)?;
        let recv_result = match timeout {
            Some(timeout) => {
                let deadline = tokio::time::Instant::now() + timeout;
                match tokio::time::timeout_at(deadline, self.write_line(&line)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        lock_pending(&self.pending).remove(&id);
                        guard.disarm();
                        return Err(err);
                    }
                    Err(_) => {
                        let reason = format!("request timed out after {timeout:?} while writing");
                        self.schedule_close_once(reason);
                        return Err(Error::protocol(
                            ProtocolErrorKind::WaitTimeout,
                            format!("request timed out after {timeout:?}"),
                        ));
                    }
                }

                match tokio::time::timeout_at(deadline, rx).await {
                    Ok(result) => result,
                    Err(_) => {
                        return Err(Error::protocol(
                            ProtocolErrorKind::WaitTimeout,
                            format!("request timed out after {timeout:?}"),
                        ));
                    }
                }
            }
            None => {
                if let Err(err) = self.write_line(&line).await {
                    lock_pending(&self.pending).remove(&id);
                    guard.disarm();
                    return Err(err);
                }
                rx.await
            }
        };

        match recv_result {
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
        let response = OutboundOkResponse {
            jsonrpc: "2.0",
            id: &id,
            result: &result,
        };
        let line = serialize_json_line(&response)?;
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
        let message = message.into();
        let response = OutboundErrorResponse {
            jsonrpc: "2.0",
            id: &id,
            error: OutboundErrorBody {
                code,
                message: &message,
                data: data.as_ref(),
            },
        };
        let line = serialize_json_line(&response)?;
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
        let message = message.into();
        let response = OutboundErrorResponse {
            jsonrpc: "2.0",
            id: &id,
            error: OutboundErrorBody {
                code,
                message: &message,
                data: data.as_ref(),
            },
        };
        let line = serialize_json_line(&response)?;
        self.write_line(&line).await
    }

    async fn write_line(&self, line: &[u8]) -> Result<(), Error> {
        self.check_closed()?;
        let mut write = self.write.lock().await;
        write.write_all(line).await?;
        write.flush().await?;
        drop(write);
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

    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
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
        let max_pending_requests = limits.max_pending_requests.max(1);
        let (notify_tx, notify_rx) = mpsc::channel::<Notification>(notify_cap);
        let (request_tx, request_rx) = mpsc::channel::<IncomingRequest>(request_cap);
        let pending: PendingRequests = Arc::new(Mutex::new(HashMap::new()));
        let cancelled_request_ids: CancelledRequestIds =
            Arc::new(Mutex::new(CancelledRequestIdsState::default()));
        let stats = Arc::new(ClientStatsInner::default());
        let write = Arc::new(tokio::sync::Mutex::new(Box::new(write) as _));
        let diagnostics_state = DiagnosticsState::new(&diagnostics);
        let handle = ClientHandle {
            write,
            next_id: Arc::new(AtomicI64::new(1)),
            pending: pending.clone(),
            max_pending_requests,
            cancelled_request_ids: cancelled_request_ids.clone(),
            stats: stats.clone(),
            diagnostics: diagnostics_state.clone(),
            closed: Arc::new(AtomicBool::new(false)),
            close_reason: Arc::new(OnceLock::new()),
            stdout_log_write_error: Arc::new(OnceLock::new()),
        };

        let stdout_log = match stdout_log {
            Some(opts) => Some(LogState::new(opts).await?),
            None => None,
        };
        let task = spawn_reader_task(
            read,
            ReaderTaskContext {
                pending,
                cancelled_request_ids,
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

    pub async fn close(&self, reason: impl Into<String>) {
        self.task.abort();
        for task in &self.transport_tasks {
            task.abort();
        }
        self.handle.close(reason).await;
    }

    /// Schedule an asynchronous close only once.
    ///
    /// This marks the client closed immediately and starts a best-effort background close path.
    /// Repeated calls after the first one are no-ops.
    pub fn close_in_background_once(&self, reason: impl Into<String>) {
        self.handle.schedule_close_once(reason.into());
    }

    pub fn child_id(&self) -> Option<u32> {
        self.child.as_ref().and_then(tokio::process::Child::id)
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

    pub async fn request_optional_with_timeout(
        &self,
        method: &str,
        params: Option<Value>,
        timeout: Duration,
    ) -> Result<Value, Error> {
        self.handle
            .request_optional_with_timeout(method, params, timeout)
            .await
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
        let deadline = tokio::time::Instant::now() + timeout;
        self.task.abort();
        for task in self.transport_tasks.drain(..) {
            task.abort();
        }
        if tokio::time::timeout_at(deadline, self.handle.close_with_reason("client closed"))
            .await
            .is_err()
        {
            if let WaitOnTimeout::Kill { kill_timeout } = on_timeout
                && let Some(child) = &mut self.child
            {
                let child_id = child.id();
                if let Err(err) = child.start_kill() {
                    return match child.try_wait() {
                        Ok(Some(status)) => Ok(Some(status)),
                        Ok(None) => Err(Error::protocol(
                            ProtocolErrorKind::WaitTimeout,
                            format!(
                                "wait timed out after {timeout:?} while closing client; failed to kill child (id={child_id:?}): {err}"
                            ),
                        )),
                        Err(try_wait_err) => Err(Error::protocol(
                            ProtocolErrorKind::WaitTimeout,
                            format!(
                                "wait timed out after {timeout:?} while closing client; failed to kill child (id={child_id:?}): {err}; try_wait failed: {try_wait_err}"
                            ),
                        )),
                    };
                }
                return match tokio::time::timeout(kill_timeout, child.wait()).await {
                    Ok(status) => Ok(Some(status?)),
                    Err(_) => Err(Error::protocol(
                        ProtocolErrorKind::WaitTimeout,
                        format!(
                            "wait timed out after {timeout:?} while closing client; killed child (id={child_id:?}) but it did not exit within {kill_timeout:?}"
                        ),
                    )),
                };
            }

            return Err(Error::protocol(
                ProtocolErrorKind::WaitTimeout,
                format!("wait timed out after {timeout:?} while closing client"),
            ));
        }

        let Some(child) = &mut self.child else {
            return Ok(None);
        };
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());

        match tokio::time::timeout(remaining, child.wait()).await {
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
        let _ = self.handle.close_reason.set("client closed".to_string());
        self.task.abort();
        for task in self.transport_tasks.drain(..) {
            task.abort();
        }
        // Best-effort: eagerly drop the underlying writer even if cloned handles remain.
        if let Ok(mut write) = self.handle.write.try_lock() {
            drop(std::mem::replace(&mut *write, Box::new(tokio::io::sink())));
        }
        let err = Error::protocol(ProtocolErrorKind::Closed, "client closed");
        drain_pending(&self.handle.pending, &err);
    }
}

struct PendingRequestGuard {
    pending: PendingRequests,
    cancelled_request_ids: CancelledRequestIds,
    id: Id,
    armed: bool,
}

impl PendingRequestGuard {
    fn new(pending: PendingRequests, cancelled_request_ids: CancelledRequestIds, id: Id) -> Self {
        Self {
            pending,
            cancelled_request_ids,
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
        drop(pending);
        remember_cancelled_request_id(&self.cancelled_request_ids, &self.id);
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
    cancelled_request_ids: CancelledRequestIds,
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
            cancelled_request_ids,
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

        let max_message_bytes = normalize_max_message_bytes(limits.max_message_bytes);
        let mut reader = tokio::io::BufReader::new(reader);
        let mut line = Vec::new();
        loop {
            let next = read_line_limited_into(&mut reader, max_message_bytes, &mut line).await;
            match next {
                Ok(true) => {
                    if is_ascii_whitespace_only(&line) {
                        continue;
                    }
                    if let Some(state) = &mut log_state {
                        let write_result = match &stdout_log_redactor {
                            Some(redactor) => state.write_line_bytes(&redactor(&line)).await,
                            None => state.write_line_bytes(&line).await,
                        };
                        if let Err(err) = write_result {
                            responder.record_stdout_log_write_error(&err);
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
                        &cancelled_request_ids,
                        &stats,
                        &notify_tx,
                        &request_tx,
                        &responder,
                    )
                    .await;
                }
                Ok(false) => {
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
    cancelled_request_ids: &CancelledRequestIds,
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
            Value::Object(mut map) => {
                let jsonrpc_valid = map.get("jsonrpc").and_then(Value::as_str) == Some("2.0");

                match map.remove("method") {
                    Some(Value::String(method)) => {
                        if !jsonrpc_valid {
                            if let Some(id_value) = map.get("id") {
                                let id_value =
                                    parse_id(id_value).map_or(Value::Null, |_| id_value.clone());
                                drop(
                                    responder
                                        .respond_error_raw_id(
                                            id_value,
                                            INVALID_REQUEST,
                                            "invalid jsonrpc version",
                                            None,
                                        )
                                        .await,
                                );
                            }
                            continue;
                        }

                        let params = map.remove("params");
                        if let Some(id_value) = map.get("id") {
                            let Some(id) = parse_id(id_value) else {
                                drop(
                                    responder
                                        .respond_error_raw_id(
                                            Value::Null,
                                            INVALID_REQUEST,
                                            "invalid request id",
                                            None,
                                        )
                                        .await,
                                );
                                continue;
                            };

                            let request = IncomingRequest {
                                id,
                                method,
                                params,
                                responder: responder.clone(),
                            };

                            match request_tx.try_send(request) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(request)) => {
                                    drop(
                                        responder
                                            .respond_error(
                                                request.id,
                                                CLIENT_OVERLOADED,
                                                "client overloaded",
                                                None,
                                            )
                                            .await,
                                    );
                                }
                                Err(mpsc::error::TrySendError::Closed(request)) => {
                                    drop(
                                        responder
                                            .respond_error(
                                                request.id,
                                                METHOD_NOT_FOUND,
                                                "no request handler installed",
                                                None,
                                            )
                                            .await,
                                    );
                                }
                            }
                            continue;
                        }

                        match notify_tx.try_send(Notification { method, params }) {
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
                    Some(_) => {
                        if let Some(id_value) = map.get("id") {
                            let id_value =
                                parse_id(id_value).map_or(Value::Null, |_| id_value.clone());
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
                    None => {}
                }

                if let Err(err) =
                    handle_response(pending, cancelled_request_ids, Value::Object(map))
                {
                    responder.close_with_error(err.to_string(), err).await;
                    return;
                }
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
    if read_line_limited_into(reader, max_bytes, &mut buf).await? {
        Ok(Some(buf))
    } else {
        Ok(None)
    }
}

async fn read_line_limited_into<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
    buf: &mut Vec<u8>,
) -> Result<bool, std::io::Error> {
    buf.clear();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if buf.len() > max_bytes {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "jsonrpc message too large",
                ));
            }
            maybe_shrink_line_buffer(buf, max_bytes);
            return Ok(!buf.is_empty());
        }

        let newline_pos = available.iter().position(|b| *b == b'\n');
        let take = newline_pos.map_or(available.len(), |idx| idx.saturating_add(1));
        // Allow only delimiter slack above the payload limit:
        // - up to 1 byte while scanning (possible trailing '\r' before '\n')
        // - up to 2 bytes when this chunk includes '\n' (possible "\r\n")
        let delimiter_slack = if newline_pos.is_some() { 2 } else { 1 };
        if buf.len().saturating_add(take) > max_bytes.saturating_add(delimiter_slack) {
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

    if buf.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "jsonrpc message too large",
        ));
    }

    maybe_shrink_line_buffer(buf, max_bytes);
    Ok(true)
}

pub(crate) fn is_ascii_whitespace_only(line: &[u8]) -> bool {
    line.is_empty()
        || (line.first().is_some_and(u8::is_ascii_whitespace)
            && line.iter().all(u8::is_ascii_whitespace))
}

fn maybe_shrink_line_buffer(buf: &mut Vec<u8>, max_bytes: usize) {
    let retain = REUSABLE_LINE_BUFFER_RETAIN_BYTES.min(max_bytes);
    if retain == 0 {
        return;
    }
    // After occasional large messages, release surplus capacity once smaller traffic resumes.
    if buf.capacity() > retain && buf.len() <= retain {
        buf.shrink_to(retain);
    }
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

fn lock_pending(
    pending: &PendingRequests,
) -> std::sync::MutexGuard<'_, HashMap<Id, oneshot::Sender<Result<Value, Error>>>> {
    pending
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn lock_cancelled_request_ids(
    cancelled_request_ids: &CancelledRequestIds,
) -> std::sync::MutexGuard<'_, CancelledRequestIdsState> {
    cancelled_request_ids
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn remember_cancelled_request_id(cancelled_request_ids: &CancelledRequestIds, id: &Id) {
    let mut guard = lock_cancelled_request_ids(cancelled_request_ids);
    if guard.latest.contains_key(id) {
        return;
    }
    while guard.order.len() >= CANCELLED_REQUEST_IDS_MAX {
        let Some((generation, evicted)) = guard.order.pop_front() else {
            break;
        };
        if guard.latest.get(&evicted).copied() == Some(generation) {
            guard.latest.remove(&evicted);
        }
    }
    let generation = guard.next_generation;
    guard.next_generation = guard.next_generation.wrapping_add(1);
    guard.order.push_back((generation, id.clone()));
    guard.latest.insert(id.clone(), generation);
}

fn take_cancelled_request_id(cancelled_request_ids: &CancelledRequestIds, id: &Id) -> bool {
    let mut guard = lock_cancelled_request_ids(cancelled_request_ids);
    guard.latest.remove(id).is_some()
}

fn type_mismatch_candidate_id(id: &Id) -> Option<Id> {
    match id {
        Id::Integer(value) => Some(Id::String(value.to_string())),
        Id::String(value) => match value.parse::<i64>() {
            Ok(parsed) if parsed.to_string() == *value => Some(Id::Integer(parsed)),
            _ => None,
        },
    }
}

fn take_cancelled_request_id_type_mismatch(
    cancelled_request_ids: &CancelledRequestIds,
    id: &Id,
) -> bool {
    let Some(candidate) = type_mismatch_candidate_id(id) else {
        return false;
    };

    let mut guard = lock_cancelled_request_ids(cancelled_request_ids);
    guard.latest.remove(&candidate).is_some()
}

fn take_pending_type_mismatch_sender(
    pending: &PendingRequests,
    id: &Id,
) -> Option<oneshot::Sender<Result<Value, Error>>> {
    let candidate = type_mismatch_candidate_id(id)?;

    let mut pending = lock_pending(pending);
    pending.remove(&candidate)
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

fn parse_id_owned(value: Value) -> Option<Id> {
    match value {
        Value::String(value) => Some(Id::String(value)),
        Value::Number(value) => value.as_i64().map(Id::Integer).or_else(|| {
            value
                .as_u64()
                .and_then(|v| i64::try_from(v).ok())
                .map(Id::Integer)
        }),
        _ => None,
    }
}

fn handle_response(
    pending: &PendingRequests,
    cancelled_request_ids: &CancelledRequestIds,
    value: Value,
) -> Result<(), Error> {
    let Value::Object(mut map) = value else {
        return Err(Error::protocol(
            ProtocolErrorKind::InvalidMessage,
            "invalid response: not an object",
        ));
    };

    let Some(id_value) = map.remove("id") else {
        return Err(Error::protocol(
            ProtocolErrorKind::InvalidMessage,
            "invalid response: missing id",
        ));
    };
    let Some(id) = parse_id_owned(id_value) else {
        return Err(Error::protocol(
            ProtocolErrorKind::InvalidMessage,
            "invalid response: invalid id",
        ));
    };

    let tx = {
        let mut pending = lock_pending(pending);
        pending.remove(&id)
    };
    let Some(tx) = tx else {
        if take_cancelled_request_id(cancelled_request_ids, &id)
            || take_cancelled_request_id_type_mismatch(cancelled_request_ids, &id)
        {
            return Ok(());
        }
        if let Some(tx) = take_pending_type_mismatch_sender(pending, &id) {
            let _ = /* pre-commit: allow-let-underscore */ tx.send(Err(Error::protocol(
                ProtocolErrorKind::InvalidMessage,
                "invalid response: response id type mismatch",
            )));
            return Ok(());
        }
        // Unknown response ids are treated as stale/stray and ignored to avoid tearing down
        // otherwise healthy connections when late responses arrive after local timeout/cancel.
        return Ok(());
    };

    if map.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
        let _ = tx.send(Err(Error::protocol(
            ProtocolErrorKind::InvalidMessage,
            "invalid response jsonrpc version",
        )));
        return Ok(());
    }

    let has_error = map.contains_key("error");
    let has_result = map.contains_key("result");
    match (has_error, has_result) {
        (true, false) => {
            let Some(error) = map.remove("error") else {
                let _ = tx.send(Err(Error::protocol(
                    ProtocolErrorKind::InvalidMessage,
                    "invalid error response",
                )));
                return Ok(());
            };
            let Value::Object(mut error) = error else {
                let _ = tx.send(Err(Error::protocol(
                    ProtocolErrorKind::InvalidMessage,
                    "invalid error response",
                )));
                return Ok(());
            };

            let Some(code) = error.get("code").and_then(Value::as_i64) else {
                let _ = tx.send(Err(Error::protocol(
                    ProtocolErrorKind::InvalidMessage,
                    "invalid error response",
                )));
                return Ok(());
            };
            let Some(message) = error
                .get("message")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned)
            else {
                let _ = tx.send(Err(Error::protocol(
                    ProtocolErrorKind::InvalidMessage,
                    "invalid error response",
                )));
                return Ok(());
            };
            let data = error.remove("data");
            let _ = tx.send(Err(Error::Rpc {
                code,
                message,
                data,
            }));
            Ok(())
        }
        (false, true) => {
            let Some(result) = map.remove("result") else {
                let _ = tx.send(Err(Error::protocol(
                    ProtocolErrorKind::InvalidMessage,
                    "invalid result response",
                )));
                return Ok(());
            };
            let _ = tx.send(Ok(result));
            Ok(())
        }
        _ => {
            let _ = tx.send(Err(Error::protocol(
                ProtocolErrorKind::InvalidMessage,
                "invalid response: must include exactly one of result/error",
            )));
            Ok(())
        }
    }
}

// Streamable HTTP and stdout_log implementations live in `streamable_http.rs` and
// `stdout_log.rs`.

#[cfg(test)]
mod line_limit_tests {
    use super::*;

    #[tokio::test]
    async fn read_line_limited_accepts_payload_equal_to_limit_with_lf() {
        let input = b"hello\n";
        let mut reader = tokio::io::BufReader::new(std::io::Cursor::new(input.as_slice()));

        let line = match read_line_limited(&mut reader, 5).await {
            Ok(Some(line)) => line,
            Ok(None) => panic!("line available"),
            Err(err) => panic!("read succeeds: {err}"),
        };

        assert_eq!(line, b"hello");
    }

    #[tokio::test]
    async fn read_line_limited_accepts_payload_equal_to_limit_with_crlf() {
        let input = b"hello\r\n";
        let mut reader = tokio::io::BufReader::new(std::io::Cursor::new(input.as_slice()));

        let line = match read_line_limited(&mut reader, 5).await {
            Ok(Some(line)) => line,
            Ok(None) => panic!("line available"),
            Err(err) => panic!("read succeeds: {err}"),
        };

        assert_eq!(line, b"hello");
    }

    #[tokio::test]
    async fn read_line_limited_rejects_payload_over_limit() {
        let input = b"helloo\n";
        let mut reader = tokio::io::BufReader::new(std::io::Cursor::new(input.as_slice()));

        let err = read_line_limited(&mut reader, 5)
            .await
            .expect_err("must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn read_line_limited_rejects_payload_over_limit_without_newline() {
        let input = b"helloo";
        let mut reader = tokio::io::BufReader::new(std::io::Cursor::new(input.as_slice()));

        let err = read_line_limited(&mut reader, 5)
            .await
            .expect_err("must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn read_line_limited_into_releases_large_buffer_after_small_line() {
        let large = vec![b'x'; REUSABLE_LINE_BUFFER_RETAIN_BYTES * 2];
        let mut input = large.clone();
        input.push(b'\n');
        input.extend_from_slice(b"ok\n");

        let mut reader = tokio::io::BufReader::new(std::io::Cursor::new(input));
        let mut line = Vec::new();

        assert!(
            read_line_limited_into(&mut reader, large.len(), &mut line)
                .await
                .expect("large line must parse")
        );
        let large_capacity = line.capacity();
        assert!(large_capacity >= large.len());

        assert!(
            read_line_limited_into(&mut reader, large.len(), &mut line)
                .await
                .expect("small line must parse")
        );
        assert_eq!(line, b"ok");
        assert!(line.capacity() <= REUSABLE_LINE_BUFFER_RETAIN_BYTES);
    }

    #[test]
    fn ascii_whitespace_only_fast_path_keeps_semantics() {
        assert!(is_ascii_whitespace_only(b""));
        assert!(is_ascii_whitespace_only(b" \t\r\n"));
        assert!(!is_ascii_whitespace_only(b"{\"jsonrpc\":\"2.0\"}"));
        assert!(!is_ascii_whitespace_only(b"\xE3\x80\x80"));
    }
}

#[cfg(test)]
mod stats_tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn max_message_bytes_zero_falls_back_to_default() {
        assert_eq!(
            normalize_max_message_bytes(0),
            Limits::default().max_message_bytes
        );
        assert_eq!(normalize_max_message_bytes(4096), 4096);
    }

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

#[cfg(test)]
#[cfg(unix)]
mod wait_timeout_tests {
    use super::*;
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
        ) -> Poll<std::io::Result<usize>> {
            self.entered.store(true, Ordering::Relaxed);
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.entered.store(true, Ordering::Relaxed);
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.entered.store(true, Ordering::Relaxed);
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn wait_with_timeout_kill_still_kills_when_close_stage_times_out() {
        let mut cmd = tokio::process::Command::new("sh");
        cmd.arg("-c").arg("exec sleep 10");

        let mut client = match Client::spawn_command(cmd).await {
            Ok(client) => client,
            Err(err) => panic!("spawn client: {err}"),
        };
        let entered = Arc::new(AtomicBool::new(false));
        {
            let mut write = client.handle.write.lock().await;
            *write = Box::new(BlockingWrite {
                entered: entered.clone(),
            });
        }

        let wait_result = client
            .wait_with_timeout(
                Duration::from_millis(20),
                WaitOnTimeout::Kill {
                    kill_timeout: Duration::from_secs(1),
                },
            )
            .await;
        let child_status = match wait_result {
            Ok(status) => status,
            Err(err) => panic!("wait should kill child even when close stage times out: {err}"),
        };
        let status = match child_status {
            Some(status) => status,
            None => panic!("child exit status"),
        };

        assert!(entered.load(Ordering::Relaxed));
        assert!(!status.success());
    }
}

#[cfg(test)]
mod background_close_tests {
    use super::*;

    #[test]
    fn schedule_close_once_without_runtime_drains_pending_without_panic() {
        let pending: PendingRequests = Arc::new(Mutex::new(HashMap::new()));
        let (tx, rx) = oneshot::channel();
        lock_pending(&pending).insert(Id::Integer(1), tx);

        let handle = ClientHandle {
            write: Arc::new(tokio::sync::Mutex::new(
                Box::new(tokio::io::sink()) as Box<dyn AsyncWrite + Send + Unpin>
            )),
            next_id: Arc::new(AtomicI64::new(1)),
            pending: pending.clone(),
            max_pending_requests: 1,
            cancelled_request_ids: Arc::new(Mutex::new(CancelledRequestIdsState::default())),
            stats: Arc::new(ClientStatsInner::default()),
            diagnostics: None,
            closed: Arc::new(AtomicBool::new(false)),
            close_reason: Arc::new(OnceLock::new()),
            stdout_log_write_error: Arc::new(OnceLock::new()),
        };

        handle.schedule_close_once("closed outside runtime".to_string());

        assert!(handle.is_closed());
        assert_eq!(
            handle.close_reason().as_deref(),
            Some("closed outside runtime")
        );
        assert!(lock_pending(&pending).is_empty());

        let drained = rx
            .blocking_recv()
            .expect("pending request should be drained");
        let err = drained.expect_err("drained pending request must receive closed error");
        assert!(matches!(
            err,
            Error::Protocol(ProtocolError {
                kind: ProtocolErrorKind::Closed,
                ..
            })
        ));
    }
}

#[cfg(test)]
mod cancelled_request_ids_tests {
    use super::*;

    #[test]
    fn cancelled_request_id_eviction_preserves_latest_reinserted_id() {
        let cancelled_request_ids = Arc::new(Mutex::new(CancelledRequestIdsState::default()));
        let id = Id::Integer(1);

        remember_cancelled_request_id(&cancelled_request_ids, &id);
        assert!(take_cancelled_request_id(&cancelled_request_ids, &id));

        // Reinsert the same id, then push enough unique ids to evict stale queue entries.
        remember_cancelled_request_id(&cancelled_request_ids, &id);
        for value in 2..=(CANCELLED_REQUEST_IDS_MAX as i64) {
            remember_cancelled_request_id(&cancelled_request_ids, &Id::Integer(value));
        }

        assert!(take_cancelled_request_id(&cancelled_request_ids, &id));
        assert!(!take_cancelled_request_id(&cancelled_request_ids, &id));

        let guard = lock_cancelled_request_ids(&cancelled_request_ids);
        assert!(guard.order.len() <= CANCELLED_REQUEST_IDS_MAX);
    }

    #[test]
    fn cancelled_request_id_type_mismatch_consumes_counterpart_entry() {
        let cancelled_request_ids = Arc::new(Mutex::new(CancelledRequestIdsState::default()));
        let id = Id::Integer(7);

        remember_cancelled_request_id(&cancelled_request_ids, &id);
        assert!(take_cancelled_request_id_type_mismatch(
            &cancelled_request_ids,
            &Id::String("7".to_string())
        ));
        assert!(!take_cancelled_request_id(&cancelled_request_ids, &id));
    }
}
