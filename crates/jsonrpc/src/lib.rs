use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use serde_json::{Map, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{mpsc, oneshot};

#[derive(Debug, Clone, Default)]
pub struct SpawnOptions {
    pub stdout_log: Option<StdoutLog>,
}

#[derive(Debug, Clone)]
pub struct StdoutLog {
    pub path: PathBuf,
    pub max_bytes_per_part: u64,
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

type PendingRequests = Arc<tokio::sync::Mutex<HashMap<u64, oneshot::Sender<Result<Value, Error>>>>>;

#[derive(Debug)]
enum Transport {
    Child {
        child: Option<Child>,
        stdin: ChildStdin,
    },
    #[cfg(unix)]
    Unix {
        write: tokio::net::unix::OwnedWriteHalf,
    },
}

#[derive(Debug)]
pub struct Client {
    transport: Transport,
    next_id: u64,
    pending: PendingRequests,
    notifications_rx: Option<mpsc::UnboundedReceiver<Notification>>,
    task: tokio::task::JoinHandle<()>,
}

impl Client {
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
        let (notify_tx, notify_rx) = mpsc::unbounded_channel::<Notification>();
        let pending: PendingRequests = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let task = spawn_reader_task(stdout, pending.clone(), notify_tx, options.stdout_log);

        Ok(Self {
            transport: Transport::Child {
                child: Some(child),
                stdin,
            },
            next_id: 1,
            pending,
            notifications_rx: Some(notify_rx),
            task,
        })
    }

    pub async fn connect_unix(path: &Path) -> Result<Self, Error> {
        #[cfg(unix)]
        {
            let stream = tokio::net::UnixStream::connect(path).await?;
            let (read, write) = stream.into_split();
            let (notify_tx, notify_rx) = mpsc::unbounded_channel::<Notification>();
            let pending: PendingRequests = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
            let task = spawn_reader_task(read, pending.clone(), notify_tx, None);
            Ok(Self {
                transport: Transport::Unix { write },
                next_id: 1,
                pending,
                notifications_rx: Some(notify_rx),
                task,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(Error::Protocol(
                "unix socket client is only supported on unix".to_string(),
            ))
        }
    }

    pub fn child_id(&self) -> Option<u32> {
        match &self.transport {
            Transport::Child { child, .. } => child.as_ref().and_then(|child| child.id()),
            #[cfg(unix)]
            Transport::Unix { .. } => None,
        }
    }

    pub fn take_child(&mut self) -> Option<Child> {
        match &mut self.transport {
            Transport::Child { child, .. } => child.take(),
            #[cfg(unix)]
            Transport::Unix { .. } => None,
        }
    }

    pub fn take_notifications(&mut self) -> Option<mpsc::UnboundedReceiver<Notification>> {
        self.notifications_rx.take()
    }

    pub async fn notify(&mut self, method: &str, params: Option<Value>) -> Result<(), Error> {
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

    pub async fn request(&mut self, method: &str, params: Value) -> Result<Value, Error> {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);

        let (tx, rx) = oneshot::channel::<Result<Value, Error>>();
        {
            let mut pending = self.pending.lock().await;
            pending.insert(id, tx);
        }
        let mut guard = PendingRequestGuard::new(self.pending.clone(), id);

        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });

        let mut line = serde_json::to_string(&req)?;
        line.push('\n');
        if let Err(err) = self.write_line(&line).await {
            let mut pending = self.pending.lock().await;
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

    async fn write_line(&mut self, line: &str) -> Result<(), Error> {
        match &mut self.transport {
            Transport::Child { stdin, .. } => {
                stdin.write_all(line.as_bytes()).await?;
                stdin.flush().await?;
            }
            #[cfg(unix)]
            Transport::Unix { write } => {
                write.write_all(line.as_bytes()).await?;
                write.flush().await?;
            }
        }
        Ok(())
    }

    pub async fn wait(&mut self) -> Result<std::process::ExitStatus, Error> {
        self.task.abort();
        match &mut self.transport {
            Transport::Child { child, .. } => match child {
                Some(child) => Ok(child.wait().await?),
                None => Err(Error::Protocol("client has no child process".to_string())),
            },
            #[cfg(unix)]
            Transport::Unix { .. } => {
                Err(Error::Protocol("client has no child process".to_string()))
            }
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct PendingRequestGuard {
    pending: PendingRequests,
    id: u64,
    armed: bool,
}

impl PendingRequestGuard {
    fn new(pending: PendingRequests, id: u64) -> Self {
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
        if let Ok(mut pending) = self.pending.try_lock() {
            pending.remove(&self.id);
        }
    }
}

#[derive(Debug, Clone)]
pub struct Notification {
    pub method: String,
    pub params: Value,
}

#[derive(Debug, serde::Deserialize)]
struct JsonRpcResponse {
    id: Value,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<JsonRpcError>,
}

#[derive(Debug, serde::Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
    #[serde(default)]
    data: Option<Value>,
}

fn spawn_reader_task<R>(
    reader: R,
    pending: PendingRequests,
    notify_tx: mpsc::UnboundedSender<Notification>,
    stdout_log: Option<StdoutLog>,
) -> tokio::task::JoinHandle<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut log_state = match stdout_log {
            Some(opts) => LogState::new(opts).await.ok(),
            None => None,
        };

        let mut lines = tokio::io::BufReader::new(reader).lines();
        loop {
            let next = lines.next_line().await;
            match next {
                Ok(Some(line)) => {
                    if line.trim().is_empty() {
                        continue;
                    }
                    if let Some(state) = &mut log_state {
                        if let Err(err) = state.write_line(&line).await {
                            eprintln!("jsonrpc: stdout log write failed: {err}");
                            log_state = None;
                        }
                    }
                    let value: Value = match serde_json::from_str(&line) {
                        Ok(value) => value,
                        Err(_) => continue,
                    };
                    let Some(method) = value
                        .get("method")
                        .and_then(|v| v.as_str())
                        .map(ToString::to_string)
                    else {
                        if value.get("id").is_none() {
                            continue;
                        }
                        let response: JsonRpcResponse = match serde_json::from_value(value) {
                            Ok(resp) => resp,
                            Err(err) => {
                                drain_pending(
                                    &pending,
                                    Error::Protocol(format!("invalid response: {err}")),
                                )
                                .await;
                                return;
                            }
                        };

                        let Some(id) = response.id.as_u64() else {
                            continue;
                        };

                        let tx = {
                            let mut pending = pending.lock().await;
                            pending.remove(&id)
                        };
                        let Some(tx) = tx else {
                            continue;
                        };

                        if let Some(err) = response.error {
                            let _ = tx.send(Err(Error::Rpc {
                                code: err.code,
                                message: err.message,
                                data: err.data,
                            }));
                            continue;
                        }

                        let Some(result) = response.result else {
                            let _ = tx.send(Err(Error::Protocol("missing result".to_string())));
                            continue;
                        };
                        let _ = tx.send(Ok(result));
                        continue;
                    };

                    let params = value.get("params").cloned().unwrap_or(Value::Null);
                    let _ = notify_tx.send(Notification { method, params });
                }
                Ok(None) => {
                    drain_pending(
                        &pending,
                        Error::Protocol("server closed connection".to_string()),
                    )
                    .await;
                    return;
                }
                Err(err) => {
                    drain_pending(&pending, Error::Io(err)).await;
                    return;
                }
            }
        }
    })
}

async fn drain_pending(pending: &PendingRequests, err: Error) {
    let pending = {
        let mut pending = pending.lock().await;
        std::mem::take(&mut *pending)
    };

    for (_id, tx) in pending {
        let _ = tx.send(Err(Error::Protocol(err.to_string())));
    }
}

struct LogState {
    base_path: PathBuf,
    max_bytes_per_part: u64,
    file: tokio::fs::File,
    current_len: u64,
    next_part: u32,
}

impl LogState {
    async fn new(opts: StdoutLog) -> Result<Self, std::io::Error> {
        let base_path = opts.path;
        let max_bytes_per_part = opts.max_bytes_per_part.max(1);
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

        Ok(Self {
            base_path,
            max_bytes_per_part,
            file,
            current_len,
            next_part,
        })
    }

    async fn write_line(&mut self, line: &str) -> Result<(), std::io::Error> {
        let mut buf = Vec::with_capacity(line.len().saturating_add(1));
        buf.extend_from_slice(line.as_bytes());
        if !line.as_bytes().ends_with(b"\n") {
            buf.push(b'\n');
        }

        let mut offset = 0usize;
        while offset < buf.len() {
            let remaining = self.max_bytes_per_part.saturating_sub(self.current_len);
            if remaining == 0 {
                self.file.flush().await?;
                self.next_part = rotate_log_file(&self.base_path, self.next_part).await?;
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
