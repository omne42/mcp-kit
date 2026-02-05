use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::Value;

use crate::Root;

use super::Manager;

const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

pub enum ServerRequestOutcome {
    Ok(Value),
    Error {
        code: i64,
        message: String,
        data: Option<Value>,
    },
    MethodNotFound,
}

pub struct ServerRequestContext {
    pub server_name: crate::ServerName,
    pub method: String,
    pub params: Option<Value>,
}

pub type ServerRequestHandler =
    Arc<dyn Fn(ServerRequestContext) -> BoxFuture<ServerRequestOutcome> + Send + Sync>;

pub struct ServerNotificationContext {
    pub server_name: crate::ServerName,
    pub method: String,
    pub params: Option<Value>,
}

pub type ServerNotificationHandler =
    Arc<dyn Fn(ServerNotificationContext) -> BoxFuture<()> + Send + Sync>;

impl Manager {
    pub(super) fn attach_client_handlers(
        &self,
        server_name: crate::ServerName,
        client: &mut mcp_jsonrpc::Client,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        use futures_util::FutureExt as _;

        let mut tasks = Vec::new();
        let handler_concurrency = self.server_handler_concurrency.max(1);
        let handler_timeout = self.server_handler_timeout;
        let handler_timeout_counts = self.server_handler_timeout_counts.clone();

        if let Some(mut requests_rx) = client.take_requests() {
            let handler = self.server_request_handler.clone();
            let roots = self.roots.clone();
            let server_name = server_name.clone();
            let handler_timeout_counts = handler_timeout_counts.clone();
            tasks.push(tokio::spawn(async move {
                let mut in_flight = tokio::task::JoinSet::new();

                loop {
                    tokio::select! {
                        Some(req) = requests_rx.recv(), if in_flight.len() < handler_concurrency => {
                            let handler = handler.clone();
                            let roots = roots.clone();
                            let server_name = server_name.clone();
                            let handler_timeout_counts = handler_timeout_counts.clone();
                            in_flight.spawn(async move {
                                const JSONRPC_SERVER_ERROR: i64 = -32000;

                                let method = req.method.clone();
                                let ctx = ServerRequestContext {
                                    server_name: server_name.clone(),
                                    method: method.clone(),
                                    params: req.params.clone(),
                                };

                                let mut outcome = match (handler_timeout, ctx) {
                                    (Some(timeout), ctx) => {
                                        let handler_fut = std::panic::AssertUnwindSafe(handler(ctx))
                                            .catch_unwind();
                                        match tokio::time::timeout(timeout, handler_fut).await {
                                            Ok(joined) => match joined {
                                                Ok(outcome) => outcome,
                                                Err(_) => ServerRequestOutcome::Error {
                                                    code: JSONRPC_SERVER_ERROR,
                                                    message: format!(
                                                        "server request handler panicked: {method}"
                                                    ),
                                                    data: None,
                                                },
                                            },
                                            Err(_) => {
                                                {
                                                    let mut counts = handler_timeout_counts
                                                        .write()
                                                        .unwrap_or_else(|poisoned| {
                                                            poisoned.into_inner()
                                                        });
                                                    *counts.entry(server_name.clone()).or_insert(0) +=
                                                        1;
                                                }
                                                ServerRequestOutcome::Error {
                                                    code: JSONRPC_SERVER_ERROR,
                                                    message: format!(
                                                        "server request handler timed out after {timeout:?}: {method}"
                                                    ),
                                                    data: None,
                                                }
                                            }
                                        }
                                    }
                                    (None, ctx) => {
                                        let handler_fut = std::panic::AssertUnwindSafe(handler(ctx))
                                            .catch_unwind();
                                        match handler_fut.await {
                                            Ok(outcome) => outcome,
                                            Err(_) => ServerRequestOutcome::Error {
                                                code: JSONRPC_SERVER_ERROR,
                                                message: format!(
                                                    "server request handler panicked: {method}"
                                                ),
                                                data: None,
                                            },
                                        }
                                    }
                                };

                                if matches!(outcome, ServerRequestOutcome::MethodNotFound) {
                                    if let Some(result) =
                                        try_handle_built_in_request(&method, roots.as_ref())
                                    {
                                        outcome = ServerRequestOutcome::Ok(result);
                                    }
                                }

                                match outcome {
                                    ServerRequestOutcome::Ok(result) => {
                                        let _ = req.respond_ok(result).await;
                                    }
                                    ServerRequestOutcome::Error { code, message, data } => {
                                        let _ = req.respond_error(code, message, data).await;
                                    }
                                    ServerRequestOutcome::MethodNotFound => {
                                        let _ = req
                                            .respond_error(
                                                JSONRPC_METHOD_NOT_FOUND,
                                                format!("method not found: {}", method.as_str()),
                                                None,
                                            )
                                            .await;
                                    }
                                }
                            });
                        }
                        Some(outcome) = in_flight.join_next(), if !in_flight.is_empty() => {
                            match outcome {
                                Ok(()) => {}
                                Err(err) if err.is_panic() => return,
                                Err(_) => {}
                            }
                        }
                        else => break,
                    }
                }

                while let Some(outcome) = in_flight.join_next().await {
                    match outcome {
                        Ok(()) => {}
                        Err(err) if err.is_panic() => return,
                        Err(_) => {}
                    }
                }
            }));
        }

        if let Some(mut notifications_rx) = client.take_notifications() {
            let handler = self.server_notification_handler.clone();
            let server_name = server_name.clone();
            let handler_timeout_counts = handler_timeout_counts.clone();
            tasks.push(tokio::spawn(async move {
                let mut in_flight = tokio::task::JoinSet::new();

                loop {
                    tokio::select! {
                        Some(note) = notifications_rx.recv(), if in_flight.len() < handler_concurrency => {
                            let handler = handler.clone();
                            let server_name = server_name.clone();
                            let handler_timeout_counts = handler_timeout_counts.clone();
                            in_flight.spawn(async move {
                                let ctx = ServerNotificationContext {
                                    server_name: server_name.clone(),
                                    method: note.method,
                                    params: note.params,
                                };

                                match (handler_timeout, ctx) {
                                    (Some(timeout), ctx) => {
                                        let handler_fut = std::panic::AssertUnwindSafe(handler(ctx))
                                            .catch_unwind();
                                        match tokio::time::timeout(timeout, handler_fut).await {
                                            Ok(Ok(())) | Ok(Err(_)) => {}
                                            Err(_) => {
                                                let mut counts = handler_timeout_counts
                                                    .write()
                                                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                                                *counts.entry(server_name).or_insert(0) += 1;
                                            }
                                        }
                                    }
                                    (None, ctx) => {
                                        let handler_fut = std::panic::AssertUnwindSafe(handler(ctx))
                                            .catch_unwind();
                                        let _ = handler_fut.await;
                                    }
                                };
                            });
                        }
                        Some(outcome) = in_flight.join_next(), if !in_flight.is_empty() => {
                            match outcome {
                                Ok(()) => {}
                                Err(err) if err.is_panic() => return,
                                Err(_) => {}
                            }
                        }
                        else => break,
                    }
                }

                while let Some(outcome) = in_flight.join_next().await {
                    match outcome {
                        Ok(()) => {}
                        Err(err) if err.is_panic() => return,
                        Err(_) => {}
                    }
                }
            }));
        }

        tasks
    }
}

pub(super) fn try_handle_built_in_request(
    method: &str,
    roots: Option<&Arc<Vec<Root>>>,
) -> Option<Value> {
    match method {
        "roots/list" => {
            let roots = roots?;
            Some(serde_json::json!({ "roots": roots.as_ref() }))
        }
        _ => None,
    }
}
