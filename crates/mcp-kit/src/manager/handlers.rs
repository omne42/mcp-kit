use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde_json::Value;

use crate::Root;

use super::Manager;

const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

async fn drive_handler_tasks<T, F, Fut>(
    mut rx: tokio::sync::mpsc::Receiver<T>,
    concurrency: usize,
    mut make_task: F,
) where
    T: Send + 'static,
    F: FnMut(T) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut in_flight = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            Some(item) = rx.recv(), if in_flight.len() < concurrency => {
                in_flight.spawn(make_task(item));
            }
            Some(outcome) = in_flight.join_next(), if !in_flight.is_empty() => {
                if join_outcome_panicked(outcome) {
                    return;
                }
            }
            else => break,
        }
    }

    while let Some(outcome) = in_flight.join_next().await {
        if join_outcome_panicked(outcome) {
            return;
        }
    }
}

fn join_outcome_panicked(outcome: Result<(), tokio::task::JoinError>) -> bool {
    match outcome {
        Ok(()) => false,
        Err(err) if err.is_panic() => true,
        Err(_) => false,
    }
}

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
        let timeout_counter = self.server_handler_timeout_counts.counter_for(&server_name);

        if let Some(requests_rx) = client.take_requests() {
            let handler = self.server_request_handler.clone();
            let roots = self.roots.clone();
            let server_name = server_name.clone();
            let timeout_counter = timeout_counter.clone();
            tasks.push(tokio::spawn(async move {
                drive_handler_tasks(requests_rx, handler_concurrency, move |req| {
                    let handler = handler.clone();
                    let roots = roots.clone();
                    let server_name = server_name.clone();
                    let timeout_counter = timeout_counter.clone();
                    async move {
                        const JSONRPC_SERVER_ERROR: i64 = -32000;

                        let method = req.method.clone();
                        let ctx = ServerRequestContext {
                            server_name: server_name.clone(),
                            method: method.clone(),
                            params: req.params.clone(),
                        };

                        let mut outcome = match (handler_timeout, ctx) {
                            (Some(timeout), ctx) => {
                                let handler_fut =
                                    std::panic::AssertUnwindSafe(handler(ctx)).catch_unwind();
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
                                        timeout_counter.fetch_add(1, Ordering::Relaxed);
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
                                let handler_fut =
                                    std::panic::AssertUnwindSafe(handler(ctx)).catch_unwind();
                                match handler_fut.await {
                                    Ok(outcome) => outcome,
                                    Err(_) => ServerRequestOutcome::Error {
                                        code: JSONRPC_SERVER_ERROR,
                                        message: format!("server request handler panicked: {method}"),
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
                    }
                })
                .await;
            }));
        }

        if let Some(notifications_rx) = client.take_notifications() {
            let handler = self.server_notification_handler.clone();
            let server_name = server_name.clone();
            let timeout_counter = timeout_counter.clone();
            tasks.push(tokio::spawn(async move {
                drive_handler_tasks(notifications_rx, handler_concurrency, move |note| {
                    let handler = handler.clone();
                    let server_name = server_name.clone();
                    let timeout_counter = timeout_counter.clone();
                    async move {
                        let ctx = ServerNotificationContext {
                            server_name: server_name.clone(),
                            method: note.method,
                            params: note.params,
                        };

                        match (handler_timeout, ctx) {
                            (Some(timeout), ctx) => {
                                let handler_fut =
                                    std::panic::AssertUnwindSafe(handler(ctx)).catch_unwind();
                                match tokio::time::timeout(timeout, handler_fut).await {
                                    Ok(Ok(())) | Ok(Err(_)) => {}
                                    Err(_) => {
                                        timeout_counter.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                            (None, ctx) => {
                                let handler_fut =
                                    std::panic::AssertUnwindSafe(handler(ctx)).catch_unwind();
                                let _ = handler_fut.await;
                            }
                        };
                    }
                })
                .await;
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
