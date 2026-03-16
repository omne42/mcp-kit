use std::time::Duration;

use anyhow::Context;
use serde_json::Value;
use tokio::process::Child;

use crate::ServerName;

use super::{
    Connection, Manager, ProtocolVersionCheck, ProtocolVersionMismatch,
    handlers::HandlerAttachSnapshot,
};

enum ProtocolVersionMismatchUpdate {
    None,
    Clear,
    Upsert(ProtocolVersionMismatch),
}

struct InitializeSnapshot {
    client_name: String,
    client_version: String,
    protocol_version: String,
    protocol_version_check: ProtocolVersionCheck,
    capabilities: Value,
    request_timeout: Duration,
}

pub(crate) struct PreparedConnectionInstall {
    server_name: ServerName,
    handler_snapshot: HandlerAttachSnapshot,
    initialize_snapshot: InitializeSnapshot,
}

pub(crate) struct CompletedConnectionInstall {
    server_name: ServerName,
    init_result: Value,
    mismatch_update: ProtocolVersionMismatchUpdate,
    connection: Connection,
}

impl InitializeSnapshot {
    async fn run(
        &self,
        server_name: &ServerName,
        client: &mcp_jsonrpc::Client,
    ) -> anyhow::Result<(Value, ProtocolVersionMismatchUpdate)> {
        if self.protocol_version.trim().is_empty() {
            anyhow::bail!("mcp protocol version must not be empty");
        }
        if !self.capabilities.is_object() {
            anyhow::bail!("mcp client capabilities must be a JSON object");
        }

        let initialize_params = serde_json::json!({
            "protocolVersion": &self.protocol_version,
            "clientInfo": {
                "name": &self.client_name,
                "version": &self.client_version,
            },
            "capabilities": &self.capabilities,
        });

        let timeout = self.request_timeout;
        let outcome =
            tokio::time::timeout(timeout, client.request("initialize", initialize_params)).await;
        let result = outcome
            .with_context(|| {
                format!(
                    "mcp initialize timed out after {timeout:?} (server={})",
                    server_name.as_str()
                )
            })?
            .with_context(|| format!("mcp initialize failed (server={})", server_name.as_str()))?;

        let mismatch_update = match result
            .get("protocolVersion")
            .and_then(serde_json::Value::as_str)
        {
            Some(server_protocol_version) if server_protocol_version != self.protocol_version => {
                match self.protocol_version_check {
                    ProtocolVersionCheck::Strict => {
                        anyhow::bail!(
                            "mcp initialize protocolVersion mismatch (server={}): client={}, server={}",
                            server_name.as_str(),
                            self.protocol_version,
                            server_protocol_version
                        );
                    }
                    ProtocolVersionCheck::Warn => {
                        ProtocolVersionMismatchUpdate::Upsert(ProtocolVersionMismatch {
                            server_name: server_name.clone(),
                            client_protocol_version: self.protocol_version.clone(),
                            server_protocol_version: server_protocol_version.to_string(),
                        })
                    }
                    ProtocolVersionCheck::Ignore => ProtocolVersionMismatchUpdate::None,
                }
            }
            Some(_) | None => ProtocolVersionMismatchUpdate::Clear,
        };

        Manager::notify_raw(
            timeout,
            server_name.as_str(),
            client,
            "notifications/initialized",
            None,
        )
        .await
        .with_context(|| {
            format!(
                "mcp initialized notification failed (server={})",
                server_name.as_str()
            )
        })?;

        Ok((result, mismatch_update))
    }
}

impl PreparedConnectionInstall {
    pub(crate) fn server_name(&self) -> &ServerName {
        &self.server_name
    }

    pub(crate) async fn run(
        self,
        mut client: mcp_jsonrpc::Client,
        child: Option<Child>,
    ) -> anyhow::Result<CompletedConnectionInstall> {
        struct HandlerTasksGuard {
            tasks: Vec<tokio::task::JoinHandle<()>>,
            armed: bool,
        }

        impl HandlerTasksGuard {
            fn new(tasks: Vec<tokio::task::JoinHandle<()>>) -> Self {
                Self { tasks, armed: true }
            }

            fn disarm(mut self) -> Vec<tokio::task::JoinHandle<()>> {
                self.armed = false;
                std::mem::take(&mut self.tasks)
            }
        }

        impl Drop for HandlerTasksGuard {
            fn drop(&mut self) {
                if !self.armed {
                    return;
                }
                for task in self.tasks.drain(..) {
                    task.abort();
                }
            }
        }

        let PreparedConnectionInstall {
            server_name,
            handler_snapshot,
            initialize_snapshot,
        } = self;

        let handler_tasks = Manager::attach_client_handlers_from_snapshot(
            handler_snapshot,
            server_name.clone(),
            &mut client,
        );
        let handler_tasks_guard = HandlerTasksGuard::new(handler_tasks);
        let (init_result, mismatch_update) = initialize_snapshot.run(&server_name, &client).await?;
        let handler_tasks = handler_tasks_guard.disarm();

        Ok(CompletedConnectionInstall {
            server_name,
            init_result,
            mismatch_update,
            connection: Connection {
                child,
                client,
                handler_tasks,
            },
        })
    }
}

pub(crate) struct PreparedDisconnect {
    server_name: String,
    connection: Option<Connection>,
}

impl PreparedDisconnect {
    pub(crate) async fn wait_with_timeout(
        self,
        timeout: Duration,
        on_timeout: mcp_jsonrpc::WaitOnTimeout,
    ) -> anyhow::Result<Option<std::process::ExitStatus>> {
        let Some(conn) = self.connection else {
            return Ok(None);
        };
        conn.wait_with_timeout(timeout, on_timeout)
            .await
            .with_context(|| format!("disconnect mcp server: {}", self.server_name))
    }

    pub(crate) async fn wait_for_jsonrpc_error_cleanup(self) {
        const DISCONNECT_TIMEOUT: Duration = Duration::from_millis(200);
        const DISCONNECT_KILL_TIMEOUT: Duration = Duration::from_millis(200);

        let Some(conn) = self.connection else {
            return;
        };

        let _ = /* pre-commit: allow-let-underscore */ conn
            .wait_with_timeout(
                DISCONNECT_TIMEOUT,
                mcp_jsonrpc::WaitOnTimeout::Kill {
                    kill_timeout: DISCONNECT_KILL_TIMEOUT,
                },
            )
            .await; // pre-commit: allow-let-underscore
    }
}

fn reap_stale_child_best_effort(mut child: Child) {
    const REAP_TIMEOUT: Duration = Duration::from_millis(200);

    if child.try_wait().ok().flatten().is_some() {
        return;
    }

    let _ = child.start_kill(); // pre-commit: allow-let-underscore
    if child.try_wait().ok().flatten().is_some() {
        return;
    }

    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        drop(handle.spawn(async move {
            let _ = tokio::time::timeout(REAP_TIMEOUT, child.wait()).await; // pre-commit: allow-let-underscore
        }));
    }
}

impl Manager {
    pub(crate) fn prepare_connection_install(
        &self,
        server_name: &ServerName,
    ) -> PreparedConnectionInstall {
        PreparedConnectionInstall {
            server_name: server_name.clone(),
            handler_snapshot: self.prepare_handler_attach(server_name),
            initialize_snapshot: InitializeSnapshot {
                client_name: self.client_name.clone(),
                client_version: self.client_version.clone(),
                protocol_version: self.protocol_version.clone(),
                protocol_version_check: self.protocol_version_check,
                capabilities: self.capabilities.clone(),
                request_timeout: self.request_timeout,
            },
        }
    }

    pub(crate) fn cleanup_failed_connection_install(&mut self, server_name: &ServerName) {
        self.clear_connection_side_state(server_name.as_str(), false);
    }

    pub(crate) fn commit_connection_install(&mut self, completed: CompletedConnectionInstall) {
        match completed.mismatch_update {
            ProtocolVersionMismatchUpdate::None => {}
            ProtocolVersionMismatchUpdate::Clear => {
                self.remove_protocol_version_mismatch(completed.server_name.as_str());
            }
            ProtocolVersionMismatchUpdate::Upsert(mismatch) => {
                if let Some(existing) = self
                    .protocol_version_mismatches
                    .iter_mut()
                    .find(|existing| existing.server_name == mismatch.server_name)
                {
                    *existing = mismatch;
                } else {
                    self.protocol_version_mismatches.push(mismatch);
                }
            }
        }

        self.init_results
            .insert(completed.server_name.clone(), completed.init_result);
        self.conns
            .insert(completed.server_name, completed.connection);
    }

    pub(crate) fn prepare_disconnect_for_wait(&mut self, server_name: &str) -> PreparedDisconnect {
        let server_name = super::normalize_server_name_lookup(server_name).to_string();
        let connection = self.remove_cached_connection(&server_name);
        self.clear_connection_side_state(&server_name, connection.is_some());
        PreparedDisconnect {
            server_name,
            connection,
        }
    }

    pub(super) fn clear_connection_side_state(
        &mut self,
        server_name: &str,
        clear_init_result: bool,
    ) {
        if clear_init_result {
            self.init_results.remove(server_name);
        }
        self.server_handler_timeout_counts.remove(server_name);
        self.remove_protocol_version_mismatch(server_name);
    }

    pub(super) fn remove_cached_connection(&mut self, server_name: &str) -> Option<Connection> {
        self.conns.remove(server_name)
    }

    pub(super) fn reap_connection_child_best_effort(conn: &mut Connection) {
        if let Some(child) = conn.child.take() {
            reap_stale_child_best_effort(child);
        }
    }

    pub(super) fn is_connected_and_alive(&mut self, server_name: &str) -> bool {
        let Some(exited) = self.connection_exited(server_name) else {
            return false;
        };
        if exited {
            if let Some(mut conn) = self.remove_cached_connection(server_name) {
                Self::reap_connection_child_best_effort(&mut conn);
            }
            self.clear_connection_side_state(server_name, true);
            return false;
        }
        true
    }

    pub(super) fn connection_exited(&mut self, server_name: &str) -> Option<bool> {
        let conn = self.conns.get_mut(server_name)?;
        let exited = match &mut conn.child {
            Some(child) => {
                if child.try_wait().ok().flatten().is_some() {
                    true
                } else {
                    conn.client.is_closed()
                }
            }
            None => conn.client.is_closed(),
        };

        if exited {
            return Some(true);
        }

        if conn
            .handler_tasks
            .iter()
            .any(tokio::task::JoinHandle::is_finished)
        {
            return Some(true);
        }

        Some(false)
    }

    pub(crate) async fn install_connection_parsed(
        &mut self,
        server_name: ServerName,
        client: mcp_jsonrpc::Client,
        child: Option<Child>,
    ) -> anyhow::Result<()> {
        let install = self.prepare_connection_install(&server_name);
        match install.run(client, child).await {
            Ok(completed) => {
                self.commit_connection_install(completed);
                Ok(())
            }
            Err(err) => {
                self.cleanup_failed_connection_install(&server_name);
                Err(err)
            }
        }
    }

    pub(crate) async fn disconnect_after_jsonrpc_error(&mut self, server_name: &str) {
        self.prepare_disconnect_for_wait(server_name)
            .wait_for_jsonrpc_error_cleanup()
            .await;
    }
}
