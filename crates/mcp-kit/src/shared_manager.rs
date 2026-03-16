use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use anyhow::Context;
use serde_json::Value;
use tokio::sync::{Mutex, MutexGuard};

use crate::{Config, Manager, McpNotification, McpRequest, ProtocolVersionMismatch, ServerName};

const REENTRANT_HANDLER_ERROR: &str = "SharedManager async operations cannot be called reentrantly from the wrapped manager's server handlers while another operation is in flight";

/// Cloneable wrapper around `Manager` for serialized shared async use.
///
/// This wrapper serializes manager state access through a single async mutex. Connected
/// request/notify operations release that lock before awaiting JSON-RPC I/O, while lifecycle and
/// inspection operations still execute under the shared lock. It is intended for callers that want
/// shared ownership ergonomics without introducing a second runtime or actor layer.
///
/// This is not an actor or fully concurrent manager:
/// - lifecycle-changing operations still serialize on the shared manager lock
/// - connected request/notify operations can overlap once they have borrowed a client handle
/// - operations that still need the shared lock reject reentrant calls from `Manager` server
///   request/notification handlers attached to the wrapped manager instead of waiting forever
/// - lock-based inspection helpers still borrow the shared mutex directly and must not be called
///   reentrantly from those handlers
#[derive(Clone)]
pub struct SharedManager {
    inner: Arc<Mutex<Manager>>,
    connect_gates: Arc<StdMutex<HashMap<String, Arc<Mutex<()>>>>>,
    manager_id: u64,
}

impl Manager {
    /// Converts this manager into a cloneable single-flight wrapper.
    pub fn into_shared(self) -> SharedManager {
        SharedManager::new(self)
    }
}

impl SharedManager {
    pub fn new(manager: Manager) -> Self {
        let manager_id = manager.instance_id();
        Self {
            inner: Arc::new(Mutex::new(manager)),
            connect_gates: Arc::new(StdMutex::new(HashMap::new())),
            manager_id,
        }
    }

    pub fn try_unwrap(self) -> Result<Manager, Self> {
        match Arc::try_unwrap(self.inner) {
            Ok(inner) => Ok(inner.into_inner()),
            Err(inner) => Err(Self {
                inner,
                connect_gates: self.connect_gates,
                manager_id: self.manager_id,
            }),
        }
    }

    /// Inspect manager state under the shared lock without exposing borrowed data directly.
    pub async fn inspect<R>(&self, f: impl FnOnce(&Manager) -> R) -> R {
        let manager = self.inner.lock().await;
        f(&manager)
    }

    fn is_reentrant_handler_call(&self) -> bool {
        crate::manager::is_in_manager_handler_scope(self.manager_id)
    }

    fn connect_gate_for(&self, server_name: &str) -> Arc<Mutex<()>> {
        let key = server_name.trim().to_string();
        let mut gates = self
            .connect_gates
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        gates
            .entry(key)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    async fn lock_for_async_op(
        &self,
        operation: &'static str,
    ) -> anyhow::Result<MutexGuard<'_, Manager>> {
        if self.is_reentrant_handler_call() {
            return self
                .inner
                .try_lock()
                .map_err(|_| anyhow::anyhow!("{REENTRANT_HANDLER_ERROR}: {operation}"));
        }
        Ok(self.inner.lock().await)
    }

    async fn try_prepare_connected_client(
        &self,
        operation: &'static str,
        server_name: &str,
    ) -> anyhow::Result<Option<crate::manager::PreparedConnectedClient>> {
        self.lock_for_async_op(operation)
            .await?
            .try_prepare_connected_client(server_name)
    }

    async fn ensure_connected(
        &self,
        operation: &'static str,
        config: &Config,
        server_name: &str,
        cwd: &Path,
    ) -> anyhow::Result<()> {
        let gate = self.connect_gate_for(server_name);
        let _gate = if self.is_reentrant_handler_call() {
            gate.try_lock()
                .map_err(|_| anyhow::anyhow!("{REENTRANT_HANDLER_ERROR}: {operation}"))?
        } else {
            gate.lock().await
        };

        if self
            .try_prepare_connected_client(operation, server_name)
            .await?
            .is_some()
        {
            return Ok(());
        }

        let prepared = {
            self.lock_for_async_op(operation)
                .await?
                .prepare_transport_connect(config, server_name, cwd)?
        };
        let Some(prepared) = prepared else {
            return Ok(());
        };

        let (client, child) = crate::manager::connect_transport(
            &prepared.ctx,
            &prepared.server_name,
            &prepared.server_cfg,
            &prepared.cwd,
        )
        .await?;

        let install = self
            .lock_for_async_op(operation)
            .await?
            .prepare_connection_install(&prepared.server_name_key);
        let install_server_name = install.server_name().clone();

        match install.run(client, child).await {
            Ok(completed) => {
                self.lock_for_async_op(operation)
                    .await?
                    .commit_connection_install(completed);
                Ok(())
            }
            Err(err) => {
                self.lock_for_async_op(operation)
                    .await?
                    .cleanup_failed_connection_install(&install_server_name);
                Err(err)
            }
        }
    }

    pub async fn is_connected(&self, server_name: &str) -> bool {
        self.inner.lock().await.is_connected(server_name)
    }

    pub async fn connected_server_names(&self) -> Vec<ServerName> {
        self.inner.lock().await.connected_server_names()
    }

    pub async fn disconnect(&self, server_name: &str) -> bool {
        self.inner.lock().await.disconnect(server_name)
    }

    pub async fn disconnect_and_wait(
        &self,
        server_name: &str,
        timeout: Duration,
        on_timeout: mcp_jsonrpc::WaitOnTimeout,
    ) -> anyhow::Result<Option<std::process::ExitStatus>> {
        let disconnect = self
            .lock_for_async_op("disconnect_and_wait")
            .await?
            .prepare_disconnect_for_wait(server_name);
        disconnect.wait_with_timeout(timeout, on_timeout).await
    }

    pub async fn request(
        &self,
        config: &Config,
        server_name: &str,
        method: &str,
        params: Option<Value>,
        cwd: &Path,
    ) -> anyhow::Result<Value> {
        if let Some(prepared) = self
            .try_prepare_connected_client("request", server_name)
            .await?
        {
            let result = Manager::request_raw_handle(
                prepared.timeout,
                &prepared.server_name,
                &prepared.client,
                method,
                params,
            )
            .await;
            if let Err(err) = &result {
                if crate::manager::should_disconnect_after_jsonrpc_error(err) {
                    let disconnect = self
                        .lock_for_async_op("request_cleanup")
                        .await?
                        .prepare_disconnect_for_wait(&prepared.server_name);
                    disconnect.wait_for_jsonrpc_error_cleanup().await;
                }
            }
            return result;
        }

        self.ensure_connected("request_connect", config, server_name, cwd)
            .await?;
        self.request_connected(server_name, method, params).await
    }

    pub async fn request_connected(
        &self,
        server_name: &str,
        method: &str,
        params: Option<Value>,
    ) -> anyhow::Result<Value> {
        let Some(prepared) = self
            .try_prepare_connected_client("request_connected", server_name)
            .await?
        else {
            anyhow::bail!("mcp server not connected: {}", server_name.trim());
        };

        let result = Manager::request_raw_handle(
            prepared.timeout,
            &prepared.server_name,
            &prepared.client,
            method,
            params,
        )
        .await;

        if let Err(err) = &result {
            if crate::manager::should_disconnect_after_jsonrpc_error(err) {
                let disconnect = self
                    .lock_for_async_op("request_connected_cleanup")
                    .await?
                    .prepare_disconnect_for_wait(&prepared.server_name);
                disconnect.wait_for_jsonrpc_error_cleanup().await;
            }
        }

        result
    }

    pub async fn request_typed<R: McpRequest>(
        &self,
        config: &Config,
        server_name: &str,
        params: Option<R::Params>,
        cwd: &Path,
    ) -> anyhow::Result<R::Result> {
        let params = match params {
            Some(params) => Some(serde_json::to_value(params).with_context(|| {
                format!("serialize MCP params: {} (server={server_name})", R::METHOD)
            })?),
            None => None,
        };
        let result = self
            .request(config, server_name, R::METHOD, params, cwd)
            .await?;
        serde_json::from_value(result).with_context(|| {
            format!(
                "deserialize MCP result: {} (server={server_name})",
                R::METHOD
            )
        })
    }

    pub async fn request_typed_connected<R: McpRequest>(
        &self,
        server_name: &str,
        params: Option<R::Params>,
    ) -> anyhow::Result<R::Result> {
        let params = match params {
            Some(params) => Some(serde_json::to_value(params).with_context(|| {
                format!("serialize MCP params: {} (server={server_name})", R::METHOD)
            })?),
            None => None,
        };
        let result = self
            .request_connected(server_name, R::METHOD, params)
            .await?;
        serde_json::from_value(result).with_context(|| {
            format!(
                "deserialize MCP result: {} (server={server_name})",
                R::METHOD
            )
        })
    }

    pub async fn notify(
        &self,
        config: &Config,
        server_name: &str,
        method: &str,
        params: Option<Value>,
        cwd: &Path,
    ) -> anyhow::Result<()> {
        if let Some(prepared) = self
            .try_prepare_connected_client("notify", server_name)
            .await?
        {
            let result = Manager::notify_raw_handle(
                prepared.timeout,
                &prepared.server_name,
                &prepared.client,
                method,
                params,
            )
            .await;
            if let Err(err) = &result {
                if crate::manager::should_disconnect_after_jsonrpc_error(err)
                    || crate::manager::contains_wait_timeout(err)
                {
                    let disconnect = self
                        .lock_for_async_op("notify_cleanup")
                        .await?
                        .prepare_disconnect_for_wait(&prepared.server_name);
                    disconnect.wait_for_jsonrpc_error_cleanup().await;
                }
            }
            return result;
        }

        self.ensure_connected("notify_connect", config, server_name, cwd)
            .await?;
        self.notify_connected(server_name, method, params).await
    }

    pub async fn notify_connected(
        &self,
        server_name: &str,
        method: &str,
        params: Option<Value>,
    ) -> anyhow::Result<()> {
        let Some(prepared) = self
            .try_prepare_connected_client("notify_connected", server_name)
            .await?
        else {
            anyhow::bail!("mcp server not connected: {}", server_name.trim());
        };

        let result = Manager::notify_raw_handle(
            prepared.timeout,
            &prepared.server_name,
            &prepared.client,
            method,
            params,
        )
        .await;

        if let Err(err) = &result {
            if crate::manager::should_disconnect_after_jsonrpc_error(err)
                || crate::manager::contains_wait_timeout(err)
            {
                let disconnect = self
                    .lock_for_async_op("notify_connected_cleanup")
                    .await?
                    .prepare_disconnect_for_wait(&prepared.server_name);
                disconnect.wait_for_jsonrpc_error_cleanup().await;
            }
        }

        result
    }

    pub async fn notify_typed<N: McpNotification>(
        &self,
        config: &Config,
        server_name: &str,
        params: Option<N::Params>,
        cwd: &Path,
    ) -> anyhow::Result<()> {
        let params = match params {
            Some(params) => Some(serde_json::to_value(params).with_context(|| {
                format!("serialize MCP params: {} (server={server_name})", N::METHOD)
            })?),
            None => None,
        };
        self.notify(config, server_name, N::METHOD, params, cwd)
            .await
    }

    pub async fn notify_typed_connected<N: McpNotification>(
        &self,
        server_name: &str,
        params: Option<N::Params>,
    ) -> anyhow::Result<()> {
        let params = match params {
            Some(params) => Some(serde_json::to_value(params).with_context(|| {
                format!("serialize MCP params: {} (server={server_name})", N::METHOD)
            })?),
            None => None,
        };
        self.notify_connected(server_name, N::METHOD, params).await
    }

    pub async fn server_handler_timeout_count(&self, server_name: &str) -> u64 {
        self.inner
            .lock()
            .await
            .server_handler_timeout_count(server_name)
    }

    /// Returns a snapshot of timeout counts for all servers without draining shared state.
    pub async fn server_handler_timeout_counts(&self) -> HashMap<ServerName, u64> {
        self.inner.lock().await.server_handler_timeout_counts()
    }

    /// Takes timeout counts for all servers and resets the shared counters for every clone.
    pub async fn take_server_handler_timeout_counts(&self) -> HashMap<ServerName, u64> {
        self.inner.lock().await.take_server_handler_timeout_counts()
    }

    /// Returns recorded protocol-version mismatches without draining shared state.
    pub async fn protocol_version_mismatches(&self) -> Vec<ProtocolVersionMismatch> {
        self.inner
            .lock()
            .await
            .protocol_version_mismatches()
            .to_vec()
    }

    /// Takes recorded protocol-version mismatches and clears them for every clone.
    pub async fn take_protocol_version_mismatches(&self) -> Vec<ProtocolVersionMismatch> {
        self.inner.lock().await.take_protocol_version_mismatches()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    #[cfg(unix)]
    use std::path::Path;
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::Duration;

    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    use crate::{
        ClientConfig, Config, Manager, McpRequest, ProtocolVersionCheck, ServerConfig, ServerName,
        ServerRequestHandler, ServerRequestOutcome, SharedManager, TrustMode,
    };

    struct NestedRequest;

    #[derive(Serialize)]
    struct NestedParams {
        phase: &'static str,
    }

    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
    struct NestedResult {
        nested: bool,
    }

    impl McpRequest for NestedRequest {
        const METHOD: &'static str = "nested";
        type Params = NestedParams;
        type Result = NestedResult;
    }

    #[tokio::test]
    async fn shared_manager_clones_share_cache() {
        let (client_stream, server_stream) = tokio::io::duplex(1024);
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (server_read, mut server_write) = tokio::io::split(server_stream);

        let server_task = tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(server_read).lines();

            let init_line = lines.next_line().await.unwrap().unwrap();
            let init_value: Value = serde_json::from_str(&init_line).unwrap();
            let init_id = init_value["id"].clone();

            let init_response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": init_id,
                "result": { "serverInfo": { "name": "demo" } },
            });
            let mut init_response_line = serde_json::to_string(&init_response).unwrap();
            init_response_line.push('\n');
            server_write
                .write_all(init_response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let initialized_line = lines.next_line().await.unwrap().unwrap();
            let initialized_value: Value = serde_json::from_str(&initialized_line).unwrap();
            assert_eq!(initialized_value["method"], "notifications/initialized");

            let request_line = lines.next_line().await.unwrap().unwrap();
            let request_value: Value = serde_json::from_str(&request_line).unwrap();
            assert_eq!(request_value["method"], "ping");
            let request_id = request_value["id"].clone();

            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": { "ok": true },
            });
            let mut response_line = serde_json::to_string(&response).unwrap();
            response_line.push('\n');
            server_write
                .write_all(response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();
        });

        let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
            .with_trust_mode(TrustMode::Trusted);
        manager
            .connect_io("srv", client_read, client_write)
            .await
            .unwrap();

        let shared = manager.into_shared();
        let clone = shared.clone();
        assert_eq!(shared.connected_server_names().await.len(), 1);
        let result = clone.request_connected("srv", "ping", None).await.unwrap();
        assert_eq!(result, serde_json::json!({ "ok": true }));

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn shared_manager_inspect_reads_initialize_result() {
        let (client_stream, server_stream) = tokio::io::duplex(1024);
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (server_read, mut server_write) = tokio::io::split(server_stream);

        let server_task = tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(server_read).lines();

            let init_line = lines.next_line().await.unwrap().unwrap();
            let init_value: Value = serde_json::from_str(&init_line).unwrap();
            let init_id = init_value["id"].clone();

            let init_response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": init_id,
                "result": { "serverInfo": { "name": "demo" } },
            });
            let mut init_response_line = serde_json::to_string(&init_response).unwrap();
            init_response_line.push('\n');
            server_write
                .write_all(init_response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let initialized_line = lines.next_line().await.unwrap().unwrap();
            let initialized_value: Value = serde_json::from_str(&initialized_line).unwrap();
            assert_eq!(initialized_value["method"], "notifications/initialized");
        });

        let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
            .with_trust_mode(TrustMode::Trusted);
        manager
            .connect_io("srv", client_read, client_write)
            .await
            .unwrap();

        let shared = manager.into_shared();
        let server_name = shared
            .inspect(|manager| {
                manager
                    .initialize_result("srv")
                    .and_then(|value| value["serverInfo"]["name"].as_str())
                    .map(str::to_string)
            })
            .await;
        assert_eq!(server_name.as_deref(), Some("demo"));

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn shared_manager_disconnect_affects_all_clones() {
        let (client_stream, server_stream) = tokio::io::duplex(1024);
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (server_read, mut server_write) = tokio::io::split(server_stream);

        let server_task = tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(server_read).lines();

            let init_line = lines.next_line().await.unwrap().unwrap();
            let init_value: Value = serde_json::from_str(&init_line).unwrap();
            let init_id = init_value["id"].clone();

            let init_response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": init_id,
                "result": {},
            });
            let mut init_response_line = serde_json::to_string(&init_response).unwrap();
            init_response_line.push('\n');
            server_write
                .write_all(init_response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let initialized_line = lines.next_line().await.unwrap().unwrap();
            let initialized_value: Value = serde_json::from_str(&initialized_line).unwrap();
            assert_eq!(initialized_value["method"], "notifications/initialized");

            let eof = lines.next_line().await.unwrap();
            assert!(eof.is_none(), "expected EOF after disconnect");
        });

        let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
            .with_trust_mode(TrustMode::Trusted);
        manager
            .connect_io("srv", client_read, client_write)
            .await
            .unwrap();
        let shared = manager.into_shared();
        let clone = shared.clone();

        assert!(shared.disconnect("srv").await);
        assert!(!clone.is_connected("srv").await);

        server_task.abort();
    }

    #[tokio::test]
    async fn shared_manager_disconnect_and_wait_releases_lock_while_waiting() {
        let (client_stream, server_stream) = tokio::io::duplex(1024);
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (server_read, mut server_write) = tokio::io::split(server_stream);

        let server_task = tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(server_read).lines();

            let init_line = lines.next_line().await.unwrap().unwrap();
            let init_value: Value = serde_json::from_str(&init_line).unwrap();
            let init_id = init_value["id"].clone();

            let init_response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": init_id,
                "result": { "protocolVersion": crate::MCP_PROTOCOL_VERSION },
            });
            let mut init_response_line = serde_json::to_string(&init_response).unwrap();
            init_response_line.push('\n');
            server_write
                .write_all(init_response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let initialized_line = lines.next_line().await.unwrap().unwrap();
            let initialized_value: Value = serde_json::from_str(&initialized_line).unwrap();
            assert_eq!(initialized_value["method"], "notifications/initialized");

            let notify = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "demo/notify",
                "params": {},
            });
            let mut notify_line = serde_json::to_string(&notify).unwrap();
            notify_line.push('\n');
            server_write
                .write_all(notify_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let eof = lines.next_line().await.unwrap();
            assert!(eof.is_none(), "expected EOF after disconnect");
        });

        let handler_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let started_for_handler = Arc::clone(&handler_started);
        let handler_dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dropped_for_handler = Arc::clone(&handler_dropped);

        let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
            .with_trust_mode(TrustMode::Trusted)
            .with_server_notification_handler(Arc::new(move |_ctx| {
                let started_for_handler = Arc::clone(&started_for_handler);
                let dropped_for_handler = Arc::clone(&dropped_for_handler);
                Box::pin(async move {
                    struct OnDrop(std::sync::Arc<std::sync::atomic::AtomicBool>);

                    impl Drop for OnDrop {
                        fn drop(&mut self) {
                            self.0.store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                    }

                    let _on_drop = OnDrop(dropped_for_handler);
                    started_for_handler.store(true, std::sync::atomic::Ordering::Relaxed);
                    std::future::pending::<()>().await;
                })
            }));
        manager
            .connect_io("srv", client_read, client_write)
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(1), async {
            while !handler_started.load(std::sync::atomic::Ordering::Relaxed) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let shared = manager.into_shared();
        let clone = shared.clone();
        let disconnect_task = tokio::spawn(async move {
            shared
                .disconnect_and_wait(
                    "srv",
                    Duration::from_millis(100),
                    mcp_jsonrpc::WaitOnTimeout::ReturnError,
                )
                .await
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let names = tokio::time::timeout(Duration::from_millis(20), clone.connected_server_names())
            .await
            .expect("connected_server_names should not be blocked by disconnect_and_wait");
        assert!(
            names.is_empty(),
            "disconnect should remove the shared connection early"
        );

        let err = disconnect_task.await.unwrap().unwrap_err();
        let err_chain = format!("{err:#}");
        assert!(
            err_chain.contains("wait timed out after"),
            "unexpected error: {err_chain}"
        );

        tokio::time::timeout(Duration::from_secs(1), async {
            while !handler_dropped.load(std::sync::atomic::Ordering::Relaxed) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        server_task.await.unwrap();
    }

    #[test]
    fn shared_manager_try_unwrap_requires_unique_owner() {
        let shared = Manager::new("test-client", "0.0.0", Duration::from_secs(1)).into_shared();
        let clone = shared.clone();
        assert!(shared.clone().try_unwrap().is_err());
        drop(clone);
        let inner = match shared.try_unwrap() {
            Ok(inner) => inner,
            Err(_) => panic!("unique owner should unwrap"),
        };
        assert_eq!(inner.trust_mode(), TrustMode::Untrusted);
    }

    #[tokio::test]
    async fn shared_manager_telemetry_drain_is_shared() {
        let (client_stream, server_stream) = tokio::io::duplex(1024);
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (server_read, mut server_write) = tokio::io::split(server_stream);

        let server_task = tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(server_read).lines();

            let init_line = lines.next_line().await.unwrap().unwrap();
            let init_value: Value = serde_json::from_str(&init_line).unwrap();
            let init_id = init_value["id"].clone();

            let init_response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": init_id,
                "result": { "protocolVersion": "1900-01-01" },
            });
            let mut init_response_line = serde_json::to_string(&init_response).unwrap();
            init_response_line.push('\n');
            server_write
                .write_all(init_response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let initialized_line = lines.next_line().await.unwrap().unwrap();
            let initialized_value: Value = serde_json::from_str(&initialized_line).unwrap();
            assert_eq!(initialized_value["method"], "notifications/initialized");
        });

        let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(1))
            .with_trust_mode(TrustMode::Trusted)
            .with_protocol_version_check(ProtocolVersionCheck::Warn);
        manager
            .connect_io("srv", client_read, client_write)
            .await
            .unwrap();

        let shared = manager.into_shared();
        let clone = shared.clone();

        let snapshot = shared.protocol_version_mismatches().await;
        assert_eq!(snapshot.len(), 1);
        let still_present = clone
            .inspect(|manager| manager.protocol_version_mismatches().len())
            .await;
        assert_eq!(still_present, 1);

        let mismatches = shared.take_protocol_version_mismatches().await;
        assert_eq!(mismatches.len(), 1);
        let after = clone
            .inspect(|manager| manager.protocol_version_mismatches().len())
            .await;
        assert_eq!(after, 0);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn shared_manager_reentrant_handler_request_connected_succeeds() {
        let (client_stream, server_stream) = tokio::io::duplex(1024);
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (server_read, mut server_write) = tokio::io::split(server_stream);

        let server_task = tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(server_read).lines();

            let init_line = lines.next_line().await.unwrap().unwrap();
            let init_value: Value = serde_json::from_str(&init_line).unwrap();
            let init_id = init_value["id"].clone();

            let init_response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": init_id,
                "result": { "serverInfo": { "name": "demo" } },
            });
            let mut init_response_line = serde_json::to_string(&init_response).unwrap();
            init_response_line.push('\n');
            server_write
                .write_all(init_response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let initialized_line = lines.next_line().await.unwrap().unwrap();
            let initialized_value: Value = serde_json::from_str(&initialized_line).unwrap();
            assert_eq!(initialized_value["method"], "notifications/initialized");

            let request_line = lines.next_line().await.unwrap().unwrap();
            let request_value: Value = serde_json::from_str(&request_line).unwrap();
            assert_eq!(request_value["method"], "ping");
            let request_id = request_value["id"].clone();

            let callback_request = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 99,
                "method": "callback",
                "params": { "phase": "reentrant" },
            });
            let mut callback_line = serde_json::to_string(&callback_request).unwrap();
            callback_line.push('\n');
            server_write
                .write_all(callback_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let nested_request_line = lines.next_line().await.unwrap().unwrap();
            let nested_request: Value = serde_json::from_str(&nested_request_line).unwrap();
            assert_eq!(nested_request["method"], "nested");
            let nested_request_id = nested_request["id"].clone();

            let nested_response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": nested_request_id,
                "result": { "nested": true },
            });
            let mut nested_response_line = serde_json::to_string(&nested_response).unwrap();
            nested_response_line.push('\n');
            server_write
                .write_all(nested_response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let callback_response_line = lines.next_line().await.unwrap().unwrap();
            let callback_response: Value = serde_json::from_str(&callback_response_line).unwrap();
            assert_eq!(callback_response["id"], 99);
            assert_eq!(
                callback_response["result"],
                serde_json::json!({ "nested": true })
            );

            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": { "ok": true },
            });
            let mut response_line = serde_json::to_string(&response).unwrap();
            response_line.push('\n');
            server_write
                .write_all(response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();
        });

        let shared_slot: Arc<StdMutex<Option<SharedManager>>> = Arc::new(StdMutex::new(None));
        let handler_slot = shared_slot.clone();
        let handler: ServerRequestHandler = Arc::new(move |_| {
            let shared = handler_slot
                .lock()
                .unwrap()
                .as_ref()
                .expect("shared manager installed")
                .clone();
            Box::pin(async move {
                let nested = shared
                    .request_connected("srv", "nested", None::<Value>)
                    .await
                    .expect("connected shared request should release manager lock during I/O");
                ServerRequestOutcome::Ok(nested)
            })
        });

        let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
            .with_trust_mode(TrustMode::Trusted)
            .with_server_request_handler(handler);
        manager
            .connect_io("srv", client_read, client_write)
            .await
            .unwrap();

        let shared = manager.into_shared();
        *shared_slot.lock().unwrap() = Some(shared.clone());

        let result = shared.request_connected("srv", "ping", None).await.unwrap();
        assert_eq!(result, serde_json::json!({ "ok": true }));

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn shared_manager_reentrant_handler_request_typed_connected_succeeds() {
        let (client_stream, server_stream) = tokio::io::duplex(1024);
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (server_read, mut server_write) = tokio::io::split(server_stream);

        let server_task = tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(server_read).lines();

            let init_line = lines.next_line().await.unwrap().unwrap();
            let init_value: Value = serde_json::from_str(&init_line).unwrap();
            let init_id = init_value["id"].clone();

            let init_response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": init_id,
                "result": { "serverInfo": { "name": "demo" } },
            });
            let mut init_response_line = serde_json::to_string(&init_response).unwrap();
            init_response_line.push('\n');
            server_write
                .write_all(init_response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let initialized_line = lines.next_line().await.unwrap().unwrap();
            let initialized_value: Value = serde_json::from_str(&initialized_line).unwrap();
            assert_eq!(initialized_value["method"], "notifications/initialized");

            let request_line = lines.next_line().await.unwrap().unwrap();
            let request_value: Value = serde_json::from_str(&request_line).unwrap();
            assert_eq!(request_value["method"], "ping");
            let request_id = request_value["id"].clone();

            let callback_request = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 99,
                "method": "callback",
                "params": { "phase": "typed" },
            });
            let mut callback_line = serde_json::to_string(&callback_request).unwrap();
            callback_line.push('\n');
            server_write
                .write_all(callback_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let nested_request_line = lines.next_line().await.unwrap().unwrap();
            let nested_request: Value = serde_json::from_str(&nested_request_line).unwrap();
            assert_eq!(nested_request["method"], "nested");
            assert_eq!(
                nested_request["params"],
                serde_json::json!({ "phase": "typed" })
            );
            let nested_request_id = nested_request["id"].clone();

            let nested_response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": nested_request_id,
                "result": { "nested": true },
            });
            let mut nested_response_line = serde_json::to_string(&nested_response).unwrap();
            nested_response_line.push('\n');
            server_write
                .write_all(nested_response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let callback_response_line = lines.next_line().await.unwrap().unwrap();
            let callback_response: Value = serde_json::from_str(&callback_response_line).unwrap();
            assert_eq!(callback_response["id"], 99);
            assert_eq!(
                callback_response["result"],
                serde_json::json!({ "nested": true })
            );

            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": { "ok": true },
            });
            let mut response_line = serde_json::to_string(&response).unwrap();
            response_line.push('\n');
            server_write
                .write_all(response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();
        });

        let shared_slot: Arc<StdMutex<Option<SharedManager>>> = Arc::new(StdMutex::new(None));
        let handler_slot = shared_slot.clone();
        let handler: ServerRequestHandler = Arc::new(move |_| {
            let shared = handler_slot
                .lock()
                .unwrap()
                .as_ref()
                .expect("shared manager installed")
                .clone();
            Box::pin(async move {
                let nested = shared
                    .request_typed_connected::<NestedRequest>(
                        "srv",
                        Some(NestedParams { phase: "typed" }),
                    )
                    .await
                    .expect(
                        "typed connected shared request should release manager lock during I/O",
                    );
                ServerRequestOutcome::Ok(serde_json::to_value(nested).unwrap())
            })
        });

        let mut manager = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
            .with_trust_mode(TrustMode::Trusted)
            .with_server_request_handler(handler);
        manager
            .connect_io("srv", client_read, client_write)
            .await
            .unwrap();

        let shared = manager.into_shared();
        *shared_slot.lock().unwrap() = Some(shared.clone());

        let result = shared.request_connected("srv", "ping", None).await.unwrap();
        assert_eq!(result, serde_json::json!({ "ok": true }));

        server_task.await.unwrap();
    }

    #[cfg(unix)]
    fn unique_socket_path(label: &str) -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};

        std::env::temp_dir().join(format!(
            "mcp-kit-shared-manager-{label}-{}-{}.sock",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shared_manager_cold_start_initialize_does_not_block_other_servers() {
        use tokio::net::UnixListener;
        use tokio::sync::oneshot;

        let slow_socket_path = unique_socket_path("slow");
        let fast_socket_path = unique_socket_path("fast");
        let _ = std::fs::remove_file(&slow_socket_path);
        let _ = std::fs::remove_file(&fast_socket_path);

        let slow_listener = UnixListener::bind(&slow_socket_path).unwrap();
        let fast_listener = UnixListener::bind(&fast_socket_path).unwrap();
        let (slow_init_seen_tx, slow_init_seen_rx) = oneshot::channel();
        let (release_slow_tx, release_slow_rx) = oneshot::channel();

        let slow_server_task = tokio::spawn(async move {
            let (stream, _) = slow_listener.accept().await.unwrap();
            let (server_read, mut server_write) = tokio::io::split(stream);
            let mut lines = tokio::io::BufReader::new(server_read).lines();

            let init_line = lines.next_line().await.unwrap().unwrap();
            let init_value: Value = serde_json::from_str(&init_line).unwrap();
            assert_eq!(init_value["method"], "initialize");
            let init_id = init_value["id"].clone();
            let _ = slow_init_seen_tx.send(());

            release_slow_rx.await.unwrap();

            let init_response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": init_id,
                "result": { "serverInfo": { "name": "slow" } },
            });
            let mut init_response_line = serde_json::to_string(&init_response).unwrap();
            init_response_line.push('\n');
            server_write
                .write_all(init_response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let initialized_line = lines.next_line().await.unwrap().unwrap();
            let initialized_value: Value = serde_json::from_str(&initialized_line).unwrap();
            assert_eq!(initialized_value["method"], "notifications/initialized");

            let request_line = lines.next_line().await.unwrap().unwrap();
            let request_value: Value = serde_json::from_str(&request_line).unwrap();
            assert_eq!(request_value["method"], "ping");
            let request_id = request_value["id"].clone();

            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": { "server": "slow" },
            });
            let mut response_line = serde_json::to_string(&response).unwrap();
            response_line.push('\n');
            server_write
                .write_all(response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let eof = lines.next_line().await.unwrap();
            assert!(eof.is_none(), "expected EOF after shared disconnect");
        });

        let fast_server_task = tokio::spawn(async move {
            let (stream, _) = fast_listener.accept().await.unwrap();
            let (server_read, mut server_write) = tokio::io::split(stream);
            let mut lines = tokio::io::BufReader::new(server_read).lines();

            let init_line = lines.next_line().await.unwrap().unwrap();
            let init_value: Value = serde_json::from_str(&init_line).unwrap();
            assert_eq!(init_value["method"], "initialize");
            let init_id = init_value["id"].clone();

            let init_response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": init_id,
                "result": { "serverInfo": { "name": "fast" } },
            });
            let mut init_response_line = serde_json::to_string(&init_response).unwrap();
            init_response_line.push('\n');
            server_write
                .write_all(init_response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let initialized_line = lines.next_line().await.unwrap().unwrap();
            let initialized_value: Value = serde_json::from_str(&initialized_line).unwrap();
            assert_eq!(initialized_value["method"], "notifications/initialized");

            let request_line = lines.next_line().await.unwrap().unwrap();
            let request_value: Value = serde_json::from_str(&request_line).unwrap();
            assert_eq!(request_value["method"], "ping");
            let request_id = request_value["id"].clone();

            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": { "server": "fast" },
            });
            let mut response_line = serde_json::to_string(&response).unwrap();
            response_line.push('\n');
            server_write
                .write_all(response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let eof = lines.next_line().await.unwrap();
            assert!(eof.is_none(), "expected EOF after shared disconnect");
        });

        let mut servers = BTreeMap::new();
        servers.insert(
            ServerName::parse("slow").unwrap(),
            ServerConfig::unix(slow_socket_path.clone()).unwrap(),
        );
        servers.insert(
            ServerName::parse("fast").unwrap(),
            ServerConfig::unix(fast_socket_path.clone()).unwrap(),
        );
        let config = Arc::new(Config::new(ClientConfig::default(), servers));

        let shared = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
            .with_trust_mode(TrustMode::Trusted)
            .into_shared();

        let slow_shared = shared.clone();
        let slow_config = Arc::clone(&config);
        let slow_request = tokio::spawn(async move {
            slow_shared
                .request(
                    slow_config.as_ref(),
                    "slow",
                    "ping",
                    None::<Value>,
                    Path::new("/"),
                )
                .await
        });

        slow_init_seen_rx.await.unwrap();

        let fast_result = tokio::time::timeout(Duration::from_millis(250), async {
            shared
                .request(
                    config.as_ref(),
                    "fast",
                    "ping",
                    None::<Value>,
                    Path::new("/"),
                )
                .await
        })
        .await
        .expect("fast cold-start should not be blocked by slow initialize")
        .unwrap();
        assert_eq!(fast_result, serde_json::json!({ "server": "fast" }));

        release_slow_tx.send(()).unwrap();

        let slow_result = tokio::time::timeout(Duration::from_secs(1), slow_request)
            .await
            .expect("slow request should finish after initialize is released")
            .unwrap()
            .unwrap();
        assert_eq!(slow_result, serde_json::json!({ "server": "slow" }));

        assert!(shared.disconnect("slow").await);
        assert!(shared.disconnect("fast").await);
        slow_server_task.await.unwrap();
        fast_server_task.await.unwrap();

        let _ = std::fs::remove_file(slow_socket_path);
        let _ = std::fs::remove_file(fast_socket_path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shared_manager_reentrant_handler_cold_start_fails_fast_on_connect_gate() {
        use tokio::net::UnixListener;

        let socket_path = unique_socket_path("reentrant-cold-start");
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).unwrap();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (server_read, mut server_write) = tokio::io::split(stream);
            let mut lines = tokio::io::BufReader::new(server_read).lines();

            let init_line = lines.next_line().await.unwrap().unwrap();
            let init_value: Value = serde_json::from_str(&init_line).unwrap();
            assert_eq!(init_value["method"], "initialize");
            let init_id = init_value["id"].clone();

            let callback_request = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 99,
                "method": "callback",
                "params": { "phase": "cold-start" },
            });
            let mut callback_line = serde_json::to_string(&callback_request).unwrap();
            callback_line.push('\n');
            server_write
                .write_all(callback_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let callback_response_line = lines.next_line().await.unwrap().unwrap();
            let callback_response: Value = serde_json::from_str(&callback_response_line).unwrap();
            assert_eq!(callback_response["id"], 99);
            let error_message = callback_response["error"]["message"]
                .as_str()
                .expect("callback should receive error response");
            assert!(
                error_message.contains(super::REENTRANT_HANDLER_ERROR),
                "unexpected callback error: {callback_response}"
            );

            let init_response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": init_id,
                "result": { "serverInfo": { "name": "demo" } },
            });
            let mut init_response_line = serde_json::to_string(&init_response).unwrap();
            init_response_line.push('\n');
            server_write
                .write_all(init_response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let initialized_line = lines.next_line().await.unwrap().unwrap();
            let initialized_value: Value = serde_json::from_str(&initialized_line).unwrap();
            assert_eq!(initialized_value["method"], "notifications/initialized");

            let request_line = lines.next_line().await.unwrap().unwrap();
            let request_value: Value = serde_json::from_str(&request_line).unwrap();
            assert_eq!(request_value["method"], "ping");
            let request_id = request_value["id"].clone();

            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": { "ok": true },
            });
            let mut response_line = serde_json::to_string(&response).unwrap();
            response_line.push('\n');
            server_write
                .write_all(response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let eof = lines.next_line().await.unwrap();
            assert!(eof.is_none(), "expected EOF after shared disconnect");
        });

        let mut servers = BTreeMap::new();
        servers.insert(
            ServerName::parse("srv").unwrap(),
            ServerConfig::unix(socket_path.clone()).unwrap(),
        );
        let config = Arc::new(Config::new(ClientConfig::default(), servers));
        let shared_slot: Arc<StdMutex<Option<SharedManager>>> = Arc::new(StdMutex::new(None));

        let handler_slot = Arc::clone(&shared_slot);
        let handler_config = Arc::clone(&config);
        let handler: ServerRequestHandler = Arc::new(move |_| {
            let shared = handler_slot
                .lock()
                .unwrap()
                .as_ref()
                .expect("shared manager installed")
                .clone();
            let config = Arc::clone(&handler_config);
            Box::pin(async move {
                match shared
                    .request(
                        config.as_ref(),
                        "srv",
                        "nested",
                        None::<Value>,
                        Path::new("/"),
                    )
                    .await
                {
                    Ok(result) => ServerRequestOutcome::Ok(result),
                    Err(err) => ServerRequestOutcome::Error {
                        code: -32001,
                        message: format!("{err:#}"),
                        data: None,
                    },
                }
            })
        });

        let shared = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
            .with_trust_mode(TrustMode::Trusted)
            .with_server_request_handler(handler)
            .into_shared();
        *shared_slot.lock().unwrap() = Some(shared.clone());

        let result = tokio::time::timeout(Duration::from_secs(1), async {
            shared
                .request(
                    config.as_ref(),
                    "srv",
                    "ping",
                    None::<Value>,
                    Path::new("/"),
                )
                .await
        })
        .await
        .expect("outer cold-start request should not deadlock")
        .unwrap();
        assert_eq!(result, serde_json::json!({ "ok": true }));

        assert!(shared.disconnect("srv").await);
        server_task.await.unwrap();

        let _ = std::fs::remove_file(socket_path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shared_manager_concurrent_cold_start_requests_share_single_connection() {
        use tokio::net::UnixListener;

        let socket_path = unique_socket_path("single-flight");
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).unwrap();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (server_read, mut server_write) = tokio::io::split(stream);
            let mut lines = tokio::io::BufReader::new(server_read).lines();

            let init_line = lines.next_line().await.unwrap().unwrap();
            let init_value: Value = serde_json::from_str(&init_line).unwrap();
            assert_eq!(init_value["method"], "initialize");
            let init_id = init_value["id"].clone();

            let init_response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": init_id,
                "result": { "serverInfo": { "name": "demo" } },
            });
            let mut init_response_line = serde_json::to_string(&init_response).unwrap();
            init_response_line.push('\n');
            server_write
                .write_all(init_response_line.as_bytes())
                .await
                .unwrap();
            server_write.flush().await.unwrap();

            let initialized_line = lines.next_line().await.unwrap().unwrap();
            let initialized_value: Value = serde_json::from_str(&initialized_line).unwrap();
            assert_eq!(initialized_value["method"], "notifications/initialized");

            for _ in 0..2 {
                let request_line = lines.next_line().await.unwrap().unwrap();
                let request_value: Value = serde_json::from_str(&request_line).unwrap();
                assert_eq!(request_value["method"], "ping");
                let request_id = request_value["id"].clone();

                let response = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": { "ok": true },
                });
                let mut response_line = serde_json::to_string(&response).unwrap();
                response_line.push('\n');
                server_write
                    .write_all(response_line.as_bytes())
                    .await
                    .unwrap();
                server_write.flush().await.unwrap();
            }

            let eof = lines.next_line().await.unwrap();
            assert!(eof.is_none(), "expected EOF after shared disconnect");

            assert!(
                tokio::time::timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err(),
                "expected no second cold-start connection"
            );
        });

        let mut servers = BTreeMap::new();
        servers.insert(
            ServerName::parse("srv").unwrap(),
            ServerConfig::unix(socket_path.clone()).unwrap(),
        );
        let config = Config::new(ClientConfig::default(), servers);

        let shared = Manager::new("test-client", "0.0.0", Duration::from_secs(5))
            .with_trust_mode(TrustMode::Trusted)
            .into_shared();

        let clone = shared.clone();
        let (result_a, result_b) = tokio::join!(
            shared.request(&config, "srv", "ping", None, Path::new("/")),
            clone.request(&config, "srv", "ping", None, Path::new("/")),
        );
        assert_eq!(result_a.unwrap(), serde_json::json!({ "ok": true }));
        assert_eq!(result_b.unwrap(), serde_json::json!({ "ok": true }));

        assert!(shared.disconnect("srv").await);
        server_task.await.unwrap();

        let _ = std::fs::remove_file(socket_path);
    }
}
