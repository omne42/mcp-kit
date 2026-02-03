# 作为库使用（mcp-kit）

本章聚焦 `mcp-kit` 的对外 API：`Config / Manager / Session`，以及常见集成方式。

## 选择 `Manager` 还是 `Session`？

- 用 `Manager`：你想“按配置管理多个 server”，并希望有连接缓存、自动 initialize、以及 `list_tools/call_tool/...` 等便捷方法。
- 用 `Session`：你想把“单 server 的已初始化连接”交给其它库/模块持有（更接近“连接句柄”的语义）。

`Manager` 内部也是通过 `Session` 的同等能力实现，只是多了缓存与按需连接。

## 读取配置：`Config::load`

```rust
let root = std::env::current_dir()?;
let config = mcp_kit::Config::load(&root, None).await?;
```

- 默认会按顺序发现（相对 `root`）：`./.mcp.json` → `./mcp.json`。
- 你也可以传入 `Some(path)` 覆盖（绝对路径或相对 `root` 的路径）。
- 对 `mcp.json v1`：schema 为 fail-closed，未知字段会报错（`deny_unknown_fields`）；对 `.mcp.json` / `mcpServers` 兼容格式：best-effort（会忽略未支持字段）。

详情见 [`配置`](config.md)。

## 创建 client：`Manager::from_config`

```rust
use std::time::Duration;

let mut manager = mcp_kit::Manager::from_config(
    &config,
    "my-client",
    "0.1.0",
    Duration::from_secs(30),
);
```

它会把 `config.client.protocol_version / capabilities / roots` 自动灌入 `Manager`：

- `protocol_version`：用于 MCP `initialize`，并在 `streamable_http` 下加到请求 header `MCP-Protocol-Version`。
- `capabilities`：透传到 initialize；如果启用了 roots，会确保声明 `capabilities.roots`。
- `roots`：启用后会内建响应 server→client 的 `roots/list`（见下文“server→client handler”）。

## 发请求：`request` / `request_typed`

最通用的方式（raw JSON）：

```rust
let v = manager
    .request(&config, "remote", "tools/list", None, &root)
    .await?;
```

更推荐的方式（typed wrapper）：

```rust
use mcp_kit::mcp;

let tools = manager
    .request_typed::<mcp::ListToolsRequest>(&config, "remote", None, &root)
    .await?;
```

说明：

- `request*` 会自动 `connect + initialize`（若未连接）。
- timeout 是 `Manager` 级别的 per-request 超时；可用 `.with_timeout(...)` 调整。
- `mcp_kit::mcp` 只覆盖常用 MCP method 的子集；缺的部分继续用 `serde_json::Value` 即可。

## 连接与会话：把 `Session` 交出去

当你希望“上层统一管理配置，但把某个 server 的会话交给另一层库持有”：

```rust
let session = manager
    .get_or_connect_session(&config, "remote", &root)
    .await?;

let tools = session.list_tools().await?;
```

相关方法：

- `Manager::get_or_connect_session`：按配置连接并返回 `Session`
- `Manager::take_session`：把已连接的会话取走（会从 `Manager` 的连接缓存中移除）
- `Manager::connect_*_session`：一次性连接并直接返回 `Session`

## server→client：处理 requests / notifications

底层 JSON-RPC（`mcp-jsonrpc`）支持 server→client 的：

- notification（无 `id`）
- request（有 `id`，需要 respond）

`mcp_kit::Manager` 默认行为：

- 未识别的 server→client request：返回 JSON-RPC `-32601 Method not found`
- 若启用 roots：内建响应 `roots/list`

如果你的 MCP server 会“反向调用”一些 client 侧能力（server→client request），通常需要两件事：

1. 在 initialize 里声明你支持的 client capabilities（`Manager::with_capabilities(...)`）
2. 实现对应的 request handler（`with_server_request_handler(...)`）

例如（声明 capability + 处理对应的 server→client request；类似一些实现会用到的 `codex/sandbox-state/update`）：

```rust
use std::sync::Arc;

use mcp_kit::{ServerRequestContext, ServerRequestOutcome};
use serde_json::json;

manager = manager.with_capabilities(json!({
    "experimental": {
        "codex/sandbox-state": { "version": "1.0.0" }
    }
}));

manager = manager.with_server_request_handler(Arc::new(|ctx: ServerRequestContext| {
    Box::pin(async move {
        match ctx.method.as_str() {
            "codex/sandbox-state/update" => ServerRequestOutcome::Ok(serde_json::json!({})),
            _ => ServerRequestOutcome::MethodNotFound,
        }
    }) as _
}));
```

你可以注入 handler：

```rust
use std::sync::Arc;
use mcp_kit::{ServerRequestOutcome, ServerRequestContext};

let handler = Arc::new(|ctx: ServerRequestContext| {
    Box::pin(async move {
        if ctx.method == "example/ping" {
            return ServerRequestOutcome::Ok(serde_json::json!({"ok": true}));
        }
        ServerRequestOutcome::MethodNotFound
    })
});

manager = manager.with_server_request_handler(handler);
```

notification handler 类似：`with_server_notification_handler(...)`。

## TrustMode 与远程策略

`Manager` 默认 `TrustMode::Untrusted`：

- 拒绝 `transport=stdio|unix`
- 允许远程 `streamable_http`，但会做安全校验（https/host/ip/sensitive headers/env secrets）

完全信任配置时显式开启：

```rust
use mcp_kit::TrustMode;
manager = manager.with_trust_mode(TrustMode::Trusted);
```

想在“不完全信任”的前提下收紧/放开远程规则，配置：

```rust
use mcp_kit::UntrustedStreamableHttpPolicy;
manager = manager.with_untrusted_streamable_http_policy(UntrustedStreamableHttpPolicy {
    allowed_hosts: vec!["example.com".into()],
    ..Default::default()
});
```

细节见 [`安全模型`](security.md)。

## 自定义 transport：`connect_io` / `connect_jsonrpc`

用于测试、复用已有管道，或接入自定义 JSON-RPC transport：

- `Manager::connect_io(server, read, write)`
- `Manager::connect_jsonrpc(server, client)`

这两者会复用同样的 initialize 与 handler 逻辑。

如果你需要调整 `mcp-jsonrpc` 的 `Limits` 或 streamable_http 的网络选项（例如 connect_timeout / redirects），推荐先用 `mcp-jsonrpc` 构建 `Client`，再用 `connect_jsonrpc` 接入；细节见 [`调优与限制`](tuning.md)。
