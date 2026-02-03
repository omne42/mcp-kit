# 示例

本章给出一些“可复制”的配置与代码片段，方便作为模板。

## 可运行示例

- `minimal_client`（最简；**默认只适用于 `transport=streamable_http`** / Untrusted）：
  - 源码：`crates/mcp-kit/examples/minimal_client.rs`
  - 运行：`cargo run -p mcp-kit --example minimal_client -- <server>`
  - 注意：`Untrusted` 默认只允许 `https://` 且拒绝 `localhost/私网` 目标；详见 `docs/security.md`。本地/测试环境请用 `client_with_policy` 的 `--allow-*` flags（或 `mcpctl --allow-*`），或直接 `--trust`
  - 如果你要连 `transport=stdio|unix`，请用 `client_with_policy --trust` 或 `mcpctl --trust`
- `client_with_policy`（支持 `--trust` + Untrusted 出站策略 flags；无 clap，手写 args）：
  - 源码：`crates/mcp-kit/examples/client_with_policy.rs`
  - 运行：`cargo run -p mcp-kit --example client_with_policy -- [flags] <server>`
- `stdio_self_spawn`（无需外部 server；演示 `transport=stdio` 的 spawn + initialize + tools/list/tools/call）：
  - 源码：`crates/mcp-kit/examples/stdio_self_spawn.rs`
  - 运行：`cargo run -p mcp-kit --example stdio_self_spawn`
  - 注意：该示例会用 `TrustMode::Trusted` 允许 spawn；`--server` 仅用于内部子进程模式
- `unix_loopback`（仅 unix；无需外部 server；演示 `transport=unix` + 本地 socket）：
  - 源码：`crates/mcp-kit/examples/unix_loopback.rs`
  - 运行：`cargo run -p mcp-kit --example unix_loopback`
  - 注意：`transport=unix` 需要 `TrustMode::Trusted`
- `in_memory_duplex`（无需外部 server；`Manager::connect_io` + duplex；演示 server→client request）：
  - 源码：`crates/mcp-kit/examples/in_memory_duplex.rs`
  - 运行：`cargo run -p mcp-kit --example in_memory_duplex`
- `session_handoff`（无需外部 server；`Manager::connect_io_session` + `Session`；演示把单连接交给其它模块持有）：
  - 源码：`crates/mcp-kit/examples/session_handoff.rs`
  - 运行：`cargo run -p mcp-kit --example session_handoff`
- `streamable_http_split`（需要真实 server；演示拆分 `sse_url/http_url`）：
  - 源码：`crates/mcp-kit/examples/streamable_http_split.rs`
  - 运行：`cargo run -p mcp-kit --example streamable_http_split -- <sse_url> <http_url>`
- `streamable_http_custom_options`（需要真实 server；演示自定义 `StreamableHttpOptions` 的网络参数，并通过 `connect_jsonrpc` 接入）：
  - 源码：`crates/mcp-kit/examples/streamable_http_custom_options.rs`
  - 运行：`cargo run -p mcp-kit --example streamable_http_custom_options -- [flags] <sse_url> [http_url]`
  - 注意：该路径会绕过 `Manager` 的 Untrusted `streamable_http` 出站策略校验；请仅在你**完全信任** URL/headers 的场景使用

## 1）最小远程配置（streamable_http）

`.mcp.json`：

```json
{
  "version": 1,
  "servers": {
    "remote": {
      "transport": "streamable_http",
      "url": "https://example.com/mcp"
    }
  }
}
```

命令：

```bash
cargo run -p mcp-kit --features cli --bin mcpctl -- list-tools remote
```

## 2）远程 + host allowlist（Untrusted 下更安全）

```bash
cargo run -p mcp-kit --features cli --bin mcpctl -- --allow-host example.com list-tools remote
```

等价的代码配置：

```rust
use mcp_kit::UntrustedStreamableHttpPolicy;
manager = manager.with_untrusted_streamable_http_policy(UntrustedStreamableHttpPolicy {
    allowed_hosts: vec!["example.com".into()],
    ..Default::default()
});
```

## 3）本地 stdio 配置（需要 --trust）

```json
{
  "version": 1,
  "servers": {
    "local": {
      "transport": "stdio",
      "argv": ["mcp-server-bin", "--stdio"],
      "env": { "NO_COLOR": "1" },
      "stdout_log": {
        "path": "./.mcp-kit/logs/mcp/server.stdout.log",
        "max_bytes_per_part": 1048576,
        "max_parts": 32
      }
    }
  }
}
```

```bash
cargo run -p mcp-kit --features cli --bin mcpctl -- --trust list-tools local
```

## 4）使用 `Session`：把单连接交给其它模块

```rust
let session = manager.get_or_connect_session(&config, "remote", &root).await?;
let tools = session.list_tools().await?;
```

## 5）处理 server→client request：自定义方法 + 保留 built-in `roots/list`

```rust
use std::sync::Arc;
use mcp_kit::{ServerRequestContext, ServerRequestOutcome};

let handler = Arc::new(|ctx: ServerRequestContext| {
    Box::pin(async move {
        match ctx.method.as_str() {
            "example/ping" => ServerRequestOutcome::Ok(serde_json::json!({"ok": true})),
            _ => ServerRequestOutcome::MethodNotFound,
        }
    }) as _
});

manager = manager.with_server_request_handler(handler);
```

可运行版本见：`crates/mcp-kit/examples/in_memory_duplex.rs`。
