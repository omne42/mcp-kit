# 示例

本章给出一些“可复制”的配置与代码片段，方便作为模板。

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
    })
});

manager = manager.with_server_request_handler(handler);
```
