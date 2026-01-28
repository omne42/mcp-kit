# mcp-kit

独立的 MCP client/runner 基建目录（Rust workspace）。

包含：

- `pm-jsonrpc`：JSON-RPC（stdio / unix / streamable http）client
- `pm-mcp-kit`：`mcp.json` 解析 + MCP 连接/生命周期管理（stdio / unix / streamable http）
- `mcpctl`：基于配置的 MCP CLI（类似 “mcpctl”）

## 快速开始

```bash
# 在 mcp-kit/ 下
cargo run -p pm-mcp-kit --features cli --bin mcpctl -- --help
```

## 配置（v1 最小 schema）

默认发现顺序（相对 `--root`，默认当前目录）：

1. `./.mcp.json`
2. `./mcp.json`
3. `./.codepm_data/spec/mcp.json`（legacy）

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

可选字段：

- `client.protocol_version` / `client.capabilities`：覆盖 MCP initialize 里的 client 配置。
- `client.roots`：启用 roots 能力，并自动响应 server→client 的 `roots/list`。
- `servers.<name>.stdout_log`：将 server stdout 旋转落盘（见 `pm-jsonrpc::StdoutLog`），支持 `max_bytes_per_part` 与 `max_parts`（0 表示不做保留上限）。
- `transport=unix`：连接已有 unix socket MCP server（见 `servers.<name>.unix_path`）。
- `transport=streamable_http`：连接远程 MCP server（见 `servers.<name>.url`），可选 `servers.<name>.bearer_token_env_var` / `servers.<name>.http_headers` / `servers.<name>.env_http_headers`。
- 安全默认（`TrustMode::Untrusted`）：仅允许连接 `https` 且非 localhost/私网的 `streamable_http`；并拒绝发送 `Authorization`/`Cookie` 等敏感 header、拒绝读取 env secrets；需要显式信任（`--trust` / `TrustMode::Trusted`）才放开。

## 作为库使用

```rust
use std::time::Duration;

use pm_mcp_kit::{mcp, Config, Manager, UntrustedStreamableHttpPolicy};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let root = std::env::current_dir()?;
    let config = Config::load(&root, None).await?;
    // 默认 TrustMode::Untrusted：
    // - 允许连接远程 `transport=streamable_http`（仅 https 且非 localhost/私网；不允许认证 header / env secrets）
    // - 拒绝本地 `transport=stdio|unix`（避免不可信仓库导致本地执行/本地 socket 滥用）
    // 如确需启用本地 transport 或 env secrets，显式开启：`.with_trust_mode(TrustMode::Trusted)`
    // 如需在不完全信任的前提下，收紧/放开远程出站规则，可配置 policy：
    // `.with_untrusted_streamable_http_policy(UntrustedStreamableHttpPolicy { allowed_hosts: vec!["example.com".into()], ..Default::default() })`
    let mut mcp = Manager::from_config(&config, "my-app", "0.1.0", Duration::from_secs(30))
        .with_untrusted_streamable_http_policy(UntrustedStreamableHttpPolicy {
            allowed_hosts: vec!["example.com".to_string()],
            ..Default::default()
        });

    let tools = mcp
        .request_typed::<mcp::ListToolsRequest>(&config, "remote", None, &root)
        .await?;

    if let Some(init) = mcp.initialize_result("remote") {
        eprintln!("server initialize: {}", serde_json::to_string_pretty(init)?);
    }

    println!("{}", serde_json::to_string_pretty(&tools)?);
    Ok(())
}
```

`Manager` 内置了 MCP 常用请求的便捷方法（`ping`、`resources/read`、`prompts/get`、`logging/setLevel` 等）；也可用 `request`/`request_typed` 发送任意自定义方法。

如需把单个 server 的会话交给其他库持有，可用 `Manager::get_or_connect_session` / `Manager::connect_*_session` 取出 `Session`，再调用 `Session::{list_tools, call_tool, read_resource}` 等。

`pm_mcp_kit::mcp` 模块提供了一组**常用方法的轻量 typed wrapper**（参考 `example/codex/codex-rs/mcp-types`），不覆盖完整 MCP schema；缺的部分可继续用 `serde_json::Value` 或自行实现 `McpRequest`/`McpNotification`。

## 常用命令

```bash
mcpctl list-servers
# 远程 streamable_http server（https + 非 localhost/私网 + 无认证 header/env secrets）可直接使用
mcpctl list-tools <server>

# 本地 stdio/unix server 或需要读取 env secrets 的远程 server，需要显式信任
mcpctl --trust list-tools <server>
mcpctl --trust call <server> <tool> --arguments-json '{"k":"v"}'
mcpctl --trust request <server> <method> --params-json '{"k":"v"}'

# 不完全信任时，也可显式放开部分出站策略（仅影响 streamable_http）
mcpctl --allow-host example.com list-tools <server>
mcpctl --allow-private-ip --allow-http list-tools <server>
```

> 提示：默认不安装到 PATH，可用 `cargo run -p pm-mcp-kit --features cli --bin mcpctl -- ...`。

## 开发

- 启用 hooks：`git config core.hooksPath githooks`
- Rust gates：`cargo fmt --all && cargo check --workspace --all-targets --all-features && cargo test --workspace --all-features && cargo clippy --workspace --all-targets --all-features -- -D warnings`
