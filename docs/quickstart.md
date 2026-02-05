# 快速开始

本章目标：**在 5 分钟内跑通一次连接**（CLI + 作为库调用），并理解为什么默认会“拒绝一些东西”。

## 前置条件

- Rust `1.85+`（本 workspace 的 `rust-version`）
- 在本仓库内操作：进入 `mcp-kit/` 目录

## 1）先把 `mcpctl` 跑起来

`mcpctl` 在 `mcp-kit` crate 中，通过 feature `cli` 启用：

```bash
cd mcp-kit
cargo run -p mcp-kit --features cli --bin mcpctl -- --help
```

## 2）准备一个最小的远程配置（推荐）

在 workspace root（你运行 `mcpctl` 的 `--root`，默认当前目录）创建 `./.mcp.json`：

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

然后：

```bash
# 查看解析后的配置（确认最终生效字段）
cargo run -p mcp-kit --features cli --bin mcpctl -- list-servers

# 探测 tools（远程 https 且非 localhost/私网：默认无需 --trust）
cargo run -p mcp-kit --features cli --bin mcpctl -- list-tools remote
```

如果你需要对远程出站做更严格/更宽松控制，见 [`安全模型`](security.md) 与 `mcpctl --help` 中的 `--allow-*` 选项。

## 3）本地 stdio/unix 为什么默认跑不起来？

如果你的 `mcp.json` 配的是本地：

```json
{
  "version": 1,
  "servers": {
    "local": {
      "transport": "stdio",
      "argv": ["mcp-server-bin", "--stdio"]
    }
  }
}
```

在默认模式下（Untrusted），`mcpctl list-tools local` 会报错：拒绝 spawn。本地 `stdio/unix` 必须显式信任：

```bash
cargo run -p mcp-kit --features cli --bin mcpctl -- --trust --yes-trust list-tools local
```

原因与威胁模型见 [`安全模型`](security.md)。

## 4）作为库使用：最小代码

`mcp-kit` 的典型流程是：

1. `Config::load` 读取并校验 `mcp.json`。
2. `Manager::from_config` 创建 client（可设置 protocol/capabilities/roots/超时/信任策略；若你手动构造 config，可改用 `Manager::try_from_config` 做 fail-fast 校验）。
3. `Manager::request` / `request_typed` 发请求（内部会按需 connect + initialize）。

示例（以 `tools/list` 为例）：

```rust
use std::time::Duration;

use mcp_kit::{mcp, Config, Manager, UntrustedStreamableHttpPolicy};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let root = std::env::current_dir()?;
    let config = Config::load(&root, None).await?;

    // `Config::load` 已隐式校验 `config.client()`；手动构造 config 时可用 `Manager::try_from_config`。
    let mut mcp = Manager::from_config(&config, "my-app", "0.1.0", Duration::from_secs(30))
        .with_untrusted_streamable_http_policy(UntrustedStreamableHttpPolicy {
            allowed_hosts: vec!["example.com".to_string()],
            ..Default::default()
        });

    let tools = mcp
        .request_typed::<mcp::ListToolsRequest>(&config, "remote", None, &root)
        .await?;

    println!("{}", serde_json::to_string_pretty(&tools)?);
    Ok(())
}
```

下一步建议：

- 想把单 server 会话交给别的库：看 [`作为库使用`](library.md) 的 `Session`。
- 想理解每个配置字段的含义与限制：看 [`配置`](config.md)。
