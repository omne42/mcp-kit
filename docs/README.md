# mcp-kit 文档

`mcp-kit` 是一个 **Rust workspace**：提供可复用的 MCP client/runner 组件，用于按配置连接 MCP servers（stdio / unix / streamable_http），并以 **Safe-by-default** 的方式提供 TrustMode 与远程出站策略。

## 1 分钟上手（复制粘贴）

1）在仓库根目录创建 `./.mcp.json`（把 URL 替换成你的 MCP server）：

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

2）用 CLI 先验证连接（默认 `Untrusted`：仅允许 `https://` 且拒绝 `localhost/私网` 目标）：

```bash
cargo run -p mcp-kit --features cli --bin mcpctl -- list-tools remote
```

3）作为库调用（最小）：

`Cargo.toml`（最小依赖）：

```toml
[dependencies]
anyhow = "1"
serde_json = "1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }

# 依赖本仓库（把 path 改成你本地 clone 的实际路径；也可以改用 git 方式）
mcp-kit = { path = "../mcp-kit/crates/mcp-kit" }
# mcp-kit = { git = "https://github.com/<owner>/mcp-kit", rev = "<sha>" }
```

```rust
use std::time::Duration;

use mcp_kit::{Config, Manager, mcp};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let root = std::env::current_dir()?;
    let config = Config::load(&root, None).await?;

    let mut manager = Manager::from_config(&config, "my-client", "0.1.0", Duration::from_secs(30));
    let tools = manager
        .request_typed::<mcp::ListToolsRequest>(&config, "remote", None, &root)
        .await?;

    println!("{}", serde_json::to_string_pretty(&tools)?);
    Ok(())
}
```

更完整的流程与本地 `--trust/--allow-*` 用法见 [`快速开始`](quickstart.md) 与 [`安全模型`](security.md)。

## 为什么用 mcp-kit？

- **Remote-first**：原生支持远程 `transport=streamable_http`（HTTP SSE + POST）。
- **Safe-by-default**：默认 `TrustMode::Untrusted`，拒绝本地 `stdio/unix`，并对远程出站做保守校验（https/host/ip/sensitive headers/env secrets）。
- **低依赖、低仪式感**：数据层以 `serde_json::Value` 为主；typed wrapper 只覆盖常用 MCP 方法子集。
- **可组合/可测试**：既能用 `Manager` 管多个 server，也能把单连接的 `Session` 交给其他模块持有；支持 `connect_io/connect_jsonrpc`（Trusted）以及更显式的 `*_unchecked` 入口接入自定义 transport。
- **CLI 先行**：`mcpctl` 适合快速验证配置、探测 tools/resources/prompts，并能显式切换 `--trust` 或收紧/放开 Untrusted 出站策略。

## 组件一览

- `mcp-jsonrpc`：最小 JSON-RPC 2.0 client（stdio / unix / streamable_http），支持 notification 与 server→client request，并内置 DoS 防护（有界队列 + 单消息大小限制）。
- `mcp-kit`：`mcp.json`（v1）解析 + MCP 连接/初始化 + 会话管理（`Config / Manager / Session`），并提供常用 MCP 方法的便捷封装。
- `mcpctl`：基于 `mcp.json` 的 CLI（`cargo run -p mcp-kit --features cli --bin mcpctl -- ...`）。
- Examples：可运行示例在 `crates/mcp-kit/examples/`，索引见 `example/README.md` 与 [`示例`](examples.md)。

## 从哪里开始

- 新手：先看 [`快速开始`](quickstart.md)（5 分钟跑通 `mcpctl` + 代码调用）。
- 想先建立整体心智模型：看 [`核心概念与术语`](concepts.md)。
- 配置：看 [`配置`](config.md)（发现顺序、schema、每种 transport 的字段与约束）。
- 作为库：看 [`作为库使用`](library.md)（`Config/Manager/Session` 最佳实践）。
- 安全：看 [`安全模型`](security.md)（默认拒绝什么、为什么拒绝、如何按需放开）。
- 传输：看 [`传输层`](transports.md) 与 [`streamable_http 传输详解`](streamable_http.md)。

## 本地预览（推荐 mdbook）

本仓库的文档结构兼容 mdbook（目录由 `docs/SUMMARY.md` 驱动；配置见 `docs/book.toml`）。

```bash
cargo install mdbook
mdbook serve docs --open
```

## llms.txt（把文档打包给 LLM）

如果你希望把文档一次性喂给 LLM（Cursor/Claude/ChatGPT），用：

- `llms.txt`（仓库根目录，生成后的单文件）
- `docs/llms.txt`（同内容副本）
- `./scripts/gen-llms-txt.sh`（生成脚本）

详情见 [`llms.txt（给 LLM 用）`](llms.md)。

## 目录导航（GitBook/HonKit）

如果你用 GitBook/HonKit 一类工具渲染这套文档，入口是：

- `docs/README.md`（本页）
- `docs/SUMMARY.md`（目录）
