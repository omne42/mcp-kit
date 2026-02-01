# mcpctl

`mcpctl` 是一个基于 `mcp.json` 的 MCP client/runner（config-driven; stdio/unix/streamable_http）。

它的定位是：

- 快速验证配置是否正确（`list-servers`）
- 探测 server 暴露的能力（tools/resources/prompts）
- 发送 raw request/notification 进行调试

## 运行方式

当前仓库内（推荐）：

```bash
cd mcp-kit
cargo run -p mcp-kit --features cli --bin mcpctl -- --help
```

> 注意：`mcpctl` 通过 feature `cli` 启用，避免 library 依赖方被迫引入 `clap`。

## 全局参数（flags）

- `--root <path>`：workspace root；用于相对路径解析，并作为 stdio server 的工作目录
- `--config <path>`：覆盖配置文件路径（绝对或相对 `--root`）
- `--json`：输出紧凑 JSON（默认 pretty JSON）
- `--timeout-ms <ms>`：per-request 超时（默认 30000）

安全相关：

- `--trust`：完全信任 `mcp.json`（允许 stdio/unix、允许读取 env secrets、允许发送认证 header）
- `--allow-http`：Untrusted 下允许连接 `http://`（默认只允许 https）
- `--allow-localhost`：Untrusted 下允许连接 `localhost/*.localhost/*.local`
- `--allow-private-ip`：Untrusted 下允许连接非公网 IP 字面量
- `--allow-host <host>`：Untrusted 下设置 host allowlist（可重复）

> `--allow-*` 只影响 `transport=streamable_http`，不会放开 stdio/unix（它们需要 `--trust`）。

## 子命令（subcommands）

### list-servers

列出解析后的配置（包含 `client` 与 servers 的关键字段），用于确认最终生效值：

```bash
cargo run -p mcp-kit --features cli --bin mcpctl -- list-servers
```

### list-tools / list-resources / list-prompts

```bash
cargo run -p mcp-kit --features cli --bin mcpctl -- list-tools remote
cargo run -p mcp-kit --features cli --bin mcpctl -- list-resources remote
cargo run -p mcp-kit --features cli --bin mcpctl -- list-prompts remote
```

### call

```bash
cargo run -p mcp-kit --features cli --bin mcpctl -- call remote my.tool --arguments-json '{"k":"v"}'
```

### request（raw JSON-RPC request）

```bash
cargo run -p mcp-kit --features cli --bin mcpctl -- request remote tools/list
cargo run -p mcp-kit --features cli --bin mcpctl -- request remote resources/read --params-json '{"uri":"file:///path/to/file"}'
```

### notify（raw JSON-RPC notification）

```bash
cargo run -p mcp-kit --features cli --bin mcpctl -- notify remote notifications/initialized
```

## 常见用法组合

- 远程 server（https + 非 localhost/私网）：默认可用
- 本地 stdio/unix 或需要读取 env secrets：加 `--trust`
- 不完全信任但需要放开部分出站：使用 `--allow-host/--allow-http/...`

安全细节见 [`安全模型`](security.md)。
