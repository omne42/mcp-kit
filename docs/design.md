# 设计

目标：把 “mcp.json 配置解析 + stdio JSON-RPC + server 生命周期管理” 做成独立库/CLI，供上层产品复用。

## 核心数据结构

- `Config { servers: BTreeMap<String, ServerConfig> }`
- `Manager { conns: HashMap<ServerName, Connection> }`
- `Connection { child, client }`

约束：

- 本仓库不引入 CodePM 的 thread/process 等领域 ID。
- 单连接请求按 `&mut client` 串行化（避免并发写导致 JSON-RPC 输出交错）。

## 策略（v1）

- **日志**：由上层选择是否将 server stdout 旋转落盘（`pm-jsonrpc::SpawnOptions`）。
- **超时**：`Manager` 级别的 per-request timeout（默认 30s）。
- **重连**：v1 不做自动重连；上层可通过 drop/重建连接实现。
- **并发**：同一连接串行；不同 server 可由上层并发使用多个 `Manager` 或拆分任务。

