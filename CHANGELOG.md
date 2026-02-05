# Changelog

本项目的所有重要变更都会记录在这个文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

> 计划下一个版本：`0.3.0`（包含若干 breaking changes；见下文标注）。

### Changed
- `mcp-kit`（BREAKING）：引入 `ServerName` 新类型，并将其用于 `Config/Manager` 的 server key；`Session::new(...)` 现在要求传入 `ServerName`（避免把任意 `String` 当作已校验的 server 名称）。
- `mcp-kit`：重构内部模块边界：`config` 拆分为 `file_format/model/load`，`manager` 抽出 `placeholders` 与 `streamable_http_validation`，并将大型 `tests` 外置，降低单文件复杂度与后续维护成本。
- `mcp-kit`：新增 `ServerNameError`（`thiserror`，`#[non_exhaustive]`），为后续把 `anyhow` 逐步替换为结构化错误打基础。
- `mcp-kit`：`ServerName::parse(...)` 的 rustdoc 现在明确其会对输入做 `trim()` 后再校验（行为不变，只是把语义写清楚）。
- `mcp-kit`：`ServerName` 内部实现改为 `Arc<str>`，避免在 handler 等路径频繁 clone 时产生额外分配（API 不变）。

### Added
- `mcp-kit`：`ServerName` 现在实现 `Deserialize`（`serde`），便于在配置/外部数据模型中直接使用。
- `mcp-kit`：新增一组接受 `&ServerName` 的便捷入口（非 breaking）：`Config::server_named`、`Manager::*_named`。
- `mcp-kit`：新增 `Manager::disconnect_and_wait` + `Connection::{wait, wait_with_timeout}` + `Session::{wait, wait_with_timeout}`，用于更明确的关闭/回收语义。
- `mcp-kit`：新增 `Manager::{connect_io_unchecked, connect_jsonrpc_unchecked}`，用于测试/显式接入自定义 transport（会绕过 `Untrusted` 安全护栏）。
- `mcp-jsonrpc`：`SpawnOptions` 新增 `kill_on_drop`（默认 `true`）、`stdout_log_redactor` 与 `diagnostics.invalid_json_sample_lines`（用于脱敏与诊断采样）。
- `mcp-jsonrpc`：`StreamableHttpOptions` 新增 `error_body_preview_bytes`（默认 `0`，避免意外泄露）。
- `mcp-jsonrpc`：最小 JSON-RPC client（stdio / unix / streamable http），支持 notifications 与可选 stdout 旋转落盘。
- `mcp-jsonrpc`：新增 `ClientStats` / `Client::stats()` / `ClientHandle::stats()`，统计无效 JSON 行与因队列满/关闭导致的 notifications 丢弃数量。
- `mcp-jsonrpc`：新增 `Client::connect_streamable_http_split_with_options(sse_url, http_url, ...)`，支持分离的 SSE 与 POST URL。
- `mcp-jsonrpc`：新增 `Client::wait_with_timeout(timeout, on_timeout)` 与 `WaitOnTimeout`，支持带超时等待 child 退出（可选 kill）。
- `mcp-jsonrpc`：新增 `Error::is_wait_timeout()`，便于在代码中判断 wait 超时错误（基于稳定 kind，不依赖具体报错文案）。
- `mcp-kit`：`mcp.json`（v1）解析、MCP server 连接与连接缓存管理（`Config/Manager/Connection`）。
- `mcpctl`：基于配置的 MCP CLI（list-servers/list-tools/list-resources/list-prompts/call）。
- `mcpctl`：新增 `--dns-check`，可选启用 Untrusted 下的 hostname DNS 校验。
- `mcpctl`：新增 `--dns-timeout-ms` 与 `--dns-fail-open`，用于调整 DNS 校验的超时与 fail-open 策略（仅在 `--dns-check` 开启时生效）。
- `mcpctl`：新增 `--yes-trust`、`--allow-config-outside-root` 与 `--no-dns-check`（用于更显式的安全开关与边界控制）。
- `McpRequest` / `McpNotification`：轻量 typed method trait + `Manager::{request_typed, notify_typed}`。
- `mcp_kit::mcp`：常用 MCP methods 的轻量 typed wrapper 子集（参考 `docs/examples.md`）。
- `transport=streamable_http`：原生支持远程 MCP server（HTTP SSE + POST），配置字段 `servers.<name>.url`。
- `transport=streamable_http`：支持分离配置 `servers.<name>.sse_url` + `servers.<name>.http_url`。
- `TrustMode`：安全默认不信任本地配置；需要显式切换到 Trusted 才允许从配置启动/连接 server。
- `roots/list`：当配置了 `client.roots` 时，内建响应 server→client request，并自动声明 `capabilities.roots`。
- `Manager::{connect_io, connect_jsonrpc}`：支持接入自定义 JSON-RPC 连接（需要 `TrustMode::Trusted`）。
- `ServerConfig::streamable_http_split(sse_url, http_url)`：便捷构造 split URL 的 `transport=streamable_http` 配置（用于手写/测试场景；现在返回 `Result`）。
- `Manager::initialize_result`：暴露 server initialize 响应。
- `mcp-kit`：新增 `ProtocolVersionCheck` 与 `Manager::with_protocol_version_check(...)`，用于控制 `initialize.protocolVersion` mismatch 的处理策略，并可通过 `Manager::protocol_version_mismatches()` 获取告警信息。
- `mcp-kit`：新增 `Manager::with_server_handler_concurrency(...)` 与 `Manager::with_server_handler_timeout(...)`，用于限制/保护 server→client handler 的并发与超时行为。
- `mcp-kit`：新增 `Manager::server_handler_timeout_count(...)` / `server_handler_timeout_counts()` / `take_server_handler_timeout_counts()`，用于观测 server→client handler 超时次数（避免 silent drop 难排查）。
- `mcp-kit`：新增 `Config::load_required(...)`，用于在缺少配置文件时 fail-fast（区别于 `Config::load` 的“缺省为空配置”语义）。
- `Manager`：补齐 MCP 常用请求便捷方法（`ping`、`resources/templates/list`、`resources/read`、`resources/subscribe`、`resources/unsubscribe`、`prompts/get`、`logging/setLevel`、`completion/complete`）。
- `Session`：单连接 MCP 会话（从 `Manager` 取出后可独立调用 `request/notify` 与便捷方法）。
- `Manager::{take_session, get_or_connect_session, connect_*_session}`：支持把握手完成的会话交给上层库持有。
- `mcp-kit`：`Config::load` 支持 Cursor/Claude Code 常见的 `.mcp.json` / `mcpServers` 兼容格式（best-effort）。
- `mcp-jsonrpc`：`streamable_http` 兼容握手前 `GET SSE` 返回 `405`，并在 `202 Accepted`（或首次获得 `mcp-session-id`）后自动重试建立 inbound SSE。
- Examples: add runnable `client_with_policy`, `in_memory_duplex`, `session_handoff`, and `streamable_http_split` under `crates/mcp-kit/examples/`.
- Examples: add runnable `streamable_http_custom_options` to demonstrate custom `StreamableHttpOptions` + `Manager::connect_jsonrpc`.
- Examples: add runnable `stdio_self_spawn` and `unix_loopback` to demonstrate self-contained stdio/unix transports.
- Docs: add a quick example index at `example/README.md`.
- Docs: expand runnable examples section and clarify Untrusted/Trusted usage in `docs/examples.md`.
- `mcp-kit`：`transport=stdio` 新增 `servers.<name>.inherit_env`（默认 `false`），用于控制是否继承宿主环境变量；当为 `false` 时会清空子进程 env 并仅透传少量基础变量，再注入 `servers.<name>.env` 以降低 secrets 泄露风险。
- `mcpctl`：新增 `--show-argv`（`list-servers` 显式输出 argv）与 `--allow-stdout-log-outside-root`（允许 stdout_log 写到 `--root` 外）。
- `mcp-kit`：新增 `Manager::with_allow_stdout_log_outside_root(bool)`，用于显式放开 stdout_log 写入范围。

### Changed
- `mcp-jsonrpc`（BREAKING）：`Error::Protocol` 现在返回结构化的 `ProtocolError { kind: ProtocolErrorKind, message: String }`，便于下游稳定匹配错误类型。
- `mcp-kit`（BREAKING）：`Config` / `ServerConfig` / `Connection` 的字段现在改为私有；新增 getter/setter/构造器以便未来收紧不变量与演进 API。
- `mcp-kit`（BREAKING）：`transport=stdio` 的 `inherit_env` 默认改为 `false`（更安全；如需继承宿主环境变量请显式设置为 `true`）。
- `mcpctl`（BREAKING）：`--trust` 现在需要 `--yes-trust`；`--allow-host` 默认启用 DNS 校验（可用 `--no-dns-check` 关闭）；`--config` 默认要求在 `--root` 内（可用 `--allow-config-outside-root` 覆盖）。
- Docs: clarify lifecycle shutdown guidance for `disconnect/take_*`, and note Windows stdout_log limitations.
- `mcp-kit`（BREAKING）：`Manager::{connect_io, connect_jsonrpc}` 现在默认要求 `TrustMode::Trusted`；如需显式绕过可用 `*_unchecked` 变体（用于测试/受控环境）。
- `mcp-kit`（BREAKING）：外部兼容格式中 `sse_url`/`http_url` 现在要求成对出现；单独设置会 fail-closed（单端点请用 `url`）。
- `mcp-kit`：`Manager` 的 request/notify 错误上下文现在包含 `server=<name>`，便于多 server 场景排查。
- `mcp_kit::mcp`（BREAKING）：`Role` 反序列化现在支持未知值（落到 `Role::Other(String)`），提升协议演进鲁棒性。
- `mcp-jsonrpc`：streamable_http 的桥接错误默认不再回显 HTTP body 预览，并对网络错误中的 URL 做脱敏处理（减少 secrets 泄露风险）。
- `Config::load` 默认路径发现：`./.mcp.json` / `./mcp.json`。
- `mcpctl` 现在需要 `--features cli` 构建（避免 library 依赖方被迫引入 clap）。
- `mcp_kit::Manager` 默认 `TrustMode::Untrusted`：拒绝 `transport=stdio|unix`；`streamable_http` 仅允许 `https` 且非 localhost/私网目标，并拒绝发送敏感 header/读取 env secrets 用于认证；需显式 `with_trust_mode(TrustMode::Trusted)` 覆盖。
- `mcp_kit::Manager` 支持自定义 untrusted 下的 `streamable_http` 出站策略：`with_untrusted_streamable_http_policy(UntrustedStreamableHttpPolicy)`。
- `mcpctl` 默认不信任本地配置：本地 stdio/unix 或需要读取 env secrets 的远程 server 需要 `--trust`。
- `mcp-jsonrpc` 增加 DoS 防护：限制单条消息大小并使用有界队列缓存 server→client 的 requests/notifications。
- `mcp-jsonrpc`：无参 requests/notifications 不再发送 `"params": null`（会省略 `params`）；新增 `Client::request_optional`。
- `mcp-jsonrpc`：server→client request 的 `id` 非法时会返回 `-32600 Invalid Request`（`id=null`），不再静默丢弃。
- `mcp-jsonrpc`（BREAKING）：`ClientHandle::respond_error_raw_id` 改为 crate 内部 API（`pub(crate)`），不再对外暴露。
- `mcp-jsonrpc`：`streamable_http` 的 SSE connect 会校验 `Content-Type: text/event-stream`（大小写不敏感）；POST 成功响应会校验 JSON `Content-Type` 与 JSON body，避免 pending 悬挂；HTTP 响应过大时会对对应 request 返回 error。
- `mcp-jsonrpc`：`streamable_http` 的 POST 会发送 `Accept: application/json, text/event-stream`；GET SSE 断开/失败会关闭 client 并 fail fast（避免静默丢失推送）。
- `mcp-jsonrpc`：`[DONE]` 只用于结束 POST 返回 SSE 的响应流；主 SSE（GET）不会把 `[DONE]` 当作断开信号。
- `mcp-jsonrpc`（BREAKING）：server→client 的 `Notification/IncomingRequest` 现在用 `Option<serde_json::Value>` 表达 `params`（保留 “省略 vs null” 语义）。
- `mcp-kit`：`transport=unix|streamable_http` 现在只要配置里出现 `argv` 字段（即使为空数组）也会被拒绝。
- `mcp-kit`：当 transport 发生 I/O/协议层错误时会自动清理连接缓存（下次请求会重新连接）。
- `mcp-kit`（BREAKING）：`Manager` 的 `is_connected/connected_server_names` 现在会做连接存活性检查并在必要时清理失活连接；因此签名改为 `&mut self`。`*_connected` 系列方法也改为 `&mut self`，以便在 I/O/协议错误时自动 `disconnect`。
- `mcp-kit`：Untrusted 下的 `streamable_http` 额外拒绝 `*.localdomain` 与单标签 host（不含 `.`），降低本地/企业网搜索域解析导致的 SSRF 风险。
- `mcp-kit`：`stdout_log.path` 现在拒绝包含 `..` 段（fail-closed），避免路径穿越。
- `mcp-kit`：`mcp.json/.mcp.json` 文件大小增加 4MiB 上限（fail-closed），避免异常配置导致内存放大。
- `mcp-jsonrpc`（BREAKING）：`Client::wait` 现在返回 `Result<Option<ExitStatus>, Error>`；对无 child 的 client（`connect_io/unix/streamable_http`）返回 `Ok(None)`。
- `mcp-kit`（BREAKING）：`ServerConfig` 新增 `sse_url/http_url` 字段以支持 streamable_http 分离 URL。
- `mcp-kit`（BREAKING）：`UntrustedStreamableHttpPolicy` 新增 `dns_check` 字段（默认关闭），用于可选启用 hostname DNS 校验。
- `mcp_kit::mcp`（BREAKING）：无参请求/通知的 `Params` 改为 `()`；部分 list 请求的 `Params` 由 `Option<...>` 改为必填结构体；`Result` type alias 弃用，改用 `JsonValue`（或 `serde_json::Value`）。
- `mcp_kit::mcp`（BREAKING）：`ToolInputSchema/ToolOutputSchema` 现在会保留未知 JSON Schema 字段（`flatten` 到 `extra`）。
- `mcp-kit`：`Session/Manager` 的无参请求不再产生 `"params": null`；typed request 的 (de)serialize 错误包含 method/server；`initialize` 会检测 `protocolVersion` mismatch。
- `mcp-kit`（BREAKING）：server→client 的 `ServerRequestContext/ServerNotificationContext` 现在用 `Option<serde_json::Value>` 表达 `params`（保留 “省略 vs null” 语义）。
- `mcp-jsonrpc` 的 `streamable_http` 增加超时能力：默认 connect timeout=10s；可选 per-request timeout（`mcp-kit` 会用 `Manager` 的 per-request timeout 进行设置）。
- `mcp-jsonrpc` 的 `streamable_http` 默认不跟随 HTTP redirects（减少 SSRF 风险），可通过 `StreamableHttpOptions.follow_redirects` 显式开启。
- `mcp-jsonrpc` 的 stdout 旋转日志支持保留上限：`StdoutLog.max_parts`（`mcp-kit` 配置字段 `servers.<name>.stdout_log.max_parts`）。
- Docs: add runnable example `crates/mcp-kit/examples/minimal_client.rs` and reference it from `docs/examples.md`.
- Docs: clarify `StreamableHttpOptions.request_timeout` semantics in `docs/jsonrpc.md`.
- Docs: document split `sse_url/http_url`, `--dns-check`, and updated `[DONE]` semantics for streamable_http.
- Docs: expand GitBook-style documentation under `docs/` and add `CONTRIBUTING.md`.
- Docs: link each transport to runnable examples (`docs/transports.md`).
- Docs: add `docs/book.toml` (mdbook) and `llms.txt` / `docs/llms.txt` (single-file doc bundle), plus a pre-commit freshness check.
- Docs: refresh `docs/README.md` with a 1-minute copy/paste quickstart (now uses typed `tools/list` request to match runnable examples).
- Docs: add a minimal `Cargo.toml` dependency snippet to the 1-minute quickstart so the Rust example compiles.
- Docs: prefer the repo-root `llms.txt` in `docs/llms.md` usage instructions.
- Docs: add a safety note for `connect_jsonrpc`/custom `StreamableHttpOptions` to avoid bypassing Untrusted policy by accident.
- Docs: document `ServerConfig::streamable_http_split(...)` in the API reference.
- Docs: expand the library guide with a capabilities + server→client request handler snippet.
- Docs: clarify migration notes for `Manager` `&mut self` APIs, `Client::wait` `Option<ExitStatus>`, Untrusted host restrictions, stdio `inherit_env` baseline env allowlist, and `mcpctl list-servers` secret-safe output.
- Docs/Examples: align `--allow-localhost` wording across troubleshooting/transports and `client_with_policy` help output.
- Docs: make `docs/SUMMARY.md` mdbook-compatible and add section landing pages (`docs/guides.md`, `docs/reference.md`, `docs/more.md`).
- Docs: clarify `stdout_log.max_parts` semantics for `mcp.json` vs Rust API.
- githooks: if `mdbook` is installed, pre-commit now runs `mdbook build docs` when docs are staged, to catch rendering issues early.
- CI: add GitHub Actions workflow (ubuntu/macos/windows) to run fmt/test/clippy/mdbook/llms checks, deriving toolchain from `Cargo.toml` `rust-version`.
- `mcp-kit`：`mcp.json v1` 中 `http_headers` 现在也接受别名字段 `headers`（便于复用 Cursor 等配置片段）。
- `mcpctl list-servers` 默认不输出 stdio `argv` 明文（避免把 token/key 打到终端/CI）；可用 `--show-argv` 显式开启。
- `dns_check`（`--dns-check`）支持可配置 DNS timeout，并默认 fail-closed（失败直接拒绝连接）；如确实需要可显式开启 fail-open，并同步更新文档说明。
- `mcp-jsonrpc`：移除未使用的 `anyhow` 依赖，保持依赖最小化。

### Fixed
- `mcp-jsonrpc`：streamable_http POST bridge 在收到无效 JSON 时会 fail-fast 关闭连接，避免 pending request 无限悬挂。
- `mcp-jsonrpc`：当 server→client request 的 `jsonrpc` 版本非法但 `id` 合法时，`-32600 Invalid Request` 现在会回显原始 `id`（而不是 `null`），保持 JSON-RPC 2.0 相关性语义。
- `mcp-jsonrpc`：补齐 `streamable_http` 的回归覆盖（`mcp-session-id` 复用/更新、POST 返回 SSE + `[DONE]`、非 JSON `Content-Type` 的错误桥接）。
- `mcp-jsonrpc`：当入站消息包含 `method` 但类型非法时，会返回 `-32600 Invalid Request`（若有 `id`）并避免误当作 response 消费 pending。
- `mcp-jsonrpc`：`streamable_http` 的 HTTP 200 + 空 JSON body（非 202）现在会桥接为 `-32000` error，避免 request 悬挂。
- `mcp-jsonrpc`：`streamable_http` 的 `Content-Type` 校验不再做额外字符串分配（小幅减少 hot path 开销）。
- Tests: add regression coverage for `streamable_http` `Content-Type` parsing helpers.
- `mcp-kit`：对无 child 的连接（unix/streamable_http）会检查 JSON-RPC client closed 状态并清理缓存，避免复用失活连接。
- `mcp-kit`：当 `initialize` 失败时会自动 abort 已挂载的 server→client handler tasks，避免遗留后台任务。
- `mcp-kit`：`ProtocolVersionCheck` / `ProtocolVersionMismatch` 现已从 crate root 重新导出（可直接用 `mcp_kit::ProtocolVersionCheck`）。
- `mcp-kit`：`protocol_version_mismatches` 在 `Warn` 模式下会按 server 去重更新，避免长期运行时无界增长。
- `mcp-kit`：Cursor/Claude style 外部配置中 `type=http|sse` 与推断 transport 冲突时会 fail-closed 报错。
- `mcp-kit`：当文件包含 `mcpServers` wrapper（例如 Claude plugin.json）时，`Config::load` 现在会优先按 wrapper 解析，而不是误判为 `mcp.json v1`。
- `mcp-kit`：`mcpServers` 现在支持 string（指向 `./.mcp.json` 等文件路径），用于兼容 Claude plugin.json 的 `mcpServers` path 写法。
- `mcp-kit`：配置加载读取做有界读取（防止特殊文件/无限流导致 hang），并要求配置文件为 regular file。
- `mcp-kit`：配置读取在 unix 下使用 `O_NOFOLLOW` 并在 open 后再校验类型/大小，降低 TOCTOU 风险；缺失文件的 best-effort 读取在 open 阶段遇到 `NotFound` 会视为缺失。
- `mcp-kit`：Trusted mode 下会展开 `${VAR}` 占位符（stdio `argv/env`、streamable_http `url/http_headers`），并支持 `${CLAUDE_PLUGIN_ROOT}` / `${MCP_ROOT}`。
- `mcp-kit`：untrusted 下的 streamable_http host 检查/allowlist 匹配逻辑不再做额外字符串分配（小幅减少 hot path 开销）。
- `mcp-kit`：Trusted mode 下的 argv/url 占位符展开与 URL 校验失败不会回显原始明文（避免 token/secret 泄露到错误链）。
- `mcp-jsonrpc`：`Client::wait()` 现在会关闭写端/child stdin，避免“等待 stdin EOF 才退出”的 stdio server 造成 hang；reader EOF/IO error 也会触发关闭写端。
- `mcp-jsonrpc`：stdout_log 打开时会拒绝包含 symlink 组件的路径，避免意外写入到不安全位置。
- `mcp-jsonrpc`：unix 下 stdout_log 打开使用 `O_NOFOLLOW`（缓解 TOCTOU symlink replacement），并调整相关测试与行为说明。
- `mcp-kit`：`mcpServers: \"path\"` 间接引用读取新增 root 边界与 canonicalize 校验，避免通过 symlink 逃逸读取 `--root` 外文件。
- `mcp-kit`：解析 `mcpServers` 间接引用时缓存 canonical root，减少重复 canonicalize 开销。
- `mcp-kit`：host allowlist 匹配逻辑不再做额外字符串分配（小幅减少 hot path 开销）。
- `mcp-kit`：外部配置格式（`type=http|sse`）校验不再做额外字符串分配（小幅减少 hot path 开销）。
- `mcp-kit`：外部配置解析对兼容字段的处理更明确（不影响行为，仅提升可读性）。
- scripts: 加固 `scripts/gen-llms-txt.sh` 路径解析，拒绝路径穿越/符号链接导致的本机文件打包泄露风险。
- scripts: `scripts/gen-llms-txt.sh` 在缺少 `realpath` 时允许回退到 `python`（提升在 Windows CI 环境中的兼容性）。
- Examples: `in_memory_duplex` 现在用 `Url::from_directory_path` 生成正确的目录 `file://` URI（支持空格/非 ASCII 的 percent-encoding）。
- Examples: `minimal_client` / `client_with_policy` 默认省略 `tools/list` 的空 `params`（与 `Manager::list_tools`/`Session::list_tools` 语义一致）。
- Examples: `streamable_http_split` 默认省略 `tools/list` 的空 `params`，提升对严格 server 的兼容性。
- Docs: `minimal_client` 补充 Untrusted 默认出站限制提示，并指向 `docs/security.md` 与 `client_with_policy` 的 `--allow-*` 用法。
- Tests: stabilize flaky `streamable_http_allows_initial_sse_405_and_retries_after_202`.
- `mcp-kit`：`minimal_client` 在选择非 `streamable_http` server 时会给出清晰提示并指向 `--trust`/`client_with_policy`，减少本地 stdio/unix 的误用困惑。
