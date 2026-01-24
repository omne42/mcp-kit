# Changelog

本项目的所有重要变更都会记录在这个文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Added
- `pm-jsonrpc`：最小 JSON-RPC client（stdio / unix），支持 notifications 与可选 stdout 旋转落盘。
- `pm-mcp-kit`：`mcp.json`（v1）解析、stdio MCP server 启动与连接缓存管理（`Config/Manager/Connection`）。
- `mcpctl`：基于配置的 MCP CLI（list-servers/list-tools/list-resources/list-prompts/call）。
