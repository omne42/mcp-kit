# llms.txt（给 LLM 用的一份“打包文档”）

有时你希望把仓库文档一次性喂给 LLM（例如 Cursor/Claude/ChatGPT）来做代码阅读、排障或生成配置。

为此本仓库提供：

- `docs/llms.txt`：把 `docs/` 下的 Markdown 文档按 `docs/SUMMARY.md` 的顺序拼接成一个文件，便于直接复制粘贴

## 如何使用

1. 打开 `docs/llms.txt`，全选复制。
2. 在你的 LLM 工具里粘贴，并告诉它：
   - 你正在使用 `mcp-kit`（Rust workspace）
   - 你希望它参考文档给出具体到文件/命令的建议

## 如何更新 / 生成

当你改动了 `docs/*.md` 或 `docs/SUMMARY.md`，运行：

```bash
./scripts/gen-llms-txt.sh
```

然后把更新后的 `docs/llms.txt` 一并提交。
