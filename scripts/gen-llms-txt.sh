#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
docs_dir="$repo_root/docs"
summary="$docs_dir/SUMMARY.md"
out="$docs_dir/llms.txt"

tmp="$(mktemp)"
cleanup() { rm -f "$tmp"; }
trap cleanup EXIT

{
  echo "# mcp-kit docs (llms.txt)"
  echo
  echo "This file is generated from the Markdown docs in \`docs/\`, following \`docs/SUMMARY.md\`."
  echo "It is meant to be pasted into LLM tooling (Cursor/Claude/ChatGPT) as a single context bundle."
  echo
  echo "Regenerate: \`./scripts/gen-llms-txt.sh\`"
} >"$tmp"

# Format: <title>\t<file>
while IFS=$'\t' read -r title file; do
  [[ -z "${file}" ]] && continue
  [[ "${file}" == "llms.md" ]] && continue

  path="$docs_dir/$file"
  if [[ ! -f "$path" ]]; then
    echo "error: missing doc file referenced from SUMMARY.md: $file" >&2
    exit 1
  fi

  {
    echo
    echo "---"
    echo
    echo "# ${title} (${file})"
    echo
    cat "$path"
  } >>"$tmp"
done < <(sed -n 's/.*\[\(.*\)\](\(.*\.md\)).*/\1\t\2/p' "$summary")

mv "$tmp" "$out"
echo "wrote $out"
