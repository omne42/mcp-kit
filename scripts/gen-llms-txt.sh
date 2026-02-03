#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
docs_dir="$repo_root/docs"
summary="$docs_dir/SUMMARY.md"
out_docs="$docs_dir/llms.txt"
out_root="$repo_root/llms.txt"

mode="write"
case "${1:-}" in
  "" ) ;;
  --check ) mode="check" ;;
  * )
    echo "usage: $0 [--check]" >&2
    exit 2
    ;;
esac

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

if [[ "$mode" == "check" ]]; then
  if [[ ! -f "$out_docs" || ! -f "$out_root" ]]; then
    echo "error: missing llms.txt outputs; run ./scripts/gen-llms-txt.sh" >&2
    exit 1
  fi
  if ! diff -q "$tmp" "$out_docs" >/dev/null; then
    echo "error: docs/llms.txt is out of date; run ./scripts/gen-llms-txt.sh" >&2
    exit 1
  fi
  if ! diff -q "$tmp" "$out_root" >/dev/null; then
    echo "error: llms.txt is out of date; run ./scripts/gen-llms-txt.sh" >&2
    exit 1
  fi
  echo "llms.txt is up to date"
  exit 0
fi

cp "$tmp" "$out_docs"
cp "$tmp" "$out_root"
echo "wrote $out_docs"
echo "wrote $out_root"
