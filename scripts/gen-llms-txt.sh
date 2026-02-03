#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
docs_dir="$repo_root/docs"
summary="$docs_dir/SUMMARY.md"
out_docs="$docs_dir/llms.txt"
out_root="$repo_root/llms.txt"

die() {
  echo "error: $*" >&2
  exit 1
}

docs_real=""

realpath_compat() {
  local path="$1"
  if command -v realpath >/dev/null 2>&1; then
    realpath "$path"
    return
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$path"
    return
  fi
  die "realpath not found (need \`realpath\` or \`python3\`): $path"
}

ensure_no_symlink_components() {
  local path="$1"
  local cur=""

  if [[ "$path" == /* ]]; then
    cur="/"
    path="${path#/}"
  fi

  local IFS='/'
  # shellcheck disable=SC2206
  local parts=($path)
  for part in "${parts[@]}"; do
    [[ -z "$part" || "$part" == "." ]] && continue
    if [[ "$cur" == "/" ]]; then
      cur="/$part"
    elif [[ -z "$cur" ]]; then
      cur="$part"
    else
      cur="$cur/$part"
    fi

    if [[ -L "$cur" ]]; then
      die "path contains symlink component: $cur"
    fi
  done
}

doc_path_or_die() {
  local file="$1"

  [[ -n "$file" ]] || die "doc path must not be empty"
  [[ "$file" != /* ]] || die "doc path must be relative: $file"

  local IFS='/'
  # shellcheck disable=SC2206
  local parts=($file)
  for part in "${parts[@]}"; do
    [[ "$part" == ".." ]] && die "doc path must not contain \`..\` segments: $file"
  done

  local path="$docs_dir/$file"
  [[ -f "$path" ]] || die "missing doc file referenced from SUMMARY.md: $file"

  ensure_no_symlink_components "$path"

  local path_real
  path_real="$(realpath_compat "$path")"

  case "$path_real" in
    "$docs_real"/*) ;;
    *) die "doc path escapes docs/: $file (resolved to $path_real)" ;;
  esac

  printf '%s\n' "$path_real"
}

ensure_no_symlink_components "$docs_dir"
[[ -f "$summary" ]] || die "missing docs/SUMMARY.md"
[[ ! -L "$summary" ]] || die "docs/SUMMARY.md must not be a symlink"
docs_real="$(realpath_compat "$docs_dir")"

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

  path="$(doc_path_or_die "$file")"

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
