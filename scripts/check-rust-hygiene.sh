#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

staged_rs_files="$(git -C "$repo_root" diff --cached --name-only --diff-filter=ACMR -- '*.rs' || true)"
if [[ -z "${staged_rs_files//[[:space:]]/}" ]]; then
  exit 0
fi

# Check only newly-added staged Rust lines, so existing debt does not block unrelated work.
git -C "$repo_root" diff --cached -U0 -- '*.rs' | awk '
function is_library_file(path) {
  return path ~ /^crates\/[^/]+\/src\// \
    && path !~ /\/tests\// \
    && path !~ /\/examples\// \
    && path !~ /\/benches\// \
    && path !~ /\/tests\.rs$/ \
    && path !~ /\/src\/tests\.rs$/ \
    && path !~ /\/src\/.*_tests\.rs$/ \
    && path !~ /\/src\/test_.*\.rs$/;
}

BEGIN {
  err_count = 0;
  file = "";
  line_no = 0;
}

/^\+\+\+ b\// {
  file = substr($0, 7);
  next;
}

/^@@/ {
  if (match($0, /\+([0-9]+)/, m)) {
    line_no = m[1] - 1;
  }
  next;
}

/^\+/ && $0 !~ /^\+\+\+/ {
  line_no++;
  line = substr($0, 2);
  if (!is_library_file(file)) {
    next;
  }

  if (line ~ /\.unwrap\(/ || line ~ /\.expect\(/) {
    if (line !~ /pre-commit:[[:space:]]*allow-unwrap/) {
      printf("rust-hygiene: %s:%d: disallow unwrap/expect in library code\n", file, line_no) > "/dev/stderr";
      err_count++;
    }
  }

  if (line ~ /let[[:space:]]+_[[:space:]]*=/) {
    if (line !~ /pre-commit:[[:space:]]*allow-let-underscore/) {
      printf("rust-hygiene: %s:%d: avoid `let _ = ...` in library code; handle or document intent explicitly\n", file, line_no) > "/dev/stderr";
      err_count++;
    }
  }
  next;
}

/^ / {
  line_no++;
  next;
}

END {
  if (err_count > 0) {
    print "" > "/dev/stderr";
    print "Hints:" > "/dev/stderr";
    print "- Propagate with `?`, or branch on `is_err()` / `if let Err(e) = ...`." > "/dev/stderr";
    print "- For intentional exceptions, add an inline marker comment:" > "/dev/stderr";
    print "  - `// pre-commit: allow-unwrap`" > "/dev/stderr";
    print "  - `// pre-commit: allow-let-underscore`" > "/dev/stderr";
    exit 1;
  }
}
'
