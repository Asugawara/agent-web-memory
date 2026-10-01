#!/usr/bin/env bash
# Local CI: run from the repository root.
set -euo pipefail

echo "step: fmt"
cargo fmt --all --check

echo "step: clippy"
cargo clippy --workspace --all-targets --locked -- -D warnings

echo "step: test"
cargo test --workspace --locked

echo "step: no-network"
tree_out="$(cargo tree -p agent-web-memory -e normal)"
if echo "$tree_out" | grep -E '(^|[^a-z_-])(reqwest|hyper|ureq|curl|isahc|attohttpc|surf) v' >/dev/null; then
  echo "no-network: FAILED (HTTP client crate found)"
  exit 1
fi
echo "no-network: ok"

echo "step: shellcheck"
if command -v shellcheck >/dev/null 2>&1; then
  files=()
  [ -f plugin/hooks/awm-hook ] && files+=(plugin/hooks/awm-hook)
  for f in scripts/*.sh; do
    [ -f "$f" ] && files+=("$f")
  done
  shellcheck "${files[@]}"
  echo "shellcheck: ok"
else
  echo "shellcheck: not installed, skipped"
fi

echo "check: all steps passed"
