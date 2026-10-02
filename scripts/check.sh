#!/usr/bin/env bash
# Local CI: run from the repository root.
set -euo pipefail

echo "step: fmt"
cargo fmt --all --check

echo "step: clippy"
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy -p agent-web-memory --all-targets --locked --features bench -- -D warnings
cargo clippy -p agent-web-memory --all-targets --locked --features sync,serve -- -D warnings
cargo build -p agent-web-memory --locked --features sync,serve

echo "step: test"
cargo test --workspace --locked
cargo test -p agent-web-memory --locked --features bench

echo "step: no-network"
tree_out="$(cargo tree -p agent-web-memory -e normal)"
if echo "$tree_out" | grep -E '(^|[^a-z_-])(reqwest|hyper|ureq|curl|isahc|attohttpc|surf) v' >/dev/null; then
  echo "no-network: FAILED (HTTP client crate found)"
  exit 1
fi
echo "no-network: ok"

# plan-v3-team §4.1 items 2-4: the HTTP crates of each feature set.
echo "step: no-network (sync)"
sync_tree="$(cargo tree -p agent-web-memory --features sync -e normal --prefix none)"
if ! echo "$sync_tree" | grep -E '^ureq v' >/dev/null; then
  echo "no-network (sync): FAILED (ureq missing)"
  exit 1
fi
if echo "$sync_tree" | grep -E '^(tokio|hyper|hyper-util|reqwest|object_store) v' >/dev/null; then
  echo "no-network (sync): FAILED (tokio, hyper, reqwest or object_store present)"
  exit 1
fi
echo "no-network (sync): ok"

echo "step: no-network (sync,serve)"
full_tree="$(cargo tree -p agent-web-memory --features sync,serve -e normal --prefix none)"
http_crates="$(echo "$full_tree" | grep -E '^(reqwest|hyper|ureq|curl|isahc|attohttpc|surf)[a-z_-]* v' | sed 's/ v.*//' | sort -u)"
unexpected="$(echo "$http_crates" | grep -vxE 'ureq|ureq-proto|hyper|hyper-util|hyper-rustls|reqwest' || true)"
if [ -n "$unexpected" ]; then
  echo "no-network (sync,serve): FAILED (unexpected HTTP crates: $unexpected)"
  exit 1
fi
echo "no-network (sync,serve): ok"

echo "step: modules"
if grep -rnE 'sync::(http|push|pull)|ureq|reqwest|hyper|tokio|awm_server|object_store|instant_acme|tokio_postgres' \
  crates/awm/src/hook crates/awm/src/matching crates/awm/src/render.rs crates/awm/src/gate.rs; then
  echo "modules: FAILED (network code in a hook, matching or render module)"
  exit 1
fi
echo "modules: ok"

echo "step: licenses"
if command -v cargo-deny >/dev/null 2>&1; then
  cargo deny check licenses
  echo "licenses: ok"
else
  echo "licenses: cargo-deny not installed, skipped"
fi

echo "step: cloud-isolation"
if [ -d crates/awm-cloud ]; then
  # The inverted tree lists awm-cloud alone when no crate depends on it.
  if [ "$(cargo tree -i awm-cloud -e normal --prefix none | wc -l)" -gt 1 ]; then
    echo "cloud-isolation: FAILED (an Apache-2.0 crate depends on awm-cloud)"
    exit 1
  fi
fi
echo "cloud-isolation: ok"

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
