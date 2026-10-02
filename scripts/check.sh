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
# awm-server with every feature (RVT2 M6): its tests are behind features (plan-v3-team §4.1, TM6),
# and the Postgres and ACME cases need AWM_TEST_PG_URL and PEBBLE_BIN. Without them those cases
# print a SKIP line and pass: counted here, a printed SKIP locally, a failure in CI.
server_log="$(mktemp)"
trap 'rm -f "$server_log"' EXIT
if ! cargo test -p awm-server --locked --features all -- --show-output >"$server_log" 2>&1; then
  cat "$server_log"
  echo "test (awm-server --features all): FAILED"
  exit 1
fi
grep -E '^ *Running |^test result:' "$server_log"
# Distinct tests (binary and name) whose output says that `$1` is not set.
skipped_cases() {
  awk -v var="$1" '
    /^ *Running / { bin = $2 }
    /^---- .* stdout ----$/ { name = $2 }
    index($0, var) && /SKIP|skipped/ && name != "" { seen[bin "/" name] = 1 }
    END { n = 0; for (k in seen) n++; print n }
  ' "$server_log"
}
if [ -z "${AWM_TEST_PG_URL:-}" ] || [ -z "${PEBBLE_BIN:-}" ]; then
  echo "SKIP: $(skipped_cases AWM_TEST_PG_URL) Postgres / $(skipped_cases PEBBLE_BIN) ACME cases not run (set AWM_TEST_PG_URL and PEBBLE_BIN)"
  if [ "${CI:-}" = "true" ]; then
    echo "test (awm-server): FAILED (CI must set AWM_TEST_PG_URL and PEBBLE_BIN)"
    exit 1
  fi
fi

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
# RVT3 F16, RVT3v V4: an allow-list by shape. In the hook-side sources every `sync::`, `team::` or
# `cli::` path (outside `std::` and `core::`) is `sync::spawn::...`, or `sync::spawn` ending a
# `use` (`;` or `}`); and no `use crate::sync as x`, `use crate::{.. team as x ..}` alias hides a
# name. The sync engine, the team code, the CLI and the HTTP client are out of reach.
# `hook_spawn::no_hook_source_reaches_the_network_modules` holds the same rule.
hook_side=(crates/awm/src/hook crates/awm/src/matching crates/awm/src/render.rs crates/awm/src/note.rs crates/awm/src/db.rs)
while IFS= read -r f; do
  flat="$(tr '\n' ' ' <"$f")"
  paths="$(printf '%s' "$flat" | sed -E 's/(std|core)::sync:://g; s/sync::spawn(::|;|\})//g')"
  if printf '%s' "$paths" | grep -qE '(sync|team|cli)::|ureq|crate::team|cli::sync' ||
    printf '%s' "$flat" | grep -qE 'crate::(sync|team|cli)[[:space:]]+as[[:space:]]|crate::\{[^}]*(sync|team|cli)[[:space:]]+as[[:space:]]'; then
    echo "modules: FAILED ($f reaches past sync::spawn: a sync::, team:: or cli:: path, an alias of one, or ureq)"
    exit 1
  fi
done < <(find "${hook_side[@]}" -name '*.rs')
echo "modules: ok"

# RVT3 F1, RVT3v V5: every AWM_* name the operator-facing text mentions is read by the server, set
# by the image or keyed in the compose file. Only the read sites count, not a comment that names
# a variable: the quoted names in `cli/serve.rs` outside `//` lines (`env("AWM_X")`,
# `from_env(.., "AWM_X")`), `ENV AWM_X=` in the Dockerfile (continuation lines joined) and
# `AWM_X:` keys in the compose file. A documented name that ends in `_` (`AWM_ACME_*`) is a
# prefix of a read name. Names of other tools are allow-listed.
echo "step: docs-env"
doc_names="$(grep -rhoE 'AWM_[A-Z0-9_]+' docs/self-host.md deploy README.md | sort -u)"
read_names="$(
  {
    grep -vE '^[[:space:]]*//' crates/awm/src/cli/serve.rs | grep -oE '"AWM_[A-Z0-9_]+"' | tr -d '"' || true
    awk '/^[[:space:]]*#/ { next } { line = cont ? line $0 : $0; if (sub(/\\$/, "", line)) { cont = 1 } else { print line; cont = 0 } }' Dockerfile |
      grep -E '^[[:space:]]*ENV[[:space:]]' | grep -oE 'AWM_[A-Z0-9_]+=' | tr -d '=' || true
    grep -vE '^[[:space:]]*#' deploy/compose/docker-compose.yml |
      grep -oE '^[[:space:]]*(-[[:space:]]*)?AWM_[A-Z0-9_]+[:=]' | grep -oE 'AWM_[A-Z0-9_]+' || true
  } | sort -u
)"
unknown=""
for name in $doc_names; do
  case "$name" in
    AWM_HOME | AWM_SMOKE_* | AWM_IMAGE | AWM_BIN) continue ;;
    *_) if printf '%s\n' "$read_names" | grep -q "^$name"; then continue; fi ;;
  esac
  if ! printf '%s\n' "$read_names" | grep -qx -- "$name"; then
    unknown="$unknown $name"
  fi
done
if [ -n "$unknown" ]; then
  echo "docs-env: FAILED (documented but not read by serve.rs, set by the Dockerfile or keyed in the compose file:$unknown)"
  exit 1
fi
echo "docs-env: ok"

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
