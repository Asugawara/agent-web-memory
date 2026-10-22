#!/usr/bin/env bash
# Documented AWM_* names must be read by the server. scripts/check.sh runs this as its docs-env step.
set -euo pipefail

cd "$(dirname "$0")/.."

# RVT3 F1, RVT3v V5: every AWM_* name the operator-facing text mentions is read by the server, set
# by the image or keyed in the compose file. Only the read sites count, not a comment that names
# a variable: the quoted names in `cli/serve.rs` outside `//` lines (`env("AWM_X")`,
# `from_env(.., "AWM_X")`), `ENV AWM_X=` in the Dockerfile (continuation lines joined) and
# `AWM_X:` keys in the compose file. A documented name that ends in `_` (`AWM_ACME_*`) is a
# prefix of a read name. Names of other tools are allow-listed.
doc_files=(docs/self-host.md deploy README.md README.ja.md)
doc_names="$(grep -rhoE 'AWM_[A-Z0-9_]+' "${doc_files[@]}" | sort -u)"
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
    AWM_HOME | AWM_SMOKE_* | AWM_IMAGE | AWM_BIN | AWM_INSTALL_*) continue ;;
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
