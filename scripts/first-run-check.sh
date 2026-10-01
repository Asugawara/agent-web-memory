#!/usr/bin/env bash
# First-run check (plan-v2 §2.1): temporary AWM_HOME, synthetic projects dir (the T6
# fixtures). Runs init --record --import --yes, search, stats and one post-tool hook
# replay; prints each step's wall time. Exits 0 only when the awm-side total is
# <= LIMIT_S seconds (default 60) and every step succeeded.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

limit_s="${LIMIT_S:-60}"
projects="crates/awm/tests/fixtures/projects"
fixture="crates/awm/tests/fixtures/hooks/PostToolUse-WebFetch-plugin-3.json"

cargo build --release --locked -p agent-web-memory >/dev/null 2>&1
bin="${AWM_BIN:-$root/target/release/awm}"

home="$(mktemp -d)"
trap 'rm -rf "$home"' EXIT
export AWM_HOME="$home/awm"

now_ms() { python3 -c 'import time; print(int(time.time()*1000))'; }

total=0
fail=0
printf '%-34s %10s  %s\n' step ms status
step() { # name, command...
  local name="$1" t0 t1 ms st=ok
  shift
  t0="$(now_ms)"
  if ! "$@" >"$home/out.txt" 2>&1; then st=FAILED; fail=1; fi
  t1="$(now_ms)"
  ms=$((t1 - t0))
  total=$((total + ms))
  printf '%-34s %10d  %s\n' "$name" "$ms" "$st"
  if [ "$st" = FAILED ]; then sed 's/^/    /' "$home/out.txt"; fi
}

replay() { "$bin" hook post-tool --plugin-version 0.1.0 <"$fixture"; }

step "awm init --record --import --yes" "$bin" init --record --import --yes --projects "$projects"
step "awm search" "$bin" search "sqlite fts5"
step "awm stats" "$bin" stats
step "awm hook post-tool (replay)" replay

printf '%-34s %10d\n' "awm-side total" "$total"
if [ "$fail" -ne 0 ]; then
  echo "FAIL: a step failed"
  exit 1
fi
if [ "$total" -gt $((limit_s * 1000)) ]; then
  echo "FAIL: awm-side total above ${limit_s} s"
  exit 1
fi
echo "OK: awm-side total within ${limit_s} s"
