#!/usr/bin/env bash
# Hook latency: replays each PostToolUse fixture 200 times through
# `target/release/awm hook post-tool` against a seeded temporary database and
# prints p50 and p95 wall milliseconds. Fails when a p95 is above 100 ms.
#
# Seeding: `awm init --record --import --projects <dir>` when the T6 fixtures
# directory exists (best effort), then 3,000 synthetic records and near-copies of
# the fixtures through the library (the ignored test `seed_latency_db`).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

runs="${RUNS:-200}"
limit_ms="${P95_LIMIT_MS:-100}"
fixtures_dir="crates/awm/tests/fixtures/hooks"
projects_dir="crates/awm/tests/fixtures/projects"

cargo build --release --locked -p agent-web-memory
bin="$root/target/release/awm"

home="$(mktemp -d)"
trap 'rm -rf "$home"' EXIT
export AWM_HOME="$home"

if [ -d "$projects_dir" ]; then
  "$bin" init --record --import --projects "$projects_dir" >/dev/null 2>&1 \
    || echo "note: awm init could not import $projects_dir; seeding through the library only"
fi

AWM_SEED_HOME="$home" cargo test --release --locked -p agent-web-memory \
  --test hooks_e2e seed_latency_db -- --ignored --exact >/dev/null

python3 - "$bin" "$runs" "$limit_ms" "$fixtures_dir"/PostToolUse-*.json <<'PY'
import json
import os
import subprocess
import sys
import time

bin_path, runs, limit = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
files = sys.argv[4:]


def pct(sorted_values, p):
    return sorted_values[min(len(sorted_values) - 1, int(round(p * (len(sorted_values) - 1))))]


def call(payload):
    t = time.perf_counter()
    out = subprocess.run(
        [bin_path, "hook", "post-tool"],
        input=json.dumps(payload).encode(),
        capture_output=True,
        env=os.environ,
        check=True,
    )
    return (time.perf_counter() - t) * 1000.0, out.stdout


failed = False
for path in files:
    with open(path) as f:
        base = json.load(f)
    call(base)  # warm-up: page cache and the first start of a new binary
    times, injected = [], 0
    for i in range(runs):
        payload = dict(base, session_id=f"latency-{i}", tool_use_id=f"toolu_latency_{os.path.basename(path)}_{i}")
        payload.pop("agent_id", None)
        ms, stdout = call(payload)
        times.append(ms)
        injected += 1 if stdout.strip() else 0
    times.sort()
    p50, p95 = pct(times, 0.50), pct(times, 0.95)
    verdict = "ok" if p95 <= limit else "TOO SLOW"
    print(f"post-tool {os.path.basename(path)}: n={runs} injected={injected} p50={p50:.1f} ms p95={p95:.1f} ms [{verdict}]")
    failed = failed or p95 > limit

if failed:
    print(f"hook-latency: FAILED (p95 above {limit:.0f} ms)")
    sys.exit(1)
print(f"hook-latency: ok (every p95 <= {limit:.0f} ms)")
PY
