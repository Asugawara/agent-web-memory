#!/usr/bin/env bash
# Regression bench on the frozen database (plan-v2 §3.6). Run from the repository root.
# Needs the git-ignored corpus in spikes/data/ (see docs/reports/P2.md).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
spikes="${AWM_SPIKES_DIR:-$root/spikes}"
[ -d "$spikes" ] || spikes=/path/to/agent-web-memory/spikes

cargo build --release --locked -p agent-web-memory --features bench

if [ ! -f "$spikes/data/query-ids.csv" ]; then
  cargo run --release --manifest-path "$spikes/match-bench/Cargo.toml" -- pool-ids
fi

set +e
"$root/target/release/awm" bench-check \
  --db "$spikes/data/frozen/awm.db" \
  --labels "$spikes/match-bench/labels/judged.csv" \
  --query-ids "$spikes/data/query-ids.csv" \
  --thresholds "$root/bench/thresholds.toml" \
  "$@"
code=$?
set -e
exit "$code"
