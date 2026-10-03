#!/usr/bin/env bash
# Post-tool hook replay (docs/reports/PERF1.md): takes the last N events of a database COPY,
# builds a PostToolUse payload for each (tool, query or url + prompt, session, agent, tool_use_id)
# and runs `awm hook post-tool` once per payload against a fresh copy of that database. Prints the
# wall time of the process and the `hook_run` total_ms / search_ms of the replay, and writes the
# note ids each run chose, so two binaries can be compared (`diff` of the ids files must be empty).
#
#   scripts/perf-replay.sh --db /path/to/copy/awm.db [--bin target/release/awm] [--n 300]
#                          [--passes 2] [--ids ids.tsv] [--sessions fresh|live]
#
# `--sessions fresh` (default) gives every trigger its own session, so no cap or shown-id state
# hides a match; `live` keeps the recorded sessions and agents (most runs then end `skipped`).
#
# Never point --db at a live database: the script copies it, and the hooks run against the copy
# through AWM_HOME. The copy must be at the binary's schema version (`AWM_HOME=<dir> awm doctor`
# upgrades a copy). Pass 1 starts a fresh copy (empty SQLite page cache in every process, the
# operating system's file cache warm from the copy); later passes repeat the triggers on a fresh
# copy again. Only counts, timings and event ids are printed.
set -euo pipefail

db=""
bin=""
n=300
passes=2
ids_out=""
sessions="fresh"
while [ $# -gt 0 ]; do
  case "$1" in
    --db) db="$2"; shift 2 ;;
    --bin) bin="$2"; shift 2 ;;
    --n) n="$2"; shift 2 ;;
    --passes) passes="$2"; shift 2 ;;
    --ids) ids_out="$2"; shift 2 ;;
    --sessions) sessions="$2"; shift 2 ;;
    *) echo "usage: $0 --db COPY.db [--bin awm] [--n 300] [--passes 2] [--ids FILE] [--sessions fresh|live]" >&2; exit 2 ;;
  esac
done
if [ -z "$db" ] || [ ! -f "$db" ]; then
  echo "perf-replay: --db must name a database copy" >&2
  exit 2
fi
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin="${bin:-$root/target/release/awm}"

python3 - "$bin" "$db" "$n" "$passes" "$ids_out" "$sessions" <<'PY'
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

bin_path, db, n, passes, ids_out = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
sessions = sys.argv[6]


def pct(sorted_values, p):
    return sorted_values[min(len(sorted_values) - 1, int(round(p * (len(sorted_values) - 1))))]


def stats(label, values):
    values = sorted(values)
    print("%-26s n=%d p50=%.1f p95=%.1f max=%.1f mean=%.1f" % (
        label, len(values), pct(values, 0.5), pct(values, 0.95), values[-1], sum(values) / len(values)))


src = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
rows = src.execute(
    "SELECT tool, query, url, fetch_prompt, session_id, agent_id, agent_type, tool_use_id FROM "
    "(SELECT * FROM event ORDER BY id DESC LIMIT ?) ORDER BY id", (n,)).fetchall()
src.close()


def payload(r, i):
    tool, query, url, prompt, session, agent, agent_type, tool_use_id = r
    tool_input = {"query": query} if tool == "WebSearch" else {"url": url, "prompt": prompt or ""}
    p = {
        "hook_event_name": "PostToolUse",
        "session_id": session if sessions == "live" else "perf-%d" % i,
        "cwd": "/perf/replay",
        "tool_name": tool,
        "tool_input": tool_input,
        "tool_response": {},
        "tool_use_id": tool_use_id,
    }
    if agent:
        p["agent_id"] = agent
        p["agent_type"] = agent_type or "subagent"
    return p


payloads = [payload(r, i) for i, r in enumerate(rows)]
ids_lines = None
for k in range(passes):
    home = tempfile.mkdtemp(prefix="perf-replay-")
    try:
        os.chmod(home, 0o700)
        shutil.copyfile(db, os.path.join(home, "awm.db"))
        c0 = sqlite3.connect(os.path.join(home, "awm.db"))
        base_max = c0.execute("SELECT COALESCE(MAX(id), 0) FROM injection").fetchone()[0]
        base_run = c0.execute("SELECT COALESCE(MAX(id), 0) FROM hook_run").fetchone()[0]
        c0.close()
        env = dict(os.environ, AWM_HOME=home)
        walls = []
        for p in payloads:
            t = time.perf_counter()
            subprocess.run([bin_path, "hook", "post-tool"], input=json.dumps(p).encode(),
                           capture_output=True, env=env, check=True)
            walls.append((time.perf_counter() - t) * 1000.0)
        conn = sqlite3.connect(os.path.join(home, "awm.db"))
        # The replayed runs are the post-tool rows added since the copy.
        runs = conn.execute(
            "SELECT total_ms, search_ms, outcome FROM hook_run WHERE hook = 'post-tool' AND id > ?",
            (base_run,)).fetchall()
        outcomes = {}
        for _, _, o in runs:
            outcomes[o] = outcomes.get(o, 0) + 1
        print("pass %d: %d runs, outcomes %s" % (k + 1, len(runs), json.dumps(outcomes, sort_keys=True)))
        stats("  wall ms (process)", walls)
        stats("  hook_run total_ms", [r[0] for r in runs])
        stats("  hook_run search_ms", [r[1] for r in runs if r[1] is not None])
        lines = []
        for inj_id, tool_use_id in conn.execute(
                "SELECT id, tool_use_id FROM injection WHERE id > ? ORDER BY id", (base_max,)).fetchall():
            items = conn.execute(
                "SELECT event_id FROM injection_item WHERE injection_id = ? ORDER BY position",
                (inj_id,)).fetchall()
            lines.append("%s\t%s" % (tool_use_id, ",".join(str(i[0]) for i in items)))
        conn.close()
        if ids_lines is None:
            ids_lines = lines
    finally:
        shutil.rmtree(home, ignore_errors=True)

if ids_out:
    with open(ids_out, "w") as f:
        f.write("\n".join(ids_lines or []) + "\n")
    print("ids: %d injections written to %s" % (len(ids_lines or []), ids_out))
PY
