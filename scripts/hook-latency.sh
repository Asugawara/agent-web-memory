#!/usr/bin/env bash
# Hook latency: replays each PostToolUse fixture 200 times through
# `target/release/awm hook post-tool`, and the PreToolUse WebSearch fixture through
# `awm hook pre-fetch`, against a seeded temporary database and
# prints p50 and p95 wall milliseconds. Fails when a p95 is above 100 ms.
#
# Seeding: `awm init --record --import --projects <dir>` when the T6 fixtures
# directory exists (best effort), then 3,000 synthetic records and near-copies of
# the fixtures through the library (the ignored test `seed_latency_db`).
#
#   scripts/hook-latency.sh [--features sync,serve] [--team unroutable]
#
# `--features` builds (and seeds) with those cargo features, so the larger binary is measured.
# `--team unroutable` adds the team replay (plan-v3-team §9.4 TM13): the same hooks, interleaved,
# against a copy of the database without a team and one with `[team]` pointing at an unroutable
# server (192.0.2.1) and `team.sync_interval_s = 0`, so every session-start and capture spawns
# `awm sync --once --quiet`. Binding: each hook's p95 within 5 ms of the run without a team and
# at most 250 ms, and no `injection` row lost. A busy machine moves a 200-sample p95 by tens of
# milliseconds (hooks that never spawn included), so the replay runs TEAM_ROUNDS rounds (default
# 3) and compares the lowest p95 of each condition; the table also prints the median round. It also times one calibration on a copy holding
# 5,000 team rows (capture runs it when the record count doubles).
set -euo pipefail

features=""
team=""
while [ $# -gt 0 ]; do
  case "$1" in
    --features) features="$2"; shift 2 ;;
    --team) team="$2"; shift 2 ;;
    *) echo "usage: $0 [--features F] [--team unroutable]" >&2; exit 2 ;;
  esac
done
if [ -n "$team" ] && [ "$team" != "unroutable" ]; then
  echo "hook-latency: --team takes 'unroutable'" >&2
  exit 2
fi
feature_args=()
if [ -n "$features" ]; then
  feature_args=(--features "$features")
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

runs="${RUNS:-200}"
limit_ms="${P95_LIMIT_MS:-100}"
statusline_limit_ms="${STATUSLINE_P95_LIMIT_MS:-20}"
fixtures_dir="crates/awm/tests/fixtures/hooks"
projects_dir="crates/awm/tests/fixtures/projects"

cargo build --release --locked -p agent-web-memory ${feature_args[@]+"${feature_args[@]}"}
bin="$root/target/release/awm"

home="$(mktemp -d)"
trap 'rm -rf "$home"' EXIT
export AWM_HOME="$home"

if [ -d "$projects_dir" ]; then
  "$bin" init --record --import --projects "$projects_dir" >/dev/null 2>&1 \
    || echo "note: awm init could not import $projects_dir; seeding through the library only"
fi

AWM_SEED_HOME="$home" cargo test --release --locked -p agent-web-memory \
  ${feature_args[@]+"${feature_args[@]}"} --test hooks_e2e seed_latency_db -- --ignored --exact >/dev/null

status=0
python3 - "$bin" "$runs" "$limit_ms" "$fixtures_dir"/PostToolUse-*.json "$fixtures_dir"/PreToolUse-WebSearch-main-cc-1.json <<'PY' || status=1
import json
import os
import subprocess
import sys
import time

bin_path, runs, limit = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
files = sys.argv[4:]


def pct(sorted_values, p):
    return sorted_values[min(len(sorted_values) - 1, int(round(p * (len(sorted_values) - 1))))]


def call(hook, payload):
    t = time.perf_counter()
    out = subprocess.run(
        [bin_path, "hook", hook],
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
    hook = "pre-fetch" if os.path.basename(path).startswith("PreToolUse-") else "post-tool"
    call(hook, base)  # warm-up: page cache and the first start of a new binary
    times, injected = [], 0
    for i in range(runs):
        payload = dict(base, session_id=f"latency-{i}", tool_use_id=f"toolu_latency_{os.path.basename(path)}_{i}")
        payload.pop("agent_id", None)
        ms, stdout = call(hook, payload)
        times.append(ms)
        injected += 1 if stdout.strip() else 0
    times.sort()
    p50, p95 = pct(times, 0.50), pct(times, 0.95)
    verdict = "ok" if p95 <= limit else "TOO SLOW"
    print(f"{hook} {os.path.basename(path)}: n={runs} injected={injected} p50={p50:.1f} ms p95={p95:.1f} ms [{verdict}]")
    failed = failed or p95 > limit

if failed:
    print(f"hook-latency: FAILED (p95 above {limit:.0f} ms)")
    sys.exit(1)
print(f"hook-latency: ok (every p95 <= {limit:.0f} ms)")
PY

python3 - "$bin" "$runs" "$statusline_limit_ms" "$home" crates/awm/tests/fixtures/statusline/integer.json <<'PY' || status=1
import json
import os
import subprocess
import sys
import time

bin_path, runs, limit, home, fixture = sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), sys.argv[4], sys.argv[5]

quota = os.path.join(home, "quota")
os.makedirs(quota, mode=0o700, exist_ok=True)
month_file = os.path.join(quota, "samples-%s.ndjson" % time.strftime("%Y-%m", time.gmtime()))
now_ms = int(time.time() * 1000)
with open(month_file, "w") as f:
    size, i = 0, 0
    while size < 16 * 1024 * 1024:
        line = json.dumps({"v": 1, "t": now_ms - 1000000 + i, "sid": "fill-%d" % (i % 50), "model": "claude-opus-5-5",
                           "h5": {"p": i % 100, "r": 1790910000}, "d7": {"p": 41, "r": 1791300000},
                           "cost": round(i * 0.0137, 4), "dur": 3600000}, separators=(",", ":")) + "\n"
        f.write(line)
        size += len(line)
        i += 1

with open(fixture) as f:
    base = json.load(f)


def pct(sorted_values, p):
    return sorted_values[min(len(sorted_values) - 1, int(round(p * (len(sorted_values) - 1))))]


def call(cost):
    payload = json.loads(json.dumps(base))
    payload["cost"]["total_cost_usd"] = cost
    t = time.perf_counter()
    subprocess.run([bin_path, "statusline", "--quiet"], input=json.dumps(payload).encode(),
                   capture_output=True, env=os.environ, check=True)
    return (time.perf_counter() - t) * 1000.0


call(0.5)  # warm-up
before = os.path.getsize(month_file)
times = sorted(call(1.0 + i * 0.001) for i in range(runs))
grew = os.path.getsize(month_file) > before
p50, p95 = pct(times, 0.50), pct(times, 0.95)
verdict = "ok" if p95 <= limit and grew else "TOO SLOW" if grew else "NOTHING WRITTEN"
print(f"statusline integer.json: n={runs} month_file={before / 1048576:.1f} MB p50={p50:.1f} ms p95={p95:.1f} ms [{verdict}]")
if p95 > limit or not grew:
    print(f"hook-latency: FAILED (statusline p95 above {limit:.0f} ms)")
    sys.exit(1)
print(f"hook-latency: statusline ok (p95 <= {limit:.0f} ms)")
PY

if [ "$team" = "unroutable" ]; then
  seed_copy="$(mktemp -d)"
  python3 - "$home/awm.db" "$seed_copy" <<'PY'
import os
import sqlite3
import sys

src, out = sys.argv[1], sys.argv[2]
for name in ("base", "team", "cal"):
    os.makedirs(os.path.join(out, name), mode=0o700)
    a = sqlite3.connect(src)
    b = sqlite3.connect(os.path.join(out, name, "awm.db"))
    a.backup(b)
    b.close()
    a.close()
PY
  python3 - "$bin" "$runs" "$seed_copy" "$fixtures_dir" "${TEAM_DELTA_MS:-5}" "${TEAM_P95_LIMIT_MS:-250}" "${TEAM_ROUNDS:-3}" <<'PY' || status=1
import base64
import json
import os
import sqlite3
import subprocess
import sys
import time

bin_path, runs, out, fixtures, delta_limit, abs_limit, rounds = sys.argv[1:8]
runs, delta_limit, abs_limit, rounds = int(runs), float(delta_limit), float(abs_limit), int(rounds)
homes = {name: os.path.join(out, name) for name in ("base", "team", "cal")}


def b64(n=32):
    return base64.urlsafe_b64encode(os.urandom(n)).rstrip(b"=").decode()


def uuid4():
    import uuid

    return str(uuid.uuid4())


# The team: an unroutable server (TEST-NET-1), a well-formed identity, and a spawn on every
# session-start and capture.
team_home = homes["team"]
with open(os.path.join(team_home, "team.toml"), "w") as f:
    f.write(
        'server_url = "https://192.0.2.1:8443"\n'
        f'org_id = "{uuid4()}"\nmember_id = "{uuid4()}"\nhandle = "me"\ndevice_id = "{uuid4()}"\n'
    )
with open(os.path.join(team_home, "team.key"), "w") as f:
    json.dump({"device_token": b64(), "device_secret": b64(),
               "epoch_keys": [{"epoch": 1, "key": b64()}], "pending_invites": []}, f)
for name in ("team.toml", "team.key"):
    os.chmod(os.path.join(team_home, name), 0o600)
with open(os.path.join(team_home, "config.toml"), "w") as f:
    f.write("[team]\nsync_interval_s = 0\n")

SPECS = [
    ("session-start", "session-start", "codex-SessionStart-none-search-1.json"),
    ("capture (Claude Code)", "capture", "PostToolUse-WebSearch-plugin-2.json"),
    ("capture (Codex inline)", "capture", "codex-PostToolUse-webrun-search-1.json"),
    ("post-tool", "post-tool", "PostToolUse-WebFetch-plugin-3.json"),
    ("pre-fetch", "pre-fetch", "PreToolUse-WebFetch-plugin-4.json"),
]
bases = {}
for label, hook, fx in SPECS:
    with open(os.path.join(fixtures, fx)) as f:
        bases[label] = json.load(f)


def payload(label, i):
    p = dict(bases[label])
    p["session_id"] = "lat-%d" % i
    p["tool_use_id"] = "toolu_lat_%s_%d" % (label.split()[0], i) + ("c" if "Codex" in label else "")
    p.pop("agent_id", None)
    return p


def call(home, hook, p):
    env = dict(os.environ, AWM_HOME=home)
    t = time.perf_counter()
    subprocess.run([bin_path, "hook", hook], input=json.dumps(p).encode(),
                   capture_output=True, env=env, check=True)
    return (time.perf_counter() - t) * 1000.0


def pct(v, q):
    v = sorted(v)
    return v[min(len(v) - 1, int(round(q * (len(v) - 1))))]


times = {(l, c): [[] for _ in range(rounds)] for l, _, _ in SPECS for c in ("base", "team")}
for label, hook, _ in SPECS:  # warm-up: page cache and the first start of a new binary
    for c in ("base", "team"):
        call(homes[c], hook, payload(label, 10_000_000))
for r in range(rounds):
    for i in range(runs):
        order = ("base", "team") if i % 2 == 0 else ("team", "base")
        for label, hook, _ in SPECS:
            for c in order:
                times[(label, c)][r].append(call(homes[c], hook, payload(label, r * runs + i)))


def rows(home, sql):
    conn = sqlite3.connect(os.path.join(home, "awm.db"))
    try:
        return conn.execute(sql).fetchone()[0]
    finally:
        conn.close()


inj = {c: rows(homes[c], "SELECT COUNT(*) FROM injection") for c in ("base", "team")}
ev = {c: rows(homes[c], "SELECT COUNT(*) FROM event") for c in ("base", "team")}
spawned = rows(homes["team"], "SELECT COUNT(*) FROM sync_state WHERE key = 'last_spawn'")

print("p95 is the lowest of %d rounds of %d runs per hook and condition (median round in brackets)" % (rounds, runs))
print("hook                      p50 base  p50 team  p95 base  p95 team   delta  limit")
failed = False
for label, hook, _ in SPECS:
    b, t = times[(label, "base")], times[(label, "team")]
    p95b = min(pct(x, 0.95) for x in b)
    p95t = min(pct(x, 0.95) for x in t)
    med = lambda rs: sorted(pct(x, 0.95) for x in rs)[len(rs) // 2]
    delta = p95t - p95b
    ok = delta <= delta_limit and p95t <= abs_limit
    failed = failed or not ok
    print("%-24s %9.1f %9.1f %9.1f %9.1f %+7.1f  %s  [median round %.1f / %.1f]" % (
        label, pct([v for x in b for v in x], 0.5), pct([v for x in t for v in x], 0.5), p95b, p95t, delta,
        "ok" if ok else "FAIL (delta <= %g ms, p95 <= %g ms)" % (delta_limit, abs_limit), med(b), med(t)))
lost = inj["base"] - inj["team"]
print("injection rows: without team %d, with team %d; event rows: %d / %d; last_spawn written: %s" % (
    inj["base"], inj["team"], ev["base"], ev["team"], "yes" if spawned else "NO"))
if lost != 0 or ev["base"] != ev["team"]:
    print("hook-latency: FAILED (a row was lost: injection %d, event %d)" % (lost, ev["base"] - ev["team"]))
    failed = True
if not spawned:
    print("hook-latency: FAILED (no spawn happened with sync_interval_s = 0)")
    failed = True

# One calibration on a database with 5,000 team rows (capture runs it when the record count doubles).
cal = homes["cal"]
conn = sqlite3.connect(os.path.join(cal, "awm.db"))
now = int(time.time() * 1000)
conn.execute("INSERT OR IGNORE INTO team_member (member_id, handle, role, updated_at) VALUES ('m-alf', 'alf', 'member', 0)")
for i in range(5000):
    text = "team record %d topic%d word%d" % (i, i % 97, i % 31)
    conn.execute(
        "INSERT INTO event (tool_use_id, tool, session_id, cwd_hash, created_at, query, status, summary, "
        "match_text, source, origin, member) VALUES (?, 'WebSearch', 'team:m-alf', 'h', ?, ?, 'ok', ?, ?, 'hook', 'team', 'm-alf')",
        ("team:cal-%d" % i, now - (i + 1) * 60_000, text, text + " summary", text + " summary"))
conn.commit()
total = conn.execute("SELECT COUNT(*) FROM event").fetchone()[0]


def meta(key, value):
    conn.execute("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))
    conn.commit()


def capture_ms(i, calibrate):
    if calibrate:
        conn.execute("DELETE FROM meta WHERE key = 'calibrated_n'")
        conn.commit()
    else:
        meta("calibrated_n", str(10 * total))
    return call(cal, "capture", payload("capture (Claude Code)", 20_000_000 + i))


calibrated = [capture_ms(i, True) for i in range(3)]
plain = [capture_ms(10 + i, False) for i in range(3)]
conn.close()
print("calibration in capture on %d records (5000 team rows): %.0f ms (median of 3); capture without it: %.0f ms" % (
    total, sorted(calibrated)[1], sorted(plain)[1]))
if failed:
    print("hook-latency: team replay FAILED")
    sys.exit(1)
print("hook-latency: team replay ok (every p95 within %g ms of the run without a team and <= %g ms)" % (delta_limit, abs_limit))
PY
  rm -rf "$seed_copy"
fi

exit "$status"
