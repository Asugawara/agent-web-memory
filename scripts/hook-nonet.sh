#!/usr/bin/env bash
# No hook opens an internet socket (plan-v3-team §4.1 item 5; TM13).
#
# Builds a `sync,serve` debug binary, configures a team (an unroutable server, and
# `team.sync_interval_s = 0` so every session-start and capture spawns `awm sync`), runs every
# hook under `strace -f -e trace=%network,%process`, and fails if a `socket(AF_INET...)`, `socket(AF_INET6...)`
# or a `connect()` to an internet address appears in the hook process. The detached
# `awm sync --once --quiet` child is a separate process and is excluded by its pid: it is the
# process that `execve`s with the arguments `sync --once --quiet` (and its descendants).
#
# A debug build is enough: the hook code path is the same, and the only `cfg(debug_assertions)`
# difference on it is `AWM_TEST_SYNC_EXE` in `sync/spawn.rs`, which this script does not set.
# It also fails when a hook panics and when a hook run ends at its deadline or in an error.
#
# Linux only (strace). Elsewhere it prints "linux only" and exits 0; CI runs it on Linux and
# needs `strace`, `python3` and `sqlite3` installed (`apt-get install -y strace python3 sqlite3`).
#
#   scripts/hook-nonet.sh              build, trace every hook
#   scripts/hook-nonet.sh --self-test  check the log analysis on synthetic strace output (any OS)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# Reads one strace -f log (`PID syscall(...) = r` lines), excluding the sync child, and prints
# the offending lines. Exit 1 when there are any.
analyze() {
  python3 - "$@" <<'PY'
import re
import sys

path = sys.argv[1]
lines = open(path, errors="replace").read().splitlines()
pid_re = re.compile(r"^(?:\[pid\s+)?(\d+)\]?\s+(.*)$")
parent = {}
child_roots = set()
parsed = []
for line in lines:
    m = pid_re.match(line)
    if not m:
        continue
    pid, rest = m.group(1), m.group(2)
    parsed.append((pid, rest))
    c = re.match(r"(?:clone3?|fork|vfork)\(.*\)\s+=\s+(\d+)", rest)
    if c:
        parent[c.group(1)] = pid
    # The exec of the detached child: `awm sync --once --quiet`.
    if rest.startswith("execve(") and re.search(r'"sync",\s*"--once",\s*"--quiet"', rest):
        child_roots.add(pid)


def in_child(pid):
    while pid is not None:
        if pid in child_roots:
            return True
        pid = parent.get(pid)
    return False


bad = []
for pid, rest in parsed:
    if in_child(pid):
        continue
    if re.match(r"socket\(AF_INET6?\b", rest) or (
        re.match(r"connect\(", rest) and re.search(r"sa_family=AF_INET6?\b", rest)
    ):
        bad.append(f"{pid} {rest}")
for b in bad:
    print(b)
sys.exit(1 if bad else 0)
PY
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  cat >"$tmp/ok.log" <<'LOG'
100 execve("/x/awm", ["awm", "hook", "session-start"], 0x0) = 0
100 socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = 3
100 clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 101
101 execve("/x/awm", ["awm", "sync", "--once", "--quiet"], 0x0) = 0
101 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 5
101 connect(5, {sa_family=AF_INET, sin_port=htons(8443), sin_addr=inet_addr("192.0.2.1")}, 16) = -1 EINPROGRESS
101 clone(child_stack=NULL, flags=CLONE_VM) = 102
102 socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP) = 6
LOG
  analyze "$tmp/ok.log" || { echo "hook-nonet self-test: FAILED (clean log rejected)"; exit 1; }
  cat >"$tmp/bad.log" <<'LOG'
100 execve("/x/awm", ["awm", "hook", "capture"], 0x0) = 0
100 socket(AF_INET6, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 5
LOG
  if analyze "$tmp/bad.log" >/dev/null; then
    echo "hook-nonet self-test: FAILED (an AF_INET6 socket in a hook was accepted)"
    exit 1
  fi
  cat >"$tmp/bad2.log" <<'LOG'
100 execve("/x/awm", ["awm", "hook", "capture"], 0x0) = 0
100 clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 101
101 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 5
LOG
  if analyze "$tmp/bad2.log" >/dev/null; then
    echo "hook-nonet self-test: FAILED (a socket in a hook's own fork child was accepted)"
    exit 1
  fi
  cat >"$tmp/bad3.log" <<'LOG'
100 execve("/x/awm", ["awm", "hook", "capture"], 0x0) = 0
100 connect(5, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.9")}, 16) = 0
LOG
  if analyze "$tmp/bad3.log" >/dev/null; then
    echo "hook-nonet self-test: FAILED (a connect to an internet address in a hook was accepted)"
    exit 1
  fi
  echo "hook-nonet self-test: ok"
  exit 0
fi

if [ "$(uname -s)" != "Linux" ]; then
  echo "hook-nonet: linux only (strace); CI runs it"
  exit 0
fi
command -v strace >/dev/null || { echo "hook-nonet: strace is not installed (apt-get install -y strace)"; exit 2; }
command -v python3 >/dev/null || { echo "hook-nonet: python3 is not installed"; exit 2; }
command -v sqlite3 >/dev/null || { echo "hook-nonet: sqlite3 is not installed"; exit 2; }

cargo build --locked -p agent-web-memory --features sync,serve
bin="$root/target/debug/awm"

home="$(mktemp -d)"
trap 'rm -rf "$home"' EXIT
export AWM_HOME="$home"
fixtures="crates/awm/tests/fixtures/hooks"

AWM_SEED_HOME="$home" cargo test --locked -p agent-web-memory --features sync,serve \
  --test hooks_e2e seed_latency_db -- --ignored --exact >/dev/null

# A team on an unroutable server; every session-start and capture spawns `awm sync`.
cat >"$home/team.toml" <<'TOML'
server_url = "https://192.0.2.1:8443"
org_id = "00000000-0000-4000-8000-000000000001"
member_id = "00000000-0000-4000-8000-000000000002"
handle = "me"
device_id = "00000000-0000-4000-8000-000000000003"
TOML
echo '{}' >"$home/team.key"
chmod 600 "$home/team.toml" "$home/team.key"
# The debug build is slow: a hook cut short by the default 500 ms deadline leaves a short trace
# that would pass. 2000 is the maximum the config accepts.
printf '[team]\nsync_interval_s = 0\n\n[hooks]\ndeadline_ms = 2000\n' >"$home/config.toml"

status=0
n=0
trace() {
  local hook="$1" fixture="$2" log
  n=$((n + 1))
  log="$home/strace-$n.log"
  # A fresh session and tool_use_id per run: capture skips a record it already has.
  python3 - "$fixtures/$fixture" "$n" >"$home/payload-$n.json" <<'PY'
import json
import sys

p = json.load(open(sys.argv[1]))
p["session_id"] = "nonet-%s" % sys.argv[2]
p["tool_use_id"] = "toolu_nonet_%s" % sys.argv[2]
print(json.dumps(p))
PY
  strace -f -qq -e trace=%network,%process -s 200 -o "$log" "$bin" hook "$hook" <"$home/payload-$n.json" >/dev/null 2>"$home/stderr-$n.log" || true
  # The detached child outlives the hook; give it a moment to exec so it is in the log.
  sleep 1
  if offenders="$(analyze "$log")"; then
    echo "ok   $hook ($fixture)"
  else
    echo "FAIL $hook ($fixture): an internet socket in the hook process:"
    echo "$offenders" | head -5
    status=1
  fi
  if grep -q 'panicked' "$home/stderr-$n.log"; then
    echo "FAIL $hook ($fixture): the hook panicked:"
    head -5 "$home/stderr-$n.log"
    status=1
  fi
}

trace session-start codex-SessionStart-none-search-1.json
trace capture PostToolUse-WebSearch-plugin-2.json
trace capture codex-PostToolUse-webrun-search-1.json
trace post-tool PostToolUse-WebFetch-plugin-3.json
trace pre-fetch PreToolUse-WebFetch-plugin-4.json
trace pre-fetch PreToolUse-WebSearch-main-cc-1.json
trace prompt UserPromptSubmit-none-plugin-1.json

# The exclusion must have been exercised: a trace holds the spawned `awm sync` child.
if ! grep -lq '"sync", "--once", "--quiet"' "$home"/strace-*.log; then
  echo "FAIL no trace holds the spawned awm sync child: the spawn was not exercised"
  status=1
fi

# A hook that ended at its deadline or in an error stopped early: its trace proves nothing.
early="$(sqlite3 "$home/awm.db" "SELECT count(*) FROM hook_run WHERE outcome IN ('deadline','error')")"
if [ "$early" != 0 ]; then
  echo "FAIL $early hook run(s) ended at the deadline or in an error:"
  sqlite3 "$home/awm.db" "SELECT hook, outcome, total_ms, error FROM hook_run WHERE outcome IN ('deadline','error')" | head -5
  status=1
fi

if [ "$status" -eq 0 ]; then
  echo "hook-nonet: ok (no AF_INET or AF_INET6 socket in any hook process)"
else
  echo "hook-nonet: FAILED"
fi
exit "$status"
