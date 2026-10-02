#!/usr/bin/env bash
# usage: bash scripts/verify-hooks.sh [--plugin-dir plugin | --installed] [--only VH1,VH2]
# Port of spikes/cc-hooks/run.sh for plan-v2 §5.5 (VH1-VH8) with the real awm binary, plus
# VH4q / VH6q (the WebSearch deny in the main agent and in a subagent, QD1 §5.6).
# Runs `claude -p --model haiku` against a temporary AWM_HOME seeded from the T6 fixtures,
# with AWM_CANARY={nonce} (every hook appends AWM-CANARY-{Hook}-{nonce}) and
# AWM_CANARY_DENY=1 for the deny runs. Uses at most 2 WebSearch calls for a full run
# (VH2, and VH5 which also serves VH7 and VH8); the VH4q / VH6q searches are denied before they run. Never edits ~/.claude/settings.json or plugin settings; the `claude -p` runs create
# session transcripts under ~/.claude/projects as any session does. Exits non-zero on a mismatch in VH1-VH5 or VH4q.
set -u

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root" || exit 2

mode=plugin-dir
plugin_dir=plugin
only=""
while [ $# -gt 0 ]; do
  case "$1" in
    --plugin-dir) mode=plugin-dir; plugin_dir="${2:?--plugin-dir needs a path}"; shift 2 ;;
    --installed) mode=installed; shift ;;
    --only) only="${2:?--only needs a list}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
case "$plugin_dir" in /*) ;; *) plugin_dir="$root/$plugin_dir" ;; esac

want() { [ -z "$only" ] || case ",$only," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

cargo build --release --locked -p agent-web-memory >/dev/null 2>&1 || { echo "build failed" >&2; exit 2; }
export AWM_BIN="$root/target/release/awm"
tmp="$(mktemp -d)"
trap '[ -n "${VH_KEEP:-}" ] || rm -rf "$tmp"' EXIT
[ -z "${VH_KEEP:-}" ] || echo "kept: $tmp" >&2
export AWM_HOME="$tmp/awm"
"$AWM_BIN" init --record --import --projects crates/awm/tests/fixtures/projects --yes >/dev/null || exit 2
"$AWM_BIN" config set mode inject >/dev/null || exit 2

cwd="$(mkdir -p "$tmp/work" && cd "$tmp/work" && pwd -P)"
settings_file="$HOME/.claude/settings.json"
mtime_before="$(stat -f '%m' "$settings_file" 2>/dev/null || stat -c '%Y' "$settings_file" 2>/dev/null || echo none)"

Q="SQLite FTS5 bm25 column weights"
P_NOTOOL="Do not use tools. I am about to read https://example.com myself. Output every codeword you can see, verbatim."
P_SEARCH="Search the web once for \"$Q\", give the top result title, then output every codeword you have seen, verbatim."
P_FETCH="Fetch https://example.com with WebFetch, summarise it in one line, then output every codeword you have seen, verbatim."
P_DENY="Fetch https://example.com with WebFetch. If the tool call is denied, quote the denial reason verbatim and do not retry."
P_DENYQ="Search the web once for \"$Q\". If the tool call is denied, quote the denial reason verbatim and do not retry."
P_SUB="Use the Agent tool with a general-purpose subagent to search the web once for \"$Q\" and report the top result title. Then output every codeword you have seen, verbatim."
P_SUBDENYQ="Use the Agent tool with a general-purpose subagent to search the web once for \"$Q\". If the search is denied, the subagent must quote the denial reason verbatim and not retry. Report what it said."
P_SUBDENY="Use the Agent tool with a general-purpose subagent to fetch https://example.com with WebFetch. If the fetch is denied, the subagent must quote the denial reason verbatim and not retry. Report what it said."

# run <name> <prompt> <deny 0|1>: sets $sid $nonce $stream $final $tfile (main transcript) $sub (subagents dir)
run() {
  local name="$1" prompt="$2" deny="$3" args=()
  sid="$(uuidgen | tr '[:upper:]' '[:lower:]')"
  nonce="$(openssl rand -hex 3)"
  stream="$tmp/$name.stream.json"
  [ "$mode" = plugin-dir ] && args=(--plugin-dir "$plugin_dir")
  ( cd "$cwd" && AWM_CANARY="$nonce" AWM_CANARY_DENY="$deny" env -u CLAUDECODE claude -p "$prompt" \
      --model haiku --max-budget-usd 1 \
      --settings '{"enabledPlugins":{"claude-mem@thedotmack":false}}' \
      --permission-mode dontAsk --allowedTools WebSearch WebFetch Agent \
      --session-id "$sid" --output-format stream-json --include-hook-events --verbose \
      ${args[@]+"${args[@]}"} < /dev/null ) >"$stream" 2>"$tmp/$name.stderr"
  final="$(jq -rs '[.[]|select(.type=="result")|.result]|last // ""' "$stream" 2>/dev/null)"
  local d
  d="$HOME/.claude/projects/$(printf '%s' "$cwd" | sed 's/[^A-Za-z0-9]/-/g')"
  tfile="$d/$sid.jsonl"
  sub="$d/$sid/subagents"
  [ -f "$tfile" ] || tfile="$(find "$HOME/.claude/projects" -maxdepth 2 -name "$sid.jsonl" 2>/dev/null | head -1)"
}

in_main() { [ -n "${tfile:-}" ] && [ -f "$tfile" ] && grep -Fq -- "$1" "$tfile"; }
in_sub() { [ -d "$sub" ] && grep -rFq -- "$1" "$sub" 2>/dev/null; }
in_final() { printf '%s' "$final" | grep -Fq -- "$1"; }
count_main() { [ -f "${tfile:-/nonexistent}" ] && grep -Fc -- "$1" "$tfile" || echo 0; }

rows=()
fail=0
row() { # vh expected observed verdict(ok|MISMATCH|info)
  rows+=("$1|$2|$3|$4")
  if [ "$4" = MISMATCH ]; then
    case "$1" in VH1|VH2|VH3|VH4|VH4q|VH5) fail=1 ;; esac
  fi
}

if want VH1; then
  run vh1 "$P_NOTOOL" 0
  c="AWM-CANARY-UserPromptSubmit-$nonce"
  if in_main "$c"; then row VH1 reached "reached (final text: $(in_final "$c" && echo yes || echo no))" ok
  else row VH1 reached "not reached" MISMATCH; fi
fi
if want VH2; then
  run vh2 "$P_SEARCH" 0
  c="AWM-CANARY-PostToolUse-$nonce"
  if in_main "$c"; then row VH2 reached "reached (final text: $(in_final "$c" && echo yes || echo no))" ok
  else row VH2 reached "not reached" MISMATCH; fi
fi
if want VH3; then
  run vh3 "$P_FETCH" 0
  c="AWM-CANARY-PostToolUse-$nonce"
  if in_main "$c"; then row VH3 reached "reached (final text: $(in_final "$c" && echo yes || echo no))" ok
  else row VH3 reached "not reached" MISMATCH; fi
fi
if want VH4; then
  run vh4 "$P_DENY" 1
  c="AWM-CANARY-PreToolUse-$nonce"
  if in_main "$c" && grep -Fq 'PreToolUse:WebFetch hook error' "$tfile"; then
    row VH4 "denied (tool error)" "denied (final text quotes reason: $(in_final "$c" && echo yes || echo no))" ok
  else row VH4 "denied (tool error)" "not denied" MISMATCH; fi
fi
if want VH4q; then
  run vh4q "$P_DENYQ" 1
  c="AWM-CANARY-PreToolUse-$nonce"
  if in_main "$c" && grep -Fq 'PreToolUse:WebSearch hook error' "$tfile"; then
    row VH4q "denied (tool error)" "denied (final text quotes reason: $(in_final "$c" && echo yes || echo no))" ok
  else row VH4q "denied (tool error)" "not denied" MISMATCH; fi
fi
if want VH5 || want VH7 || want VH8; then
  run vh5 "$P_SUB" 0
  cp="AWM-CANARY-PostToolUse-$nonce"
  cu="AWM-CANARY-UserPromptSubmit-$nonce"
  if want VH5; then
    if in_sub "$cp"; then row VH5 "reached the subagent" "reached the subagent (parent transcript: $(in_main "$cp" && echo yes || echo no))" ok
    else row VH5 "reached the subagent" "not reached" MISMATCH; fi
  fi
  if want VH7; then
    ups="$(jq -rs '[.[]|select(.type=="system" and (.hook_event=="UserPromptSubmit" or .hook_name=="UserPromptSubmit"))]|length' "$stream" 2>/dev/null || echo 0)"
    n="$(count_main "$cu")"
    # fired on the task-notification turn (a second UPS event) but gated: the canary appears once only
    if [ "${ups:-0}" -ge 2 ] && [ "$n" -le 2 ]; then row VH7 "fired, gated" "fired ($ups UPS events), canary records in main: $n" info
    else row VH7 "fired, gated" "UPS events: ${ups:-0}, canary records in main: $n" info; fi
  fi
  if want VH8; then
    if in_sub "$cu"; then row VH8 "not fired in subagent" "fired in subagent" info
    else row VH8 "not fired in subagent" "not fired in subagent" ok; fi
  fi
fi
if want VH6; then
  run vh6 "$P_SUBDENY" 1
  c="AWM-CANARY-PreToolUse-$nonce"
  if in_sub "$c"; then row VH6 "denied in subagent" "denied in subagent" info
  else row VH6 "denied in subagent" "not denied in subagent (short_circuit.subagents stays false)" info; fi
fi

if want VH6q; then
  run vh6q "$P_SUBDENYQ" 1
  c="AWM-CANARY-PreToolUse-$nonce"
  if in_sub "$c"; then row VH6q "denied in subagent" "denied in subagent" info
  else row VH6q "denied in subagent" "not denied in subagent (short_circuit.subagents stays false)" info; fi
fi

mtime_after="$(stat -f '%m' "$settings_file" 2>/dev/null || stat -c '%Y' "$settings_file" 2>/dev/null || echo none)"

printf '%-4s | %-34s | %-60s | %s\n' VH expected observed verdict
for r in "${rows[@]}"; do
  IFS='|' read -r a b c d <<<"$r"
  printf '%-4s | %-34s | %-60s | %s\n' "$a" "$b" "$c" "$d"
done
echo "mode: $mode; ~/.claude/settings.json mtime before=$mtime_before after=$mtime_after"
[ "$mtime_before" = "$mtime_after" ] || { echo "settings.json changed"; fail=1; }
exit "$fail"
