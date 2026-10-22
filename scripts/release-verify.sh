#!/bin/sh
# Check that every place that carries the release version agrees with it.
# Usage: sh scripts/release-verify.sh <version> [--notes OUTFILE]
#   --notes OUTFILE   also write the body of the "## <version>" section of CHANGELOG.md
set -eu

cd "$(dirname "$0")/.."

[ $# -ge 1 ] || { echo "usage: sh scripts/release-verify.sh <version> [--notes OUTFILE]" >&2; exit 2; }
V=${1#v}
shift
notes=""
if [ "${1:-}" = --notes ]; then
  [ $# -eq 2 ] || { echo "usage: sh scripts/release-verify.sh <version> [--notes OUTFILE]" >&2; exit 2; }
  notes=$2
fi

bad=0
mismatch() { echo "release-verify: $*" >&2; bad=1; }

for c in awm awm-proto awm-server; do
  f=crates/$c/Cargo.toml
  got=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$f" | head -n 1)
  [ "$got" = "$V" ] || mismatch "$f has version '$got', expected '$V'"
done

for pkg in agent-web-memory awm-proto awm-server; do
  got=$(awk -v p="$pkg" '$0 == "name = \"" p "\"" { getline; print; exit }' Cargo.lock | sed -n 's/^version = "\(.*\)"$/\1/p')
  [ "$got" = "$V" ] || mismatch "Cargo.lock has $pkg at '$got', expected '$V'"
done

got=$(sed -n 's/^ *"version": *"\(.*\)",\{0,1\}$/\1/p' plugin/.claude-plugin/plugin.json | head -n 1)
[ "$got" = "$V" ] || mismatch "plugin/.claude-plugin/plugin.json has version '$got', expected '$V'"

got=$(sed -n 's/^ *"version": *"\(.*\)",\{0,1\}$/\1/p' .claude-plugin/marketplace.json | head -n 1)
[ "$got" = "$V" ] || mismatch ".claude-plugin/marketplace.json has version '$got', expected '$V'"

got=$(sed -n 's/.*--plugin-version \([0-9A-Za-z.+-]*\).*/\1/p' plugin/hooks/awm-hook | head -n 1)
[ "$got" = "$V" ] || mismatch "plugin/hooks/awm-hook has --plugin-version '$got', expected '$V'"

section=$(awk -v h="## $V" '
  $0 == h { on = 1; next }
  on && /^## / { exit }
  on { print }
' CHANGELOG.md)
if ! grep -qx "## $V" CHANGELOG.md; then
  mismatch "CHANGELOG.md has no '## $V' heading"
elif [ -n "$notes" ]; then
  printf '%s\n' "$section" >"$notes"
fi

[ "$bad" = 0 ] || exit 1
echo "release-verify: $V ok"
