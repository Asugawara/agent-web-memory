#!/bin/sh
# Offline test of scripts/install.sh: a fake release laid out as a file:// mirror, a temp prefix.
# Usage: sh scripts/install-test.sh   (needs curl: wget has no file://)
set -eu

cd "$(dirname "$0")/.."
root=$(pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() { echo "install-test: FAILED: $*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || fail "curl is required"

# The triple install.sh picks on this machine (same rules as detect_triple).
case "$(uname -s)/$(uname -m)" in
  Darwin/arm64 | Darwin/aarch64) triple=aarch64-apple-darwin ;;
  Darwin/x86_64)
    if [ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then triple=aarch64-apple-darwin; else triple=x86_64-apple-darwin; fi ;;
  Linux/x86_64 | Linux/amd64) triple=x86_64-unknown-linux-gnu ;;
  Linux/aarch64 | Linux/arm64) triple=aarch64-unknown-linux-gnu ;;
  *) fail "unsupported test platform" ;;
esac

v=9.9.9
mirror=$work/mirror
mkdir -p "$mirror/download/v$v" "$mirror/latest/download" "$work/stage/awm-$v-$triple"
printf '#!/bin/sh\necho "awm %s"\n' "$v" >"$work/stage/awm-$v-$triple/awm"
chmod 755 "$work/stage/awm-$v-$triple/awm"
echo license >"$work/stage/awm-$v-$triple/LICENSE"
echo licenses >"$work/stage/awm-$v-$triple/THIRD_PARTY_LICENSES.md"
(cd "$work/stage" && tar -czf "$mirror/download/v$v/awm-$v-$triple.tar.gz" "awm-$v-$triple")

# Four lines, the first one for another triple: the installer must pick its own line.
sum() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi; }
cd "$mirror/download/v$v"
for t in aarch64-apple-darwin x86_64-apple-darwin x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu; do
  [ "$t" = "$triple" ] || echo other >"awm-$v-$t.tar.gz"
done
{
  for t in aarch64-apple-darwin x86_64-apple-darwin x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu; do
    sum "awm-$v-$t.tar.gz"
  done
} >SHA256SUMS.all
# aarch64-apple-darwin first unless that is our own triple, then x86_64-apple-darwin first
if [ "$triple" = aarch64-apple-darwin ]; then
  { sed -n 2p SHA256SUMS.all; sed -n '1p;3,4p' SHA256SUMS.all; } >SHA256SUMS
else
  mv SHA256SUMS.all SHA256SUMS
fi
rm -f SHA256SUMS.all
cd "$root"
cp "$mirror/download/v$v/SHA256SUMS" "$mirror/latest/download/SHA256SUMS"
[ "$(wc -l <"$mirror/latest/download/SHA256SUMS" | tr -d ' ')" = 4 ] || fail "SHA256SUMS should have 4 lines"

export HOME="$work/home"
mkdir -p "$HOME"
export AWM_INSTALL_BASE_URL="file://$mirror"

run() { prefix=$1; shift; AWM_INSTALL_PREFIX=$prefix sh "$root/scripts/install.sh" "$@"; }

echo "install-test: (a) good install"
run "$work/p1" >"$work/a.log" 2>&1 || { cat "$work/a.log"; fail "(a) install failed"; }
[ "$("$work/p1/bin/awm" --version)" = "awm $v" ] || fail "(a) wrong binary"
for f in "$work"/p1/bin/.awm.*; do [ ! -e "$f" ] || fail "(a) temp file left behind"; done

echo "install-test: (b) second run"
run "$work/p1" >"$work/b.log" 2>&1 || fail "(b) second run failed"
grep -q 'already installed' "$work/b.log" || fail "(b) no 'already installed'"

echo "install-test: (c) --force"
run "$work/p1" --force >"$work/c.log" 2>&1 || fail "(c) --force failed"
grep -q 'already installed' "$work/c.log" && fail "(c) --force said already installed"
grep -q 'installed:' "$work/c.log" || fail "(c) --force did not install"

echo "install-test: (d) tampered SHA256SUMS"
cp "$mirror/download/v$v/SHA256SUMS" "$work/good"
sum_line=$(grep "awm-$v-$triple" "$work/good" | sed 's/^[0-9a-f]*/0000000000000000000000000000000000000000000000000000000000000000/')
echo "$sum_line" >"$mirror/download/v$v/SHA256SUMS"
if run "$work/p2" --version "v$v" >"$work/d.log" 2>&1; then fail "(d) tampered sums installed"; fi
[ ! -e "$work/p2/bin/awm" ] || fail "(d) a binary was installed"
cp "$work/good" "$mirror/download/v$v/SHA256SUMS"

echo "install-test: (e) unsupported platform"
mkdir "$work/fakebin"
cat >"$work/fakebin/uname" <<'STUB'
#!/bin/sh
case "$1" in -s) echo Plan9 ;; *) echo mips ;; esac
STUB
chmod 755 "$work/fakebin/uname"
if PATH="$work/fakebin:$PATH" run "$work/p3" >"$work/e.log" 2>&1; then fail "(e) unsupported platform installed"; fi
[ ! -e "$work/p3/bin/awm" ] || fail "(e) a binary was installed"

echo "install-test: (f) bin/awm is a directory"
mkdir -p "$work/p4/bin/awm"
if run "$work/p4" >"$work/f.log" 2>&1; then fail "(f) installed over a directory"; fi
[ -z "$(ls -A "$work/p4/bin/awm")" ] || fail "(f) something was moved into the directory"

echo "install-test: ok"
