#!/usr/bin/env bash
# Build awm from this checkout and install it locally. No network beyond what cargo needs for cached deps.
set -euo pipefail

cd "$(dirname "$0")/.."

prefix="${AWM_INSTALL_PREFIX:-$HOME/.local}"
dir="$prefix/bin"

cargo build --release --locked

mkdir -p "$dir"
tmp="$(mktemp "$dir/.awm.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
cp target/release/awm "$tmp"
chmod 0755 "$tmp"
mv -f "$tmp" "$dir/awm"
trap - EXIT

version="$("$dir/awm" --version)"
echo "$version"
echo "$version installed to $dir/awm. Next: awm init"

case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "Add $dir to your PATH." ;;
esac
