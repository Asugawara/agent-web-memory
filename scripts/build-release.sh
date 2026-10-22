#!/bin/sh
# Pack awm-<version>-<triple>.tar.gz into <outdir> from an already built target/release/awm.
# Usage: sh scripts/build-release.sh <version> <triple> <outdir>
# Writes only the tarball: SHA256SUMS is made once for all four by the `sums` job of release.yml.
set -eu

usage() {
  echo "usage: sh scripts/build-release.sh <version> <triple> <outdir>" >&2
  exit 2
}

main() {
  [ $# -eq 3 ] || usage
  V=${1#v}
  triple=$2
  mkdir -p "$3"
  OUT=$(cd "$3" && pwd)
  ROOT=$(cd "$(dirname "$0")/.." && pwd)
  cd "$ROOT"

  [ -f target/release/awm ] || { echo "build-release: target/release/awm is missing (run cargo build --release first)" >&2; exit 1; }

  name=awm-$V-$triple
  stage=$OUT/stage/$name
  rm -rf "$OUT/stage"
  mkdir -p "$stage"
  cp target/release/awm "$stage/awm"
  cp LICENSE THIRD_PARTY_LICENSES.md "$stage/"
  chmod 755 "$stage/awm"

  # This runs the binary of every native archive: it must print the release version.
  got=$("$stage/awm" --version)
  [ "$got" = "awm $V" ] || { echo "build-release: awm --version printed '$got', expected 'awm $V'" >&2; exit 1; }

  tarball=$OUT/$name.tar.gz
  rm -f "$tarball"
  if tar --version 2>/dev/null | grep -qi 'bsdtar'; then
    # best effort: bsdtar (macOS) has no --sort, so the bytes are not reproducible
    (cd "$OUT/stage" && COPYFILE_DISABLE=1 tar --uid 0 --gid 0 --no-mac-metadata -czf "$tarball" "$name")
  else
    epoch=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || true)}
    [ -n "$epoch" ] || { echo "build-release: set SOURCE_DATE_EPOCH (no git commit time available for the tar mtime)" >&2; exit 1; }
    (cd "$OUT/stage" && tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner -czf "$tarball" "$name")
  fi

  case $(uname -s) in
    Linux)
      if command -v objdump >/dev/null 2>&1; then
        echo "glibc ceiling: $(objdump -T "$stage/awm" | grep -o 'GLIBC_[0-9.]*' | sort -V | tail -n 1)"
      fi ;;
  esac
  rm -rf "$OUT/stage"
  echo "$tarball"
}

main "$@"
