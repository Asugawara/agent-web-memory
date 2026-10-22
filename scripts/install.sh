#!/bin/sh
# awm installer: downloads a release tarball, verifies it and installs bin/awm.
# Usage: curl -fsSL https://github.com/Asugawara/agent-web-memory/releases/latest/download/install.sh | sh -s -- [--version vX.Y.Z] [--force]
# It installs the binary only; it never touches ~/.claude, ~/.codex or the awm data directory.
set -eu

# The whole script lives in main(), called on the last line: a truncated download runs nothing.
main() {
  REPO=Asugawara/agent-web-memory
  BASE=${AWM_INSTALL_BASE_URL:-https://github.com/$REPO/releases}
  PREFIX=${AWM_INSTALL_PREFIX:-$HOME/.local}
  BIN_DIR=$PREFIX/bin
  V=${AWM_INSTALL_VERSION:-}
  FORCE=0
  TMP=""
  TMP_BIN=""

  trap cleanup EXIT
  trap 'exit 130' INT TERM

  parse_args "$@"
  need tar mkdir mv rm cp chmod uname mktemp
  if [ "$(id -u 2>/dev/null || echo 1)" = 0 ]; then
    say "warning: running as root: the files under $PREFIX will be owned by root"
  fi
  detect_triple
  resolve_version
  install_version
  path_hint
  next_steps
}

say() { echo "awm-install: $*" >&2; }
err() { echo "awm-install: error: $*" >&2; }

usage_text() {
  cat <<USAGE
usage: install.sh [--version vX.Y.Z] [--force]
  --version   install this version (default: latest release)
  --force     reinstall even when this version is already installed
env: AWM_INSTALL_VERSION AWM_INSTALL_PREFIX (default \$HOME/.local; the binary goes to <prefix>/bin/awm)
     AWM_INSTALL_BASE_URL AWM_INSTALL_DOWNLOADER=curl|wget
USAGE
}

usage() { usage_text >&2; }

parse_args() {
  while [ $# -gt 0 ]; do
    case $1 in
      --version)
        [ $# -ge 2 ] || { usage; exit 2; }
        V=$2; shift 2 ;;
      --version=*) V=${1#--version=}; shift ;;
      --force) FORCE=1; shift ;;
      -h|--help) usage_text; exit 0 ;;
      *) usage; exit 2 ;;
    esac
  done
  V=${V#v}
}

need() {
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || { err "required command not found: $c"; exit 1; }
  done
}

cleanup() {
  [ -z "$TMP" ] || rm -rf "$TMP"
  [ -z "$TMP_BIN" ] || rm -f "$TMP_BIN"
}

detect_triple() {
  os=$(uname -s)
  arch=$(uname -m)
  case $os/$arch in
    Darwin/arm64|Darwin/aarch64) TRIPLE=aarch64-apple-darwin ;;
    Darwin/x86_64)
      # an x86_64 shell on Apple silicon (Rosetta): install the native binary
      if [ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then
        TRIPLE=aarch64-apple-darwin
      else
        TRIPLE=x86_64-apple-darwin
      fi ;;
    Linux/x86_64|Linux/amd64) TRIPLE=x86_64-unknown-linux-gnu ;;
    Linux/aarch64|Linux/arm64) TRIPLE=aarch64-unknown-linux-gnu ;;
    *) err "unsupported platform: $os/$arch"; exit 1 ;;
  esac
}

fetch() {
  url=$1 out=$2
  dl=${AWM_INSTALL_DOWNLOADER:-}
  https=0
  case $BASE in https://*) https=1 ;; esac
  if [ -z "$dl" ]; then
    if command -v curl >/dev/null 2>&1; then dl=curl
    elif command -v wget >/dev/null 2>&1; then dl=wget
    fi
  fi
  case $dl in
    curl) command -v curl >/dev/null 2>&1 || { err "need curl or wget"; exit 1; }
          if [ "$https" = 1 ]; then
            curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 15 --retry 3 -o "$out" "$url"
          else
            curl -fsSL --connect-timeout 15 --retry 3 -o "$out" "$url"
          fi ;;
    wget) command -v wget >/dev/null 2>&1 || { err "need curl or wget"; exit 1; }
          if [ "$https" = 1 ]; then
            wget -q --https-only -O "$out" "$url"
          else
            wget -q -O "$out" "$url"
          fi ;;
    *) err "need curl or wget"; exit 1 ;;
  esac
}

resolve_version() {
  [ -z "$V" ] || return 0
  t=$(mktemp)
  if ! fetch "$BASE/latest/download/SHA256SUMS" "$t" 2>/dev/null; then
    rm -f "$t"
    err "no published release found at $BASE (or no network)"
    exit 1
  fi
  # only the line of this platform: SHA256SUMS lists one archive per triple
  V=$(sed -n "s/.*awm-\\([0-9][0-9A-Za-z.+-]*\\)-$TRIPLE\\.tar\\.gz\$/\\1/p" "$t" | head -n 1)
  rm -f "$t"
  [ -n "$V" ] || { err "no release of awm for $TRIPLE found at $BASE"; exit 1; }
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d ' ' -f 1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d ' ' -f 1
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 -r "$1" | cut -d ' ' -f 1
  else
    err "need sha256sum, shasum or openssl to verify the download"
    exit 1
  fi
}

install_version() {
  want_v="awm $V"
  if [ -d "$BIN_DIR/awm" ]; then
    err "$BIN_DIR/awm is a directory; remove it and run again"
    exit 1
  fi
  if [ "$FORCE" = 0 ] && [ -x "$BIN_DIR/awm" ] && [ "$("$BIN_DIR/awm" --version 2>/dev/null || true)" = "$want_v" ]; then
    say "awm $V is already installed at $BIN_DIR/awm"
    return 0
  fi

  name=awm-$V-$TRIPLE
  TMP=$(mktemp -d)
  say "downloading awm $V ($TRIPLE)"
  fetch "$BASE/download/v$V/$name.tar.gz" "$TMP/$name.tar.gz" \
    || { err "download failed: $BASE/download/v$V/$name.tar.gz"; exit 1; }
  fetch "$BASE/download/v$V/SHA256SUMS" "$TMP/SHA256SUMS" \
    || { err "download failed: $BASE/download/v$V/SHA256SUMS"; exit 1; }

  # verify before extracting anything
  want=$(awk -v f="$name.tar.gz" '$2 == f || $2 == "*" f { print $1; exit }' "$TMP/SHA256SUMS")
  got=$(sha256 "$TMP/$name.tar.gz")
  if [ -z "$want" ] || [ "$want" != "$got" ]; then
    err "checksum mismatch for $name.tar.gz; aborting"
    exit 1
  fi

  mkdir "$TMP/x"
  tar -xzf "$TMP/$name.tar.gz" -C "$TMP/x"
  new=$TMP/x/$name/awm
  [ -f "$new" ] || { err "the archive has no $name/awm"; exit 1; }
  chmod 0755 "$new"
  got_v=$("$new" --version 2>/dev/null || true)
  if [ "$got_v" != "$want_v" ]; then
    err "smoke test failed: awm --version printed '$got_v', expected '$want_v'"
    exit 1
  fi

  mkdir -p "$BIN_DIR"
  TMP_BIN=$(mktemp "$BIN_DIR/.awm.XXXXXX")
  cp "$new" "$TMP_BIN"
  chmod 0755 "$TMP_BIN"
  mv -f "$TMP_BIN" "$BIN_DIR/awm"
  TMP_BIN=""
  say "awm $V installed: $BIN_DIR/awm"
}

path_hint() {
  case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
      say "$BIN_DIR is not on your PATH. Add it:"
      echo "  bash/zsh: export PATH=\"$BIN_DIR:\$PATH\"" >&2
      echo "  fish:     fish_add_path $BIN_DIR" >&2
      return 0 ;;
  esac
  other=$(command -v awm 2>/dev/null || true)
  if [ -n "$other" ] && [ "$other" != "$BIN_DIR/awm" ]; then
    say "warning: another awm comes first on your PATH: $other ($("$other" --version 2>/dev/null || echo unknown version))"
  fi
}

next_steps() {
  cat >&2 <<MSG
Next:
  claude plugin marketplace add Asugawara/agent-web-memory
  claude plugin install agent-web-memory@agent-web-memory
  awm init
MSG
}

main "$@"
