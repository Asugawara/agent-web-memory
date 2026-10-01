#!/usr/bin/env bash
# Remove the locally installed awm binary. Never touches the data directory.
set -euo pipefail

prefix="${AWM_INSTALL_PREFIX:-$HOME/.local}"
bin="$prefix/bin/awm"

if [ -e "$bin" ]; then
  rm -f "$bin"
  echo "Removed $bin"
else
  echo "Nothing to remove: $bin does not exist"
fi

cat <<'MSG'
Your recorded data is untouched. To delete it, run (before removing the binary, if still installed):
  awm uninstall
To remove the plugin:
  claude plugin uninstall agent-web-memory@agent-web-memory
  claude plugin marketplace remove agent-web-memory
MSG
