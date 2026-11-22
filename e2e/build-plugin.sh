#!/usr/bin/env bash
# Builds the plugin for the end-to-end tests into e2e/.plugins/headlamp_kubescape (main.js,
# package.json, main.wasm and the Kubescape data), the plugins directory e2e/headlamp.sh mounts.
# It builds a copy of the checkout like `make local`, but leaves Headlamp desktop alone.
#
#   e2e/build-plugin.sh
#   PYTHON=py e2e/build-plugin.sh      # another Python 3.8+
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$here")

if [ -z "${PYTHON:-}" ]; then
  for candidate in python3 python py; do
    if "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 8))' >/dev/null 2>&1; then
      PYTHON=$candidate
      break
    fi
  done
fi
if [ -z "${PYTHON:-}" ]; then
  echo "Python 3.8 or newer is needed (set PYTHON)" >&2
  exit 1
fi

"$PYTHON" "$root/scripts/install_headlamp_plugin.py" --source "$root" \
  --output "$here/.plugins/headlamp_kubescape"
