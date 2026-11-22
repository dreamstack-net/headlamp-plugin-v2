#!/usr/bin/env bash
# Runs Headlamp in server mode in Docker for the end-to-end tests: on the network of the kind
# cluster, with the kubeconfig kind gives for that network and the plugin of e2e/build-plugin.sh
# as its plugins directory, at http://localhost:4488 (HEADLAMP_PORT). Running it again restarts it.
#
#   e2e/headlamp.sh          # start (or restart) Headlamp
#   e2e/headlamp.sh stop     # remove the container
set -euo pipefail

CLUSTER=${CLUSTER:-kubescape-e2e}
# a release at least two weeks old, pinned by digest
HEADLAMP_IMAGE=${HEADLAMP_IMAGE:-ghcr.io/headlamp-k8s/headlamp:v0.46.0@sha256:8a0ef97527544baa2b35825940ddf4db6e2d09c30cd5aa31fd269ff604cc8b75}
HEADLAMP_PORT=${HEADLAMP_PORT:-4488}
CONTAINER=${HEADLAMP_CONTAINER:-headlamp-kubescape-e2e}
here=$(cd "$(dirname "$0")" && pwd)
plugins="$here/.plugins"
state="$here/.headlamp"

# Docker Desktop on Windows takes Windows paths; Git Bash would mangle the container paths
host_path() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}
export MSYS_NO_PATHCONV=1

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
if [ "${1:-}" = stop ]; then
  exit 0
fi

if [ ! -f "$plugins/headlamp_kubescape/main.js" ]; then
  echo "No plugin build in $plugins/headlamp_kubescape: run e2e/build-plugin.sh first" >&2
  exit 1
fi

# the API server as the containers on the kind network reach it
mkdir -p "$state"
kind get kubeconfig --internal --name "$CLUSTER" >"$state/kubeconfig"
chmod 644 "$state/kubeconfig"

docker run -d --name "$CONTAINER" --network kind \
  -p "127.0.0.1:$HEADLAMP_PORT:4466" \
  --mount "type=bind,source=$(host_path "$state/kubeconfig"),target=/headlamp/kubeconfig,readonly" \
  --mount "type=bind,source=$(host_path "$plugins"),target=/headlamp/plugins,readonly" \
  "$HEADLAMP_IMAGE" -kubeconfig /headlamp/kubeconfig >/dev/null

url="http://localhost:$HEADLAMP_PORT"
for _ in $(seq 1 60); do
  if curl -fsS "$url/plugins" 2>/dev/null | grep -q headlamp_kubescape; then
    echo "Headlamp runs at $url with the plugin (cluster kind-$CLUSTER)"
    exit 0
  fi
  sleep 2
done
echo "Headlamp did not start or did not load the plugin:" >&2
docker logs "$CONTAINER" >&2 || true
exit 1
