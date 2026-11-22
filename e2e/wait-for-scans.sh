#!/usr/bin/env bash
# Waits until Kubescape produced what the end-to-end tests read: the configuration and
# vulnerability scans of the test workloads, their relevant (filtered) reports, the container
# profiles, the generated network policies, the cluster totals of the Kubescape exporter in
# Prometheus and the runtime alerts of the intruder pod in Alertmanager (fresh-alerts.sh, which
# starts the intruder again when its alerts expired). A new cluster takes 10-20 minutes.
#
#   e2e/wait-for-scans.sh
#   TIMEOUT=3600 e2e/wait-for-scans.sh
set -euo pipefail

CLUSTER=${CLUSTER:-kubescape-e2e}
TIMEOUT=${TIMEOUT:-2400}
# always this context, never the current one of the kubeconfig
context="kind-$CLUSTER"
k() { kubectl --context "$context" "$@"; }
here=$(cd "$(dirname "$0")" && pwd)
prometheus=/api/v1/namespaces/monitoring/services/monitoring-kube-prometheus-prometheus:9090/proxy

deadline=$(($(date +%s) + TIMEOUT))

# wait_for DESCRIPTION COMMAND...: runs the command every 15 seconds until it succeeds
wait_for() {
  local description=$1
  shift
  printf 'Waiting for %s ' "$description"
  until "$@" >/dev/null 2>&1; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo "timed out"
      return 1
    fi
    printf '.'
    sleep 15
  done
  echo "ok"
}

# has_names RESOURCE NAMESPACE PATTERN...: every pattern matches a name of the resource
has_names() {
  local resource=$1 namespace=$2
  shift 2
  local names
  names=$(k get "$resource" -n "$namespace" -o name)
  for pattern in "$@"; do
    grep -q -- "$pattern" <<<"$names" || return 1
  done
}

configuration_scans() {
  has_names workloadconfigurationscansummaries shop deployment-web deployment-api statefulset-cache \
    && has_names workloadconfigurationscansummaries tools deployment-intruder deployment-toolbox
}

# The operator does not always scan the configuration after it starts, and the daily scan of the
# kubescape-scheduler CronJob is far away, so the script asks for a scan like the Scan now button
request_configuration_scan() {
  local body guid
  body=$(printf '%s' '{"commandName":"kubescapeScan","args":{"scanV1":{"submit":true}}}' | base64 | tr -d '\n')
  guid=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n' \
    | sed -E 's/^(.{8})(.{4})(.{4})(.{4})(.{12})$/\1-\2-\3-\4-\5/')
  k create -o name -f - <<YAML
apiVersion: kubescape.io/v1alpha1
kind: OperatorCommand
metadata:
  generateName: e2e-scan-
  namespace: kubescape
  labels:
    kubescape.io/app-name: operator
spec:
  guid: $guid
  commandType: OperatorAPI
  body: $body
YAML
}

relevant_reports() {
  # the summary refers to a relevant (filtered) report once the learning period ended; the
  # storage lists objects without their spec, so the summary is read by name
  [ -n "$(k get vulnerabilitymanifestsummaries -n shop deployment-web-nginx \
    -o jsonpath='{.spec.vulnerabilitiesRef.relevant.name}')" ]
}

completed_profile() {
  k get containerprofiles -n tools \
    -o jsonpath='{range .items[*]}{.metadata.name} {.metadata.annotations.kubescape\.io/status}{"\n"}{end}' \
    | grep intruder | grep -Eq ' (completed|ready)$'
}

prometheus_totals() {
  k get --raw "$prometheus/api/v1/query?query=kubescape_controls_total_cluster_critical" \
    | grep -q '"value"'
}

# the workloads have to run before they are scanned
k wait --for=condition=Available deployment --all -n shop --timeout=10m >/dev/null
k wait --for=condition=Available deployment --all -n tools --timeout=10m >/dev/null
for _ in 1 2 3; do
  if configuration_scans >/dev/null 2>&1; then break; fi
  echo "Requesting a configuration scan"
  request_configuration_scan
  step=$(($(date +%s) + 600))
  until configuration_scans >/dev/null 2>&1 || [ "$(date +%s)" -ge "$step" ]; do sleep 15; done
done
wait_for "the configuration scans" configuration_scans
wait_for "the vulnerability scans" has_names vulnerabilitymanifestsummaries shop \
  deployment-web-nginx deployment-web-sidecar deployment-api-api statefulset-cache-redis
wait_for "the vulnerability scans in tools" has_names vulnerabilitymanifestsummaries tools \
  deployment-toolbox-alpine deployment-intruder-intruder
wait_for "the relevant reports" relevant_reports
wait_for "the container profile of the intruder" completed_profile
wait_for "the generated network policies" has_names generatednetworkpolicies shop deployment-api deployment-web
wait_for "the cluster totals in Prometheus" prometheus_totals
# the alerts of the intruder, which expire an hour after they were sent
TIMEOUT=$((deadline - $(date +%s))) KUBE_CONTEXT=$context bash "$here/fresh-alerts.sh"
echo "Kubescape has scanned the cluster $context."
