#!/usr/bin/env bash
# Creates a kind cluster with the Kubescape operator, Prometheus and Alertmanager, and workloads
# for the end-to-end tests of the plugin. Running it again updates what it installed.
#
#   e2e/setup-kind.sh            # cluster kubescape-e2e
#   CLUSTER=other e2e/setup-kind.sh
set -euo pipefail

CLUSTER=${CLUSTER:-kubescape-e2e}
KUBESCAPE_CHART_VERSION=${KUBESCAPE_CHART_VERSION:-1.42.0}
PROMETHEUS_CHART_VERSION=${PROMETHEUS_CHART_VERSION:-93.6.1}
here=$(cd "$(dirname "$0")" && pwd)
# every command names this context; the current one of the kubeconfig stays the user's
context="kind-$CLUSTER"

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  previous=$(kubectl config current-context 2>/dev/null || true)
  kind create cluster --name "$CLUSTER" --wait 180s
  # kind makes the new cluster the current context
  if [ -n "$previous" ] && [ "$previous" != "$context" ]; then
    kubectl config use-context "$previous" >/dev/null
  fi
fi

helm repo add kubescape https://kubescape.github.io/helm-charts/ >/dev/null
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts >/dev/null
helm repo update >/dev/null

# Prometheus, which the Trends of the overview read, and the Alertmanager the node-agent sends its
# runtime alerts to; no Grafana or node exporters, which the plugin does not use
helm upgrade --install monitoring prometheus-community/kube-prometheus-stack \
  --kube-context "$context" --namespace monitoring --create-namespace \
  --version "$PROMETHEUS_CHART_VERSION" \
  --set grafana.enabled=false \
  --set nodeExporter.enabled=false \
  --set prometheus-node-exporter.enabled=false \
  --set kubeStateMetrics.enabled=false \
  --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false \
  --set prometheus.prometheusSpec.podMonitorSelectorNilUsesHelmValues=false \
  --set prometheus.prometheusSpec.scrapeInterval=30s \
  --wait --timeout 15m

helm upgrade --install kubescape kubescape/kubescape-operator \
  --kube-context "$context" --namespace kubescape --create-namespace \
  --version "$KUBESCAPE_CHART_VERSION" \
  --set clusterName="$context" \
  --set capabilities.continuousScan=enable \
  --set capabilities.runtimeDetection=enable \
  --set capabilities.prometheusExporter=enable \
  --set prometheusExporter.serviceMonitor.enabled=true \
  --set alertCRD.installDefault=true \
  --set nodeAgent.config.learningPeriod=2m \
  --set nodeAgent.config.maxLearningPeriod=3m \
  --set nodeAgent.config.updatePeriod=1m \
  --set "nodeAgent.config.alertManagerExporterUrls[0]=monitoring-kube-prometheus-alertmanager.monitoring.svc.cluster.local:9093" \
  --wait --timeout 20m

kubectl --context "$context" apply -f "$here/workloads.yaml"

# learningPeriod is only the delay before the first profile is written; maxLearningPeriod ends the
# learning (24h by default), after which the node-agent alerts on the intruder. A container that
# started before the node-agent (when an upgrade restarted it) only gets a partial profile, so
# the intruder then starts again, to be learned from its start.
kubectl --context "$context" rollout status ds/node-agent -n kubescape --timeout=10m
kubectl --context "$context" rollout status deployment/intruder -n tools --timeout=10m
agent_started=$(kubectl --context "$context" get pods -n kubescape \
  -l app.kubernetes.io/component=node-agent -o jsonpath='{.items[0].status.startTime}')
intruder_started=$(kubectl --context "$context" get pods -n tools -l app=intruder \
  -o jsonpath='{.items[0].status.startTime}')
if [[ "$intruder_started" < "$agent_started" ]]; then
  kubectl --context "$context" rollout restart deployment/intruder -n tools
fi

echo "Cluster $CLUSTER is ready: context $context."
echo "Plugin settings: Alertmanager monitoring/monitoring-kube-prometheus-alertmanager:9093,"
echo "Prometheus monitoring/monitoring-kube-prometheus-prometheus:9090."
