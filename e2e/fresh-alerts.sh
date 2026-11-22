#!/usr/bin/env bash
# Makes sure Alertmanager holds runtime alerts of the intruder pod for the tests: its unexpected
# processes and its DNS lookup, active for at least MIN_LEFT seconds more (20 minutes).
#
# The node-agent alerts once on each process and domain of a container, and Alertmanager drops an
# alert an hour after the node-agent sent it, so an hour after the intruder started its alerts are
# gone. A new intruder pod alerts again: it is learned for 3 minutes (maxLearningPeriod) and
# starts the processes after 5 (the sleep of its command), so this restarts the intruder when its
# alerts are gone or about to go, and waits for the new ones.
#
#   e2e/fresh-alerts.sh
#   MIN_LEFT=3000 e2e/fresh-alerts.sh    # alerts that last 50 more minutes
set -euo pipefail

CLUSTER=${CLUSTER:-kubescape-e2e}
TIMEOUT=${TIMEOUT:-1200}
MIN_LEFT=${MIN_LEFT:-1200}
# always this context, never the current one of the kubeconfig
context=${KUBE_CONTEXT:-kind-$CLUSTER}
k() { kubectl --context "$context" "$@"; }
alertmanager=/api/v1/namespaces/monitoring/services/monitoring-kube-prometheus-alertmanager:9093/proxy
# the time an intruder pod needs for its first alerts: the sleep of its command, and the export
first_alerts=420

# The seconds until the first of the intruder's kinds of alerts expires, 0 when one is missing.
# Fails, and prints nothing, when Alertmanager cannot be read: that says nothing about its alerts.
alerts_left() {
  local alerts
  alerts=$(k get --raw "$alertmanager/api/v2/alerts?active=true&silenced=false&inhibited=false" 2>/dev/null) || return 1
  # on standard input: the alerts of a cluster are too long for an argument on Windows
  node -e '
    let body = "";
    process.stdin.on("data", data => (body += data)).on("end", () => {
      const alerts = JSON.parse(body).filter(
        alert => alert.labels.namespace === "tools" && /^intruder-/.test(alert.labels.pod_name ?? "")
      );
      const left = rule =>
        Math.max(0, ...alerts.filter(alert => alert.labels.rule_name === rule).map(alert => Date.parse(alert.endsAt) - Date.now()));
      const seconds = Math.min(left("Unexpected process launched"), left("DNS Anomalies in container"));
      console.log(Math.floor(seconds / 1000));
    });' <<<"$alerts" 2>/dev/null
}

# The age in seconds of the newest intruder pod, 0 while it has not started
intruder_age() {
  local started
  started=$(k get pods -n tools -l app=intruder --sort-by=.status.startTime \
    -o jsonpath='{.items[-1:].status.startTime}' 2>/dev/null) || started=
  node -e '
    const age = Math.floor((Date.now() - Date.parse(process.argv[1])) / 1000);
    console.log(Number.isFinite(age) ? age : 0);' "$started"
}

deadline=$(($(date +%s) + TIMEOUT))
restarts=0
waiting=
while :; do
  # empty when Alertmanager could not be read, which is tried again rather than taken for an answer
  left=$(alerts_left) || left=
  if [ -n "$left" ] && [ "$left" -ge "$MIN_LEFT" ]; then
    break
  fi
  if [ -z "$waiting" ]; then
    printf 'Waiting for fresh alerts of the intruder '
    waiting=1
  fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "timed out"
    exit 1
  fi
  # a pod older than its first alerts has alerted already, or never will (a partial profile)
  if [ -n "$left" ] && [ "$(intruder_age)" -ge "$first_alerts" ] && [ "$restarts" -lt 2 ]; then
    k rollout restart deployment/intruder -n tools >/dev/null
    k rollout status deployment/intruder -n tools --timeout=5m >/dev/null
    restarts=$((restarts + 1))
    printf '(restarted the intruder) '
  fi
  printf '.'
  sleep 15
done
if [ -n "$waiting" ]; then
  echo "ok"
else
  echo "Alertmanager holds alerts of the intruder for $((left / 60)) more minutes."
fi
