/*
  What the end-to-end tests share apart from the fixtures: the cluster, its kube context and
  kubectl, which the tests use to check what the plugin changed and to clean up after themselves.
*/
import { execFileSync } from 'node:child_process';

// The name Headlamp gives the cluster: the context in the kubeconfig of e2e/headlamp.sh
export const cluster = process.env.E2E_CLUSTER ?? 'kind-kubescape-e2e';
// The kube context of the same cluster for kubectl, never another one
export const kubeContext = process.env.E2E_KUBE_CONTEXT ?? cluster;

// The plugin settings of the tests: the Alertmanager and Prometheus of e2e/setup-kind.sh
export const alertmanagerAddress = 'monitoring/monitoring-kube-prometheus-alertmanager:9093';
export const prometheusAddress = 'monitoring/monitoring-kube-prometheus-prometheus:9090';

/** The URL path of a page of the plugin in the test cluster, such as kubescapePath('overview'). */
export function kubescapePath(path: string): string {
  return `/c/${cluster}/kubescape/${path.replace(/^\/+/, '')}`;
}

/** Runs kubectl in the test cluster and returns its output. */
export function kubectl(args: string[], input?: string): string {
  return execFileSync('kubectl', ['--context', kubeContext, ...args], {
    encoding: 'utf8',
    input,
    stdio: ['pipe', 'pipe', 'pipe'],
    maxBuffer: 256 * 1024 * 1024,
  });
}

export function kubectlJson<T = any>(args: string[]): T {
  return JSON.parse(kubectl([...args, '-o', 'json']));
}

/** Deletes an object if it exists, such as one a failed test left behind. */
export function deleteIfExists(resource: string, name: string, namespace?: string) {
  kubectl([
    'delete',
    resource,
    name,
    ...(namespace ? ['-n', namespace] : []),
    '--ignore-not-found',
    '--wait=false',
  ]);
}

export function exists(resource: string, name: string, namespace?: string): boolean {
  return (
    kubectl([
      'get',
      resource,
      name,
      ...(namespace ? ['-n', namespace] : []),
      '--ignore-not-found',
      '-o',
      'name',
    ]).trim() !== ''
  );
}
