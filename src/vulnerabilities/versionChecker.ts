// The results of version-checker, when it runs in a cluster, read from its metrics.
import { request } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import { imageTag, parseImageReference } from './registry';

export interface VersionCheckerResult {
  latest: string;
  isLatest: boolean;
}

const versionCheckers = new Map<
  string,
  { expires: number; value: Promise<Map<string, VersionCheckerResult>> }
>();

/** Forgets the results kept in memory; the tests start from nothing. */
export function clearVersionCheckers() {
  versionCheckers.clear();
}

/** The key of an image for version-checker's results: registry/repository:tag. */
export function imageVersionKey(image: string): string | undefined {
  const reference = parseImageReference(image);
  const tag = imageTag(image);
  return reference && tag ? `${reference.registry}/${reference.repository}:${tag}` : undefined;
}

function unescapeLabel(value: string) {
  return value.replace(/\\(["\\n])/g, (_, char) => (char === 'n' ? '\n' : char));
}

/** version-checker's results, by imageVersionKey, from its Prometheus metrics. */
export function parseVersionCheckerMetrics(text: string): Map<string, VersionCheckerResult> {
  const results = new Map<string, VersionCheckerResult>();
  for (const line of text.split('\n')) {
    const match = line.match(/^version_checker_is_latest_version\{(.*)\}\s+(\S+)/);
    if (!match) continue;
    const labels: Record<string, string> = {};
    for (const [, name, value] of match[1].matchAll(/(\w+)="((?:[^"\\]|\\.)*)"/g)) {
      labels[name] = unescapeLabel(value);
    }
    const key =
      labels.image && labels.current_version
        ? imageVersionKey(`${labels.image}:${labels.current_version}`)
        : undefined;
    if (key && labels.latest_version) {
      results.set(key, { latest: labels.latest_version, isLatest: Number(match[2]) === 1 });
    }
  }
  return results;
}

/**
 * The results of version-checker in a cluster, read from its metrics through the API server's
 * service proxy; empty when it does not run there. Kept for five minutes.
 */
export function versionCheckerResults(
  cluster: string,
  now: number = Date.now()
): Promise<Map<string, VersionCheckerResult>> {
  const entry = versionCheckers.get(cluster);
  if (entry && now < entry.expires) return entry.value;
  const value = (async () => {
    const services = await request(
      `/api/v1/services?labelSelector=${encodeURIComponent(
        'app.kubernetes.io/name=version-checker'
      )}`,
      { cluster, autoLogoutOnAuthError: false }
    );
    const service = services?.items?.[0];
    const ports: Array<{ name?: string; port: number }> = service?.spec?.ports ?? [];
    const port = ports.find(p => p.name === 'web') ?? ports[0];
    if (!service || !port) return new Map<string, VersionCheckerResult>();
    const response = await request(
      `/api/v1/namespaces/${service.metadata.namespace}/services/${service.metadata.name}:${port.port}/proxy/metrics`,
      { cluster, isJSON: false, autoLogoutOnAuthError: false }
    );
    return parseVersionCheckerMetrics(await response.text());
  })().catch(() => new Map<string, VersionCheckerResult>());
  versionCheckers.set(cluster, { expires: now + 5 * 60 * 1000, value });
  return value;
}
