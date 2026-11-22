/*
  What changed in a trend between two points: the totals of each namespace, which the Kubescape
  Prometheus exporter publishes next to the cluster totals, before and after, and the time of
  the daily scan, so that a step in the chart can be told apart: a few namespaces that changed
  (workloads added, removed or moved to other images), or most namespaces at once around the
  daily rescan (an update of the vulnerability database, or of the controls).

  The exporter counts the findings of each workload container: replicas do not count, but every
  workload that runs an image counts its CVEs.
*/
import { request } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import { getPrometheusUrl } from '../common/config-store';
import { getKubescapeNamespace } from '../custom-objects/api-queries';
import type { TrendKey, TrendRow } from './prometheus';

/** The charts of the trends: the CVEs of the reports, and the failed controls. */
export type TrendKind = 'cves' | 'controls';

const namespaceMetrics: Record<TrendKind, { critical: string; high: string }> = {
  cves: {
    critical: 'kubescape_vulnerabilities_total_namespace_critical',
    high: 'kubescape_vulnerabilities_total_namespace_high',
  },
  controls: {
    critical: 'kubescape_controls_total_namespace_critical',
    high: 'kubescape_controls_total_namespace_high',
  },
};

/** The columns of the trend rows that each chart draws, critical and high. */
export const trendKeys: Record<TrendKind, { critical: TrendKey; high: TrendKey }> = {
  cves: { critical: 'cvesCritical', high: 'cvesHigh' },
  controls: { critical: 'controlsCritical', high: 'controlsHigh' },
};

/** Two points of a trend, in milliseconds. */
export interface TrendInterval {
  before: number;
  after: number;
}

function change(before: TrendRow, after: TrendRow, kind: TrendKind): number | undefined {
  const { critical, high } = trendKeys[kind];
  const values = [before[critical], after[critical], before[high], after[high]];
  if (values.some(value => value === undefined)) return undefined;
  const [criticalBefore, criticalAfter, highBefore, highAfter] = values as number[];
  return Math.abs(criticalAfter - criticalBefore) + Math.abs(highAfter - highBefore);
}

/**
 * The two neighbouring points with the largest change of a chart: around the point at index
 * near, as a click seldom hits the point right after a step, or over all points.
 */
export function largestChange(
  rows: TrendRow[],
  kind: TrendKind,
  near?: number
): TrendInterval | undefined {
  if (rows.length < 2) return undefined;
  const from = near === undefined ? 1 : Math.max(1, near - 2);
  const to = near === undefined ? rows.length - 1 : Math.min(rows.length - 1, near + 2);
  let best: { index: number; size: number } | undefined;
  for (let index = from; index <= to; index++) {
    const size = change(rows[index - 1], rows[index], kind);
    if (size !== undefined && (!best || size > best.size)) best = { index, size };
  }
  if (!best || (best.size === 0 && near === undefined)) return undefined;
  // nothing changed near the point: the point and the one before it
  const index = best.size === 0 ? Math.min(Math.max(near ?? 1, 1), rows.length - 1) : best.index;
  return { before: rows[index - 1].time, after: rows[index].time };
}

/** The totals of a namespace at a point, undefined where the namespace had no total. */
export interface NamespaceTotals {
  critical?: number;
  high?: number;
}

export interface NamespaceChange {
  namespace: string;
  before: NamespaceTotals;
  after: NamespaceTotals;
}

export interface TrendChanges {
  // the namespaces whose totals changed, the largest change first
  changes: NamespaceChange[];
  // the namespaces with a total at either point
  namespaceCount: number;
}

/**
 * The totals of a metric per namespace at a time. The exporter names the namespace of the
 * workloads in its label namespace, which Prometheus renames to exported_namespace when it
 * scrapes with the labels of the target, as the ServiceMonitor of the Kubescape chart does: its
 * namespace label then names the namespace of the exporter. With honorLabels, it is namespace.
 */
async function totalsAt(cluster: string, metric: string, time: number) {
  const params = new URLSearchParams({
    // more than one exporter, or a restart, may report the same total
    query: `max by (namespace, exported_namespace) (${metric})`,
    time: String(Math.floor(time / 1000)),
  });
  // a 401 of a proxy in front of Prometheus is not the end of the user's session
  const response = await request(`${getPrometheusUrl()}/api/v1/query?${params.toString()}`, {
    cluster,
    autoLogoutOnAuthError: false,
  });
  const totals = new Map<string, number>();
  for (const series of response?.data?.result ?? []) {
    const namespace = series.metric?.exported_namespace ?? series.metric?.namespace;
    if (!namespace) continue;
    const value = Number(series.value?.[1]);
    // exporters in several namespaces may report the same namespace
    totals.set(namespace, Math.max(value, totals.get(namespace) ?? value));
  }
  return totals;
}

export function changeSize(found: NamespaceChange): number {
  return (
    Math.abs((found.after.critical ?? 0) - (found.before.critical ?? 0)) +
    Math.abs((found.after.high ?? 0) - (found.before.high ?? 0))
  );
}

/** Whether a namespace had totals at one of the points only. */
export function appearedOrWent(found: NamespaceChange): 'new' | 'gone' | undefined {
  const before = found.before.critical !== undefined || found.before.high !== undefined;
  const after = found.after.critical !== undefined || found.after.high !== undefined;
  if (before === after) return undefined;
  return after ? 'new' : 'gone';
}

/** The totals of each namespace at the two points, and the namespaces that changed. */
export async function fetchTrendChanges(
  cluster: string,
  kind: TrendKind,
  { before, after }: TrendInterval
): Promise<TrendChanges> {
  const metrics = namespaceMetrics[kind];
  const [criticalBefore, criticalAfter, highBefore, highAfter] = await Promise.all([
    totalsAt(cluster, metrics.critical, before),
    totalsAt(cluster, metrics.critical, after),
    totalsAt(cluster, metrics.high, before),
    totalsAt(cluster, metrics.high, after),
  ]);
  const namespaces = new Set([
    ...criticalBefore.keys(),
    ...criticalAfter.keys(),
    ...highBefore.keys(),
    ...highAfter.keys(),
  ]);
  const changes = [...namespaces]
    .map(
      (namespace): NamespaceChange => ({
        namespace,
        before: { critical: criticalBefore.get(namespace), high: highBefore.get(namespace) },
        after: { critical: criticalAfter.get(namespace), high: highAfter.get(namespace) },
      })
    )
    .filter(found => changeSize(found) > 0 || appearedOrWent(found))
    .sort((a, b) => changeSize(b) - changeSize(a) || a.namespace.localeCompare(b.namespace));
  return { changes, namespaceCount: namespaces.size };
}

/** A daily scan of the Kubescape operator: the CronJob that starts it, and when. */
export interface ScanSchedule {
  cronJob: string;
  schedule: string;
  // the time of day in UTC, when the schedule is a plain daily one
  minute?: number;
  hour?: number;
}

// the CronJobs of the operator that start a scan of all images, or of the configuration
const scanCronJobs: Record<TrendKind, string> = {
  cves: 'kubevuln-scheduler',
  controls: 'kubescape-scheduler',
};

/**
 * The time of day of a daily schedule such as 12 1 * * *, in UTC: CronJobs without a time zone
 * run in the time zone of the controller manager, which is UTC on managed clusters.
 */
export function dailyTime(
  schedule: string,
  timeZone?: string
): { minute: number; hour: number } | undefined {
  if (timeZone && !/^(Etc\/)?UTC$/.test(timeZone)) return undefined;
  const match = /^(\d{1,2})\s+(\d{1,2})\s+\*\s+\*\s+\*$/.exec(schedule.trim());
  if (!match) return undefined;
  const [minute, hour] = [Number(match[1]), Number(match[2])];
  return minute < 60 && hour < 24 ? { minute, hour } : undefined;
}

/** The schedule of the daily scan of a chart, undefined when it cannot be read. */
export async function fetchScanSchedule(
  cluster: string,
  kind: TrendKind
): Promise<ScanSchedule | undefined> {
  try {
    const { kubeScapeNamespace } = await getKubescapeNamespace(cluster);
    if (!kubeScapeNamespace) return undefined;
    const cronJob = scanCronJobs[kind];
    const found = await request(
      `/apis/batch/v1/namespaces/${encodeURIComponent(kubeScapeNamespace)}/cronjobs/${cronJob}`,
      { cluster }
    );
    const schedule: string | undefined = found?.spec?.schedule;
    if (!schedule) return undefined;
    return { cronJob, schedule, ...dailyTime(schedule, found?.spec?.timeZone) };
  } catch {
    return undefined;
  }
}

/** When the daily scan last started at or before a time, in milliseconds. */
export function lastScanStart(schedule: ScanSchedule, time: number): number | undefined {
  if (schedule.hour === undefined || schedule.minute === undefined) return undefined;
  const day = new Date(time);
  const start = Date.UTC(
    day.getUTCFullYear(),
    day.getUTCMonth(),
    day.getUTCDate(),
    schedule.hour,
    schedule.minute
  );
  return start <= time ? start : start - 24 * 3600 * 1000;
}

// a full scan of a big cluster takes some hours before all reports are written
const scanDuration = 6 * 3600 * 1000;

/** Whether the daily scan ran in the interval, or shortly before it. */
export function scanNear(schedule: ScanSchedule | undefined, interval: TrendInterval): boolean {
  const start = schedule && lastScanStart(schedule, interval.after);
  return start !== undefined && start > interval.before - scanDuration;
}

/** What most likely caused the change, from how it is spread over the namespaces. */
export function likelyCause(found: TrendChanges, kind: TrendKind, nearScan: boolean): string {
  const total = found.changes.reduce((sum, item) => sum + changeSize(item), 0);
  if (total === 0 && found.changes.length === 0) {
    return (
      'No namespace total changed between these points: the cluster total may have changed ' +
      'while the exporter restarted, or between two exporters.'
    );
  }
  const fromNamespaces = found.changes
    .filter(item => appearedOrWent(item))
    .reduce((sum, item) => sum + changeSize(item), 0);
  if (fromNamespaces * 2 >= total) {
    return (
      'Mostly namespaces that appeared or went: their workloads were added or removed, or the ' +
      'scans of removed workloads were cleaned up.'
    );
  }
  const changedShare = found.changes.length / Math.max(1, found.namespaceCount);
  if (nearScan && found.changes.length >= 3 && changedShare >= 0.5) {
    return kind === 'cves'
      ? 'Most namespaces changed together around the daily rescan: most likely the ' +
          'vulnerability database was updated, which changes the reports of all images at ' +
          'once. A CVE in an image counts once for every workload that runs it.'
      : 'Most namespaces changed together around the daily configuration scan: most likely ' +
          'the controls or their configuration were updated.';
  }
  const top = found.changes.slice(0, 2);
  const topShare = top.reduce((sum, item) => sum + changeSize(item), 0) / Math.max(1, total);
  if (topShare >= 0.8) {
    const names = top.map(item => item.namespace).join(' and ');
    return kind === 'cves'
      ? `Mostly in ${names}: workloads there were added, removed or moved to other images. ` +
          'Scaling does not count, as the totals count each workload once.'
      : `Mostly in ${names}: workloads there were added or removed, or changed their ` +
          'configuration.';
  }
  return (
    `Spread over ${found.changes.length} namespaces` +
    (nearScan ? ', around the daily scan.' : ', not at the time of the daily scan.')
  );
}
