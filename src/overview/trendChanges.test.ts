import { vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  request: vi.fn(),
  getKubescapeNamespace: vi.fn(),
}));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ request: mocks.request }));
vi.mock('../common/config-store', () => ({ getPrometheusUrl: () => '/proxy' }));
vi.mock('../custom-objects/api-queries', () => ({
  getKubescapeNamespace: mocks.getKubescapeNamespace,
}));

import type { TrendRow } from './prometheus';
import {
  appearedOrWent,
  dailyTime,
  fetchScanSchedule,
  fetchTrendChanges,
  largestChange,
  lastScanStart,
  likelyCause,
  NamespaceChange,
  scanNear,
} from './trendChanges';

const hour = 3600 * 1000;
const at = (time: string) => new Date(time).getTime();

beforeEach(() => {
  mocks.request.mockReset();
  mocks.getKubescapeNamespace.mockReset().mockResolvedValue({ kubeScapeNamespace: 'kubescape' });
});

describe('largestChange', () => {
  const rows: TrendRow[] = [
    { time: 1, cvesCritical: 10, cvesHigh: 100 },
    { time: 2, cvesCritical: 10, cvesHigh: 102 },
    // the step
    { time: 3, cvesCritical: 40, cvesHigh: 900 },
    { time: 4, cvesCritical: 41, cvesHigh: 905 },
    { time: 5, cvesCritical: 41, cvesHigh: 905 },
    { time: 6, cvesCritical: 41, cvesHigh: 905 },
    { time: 7, cvesCritical: 30, cvesHigh: 905 },
  ];

  it('finds the largest step over all points', () => {
    expect(largestChange(rows, 'cves')).toEqual({ before: 2, after: 3 });
  });

  it('finds the step near a chosen point, as a click seldom hits the point after it', () => {
    expect(largestChange(rows, 'cves', 4)).toEqual({ before: 2, after: 3 });
    // the drop at the end is nearer
    expect(largestChange(rows, 'cves', 6)).toEqual({ before: 6, after: 7 });
  });

  it('takes the chosen point when nothing changed near it, and nothing without points', () => {
    const flat = rows.map(row => ({ ...row, cvesCritical: 1, cvesHigh: 1 }));
    expect(largestChange(flat, 'cves', 4)).toEqual({ before: 4, after: 5 });
    expect(largestChange(flat, 'cves')).toBeUndefined();
    expect(largestChange(rows.slice(0, 1), 'cves')).toBeUndefined();
    // the failed controls have no values in these rows
    expect(largestChange(rows, 'controls')).toBeUndefined();
  });
});

// the namespace of the workloads as the ServiceMonitor of the Kubescape chart scrapes it, in
// exported_namespace next to the namespace of the exporter, or in namespace with honorLabels
function vector(values: Record<string, number>, honorLabels = false) {
  return {
    data: {
      result: Object.entries(values).map(([namespace, value]) => ({
        metric: honorLabels
          ? { namespace }
          : { namespace: 'kubescape', exported_namespace: namespace },
        value: [0, String(value)],
      })),
    },
  };
}

describe('fetchTrendChanges', () => {
  it('compares the totals of each namespace at the two points', async () => {
    const before = at('2026-11-18T00:00:00Z');
    const after = at('2026-11-18T05:00:00Z');
    mocks.request.mockImplementation(async (url: string) => {
      const params = new URL(url, 'http://localhost').searchParams;
      const critical = params.get('query')!.includes('critical');
      const later = params.get('time') === String(after / 1000);
      if (critical) {
        return vector(later ? { shop: 12, tools: 3, preview: 5 } : { shop: 2, tools: 3, old: 1 });
      }
      // a Prometheus that keeps the labels of the exporter
      return vector(
        later ? { shop: 80, tools: 30, preview: 9 } : { shop: 20, tools: 30, old: 4 },
        true
      );
    });

    const found = await fetchTrendChanges('prd', 'cves', { before, after });

    expect(found.namespaceCount).toBe(4);
    // tools did not change
    expect(found.changes.map(item => item.namespace)).toEqual(['shop', 'preview', 'old']);
    expect(found.changes[0]).toEqual({
      namespace: 'shop',
      before: { critical: 2, high: 20 },
      after: { critical: 12, high: 80 },
    });
    expect(found.changes.map(appearedOrWent)).toEqual([undefined, 'new', 'gone']);
    const [url, options] = mocks.request.mock.calls[0];
    expect(url).toContain('/proxy/api/v1/query?');
    expect(new URL(url, 'http://localhost').searchParams.get('query')).toBe(
      'max by (namespace, exported_namespace) (kubescape_vulnerabilities_total_namespace_critical)'
    );
    expect(options).toEqual({ cluster: 'prd', autoLogoutOnAuthError: false });
  });
});

describe('the daily scan', () => {
  it('reads the time of a daily schedule in UTC', () => {
    expect(dailyTime('12 1 * * *')).toEqual({ minute: 12, hour: 1 });
    expect(dailyTime('0 23 * * *', 'Etc/UTC')).toEqual({ minute: 0, hour: 23 });
    // another time zone, or another schedule, is not a time of day this can place
    expect(dailyTime('12 1 * * *', 'Europe/Amsterdam')).toBeUndefined();
    expect(dailyTime('*/30 * * * *')).toBeUndefined();
    expect(dailyTime('12 1 * * 1')).toBeUndefined();
  });

  it('reads the CronJob of the rescan in the namespace of Kubescape', async () => {
    mocks.request.mockResolvedValue({ spec: { schedule: '12 1 * * *' } });

    expect(await fetchScanSchedule('prd', 'cves')).toEqual({
      cronJob: 'kubevuln-scheduler',
      schedule: '12 1 * * *',
      minute: 12,
      hour: 1,
    });
    expect(mocks.request).toHaveBeenCalledWith(
      '/apis/batch/v1/namespaces/kubescape/cronjobs/kubevuln-scheduler',
      { cluster: 'prd' }
    );

    // the configuration scan of the failed controls
    await fetchScanSchedule('prd', 'controls');
    expect(mocks.request.mock.calls[1][0]).toContain('/cronjobs/kubescape-scheduler');

    // not allowed to read it
    mocks.request.mockRejectedValue(Object.assign(new Error('forbidden'), { status: 403 }));
    expect(await fetchScanSchedule('prd', 'cves')).toBeUndefined();
  });

  it('knows when the scan last started, and whether it was near an interval', () => {
    const schedule = { cronJob: 'kubevuln-scheduler', schedule: '12 1 * * *', minute: 12, hour: 1 };
    expect(lastScanStart(schedule, at('2026-11-18T05:00:00Z'))).toBe(at('2026-11-18T01:12:00Z'));
    // before the scan of the day, the scan of the day before
    expect(lastScanStart(schedule, at('2026-11-18T00:30:00Z'))).toBe(at('2026-11-17T01:12:00Z'));

    const after = at('2026-11-18T05:00:00Z');
    expect(scanNear(schedule, { before: after - 4 * hour, after })).toBe(true);
    // a scan that started some hours before the interval still writes its reports
    expect(
      scanNear(schedule, { before: at('2026-11-18T06:00:00Z'), after: after + 2 * hour })
    ).toBe(true);
    expect(
      scanNear(schedule, { before: at('2026-11-18T12:00:00Z'), after: at('2026-11-18T14:00:00Z') })
    ).toBe(false);
    expect(scanNear(undefined, { before: 0, after })).toBe(false);
  });
});

describe('likelyCause', () => {
  const item = (
    namespace: string,
    before: [number, number] | undefined,
    after: [number, number] | undefined
  ): NamespaceChange => ({
    namespace,
    before: before ? { critical: before[0], high: before[1] } : {},
    after: after ? { critical: after[0], high: after[1] } : {},
  });

  it('names namespaces that appeared or went', () => {
    const found = {
      changes: [item('preview-42', undefined, [10, 200]), item('shop', [1, 10], [2, 12])],
      namespaceCount: 20,
    };
    expect(likelyCause(found, 'cves', true)).toMatch(/^Mostly namespaces that appeared or went/);
  });

  it('points at an update of the vulnerability database when most namespaces changed at the scan', () => {
    const changes = ['a', 'b', 'c', 'd', 'e', 'f'].map(name => item(name, [1, 10], [2, 14]));
    const found = { changes, namespaceCount: 8 };
    expect(likelyCause(found, 'cves', true)).toMatch(/vulnerability database was updated/);
    expect(likelyCause(found, 'controls', true)).toMatch(/controls or their configuration/);
    // not at the time of the scan
    expect(likelyCause(found, 'cves', false)).toBe(
      'Spread over 6 namespaces, not at the time of the daily scan.'
    );
  });

  it('names the namespaces that carry the change', () => {
    const found = {
      changes: [item('shop', [1, 10], [30, 400]), item('tools', [1, 10], [2, 11])],
      namespaceCount: 30,
    };
    expect(likelyCause(found, 'cves', true)).toMatch(
      /^Mostly in shop and tools: workloads there were added, removed or moved to other images/
    );
  });

  it('says when no namespace changed', () => {
    expect(likelyCause({ changes: [], namespaceCount: 5 }, 'cves', false)).toMatch(
      /^No namespace total changed/
    );
  });
});
