import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import type { ReactNode } from 'react';
import { vi } from 'vitest';
import { TrendsSection } from './Trends';

const mocks = vi.hoisted(() => ({
  fetchTrends: vi.fn(),
  detectPrometheus: vi.fn(),
  update: vi.fn(),
  prometheusUrl: '/proxy' as string | undefined,
  clusters: ['cluster-a'],
  fetchTrendChanges: vi.fn(),
  fetchScanSchedule: vi.fn(),
}));
vi.mock('./prometheus', async importOriginal => ({
  ...(await importOriginal<typeof import('./prometheus')>()),
  fetchTrends: mocks.fetchTrends,
  detectPrometheus: mocks.detectPrometheus,
}));
vi.mock('../common/config-store', () => ({
  getPrometheusUrl: () => mocks.prometheusUrl,
  isValidAlertmanagerAddress: () => true,
  kubescapeConfigStore: { useConfig: () => () => ({}), update: mocks.update },
}));
vi.mock('../index', () => ({
  useHLSelectedClusters: () => mocks.clusters,
  RoutingName: {
    VulnerabilitiesNamespaceSummary: 'vulnerabilities',
    KubescapeConfigurationScanNamespaceSummary: 'compliance',
  },
}));
vi.mock('../custom-objects/api-queries', () => ({ getKubescapeNamespace: vi.fn() }));
vi.mock('./trendChanges', async importOriginal => ({
  ...(await importOriginal<typeof import('./trendChanges')>()),
  fetchTrendChanges: mocks.fetchTrendChanges,
  fetchScanSchedule: mocks.fetchScanSchedule,
}));
vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', () => ({
  SectionBox: ({ title, children }: { title: string; children: ReactNode }) => (
    <section>
      <h2>{title}</h2>
      {children}
    </section>
  ),
  // like Headlamp's link, it names the cluster and the page it opens
  Link: ({ children, routeName, params, activeCluster }: any) => (
    <a href={`/${activeCluster}/${routeName}/${params.namespace}`}>{children as ReactNode}</a>
  ),
}));
// jsdom has no layout to draw charts in; the legend and table carry the values
vi.mock('recharts', () => {
  const Nothing = () => null;
  return {
    ResponsiveContainer: ({ children }: { children: ReactNode }) => <div>{children}</div>,
    LineChart: Nothing,
    ReferenceArea: Nothing,
    CartesianGrid: Nothing,
    Line: Nothing,
    Tooltip: Nothing,
    XAxis: Nothing,
    YAxis: Nothing,
  };
});

const rows = [
  {
    time: new Date('2026-10-28T12:00:00').getTime(),
    controlsCritical: 4,
    controlsHigh: 20,
    cvesCritical: 9,
    cvesHigh: 120,
  },
  {
    time: new Date('2026-10-29T12:00:00').getTime(),
    controlsCritical: 2,
    controlsHigh: 18,
    cvesCritical: 7,
    cvesHigh: 1500,
  },
];

beforeEach(() => {
  mocks.fetchTrendChanges.mockReset();
  mocks.fetchScanSchedule.mockReset().mockResolvedValue(undefined);
  mocks.fetchTrends.mockReset().mockResolvedValue(rows);
  mocks.detectPrometheus.mockReset().mockResolvedValue([]);
  mocks.update.mockReset();
  mocks.prometheusUrl = '/proxy';
  mocks.clusters = ['cluster-a'];
});
afterEach(cleanup);

it('shows the latest values and a table of the days', async () => {
  render(<TrendsSection />);

  const controls = (await screen.findByText('Failed controls')).parentElement!;
  expect(within(controls).getByText('2')).toBeTruthy();
  expect(within(controls).getByText('18')).toBeTruthy();
  expect(mocks.fetchTrends).toHaveBeenCalledWith('cluster-a', 30);

  fireEvent.click(screen.getByRole('button', { name: 'Show table' }));
  const tableRows = screen.getAllByRole('row');
  expect(tableRows).toHaveLength(3);
  // newest first
  expect(within(tableRows[1]).getByText((1500).toLocaleString())).toBeTruthy();
});

it('reads the chosen time range', async () => {
  mocks.fetchTrends
    .mockResolvedValueOnce(rows)
    .mockResolvedValueOnce([{ ...rows[1], controlsHigh: 33 }]);
  render(<TrendsSection />);
  await screen.findByText('Failed controls');

  fireEvent.click(screen.getByRole('button', { name: 'Last 90 days' }));

  expect(mocks.fetchTrends).toHaveBeenLastCalledWith('cluster-a', 90);
  // the values of the range are shown
  expect(await screen.findByText('33')).toBeTruthy();
});

it('does not show the trends of the cluster chosen before under another cluster', async () => {
  let answer: (found: unknown) => void = () => {};
  mocks.fetchTrends
    .mockResolvedValueOnce(rows)
    .mockImplementationOnce(() => new Promise(resolve => (answer = resolve)));
  const { rerender } = render(<TrendsSection />);
  const controls = (await screen.findByText('Failed controls')).parentElement!;
  expect(within(controls).getByText('18')).toBeTruthy();

  // another cluster, whose Prometheus has yet to answer
  mocks.clusters = ['cluster-b'];
  rerender(<TrendsSection />);

  expect(mocks.fetchTrends).toHaveBeenLastCalledWith('cluster-b', 30);
  expect(screen.queryByText('Failed controls')).toBeNull();
  expect(screen.getByText('Reading the trends…')).toBeTruthy();

  await act(async () => answer([{ ...rows[1], controlsHigh: 33 }]));
  const answered = screen.getByText('Failed controls').parentElement!;
  expect(within(answered).getByText('33')).toBeTruthy();
});

it('explains how to get metrics when Prometheus has none', async () => {
  mocks.fetchTrends.mockResolvedValue([]);
  render(<TrendsSection />);

  expect(await screen.findByText(/prometheusExporter.serviceMonitor.enabled=true/)).toBeTruthy();
});

it('offers the Prometheus found in the cluster while none is configured', async () => {
  mocks.prometheusUrl = undefined;
  mocks.detectPrometheus.mockResolvedValue(['monitoring/prometheus:9090']);
  render(<TrendsSection />);

  fireEvent.click(await screen.findByText('Use monitoring/prometheus:9090'));

  expect(mocks.update).toHaveBeenCalledWith({ prometheusUrl: 'monitoring/prometheus:9090' });
  expect(mocks.fetchTrends).not.toHaveBeenCalled();
});

it('shows why the trends could not be read', async () => {
  mocks.fetchTrends.mockRejectedValue(new Error('503 Service Unavailable'));
  render(<TrendsSection />);

  expect(
    await screen.findByText('Unable to read the trends from Prometheus: 503 Service Unavailable')
  ).toBeTruthy();
});

it('explains a change of the CVEs by the namespaces that changed and the daily rescan', async () => {
  mocks.fetchTrendChanges.mockResolvedValue({
    namespaceCount: 3,
    changes: [
      {
        namespace: 'preview-42',
        before: {},
        after: { critical: 2, high: 1300 },
      },
      {
        namespace: 'shop',
        before: { critical: 9, high: 120 },
        after: { critical: 5, high: 200 },
      },
    ],
  });
  // the rescan starts at 01:12 UTC every day
  mocks.fetchScanSchedule.mockResolvedValue({
    cronJob: 'kubevuln-scheduler',
    schedule: '12 1 * * *',
    minute: 12,
    hour: 1,
  });
  render(<TrendsSection />);
  await screen.findByText('CVEs');

  // the largest change of the CVEs: from the first point to the second
  const cves = screen.getByText('CVEs').parentElement!;
  fireEvent.click(within(cves).getByRole('button', { name: 'explain the largest change' }));

  expect(await screen.findByText('What changed in the CVEs')).toBeTruthy();
  expect(mocks.fetchTrendChanges).toHaveBeenCalledWith('cluster-a', 'cves', {
    before: rows[0].time,
    after: rows[1].time,
  });
  expect(mocks.fetchScanSchedule).toHaveBeenCalledWith('cluster-a', 'cves');
  expect(await screen.findByText(/^Mostly namespaces that appeared or went/)).toBeTruthy();
  expect(
    screen.getByText(
      /The daily vulnerability rescan of all images \(kubevuln-scheduler, 01:12 UTC\)/
    )
  ).toBeTruthy();
  // the sums over the namespaces, and each namespace with its page
  expect(screen.getByText('in 2 of 3 namespaces')).toBeTruthy();
  expect(screen.getByText(`+${(1380).toLocaleString()}`)).toBeTruthy();
  expect(screen.getByRole('link', { name: 'preview-42' }).getAttribute('href')).toBe(
    '/cluster-a/vulnerabilities/preview-42'
  );
  expect(screen.getByText('new')).toBeTruthy();
  expect(screen.getByText('-4')).toBeTruthy();

  fireEvent.click(screen.getByRole('button', { name: 'Close' }));
  expect(screen.queryByText('What changed in the CVEs')).toBeNull();
});
