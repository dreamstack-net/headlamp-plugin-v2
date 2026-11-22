import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ReactNode } from 'react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { vi } from 'vitest';
import { manifest, summary } from './testFixtures';

const mocks = vi.hoisted(() => ({
  request: vi.fn(),
  clusters: ['cluster-a'] as string[],
}));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ request: mocks.request }));
vi.mock('../common/clusterContext', () => ({
  getAllowedNamespaces: () => [],
  isAllowedNamespaceUpdated: () => false,
}));
vi.mock('../custom-objects/api-queries', () => ({
  getKubescapeNamespace: async () => ({ kubeScapeNamespace: 'kubescape' }),
}));
vi.mock('../common/config-store', () => ({
  kubescapeConfigStore: { useConfig: () => () => ({ pageSize: 50 }) },
}));
vi.mock('../common/SetupCheck', () => ({ SetupCheck: () => null }));
vi.mock('../index', () => ({
  RoutingName: { KubescapeClusterComparison: 'cluster-comparison' },
  useHLSelectedClusters: () => mocks.clusters,
}));
vi.mock('../model', () => {
  const objectClass = (pluralName: string) => ({
    pluralName,
    apiEndpoint: {
      apiInfo: [{ group: 'spdx.softwarecomposition.kubescape.io', version: 'v1beta1' }],
    },
  });
  return {
    vulnerabilityManifestClass: objectClass('vulnerabilitymanifests'),
    vulnerabilityManifestSummaryClass: objectClass('vulnerabilitymanifestsummaries'),
  };
});
// the tabs as buttons, the shown one pressed; like Headlamp's, they follow defaultIndex
vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', () => ({
  Link: ({ children, routeName }: { children: ReactNode; routeName: string }) => (
    <a href={`/${routeName}`}>{children}</a>
  ),
  SectionBox: ({ children }: { children: ReactNode }) => <section>{children}</section>,
  Tabs: ({ tabs, defaultIndex, onTabChanged }: any) => (
    <div>
      {tabs.map((tab: { label: string }, index: number) => (
        <button
          key={tab.label}
          aria-pressed={index === defaultIndex}
          onClick={() => onTabChanged(index)}
        >
          {tab.label}
        </button>
      ))}
    </div>
  ),
}));

import KubescapeVulnerabilities, { vulnerabilityContext } from './Vulnerabilities';

const api = '/apis/spdx.softwarecomposition.kubescape.io/v1beta1';

// one workload per cluster, in its one namespace, whose report is in the operator namespace;
// `pending` holds back the summaries of a cluster, `reportPending` the report
function respond(
  pending: Map<string, Promise<unknown>> = new Map(),
  reportPending: Promise<unknown> = Promise.resolve()
) {
  mocks.request.mockImplementation(async (url: string, options: { cluster: string }) => {
    const cluster = options.cluster;
    // the metadata of the summaries, which names their namespaces
    if (url === `${api}/vulnerabilitymanifestsummaries?limit=1000`) {
      return { items: [{ metadata: { name: 'deployment-web', namespace: 'workloads' } }] };
    }
    if (url.startsWith(`${api}/namespaces/workloads/vulnerabilitymanifestsummaries?`)) {
      await pending.get(cluster);
      const s = summary();
      s.metadata = {
        ...s.metadata,
        name: `deployment-web-${cluster}`,
        labels: { ...s.metadata.labels, 'kubescape.io/workload-name': `web-${cluster}` },
      };
      s.spec.vulnerabilitiesRef = {
        all: { kind: 'VulnerabilityManifest', name: 'nginx', namespace: 'kubescape' },
        relevant: null as any,
      };
      return { items: [s], metadata: {} };
    }
    if (url === `${api}/namespaces/kubescape/vulnerabilitymanifests/nginx`) {
      await reportPending;
      const report = manifest();
      report.metadata = { ...report.metadata, name: 'nginx', namespace: 'kubescape' };
      return report;
    }
    throw Object.assign(new Error('not found'), { status: 404 });
  });
}

let search = '';
function LocationProbe() {
  search = useLocation().search;
  return null;
}

function page(path = '/c/cluster-a/kubescape/vulnerabilities') {
  return (
    <MemoryRouter initialEntries={[path]}>
      <KubescapeVulnerabilities />
      <LocationProbe />
    </MemoryRouter>
  );
}

function summaryReads(cluster: string) {
  return mocks.request.mock.calls.filter(
    ([url, options]) =>
      url.includes('/vulnerabilitymanifestsummaries?resourceVersion=fullSpec') &&
      options.cluster === cluster
  ).length;
}

beforeEach(() => {
  vulnerabilityContext.queryTasks = [];
  vulnerabilityContext.workloadScans = [];
  vulnerabilityContext.imageScans.clear();
  window.sessionStorage.clear();
  mocks.request.mockReset();
  mocks.clusters = ['cluster-a'];
});
afterEach(cleanup);

it('reads the scans of the clusters again when clusters are added to the page', async () => {
  respond();
  const shown = render(page());
  expect(await screen.findByText('1 scans')).toBeTruthy();

  // Headlamp keeps the page when a cluster is added to the URL
  mocks.clusters = ['cluster-a', 'cluster-b'];
  shown.rerender(page());

  expect(await screen.findByText('2 scans')).toBeTruthy();
  expect(summaryReads('cluster-a')).toBe(1);
  expect(summaryReads('cluster-b')).toBe(1);
  expect(vulnerabilityContext.workloadScans.map(w => w.name).sort()).toEqual([
    'web-cluster-a',
    'web-cluster-b',
  ]);
});

it('keeps the read of the clusters selected before out of the page and the cache', async () => {
  let finishA: () => void = () => {};
  respond(new Map([['cluster-a', new Promise<void>(resolve => (finishA = resolve))]]));
  const shown = render(page());
  await act(async () => {});
  expect(summaryReads('cluster-a')).toBe(1);

  // another cluster before the first one answered
  mocks.clusters = ['cluster-b'];
  shown.rerender(page());
  expect(await screen.findByText('1 scans')).toBeTruthy();

  // the first cluster answers late
  await act(async () => finishA());
  expect(screen.getByText('1 scans')).toBeTruthy();
  expect(vulnerabilityContext.workloadScans.map(w => w.name)).toEqual(['web-cluster-b']);
});

it('opens the tab a link asks for and keeps the tab the user chooses next', async () => {
  respond();
  render(page('/c/cluster-a/kubescape/vulnerabilities?tab=upgrades'));

  expect(
    (await screen.findByRole('button', { name: 'Upgrades' })).getAttribute('aria-pressed')
  ).toBe('true');

  fireEvent.click(screen.getByRole('button', { name: 'Images' }));

  // the address no longer asks for the Upgrades tab, which would open it again
  expect(search).toBe('');
  expect(screen.getByRole('button', { name: 'Images' }).getAttribute('aria-pressed')).toBe('true');
});

it('reads on where reading stopped with More scans', async () => {
  let failing = true;
  respond();
  const answer = mocks.request.getMockImplementation()!;
  mocks.request.mockImplementation(async (url: string, options: { cluster: string }) => {
    if (failing && url.endsWith('/vulnerabilitymanifests/nginx')) {
      throw Object.assign(new Error('timeout'), { status: 504 });
    }
    return answer(url, options);
  });
  const error = vi.spyOn(console, 'error').mockImplementation(() => {});
  render(page());

  const more = await screen.findByRole('button', { name: 'More scans' });
  expect(screen.getByText(/1 image reports could not be read/)).toBeTruthy();

  // the report can be read now
  failing = false;
  fireEvent.click(more);

  await waitFor(() => expect(screen.queryByRole('button', { name: 'More scans' })).toBeNull());
  expect(screen.getByText('1 scans')).toBeTruthy();
  expect(screen.queryByText(/image reports could not be read/)).toBeNull();
  expect(vulnerabilityContext.workloadScans[0].imageScan?.manifestName).toBe('nginx');
  error.mockRestore();
});

it('shows the workloads while their reports are read, and what it read after', async () => {
  let finishReport: () => void = () => {};
  respond(new Map(), new Promise<void>(resolve => (finishReport = resolve)));
  render(page());

  // the tabs with a line of progress instead of the spinner of the page
  const progress = await screen.findByRole('status', {}, { timeout: 2000 });
  expect(progress.textContent).toContain('Reading 0 of 1 image reports');
  expect(screen.getByRole('button', { name: 'Resources' })).toBeTruthy();
  expect(screen.queryByText('1 scans')).toBeNull();

  await act(async () => finishReport());

  expect(await screen.findByText('1 scans')).toBeTruthy();
  expect(screen.queryByRole('status')).toBeNull();
  expect(screen.getByText(/^Read 1 workload and 1 image report in \d+\.\d s$/)).toBeTruthy();
  expect(vulnerabilityContext.workloadScans[0].imageScan?.manifestName).toBe('nginx');
});

it('links to the comparison of the clusters when more than one is selected', async () => {
  respond();
  const shown = render(page());
  expect(await screen.findByText('1 scans')).toBeTruthy();
  expect(screen.queryByRole('link', { name: 'Compare clusters' })).toBeNull();

  mocks.clusters = ['cluster-a', 'cluster-b'];
  shown.rerender(page());

  expect(await screen.findByText('2 scans')).toBeTruthy();
  expect(screen.getByRole('link', { name: 'Compare clusters' }).getAttribute('href')).toBe(
    '/cluster-comparison'
  );
});
