import { cleanup, render, screen, within } from '@testing-library/react';
import { ReactNode } from 'react';
import { vi } from 'vitest';
import { kevCatalogUrl, resetExploitData } from '../vulnerabilities/exploitData';
import { getImageScanKey, toImageScan, toWorkloadScan } from '../vulnerabilities/scanData';
import { manifest, match, summary } from '../vulnerabilities/testFixtures';

const mocks = vi.hoisted(() => ({
  readVulnerabilityScans: vi.fn(),
  configurationScans: [] as unknown[],
  config: {} as Record<string, unknown>,
}));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ request: vi.fn(), post: vi.fn() }));
vi.mock('@kinvolk/headlamp-plugin/lib/Utils', () => ({ getCluster: () => 'cluster-a' }));
vi.mock('../index', () => ({
  RoutingName: {
    ComplianceView: 'compliance',
    KubescapeVulnerabilities: 'vulnerabilities',
    ImageVulnerabilityDetails: 'image',
    ApplicationProfiles: 'runtime',
  },
  useHLSelectedClusters: () => ['cluster-a'],
}));
vi.mock('../common/config-store', () => ({
  kubescapeConfigStore: { useConfig: () => () => mocks.config },
  getAlertmanagerUrl: () => undefined,
  // the framework chosen on the Compliance page, which the overview does not count by
  selectedFrameworkName: () => 'NSA',
}));
vi.mock('../common/clusterContext', () => ({
  getAllowedNamespaces: () => [],
  isAllowedNamespaceUpdated: () => false,
}));
vi.mock('../custom-objects/api-queries', () => ({ getKubescapeNamespace: vi.fn() }));
vi.mock('../model', () => ({}));
vi.mock('../common/SetupCheck', () => ({ SetupCheck: () => null }));
vi.mock('../compliance/Compliance', () => ({
  configurationScanContext: { queryTasks: [], exceptionErrors: [] },
  readConfigurationScans: async () => mocks.configurationScans,
}));
vi.mock('../rego', () => ({
  activeFrameworkNames: () => [],
  useRegoData: () => ({ frameworks: [] }),
}));
vi.mock('../exceptions/apply-security-exceptions', () => ({
  fetchSecurityExceptions: async () => ({
    namespaced: [],
    cluster: [],
    namespaceLabelsByName: new Map(),
  }),
}));
vi.mock('./Trends', () => ({ TrendsSection: () => null }));
vi.mock('../vulnerabilities/Vulnerabilities', async importOriginal => ({
  ...(await importOriginal<typeof import('../vulnerabilities/Vulnerabilities')>()),
  readVulnerabilityScans: mocks.readVulnerabilityScans,
  vulnerabilityContext: { queryTasks: [] },
}));
// like Headlamp's link, it does not call a click handler of its caller
vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', () => ({
  Link: ({ children, routeName, search }: any) => (
    <a href={`/${routeName}${search ?? ''}`}>{children as ReactNode}</a>
  ),
  SectionBox: ({ title, children }: { title: string; children: ReactNode }) => (
    <section>
      <h2>{title}</h2>
      {children}
    </section>
  ),
  NameValueTable: ({ rows }: any) => (
    <dl>
      {rows.map((row: any) => (
        <div key={row.name}>
          <dt>{row.name}</dt>
          <dd>{row.value}</dd>
        </div>
      ))}
    </dl>
  ),
  DateLabel: ({ date }: { date: string }) => <time dateTime={date}>{date}</time>,
}));

import KubescapeOverview from './Overview';

beforeEach(() => {
  mocks.config = {};
  mocks.configurationScans = [];
  mocks.readVulnerabilityScans.mockReset().mockResolvedValue([]);
  resetExploitData();
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it('counts the failed checks of all controls, whatever framework the Compliance page shows', async () => {
  const result = (controlID: string, exceptedInFrameworks?: string[]) => ({
    controlID,
    status: { status: 'failed' },
    exceptedByPolicy: false,
    exceptedInFrameworks,
  });
  mocks.configurationScans = [
    {
      metadata: { labels: {}, cluster: 'cluster-a' },
      exceptedByPolicy: false,
      // C-2 is excepted in the framework that the Compliance page shows, and only there
      spec: { controls: { 'C-1': result('C-1'), 'C-2': result('C-2', ['nsa']) } },
    },
  ];
  render(<KubescapeOverview />);

  const row = (await screen.findByText('Failed checks')).closest('div')!;

  expect(within(row).getByText('2')).toBeTruthy();
});

it('links to the Upgrades tab of the Vulnerabilities page in the address', async () => {
  // an image with a fixable CVE
  const image = toImageScan(manifest());
  mocks.readVulnerabilityScans.mockResolvedValue([
    toWorkloadScan(summary(), new Map([[getImageScanKey(image), image]])),
  ]);
  render(<KubescapeOverview />);

  const link = await screen.findByText('All upgrades');

  expect(link.getAttribute('href')).toBe('/vulnerabilities?tab=upgrades');
});

it('counts the known exploited CVEs once that setting is on', async () => {
  mocks.config = { knownExploited: true };
  const fetchMock = vi.fn(async (url: string) =>
    url === kevCatalogUrl
      ? new Response(
          JSON.stringify({
            vulnerabilities: [{ cveID: 'CVE-2023-4863', dateAdded: '2023-09-13' }],
          }),
          { status: 200 }
        )
      : new Response('{}', { status: 404 })
  );
  vi.stubGlobal('fetch', fetchMock);
  // a CVE of the catalog, an advisory of the same CVE, and another CVE
  const image = toImageScan(manifest());
  const advisory = match('GHSA-j7hp-h8jx-5ppr');
  advisory.relatedVulnerabilities = [{ id: 'CVE-2023-4863', description: '' }];
  image.matches = [match('CVE-2023-4863'), advisory, match('CVE-1')];
  mocks.readVulnerabilityScans.mockResolvedValue([
    toWorkloadScan(summary(), new Map([[getImageScanKey(image), image]])),
  ]);
  render(<KubescapeOverview />);

  const count = await screen.findByText('2');
  expect(count.getAttribute('href')).toBe('/vulnerabilities?tab=cves');
  expect(within(count.closest('div')!).getByText('Known exploited CVEs')).toBeTruthy();
  expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([kevCatalogUrl]);
});
