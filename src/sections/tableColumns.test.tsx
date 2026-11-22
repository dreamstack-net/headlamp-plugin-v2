import { cleanup, render, screen } from '@testing-library/react';
import type { ReactNode } from 'react';
import { vi } from 'vitest';
import { addKubescapeColumns } from './tableColumns';
import { clearWorkloadSummaries } from './workloadSummaries';

const mocks = vi.hoisted(() => ({
  listQuery: vi.fn(),
  config: {} as any,
  // the requests for the exceptions, and the setup of the cluster
  request: vi.fn(),
  setup: {} as any,
}));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ request: mocks.request }));
vi.mock('../common/clusterContext', () => ({ getAllowedNamespaces: () => [] }));
vi.mock('../common/kubescapeSetup', () => ({
  readClusterSetup: async () => mocks.setup,
  scannersApplyExceptions: (setup: any) => setup.capabilities?.riskAcceptance === 'enable',
}));
vi.mock('../query', () => ({
  paginatedListQuery: async (cluster: string, resourceClass: any, ...rest: any[]) => ({
    items: await mocks.listQuery(resourceClass, cluster, ...rest),
  }),
}));
vi.mock('../model', () => ({
  vulnerabilityManifestSummaryClass: { pluralName: 'vulnerabilitymanifestsummaries' },
  workloadConfigurationScanSummaryClass: { pluralName: 'workloadconfigurationscansummaries' },
}));
vi.mock('../common/config-store', () => ({ kubescapeConfigStore: { get: () => mocks.config } }));
vi.mock('../index', () => ({
  RoutingName: {
    KubescapeVulnerabilityDetails: 'Vulnerability',
    KubescapeWorkloadConfigurationScanDetails: 'Configuration Scan',
  },
}));
vi.mock('@kinvolk/headlamp-plugin/lib/Utils', () => ({ getCluster: () => 'current' }));
vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', () => ({
  // like Headlamp's Link: with an activeCluster, the cluster parameter of the route is all
  // selected clusters, that one first; the route of a configuration scan has it twice
  Link: ({ children, routeName, params, activeCluster, 'aria-label': label }: any) => {
    const cluster = activeCluster ? `${activeCluster}+cluster-z` : params.cluster;
    const scanCluster = routeName === 'Configuration Scan' ? `/${cluster}` : '';
    return (
      <a
        href={`/c/${cluster}/${routeName}${scanCluster}/${params.namespace}/${params.name}`}
        aria-label={label}
      >
        {children}
      </a>
    );
  },
}));

const workloadLabels = {
  'kubescape.io/workload-kind': 'Deployment',
  'kubescape.io/workload-name': 'web',
  'kubescape.io/workload-namespace': 'shop',
};

beforeEach(() => {
  mocks.config = {};
  // the scanners apply the exceptions, unless a test says otherwise
  mocks.setup = { capabilities: { riskAcceptance: 'enable' } };
  mocks.request.mockReset().mockResolvedValue({ items: [] });
  clearWorkloadSummaries();
  mocks.listQuery.mockReset().mockImplementation(async (resourceClass: any) =>
    resourceClass.pluralName === 'vulnerabilitymanifestsummaries'
      ? [
          {
            metadata: {
              name: 'deployment-web-web',
              namespace: 'shop',
              labels: { ...workloadLabels, 'kubescape.io/workload-container-name': 'web' },
            },
            spec: {
              severities: {
                critical: { all: 2 },
                high: { all: 7 },
                medium: { all: 0 },
                low: { all: 0 },
              },
            },
          },
        ]
      : [
          {
            metadata: { name: 'deployment-web', namespace: 'shop', labels: workloadLabels },
            spec: {
              severities: { critical: 1, high: 4, medium: 0, low: 0 },
              controls: Object.fromEntries(
                ['C-0001', 'C-0002', 'C-0003', 'C-0004', 'C-0005'].map((controlID, index) => [
                  controlID,
                  {
                    controlID,
                    severity: { severity: index === 0 ? 'Critical' : 'High' },
                    status: { status: 'failed' },
                  },
                ])
              ),
            },
          },
        ]
  );
});
afterEach(cleanup);

it('adds the columns to the workload lists before the age column', () => {
  const columns = addKubescapeColumns({ id: 'headlamp-deployments', columns: ['name', 'age'] });
  expect(columns.map((column: any) => column.id ?? column)).toEqual([
    'name',
    'kubescape-vulnerabilities',
    'kubescape-controls',
    'age',
  ]);
  // processors may run more than once
  expect(addKubescapeColumns({ id: 'headlamp-deployments', columns })).toHaveLength(4);
});

it('leaves other lists alone, and all lists when turned off', () => {
  expect(addKubescapeColumns({ id: 'headlamp-services', columns: ['name'] })).toEqual(['name']);
  mocks.config = { tableColumns: false };
  expect(addKubescapeColumns({ id: 'headlamp-pods', columns: ['name'] })).toEqual(['name']);
});

it('shows the critical and high counts of the workload that runs a pod', async () => {
  const [cves, controls] = addKubescapeColumns({ id: 'headlamp-pods', columns: [] });
  const pod = {
    kind: 'Pod',
    cluster: 'cluster-a',
    metadata: {
      name: 'web-6d4cf56db6-abcde',
      namespace: 'shop',
      labels: { 'pod-template-hash': '6d4cf56db6' },
      ownerReferences: [{ kind: 'ReplicaSet', name: 'web-6d4cf56db6', controller: true }],
    },
  };

  render(
    <>
      {cves.render(pod) as ReactNode}
      {controls.render(pod) as ReactNode}
    </>
  );

  // the page of the CVEs reads the first cluster of the address
  expect((await screen.findByLabelText('2 Critical findings')).getAttribute('href')).toBe(
    '/c/cluster-a+cluster-z/Vulnerability/shop/deployment-web-web'
  );
  expect(screen.getByLabelText('7 High findings')).toBeTruthy();
  // the page of the configuration scan reads its cluster from the path of the route
  expect(screen.getByLabelText('4 High findings').getAttribute('href')).toBe(
    '/c/cluster-a/Configuration Scan/cluster-a/shop/deployment-web'
  );
  expect(mocks.listQuery.mock.calls.map(call => call[1])).toEqual(['cluster-a', 'cluster-a']);
});

it('is neither sorted nor searched, as the counts arrive after the table sorted its rows', async () => {
  // Headlamp's table sorts its rows, and takes the values it searches, once per change of its
  // data: rows whose counts were read later would keep the place of rows without results
  const columns = addKubescapeColumns({ id: 'headlamp-deployments', columns: [] });
  const web = { kind: 'Deployment', metadata: { name: 'web', namespace: 'shop' } };

  render(<>{columns[0].render(web) as ReactNode}</>);
  await screen.findByLabelText('2 Critical findings');

  for (const column of columns) {
    expect(column.sort).toBe(false);
    expect(column.getValue(web)).toBe('');
  }
});

it('leaves out the controls that exceptions exclude where the plugin applies them', async () => {
  mocks.setup = { capabilities: {} };
  mocks.request.mockImplementation(async (url: string) =>
    url === '/apis/kubescape.io/v1beta1/securityexceptions'
      ? {
          items: [
            {
              kind: 'SecurityException',
              metadata: { name: 'accepted', namespace: 'shop' },
              spec: { posture: [{ controlID: 'C-0002', action: 'ignore' }] },
            },
          ],
        }
      : { items: [] }
  );
  const [, controls] = addKubescapeColumns({ id: 'headlamp-deployments', columns: [] });
  const web = {
    kind: 'Deployment',
    cluster: 'cluster-b',
    metadata: { name: 'web', namespace: 'shop' },
  };

  render(<>{controls.render(web) as ReactNode}</>);

  expect(await screen.findByLabelText('3 High findings')).toBeTruthy();
  expect(screen.getByLabelText('1 Critical findings')).toBeTruthy();
});
