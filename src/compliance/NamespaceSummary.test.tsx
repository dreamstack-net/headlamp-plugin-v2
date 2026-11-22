import { cleanup, render, screen } from '@testing-library/react';
import { vi } from 'vitest';
import KubescapeConfigurationScanNamespaceSummary, {
  countFailedControls,
} from './NamespaceSummary';

const mocks = vi.hoisted(() => ({
  context: { workloadScans: [] as any[], queryTasks: [] as any[], exceptionErrors: [] as any[] },
  readConfigurationScans: vi.fn(),
}));

vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', () => ({
  Link: () => null,
  NameValueTable: ({ rows }: any) => (
    <dl>
      {rows.map((row: any) => (
        <div key={row.name} data-testid={row.name}>
          {row.value}
        </div>
      ))}
    </dl>
  ),
  SectionBox: ({ children }: any) => <section>{children}</section>,
  Table: ({ data }: any) => <div>{`${data.length} workloads`}</div>,
}));
vi.mock('@kinvolk/headlamp-plugin/lib/Utils', () => ({ getCluster: () => 'cluster-a' }));
vi.mock('../common/config-store', () => ({
  kubescapeConfigStore: { get: () => ({}) },
  selectedFrameworkName: () => 'NSA',
}));
vi.mock('../common/url', () => ({ getLastURLSegment: () => 'shop' }));
vi.mock('../index', () => ({ RoutingName: {} }));
vi.mock('../query', () => ({
  queryTaskErrors: (tasks: any[]) =>
    tasks.filter(task => task.error).map(task => ({ cluster: task.cluster, message: task.error })),
}));
vi.mock('./Compliance', () => ({
  configurationScanContext: mocks.context,
  readConfigurationScans: mocks.readConfigurationScans,
}));

afterEach(cleanup);

function scan(cluster: string, namespace: string, results: Array<[string, string, string[]?]>) {
  return {
    metadata: { name: `deployment-${results.length}`, namespace, cluster },
    spec: {
      controls: Object.fromEntries(
        results.map(([controlID, severity, exceptedInFrameworks]) => [
          controlID,
          {
            controlID,
            severity: { scoreFactor: 5, severity },
            status: { status: 'failed' },
            exceptedByPolicy: false,
            exceptedInFrameworks,
          },
        ])
      ),
      // what the storage counts, without the exceptions the plugin applies
      severities: { critical: 9, high: 9, medium: 9, low: 9, unknown: 0 },
    },
    exceptedByPolicy: false,
  } as any;
}

const shop = scan('cluster-a', 'shop', [
  ['C-0001', 'High', ['nsa']],
  ['C-0002', 'Critical'],
  ['C-0003', 'Low'],
]);

it('counts the failed controls of the scans that no exception applies to', () => {
  expect(countFailedControls([shop], 'NSA')).toEqual({ critical: 1, high: 0, medium: 0, low: 1 });
  expect(countFailedControls([shop])).toEqual({ critical: 1, high: 1, medium: 0, low: 1 });
});

it('counts the header from the scans of its table, keeping the other clusters in the cache', async () => {
  mocks.readConfigurationScans.mockImplementation(async () => {
    mocks.context.queryTasks = [
      { cluster: 'cluster-a', error: 'namespace kube-system: forbidden' },
      { cluster: 'cluster-b', error: 'unreachable' },
    ];
    mocks.context.exceptionErrors = [
      { cluster: 'cluster-a', message: 'SecurityExceptions: forbidden' },
      { cluster: 'cluster-b', message: 'unreachable' },
    ];
    return [
      shop,
      scan('cluster-a', 'blog', [['C-0002', 'Critical']]),
      scan('cluster-b', 'shop', [['C-0002', 'Critical']]),
    ];
  });

  render(<KubescapeConfigurationScanNamespaceSummary />);

  expect(await screen.findByText('1 workloads')).toBeTruthy();
  expect(screen.getByTestId('Failed Controls').textContent).toBe('1 Critical0 High0 Medium1 Low');
  expect(mocks.readConfigurationScans.mock.calls[0][0]).toEqual(['cluster-a']);
  expect(mocks.readConfigurationScans.mock.calls[0][5]).toEqual({ keepOtherClusters: true });
  expect(
    screen.getByText(
      /Unable to read the security exceptions of cluster cluster-a: SecurityExceptions: forbidden/
    )
  ).toBeTruthy();
  expect(
    screen.getByText(
      /Unable to read the configuration scans of cluster cluster-a: namespace kube-system/
    )
  ).toBeTruthy();
  expect(screen.queryByText(/cluster-b/)).toBeNull();
});
