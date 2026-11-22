import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { vi } from 'vitest';
import { WorkloadConfigurationScanSummary } from '../softwarecomposition/WorkloadConfigurationScanSummary';
import KubescapeControlResults, { isExcluded, statusOf } from './ControlResults';

const mocks = vi.hoisted(() => ({
  context: { workloadScans: [] as any[], queryTasks: [] as any[], exceptionErrors: [] as any[] },
  readConfigurationScans: vi.fn(),
  clusters: ['cluster-a'],
  // the access reviews
  post: vi.fn(),
  // what the links of the rows were given
  links: [] as any[],
}));

vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ post: mocks.post, request: vi.fn() }));

vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', () => ({
  Link: (props: any) => {
    mocks.links.push(props);
    return null;
  },
  NameValueTable: ({ rows }: any) => (
    <dl>
      {rows.map((row: any) => (
        <div key={row.name}>{`${row.name}: ${typeof row.value === 'string' ? row.value : ''}`}</div>
      ))}
    </dl>
  ),
  SectionBox: ({ children }: any) => <section>{children}</section>,
  // the links of a row and the buttons that open the exception form
  Table: ({ data, columns }: any) => (
    <div>
      {data?.map((row: any) => (
        <div key={row.metadata.name}>
          {columns
            .filter((column: any) => ['Name', 'fix', 'exception'].includes(column.id))
            .map((column: any) => (
              <span key={column.id}>
                {column.Cell({
                  row: { original: row },
                  cell: { row: { original: row }, getValue: () => row.metadata.name },
                })}
              </span>
            ))}
        </div>
      ))}
    </div>
  ),
}));
vi.mock('../common/config-store', () => ({
  kubescapeConfigStore: { get: () => ({}) },
  selectedFrameworkName: () => undefined,
}));
vi.mock('../common/url', () => ({ getLastURLSegment: () => 'C-0001' }));
vi.mock('../index', () => ({ RoutingName: {}, useHLSelectedClusters: () => mocks.clusters }));
vi.mock('../rego', () => ({
  useRegoData: () => ({ controls: [{ controlID: 'C-0001', name: 'Privileged' }], loading: false }),
}));
vi.mock('../exceptions/GuidedComplianceExceptionForm', () => ({
  GuidedComplianceExceptionForm: ({ workloadName, workloadNamespace }: any) => (
    <p>{`Exception form for ${workloadNamespace}/${workloadName}`}</p>
  ),
}));
vi.mock('./Compliance', () => ({
  configurationScanContext: mocks.context,
  readConfigurationScans: mocks.readConfigurationScans,
}));

afterEach(cleanup);

function scan(status: string, marks: { exceptedInFrameworks?: string[]; byPolicy?: boolean } = {}) {
  return {
    metadata: { name: 'deployment-web', namespace: 'shop', cluster: 'cluster-a', labels: {} },
    spec: {
      controls: {
        'C-0001': {
          controlID: 'C-0001',
          status: { status },
          exceptedByPolicy: !!marks.byPolicy,
          exceptedInFrameworks: marks.exceptedInFrameworks,
        },
      },
    },
    exceptedByPolicy: false,
  } as unknown as WorkloadConfigurationScanSummary;
}

it('excludes a result that an exception covers in the framework of the page', () => {
  const limited = scan('failed', { exceptedInFrameworks: ['nsa'] });
  expect(isExcluded(limited, 'C-0001', 'NSA')).toBe(true);
  expect(statusOf(limited, 'C-0001', 'NSA')).toBe('excluded');
  expect(isExcluded(limited, 'C-0001', 'MITRE')).toBe(false);
  expect(statusOf(limited, 'C-0001', 'MITRE')).toBe('failed');
  // the combined view of all controls is no framework
  expect(statusOf(limited, 'C-0001')).toBe('failed');

  expect(statusOf(scan('failed', { byPolicy: true }), 'C-0001')).toBe('excluded');
  const excludedWorkload = scan('passed');
  excludedWorkload.exceptedByPolicy = true;
  expect(statusOf(excludedWorkload, 'C-0001')).toBe('excluded');
  // a workload that the control did not check
  expect(isExcluded(scan('failed'), 'C-0002')).toBe(false);
  expect(statusOf(scan('failed'), 'C-0002')).toBe('');
});

it('says which clusters of the page have exceptions that could not be read', async () => {
  mocks.readConfigurationScans.mockImplementation(async () => {
    mocks.context.exceptionErrors = [
      { cluster: 'cluster-a', message: 'SecurityExceptions: forbidden' },
      // a cluster whose scans another page read
      { cluster: 'cluster-z', message: 'unreachable' },
    ];
    return [scan('failed')];
  });

  render(<KubescapeControlResults />);

  expect(
    await screen.findByText(
      /Unable to read the security exceptions of cluster cluster-a: SecurityExceptions: forbidden/
    )
  ).toBeTruthy();
  expect(screen.queryByText(/cluster-z/)).toBeNull();
  expect(screen.getByText('Passed: 0 of 1')).toBeTruthy();
});

it('links to the scan and its fix in the cluster of the scan alone', async () => {
  mocks.links = [];
  mocks.readConfigurationScans.mockImplementation(async () => {
    mocks.context.exceptionErrors = [];
    return [scan('failed')];
  });

  render(<KubescapeControlResults />);
  await screen.findByText('Passed: 0 of 1');

  // the routes name the cluster of the scan in their path as well; with an activeCluster,
  // Headlamp's Link fills in all selected clusters there (cluster-a+cluster-b)
  expect(mocks.links.length).toBeGreaterThanOrEqual(2);
  for (const link of mocks.links) {
    expect(link.params.cluster).toBe('cluster-a');
    expect(link.activeCluster).toBeUndefined();
  }
});

it('opens the exception form for a user who may not create exceptions', async () => {
  // the form offers the exception as YAML, also to a user who may only read (GitOps)
  mocks.post.mockResolvedValue({ status: { allowed: false } });
  const failed = scan('failed');
  failed.metadata.labels = {
    'kubescape.io/workload-kind': 'Deployment',
    'kubescape.io/workload-name': 'web',
    'kubescape.io/workload-namespace': 'shop',
  };
  mocks.readConfigurationScans.mockImplementation(async () => {
    mocks.context.exceptionErrors = [];
    return [failed];
  });

  render(<KubescapeControlResults />);
  const create = await screen.findByRole('button', { name: 'Create Security Exception' });
  await act(async () => {});

  expect(create.hasAttribute('disabled')).toBe(false);
  fireEvent.click(create);
  expect(screen.getByText('Exception form for shop/web')).toBeTruthy();
  // the button asks nothing; the form checks whether the user may create the exception
  expect(mocks.post).not.toHaveBeenCalled();
});
