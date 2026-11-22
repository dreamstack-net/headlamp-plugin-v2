import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { vi } from 'vitest';
import KubescapeWorkloadConfigurationScanDetails, { markExceptions } from './WorkloadScanDetails';

const mocks = vi.hoisted(() => ({
  context: { workloadScans: [] as any[], queryTasks: [] as any[], exceptionErrors: [] as any[] },
  readClusterSetup: vi.fn(),
  fetchSecurityExceptions: vi.fn(),
  applySecurityExceptionsToWorkloadScans: vi.fn(),
  markScannerExceptions: vi.fn(),
  fetchObject: vi.fn(),
  // the access reviews
  post: vi.fn(),
}));

vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ post: mocks.post, request: vi.fn() }));

vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', () => ({
  Link: () => null,
  NameValueTable: () => null,
  SectionBox: ({ children }: any) => <section>{children}</section>,
  // the buttons of the rows of the controls, and the value of their status, which decides
  // whether Headlamp draws the cell again
  Table: ({ data, columns }: any) => (
    <div>
      {data?.map((row: any) => (
        <div key={row.controlID}>
          {columns
            .filter((column: any) => column.id === 'Status')
            .map((column: any) => (
              <span key={column.id} data-testid={`status-${row.controlID}`}>
                {column.accessorFn(row)}
              </span>
            ))}
          {columns
            .filter((column: any) => column.id === 'actions')
            .map((column: any) => (
              <span key={column.id}>{column.Cell({ row: { original: row } })}</span>
            ))}
        </div>
      ))}
    </div>
  ),
}));
vi.mock('../common/clusterContext', () => ({ getAllowedNamespaces: () => ['shop'] }));
vi.mock('../common/config-store', () => ({ selectedFrameworkName: () => undefined }));
vi.mock('../common/kubescapeSetup', () => ({
  readClusterSetup: mocks.readClusterSetup,
  scannersApplyExceptions: (setup: any) => setup.capabilities?.riskAcceptance === 'enable',
}));
vi.mock('../common/url', () => ({
  getURLSegments: () => ['deployment-web', 'shop', 'cluster-a'],
}));
vi.mock('../exceptions/apply-security-exceptions', () => ({
  applySecurityExceptionsToWorkloadScans: mocks.applySecurityExceptionsToWorkloadScans,
  fetchSecurityExceptions: mocks.fetchSecurityExceptions,
  markScannerExceptions: mocks.markScannerExceptions,
}));
vi.mock('../exceptions/GuidedComplianceExceptionForm', () => ({
  GuidedComplianceExceptionForm: ({ controlID, workloadName, workloadNamespace }: any) => (
    <p>{`Exception form for ${controlID} of ${workloadNamespace}/${workloadName}`}</p>
  ),
}));
vi.mock('../index', () => ({ RoutingName: {} }));
vi.mock('../model', () => ({ fetchObject: mocks.fetchObject, workloadConfigurationScanClass: {} }));
vi.mock('../rego', () => ({ useRegoData: () => ({ controls: [] }) }));
vi.mock('./Compliance', () => ({ configurationScanContext: mocks.context }));

afterEach(cleanup);

function control(controlID: string, marks: Record<string, unknown> = {}) {
  return { controlID, status: { status: 'failed' }, rules: [], exceptedByPolicy: false, ...marks };
}

function workloadScan(): any {
  return {
    metadata: {
      name: 'deployment-web',
      namespace: 'shop',
      labels: {
        'kubescape.io/workload-kind': 'Deployment',
        'kubescape.io/workload-name': 'web',
        'kubescape.io/workload-namespace': 'shop',
      },
    },
    spec: {
      controls: {
        'C-0001': control('C-0001'),
        'C-0002': control('C-0002'),
        // a mark that the summary in the cache no longer has
        'C-0003': control('C-0003', { exceptedInFrameworks: ['mitre'] }),
      },
    },
    exceptedByPolicy: false,
  };
}

beforeEach(() => {
  mocks.context.workloadScans = [
    {
      metadata: { name: 'deployment-web', namespace: 'shop', cluster: 'cluster-a' },
      spec: {
        controls: {
          'C-0001': control('C-0001', { exceptedInFrameworks: ['nsa'] }),
          'C-0002': control('C-0002', { exceptedByPolicy: true }),
          'C-0003': control('C-0003'),
        },
      },
      exceptedByPolicy: false,
    },
  ];
  mocks.context.exceptionErrors = [
    { cluster: 'cluster-a', message: 'SecurityExceptions: forbidden' },
    { cluster: 'cluster-b', message: 'unreachable' },
  ];
  mocks.readClusterSetup.mockReset().mockResolvedValue({});
  mocks.fetchSecurityExceptions.mockReset();
  mocks.applySecurityExceptionsToWorkloadScans.mockReset();
  mocks.markScannerExceptions.mockReset();
});

it('copies the marks of the summary in the cache, with the errors of its cluster', async () => {
  const scan = workloadScan();

  const errors = await markExceptions(scan, 'cluster-a', true);

  expect(scan.spec.controls['C-0001']).toMatchObject({
    exceptedByPolicy: false,
    exceptedInFrameworks: ['nsa'],
  });
  expect(scan.spec.controls['C-0002'].exceptedByPolicy).toBe(true);
  expect(scan.spec.controls['C-0003'].exceptedInFrameworks).toBeUndefined();
  expect(errors).toEqual(['SecurityExceptions: forbidden']);
  expect(mocks.fetchSecurityExceptions).not.toHaveBeenCalled();
});

it('reads the exceptions itself without the cache, and reports what it could not read', async () => {
  const exceptions = {
    namespaced: [],
    cluster: [],
    namespaceLabelsByName: new Map(),
    errors: ['ClusterSecurityExceptions: forbidden'],
  };
  mocks.fetchSecurityExceptions.mockResolvedValue(exceptions);
  const scan = workloadScan();

  expect(await markExceptions(scan, 'cluster-a', false)).toEqual([
    'ClusterSecurityExceptions: forbidden',
  ]);
  expect(mocks.fetchSecurityExceptions).toHaveBeenCalledWith('cluster-a', [scan], [], ['shop']);
  expect(mocks.applySecurityExceptionsToWorkloadScans).toHaveBeenCalledWith([scan], exceptions);

  // where the scanners apply the exceptions, nothing is read
  mocks.readClusterSetup.mockResolvedValue({ capabilities: { riskAcceptance: 'enable' } });
  expect(await markExceptions(workloadScan(), 'cluster-a', false)).toEqual([]);
  expect(mocks.markScannerExceptions).toHaveBeenCalled();
  expect(mocks.fetchSecurityExceptions).toHaveBeenCalledTimes(1);
});

it('shows on the page that exceptions could not be read', async () => {
  mocks.context.workloadScans = [];
  mocks.fetchObject.mockResolvedValue(workloadScan());
  mocks.fetchSecurityExceptions.mockRejectedValue(new Error('the server is unreachable'));

  render(<KubescapeWorkloadConfigurationScanDetails />);

  expect(
    await screen.findByText(
      /Unable to read the security exceptions of cluster cluster-a: the server is unreachable/
    )
  ).toBeTruthy();
});

it('gives the status cell the status it shows, so that an excluded control is drawn again', async () => {
  // the summary in the cache excludes C-0002
  mocks.fetchObject.mockResolvedValue(workloadScan());

  render(<KubescapeWorkloadConfigurationScanDetails />);

  expect((await screen.findByTestId('status-C-0002')).textContent).toBe('excluded');
  expect(screen.getByTestId('status-C-0003').textContent).toBe('failed');
  // excepted in NSA only, which is not the framework of the page
  expect(screen.getByTestId('status-C-0001').textContent).toBe('failed');
});

it('shows a control that came without rules, which has no fix', async () => {
  const scan = workloadScan();
  scan.spec.controls['C-0004'] = { ...control('C-0004'), rules: null };
  mocks.fetchObject.mockResolvedValue(scan);

  render(<KubescapeWorkloadConfigurationScanDetails />);

  expect(await screen.findAllByRole('button', { name: 'Create Security Exception' })).toHaveLength(
    4
  );
});

it('opens the exception form for a user who may not create exceptions', async () => {
  // the form offers the exception as YAML, also to a user who may only read (GitOps)
  mocks.post.mockResolvedValue({ status: { allowed: false } });
  mocks.fetchObject.mockResolvedValue(workloadScan());

  render(<KubescapeWorkloadConfigurationScanDetails />);
  const buttons = await screen.findAllByRole('button', { name: 'Create Security Exception' });
  await act(async () => {});

  expect(buttons.map(button => button.hasAttribute('disabled'))).toEqual([false, false, false]);
  fireEvent.click(buttons[0]);
  expect(screen.getByText('Exception form for C-0001 of shop/web')).toBeTruthy();
  // the button asks nothing; the form checks whether the user may create the exception
  expect(mocks.post).not.toHaveBeenCalled();
});
