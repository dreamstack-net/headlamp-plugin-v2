import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { vi } from 'vitest';
import { clearClusterSetups } from '../common/kubescapeSetup';
import ComplianceView, {
  configurationScanContext,
  excludedCountsLine,
  readConfigurationScans,
} from './Compliance';

// Values returned by hooks are created once, so that the effects depending on them only run once
const mocks = vi.hoisted(() => ({
  request: vi.fn(),
  // the access reviews
  post: vi.fn(),
  config: { framework: '', activeFrameworks: [], pageSize: 1, alertmanagerUrl: undefined },
  regoData: {
    controls: [],
    frameworks: [] as any[],
    fullRegolibraryFramework: { name: 'Full Regolibrary', controls: [] as any[] },
    loading: false,
  },
  clusters: ['cluster-a'],
  // the rows the table of the controls got, on each render
  tableData: [] as unknown[][],
}));
// The setup check has its own tests
vi.mock('../common/SetupCheck', () => ({ SetupCheck: () => null }));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({
  request: mocks.request,
  post: mocks.post,
}));
vi.mock('../common/clusterContext', () => ({
  getAllowedNamespaces: () => [],
  isAllowedNamespaceUpdated: () => false,
}));
vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', () => ({
  Link: () => null,
  SectionBox: ({ children }: { children: ReactNode }) => <section>{children}</section>,
  // the buttons of the rows of the controls
  Table: ({ data, columns }: any) => {
    mocks.tableData.push(data);
    return (
      <div>
        {data?.map((row: any) => (
          <div key={row.controlID}>
            {columns
              .filter((column: any) => column.id === 'actions')
              .map((column: any) => (
                <span key={column.id}>{column.Cell({ row: { original: row } })}</span>
              ))}
          </div>
        ))}
      </div>
    );
  },
  // the Controls tab
  Tabs: ({ tabs }: any) => <>{tabs[0].component}</>,
}));
vi.mock('../index', () => ({ RoutingName: {}, useHLSelectedClusters: () => mocks.clusters }));
vi.mock('../common/config-store', () => ({
  kubescapeConfigStore: { useConfig: () => () => mocks.config },
}));
vi.mock('../rego', () => ({ useRegoData: () => mocks.regoData }));
vi.mock('../model', () => ({
  customObjectLabel: 'kubescape.io/custom-object',
  workloadConfigurationScanSummaryClass: {
    apiEndpoint: {
      apiInfo: [{ group: 'spdx.softwarecomposition.kubescape.io', version: 'v1beta1' }],
    },
    pluralName: 'workloadconfigurationscansummaries',
  },
}));
vi.mock('./ClusterView', () => ({ default: () => null }));
vi.mock('./FrameworkButtons', () => ({ FrameworkButtons: () => null }));
vi.mock('./NamespaceView', () => ({ default: () => null }));
vi.mock('./ResourceList', () => ({ default: () => null }));
vi.mock('../exceptions/GuidedClusterComplianceExceptionForm', () => ({
  GuidedClusterComplianceExceptionForm: ({ onCreated, onClose }: any) => (
    <button
      onClick={() => {
        onCreated?.();
        onClose();
      }}
    >
      Create exception
    </button>
  ),
}));

function scan(namespace: string, name: string, controlIDs = ['C-0001']) {
  return {
    metadata: {
      name: `deployment-${name}`,
      namespace,
      labels: {
        'kubescape.io/workload-kind': 'Deployment',
        'kubescape.io/workload-name': name,
        'kubescape.io/workload-namespace': namespace,
      },
    } as any,
    spec: {
      controls: Object.fromEntries(
        controlIDs.map(controlID => [
          controlID,
          {
            controlID,
            severity: { scoreFactor: 7, severity: 'High' },
            status: { status: 'failed' },
          },
        ])
      ),
      severities: {},
    },
  };
}

const api = '/apis/spdx.softwarecomposition.kubescape.io/v1beta1';
// the list of the metadata of all summaries, which names the namespaces to read
const isNamespaceDiscovery = (url: string) =>
  url === `${api}/workloadconfigurationscansummaries?limit=1000`;

/**
 * The answer of the storage to a list of these summaries: without fullSpec, the metadata of all
 * of them, which names their namespaces; with it, the summaries of the namespace of the list.
 */
function summaryList(url: string, scans: ReturnType<typeof scan>[]) {
  if (!url.includes('resourceVersion=fullSpec')) {
    return { items: scans.map(({ metadata }) => ({ metadata: { ...metadata } })), metadata: {} };
  }
  const namespace = /\/namespaces\/([^/]+)\//.exec(url)?.[1];
  return {
    items: scans.filter(found => !namespace || found.metadata.namespace === namespace),
    metadata: {},
  };
}

const control = (controlID: string) => ({
  controlID,
  name: controlID,
  baseScore: 7,
  description: '',
  remediation: '',
});

function resetCache() {
  configurationScanContext.queryTasks = [];
  configurationScanContext.workloadScans = [];
  configurationScanContext.exceptionErrors = [];
}

// the request of the namespace of Kubescape, with or without a leading slash
const isPodsRequest = (url: string) => /^\/?api\/v1\/pods\?/.test(url);

// the header line with the counts
async function findHeader(pattern: RegExp) {
  return screen.findByText(
    (_text, element) =>
      !!element?.textContent &&
      element.tagName !== 'BODY' &&
      element.children.length === 0 &&
      pattern.test(element.textContent.replace(/\s+/g, ' '))
  );
}

afterEach(cleanup);
// each test installs Kubescape with other capabilities
beforeEach(clearClusterSetups);

it('shows and applies exceptions to the scans read with "More scans"', async () => {
  let resolveFirstPage: (page: unknown) => void = () => {};
  let billingReads = 0;
  mocks.request.mockImplementation(async (url: string) => {
    if (isNamespaceDiscovery(url))
      return summaryList(url, [scan('shop', 'web'), scan('billing', 'api')]);
    if (url.startsWith(`${api}/namespaces/shop/workloadconfigurationscansummaries?`)) {
      return { items: [scan('shop', 'web')], metadata: {} };
    }
    if (url.startsWith(`${api}/namespaces/billing/workloadconfigurationscansummaries?`)) {
      if (url.includes('continue=page-2')) return { items: [], metadata: {} };
      // the first read of billing is held back
      if (billingReads++ === 0) return new Promise(resolve => (resolveFirstPage = resolve));
      return { items: [scan('billing', 'api')], metadata: { continue: 'page-2' } };
    }
    if (url === '/apis/kubescape.io/v1beta1/securityexceptions') {
      const resourceLevelException = {
        kind: 'SecurityException',
        metadata: { name: 'exempt-billing', namespace: 'billing' },
        spec: {},
      };
      return { items: [resourceLevelException] };
    }
    return { items: [] };
  });

  render(<ComplianceView />);

  // Cancel reading while the first page of billing is loading, which leaves billing unread
  fireEvent.click(await screen.findByRole('button', { name: 'Cancel' }, { timeout: 2000 }));
  await act(async () => {
    resolveFirstPage({ items: [scan('billing', 'api')], metadata: { continue: 'page-2' } });
  });
  expect(await screen.findByText(/1 total checks, .* excluding 0 resources/)).toBeTruthy();

  fireEvent.click(screen.getByRole('button', { name: 'More scans' }));

  expect(await screen.findByText(/2 total checks, .* excluding 1 resource and/)).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'More scans' })).toBeNull();
});

it('uses the exceptions that the scanner applied when risk acceptance is enabled', async () => {
  configurationScanContext.queryTasks = [];
  configurationScanContext.workloadScans = [];
  const excepted = scan('billing', 'api');
  excepted.spec.controls['C-0001'].status = { status: 'passed', subStatus: 'w/exceptions' } as any;
  mocks.request.mockReset().mockImplementation(async (url: string) => {
    if (url.includes('/workloadconfigurationscansummaries?')) {
      return summaryList(url, [scan('shop', 'web'), excepted]);
    }
    if (url === '/apis/spdx.softwarecomposition.kubescape.io/v1beta1') {
      return { resources: [{ name: 'workloadconfigurationscansummaries' }] };
    }
    if (isPodsRequest(url)) {
      return { items: [{ metadata: { namespace: 'kubescape' } }] };
    }
    if (url === '/api/v1/namespaces/kubescape/configmaps/ks-capabilities') {
      return {
        data: { capabilities: JSON.stringify({ capabilities: { riskAcceptance: 'enable' } }) },
      };
    }
    return { items: [] };
  });

  render(<ComplianceView />);

  expect(await screen.findByText(/2 total checks, .* excluding 1 resource and/)).toBeTruthy();
  expect(mocks.request.mock.calls.map(([url]) => url)).not.toContain(
    '/apis/kubescape.io/v1beta1/securityexceptions'
  );
});

describe('with exceptions that the plugin applies', () => {
  afterEach(() => {
    mocks.config.framework = '';
    mocks.regoData.frameworks = [];
    mocks.regoData.fullRegolibraryFramework.controls = [];
    // the Failed controls switch, which a test switched off
    window.sessionStorage.removeItem('kubescape.FailedControls');
  });

  it('gives the table of all controls new rows after excluding a control', async () => {
    resetCache();
    mocks.regoData.fullRegolibraryFramework.controls = [control('C-0001')];
    let created = false;
    mocks.request.mockReset().mockImplementation(async (url: string) => {
      if (url.includes('/workloadconfigurationscansummaries?')) {
        return { items: [scan('shop', 'web')], metadata: {} };
      }
      if (url === '/apis/kubescape.io/v1beta1/clustersecurityexceptions') {
        const exception = {
          kind: 'ClusterSecurityException',
          metadata: { name: 'c-0001-cluster' },
          spec: { match: {}, posture: [{ controlID: 'C-0001', action: 'ignore' }] },
        };
        return { items: created ? [exception] : [] };
      }
      return { items: [] };
    });

    render(<ComplianceView />);
    await findHeader(/1 configuration issues, excluding 0 resources and 0 control results$/);
    // all controls of the framework, which are the same on every render
    fireEvent.click(screen.getByLabelText('Failed controls'));
    const rows = mocks.tableData.at(-1);
    expect(rows).toEqual([control('C-0001')]);

    fireEvent.click(await screen.findByRole('button', { name: 'Exclude control cluster-wide' }));
    created = true;
    fireEvent.click(screen.getByRole('button', { name: 'Create exception' }));
    await findHeader(/0 configuration issues, excluding 0 resources and 1 control result$/);

    // Headlamp's table keeps the values of its rows, such as the failed resources of a control,
    // until it gets other data
    expect(mocks.tableData.at(-1)).not.toBe(rows);
    expect(mocks.tableData.at(-1)).toEqual(rows);
  });

  it('applies the exceptions again after excluding a control cluster-wide', async () => {
    resetCache();
    mocks.regoData.fullRegolibraryFramework.controls = [control('C-0001')];
    let created = false;
    mocks.request.mockReset().mockImplementation(async (url: string) => {
      if (url.includes('/workloadconfigurationscansummaries?')) {
        return { items: [scan('shop', 'web')], metadata: {} };
      }
      if (url === '/apis/kubescape.io/v1beta1/clustersecurityexceptions') {
        const exception = {
          kind: 'ClusterSecurityException',
          metadata: { name: 'c-0001-cluster' },
          spec: { match: {}, posture: [{ controlID: 'C-0001', action: 'ignore' }] },
        };
        return { items: created ? [exception] : [] };
      }
      return { items: [] };
    });

    render(<ComplianceView />);
    await findHeader(/1 configuration issues, excluding 0 resources and 0 control results$/);

    fireEvent.click(await screen.findByRole('button', { name: 'Exclude control cluster-wide' }));
    created = true;
    fireEvent.click(screen.getByRole('button', { name: 'Create exception' }));

    await findHeader(/0 configuration issues, excluding 0 resources and 1 control result$/);
  });

  it('counts the controls of the chosen framework, with its exceptions', async () => {
    resetCache();
    // C-0002 is not in the framework, C-0003 is excepted in the framework only
    mocks.regoData.frameworks = [{ name: 'NSA', controls: [control('C-0001'), control('C-0003')] }];
    mocks.config.framework = 'NSA';
    mocks.request.mockReset().mockImplementation(async (url: string) => {
      if (url.includes('/workloadconfigurationscansummaries?')) {
        return { items: [scan('shop', 'web', ['C-0001', 'C-0002', 'C-0003'])], metadata: {} };
      }
      if (url === '/apis/kubescape.io/v1beta1/securityexceptions') {
        const exception = {
          kind: 'SecurityException',
          metadata: { name: 'nsa-only', namespace: 'shop' },
          spec: { posture: [{ controlID: 'C-0003', frameworkName: 'NSA', action: 'ignore' }] },
        };
        return { items: [exception] };
      }
      return { items: [] };
    });

    render(<ComplianceView />);

    await findHeader(
      /1 total checks, 1 configuration issues, excluding 0 resources and 1 control result$/
    );
  });

  it('shows the exception errors of the clusters of the page only', async () => {
    resetCache();
    configurationScanContext.exceptionErrors = [{ cluster: 'cluster-z', message: 'old' }];
    mocks.request.mockReset().mockImplementation(async (url: string) => {
      if (url.includes('/workloadconfigurationscansummaries?')) {
        return { items: [scan('shop', 'web')], metadata: {} };
      }
      if (url === '/apis/kubescape.io/v1beta1/securityexceptions') {
        throw Object.assign(new Error('securityexceptions is forbidden'), { status: 403 });
      }
      return { items: [] };
    });

    render(<ComplianceView />);

    expect(
      await screen.findByText(
        /Unable to read the security exceptions of cluster cluster-a: SecurityExceptions: securityexceptions is forbidden/
      )
    ).toBeTruthy();
    expect(screen.queryByText(/cluster cluster-z/)).toBeNull();
  });

  it('opens the form to exclude a control for a user who may not create exceptions', async () => {
    resetCache();
    mocks.regoData.fullRegolibraryFramework.controls = [control('C-0001')];
    // the form offers the exception as YAML, also to a user who may only read (GitOps)
    mocks.post.mockReset().mockResolvedValue({ status: { allowed: false } });
    mocks.request
      .mockReset()
      .mockImplementation(async (url: string) =>
        url.includes('/workloadconfigurationscansummaries?')
          ? { items: [scan('shop', 'web')], metadata: {} }
          : { items: [] }
      );

    render(<ComplianceView />);
    await findHeader(/1 configuration issues/);
    // the Scan now button asked for its permission, and was denied
    await waitFor(() => expect(mocks.post).toHaveBeenCalled());

    const exclude = screen.getByRole('button', { name: 'Exclude control cluster-wide' });
    expect(exclude.hasAttribute('disabled')).toBe(false);
    fireEvent.click(exclude);
    expect(screen.getByRole('button', { name: 'Create exception' })).toBeTruthy();
    const reviewed = mocks.post.mock.calls.map(
      ([, review]) => review?.spec?.resourceAttributes?.resource
    );
    expect(reviewed).not.toContain('clustersecurityexceptions');
    mocks.post.mockReset();
  });
});

describe('readConfigurationScans', () => {
  const config = mocks.config as any;
  const otherTask = () => ({
    cluster: 'cluster-b',
    allowedNamespaces: [],
    continuation: undefined,
    objectClass: {} as any,
    pageSize: 50,
    handleData: () => {},
  });

  beforeEach(() => {
    resetCache();
    mocks.request
      .mockReset()
      .mockImplementation(async (url: string) =>
        url.includes('/workloadconfigurationscansummaries?')
          ? { items: [scan('shop', 'web')], metadata: {} }
          : { items: [] }
      );
  });

  it('keeps the scans of the other clusters for a page of one cluster', async () => {
    const otherScan = { ...scan('blog', 'api'), exceptedByPolicy: false } as any;
    otherScan.metadata.cluster = 'cluster-b';
    configurationScanContext.queryTasks = [otherTask()];
    configurationScanContext.workloadScans = [otherScan];
    configurationScanContext.exceptionErrors = [{ cluster: 'cluster-b', message: 'forbidden' }];

    const scans = await readConfigurationScans(
      ['cluster-a'],
      config,
      { current: true },
      () => {},
      () => {},
      { keepOtherClusters: true }
    );

    expect(scans.map(w => `${w.metadata.cluster}/${w.metadata.name}`)).toEqual([
      'cluster-b/deployment-api',
      'cluster-a/deployment-web',
    ]);
    expect(configurationScanContext.queryTasks.map(task => task.cluster)).toEqual([
      'cluster-b',
      'cluster-a',
    ]);
    expect(configurationScanContext.exceptionErrors).toEqual([
      { cluster: 'cluster-b', message: 'forbidden' },
    ]);
    // only the cluster of the page is read
    expect(mocks.request.mock.calls.every(([, options]) => options?.cluster !== 'cluster-b')).toBe(
      true
    );

    // the Compliance page reads the clusters it shows, without the others
    const selected = await readConfigurationScans(
      ['cluster-a'],
      config,
      { current: true },
      () => {},
      () => {}
    );
    expect(selected.map(w => w.metadata.cluster)).toEqual(['cluster-a']);
    expect(configurationScanContext.exceptionErrors).toEqual([]);
  });
});

describe('reads that were replaced', () => {
  const config = mocks.config as any;
  // the lists of the summaries with their spec, a namespace at a time
  const summariesOf = (url: string) =>
    url.includes('/workloadconfigurationscansummaries?resourceVersion=fullSpec');
  // the list of their metadata names one namespace per cluster
  const discovered = (url: string, options: any) =>
    summaryList(url, [options.cluster === 'cluster-b' ? scan('blog', 'api') : scan('shop', 'web')]);

  afterEach(() => {
    mocks.clusters = ['cluster-a'];
  });

  it('stores nothing of a page read for a cluster that the cache dropped', async () => {
    resetCache();
    let resolveA: (page: unknown) => void = () => {};
    mocks.request.mockReset().mockImplementation(async (url: string, options: any) => {
      if (isNamespaceDiscovery(url)) return discovered(url, options);
      if (!summariesOf(url)) return { items: [] };
      if (options.cluster === 'cluster-a') return new Promise(resolve => (resolveA = resolve));
      return { items: [scan('blog', 'api')], metadata: {} };
    });

    const readingA = readConfigurationScans(
      ['cluster-a'],
      config,
      { current: true },
      () => {},
      () => {}
    );
    await vi.waitFor(() =>
      expect(mocks.request.mock.calls.some(([url]) => summariesOf(url))).toBe(true)
    );
    // cluster-b is selected instead while the page of cluster-a is read
    await readConfigurationScans(
      ['cluster-b'],
      config,
      { current: true },
      () => {},
      () => {}
    );
    resolveA({ items: [scan('shop', 'web')], metadata: {} });
    await readingA;

    expect(configurationScanContext.workloadScans.map(w => w.metadata.cluster)).toEqual([
      'cluster-b',
    ]);
  });

  it('lets More scans leave the page to the read of other clusters', async () => {
    resetCache();
    const pending: Record<string, (page: unknown) => void> = {};
    let readsOfA = 0;
    mocks.request.mockReset().mockImplementation(async (url: string, options: any) => {
      if (isNamespaceDiscovery(url)) return discovered(url, options);
      if (!summariesOf(url)) return { items: [] };
      let page = 'b';
      if (options.cluster === 'cluster-a') page = readsOfA++ === 0 ? 'first' : 'more';
      return new Promise(resolve => (pending[page] = resolve));
    });

    const { rerender } = render(<ComplianceView />);
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel' }, { timeout: 2000 }));
    // stopped between the pages of namespace shop, which More scans reads again
    await act(async () => {
      pending.first({ items: [scan('shop', 'web')], metadata: { continue: 'page-2' } });
    });
    fireEvent.click(await screen.findByRole('button', { name: 'More scans' }));
    await waitFor(() => expect(pending.more).toBeDefined());

    // other clusters are selected while More scans reads namespace shop of cluster-a
    mocks.clusters = ['cluster-b'];
    rerender(<ComplianceView />);
    await waitFor(() => expect(pending.b).toBeDefined());
    await act(async () => {
      pending.more({ items: [scan('shop', 'api')], metadata: {} });
    });

    // the page still reads cluster-b, so it shows no counts, and cluster-a is not stored
    expect(screen.queryByText(/total checks/)).toBeNull();
    expect(configurationScanContext.workloadScans).toEqual([]);

    await act(async () => {
      pending.b({ items: [scan('blog', 'db')], metadata: {} });
    });
    await findHeader(/^1 total checks, 1 configuration issues/);
    expect(configurationScanContext.workloadScans.map(w => w.metadata.cluster)).toEqual([
      'cluster-b',
    ]);
  });
});

describe('read a namespace at a time', () => {
  it('reads the namespaces that failed again with More scans, and says what it read', async () => {
    resetCache();
    let billingFails = true;
    mocks.request.mockReset().mockImplementation(async (url: string) => {
      // the namespaces with summaries, without the spec of the summaries
      if (isNamespaceDiscovery(url)) {
        return summaryList(url, [scan('shop', 'web'), scan('billing', 'api')]);
      }
      if (url.startsWith(`${api}/namespaces/shop/workloadconfigurationscansummaries?`)) {
        return { items: [scan('shop', 'web')], metadata: {} };
      }
      if (url.startsWith(`${api}/namespaces/billing/workloadconfigurationscansummaries?`)) {
        if (billingFails) throw Object.assign(new Error('timeout'), { status: 504 });
        return { items: [scan('billing', 'api')], metadata: {} };
      }
      return { items: [] };
    });

    render(<ComplianceView />);

    await findHeader(/^1 total checks/);
    expect(
      screen.getByText(
        /Unable to read all configuration scans of cluster cluster-a: namespace billing: timeout/
      )
    ).toBeTruthy();
    expect(
      screen.getByText(/^Read 1 configuration scan in \d+\.\d s; 1 request failed$/)
    ).toBeTruthy();
    // the cluster was not read as a whole
    expect(
      mocks.request.mock.calls.some(([url]) =>
        url.startsWith(`${api}/workloadconfigurationscansummaries?resourceVersion=fullSpec`)
      )
    ).toBe(false);

    billingFails = false;
    mocks.request.mockClear();
    fireEvent.click(screen.getByRole('button', { name: 'More scans' }));

    await findHeader(/^2 total checks/);
    expect(screen.queryByText(/namespace billing: timeout/)).toBeNull();
    expect(screen.queryByRole('button', { name: 'More scans' })).toBeNull();
    expect(screen.getByText(/^Read 1 configuration scan in \d+\.\d s$/)).toBeTruthy();
    // only the namespace that failed is read again
    expect(
      mocks.request.mock.calls
        .map(([url]) => url as string)
        .filter(url => url.includes('workloadconfigurationscansummaries'))
    ).toEqual([
      `${api}/namespaces/billing/workloadconfigurationscansummaries?resourceVersion=fullSpec&limit=1`,
    ]);
  });
});

it('calls what exceptions exclude in resources results of controls, one per control and resource', () => {
  // countExcludedControls counts a control once for each resource it is excluded in
  expect(excludedCountsLine(0, 10)).toBe('0 resources and 10 control results');
  expect(excludedCountsLine(1, 1)).toBe('1 resource and 1 control result');
});
