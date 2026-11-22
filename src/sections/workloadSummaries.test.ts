import { renderHook, waitFor } from '@testing-library/react';
import { vi } from 'vitest';
import {
  cachedWorkloadSummaries,
  clearWorkloadSummaries,
  failedControlCounts,
  findWorkloadSummary,
  loadWorkloadSummaries,
  readClusterExceptions,
  summarizeWorkloads,
  useFailedControlCounts,
  useNamespaceFailedControls,
  workloadExceptionsError,
  workloadSummariesError,
} from './workloadSummaries';

const mocks = vi.hoisted(() => ({
  paginatedListQuery: vi.fn(),
  // the requests for the exceptions
  request: vi.fn(),
  readClusterSetup: vi.fn(),
}));
vi.mock('../query', () => ({ paginatedListQuery: mocks.paginatedListQuery }));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ request: mocks.request }));
vi.mock('../common/clusterContext', () => ({ getAllowedNamespaces: () => [] }));
vi.mock('../common/kubescapeSetup', () => ({
  readClusterSetup: mocks.readClusterSetup,
  scannersApplyExceptions: (setup: any) => setup.capabilities?.riskAcceptance === 'enable',
}));
vi.mock('../model', () => ({
  vulnerabilityManifestSummaryClass: { pluralName: 'vulnerabilitymanifestsummaries' },
  workloadConfigurationScanSummaryClass: { pluralName: 'workloadconfigurationscansummaries' },
}));

function labels(kind: string, name: string, container?: string) {
  return {
    'kubescape.io/workload-kind': kind,
    'kubescape.io/workload-name': name,
    'kubescape.io/workload-namespace': 'shop',
    ...(container ? { 'kubescape.io/workload-container-name': container } : {}),
  };
}

function vulnerabilitySummary(container: string, critical: number, high: number) {
  return {
    metadata: {
      name: `deployment-web-${container}`,
      namespace: 'shop',
      labels: labels('Deployment', 'web', container),
    },
    spec: {
      severities: {
        critical: { all: critical },
        high: { all: high },
        medium: { all: 1 },
        low: { all: 0 },
      },
    },
  };
}

const configurationSummary = {
  metadata: { name: 'deployment-web', namespace: 'shop', labels: labels('Deployment', 'web') },
  spec: { severities: { critical: 0, high: 3, medium: 5, low: 2 } },
};

// the scanners apply the exceptions, unless a test says otherwise
const scannersApply = { capabilities: { riskAcceptance: 'enable' } };

beforeEach(() => {
  mocks.paginatedListQuery.mockReset();
  mocks.request.mockReset().mockResolvedValue({ items: [] });
  mocks.readClusterSetup.mockReset().mockResolvedValue(scannersApply);
  clearWorkloadSummaries();
});

it('totals the CVEs of the containers of a workload', () => {
  const summaries = summarizeWorkloads(
    [vulnerabilitySummary('web', 2, 10), vulnerabilitySummary('sidecar', 1, 4)],
    [configurationSummary]
  );

  const web = summaries.vulnerabilities.get('shop/deployment/web')!;
  expect([web.critical, web.high, web.medium]).toEqual([3, 14, 2]);
  expect(web.containers.map(container => container.container)).toEqual(['web', 'sidecar']);
  expect(summaries.controls.get('shop/deployment/web')).toEqual({
    name: 'deployment-web',
    critical: 0,
    high: 3,
    medium: 5,
    low: 2,
  });
});

it('skips summaries without workload labels', () => {
  const summaries = summarizeWorkloads([{ metadata: { name: 'x', namespace: 'shop' } }], []);
  expect(summaries.vulnerabilities.size).toBe(0);
});

it('finds the summary of the first scanned candidate', () => {
  const summaries = new Map([['shop/job/once', 'job summary']]);
  expect(
    findWorkloadSummary(summaries, 'shop', [
      { kind: 'CronJob', name: 'once' },
      { kind: 'Job', name: 'once' },
    ])
  ).toBe('job summary');
});

it('reads the summaries of a namespace, with their spec, once in a while', async () => {
  mocks.paginatedListQuery.mockImplementation(async (_cluster, resourceClass) => ({
    items:
      resourceClass.pluralName === 'vulnerabilitymanifestsummaries'
        ? [vulnerabilitySummary('web', 1, 0)]
        : [configurationSummary],
  }));

  loadWorkloadSummaries('cluster-a', 'shop', 0);
  loadWorkloadSummaries('cluster-a', 'shop', 0);
  await vi.waitFor(() => expect(cachedWorkloadSummaries('cluster-a', 'shop')).toBeDefined());

  expect(mocks.paginatedListQuery).toHaveBeenCalledTimes(2);
  // a namespace, all its pages; paginatedListQuery asks for the full spec
  expect(
    mocks.paginatedListQuery.mock.calls.map(([cluster, , , , namespaces]) => [cluster, namespaces])
  ).toEqual([
    ['cluster-a', ['shop']],
    ['cluster-a', ['shop']],
  ]);
  expect(cachedWorkloadSummaries('cluster-a', 'shop')!.controls.size).toBe(1);
  expect(cachedWorkloadSummaries('cluster-a', 'blog')).toBeUndefined();

  // read again after five minutes
  loadWorkloadSummaries('cluster-a', 'shop', Date.now() + 1000);
  expect(mocks.paginatedListQuery).toHaveBeenCalledTimes(2);
  loadWorkloadSummaries('cluster-a', 'shop', Date.now() + 6 * 60 * 1000);
  expect(mocks.paginatedListQuery).toHaveBeenCalledTimes(4);
});

it('reads a few namespaces at a time', async () => {
  const pending: Array<() => void> = [];
  mocks.paginatedListQuery.mockImplementation(
    () => new Promise(resolve => pending.push(() => resolve({ items: [] })))
  );

  for (let index = 0; index < 10; index++) loadWorkloadSummaries('cluster-a', `ns-${index}`);
  expect(mocks.paginatedListQuery).toHaveBeenCalledTimes(4 * 2);

  pending.splice(0, 2).forEach(resolve => resolve());
  await vi.waitFor(() => expect(mocks.paginatedListQuery).toHaveBeenCalledTimes(5 * 2));

  // let the rest finish, so the next test starts with no reads running
  while (pending.length > 0) {
    pending.splice(0).forEach(resolve => resolve());
    await vi.waitFor(() => expect(cachedWorkloadSummaries('cluster-a', 'ns-0')).toBeDefined());
    await new Promise(resolve => setTimeout(resolve, 0));
  }
  await vi.waitFor(() => expect(cachedWorkloadSummaries('cluster-a', 'ns-9')).toBeDefined());
});

it('gives a namespace without Kubescape results empty summaries', async () => {
  mocks.paginatedListQuery.mockRejectedValue(
    Object.assign(new Error('404 page not found'), { status: 404 })
  );

  loadWorkloadSummaries('cluster-b', 'shop');
  await vi.waitFor(() => expect(cachedWorkloadSummaries('cluster-b', 'shop')).toBeDefined());

  expect(cachedWorkloadSummaries('cluster-b', 'shop')!.vulnerabilities.size).toBe(0);
  expect(workloadSummariesError('cluster-b', 'shop', 'vulnerabilities')).toBeUndefined();
});

it('keeps the results read before when a list cannot be read, and reads it again soon', async () => {
  mocks.paginatedListQuery.mockImplementation(async (_cluster, resourceClass) => ({
    items:
      resourceClass.pluralName === 'vulnerabilitymanifestsummaries'
        ? [vulnerabilitySummary('web', 1, 0)]
        : [configurationSummary],
  }));
  loadWorkloadSummaries('cluster-c', 'shop', 0);
  await vi.waitFor(() => expect(cachedWorkloadSummaries('cluster-c', 'shop')).toBeDefined());

  // the storage times out on the next read of the vulnerabilities
  mocks.paginatedListQuery.mockImplementation(async (_cluster, resourceClass) => {
    if (resourceClass.pluralName === 'vulnerabilitymanifestsummaries') {
      throw Object.assign(new Error('the server is currently unable to handle the request'), {
        status: 503,
      });
    }
    return { items: [configurationSummary] };
  });
  loadWorkloadSummaries('cluster-c', 'shop', Date.now() + 6 * 60 * 1000);
  await vi.waitFor(() =>
    expect(workloadSummariesError('cluster-c', 'shop', 'vulnerabilities')).toBe(
      'the server is currently unable to handle the request'
    )
  );

  expect(cachedWorkloadSummaries('cluster-c', 'shop')!.vulnerabilities.size).toBe(1);
  expect(workloadSummariesError('cluster-c', 'shop', 'controls')).toBeUndefined();
  // read again after half a minute instead of five
  const calls = mocks.paginatedListQuery.mock.calls.length;
  loadWorkloadSummaries('cluster-c', 'shop', Date.now() + 31 * 1000);
  expect(mocks.paginatedListQuery.mock.calls.length).toBe(calls + 2);
});

it('reads a namespace again when its summaries could not be counted', async () => {
  // a summary that the storage returns without its metadata
  mocks.paginatedListQuery.mockResolvedValue({ items: [null] });

  loadWorkloadSummaries('cluster-i', 'shop', 0);
  await vi.waitFor(() =>
    expect(workloadSummariesError('cluster-i', 'shop', 'controls')).toMatch(/metadata/)
  );
  expect(workloadSummariesError('cluster-i', 'shop', 'vulnerabilities')).toMatch(/metadata/);

  // not loading for ever: read again after half a minute, like a list that could not be read
  mocks.paginatedListQuery.mockResolvedValue({ items: [configurationSummary] });
  loadWorkloadSummaries('cluster-i', 'shop', Date.now() + 31 * 1000);
  await vi.waitFor(() =>
    expect(workloadSummariesError('cluster-i', 'shop', 'controls')).toBeUndefined()
  );
  expect(cachedWorkloadSummaries('cluster-i', 'shop')!.controls.size).toBe(1);
});

describe('where the plugin applies the exceptions', () => {
  function control(controlID: string, severity: string, status = 'failed') {
    return { controlID, severity: { scoreFactor: 5, severity }, status: { status } };
  }
  // the storage counts the failed controls without the exceptions the plugin applies
  const scannedWorkload = {
    metadata: { name: 'deployment-web', namespace: 'shop', labels: labels('Deployment', 'web') },
    spec: {
      severities: { critical: 1, high: 2, medium: 0, low: 0 },
      controls: {
        'C-0001': control('C-0001', 'Critical'),
        'C-0002': control('C-0002', 'High'),
        'C-0003': control('C-0003', 'High'),
        'C-0004': control('C-0004', 'Low', 'passed'),
      },
    },
  };
  const exception = (spec: object, namespace = 'shop') => ({
    kind: 'SecurityException',
    metadata: { name: 'exception', namespace },
    spec,
  });
  const exceptions = (...items: any[]) => ({
    namespaced: items,
    cluster: [],
    namespaceLabelsByName: new Map(),
  });

  beforeEach(() => {
    mocks.readClusterSetup.mockResolvedValue({ capabilities: {} });
  });

  it('counts the failed controls without those that exceptions exclude in every framework', () => {
    const data = exceptions(
      exception({
        posture: [
          { controlID: 'C-0002', action: 'ignore' },
          // still failed in scoring
          { controlID: 'C-0001', action: 'alert_only' },
          // the counts are of all controls, where an entry limited to a framework does not apply
          { controlID: 'C-0003', frameworkName: 'NSA', action: 'ignore' },
        ],
      })
    );

    expect(failedControlCounts(scannedWorkload, data)).toEqual({
      critical: 1,
      high: 1,
      medium: 0,
      low: 0,
    });
    expect(failedControlCounts(scannedWorkload, exceptions(exception({})))).toEqual({
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    });
    // an exception of another namespace
    expect(failedControlCounts(scannedWorkload, exceptions(exception({}, 'blog'))).high).toBe(2);
    // the counts of the storage where the scanners apply the exceptions
    expect(failedControlCounts(scannedWorkload)).toEqual({
      critical: 1,
      high: 2,
      medium: 0,
      low: 0,
    });
  });

  it('reads the exceptions of a cluster once for its namespaces and applies them', async () => {
    mocks.paginatedListQuery.mockImplementation(async (_cluster, resourceClass) => ({
      items: resourceClass.pluralName === 'vulnerabilitymanifestsummaries' ? [] : [scannedWorkload],
    }));
    mocks.request.mockImplementation(async (url: string) =>
      url === '/apis/kubescape.io/v1beta1/securityexceptions'
        ? { items: [exception({ posture: [{ controlID: 'C-0001', action: 'ignore' }] })] }
        : { items: [] }
    );

    loadWorkloadSummaries('cluster-d', 'shop');
    loadWorkloadSummaries('cluster-d', 'blog');
    await vi.waitFor(() => expect(cachedWorkloadSummaries('cluster-d', 'blog')).toBeDefined());
    await vi.waitFor(() => expect(cachedWorkloadSummaries('cluster-d', 'shop')).toBeDefined());

    expect(
      cachedWorkloadSummaries('cluster-d', 'shop')!.controls.get('shop/deployment/web')
    ).toEqual({ name: 'deployment-web', critical: 0, high: 2, medium: 0, low: 0 });
    const exceptionLists = mocks.request.mock.calls.filter(([url]) =>
      url.endsWith('/securityexceptions')
    );
    expect(exceptionLists).toHaveLength(1);
    expect(exceptionLists[0][1]).toEqual({ cluster: 'cluster-d' });
  });

  it('reads no exceptions where the scanners apply them', async () => {
    mocks.readClusterSetup.mockResolvedValue(scannersApply);
    expect(await readClusterExceptions('cluster-e')).toEqual({});
    expect(mocks.request).not.toHaveBeenCalled();
  });

  it('says that the exceptions could not be read, and reads them again soon', async () => {
    mocks.request.mockImplementation(async (url: string) => {
      if (url === '/apis/kubescape.io/v1beta1/clustersecurityexceptions') {
        throw Object.assign(new Error('clustersecurityexceptions is forbidden'), { status: 403 });
      }
      return { items: [] };
    });
    mocks.paginatedListQuery.mockResolvedValue({ items: [scannedWorkload] });

    loadWorkloadSummaries('cluster-f', 'shop', 0);
    await vi.waitFor(() => expect(cachedWorkloadSummaries('cluster-f', 'shop')).toBeDefined());

    expect(workloadExceptionsError('cluster-f', 'shop')).toBe(
      'ClusterSecurityExceptions: clustersecurityexceptions is forbidden'
    );
    const reads = mocks.request.mock.calls.length;
    await readClusterExceptions('cluster-f', 31 * 1000);
    expect(mocks.request.mock.calls.length).toBeGreaterThan(reads);
  });

  it('totals the failed controls of a namespace, and of one summary', async () => {
    mocks.paginatedListQuery.mockImplementation(async (_cluster, resourceClass) => ({
      items:
        resourceClass.pluralName === 'vulnerabilitymanifestsummaries'
          ? []
          : [
              scannedWorkload,
              {
                ...scannedWorkload,
                metadata: { ...scannedWorkload.metadata, labels: labels('Deployment', 'api') },
              },
            ],
    }));
    mocks.request.mockImplementation(async (url: string) =>
      url === '/apis/kubescape.io/v1beta1/securityexceptions'
        ? { items: [exception({ posture: [{ controlID: 'C-0003', action: 'ignore' }] })] }
        : { items: [] }
    );

    const namespace = renderHook(() => useNamespaceFailedControls('cluster-g', 'shop'));
    await waitFor(() => expect(namespace.result.current.counts).toBeDefined());
    expect(namespace.result.current).toEqual({
      counts: { critical: 2, high: 2, medium: 0, low: 0 },
      exceptionsError: undefined,
    });

    const workload = renderHook(() => useFailedControlCounts('cluster-g', scannedWorkload));
    await waitFor(() => expect(workload.result.current.counts).toBeDefined());
    expect(workload.result.current.counts).toEqual({ critical: 1, high: 1, medium: 0, low: 0 });
  });

  it('reads nothing for a namespace while not enabled', async () => {
    const { result } = renderHook(() => useNamespaceFailedControls('cluster-h', 'shop', false));
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(result.current.counts).toBeUndefined();
    expect(mocks.paginatedListQuery).not.toHaveBeenCalled();
  });
});
