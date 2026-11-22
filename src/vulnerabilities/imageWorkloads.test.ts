import { vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  request: vi.fn(),
  namespaces: [] as string[],
}));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ request: mocks.request }));
vi.mock('../common/clusterContext', () => ({ getAllowedNamespaces: () => mocks.namespaces }));

import { fetchImageWorkloads, latestScan } from './imageWorkloads';

const api = '/apis/spdx.softwarecomposition.kubescape.io/v1beta1';
const selector = 'labelSelector=kubescape.io%2Fimage-id%3Dimage-1';
const forbidden = () => Object.assign(new Error('forbidden'), { status: 403 });

// the metadata of the summary of a container, as a list without fullSpec returns it
function summary(namespace: string, name: string, timestamp?: string) {
  return {
    metadata: {
      name: `deployment-${name}-app`,
      namespace,
      labels: {
        'kubescape.io/workload-kind': 'Deployment',
        'kubescape.io/workload-name': name,
        'kubescape.io/workload-namespace': namespace,
        'kubescape.io/workload-container-name': 'app',
      },
      annotations: timestamp ? { 'kubescape.io/timestamp': timestamp } : {},
    },
  };
}

beforeEach(() => {
  mocks.request.mockReset();
  mocks.namespaces = [];
});
afterEach(() => {
  vi.restoreAllMocks();
});

it('lists the workloads that run the image, by namespace and name', async () => {
  mocks.request.mockResolvedValue({
    items: [summary('shop', 'web', '1790000000'), summary('batch', 'worker', '1790003600')],
  });

  const { workloads, errors } = await fetchImageWorkloads('image-1', 'cluster-a');

  expect(mocks.request.mock.calls).toEqual([
    [`${api}/vulnerabilitymanifestsummaries?${selector}`, { cluster: 'cluster-a' }],
  ]);
  expect(errors).toEqual([]);
  expect(workloads.map(workload => `${workload.namespace}/${workload.name}`)).toEqual([
    'batch/worker',
    'shop/web',
  ]);
  expect(workloads[1]).toMatchObject({
    kind: 'Deployment',
    container: 'app',
    summaryName: 'deployment-web-app',
    summaryNamespace: 'shop',
  });
  expect(latestScan(workloads)).toBe(new Date(1790003600 * 1000).toISOString());
});

it('leaves the other allowed namespaces when one of them cannot be read', async () => {
  mocks.namespaces = ['team-a', 'team-b', 'team-c'];
  mocks.request.mockImplementation(async (url: string) => {
    if (url.includes('/namespaces/team-b/')) throw forbidden();
    return { items: [summary(url.split('/namespaces/')[1].split('/')[0], 'web')] };
  });

  const { workloads, errors } = await fetchImageWorkloads('image-1', 'cluster-a');

  expect(mocks.request.mock.calls.map(([url]) => url)).toEqual(
    ['team-a', 'team-b', 'team-c'].map(
      namespace => `${api}/namespaces/${namespace}/vulnerabilitymanifestsummaries?${selector}`
    )
  );
  expect(workloads.map(workload => workload.namespace)).toEqual(['team-a', 'team-c']);
  // the namespace that could not be read is named, for the page to show
  expect(errors).toEqual(['namespace team-b: forbidden']);
});

it('rejects when none of the namespaces can be read', async () => {
  mocks.request.mockRejectedValue(forbidden());

  mocks.namespaces = ['team-a', 'team-b'];
  await expect(fetchImageWorkloads('image-1', 'cluster-a')).rejects.toThrow('forbidden');
  // as does the list of all namespaces
  mocks.namespaces = [];
  await expect(fetchImageWorkloads('image-1', 'cluster-a')).rejects.toThrow('forbidden');
});
