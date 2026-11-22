import { renderHook, waitFor } from '@testing-library/react';
import { vi } from 'vitest';
import { getKubescapeNamespace, useKubescapeNamespace } from './api-queries';

const mocks = vi.hoisted(() => ({
  request: vi.fn(),
  allowedNamespaces: [] as string[],
  currentCluster: 'current' as string | null,
}));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ request: mocks.request }));
vi.mock('@kinvolk/headlamp-plugin/lib/Utils', () => ({ getCluster: () => mocks.currentCluster }));
vi.mock('../common/clusterContext', () => ({
  getAllowedNamespaces: () => mocks.allowedNamespaces,
}));
vi.mock('../model', () => ({ customObjectLabel: 'kubescape.io/custom-object' }));

beforeEach(() => {
  mocks.request.mockReset();
  mocks.allowedNamespaces = [];
  mocks.currentCluster = 'current';
  window.sessionStorage.clear();
});

const operator = 'app.kubernetes.io/name=kubescape-operator,app.kubernetes.io/component=operator';

function selectorOf(url: string) {
  return new URLSearchParams(url.split('?')[1]).get('labelSelector');
}

function pods(namespace?: string) {
  return { items: namespace ? [{ metadata: { namespace } }] : [] };
}

it('finds the namespace of the operator, which every install runs', async () => {
  mocks.request.mockResolvedValue(pods('security'));

  expect(await getKubescapeNamespace('cluster-a')).toEqual({
    kubeScapeNamespace: 'security',
    error: null,
  });
  expect(mocks.request).toHaveBeenCalledTimes(1);
  const [url, options] = mocks.request.mock.calls[0];
  expect(url.split('?')[0]).toBe('/api/v1/pods');
  expect(selectorOf(url)).toBe(operator);
  expect(new URLSearchParams(url.split('?')[1]).get('limit')).toBe('1');
  expect(options).toEqual({ cluster: 'cluster-a' });

  // remembered for the session
  await getKubescapeNamespace('cluster-a');
  expect(mocks.request).toHaveBeenCalledTimes(1);
});

it('falls back to any pod of the chart when the operator does not run', async () => {
  mocks.request.mockImplementation(async (url: string) =>
    selectorOf(url) === 'app.kubernetes.io/part-of=kubescape' ? pods('ks') : pods()
  );

  expect((await getKubescapeNamespace('cluster-b')).kubeScapeNamespace).toBe('ks');
  expect(mocks.request.mock.calls.map(([url]) => selectorOf(url))).toEqual([
    operator,
    'app.kubernetes.io/name=kubescape-operator',
    'app.kubernetes.io/part-of=kubescape',
  ]);
});

it('looks a cluster up once when it is asked for from several places at once', async () => {
  let answer: (value: unknown) => void = () => {};
  mocks.request.mockReturnValue(new Promise(resolve => (answer = resolve)));

  const lookups = [getKubescapeNamespace('cluster-c'), getKubescapeNamespace('cluster-c')];
  answer(pods('kubescape'));

  expect((await Promise.all(lookups)).map(result => result.kubeScapeNamespace)).toEqual([
    'kubescape',
    'kubescape',
  ]);
  expect(mocks.request).toHaveBeenCalledTimes(1);
});

it('looks in the allowed namespaces when pods cannot be listed in all namespaces', async () => {
  mocks.allowedNamespaces = ['shop', 'security'];
  mocks.request.mockImplementation(async (url: string) => {
    if (url.startsWith('/api/v1/pods'))
      throw Object.assign(new Error('forbidden'), { status: 403 });
    return url.startsWith('/api/v1/namespaces/security/') && selectorOf(url) === operator
      ? pods('security')
      : pods();
  });

  expect((await getKubescapeNamespace('cluster-d')).kubeScapeNamespace).toBe('security');

  mocks.allowedNamespaces = [];
  mocks.request.mockRejectedValue(new Error('forbidden'));
  expect(await getKubescapeNamespace('cluster-e')).toEqual({
    kubeScapeNamespace: undefined,
    error: 'Failed to look up the Kubescape operator namespace: forbidden',
  });
});

it('follows the cluster it is asked about', async () => {
  mocks.request.mockImplementation(async (_url: string, { cluster }) =>
    pods(cluster === 'cluster-f' ? 'kubescape' : 'ks-system')
  );

  const { result, rerender } = renderHook(({ cluster }) => useKubescapeNamespace(cluster), {
    initialProps: { cluster: 'cluster-f' as string | undefined },
  });
  await waitFor(() => expect(result.current.kubeScapeNamespace).toBe('kubescape'));

  rerender({ cluster: 'cluster-g' });
  // not the namespace of the cluster before
  expect(result.current).toEqual({ kubeScapeNamespace: undefined, error: null, loading: true });
  await waitFor(() => expect(result.current.kubeScapeNamespace).toBe('ks-system'));

  // by default the current cluster, also after the user switched to another one
  mocks.currentCluster = 'cluster-f';
  rerender({ cluster: undefined });
  await waitFor(() => expect(result.current.kubeScapeNamespace).toBe('kubescape'));
});
