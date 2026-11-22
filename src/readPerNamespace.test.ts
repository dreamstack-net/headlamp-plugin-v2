import { vi } from 'vitest';
import { ReadRecorder } from './common/readStatistics';
import { handleListPaginationTasks, QueryTask, queryTaskErrors, readPerNamespace } from './query';

const request = vi.hoisted(() => vi.fn());
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ request }));

const api = '/apis/spdx.softwarecomposition.kubescape.io/v1beta1';
const scanClass = {
  apiEndpoint: {
    apiInfo: [{ group: 'spdx.softwarecomposition.kubescape.io', version: 'v1beta1' }],
  },
  pluralName: 'workloadconfigurationscansummaries',
} as unknown as QueryTask['objectClass'];
const otherClass = { ...scanClass, pluralName: 'others' } as unknown as typeof scanClass;

const namespaceList = (...names: string[]) => ({
  items: names.map(name => ({ metadata: { name } })),
});
const scan = (namespace: string, name: string) => ({ metadata: { namespace, name } });
const forbidden = () => Object.assign(new Error('forbidden'), { status: 403 });

// the list of the metadata of all scans, without fullSpec, which names their namespaces
const discovery = `${api}/workloadconfigurationscansummaries?limit=1000`;
/** A page of that list: the metadata of scans in these namespaces. */
const metadataPage = (namespaces: string[], next = '') => ({
  items: namespaces.map((namespace, i) => ({
    metadata: { namespace, name: `scan-${i}`, uid: `uid-${namespace}-${i}`, resourceVersion: '1' },
  })),
  metadata: next ? { continue: next } : {},
});

/** A task that reads per namespace, and the names of the items it was handed. */
function perNamespaceTask(
  handled: string[],
  options: { allowedNamespaces?: string[]; recorder?: ReadRecorder; pageSize?: number } = {}
) {
  const progress: string[] = [];
  const task: QueryTask = {
    cluster: 'cluster-a',
    allowedNamespaces: options.allowedNamespaces ?? [],
    pageSize: options.pageSize ?? 50,
    continuation: '',
    objectClass: scanClass,
    handleData: (_task, items) =>
      handled.push(...items.map((item: any) => `${item.metadata.cluster}/${item.metadata.name}`)),
    read: (queryTask, continueReading) =>
      (options.recorder ?? new ReadRecorder()).time('cluster-a', 'scans', counter =>
        readPerNamespace(queryTask, continueReading, {
          counter,
          onProgress: (read, total) => progress.push(`${read}/${total}`),
        })
      ),
  };
  return { task, progress };
}

/** A task after the one that reads per namespace, which uses its data. */
function laterTask(handled: string[]): QueryTask {
  return {
    cluster: 'cluster-a',
    allowedNamespaces: [],
    pageSize: 50,
    continuation: '',
    objectClass: otherClass,
    handleData: () => handled.push('later'),
    read: async task => {
      handled.push('later');
      task.continuation = undefined;
    },
  };
}

beforeEach(() => {
  request.mockReset();
});

it('reads each namespace to its last page, six at a time, and hands each one at once', async () => {
  let running = 0;
  let most = 0;
  request.mockImplementation(async (url: string) => {
    // two pages of metadata, which name namespace a twice
    if (url === discovery) return metadataPage(['a', 'a', 'b', 'c'], 'meta-2');
    if (url === `${discovery}&continue=meta-2`) return metadataPage(['d', 'e', 'f', 'g', 'h']);
    running++;
    most = Math.max(most, running);
    await new Promise(resolve => setTimeout(resolve, 1));
    running--;
    const namespace = url.split('/')[5];
    // namespace a has two pages
    if (namespace === 'a' && !url.includes('continue=')) {
      return { items: [scan('a', 'a-1')], metadata: { continue: 'a-2' } };
    }
    if (namespace === 'a') return { items: [scan('a', 'a-2')], metadata: {} };
    return { items: [scan(namespace, `${namespace}-1`)], metadata: {} };
  });
  const handled: string[] = [];
  const recorder = new ReadRecorder();
  const statistics = recorder.start('test');
  const { task, progress } = perNamespaceTask(handled, { recorder, pageSize: 1 });

  await handleListPaginationTasks([task], { current: true }, vi.fn());

  expect(handled.sort()).toEqual(
    ['a-1', 'a-2', 'b-1', 'c-1', 'd-1', 'e-1', 'f-1', 'g-1', 'h-1'].map(name => `cluster-a/${name}`)
  );
  expect(most).toBe(6);
  expect(task.continuation).toBeUndefined();
  expect(queryTaskErrors([task])).toEqual([]);
  expect(progress).toHaveLength(8);
  expect(progress[7]).toBe('8/8');
  const urls = request.mock.calls.map(([url]) => url);
  expect(urls).toContain(
    `${api}/namespaces/a/workloadconfigurationscansummaries?resourceVersion=fullSpec&limit=1&continue=a-2`
  );
  expect(urls).not.toContain('/api/v1/namespaces');
  // two pages of metadata, two pages of a and one of each other namespace
  expect(statistics.phase('cluster-a', 'scans')).toMatchObject({ requests: 11, items: 9 });
});

it('reads only the namespaces that have objects, which a list of their metadata names', async () => {
  request.mockImplementation(async (url: string) => {
    if (url === discovery) return metadataPage(['shop', 'shop', 'billing']);
    const namespace = url.split('/')[5];
    return { items: [scan(namespace, namespace)], metadata: {} };
  });
  const handled: string[] = [];
  const { task, progress } = perNamespaceTask(handled);

  await handleListPaginationTasks([task], { current: true }, vi.fn());

  // the other namespaces of the cluster, without scans, are not asked
  expect(request.mock.calls.map(([url]) => url)).toEqual([
    discovery,
    `${api}/namespaces/shop/workloadconfigurationscansummaries?resourceVersion=fullSpec&limit=50`,
    `${api}/namespaces/billing/workloadconfigurationscansummaries?resourceVersion=fullSpec&limit=50`,
  ]);
  expect(handled).toEqual(['cluster-a/shop', 'cluster-a/billing']);
  expect(progress).toEqual(['1/2', '2/2']);
  expect(task.continuation).toBeUndefined();
});

it('reads nothing more when no namespace has objects', async () => {
  request.mockResolvedValue({ items: [], metadata: {} });
  const handled: string[] = [];
  const { task, progress } = perNamespaceTask(handled);

  await handleListPaginationTasks([task, laterTask(handled)], { current: true }, vi.fn());

  expect(request.mock.calls.map(([url]) => url)).toEqual([discovery]);
  expect(handled).toEqual(['later']);
  expect(progress).toEqual([]);
  expect(task.continuation).toBeUndefined();
  expect(task.clusterWide).toBeUndefined();
});

it('lists the metadata again after it was stopped between its pages', async () => {
  const continueReading = { current: true };
  request.mockImplementation(async (url: string) => {
    if (url === discovery) {
      continueReading.current = false;
      return metadataPage(['shop'], 'meta-2');
    }
    if (url === `${discovery}&continue=meta-2`) return metadataPage(['billing']);
    const namespace = url.split('/')[5];
    return { items: [scan(namespace, namespace)], metadata: {} };
  });
  const handled: string[] = [];
  const { task } = perNamespaceTask(handled);

  await handleListPaginationTasks([task], continueReading, vi.fn());

  expect(request.mock.calls.map(([url]) => url)).toEqual([discovery]);
  expect(task.pendingNamespaces).toBeUndefined();
  expect(task.continuation).toBe('');

  // More scans
  request.mockClear();
  await handleListPaginationTasks([task], { current: true }, vi.fn());

  expect(request.mock.calls.map(([url]) => url)).toEqual([
    discovery,
    `${discovery}&continue=meta-2`,
    `${api}/namespaces/shop/workloadconfigurationscansummaries?resourceVersion=fullSpec&limit=50`,
    `${api}/namespaces/billing/workloadconfigurationscansummaries?resourceVersion=fullSpec&limit=50`,
  ]);
  expect(handled).toEqual(['cluster-a/shop', 'cluster-a/billing']);
  expect(task.continuation).toBeUndefined();
});

it('reads the namespaces of the cluster when the metadata cannot be listed', async () => {
  request.mockImplementation(async (url: string) => {
    if (url === discovery) throw Object.assign(new Error('internal error'), { status: 500 });
    if (url === '/api/v1/namespaces') return namespaceList('shop', 'empty');
    const namespace = url.split('/')[5];
    return { items: namespace === 'shop' ? [scan('shop', 'web')] : [], metadata: {} };
  });
  const handled: string[] = [];
  const recorder = new ReadRecorder();
  const statistics = recorder.start('test');
  const { task } = perNamespaceTask(handled, { recorder });
  const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});

  await handleListPaginationTasks([task], { current: true }, vi.fn());

  expect(warn).toHaveBeenCalledTimes(1);
  warn.mockRestore();
  expect(request.mock.calls.map(([url]) => url)).toEqual([
    discovery,
    '/api/v1/namespaces',
    `${api}/namespaces/shop/workloadconfigurationscansummaries?resourceVersion=fullSpec&limit=50`,
    `${api}/namespaces/empty/workloadconfigurationscansummaries?resourceVersion=fullSpec&limit=50`,
  ]);
  expect(handled).toEqual(['cluster-a/web']);
  expect(queryTaskErrors([task])).toEqual([]);
  expect(statistics.phase('cluster-a', 'scans')).toMatchObject({ requests: 4, failures: 1 });
});

it('does not take metadata without namespaces for a cluster without objects', async () => {
  request.mockImplementation(async (url: string) => {
    if (url === discovery) return { items: [{ metadata: { name: 'web' } }], metadata: {} };
    if (url === '/api/v1/namespaces') return namespaceList('shop');
    return { items: [scan('shop', 'web')], metadata: {} };
  });
  const handled: string[] = [];
  const { task } = perNamespaceTask(handled);
  const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});

  await handleListPaginationTasks([task], { current: true }, vi.fn());

  warn.mockRestore();
  expect(handled).toEqual(['cluster-a/web']);
  expect(task.pendingNamespaces).toEqual([]);
});

it('reads only the allowed namespaces when there are', async () => {
  request.mockResolvedValue({ items: [scan('shop', 'web')], metadata: {} });
  const handled: string[] = [];
  const { task } = perNamespaceTask(handled, { allowedNamespaces: ['shop'] });

  await handleListPaginationTasks([task], { current: true }, vi.fn());

  expect(request.mock.calls.map(([url]) => url)).toEqual([
    `${api}/namespaces/shop/workloadconfigurationscansummaries?resourceVersion=fullSpec&limit=50`,
  ]);
  expect(handled).toEqual(['cluster-a/web']);
});

it('reads pages of the whole cluster when neither the metadata nor the namespaces can be listed', async () => {
  request.mockImplementation(async (url: string) => {
    if (url === discovery || url === '/api/v1/namespaces') throw forbidden();
    const page = url.includes('continue=page-2') ? 2 : 1;
    return {
      items: [scan('shop', `web-${page}`)],
      metadata: { continue: page === 1 ? 'page-2' : '' },
    };
  });
  const handled: string[] = [];
  const { task } = perNamespaceTask(handled);
  const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});

  await handleListPaginationTasks([task], { current: true }, vi.fn());

  warn.mockRestore();
  expect(handled).toEqual(['cluster-a/web-1', 'cluster-a/web-2']);
  expect(request.mock.calls.map(([url]) => url)).toEqual([
    discovery,
    '/api/v1/namespaces',
    `${api}/workloadconfigurationscansummaries?resourceVersion=fullSpec&limit=50`,
    `${api}/workloadconfigurationscansummaries?resourceVersion=fullSpec&limit=50&continue=page-2`,
  ]);
  expect(task.clusterWide).toBe(true);
});

it('reads the namespaces it did not read after it was stopped, and only those', async () => {
  const continueReading = { current: true };
  request.mockImplementation(async (url: string) => {
    if (url === discovery) return metadataPage(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h']);
    const namespace = url.split('/')[5];
    await new Promise(resolve => setTimeout(resolve, 1));
    // Cancel while the first namespaces are read
    if (namespace === 'a') continueReading.current = false;
    return { items: [scan(namespace, namespace)], metadata: {} };
  });
  const handled: string[] = [];
  const { task } = perNamespaceTask(handled);

  await handleListPaginationTasks([task], continueReading, vi.fn());

  // the six namespaces that were being read are kept
  expect(handled.sort()).toEqual(['a', 'b', 'c', 'd', 'e', 'f'].map(ns => `cluster-a/${ns}`));
  expect(task.continuation).toBe('');
  expect(task.pendingNamespaces).toEqual(['g', 'h']);
  expect(queryTaskErrors([task])).toEqual([]);

  // More scans
  request.mockClear();
  await handleListPaginationTasks([task], { current: true }, vi.fn());

  expect(request.mock.calls.map(([url]) => url.split('/')[5])).toEqual(['g', 'h']);
  expect(handled).toHaveLength(8);
  expect(task.continuation).toBeUndefined();
});

it('drops a namespace stopped between its pages, to read it again from its first page', async () => {
  const continueReading = { current: true };
  request.mockImplementation(async (url: string) => {
    if (url.includes('continue=')) return { items: [scan('shop', 'web-2')], metadata: {} };
    continueReading.current = false;
    return { items: [scan('shop', 'web-1')], metadata: { continue: 'page-2' } };
  });
  const handled: string[] = [];
  const { task } = perNamespaceTask(handled, { allowedNamespaces: ['shop'] });

  await handleListPaginationTasks([task], continueReading, vi.fn());
  expect(handled).toEqual([]);
  expect(task.pendingNamespaces).toEqual(['shop']);

  request.mockImplementation(async (url: string) =>
    url.includes('continue=')
      ? { items: [scan('shop', 'web-2')], metadata: {} }
      : { items: [scan('shop', 'web-1')], metadata: { continue: 'page-2' } }
  );
  await handleListPaginationTasks([task], { current: true }, vi.fn());
  expect(handled).toEqual(['cluster-a/web-1', 'cluster-a/web-2']);
});

it('reads the namespaces that failed again, and lets the tasks after it read meanwhile', async () => {
  let failing = true;
  request.mockImplementation(async (url: string) => {
    if (url === discovery) return metadataPage(['shop', 'n1', 'n2', 'n3', 'n4']);
    const namespace = url.split('/')[5];
    if (failing && namespace !== 'shop') throw new Error('timeout');
    return { items: [scan(namespace, namespace)], metadata: {} };
  });
  const handled: string[] = [];
  const { task } = perNamespaceTask(handled);

  await handleListPaginationTasks([task, laterTask(handled)], { current: true }, vi.fn());

  expect(handled).toEqual(['cluster-a/shop', 'later']);
  expect(task.failedNamespaces).toEqual(['n1', 'n2', 'n3', 'n4']);
  expect(queryTaskErrors([task])).toEqual([
    {
      cluster: 'cluster-a',
      message: 'namespace n1: timeout; namespace n2: timeout; namespace n3: timeout; and 1 more',
    },
  ]);

  failing = false;
  request.mockClear();
  await handleListPaginationTasks([task], { current: true }, vi.fn());

  expect(request.mock.calls.map(([url]) => url.split('/')[5])).toEqual(['n1', 'n2', 'n3', 'n4']);
  expect(queryTaskErrors([task])).toEqual([]);
  expect(task.failedNamespaces).toBeUndefined();
  expect(task.continuation).toBeUndefined();
});

it('stops the tasks after it when neither the metadata nor the namespaces can be listed', async () => {
  request.mockRejectedValue(Object.assign(new Error('unavailable'), { status: 503 }));
  const handled: string[] = [];
  const { task } = perNamespaceTask(handled);
  const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {});
  const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});

  await handleListPaginationTasks([task, laterTask(handled)], { current: true }, vi.fn());

  consoleError.mockRestore();
  warn.mockRestore();
  expect(request.mock.calls.map(([url]) => url)).toEqual([discovery, '/api/v1/namespaces']);
  expect(handled).toEqual([]);
  expect(queryTaskErrors([task])).toEqual([{ cluster: 'cluster-a', message: 'unavailable' }]);
  expect(task.continuation).toBe('');
});
