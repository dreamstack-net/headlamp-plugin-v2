import { vi } from 'vitest';
import {
  fullSpecListQuery,
  handleListPaginationTasks,
  listInNamespaces,
  paginatedListQuery,
  QueryTask,
  queryTaskErrors,
} from './query';
import { T1, T2 } from './vulnerabilities/testFixtures';

const request = vi.hoisted(() => vi.fn());
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ request }));

const objectClass = {
  apiEndpoint: {
    apiInfo: [{ group: 'spdx.softwarecomposition.kubescape.io', version: 'v1beta1' }],
  },
  pluralName: 'vulnerabilitymanifests',
} as unknown as Parameters<typeof paginatedListQuery>[1];

it.each([{ namespaces: [] }, { namespaces: ['reports', 'relevant-reports'] }])(
  'queries the originating cluster with namespace restrictions $namespaces',
  async ({ namespaces }) => {
    request.mockReset().mockImplementation(async (_url, { cluster }) => ({
      items: [
        {
          metadata: { name: 'same-image' },
          spec: { metadata: { report: { createdAt: cluster === 'cluster-a' ? T1 : T2 } } },
        },
      ],
      // the last page of a namespace; across all namespaces, a page of many
      metadata: { continue: namespaces.length ? '' : 'next-page' },
    }));
    for (const cluster of ['cluster-a', 'cluster-b']) {
      const result = await paginatedListQuery(cluster, objectClass, '', 50, namespaces);
      expect(result.items).toHaveLength(namespaces.length || 1);
      for (const item of result.items) {
        expect(item.metadata.cluster).toBe(cluster);
        expect(item.spec.metadata.report.createdAt).toBe(cluster === 'cluster-a' ? T1 : T2);
      }
    }
    expect(request).toHaveBeenCalledTimes(2 * (namespaces.length || 1));
    expect(
      request.mock.calls.every(([url]) => url.endsWith('?resourceVersion=fullSpec&limit=50'))
    ).toBe(true);
    expect(request.mock.calls.map(([, options]) => options.cluster)).toEqual(
      ['cluster-a', 'cluster-b'].flatMap(cluster => Array(namespaces.length || 1).fill(cluster))
    );
  }
);

it('encodes the continuation token and treats an empty token as the last page', async () => {
  request.mockReset().mockResolvedValue({ items: [], metadata: { continue: '' } });

  const result = await paginatedListQuery('cluster-a', objectClass, 'a+b/c=', 50);

  expect(request.mock.calls[0][0]).toBe(
    '/apis/spdx.softwarecomposition.kubescape.io/v1beta1/vulnerabilitymanifests' +
      '?resourceVersion=fullSpec&limit=50&continue=a%2Bb%2Fc%3D'
  );
  expect(result.continuation).toBeUndefined();
});

it('reads every page of each allowed namespace', async () => {
  request.mockReset().mockImplementation(async (url: string) => {
    const namespace = url.split('/')[5];
    const page = url.includes('continue=') ? 2 : 1;
    return {
      items: [{ metadata: { name: `${namespace}-${page}` } }],
      metadata: { continue: page === 1 ? `${namespace}-page-2` : '' },
    };
  });

  const result = await paginatedListQuery('cluster-a', objectClass, '', 50, ['shop', 'blog']);

  expect(result.items.map((item: any) => item.metadata.name)).toEqual([
    'shop-1',
    'shop-2',
    'blog-1',
    'blog-2',
  ]);
  expect(result.continuation).toBeUndefined();
  expect(request.mock.calls.map(([url]) => url.split('?')[1])).toContain(
    'resourceVersion=fullSpec&limit=50&continue=shop-page-2'
  );
});

it('reads clusters in parallel and the tasks of one cluster in order', async () => {
  // Pending requests by "<cluster> <resource>"
  const pending = new Map<string, () => void>();
  request.mockReset().mockImplementation(
    (url: string, { cluster }) =>
      new Promise(resolve => {
        const resource = url.split('?')[0].split('/').pop();
        pending.set(`${cluster} ${resource}`, () =>
          resolve({ items: [{ metadata: {} }], metadata: {} })
        );
      })
  );
  const summaryClass = {
    ...objectClass,
    pluralName: 'vulnerabilitymanifestsummaries',
  } as unknown as typeof objectClass;
  const handled: string[] = [];
  const task = (cluster: string, taskClass: typeof objectClass): QueryTask => ({
    cluster,
    allowedNamespaces: [],
    pageSize: 50,
    continuation: '',
    objectClass: taskClass,
    handleData: queryTask => handled.push(`${cluster} ${queryTask.objectClass.pluralName}`),
  });
  const setLoading = vi.fn();

  const done = handleListPaginationTasks(
    [
      task('cluster-a', objectClass),
      task('cluster-a', summaryClass),
      task('cluster-b', objectClass),
    ],
    { current: true },
    setLoading
  );

  // Both clusters start at once, the summaries of cluster-a wait for its manifests
  await vi.waitFor(() =>
    expect([...pending.keys()]).toEqual([
      'cluster-a vulnerabilitymanifests',
      'cluster-b vulnerabilitymanifests',
    ])
  );
  pending.get('cluster-a vulnerabilitymanifests')!();
  await vi.waitFor(() =>
    expect(pending.has('cluster-a vulnerabilitymanifestsummaries')).toBe(true)
  );
  pending.get('cluster-a vulnerabilitymanifestsummaries')!();
  pending.get('cluster-b vulnerabilitymanifests')!();
  await done;

  expect(handled.sort()).toEqual([
    'cluster-a vulnerabilitymanifests',
    'cluster-a vulnerabilitymanifestsummaries',
    'cluster-b vulnerabilitymanifests',
  ]);
  expect(setLoading.mock.calls).toEqual([[true], [false]]);
});

function pagedTask(cluster: string, handled: string[], taskClass = objectClass): QueryTask {
  return {
    cluster,
    allowedNamespaces: [],
    pageSize: 50,
    continuation: '',
    objectClass: taskClass,
    handleData: (_task, items) => handled.push(...items.map((item: any) => item.metadata.name)),
  };
}

// three pages: page-1, page-2 and page-3
function threePages(url: string) {
  const page = Number(url.match(/continue=page-(\d)/)?.[1] ?? 1);
  return Promise.resolve({
    items: [{ metadata: { name: `page-${page}` } }],
    metadata: { continue: page < 3 ? `page-${page + 1}` : '' },
  });
}

it('reads each page once when two pages read the same tasks at once', async () => {
  request.mockReset().mockImplementation(threePages);
  const handled: string[] = [];
  const task = pagedTask('cluster-a', handled);

  await Promise.all([
    handleListPaginationTasks([task], { current: true }, vi.fn()),
    handleListPaginationTasks([task], { current: true }, vi.fn()),
  ]);

  expect(handled).toEqual(['page-1', 'page-2', 'page-3']);
  expect(request).toHaveBeenCalledTimes(3);
});

it('goes on reading when the page that started the read stops', async () => {
  request.mockReset().mockImplementation(threePages);
  const handled: string[] = [];
  const task = pagedTask('cluster-a', handled);
  const left = { current: true };

  const first = handleListPaginationTasks([task], left, vi.fn());
  // the page that started it is left while its first page is read
  left.current = false;
  await Promise.all([first, handleListPaginationTasks([task], { current: true }, vi.fn())]);

  expect(handled).toEqual(['page-1', 'page-2', 'page-3']);
});

it('keeps a page that failed for the next read and stops the tasks after it', async () => {
  let fail = true;
  request.mockReset().mockImplementation((url: string) => {
    if (fail && url.includes('continue=page-2')) return Promise.reject(new Error('timeout'));
    return threePages(url);
  });
  const handled: string[] = [];
  const summaryClass = {
    ...objectClass,
    pluralName: 'vulnerabilitymanifestsummaries',
  } as unknown as typeof objectClass;
  const tasks = [pagedTask('cluster-a', handled), pagedTask('cluster-a', handled, summaryClass)];
  const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {});

  await handleListPaginationTasks(tasks, { current: true }, vi.fn());

  expect(consoleError).toHaveBeenCalledWith(
    'Error fetching data in cluster cluster-a:',
    expect.objectContaining({ message: 'timeout' })
  );
  consoleError.mockRestore();
  expect(handled).toEqual(['page-1']);
  expect(tasks[0].continuation).toBe('page-2');
  expect(queryTaskErrors(tasks)).toEqual([{ cluster: 'cluster-a', message: 'timeout' }]);
  // the summaries need the manifests, so they are not read yet
  expect(request.mock.calls.some(([url]) => url.includes('summaries'))).toBe(false);

  fail = false;
  await handleListPaginationTasks(tasks, { current: true }, vi.fn());

  expect(handled).toEqual(['page-1', 'page-2', 'page-3', 'page-1', 'page-2', 'page-3']);
  expect(queryTaskErrors(tasks)).toEqual([]);
});

it('keeps the items of the namespaces that could be read', async () => {
  request.mockReset().mockImplementation(async (url: string) => {
    if (url.includes('/namespaces/secret/')) throw new Error('forbidden');
    return { items: [{ metadata: { name: 'shop-1' } }], metadata: {} };
  });

  const result = await paginatedListQuery('cluster-a', objectClass, '', 50, ['shop', 'secret']);

  expect(result.items.map((item: any) => item.metadata.name)).toEqual(['shop-1']);
  expect(result.errors).toEqual(['namespace secret: forbidden']);
  // none at all is an error of the list
  await expect(paginatedListQuery('cluster-a', objectClass, '', 50, ['secret'])).rejects.toThrow(
    'forbidden'
  );
});

it('reads the allowed namespaces that failed again, and only those', async () => {
  let secretFails = true;
  request.mockReset().mockImplementation(async (url: string) => {
    const namespace = url.split('/')[5];
    if (namespace === 'secret' && secretFails) throw new Error('timeout');
    return { items: [{ metadata: { name: `${namespace}-1` } }], metadata: {} };
  });
  const handled: string[] = [];
  const summaryClass = {
    ...objectClass,
    pluralName: 'vulnerabilitymanifestsummaries',
  } as unknown as typeof objectClass;
  const tasks = [pagedTask('cluster-a', handled), pagedTask('cluster-a', handled, summaryClass)];
  for (const task of tasks) task.allowedNamespaces = ['shop', 'secret'];
  const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {});

  await handleListPaginationTasks(tasks, { current: true }, vi.fn());

  // the namespace that could be read does not wait for the one that could not
  expect(handled).toEqual(['shop-1', 'shop-1']);
  expect(tasks[0].failedNamespaces).toEqual(['secret']);
  expect(tasks[0].continuation).toBe('');
  expect(queryTaskErrors(tasks)).toEqual([
    { cluster: 'cluster-a', message: 'namespace secret: timeout' },
  ]);

  // still failing: the error is kept, and nothing is read twice
  request.mockClear();
  await handleListPaginationTasks(tasks, { current: true }, vi.fn());
  expect(request.mock.calls.map(([url]) => url.split('/')[5])).toEqual(['secret', 'secret']);
  expect(handled).toEqual(['shop-1', 'shop-1']);
  expect(queryTaskErrors(tasks)).toEqual([
    { cluster: 'cluster-a', message: 'namespace secret: timeout' },
  ]);
  consoleError.mockRestore();

  secretFails = false;
  request.mockClear();
  await handleListPaginationTasks(tasks, { current: true }, vi.fn());

  expect(request).toHaveBeenCalledTimes(2);
  expect(handled).toEqual(['shop-1', 'shop-1', 'secret-1', 'secret-1']);
  expect(queryTaskErrors(tasks)).toEqual([]);
  expect(tasks.map(task => [task.continuation, task.failedNamespaces])).toEqual([
    [undefined, undefined],
    [undefined, undefined],
  ]);
});

it('names the namespaces that could not be read', async () => {
  request.mockReset().mockImplementation(async (url: string) => {
    if (url.includes('/namespaces/secret/')) throw new Error('forbidden');
    return { items: [], metadata: {} };
  });

  const result = await paginatedListQuery('cluster-a', objectClass, '', 50, ['shop', 'secret']);

  expect(result.failedNamespaces).toEqual(['secret']);
  expect(
    (await paginatedListQuery('cluster-a', objectClass, '', 50, ['shop'])).failedNamespaces
  ).toBeUndefined();
});

it('reads all objects with their spec, naming the namespaces that could not be read', async () => {
  request.mockReset().mockImplementation(async (url: string) => {
    if (url.includes('/namespaces/secret/')) throw new Error('forbidden');
    return { items: [{ metadata: { name: 'web' } }], metadata: {} };
  });

  const result = await fullSpecListQuery('cluster-a', objectClass, ['shop', 'secret']);

  expect(result).toEqual({
    items: [{ metadata: { name: 'web', cluster: 'cluster-a' } }],
    errors: ['namespace secret: forbidden'],
  });
  expect(request.mock.calls[0][0]).toContain('?resourceVersion=fullSpec&limit=500');
  // none at all is an error of the list
  await expect(fullSpecListQuery('cluster-a', objectClass, ['secret'])).rejects.toThrow(
    'forbidden'
  );
});

it('keeps the pages of the cluster read before one that could not be read', async () => {
  request.mockReset().mockImplementation(async (url: string) => {
    if (url.includes('continue=page-3')) throw new Error('timeout');
    const page = url.includes('continue=page-2') ? 2 : 1;
    return {
      items: [{ metadata: { name: `web-${page}` } }],
      metadata: { continue: `page-${page + 1}` },
    };
  });

  const result = await fullSpecListQuery('cluster-a', objectClass, [], 1);

  expect(result.items.map((item: any) => item.metadata.name)).toEqual(['web-1', 'web-2']);
  expect(result.errors).toEqual(['the objects after the first 2: timeout']);
  // the first page is an error of the list
  request.mockReset().mockRejectedValue(new Error('timeout'));
  await expect(fullSpecListQuery('cluster-a', objectClass)).rejects.toThrow('timeout');
});

it('lists the namespaces that can be read and names those that cannot', async () => {
  request.mockReset().mockImplementation(async (url: string) => {
    if (url.includes('/namespaces/secret/')) throw new Error('forbidden');
    // a list without items, as some API servers answer for an empty list
    if (url.includes('/namespaces/empty/')) return { items: null };
    return { items: [{ metadata: { name: 'web' } }] };
  });

  const result = await listInNamespaces(objectClass, 'cluster-a', ['shop', 'secret', 'empty']);

  expect(result.items).toEqual([{ metadata: { name: 'web', cluster: 'cluster-a' } }]);
  expect(result.errors).toEqual(['namespace secret: forbidden']);
  expect(request.mock.calls.map(([url, options]) => [url, options])).toContainEqual([
    '/apis/spdx.softwarecomposition.kubescape.io/v1beta1/namespaces/shop/vulnerabilitymanifests',
    { cluster: 'cluster-a' },
  ]);

  // none at all is an error of the list
  await expect(listInNamespaces(objectClass, 'cluster-a', ['secret'])).rejects.toThrow('forbidden');

  // without allowed namespaces, the cluster is listed at once
  request.mockReset().mockResolvedValue({ items: null });
  expect(await listInNamespaces(objectClass, null, [])).toEqual({ items: [], errors: [] });
  expect(request).toHaveBeenCalledWith(
    '/apis/spdx.softwarecomposition.kubescape.io/v1beta1/vulnerabilitymanifests',
    {}
  );
});
