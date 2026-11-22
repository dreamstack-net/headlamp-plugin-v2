import { request } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import { KubeObjectClass } from '@kinvolk/headlamp-plugin/lib/k8s/cluster';
import { runConcurrently } from './common/concurrency';
import { errorMessage, errorStatus } from './common/errors';
import { noCounter, ReadCounter } from './common/readStatistics';
import type { ClusterError } from './model';

// the namespaces read at once; the browser opens six connections to a host
const namespaceConcurrency = 6;

export type QueryTask = {
  cluster: string;
  allowedNamespaces: string[];
  pageSize: number;
  // '' requests the first page, undefined means all pages have been read
  continuation: string | undefined;
  objectClass: KubeObjectClass;
  handleData: (queryTask: QueryTask, items: any[]) => void;
  // why the last page could not be read, or which allowed namespaces could not; a page that
  // failed is read again by the next read of the task
  error?: string;
  // the allowed namespaces that could not be read, which the next read of the task reads again,
  // and only those, as the others were read; continuation is then ''
  failedNamespaces?: string[];
  // the page being read, which other reads of the task wait for instead of reading it again
  reading?: Promise<void>;
  // reads the task in another way than by the pages of a list, such as the objects that the
  // tasks before it refer to; it hands the data to the task and sets continuation and error
  read?: (task: QueryTask, continueReading: { current: boolean }) => Promise<void>;
  // for readPerNamespace: the namespaces it has yet to read, including the ones that failed,
  // undefined before it knows them
  pendingNamespaces?: string[];
  // for readPerNamespace: the namespaces it read or has to read, for the progress
  namespaceCount?: number;
  // for readPerNamespace: neither the objects without their spec nor the namespaces can be
  // listed, so it reads pages of the whole cluster
  clusterWide?: boolean;
};

/** The clusters whose tasks could not be read completely, to show next to the data. */
export function queryTaskErrors(queryTasks: QueryTask[]): ClusterError[] {
  const errors = new Map<string, string>();
  for (const task of queryTasks) {
    if (task.error && !errors.has(task.cluster)) errors.set(task.cluster, task.error);
  }
  return [...errors].map(([cluster, message]) => ({ cluster, message }));
}

/** Reads the next page of the list of a task and hands its items to the task. */
async function readListPage(task: QueryTask, counter: ReadCounter = noCounter) {
  const namespaces = task.failedNamespaces ?? task.allowedNamespaces;
  const response = await paginatedListQuery(
    task.cluster,
    task.objectClass,
    task.continuation ?? '',
    task.pageSize,
    namespaces,
    () => counter.request()
  );
  task.failedNamespaces = response.failedNamespaces?.length ? response.failedNamespaces : undefined;
  task.continuation = task.failedNamespaces ? '' : response.continuation;
  task.error = response.errors?.length ? response.errors.join('; ') : undefined;
  if (response.errors?.length) counter.failure(response.errors.length);
  counter.items(response.items.length);
  task.handleData(task, response.items);
}

/** Reads the next page of a task and hands its items to the task. */
async function readPage(task: QueryTask, continueReading: { current: boolean }) {
  try {
    if (task.read) {
      await task.read(task, continueReading);
      return;
    }
    await readListPage(task);
  } catch (error) {
    console.error(`Error fetching data in cluster ${task.cluster}:`, error);
    // the continuation and the failed namespaces are kept, so they are read again the next time
    task.error = task.failedNamespaces
      ? `namespace ${task.failedNamespaces.join(', ')}: ${errorMessage(error)}`
      : errorMessage(error);
  }
}

/**
 * Handles paginated list queries for a set of query tasks. This function continues
 * fetching data for each task until the `continuation` token is undefined or
 * `continueReading` is set to false. Clusters are read in parallel. The tasks of one
 * cluster are read in the given order, because a task may use the data of the tasks
 * before it (vulnerability summaries refer to manifests). It sets the loading state
 * during the process.
 *
 * Pages that could not be read stop the tasks of their cluster and leave an error on the task
 * (see queryTaskErrors); the next call reads them again. Allowed namespaces that could not be
 * read leave an error too, but not the tasks after it, as the other namespaces were read; the
 * next call reads those namespaces again. Pages are read once, also when pages
 * share their tasks: a call that finds a page being read waits for it, and continues reading
 * when the call that started it stops.
 *
 * @param queryTasks - An array of QueryTasks, each representing a task with details
 *                     for querying a paginated list.
 * @param continueReading - A mutable reference that controls whether to continue
 *                          reading pages of data.
 * @param setLoading - A callback function to set the loading state.
 * @returns A promise that resolves when all tasks have been processed.
 */
export async function handleListPaginationTasks(
  queryTasks: QueryTask[],
  continueReading: React.MutableRefObject<boolean>,
  setLoading: (loading: boolean) => void
): Promise<void> {
  if (queryTasks.some(task => task.continuation !== undefined)) {
    setLoading(true);

    const tasksByCluster = new Map<string, QueryTask[]>();
    for (const task of queryTasks) {
      tasksByCluster.set(task.cluster, [...(tasksByCluster.get(task.cluster) ?? []), task]);
    }

    await Promise.all(
      [...tasksByCluster.values()].map(async clusterTasks => {
        for (const task of clusterTasks) {
          // a page that failed before is read again
          if (task.continuation !== undefined) task.error = undefined;
          while (continueReading.current && task.continuation !== undefined && !task.error) {
            if (!task.reading) {
              task.reading = readPage(task, continueReading).finally(() => {
                task.reading = undefined;
              });
            }
            await task.reading;
          }
          // the tasks after it may need its data, unless only some namespaces are missing
          if (task.error && task.continuation !== undefined && !task.failedNamespaces) break;
        }
      })
    );
  }
  setLoading(false);
}

/**
 * All objects of a class in a cluster with their spec, read page by page: the Kubescape storage
 * only returns the spec of the objects of a list that asks for fullSpec. Allowed namespaces that
 * cannot be read, or a page after the first, do not take the objects read with them: the errors
 * say what could not be read; when nothing could be, it rejects.
 */
export async function fullSpecListQuery(
  cluster: string,
  objectClass: KubeObjectClass,
  allowedNamespaces: string[] = [],
  pageSize: number = 500
): Promise<NamespacedList> {
  const items: any[] = [];
  const errors: string[] = [];
  let continuation: string | undefined = '';
  do {
    let page: Awaited<ReturnType<typeof paginatedListQuery>>;
    try {
      page = await paginatedListQuery(
        cluster,
        objectClass,
        continuation,
        pageSize,
        allowedNamespaces
      );
    } catch (error) {
      if (!continuation) throw error;
      errors.push(`the objects after the first ${items.length}: ${errorMessage(error)}`);
      break;
    }
    errors.push(...(page.errors ?? []));
    items.push(...page.items);
    continuation = page.continuation;
  } while (continuation);
  return { items, errors };
}

/**
 * Queries a paginated list of objects of the given class.
 *
 * @param cluster - The name of the cluster to query.
 * @param objectClass - The class of objects to query.
 * @param continuation - The continuation token of the page to fetch, '' for the first page.
 * @param pageSize - An optional page size to limit the number of items fetched.
 * @param allowedNamespaces - An optional list of namespaces to query.
 * @param onRequest - Called for each request, to count them.
 * @returns A promise that resolves with an object containing the list of items and the
 *          continuation token, which is undefined when there are no more pages. With allowed
 *          namespaces, the errors say why namespaces could not be read and failedNamespaces
 *          names them; it rejects only when none could be read.
 */
export async function paginatedListQuery(
  cluster: string,
  objectClass: KubeObjectClass,
  continuation: string,
  pageSize: number | undefined,
  allowedNamespaces: string[] = [],
  onRequest: () => void = () => {}
): Promise<{
  items: any[];
  continuation: string | undefined;
  errors?: string[];
  failedNamespaces?: string[];
}> {
  const group = objectClass.apiEndpoint.apiInfo[0].group;
  const version = objectClass.apiEndpoint.apiInfo[0].version;
  const queryFragment = fullSpecQuery(objectClass, pageSize);
  if (allowedNamespaces.length > 0) {
    // each namespace is read to its last page, as one page of the task; a namespace that
    // cannot be read does not take the items of the others with it
    const results = await Promise.allSettled(
      allowedNamespaces.map(
        async namespace =>
          (await readNamespacePages(cluster, objectClass, namespace, pageSize, onRequest))!
      )
    );

    const failedNamespaces = allowedNamespaces.filter((_, i) => results[i].status === 'rejected');
    const errors = results.flatMap((result, i) =>
      result.status === 'rejected'
        ? [`namespace ${allowedNamespaces[i]}: ${errorMessage(result.reason)}`]
        : []
    );
    if (errors.length === allowedNamespaces.length) {
      throw (results[0] as PromiseRejectedResult).reason;
    }
    const items = results.flatMap(result => (result.status === 'fulfilled' ? result.value : []));
    items.forEach((item: any) => {
      item.metadata.cluster = cluster;
    });
    return {
      items,
      continuation: undefined,
      ...(errors.length ? { errors, failedNamespaces } : {}),
    };
  } else {
    const fragment = continuation
      ? `${queryFragment}&continue=${encodeURIComponent(continuation)}`
      : queryFragment;
    onRequest();
    const overviewList = await request(`/apis/${group}/${version}/${fragment}`, {
      cluster: cluster,
    });
    overviewList.items.forEach((item: any) => {
      item.metadata.cluster = cluster;
    });
    // The API server signals the last page with an absent or empty continue token
    return {
      items: overviewList.items,
      continuation: overviewList.metadata?.continue || undefined,
    };
  }
}

/** The query of a list of objects with their spec, in pages of `pageSize` when given. */
function fullSpecQuery(objectClass: KubeObjectClass, pageSize: number | undefined): string {
  const query = `${objectClass.pluralName}?resourceVersion=fullSpec`;
  return pageSize !== undefined ? `${query}&limit=${pageSize}` : query;
}

/**
 * The objects of a class in a namespace with their spec, read to the last page; undefined when
 * `shouldContinue` said to stop between two pages.
 */
async function readNamespacePages(
  cluster: string,
  objectClass: KubeObjectClass,
  namespace: string,
  pageSize: number | undefined,
  onRequest: () => void,
  shouldContinue: () => boolean = () => true
): Promise<any[] | undefined> {
  const group = objectClass.apiEndpoint.apiInfo[0].group;
  const version = objectClass.apiEndpoint.apiInfo[0].version;
  const queryFragment = fullSpecQuery(objectClass, pageSize);
  const items: any[] = [];
  let next = '';
  do {
    if (next && !shouldContinue()) return undefined;
    const fragment = next ? `${queryFragment}&continue=${encodeURIComponent(next)}` : queryFragment;
    onRequest();
    const list = await request(
      `/apis/${group}/${version}/namespaces/${encodeURIComponent(namespace)}/${fragment}`,
      { cluster }
    );
    items.push(...(list.items ?? []));
    next = list.metadata?.continue || '';
  } while (next);
  return items;
}

// the failed namespaces that the error of a task names
const namedFailures = 3;

// the objects whose metadata a page of the list that finds their namespaces holds
const discoveryPageSize = 1000;

/**
 * The namespaces that have objects of a class, in the order the list names them, from a list of
 * their metadata: without fullSpec, the Kubescape storage answers a list from its index, without
 * reading and decoding the objects. Undefined when `shouldContinue` said to stop between two
 * pages.
 */
async function namespacesWithObjects(
  cluster: string,
  objectClass: KubeObjectClass,
  counter: ReadCounter,
  shouldContinue: () => boolean
): Promise<string[] | undefined> {
  const group = objectClass.apiEndpoint.apiInfo[0].group;
  const version = objectClass.apiEndpoint.apiInfo[0].version;
  const namespaces = new Set<string>();
  let next = '';
  do {
    if (next && !shouldContinue()) return undefined;
    const query = `limit=${discoveryPageSize}${
      next ? `&continue=${encodeURIComponent(next)}` : ''
    }`;
    counter.request();
    const list = await request(`/apis/${group}/${version}/${objectClass.pluralName}?${query}`, {
      cluster,
    });
    for (const item of list?.items ?? []) {
      const namespace = item?.metadata?.namespace;
      // an object without its namespace would be left out of the read
      if (!namespace) throw new Error(`a listed ${objectClass.pluralName} has no namespace`);
      namespaces.add(namespace);
    }
    next = list?.metadata?.continue || '';
  } while (next);
  return [...namespaces];
}

/**
 * The namespaces of the cluster; undefined without permission to list them, or when it has none.
 */
async function clusterNamespaces(
  cluster: string,
  counter: ReadCounter
): Promise<string[] | undefined> {
  try {
    counter.request();
    const list = await request('/api/v1/namespaces', { cluster });
    const names: string[] = (list?.items ?? []).map(
      (namespace: { metadata: { name: string } }) => namespace.metadata.name
    );
    return names.length > 0 ? names : undefined;
  } catch (error) {
    if (errorStatus(error) !== 403) throw error;
    return undefined;
  }
}

/**
 * Reads a task a namespace at a time, six namespaces at once, as the `read` of a QueryTask. The
 * Kubescape storage reads and decodes the objects of a list one after the other within one
 * request, while it locks per object, so lists of separate namespaces are read in parallel. Each
 * namespace is read to its last page and handed to the task at once.
 *
 * With allowed namespaces, those are read. Otherwise a list of the metadata of the objects of the
 * task's class, which the storage answers cheaply, names the namespaces that have any, so only
 * those are read. When that list fails, the namespaces of the cluster are listed instead; without
 * permission to list them, or when there are none, the task reads pages of the whole cluster.
 *
 * A read that stops leaves the namespaces it did not read, which the next read reads; the
 * namespaces that could not be read leave an error on the task and are read again too, while the
 * tasks after it go on (failedNamespaces).
 */
export async function readPerNamespace(
  task: QueryTask,
  continueReading: { current: boolean },
  options: {
    counter?: ReadCounter;
    // after each namespace: how many of all were read
    onProgress?: (read: number, total: number) => void;
  } = {}
): Promise<void> {
  const counter = options.counter ?? noCounter;
  if (task.clusterWide) {
    await readListPage(task, counter);
    return;
  }
  if (task.pendingNamespaces === undefined) {
    let namespaces: string[] | undefined = task.allowedNamespaces;
    if (namespaces.length === 0) {
      try {
        namespaces = await namespacesWithObjects(
          task.cluster,
          task.objectClass,
          counter,
          () => continueReading.current
        );
        // stopped between pages: the next read lists them again
        if (namespaces === undefined) return;
      } catch (error) {
        counter.failure();
        console.warn(
          `Kubescape plugin: the ${task.objectClass.pluralName} of ${task.cluster} could not be listed without their spec, so the namespaces of the cluster are read`,
          error
        );
        namespaces = await clusterNamespaces(task.cluster, counter);
      }
      // without namespaces to read, the cluster is read at once
      if (namespaces === undefined) {
        task.clusterWide = true;
        await readListPage(task, counter);
        return;
      }
    }
    task.pendingNamespaces = [...namespaces];
    task.namespaceCount = namespaces.length;
  }

  const pending = task.pendingNamespaces;
  const total = task.namespaceCount ?? pending.length;
  const read = new Set<string>();
  const failed = new Map<string, string>();
  await runConcurrently(
    pending,
    namespaceConcurrency,
    async namespace => {
      try {
        const items = await readNamespacePages(
          task.cluster,
          task.objectClass,
          namespace,
          task.pageSize,
          () => counter.request(),
          () => continueReading.current
        );
        if (!items) return; // stopped between pages: read again by the next read
        for (const item of items) item.metadata.cluster = task.cluster;
        read.add(namespace);
        counter.items(items.length);
        task.handleData(task, items);
      } catch (error) {
        counter.failure();
        failed.set(namespace, errorMessage(error));
      }
      options.onProgress?.(total - pending.length + read.size, total);
    },
    () => continueReading.current
  );

  task.pendingNamespaces = pending.filter(namespace => !read.has(namespace));
  task.continuation = task.pendingNamespaces.length > 0 ? '' : undefined;
  task.failedNamespaces = failed.size > 0 ? [...failed.keys()] : undefined;
  const failures = [...failed].map(([namespace, message]) => `namespace ${namespace}: ${message}`);
  task.error =
    failures.length > 0
      ? failures.slice(0, namedFailures).join('; ') +
        (failures.length > namedFailures ? `; and ${failures.length - namedFailures} more` : '')
      : undefined;
}

/** The objects of a list, and why namespaces could not be read. */
export interface NamespacedList {
  items: any[];
  errors: string[];
}

/**
 * Lists the objects of a class in a cluster at once, in the given namespaces or, without them,
 * in all namespaces. A namespace that cannot be read does not take the others with it: the
 * errors say why; when none can be read, it rejects. A list without items counts as empty.
 */
export async function listInNamespaces(
  objectClass: KubeObjectClass,
  cluster: string | null,
  namespaces: string[]
): Promise<NamespacedList> {
  const group = objectClass.apiEndpoint.apiInfo[0].group;
  const version = objectClass.apiEndpoint.apiInfo[0].version;
  const pluralName = objectClass.pluralName;
  const requestOptions = cluster ? { cluster } : {};

  let items: any[];
  const errors: string[] = [];
  if (namespaces.length > 0) {
    const results = await Promise.allSettled(
      namespaces.map(namespace =>
        request(
          `/apis/${group}/${version}/namespaces/${encodeURIComponent(namespace)}/${pluralName}`,
          requestOptions
        )
      )
    );
    results.forEach((result, i) => {
      if (result.status === 'rejected') {
        errors.push(`namespace ${namespaces[i]}: ${errorMessage(result.reason)}`);
      }
    });
    if (errors.length === namespaces.length) throw (results[0] as PromiseRejectedResult).reason;
    items = results.flatMap(result =>
      result.status === 'fulfilled' ? result.value?.items ?? [] : []
    );
  } else {
    const list = await request(`/apis/${group}/${version}/${pluralName}`, requestOptions);
    items = list?.items ?? [];
  }
  for (const item of items) {
    item.metadata.cluster = cluster ?? '';
  }
  return { items, errors };
}

/**
 * Lists the objects of a namespaced class in a cluster a namespace at a time, several at once,
 * handing the items of each namespace to `onItems` as they arrive. The Kubescape storage builds
 * some lists, such as the generated network policies, from other objects within one request;
 * per namespace, it builds them in parallel. With allowed namespaces, those are read. Without
 * permission to list the namespaces, the cluster is listed at once.
 *
 * @returns Why namespaces could not be read; when none could, it throws.
 */
export async function listPerNamespace(
  objectClass: KubeObjectClass,
  cluster: string,
  allowedNamespaces: string[],
  onItems: (items: any[]) => void,
  continueReading: { current: boolean } = { current: true }
): Promise<string[]> {
  const group = objectClass.apiEndpoint.apiInfo[0].group;
  const version = objectClass.apiEndpoint.apiInfo[0].version;
  const pluralName = objectClass.pluralName;
  const withCluster = (items: any[]) => {
    for (const item of items) item.metadata.cluster = cluster;
    return items;
  };

  let namespaces = allowedNamespaces;
  if (namespaces.length === 0) {
    try {
      const list = await request('/api/v1/namespaces', { cluster });
      namespaces = (list.items ?? []).map((ns: { metadata: { name: string } }) => ns.metadata.name);
    } catch (error) {
      if (errorStatus(error) !== 403) throw error;
      const all = await request(`/apis/${group}/${version}/${pluralName}`, { cluster });
      onItems(withCluster(all.items ?? []));
      return [];
    }
  }

  const errors: string[] = [];
  await runConcurrently(
    namespaces,
    namespaceConcurrency,
    async namespace => {
      try {
        const list = await request(
          `/apis/${group}/${version}/namespaces/${encodeURIComponent(namespace)}/${pluralName}`,
          { cluster }
        );
        onItems(withCluster(list.items ?? []));
      } catch (error) {
        errors.push(`namespace ${namespace}: ${errorMessage(error)}`);
      }
    },
    () => continueReading.current
  );
  if (namespaces.length > 0 && errors.length === namespaces.length) throw new Error(errors[0]);
  return errors;
}
