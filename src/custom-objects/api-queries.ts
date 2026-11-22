import { request } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import { KubeConfigMap } from '@kinvolk/headlamp-plugin/lib/k8s/configMap';
import { getCluster } from '@kinvolk/headlamp-plugin/lib/Utils';
import { useEffect, useState } from 'react';
import { getAllowedNamespaces } from '../common/clusterContext';
import { errorMessage } from '../common/errors';
import {
  getItemFromSessionStorage,
  KubescapeSettings,
  setItemInSessionStorage,
} from '../common/sessionStorage';
import { customObjectLabel } from '../model';

/**
 * The ConfigMaps of the custom objects of a type, such as custom frameworks. The plugin writes
 * them in the Kubescape namespace, where a user who may change them can also list them; only
 * when that namespace is not known are they listed in all namespaces.
 */
export async function listCustomObjectConfigMaps(
  customObject: string,
  cluster: string | null = getCluster()
): Promise<KubeConfigMap[]> {
  const query = new URLSearchParams({ labelSelector: `${customObjectLabel}=${customObject}` });
  const options = cluster ? { cluster } : {};
  const { kubeScapeNamespace } = await getKubescapeNamespace(cluster);
  const path = kubeScapeNamespace
    ? `/api/v1/namespaces/${encodeURIComponent(kubeScapeNamespace)}/configmaps`
    : '/api/v1/configmaps';
  const response = await request(`${path}?${query.toString()}`, options);
  return response.items ?? [];
}

export async function checkUniqueness(name: string, uid: string | undefined, customObject: string) {
  const configMaps = await listCustomObjectConfigMaps(customObject);
  return !configMaps.some(
    configMap => configMap.metadata.uid !== uid && configMap.data?.name === name
  );
}

type KubescapeNamespaceResult = {
  kubeScapeNamespace: string | undefined;
  error: string | null;
};

/**
 * The pods that tell where Kubescape runs, asked in this order. The kubescape-operator chart
 * labels each pod with the chart name and its component. The operator runs in every install
 * unless its capability is disabled, whereas the kubescape component only runs with
 * configuration scanning. After that any pod of the chart will do, also when nameOverride
 * renamed the chart (app.kubernetes.io/part-of, since chart 1.27).
 */
export const kubescapePodSelectors = [
  'app.kubernetes.io/name=kubescape-operator,app.kubernetes.io/component=operator',
  'app.kubernetes.io/name=kubescape-operator',
  'app.kubernetes.io/part-of=kubescape',
];

// one lookup per cluster at a time, as a page asks for the namespace from several places at once
const lookups = new Map<string, Promise<KubescapeNamespaceResult>>();

function cachedNamespaces(): Record<string, string> {
  const cached = getItemFromSessionStorage<Record<string, string> | string>(
    KubescapeSettings.KubescapeNamespace
  );
  // Older plugin versions cached a single namespace for all clusters, which is ignored.
  return cached && typeof cached === 'object' ? cached : {};
}

/**
 * Return the namespace of the Kubescape operator in the given cluster.
 * The namespace is read from SessionStorage, where it is cached per cluster. If not found,
 * it is the namespace of the first pod found by {@link kubescapePodSelectors}.
 * @param cluster - The cluster to look in, the current cluster by default.
 * @returns An object with a namespace and an error.
 *          If the namespace is found, the error is null.
 *          If the namespace is not found, the namespace is undefined and the error says why.
 */
export function getKubescapeNamespace(
  cluster: string | null = getCluster()
): Promise<KubescapeNamespaceResult> {
  const cacheKey = cluster ?? '';
  const cached = cachedNamespaces()[cacheKey];
  if (cached) return Promise.resolve({ kubeScapeNamespace: cached, error: null });

  let lookup = lookups.get(cacheKey);
  if (!lookup) {
    lookup = lookUpKubescapeNamespace(cluster).finally(() => lookups.delete(cacheKey));
    lookups.set(cacheKey, lookup);
  }
  return lookup;
}

async function lookUpKubescapeNamespace(cluster: string | null): Promise<KubescapeNamespaceResult> {
  const options = cluster ? { cluster } : {};
  const firstPodNamespace = async (namespace: string | undefined, selector: string) => {
    const query = new URLSearchParams({ labelSelector: selector, limit: '1' });
    const path = namespace
      ? `/api/v1/namespaces/${encodeURIComponent(namespace)}/pods`
      : '/api/v1/pods';
    const response = await request(`${path}?${query.toString()}`, options);
    return response?.items?.[0]?.metadata?.namespace as string | undefined;
  };

  let namespace: string | undefined;
  try {
    namespace = await firstFound(kubescapePodSelectors, selector =>
      firstPodNamespace(undefined, selector)
    );
  } catch (error) {
    // a user who may not list pods in all namespaces looks in the namespaces they may see,
    // or in the namespace that the Kubescape chart installs to by default; the operator in one
    // of them wins over another pod of the chart in another
    const allowed = cluster ? getAllowedNamespaces(cluster) : [];
    const candidates = allowed.length > 0 ? allowed : ['kubescape'];
    namespace = await firstFound(kubescapePodSelectors, selector =>
      firstFound(candidates, candidate =>
        firstPodNamespace(candidate, selector).catch(() => undefined)
      )
    );
    if (!namespace) {
      return {
        kubeScapeNamespace: undefined,
        error: `Failed to look up the Kubescape operator namespace: ${errorMessage(error)}`,
      };
    }
  }

  if (!namespace) {
    return { kubeScapeNamespace: undefined, error: 'Kubescape operator namespace not found.' };
  }
  setItemInSessionStorage(KubescapeSettings.KubescapeNamespace, {
    ...cachedNamespaces(),
    [cluster ?? '']: namespace,
  });
  return { kubeScapeNamespace: namespace, error: null };
}

/** The first answer of the items in turn, without asking the items after it. */
async function firstFound<T>(
  items: T[],
  find: (item: T) => Promise<string | undefined>
): Promise<string | undefined> {
  for (const item of items) {
    const found = await find(item);
    if (found) return found;
  }
  return undefined;
}

/**
 * Hook around {@link getKubescapeNamespace}: the namespace in the given cluster, or by default in
 * the current cluster, which it follows when the user switches clusters.
 */
export function useKubescapeNamespace(
  cluster?: string | null
): KubescapeNamespaceResult & { loading: boolean } {
  const target = cluster === undefined ? getCluster() : cluster;
  const [result, setResult] = useState<
    KubescapeNamespaceResult & { loading: boolean; cluster: string | null }
  >({ kubeScapeNamespace: undefined, error: null, loading: true, cluster: target });

  useEffect(() => {
    let active = true;
    getKubescapeNamespace(target).then(namespaceResult => {
      if (active) setResult({ ...namespaceResult, loading: false, cluster: target });
    });
    return () => {
      active = false;
    };
  }, [target]);

  // the answer for the cluster shown before is not shown for this one
  if (result.cluster !== target) {
    return { kubeScapeNamespace: undefined, error: null, loading: true };
  }
  return {
    kubeScapeNamespace: result.kubeScapeNamespace,
    error: result.error,
    loading: result.loading,
  };
}
