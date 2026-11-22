/*
  Reads the vulnerability reports that the summaries of workloads refer to, a few at a time.

  The Kubescape storage reads and decodes every object of a list one after the other in one
  request, and a list of all reports also holds those of images that no longer run. Reading each
  referenced report on its own lets the storage read several at once (it locks per object), and
  leaves out the reports no workload uses.

  With the reports kept between sessions (reportCache.ts), the metadata of the reports is listed
  first, which the storage answers without reading the reports, and only the reports whose uid or
  resourceVersion changed since they were stored are read.
*/
import { request } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import { runConcurrently } from '../common/concurrency';
import { errorMessage, errorStatus } from '../common/errors';
import { noCounter, PhaseRun, ReadCounter } from '../common/readStatistics';
import { getKubescapeNamespace } from '../custom-objects/api-queries';
import { VulnerabilityManifest } from '../softwarecomposition/VulnerabilityManifest';
import { ClusterReportCache, openReportCache, ReportVersion } from './reportCache';
import { getManifestNamespace, ImageScan, toImageScan } from './scanData';

export type ManifestReference = { name: string; namespace?: string };

// the browser opens six connections to a host, so more would only wait
export const manifestConcurrency = 6;

const api = '/apis/spdx.softwarecomposition.kubescape.io/v1beta1';

const manifestPath = (namespace: string, name: string) =>
  `${api}/namespaces/${encodeURIComponent(namespace)}/vulnerabilitymanifests/${encodeURIComponent(
    name
  )}`;

export interface ManifestReadResult {
  // the references that exist neither where they point nor in the operator namespace
  missing: ManifestReference[];
  // the references that could not be read, which a later read tries again, and why
  failed: ManifestReference[];
  errors: string[];
  // whether reading stopped before all references were read
  stopped: boolean;
}

/**
 * Reads the reports of the references in a cluster, at most `concurrency` at a time, handing
 * each report to `onManifest` as it arrives. A report that is not where its reference points is
 * looked up in the operator namespace, where the storage may keep all reports. Reading stops
 * starting new requests when `continueReading` turns false.
 */
export async function readManifests(
  cluster: string,
  references: ManifestReference[],
  options: {
    continueReading: { current: boolean };
    onManifest: (manifest: VulnerabilityManifest) => void;
    onProgress?: (read: number, total: number) => void;
    // called for each request, to count them
    onRequest?: () => void;
    concurrency?: number;
  }
): Promise<ManifestReadResult> {
  const { continueReading, onManifest, onProgress } = options;
  const get = (namespace: string, name: string) => {
    options.onRequest?.();
    return request(manifestPath(namespace, name), { cluster });
  };
  const result: ManifestReadResult = { missing: [], failed: [], errors: [], stopped: false };
  // the operator namespace, or the default one while it could not be looked up
  let operatorNamespace: Promise<{ namespace: string; known: boolean }> | undefined;
  const operatorNamespaceOf = () =>
    (operatorNamespace ??= getKubescapeNamespace(cluster).then(
      found => ({
        namespace: found.kubeScapeNamespace || getManifestNamespace({}),
        known: !!found.kubeScapeNamespace,
      }),
      () => ({ namespace: getManifestNamespace({}), known: false })
    ));

  const read = async (reference: ManifestReference) => {
    const referenced = getManifestNamespace(reference);
    try {
      return await get(referenced, reference.name);
    } catch (error) {
      if (errorStatus(error) !== 404) throw error;
      const fallback = await operatorNamespaceOf();
      if (fallback.namespace !== referenced) {
        try {
          return await get(fallback.namespace, reference.name);
        } catch (fallbackError) {
          if (errorStatus(fallbackError) !== 404) throw fallbackError;
        }
      }
      // only a report that is in neither namespace of a known operator is missing; otherwise
      // a later read tries again
      if (fallback.known) return null;
      throw new Error(
        `not found in namespace ${referenced} or ${fallback.namespace}, and the namespace of Kubescape could not be looked up`
      );
    }
  };

  let done = 0;
  result.stopped = await runConcurrently(
    references,
    options.concurrency ?? manifestConcurrency,
    async reference => {
      try {
        const manifest: VulnerabilityManifest | null = await read(reference);
        if (manifest) {
          manifest.metadata.cluster = cluster;
          onManifest(manifest);
        } else {
          result.missing.push(reference);
        }
      } catch (error) {
        result.failed.push(reference);
        result.errors.push(
          `${getManifestNamespace(reference)}/${reference.name}: ${errorMessage(error)}`
        );
      }
      onProgress?.(++done, references.length);
    },
    () => continueReading.current
  );
  return result;
}

// the metadata of the reports listed at a time; the storage answers it from its index
const versionPageSize = 1000;

/**
 * The versions of the reports of a cluster, from a list of their metadata without fullSpec, which
 * the storage answers without reading the reports. With namespaces, those are listed; a
 * namespace that cannot be listed is left out, and when none can be, it rejects.
 */
export async function listReportVersions(
  cluster: string,
  namespaces: string[],
  counter: ReadCounter = noCounter
): Promise<ReportVersion[]> {
  const listAll = async (path: string) => {
    const versions: ReportVersion[] = [];
    let next = '';
    do {
      const query = `limit=${versionPageSize}${
        next ? `&continue=${encodeURIComponent(next)}` : ''
      }`;
      counter.request();
      const list = await request(`${path}?${query}`, { cluster });
      for (const item of list?.items ?? []) {
        const metadata = item?.metadata;
        if (!metadata?.name || !metadata.namespace) continue;
        versions.push({
          namespace: metadata.namespace,
          name: metadata.name,
          uid: metadata.uid ?? '',
          resourceVersion: metadata.resourceVersion ?? '',
        });
      }
      next = list?.metadata?.continue || '';
    } while (next);
    return versions;
  };

  if (namespaces.length === 0) return listAll(`${api}/vulnerabilitymanifests`);
  const versions: ReportVersion[] = [];
  const errors: unknown[] = [];
  await runConcurrently(namespaces, manifestConcurrency, async namespace => {
    try {
      versions.push(
        ...(await listAll(
          `${api}/namespaces/${encodeURIComponent(namespace)}/vulnerabilitymanifests`
        ))
      );
    } catch (error) {
      errors.push(error);
    }
  });
  if (errors.length === namespaces.length) throw errors[0];
  return versions;
}

/** The stored reports of a cluster, and the versions of its reports by name. */
export interface StoredReports {
  cache: ClusterReportCache;
  versions: Map<string, ReportVersion[]>;
}

/**
 * The stored reports of a cluster with the versions of its reports, to read only the reports that
 * changed; undefined when the browser keeps no reports or their metadata cannot be listed, so
 * that every report is read. With allowed namespaces, those and the operator namespace, where
 * the storage keeps the reports, are listed.
 */
export async function openStoredReports(
  cluster: string,
  allowedNamespaces: string[],
  counter: ReadCounter = noCounter
): Promise<StoredReports | undefined> {
  const cache = await openReportCache(cluster);
  if (!cache) return undefined;
  let namespaces = allowedNamespaces;
  if (namespaces.length > 0) {
    const operator = await getKubescapeNamespace(cluster).then(
      found => found.kubeScapeNamespace,
      () => undefined
    );
    if (operator && !namespaces.includes(operator)) namespaces = [...namespaces, operator];
  }
  try {
    const listed = await listReportVersions(cluster, namespaces, counter);
    counter.items(listed.length);
    const versions = new Map<string, ReportVersion[]>();
    for (const version of listed) {
      versions.set(version.name, [...(versions.get(version.name) ?? []), version]);
    }
    return { cache, versions };
  } catch (error) {
    counter.failure();
    console.warn(
      `Kubescape plugin: the vulnerability reports of ${cluster} could not be listed, so all are read`,
      error
    );
    return undefined;
  }
}

/**
 * The listed version of the report a reference names: in the referenced namespace, or the only
 * report of that name, as the storage may keep the reports in the operator namespace. Only a
 * version with a uid and a resourceVersion can tell a stored report from a changed one.
 */
export function referencedVersion(
  versions: Map<string, ReportVersion[]>,
  reference: ManifestReference
): ReportVersion | undefined {
  const candidates = versions.get(reference.name) ?? [];
  const found =
    candidates.find(version => version.namespace === getManifestNamespace(reference)) ??
    (candidates.length === 1 ? candidates[0] : undefined);
  return found?.uid && found.resourceVersion ? found : undefined;
}

// the stored reports read at a time, and the reports stored at a time
const storedBatch = 25;

/**
 * Reads the reports of the references, handing each to `onImageScan` as the page keeps it. With
 * stored reports, the ones whose version did not change come from the browser storage, and the
 * others are read from the cluster and stored; without them, all are read from the cluster.
 */
export async function readReports(
  cluster: string,
  references: ManifestReference[],
  options: {
    continueReading: { current: boolean };
    onImageScan: (scan: ImageScan) => void;
    onProgress?: (read: number, total: number) => void;
    stored?: StoredReports;
    // starts the statistics of a phase of the read
    phase?: (name: 'cached reports' | 'reports') => PhaseRun;
  }
): Promise<ManifestReadResult> {
  const { continueReading, onImageScan, onProgress, stored } = options;
  const startPhase = (name: 'cached reports' | 'reports'): PhaseRun =>
    options.phase?.(name) ?? { ...noCounter, end: () => {} };
  const total = references.length;
  let toRead = references;
  let fromStorage = 0;
  onProgress?.(0, total);
  // the version that each reference resolved to, by name
  const versionOf = new Map<string, ReportVersion>();

  if (stored) {
    for (const reference of references) {
      const version = referencedVersion(stored.versions, reference);
      if (version) versionOf.set(reference.name, version);
    }
    const resolved = [...versionOf.values()];
    const found = new Set<string>();
    const phase = resolved.length > 0 ? startPhase('cached reports') : undefined;
    try {
      for (let i = 0; i < resolved.length; i += storedBatch) {
        if (!continueReading.current) {
          return { missing: [], failed: [], errors: [], stopped: true };
        }
        const scans = await stored.cache.read(resolved.slice(i, i + storedBatch));
        phase?.items(scans.length);
        phase?.fromCache(scans.length);
        for (const scan of scans) {
          found.add(scan.manifestName);
          onImageScan(scan);
        }
        fromStorage += scans.length;
        onProgress?.(fromStorage, total);
      }
    } finally {
      phase?.end();
    }
    // the others are read where the metadata says they are
    toRead = references
      .filter(reference => !found.has(reference.name))
      .map(reference => {
        const version = versionOf.get(reference.name);
        return version ? { name: reference.name, namespace: version.namespace } : reference;
      });
  }

  if (toRead.length === 0) return { missing: [], failed: [], errors: [], stopped: false };
  const phase = startPhase('reports');
  const toStore: Array<{ version: ReportVersion; scan: ImageScan }> = [];
  const writes: Promise<void>[] = [];
  const store = () => {
    if (stored && toStore.length > 0) writes.push(stored.cache.write(toStore.splice(0)));
  };
  try {
    const result = await readManifests(cluster, toRead, {
      continueReading,
      onRequest: () => phase.request(),
      onProgress: read => onProgress?.(fromStorage + read, total),
      onManifest: manifest => {
        const scan = toImageScan(manifest);
        phase.items(1);
        onImageScan(scan);
        const version = versionOf.get(scan.manifestName);
        if (version && version.namespace === scan.namespace) {
          toStore.push({ version, scan });
          if (toStore.length >= storedBatch) store();
        }
      },
    });
    phase.failure(result.failed.length);
    store();
    // writing never fails: a write that cannot store leaves the reports to be read next time
    await Promise.all(writes);
    return result;
  } finally {
    phase.end();
  }
}
