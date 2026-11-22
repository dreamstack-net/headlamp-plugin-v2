/*
  Keeps the vulnerability reports between Headlamp sessions, in the plugin's IndexedDB database.

  A report is stored as the page keeps it (the slimmed ImageScan), keyed by cluster, namespace and
  name, with the uid and resourceVersion of the report it was read from. The storage raises the
  resourceVersion on every save, and lists the metadata of all reports cheaply, so a read lists
  that metadata, takes the reports whose uid and resourceVersion are unchanged from here, and asks
  the cluster only for the others (manifestReader.ts).

  A cluster is identified by the uid of its kube-system namespace, so two clusters with the same
  context name do not share reports; by its name when that namespace cannot be read. Reports not
  used for a week are pruned, and the store is bounded. Nothing here throws: without the
  database, reads ask the cluster for everything.
*/
import { request } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import type { KubescapeConfig } from '../common/config-store';
import { inTransaction, openPluginDatabase, pluginStores } from '../common/pluginDatabase';
import type { ImageScan } from './scanData';

/** The version of a stored report, as the metadata of the report names it. */
export interface ReportVersion {
  namespace: string;
  name: string;
  uid: string;
  resourceVersion: string;
}

// the form of the stored reports: raise it when toImageScan keeps other fields, so that reports
// stored by an older version of the plugin are read again
export const reportFormat = 1;

interface VersionRecord {
  key: string;
  format: number;
  uid: string;
  resourceVersion: string;
  // when a read last used or stored the report, in ms since the epoch
  seen: number;
  // the findings of the report, to bound the store
  size: number;
}

interface ReportRecord {
  key: string;
  scan: ImageScan;
}

const day = 24 * 60 * 60 * 1000;

export const reportCacheLimits = {
  // reports not used for this long are pruned
  maxAgeMs: 7 * day,
  maxReports: 5000,
  // the findings of all reports; a finding takes about a kilobyte
  maxFindings: 300_000,
  // a report used again is marked as seen when it was last marked this long ago
  seenIntervalMs: 60 * 60 * 1000,
  // pruning runs at most this often
  pruneIntervalMs: 60 * 60 * 1000,
};

/** Whether the reports are kept between sessions: on unless the setting is off. */
export function reportCacheEnabled(config: Partial<KubescapeConfig> | undefined | null): boolean {
  return config?.keepVulnerabilityReports !== false;
}

// the identity of each cluster, looked up once per session
const identities = new Map<string, Promise<string>>();

/** The uid of the kube-system namespace of the cluster, or its name when that cannot be read. */
export function clusterIdentity(cluster: string): Promise<string> {
  let identity = identities.get(cluster);
  if (!identity) {
    identity = request('/api/v1/namespaces/kube-system', { cluster }).then(
      (namespace: { metadata?: { uid?: string } }) =>
        namespace?.metadata?.uid ? `uid:${namespace.metadata.uid}` : `name:${cluster}`,
      () => `name:${cluster}`
    );
    identities.set(cluster, identity);
  }
  return identity;
}

function recordKey(clusterId: string, namespace: string, name: string): string {
  return JSON.stringify([clusterId, namespace, name]);
}

function findings(scan: ImageScan): number {
  return 1 + scan.matches.length + (scan.ignoredMatches?.length ?? 0);
}

// raised when the store is cleared, so that a read that began before writes nothing after it
let generation = 0;
// a write failed, for instance as the storage is full: the session writes no more
let writesFailed = false;
let lastPrune = -Infinity;

function warn(what: string, error: unknown) {
  console.warn(
    `Kubescape plugin: ${what}; the vulnerability reports are read from the cluster`,
    error
  );
}

/** The reports of one cluster that the database keeps. */
export interface ClusterReportCache {
  /** The stored reports of these versions, as the cluster now names them. */
  read(versions: ReportVersion[]): Promise<ImageScan[]>;
  /** Stores the reports, each read at its version. */
  write(entries: Array<{ version: ReportVersion; scan: ImageScan }>): Promise<void>;
}

/**
 * The stored reports of a cluster; undefined when the browser keeps no database, so that the
 * cluster is asked for every report.
 */
export async function openReportCache(
  cluster: string,
  now: () => number = Date.now
): Promise<ClusterReportCache | undefined> {
  const db = await openPluginDatabase();
  if (!db) return undefined;
  const clusterId = await clusterIdentity(cluster);
  const opened = generation;
  const stores = [pluginStores.reportVersions, pluginStores.reports];

  return {
    async read(versions) {
      if (versions.length === 0) return [];
      const found: Array<{ record: VersionRecord; scan: ImageScan }> = [];
      try {
        await inTransaction(db, stores, 'readonly', transaction => {
          const versionStore = transaction.objectStore(pluginStores.reportVersions);
          const reportStore = transaction.objectStore(pluginStores.reports);
          for (const version of versions) {
            const key = recordKey(clusterId, version.namespace, version.name);
            const lookup = versionStore.get(key);
            lookup.onsuccess = () => {
              const record = lookup.result as VersionRecord | undefined;
              if (
                !record ||
                record.format !== reportFormat ||
                record.uid !== version.uid ||
                record.resourceVersion !== version.resourceVersion
              ) {
                return;
              }
              const report = reportStore.get(key);
              report.onsuccess = () => {
                const stored = report.result as ReportRecord | undefined;
                if (stored?.scan) found.push({ record, scan: stored.scan });
              };
            };
          }
        });
      } catch (error) {
        warn('the stored vulnerability reports could not be read', error);
        return [];
      }

      // marks them as used, at most once in a while, so that pruning keeps them
      const time = now();
      const stale = found
        .map(({ record }) => record)
        .filter(record => time - record.seen > reportCacheLimits.seenIntervalMs);
      if (stale.length > 0 && !writesFailed && generation === opened) {
        await inTransaction(db, [pluginStores.reportVersions], 'readwrite', transaction => {
          const versionStore = transaction.objectStore(pluginStores.reportVersions);
          for (const record of stale) versionStore.put({ ...record, seen: time });
        }).catch(error =>
          warn('the use of stored vulnerability reports could not be noted', error)
        );
      }
      // the scans as this read names them: the cluster may have another name than when stored
      return found.map(({ scan }) => ({ ...scan, cluster }));
    },

    async write(entries) {
      if (entries.length === 0 || writesFailed || generation !== opened) return;
      const time = now();
      try {
        await inTransaction(db, stores, 'readwrite', transaction => {
          const versionStore = transaction.objectStore(pluginStores.reportVersions);
          const reportStore = transaction.objectStore(pluginStores.reports);
          for (const { version, scan } of entries) {
            const key = recordKey(clusterId, version.namespace, version.name);
            const record: VersionRecord = {
              key,
              format: reportFormat,
              uid: version.uid,
              resourceVersion: version.resourceVersion,
              seen: time,
              size: findings(scan),
            };
            versionStore.put(record);
            reportStore.put({ key, scan } satisfies ReportRecord);
          }
        });
      } catch (error) {
        writesFailed = true;
        warn('the vulnerability reports could not be stored', error);
      }
    },
  };
}

/**
 * Removes the reports not used for a week, and the least recently used ones while the store holds
 * more than its limits. It runs at most once an hour, unless forced.
 */
export async function pruneReportCache(
  options: { now?: number; force?: boolean } = {}
): Promise<void> {
  const now = options.now ?? Date.now();
  if (!options.force && now - lastPrune < reportCacheLimits.pruneIntervalMs) return;
  lastPrune = now;
  const db = await openPluginDatabase();
  if (!db) return;
  try {
    await inTransaction(
      db,
      [pluginStores.reportVersions, pluginStores.reports],
      'readwrite',
      transaction => {
        const versionStore = transaction.objectStore(pluginStores.reportVersions);
        const reportStore = transaction.objectStore(pluginStores.reports);
        const all = versionStore.getAll();
        all.onsuccess = () => {
          const records = (all.result as VersionRecord[]).sort((a, b) => b.seen - a.seen);
          let reports = 0;
          let size = 0;
          for (const record of records) {
            reports++;
            size += record.size;
            const keep =
              now - record.seen <= reportCacheLimits.maxAgeMs &&
              reports <= reportCacheLimits.maxReports &&
              size <= reportCacheLimits.maxFindings;
            if (keep) continue;
            versionStore.delete(record.key);
            reportStore.delete(record.key);
          }
        };
      }
    );
  } catch (error) {
    console.warn('Kubescape plugin: the stored vulnerability reports could not be pruned', error);
  }
}

/** Removes all stored reports, as when the setting is switched off. */
export async function clearReportCache(): Promise<void> {
  generation++;
  const db = await openPluginDatabase();
  if (!db) return;
  try {
    await inTransaction(
      db,
      [pluginStores.reportVersions, pluginStores.reports],
      'readwrite',
      transaction => {
        transaction.objectStore(pluginStores.reportVersions).clear();
        transaction.objectStore(pluginStores.reports).clear();
      }
    );
  } catch (error) {
    console.warn('Kubescape plugin: the stored vulnerability reports could not be removed', error);
  }
}

/** Forgets what the session knows about the store, for tests. */
export function resetReportCacheState() {
  identities.clear();
  writesFailed = false;
  lastPrune = -Infinity;
}
