/*
  The Kubescape results of the workloads in a namespace, read for the Headlamp resource lists
  and kept for a few minutes.
*/
import { useEffect, useState, useSyncExternalStore } from 'react';
import { getAllowedNamespaces } from '../common/clusterContext';
import { errorMessage, errorStatus } from '../common/errors';
import { readClusterSetup, scannersApplyExceptions } from '../common/kubescapeSetup';
import {
  fetchSecurityExceptions,
  SecurityExceptionData,
  workloadExceptionMarks,
} from '../exceptions/apply-security-exceptions';
import { vulnerabilityManifestSummaryClass, workloadConfigurationScanSummaryClass } from '../model';
import { paginatedListQuery } from '../query';
import type { WorkloadRef } from './scannedWorkload';

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface ContainerVulnerabilities extends SeverityCounts {
  container: string;
  // name of the VulnerabilityManifestSummary
  name: string;
}

export interface WorkloadVulnerabilities extends SeverityCounts {
  containers: ContainerVulnerabilities[];
}

export interface WorkloadControls extends SeverityCounts {
  // name of the WorkloadConfigurationScanSummary
  name: string;
}

export interface WorkloadSummaries {
  vulnerabilities: Map<string, WorkloadVulnerabilities>;
  controls: Map<string, WorkloadControls>;
}

const severities = ['critical', 'high', 'medium', 'low'] as const;

export function workloadKey(namespace: string, kind: string, name: string) {
  return `${namespace}/${kind}/${name}`.toLowerCase();
}

function keyOfSummary(summary: any): string | undefined {
  const labels = summary.metadata?.labels ?? {};
  const kind = labels['kubescape.io/workload-kind'];
  const name = labels['kubescape.io/workload-name'];
  const namespace = labels['kubescape.io/workload-namespace'] ?? summary.metadata?.namespace;
  return kind && name && namespace ? workloadKey(namespace, kind, name) : undefined;
}

function noCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0 };
}

/**
 * The failed controls of a configuration scan summary per severity. The counts of the storage
 * (spec.severities) leave out the controls the scanners excepted; where the plugin applies the
 * exceptions itself, as the scanners do not, the controls of the summary are counted without
 * those the exceptions exclude in every framework, as the counts are of all controls.
 */
export function failedControlCounts(
  summary: any,
  exceptions?: SecurityExceptionData
): SeverityCounts {
  const controls = summary?.spec?.controls;
  if (!exceptions || !controls || !summary.metadata?.labels) {
    const severities = summary?.spec?.severities ?? {};
    return {
      critical: severities.critical ?? 0,
      high: severities.high ?? 0,
      medium: severities.medium ?? 0,
      low: severities.low ?? 0,
    };
  }
  const counts = noCounts();
  const marks = workloadExceptionMarks(summary, exceptions);
  if (marks.workload) return counts;
  for (const control of Object.values<any>(controls)) {
    if (control?.status?.status !== 'failed' || marks.everywhere.has(control.controlID)) continue;
    const severity = control.severity?.severity?.toLowerCase();
    if (severity in counts) counts[severity as keyof SeverityCounts]++;
  }
  return counts;
}

/**
 * Totals the summaries per workload: CVEs over the containers, and failed controls, without
 * the controls that the given exceptions exclude.
 */
export function summarizeWorkloads(
  vulnerabilitySummaries: any[],
  configurationSummaries: any[],
  exceptions?: SecurityExceptionData
): WorkloadSummaries {
  const vulnerabilities = new Map<string, WorkloadVulnerabilities>();
  for (const summary of vulnerabilitySummaries) {
    const key = keyOfSummary(summary);
    if (!key) continue;
    const workload = vulnerabilities.get(key) ?? {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      containers: [],
    };
    const container: ContainerVulnerabilities = {
      container: summary.metadata.labels['kubescape.io/workload-container-name'] ?? '',
      name: summary.metadata.name,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };
    for (const severity of severities) {
      container[severity] = summary.spec?.severities?.[severity]?.all ?? 0;
      workload[severity] += container[severity];
    }
    workload.containers.push(container);
    vulnerabilities.set(key, workload);
  }

  const controls = new Map<string, WorkloadControls>();
  for (const summary of configurationSummaries) {
    const key = keyOfSummary(summary);
    if (!key) continue;
    controls.set(key, { name: summary.metadata.name, ...failedControlCounts(summary, exceptions) });
  }

  return { vulnerabilities, controls };
}

/** The summary of the first candidate (scannedWorkloadCandidates) that Kubescape scanned. */
export function findWorkloadSummary<T>(
  summaries: Map<string, T>,
  namespace: string,
  candidates: WorkloadRef[]
): T | undefined {
  for (const candidate of candidates) {
    const summary = summaries.get(workloadKey(namespace, candidate.kind, candidate.name));
    if (summary) return summary;
  }
  return undefined;
}

// ── Cache ────────────────────────────────────────────────────────────────────

const maxAge = 5 * 60 * 1000;
// a namespace whose summaries could not be read is read again sooner
const retryAfter = 30 * 1000;
// namespaces read at the same time; a page of pods can show many namespaces
const maxParallel = 4;
const pageSize = 500;

interface Entry {
  summaries?: WorkloadSummaries;
  // why the summaries of a kind could not be read; the rows then keep what was read before
  errors?: Partial<Record<keyof WorkloadSummaries, string>>;
  // why the exceptions could not be read, so that the failed controls may include excepted ones
  exceptionsError?: string;
  loadedAt: number;
  loading: boolean;
}

const entries = new Map<string, Entry>();

/** The exceptions of a cluster that the plugin applies to the failed controls. */
export interface ClusterExceptions {
  // undefined where the scanners apply the exceptions, as the counts of the storage are right
  data?: SecurityExceptionData;
  // what could not be read; the counts may then include controls that exceptions cover
  error?: string;
}

// The kinds whose workloads the object selectors of exceptions are matched against
const selectableKinds = [
  'Deployment',
  'StatefulSet',
  'DaemonSet',
  'ReplicaSet',
  'Job',
  'CronJob',
  'Pod',
];
const exceptionsByCluster = new Map<string, { read: Promise<ClusterExceptions>; readAt: number }>();

async function lookUpClusterExceptions(cluster: string): Promise<ClusterExceptions> {
  try {
    if (scannersApplyExceptions(await readClusterSetup(cluster))) return {};
    const data = await fetchSecurityExceptions(
      cluster,
      [],
      selectableKinds,
      getAllowedNamespaces(cluster)
    );
    return { data, error: data.errors?.join('; ') };
  } catch (error) {
    return { error: errorMessage(error) };
  }
}

/**
 * The exceptions that the plugin applies to the failed controls of a cluster, read once for all
 * its namespaces and kept as long as the summaries; none where the scanners apply them.
 */
export function readClusterExceptions(
  cluster: string,
  now: number = Date.now()
): Promise<ClusterExceptions> {
  const cached = exceptionsByCluster.get(cluster);
  if (cached && now - cached.readAt < maxAge) return cached.read;
  const entry = { read: lookUpClusterExceptions(cluster), readAt: now };
  exceptionsByCluster.set(cluster, entry);
  // exceptions that could not be read are read again sooner
  entry.read.then(result => {
    if (result.error) entry.readAt = now - maxAge + retryAfter;
  });
  return entry.read;
}
const listeners = new Set<() => void>();
let version = 0;
const queue: Array<() => Promise<void>> = [];
let running = 0;

function changed() {
  version++;
  listeners.forEach(listener => listener());
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

function keyOf(cluster: string, namespace: string) {
  return `${cluster}\u0000${namespace}`;
}

function runQueued() {
  while (running < maxParallel && queue.length > 0) {
    const read = queue.shift()!;
    running++;
    read().finally(() => {
      running--;
      runQueued();
    });
  }
}

// The storage only returns the spec, which holds the counts, of a fullSpec list
async function listSummaries(cluster: string, namespace: string, objectClass: any) {
  const { items } = await paginatedListQuery(cluster, objectClass, '', pageSize, [namespace]);
  return items;
}

/**
 * Reads the summaries of a namespace, unless they were read recently. The lists only read the
 * namespaces of the rows they show, which on a big cluster is a fraction of all summaries.
 * A namespace without Kubescape results gets empty summaries, so its rows stay empty.
 */
export function loadWorkloadSummaries(
  cluster: string,
  namespace: string,
  now: number = Date.now()
) {
  const key = keyOf(cluster, namespace);
  const entry = entries.get(key);
  if (entry && (entry.loading || now - entry.loadedAt < maxAge)) return;

  entries.set(key, {
    summaries: entry?.summaries,
    errors: entry?.errors,
    loadedAt: entry?.loadedAt ?? 0,
    loading: true,
  });
  const readNamespace = async () => {
    const exceptionsRead = readClusterExceptions(cluster, now);
    const [vulnerabilities, configurations] = await Promise.allSettled([
      listSummaries(cluster, namespace, vulnerabilityManifestSummaryClass),
      listSummaries(cluster, namespace, workloadConfigurationScanSummaryClass),
    ]);
    const exceptions = await exceptionsRead;
    const read = summarizeWorkloads(
      vulnerabilities.status === 'fulfilled' ? vulnerabilities.value : [],
      configurations.status === 'fulfilled' ? configurations.value : [],
      exceptions.data
    );
    // a cluster without the Kubescape storage has no results: not found is not an error
    const message = (result: PromiseSettledResult<unknown>) =>
      result.status === 'rejected' && errorStatus(result.reason) !== 404
        ? errorMessage(result.reason)
        : undefined;
    const errors = {
      vulnerabilities: message(vulnerabilities),
      controls: message(configurations),
    };
    const previous = entries.get(key)?.summaries;
    entries.set(key, {
      // a list that could not be read keeps the results read before, rather than showing the
      // workloads as not scanned
      summaries: {
        vulnerabilities:
          errors.vulnerabilities && previous ? previous.vulnerabilities : read.vulnerabilities,
        controls: errors.controls && previous ? previous.controls : read.controls,
      },
      errors: errors.vulnerabilities || errors.controls ? errors : undefined,
      exceptionsError: exceptions.error,
      loadedAt:
        errors.vulnerabilities || errors.controls || exceptions.error
          ? Date.now() - maxAge + retryAfter
          : Date.now(),
      loading: false,
    });
    changed();
  };
  // a read that fails as a whole, such as on a summary that cannot be counted, does not leave
  // the namespace loading for the rest of the session: it is read again like a list that failed
  queue.push(() =>
    readNamespace().catch((error: unknown) => {
      const message = errorMessage(error);
      entries.set(key, {
        summaries: entries.get(key)?.summaries,
        errors: { vulnerabilities: message, controls: message },
        loadedAt: Date.now() - maxAge + retryAfter,
        loading: false,
      });
      changed();
    })
  );
  runQueued();
}

/** Why the summaries of a kind of a namespace could not be read, if they could not. */
export function workloadSummariesError(
  cluster: string,
  namespace: string,
  which: keyof WorkloadSummaries
): string | undefined {
  return entries.get(keyOf(cluster, namespace))?.errors?.[which];
}

/** Why the exceptions of the namespace's cluster could not be read, if they could not. */
export function workloadExceptionsError(cluster: string, namespace: string): string | undefined {
  return entries.get(keyOf(cluster, namespace))?.exceptionsError;
}

/** The summaries of a namespace read so far, without reading them. */
export function cachedWorkloadSummaries(
  cluster: string,
  namespace: string
): WorkloadSummaries | undefined {
  return entries.get(keyOf(cluster, namespace))?.summaries;
}

/**
 * The summaries of a namespace, read when needed (unless not enabled); undefined until they are
 * read.
 */
export function useWorkloadSummaries(
  cluster: string,
  namespace: string,
  enabled: boolean = true
): WorkloadSummaries | undefined {
  useSyncExternalStore(subscribe, () => version);
  useEffect(() => {
    if (enabled) loadWorkloadSummaries(cluster, namespace);
  }, [cluster, namespace, enabled]);
  return cachedWorkloadSummaries(cluster, namespace);
}

/**
 * The failed controls of the workloads of a namespace, with the exceptions that the plugin
 * applies; undefined until they are read, or when they could not be read (error). Only read
 * when enabled, such as for a namespace that Kubescape scanned.
 */
export function useNamespaceFailedControls(
  cluster: string,
  namespace: string,
  enabled: boolean = true
): { counts?: SeverityCounts; error?: string; exceptionsError?: string } {
  const summaries = useWorkloadSummaries(cluster, namespace, enabled);
  const error = workloadSummariesError(cluster, namespace, 'controls');
  const exceptionsError = workloadExceptionsError(cluster, namespace);
  if (!summaries || error) return { error, exceptionsError };
  const counts = noCounts();
  for (const workload of summaries.controls.values()) {
    for (const severity of severities) counts[severity] += workload[severity];
  }
  return { counts, exceptionsError };
}

/**
 * The failed controls of a configuration scan summary, with the exceptions that the plugin
 * applies; undefined until the exceptions of the cluster are read.
 */
export function useFailedControlCounts(
  cluster: string,
  summary: any
): { counts?: SeverityCounts; exceptionsError?: string } {
  const [result, setResult] = useState<{ counts?: SeverityCounts; exceptionsError?: string }>({});
  useEffect(() => {
    if (!summary) return;
    let active = true;
    readClusterExceptions(cluster).then(exceptions => {
      if (!active) return;
      setResult({
        counts: failedControlCounts(summary, exceptions.data),
        exceptionsError: exceptions.error,
      });
    });
    return () => {
      active = false;
    };
  }, [cluster, summary]);
  return result;
}

/** Forgets the summaries and exceptions, for tests. */
export function clearWorkloadSummaries() {
  entries.clear();
  exceptionsByCluster.clear();
  changed();
}
