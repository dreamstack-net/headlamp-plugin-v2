/*
  Checks what the listed exceptions cover, with the scans of the caches that the Compliance and
  Vulnerabilities pages share: scans those pages read already are not read again.
*/
import type { Dispatch, MutableRefObject, SetStateAction } from 'react';
import { getAllowedNamespaces } from '../common/clusterContext';
import { KubescapeConfig, kubescapeConfigStore } from '../common/config-store';
import { errorMessage } from '../common/errors';
import { configurationScanContext, readConfigurationScans } from '../compliance/Compliance';
import type { QueryTask } from '../query';
import type { WorkloadConfigurationScanSummary } from '../softwarecomposition/WorkloadConfigurationScanSummary';
import {
  readVulnerabilityScans,
  vulnerabilityContext,
  WorkloadScan,
} from '../vulnerabilities/Vulnerabilities';
import { fetchSecurityExceptions } from './apply-security-exceptions';
import { clusterCoverage, CoverageCheck, ExceptionCoverage, exceptionKey } from './coverage';
import type { ClusterException } from './exceptionYaml';

/**
 * The clusters whose tasks failed or were not read to the end, such as after Cancel, with why:
 * an exception must not look stale because its scans were not read.
 */
function unfinishedClusters(
  tasks: QueryTask[],
  clusters: Set<string>,
  what: string,
  found: Map<string, string>
) {
  for (const task of tasks) {
    if (!clusters.has(task.cluster) || found.has(task.cluster)) continue;
    if (task.error) found.set(task.cluster, `${what}: ${task.error}`);
    else if (task.continuation !== undefined) {
      found.set(task.cluster, `${what}: the read was stopped before the end`);
    }
  }
}

function groupByCluster<T>(items: T[], clusterOf: (item: T) => string): Map<string, T[]> {
  const groups = new Map<string, T[]>();
  for (const item of items) {
    const cluster = clusterOf(item);
    const group = groups.get(cluster);
    if (group) group.push(item);
    else groups.set(cluster, [item]);
  }
  return groups;
}

/**
 * Reads the scans of the clusters of the exceptions through the shared caches and finds what
 * each exception covers. Configuration scans are read for the clusters with exceptions of
 * controls or whole workloads, vulnerability scans for those with exceptions of CVEs. The
 * vulnerability cache drops the clusters it is not asked for, so the selected clusters it holds
 * are asked for too, which costs nothing.
 *
 * @param selectedClusters - The clusters selected in Headlamp.
 * @param continueReading - Cleared to stop reading; the clusters not read to the end are then
 *   reported as incomplete.
 */
export async function checkCoverage(
  exceptions: ClusterException[],
  selectedClusters: string[],
  continueReading: MutableRefObject<boolean>,
  setProgress: (message: string) => void
): Promise<CoverageCheck> {
  const postureClusters = new Set<string>();
  const vulnerabilityClusters = new Set<string>();
  for (const { cluster, exception } of exceptions) {
    const { posture, vulnerabilities } = exception.spec;
    if (posture?.length || !vulnerabilities?.length) postureClusters.add(cluster);
    if (vulnerabilities?.length) vulnerabilityClusters.add(cluster);
  }
  const cached = new Set(vulnerabilityContext.queryTasks.map(task => task.cluster));
  const vulnerabilityReads = [
    ...new Set([
      ...vulnerabilityClusters,
      ...selectedClusters.filter(cluster => cached.has(cluster)),
    ]),
  ];

  const config = (kubescapeConfigStore.get() ?? {}) as KubescapeConfig;
  const progress: Dispatch<SetStateAction<string>> = value =>
    setProgress(typeof value === 'function' ? value('') : value);
  const incomplete = new Map<string, string>();
  const failed = (clusters: Iterable<string>, what: string) => (error: unknown) => {
    for (const cluster of clusters) incomplete.set(cluster, `${what}: ${errorMessage(error)}`);
    return [];
  };

  const [configurationScans, vulnerabilityScans] = await Promise.all([
    postureClusters.size > 0
      ? readConfigurationScans([...postureClusters], config, continueReading, () => {}, progress, {
          keepOtherClusters: true,
        }).catch(failed(postureClusters, 'configuration scans'))
      : ([] as WorkloadConfigurationScanSummary[]),
    vulnerabilityClusters.size > 0
      ? readVulnerabilityScans(
          vulnerabilityReads,
          config,
          continueReading,
          () => {},
          progress
        ).catch(failed(vulnerabilityClusters, 'vulnerability scans'))
      : ([] as WorkloadScan[]),
  ]);
  unfinishedClusters(
    configurationScanContext.queryTasks,
    postureClusters,
    'configuration scans',
    incomplete
  );
  unfinishedClusters(
    vulnerabilityContext.queryTasks,
    vulnerabilityClusters,
    'vulnerability scans',
    incomplete
  );

  const configurationByCluster = groupByCluster(
    configurationScans,
    scan => scan.metadata.cluster ?? ''
  );
  const vulnerabilitiesByCluster = groupByCluster(vulnerabilityScans, scan => scan.cluster);
  const coverage = new Map<string, ExceptionCoverage>();
  setProgress('Matching the exceptions with the scans...');
  await Promise.all(
    [...new Set([...postureClusters, ...vulnerabilityClusters])].map(async cluster => {
      const configuration = configurationByCluster.get(cluster) ?? [];
      const vulnerabilities = vulnerabilitiesByCluster.get(cluster) ?? [];
      try {
        // the exceptions with what is needed to match them: the labels of the namespaces and
        // the workloads that object selectors select
        const data = await fetchSecurityExceptions(
          cluster,
          configuration,
          [...new Set(vulnerabilities.map(scan => scan.kind))],
          getAllowedNamespaces(cluster)
        );
        if (data.errors?.length && !incomplete.has(cluster)) {
          incomplete.set(cluster, `security exceptions: ${data.errors.join('; ')}`);
        }
        const found = clusterCoverage(data, {
          configuration: postureClusters.has(cluster) ? configuration : undefined,
          vulnerabilities: vulnerabilityClusters.has(cluster) ? vulnerabilities : undefined,
        });
        found.forEach((value, exception) => coverage.set(exceptionKey(cluster, exception), value));
      } catch (error) {
        incomplete.set(cluster, `security exceptions: ${errorMessage(error)}`);
      }
    })
  );
  return {
    coverage,
    incomplete: [...incomplete].map(([cluster, message]) => ({ cluster, message })),
  };
}
