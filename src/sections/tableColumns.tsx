/*
  Kubescape columns in the Headlamp resource lists of workloads and pods: the critical and
  high CVEs and failed controls of each workload.
*/
import { Icon } from '@iconify/react';
import { getCluster } from '@kinvolk/headlamp-plugin/lib/Utils';
import { Box, Stack, Tooltip } from '@mui/material';
import { kubescapeConfigStore } from '../common/config-store';
import { SeverityCountBox } from '../common/SeverityCountBox';
import { RoutingName } from '../index';
import { scannedWorkloadCandidates } from './scannedWorkload';
import {
  findWorkloadSummary,
  SeverityCounts,
  useWorkloadSummaries,
  WorkloadControls,
  workloadExceptionsError,
  WorkloadSummaries,
  workloadSummariesError,
  WorkloadVulnerabilities,
} from './workloadSummaries';

// The ids of the Headlamp tables that get the columns
export const kubescapeColumnTables = [
  'headlamp-deployments',
  'headlamp-statefulsets',
  'headlamp-daemonsets',
  'headlamp-jobs',
  'headlamp-cronjobs',
  'headlamp-pods',
];

type Which = keyof WorkloadSummaries;

interface ListedItem {
  kind: string;
  cluster?: string;
  metadata: { name: string; namespace: string; labels?: Record<string, string> };
}

function clusterOf(item: ListedItem): string {
  return item.cluster || getCluster() || '';
}

function lookUp(summaries: WorkloadSummaries | undefined, which: Which, item: ListedItem) {
  if (!summaries) return undefined;
  return findWorkloadSummary<SeverityCounts>(
    summaries[which],
    item.metadata.namespace,
    scannedWorkloadCandidates(item)
  );
}

// Most critical first, then most high; counts without results last
function compareCounts(a: SeverityCounts | undefined, b: SeverityCounts | undefined) {
  if (!a || !b) return Number(!a) - Number(!b);
  return b.critical - a.critical || b.high - a.high || b.medium - a.medium;
}

function breakdown(counts: SeverityCounts) {
  return `${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low`;
}

function vulnerabilityTooltip(summary: WorkloadVulnerabilities) {
  return (
    <>
      <div>CVEs: {breakdown(summary)}</div>
      {summary.containers.length > 1 &&
        summary.containers.map(container => (
          <div key={container.name}>
            {container.container}: {breakdown(container)}
          </div>
        ))}
    </>
  );
}

function KubescapeCell(props: Readonly<{ item: ListedItem; which: Which }>) {
  const { item, which } = props;
  const cluster = clusterOf(item);
  const namespace = item.metadata.namespace;
  const summary = lookUp(useWorkloadSummaries(cluster, namespace), which, item);
  const error = workloadSummariesError(cluster, namespace, which);
  if (!summary) {
    // a workload whose results could not be read is not shown as one that was not scanned
    return error ? (
      <Tooltip title={`Unable to read the Kubescape results: ${error}`}>
        <Box component="span" sx={{ display: 'inline-flex', color: 'warning.main' }}>
          <Icon icon="mdi:alert-circle-outline" width={18} aria-label="Unable to read" />
        </Box>
      </Tooltip>
    ) : null;
  }

  let tooltip;
  let link;
  if (which === 'vulnerabilities') {
    const vulnerabilities = summary as WorkloadVulnerabilities;
    // the container with the most serious CVEs
    const container = [...vulnerabilities.containers].sort(compareCounts)[0];
    tooltip = vulnerabilityTooltip(vulnerabilities);
    link = {
      routeName: RoutingName.KubescapeVulnerabilityDetails,
      params: { namespace, name: container.name },
      activeCluster: cluster,
    };
  } else {
    const exceptionsError = workloadExceptionsError(cluster, namespace);
    tooltip = (
      <>
        <div>Failed controls: {breakdown(summary)}</div>
        {exceptionsError && (
          <div>
            Unable to read the security exceptions: {exceptionsError}. Controls that exceptions
            cover may be counted as failed.
          </div>
        )}
      </>
    );
    // no activeCluster: the route also names the cluster of the scan in its path, and Headlamp's
    // Link would fill in all selected clusters there (cluster-b+cluster-a)
    link = {
      routeName: RoutingName.KubescapeWorkloadConfigurationScanDetails,
      params: { cluster, namespace, name: (summary as WorkloadControls).name },
    };
  }

  return (
    <Stack direction="row" spacing={0.5}>
      {(['Critical', 'High'] as const).map(severity => (
        <SeverityCountBox
          key={severity}
          severity={severity}
          count={summary[severity === 'Critical' ? 'critical' : 'high']}
          tooltip={<Box>{tooltip}</Box>}
          link={link}
        />
      ))}
    </Stack>
  );
}

function column(which: Which, label: string) {
  return {
    id: `kubescape-${which}`,
    label,
    gridTemplate: 'min-content',
    // Neither sorted nor searched: Headlamp's table sorts its rows, and takes the values it
    // searches, once per change of its data, while the counts are read later, a namespace at a
    // time. Rows whose counts arrived after a sort would stay where it put them, as rows without
    // results, until the list changes. The Vulnerabilities and Compliance pages sort by them.
    getValue: () => '',
    sort: false,
    render: (item: ListedItem) => <KubescapeCell item={item} which={which} />,
  };
}

/** Adds the Kubescape columns to the workload and pod lists, before their Age column. */
export function addKubescapeColumns(args: { id: string; columns: any[] }) {
  const { id, columns } = args;
  if (!kubescapeColumnTables.includes(id)) return columns;
  if (kubescapeConfigStore.get()?.tableColumns === false) return columns;
  if (columns.some(existing => existing?.id === 'kubescape-vulnerabilities')) return columns;

  const age = columns.findIndex(existing => existing === 'age' || existing?.id === 'age');
  const at = age === -1 ? columns.length : age;
  return [
    ...columns.slice(0, at),
    column('vulnerabilities', 'CVEs'),
    column('controls', 'Failed controls'),
    ...columns.slice(at),
  ];
}
