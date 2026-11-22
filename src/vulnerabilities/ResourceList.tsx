/*
  Show workload configuration scans. This view is part of the main Vulnerabilities page.
*/
import { Icon } from '@iconify/react';
import { Link, SectionBox } from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { Box, IconButton, Tooltip } from '@mui/material';
import { useMemo, useState } from 'react';
import { makeNamespaceLink } from '../common/Namespace';
import { severityColors, SeverityCountStack } from '../common/SeverityCountBox';
import HeadlampTable from '../common/Table';
import { GuidedVulnerabilityExceptionForm } from '../exceptions/GuidedVulnerabilityExceptionForm';
import {
  summarizeWorkloadExceptions,
  workloadCveExceptions,
  WorkloadExceptions,
} from '../exceptions/vulnerabilityExceptions';
import { RoutingName, useHLSelectedClusters } from '../index';
import {
  AcceptedChip,
  acceptedChipValue,
  ExceptionReadErrors,
  useSecurityExceptions,
} from './exceptionChips';
import { findingKey, relevantFindingKeys } from './relevance';
import { getWorkloadScanKey } from './scanData';
import { WorkloadScan } from './Vulnerabilities';

export default function WorkloadScanListView(
  props: Readonly<{
    workloadScans: WorkloadScan[] | null;
  }>
) {
  const { workloadScans } = props;
  const clusters = useHLSelectedClusters();
  const kinds = useMemo(() => (workloadScans ?? []).map(w => w.kind), [workloadScans]);
  const { exceptions, errors: exceptionErrors, reload } = useSecurityExceptions(clusters, kinds);
  const [accepting, setAccepting] = useState<{ workloadScan: WorkloadScan; cveIds: string[] }>();

  // what the exceptions say about the CVEs of each workload
  const exceptionSummaries = useMemo(() => {
    const summaries = new Map<WorkloadScan, WorkloadExceptions>();
    for (const workloadScan of workloadScans ?? []) {
      const data = exceptions.get(workloadScan.cluster);
      const imageScan = workloadScan.imageScan;
      if (!data || !imageScan) continue;
      const covered = workloadCveExceptions(data, {
        kind: workloadScan.kind,
        name: workloadScan.name,
        namespace: workloadScan.namespace,
        image: imageScan.imageName,
      });
      if (covered.size === 0) continue;
      summaries.set(
        workloadScan,
        summarizeWorkloadExceptions(covered, imageScan.matches, imageScan.ignoredMatches)
      );
    }
    return summaries;
  }, [workloadScans, exceptions]);

  if (!workloadScans) {
    return <></>;
  }

  const filteredWorkloadScans = workloadScans.filter(w => w.name && w.namespace);
  const acceptedCount = (workloadScan: WorkloadScan) =>
    exceptionSummaries.get(workloadScan)?.accepted.size ?? 0;
  // the CVEs that no exception covers yet
  const openCves = (workloadScan: WorkloadScan) =>
    exceptionSummaries.get(workloadScan)?.open ?? [
      ...new Set(workloadScan.imageScan?.matches.map(match => match.vulnerability.id)),
    ];

  return (
    <>
      <h5>{filteredWorkloadScans.length} resources</h5>
      <ExceptionReadErrors errors={exceptionErrors} />
      <SectionBox>
        <HeadlampTable
          csvExport={{
            fileName: 'kubescape-vulnerable-resources.csv',
            header: [
              'Name',
              'Container',
              'Kind',
              'Namespace',
              'Cluster',
              'Image',
              ...Object.keys(severityColors),
              'Relevant',
              'Accepted',
            ],
            rows: () =>
              filteredWorkloadScans.map(w => [
                w.name,
                w.container,
                w.kind,
                w.namespace,
                w.cluster,
                w.imageScan?.imageName,
                ...Object.keys(severityColors).map(severity => countScans(w, severity)),
                relevantSummary(w),
                acceptedCount(w),
              ]),
          }}
          data={filteredWorkloadScans}
          columns={[
            {
              header: 'Name',
              accessorKey: 'name',
              Cell: ({ cell }) => {
                return (
                  <Link
                    routeName={RoutingName.KubescapeVulnerabilityDetails}
                    activeCluster={cell.row.original.cluster}
                    params={{
                      name: cell.row.original.manifestName,
                      namespace: cell.row.original.namespace,
                    }}
                  >
                    {cell.getValue()}
                  </Link>
                );
              },
              gridTemplate: 'max-content',
            },
            {
              header: 'Container',
              accessorKey: 'container',
              gridTemplate: 'min-content',
            },
            {
              header: 'Kind',
              accessorKey: 'kind',
              gridTemplate: 'min-content',
            },
            {
              header: 'Namespace',
              accessorKey: 'namespace',
              Cell: ({ cell, row }) => makeNamespaceLink(cell.getValue(), row.original.cluster),
              gridTemplate: 'min-content',
            },
            // no column, also not an empty one, while one cluster is selected
            ...(clusters.length > 1
              ? [
                  {
                    header: 'Cluster',
                    accessorKey: 'cluster',
                  },
                ]
              : []),
            {
              header: 'Image',
              // text also before the report is read: the table only searches a column whose
              // value in the first row is text or a number
              accessorFn: (workloadScan: WorkloadScan) => workloadScan.imageScan?.imageName ?? '',
            },
            {
              id: 'CVE',
              header: 'CVE',
              Cell: ({ row }) => resultStack(row.original),
              // the counts, and whether the summary counted them, so that the cell is drawn
              // again when the report arrives with the same counts
              accessorFn: (workloadScan: WorkloadScan) =>
                countResourceScans(workloadScan).join('.') +
                (countedBySummary(workloadScan) ? summaryMark : ''),
              // by the numbers of the counts: the table picks how to sort from the rows after
              // the tenth, so that ten rows or fewer would sort as text, 9 above 12
              sortingFn: 'alphanumeric',
            },
            {
              header: 'Relevant',
              accessorFn: relevantSummary,
              // by its numbers, like the counts
              sortingFn: 'alphanumeric',
              gridTemplate: 'min-content',
            },
            {
              id: 'Accepted',
              header: 'Accepted',
              // the open CVEs and the exceptions too, so that the chip is drawn again when they
              // change; sorted by the count
              accessorFn: (workloadScan: WorkloadScan) =>
                acceptedChipValue(exceptionSummaries.get(workloadScan)),
              sortingFn: (a, b) => acceptedCount(a.original) - acceptedCount(b.original),
              sortDescFirst: true,
              Cell: ({ row }) => {
                const summary = exceptionSummaries.get(row.original);
                return summary ? (
                  <AcceptedChip summary={summary} cluster={row.original.cluster} />
                ) : null;
              },
              gridTemplate: 'min-content',
            },
            {
              id: 'SBOM',
              header: 'SBOM',
              // a plain value for sorting and redrawing; the link is rendered in the cell
              accessorFn: (workloadScan: WorkloadScan) =>
                workloadScan.relevant?.manifestName ?? workloadScan.imageScan?.manifestName ?? '',
              Cell: ({ row }) => {
                const workloadScan: WorkloadScan = row.original;
                // the report that the value names: the cell is not drawn again when the report
                // of the image arrives after the relevant one, as the value stays the same
                const report = workloadScan.relevant ?? workloadScan.imageScan;
                if (report?.manifestName) {
                  return (
                    <Link
                      routeName={RoutingName.KubescapeSBOMDetails}
                      activeCluster={workloadScan.cluster}
                      params={{
                        name: report.manifestName,
                        namespace: report.namespace,
                      }}
                      search={workloadScan.relevant ? '?filtered' : ''}
                    >
                      SBOM
                    </Link>
                  );
                }
                return null;
              },
              gridTemplate: 'min-content',
            },
            {
              id: 'actions',
              header: '',
              // the open CVEs, so that the button is drawn again when exceptions change them
              accessorFn: (workloadScan: WorkloadScan) => openCves(workloadScan).join(','),
              // rendered for the rows on the page only; the form also offers the exception as
              // YAML, so it opens without the permission to create one
              Cell: ({ row }) => {
                const workloadScan: WorkloadScan = row.original;
                const cveIds = openCves(workloadScan);
                const title = `Accept the risk of the ${
                  cveIds.length === 1 ? 'open CVE' : `${cveIds.length} open CVEs`
                }`;
                return (
                  cveIds.length > 0 && (
                    <Tooltip title={title}>
                      <IconButton
                        size="small"
                        aria-label={title}
                        onClick={() => setAccepting({ workloadScan, cveIds })}
                      >
                        <Icon icon="mdi:shield-check-outline" />
                      </IconButton>
                    </Tooltip>
                  )
                );
              },
              gridTemplate: 'min-content',
            },
          ]}
          initialState={{
            sorting: [
              {
                id: 'CVE',
                desc: true,
              },
            ],
          }}
          getRowId={getWorkloadScanKey}
          reflectInURL="resources"
        />
      </SectionBox>

      {accepting && (
        <GuidedVulnerabilityExceptionForm
          acceptRisk
          cveIds={accepting.cveIds}
          imageRef={accepting.workloadScan.imageScan?.imageName}
          workloadName={accepting.workloadScan.name}
          workloadNamespace={accepting.workloadScan.namespace}
          workloadKind={accepting.workloadScan.kind}
          cluster={accepting.workloadScan.cluster}
          onClose={() => setAccepting(undefined)}
          onCreated={reload}
        />
      )}
    </>
  );
}

// what marks a count of the summary, until the report is read
const summaryMark = ' (summary)';

/** Whether the counts of the workload are its summary's, as its report was not read (yet). */
export function countedBySummary(workloadScan: WorkloadScan): boolean {
  return !workloadScan.imageScan && !!workloadScan.summaryCounts;
}

// Number of relevant findings of the total, e.g. "3 of 40"
function relevantSummary(workloadScan: WorkloadScan): string {
  if (countedBySummary(workloadScan)) {
    const counts = Object.values(workloadScan.summaryCounts ?? {});
    const total = counts.reduce((sum, count) => sum + count.all, 0);
    // the summary counts relevant findings per CVE and package, as the page does
    const relevant = counts.every(count => count.relevant === undefined)
      ? '?'
      : counts.reduce((sum, count) => sum + (count.relevant ?? 0), 0);
    return `${relevant} of ${total}${summaryMark}`;
  }
  if (!workloadScan.imageScan) return 'Unknown';

  const total = workloadScan.imageScan.matches.length;
  if (!workloadScan.relevant) return `? of ${total}`;

  // relevance is per CVE and package, as the relevant counts of Kubescape are; the findings an
  // exception hid from the relevant report are relevant too, as on the page of the workload
  const relevantKeys = relevantFindingKeys(
    workloadScan.relevant.matches,
    workloadScan.relevant.ignoredMatches
  );
  const count = workloadScan.imageScan.matches.filter(match =>
    relevantKeys.has(findingKey(match))
  ).length;
  return `${count} of ${total}`;
}

function countScans(workloadScan: WorkloadScan, severity: string): number {
  let count: number = 0;

  if (countedBySummary(workloadScan)) {
    return workloadScan.summaryCounts?.[severity]?.all ?? 0;
  }
  if (workloadScan.imageScan) {
    for (const match of workloadScan.imageScan.matches) {
      if (match.vulnerability.severity === severity) {
        count++;
      }
    }
  }
  return count;
}

function resultStack(workloadScan: WorkloadScan) {
  const link = {
    routeName: RoutingName.KubescapeVulnerabilityDetails,
    params: { name: workloadScan.manifestName, namespace: workloadScan.namespace },
    activeCluster: workloadScan.cluster,
  };
  if (countedBySummary(workloadScan)) {
    // dimmed, as the summary counts them until the report is read
    return (
      <Box sx={{ opacity: 0.6, fontStyle: 'italic' }} data-testid="summary-counts">
        <SeverityCountStack
          count={severity => countScans(workloadScan, severity)}
          tooltip={severity =>
            `${severity}: counted by the summary of the scan, as its report is not read yet`
          }
          link={link}
        />
      </Box>
    );
  }
  if (!workloadScan.imageScan) {
    return <div />;
  }

  return <SeverityCountStack count={severity => countScans(workloadScan, severity)} link={link} />;
}

function countResourceScans(workloadScan: WorkloadScan) {
  const counters: number[] = [];
  const severities = ['Critical', 'High', 'Medium', 'Low'];

  severities.map(severity => {
    const count = countScans(workloadScan, severity);
    counters.push(count);
  });

  return counters;
}
