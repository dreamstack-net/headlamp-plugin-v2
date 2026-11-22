/* 
  List configuration scans for all workloads.  
*/
import { Link, TableColumn } from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { Box, Stack } from '@mui/material';
import { useMemo } from 'react';
import { makeNamespaceLink } from '../common/Namespace';
import { severityColors, SeverityCountStack } from '../common/SeverityCountBox';
import Table from '../common/Table';
import { RoutingName, useHLSelectedClusters } from '../index';
import { FrameWork } from '../rego';
import { WorkloadConfigurationScanSummary } from '../softwarecomposition/WorkloadConfigurationScanSummary';
import { isControlExcepted } from './workload-scanning';

export default function KubescapeWorkloadConfigurationScanList(
  props: Readonly<{
    workloadScanData: WorkloadConfigurationScanSummary[] | null;
    framework: FrameWork;
    // the controls of the chosen framework, which the counts are limited to; undefined for the
    // combined view of all controls
    controlIDs?: Set<string>;
    isFailedControlSwitchChecked: boolean;
  }>
) {
  const clusters = useHLSelectedClusters();

  const { workloadScanData, framework, controlIDs, isFailedControlSwitchChecked } = props;
  const frameworkName = framework.name;
  // the same rows on every render, so the table does not compute its cells again; new rows for
  // another framework, whose controls and exceptions differ
  const workloads = useMemo(
    () =>
      workloadScanData && isFailedControlSwitchChecked
        ? getWorkloadsWithFindings(workloadScanData, frameworkName, controlIDs)
        : workloadScanData && [...workloadScanData],
    [workloadScanData, isFailedControlSwitchChecked, frameworkName, controlIDs]
  );
  if (!workloadScanData || !workloads) {
    return <></>;
  }

  const labels = (w: WorkloadConfigurationScanSummary) => w.metadata.labels;
  return (
    <Box>
      <Table
        csvExport={{
          fileName: 'kubescape-compliance-resources.csv',
          header: [
            'Name',
            'Kind',
            'Namespace',
            'Cluster',
            'Excluded',
            ...Object.keys(severityColors).map(severity => `${severity} failed controls`),
            'Failed controls',
          ],
          rows: () =>
            workloads.map(w => [
              labels(w)['kubescape.io/workload-name'],
              labels(w)['kubescape.io/workload-kind'],
              labels(w)['kubescape.io/workload-namespace'],
              w.metadata.cluster,
              w.exceptedByPolicy ? 'Yes' : 'No',
              ...Object.keys(severityColors).map(
                severity =>
                  failedControls(w, frameworkName, controlIDs).filter(
                    scan => scan.severity.severity === severity
                  ).length
              ),
              failedControls(w, frameworkName, controlIDs)
                .map(scan => scan.controlID)
                .join('; '),
            ]),
        }}
        data={workloads}
        getRowId={(w: WorkloadConfigurationScanSummary) =>
          JSON.stringify([w.metadata.cluster, w.metadata.namespace, w.metadata.name])
        }
        columns={[
          {
            header: 'Name',
            accessorFn: (workloadScan: WorkloadConfigurationScanSummary) =>
              workloadScan.metadata.labels['kubescape.io/workload-name'],
            Cell: ({ cell, row }) => (
              <Link
                routeName={RoutingName.KubescapeWorkloadConfigurationScanDetails}
                params={{
                  name: row.original.metadata.name,
                  namespace: row.original.metadata.namespace,
                  cluster: row.original.metadata.cluster,
                }}
              >
                {cell.getValue()}
              </Link>
            ),
            gridTemplate: 'auto',
          },
          {
            header: 'Excluded',
            accessorKey: 'exceptedByPolicy',
            Cell: ({ cell }) => (cell.getValue() ? 'Yes' : 'No'),
            gridTemplate: 'auto',
          },
          {
            header: 'Kind',
            accessorFn: (workloadScan: WorkloadConfigurationScanSummary) =>
              workloadScan.metadata.labels['kubescape.io/workload-kind'],
            gridTemplate: 'auto',
          },
          {
            header: 'Namespace',
            accessorFn: (workloadScan: WorkloadConfigurationScanSummary) =>
              workloadScan.metadata.labels['kubescape.io/workload-namespace'],
            // the namespace of the cluster of the row, as the table may have several clusters
            Cell: ({ cell, row }) =>
              cell.getValue()
                ? makeNamespaceLink(cell.getValue(), row.original.metadata.cluster)
                : '',
            gridTemplate: 'auto',
          },
          // no column without clusters to tell apart: an empty one would take its width
          ...(clusters.length > 1
            ? [
                {
                  header: 'Cluster',
                  accessorKey: 'metadata.cluster',
                } as TableColumn<WorkloadConfigurationScanSummary>,
              ]
            : []),
          {
            id: 'Passed',
            header: 'Passed',
            // the controls that passed or that an exception excludes, as the compliance score
            // counts them
            accessorFn: (workloadScan: WorkloadConfigurationScanSummary) =>
              passedShare(workloadScan, frameworkName, controlIDs),
            Cell: ({ cell }) => <progress value={cell.getValue()} />,
            gridTemplate: 'auto',
          },
          {
            id: 'Failed Controls',
            header: 'Failed Controls',
            Cell: ({ row }) => resultStack(row.original, framework, controlIDs),
            // by the counts per severity, as numbers: as text, 10 failed sorts before 2
            sortingFn: (a, b) =>
              compareCounts(
                countResourceScans(a.original, frameworkName, controlIDs),
                countResourceScans(b.original, frameworkName, controlIDs)
              ),
            // the counts sort; the failed controls, which the tooltips list, draw the cell again
            // when another framework fails other controls as often
            accessorFn: (workloadScan: WorkloadConfigurationScanSummary) =>
              `${countResourceScans(workloadScan, frameworkName, controlIDs).join(
                '.'
              )} ${failedControls(workloadScan, frameworkName, controlIDs)
                .map(scan => scan.controlID)
                .join(',')}`,
            gridTemplate: 'auto',
          },
        ]}
        initialState={{
          sorting: [
            {
              id: 'Failed Controls',
              desc: true,
            },
          ],
        }}
        reflectInURL="resources"
      />
    </Box>
  );
}

// The failed controls of a severity, as many as the cell counts: also those the framework does
// not describe, such as controls of no framework in the combined view
export function controlsList(
  workloadScan: WorkloadConfigurationScanSummary,
  framework: FrameWork,
  severity: string,
  controlIDs?: Set<string>
) {
  const names = new Map(framework.controls.map(control => [control.controlID, control.name]));
  const controls = failedControls(workloadScan, framework.name, controlIDs)
    .filter(scan => scan.severity.severity === severity)
    .map(scan => ({ controlID: scan.controlID, name: names.get(scan.controlID) }));

  if (controls.length > 0) {
    return (
      <>
        <div style={{ fontSize: 'smaller' }}>{severity}</div>
        <br />
        <div style={{ whiteSpace: 'normal', textAlign: 'left', fontSize: 'small' }}>
          <Stack spacing={1}>
            {controls.map(control => (
              <div key={control.controlID}>
                {control.name ? `${control.controlID}: ${control.name}` : control.controlID}
              </div>
            ))}
          </Stack>
        </div>
      </>
    );
  }
}

// The results of a resource of the given controls (of the framework), or of all its controls
function resultsOf(workloadScan: WorkloadConfigurationScanSummary, controlIDs?: Set<string>) {
  const results = Object.values(workloadScan.spec.controls);
  return controlIDs ? results.filter(scan => controlIDs.has(scan.controlID)) : results;
}

/**
 * Failed controls of a resource that no exception applies to in the framework; none when an
 * exception excludes the whole resource. With the controls of the framework, only those.
 */
export function failedControls(
  workloadScan: WorkloadConfigurationScanSummary,
  frameworkName?: string,
  controlIDs?: Set<string>
) {
  if (workloadScan.exceptedByPolicy) return [];
  return resultsOf(workloadScan, controlIDs).filter(
    scan =>
      !isControlExcepted(scan, frameworkName) &&
      scan.status.status === WorkloadConfigurationScanSummary.Status.Failed
  );
}

/**
 * The share of the controls of a resource that passed or that an exception excludes, as the
 * compliance score of a control counts them. With the controls of the framework, only those.
 */
export function passedShare(
  workloadScan: WorkloadConfigurationScanSummary,
  frameworkName?: string,
  controlIDs?: Set<string>
): number {
  const controls = resultsOf(workloadScan, controlIDs);
  if (controls.length === 0) return 0;
  if (workloadScan.exceptedByPolicy) return 1;
  const passedCount = controls.filter(
    scan =>
      isControlExcepted(scan, frameworkName) ||
      scan.status.status === WorkloadConfigurationScanSummary.Status.Passed
  ).length;
  return passedCount / controls.length;
}

function resultStack(
  workloadScan: WorkloadConfigurationScanSummary,
  framework: FrameWork,
  controlIDs?: Set<string>
) {
  return (
    <SeverityCountStack
      count={severity =>
        failedControls(workloadScan, framework.name, controlIDs).filter(
          scan => scan.severity.severity === severity
        ).length
      }
      tooltip={severity => controlsList(workloadScan, framework, severity, controlIDs)}
    />
  );
}

/** The failed controls of a resource per severity, from critical to low. */
/** Orders counts per severity, the most severe first, as numbers. */
export function compareCounts(a: number[], b: number[]): number {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const difference = (a[i] ?? 0) - (b[i] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
}

export function countResourceScans(
  workloadScan: WorkloadConfigurationScanSummary,
  frameworkName?: string,
  controlIDs?: Set<string>
) {
  const counters: number[] = [];
  const severities = ['Critical', 'High', 'Medium', 'Low'];

  const failed = failedControls(workloadScan, frameworkName, controlIDs);
  severities.forEach(severity => {
    counters.push(failed.filter(scan => scan.severity.severity === severity).length);
  });

  return counters;
}

// The resources with failed controls (of the framework) that no exception applies to
function getWorkloadsWithFindings(
  workloadScanData: WorkloadConfigurationScanSummary[],
  frameworkName: string,
  controlIDs?: Set<string>
): WorkloadConfigurationScanSummary[] {
  return workloadScanData.filter(
    workload => failedControls(workload, frameworkName, controlIDs).length > 0
  );
}
