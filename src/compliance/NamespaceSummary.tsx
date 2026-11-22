/*
  Show the configuration findings for workloads in a single namespace.
*/
import {
  Link as HeadlampLink,
  NameValueTable,
  SectionBox,
} from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { getCluster } from '@kinvolk/headlamp-plugin/lib/Utils';
import { Box, Stack } from '@mui/material';
import { useEffect, useMemo, useState } from 'react';
import { ClusterErrors } from '../common/ClusterErrors';
import {
  KubescapeConfig,
  kubescapeConfigStore,
  selectedFrameworkName,
} from '../common/config-store';
import { errorMessage } from '../common/errors';
import { SeverityCountStack } from '../common/SeverityCountBox';
import Table from '../common/Table';
import { getLastURLSegment } from '../common/url';
import { RoutingName } from '../index';
import type { ClusterError } from '../model';
import { queryTaskErrors } from '../query';
import { WorkloadConfigurationScanSummary } from '../softwarecomposition/WorkloadConfigurationScanSummary';
import { configurationScanContext, readConfigurationScans } from './Compliance';
import { ControlExceptionErrors } from './ControlExceptionErrors';
import { failedControls, passedShare } from './ResourceList';

type Scan = WorkloadConfigurationScanSummary;

/** The failed controls per severity, as many as the table below counts. */
export interface FailedControlCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

/**
 * The failed controls of the scans per severity that no exception applies to, as the table of
 * the page counts them. The counts of the storage's summary of the namespace leave out the
 * exceptions that the plugin applies itself, where the scanners do not.
 */
export function countFailedControls(scans: Scan[], frameworkName?: string): FailedControlCounts {
  const counts: FailedControlCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const scan of scans) {
    for (const control of failedControls(scan, frameworkName)) {
      const severity = control.severity?.severity?.toLowerCase();
      if (severity && severity in counts) counts[severity as keyof FailedControlCounts]++;
    }
  }
  return counts;
}

export default function KubescapeConfigurationScanNamespaceSummary() {
  const namespace = getLastURLSegment();
  // the namespace of the cluster of the page; the cache holds those of all selected clusters
  const cluster = getCluster() ?? '';
  // the scans the Compliance page read, which this page reads itself when opened directly,
  // with the exceptions applied
  const [scans, setScans] = useState(() => [...configurationScanContext.workloadScans]);
  const [loading, setLoading] = useState(false);
  const [readErrors, setReadErrors] = useState<ClusterError[]>([]);
  const [exceptionErrors, setExceptionErrors] = useState<ClusterError[]>([]);

  useEffect(() => {
    if (!cluster) return;
    let active = true;
    const continueReading = { current: true };
    readConfigurationScans(
      [cluster],
      (kubescapeConfigStore.get() ?? {}) as KubescapeConfig,
      continueReading,
      busy => active && setLoading(busy),
      () => {},
      // the cache keeps the scans of the other selected clusters for the Compliance page
      { keepOtherClusters: true }
    )
      .then(found => {
        if (!active) return;
        setScans(found);
        setReadErrors(
          queryTaskErrors(
            configurationScanContext.queryTasks.filter(task => task.cluster === cluster)
          )
        );
        setExceptionErrors(configurationScanContext.exceptionErrors);
      })
      .catch(error => {
        console.error('Unable to read the configuration scans', error);
        if (active) setReadErrors([{ cluster, message: errorMessage(error) }]);
      });
    return () => {
      active = false;
      continueReading.current = false;
    };
  }, [cluster]);

  const configurationScans = useMemo(
    () => scans.filter(w => w.metadata.namespace === namespace && w.metadata.cluster === cluster),
    [scans, namespace, cluster]
  );
  // the exceptions limited to a framework apply in the framework of the Compliance page
  const frameworkName = selectedFrameworkName();

  return (
    <SectionBox title="Namespace Configuration scans" backLink>
      {!loading && (
        <>
          <ClusterErrors errors={readErrors} what="the configuration scans" />
          <ControlExceptionErrors errors={exceptionErrors} clusters={[cluster]} />
        </>
      )}
      <NameValueTable
        rows={[
          {
            name: 'Namespace',
            value: namespace,
          },
          {
            name: 'Failed Controls',
            value:
              loading && configurationScans.length === 0
                ? 'Reading the scans…'
                : resultStack(countFailedControls(configurationScans, frameworkName)),
          },
        ]}
      />

      <ConfigurationScans
        configurationScans={configurationScans}
        loading={loading}
        frameworkName={frameworkName}
      />
    </SectionBox>
  );
}

function ConfigurationScans(
  props: Readonly<{ configurationScans: Scan[]; loading: boolean; frameworkName?: string }>
) {
  const { configurationScans, loading, frameworkName } = props;

  return (
    <Table
      data={configurationScans}
      loading={loading && configurationScans.length === 0}
      getRowId={(w: WorkloadConfigurationScanSummary) => w.metadata.name}
      columns={[
        {
          header: 'Name',
          accessorKey: 'metadata.name',
          Cell: ({ cell }) => (
            <HeadlampLink
              routeName={RoutingName.KubescapeWorkloadConfigurationScanDetails}
              params={{
                name: cell.row.original.metadata.name,
                namespace: cell.row.original.metadata.namespace,
                cluster: cell.row.original.metadata.cluster,
              }}
            >
              {cell.getValue()}
            </HeadlampLink>
          ),
          gridTemplate: 'auto',
        },
        {
          header: 'Kind',
          accessorFn: (workloadScan: WorkloadConfigurationScanSummary) =>
            workloadScan.metadata.labels['kubescape.io/workload-kind'],
          gridTemplate: 'auto',
        },
        {
          id: 'Passed',
          header: 'Passed',
          // the controls that passed or that an exception excludes
          accessorFn: (workloadScan: WorkloadConfigurationScanSummary) =>
            passedShare(workloadScan, frameworkName),
          Cell: ({ cell }) => <progress value={cell.getValue()} />,
          gridTemplate: 'auto',
        },
        {
          id: 'Failed Controls',
          header: 'Failed Controls',
          // the failed controls that no exception applies to
          accessorFn: (w: WorkloadConfigurationScanSummary) =>
            failedControls(w, frameworkName).length,
          Cell: ({ row }) => {
            const failed = failedControls(row.original, frameworkName);
            return (
              <SeverityCountStack
                count={severity =>
                  failed.filter(scan => scan.severity.severity === severity).length
                }
              />
            );
          },
          gridTemplate: 'auto',
        },
      ]}
    />
  );
}

export function resultStack(counts: FailedControlCounts) {
  function controlsBox(color: string, severity: string, countScan: number) {
    return (
      <Box
        sx={{
          borderLeft: 2,
          borderTop: 1,
          borderRight: 1,
          borderBottom: 1,
          borderColor: `gray gray gray ${color}`,
          textAlign: 'center',
          width: 100,
        }}
      >
        {countScan} {severity}
      </Box>
    );
  }

  return (
    <Stack direction="row" spacing={1}>
      {controlsBox('purple', 'Critical', counts.critical)}
      {controlsBox('red', 'High', counts.high)}
      {controlsBox('orange', 'Medium', counts.medium)}
      {controlsBox('yellow', 'Low', counts.low)}
    </Stack>
  );
}
