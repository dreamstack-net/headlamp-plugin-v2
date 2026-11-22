/*
  Information about a control and failed workloads.
*/
import { Icon } from '@iconify/react';
import {
  Link as HeadlampLink,
  NameValueTable,
  SectionBox,
  TableColumn,
} from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { Alert, FormControlLabel, IconButton, Link, Switch, Tooltip } from '@mui/material';
import { useEffect, useMemo, useState } from 'react';
import {
  KubescapeConfig,
  kubescapeConfigStore,
  selectedFrameworkName,
} from '../common/config-store';
import { errorMessage } from '../common/errors';
import { makeNamespaceLink } from '../common/Namespace';
import { KubescapeSettings, useSessionStorage } from '../common/sessionStorage';
import Table from '../common/Table';
import { getLastURLSegment } from '../common/url';
import { GuidedComplianceExceptionForm } from '../exceptions/GuidedComplianceExceptionForm';
import { RoutingName, useHLSelectedClusters } from '../index';
import type { ClusterError } from '../model';
import { useRegoData } from '../rego';
import { WorkloadConfigurationScanSummary } from '../softwarecomposition/WorkloadConfigurationScanSummary';
import { configurationScanContext, readConfigurationScans } from './Compliance';
import { ControlExceptionErrors } from './ControlExceptionErrors';
import { isControlExcepted } from './workload-scanning';

type Scan = WorkloadConfigurationScanSummary;

// identifies the scan of a workload in all selected clusters
function scanKey(scan: Scan) {
  return JSON.stringify([scan.metadata.cluster, scan.metadata.namespace, scan.metadata.name]);
}

function controlOf(scan: Scan, controlID: string) {
  return Object.values(scan.spec.controls).find(c => c.controlID === controlID);
}

/**
 * Whether an exception excludes the workload or its result of the control; the exceptions
 * limited to a framework apply in the framework of the Compliance page.
 */
export function isExcluded(scan: Scan, controlID: string, frameworkName?: string) {
  const control = controlOf(scan, controlID);
  return scan.exceptedByPolicy || (!!control && isControlExcepted(control, frameworkName));
}

/** The status of the result of the control, 'excluded' when an exception excludes it. */
export function statusOf(scan: Scan, controlID: string, frameworkName?: string) {
  return isExcluded(scan, controlID, frameworkName)
    ? 'excluded'
    : controlOf(scan, controlID)?.status.status ?? '';
}

export default function KubescapeControlResults() {
  const controlID = getLastURLSegment();
  const clusters = useHLSelectedClusters();
  const clusterKey = clusters.join(',');
  const { controls, loading } = useRegoData();

  const [isFailedControlSwitchChecked, setIsFailedControlSwitchChecked] =
    useSessionStorage<boolean>(KubescapeSettings.FailedControls, true);
  // the scans the other pages read; this page reads them itself when it is opened directly,
  // and again after an exception was created here
  const [scans, setScans] = useState<Scan[]>(() => [...configurationScanContext.workloadScans]);
  const [reading, setReading] = useState(false);
  const [readError, setReadError] = useState<string | null>(null);
  // the clusters whose exceptions could not be read
  const [exceptionErrors, setExceptionErrors] = useState<ClusterError[]>(
    () => configurationScanContext.exceptionErrors
  );
  const [reloadKey, setReloadKey] = useState(0);
  const [exceptionFormWorkload, setExceptionFormWorkload] = useState<Scan | null>(null);
  const control = controls.find(element => element.controlID === controlID);

  useEffect(() => {
    if (clusters.length === 0) return;
    let active = true;
    const continueReading = { current: true };
    readConfigurationScans(
      clusters,
      (kubescapeConfigStore.get() ?? {}) as KubescapeConfig,
      continueReading,
      busy => active && setReading(busy),
      () => {}
    )
      .then(found => {
        if (!active) return;
        setScans(found);
        setExceptionErrors(configurationScanContext.exceptionErrors);
      })
      .catch(error => active && setReadError(errorMessage(error)));
    return () => {
      active = false;
      continueReading.current = false;
    };
    // clusterKey covers clusters, which is a new array on every render
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clusterKey, reloadKey]);

  // the exceptions limited to a framework apply in the framework of the Compliance page
  const frameworkName = selectedFrameworkName();
  // the workloads that the control checked, and of them the ones the table shows
  const affected = useMemo(
    () => scans.filter(scan => !!controlOf(scan, controlID)),
    [scans, controlID]
  );
  const resourceList = useMemo(
    () =>
      isFailedControlSwitchChecked
        ? affected.filter(
            scan =>
              !isExcluded(scan, controlID, frameworkName) &&
              controlOf(scan, controlID)?.status.status !==
                WorkloadConfigurationScanSummary.Status.Passed
          )
        : affected,
    [affected, controlID, isFailedControlSwitchChecked, frameworkName]
  );
  const passed = affected.filter(
    scan =>
      !isExcluded(scan, controlID, frameworkName) &&
      controlOf(scan, controlID)?.status.status === WorkloadConfigurationScanSummary.Status.Passed
  ).length;
  const excluded = affected.filter(scan => isExcluded(scan, controlID, frameworkName)).length;

  if (loading) {
    return <></>;
  }
  if (!control) {
    return <p>The control {controlID} was not found.</p>;
  }

  return (
    <>
      <SectionBox title={`${controlID}: ${control.name}`} backLink>
        {readError && (
          <Alert severity="error" sx={{ mb: 1 }}>
            Unable to read the configuration scans: {readError}
          </Alert>
        )}
        {!reading && <ControlExceptionErrors errors={exceptionErrors} clusters={clusters} />}
        <NameValueTable
          rows={[
            {
              name: 'Description',
              value: control.description,
            },
            {
              name: 'Category',
              value: control.category?.name,
            },
            {
              name: 'Remediation',
              value: control.remediation,
            },
            {
              name: 'More information',
              value: (
                <Link
                  target="_blank"
                  href={'https://kubescape.io/docs/controls/' + controlID.toLowerCase()}
                >
                  https://kubescape.io/docs/controls/{controlID.toLowerCase()}
                </Link>
              ),
            },
            {
              name: 'Passed',
              value: reading
                ? 'Reading the scans…'
                : `${passed} of ${affected.length}${
                    excluded > 0 ? `, ${excluded} excluded by exceptions` : ''
                  }`,
            },
          ]}
        />
      </SectionBox>

      <SectionBox title="Resources">
        <FormControlLabel
          checked={isFailedControlSwitchChecked}
          control={<Switch color="primary" />}
          label={'Failed controls'}
          onChange={(_event, checked) => {
            setIsFailedControlSwitchChecked(checked);
          }}
        />
        <Table
          data={resourceList}
          loading={reading && resourceList.length === 0}
          getRowId={scanKey}
          columns={[
            {
              id: 'Status',
              header: 'Status',
              accessorFn: (scan: Scan) => statusOf(scan, controlID, frameworkName),
            },
            {
              id: 'Name',
              header: 'Name',
              accessorFn: (scan: Scan) => scan.metadata.labels['kubescape.io/workload-name'],
              // no activeCluster: the route also names the cluster of the scan in its path, and
              // Headlamp's Link would fill in all selected clusters there (cluster-b+cluster-a)
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
            },
            {
              header: 'Kind',
              accessorFn: (scan: Scan) => scan.metadata.labels['kubescape.io/workload-kind'],
            },
            {
              header: 'Namespace',
              accessorFn: (scan: Scan) => scan.metadata.labels['kubescape.io/workload-namespace'],
              Cell: ({ cell, row }) =>
                cell.getValue()
                  ? makeNamespaceLink(cell.getValue(), row.original.metadata.cluster)
                  : '',
            },
            // only with several clusters; an empty object would be a column without a header
            ...(clusters.length > 1
              ? [{ header: 'Cluster', accessorKey: 'metadata.cluster' } as TableColumn<Scan>]
              : []),
            {
              header: 'Scan name',
              accessorFn: (scan: Scan) => scan.metadata.name,
            },
            {
              id: 'fix',
              header: '',
              // the status, so that the cell is drawn again when it changes
              accessorFn: (scan: Scan) => statusOf(scan, controlID, frameworkName),
              enableSorting: false,
              Cell: ({ row }) => {
                const scan: Scan = row.original;
                if (
                  controlOf(scan, controlID)?.status.status ===
                  WorkloadConfigurationScanSummary.Status.Passed
                ) {
                  return null;
                }
                // no activeCluster, as for the link of the name
                return (
                  <HeadlampLink
                    routeName={RoutingName.KubescapeWorkloadConfigurationScanFixes}
                    params={{
                      name: scan.metadata.name,
                      namespace: scan.metadata.namespace,
                      cluster: scan.metadata.cluster,
                      control: controlID,
                    }}
                  >
                    Fix
                  </HeadlampLink>
                );
              },
            },
            {
              id: 'exception',
              header: '',
              accessorFn: (scan: Scan) => statusOf(scan, controlID, frameworkName),
              enableSorting: false,
              Cell: ({ row }) => {
                const scan: Scan = row.original;
                if (
                  statusOf(scan, controlID, frameworkName) !==
                  WorkloadConfigurationScanSummary.Status.Failed
                ) {
                  return null;
                }
                // the form checks whether the user may create the exception; without
                // permission, it still offers its YAML for GitOps
                return (
                  <Tooltip title="Create Security Exception">
                    <IconButton
                      size="small"
                      aria-label="Create Security Exception"
                      onClick={() => setExceptionFormWorkload(scan)}
                    >
                      <Icon icon="mdi:shield-plus-outline" />
                    </IconButton>
                  </Tooltip>
                );
              },
              gridTemplate: 'auto',
            },
          ]}
        />
      </SectionBox>
      {exceptionFormWorkload && (
        <GuidedComplianceExceptionForm
          controlID={controlID}
          workloadName={exceptionFormWorkload.metadata.labels['kubescape.io/workload-name']}
          workloadNamespace={
            exceptionFormWorkload.metadata.labels['kubescape.io/workload-namespace']
          }
          workloadKind={exceptionFormWorkload.metadata.labels['kubescape.io/workload-kind']}
          cluster={exceptionFormWorkload.metadata.cluster}
          onClose={() => setExceptionFormWorkload(null)}
          onCreated={() => setReloadKey(key => key + 1)}
        />
      )}
    </>
  );
}
