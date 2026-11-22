/* 
  Show configuration scan results for a workload. 
*/
import { Icon } from '@iconify/react';
import {
  Link as HeadlampLink,
  NameValueTable,
  SectionBox,
} from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { Alert, IconButton, Link, Tooltip } from '@mui/material';
import { useEffect, useState } from 'react';
import { getAllowedNamespaces } from '../common/clusterContext';
import { selectedFrameworkName } from '../common/config-store';
import { errorMessage } from '../common/errors';
import { readClusterSetup, scannersApplyExceptions } from '../common/kubescapeSetup';
import { StatusLabel, StatusLabelProps } from '../common/StatusLabel';
import HeadlampTable from '../common/Table';
import { getURLSegments } from '../common/url';
import {
  applySecurityExceptionsToWorkloadScans,
  fetchSecurityExceptions,
  markScannerExceptions,
} from '../exceptions/apply-security-exceptions';
import { GuidedComplianceExceptionForm } from '../exceptions/GuidedComplianceExceptionForm';
import { RoutingName } from '../index';
import { fetchObject, workloadConfigurationScanClass } from '../model';
import { useRegoData } from '../rego';
import { WorkloadConfigurationScan } from '../softwarecomposition/WorkloadConfigurationScan';
import { WorkloadConfigurationScanSummary } from '../softwarecomposition/WorkloadConfigurationScanSummary';
import { configurationScanContext } from './Compliance';
import { ControlExceptionErrors } from './ControlExceptionErrors';
import { isControlExcepted } from './workload-scanning';

/**
 * Marks the controls of the scan that exceptions apply to: as the summary in the cache of the
 * Compliance page says, or, when the page was opened directly, as the exceptions of the cluster
 * or the scanner say.
 *
 * @returns What could not be read of the exceptions, so that controls they cover may be shown
 * as failed.
 */
export async function markExceptions(
  scan: WorkloadConfigurationScan,
  cluster: string,
  // after an exception was created here, the cache does not know it yet
  useCache: boolean
): Promise<string[]> {
  const summary =
    useCache &&
    configurationScanContext.workloadScans.find(
      w =>
        w.metadata.cluster === cluster &&
        w.metadata.name === scan.metadata.name &&
        w.metadata.namespace === scan.metadata.namespace
    );
  if (summary) {
    scan.exceptedByPolicy = summary.exceptedByPolicy;
    const marks = new Map(
      Object.values(summary.spec.controls).map(control => [control.controlID, control])
    );
    Object.values(scan.spec.controls).forEach(control => {
      const mark = marks.get(control.controlID);
      control.exceptedByPolicy = mark?.exceptedByPolicy ?? false;
      if (mark?.exceptedInFrameworks) control.exceptedInFrameworks = mark.exceptedInFrameworks;
      else delete control.exceptedInFrameworks;
    });
    return configurationScanContext.exceptionErrors
      .filter(error => error.cluster === cluster)
      .map(error => error.message);
  }
  // the scan has the labels and controls of its summary
  const asSummary = scan as unknown as WorkloadConfigurationScanSummary;
  if (scannersApplyExceptions(await readClusterSetup(cluster))) {
    markScannerExceptions([asSummary]);
    return [];
  }
  const exceptions = await fetchSecurityExceptions(
    cluster,
    [asSummary],
    [],
    getAllowedNamespaces(cluster)
  );
  applySecurityExceptionsToWorkloadScans([asSummary], exceptions);
  return exceptions.errors ?? [];
}

export default function KubescapeWorkloadConfigurationScanDetails() {
  const [name, namespace, cluster] = getURLSegments(-1, -2, -3);
  const [configurationScan, setConfigurationScan] = useState<WorkloadConfigurationScan | null>(
    null
  );
  const [error, setError] = useState<string | null>(null);
  // what could not be read of the security exceptions
  const [exceptionErrors, setExceptionErrors] = useState<string[]>([]);
  // changed to read the scan again, after an exception was created
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let active = true;
    setError(null);
    fetchObject(name, namespace, cluster, workloadConfigurationScanClass)
      .then(async (result: WorkloadConfigurationScan) => {
        if (!result) throw new Error(`The scan ${namespace}/${name} was not found`);
        result.metadata.cluster = cluster;
        const markErrors = await markExceptions(result, cluster, reloadKey === 0).catch(
          (markError: unknown) => {
            console.error('Unable to apply the security exceptions', markError);
            return [errorMessage(markError)];
          }
        );
        if (!active) return;
        setExceptionErrors(markErrors);
        setConfigurationScan(result);
      })
      .catch(fetchError => {
        if (active) setError(errorMessage(fetchError));
      });
    return () => {
      active = false;
    };
  }, [name, namespace, cluster, reloadKey]);

  if (error) {
    return (
      <SectionBox title="Workload Configuration Scan" backLink>
        <Alert severity="error">Unable to read the configuration scan: {error}</Alert>
      </SectionBox>
    );
  }
  if (!configurationScan) {
    return <></>;
  }

  return (
    <>
      <SectionBox title="Workload Configuration Scan" backLink>
        <ControlExceptionErrors
          errors={
            exceptionErrors.length > 0 ? [{ cluster, message: exceptionErrors.join('; ') }] : []
          }
        />
        <NameValueTable
          rows={[
            {
              name: 'Name',
              value: configurationScan.metadata.labels['kubescape.io/workload-name'],
            },
            {
              name: 'Namespace',
              value: configurationScan.metadata.labels['kubescape.io/workload-namespace'],
            },
            {
              name: 'Cluster',
              value: configurationScan.metadata.cluster,
            },
            {
              name: 'Kind',
              value: configurationScan.metadata.labels['kubescape.io/workload-kind'],
            },
            {
              name: 'Last scan',
              value: configurationScan.spec.metadata?.report?.createdAt || 'Unknown',
            },
            {
              name: 'Results',
              value: getResults(configurationScan),
            },
          ]}
        />
      </SectionBox>

      <Controls
        workloadConfigurationScan={configurationScan}
        cluster={cluster}
        // the Compliance page applies the new exception when it reads the scans again
        onExceptionCreated={() => setReloadKey(key => key + 1)}
      />
    </>
  );
}

function Controls(
  props: Readonly<{
    workloadConfigurationScan: WorkloadConfigurationScan;
    cluster: string;
    onExceptionCreated: () => void;
  }>
) {
  const { workloadConfigurationScan, cluster, onExceptionCreated } = props;
  const { controls } = useRegoData();
  const [exceptionControl, setExceptionControl] =
    useState<WorkloadConfigurationScan.Control | null>(null);

  const workloadName = workloadConfigurationScan.metadata.labels['kubescape.io/workload-name'];
  const workloadNamespace =
    workloadConfigurationScan.metadata.labels['kubescape.io/workload-namespace'];
  const workloadKind = workloadConfigurationScan.metadata.labels['kubescape.io/workload-kind'];
  const canCreateException = !!(workloadName && workloadNamespace && workloadKind);

  return (
    <SectionBox title="Controls">
      <HeadlampTable
        data={Object.values(workloadConfigurationScan.spec.controls)}
        getRowId={(control: WorkloadConfigurationScan.Control) => control.controlID}
        columns={[
          {
            id: 'Status',
            header: 'Status',
            // the status shown, so that the cell is drawn again when an exception excludes the
            // control
            accessorFn: (control: WorkloadConfigurationScan.Control) =>
              shownStatus(workloadConfigurationScan, control),
            Cell: ({ row }) => makeStatusLabel(workloadConfigurationScan, row.original),
            // by the result of the scan, as before: the failed controls first, excluded or not
            sortingFn: (a, b) => a.original.status.status.localeCompare(b.original.status.status),
            gridTemplate: 'min-content',
          },
          {
            header: 'Control',
            accessorKey: 'controlID',
            Cell: ({ cell }) => {
              return (
                <Link
                  target="_blank"
                  href={'https://kubescape.io/docs/controls/' + cell.getValue().toLowerCase()}
                >
                  {cell.getValue()}
                </Link>
              );
            },
            gridTemplate: 'min-content',
          },
          {
            header: 'Name',
            accessorKey: 'name',
          },
          {
            header: 'Category',
            accessorFn: (control: WorkloadConfigurationScan.Control) => {
              const controlInfo = controls.find(
                controlInfo => controlInfo.controlID === control.controlID
              );
              return controlInfo?.category?.subCategory?.name ?? controlInfo?.category?.name;
            },
            gridTemplate: 'auto',
          },
          {
            header: 'Severity',
            accessorKey: 'severity.severity',
            gridTemplate: 'min-content',
          },
          {
            header: 'Explain',
            accessorFn: (control: WorkloadConfigurationScan.Control) =>
              controls.find(controlInfo => controlInfo.controlID === control.controlID)
                ?.description,
          },
          {
            header: 'Remediation',
            accessorFn: (control: WorkloadConfigurationScan.Control) =>
              controls.find(controlInfo => controlInfo.controlID === control.controlID)
                ?.remediation,
          },
          {
            id: 'actions',
            header: '',
            accessorKey: 'controlID',
            enableSorting: false,
            Cell: ({ row }) => {
              const control: WorkloadConfigurationScan.Control = row.original;
              return (
                <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  {/* a control may come without rules */}
                  {control.rules?.some(rule => rule.paths) && (
                    <HeadlampLink
                      routeName={RoutingName.KubescapeWorkloadConfigurationScanFixes}
                      params={{
                        name: workloadConfigurationScan.metadata.name,
                        namespace: workloadConfigurationScan.metadata.namespace,
                        cluster,
                        control: control.controlID,
                      }}
                    >
                      Fix
                    </HeadlampLink>
                  )}
                  {/* the form checks whether the user may create the exception; without
                      permission, it still offers its YAML for GitOps */}
                  {canCreateException ? (
                    <Tooltip title="Create Security Exception">
                      <IconButton
                        size="small"
                        aria-label="Create Security Exception"
                        onClick={() => setExceptionControl(control)}
                      >
                        <Icon icon="mdi:shield-plus-outline" />
                      </IconButton>
                    </Tooltip>
                  ) : (
                    <Tooltip title="Workload labels missing — cannot create exception">
                      <span>
                        <IconButton size="small" disabled>
                          <Icon icon="mdi:shield-plus-outline" />
                        </IconButton>
                      </span>
                    </Tooltip>
                  )}
                </span>
              );
            },
            gridTemplate: 'min-content',
          },
        ]}
        initialState={{
          sorting: [
            {
              id: 'Status',
              desc: false,
            },
          ],
        }}
      />
      {exceptionControl && canCreateException && (
        <GuidedComplianceExceptionForm
          controlID={exceptionControl.controlID}
          workloadName={workloadName!}
          workloadNamespace={workloadNamespace!}
          workloadKind={workloadKind!}
          cluster={cluster}
          onClose={() => setExceptionControl(null)}
          onCreated={onExceptionCreated}
        />
      )}
    </SectionBox>
  );
}

function getResults(workloadConfigurationScan: WorkloadConfigurationScan): string {
  let failCount: number = 0;
  let passedCount: number = 0;
  let skippedCount: number = 0;
  let excludedCount: number = 0;
  const frameworkName = selectedFrameworkName();
  if (workloadConfigurationScan.exceptedByPolicy) {
    excludedCount = Object.values(workloadConfigurationScan.spec.controls).length;
  } else {
    for (const scan of Object.values(workloadConfigurationScan.spec.controls)) {
      if (isControlExcepted(scan, frameworkName)) {
        excludedCount++;
        continue;
      }
      switch (scan.status.status) {
        case 'failed': {
          failCount++;
          break;
        }
        case 'passed': {
          passedCount++;
          break;
        }
        case 'skipped': {
          skippedCount++;
          break;
        }
      }
    }
  }

  return `Failed ${failCount}, Passed ${passedCount}, Skipped ${skippedCount}, Excluded ${excludedCount}`;
}

/** The status of a control as the page shows it: excluded when an exception covers it. */
export function shownStatus(
  workloadConfigurationScan: WorkloadConfigurationScan,
  control: WorkloadConfigurationScan.Control
): string {
  return workloadConfigurationScan.exceptedByPolicy ||
    isControlExcepted(control, selectedFrameworkName())
    ? 'excluded'
    : control.status.status;
}

function makeStatusLabel(
  workloadConfigurationScan: WorkloadConfigurationScan,
  control: WorkloadConfigurationScan.Control
) {
  let status: StatusLabelProps['status'] = '';
  const statusLabel = shownStatus(workloadConfigurationScan, control);

  if (statusLabel === 'failed') {
    status = 'error';
  } else if (statusLabel !== 'excluded') {
    status = 'success';
  }

  return <StatusLabel status={status}>{statusLabel}</StatusLabel>;
}
