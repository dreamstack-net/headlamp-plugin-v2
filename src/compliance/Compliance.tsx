/* 
  Overview  page for configuration controls and resources. 
*/
import { Icon } from '@iconify/react';
import {
  Link as HeadlampLink,
  SectionBox,
  Tabs as HeadlampTabs,
} from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import {
  Box,
  Button,
  FormControlLabel,
  IconButton,
  Stack,
  Switch,
  Tooltip,
  Typography,
} from '@mui/material';
import React, { MutableRefObject, useEffect, useMemo, useRef, useState } from 'react';
import { getAllowedNamespaces, isAllowedNamespaceUpdated } from '../common/clusterContext';
import { ClusterErrors } from '../common/ClusterErrors';
import { KubescapeConfig, kubescapeConfigStore } from '../common/config-store';
import { errorMessage } from '../common/errors';
import { readClusterSetup, scannersApplyExceptions } from '../common/kubescapeSetup';
import { configurationScanCommand } from '../common/operatorCommands';
import { ProgressIndicator, useCurrentReadFlag } from '../common/ProgressIndicator';
import { ReadRecorder, ReadStatistics, readSummary } from '../common/readStatistics';
import { ScanNowButton } from '../common/ScanNowButton';
import {
  getItemFromSessionStorage,
  KubescapeSettings,
  setItemInSessionStorage,
  useSessionStorage,
} from '../common/sessionStorage';
import { SetupCheck } from '../common/SetupCheck';
import { StatusLabel, StatusLabelProps } from '../common/StatusLabel';
import Table from '../common/Table';
import {
  applySecurityExceptionsToWorkloadScans,
  countExcludedControls,
  countExcludedResources,
  countExcludedWorkloadsForControl,
  fetchSecurityExceptions,
  markScannerExceptions,
} from '../exceptions/apply-security-exceptions';
import { GuidedClusterComplianceExceptionForm } from '../exceptions/GuidedClusterComplianceExceptionForm';
import { fetchCustomFrameworks } from '../framework/useCustomFrameworks';
import { RoutingName, useHLSelectedClusters } from '../index';
import { ClusterError, workloadConfigurationScanSummaryClass } from '../model';
import {
  handleListPaginationTasks as handleQueryTasks,
  QueryTask,
  queryTaskErrors,
  readPerNamespace,
} from '../query';
import { Control, FrameWork, useRegoData } from '../rego';
import { WorkloadConfigurationScanSummary } from '../softwarecomposition/WorkloadConfigurationScanSummary';
import ClusterView from './ClusterView';
import { ControlExceptionErrors } from './ControlExceptionErrors';
import { FrameworkButtons } from './FrameworkButtons';
import NamespaceView from './NamespaceView';
import KubescapeWorkloadConfigurationScanList from './ResourceList';
import {
  controlComplianceScore,
  countFailedScans,
  countScans,
  getControlsWithFindings,
  hasFailedScans,
} from './workload-scanning';

// workloadScans are cached in global scope because it is an expensive query for the API server
type ConfigurationScanContext = {
  workloadScans: WorkloadConfigurationScanSummary[];
  queryTasks: QueryTask[];
  // the clusters whose security exceptions could not be read, so the scans count as failed
  // what exceptions may cover
  exceptionErrors: ClusterError[];
};

export const configurationScanContext: ConfigurationScanContext = {
  workloadScans: [],
  queryTasks: [],
  exceptionErrors: [],
};

// the progress of the reads, shown by the page that asked to read last; the pages share the
// reads of the cache
let reportProgress: (message: string) => void = () => {};

// the statistics of the reads in progress
const readRecorder = new ReadRecorder();

/** The line about a read of the configuration scans that the page shows. */
export function configurationReadSummary(statistics: ReadStatistics): string | undefined {
  return readSummary(statistics, [
    { noun: 'configuration scans', one: 'configuration scan', phases: ['configuration scans'] },
  ]);
}

/**
 * Overview page for configuration controls and resources.
 *
 * This page is the main entry point for viewing the compliance posture of the cluster.
 * It displays a list of all controls and resources that have been scanned by Kubescape,
 * along with information about the compliance posture of each control and resource.
 * The page also provides a filter for viewing the compliance posture of specific
 * resources and controls.
 *
 * @returns The ComplianceView component.
 */
export default function ComplianceView(): JSX.Element {
  const pluginConfig = kubescapeConfigStore.useConfig();
  const kubescapeConfig = pluginConfig() as KubescapeConfig;
  const { controls, frameworks, fullRegolibraryFramework, loading: regoLoading } = useRegoData();

  const [workloadScanData, setWorkloadScanData] = useState<
    WorkloadConfigurationScanSummary[] | null
  >(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [progressMessage, setProgressMessage] = useState('Reading Kubescape scans');
  // what the last read of the page read, and how long it took
  const [readLine, setReadLine] = useState<string | undefined>();

  const clusters = useHLSelectedClusters();
  const [customFrameworks, setCustomFrameworks] = useState<FrameWork[]>([]);
  // whether the custom frameworks of the cluster were read, so that a chosen framework the
  // cluster does not have can be named
  const [customFrameworksRead, setCustomFrameworksRead] = useState(false);

  const [isFailedControlSwitchChecked, setIsFailedControlSwitchChecked] =
    useSessionStorage<boolean>(KubescapeSettings.FailedControls, true);
  // the flag of the current read, which the Cancel button of the progress indicator clears; each
  // read has its own, so that a read that was replaced stops
  const reading = useRef<MutableRefObject<boolean>>({ current: true });
  // what the Cancel button of the progress stops
  const currentRead = useCurrentReadFlag(reading);
  const newRead = () => {
    reading.current.current = false;
    reading.current = { current: true };
    return reading.current;
  };
  // whether the read is the current one of the page, which shows what it read; a read that was
  // replaced, or that outlived the page, leaves the page alone
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      // stops a read of More scans or Reload results
      reading.current.current = false;
    };
  }, []);
  const isCurrentRead = (continueReading: MutableRefObject<boolean>) =>
    mounted.current && reading.current === continueReading;
  const [scanStarted, setScanStarted] = useState(false);
  const clusterKey = clusters.join(',');
  const pageSize = kubescapeConfig?.pageSize;

  // the framework chosen with the buttons, undefined for the combined view of all controls
  const selectedFramework =
    frameworks.find(fw => fw.name === kubescapeConfig?.framework) ??
    customFrameworks?.find(fw => fw.name === kubescapeConfig?.framework);
  const framework = selectedFramework ?? fullRegolibraryFramework;
  // with a framework chosen, the counts of the resources and namespaces are of its controls,
  // whose exceptions limited to a framework apply
  const controlIDs = useMemo(
    () =>
      selectedFramework
        ? new Set(selectedFramework.controls.map(control => control.controlID))
        : undefined,
    [selectedFramework]
  );

  // fetch workload scans; choosing another framework only filters what was read
  useEffect(() => {
    if (regoLoading) return;
    let active = true;
    const continueReading = newRead();

    async function fetchData() {
      setReadLine(undefined);
      const workloadScans = await readConfigurationScans(
        clusters,
        kubescapeConfig,
        continueReading,
        loading => active && setLoading(loading),
        message => active && setProgressMessage(message),
        { onStatistics: statistics => active && setReadLine(configurationReadSummary(statistics)) }
      );

      const custom = await fetchCustomFrameworks(controls).catch(error => {
        console.error(error);
        return [];
      });
      if (active) {
        setCustomFrameworks(custom);
        setCustomFrameworksRead(true);
        setWorkloadScanData(workloadScans);
      }
    }

    fetchData().catch(error => {
      console.error('Failed to load compliance data', error);
      if (active) setLoading(false);
    });
    return () => {
      active = false;
      continueReading.current = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clusterKey, pageSize, regoLoading, controls]);

  // read the remaining pages of scans after reading was cancelled
  async function readMoreScans() {
    const continueReading = newRead();
    reportProgress = message => isCurrentRead(continueReading) && setProgressMessage(message);
    setReadLine(undefined);
    const statistics = readRecorder.start('configuration scans');
    try {
      await handleQueryTasks(
        configurationScanContext.queryTasks.filter(task => clusters.includes(task.cluster)),
        continueReading,
        busy => isCurrentRead(continueReading) && setLoading(busy)
      );
      if (!isCurrentRead(continueReading)) return;

      await applySecurityExceptions(clusters);
    } finally {
      readRecorder.finish(statistics);
      if (isCurrentRead(continueReading)) setReadLine(configurationReadSummary(statistics));
    }
    if (isCurrentRead(continueReading)) {
      setWorkloadScanData([...configurationScanContext.workloadScans]);
    }
  }

  // applies the exceptions again, after one was created from this page
  async function reapplyExceptions() {
    await applySecurityExceptions(clusters);
    if (mounted.current) setWorkloadScanData([...configurationScanContext.workloadScans]);
  }

  // read all scans again, after a scan that was started from this page
  async function reloadScans() {
    configurationScanContext.queryTasks = [];
    configurationScanContext.workloadScans = [];
    configurationScanContext.exceptionErrors = [];
    const continueReading = newRead();
    setReadLine(undefined);
    const scans = await readConfigurationScans(
      clusters,
      kubescapeConfig,
      continueReading,
      busy => isCurrentRead(continueReading) && setLoading(busy),
      message => isCurrentRead(continueReading) && setProgressMessage(message),
      {
        onStatistics: statistics =>
          isCurrentRead(continueReading) && setReadLine(configurationReadSummary(statistics)),
      }
    );
    if (isCurrentRead(continueReading)) setWorkloadScanData(scans);
  }

  return (
    <>
      <h1>Compliance</h1>
      <SetupCheck features={['compliance']} />
      {!loading && (
        <>
          <ClusterErrors
            errors={queryTaskErrors(configurationScanContext.queryTasks)}
            what="all configuration scans"
          />
          <ControlExceptionErrors
            errors={configurationScanContext.exceptionErrors}
            clusters={clusters}
          />
        </>
      )}

      {!loading && (
        <Stack direction="row" spacing={2} alignItems="center">
          <ScanNowButton
            clusters={clusters}
            command={configurationScanCommand}
            tooltip="Ask Kubescape to scan the configuration of all workloads now, instead of waiting for the scheduled scan"
            onStarted={() => setScanStarted(true)}
          />
          {scanStarted && (
            <Button
              variant="outlined"
              size="small"
              onClick={() =>
                reloadScans().catch(error => {
                  console.error('Failed to reload compliance scans', error);
                  if (mounted.current) setLoading(false);
                })
              }
            >
              Reload results
            </Button>
          )}
          {configurationScanContext.queryTasks.some(task => task.continuation !== undefined) && (
            <Button
              onClick={() => {
                setTimeout(() => {
                  readMoreScans().catch(error => {
                    console.error('Failed to load more compliance scans', error);
                    if (mounted.current) setLoading(false);
                  });
                });
              }}
              variant="contained"
              sx={{ padding: 1 }}
            >
              More scans
            </Button>
          )}
          {readLine && (
            <Typography variant="body2" color="text.secondary">
              {readLine}
            </Typography>
          )}
        </Stack>
      )}

      {loading && (
        <Box sx={{ padding: 2 }}>
          <ProgressIndicator continueReading={currentRead} progressMessage={progressMessage} />
        </Box>
      )}

      {!loading && workloadScanData && (
        <>
          <Stack direction="row" spacing={1}>
            <FormControlLabel
              checked={isFailedControlSwitchChecked}
              control={<Switch color="primary" />}
              label={'Failed controls'}
              onChange={(_event, checked) => {
                setIsFailedControlSwitchChecked(checked);
              }}
            />
            <FrameworkButtons
              frameworkName={kubescapeConfig?.framework}
              customFrameworks={customFrameworks}
              customFrameworksRead={customFrameworksRead}
            />
          </Stack>
          <Typography variant="body1" component="div" sx={{ padding: 2 }}>
            {`${workloadScanData.length} total checks, ${countFailedScans(
              workloadScanData,
              framework.name,
              controlIDs
            )} configuration issues, excluding ${excludedCountsLine(
              countExcludedResources(workloadScanData),
              // a result of a control in a resource, so a control of several resources counts
              // several times
              countExcludedControls(workloadScanData, framework.name, controlIDs)
            )}`}
          </Typography>
          <HeadlampTabs
            defaultIndex={getItemFromSessionStorage(KubescapeSettings.ComplianceTab) ?? 0}
            onTabChanged={tabIndex =>
              setItemInSessionStorage(KubescapeSettings.ComplianceTab, tabIndex)
            }
            tabs={[
              {
                label: 'Controls',
                component: (
                  <ConfigurationScanningListView
                    workloadScanData={workloadScanData}
                    framework={framework}
                    isFailedControlSwitchChecked={isFailedControlSwitchChecked}
                    onExceptionCreated={() =>
                      reapplyExceptions().catch(error =>
                        console.error('Failed to apply the security exceptions', error)
                      )
                    }
                  />
                ),
              },
              {
                label: 'Resources',
                component: (
                  <KubescapeWorkloadConfigurationScanList
                    workloadScanData={workloadScanData}
                    framework={framework}
                    controlIDs={controlIDs}
                    isFailedControlSwitchChecked={isFailedControlSwitchChecked}
                  />
                ),
              },
              {
                label: 'Namespaces',
                component: (
                  <NamespaceView
                    workloadScanData={workloadScanData}
                    frameworkName={framework.name}
                    controlIDs={controlIDs}
                  />
                ),
              },
              {
                label: 'Clusters',
                component: (
                  <ClusterView
                    workloadScanData={workloadScanData}
                    customFrameworks={customFrameworks}
                  />
                ),
              },
            ]}
            ariaLabel="Navigation Tabs"
          />
        </>
      )}
    </>
  );
}

function ConfigurationScanningListView(
  props: Readonly<{
    workloadScanData: WorkloadConfigurationScanSummary[];
    framework: FrameWork;
    isFailedControlSwitchChecked: boolean;
    // to show the scans with the exception that was created
    onExceptionCreated?: () => void;
  }>
) {
  const { workloadScanData, framework, isFailedControlSwitchChecked, onExceptionCreated } = props;

  const [selectedControl, setSelectedControl] = useState<string | null>(null);
  // a control is excluded cluster-wide in the clusters whose scans the page shows
  const clusters = [...new Set(workloadScanData.map(scan => scan.metadata.cluster))];

  // new rows for other scans or exceptions: the table keeps the values of its rows, which are
  // counted from the scans, until its data changes, and the controls of a framework stay the same
  const controls = useMemo(
    () =>
      isFailedControlSwitchChecked
        ? getControlsWithFindings(workloadScanData, framework)
        : [...framework.controls],
    [workloadScanData, framework, isFailedControlSwitchChecked]
  );

  return (
    <SectionBox>
      <Table
        csvExport={{
          fileName: 'kubescape-controls.csv',
          header: [
            'ID',
            'Control name',
            'Severity',
            'Category',
            'Compliance %',
            'Failed resources',
            'Accepted resources',
            'Excluded resources',
            'Remediation',
          ],
          rows: () =>
            controls.map(control => [
              control.controlID,
              control.name,
              complianceSeverity(control.baseScore),
              control.category?.subCategory?.name ?? control.category?.name,
              Math.trunc(controlComplianceScore(workloadScanData, control, framework.name)),
              countScans(workloadScanData, control, 'failed', framework.name),
              countScans(workloadScanData, control, 'passed', framework.name),
              countExcludedWorkloadsForControl(workloadScanData, control, framework.name),
              control.remediation,
            ]),
        }}
        data={controls}
        getRowId={(control: Control) => control.controlID}
        columns={[
          {
            id: 'Severity',
            header: 'Severity',
            // the score sorts; the label is drawn in the cell
            accessorFn: (control: Control) => control.baseScore,
            Cell: ({ row }) =>
              makeSeverityLabel(
                row.original.baseScore,
                hasFailedScans(workloadScanData, row.original)
              ),
            gridTemplate: 'min-content',
          },
          {
            id: 'ID',
            header: 'ID',
            accessorKey: 'controlID',
            Cell: ({ cell }) => (
              <HeadlampLink
                routeName={RoutingName.KubescapeControlResults}
                params={{
                  control: cell.getValue(),
                }}
              >
                <div>{cell.getValue()}</div>
              </HeadlampLink>
            ),
            gridTemplate: 'auto',
          },
          {
            header: 'Control Name',
            accessorKey: 'name',
            Cell: ({ cell, row }) => (
              <Tooltip
                title={row.original.description}
                slotProps={{ tooltip: { sx: { fontSize: '0.9em' } } }}
              >
                <Box>{cell.getValue()}</Box>
              </Tooltip>
            ),
            gridTemplate: 'auto',
          },
          {
            header: 'Category',
            accessorFn: (control: Control) =>
              control.category?.subCategory?.name ?? control.category?.name,
            gridTemplate: 'auto',
          },
          {
            header: 'Remediation',
            accessorFn: (control: Control) => control.remediation.replaceAll('`', "'"),
          },
          {
            header: 'Compliance',
            accessorFn: (control: Control) =>
              Math.trunc(controlComplianceScore(workloadScanData, control, framework.name)),
            Cell: ({ cell }) => cell.getValue() + '%',
            gridTemplate: 'auto',
          },
          {
            header: 'Excluded',
            accessorFn: (control: Control) =>
              countExcludedWorkloadsForControl(workloadScanData, control, framework.name),
            Cell: ({ cell }) => cell.getValue(),
            gridTemplate: 'auto',
          },
          {
            id: 'Resources',
            header: 'Resources',
            // the failed and passed counts sort; the label is drawn in the cell
            accessorFn: (control: Control) =>
              countScans(workloadScanData, control, 'failed', framework.name) * 1e6 +
              countScans(workloadScanData, control, 'passed', framework.name),
            Cell: ({ row }) => makeResultsLabel(workloadScanData, row.original, framework.name),
            gridTemplate: 'auto',
          },
          {
            id: 'actions',
            header: '',
            accessorKey: 'controlID',
            enableSorting: false,
            // the form checks whether the user may create the exception; without permission,
            // it still offers its YAML for GitOps
            Cell: ({ row }) => (
              <Tooltip title="Exclude control cluster-wide">
                <IconButton
                  size="small"
                  aria-label="Exclude control cluster-wide"
                  onClick={() => setSelectedControl(row.original.controlID)}
                >
                  <Icon icon="mdi:shield-plus-outline" />
                </IconButton>
              </Tooltip>
            ),
            gridTemplate: 'min-content',
          },
        ]}
        initialState={{
          sorting: [
            {
              id: 'ID',
              desc: false,
            },
          ],
        }}
        reflectInURL="controls"
      />

      {selectedControl && (
        <GuidedClusterComplianceExceptionForm
          controlID={selectedControl}
          clusters={clusters}
          onClose={() => setSelectedControl(null)}
          onCreated={onExceptionCreated}
        />
      )}
    </SectionBox>
  );
}

/**
 * What the exceptions exclude: whole resources, and the results of controls in the other
 * resources, which countExcludedControls counts per resource.
 */
export function excludedCountsLine(resources: number, controlResults: number): string {
  return `${resources} ${resources === 1 ? 'resource' : 'resources'} and ${controlResults} ${
    controlResults === 1 ? 'control result' : 'control results'
  }`;
}

function makeSeverityLabel(baseScore: number, hasFailedScans: boolean) {
  const severity = complianceSeverity(baseScore);
  let status: StatusLabelProps['status'] = '';

  if (hasFailedScans) {
    status = 'error';
  } else {
    status = 'success';
  }

  if (baseScore >= 7.0 && hasFailedScans) {
    return <StatusLabel status={status}>{severity}</StatusLabel>;
  } else {
    return severity;
  }
}

export function complianceSeverity(baseScore: number) {
  let severity: string;

  if (baseScore < 0.1) {
    severity = 'None';
  } else if (baseScore < 4.0) {
    severity = 'Low';
  } else if (baseScore < 7.0) {
    severity = 'Medium';
  } else if (baseScore < 9.0) {
    severity = 'High';
  } else {
    severity = 'Critical';
  }
  return severity;
}

function makeResultsLabel(
  workloadScanData: WorkloadConfigurationScanSummary[],
  control: Control,
  frameworkName: string
) {
  const failCount = countScans(workloadScanData, control, 'failed', frameworkName);
  const passedCount = countScans(workloadScanData, control, 'passed', frameworkName);

  if (failCount > 0) {
    return (
      <HeadlampLink
        routeName={RoutingName.KubescapeControlResults}
        params={{
          control: control.controlID,
        }}
      >
        <div>
          {failCount} Failed, {passedCount} Accepted
        </div>
      </HeadlampLink>
    );
  } else {
    return passedCount;
  }
}

/**
 * Reads the configuration scans of the clusters into the cache, which other pages share, and
 * applies the security exceptions to them. The scans of other clusters are dropped from the
 * cache, unless keepOtherClusters is set, as by a page of one of the selected clusters.
 *
 * @returns A copy of the cached scans.
 */
export async function readConfigurationScans(
  clusters: string[],
  kubescapeConfig: KubescapeConfig,
  continueReading: React.MutableRefObject<boolean>,
  setLoading: (loading: boolean) => void,
  setProgressMessage: React.Dispatch<React.SetStateAction<string>>,
  options: {
    keepOtherClusters?: boolean;
    // what the read read and how long it took, when it ends
    onStatistics?: (statistics: ReadStatistics) => void;
  } = {}
): Promise<WorkloadConfigurationScanSummary[]> {
  const statistics = readRecorder.start('configuration scans');
  try {
    initQueryTasks(clusters, setProgressMessage, kubescapeConfig, !!options.keepOtherClusters);
    await handleQueryTasks(
      configurationScanContext.queryTasks.filter(task => clusters.includes(task.cluster)),
      continueReading,
      setLoading
    );
    await applySecurityExceptions(clusters);
  } finally {
    readRecorder.finish(statistics);
    options.onStatistics?.(statistics);
  }
  return [...configurationScanContext.workloadScans];
}

// Marks the scans that SecurityExceptions apply to. Exceptions only apply to scans from the
// cluster they are defined in. Where the scanners do not apply them, the plugin does.
async function applySecurityExceptions(clusters: string[]) {
  const errors: ClusterError[] = [];
  await Promise.all(
    clusters.map(async cluster => {
      const clusterScans = configurationScanContext.workloadScans.filter(
        scan => scan.metadata.cluster === cluster
      );
      if (scannersApplyExceptions(await readClusterSetup(cluster))) {
        markScannerExceptions(clusterScans);
        return;
      }
      const phase = readRecorder.phase(cluster, 'security exceptions');
      const exceptions = await fetchSecurityExceptions(
        cluster,
        clusterScans,
        [],
        getAllowedNamespaces(cluster)
      ).catch((error: unknown) => ({
        namespaced: [],
        cluster: [],
        namespaceLabelsByName: new Map(),
        errors: [errorMessage(error)],
      }));
      phase.items(exceptions.namespaced.length + exceptions.cluster.length);
      if (exceptions.errors?.length) phase.failure(exceptions.errors.length);
      phase.end();
      if (exceptions.errors?.length) {
        errors.push({ cluster, message: exceptions.errors.join('; ') });
      }
      applySecurityExceptionsToWorkloadScans(clusterScans, exceptions);
    })
  );
  // the errors of the other clusters in the cache stay
  configurationScanContext.exceptionErrors = [
    ...configurationScanContext.exceptionErrors.filter(error => !clusters.includes(error.cluster)),
    ...errors,
  ];
}

/** Whether the task is one of the cache, rather than one that the cache dropped. */
function isCurrentTask(task: QueryTask) {
  return configurationScanContext.queryTasks.includes(task);
}

function initQueryTasks(
  clusters: string[],
  setProgressMessage: React.Dispatch<React.SetStateAction<string>>,
  kubescapeConfig: KubescapeConfig,
  keepOtherClusters: boolean
) {
  reportProgress = message => setProgressMessage(message);
  // remove queryTask and data from clusters that are no more selected (unless kept) or where
  // allowed namespaces are changed
  const invalidated = new Set(
    configurationScanContext.queryTasks
      .filter(
        queryTask =>
          (!keepOtherClusters && !clusters.includes(queryTask.cluster)) ||
          isAllowedNamespaceUpdated(queryTask)
      )
      .map(queryTask => queryTask.cluster)
  );
  configurationScanContext.queryTasks = configurationScanContext.queryTasks.filter(
    queryTask => !invalidated.has(queryTask.cluster)
  );
  configurationScanContext.workloadScans = configurationScanContext.workloadScans.filter(
    scan => !invalidated.has(scan.metadata.cluster)
  );
  configurationScanContext.exceptionErrors = configurationScanContext.exceptionErrors.filter(
    error => !invalidated.has(error.cluster)
  );

  // add queryTask for new selected clusters
  for (const cluster of clusters) {
    if (!configurationScanContext.queryTasks.find(q => q.cluster === cluster)) {
      configurationScanContext.queryTasks.push({
        cluster: cluster,
        allowedNamespaces: getAllowedNamespaces(cluster),
        continuation: '',
        objectClass: workloadConfigurationScanSummaryClass,
        pageSize: kubescapeConfig?.pageSize || 50,
        handleData: (queryTask: QueryTask, items: any[]) => {
          // a page read for a task that the cache dropped, as its cluster was deselected or its
          // allowed namespaces changed, is not stored: the cluster would get it twice when the
          // cluster is read again
          if (!isCurrentTask(queryTask)) return;
          configurationScanContext.workloadScans.push(...items);
          reportProgress(`Reading ${configurationScanContext.workloadScans.length} scans...`);
        },
        // a namespace at a time, six at once: the storage reads the objects of one list one
        // after the other
        read: (queryTask, continueReading) =>
          readRecorder.time(queryTask.cluster, 'configuration scans', counter =>
            readPerNamespace(queryTask, continueReading, {
              counter,
              onProgress: (read, total) => {
                if (!isCurrentTask(queryTask)) return;
                reportProgress(
                  `Reading ${configurationScanContext.workloadScans.length} scans, ${read} of ${total} namespaces...`
                );
              },
            })
          ),
      });
    }
  }
}
