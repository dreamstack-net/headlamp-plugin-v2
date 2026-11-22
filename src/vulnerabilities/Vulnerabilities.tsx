/* 
  Overview page for vulnerability issues, workloads and images. 
*/
import { Icon } from '@iconify/react';
import { ApiError } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import {
  Link as HeadlampLink,
  SectionBox,
  ShowHideLabel,
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
import { MutableRefObject, useEffect, useMemo, useRef, useState } from 'react';
import { getAllowedNamespaces } from '../common/clusterContext';
import { isAllowedNamespaceUpdated } from '../common/clusterContext';
import { ClusterErrors } from '../common/ClusterErrors';
import { KubescapeConfig, kubescapeConfigStore } from '../common/config-store';
import { ErrorMessage } from '../common/ErrorMessage';
import { ProgressIndicator, ProgressLine, useCurrentReadFlag } from '../common/ProgressIndicator';
import { ReadRecorder, ReadStatistics, readSummary } from '../common/readStatistics';
import {
  getItemFromSessionStorage,
  KubescapeSettings,
  setItemInSessionStorage,
  useSessionStorage,
} from '../common/sessionStorage';
import { SetupCheck } from '../common/SetupCheck';
import makeSeverityLabel from '../common/SeverityLabel';
import HeadlampTable from '../common/Table';
import { throttle } from '../common/throttle';
import { useURLSearchParam } from '../common/url';
import { GuidedClusterVulnerabilityExceptionForm } from '../exceptions/GuidedClusterVulnerabilityExceptionForm';
import { RoutingName, useHLSelectedClusters } from '../index';
import { vulnerabilityManifestClass, vulnerabilityManifestSummaryClass } from '../model';
import { handleListPaginationTasks, QueryTask, queryTaskErrors, readPerNamespace } from '../query';
import { VulnerabilityManifestSummary } from '../softwarecomposition/VulnerabilityManifestSummary';
import { CVEScan, getCVEList } from './cveList';
import { exploitIds } from './exploitData';
import ImageListView from './ImageList';
import {
  exploitColumns,
  exploitCsvHeader,
  exploitCsvValues,
  ExploitDataErrors,
  knownExploitedEmptyMessage,
  KnownExploitedSwitch,
  useExploitData,
  WithExploit,
  withExploits,
} from './KnownExploited';
import { openStoredReports, readReports, StoredReports } from './manifestReader';
import { pruneReportCache, reportCacheEnabled } from './reportCache';
import WorkloadScanListView from './ResourceList';
import {
  getImageScanKey,
  ImageScan,
  imageScansChanged,
  invalidateScanClusters,
  linkWorkloadScans,
  reportNameKey,
  toWorkloadScan,
  unreadReferences,
  VulnerabilityContext,
  WorkloadScan,
} from './scanData';
import UpgradeListView from './UpgradeList';

export type { ImageScan, WorkloadScan } from './scanData';

// A VulnerabilityManifestSummary holds counts and two references, about a kilobyte
const summaryPageSize = 500;

// workloadScans are cached in global scope because it is an expensive query for the API server
export const vulnerabilityContext: VulnerabilityContext = {
  workloadScans: [],
  imageScans: new Map<string, ImageScan>(),
  queryTasks: [],
};

// the reads in progress, in the order they began, with where each shows the progress; the pages
// share the reads of the cache
const progressReporters: Array<{
  report: (message: string) => void;
  continueReading: { current: boolean };
}> = [];

/**
 * Shows the progress of the reads on the page that asked to read last and still reads. A page
 * that stopped, such as a search that was closed, leaves the progress to the page before it,
 * which may wait for the same reports.
 */
function reportProgress(message: string) {
  for (let i = progressReporters.length - 1; i >= 0; i--) {
    if (progressReporters[i].continueReading.current) {
      progressReporters[i].report(message);
      return;
    }
  }
}

// the statistics of the reads in progress
const readRecorder = new ReadRecorder();

// whether the reports are kept between sessions, as the settings of the last read say
let keepReports = true;

// the reads in progress that show the scans while the reports arrive
const scanListeners = new Set<() => void>();

// the tasks that read the summaries, which are read before the reports of all clusters
const summaryTasks = new WeakSet<QueryTask>();

// the reports handed to the cache at a time, so the workloads are linked to them in batches
const manifestBatch = 25;

// the scans that a page gets at most this often while the reports are read
const scanUpdateIntervalMs = 500;

/** The line about a read of the vulnerability scans that the page shows. */
export function vulnerabilityReadSummary(statistics: ReadStatistics): string | undefined {
  return readSummary(statistics, [
    { noun: 'workloads', one: 'workload', phases: ['summaries'] },
    { noun: 'image reports', one: 'image report', phases: ['cached reports', 'reports'] },
  ]);
}

/**
 * Reads the reports that the summaries of the task's cluster refer to and that are not in the
 * cache, several at a time. With the reports kept between sessions, the unchanged ones come from
 * the browser storage. A stopped read, or reports that could not be read, leave the task to be
 * continued.
 */
async function readReferencedManifests(
  task: QueryTask,
  continueReading: { current: boolean },
  missing: Set<string>
) {
  const batch: ImageScan[] = [];
  const flush = () => {
    if (batch.length > 0) task.handleData(task, batch.splice(0));
  };
  // the reports that failed in this read, which the next read tries again
  const failed = new Set<string>();
  const errors: string[] = [];
  let stopped = false;
  // the stored reports and the versions of the cluster's reports, listed once per read
  let stored: StoredReports | undefined;
  let listed = false;
  // other reads of the summaries, such as of a namespace that failed before, may add workloads
  // while the reports are read, so it reads on until none of them misses a report
  for (;;) {
    const references = unreadReferences(
      vulnerabilityContext.workloadScans,
      vulnerabilityContext.imageScans,
      task.cluster,
      new Set([...missing, ...failed])
    );
    if (references.length === 0) break;
    if (!listed && keepReports) {
      listed = true;
      stored = await readRecorder.time(task.cluster, 'report versions', counter =>
        openStoredReports(task.cluster, task.allowedNamespaces, counter)
      );
    }
    const result = await readReports(task.cluster, references, {
      continueReading,
      stored,
      phase: name => readRecorder.phase(task.cluster, name),
      onImageScan: scan => {
        batch.push(scan);
        if (batch.length >= manifestBatch) flush();
      },
      onProgress: (read, total) =>
        reportProgress(`${task.cluster}: Reading ${read} of ${total} image reports...`),
    });
    flush();
    for (const reference of result.missing)
      missing.add(reportNameKey(task.cluster, reference.name));
    for (const reference of result.failed) failed.add(reportNameKey(task.cluster, reference.name));
    errors.push(...result.errors);
    if (result.stopped) {
      stopped = true;
      break;
    }
  }
  task.error =
    errors.length > 0
      ? `${errors.length} image reports could not be read: ${errors.slice(0, 3).join('; ')}`
      : undefined;
  task.continuation = stopped || errors.length > 0 ? '' : undefined;
  // at most once an hour, the reports no longer used are removed from the browser storage,
  // without holding up the read; it never fails
  if (stored) pruneReportCache();
}

// The tabs of the page, by the name with which a link opens one: ?tab=upgrades
export const vulnerabilityTabs = ['cves', 'resources', 'images', 'upgrades'] as const;
export type VulnerabilityTab = (typeof vulnerabilityTabs)[number];

/** The search of a link to the page that opens the tab. */
export function vulnerabilityTabSearch(tab: VulnerabilityTab): string {
  return `?tab=${tab}`;
}

export default function KubescapeVulnerabilities() {
  const pluginConfig = kubescapeConfigStore.useConfig();
  const kubescapeConfig = pluginConfig() as KubescapeConfig;

  // the scans of the selected clusters, shown once their summaries are read and filled in as
  // the reports arrive
  const [workloadScanData, setWorkloadScanData] = useState<WorkloadScan[] | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [progressMessage, setProgressMessage] = useState('Reading Kubescape scans');
  const [error, setError] = useState<ApiError | null>(null);
  // what the last read of the page read, and how long it took
  const [readLine, setReadLine] = useState<string | undefined>();
  const clusters = useHLSelectedClusters();
  const clusterKey = clusters.join(',');
  // the flag of the current read, which the Cancel button of the progress indicator clears
  const reading = useRef<MutableRefObject<boolean>>({ current: true });
  // what the Cancel button of the progress stops
  const currentRead = useCurrentReadFlag(reading);
  // More scans reads on where reading stopped
  const [readMore, setReadMore] = useState(0);

  // the tab a link asked for, which the page keeps showing when it comes back
  const [tabParam, clearTabParam] = useURLSearchParam('tab');
  const linkedTab = vulnerabilityTabs.indexOf(tabParam as VulnerabilityTab);
  useEffect(() => {
    if (linkedTab >= 0) setItemInSessionStorage(KubescapeSettings.VulnerabilityTab, linkedTab);
  }, [linkedTab]);

  // the scans of other clusters are not shown while the selected ones are read; reading more
  // keeps showing what was read
  useEffect(() => {
    setWorkloadScanData(null);
  }, [clusterKey]);

  // Headlamp keeps the page when clusters are added to or removed from the URL, so the scans are
  // read again for the clusters; each read has its own flag, so the read it replaces stops
  useEffect(() => {
    let active = true;
    const continueReading = { current: true };
    reading.current = continueReading;
    setError(null);
    setReadLine(undefined);
    readVulnerabilityScans(
      clusters,
      kubescapeConfig,
      continueReading,
      loading => active && setLoading(loading),
      message => active && setProgressMessage(message),
      {
        // new arrays of new workload objects, so the tables draw the rows that changed
        onScans: scans => active && setWorkloadScanData(scans),
        onStatistics: statistics => active && setReadLine(vulnerabilityReadSummary(statistics)),
      }
    )
      .then(scans => {
        if (active) setWorkloadScanData(scans);
      })
      .catch(error => {
        console.error('Failed to read the vulnerability scans', error);
        if (!active) return;
        setError(error);
        setLoading(false);
      });
    return () => {
      active = false;
      continueReading.current = false;
    };
    // clusterKey covers clusters, which is a new array on every render
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clusterKey, readMore]);

  return (
    <>
      <h1>Vulnerabilities</h1>
      <SetupCheck features={['vulnerabilities']} />
      {error && <ErrorMessage error={error} />}
      {!loading && (
        <ClusterErrors
          errors={queryTaskErrors(vulnerabilityContext.queryTasks)}
          what="all vulnerability scans"
        />
      )}
      {!error && !loading && (
        <Stack direction="row" spacing={2} alignItems="center">
          <Typography variant="body1" component="div">
            {vulnerabilityContext.workloadScans.length} scans{' '}
          </Typography>
          {clusters.length > 1 && (
            <HeadlampLink routeName={RoutingName.KubescapeClusterComparison}>
              Compare clusters
            </HeadlampLink>
          )}
          {vulnerabilityContext.queryTasks.some(q => q.continuation !== undefined) && (
            <Button
              // shows the scans that were read in addition to the ones already shown
              onClick={() => setReadMore(count => count + 1)}
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

      {!error && loading && !workloadScanData && (
        <Box sx={{ padding: 2 }}>
          <ProgressIndicator continueReading={currentRead} progressMessage={progressMessage} />
        </Box>
      )}

      {!error && loading && workloadScanData && (
        <ProgressLine continueReading={currentRead} progressMessage={progressMessage} />
      )}

      {!error && workloadScanData && (
        <HeadlampTabs
          defaultIndex={
            linkedTab >= 0
              ? linkedTab
              : getItemFromSessionStorage(KubescapeSettings.VulnerabilityTab) ?? 0
          }
          onTabChanged={tabIndex => {
            setItemInSessionStorage(KubescapeSettings.VulnerabilityTab, tabIndex);
            // the tab the user chose, also when the tabs are shown again after reading more
            if (tabParam) clearTabParam();
          }}
          tabs={[
            {
              label: 'CVEs',
              component: <CVEListView workloadScans={workloadScanData} />,
            },
            {
              label: 'Resources',
              component: <WorkloadScanListView workloadScans={workloadScanData} />,
            },
            {
              label: 'Images',
              component: <ImageListView workloadScans={workloadScanData} />,
            },
            {
              label: 'Upgrades',
              component: <UpgradeListView workloadScans={workloadScanData} />,
            },
          ]}
          ariaLabel="Navigation Tabs"
        />
      )}
    </>
  );
}

type CVERow = WithExploit<CVEScan>;

const cveExploitIds = (cve: CVEScan) => exploitIds(cve.CVE, cve.relatedIds);

/** The list of the CVEs of the scans; exported for tests. */
export function CVEListView(props: Readonly<{ workloadScans: WorkloadScan[] }>) {
  const { workloadScans } = props;
  const [isRelevantCVESwitchChecked, setIsRelevantCVESwitchChecked] = useSessionStorage<boolean>(
    KubescapeSettings.RelevantCVEs,
    false
  );
  const [isFixedCVESwitchChecked, setIsFixedCVESwitchChecked] = useSessionStorage<boolean>(
    KubescapeSettings.FixedCVEs,
    false
  );
  const [exploitedOnly, setExploitedOnly] = useState(false);
  const [exceptionCves, setExceptionCves] = useState<string[] | null>(null);
  // clears the selection once the exception for the selected CVEs exists
  const clearSelection = useRef<() => void>(() => {});

  // built once per set of scans; selecting rows or opening a dialog renders again
  const cveList = useMemo(() => getCVEList(workloadScans), [workloadScans]);
  // the EPSS scores of the CVEs with the highest CVSS score, at the top of the list, first
  const cveIds = useMemo(
    () => [...cveList].sort((a, b) => b.baseScore - a.baseScore).flatMap(cve => cveExploitIds(cve)),
    [cveList]
  );
  const exploitData = useExploitData(cveIds);
  const { settings: exploitSettings } = exploitData;
  // new rows when the exploit data arrives, so that the table draws them again
  const cveRows = useMemo(
    () => withExploits(cveList, cveExploitIds, exploitData),
    [cveList, exploitData]
  );
  const showExploitedOnly = exploitSettings.knownExploited && exploitedOnly;
  const cveListSwitched = useMemo(
    () =>
      cveRows.filter(
        cve =>
          (!isRelevantCVESwitchChecked || cve.relevant === undefined || cve.relevant) &&
          (!isFixedCVESwitchChecked || cve.fixed)
      ),
    [cveRows, isRelevantCVESwitchChecked, isFixedCVESwitchChecked]
  );
  const cveListFiltered = useMemo(
    () => (showExploitedOnly ? cveListSwitched.filter(cve => cve.exploit?.kev) : cveListSwitched),
    [cveListSwitched, showExploitedOnly]
  );
  const knownExploitedCount = useMemo(
    () => (exploitData.kev ? cveListFiltered.filter(cve => cve.exploit?.kev).length : undefined),
    [cveListFiltered, exploitData.kev]
  );

  return (
    <>
      <h5>
        {workloadScans.length} workload scans, {cveListFiltered.length} CVE issues
        {knownExploitedCount !== undefined && `, ${knownExploitedCount} known to be exploited`}
      </h5>
      <ExploitDataErrors data={exploitData} />
      <SectionBox>
        <HeadlampTable
          toolbarStart={
            <>
              <FormControlLabel
                checked={isRelevantCVESwitchChecked}
                control={<Switch color="primary" />}
                label={'Relevant'}
                onChange={(_event, checked) => {
                  setIsRelevantCVESwitchChecked(checked);
                }}
              />
              <FormControlLabel
                checked={isFixedCVESwitchChecked}
                control={<Switch color="primary" />}
                label={'Fixed'}
                onChange={(_event, checked) => {
                  setIsFixedCVESwitchChecked(checked);
                }}
              />
              <KnownExploitedSwitch
                settings={exploitSettings}
                checked={exploitedOnly}
                onChange={setExploitedOnly}
              />
            </>
          }
          emptyMessage={
            showExploitedOnly && cveListSwitched.length > 0
              ? knownExploitedEmptyMessage(exploitData, 'CVEs')
              : undefined
          }
          csvExport={{
            fileName: 'kubescape-cves.csv',
            header: [
              'CVE',
              'Severity',
              'CVSS',
              ...exploitCsvHeader(exploitSettings),
              'Components',
              'Relevant',
              'Fixed',
              'Images',
              'Workloads',
              'Description',
            ],
            rows: () =>
              cveListFiltered.map(cve => [
                cve.CVE,
                cve.severity,
                cve.baseScore,
                ...exploitCsvValues(cve.exploit, exploitSettings),
                Array.from(cve.artifacts).join('; '),
                cve.relevant === undefined ? 'Unknown' : cve.relevant ? 'Yes' : 'No',
                cve.fixed ? 'Yes' : 'No',
                Array.from(cve.images).join('; '),
                Array.from(cve.workloads).join('; '),
                cve.description,
              ]),
          }}
          data={cveListFiltered}
          columns={[
            {
              header: 'Severity',
              accessorFn: (item: CVERow) => item.severity,
              Cell: ({ cell }) => makeSeverityLabel(cell.row.original.severity),
              gridTemplate: '0.2fr',
            },
            {
              header: 'CVE ID',
              accessorFn: (item: CVERow) => item.CVE,
              Cell: ({ cell }) => (
                <HeadlampLink
                  routeName={RoutingName.KubescapeCVEResults}
                  params={{
                    cve: cell.getValue(),
                  }}
                >
                  {cell.getValue()}
                </HeadlampLink>
              ),
              gridTemplate: 'auto',
            },
            {
              id: 'Score',
              header: 'CVSS',
              accessorFn: (item: CVERow) => item.baseScore,
              gridTemplate: 'min-content',
            },
            ...exploitColumns<CVERow>(exploitSettings),
            {
              header: 'Component',
              // text, so the table can search and sort it
              accessorFn: (item: CVERow) => Array.from(item.artifacts).join('\n'),
              Cell: ({ cell }) => <div style={{ whiteSpace: 'pre-line' }}>{cell.getValue()}</div>,
              gridTemplate: 'auto',
            },
            {
              header: 'Relevant',
              accessorFn: (item: CVERow) =>
                item.relevant === undefined ? 'Unknown' : item.relevant ? 'Yes' : 'No',
              gridTemplate: '1fr',
            },
            {
              header: 'Fixed',
              accessorFn: (item: CVERow) => (item.fixed ? 'Yes' : ''),
              gridTemplate: '1fr',
            },
            {
              header: 'Images',
              accessorFn: (item: CVERow) => item.images.size,
              gridTemplate: 'min-content',
            },
            {
              header: 'Workloads',
              accessorFn: (item: CVERow) => item.workloads.size,
              Cell: ({ cell, row }) => (
                <HeadlampLink
                  routeName={RoutingName.KubescapeCVEResults}
                  params={{
                    cve: row.original.CVE,
                  }}
                >
                  {cell.getValue()}
                </HeadlampLink>
              ),
              gridTemplate: 'min-content',
            },
            {
              header: 'Description',
              accessorKey: 'description',
              Cell: ({ cell }) => <ShowHideLabel>{cell.getValue()}</ShowHideLabel>,
              gridTemplate: 'auto',
            },
            {
              id: 'actions',
              header: '',
              // a value per CVE, so that the button of each row is its own
              accessorFn: (item: CVERow) => item.CVE,
              // rendered for the rows on the page only, not for every CVE; the form also offers
              // the exception as YAML, so it opens without the permission to create one
              Cell: ({ row }) => (
                <Tooltip title="Exclude CVE cluster-wide">
                  <IconButton
                    size="small"
                    aria-label="Exclude CVE cluster-wide"
                    onClick={() => setExceptionCves([row.original.CVE])}
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
                id: 'Score',
                desc: true,
              },
            ],
          }}
          reflectInURL="cve"
          enableRowSelection
          getRowId={(item: CVERow) => item.CVE}
          renderRowSelectionToolbar={({ table }) => {
            const selected = table.getSelectedRowModel().rows.map(row => row.original.CVE);
            clearSelection.current = () => table.resetRowSelection();
            return (
              <Button
                variant="contained"
                size="small"
                startIcon={<Icon icon="mdi:shield-plus-outline" />}
                onClick={() => setExceptionCves(selected)}
              >
                Exclude {selected.length} {selected.length === 1 ? 'CVE' : 'CVEs'} cluster-wide
              </Button>
            );
          }}
        />
      </SectionBox>

      {exceptionCves && (
        <GuidedClusterVulnerabilityExceptionForm
          cveIds={exceptionCves}
          clusters={clustersWithCves(workloadScans, exceptionCves)}
          onClose={() => setExceptionCves(null)}
          onCreated={() => clearSelection.current()}
        />
      )}
    </>
  );
}

/** The clusters in which a workload has one of the CVEs, where their exception is created. */
export function clustersWithCves(workloadScans: WorkloadScan[], cveIds: string[]): string[] {
  const wanted = new Set(cveIds);
  const clusters = new Set<string>();
  for (const scan of workloadScans) {
    if (clusters.has(scan.cluster)) continue;
    if (scan.imageScan?.matches.some(match => wanted.has(match.vulnerability.id))) {
      clusters.add(scan.cluster);
    }
  }
  return [...clusters];
}

export interface VulnerabilityReadOptions {
  // the scans as they are read: once the summaries of all clusters are read, then while the
  // reports arrive, at most twice a second; each time a new array
  onScans?: (scans: WorkloadScan[]) => void;
  // what the read read and how long it took, when it ends
  onStatistics?: (statistics: ReadStatistics) => void;
}

/**
 * Reads the vulnerability scans of the clusters into the cache, which other pages share: first
 * the summaries of all clusters, which name the workloads and count their findings, then the
 * reports they refer to.
 *
 * @returns A copy of the cached workload scans.
 */
export async function readVulnerabilityScans(
  clusters: string[],
  kubescapeConfig: KubescapeConfig,
  continueReading: React.MutableRefObject<boolean>,
  setLoading: (loading: boolean) => void,
  setProgressMessage: React.Dispatch<React.SetStateAction<string>>,
  options: VulnerabilityReadOptions = {}
): Promise<WorkloadScan[]> {
  const statistics = readRecorder.start('vulnerability scans');
  const { onScans } = options;
  const updates =
    onScans &&
    throttle(() => onScans([...vulnerabilityContext.workloadScans]), scanUpdateIntervalMs);
  // the progress goes to this read while it is the last one that still reads
  const reporter = {
    report: (message: string) => setProgressMessage(message),
    continueReading,
  };
  progressReporters.push(reporter);
  try {
    keepReports = reportCacheEnabled(kubescapeConfig);
    initQueryTasks(clusters, kubescapeConfig);
    const tasks = vulnerabilityContext.queryTasks;
    const summaries = tasks.filter(task => summaryTasks.has(task));
    // the loading ends with the reports
    await handleListPaginationTasks(summaries, continueReading, loading => {
      if (loading) setLoading(true);
    });
    onScans?.([...vulnerabilityContext.workloadScans]);

    // the reports of the clusters whose summaries could be read, or some of their namespaces
    const unread = new Set(
      summaries
        .filter(task => task.error && task.continuation !== undefined && !task.failedNamespaces)
        .map(task => task.cluster)
    );
    if (updates) scanListeners.add(updates.schedule);
    await handleListPaginationTasks(
      tasks.filter(task => !summaryTasks.has(task) && !unread.has(task.cluster)),
      continueReading,
      setLoading
    );
  } finally {
    progressReporters.splice(progressReporters.indexOf(reporter), 1);
    if (updates) {
      scanListeners.delete(updates.schedule);
      updates.cancel();
    }
    readRecorder.finish(statistics);
    options.onStatistics?.(statistics);
  }
  return [...vulnerabilityContext.workloadScans];
}

/**
 * Whether the task is one of the cache. A read that began before its cluster was deselected, or
 * its allowed namespaces changed, keeps the pages it still reads out of the cache: the cache no
 * longer has a task for them, so they would stay when the cluster is selected again and be read
 * a second time.
 */
function isCurrentTask(task: QueryTask) {
  return vulnerabilityContext.queryTasks.includes(task);
}

function initQueryTasks(clusters: string[], kubescapeConfig: KubescapeConfig) {
  const storeImageScans = (task: QueryTask, items: ImageScan[]) => {
    if (!isCurrentTask(task)) return;
    for (const imageScan of items) {
      vulnerabilityContext.imageScans.set(getImageScanKey(imageScan), imageScan);
    }
    imageScansChanged(vulnerabilityContext.imageScans);
    vulnerabilityContext.workloadScans = linkWorkloadScans(
      vulnerabilityContext.workloadScans,
      vulnerabilityContext.imageScans,
      task.cluster
    );
    for (const listener of scanListeners) listener();
  };

  invalidateScanClusters(vulnerabilityContext, clusters, isAllowedNamespaceUpdated);

  // add new query tasks: the summaries of the workloads, then the reports they refer to
  for (const cluster of clusters) {
    if (!vulnerabilityContext.queryTasks.find(q => q.cluster === cluster)) {
      const task = {
        cluster: cluster,
        allowedNamespaces: getAllowedNamespaces(cluster),
        continuation: '',
        pageSize: kubescapeConfig?.pageSize || 50,
      };
      // the keys of the references whose reports do not exist, which are not asked for again
      const missing = new Set<string>();
      const manifests: QueryTask = {
        ...task,
        objectClass: vulnerabilityManifestClass,
        // the reports as the cache keeps them
        handleData: storeImageScans,
        read: (manifestTask, continueReading) =>
          readReferencedManifests(manifestTask, continueReading, missing),
      };
      const summaries: QueryTask = {
        ...task,
        // summaries are small, so they are read in larger pages
        pageSize: Math.max(task.pageSize, summaryPageSize),
        objectClass: vulnerabilityManifestSummaryClass,
        handleData: (summaryTask: QueryTask, items: VulnerabilityManifestSummary[]) => {
          if (!isCurrentTask(summaryTask)) return;
          for (const item of items) {
            const workload = toWorkloadScan(item, vulnerabilityContext.imageScans);
            if (!workload.name || !workload.namespace) continue; // invalid summary from kubescape
            vulnerabilityContext.workloadScans.push(workload);
          }
          // the reports of these workloads are read next
          manifests.continuation = '';
          reportProgress(
            `${summaryTask.cluster}: Reading ${vulnerabilityContext.workloadScans.length} Workloads...`
          );
        },
        // a namespace at a time, six at once: the storage reads the objects of one list one
        // after the other
        read: (summaryTask, continueReading) =>
          readRecorder.time(summaryTask.cluster, 'summaries', counter =>
            readPerNamespace(summaryTask, continueReading, {
              counter,
              onProgress: (read, total) => {
                if (!isCurrentTask(summaryTask)) return;
                reportProgress(
                  `${summaryTask.cluster}: Reading ${vulnerabilityContext.workloadScans.length} workloads, ${read} of ${total} namespaces...`
                );
              },
            })
          ),
      };
      summaryTasks.add(summaries);
      vulnerabilityContext.queryTasks.push(summaries, manifests);
    }
  }

  return vulnerabilityContext.queryTasks;
}
