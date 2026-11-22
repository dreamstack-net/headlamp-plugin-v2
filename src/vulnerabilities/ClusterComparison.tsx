/*
  Compares the images of the selected clusters, such as clusters that are upgraded in turn: the
  versions each cluster runs with their CVEs, where the clusters differ, and which cluster runs a
  version with CVEs that the version of another cluster does not have. An image opens a dialog
  with its versions per cluster, the upgrades it can take and the workloads that run it.
*/
import { Icon } from '@iconify/react';
import {
  Link as HeadlampLink,
  SectionBox,
  TableColumn,
  Tabs as HeadlampTabs,
} from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import {
  Alert,
  Box,
  Button,
  Card,
  CardActionArea,
  Chip,
  Dialog,
  DialogContent,
  DialogTitle,
  IconButton,
  Link,
  MenuItem,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import { Fragment, MutableRefObject, ReactNode, useEffect, useMemo, useRef, useState } from 'react';
import { ClusterErrors } from '../common/ClusterErrors';
import { KubescapeConfig, kubescapeConfigStore } from '../common/config-store';
import { errorMessage } from '../common/errors';
import { ProgressIndicator, useCurrentReadFlag } from '../common/ProgressIndicator';
import { KubescapeSettings, useSessionStorage } from '../common/sessionStorage';
import { SetupCheck } from '../common/SetupCheck';
import { SeverityCountStack } from '../common/SeverityCountBox';
import HeadlampTable from '../common/Table';
import { RoutingName, useHLSelectedClusters } from '../index';
import { queryTaskErrors } from '../query';
import {
  candidateOrderText,
  candidateWorkloads,
  ClusterComparison,
  ClusterVersion,
  compareClusters,
  CveCounts,
  CveDelta,
  describeCandidate,
  describeDifference,
  filterRepositories,
  ImageFilter,
  listClusters,
  recommendedUpgrade,
  RepositoryComparison,
  repositoryStatus,
  repositoryStatusParts,
  severityCount,
  severityText,
  splitRepository,
  StatusPart,
  TagVersion,
  UpgradeCandidate,
  UpgradeOption,
  Variant,
  variantWorkloads,
  WorkloadReference,
} from './imagesAcrossClusters';
import {
  EndOfLifeLabel,
  ImageInCluster,
  ImageVersion,
  imageVersionMapKey,
  LatestVersionLabel,
  useImageVersions,
  useImageVersionSettings,
} from './ImageVersion';
import { workloadLabel, WorkloadScan } from './scanData';
import { readVulnerabilityScans, vulnerabilityContext } from './Vulnerabilities';

export default function KubescapeClusterComparison() {
  const clusters = useHLSelectedClusters();
  return (
    <>
      <h1>Images across clusters</h1>
      {clusters.length < 2 ? (
        <SelectSeveralClusters clusters={clusters} />
      ) : (
        <Comparison clusters={clusters} />
      )}
    </>
  );
}

function SelectSeveralClusters(props: Readonly<{ clusters: string[] }>) {
  const { clusters } = props;
  return (
    <Alert severity="info">
      <Typography variant="body2" sx={{ mb: 1 }}>
        This page compares the images that the selected clusters run: the versions in each cluster
        with their CVEs, and the CVEs of a version that the version of another cluster does not
        have.{' '}
        {clusters.length === 1 ? `Only ${clusters[0]} is selected.` : 'No cluster is selected.'}
      </Typography>
      <Typography variant="body2">
        To select several clusters, open Home in Headlamp, tick the clusters in the All Clusters
        table and choose View Clusters, then open Kubescape, Vulnerabilities, Clusters. The address
        names the selected clusters joined by a plus sign, such as /c/test+production/ followed by
        the page.
      </Typography>
    </Alert>
  );
}

/** Reads the vulnerability scans of the clusters into the cache that the other pages share. */
function useVulnerabilityScans(clusters: string[]) {
  const clusterKey = clusters.join(',');
  const [scans, setScans] = useState<WorkloadScan[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState('Reading Kubescape scans');
  const [error, setError] = useState<string | null>(null);
  // Read on continues where reading stopped
  const [readMore, setReadMore] = useState(0);
  // the flag of the current read, which the Cancel button of the progress indicator clears
  const reading = useRef<MutableRefObject<boolean>>({ current: true });
  const currentRead = useCurrentReadFlag(reading);

  useEffect(() => {
    let active = true;
    // each read has a flag of its own, so a read for other clusters stops when this one starts
    const continueReading = { current: true };
    reading.current = continueReading;
    setError(null);
    readVulnerabilityScans(
      clusters,
      (kubescapeConfigStore.get() ?? {}) as KubescapeConfig,
      continueReading,
      isLoading => active && setLoading(isLoading),
      message => active && setProgress(message)
    )
      .then(result => active && setScans(result))
      .catch(err => {
        if (!active) return;
        setError(errorMessage(err));
        setLoading(false);
      });
    return () => {
      active = false;
      continueReading.current = false;
    };
    // clusterKey covers clusters, which is a new array on every render
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clusterKey, readMore]);

  return { scans, loading, progress, error, currentRead, readOn: () => setReadMore(n => n + 1) };
}

function Comparison(props: Readonly<{ clusters: string[] }>) {
  const { clusters } = props;
  const clusterKey = clusters.join(',');
  const { scans, loading, progress, error, currentRead, readOn } = useVulnerabilityScans(clusters);
  // compared once per read
  const comparison = useMemo(
    () => (scans ? compareClusters(scans, clusters) : null),
    // clusterKey covers clusters
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [scans, clusterKey]
  );
  const incomplete =
    !loading &&
    !!scans &&
    vulnerabilityContext.queryTasks.some(
      task => clusters.includes(task.cluster) && task.continuation !== undefined
    );

  return (
    <>
      <Stack
        direction="row"
        spacing={1}
        alignItems="center"
        flexWrap="wrap"
        useFlexGap
        sx={{ mb: 2 }}
      >
        <Typography variant="body2" color="text.secondary">
          Compares the images that run in
        </Typography>
        {clusters.map(cluster => (
          <Chip key={cluster} size="small" label={cluster} />
        ))}
        <Tooltip
          title={
            'Differences compare all CVEs of the reports, also those an exception accepts, as ' +
            'exceptions differ per cluster. The counts are of the open CVEs, as on the image ' +
            'pages. Versions are ordered where their tags are versions of one format.'
          }
        >
          <Box
            component="span"
            aria-label="How images are compared"
            sx={{ display: 'inline-flex', color: 'text.secondary' }}
          >
            <Icon icon="mdi:information-outline" width={18} />
          </Box>
        </Tooltip>
      </Stack>
      <SetupCheck features={['vulnerabilities']} />
      {error && (
        <Alert severity="error" sx={{ mb: 1 }}>
          Unable to read the vulnerability scans: {error}
        </Alert>
      )}
      {!loading && (
        <ClusterErrors
          errors={queryTaskErrors(vulnerabilityContext.queryTasks)}
          what="all vulnerability scans"
        />
      )}
      {loading && (
        <Box sx={{ padding: 2 }}>
          <ProgressIndicator continueReading={currentRead} progressMessage={progress} />
        </Box>
      )}
      {incomplete && (
        <Alert
          severity="warning"
          sx={{ mb: 1 }}
          action={
            <Button color="inherit" size="small" onClick={readOn}>
              Read on
            </Button>
          }
        >
          Not all scans were read, so images may seem to be missing in a cluster.
        </Alert>
      )}
      {!loading && comparison && <ComparisonView comparison={comparison} />}
    </>
  );
}

function plural(count: number, one: string, many = `${one}s`): string {
  return `${count} ${count === 1 ? one : many}`;
}

function cveCount(count: number): string {
  return plural(count, 'CVE');
}

/**
 * The workloads of which no report was read. These are mostly Jobs and CronJobs: their summary
 * stays while Kubescape's storage removes the report of an image that no pod runs, so between two
 * runs the summary names a report that is gone. The workloads are listed on request, so the note
 * stays short.
 */
function MissingReportsNote(
  props: Readonly<{ withoutReports: ClusterComparison['withoutReports'] }>
) {
  const { withoutReports } = props;
  const [shown, setShown] = useState(false);
  const total = withoutReports.reduce((sum, { workloads }) => sum + workloads.length, 0);
  return (
    <Alert
      severity="info"
      sx={{ mb: 1 }}
      action={
        <Button color="inherit" size="small" onClick={() => setShown(!shown)}>
          {shown ? 'Hide workloads' : 'Show workloads'}
        </Button>
      }
    >
      No vulnerability report was read for {plural(total, 'workload')} (
      {withoutReports
        .map(({ cluster, workloads }) => `${workloads.length} of ${cluster}`)
        .join(', ')}
      ), mostly Jobs and CronJobs: Kubescape removes the report of an image while no pod runs it.
      Their images count as possibly running in that cluster, not as missing.
      {shown && (
        <Box component="ul" sx={{ m: 0, mt: 1, pl: 2 }}>
          {withoutReports.map(({ cluster, workloads }) => (
            <li key={cluster}>
              {cluster}: {workloads.map(workload => workloadLabel(workload, false)).join(', ')}
            </li>
          ))}
        </Box>
      )}
    </Alert>
  );
}

const imageFilterLabels: Record<ImageFilter, string> = {
  differ: 'Images that differ',
  versions: 'Other versions',
  reports: 'Other reports',
  missing: 'Not in every cluster',
  newerAdds: 'Newer version adds CVEs',
  all: 'All images',
};

// the tabs of the page, by their index
const candidatesTab = 0;
const imagesTab = 1;

// the newest upstream version of each tag, by repository and tag
type Upstream = Map<string, Map<string, ImageVersion>>;

/** The image the upstream version of a tag is looked up for: one of its names, in a cluster. */
function tagLookup(tag: TagVersion): ImageInCluster {
  const version = tag.versions[0];
  return {
    image: version.imageNames[0],
    cluster: version.cluster,
    source: version.reports[0]?.source,
  };
}

/**
 * The newest upstream version of each tag, in the format of the tag, from the lookups the other
 * image pages use; empty while the setting of the image versions is off.
 */
function useUpstreamVersions(comparison: ClusterComparison): Upstream {
  const lookups = useMemo(
    () => comparison.repositories.flatMap(repository => repository.tags.map(tagLookup)),
    [comparison]
  );
  const versions = useImageVersions(lookups);
  return useMemo(
    () =>
      new Map(
        comparison.repositories.map(repository => [
          repository.repository,
          new Map(
            repository.tags.flatMap((tag): Array<[string, ImageVersion]> => {
              const found = versions.get(imageVersionMapKey(tagLookup(tag)));
              return found ? [[tag.version, found]] : [];
            })
          ),
        ])
      ),
    [comparison, versions]
  );
}

/** What the upstream versions are, or how to see them. */
function upstreamNote(enabled: boolean): string {
  return enabled
    ? ' Upstream is the newest version that the registry or project of the image publishes in ' +
        'the format of the tag.'
    : ' To compare with the newest upstream versions, switch on Show the newest version of ' +
        'images in the plugin settings.';
}

function ComparisonView(props: Readonly<{ comparison: ClusterComparison }>) {
  const { comparison } = props;
  const { withoutScans, withoutReports, upgradeCandidates } = comparison;
  const [savedFilter, setFilter] = useSessionStorage<ImageFilter>(
    KubescapeSettings.ClusterComparisonFilter,
    'differ'
  );
  // a filter of an older version of the plugin is not offered
  const filter: ImageFilter = savedFilter in imageFilterLabels ? savedFilter : 'differ';
  const [tab, setTab] = useSessionStorage<number>(
    KubescapeSettings.ClusterComparisonTab,
    candidatesTab
  );
  // the repository whose dialog is open
  const [opened, setOpened] = useState<string | null>(null);
  const upstream = useUpstreamVersions(comparison);
  const versionCounts = useMemo(
    () =>
      new Map(
        comparison.repositories.map(repository => [repository.repository, repository.tags.length])
      ),
    [comparison]
  );
  const withUpstream = useImageVersionSettings().enabled;
  const openedRepository = useMemo(
    () => comparison.repositories.find(repository => repository.repository === opened),
    [comparison, opened]
  );

  return (
    <>
      {withoutScans.length > 0 && (
        <Alert severity="info" sx={{ mb: 1 }}>
          No vulnerability scans were read of {listClusters(withoutScans)}, so the comparison leaves{' '}
          {withoutScans.length === 1 ? 'it' : 'them'} out.
        </Alert>
      )}
      {withoutReports.length > 0 && <MissingReportsNote withoutReports={withoutReports} />}
      <SummaryTiles
        comparison={comparison}
        filter={tab === imagesTab ? filter : undefined}
        candidatesShown={tab === candidatesTab}
        onFilter={chosen => {
          setFilter(chosen);
          setTab(imagesTab);
        }}
        onCandidates={() => setTab(candidatesTab)}
      />
      <HeadlampTabs
        defaultIndex={tab}
        onTabChanged={setTab}
        ariaLabel="Comparison tabs"
        tabs={[
          {
            label: 'Upgrade candidates',
            component: (
              <UpgradeCandidates
                candidates={upgradeCandidates}
                versionCounts={versionCounts}
                upstream={upstream}
                withUpstream={withUpstream}
                onOpen={setOpened}
              />
            ),
          },
          {
            label: 'Images',
            component: (
              <ImageVersions
                comparison={comparison}
                filter={filter}
                upstream={upstream}
                withUpstream={withUpstream}
                onFilter={setFilter}
                onOpen={setOpened}
              />
            ),
          },
        ]}
      />
      {openedRepository && (
        <ImageDialog
          repository={openedRepository}
          upstream={upstream.get(openedRepository.repository)}
          onClose={() => setOpened(null)}
        />
      )}
    </>
  );
}

interface Tile {
  label: string;
  value: number;
  caption: string;
  filter?: ImageFilter;
}

/**
 * The counts of the comparison: a count of images opens the Images tab with those images, and
 * the upgrade candidates their tab.
 */
function SummaryTiles(
  props: Readonly<{
    comparison: ClusterComparison;
    // the filter of the Images tab, while it is shown
    filter?: ImageFilter;
    candidatesShown: boolean;
    onFilter: (filter: ImageFilter) => void;
    onCandidates: () => void;
  }>
) {
  const { comparison, filter, candidatesShown, onFilter, onCandidates } = props;
  const { summary, upgradeCandidates } = comparison;
  const tiles: Tile[] = [
    {
      label: 'Images',
      value: summary.images,
      caption: `${summary.inSeveralClusters} in more than one cluster`,
      filter: 'all',
    },
    {
      label: 'Upgrade candidates',
      value: upgradeCandidates.length,
      caption: 'Versions with a newer version in another cluster that lacks some of their CVEs',
    },
    {
      label: 'Differ between clusters',
      value: summary.differ,
      caption: 'Other versions or reports, or not in every cluster',
      filter: 'differ',
    },
    {
      label: 'Other versions',
      value: summary.versionsDiffer,
      caption: 'Clusters run other tags',
      filter: 'versions',
    },
    {
      label: 'Other reports',
      value: summary.reportsDiffer,
      caption: 'One tag with other CVEs: rebuilt, or scanned with another database',
      filter: 'reports',
    },
    {
      label: 'Not in every cluster',
      value: summary.notInEveryCluster,
      caption:
        comparison.withoutReports.length > 0
          ? 'A selected cluster does not run them, or has no report of them'
          : 'A selected cluster does not run them',
      filter: 'missing',
    },
    {
      label: 'Newer version adds CVEs',
      value: summary.newerAddCves,
      caption: 'The newer version has CVEs the older one does not',
      filter: 'newerAdds',
    },
  ];

  return (
    <Box
      sx={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(170px, 1fr))',
        gap: 2,
        mb: 2,
      }}
    >
      {tiles.map(tile => {
        const selected = tile.filter ? tile.filter === filter : candidatesShown;
        return (
          <Card
            key={tile.label}
            variant="outlined"
            sx={{
              borderColor: selected ? 'primary.main' : undefined,
              borderWidth: selected ? 2 : 1,
            }}
          >
            <CardActionArea
              aria-pressed={selected}
              onClick={() => (tile.filter ? onFilter(tile.filter) : onCandidates())}
              sx={{
                height: '100%',
                p: 1.5,
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'flex-start',
                justifyContent: 'flex-start',
              }}
            >
              <Typography sx={{ fontSize: '1.75rem', fontWeight: 600, lineHeight: 1.2 }}>
                {tile.value}
              </Typography>
              <Typography variant="body2" sx={{ fontWeight: 500 }}>
                {tile.label}
              </Typography>
              <Typography variant="caption" color="text.secondary" component="div">
                {tile.caption}
              </Typography>
            </CardActionArea>
          </Card>
        );
      })}
    </Box>
  );
}

/** The name of an image, which opens its dialog, over the registry and path in front of it. */
function ImageName(props: Readonly<{ repository: string; onOpen: (repository: string) => void }>) {
  const { repository, onOpen } = props;
  const { name, path } = splitRepository(repository);
  return (
    <Box sx={{ minWidth: 0 }}>
      <Link
        component="button"
        variant="body2"
        title={`Versions, upgrades and workloads of ${repository}`}
        onClick={() => onOpen(repository)}
        sx={{ fontWeight: 500, textAlign: 'left', overflowWrap: 'anywhere' }}
      >
        {name}
      </Link>
      {path && (
        <Typography
          variant="caption"
          color="text.secondary"
          component="div"
          sx={{ overflowWrap: 'anywhere' }}
        >
          {path}
        </Typography>
      )}
    </Box>
  );
}

/** A tag, which may be long, in a monospace font. */
function VersionTag(props: Readonly<{ version: string }>) {
  return (
    <Box
      component="span"
      sx={{ fontFamily: 'monospace', fontSize: '0.8125rem', overflowWrap: 'anywhere' }}
    >
      {props.version}
    </Box>
  );
}

/** The report of a version in its cluster, on the image page. */
function ReportLink(props: Readonly<{ version: ClusterVersion; children: ReactNode }>) {
  const { version, children } = props;
  const report = version.reports[0];
  if (!report) return <>{children}</>;
  return (
    <HeadlampLink
      routeName={RoutingName.ImageVulnerabilityDetails}
      activeCluster={version.cluster}
      params={{ name: report.manifestName, namespace: report.namespace }}
    >
      {children}
    </HeadlampLink>
  );
}

/** A cluster that runs a version, which opens the version's report in that cluster. */
function ClusterChip(props: Readonly<{ version: ClusterVersion }>) {
  const { version } = props;
  return (
    <ReportLink version={version}>
      <Tooltip title={`The report of ${version.version} in ${version.cluster}`}>
        <Chip
          size="small"
          variant="outlined"
          label={version.cluster}
          sx={{ cursor: 'pointer', '&:hover': { backgroundColor: 'action.hover' } }}
        />
      </Tooltip>
    </ReportLink>
  );
}

function ClusterChips(props: Readonly<{ variant: Variant }>) {
  return (
    <Stack direction="row" flexWrap="wrap" useFlexGap spacing={0.5}>
      {props.variant.versions.map(version => (
        <ClusterChip key={version.cluster} version={version} />
      ))}
    </Stack>
  );
}

const orderChips: Record<
  UpgradeOption['order'],
  { color: 'success' | 'info' | 'default'; help: string }
> = {
  newer: { color: 'success', help: 'A newer version of the same tag format.' },
  'same version': {
    color: 'info',
    help: 'Another variant of the same version, such as -alpine instead of -bookworm.',
  },
  unordered: {
    color: 'default',
    help:
      'The tags are not versions of one format, such as branch builds, so which one is newer is ' +
      'unknown.',
  },
};

function OrderChip(props: Readonly<{ order: UpgradeOption['order'] }>) {
  const { order } = props;
  return (
    <Tooltip title={orderChips[order].help}>
      <Chip
        size="small"
        color={orderChips[order].color}
        variant="outlined"
        label={candidateOrderText(order)}
        sx={{ height: 20, fontSize: '0.7rem' }}
      />
    </Tooltip>
  );
}

/** A version and the clusters that run it, each opening its report. */
function VariantCell(props: Readonly<{ variant: Variant; note?: string }>) {
  const { variant, note } = props;
  return (
    <Stack spacing={0.5} alignItems="flex-start">
      <VersionTag version={variant.version} />
      <ClusterChips variant={variant} />
      {note && (
        <Typography variant="caption" color="text.secondary" sx={{ overflowWrap: 'anywhere' }}>
          {note}
        </Typography>
      )}
    </Stack>
  );
}

// Also newer: 18.4, 18.2
function alternativesNote(candidate: UpgradeCandidate): string | undefined {
  const versions = candidate.alternatives.map(option => option.to.version);
  return versions.length > 0 ? `Also newer: ${versions.join(', ')}` : undefined;
}

// the counts, padded to sort as text, most severe first; then the CVEs, which the tooltips list,
// so that the cell is drawn again when they change
function deltaValue(delta: CveDelta): string {
  const counts = [delta.critical, delta.high, delta.medium, delta.low, delta.cves.length]
    .map(count => String(count).padStart(5, '0'))
    .join('.');
  return `${counts} ${delta.cves.map(cve => cve.id).join(' ')}`;
}

// the CVEs a tooltip lists at most
const tooltipCves = 30;

function CveTooltip(props: Readonly<{ cves: CveDelta['cves']; severity: string }>) {
  const { cves, severity } = props;
  if (cves.length === 0) return <>No {severity.toLowerCase()} CVEs</>;
  const more = cves.length - tooltipCves;
  return (
    <Box>
      {cves.slice(0, tooltipCves).map(cve => (
        <div key={cve.id}>{cve.id}</div>
      ))}
      {more > 0 && <div>and {more} more</div>}
    </Box>
  );
}

function DeltaStack(props: Readonly<{ delta: CveDelta }>) {
  const { delta } = props;
  return (
    <SeverityCountStack
      count={severity => severityCount(delta, severity)}
      tooltip={severity => (
        <CveTooltip
          severity={severity}
          cves={delta.cves.filter(cve => cve.severity === severity)}
        />
      )}
    />
  );
}

/** What a move removes and adds, a line each, as narrow as a table of many columns needs. */
function DeltaPair(props: Readonly<{ removed: CveDelta; added: CveDelta }>) {
  const lines: Array<[string, CveDelta]> = [
    ['Removes', props.removed],
    ['Adds', props.added],
  ];
  return (
    <Box
      sx={{
        display: 'grid',
        gridTemplateColumns: '3.5rem max-content auto',
        columnGap: 1,
        rowGap: 0.75,
        alignItems: 'center',
      }}
    >
      {lines.map(([label, delta]) => (
        <Fragment key={label}>
          <Typography variant="caption" color="text.secondary">
            {label}
          </Typography>
          {delta.cves.length > 0 ? (
            <DeltaStack delta={delta} />
          ) : (
            <Typography variant="body2" color="text.secondary">
              None
            </Typography>
          )}
          <Typography variant="caption" color="text.secondary" sx={{ whiteSpace: 'nowrap' }}>
            {delta.cves.length > 0 ? cveCount(delta.cves.length) : ''}
          </Typography>
        </Fragment>
      ))}
    </Box>
  );
}

// the kinds as Kubernetes writes them; the labels of the summaries have them in lower case
const kindNames = new Map(
  ['CronJob', 'DaemonSet', 'Deployment', 'Job', 'Pod', 'ReplicaSet', 'StatefulSet'].map(kind => [
    kind.toLowerCase(),
    kind,
  ])
);

function kindLabel(kind: string): string {
  return kindNames.get(kind.toLowerCase()) ?? kind.charAt(0).toUpperCase() + kind.slice(1);
}

/** The vulnerability page of a workload in its cluster. */
function WorkloadLink(props: Readonly<{ workload: WorkloadReference }>) {
  const { workload } = props;
  return (
    <HeadlampLink
      routeName={RoutingName.KubescapeVulnerabilityDetails}
      activeCluster={workload.cluster}
      params={{ name: workload.manifestName, namespace: workload.namespace }}
    >
      {workload.name}
    </HeadlampLink>
  );
}

// the workloads a cell of the candidates names, the others are in the dialog
const shownWorkloads = 3;

/** The workloads that run a version, by namespace, name, cluster and container. */
function WorkloadLines(
  props: Readonly<{
    workloads: WorkloadReference[];
    onMore: () => void;
    // how many it names, the others behind onMore
    limit?: number;
  }>
) {
  const { workloads, onMore, limit = shownWorkloads } = props;
  const more = workloads.length - limit;
  return (
    <Stack spacing={0.5} alignItems="flex-start">
      {workloads.slice(0, limit).map(workload => (
        <Box
          key={[workload.cluster, workload.namespace, workload.manifestName].join('/')}
          title={`${kindLabel(workload.kind)} ${workload.name}, container ${
            workload.container
          }, in namespace ${workload.namespace} of ${workload.cluster}`}
          sx={{ overflowWrap: 'anywhere', lineHeight: 1.3 }}
        >
          <Typography variant="body2" component="span" color="text.secondary">
            {workload.namespace}/
          </Typography>
          <Typography variant="body2" component="span">
            <WorkloadLink workload={workload} />
          </Typography>
          <Typography variant="caption" component="div" color="text.secondary">
            {workload.cluster} · {workload.container}
          </Typography>
        </Box>
      ))}
      {more > 0 && (
        <Link component="button" variant="caption" onClick={onMore} sx={{ textAlign: 'left' }}>
          and {plural(more, 'more workload', 'more workloads')}
        </Link>
      )}
    </Stack>
  );
}

function workloadsValue(workloads: WorkloadReference[]): string {
  return `${String(workloads.length).padStart(6, '0')} ${workloads
    .map(workload => `${workload.cluster}/${workload.namespace}/${workload.name}`)
    .join(' ')}`;
}

/** The upgrade candidates of an image, the worst first, with the upstream versions of its tags. */
interface CandidateRow {
  repository: string;
  candidates: UpgradeCandidate[];
  // all versions of the image, also the newest ones, which have no upgrade and so no line
  versionCount: number;
  upstream?: Map<string, ImageVersion>;
}

const upgradeLabels = ['Current version', 'Runs in', 'Move to', 'Removes and adds'];

// the columns of the upgrades of an image, of a width of their own, so that the header and the
// upgrades of all images line up
const upgradeGrid = {
  display: 'grid',
  gridTemplateColumns: '9rem 11rem 10rem 25rem',
  columnGap: 2,
  alignItems: 'start',
};

function UpgradeHeader() {
  return (
    <Box sx={upgradeGrid}>
      {upgradeLabels.map(label => (
        <Box key={label}>{label}</Box>
      ))}
    </Box>
  );
}

/** The newest upstream version of a current version, under it, which saves a column. */
function UpstreamLine(props: Readonly<{ version?: ImageVersion }>) {
  if (!props.version?.latest) return null;
  return (
    <Stack direction="row" spacing={0.5} alignItems="center" flexWrap="wrap" useFlexGap>
      <Typography variant="caption" color="text.secondary">
        Upstream
      </Typography>
      <LatestVersionLabel version={props.version} />
    </Stack>
  );
}

/** The versions of an image that can upgrade, a line each. */
function UpgradeLines(
  props: Readonly<{
    row: CandidateRow;
    withUpstream: boolean;
    onOpen: (repository: string) => void;
  }>
) {
  const { row, withUpstream, onOpen } = props;
  return (
    <Box sx={{ ...upgradeGrid, rowGap: 1.5 }}>
      {row.candidates.map((candidate, i) => (
        <Fragment key={candidate.id}>
          {i > 0 && <Box sx={{ gridColumn: '1 / -1', borderTop: 1, borderColor: 'divider' }} />}
          <Stack spacing={0.5} alignItems="flex-start">
            <VersionTag version={candidate.from.version} />
            <ClusterChips variant={candidate.from} />
            {withUpstream && <UpstreamLine version={row.upstream?.get(candidate.from.version)} />}
          </Stack>
          <WorkloadLines
            workloads={candidateWorkloads(candidate)}
            onMore={() => onOpen(row.repository)}
          />
          <VariantCell variant={candidate.to} note={alternativesNote(candidate)} />
          <DeltaPair removed={candidate.removed} added={candidate.added} />
        </Fragment>
      ))}
    </Box>
  );
}

// what the upgrades of an image show, so that the cell is drawn again when that changes, and can
// be searched
function upgradesValue(row: CandidateRow): string {
  return row.candidates
    .map(candidate =>
      [
        candidate.from.version,
        ...candidate.from.clusters,
        ...candidateWorkloads(candidate).map(
          workload => `${workload.cluster}/${workload.namespace}/${workload.name}`
        ),
        candidate.to.version,
        ...candidate.to.clusters,
        alternativesNote(candidate) ?? '',
        deltaValue(candidate.removed),
        deltaValue(candidate.added),
        row.upstream?.get(candidate.from.version)?.latest?.latest ?? '',
      ].join(' ')
    )
    .join('\n');
}

// the most critical, then high, then other CVEs the worst upgrade of an image removes
function compareWorst(a: CandidateRow, b: CandidateRow): number {
  const [x, y] = [a.candidates[0].removed, b.candidates[0].removed];
  return x.critical - y.critical || x.high - y.high || x.cves.length - y.cves.length;
}

function UpgradeCandidates(
  props: Readonly<{
    candidates: UpgradeCandidate[];
    // the number of versions of each image
    versionCounts: Map<string, number>;
    upstream: Upstream;
    withUpstream: boolean;
    onOpen: (repository: string) => void;
  }>
) {
  const { candidates, versionCounts, upstream, withUpstream, onOpen } = props;
  // a row per image, in the order of their worst candidate; new rows when upstream versions are
  // found, as the table keeps the values of a row until its data changes
  const rows = useMemo(() => {
    const byRepository = new Map<string, UpgradeCandidate[]>();
    for (const candidate of candidates) {
      const ofRepository = byRepository.get(candidate.repository) ?? [];
      ofRepository.push(candidate);
      byRepository.set(candidate.repository, ofRepository);
    }
    return [...byRepository].map(
      ([repository, ofRepository]): CandidateRow => ({
        repository,
        candidates: ofRepository,
        versionCount: versionCounts.get(repository) ?? ofRepository.length,
        upstream: upstream.get(repository),
      })
    );
  }, [candidates, versionCounts, upstream]);
  const columns = useMemo<TableColumn<CandidateRow>[]>(
    () => [
      {
        id: 'Image',
        header: 'Image',
        // the counts are part of the value, so that the cell is drawn again when they change
        accessorFn: (row: CandidateRow) =>
          `${row.repository} ${row.candidates.length}/${row.versionCount}`,
        Cell: ({ row }) => (
          <Box>
            <ImageName repository={row.original.repository} onOpen={onOpen} />
            {/* the newest versions have no upgrade, and so no line, though the dialog has them */}
            <Typography variant="caption" color="text.secondary" component="div" sx={{ mt: 0.5 }}>
              {row.original.candidates.length} of {plural(row.original.versionCount, 'version')} can
              upgrade
            </Typography>
          </Box>
        ),
        // the name and the registry path do not wrap within words
        gridTemplate: 'minmax(10rem, auto)',
      },
      {
        id: 'Upgrades',
        header: 'Upgrades',
        Header: () => <UpgradeHeader />,
        accessorFn: upgradesValue,
        sortingFn: (a, b) => compareWorst(a.original, b.original),
        sortDescFirst: true,
        Cell: ({ row }) => (
          <UpgradeLines row={row.original} withUpstream={withUpstream} onOpen={onOpen} />
        ),
        gridTemplate: 'auto',
      },
    ],
    [onOpen, withUpstream]
  );

  return (
    <SectionBox>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 2, mb: 1 }}>
        Each image with the versions of which another selected cluster runs a newer version without
        some of their CVEs: the workloads that run a version, and the newest such version. Removes
        counts the CVEs the move removes by severity, Adds those it adds. Tags that are not
        versions, such as branch builds, cannot be ordered and are compared in the dialog of the
        image. Choose an image or a row for all its versions and workloads.
        {upstreamNote(withUpstream)}
      </Typography>
      <HeadlampTable
        data={rows}
        getRowId={(row: CandidateRow) => row.repository}
        onRowClick={row => onOpen(row.repository)}
        emptyMessage="No cluster runs a version with CVEs that the version of another cluster does not have."
        csvExport={{
          fileName: 'kubescape-upgrade-candidates.csv',
          header: [
            'Image',
            'Clusters',
            'Version',
            'Move to',
            'Run in',
            'Removes CVEs',
            'Removes critical',
            'Removes high',
            'Adds CVEs',
            'Adds critical',
            'Adds high',
            'Removed CVEs',
            'Added CVEs',
            'Summary',
            'Workloads',
            'Other newer versions',
            ...(withUpstream ? ['Upstream'] : []),
          ],
          rows: () =>
            candidates.map(candidate => [
              candidate.repository,
              candidate.from.clusters.join('; '),
              candidate.from.version,
              candidate.to.version,
              candidate.to.clusters.join('; '),
              candidate.removed.cves.length,
              candidate.removed.critical,
              candidate.removed.high,
              candidate.added.cves.length,
              candidate.added.critical,
              candidate.added.high,
              candidate.removed.cves.map(cve => cve.id).join('; '),
              candidate.added.cves.map(cve => cve.id).join('; '),
              describeCandidate(candidate),
              candidateWorkloads(candidate)
                .map(workload =>
                  [workload.cluster, workload.namespace, workload.name, workload.container].join(
                    '/'
                  )
                )
                .join('; '),
              candidate.alternatives.map(option => option.to.version).join('; '),
              ...(withUpstream
                ? [upstream.get(candidate.repository)?.get(candidate.from.version)?.latest?.latest]
                : []),
            ]),
        }}
        columns={columns}
        initialState={{ sorting: [{ id: 'Upgrades', desc: true }] }}
        reflectInURL="candidates"
      />
    </SectionBox>
  );
}

function countsTooltip(counts: CveCounts, severity: string): string {
  const count = severityCount(counts, severity);
  const text = `${count} ${severity.toLowerCase()} ${count === 1 ? 'CVE' : 'CVEs'}`;
  let relevant: number | undefined;
  if (severity === 'Critical') relevant = counts.relevant?.critical;
  else if (severity === 'High') relevant = counts.relevant?.high;
  return relevant === undefined ? text : `${text}, ${relevant} relevant`;
}

// 120 CVEs, 40 fixable, 12 relevant
function countsLine(counts: CveCounts): string {
  const parts = [cveCount(counts.total), `${counts.fixable} fixable`];
  if (counts.relevant) parts.push(`${counts.relevant.total} relevant`);
  return parts.join(', ');
}

/** The upgrade to recommend for a tag, with what it removes and adds in its tooltip. */
function UpgradeChip(props: Readonly<{ tag: TagVersion }>) {
  const upgrade = recommendedUpgrade(props.tag);
  if (!upgrade) return null;
  const removes = severityText(upgrade.removed);
  const adds = severityText(upgrade.added);
  return (
    <Tooltip
      title={
        `${listClusters(upgrade.to.clusters)} ${
          upgrade.to.clusters.length === 1 ? 'runs' : 'run'
        } ` +
        `the newer ${upgrade.to.version}: upgrading to it removes ${cveCount(
          upgrade.removed.cves.length
        )}` +
        `${removes ? ` (${removes})` : ''} and adds ${cveCount(upgrade.added.cves.length)}` +
        `${adds ? ` (${adds})` : ''}`
      }
    >
      <Chip
        size="small"
        color="warning"
        variant="outlined"
        icon={<Icon icon="mdi:arrow-up-bold" />}
        label={upgrade.to.version}
        aria-label={`Upgrade to ${upgrade.to.version}`}
        sx={{ maxWidth: '100%' }}
      />
    </Tooltip>
  );
}

/**
 * The tags of an image over all clusters, newest first, a line each: the tag with the clusters
 * that run it, its CVEs with its workloads, its upstream version and the upgrade to recommend.
 * The columns have a width of their own, so the lines of all images line up, and the clusters
 * are under the tag, so a line fits the column of a table next to others.
 */
function TagLines(
  props: Readonly<{
    repository: RepositoryComparison;
    upstream?: Map<string, ImageVersion>;
    withUpstream: boolean;
  }>
) {
  const { repository, upstream, withUpstream } = props;
  return (
    <Box
      sx={{
        display: 'grid',
        gridTemplateColumns: `10rem max-content${withUpstream ? ' 7rem' : ''} minmax(6rem, 1fr)`,
        justifyContent: 'start',
        alignItems: 'start',
        columnGap: 2,
        rowGap: 1.5,
      }}
    >
      {repository.tags.map(tag => (
        <Fragment key={tag.id}>
          <Stack spacing={0.5} alignItems="flex-start" sx={{ minWidth: 0 }}>
            <VersionTag version={tag.version} />
            <ClusterChips variant={tag} />
            {tag.reportsDiffer && (
              <Tooltip
                title={
                  `The reports of ${listClusters(tag.clusters)} differ in some CVEs: a rebuilt ` +
                  'image, or a scan with another vulnerability database. The counts include the ' +
                  'CVEs of all of them.'
                }
              >
                <Typography variant="caption" color="text.secondary">
                  reports differ
                </Typography>
              </Tooltip>
            )}
          </Stack>
          <Stack spacing={0.5} alignItems="flex-start">
            <SeverityCountStack
              count={severity => severityCount(tag.counts, severity)}
              tooltip={severity => countsTooltip(tag.counts, severity)}
            />
            <Typography variant="caption" color="text.secondary">
              {plural(tag.workloads.length, 'workload')}
            </Typography>
          </Stack>
          {withUpstream && (
            <Box>
              <LatestVersionLabel version={upstream?.get(tag.version)} />
            </Box>
          )}
          <Box sx={{ minWidth: 0 }}>
            <UpgradeChip tag={tag} />
          </Box>
        </Fragment>
      ))}
    </Box>
  );
}

// what the versions of an image show, so that the cell is drawn again when that changes, and can
// be searched
function tagsValue(row: ImageRow): string {
  return row.tags
    .map(tag =>
      [
        tag.version,
        ...tag.clusters,
        tag.workloads.length,
        tag.counts.critical,
        tag.counts.high,
        tag.counts.medium,
        tag.counts.low,
        recommendedUpgrade(tag)?.to.version ?? '',
        row.upstream?.get(tag.version)?.latest?.latest ?? '',
        ...tag.versions.flatMap(version => version.reports.map(report => report.manifestName)),
      ].join(' ')
    )
    .join('\n');
}

function repositoryWorkloads(repository: RepositoryComparison): WorkloadReference[] {
  return repository.tags.flatMap(tag => tag.workloads);
}

// in shop; in 3 namespaces
function namespacesText(workloads: WorkloadReference[]): string {
  const namespaces = new Set(
    workloads.map(workload => `${workload.cluster}/${workload.namespace}`)
  );
  const names = new Set(workloads.map(workload => workload.namespace));
  return names.size === 1 ? `in ${[...names][0]}` : `in ${plural(namespaces.size, 'namespace')}`;
}

/** The number of workloads that run an image, and in how many namespaces. */
function WorkloadCount(props: Readonly<{ workloads: WorkloadReference[] }>) {
  const { workloads } = props;
  return (
    <Box>
      <Typography variant="body2">{plural(workloads.length, 'workload')}</Typography>
      <Typography variant="caption" color="text.secondary" component="div">
        {namespacesText(workloads)}
      </Typography>
    </Box>
  );
}

const statusColors: Record<StatusPart['kind'], 'warning' | 'info' | 'default' | 'success'> = {
  versions: 'warning',
  reports: 'info',
  missing: 'default',
  unknown: 'default',
  same: 'success',
};

function StatusChips(props: Readonly<{ repository: RepositoryComparison }>) {
  return (
    <Stack direction="row" flexWrap="wrap" useFlexGap spacing={0.5}>
      {repositoryStatusParts(props.repository).map(part => (
        <Chip
          key={part.label}
          size="small"
          variant="outlined"
          color={statusColors[part.kind]}
          label={part.label}
        />
      ))}
    </Stack>
  );
}

/** An image with the upstream versions of its tags. */
type ImageRow = RepositoryComparison & { upstream?: Map<string, ImageVersion> };

function ImageVersions(
  props: Readonly<{
    comparison: ClusterComparison;
    filter: ImageFilter;
    upstream: Upstream;
    withUpstream: boolean;
    onFilter: (filter: ImageFilter) => void;
    onOpen: (repository: string) => void;
  }>
) {
  const { comparison, filter, upstream, withUpstream, onFilter, onOpen } = props;
  // new rows when upstream versions are found, as the table keeps the values of a row until its
  // data changes
  const rows = useMemo(
    () =>
      filterRepositories(comparison.repositories, filter).map(
        (repository): ImageRow => ({ ...repository, upstream: upstream.get(repository.repository) })
      ),
    [comparison, filter, upstream]
  );
  const columns = useMemo<TableColumn<ImageRow>[]>(
    () => [
      {
        id: 'Image',
        header: 'Image',
        accessorKey: 'repository',
        Cell: ({ row }) => <ImageName repository={row.original.repository} onOpen={onOpen} />,
        // the name and the registry path do not wrap within words
        gridTemplate: 'minmax(10rem, auto)',
      },
      {
        id: 'Versions',
        header: 'Versions',
        accessorFn: (row: ImageRow) => tagsValue(row),
        // by the number of versions
        sortingFn: (a, b) => a.original.tags.length - b.original.tags.length,
        sortDescFirst: true,
        Cell: ({ row }) => (
          <TagLines
            repository={row.original}
            upstream={row.original.upstream}
            withUpstream={withUpstream}
          />
        ),
        gridTemplate: 'auto',
      },
      {
        id: 'Workloads',
        header: 'Workloads',
        accessorFn: (repository: RepositoryComparison) =>
          workloadsValue(repositoryWorkloads(repository)),
        Cell: ({ row }) => <WorkloadCount workloads={repositoryWorkloads(row.original)} />,
        sortDescFirst: true,
        gridTemplate: 'min-content',
      },
      {
        id: 'Status',
        header: 'Status',
        accessorFn: (repository: RepositoryComparison) => repositoryStatus(repository),
        Cell: ({ row }) => <StatusChips repository={row.original} />,
        gridTemplate: 'min-content',
      },
    ],
    [onOpen, withUpstream]
  );

  let emptyMessage = `No image is in "${imageFilterLabels[filter]}".`;
  if (comparison.repositories.length === 0) {
    emptyMessage = 'No images were scanned in the selected clusters.';
  } else if (filter === 'differ') {
    emptyMessage = 'The selected clusters run the same versions of all images, with the same CVEs.';
  }

  return (
    <SectionBox>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 2, mb: 1 }}>
        Each image with its versions over all clusters, newest first: the clusters that run a
        version (a cluster opens its report), its workloads, its open CVEs by severity, and the
        newer version another cluster runs without some of them. Choose an image or a row for the
        workloads and the upgrades.
        {upstreamNote(withUpstream)}
      </Typography>
      <HeadlampTable
        toolbarStart={
          <TextField
            select
            size="small"
            label="Show"
            value={filter}
            onChange={event => onFilter(event.target.value as ImageFilter)}
            sx={{ minWidth: 220, my: 0.5 }}
          >
            {(Object.keys(imageFilterLabels) as ImageFilter[]).map(key => (
              <MenuItem key={key} value={key}>
                {imageFilterLabels[key]}
              </MenuItem>
            ))}
          </TextField>
        }
        data={rows}
        getRowId={(row: ImageRow) => row.repository}
        onRowClick={row => onOpen(row.repository)}
        emptyMessage={emptyMessage}
        csvExport={{
          fileName: 'kubescape-cluster-images.csv',
          header: [
            'Image',
            'Cluster',
            'Version',
            'Image names',
            'Workloads',
            'Critical',
            'High',
            'Relevant critical',
            'Relevant high',
            'CVEs',
            'Fixable',
            'Status',
            'Differences',
          ],
          rows: () =>
            rows.flatMap(repository =>
              [...repository.versions.values()]
                .flat()
                .map(version => [
                  repository.repository,
                  version.cluster,
                  version.version,
                  version.imageNames.join('; '),
                  version.workloads.join('; '),
                  version.counts.critical,
                  version.counts.high,
                  version.counts.relevant?.critical,
                  version.counts.relevant?.high,
                  version.counts.total,
                  version.counts.fixable,
                  repositoryStatus(repository),
                  repository.differences.map(describeDifference).join('; '),
                ])
            ),
        }}
        columns={columns}
        initialState={{ sorting: [{ id: 'Image', desc: false }] }}
        reflectInURL="images"
      />
    </SectionBox>
  );
}

function Label(props: Readonly<{ children: ReactNode }>) {
  return (
    <Typography
      variant="caption"
      color="text.secondary"
      component="div"
      sx={{ fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.4, mb: 0.5 }}
    >
      {props.children}
    </Typography>
  );
}

// the critical or high CVEs of a move the dialog links to at most, per severity
const linkedCves = 40;

/**
 * The critical and high CVEs of a delta as links to their pages. A CVE that exceptions hide in
 * all reports of the version that has it is named without a link: the page of a CVE lists the
 * workloads whose reports count it, which would be none of this version.
 */
function CveLinks(
  props: Readonly<{
    label: string;
    delta: CveDelta;
    // the CVEs of the version that has the CVEs of the delta, which say whether they are open
    versionCves: Variant['cves'];
  }>
) {
  const { label, delta, versionCves } = props;
  const severe = ['Critical', 'High']
    .map(severity => ({ severity, cves: delta.cves.filter(cve => cve.severity === severity) }))
    .filter(group => group.cves.length > 0);
  const other = delta.cves.length - delta.critical - delta.high;
  return (
    <Box>
      <Label>{label}</Label>
      {delta.cves.length === 0 && (
        <Typography variant="body2" color="text.secondary">
          None
        </Typography>
      )}
      {severe.map(({ severity, cves }) => (
        <Typography key={severity} variant="body2" sx={{ mb: 0.5, overflowWrap: 'anywhere' }}>
          <Box component="span" sx={{ fontWeight: 600 }}>
            {severity} ({cves.length}):
          </Box>{' '}
          {cves.slice(0, linkedCves).map((cve, i) => (
            <Fragment key={cve.id}>
              {i > 0 && ', '}
              {versionCves.get(cve.id)?.open ? (
                <HeadlampLink routeName={RoutingName.KubescapeCVEResults} params={{ cve: cve.id }}>
                  {cve.id}
                </HeadlampLink>
              ) : (
                <Box
                  component="span"
                  title="An exception hides this CVE in the reports of this version"
                >
                  {cve.id}
                </Box>
              )}
            </Fragment>
          ))}
          {cves.length > linkedCves && ` and ${cves.length - linkedCves} more`}
        </Typography>
      ))}
      {other > 0 && (
        <Typography variant="caption" color="text.secondary">
          and {plural(other, 'CVE')} of lower severity, which the boxes list
        </Typography>
      )}
    </Box>
  );
}

// the workloads a version of the dialog names before Show all
const dialogWorkloads = 5;

/** The workloads that run a version, all of them on request. */
function AllWorkloadLines(props: Readonly<{ workloads: WorkloadReference[] }>) {
  const { workloads } = props;
  const [all, setAll] = useState(false);
  return (
    <WorkloadLines
      workloads={workloads}
      limit={all ? workloads.length : dialogWorkloads}
      onMore={() => setAll(true)}
    />
  );
}

/** Another tag a version could move to: where it runs, what it removes and adds, and its CVEs. */
function OptionLine(
  props: Readonly<{
    option: UpgradeOption;
    // the version that could move to it
    from: TagVersion;
    label: string;
  }>
) {
  const { option, from, label } = props;
  const [open, setOpen] = useState(false);
  const workloads = variantWorkloads(option.to);
  return (
    <Box
      sx={{
        display: 'grid',
        // the last column takes the rest, so that unfolded CVEs wrap within the dialog
        gridTemplateColumns: '18rem 25rem auto',
        columnGap: 2,
        rowGap: 1,
        alignItems: 'start',
      }}
    >
      <Stack spacing={0.5} alignItems="flex-start">
        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
          <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600 }}>
            {label}
          </Typography>
          <VersionTag version={option.to.version} />
          {option.order !== 'newer' && <OrderChip order={option.order} />}
        </Stack>
        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
          <ClusterChips variant={option.to} />
          <Tooltip
            title={
              <Box sx={{ whiteSpace: 'pre-line' }}>
                {workloads
                  .map(workload => `${workload.cluster} · ${workload.namespace}/${workload.name}`)
                  .join('\n')}
              </Box>
            }
          >
            <Typography variant="caption" color="text.secondary">
              {plural(workloads.length, 'workload')}
            </Typography>
          </Tooltip>
        </Stack>
      </Stack>
      <DeltaPair removed={option.removed} added={option.added} />
      <Button
        size="small"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
        endIcon={<Icon icon={open ? 'mdi:chevron-up' : 'mdi:chevron-down'} />}
      >
        CVEs
      </Button>
      {open && (
        <Stack
          direction={{ xs: 'column', md: 'row' }}
          spacing={3}
          sx={{ gridColumn: '1 / -1', minWidth: 0, pl: 1, pb: 1 }}
        >
          <Box sx={{ flex: 1 }}>
            <CveLinks label="Removes" delta={option.removed} versionCves={from.cves} />
          </Box>
          <Box sx={{ flex: 1 }}>
            <CveLinks label="Adds" delta={option.added} versionCves={option.to.cves} />
          </Box>
        </Stack>
      )}
    </Box>
  );
}

/** The upgrades of a version, the recommended one first, and the other tags folded away. */
function VersionUpgrades(props: Readonly<{ tag: TagVersion }>) {
  const { tag } = props;
  const [showOthers, setShowOthers] = useState(false);
  const recommended = recommendedUpgrade(tag);
  return (
    <Stack spacing={1}>
      {tag.upgrades.length === 0 && (
        <Typography variant="caption" color="text.secondary">
          No newer version runs in another selected cluster.
        </Typography>
      )}
      {[...(recommended ? [recommended] : []), ...tag.upgrades.filter(o => o !== recommended)].map(
        option => (
          <OptionLine
            key={option.to.id}
            option={option}
            from={tag}
            label={option === recommended ? 'Upgrade to' : 'Also newer'}
          />
        )
      )}
      {tag.others.length > 0 && (
        <Box>
          <Button
            size="small"
            aria-expanded={showOthers}
            onClick={() => setShowOthers(!showOthers)}
            endIcon={<Icon icon={showOthers ? 'mdi:chevron-up' : 'mdi:chevron-down'} />}
          >
            Compare with {plural(tag.others.length, 'other tag')}
          </Button>
          {showOthers && (
            <Stack spacing={1} sx={{ mt: 0.5 }}>
              <Typography variant="caption" color="text.secondary">
                Tags that are not versions of one format, such as branch builds or a release line
                like 18 next to 18.4, and other variants of {tag.version}: which one is newer is
                unknown, so they are no upgrade, but they may lack some of its CVEs.
              </Typography>
              {tag.others.map(option => (
                <OptionLine key={option.to.id} option={option} from={tag} label="Other tag" />
              ))}
            </Stack>
          )}
        </Box>
      )}
    </Stack>
  );
}

const versionLabels = ['Version', 'Runs in', 'Open CVEs', 'Upstream'];

/**
 * The versions of an image, newest first, as lines of one grid under its labels: the clusters,
 * the workloads, the CVEs and the upstream version of each, and its upgrades under it.
 */
function VersionLines(
  props: Readonly<{
    versions: Array<{ tag: TagVersion; workloads: WorkloadReference[] }>;
    upstream?: Map<string, ImageVersion>;
  }>
) {
  const { versions, upstream } = props;
  const { enabled, endOfLife } = useImageVersionSettings();
  const labels = enabled ? versionLabels : versionLabels.slice(0, 3);
  return (
    <Box
      sx={{
        display: 'grid',
        gridTemplateColumns: `11rem minmax(14rem, 1fr) 17rem${enabled ? ' 11rem' : ''}`,
        columnGap: 2,
        rowGap: 1.5,
        alignItems: 'start',
      }}
    >
      {labels.map(label => (
        <Label key={label}>{label}</Label>
      ))}
      {versions.map(({ tag, workloads }) => {
        const found = upstream?.get(tag.version);
        return (
          <Fragment key={tag.id}>
            <Box sx={{ gridColumn: '1 / -1', borderTop: 1, borderColor: 'divider' }} />
            <Stack spacing={0.75} alignItems="flex-start">
              <Typography
                component="h3"
                sx={{
                  fontFamily: 'monospace',
                  fontWeight: 600,
                  fontSize: '0.95rem',
                  overflowWrap: 'anywhere',
                }}
              >
                {tag.version}
              </Typography>
              <ClusterChips variant={tag} />
              {tag.reportsDiffer && (
                <Tooltip
                  title={
                    `The reports of ${listClusters(tag.clusters)} differ in some CVEs: a rebuilt ` +
                    'image, or a scan with another vulnerability database. The counts include ' +
                    'the CVEs of all of them.'
                  }
                >
                  <Typography variant="caption" color="text.secondary">
                    reports differ
                  </Typography>
                </Tooltip>
              )}
            </Stack>
            <AllWorkloadLines workloads={workloads} />
            <Stack spacing={0.5} alignItems="flex-start">
              <SeverityCountStack
                count={severity => severityCount(tag.counts, severity)}
                tooltip={severity => countsTooltip(tag.counts, severity)}
              />
              <Typography variant="caption" color="text.secondary">
                {countsLine(tag.counts)}
              </Typography>
            </Stack>
            {enabled && (
              <Stack spacing={0.5} alignItems="flex-start">
                <LatestVersionLabel version={found} />
                {endOfLife && <EndOfLifeLabel line={found?.line} />}
              </Stack>
            )}
            <Box sx={{ gridColumn: '2 / -1' }}>
              <VersionUpgrades tag={tag} />
            </Box>
          </Fragment>
        );
      })}
    </Box>
  );
}

function workloadMatches(workload: WorkloadReference, version: string, words: string[]) {
  const text = [
    workload.cluster,
    workload.namespace,
    workload.kind,
    workload.name,
    workload.container,
    version,
  ]
    .join(' ')
    .toLowerCase();
  return words.every(word => text.includes(word));
}

/** An image in all clusters: its versions, newest first, with where they run and their upgrades. */
function ImageDialog(
  props: Readonly<{
    repository: RepositoryComparison;
    upstream?: Map<string, ImageVersion>;
    onClose: () => void;
  }>
) {
  const { repository, upstream, onClose } = props;
  const { name } = splitRepository(repository.repository);
  const [search, setSearch] = useState('');
  const words = search.toLowerCase().split(/\s+/).filter(Boolean);
  const workloadCount = repository.tags.reduce((count, tag) => count + tag.workloads.length, 0);
  const shown = repository.tags
    .map(tag => ({
      tag,
      workloads: words.length
        ? tag.workloads.filter(workload => workloadMatches(workload, tag.version, words))
        : tag.workloads,
    }))
    .filter(({ workloads }) => workloads.length > 0 || words.length === 0);

  return (
    <Dialog open onClose={onClose} maxWidth="lg" fullWidth aria-labelledby="image-dialog-title">
      <DialogTitle id="image-dialog-title" component="div">
        <Stack direction="row" spacing={1} alignItems="flex-start">
          <Box sx={{ flexGrow: 1, minWidth: 0 }}>
            <Typography variant="h6" component="h2">
              {name}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ overflowWrap: 'anywhere' }}>
              {repository.repository}
            </Typography>
          </Box>
          <Box sx={{ pt: 0.5 }}>
            <StatusChips repository={repository} />
          </Box>
          <IconButton aria-label="Close" onClick={onClose}>
            <Icon icon="mdi:close" />
          </IconButton>
        </Stack>
      </DialogTitle>
      <DialogContent dividers>
        <Stack
          direction="row"
          spacing={2}
          alignItems="center"
          justifyContent="space-between"
          flexWrap="wrap"
          useFlexGap
          sx={{ mb: 2 }}
        >
          <Typography variant="body2" color="text.secondary">
            {plural(repository.tags.length, 'version')} in {listClusters(repository.runningIn)}, run
            by {plural(workloadCount, 'workload')}; the newest version first.
          </Typography>
          {workloadCount > 8 && (
            <TextField
              size="small"
              label="Filter workloads"
              placeholder="Cluster, namespace, name, container or version"
              value={search}
              onChange={event => setSearch(event.target.value)}
              sx={{ minWidth: 320 }}
            />
          )}
        </Stack>
        {shown.length > 0 && <VersionLines versions={shown} upstream={upstream} />}
        {shown.length === 0 && (
          <Typography variant="body2" color="text.secondary">
            No workload matches the filter.
          </Typography>
        )}
      </DialogContent>
    </Dialog>
  );
}
