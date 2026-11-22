/*
  A search of the Kubescape data in Headlamp's top bar: CVEs, packages, images, workloads and
  controls. The vulnerability reports are read once per session, into the cache that the
  Vulnerabilities pages share, so the first search of a session waits for them.
*/
import { Icon } from '@iconify/react';
import { Router } from '@kinvolk/headlamp-plugin/lib';
import {
  Alert,
  Box,
  Dialog,
  DialogContent,
  DialogTitle,
  IconButton,
  InputAdornment,
  LinearProgress,
  List,
  ListItem,
  ListItemButton,
  ListItemText,
  ListSubheader,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import { ReactNode, useEffect, useMemo, useRef, useState } from 'react';
import { Link as RouterLink, useHistory } from 'react-router-dom';
import { KubescapeConfig, kubescapeConfigStore } from '../common/config-store';
import { errorMessage } from '../common/errors';
import makeSeverityLabel from '../common/SeverityLabel';
import { RoutingName, useHLSelectedClusters } from '../index';
import { queryTaskErrors } from '../query';
import type { Control } from '../rego/Control';
import { fetchRegoData } from '../rego/RegoDataProvider';
import type { WorkloadScan } from '../vulnerabilities/scanData';
import { readVulnerabilityScans, vulnerabilityContext } from '../vulnerabilities/Vulnerabilities';
import {
  buildVulnerabilityIndex,
  minimumQueryLength,
  search,
  SearchGroup,
  SearchResults,
} from './searchIndex';

const { createRouteURL } = Router;

const searchHint = 'CVE, package, image, workload or control';

/** The button in Headlamp's top bar that opens the Kubescape search. */
export function KubescapeSearchButton() {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Tooltip title={`Search Kubescape: ${searchHint}`}>
        <IconButton aria-label="Search Kubescape" onClick={() => setOpen(true)}>
          <Icon icon="mdi:shield-search" />
        </IconButton>
      </Tooltip>
      {open && <KubescapeSearchDialog onClose={() => setOpen(false)} />}
    </>
  );
}

/** Where a result leads: a route of the plugin, in the cluster of the result if it has one. */
interface Target {
  routeName: string;
  params: Record<string, string>;
  activeCluster?: string;
}

/**
 * The address of a result. Like Headlamp's links, the cluster of the result comes first and the
 * other selected clusters stay selected; without one, the route stays in the clusters shown.
 */
function targetURL(target: Target, selectedClusters: string[]): string {
  const params = { ...target.params };
  if (target.activeCluster) {
    params.cluster = [
      target.activeCluster,
      ...selectedClusters.filter(cluster => cluster !== target.activeCluster),
    ].join('+');
  }
  return createRouteURL(target.routeName, params);
}

interface ResultRow {
  key: string;
  primary: ReactNode;
  secondary: ReactNode;
  // the page of the result; none outside of a cluster, where Headlamp has no address for the
  // pages of the plugin: createRouteURL then gives its home page
  url?: string;
}

interface ResultSection {
  title: string;
  total: number;
  rows: ResultRow[];
}

function ResultGroup(props: Readonly<{ section: ResultSection; onOpen: () => void }>) {
  const { section, onOpen } = props;
  if (section.total === 0) return null;
  return (
    <>
      <ListSubheader disableSticky>
        {section.title} ({section.total})
      </ListSubheader>
      {section.rows.map(({ key, primary, secondary, url }) => {
        const text = (
          <ListItemText
            primary={primary}
            secondary={secondary}
            secondaryTypographyProps={{ noWrap: true }}
          />
        );
        return url ? (
          // a link of the router, which closes the search before it navigates; Headlamp's own
          // link takes neither a ref nor the click handler of its caller
          <ListItemButton key={key} component={RouterLink} to={url} onClick={onOpen} dense>
            {text}
          </ListItemButton>
        ) : (
          // a result without a page to open is no link
          <ListItem key={key} dense>
            {text}
          </ListItem>
        );
      })}
      {section.total > section.rows.length && (
        <Typography variant="body2" color="text.secondary" sx={{ px: 2, pb: 1 }}>
          {section.total - section.rows.length} more: type more of the name to narrow them down.
        </Typography>
      )}
    </>
  );
}

function plural(count: number, word: string) {
  return `${count} ${word}${count === 1 ? '' : 's'}`;
}

export function KubescapeSearchDialog(props: Readonly<{ onClose: () => void }>) {
  const { onClose } = props;
  const clusters: string[] = useHLSelectedClusters() ?? [];
  const clusterKey = clusters.join(',');
  const [query, setQuery] = useState('');
  const [scans, setScans] = useState<WorkloadScan[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState('');
  const [error, setError] = useState('');
  const [controls, setControls] = useState<Control[]>([]);
  const history = useHistory();
  // the search was opened to type in it; the dialog renders its content after it mounts
  const focused = useRef(false);
  const focusOnce = (element: HTMLInputElement | null) => {
    if (element && !focused.current) {
      focused.current = true;
      element.focus();
    }
  };

  useEffect(() => {
    let active = true;
    fetchRegoData()
      .then(data => active && setControls(data.controls))
      .catch(() => active && setControls([]));
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (clusters.length === 0) return;
    let active = true;
    // each read has its own flag, so the read for the clusters selected before stops
    const continueReading = { current: true };
    readVulnerabilityScans(
      clusters,
      (kubescapeConfigStore.get() ?? {}) as KubescapeConfig,
      continueReading,
      loading => active && setLoading(loading),
      message => active && setProgress(message)
    )
      .then(found => {
        if (!active) return;
        setScans(found);
        const errors = queryTaskErrors(vulnerabilityContext.queryTasks);
        if (errors.length > 0) {
          setError(errors.map(({ cluster, message }) => `${cluster}: ${message}`).join('; '));
        }
      })
      .catch(err => active && setError(errorMessage(err)));
    // a closed search stops reading; the next one continues where it stopped
    return () => {
      active = false;
      continueReading.current = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clusterKey]);

  const index = useMemo(() => (scans ? buildVulnerabilityIndex(scans) : null), [scans]);
  const results = useMemo(() => search(index, controls, query), [index, controls, query]);
  const sections = useMemo(
    () => (results ? resultSections(results, clusters) : []),
    // clusterKey covers clusters, which is a new array on every render
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [results, clusterKey]
  );
  const found = sections.reduce((count, section) => count + section.total, 0);
  // what Enter opens, when it has a page
  const firstResult = sections.find(section => section.rows.length > 0)?.rows[0];

  const open = (url: string) => {
    onClose();
    history.push(url);
  };

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="md" aria-labelledby="kubescape-search-title">
      <DialogTitle id="kubescape-search-title">Search Kubescape</DialogTitle>
      <DialogContent>
        <TextField
          inputRef={focusOnce}
          fullWidth
          placeholder={searchHint}
          value={query}
          onChange={event => setQuery(event.target.value)}
          onKeyDown={event => {
            if (event.key === 'Enter' && firstResult?.url) {
              event.preventDefault();
              open(firstResult.url);
            }
          }}
          inputProps={{ 'aria-label': 'Search Kubescape' }}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <Icon icon="mdi:magnify" />
              </InputAdornment>
            ),
          }}
          sx={{ mt: 1 }}
        />
        {clusters.length === 0 && (
          <Alert severity="info" sx={{ mt: 2 }}>
            Open a cluster to search its Kubescape data.
          </Alert>
        )}
        {error && (
          <Alert severity="error" sx={{ mt: 2 }}>
            Unable to read the vulnerability reports: {error}
          </Alert>
        )}
        {loading && (
          <Box sx={{ mt: 2 }}>
            <LinearProgress />
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              {progress || 'Reading the vulnerability reports…'} The first search of a session reads
              them; later searches and the Vulnerabilities pages reuse them. Controls can be
              searched already.
            </Typography>
          </Box>
        )}
        {!results ? (
          <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
            Type at least {minimumQueryLength} characters: a CVE or GHSA id, a package such as
            openssl, an image, a workload or a control such as C-0017.
          </Typography>
        ) : found === 0 ? (
          <Typography variant="body2" sx={{ mt: 2 }}>
            Nothing found for “{query.trim()}”{loading ? ' yet' : ''}.
          </Typography>
        ) : (
          <List dense sx={{ mt: 1 }}>
            {sections.map(section => (
              <ResultGroup key={section.title} section={section} onOpen={onClose} />
            ))}
          </List>
        )}
      </DialogContent>
    </Dialog>
  );
}

/**
 * The results by group, with the address each one opens. Outside of a cluster, where only the
 * controls are found, the results have no address: their pages are pages of a cluster.
 */
function resultSections(results: SearchResults, clusters: string[]): ResultSection[] {
  const severalClusters = clusters.length > 1;
  const section = <T,>(
    title: string,
    group: SearchGroup<T>,
    row: (item: T) => Omit<ResultRow, 'url'> & { target: Target }
  ): ResultSection => ({
    title,
    total: group.total,
    rows: group.items.map(item => {
      const { target, ...rest } = row(item);
      return { ...rest, url: clusters.length > 0 ? targetURL(target, clusters) : undefined };
    }),
  });

  return [
    section('CVEs', results.cves, cve => ({
      key: cve.id,
      primary: (
        <Stack direction="row" spacing={1} alignItems="center" component="span">
          <span>{cve.id}</span>
          {makeSeverityLabel(cve.severity)}
        </Stack>
      ),
      secondary: [
        cve.packages.slice(0, 3).join(', ') +
          (cve.packages.length > 3 ? ` and ${cve.packages.length - 3} more` : ''),
        plural(cve.images, 'image'),
        plural(cve.workloads, 'workload'),
        cve.aliases.length > 0 ? `also ${cve.aliases.join(', ')}` : '',
        severalClusters ? cve.clusters.join(', ') : '',
      ]
        .filter(Boolean)
        .join(' · '),
      target: { routeName: RoutingName.KubescapeCVEResults, params: { cve: cve.id } },
    })),
    section('Images', results.images, image => ({
      key: `${image.cluster}/${image.namespace}/${image.manifestName}`,
      primary: image.image,
      secondary: [
        `${image.critical} critical, ${image.high} high`,
        plural(image.workloads, 'workload'),
        severalClusters ? image.cluster : '',
      ]
        .filter(Boolean)
        .join(' · '),
      target: {
        routeName: RoutingName.ImageVulnerabilityDetails,
        params: { namespace: image.namespace, name: image.manifestName },
        activeCluster: image.cluster,
      },
    })),
    section('Workloads', results.workloads, workload => ({
      key: `${workload.cluster}/${workload.namespace}/${workload.manifestName}`,
      primary: `${workload.name} / ${workload.container}`,
      secondary: [workload.kind, workload.namespace, severalClusters ? workload.cluster : '']
        .filter(Boolean)
        .join(' · '),
      target: {
        routeName: RoutingName.KubescapeVulnerabilityDetails,
        params: { namespace: workload.namespace, name: workload.manifestName },
        activeCluster: workload.cluster,
      },
    })),
    section('Controls', results.controls, control => ({
      key: control.controlID,
      primary: `${control.controlID} ${control.name}`,
      secondary: control.description,
      target: {
        routeName: RoutingName.KubescapeControlResults,
        params: { control: control.controlID },
      },
    })),
  ];
}
