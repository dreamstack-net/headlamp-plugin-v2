// Loads the mock data of the test dialog from a container profile of the cluster.
import { Icon } from '@iconify/react';
import { Alert, Button, MenuItem, Stack, TextField } from '@mui/material';
import * as yaml from 'js-yaml';
import { useEffect, useRef, useState } from 'react';
import { getAllowedNamespaces } from '../common/clusterContext';
import { errorMessage } from '../common/errors';
import { discoverProfileResource } from '../softwarecomposition/profileApi';
import type { BaselineKind, ProfileSource } from './profileLoader';
import {
  containerProfileToMockYAML,
  getContainerProfile,
  listContainerProfileNames,
  listSelectableNamespaces,
} from './profileLoader';

export type LoadMeta = { namespace: string; workload: string; containerName: string };

export function ClusterMockLoader({
  baselineKind,
  onLoad,
}: Readonly<{
  baselineKind: BaselineKind;
  onLoad: (yaml: string, meta: LoadMeta) => void;
}>) {
  const [open, setOpen] = useState(false);
  const [namespaces, setNamespaces] = useState<string[]>([]);
  const [namespace, setNamespace] = useState('');
  const [workloads, setWorkloads] = useState<string[]>([]);
  const [workload, setWorkload] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [workloadsLoaded, setWorkloadsLoaded] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [source, setSource] = useState<ProfileSource | null>(null);
  const discoveryRequest = useRef(0);
  // the latest load; the answer to one that was cancelled is dropped
  const loadRequest = useRef(0);

  const dropLoad = () => {
    loadRequest.current++;
    setLoading(false);
  };

  const handleOpen = () => {
    const requestID = ++discoveryRequest.current;
    dropLoad();
    setOpen(true);
    setError('');
    setSource(null);
    setRefresh(value => value + 1);
    Promise.all([
      listSelectableNamespaces(getAllowedNamespaces()),
      discoverProfileResource(baselineKind === 'application' ? 'behavior' : 'network'),
    ])
      .then(([availableNamespaces, discoveredSource]) => {
        if (requestID !== discoveryRequest.current) return;
        setNamespaces(availableNamespaces);
        setNamespace(current =>
          availableNamespaces.includes(current)
            ? current
            : availableNamespaces.length === 1
            ? availableNamespaces[0]
            : ''
        );
        setSource(discoveredSource);
      })
      .catch((err: unknown) => {
        if (requestID === discoveryRequest.current) setError(errorMessage(err));
      });
  };

  useEffect(() => {
    setWorkload('');
    setWorkloads([]);
    setWorkloadsLoaded(false);
    setError('');
    if (!namespace || !source) return;
    let active = true;
    listContainerProfileNames(namespace, source)
      .then(names => {
        if (active) {
          setWorkloads(names);
          setWorkloadsLoaded(true);
        }
      })
      .catch((err: unknown) => {
        if (active) setError(errorMessage(err));
      });
    return () => {
      active = false;
    };
  }, [namespace, source, refresh]);

  const emptyComment =
    baselineKind === 'network'
      ? [
          '# No network baseline found for this container profile.',
          '# Network baseline is recorded by Kubescape after observing the',
          '# workload during its learning phase. The network functions of cp.*',
          '# (nn.*) return false until baseline data is available.',
        ].join('\n')
      : [
          '# No application baseline found for this container profile.',
          '# The profile is recorded by Kubescape during the learning phase.',
          '# The cp.* functions (ap.*) return false until baseline data is available.',
        ].join('\n');

  const handleLoad = async () => {
    if (!namespace || !workload || !source) return;
    const requestID = ++loadRequest.current;
    setLoading(true);
    setError('');
    try {
      const profile = await getContainerProfile(namespace, workload, source);
      // cancelled meanwhile: the mock and the event stay as the user left them
      if (requestID !== loadRequest.current) return;
      const converted = containerProfileToMockYAML(profile, baselineKind);
      const parsed = yaml.load(converted) as any;
      const containerName = Object.keys(parsed?.containers ?? {})[0] ?? '';
      const hasData = !!containerName;
      onLoad(hasData ? converted : emptyComment, { namespace, workload, containerName });
      setOpen(false);
    } catch (err) {
      if (requestID === loadRequest.current) setError(errorMessage(err));
    } finally {
      if (requestID === loadRequest.current) setLoading(false);
    }
  };

  if (!open) {
    return (
      <Button
        size="small"
        startIcon={<Icon icon="mdi:cloud-download-outline" />}
        onClick={handleOpen}
        sx={{ mb: 1 }}
      >
        Load from cluster
      </Button>
    );
  }

  return (
    <Stack spacing={1} sx={{ mb: 1 }}>
      {error && (
        <Alert
          severity="error"
          action={
            <Button color="inherit" size="small" onClick={handleOpen}>
              Retry
            </Button>
          }
        >
          {error}
        </Alert>
      )}
      {source && namespaces.length === 0 && (
        <Alert severity="info">No accessible namespaces found.</Alert>
      )}
      {workloadsLoaded && workloads.length === 0 && (
        <Alert severity="info">No profiles found in this namespace.</Alert>
      )}
      <Stack direction="row" spacing={1} alignItems="center" sx={{ flexWrap: 'wrap', gap: 1 }}>
        <TextField
          select
          label="Namespace"
          value={namespace}
          onChange={e => setNamespace(e.target.value)}
          size="small"
          sx={{ minWidth: 160 }}
          disabled={!source}
        >
          {namespaces.map(ns => (
            <MenuItem key={ns} value={ns}>
              {ns}
            </MenuItem>
          ))}
        </TextField>
        <TextField
          select
          label="Profile"
          value={workload}
          onChange={e => setWorkload(e.target.value)}
          size="small"
          sx={{ minWidth: 200 }}
          disabled={!source || !workloads.length}
        >
          {workloads.map(w => (
            <MenuItem key={w} value={w}>
              {w}
            </MenuItem>
          ))}
        </TextField>
        <Button
          variant="contained"
          size="small"
          onClick={handleLoad}
          disabled={!source || !workload || loading}
        >
          Load
        </Button>
        <Button
          size="small"
          onClick={() => {
            discoveryRequest.current++;
            dropLoad();
            setOpen(false);
          }}
        >
          Cancel
        </Button>
      </Stack>
    </Stack>
  );
}
