import { Icon } from '@iconify/react';
import { remove } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import { Link as HeadlampLink, SectionBox } from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import type { KubeObject } from '@kinvolk/headlamp-plugin/lib/k8s/cluster';
import { getCluster } from '@kinvolk/headlamp-plugin/lib/Utils';
import {
  Alert,
  Button,
  FormControlLabel,
  IconButton,
  Switch,
  Tooltip,
  Typography,
} from '@mui/material';
import { useSnackbar } from 'notistack';
import { useEffect, useMemo, useRef, useState } from 'react';
import { getAllowedNamespaces } from '../common/clusterContext';
import { ClusterErrors } from '../common/ClusterErrors';
import { clusterColumns } from '../common/clusters';
import { ConfirmDeleteDialog } from '../common/ConfirmDeleteDialog';
import { errorMessage, errorStatus } from '../common/errors';
import { saveToFile } from '../common/filedialog';
import {
  AccessCheck,
  createExceptionCheck,
  PermittedIconButton,
  useDeniedCheck,
} from '../common/permissions';
import { ProgressLine } from '../common/ProgressIndicator';
import { SetupCheck } from '../common/SetupCheck';
import Table from '../common/Table';
import { RoutingName, useHLSelectedClusters } from '../index';
import type { ClusterError } from '../model';
import { clusterSecurityExceptionClass, securityExceptionClass } from '../model';
import { isExceptionExpired } from './apply-security-exceptions';
import { CoverageCheck, CoverageResult, coverageResults, exceptionKey, isStale } from './coverage';
import { checkCoverage } from './coverageCheck';
import {
  AnyException,
  ClusterException,
  exceptionsFileName,
  exceptionsYaml,
  saveExceptionYaml,
} from './exceptionYaml';
import { exceptionHistory } from './history';
import { SecurityExceptionForm } from './SecurityExceptionForm';

interface Row {
  cluster: string;
  name: string;
  namespace: string;
  author: string;
  // who changed the exception last, according to its history
  lastChange: string;
  reason: string;
  expiresAt: string;
  postureCount: number;
  vulnCount: number;
  creationTimestamp: string;
  isCluster: boolean;
  exception: AnyException;
  // what the last check of the coverage found
  coverage?: CoverageResult;
}

// Changing or deleting the exception of the row
function exceptionCheck(row: Row, verb: 'update' | 'delete'): AccessCheck {
  return row.isCluster
    ? { group: 'kubescape.io', resource: 'clustersecurityexceptions', verb, name: row.name }
    : {
        group: 'kubescape.io',
        resource: 'securityexceptions',
        verb,
        namespace: row.namespace,
        name: row.name,
      };
}

// identifies the exception of a row, in all selected clusters
function rowId(row: Row) {
  return exceptionKey(row.cluster, row.exception);
}

function toRow({ cluster, exception }: ClusterException, coverage?: CoverageResult): Row {
  const spec = exception.spec ?? {};
  const isCluster = exception.kind === 'ClusterSecurityException';
  const lastEntry = exceptionHistory(exception).at(-1);
  return {
    cluster,
    name: exception.metadata.name,
    namespace: isCluster ? 'Cluster-scoped' : exception.metadata.namespace ?? '',
    author: spec.author ?? '',
    lastChange:
      lastEntry?.action === 'changed'
        ? `${lastEntry.user ?? 'unknown user'}, ${new Date(lastEntry.time).toLocaleString()}`
        : '',
    reason: spec.reason ?? '',
    expiresAt: spec.expiresAt ?? '',
    postureCount: spec.posture?.length ?? 0,
    vulnCount: spec.vulnerabilities?.length ?? 0,
    creationTimestamp: exception.metadata.creationTimestamp ?? '',
    isCluster,
    exception,
    coverage,
  };
}

/** The errors of the lists, without those of clusters that do not have the CRDs. */
function listErrors(errors: unknown[] | null | undefined): ClusterError[] {
  return (errors ?? [])
    .filter(error => errorStatus(error) !== 404)
    .map(error => ({
      cluster: (error as { cluster?: string }).cluster ?? '',
      message: errorMessage(error),
    }));
}

/**
 * Opens the form, which creates an exception in a namespace or for the whole cluster, or
 * downloads it as YAML for a GitOps repository; a user who may create neither is told so. A
 * user limited to some namespaces is asked about the first of them.
 */
function CreateButton(props: Readonly<{ onClick: () => void }>) {
  const cluster = getCluster();
  const namespace = cluster ? getAllowedNamespaces(cluster)[0] : undefined;
  const clusterDenied = useDeniedCheck([createExceptionCheck()]);
  const namespacedDenied = useDeniedCheck([
    { group: 'kubescape.io', resource: 'securityexceptions', verb: 'create', namespace },
  ]);
  const button = (
    <Button variant="contained" onClick={props.onClick}>
      Create
    </Button>
  );
  return clusterDenied && namespacedDenied ? (
    <Tooltip
      describeChild
      title="You are not allowed to create securityexceptions or clustersecurityexceptions, but the form can download an exception as YAML for a GitOps repository."
    >
      {button}
    </Tooltip>
  ) : (
    button
  );
}

// What the check found, red for exceptions that are likely stale
function CoverageCell(props: Readonly<{ result?: CoverageResult }>) {
  const { result } = props;
  if (!result) return null;
  let color = 'text.primary';
  if (isStale(result)) color = 'error.main';
  else if (result.status !== 'covers') color = 'text.secondary';
  return (
    <Typography variant="body2" color={color}>
      {result.text}
    </Typography>
  );
}

export function SecurityExceptions() {
  const clusters = useHLSelectedClusters();
  const namespacedList = securityExceptionClass.useList({ clusters });
  const clusterList = clusterSecurityExceptionClass.useList({ clusters });
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<Row | null>(null);
  // the exception to delete once the user confirms
  const [deleting, setDeleting] = useState<Row | null>(null);
  // the exceptions deleted here, hidden until the lists no longer have them
  const [deleted, setDeleted] = useState<Set<string>>(new Set());
  const [check, setCheck] = useState<CoverageCheck | null>(null);
  const [checking, setChecking] = useState(false);
  const [progress, setProgress] = useState('');
  const [staleOnly, setStaleOnly] = useState(false);
  // the flag of the current check, which leaving the page or Cancel clears
  const reading = useRef({ current: false });
  const { enqueueSnackbar } = useSnackbar();

  useEffect(
    () => () => {
      reading.current.current = false;
    },
    []
  );

  const listed: ClusterException[] = useMemo(
    () =>
      [...(namespacedList.items ?? []), ...(clusterList.items ?? [])].map((obj: KubeObject) => ({
        cluster: obj.cluster || getCluster() || '',
        exception: obj.jsonData as AnyException,
      })),
    [namespacedList.items, clusterList.items]
  );
  const exceptions = useMemo(
    () => listed.filter(item => !deleted.has(exceptionKey(item.cluster, item.exception))),
    [listed, deleted]
  );
  // an exception created again with the name of one deleted here is shown
  useEffect(() => {
    if (deleted.size === 0) return;
    const present = new Set(listed.map(item => exceptionKey(item.cluster, item.exception)));
    if ([...deleted].some(key => !present.has(key))) {
      setDeleted(new Set([...deleted].filter(key => present.has(key))));
    }
  }, [listed, deleted]);
  const results = useMemo(
    () => (check ? coverageResults(exceptions, check) : undefined),
    [exceptions, check]
  );
  // new rows when the results change, as the table keeps the values of a row until then
  const rows = useMemo(
    () =>
      exceptions.map(item => toRow(item, results?.get(exceptionKey(item.cluster, item.exception)))),
    [exceptions, results]
  );
  const staleCount = rows.filter(row => isStale(row.coverage)).length;
  const shownRows = staleOnly && results ? rows.filter(row => isStale(row.coverage)) : rows;
  const errors = [...listErrors(namespacedList.errors), ...listErrors(clusterList.errors)];

  // an error is shown in the dialog that asked
  async function handleDelete(row: Row) {
    const options = { cluster: row.cluster };
    if (row.isCluster) {
      await remove(`/apis/kubescape.io/v1beta1/clustersecurityexceptions/${row.name}`, options);
    } else {
      await remove(
        `/apis/kubescape.io/v1beta1/namespaces/${row.namespace}/securityexceptions/${row.name}`,
        options
      );
    }
    setDeleted(previous => new Set(previous).add(rowId(row)));
    enqueueSnackbar('Security exception deleted', { variant: 'success' });
  }

  async function runCheck() {
    const flag = { current: true };
    reading.current.current = false;
    reading.current = flag;
    setChecking(true);
    setProgress('');
    try {
      const found = await checkCoverage(exceptions, clusters, flag, message => {
        if (reading.current === flag) setProgress(message);
      });
      if (reading.current === flag) setCheck(found);
    } catch (error) {
      enqueueSnackbar(`Unable to check the coverage: ${errorMessage(error)}`, {
        variant: 'error',
      });
    } finally {
      if (reading.current === flag) setChecking(false);
    }
  }

  const downloadAll = () =>
    saveToFile(
      exceptionsYaml(exceptions),
      exceptionsFileName([...new Set(exceptions.map(item => item.cluster))]),
      enqueueSnackbar
    );

  return (
    <SectionBox
      title="Security Exceptions"
      headerProps={{
        actions: [
          <Tooltip
            key="check"
            describeChild
            title="Reads the configuration and vulnerability scans of the clusters, and shows what each exception covers in them. Exceptions that cover nothing are likely stale."
          >
            <span>
              <Button
                variant="outlined"
                startIcon={<Icon icon="mdi:magnify-scan" />}
                disabled={checking || exceptions.length === 0}
                onClick={runCheck}
              >
                Check coverage
              </Button>
            </span>
          </Tooltip>,
          <Tooltip
            key="download"
            describeChild
            title="Saves the exceptions of the selected clusters as one YAML file, without the fields the clusters set, to add them to a GitOps repository."
          >
            <span>
              <Button
                variant="outlined"
                startIcon={<Icon icon="mdi:download" />}
                disabled={exceptions.length === 0}
                onClick={downloadAll}
              >
                Download all as YAML
              </Button>
            </span>
          </Tooltip>,
          <CreateButton key="create" onClick={() => setFormOpen(true)} />,
        ],
      }}
    >
      <SetupCheck features={['exceptions']} />
      <ClusterErrors errors={errors} what="the security exceptions" />
      {checking && (
        <ProgressLine
          continueReading={reading.current}
          progressMessage={progress || 'Reading the scans…'}
        />
      )}
      {check && !checking && (
        <>
          {check.incomplete.map(({ cluster, message }) => (
            <Alert key={cluster} severity="warning" sx={{ mb: 1 }}>
              Unable to read all scans of cluster {cluster} ({message}), so its exceptions are not
              marked as covering nothing.
            </Alert>
          ))}
          <Typography variant="body2" sx={{ mb: 1 }}>
            {staleCount === 0
              ? 'Every exception covers findings in the current scans.'
              : `${staleCount} of ${rows.length} exceptions cover nothing in the current scans or have expired, and are likely stale: the workload is gone, the image was updated or the finding was fixed.`}
          </Typography>
        </>
      )}
      <Table
        data={shownRows}
        getRowId={rowId}
        sortingKey="security-exceptions"
        toolbarStart={
          results && (
            <FormControlLabel
              control={
                <Switch checked={staleOnly} onChange={(_, checked) => setStaleOnly(checked)} />
              }
              label={`Only stale exceptions (${staleCount})`}
            />
          )
        }
        columns={[
          {
            header: 'Name',
            accessorKey: 'name',
            Cell: ({ cell, row }) =>
              row.original.isCluster ? (
                <HeadlampLink
                  routeName={RoutingName.SecurityExceptionClusterDetail}
                  params={{ name: cell.getValue() }}
                  activeCluster={row.original.cluster}
                >
                  {cell.getValue()}
                </HeadlampLink>
              ) : (
                <HeadlampLink
                  routeName={RoutingName.SecurityExceptionDetail}
                  params={{ namespace: row.original.namespace, name: cell.getValue() }}
                  activeCluster={row.original.cluster}
                >
                  {cell.getValue()}
                </HeadlampLink>
              ),
          },
          ...clusterColumns<Row>(clusters, row => row.cluster),
          {
            header: 'Namespace',
            accessorKey: 'namespace',
          },
          {
            header: 'Author',
            accessorKey: 'author',
          },
          {
            header: 'Last changed by',
            accessorKey: 'lastChange',
          },
          {
            header: 'Reason',
            accessorKey: 'reason',
          },
          {
            header: 'Expires',
            accessorKey: 'expiresAt',
            Cell: ({ cell, row }) => {
              const val = cell.getValue();
              if (!val) return '';
              const expired = new Date(val) < new Date();
              // vulnerability entries with an expiry of their own outlast the exception
              const entriesApply = expired && !isExceptionExpired(row.original.exception);
              return (
                <span style={expired ? { color: 'red', fontWeight: 'bold' } : {}}>
                  {new Date(val).toLocaleDateString()}
                  {expired &&
                    (entriesApply
                      ? ' (expired; entries with their own expiry still apply)'
                      : ' (expired, no longer applied)')}
                </span>
              );
            },
          },
          {
            header: 'Posture entries',
            accessorKey: 'postureCount',
          },
          {
            header: 'Vuln entries',
            accessorKey: 'vulnCount',
          },
          ...(results
            ? [
                {
                  id: 'coverage',
                  header: 'Coverage',
                  accessorFn: (row: Row) => row.coverage?.text ?? '',
                  Cell: ({ row }: { row: { original: Row } }) => (
                    <CoverageCell result={row.original.coverage} />
                  ),
                },
              ]
            : []),
          {
            header: 'Age',
            accessorKey: 'creationTimestamp',
            Cell: ({ cell }) => {
              const val = cell.getValue();
              if (!val) return '';
              const days = Math.floor(
                (Date.now() - new Date(val).getTime()) / (1000 * 60 * 60 * 24)
              );
              return days === 0 ? '<1d' : `${days}d`;
            },
          },
          {
            id: 'actions',
            header: '',
            // the version of the exception, so that the buttons are drawn again for a change
            accessorFn: (row: Row) =>
              `${rowId(row)}${
                (row.exception.metadata as { resourceVersion?: string }).resourceVersion ?? ''
              }`,
            enableSorting: false,
            Cell: ({ row }) => (
              <>
                <Tooltip title="Download YAML">
                  <IconButton
                    size="small"
                    aria-label="Download YAML"
                    onClick={() => saveExceptionYaml(row.original.exception, enqueueSnackbar)}
                  >
                    <Icon icon="mdi:download" />
                  </IconButton>
                </Tooltip>
                {/* the form checks whether Save is allowed, and can download the change as YAML */}
                <Tooltip title="Edit">
                  <IconButton
                    size="small"
                    aria-label="Edit"
                    onClick={() => setEditing(row.original)}
                  >
                    <Icon icon="mdi:pencil" />
                  </IconButton>
                </Tooltip>
                <PermittedIconButton
                  check={exceptionCheck(row.original, 'delete')}
                  cluster={row.original.cluster}
                  title="Delete"
                  onClick={() => setDeleting(row.original)}
                >
                  <Icon icon="mdi:delete" />
                </PermittedIconButton>
              </>
            ),
            gridTemplate: 'auto',
          },
        ]}
      />
      {/* with several clusters selected, the form names the one the exception goes to */}
      {formOpen && (
        <SecurityExceptionForm
          cluster={clusters.length > 1 ? clusters[0] : undefined}
          onClose={() => setFormOpen(false)}
        />
      )}
      {deleting && (
        <ConfirmDeleteDialog
          target={{
            kind: deleting.isCluster ? 'ClusterSecurityException' : 'SecurityException',
            name: deleting.name,
            namespace: deleting.isCluster ? undefined : deleting.namespace,
            cluster: deleting.cluster || undefined,
          }}
          consequence="The findings it covers count again once the scanners or this page apply the exceptions again."
          onDelete={() => handleDelete(deleting)}
          onClose={() => setDeleting(null)}
        />
      )}
      {editing && (
        <SecurityExceptionForm
          existing={editing.exception}
          cluster={editing.cluster || undefined}
          onClose={() => setEditing(null)}
        />
      )}
    </SectionBox>
  );
}
