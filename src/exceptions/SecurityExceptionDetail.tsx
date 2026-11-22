import { Icon } from '@iconify/react';
import {
  DateLabel,
  NameValueTable,
  SectionBox,
} from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { KubeObject } from '@kinvolk/headlamp-plugin/lib/k8s/cluster';
import { Button, Chip, Typography } from '@mui/material';
import { useSnackbar } from 'notistack';
import { useEffect, useState } from 'react';
import { errorMessage } from '../common/errors';
import Table from '../common/Table';
import { getURLSegments } from '../common/url';
import { clusterSecurityExceptionClass, securityExceptionClass } from '../model';
import { VulnerabilityException } from '../softwarecomposition/SecurityException';
import {
  entryExpiresAt,
  formatLabelSelector,
  isExceptionExpired,
  isExpired,
} from './apply-security-exceptions';
import { eventTime, ExceptionEvent, fetchExceptionEvents } from './events';
import { AnyException, saveExceptionYaml } from './exceptionYaml';
import { exceptionHistory, HistoryEntry } from './history';

export function SecurityExceptionDetail() {
  const [namespace, name] = getURLSegments(-2, -1);
  const [obj, setObj] = useState<KubeObject | null>(null);
  const [error, setError] = useState<unknown>(null);

  securityExceptionClass.useApiGet(setObj, name, namespace, setError);

  if (!obj) return <ReadError name={name} error={error} />;
  return <SecurityExceptionView obj={obj} />;
}

export function ClusterSecurityExceptionDetail() {
  const [name] = getURLSegments(-1);
  const [obj, setObj] = useState<KubeObject | null>(null);
  const [error, setError] = useState<unknown>(null);

  clusterSecurityExceptionClass.useApiGet(setObj, name, undefined, setError);

  if (!obj) return <ReadError name={name} error={error} />;
  return <SecurityExceptionView obj={obj} isCluster />;
}

// Why the page has no exception to show: it was deleted, which a finding it once hid can still
// link to, or the user may not read it. Nothing while it is being read.
function ReadError({ name, error }: Readonly<{ name: string; error: unknown }>) {
  if (!error) return <></>;
  return (
    <SectionBox title="Security Exception">
      <Typography variant="body2" color="error">
        Unable to read the exception {name}: {errorMessage(error)}
      </Typography>
    </SectionBox>
  );
}

function SecurityExceptionView({
  obj,
  isCluster = false,
}: Readonly<{ obj: KubeObject; isCluster?: boolean }>) {
  const spec = obj.jsonData?.spec ?? {};
  const { enqueueSnackbar } = useSnackbar();

  const exception = obj.jsonData as AnyException;
  const expiresAt = spec.expiresAt ? new Date(spec.expiresAt) : null;
  const expired = expiresAt ? expiresAt < new Date() : false;
  // vulnerability entries with an expiry of their own outlast the exception
  let expiredNote = '';
  if (expired) {
    expiredNote = isExceptionExpired(exception)
      ? '(expired, no longer applied)'
      : '(expired; entries with their own expiry still apply)';
  }

  const overviewRows = [
    { name: 'Name', value: obj.metadata.name },
    {
      name: isCluster ? 'Scope' : 'Namespace',
      value: isCluster ? 'Cluster-scoped' : obj.metadata.namespace,
    },
    { name: 'Author', value: spec.author ?? '—' },
    {
      name: 'Created',
      value: obj.metadata.creationTimestamp ? (
        <DateLabel date={obj.metadata.creationTimestamp} />
      ) : (
        '—'
      ),
    },
    { name: 'Reason', value: spec.reason ?? '—' },
    {
      name: 'Expires',
      value: expiresAt ? (
        <span style={expired ? { color: 'red', fontWeight: 'bold' } : {}}>
          {expiresAt.toISOString()} {expiredNote}
        </span>
      ) : (
        '—'
      ),
    },
  ];

  const matchRows = [
    {
      name: 'Resources',
      value:
        spec.match?.resources && spec.match.resources.length > 0
          ? spec.match.resources.map((r: any) => `${r.kind}/${r.name ?? '*'}`).join(', ')
          : '—',
    },
    {
      name: 'Images',
      value:
        spec.match?.images && spec.match.images.length > 0 ? spec.match.images.join(', ') : '—',
    },
    ...(isCluster && spec.match?.namespaceSelector
      ? [
          {
            name: 'Namespace selector',
            value: formatLabelSelector(spec.match.namespaceSelector) || 'all namespaces',
          },
        ]
      : []),
    // the workloads must also have these labels
    ...(spec.match?.objectSelector
      ? [
          {
            name: 'Workload selector',
            value: formatLabelSelector(spec.match.objectSelector) || 'all workloads',
          },
        ]
      : []),
  ];

  return (
    <>
      <SectionBox
        title={obj.metadata.name}
        backLink
        headerProps={{
          actions: [
            <Button
              key="download"
              startIcon={<Icon icon="mdi:download" />}
              title="Saves the exception without the fields the cluster sets, to add it to a GitOps repository"
              onClick={() => saveExceptionYaml(exception, enqueueSnackbar)}
            >
              Download YAML
            </Button>,
          ],
        }}
      >
        <NameValueTable rows={overviewRows} />
      </SectionBox>

      <SectionBox title="Match">
        <NameValueTable rows={matchRows} />
      </SectionBox>

      {spec.posture && spec.posture.length > 0 && (
        <SectionBox title="Posture Exceptions">
          <Table
            data={spec.posture}
            columns={[
              { header: 'Control ID', accessorKey: 'controlID' },
              { header: 'Framework', accessorKey: 'frameworkName' },
              {
                header: 'Action',
                accessorKey: 'action',
                Cell: ({ cell }) => (
                  <Chip
                    label={cell.getValue()}
                    size="small"
                    color={cell.getValue() === 'ignore' ? 'error' : 'warning'}
                  />
                ),
              },
            ]}
          />
        </SectionBox>
      )}

      <ExceptionHistory obj={obj} />
      <ExceptionMatches obj={obj} isCluster={isCluster} />

      {spec.vulnerabilities && spec.vulnerabilities.length > 0 && (
        <SectionBox title="Vulnerability Exceptions">
          <Table
            data={spec.vulnerabilities}
            columns={[
              {
                header: 'CVE ID',
                accessorFn: (v: VulnerabilityException) => v.vulnerability.id,
              },
              { header: 'Status', accessorKey: 'status' },
              { header: 'Justification', accessorKey: 'justification' },
              {
                header: 'Expired on Fix',
                accessorKey: 'expiredOnFix',
                Cell: ({ cell }) => (cell.getValue() ? 'Yes' : 'No'),
              },
              {
                // an entry's own expiry overrides that of the exception, as for kubevuln
                header: 'Expires',
                accessorFn: (v: VulnerabilityException) => entryExpiresAt(exception, v) ?? '',
                Cell: ({ cell }) => {
                  const value: string = cell.getValue();
                  if (!value) return '—';
                  return isExpired(value) ? (
                    <span style={{ color: 'red', fontWeight: 'bold' }}>{value} (expired)</span>
                  ) : (
                    value
                  );
                },
              },
              { header: 'Impact Statement', accessorKey: 'impactStatement' },
            ]}
          />
        </SectionBox>
      )}
    </>
  );
}

// The creates and changes of the exception that this plugin recorded, newest first
function ExceptionHistory({ obj }: Readonly<{ obj: KubeObject }>) {
  const history = exceptionHistory(obj.jsonData).reverse();
  return (
    <SectionBox title="History">
      {history.length === 0 ? (
        <Typography variant="body2">
          No changes recorded. The history only contains changes made with this plugin.
        </Typography>
      ) : (
        <Table
          data={history}
          columns={[
            {
              header: 'Time',
              accessorKey: 'time',
              Cell: ({ cell }) => <DateLabel date={cell.getValue()} />,
            },
            {
              header: 'Change',
              accessorFn: (entry: HistoryEntry) =>
                entry.action === 'created' ? 'Created' : 'Changed',
            },
            {
              header: 'User',
              accessorFn: (entry: HistoryEntry) => entry.user ?? 'Unknown',
            },
          ]}
        />
      )}
    </SectionBox>
  );
}

// The findings that the Kubescape scanner suppressed with the exception, as reported in events
function ExceptionMatches({ obj, isCluster }: Readonly<{ obj: KubeObject; isCluster: boolean }>) {
  const [events, setEvents] = useState<ExceptionEvent[] | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    fetchExceptionEvents(
      isCluster ? 'ClusterSecurityException' : 'SecurityException',
      obj.metadata.name,
      isCluster ? undefined : obj.metadata.namespace
    )
      .then(found => {
        if (active) setEvents(found);
      })
      .catch(err => {
        if (active) setError(errorMessage(err));
      });
    return () => {
      active = false;
    };
  }, [obj.metadata.name, obj.metadata.namespace, isCluster]);

  return (
    <SectionBox title="Applied by the scanner">
      {error ? (
        <Typography variant="body2" color="error">
          Unable to read the events of the exception: {error}
        </Typography>
      ) : events === null ? (
        <Typography variant="body2" color="text.secondary">
          Reading events…
        </Typography>
      ) : events.length === 0 ? (
        <Typography variant="body2">
          No recent reports. When the riskAcceptance capability of the operator is enabled, the
          scanner reports every finding it suppresses with this exception. Kubernetes keeps these
          events for a limited time, by default one hour.
        </Typography>
      ) : (
        <Table
          data={events}
          columns={[
            {
              header: 'Last seen',
              accessorFn: (event: ExceptionEvent) => eventTime(event),
              Cell: ({ cell }) => (cell.getValue() ? <DateLabel date={cell.getValue()} /> : ''),
            },
            { header: 'Report', accessorKey: 'message' },
            {
              header: 'Count',
              accessorFn: (event: ExceptionEvent) => event.count ?? 1,
            },
          ]}
        />
      )}
    </SectionBox>
  );
}
