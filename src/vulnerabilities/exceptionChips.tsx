/*
  The exceptions of the CVEs of workloads, as chips coloured by what they say about the CVE.
*/
import { Icon } from '@iconify/react';
import { Link } from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { Alert, Box, Button, Chip, ChipProps, Stack, Tooltip, Typography } from '@mui/material';
import { useEffect, useState } from 'react';
import { getAllowedNamespaces } from '../common/clusterContext';
import { errorMessage } from '../common/errors';
import {
  fetchSecurityExceptions,
  SecurityExceptionData,
} from '../exceptions/apply-security-exceptions';
import {
  CveException,
  ExceptionState,
  exceptionStateLabels,
  WorkloadExceptions,
} from '../exceptions/vulnerabilityExceptions';
import { RoutingName } from '../index';
import type { ClusterError } from '../model';

const stateColors: Record<ExceptionState, ChipProps['color']> = {
  accepted: 'success',
  not_affected: 'info',
  fixed: 'info',
  planned: 'warning',
  investigating: 'default',
};

/**
 * The security exceptions of the clusters, read again with reload. Workloads of the kinds are
 * matched against the object selectors of the exceptions. The errors name the clusters whose
 * exceptions could not be read, whose findings may be shown as open although an exception
 * covers them.
 */
export function useSecurityExceptions(clusters: string[], kinds: string[]) {
  const [exceptions, setExceptions] = useState<Map<string, SecurityExceptionData>>(new Map());
  const [errors, setErrors] = useState<ClusterError[]>([]);
  const [reloadKey, setReloadKey] = useState(0);
  const clusterKey = clusters.join(',');
  const kindKey = [...new Set(kinds)].sort().join(',');

  useEffect(() => {
    let cancelled = false;
    Promise.all(
      clusters.map(async cluster => {
        try {
          const data = await fetchSecurityExceptions(
            cluster,
            [],
            kindKey ? kindKey.split(',') : [],
            getAllowedNamespaces(cluster)
          );
          return { cluster, data };
        } catch (error) {
          return { cluster, error: errorMessage(error) };
        }
      })
    ).then(results => {
      if (cancelled) return;
      setExceptions(new Map(results.flatMap(r => (r.data ? [[r.cluster, r.data] as const] : []))));
      setErrors(
        results.flatMap(r => {
          const messages = r.error ? [r.error] : r.data?.errors ?? [];
          return messages.length > 0 ? [{ cluster: r.cluster, message: messages.join('; ') }] : [];
        })
      );
    });
    return () => {
      cancelled = true;
    };
  }, [clusterKey, kindKey, reloadKey]);

  return { exceptions, errors, reload: () => setReloadKey(key => key + 1) };
}

/** Says which clusters' exceptions could not be read, so their findings may be shown as open. */
export function ExceptionReadErrors(props: Readonly<{ errors: ClusterError[] }>) {
  return (
    <>
      {props.errors.map(({ cluster, message }) => (
        <Alert key={cluster} severity="warning" sx={{ mb: 1 }}>
          Unable to read the security exceptions of cluster {cluster}: {message}. Findings that
          exceptions cover may be shown as open.
        </Alert>
      ))}
    </>
  );
}

/**
 * Opens the acceptance of the risk of the open CVEs of a page: a SecurityException in the
 * namespace, or a ClusterSecurityException without one. It opens without the permission to
 * create exceptions, as the form also offers the exception as YAML, such as for GitOps; the form
 * checks that permission itself.
 */
export function AcceptRiskButton(
  props: Readonly<{
    cveIds: string[];
    onClick: () => void;
  }>
) {
  const { cveIds, onClick } = props;
  return (
    <Button
      variant="outlined"
      size="small"
      startIcon={<Icon icon="mdi:shield-check-outline" />}
      onClick={onClick}
    >
      Accept the risk of {cveIds.length === 1 ? 'the open CVE' : `the ${cveIds.length} open CVEs`}
    </Button>
  );
}

function ExceptionLink({
  exception,
  cluster,
}: Readonly<{ exception: CveException; cluster?: string }>) {
  const label = exception.namespace ? `${exception.namespace}/${exception.name}` : exception.name;
  return exception.namespace ? (
    <Link
      routeName={RoutingName.SecurityExceptionDetail}
      params={{ namespace: exception.namespace, name: exception.name }}
      activeCluster={cluster}
    >
      {label}
    </Link>
  ) : (
    <Link
      routeName={RoutingName.SecurityExceptionClusterDetail}
      params={{ name: exception.name }}
      activeCluster={cluster}
    >
      {label}
    </Link>
  );
}

/** Who made the exception, why and until when. */
export function ExceptionDetails(props: Readonly<{ exception: CveException; cluster?: string }>) {
  const { exception, cluster } = props;
  const until = exception.expiresAt
    ? `until ${new Date(exception.expiresAt).toLocaleDateString()}`
    : 'does not expire';
  return (
    <Box>
      <Typography variant="body2" fontWeight="bold">
        {exceptionStateLabels[exception.state]}:{' '}
        <ExceptionLink exception={exception} cluster={cluster} />
      </Typography>
      <Typography variant="caption" component="div">
        {[exception.author && `by ${exception.author}`, until].filter(Boolean).join(', ')}
        {exception.expiredOnFix && ', or until a fix is available'}
      </Typography>
      {exception.reason && (
        <Typography variant="caption" component="div">
          Reason: {exception.reason}
        </Typography>
      )}
      {exception.statement && (
        <Typography variant="caption" component="div">
          {exception.state === 'accepted' || exception.state === 'planned' ? 'Action' : 'Impact'}:{' '}
          {exception.statement}
        </Typography>
      )}
    </Box>
  );
}

// what ExceptionDetails shows of an exception
function exceptionDetailsKey(exception: CveException) {
  return JSON.stringify([
    exception.kind,
    exception.namespace,
    exception.name,
    exception.state,
    exception.author,
    exception.expiresAt,
    exception.expiredOnFix,
    exception.reason,
    exception.statement,
  ]);
}

/**
 * The value of a table cell with an ExceptionChip: the label and the name of the exception, by
 * which the column sorts and the table searches, then the rest of what the chip shows. Headlamp
 * only draws a cell again when its value changes.
 */
export function exceptionChipValue(exception: CveException | undefined, note?: string): string {
  if (!exception) return '';
  return `${exceptionStateLabels[exception.state]}: ${exception.name} ${JSON.stringify([
    exceptionDetailsKey(exception),
    note,
  ])}`;
}

/** The state of the exception of a finding, with the exception in the tooltip. */
export function ExceptionChip(
  props: Readonly<{ exception: CveException; cluster?: string; note?: string }>
) {
  const { exception, cluster, note } = props;
  return (
    <Tooltip
      title={
        <Stack spacing={1}>
          <ExceptionDetails exception={exception} cluster={cluster} />
          {note && <Typography variant="caption">{note}</Typography>}
        </Stack>
      }
    >
      <Chip
        size="small"
        color={stateColors[exception.state]}
        variant={exception.state === 'accepted' ? 'filled' : 'outlined'}
        label={exceptionStateLabels[exception.state]}
      />
    </Tooltip>
  );
}

// shown in a tooltip; more are on the findings page of the workload
const maxListedExceptions = 5;

/**
 * The value of a table cell with an AcceptedChip: the counts of accepted and open CVEs and the
 * names of the exceptions, by which the table searches, then the rest of what the chip shows.
 */
export function acceptedChipValue(summary: WorkloadExceptions | undefined): string {
  if (!summary || summary.accepted.size === 0) return '';
  const listed = summary.exceptions.slice(0, maxListedExceptions);
  return `${summary.accepted.size} accepted, ${summary.open.length} open: ${summary.exceptions
    .map(exception => exception.name)
    .join(', ')} ${JSON.stringify(listed.map(exceptionDetailsKey))}`;
}

/** How many CVEs of a workload are accepted, with the exceptions that cover them. */
export function AcceptedChip(props: Readonly<{ summary: WorkloadExceptions; cluster?: string }>) {
  const { summary, cluster } = props;
  const count = summary.accepted.size;
  if (count === 0) return null;
  const all = summary.open.length === 0;
  return (
    <Tooltip
      title={
        <Stack spacing={1}>
          {summary.exceptions.slice(0, maxListedExceptions).map(exception => (
            <ExceptionDetails
              key={exceptionDetailsKey(exception)}
              exception={exception}
              cluster={cluster}
            />
          ))}
          {summary.exceptions.length > maxListedExceptions && (
            <Typography variant="caption">
              and {summary.exceptions.length - maxListedExceptions} more exceptions
            </Typography>
          )}
        </Stack>
      }
    >
      <Chip
        size="small"
        color="success"
        variant={all ? 'filled' : 'outlined'}
        label={all ? `All ${count} accepted` : `${count} accepted`}
      />
    </Tooltip>
  );
}
