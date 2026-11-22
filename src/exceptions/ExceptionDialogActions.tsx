/*
  The buttons of the forms that create or change an exception: Cancel, Download YAML, which
  saves the exception for a GitOps repository and needs no permission in the cluster, and
  Create or Save, disabled with an explanation where the user may not change the cluster.
*/
import { Icon } from '@iconify/react';
import { Button, DialogActions, Tooltip } from '@mui/material';
import { ReactElement, useEffect, useState } from 'react';
import { AccessCheck, canI, deniedMessage } from '../common/permissions';

/**
 * The clusters in which the user is denied the check, once all clusters answered; undefined
 * while asking. Unanswered checks count as allowed. Undefined in the clusters stands for the
 * current cluster.
 */
export function useDeniedClusters(
  check: AccessCheck | null,
  clusters: Array<string | undefined>
): Array<string | undefined> | undefined {
  const [answer, setAnswer] = useState<{ key: string; denied: Array<string | undefined> }>();
  const key = JSON.stringify([check, clusters]);

  useEffect(() => {
    if (!check) return;
    let active = true;
    Promise.all(clusters.map(cluster => canI(check, cluster))).then(answers => {
      if (active) setAnswer({ key, denied: clusters.filter((_, i) => answers[i] === false) });
    });
    return () => {
      active = false;
    };
    // key covers check and clusters, which may be new objects on every render
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  return check && answer?.key === key ? answer.denied : undefined;
}

/**
 * An action in one or more clusters, disabled with an explanation when the user may do it in
 * none of them; when only some deny it, it stays enabled and says where it fails.
 */
export function PermittedInClusters(
  props: Readonly<{
    check: AccessCheck | null;
    // the current cluster by default
    clusters?: Array<string | undefined>;
    children: (allowed: boolean) => ReactElement;
  }>
) {
  const { check, children } = props;
  const clusters = props.clusters?.length ? props.clusters : [undefined];
  const denied = useDeniedClusters(check, clusters) ?? [];
  if (!check || denied.length === 0) return children(true);
  const named = denied.filter((cluster): cluster is string => !!cluster);
  const where =
    clusters.length > 1 && named.length > 0
      ? ` in ${named.length === 1 ? 'cluster' : 'clusters'} ${named.join(', ')}`
      : '';
  const message = `${deniedMessage(check).replace(/\.$/, '')}${where}.`;
  const allDenied = denied.length === clusters.length;
  return (
    <Tooltip
      describeChild
      title={
        allDenied
          ? `${message} Download the YAML to add it to a GitOps repository instead.`
          : `${message} It is only created in the other clusters.`
      }
    >
      <span>{children(!allDenied)}</span>
    </Tooltip>
  );
}

export function ExceptionDialogActions(
  props: Readonly<{
    onCancel: () => void;
    // saves the exception that the submit would send as YAML
    onDownload: () => void;
    onSubmit: () => void;
    submitLabel: string;
    // what the submit needs, nothing to check while the form misses the namespace
    check: AccessCheck | null;
    // the clusters the submit changes, the current one by default
    clusters?: Array<string | undefined>;
  }>
) {
  const { onCancel, onDownload, onSubmit, submitLabel, check, clusters } = props;
  return (
    <DialogActions>
      <Button onClick={onCancel}>Cancel</Button>
      <Tooltip
        describeChild
        title="Saves the exception as a YAML file, to add it to a GitOps repository instead of changing the cluster here."
      >
        <Button startIcon={<Icon icon="mdi:download" />} onClick={onDownload}>
          Download YAML
        </Button>
      </Tooltip>
      <PermittedInClusters check={check} clusters={clusters}>
        {allowed => (
          <Button onClick={onSubmit} variant="contained" disabled={!allowed}>
            {submitLabel}
          </Button>
        )}
      </PermittedInClusters>
    </DialogActions>
  );
}
