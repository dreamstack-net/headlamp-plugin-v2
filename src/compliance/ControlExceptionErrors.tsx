import { Alert } from '@mui/material';
import type { ClusterError } from '../model';

/**
 * Says which clusters' security exceptions could not be read, so that controls they cover may be
 * counted as failed. Only the clusters of the page, when given: the scans of other clusters may
 * be in the cache of the pages.
 */
export function ControlExceptionErrors(
  props: Readonly<{ errors: ClusterError[]; clusters?: string[] }>
) {
  const { errors, clusters } = props;
  return (
    <>
      {errors
        .filter(({ cluster }) => !clusters || clusters.includes(cluster))
        .map(({ cluster, message }) => (
          <Alert key={cluster} severity="warning" sx={{ mb: 1 }}>
            Unable to read the security exceptions of cluster {cluster}: {message}. Controls that
            exceptions cover may be counted as failed.
          </Alert>
        ))}
    </>
  );
}
