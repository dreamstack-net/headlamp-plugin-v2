/*
  The workloads that run an image, from the vulnerability summaries of their containers.
*/
import { request } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import { getAllowedNamespaces } from '../common/clusterContext';
import { errorMessage } from '../common/errors';
import { getScanTime } from './reportTimestamp';

export interface ImageWorkload {
  kind: string;
  name: string;
  namespace: string;
  container: string;
  // the VulnerabilityManifestSummary of the container
  summaryName: string;
  summaryNamespace: string;
  scannedAt?: string;
}

/** The workloads that run an image, and the allowed namespaces that could not be read. */
export interface ImageWorkloadList {
  workloads: ImageWorkload[];
  // such as namespace team-b: forbidden
  errors: string[];
}

const summaries = '/apis/spdx.softwarecomposition.kubescape.io/v1beta1';

/**
 * The containers that run the image with the given kubescape.io/image-id label. The summaries
 * of their containers carry the same label as the report of the image; their metadata, which
 * a list without fullSpec returns, names the workload.
 */
export async function fetchImageWorkloads(
  imageId: string,
  cluster: string
): Promise<ImageWorkloadList> {
  const query = new URLSearchParams({ labelSelector: `kubescape.io/image-id=${imageId}` });
  const namespaces = getAllowedNamespaces(cluster);
  const paths =
    namespaces.length > 0
      ? namespaces.map(
          namespace =>
            `${summaries}/namespaces/${namespace}/vulnerabilitymanifestsummaries?${query}`
        )
      : [`${summaries}/vulnerabilitymanifestsummaries?${query}`];
  // an allowed namespace that cannot be read leaves the others, and the errors name it; when
  // none can be read, it rejects
  const results = await Promise.allSettled(paths.map(path => request(path, { cluster })));
  const errors = results.flatMap((result, i) =>
    result.status === 'rejected'
      ? [`namespace ${namespaces[i]}: ${errorMessage(result.reason)}`]
      : []
  );
  if (errors.length === results.length) throw (results[0] as PromiseRejectedResult).reason;

  const workloads = results
    .flatMap(result => (result.status === 'fulfilled' ? result.value.items ?? [] : []))
    .map((summary: any): ImageWorkload => {
      const labels = summary.metadata.labels ?? {};
      return {
        kind: labels['kubescape.io/workload-kind'] ?? '',
        name: labels['kubescape.io/workload-name'] ?? summary.metadata.name,
        namespace: labels['kubescape.io/workload-namespace'] ?? summary.metadata.namespace,
        container: labels['kubescape.io/workload-container-name'] ?? '',
        summaryName: summary.metadata.name,
        summaryNamespace: summary.metadata.namespace,
        scannedAt: getScanTime(summary),
      };
    })
    .sort((a, b) =>
      `${a.namespace}/${a.kind}/${a.name}`.localeCompare(`${b.namespace}/${b.kind}/${b.name}`)
    );
  return { workloads, errors };
}

/** When the image was last scanned for one of the workloads. */
export function latestScan(workloads: ImageWorkload[]): string | undefined {
  return workloads
    .map(workload => workload.scannedAt)
    .filter((time): time is string => !!time)
    .sort()
    .pop();
}
