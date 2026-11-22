/*
  Security exceptions as YAML for a GitOps repository: the object as a user would write it,
  without what the API server, kubectl, Argo CD or this plugin set on it in a cluster.
*/
import * as yaml from 'js-yaml';
import { saveToFile } from '../common/filedialog';
import {
  ClusterSecurityException,
  SecurityException,
} from '../softwarecomposition/SecurityException';
import { historyAnnotation } from './history';

export type AnyException = SecurityException | ClusterSecurityException;

// The fields of the metadata that the API server sets, and the owners, which are named by their
// uid in the cluster. cluster is not a Kubernetes field, but Headlamp may add it.
const clusterSetMetadata = new Set([
  'uid',
  'resourceVersion',
  'creationTimestamp',
  'managedFields',
  'generation',
  'selfLink',
  'deletionTimestamp',
  'deletionGracePeriodSeconds',
  'ownerReferences',
  'cluster',
]);

// Annotations that tools set when they apply or change the object in a cluster
const clusterSetAnnotations = new Set([
  // the history of the changes made with this plugin. It is left out: it records who created
  // and changed the exception in the cluster, which in Git is the commit log. A copy in the file
  // would be frozen at the download, name a create in the cluster that a form's file never had
  // (Argo CD applies it, not the user), and differ from the live annotation after the next
  // change. spec.author is kept: it names who wrote the exception, which stays true wherever the
  // file is applied, and Kubescape's own tools show it.
  historyAnnotation,
  // the copy of the applied object that kubectl apply keeps
  'kubectl.kubernetes.io/last-applied-configuration',
  // set by Argo CD on every sync, to know which application the object belongs to
  'argocd.argoproj.io/tracking-id',
]);

/**
 * The exception as it belongs in a GitOps repository: apiVersion, kind, metadata and spec,
 * without the status and the fields that the API server and tools set in the cluster.
 */
export function exportableException<T extends AnyException>(exception: T): T {
  const metadata: Record<string, any> = {};
  for (const [key, value] of Object.entries(exception.metadata ?? {})) {
    if (!clusterSetMetadata.has(key)) metadata[key] = value;
  }
  const annotations = Object.fromEntries(
    Object.entries(exception.metadata?.annotations ?? {}).filter(
      ([key]) => !clusterSetAnnotations.has(key)
    )
  );
  delete metadata.annotations;
  const { name, namespace, ...rest } = metadata;
  return {
    apiVersion: exception.apiVersion ?? 'kubescape.io/v1beta1',
    kind: exception.kind,
    metadata: {
      name,
      ...(exception.kind === 'SecurityException' && { namespace }),
      ...rest,
      ...(Object.keys(annotations).length > 0 && { annotations }),
    },
    spec: exception.spec,
  } as T;
}

/** The exception as one YAML document, see {@link exportableException}. */
export function exceptionYaml(exception: AnyException): string {
  // long reasons stay on one line instead of being folded
  return yaml.dump(exportableException(exception), { lineWidth: -1, noRefs: true });
}

/** The file an exception is saved to, named after it. */
export function exceptionFileName(exception: AnyException): string {
  return `${exception.metadata.name}.yaml`;
}

/** Saves the exception as a YAML file, see {@link exportableException}. */
export function saveExceptionYaml(exception: AnyException, enqueueSnackbar: Function) {
  return saveToFile(exceptionYaml(exception), exceptionFileName(exception), enqueueSnackbar);
}

/** An exception and the cluster it was read from. */
export interface ClusterException {
  cluster: string;
  exception: AnyException;
}

/**
 * The exceptions as one file of YAML documents, cluster-scoped ones first, then by namespace and
 * name. With exceptions of several clusters, a comment names the clusters of each document, and
 * an exception that is the same in several clusters is written once, as a GitOps repository
 * would hold it once for all of them.
 */
export function exceptionsYaml(exceptions: ClusterException[]): string {
  const sortKey = ({ cluster, exception }: ClusterException) => [
    exception.kind,
    exception.kind === 'SecurityException' ? exception.metadata.namespace : '',
    exception.metadata.name,
    cluster,
  ];
  const compare = (a: ClusterException, b: ClusterException) => {
    const [keyA, keyB] = [sortKey(a), sortKey(b)];
    for (let i = 0; i < keyA.length; i++) {
      const order = keyA[i].localeCompare(keyB[i]);
      if (order !== 0) return order;
    }
    return 0;
  };
  const sorted = [...exceptions].sort(compare);
  const several = new Set(exceptions.map(({ cluster }) => cluster)).size > 1;
  // the clusters of each document
  const documents = new Map<string, string[]>();
  for (const { cluster, exception } of sorted) {
    const document = exceptionYaml(exception);
    const clusters = documents.get(document);
    if (clusters) clusters.push(cluster);
    else documents.set(document, [cluster]);
  }
  return [...documents]
    .map(([document, clusters]) =>
      several
        ? `# ${clusters.length > 1 ? 'Clusters' : 'Cluster'}: ${clusters.join(', ')}\n${document}`
        : document
    )
    .join('---\n');
}

/** The file that the exceptions of the clusters are saved to. */
export function exceptionsFileName(clusters: string[]): string {
  return clusters.length === 1 && clusters[0]
    ? `security-exceptions-${clusters[0]}.yaml`
    : 'security-exceptions.yaml';
}
