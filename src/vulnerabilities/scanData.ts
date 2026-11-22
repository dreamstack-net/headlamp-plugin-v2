import type { QueryTask } from '../query';
import type { VulnerabilityManifest } from '../softwarecomposition/VulnerabilityManifest';
import type { VulnerabilityManifestSummary } from '../softwarecomposition/VulnerabilityManifestSummary';
import { imageSourceLabel } from './imageSource';
import { getScanTime, getVulnerabilityReportCreatedAt } from './reportTimestamp';

export interface ImageScan {
  manifestName: string;
  namespace: string;
  cluster: string;
  imageName: string;
  creationTimestamp: string;
  reportCreatedAt?: string;
  matches: VulnerabilityManifest.Match[];
  // the findings that kubevuln hid because of a security exception
  ignoredMatches?: VulnerabilityManifest.IgnoredMatch[];
  // the source repository the labels of the image name
  source?: string;
}

export interface WorkloadScan {
  manifestName: string;
  name: string;
  kind: string;
  container: string;
  namespace: string;
  cluster: string;
  imageScan: ImageScan | undefined;
  relevant: ImageScan | undefined;
  // the image of the container, from the summary (`kubescape.io/image-tag`), known also when
  // its report is not
  image?: string;
  // when kubevuln last scanned the container
  scannedAt?: string;
  // the reports the summary refers to, which are read after the summaries
  references?: { all?: ManifestReference | null; relevant?: ManifestReference | null };
  // the findings per severity (Critical, High, ...) that the summary counts, which the pages
  // show until the report is read
  summaryCounts?: SummaryCounts;
}

/** The findings of a workload per severity, all and relevant, as its summary counts them. */
export type SummaryCounts = Record<string, { all: number; relevant?: number }>;

// the severities of a summary as the findings of the reports name them
const summarySeverities: Record<string, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  negligible: 'Negligible',
  unknown: 'Unknown',
};

/** The counts of a summary by the severities of the findings; undefined without counts. */
export function summaryCountsOf(
  severities: VulnerabilityManifestSummary['spec']['severities'] | undefined
): SummaryCounts | undefined {
  if (!severities) return undefined;
  const counts: SummaryCounts = {};
  for (const [key, severity] of Object.entries(summarySeverities)) {
    const score = severities[key as keyof typeof severities];
    if (!score) continue;
    counts[severity] = {
      all: score.all ?? 0,
      ...(typeof score.relevant === 'number' ? { relevant: score.relevant } : {}),
    };
  }
  return Object.keys(counts).length > 0 ? counts : undefined;
}

type ManifestReference = { name?: string; namespace?: string };

/**
 * The container of a workload as the lists name it: by namespace, as workloads of other
 * namespaces often have the same name, and by cluster when the scans are of several clusters.
 */
export function workloadLabel(
  scan: Pick<WorkloadScan, 'cluster' | 'namespace' | 'name' | 'container'>,
  withCluster: boolean
): string {
  const label = `${scan.namespace}/${scan.name}/${scan.container}`;
  return withCluster ? `${scan.cluster}/${label}` : label;
}

/** Identifies the scan of a workload's container, in all selected clusters. */
export function getWorkloadScanKey(
  scan: Pick<WorkloadScan, 'cluster' | 'namespace' | 'manifestName'>
): string {
  return JSON.stringify([scan.cluster, scan.namespace, scan.manifestName]);
}

/** Whether the scans are of more than one cluster. */
export function ofSeveralClusters(scans: readonly { cluster: string }[]): boolean {
  return scans.some(scan => scan.cluster !== scans[0].cluster);
}

export function getImageScanKey(image: Pick<ImageScan, 'cluster' | 'namespace' | 'manifestName'>) {
  return JSON.stringify([image.cluster, image.namespace, image.manifestName]);
}

export function getManifestNamespace(reference: { namespace?: string }) {
  return reference.namespace || 'kubescape';
}

export function getManifestReferenceKey(
  cluster: string,
  reference?: { name?: string; namespace?: string } | null
) {
  return reference?.name
    ? getImageScanKey({
        cluster,
        namespace: getManifestNamespace(reference),
        manifestName: reference.name,
      })
    : undefined;
}

// The reports of each cluster by name, built again when reports were added, removed or replaced
const reportsByName = new WeakMap<
  Map<string, ImageScan>,
  { size: number; byName: Map<string, ImageScan> }
>();

/**
 * Drops the index by name of the reports, after reports were replaced or removed. A cluster
 * that is read again often has as many reports as before, which the size does not show.
 */
export function imageScansChanged(images: Map<string, ImageScan>) {
  reportsByName.delete(images);
}

function findReportByName(images: Map<string, ImageScan>, cluster: string, name: string) {
  const lookup = () => {
    let index = reportsByName.get(images);
    if (!index || index.size !== images.size) {
      const byName = new Map<string, ImageScan>();
      for (const image of images.values()) {
        byName.set(JSON.stringify([image.cluster, image.manifestName]), image);
      }
      index = { size: images.size, byName };
      reportsByName.set(images, index);
    }
    return index.byName.get(JSON.stringify([cluster, name]));
  };
  const found = lookup();
  // a report that was replaced since the index was built is looked up in a new index
  if (found && images.get(getImageScanKey(found)) !== found) {
    imageScansChanged(images);
    return lookup();
  }
  return found;
}

/**
 * The report a summary refers to. Kubescape storage keeps the reports in the operator
 * namespace while summaries can refer to the namespace of their workload, so a report that is
 * not in the referenced namespace is looked up by its name, which is unique in a cluster.
 */
export function findImageScan(
  images: Map<string, ImageScan>,
  cluster: string,
  reference?: { name?: string; namespace?: string } | null
): ImageScan | undefined {
  const key = getManifestReferenceKey(cluster, reference);
  if (!key || !reference?.name) return undefined;
  return images.get(key) ?? findReportByName(images, cluster, reference.name);
}

export function toImageScan(manifest: VulnerabilityManifest): ImageScan {
  return {
    manifestName: manifest.metadata.name,
    namespace: manifest.metadata.namespace,
    cluster: manifest.metadata.cluster,
    imageName: manifest.metadata.annotations['kubescape.io/image-tag'],
    creationTimestamp: manifest.metadata.creationTimestamp,
    reportCreatedAt: getVulnerabilityReportCreatedAt(manifest),
    matches: (manifest.spec.payload.matches ?? []).map(slimMatch),
    ignoredMatches: manifest.spec.payload.ignoredMatches?.map(match => ({
      ...slimMatch(match),
      appliedIgnoreRules: match.appliedIgnoreRules,
    })),
    source: imageSourceLabel(manifest.spec.payload.source?.target?.config),
  };
}

/**
 * The fields of a match that the pages show. The scanner also stores how each match was
 * found and where the package is, which is most of a manifest; the cache keeps only these,
 * so the rest can be freed.
 */
function slimMatch(match: VulnerabilityManifest.Match): VulnerabilityManifest.Match {
  const { vulnerability, artifact, relatedVulnerabilities } = match;
  return {
    artifact: { name: artifact?.name, version: artifact?.version },
    relatedVulnerabilities: relatedVulnerabilities?.map(({ id, description }) => ({
      id,
      description,
    })),
    vulnerability: {
      id: vulnerability.id,
      severity: vulnerability.severity,
      description: vulnerability.description,
      dataSource: vulnerability.dataSource,
      fix: vulnerability.fix,
      cvss: vulnerability.cvss?.map(({ metrics }) => ({
        metrics: { baseScore: metrics?.baseScore },
      })),
    },
  };
}

export function getImageScans(workloadScans: WorkloadScan[]): ImageScan[] {
  const images = new Map<string, ImageScan>();
  workloadScans.forEach(({ imageScan }) => {
    if (imageScan) images.set(getImageScanKey(imageScan), imageScan);
  });
  return Array.from(images.values());
}

export function toWorkloadScan(
  summary: VulnerabilityManifestSummary,
  images: Map<string, ImageScan>
): WorkloadScan {
  const cluster = summary.metadata.cluster;
  // a summary without labels is left out by the reads, rather than stopping them
  const labels: Record<string, string> = summary.metadata.labels ?? {};
  return {
    manifestName: summary.metadata.name,
    name: labels['kubescape.io/workload-name'],
    namespace: labels['kubescape.io/workload-namespace'],
    cluster,
    container: labels['kubescape.io/workload-container-name'],
    kind: labels['kubescape.io/workload-kind'],
    imageScan: findImageScan(images, cluster, summary.spec.vulnerabilitiesRef?.all),
    relevant: findImageScan(images, cluster, summary.spec.vulnerabilitiesRef?.relevant),
    image: summary.metadata.annotations?.['kubescape.io/image-tag'] || undefined,
    scannedAt: getScanTime(summary),
    references: {
      all: summary.spec.vulnerabilitiesRef?.all,
      relevant: summary.spec.vulnerabilitiesRef?.relevant,
    },
    summaryCounts: summaryCountsOf(summary.spec.severities),
  };
}

/**
 * The workloads, with the reports of the cluster that their summaries refer to and that were read
 * since. A workload that changes is a new object, so the tables draw it again.
 */
export function linkWorkloadScans(
  workloads: WorkloadScan[],
  images: Map<string, ImageScan>,
  cluster: string
): WorkloadScan[] {
  return workloads.map(workload => {
    if (workload.cluster !== cluster || !workload.references) return workload;
    const imageScan = workload.imageScan ?? findImageScan(images, cluster, workload.references.all);
    const relevant =
      workload.relevant ?? findImageScan(images, cluster, workload.references.relevant);
    return imageScan === workload.imageScan && relevant === workload.relevant
      ? workload
      : { ...workload, imageScan, relevant };
  });
}

/**
 * Identifies a report by its name in a cluster. Summaries of several namespaces may refer to the
 * report of one image, each in its own namespace, while the storage keeps it once in the
 * operator namespace; findImageScan also finds a report by its name.
 */
export function reportNameKey(cluster: string, name: string): string {
  return JSON.stringify([cluster, name]);
}

/**
 * The reports that the workloads of a cluster refer to and that were not read, each name once,
 * leaving out the ones in `skip` (keys of reportNameKey).
 */
export function unreadReferences(
  workloads: WorkloadScan[],
  images: Map<string, ImageScan>,
  cluster: string,
  skip: Set<string>
): Array<{ name: string; namespace?: string }> {
  const unread = new Map<string, { name: string; namespace?: string }>();
  for (const workload of workloads) {
    if (workload.cluster !== cluster) continue;
    for (const reference of [workload.references?.all, workload.references?.relevant]) {
      if (!reference?.name) continue;
      const key = reportNameKey(cluster, reference.name);
      if (skip.has(key) || unread.has(key)) continue;
      if (findImageScan(images, cluster, reference)) continue;
      unread.set(key, { name: reference.name, namespace: reference.namespace });
    }
  }
  return [...unread.values()];
}

export interface VulnerabilityContext {
  workloadScans: WorkloadScan[];
  imageScans: Map<string, ImageScan>;
  queryTasks: QueryTask[];
}

export function invalidateScanClusters(
  context: VulnerabilityContext,
  clusters: string[],
  isNamespaceUpdated: (task: QueryTask) => boolean
) {
  const invalidated = new Set(
    context.queryTasks
      .filter(task => !clusters.includes(task.cluster) || isNamespaceUpdated(task))
      .map(task => task.cluster)
  );
  context.queryTasks = context.queryTasks.filter(task => !invalidated.has(task.cluster));
  context.workloadScans = context.workloadScans.filter(scan => !invalidated.has(scan.cluster));
  context.imageScans.forEach((scan, key) => {
    if (invalidated.has(scan.cluster)) context.imageScans.delete(key);
  });
  if (invalidated.size > 0) imageScansChanged(context.imageScans);
}
