/*
  Compares the images of the selected clusters, such as a test, an acceptance and a production
  cluster that are upgraded in turn: per image repository the versions each cluster runs with
  their CVEs, where the clusters differ, and the versions of other clusters that lack CVEs a
  cluster has. One pass over the workload scans groups their reports by repository, cluster and
  version, and the CVEs of each group are collected once.
*/
import type { VulnerabilityManifest } from '../softwarecomposition/VulnerabilityManifest';
import { imageTag, parseImageReference } from './registry';
import { getImageScanKey, ImageScan, workloadLabel, WorkloadScan } from './scanData';
import { compareVersions, isDate, isPrerelease, parseVersion } from './versions';

export const severityOrder = ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown'];

function severityRank(severity: string): number {
  const rank = severityOrder.indexOf(severity);
  return rank < 0 ? severityOrder.length : rank;
}

/** A CVE of a version, over all the packages it is found in. */
export interface CveInfo {
  // the most severe of its findings
  severity: string;
  // a finding of it has a fix
  fixable: boolean;
  // a finding of it is open: not hidden by an exception of the cluster
  open: boolean;
  // a relevant report of a workload of the version has it, in any package
  relevant: boolean;
}

/** The open CVEs of a version in a cluster, as its image page lists them. */
export interface CveCounts {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  fixable: number;
  // undefined when no workload of the version has a relevant report
  relevant?: { total: number; critical: number; high: number };
}

/** A workload container that runs a version, with what its vulnerability page needs. */
export interface WorkloadReference {
  cluster: string;
  namespace: string;
  kind: string;
  name: string;
  container: string;
  // the summary of the container, which names its vulnerability page
  manifestName: string;
}

/** A version of an image repository in one cluster, with the reports and workloads that run it. */
export interface ClusterVersion {
  cluster: string;
  // the tag, latest for an image without tag or digest, or the start of the digest
  version: string;
  imageNames: string[];
  // the reports of the version: a cluster that runs several builds of a tag has one for each
  reports: ImageScan[];
  // namespace/name/container of the workloads that run it
  workloads: string[];
  // the same workloads, in the same order
  workloadReferences: WorkloadReference[];
  // all CVEs of the reports, also those an exception hid, as exceptions differ per cluster
  cves: Map<string, CveInfo>;
  counts: CveCounts;
}

/** A version with the same CVEs in one or more clusters. */
export interface Variant {
  // the version, the clusters and the report each of them has, so it changes with the reports
  id: string;
  version: string;
  // in the order of the selected clusters
  clusters: string[];
  // one for each of the clusters
  versions: ClusterVersion[];
  cves: Map<string, CveInfo>;
}

/**
 * How two versions relate: newer when the first is a newer version, same version for tags of one
 * version (1.25.3 and 1.25.3-alpine), same tag for a tag with other reports (a rebuilt image, or
 * a scan with another vulnerability database), and unordered for tags that are not versions, of
 * other formats, or a release line and a release of it (1.25 and 1.25.3).
 */
export type VersionOrder = 'newer' | 'same version' | 'same tag' | 'unordered';

/** CVEs that one version has and another does not. */
export interface CveDelta {
  // most severe first
  cves: Array<{ id: string; severity: string }>;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

/** Two versions of a repository in different clusters that differ in tag or in CVEs. */
export interface VersionDifference {
  id: string;
  repository: string;
  // the newer version when the order is known, else the one of the first selected cluster
  a: Variant;
  b: Variant;
  // of a relative to b
  order: VersionOrder;
  onlyInA: CveDelta;
  onlyInB: CveDelta;
}

/**
 * A tag of a repository in all the clusters that run it. Clusters may have other reports of one
 * tag, of a rebuilt image or of a scan with another vulnerability database, which differ in a
 * few CVEs; the tag has the CVEs of all of them.
 */
export interface TagVersion extends Variant {
  // the reports of the clusters differ
  reportsDiffer: boolean;
  // the CVEs open in any of the clusters
  counts: CveCounts;
  // the workloads that run it, in the order of the clusters
  workloads: WorkloadReference[];
  // the newer tags of the repository, newest first, where one of the two runs in a cluster
  // that the other does not run in
  upgrades: UpgradeOption[];
  // the tags that cannot be ordered with it (branch builds, a release line such as 18 and
  // 18.4) and other variants of its version (-alpine instead of -bookworm), most CVEs removed
  // first
  others: UpgradeOption[];
}

/** Another tag of the repository, with the CVEs moving to it would remove and add. */
export interface UpgradeOption {
  to: TagVersion;
  // of to relative to the tag it is an option of
  order: Exclude<VersionOrder, 'same tag'>;
  // CVEs of the tag that to does not have
  removed: CveDelta;
  // CVEs of to that the tag does not have
  added: CveDelta;
}

/**
 * A tag that clusters run while a newer tag runs in another cluster without some of its CVEs:
 * the newest such tag, and the other newer tags.
 */
export interface UpgradeCandidate {
  id: string;
  repository: string;
  // the tag with the CVEs, and the clusters that run it
  from: TagVersion;
  // the newest tag that removes CVEs, and the clusters that run it
  to: TagVersion;
  order: 'newer';
  // CVEs of from that to does not have
  removed: CveDelta;
  // CVEs of to that from does not have
  added: CveDelta;
  // the other newer tags
  alternatives: UpgradeOption[];
}

export interface RepositoryComparison {
  // registry/repository, without tag or digest
  repository: string;
  // the versions each cluster runs, newest first
  versions: Map<string, ClusterVersion[]>;
  // the tags over all clusters, newest first
  tags: TagVersion[];
  // the clusters that run it, in the selected order
  runningIn: string[];
  // the clusters with scans that do not run it: each of their workloads has a report
  missingIn: string[];
  // the clusters with scans whose reports do not have it, while some of their workloads have no
  // report, so they may run it
  unknownIn: string[];
  // clusters run other tags
  versionsDiffer: boolean;
  // clusters run one tag with other reports
  reportsDiffer: boolean;
  differences: VersionDifference[];
}

export interface ClusterComparison {
  // the selected clusters of which scans were read, in the selected order
  clusters: string[];
  // the selected clusters of which no scans were read, which are left out of the comparison
  withoutScans: string[];
  // per cluster with scans, in the selected order, the workloads whose report was not read
  // (missing, failed or not named by the summary), so the image they run is not known
  withoutReports: Array<{ cluster: string; workloads: WorkloadReference[] }>;
  repositories: RepositoryComparison[];
  // the most critical CVEs removed first
  upgradeCandidates: UpgradeCandidate[];
  summary: {
    images: number;
    inSeveralClusters: number;
    // images with other versions, other reports, or not in every cluster (hasDifferences)
    differ: number;
    versionsDiffer: number;
    reportsDiffer: number;
    notInEveryCluster: number;
    // images of which a newer version has CVEs that the older version of another cluster does not
    newerAddCves: number;
  };
}

/** The images the Images table shows, by what the summary counts. */
export type ImageFilter = 'differ' | 'versions' | 'reports' | 'missing' | 'newerAdds' | 'all';

const imageFilterTests: Record<ImageFilter, (repository: RepositoryComparison) => boolean> = {
  differ: repository => hasDifferences(repository),
  versions: repository => repository.versionsDiffer,
  reports: repository => repository.reportsDiffer,
  missing: repository => repository.missingIn.length > 0 || repository.unknownIn.length > 0,
  newerAdds: repository => repository.differences.some(newerAddsCves),
  all: () => true,
};

/** The images of the comparison that the filter shows. */
export function filterRepositories(
  repositories: RepositoryComparison[],
  filter: ImageFilter
): RepositoryComparison[] {
  return filter === 'all' ? repositories : repositories.filter(imageFilterTests[filter]);
}

/**
 * The name of an image repository and the registry and path in front of it:
 * europe-docker.pkg.dev/project/team/api gives api and europe-docker.pkg.dev/project/team.
 */
export function splitRepository(repository: string): { name: string; path: string } {
  const slash = repository.lastIndexOf('/');
  return slash < 0
    ? { name: repository, path: '' }
    : { name: repository.slice(slash + 1), path: repository.slice(0, slash) };
}

/** The repository of an image, the same for each way to write it: docker.io/library/nginx. */
export function imageRepository(imageName: string): string {
  const reference = parseImageReference(imageName);
  return reference ? `${reference.registry}/${reference.repository}` : imageName.trim();
}

/** The version of an image: its tag, latest without tag or digest, or the start of its digest. */
export function imageVersion(imageName: string): string {
  const tag = imageTag(imageName);
  if (tag) return tag;
  const digest = imageName.trim().split('@')[1];
  // sha256: and 12 hex digits, as docker images shows image ids
  return digest ? `@${digest.slice(0, 19)}` : 'latest';
}

const withoutV = (prefix: string) => prefix.replace(/v$/, '');

/**
 * Orders two tags of a repository: positive when a is the newer version, 0 for one version, and
 * undefined when they cannot be ordered. Tags are versions of one format when their prefixes
 * only differ in a v; a release line such as 1.25 holds 1.25.3, so only another line is ordered
 * with it, and variants such as -alpine and -bookworm of one version are the same version.
 */
export function compareTags(a: string, b: string): number | undefined {
  const [versionA, versionB] = [parseVersion(a), parseVersion(b)];
  if (!versionA || !versionB) return undefined;
  if (withoutV(versionA.prefix) !== withoutV(versionB.prefix)) return undefined;
  // a date such as 20240101 tags a build, which is not ordered with a version or with a
  // release line such as 3, as alpine tags both
  if (isDate(versionA) !== isDate(versionB)) return undefined;
  const [numbersA, numbersB] = [versionA.numbers, versionB.numbers];
  for (let i = 0; i < Math.min(numbersA.length, numbersB.length); i++) {
    if (numbersA[i] !== numbersB[i]) return numbersA[i] - numbersB[i];
  }
  if (numbersA.length !== numbersB.length) return undefined;
  if (isPrerelease(versionA) !== isPrerelease(versionB)) return isPrerelease(versionA) ? -1 : 1;
  if (versionA.shape !== versionB.shape) return 0;
  return compareVersions(versionA, versionB);
}

/** Sorts tags newest first: versions by their numbers, then the tags that are not versions. */
export function newestFirst(a: string, b: string): number {
  const [versionA, versionB] = [parseVersion(a), parseVersion(b)];
  if (versionA && versionB) return compareVersions(versionB, versionA) || a.localeCompare(b);
  if (versionA || versionB) return versionA ? -1 : 1;
  return a.localeCompare(b);
}

// the workload scans of one version of a repository in one cluster
interface Group {
  repository: string;
  cluster: string;
  version: string;
  imageNames: Set<string>;
  reports: Map<string, ImageScan>;
  relevantReports: Map<string, ImageScan>;
  // by namespace/name/container
  workloads: Map<string, WorkloadReference>;
}

// the position of each selected cluster, by which variants and their clusters are ordered
type ClusterOrder = Map<string, number>;

/** Groups the scans of the clusters by repository, cluster and version, in one pass. */
function groupScans(workloadScans: readonly WorkloadScan[], order: ClusterOrder) {
  // images that many workloads run are parsed once
  const imageOf = new Map<string, { repository: string; version: string }>();
  const groups = new Map<string, Group>();
  const withScans = new Set<string>();
  // by cluster: a workload without a report runs the image its summary names, or any image when
  // the summary names none, so its cluster is not counted as missing that image (or any)
  const withoutReports = new Map<string, WorkloadReference[]>();
  const unknownRepositories = new Map<string, UnknownRepositories>();
  for (const scan of workloadScans) {
    if (!order.has(scan.cluster)) continue;
    withScans.add(scan.cluster);
    const report = scan.imageScan;
    if (!report?.imageName) {
      const ofCluster = withoutReports.get(scan.cluster) ?? [];
      ofCluster.push(workloadReference(scan));
      withoutReports.set(scan.cluster, ofCluster);
      const unknown = unknownRepositories.get(scan.cluster) ?? new Set<string>();
      if (unknown !== 'all') {
        if (scan.image) unknown.add(imageRepository(scan.image));
        unknownRepositories.set(scan.cluster, scan.image ? unknown : 'all');
      }
      continue;
    }
    let image = imageOf.get(report.imageName);
    if (!image) {
      image = {
        repository: imageRepository(report.imageName),
        version: imageVersion(report.imageName),
      };
      imageOf.set(report.imageName, image);
    }
    const key = JSON.stringify([image.repository, scan.cluster, image.version]);
    let group = groups.get(key);
    if (!group) {
      group = {
        ...image,
        cluster: scan.cluster,
        imageNames: new Set(),
        reports: new Map(),
        relevantReports: new Map(),
        workloads: new Map(),
      };
      groups.set(key, group);
    }
    group.imageNames.add(report.imageName);
    group.reports.set(getImageScanKey(report), report);
    if (scan.relevant) group.relevantReports.set(getImageScanKey(scan.relevant), scan.relevant);
    group.workloads.set(workloadLabel(scan, false), workloadReference(scan));
  }
  return { groups: groups.values(), withScans, withoutReports, unknownRepositories };
}

// the repositories a cluster may run without a report of them: those of the images its summaries
// name, or all of them when a summary names no image
type UnknownRepositories = Set<string> | 'all';

function workloadReference(scan: WorkloadScan): WorkloadReference {
  return {
    cluster: scan.cluster,
    namespace: scan.namespace,
    kind: scan.kind,
    name: scan.name,
    container: scan.container,
    manifestName: scan.manifestName,
  };
}

/**
 * Compares the images that the selected clusters run. Scans of other clusters are left out, a
 * selected cluster of which no scans were read is not counted as missing an image, and neither is
 * a cluster with workloads whose report was not read, as they may run it.
 */
export function compareClusters(
  workloadScans: readonly WorkloadScan[],
  selectedClusters: readonly string[]
): ClusterComparison {
  const selected = [
    ...new Set(
      selectedClusters.length > 0 ? selectedClusters : workloadScans.map(scan => scan.cluster)
    ),
  ];
  const order: ClusterOrder = new Map(selected.map((cluster, i) => [cluster, i]));
  const { groups, withScans, withoutReports, unknownRepositories } = groupScans(
    workloadScans,
    order
  );

  const byRepository = new Map<string, ClusterVersion[]>();
  for (const group of groups) {
    let versions = byRepository.get(group.repository);
    if (!versions) {
      versions = [];
      byRepository.set(group.repository, versions);
    }
    versions.push(toClusterVersion(group));
  }

  const clusters = selected.filter(cluster => withScans.has(cluster));
  const repositories = [...byRepository]
    .map(([repository, versions]) =>
      compareRepository(repository, versions, clusters, order, unknownRepositories)
    )
    .sort((a, b) => a.repository.localeCompare(b.repository));
  const count = (test: (repository: RepositoryComparison) => boolean) =>
    repositories.filter(test).length;

  return {
    clusters,
    withoutScans: selected.filter(cluster => !withScans.has(cluster)),
    withoutReports: clusters.flatMap(cluster => {
      const workloads = withoutReports.get(cluster);
      return workloads ? [{ cluster, workloads }] : [];
    }),
    repositories,
    upgradeCandidates: sortCandidates(
      repositories.flatMap(repository =>
        repository.tags.flatMap(tag => upgradeCandidate(repository.repository, tag))
      )
    ),
    summary: {
      images: repositories.length,
      inSeveralClusters: count(repository => repository.runningIn.length > 1),
      differ: count(imageFilterTests.differ),
      versionsDiffer: count(imageFilterTests.versions),
      reportsDiffer: count(imageFilterTests.reports),
      notInEveryCluster: count(imageFilterTests.missing),
      newerAddCves: count(imageFilterTests.newerAdds),
    },
  };
}

/**
 * The versions of a repository in each cluster and how they differ.
 *
 * @param clusters - The clusters with scans, in the selected order.
 * @param unknownRepositories - By cluster, the repositories its workloads without a report run.
 */
function compareRepository(
  repository: string,
  clusterVersions: ClusterVersion[],
  clusters: string[],
  order: ClusterOrder,
  unknownRepositories: ReadonlyMap<string, UnknownRepositories>
): RepositoryComparison {
  const byCluster = new Map<string, ClusterVersion[]>();
  for (const clusterVersion of clusterVersions) {
    const ofCluster = byCluster.get(clusterVersion.cluster) ?? [];
    ofCluster.push(clusterVersion);
    byCluster.set(clusterVersion.cluster, ofCluster);
  }
  for (const ofCluster of byCluster.values()) {
    ofCluster.sort((a, b) => newestFirst(a.version, b.version));
  }
  const runningIn = clusters.filter(cluster => byCluster.has(cluster));
  const tagLists = new Set(
    runningIn.map(cluster =>
      byCluster
        .get(cluster)!
        .map(clusterVersion => clusterVersion.version)
        .join('\n')
    )
  );
  const differences = compareVariants(repository, toVariants(clusterVersions, order), order);
  const notRunning = clusters.filter(cluster => !byCluster.has(cluster));
  const mayRun = (cluster: string) => {
    const unknown = unknownRepositories.get(cluster);
    return unknown === 'all' || !!unknown?.has(repository);
  };
  return {
    repository,
    // in the order of the clusters
    versions: new Map(runningIn.map(cluster => [cluster, byCluster.get(cluster)!])),
    tags: toTags(clusterVersions, order),
    runningIn,
    missingIn: notRunning.filter(cluster => !mayRun(cluster)),
    unknownIn: notRunning.filter(mayRun),
    versionsDiffer: tagLists.size > 1,
    reportsDiffer: differences.some(difference => difference.order === 'same tag'),
    differences,
  };
}

function position(cluster: string, order: ClusterOrder): number {
  return order.get(cluster) ?? order.size;
}

/** Merges the versions of the clusters that run one tag with the same CVEs, newest first. */
function toVariants(clusterVersions: ClusterVersion[], order: ClusterOrder): Variant[] {
  const byVersion = new Map<string, ClusterVersion[][]>();
  for (const clusterVersion of clusterVersions) {
    const sets = byVersion.get(clusterVersion.version) ?? [];
    byVersion.set(clusterVersion.version, sets);
    // a cluster runs a tag once, so a tag has few sets to compare with
    const same = sets.find(set => sameCves(set[0].cves, clusterVersion.cves));
    if (same) same.push(clusterVersion);
    else sets.push([clusterVersion]);
  }
  const variants = [...byVersion.values()].flat().map((set): Variant => {
    const versions = set.sort((a, b) => position(a.cluster, order) - position(b.cluster, order));
    return {
      id: JSON.stringify([
        versions[0].version,
        ...versions.map(version => [version.cluster, ...version.reports.map(getImageScanKey)]),
      ]),
      version: versions[0].version,
      clusters: versions.map(version => version.cluster),
      versions,
      cves: versions[0].cves,
    };
  });
  return variants.sort(
    (a, b) =>
      newestFirst(a.version, b.version) ||
      position(a.clusters[0], order) - position(b.clusters[0], order)
  );
}

/** The CVEs of several reports of one tag: a CVE is open, fixable or relevant in any of them. */
function unionCves(versions: ClusterVersion[]): Map<string, CveInfo> {
  if (versions.length === 1) return versions[0].cves;
  const cves = new Map<string, CveInfo>();
  for (const version of versions) {
    for (const [id, cve] of version.cves) {
      const known = cves.get(id);
      if (!known) {
        cves.set(id, { ...cve });
        continue;
      }
      if (severityRank(cve.severity) < severityRank(known.severity)) known.severity = cve.severity;
      known.fixable ||= cve.fixable;
      known.open ||= cve.open;
      known.relevant ||= cve.relevant;
    }
  }
  return cves;
}

/**
 * The tags of a repository over all clusters, newest first, with the tags each could move to.
 * An option needs a cluster that runs one of the two tags and not the other, as the page compares
 * clusters; an older tag is no option.
 */
function toTags(clusterVersions: ClusterVersion[], order: ClusterOrder): TagVersion[] {
  const byTag = new Map<string, ClusterVersion[]>();
  for (const clusterVersion of clusterVersions) {
    const ofTag = byTag.get(clusterVersion.version) ?? [];
    ofTag.push(clusterVersion);
    byTag.set(clusterVersion.version, ofTag);
  }
  const tags = [...byTag.values()]
    .map((versions): TagVersion => {
      versions.sort((a, b) => position(a.cluster, order) - position(b.cluster, order));
      const cves = unionCves(versions);
      return {
        id: JSON.stringify([
          versions[0].version,
          ...versions.map(version => [version.cluster, ...version.reports.map(getImageScanKey)]),
        ]),
        version: versions[0].version,
        clusters: versions.map(version => version.cluster),
        versions,
        cves,
        reportsDiffer: versions.some(version => !sameCves(version.cves, versions[0].cves)),
        counts: countCves(
          cves,
          versions.some(version => version.counts.relevant)
        ),
        workloads: versions.flatMap(version => version.workloadReferences),
        upgrades: [],
        others: [],
      };
    })
    .sort((a, b) => newestFirst(a.version, b.version));

  for (const tag of tags) {
    for (const other of tags) {
      if (other === tag || !inOtherClusters(tag, other)) continue;
      const compared = compareTags(other.version, tag.version);
      // an older tag is no option
      if (compared !== undefined && compared < 0) continue;
      let optionOrder: UpgradeOption['order'] = 'unordered';
      if (compared === 0) optionOrder = 'same version';
      else if (compared !== undefined) optionOrder = 'newer';
      const option: UpgradeOption = {
        to: other,
        order: optionOrder,
        removed: cveDelta(tag.cves, other.cves),
        added: cveDelta(other.cves, tag.cves),
      };
      if (optionOrder === 'newer') tag.upgrades.push(option);
      else tag.others.push(option);
    }
    // the tags are newest first, and so are the upgrades
    tag.others.sort(
      (x, y) =>
        y.removed.critical - x.removed.critical ||
        y.removed.high - x.removed.high ||
        y.removed.cves.length - x.removed.cves.length
    );
  }
  return tags;
}

/** The upgrade of a tag to recommend: the newest newer tag that removes some of its CVEs. */
export function recommendedUpgrade(tag: TagVersion): UpgradeOption | undefined {
  return tag.upgrades.find(option => option.removed.cves.length > 0);
}

/** The newest tag of the newer ones that removes CVEs of the tag, with the other newer tags. */
function upgradeCandidate(repository: string, tag: TagVersion): UpgradeCandidate[] {
  const best = recommendedUpgrade(tag);
  if (!best) return [];
  return [
    {
      id: JSON.stringify([repository, tag.id, best.to.id]),
      repository,
      from: tag,
      to: best.to,
      order: 'newer',
      removed: best.removed,
      added: best.added,
      alternatives: tag.upgrades.filter(option => option !== best),
    },
  ];
}

/** The differences between the variants of a repository that run in other clusters. */
function compareVariants(
  repository: string,
  variants: Variant[],
  order: ClusterOrder
): VersionDifference[] {
  const differences: VersionDifference[] = [];
  for (let i = 0; i < variants.length; i++) {
    for (let j = i + 1; j < variants.length; j++) {
      // two versions of one cluster are not a difference between clusters
      if (!inOtherClusters(variants[i], variants[j])) continue;
      const { a, b, versionOrder } = orderVariants(variants[i], variants[j], order);
      differences.push({
        id: JSON.stringify([repository, a.id, b.id]),
        repository,
        a,
        b,
        order: versionOrder,
        onlyInA: cveDelta(a.cves, b.cves),
        onlyInB: cveDelta(b.cves, a.cves),
      });
    }
  }
  return differences;
}

/** The newer variant first, or else the one of the first selected cluster. */
function orderVariants(x: Variant, y: Variant, order: ClusterOrder) {
  const byCluster = (versionOrder: VersionOrder) =>
    position(x.clusters[0], order) <= position(y.clusters[0], order)
      ? { a: x, b: y, versionOrder }
      : { a: y, b: x, versionOrder };
  if (x.version === y.version) return byCluster('same tag');
  const compared = compareTags(x.version, y.version);
  if (compared === undefined) return byCluster('unordered');
  if (compared === 0) return byCluster('same version');
  const versionOrder: VersionOrder = 'newer';
  return compared > 0 ? { a: x, b: y, versionOrder } : { a: y, b: x, versionOrder };
}

// whether a cluster runs one of the two and not the other: versions that the same clusters run
// are no difference between clusters, however many clusters that are
function inOtherClusters(x: Variant, y: Variant): boolean {
  return (
    x.clusters.some(cluster => !y.clusters.includes(cluster)) ||
    y.clusters.some(cluster => !x.clusters.includes(cluster))
  );
}

function sameCves(a: Map<string, CveInfo>, b: Map<string, CveInfo>): boolean {
  if (a.size !== b.size) return false;
  for (const id of a.keys()) {
    if (!b.has(id)) return false;
  }
  return true;
}

function toClusterVersion(group: Group): ClusterVersion {
  const relevantIds = new Set<string>();
  for (const report of group.relevantReports.values()) {
    for (const match of report.matches) relevantIds.add(match.vulnerability.id);
    for (const match of report.ignoredMatches ?? []) relevantIds.add(match.vulnerability.id);
  }
  const cves = new Map<string, CveInfo>();
  const add = (match: VulnerabilityManifest.Match, open: boolean) => {
    const { id, severity } = match.vulnerability;
    const fixable = match.vulnerability.fix?.state === 'fixed';
    const known = cves.get(id);
    if (!known) {
      cves.set(id, { severity, fixable, open, relevant: relevantIds.has(id) });
      return;
    }
    if (severityRank(severity) < severityRank(known.severity)) known.severity = severity;
    known.fixable ||= fixable;
    known.open ||= open;
  };
  // a report that several workloads share is read once
  for (const report of group.reports.values()) {
    for (const match of report.matches) add(match, true);
    for (const match of report.ignoredMatches ?? []) add(match, false);
  }
  const workloads = [...group.workloads.keys()].sort();
  return {
    cluster: group.cluster,
    version: group.version,
    imageNames: [...group.imageNames].sort(),
    reports: [...group.reports.values()],
    workloads,
    workloadReferences: workloads.map(label => group.workloads.get(label)!),
    cves,
    counts: countCves(cves, group.relevantReports.size > 0),
  };
}

function countCves(cves: Map<string, CveInfo>, withRelevant: boolean): CveCounts {
  const counts = { total: 0, critical: 0, high: 0, medium: 0, low: 0, fixable: 0 };
  const relevant = { total: 0, critical: 0, high: 0 };
  for (const cve of cves.values()) {
    if (!cve.open) continue;
    const critical = cve.severity === 'Critical';
    const high = cve.severity === 'High';
    counts.total++;
    if (critical) counts.critical++;
    if (high) counts.high++;
    if (cve.severity === 'Medium') counts.medium++;
    if (cve.severity === 'Low') counts.low++;
    if (cve.fixable) counts.fixable++;
    if (cve.relevant) {
      relevant.total++;
      if (critical) relevant.critical++;
      if (high) relevant.high++;
    }
  }
  return withRelevant ? { ...counts, relevant } : counts;
}

/** The CVEs of one version that the other does not have, most severe first. */
function cveDelta(of: Map<string, CveInfo>, other: Map<string, CveInfo>): CveDelta {
  const cves: CveDelta['cves'] = [];
  for (const [id, cve] of of) {
    if (!other.has(id)) cves.push({ id, severity: cve.severity });
  }
  cves.sort(
    (a, b) => severityRank(a.severity) - severityRank(b.severity) || a.id.localeCompare(b.id)
  );
  const count = (severity: string) => cves.filter(cve => cve.severity === severity).length;
  return {
    cves,
    critical: count('Critical'),
    high: count('High'),
    medium: count('Medium'),
    low: count('Low'),
  };
}

/** The number of CVEs of a severity in a delta or in counts: Critical, High, Medium or Low. */
export function severityCount(counts: CveDelta | CveCounts, severity: string): number {
  const key = severity.toLowerCase();
  return key === 'critical' || key === 'high' || key === 'medium' || key === 'low'
    ? counts[key]
    : 0;
}

/** The workloads that run a variant, in the order of its clusters. */
export function variantWorkloads(variant: Variant): WorkloadReference[] {
  return variant.versions.flatMap(version => version.workloadReferences);
}

/** The workloads of a candidate's version: those that would move. */
export function candidateWorkloads(candidate: UpgradeCandidate): WorkloadReference[] {
  return variantWorkloads(candidate.from);
}

/** Whether the newer of two versions has CVEs the older one does not. */
export function newerAddsCves(difference: VersionDifference): boolean {
  return difference.order === 'newer' && difference.onlyInA.cves.length > 0;
}

function sortCandidates(candidates: UpgradeCandidate[]): UpgradeCandidate[] {
  return candidates.sort(
    (x, y) =>
      y.removed.critical - x.removed.critical ||
      y.removed.high - x.removed.high ||
      y.removed.cves.length - x.removed.cves.length ||
      x.added.cves.length - y.added.cves.length ||
      x.repository.localeCompare(y.repository)
  );
}

/** Whether the clusters differ in the versions of the repository, or run it or not. */
export function hasDifferences(repository: RepositoryComparison): boolean {
  return (
    repository.versionsDiffer ||
    repository.reportsDiffer ||
    repository.missingIn.length > 0 ||
    repository.unknownIn.length > 0
  );
}

/** tst; tst and prd; tst, acc and prd */
export function listClusters(clusters: readonly string[]): string {
  if (clusters.length <= 1) return clusters[0] ?? '';
  return `${clusters.slice(0, -1).join(', ')} and ${clusters[clusters.length - 1]}`;
}

function cveCount(count: number): string {
  return `${count} ${count === 1 ? 'CVE' : 'CVEs'}`;
}

/** The critical and high CVEs of a delta, such as 4 critical, 2 high; empty without them. */
export function severityText(delta: CveDelta): string {
  const parts: string[] = [];
  if (delta.critical > 0) parts.push(`${delta.critical} critical`);
  if (delta.high > 0) parts.push(`${delta.high} high`);
  return parts.join(', ');
}

function withSeverity(text: string, delta: CveDelta): string {
  const severity = severityText(delta);
  return severity ? `${text} (${severity})` : text;
}

// tst runs; tst and acc run
function clustersRun(variant: Variant): string {
  return `${listClusters(variant.clusters)} ${variant.clusters.length === 1 ? 'runs' : 'run'}`;
}

function runs(variant: Variant): string {
  return `${clustersRun(variant)} ${variant.version}`;
}

function reportOf(variant: Variant): string {
  return variant.clusters.length === 1
    ? `${variant.clusters[0]}'s report`
    : `the reports of ${listClusters(variant.clusters)}`;
}

function notIn(delta: CveDelta, of: Variant, other: Variant): string {
  const count = delta.cves.length;
  return withSeverity(
    `${cveCount(count)} of ${listClusters(of.clusters)} ${count === 1 ? 'is' : 'are'} not in ` +
      reportOf(other),
    delta
  );
}

/**
 * The difference as a sentence: tst runs 1.25.3, prd runs 1.25.1: 12 CVEs of prd are not in
 * tst's report (4 critical); the newer 1.25.3 adds 2 CVEs (1 high).
 */
export function describeDifference(difference: VersionDifference): string {
  const { a, b, order, onlyInA, onlyInB } = difference;
  const head =
    order === 'same tag'
      ? `${listClusters([...a.clusters, ...b.clusters])} run ${a.version} with other reports`
      : `${runs(a)}, ${runs(b)}`;
  const parts: string[] = [];
  if (onlyInB.cves.length > 0) parts.push(notIn(onlyInB, b, a));
  if (onlyInA.cves.length > 0) {
    parts.push(
      order === 'newer'
        ? withSeverity(`the newer ${a.version} adds ${cveCount(onlyInA.cves.length)}`, onlyInA)
        : notIn(onlyInA, a, b)
    );
  }
  if (parts.length === 0) parts.push('the reports have the same CVEs');
  return `${head}: ${parts.join('; ')}`;
}

/**
 * The candidate as a sentence: prd runs 1.25.1: moving to 1.25.3, which tst runs, removes 12
 * CVEs (4 critical) and adds 2 (1 high).
 */
export function describeCandidate(candidate: UpgradeCandidate): string {
  const { from, to, removed, added } = candidate;
  const adds = added.cves.length > 0 ? withSeverity(` and adds ${added.cves.length}`, added) : '';
  return (
    `${runs(from)}: moving to ${to.version}, which ${clustersRun(to)}, ` +
    `removes ${withSeverity(cveCount(removed.cves.length), removed)}${adds}`
  );
}

/** A part of the state of a repository in the clusters, with what it is about. */
export interface StatusPart {
  label: string;
  kind: 'versions' | 'reports' | 'missing' | 'unknown' | 'same';
}

/** The state of a repository in the clusters, such as Versions differ and Not in prd. */
export function repositoryStatusParts(repository: RepositoryComparison): StatusPart[] {
  const parts: StatusPart[] = [];
  if (repository.versionsDiffer) parts.push({ label: 'Versions differ', kind: 'versions' });
  else if (repository.reportsDiffer) parts.push({ label: 'Reports differ', kind: 'reports' });
  if (repository.missingIn.length > 0) {
    parts.push({
      label:
        repository.runningIn.length === 1 && repository.unknownIn.length === 0
          ? `Only in ${repository.runningIn[0]}`
          : `Not in ${listClusters(repository.missingIn)}`,
      kind: 'missing',
    });
  }
  // not "Not in": a workload of the cluster without a report may run it
  if (repository.unknownIn.length > 0) {
    const [only] = repository.unknownIn;
    parts.push({
      label:
        repository.unknownIn.length === 1
          ? `Not in ${only}'s reports`
          : `Not in the reports of ${listClusters(repository.unknownIn)}`,
      kind: 'unknown',
    });
  }
  return parts.length > 0 ? parts : [{ label: 'Same', kind: 'same' }];
}

/** The state of a repository in the clusters, such as Versions differ; Not in prd. */
export function repositoryStatus(repository: RepositoryComparison): string {
  return repositoryStatusParts(repository)
    .map(part => part.label)
    .join('; ');
}

/** How the version a candidate moves to relates to the version it moves from. */
export function candidateOrderText(order: UpgradeOption['order']): string {
  if (order === 'newer') return 'Newer version';
  if (order === 'same version') return 'Other variant';
  return 'Not comparable';
}
