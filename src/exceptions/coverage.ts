/*
  What security exceptions currently cover in the scans of their cluster. An exception that
  covers nothing is likely stale: the workload is gone, the image was updated, the CVE or the
  control was fixed.

  Posture entries cover the controls of the workloads they match that fail, or passed because
  of an exception; a control that passes on its own needs no exception. Vulnerability entries
  cover the CVEs that the reports of the workloads they match have, open or already hidden by
  kubevuln. The scans are indexed once per check, so that each exception only looks at the
  workloads its namespace or resources name.
*/
import type { WorkloadConfigurationScanSummary } from '../softwarecomposition/WorkloadConfigurationScanSummary';
import type { ImageScan, WorkloadScan } from '../vulnerabilities/scanData';
import {
  ControlIds,
  entryExpiresAt,
  isExceptionExpired,
  isExpired,
  matchesWorkload,
  MatchRules,
  SecurityExceptionData,
  WorkloadExceptionMarks,
  workloadExceptionMarks,
} from './apply-security-exceptions';
import type { AnyException } from './exceptionYaml';
import { hasKnownFix, imageMatches } from './vulnerabilityExceptions';

/** What an exception covers in the scans of its cluster. */
export interface ExceptionCoverage {
  // the workloads it matches that were scanned, as kind/namespace/name
  matched: Set<string>;
  // the workloads its vulnerability entries may cover whose reports were not read, such as a
  // report that is missing, as kind/namespace/name
  unscanned: Set<string>;
  // the workloads whose findings it covers
  workloads: Set<string>;
  // the controls of its posture entries that fail in those workloads, or passed by an exception
  controls: Set<string>;
  // the CVEs of its entries that the reports of those workloads have
  cves: Set<string>;
  // the images of those reports
  images: Set<string>;
  // the CVEs whose entries end on a fix, and that have one now
  endedOnFix: Set<string>;
}

export function emptyCoverage(): ExceptionCoverage {
  return {
    matched: new Set(),
    unscanned: new Set(),
    workloads: new Set(),
    controls: new Set(),
    cves: new Set(),
    images: new Set(),
    endedOnFix: new Set(),
  };
}

/** Whether the exception covers any finding. */
export function coversFindings(coverage: ExceptionCoverage): boolean {
  return coverage.controls.size > 0 || coverage.cves.size > 0;
}

interface WorkloadIdentity {
  kind: string;
  name: string;
  namespace: string;
  // of a configuration scan; '' for the core group
  apiGroup?: string;
}

/** The workloads by namespace and by kind and name, to find those an exception may match. */
interface WorkloadIndex<T> {
  all: T[];
  byNamespace: Map<string, T[]>;
  byKindName: Map<string, T[]>;
}

const kindNameKey = (kind: string, name: string) => `${kind.toLowerCase()}/${name}`;

function pushTo<K, V>(map: Map<K, V[]>, key: K, value: V) {
  const values = map.get(key);
  if (values) values.push(value);
  else map.set(key, [value]);
}

function indexWorkloads<T>(items: T[], identity: (item: T) => WorkloadIdentity): WorkloadIndex<T> {
  const index: WorkloadIndex<T> = { all: items, byNamespace: new Map(), byKindName: new Map() };
  for (const item of items) {
    const { kind, name, namespace } = identity(item);
    pushTo(index.byNamespace, namespace, item);
    pushTo(index.byKindName, kindNameKey(kind, name), item);
  }
  return index;
}

// Whether a pattern of Kubescape only matches itself (with its case)
const plainText = (pattern: string) => !/[\\^$.|?*+()[\]{}]/.test(pattern);

/**
 * The workloads the exception may match: those of the resources it names, those of the
 * namespace of a SecurityException, or all. matchesWorkload decides. Kubescape reads the kind
 * and the name of a resource as regular expressions, so resources whose names are patterns
 * are not looked up by name.
 */
function candidates<T>(
  index: WorkloadIndex<T>,
  exception: AnyException,
  scanner: MatchRules['scanner']
): T[] {
  const resources = exception.spec.match?.resources ?? [];
  const named = (resource: { kind: string; name?: string }) =>
    !!resource.name &&
    (scanner === 'kubevuln' || (plainText(resource.kind) && plainText(resource.name)));
  if (resources.length > 0 && resources.every(named)) {
    const found = new Set<T>();
    for (const resource of resources) {
      for (const item of index.byKindName.get(kindNameKey(resource.kind, resource.name!)) ?? []) {
        found.add(item);
      }
    }
    return [...found];
  }
  if (exception.kind === 'SecurityException') {
    return index.byNamespace.get(exception.metadata.namespace) ?? [];
  }
  return index.all;
}

const workloadKey = ({ kind, namespace, name }: WorkloadIdentity) => `${kind}/${namespace}/${name}`;

function configurationIdentity(scan: WorkloadConfigurationScanSummary): WorkloadIdentity {
  const labels = scan.metadata.labels ?? {};
  const kind = labels['kubescape.io/workload-kind'] ?? '';
  const name = labels['kubescape.io/workload-name'] ?? '';
  return {
    kind,
    name,
    // Kubescape takes a Namespace to be in the namespace of its name
    namespace: kind === 'Namespace' ? name : labels['kubescape.io/workload-namespace'] ?? '',
    apiGroup: labels['kubescape.io/workload-api-group'],
  };
}

/** Whether a control needs an exception: it fails, or passed because of one. */
function inEffect(control: WorkloadConfigurationScanSummary.Control | undefined): boolean {
  return (
    !!control &&
    (control.status?.status === 'failed' || control.status?.subStatus === 'w/exceptions')
  );
}

/** The exception alone, to match it as the plugin applies exceptions (workloadExceptionMarks). */
function onlyException(data: SecurityExceptionData, exception: AnyException) {
  return {
    ...data,
    namespaced: exception.kind === 'SecurityException' ? [exception] : [],
    cluster: exception.kind === 'ClusterSecurityException' ? [exception] : [],
  };
}

// Whether the exception matches the workload, by the rules of the scanner that applies its
// posture entries (Kubescape) or its vulnerability entries (kubevuln)
function matches(
  data: SecurityExceptionData,
  exception: AnyException,
  workload: WorkloadIdentity,
  scanner: MatchRules['scanner']
) {
  return matchesWorkload(
    exception,
    workload.kind,
    workload.name,
    workload.namespace,
    data.namespaceLabelsByName,
    data.objectSelectorMatches ?? new Map(),
    { scanner, apiGroup: workload.apiGroup }
  );
}

// Whether the exception has posture entries, or is one of a whole workload without entries
function hasPostureScope(exception: AnyException) {
  const { posture, vulnerabilities } = exception.spec;
  return !!posture?.length || !vulnerabilities?.length;
}

function postureCoverage(
  data: SecurityExceptionData,
  exception: AnyException,
  index: WorkloadIndex<WorkloadConfigurationScanSummary>,
  coverage: ExceptionCoverage
) {
  // what the exception excludes of a workload it matches, the same for every such workload
  let marks: WorkloadExceptionMarks | undefined;
  // an alert_only entry does not exclude the control, but acknowledges its failure
  const alertOnly = new ControlIds();
  const entryIDs = (exception.spec.posture ?? []).map(entry => {
    if (entry.action === 'alert_only') alertOnly.add(entry.controlID);
    return entry.controlID;
  });
  // The entries name controls as Kubescape compares them: without case, and as patterns. Ids
  // of plain text, as most are, are looked up in the controls of a scan, which are named in
  // capitals, rather than compared with each of them.
  const lookup = entryIDs.every(plainText)
    ? [...new Set(entryIDs.flatMap(id => [id, id.toUpperCase()]))]
    : undefined;
  const alone = onlyException(data, exception);
  for (const scan of candidates(index, exception, 'kubescape')) {
    const workload = configurationIdentity(scan);
    if (!matches(data, exception, workload, 'kubescape')) continue;
    const key = workloadKey(workload);
    coverage.matched.add(key);
    marks ??= workloadExceptionMarks(scan, alone);
    const { workload: whole, everywhere, inFrameworks } = marks;
    const controls = scan.spec.controls ?? {};
    const covered = (whole || !lookup ? Object.values(controls) : lookup.map(id => controls[id]))
      .filter(
        control =>
          inEffect(control) &&
          (whole ||
            everywhere.has(control.controlID) ||
            !!inFrameworks.get(control.controlID) ||
            alertOnly.has(control.controlID))
      )
      .map(control => control.controlID);
    if (covered.length === 0) continue;
    coverage.workloads.add(key);
    for (const id of covered) coverage.controls.add(id);
  }
}

/** A CVE in a report: whether one of its findings has no fix, and whether kubevuln hid it. */
interface CveFinding {
  unfixed: boolean;
  ignored: boolean;
}

/** The CVEs of the reports, by id and related id, each report indexed once per check. */
class ReportIndex {
  private readonly findings = new Map<ImageScan, Map<string, CveFinding>>();

  of(image: ImageScan): Map<string, CveFinding> {
    let found = this.findings.get(image);
    if (found) return found;
    const cves = new Map<string, CveFinding>();
    const add = (match: ImageScan['matches'][number], ignored: boolean) => {
      // the cached reports leave out the CPE matches by which kubevuln also finds a fix
      const unfixed = !hasKnownFix(match);
      const ids = [
        match.vulnerability?.id,
        ...(match.relatedVulnerabilities ?? []).map(related => related.id),
      ];
      for (const id of ids) {
        if (!id) continue;
        const known = cves.get(id);
        cves.set(id, {
          unfixed: unfixed || !!known?.unfixed,
          ignored: ignored || !!known?.ignored,
        });
      }
    };
    for (const match of image.matches ?? []) add(match, false);
    for (const match of image.ignoredMatches ?? []) add(match, true);
    found = cves;
    this.findings.set(image, found);
    return found;
  }
}

function vulnerabilityCoverage(
  data: SecurityExceptionData,
  exception: AnyException,
  index: WorkloadIndex<WorkloadScan>,
  reports: ReportIndex,
  coverage: ExceptionCoverage
) {
  // an entry ends at its own expiry, or else at that of the exception
  const entries = (exception.spec.vulnerabilities ?? []).filter(
    entry => !isExpired(entryExpiresAt(exception, entry))
  );
  if (entries.length === 0) return;
  const patterns = exception.spec.match?.images ?? [];
  // per report: whether the image patterns match it, and the CVEs of the entries it has
  const imageMatched = new Map<ImageScan, boolean>();
  const coveredOf = new Map<ImageScan, string[]>();
  const covered = (image: ImageScan) => {
    let ids = coveredOf.get(image);
    if (ids) return ids;
    const cves = reports.of(image);
    ids = [];
    for (const entry of entries) {
      let finding: CveFinding | undefined;
      for (const id of [entry.vulnerability.id, ...(entry.vulnerability.aliases ?? [])]) {
        finding ??= cves.get(id);
      }
      if (!finding) continue;
      // kubevuln no longer applies an entry that ends on a fix once the CVE has one
      if (entry.expiredOnFix && !finding.unfixed && !finding.ignored) {
        coverage.endedOnFix.add(entry.vulnerability.id);
      } else {
        ids.push(entry.vulnerability.id);
      }
    }
    coveredOf.set(image, ids);
    return ids;
  };

  for (const scan of candidates(index, exception, 'kubevuln')) {
    if (!matches(data, exception, scan, 'kubevuln')) continue;
    const image = scan.imageScan;
    if (!image) {
      // its report is missing or was not read: whether it has the CVEs, or the image of the
      // patterns, is not known
      coverage.unscanned.add(workloadKey(scan));
      continue;
    }
    let matched = imageMatched.get(image);
    if (matched === undefined) {
      matched =
        patterns.length === 0 ||
        patterns.some(pattern => imageMatches(pattern, image.imageName ?? ''));
      imageMatched.set(image, matched);
    }
    if (!matched) continue;
    const key = workloadKey(scan);
    coverage.matched.add(key);
    const ids = covered(image);
    if (ids.length === 0) continue;
    coverage.workloads.add(key);
    coverage.images.add(image.imageName);
    for (const id of ids) coverage.cves.add(id);
  }
}

/**
 * What each exception of a cluster covers in the scans of that cluster. What has expired covers
 * nothing, as it no longer applies: the posture entries of an expired exception, and the
 * vulnerability entries past their own expiry or, without one, that of the exception.
 *
 * @param scans - The scans of the cluster; undefined for those that were not read.
 */
export function clusterCoverage(
  data: SecurityExceptionData,
  scans: {
    configuration?: WorkloadConfigurationScanSummary[];
    vulnerabilities?: WorkloadScan[];
  }
): Map<AnyException, ExceptionCoverage> {
  const configurationIndex = scans.configuration
    ? indexWorkloads(scans.configuration, configurationIdentity)
    : undefined;
  const vulnerabilityIndex = scans.vulnerabilities
    ? indexWorkloads(scans.vulnerabilities, scan => scan)
    : undefined;
  const reports = new ReportIndex();

  const result = new Map<AnyException, ExceptionCoverage>();
  for (const exception of [...data.namespaced, ...data.cluster]) {
    const coverage = emptyCoverage();
    result.set(exception, coverage);
    if (configurationIndex && hasPostureScope(exception) && !isExpired(exception.spec.expiresAt)) {
      postureCoverage(data, exception, configurationIndex, coverage);
    }
    if (vulnerabilityIndex && exception.spec.vulnerabilities?.length) {
      vulnerabilityCoverage(data, exception, vulnerabilityIndex, reports, coverage);
    }
  }
  return result;
}

/** Identifies an exception in the clusters: a namespaced and a cluster-wide one may share a name. */
export function exceptionKey(cluster: string, exception: AnyException): string {
  return JSON.stringify([
    cluster,
    exception.kind,
    exception.kind === 'SecurityException' ? exception.metadata.namespace : '',
    exception.metadata.name,
  ]);
}

export type CoverageStatus = 'covers' | 'nothing' | 'expired' | 'unknown' | 'unchecked';

/** What the check found for an exception, as the Coverage column shows it. */
export interface CoverageResult {
  status: CoverageStatus;
  text: string;
}

/** Whether the exception is likely stale: it covers nothing or has expired. */
export function isStale(result: CoverageResult | undefined): boolean {
  return result?.status === 'nothing' || result?.status === 'expired';
}

const plural = (count: number, word: string) => `${count} ${word}${count === 1 ? '' : 's'}`;

function listed(ids: string[], shown = 3) {
  const more = ids.length - shown;
  return more > 0 ? `${ids.slice(0, shown).join(', ')} and ${more} more` : ids.join(', ');
}

/** What the exception covers, or why it covers nothing, in a line. */
export function describeCoverage(exception: AnyException, coverage: ExceptionCoverage): string {
  if (coversFindings(coverage)) {
    const counts = [
      plural(coverage.workloads.size, 'workload'),
      ...(coverage.images.size > 0 ? [plural(coverage.images.size, 'image')] : []),
    ];
    const findings = [...[...coverage.controls].sort(), ...[...coverage.cves].sort()];
    return `${counts.join(', ')}: ${listed(findings)}`;
  }
  const ended =
    coverage.endedOnFix.size > 0
      ? `; ended as a fix exists: ${listed([...coverage.endedOnFix].sort())}`
      : '';
  if (coverage.matched.size === 0) return `Covers nothing: no scanned workload matches${ended}`;
  const posture = hasPostureScope(exception);
  const vulnerabilities = !!exception.spec.vulnerabilities?.length;
  let what = 'failed controls or CVEs';
  if (!vulnerabilities) what = 'failed controls';
  else if (!posture) what = 'CVEs';
  return `Covers nothing: ${
    coverage.matched.size === 1
      ? 'the 1 matching workload has none of its'
      : `the ${coverage.matched.size} matching workloads have none of its`
  } ${what}${ended}`;
}

/** The result of a check of the exceptions of the clusters. */
export interface CoverageCheck {
  // by exceptionKey
  coverage: Map<string, ExceptionCoverage>;
  // the clusters whose scans or exceptions could not be read completely, with why
  incomplete: Array<{ cluster: string; message: string }>;
}

/**
 * The results of the check for the listed exceptions, by exceptionKey. An exception that exists
 * in several clusters, as one from a GitOps repository does, and covers findings in only some
 * of them, names those clusters.
 */
export function coverageResults(
  exceptions: Array<{ cluster: string; exception: AnyException }>,
  check: CoverageCheck
): Map<string, CoverageResult> {
  const incomplete = new Map(check.incomplete.map(({ cluster, message }) => [cluster, message]));
  const results = new Map<string, CoverageResult>();
  // the clusters of each exception by kind, namespace and name, and those it covers findings in
  const groups = new Map<string, { keys: string[]; covering: string[] }>();
  for (const { cluster, exception } of exceptions) {
    const key = exceptionKey(cluster, exception);
    const coverage = check.coverage.get(key);
    let result: CoverageResult;
    if (isExceptionExpired(exception)) {
      result = { status: 'expired', text: 'Expired' };
    } else if (incomplete.has(cluster)) {
      result = {
        status: 'unknown',
        text: `Unknown: the scans of cluster ${cluster} could not be read completely`,
      };
    } else if (!coverage) {
      result = { status: 'unchecked', text: 'Not checked' };
    } else if (!coversFindings(coverage) && coverage.unscanned.size > 0) {
      // what it covers in the workloads without a report is not known
      result = {
        status: 'unknown',
        text: `Unknown: no vulnerability report was read for ${listed(
          [...coverage.unscanned].sort()
        )}`,
      };
    } else {
      result = {
        status: coversFindings(coverage) ? 'covers' : 'nothing',
        text: describeCoverage(exception, coverage),
      };
    }
    results.set(key, result);
    if (result.status !== 'covers' && result.status !== 'nothing') continue;
    const groupKey = exceptionKey('', exception);
    let group = groups.get(groupKey);
    if (!group) {
      group = { keys: [], covering: [] };
      groups.set(groupKey, group);
    }
    group.keys.push(key);
    if (result.status === 'covers') group.covering.push(cluster);
  }
  for (const { keys, covering } of groups.values()) {
    if (covering.length === 0 || covering.length === keys.length) continue;
    const note = `; covers findings only in ${covering.sort().join(', ')}`;
    for (const key of keys) {
      const result = results.get(key)!;
      results.set(key, { ...result, text: result.text + note });
    }
  }
  return results;
}
