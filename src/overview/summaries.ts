import { frameworkComplianceScore } from '../compliance/workload-scanning';
import { entryExpiresAt } from '../exceptions/apply-security-exceptions';
import { FrameWork } from '../rego';
import { severityRank } from '../search/searchIndex';
import {
  ClusterSecurityException,
  SecurityException,
} from '../softwarecomposition/SecurityException';
import { WorkloadConfigurationScanSummary } from '../softwarecomposition/WorkloadConfigurationScanSummary';
import { KevCatalog, matchExploitIds } from '../vulnerabilities/exploitData';
import { getImageScans, WorkloadScan } from '../vulnerabilities/scanData';

export interface CveCount {
  total: number;
  fixable: number;
}

/**
 * Distinct CVEs per severity in the scanned images, and how many of them have a fix. A CVE
 * counts once, with its most severe rating: the distributions of the images rate a CVE apart.
 */
export function countCves(workloadScans: WorkloadScan[]): Record<string, CveCount> {
  const fixableById = new Map<string, { severity: string; fixable: boolean }>();
  for (const image of getImageScans(workloadScans)) {
    for (const match of image.matches) {
      const known = fixableById.get(match.vulnerability.id);
      const { severity } = match.vulnerability;
      const fixable = match.vulnerability.fix?.state === 'fixed';
      fixableById.set(match.vulnerability.id, {
        severity:
          known && severityRank(known.severity) <= severityRank(severity)
            ? known.severity
            : severity,
        fixable: (known?.fixable ?? false) || fixable,
      });
    }
  }

  const counts: Record<string, CveCount> = {};
  for (const { severity, fixable } of fixableById.values()) {
    counts[severity] ??= { total: 0, fixable: 0 };
    counts[severity].total++;
    if (fixable) counts[severity].fixable++;
  }
  return counts;
}

/**
 * Distinct CVEs in the scanned images that CISA's catalog of known exploited vulnerabilities
 * lists, by their own id or, for a GHSA, a related CVE.
 */
export function countKnownExploited(workloadScans: WorkloadScan[], kev: KevCatalog): number {
  const exploited = new Set<string>();
  const checked = new Set<string>();
  for (const image of getImageScans(workloadScans)) {
    for (const match of image.matches) {
      const id = match.vulnerability.id;
      if (checked.has(id)) continue;
      checked.add(id);
      if (matchExploitIds(match).some(cve => kev.has(cve))) exploited.add(id);
    }
  }
  return exploited.size;
}

/** The compliance score of each of the named frameworks that is known. */
export function frameworkScores(
  workloadScans: WorkloadConfigurationScanSummary[],
  frameworks: FrameWork[],
  names: string[]
): Array<{ name: string; score: number }> {
  return names
    .map(name => frameworks.find(framework => framework.name === name))
    .filter((framework): framework is FrameWork => !!framework && framework.controls.length > 0)
    .map(framework => ({
      name: framework.name,
      score: Math.trunc(frameworkComplianceScore(workloadScans, framework)),
    }));
}

export interface ExceptionExpiry {
  name: string;
  // undefined for a ClusterSecurityException
  namespace?: string;
  cluster: string;
  expiresAt: string;
  expired: boolean;
  // the entries that expire then, by CVE or control id, while others of the exception apply
  // before or after; undefined when the exception as a whole expires
  entries?: string[];
}

// When a time ends: never for none, or one that cannot be read
function endTime(at: string | undefined): number {
  const time = at ? new Date(at).getTime() : NaN;
  return Number.isNaN(time) ? Infinity : time;
}

/**
 * The exceptions of a cluster that have expired, and so no longer apply, or that expire within
 * the given number of days, and the entries of exceptions that expire on their own. Ordered by
 * expiry. A vulnerability entry ends at its own expiry, which overrides that of the exception
 * as in kubevuln (entryExpiresAt), so it can outlast the exception: then the exception's expiry
 * is that of its other entries, and the entry is reported at its own.
 */
export function expiringExceptions(
  exceptions: { namespaced: SecurityException[]; cluster: ClusterSecurityException[] },
  cluster: string,
  now: Date = new Date(),
  days: number = 14
): ExceptionExpiry[] {
  const soon = now.getTime() + days * 24 * 60 * 60 * 1000;
  const expiries: ExceptionExpiry[] = [];
  for (const exception of [...exceptions.namespaced, ...exceptions.cluster]) {
    const base = {
      name: exception.metadata.name,
      namespace: exception.kind === 'SecurityException' ? exception.metadata.namespace : undefined,
      cluster,
    };
    const { posture = [], vulnerabilities = [], expiresAt: own } = exception.spec;
    // the parts of the exception with when they end: its posture entries, or the whole workload
    // without entries, end with it, and each vulnerability entry at its own expiry or else then
    const parts = [
      ...posture.map(entry => ({ id: entry.controlID, expiresAt: own })),
      ...vulnerabilities.map(entry => ({
        id: entry.vulnerability?.id,
        expiresAt: entryExpiresAt(exception, entry),
      })),
    ];
    if (parts.length === 0) parts.push({ id: '', expiresAt: own });
    const ownTime = endTime(own);
    const last = Math.max(...parts.map(part => endTime(part.expiresAt)));
    // the parts that end within the days, by the time they end
    const byTime = new Map<number, { expiresAt: string; ids: Set<string> }>();
    for (const { id, expiresAt } of parts) {
      const time = endTime(expiresAt);
      if (time >= soon) continue;
      const group = byTime.get(time) ?? { expiresAt: expiresAt!, ids: new Set<string>() };
      if (id) group.ids.add(id);
      byTime.set(time, group);
    }
    for (const [time, { expiresAt, ids }] of byTime) {
      const expired = time < now.getTime();
      if (time === ownTime && time === last) {
        expiries.push({ ...base, expiresAt: own!, expired });
      } else if (ids.size > 0) {
        expiries.push({ ...base, expiresAt, expired, entries: [...ids] });
      }
    }
  }
  return expiries.sort((a, b) => new Date(a.expiresAt).getTime() - new Date(b.expiresAt).getTime());
}
