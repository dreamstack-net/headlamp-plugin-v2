import type { VulnerabilityManifest } from '../softwarecomposition/VulnerabilityManifest';

type Finding = Pick<VulnerabilityManifest.Match, 'vulnerability' | 'artifact'>;

/**
 * A finding is a CVE in one package. The same CVE is often found in several packages of an
 * image (busybox, busybox-binsh and ssl_client share the busybox CVEs), and the relevant report
 * only holds the packages that the workload was seen to use, so relevance is a property of the
 * CVE in a package, not of the CVE. Kubescape's relevant counts count these findings too.
 */
export function findingKey(finding: Finding): string {
  return JSON.stringify([
    finding.vulnerability.id,
    finding.artifact?.name ?? '',
    finding.artifact?.version ?? '',
  ]);
}

/** The findings of a relevant report, including those that an exception hid. */
export function relevantFindingKeys(...lists: (Finding[] | null | undefined)[]): Set<string> {
  const keys = new Set<string>();
  for (const list of lists) {
    for (const finding of list ?? []) keys.add(findingKey(finding));
  }
  return keys;
}

/**
 * An id for each finding that is unique within the list. A package that is installed at several
 * paths (undici bundled with npm and with the application) gives findings with the same CVE,
 * name and version; their ids are told apart by the package id of the scanner and, when that is
 * missing or shared, by their order. Tables key their rows by these ids, and rows with the same
 * key are left on the page when a filter removes them.
 */
export function uniqueFindingIds<T extends Finding & { hidden?: boolean }>(
  findings: T[]
): string[] {
  const seen = new Map<string, number>();
  return findings.map(finding => {
    const base = JSON.stringify([
      finding.vulnerability.id,
      finding.artifact?.name ?? '',
      finding.artifact?.version ?? '',
      finding.artifact?.id ?? '',
      !!finding.hidden,
    ]);
    const count = seen.get(base) ?? 0;
    seen.set(base, count + 1);
    return count === 0 ? base : `${base}#${count}`;
  });
}
