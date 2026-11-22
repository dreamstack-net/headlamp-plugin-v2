import { describe, expect, it } from 'vitest';
import type {
  ClusterSecurityException,
  SecurityException,
  SecurityExceptionSpec,
} from '../softwarecomposition/SecurityException';
import type { VulnerabilityManifest } from '../softwarecomposition/VulnerabilityManifest';
import type { WorkloadConfigurationScanSummary } from '../softwarecomposition/WorkloadConfigurationScanSummary';
import type { ImageScan, WorkloadScan } from '../vulnerabilities/scanData';
import type { SecurityExceptionData } from './apply-security-exceptions';
import {
  clusterCoverage,
  CoverageCheck,
  coverageResults,
  describeCoverage,
  emptyCoverage,
  ExceptionCoverage,
  exceptionKey,
  isStale,
} from './coverage';

type Status = { status: string; subStatus?: string };

function configScan(
  kind: string,
  namespace: string,
  name: string,
  controls: Record<string, Status>
): WorkloadConfigurationScanSummary {
  return {
    metadata: {
      name: `${kind.toLowerCase()}-${name}`,
      namespace,
      cluster: 'prd',
      labels: {
        'kubescape.io/workload-kind': kind,
        'kubescape.io/workload-name': name,
        'kubescape.io/workload-namespace': namespace,
      },
    },
    spec: {
      controls: Object.fromEntries(
        Object.entries(controls).map(([controlID, status]) => [
          controlID,
          { controlID, status, severity: { scoreFactor: 7, severity: 'High' } },
        ])
      ),
    },
  } as unknown as WorkloadConfigurationScanSummary;
}

function match(id: string, options: { fixed?: boolean; related?: string } = {}) {
  return {
    artifact: { name: 'openssl', version: '3.0' },
    relatedVulnerabilities: options.related ? [{ id: options.related, description: '' }] : [],
    vulnerability: {
      id,
      severity: 'High',
      fix: { state: options.fixed ? 'fixed' : 'not-fixed', versions: [] },
    },
  } as unknown as VulnerabilityManifest.Match;
}

function image(
  imageName: string,
  matches: VulnerabilityManifest.Match[],
  ignoredMatches: VulnerabilityManifest.Match[] = []
): ImageScan {
  return {
    manifestName: imageName,
    namespace: 'kubescape',
    cluster: 'prd',
    imageName,
    creationTimestamp: '',
    matches,
    ignoredMatches,
  };
}

function workload(kind: string, namespace: string, name: string, imageScan?: ImageScan) {
  return {
    manifestName: `${kind}-${name}`,
    kind,
    name,
    namespace,
    container: 'main',
    cluster: 'prd',
    imageScan,
    relevant: undefined,
  } as WorkloadScan;
}

function namespaced(name: string, namespace: string, spec: SecurityExceptionSpec) {
  return {
    apiVersion: 'kubescape.io/v1beta1',
    kind: 'SecurityException',
    metadata: { name, namespace },
    spec,
  } as SecurityException;
}

function clusterWide(name: string, spec: SecurityExceptionSpec) {
  return {
    apiVersion: 'kubescape.io/v1beta1',
    kind: 'ClusterSecurityException',
    metadata: { name },
    spec,
  } as ClusterSecurityException;
}

function data(
  namespacedExceptions: SecurityException[],
  clusterExceptions: ClusterSecurityException[] = [],
  namespaceLabels: Record<string, Record<string, string>> = {}
): SecurityExceptionData {
  return {
    namespaced: namespacedExceptions,
    cluster: clusterExceptions,
    namespaceLabelsByName: new Map(Object.entries(namespaceLabels)),
  };
}

const failed = { status: 'failed' };
const passed = { status: 'passed' };
const passedByException = { status: 'passed', subStatus: 'w/exceptions' };

describe('posture entries', () => {
  const scans = [
    configScan('Deployment', 'shop', 'web', { 'C-0017': failed, 'C-0030': passed }),
    configScan('Deployment', 'shop', 'api', { 'C-0017': passedByException, 'C-0030': failed }),
    configScan('Deployment', 'dev', 'web', { 'C-0017': failed }),
  ];

  it('covers the controls of the matched workloads that fail or passed by an exception', () => {
    const ignore = namespaced('c-0017', 'shop', {
      posture: [{ controlID: 'C-0017', action: 'ignore' }],
    });
    // a control that passes on its own needs no exception
    const fixed = namespaced('c-0030-web', 'shop', {
      match: { resources: [{ kind: 'Deployment', name: 'web' }] },
      posture: [{ controlID: 'C-0030', action: 'ignore' }],
    });
    const coverage = clusterCoverage(data([ignore, fixed]), { configuration: scans });

    const covering = coverage.get(ignore)!;
    expect([...covering.workloads].sort()).toEqual(['Deployment/shop/api', 'Deployment/shop/web']);
    expect([...covering.controls]).toEqual(['C-0017']);
    const stale = coverage.get(fixed)!;
    expect([...stale.matched]).toEqual(['Deployment/shop/web']);
    expect(stale.workloads.size).toBe(0);
    expect(describeCoverage(fixed, stale)).toBe(
      'Covers nothing: the 1 matching workload has none of its failed controls'
    );
  });

  it('counts alert_only entries, exceptions of a whole workload, and namespace selectors', () => {
    const acknowledged = clusterWide('ack', {
      match: { namespaceSelector: { matchLabels: { env: 'dev' } } },
      posture: [{ controlID: 'C-0017', action: 'alert_only' }],
    });
    const whole = namespaced('whole-api', 'shop', {
      match: { resources: [{ kind: 'Deployment', name: 'api' }] },
    });
    const coverage = clusterCoverage(data([whole], [acknowledged], { dev: { env: 'dev' } }), {
      configuration: scans,
    });

    expect([...coverage.get(acknowledged)!.workloads]).toEqual(['Deployment/dev/web']);
    expect([...coverage.get(whole)!.controls].sort()).toEqual(['C-0017', 'C-0030']);
  });

  it('matches resources and control ids as Kubescape does: as patterns, ids without case', () => {
    const byName = namespaced('by-name', 'shop', {
      match: { resources: [{ kind: 'Deployment', name: 'web|api' }] },
      posture: [{ controlID: 'c-0017', action: 'ignore' }],
    });
    const byPattern = namespaced('by-pattern', 'shop', {
      posture: [{ controlID: 'C-00(17|30)', action: 'ignore' }],
    });
    const wrongCase = namespaced('wrong-case', 'shop', {
      match: { resources: [{ kind: 'deployment', name: 'web' }] },
      posture: [{ controlID: 'C-0017', action: 'ignore' }],
    });
    const coverage = clusterCoverage(data([byName, byPattern, wrongCase]), {
      configuration: scans,
    });

    expect([...coverage.get(byName)!.workloads].sort()).toEqual([
      'Deployment/shop/api',
      'Deployment/shop/web',
    ]);
    expect([...coverage.get(byName)!.controls]).toEqual(['C-0017']);
    expect([...coverage.get(byPattern)!.controls].sort()).toEqual(['C-0017', 'C-0030']);
    expect(coverage.get(wrongCase)!.matched.size).toBe(0);
  });

  it('says that no workload matches an exception of a workload that is gone', () => {
    const gone = namespaced('gone', 'shop', {
      match: { resources: [{ kind: 'StatefulSet', name: 'db' }] },
      posture: [{ controlID: 'C-0017', action: 'ignore' }],
    });
    const coverage = clusterCoverage(data([gone]), { configuration: scans }).get(gone)!;
    expect(describeCoverage(gone, coverage)).toBe('Covers nothing: no scanned workload matches');
  });

  it('covers nothing when expired', () => {
    const expired = namespaced('old', 'shop', {
      expiresAt: '2020-01-01T00:00:00Z',
      posture: [{ controlID: 'C-0017', action: 'ignore' }],
    });
    const coverage = clusterCoverage(data([expired]), { configuration: scans }).get(expired)!;
    expect(coverage.matched.size).toBe(0);
  });
});

describe('vulnerability entries', () => {
  const nginx = image(
    'docker.io/library/nginx:1.27',
    [match('CVE-1'), match('CVE-2', { fixed: true }), match('GHSA-3', { related: 'CVE-3' })],
    [match('CVE-4')]
  );
  const redis = image('docker.io/library/redis:7', [match('CVE-1')]);
  const scans = [
    workload('Deployment', 'shop', 'web', nginx),
    workload('Deployment', 'shop', 'cache', redis),
    workload('Deployment', 'dev', 'web', nginx),
    // its report was not read
    workload('Deployment', 'shop', 'new'),
  ];
  const entry = (id: string, extra = {}) => ({
    vulnerability: { id },
    status: 'not_affected' as const,
    justification: 'component_not_present' as const,
    ...extra,
  });

  it('covers the CVEs in the reports of matched workloads, open, hidden or by a related id', () => {
    const exception = namespaced('web', 'shop', {
      match: { resources: [{ kind: 'Deployment', name: 'web' }] },
      vulnerabilities: [entry('CVE-1'), entry('CVE-3'), entry('CVE-4'), entry('CVE-9')],
    });
    const coverage = clusterCoverage(data([exception]), { vulnerabilities: scans }).get(exception)!;

    expect([...coverage.workloads]).toEqual(['Deployment/shop/web']);
    expect([...coverage.images]).toEqual(['docker.io/library/nginx:1.27']);
    expect([...coverage.cves].sort()).toEqual(['CVE-1', 'CVE-3', 'CVE-4']);
    expect(describeCoverage(exception, coverage)).toBe('1 workload, 1 image: CVE-1, CVE-3, CVE-4');
  });

  it('matches images by pattern and aliases of the entry', () => {
    const exception = clusterWide('nginx', {
      match: { images: ['docker.io/library/nginx:*'] },
      vulnerabilities: [entry('GHSA-1', { vulnerability: { id: 'GHSA-1', aliases: ['CVE-1'] } })],
    });
    const coverage = clusterCoverage(data([], [exception]), { vulnerabilities: scans }).get(
      exception
    )!;
    expect([...coverage.workloads].sort()).toEqual(['Deployment/dev/web', 'Deployment/shop/web']);
    expect([...coverage.cves]).toEqual(['GHSA-1']);
  });

  it('ends an entry that ends on a fix once the CVE has one', () => {
    const exception = namespaced('fix', 'shop', {
      vulnerabilities: [entry('CVE-2', { expiredOnFix: true }), entry('CVE-8')],
    });
    const coverage = clusterCoverage(data([exception]), { vulnerabilities: scans }).get(exception)!;
    expect(coverage.cves.size).toBe(0);
    expect([...coverage.endedOnFix]).toEqual(['CVE-2']);
    expect(describeCoverage(exception, coverage)).toBe(
      'Covers nothing: the 2 matching workloads have none of its CVEs; ended as a fix exists: CVE-2'
    );
  });

  it('ends an entry that ends on a fix also when the CVE only lists fixed versions', () => {
    const listed = match('CVE-7');
    listed.vulnerability.fix.versions = ['1.2.3'];
    const exception = namespaced('fix', 'shop', {
      match: { resources: [{ kind: 'Deployment', name: 'web' }] },
      vulnerabilities: [entry('CVE-7', { expiredOnFix: true })],
    });
    const coverage = clusterCoverage(data([exception]), {
      vulnerabilities: [workload('Deployment', 'shop', 'web', image('app:1', [listed]))],
    }).get(exception)!;
    expect(coverage.cves.size).toBe(0);
    expect([...coverage.endedOnFix]).toEqual(['CVE-7']);
  });

  it('gives Unknown, not stale, while workloads it matches have no report', () => {
    const exception = namespaced('new', 'shop', {
      match: { resources: [{ kind: 'Deployment', name: 'new' }] },
      vulnerabilities: [entry('CVE-1')],
    });
    // it covers CVE-1 in the other workloads of the namespace
    const namespaceWide = namespaced('shop', 'shop', { vulnerabilities: [entry('CVE-1')] });
    const coverage = clusterCoverage(data([exception, namespaceWide]), { vulnerabilities: scans });
    expect([...coverage.get(exception)!.unscanned]).toEqual(['Deployment/shop/new']);
    expect(coverage.get(exception)!.matched.size).toBe(0);

    const key = exceptionKey('prd', exception);
    const wideKey = exceptionKey('prd', namespaceWide);
    const results = coverageResults(
      [
        { cluster: 'prd', exception },
        { cluster: 'prd', exception: namespaceWide },
      ],
      {
        coverage: new Map([
          [key, coverage.get(exception)!],
          [wideKey, coverage.get(namespaceWide)!],
        ]),
        incomplete: [],
      }
    );
    expect(results.get(key)).toEqual({
      status: 'unknown',
      text: 'Unknown: no vulnerability report was read for Deployment/shop/new',
    });
    expect(isStale(results.get(key))).toBe(false);
    expect(results.get(wideKey)!.status).toBe('covers');
  });

  it('leaves out expired entries and the scans that were not read', () => {
    const exception = namespaced('mixed', 'shop', {
      posture: [{ controlID: 'C-0017', action: 'ignore' }],
      vulnerabilities: [entry('CVE-1', { expiresAt: '2020-01-01T00:00:00Z' })],
    });
    // only the vulnerability scans were read
    const coverage = clusterCoverage(data([exception]), { vulnerabilities: scans }).get(exception)!;
    expect(coverage.cves.size).toBe(0);
    expect(describeCoverage(exception, coverage)).toBe(
      'Covers nothing: no scanned workload matches'
    );
  });

  it('covers the CVE of an entry that outlasts its expired exception, as kubevuln applies it', () => {
    const exception = namespaced('outlasting', 'shop', {
      expiresAt: '2020-01-01T00:00:00Z',
      match: { resources: [{ kind: 'Deployment', name: 'web' }] },
      vulnerabilities: [entry('CVE-1', { expiresAt: '2999-01-01T00:00:00Z' }), entry('CVE-4')],
    });
    const coverage = clusterCoverage(data([exception]), { vulnerabilities: scans }).get(exception)!;
    expect([...coverage.cves]).toEqual(['CVE-1']);

    const key = exceptionKey('prd', exception);
    const results = coverageResults([{ cluster: 'prd', exception }], {
      coverage: new Map([[key, coverage]]),
      incomplete: [],
    });
    expect(results.get(key)).toEqual({ status: 'covers', text: '1 workload, 1 image: CVE-1' });
  });

  it('calls an exception expired once all its entries are, by their own expiry or its own', () => {
    const exception = namespaced('ended', 'shop', {
      vulnerabilities: [entry('CVE-1', { expiresAt: '2020-01-01T00:00:00Z' })],
    });
    const key = exceptionKey('prd', exception);
    const results = coverageResults([{ cluster: 'prd', exception }], {
      coverage: new Map([[key, emptyCoverage()]]),
      incomplete: [],
    });
    expect(results.get(key)).toEqual({ status: 'expired', text: 'Expired' });
  });
});

describe('coverageResults', () => {
  const shared = clusterWide('shared', { posture: [{ controlID: 'C-0017', action: 'ignore' }] });
  const expired = clusterWide('expired', {
    expiresAt: '2020-01-01T00:00:00Z',
    posture: [{ controlID: 'C-0017', action: 'ignore' }],
  });
  const covering = (): ExceptionCoverage => ({
    ...emptyCoverage(),
    matched: new Set(['Deployment/shop/web']),
    workloads: new Set(['Deployment/shop/web']),
    controls: new Set(['C-0017']),
  });

  it('marks stale and expired exceptions, and names the clusters an exception covers in', () => {
    const exceptions = [
      { cluster: 'prd', exception: shared },
      { cluster: 'tst', exception: shared },
      { cluster: 'acc', exception: shared },
      { cluster: 'prd', exception: expired },
    ];
    const check: CoverageCheck = {
      coverage: new Map([
        [exceptionKey('prd', shared), covering()],
        [exceptionKey('tst', shared), emptyCoverage()],
        [exceptionKey('acc', shared), covering()],
        [exceptionKey('prd', expired), emptyCoverage()],
      ]),
      incomplete: [],
    };
    const results = coverageResults(exceptions, check);

    expect(results.get(exceptionKey('prd', shared))).toEqual({
      status: 'covers',
      text: '1 workload: C-0017; covers findings only in acc, prd',
    });
    const tst = results.get(exceptionKey('tst', shared))!;
    expect(tst.text).toBe(
      'Covers nothing: no scanned workload matches; covers findings only in acc, prd'
    );
    expect(isStale(tst)).toBe(true);
    expect(results.get(exceptionKey('prd', expired))).toEqual({
      status: 'expired',
      text: 'Expired',
    });
  });

  it('does not call an exception stale whose scans were not read completely', () => {
    const later = clusterWide('later', { posture: [{ controlID: 'C-0017', action: 'ignore' }] });
    const results = coverageResults(
      [
        { cluster: 'prd', exception: shared },
        { cluster: 'prd', exception: later },
        { cluster: 'tst', exception: shared },
      ],
      {
        coverage: new Map([[exceptionKey('prd', shared), emptyCoverage()]]),
        incomplete: [{ cluster: 'tst', message: 'stopped' }],
      }
    );

    expect(results.get(exceptionKey('tst', shared))!.status).toBe('unknown');
    // created after the check
    expect(results.get(exceptionKey('prd', later))!.status).toBe('unchecked');
    // the clusters that could not be checked are not compared
    expect(results.get(exceptionKey('prd', shared))!.text).toBe(
      'Covers nothing: no scanned workload matches'
    );
    expect([...results.values()].filter(isStale)).toHaveLength(1);
  });
});
