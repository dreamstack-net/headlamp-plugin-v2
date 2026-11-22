import { FrameWork } from '../rego';
import {
  ClusterSecurityException,
  SecurityException,
} from '../softwarecomposition/SecurityException';
import { WorkloadConfigurationScanSummary } from '../softwarecomposition/WorkloadConfigurationScanSummary';
import {
  getImageScanKey,
  ImageScan,
  toImageScan,
  toWorkloadScan,
} from '../vulnerabilities/scanData';
import { manifest, match, summary } from '../vulnerabilities/testFixtures';
import { countCves, expiringExceptions, frameworkScores } from './summaries';

it('counts distinct CVEs per severity and those with a fix', () => {
  const image = toImageScan(manifest());
  const critical = (id: string, fixed: boolean) => {
    const m = match(id);
    m.vulnerability.severity = 'Critical';
    m.vulnerability.fix = fixed
      ? { state: 'fixed', versions: ['2.0'] }
      : { state: 'not-fixed', versions: [] };
    return m;
  };
  // CVE-1 is found in two packages, one of which has a fix
  image.matches = [critical('CVE-1', false), critical('CVE-1', true), critical('CVE-2', false)];
  image.matches.push(match('CVE-3'));
  const workloads = [toWorkloadScan(summary(), new Map([[getImageScanKey(image), image]]))];

  expect(countCves(workloads)).toEqual({
    Critical: { total: 2, fixable: 1 },
    High: { total: 1, fixable: 1 },
  });
});

it('counts a CVE that images rate apart once, with its most severe rating', () => {
  const rated = (id: string, severity: string) => {
    const m = match(id);
    m.vulnerability.severity = severity;
    return m;
  };
  const image = (name: string, matches: ReturnType<typeof match>[]): ImageScan => ({
    ...toImageScan(manifest()),
    manifestName: name,
    matches,
  });
  // the distribution of one image rates CVE-1 lower than that of the other, and CVE-2 higher
  const alpine = image('alpine', [rated('CVE-1', 'Critical'), rated('CVE-2', 'Low')]);
  const debian = image('debian', [rated('CVE-1', 'Negligible'), rated('CVE-2', 'High')]);
  const workload = (imageScan: ImageScan) => ({
    ...toWorkloadScan(summary(), new Map()),
    imageScan,
  });

  // whichever image is counted first
  for (const images of [
    [alpine, debian],
    [debian, alpine],
  ]) {
    expect(countCves(images.map(workload))).toEqual({
      Critical: { total: 1, fixable: 1 },
      High: { total: 1, fixable: 1 },
    });
  }
});

it('scores the named frameworks that are known and have controls', () => {
  const control = (controlID: string) => ({ controlID } as FrameWork['controls'][number]);
  const frameworks = [
    { name: 'NSA', controls: [control('C-1'), control('C-2')] },
    { name: 'Empty', controls: [] },
  ] as unknown as FrameWork[];
  const scan = {
    metadata: { labels: {} },
    exceptedByPolicy: false,
    spec: {
      controls: {
        'C-1': { controlID: 'C-1', status: { status: 'passed' } },
        'C-2': { controlID: 'C-2', status: { status: 'failed' } },
      },
    },
  } as unknown as WorkloadConfigurationScanSummary;

  expect(frameworkScores([scan], frameworks, ['NSA', 'Empty', 'Unknown'])).toEqual([
    { name: 'NSA', score: 50 },
  ]);
});

it('lists expired exceptions and those expiring within two weeks, soonest first', () => {
  const now = new Date('2026-10-30T12:00:00Z');
  const namespaced = (name: string, expiresAt?: string): SecurityException => ({
    apiVersion: 'kubescape.io/v1beta1',
    kind: 'SecurityException',
    metadata: { name, namespace: 'shop' },
    spec: { expiresAt },
  });
  const clusterWide: ClusterSecurityException = {
    apiVersion: 'kubescape.io/v1beta1',
    kind: 'ClusterSecurityException',
    metadata: { name: 'cluster-wide' },
    spec: { expiresAt: '2026-11-05T00:00:00Z' },
  };

  expect(
    expiringExceptions(
      {
        namespaced: [
          namespaced('no-expiry'),
          namespaced('later', '2026-12-31T00:00:00Z'),
          namespaced('expired', '2026-10-01T00:00:00Z'),
        ],
        cluster: [clusterWide],
      },
      'cluster-a',
      now
    )
  ).toEqual([
    {
      name: 'expired',
      namespace: 'shop',
      cluster: 'cluster-a',
      expiresAt: '2026-10-01T00:00:00Z',
      expired: true,
    },
    {
      name: 'cluster-wide',
      namespace: undefined,
      cluster: 'cluster-a',
      expiresAt: '2026-11-05T00:00:00Z',
      expired: false,
    },
  ]);
});

it('lists the entries of an exception that expire on their own', () => {
  const now = new Date('2026-10-30T12:00:00Z');
  const entry = (id: string, expiresAt?: string) => ({
    vulnerability: { id },
    status: 'not_affected' as const,
    expiresAt,
  });
  const exception: SecurityException = {
    apiVersion: 'kubescape.io/v1beta1',
    kind: 'SecurityException',
    metadata: { name: 'per-cve', namespace: 'shop' },
    spec: {
      vulnerabilities: [
        entry('CVE-1', '2026-10-01T00:00:00Z'),
        entry('CVE-2', '2026-11-05T00:00:00Z'),
        entry('CVE-3', '2026-11-05T00:00:00Z'),
        // later than two weeks, and without an expiry
        entry('CVE-4', '2027-01-01T00:00:00Z'),
        entry('CVE-5'),
      ],
    },
  } as SecurityException;

  expect(expiringExceptions({ namespaced: [exception], cluster: [] }, 'cluster-a', now)).toEqual([
    {
      name: 'per-cve',
      namespace: 'shop',
      cluster: 'cluster-a',
      expiresAt: '2026-10-01T00:00:00Z',
      expired: true,
      entries: ['CVE-1'],
    },
    {
      name: 'per-cve',
      namespace: 'shop',
      cluster: 'cluster-a',
      expiresAt: '2026-11-05T00:00:00Z',
      expired: false,
      entries: ['CVE-2', 'CVE-3'],
    },
  ]);

  // an entry with an expiry of its own outlasts its exception, as in kubevuln: the exception's
  // expiry ends the entries without one, and the others end at their own
  exception.spec.expiresAt = '2026-10-15T00:00:00Z';
  expect(
    expiringExceptions({ namespaced: [exception], cluster: [] }, 'cluster-a', now).map(
      ({ expiresAt, expired, entries }) => ({ expiresAt, expired, entries })
    )
  ).toEqual([
    { expiresAt: '2026-10-01T00:00:00Z', expired: true, entries: ['CVE-1'] },
    { expiresAt: '2026-10-15T00:00:00Z', expired: true, entries: ['CVE-5'] },
    { expiresAt: '2026-11-05T00:00:00Z', expired: false, entries: ['CVE-2', 'CVE-3'] },
  ]);
});

it('names what ends with an exception whose entries outlast it', () => {
  const now = new Date('2026-10-30T12:00:00Z');
  const exception = {
    apiVersion: 'kubescape.io/v1beta1',
    kind: 'ClusterSecurityException',
    metadata: { name: 'mixed' },
    spec: {
      expiresAt: '2026-10-20T00:00:00Z',
      posture: [{ controlID: 'C-0017', action: 'ignore' }],
      vulnerabilities: [
        {
          vulnerability: { id: 'CVE-1' },
          status: 'not_affected',
          expiresAt: '2026-11-10T00:00:00Z',
        },
      ],
    },
  } as ClusterSecurityException;
  const expiries = () =>
    expiringExceptions({ namespaced: [], cluster: [exception] }, 'cluster-a', now);

  expect(expiries()).toEqual([
    {
      name: 'mixed',
      namespace: undefined,
      cluster: 'cluster-a',
      expiresAt: '2026-10-20T00:00:00Z',
      expired: true,
      entries: ['C-0017'],
    },
    {
      name: 'mixed',
      namespace: undefined,
      cluster: 'cluster-a',
      expiresAt: '2026-11-10T00:00:00Z',
      expired: false,
      entries: ['CVE-1'],
    },
  ]);

  // the entry ends before the exception, which then expires as a whole
  exception.spec.vulnerabilities![0].expiresAt = '2026-10-10T00:00:00Z';
  expect(expiries().map(({ expiresAt, entries }) => [expiresAt, entries])).toEqual([
    ['2026-10-10T00:00:00Z', ['CVE-1']],
    ['2026-10-20T00:00:00Z', undefined],
  ]);
});
