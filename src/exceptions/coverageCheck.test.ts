import { beforeEach, expect, it, vi } from 'vitest';
import type {
  ClusterSecurityException,
  SecurityException,
} from '../softwarecomposition/SecurityException';
import { exceptionKey } from './coverage';
import { checkCoverage } from './coverageCheck';

const mocks = vi.hoisted(() => ({
  readConfigurationScans: vi.fn(),
  readVulnerabilityScans: vi.fn(),
  fetchSecurityExceptions: vi.fn(),
  configurationTasks: [] as any[],
  vulnerabilityTasks: [] as any[],
}));
vi.mock('../compliance/Compliance', () => ({
  configurationScanContext: {
    get queryTasks() {
      return mocks.configurationTasks;
    },
  },
  readConfigurationScans: mocks.readConfigurationScans,
}));
vi.mock('../vulnerabilities/Vulnerabilities', () => ({
  vulnerabilityContext: {
    get queryTasks() {
      return mocks.vulnerabilityTasks;
    },
  },
  readVulnerabilityScans: mocks.readVulnerabilityScans,
}));
vi.mock('../common/config-store', () => ({ kubescapeConfigStore: { get: () => ({}) } }));
vi.mock('../common/clusterContext', () => ({ getAllowedNamespaces: () => [] }));
vi.mock('./apply-security-exceptions', async importOriginal => ({
  ...(await importOriginal<typeof import('./apply-security-exceptions')>()),
  fetchSecurityExceptions: mocks.fetchSecurityExceptions,
}));

const posture: ClusterSecurityException = {
  apiVersion: 'kubescape.io/v1beta1',
  kind: 'ClusterSecurityException',
  metadata: { name: 'c-0017' },
  spec: { posture: [{ controlID: 'C-0017', action: 'ignore' }] },
};
const cve: SecurityException = {
  apiVersion: 'kubescape.io/v1beta1',
  kind: 'SecurityException',
  metadata: { name: 'cve-1', namespace: 'shop' },
  spec: { vulnerabilities: [{ vulnerability: { id: 'CVE-1' }, status: 'fixed' }] },
};

const configScan = {
  metadata: {
    name: 'deployment-web',
    namespace: 'shop',
    cluster: 'prd',
    labels: {
      'kubescape.io/workload-kind': 'Deployment',
      'kubescape.io/workload-name': 'web',
      'kubescape.io/workload-namespace': 'shop',
    },
  },
  spec: { controls: { 'C-0017': { controlID: 'C-0017', status: { status: 'failed' } } } },
};
const vulnerabilityScan = {
  kind: 'Deployment',
  name: 'web',
  namespace: 'shop',
  cluster: 'tst',
  imageScan: { imageName: 'nginx:1.27', matches: [{ vulnerability: { id: 'CVE-1' } }] },
};

beforeEach(() => {
  mocks.configurationTasks = [{ cluster: 'prd', continuation: undefined }];
  // acc is in the cache, but has no exceptions of CVEs
  mocks.vulnerabilityTasks = [
    { cluster: 'tst', continuation: undefined },
    { cluster: 'acc', continuation: undefined },
  ];
  mocks.readConfigurationScans.mockReset().mockResolvedValue([configScan]);
  mocks.readVulnerabilityScans.mockReset().mockResolvedValue([vulnerabilityScan]);
  mocks.fetchSecurityExceptions.mockReset().mockImplementation(async (cluster: string) => ({
    namespaced: cluster === 'tst' ? [cve] : [],
    cluster: cluster === 'prd' ? [posture] : [],
    namespaceLabelsByName: new Map(),
  }));
});

it('reads the scans each cluster needs through the shared caches', async () => {
  const check = await checkCoverage(
    [
      { cluster: 'prd', exception: posture },
      { cluster: 'tst', exception: cve },
    ],
    ['prd', 'tst', 'acc'],
    { current: true },
    () => {}
  );

  // the configuration scans of the clusters with posture entries, keeping the cache of the others
  expect(mocks.readConfigurationScans.mock.calls[0][0]).toEqual(['prd']);
  expect(mocks.readConfigurationScans.mock.calls[0][5]).toEqual({ keepOtherClusters: true });
  // the vulnerability cache keeps acc, as it is asked for too
  expect(mocks.readVulnerabilityScans.mock.calls[0][0]).toEqual(['tst', 'acc']);
  // the object selectors are matched against the kinds of the workloads of the reports
  expect(mocks.fetchSecurityExceptions).toHaveBeenCalledWith('tst', [], ['Deployment'], []);

  expect(check.incomplete).toEqual([]);
  expect([...check.coverage.get(exceptionKey('prd', posture))!.controls]).toEqual(['C-0017']);
  expect([...check.coverage.get(exceptionKey('tst', cve))!.cves]).toEqual(['CVE-1']);
});

it('reports the clusters whose scans or exceptions could not be read completely', async () => {
  // Cancel stopped the read of the reports of tst
  mocks.vulnerabilityTasks = [{ cluster: 'tst', continuation: '' }];
  mocks.fetchSecurityExceptions.mockImplementation(async (cluster: string) => ({
    namespaced: [],
    cluster: [posture],
    namespaceLabelsByName: new Map(),
    ...(cluster === 'prd' && { errors: ['the labels of the namespaces: forbidden'] }),
  }));

  const check = await checkCoverage(
    [
      { cluster: 'prd', exception: posture },
      { cluster: 'tst', exception: cve },
    ],
    ['prd', 'tst'],
    { current: false },
    () => {}
  );

  expect(check.incomplete).toEqual([
    { cluster: 'tst', message: 'vulnerability scans: the read was stopped before the end' },
    { cluster: 'prd', message: 'security exceptions: the labels of the namespaces: forbidden' },
  ]);
});
