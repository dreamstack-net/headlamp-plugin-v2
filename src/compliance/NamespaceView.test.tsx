import { cleanup, render } from '@testing-library/react';
import { vi } from 'vitest';
import { WorkloadConfigurationScanSummary } from '../softwarecomposition/WorkloadConfigurationScanSummary';
import NamespaceView, { getNamespaceResults } from './NamespaceView';

const mocks = vi.hoisted(() => ({
  clusters: ['cluster-a'],
  // the columns the table got
  columns: [] as any[],
}));
vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', () => ({
  Link: () => null,
  SectionBox: ({ children }: any) => <section>{children}</section>,
  Table: ({ columns }: any) => {
    mocks.columns = columns;
    return null;
  },
}));
vi.mock('../index', () => ({ RoutingName: {}, useHLSelectedClusters: () => mocks.clusters }));

afterEach(() => {
  cleanup();
  mocks.clusters = ['cluster-a'];
});

type Result = [
  controlID: string,
  status: string,
  severity: string,
  exceptedInFrameworks?: string[]
];

function scan(
  cluster: string,
  namespace: string,
  results: Result[],
  exceptedByPolicy = false
): WorkloadConfigurationScanSummary {
  return {
    metadata: { name: `deployment-${results.length}`, namespace, cluster } as any,
    spec: {
      controls: Object.fromEntries(
        results.map(([controlID, status, severity, exceptedInFrameworks]) => [
          controlID,
          {
            controlID,
            severity: { scoreFactor: 5, severity },
            status: { status: status as WorkloadConfigurationScanSummary.Status },
            exceptedByPolicy: false,
            exceptedInFrameworks,
          },
        ])
      ),
      severities: {} as any,
    },
    exceptedByPolicy,
  };
}

const scans = [
  scan('cluster-a', 'shop', [
    ['C-0001', 'failed', 'High', ['nsa']],
    ['C-0002', 'failed', 'Critical'],
    ['C-0003', 'passed', 'Low'],
  ]),
  scan('cluster-a', 'shop', [['C-0002', 'failed', 'Medium']], true),
  // the same namespace in another cluster is another row
  scan('cluster-b', 'shop', [['C-0002', 'failed', 'Low']]),
];

function summary(results: ReturnType<typeof getNamespaceResults>) {
  return results.map(result => ({
    row: `${result.cluster}/${result.namespace}`,
    total: result.total,
    passed: result.passed,
    failed: result.failed,
    excepted: result.exceptedControls,
    critical: result.criticalCount,
    high: result.highCount,
    medium: result.mediumCount,
    low: result.lowCount,
    exceptedNamespace: result.exceptedNamespace,
    passedShare: result.passedShare,
  }));
}

it('counts the results per namespace of each cluster, with the exceptions of the framework', () => {
  expect(summary(getNamespaceResults(scans, 'NSA'))).toEqual([
    {
      row: 'cluster-a/shop',
      total: 4,
      passed: 1,
      failed: 1,
      // C-0001 in NSA, and the result of the excepted workload
      excepted: 2,
      critical: 1,
      high: 0,
      medium: 0,
      low: 0,
      exceptedNamespace: false,
      passedShare: 3 / 4,
    },
    {
      row: 'cluster-b/shop',
      total: 1,
      passed: 0,
      failed: 1,
      excepted: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 1,
      exceptedNamespace: false,
      passedShare: 0,
    },
  ]);
  // in another framework, the exception limited to NSA does not apply
  expect(summary(getNamespaceResults(scans, 'MITRE'))[0]).toMatchObject({
    failed: 2,
    excepted: 1,
    high: 1,
  });
});

it('counts only the controls of the framework when given', () => {
  const [shop] = getNamespaceResults(scans, 'NSA', new Set(['C-0001', 'C-0003']));
  expect(shop).toMatchObject({
    total: 2,
    passed: 1,
    failed: 0,
    exceptedControls: 1,
    criticalCount: 0,
  });
  expect(shop.passedShare).toBe(1);
});

it('calls a namespace excluded when an exception excludes all its workloads', () => {
  const [excluded] = getNamespaceResults([scans[1]]);
  expect(excluded.exceptedNamespace).toBe(true);
  expect(excluded.passedShare).toBe(1);
});

it('has a column for the cluster with several clusters, and no empty column with one', () => {
  const headers = () => {
    render(<NamespaceView workloadScanData={scans} />);
    return mocks.columns.map(column => column.header);
  };

  expect(headers()).not.toContain('Cluster');
  // every column has a header: one without would show as an empty column
  expect(headers().every(header => !!header)).toBe(true);
  mocks.clusters = ['cluster-a', 'cluster-b'];
  expect(headers().slice(0, 2)).toEqual(['Namespace', 'Cluster']);
});
