import { cleanup, render, screen } from '@testing-library/react';
import { vi } from 'vitest';
import { WorkloadConfigurationScanSummary } from '../softwarecomposition/WorkloadConfigurationScanSummary';
import KubescapeWorkloadConfigurationScanList, {
  compareCounts,
  controlsList,
  countResourceScans,
  failedControls,
  passedShare,
} from './ResourceList';

const mocks = vi.hoisted(() => ({
  clusters: ['cluster-a'],
  // the columns the table got
  columns: [] as any[],
}));
vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', () => ({
  Link: ({ children, activeCluster }: any) => <span data-cluster={activeCluster}>{children}</span>,
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

function workload(results: Result[], exceptedByPolicy = false): WorkloadConfigurationScanSummary {
  return {
    metadata: { name: 'deployment-web', namespace: 'shop' } as any,
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

const w = workload([
  ['C-0001', 'failed', 'High', ['nsa']],
  ['C-0002', 'failed', 'Critical'],
  ['C-0003', 'passed', 'Low'],
  ['C-0004', 'failed', 'High'],
]);
const ids = (results: { controlID: string }[]) => results.map(result => result.controlID);

it('applies the exceptions limited to a framework only in that framework', () => {
  expect(ids(failedControls(w, 'NSA'))).toEqual(['C-0002', 'C-0004']);
  expect(ids(failedControls(w, 'MITRE'))).toEqual(['C-0001', 'C-0002', 'C-0004']);
  expect(ids(failedControls(w))).toEqual(['C-0001', 'C-0002', 'C-0004']);
  // passed or excepted
  expect(passedShare(w, 'NSA')).toBe(2 / 4);
  expect(passedShare(w)).toBe(1 / 4);
});

it('counts only the controls of the framework when given', () => {
  const nsa = new Set(['C-0001', 'C-0003', 'C-0004']);
  expect(ids(failedControls(w, 'NSA', nsa))).toEqual(['C-0004']);
  expect(passedShare(w, 'NSA', nsa)).toBe(2 / 3);
  expect(countResourceScans(w, 'NSA', nsa)).toEqual([0, 1, 0, 0]);
  expect(countResourceScans(w, 'NSA')).toEqual([1, 1, 0, 0]);
  // a resource without results of the framework
  expect(passedShare(w, 'NSA', new Set(['C-0099']))).toBe(0);
});

it('counts nothing of a resource that an exception excludes', () => {
  const excluded = workload([['C-0001', 'failed', 'High']], true);
  expect(failedControls(excluded, 'NSA', new Set(['C-0001']))).toEqual([]);
  expect(passedShare(excluded, 'NSA', new Set(['C-0001']))).toBe(1);
});

it('lists in the tooltip the failed controls that the cell counts', () => {
  const framework = {
    name: 'Full Regolibrary',
    controls: [{ controlID: 'C-0004', name: 'Resource limits' }],
  } as any;

  render(<>{controlsList(w, framework, 'High')}</>);

  // C-0001 is in no framework of the plugin's data, and still counted
  expect(screen.getByText('C-0001')).toBeTruthy();
  expect(screen.getByText('C-0004: Resource limits')).toBeTruthy();
  expect(controlsList(w, framework, 'High', new Set(['C-0002']))).toBeUndefined();
});

function renderList() {
  render(
    <KubescapeWorkloadConfigurationScanList
      workloadScanData={[w]}
      framework={{ name: 'NSA', controls: [] }}
      isFailedControlSwitchChecked={false}
    />
  );
  return mocks.columns;
}

it('links the namespace of a row to the cluster of the row', () => {
  mocks.clusters = ['cluster-a', 'cluster-b'];
  const namespace = renderList().find(column => column.header === 'Namespace');
  const row = { original: { metadata: { cluster: 'cluster-b' } } };

  render(<>{namespace.Cell({ cell: { getValue: () => 'shop' }, row })}</>);

  expect(screen.getByText('shop').getAttribute('data-cluster')).toBe('cluster-b');
});

it('has a column for the cluster with several clusters, and no empty column with one', () => {
  const headers = () => renderList().map(column => column.header);

  expect(headers()).toEqual(['Name', 'Excluded', 'Kind', 'Namespace', 'Passed', 'Failed Controls']);
  mocks.clusters = ['cluster-a', 'cluster-b'];
  expect(headers()).toEqual([
    'Name',
    'Excluded',
    'Kind',
    'Namespace',
    'Cluster',
    'Passed',
    'Failed Controls',
  ]);
});

it('orders the failed controls by their counts as numbers, the most severe first', () => {
  const sorted = [
    [2, 0, 0, 0],
    [10, 0, 0, 0],
    [2, 5, 0, 0],
    [0, 30, 1, 0],
  ].sort(compareCounts);
  expect(sorted).toEqual([
    [0, 30, 1, 0],
    [2, 0, 0, 0],
    [2, 5, 0, 0],
    [10, 0, 0, 0],
  ]);
});
