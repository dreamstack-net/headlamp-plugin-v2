import { cleanup, render, screen } from '@testing-library/react';
import { vi } from 'vitest';
import ClusterView from './ClusterView';

const mocks = vi.hoisted(() => ({
  config: { framework: '', activeFrameworks: [] as string[] },
  frameworks: [] as any[],
}));

vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', () => ({
  SectionBox: ({ children }: any) => <section>{children}</section>,
  // a row per cluster with the header and value of each column
  Table: ({ data, columns }: any) => (
    <table>
      <tbody>
        {data.map((row: any) => (
          <tr key={row.cluster}>
            {columns.map((column: any) => (
              <td key={column.header}>
                {`${column.header}: ${
                  column.accessorFn ? column.accessorFn(row) : row[column.accessorKey]
                }`}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  ),
}));
vi.mock('../common/config-store', () => ({ kubescapeConfigStore: { get: () => mocks.config } }));
vi.mock('../rego', async importOriginal => ({
  ...(await importOriginal<typeof import('../rego')>()),
  useRegoData: () => ({ frameworks: mocks.frameworks }),
}));

afterEach(cleanup);

function scan(cluster: string, status: string) {
  return {
    metadata: { name: `deployment-${status}`, namespace: 'shop', cluster },
    spec: {
      controls: { 'C-0001': { controlID: 'C-0001', status: { status }, exceptedByPolicy: false } },
    },
    exceptedByPolicy: false,
  } as any;
}

const control = { controlID: 'C-0001' };
const scans = [
  scan('cluster-a', 'failed'),
  scan('cluster-a', 'passed'),
  scan('cluster-b', 'passed'),
];

beforeEach(() => {
  mocks.config = { framework: '', activeFrameworks: [] };
  mocks.frameworks = [
    { name: 'NSA', controls: [control] },
    { name: 'MITRE', controls: [control] },
    { name: 'cis-v1.10.0', controls: [control] },
    { name: 'SOC2', controls: [control] },
  ];
});

it('shows the scores of the default frameworks while none are chosen', () => {
  render(<ClusterView workloadScanData={scans} />);

  expect(screen.getAllByRole('row').map(row => row.textContent)).toEqual([
    'Cluster: cluster-acis-v1.10.0: 50MITRE: 50NSA: 50',
    'Cluster: cluster-bcis-v1.10.0: 100MITRE: 100NSA: 100',
  ]);
});

it('shows the chosen frameworks, also custom ones, and scores one without controls 100', () => {
  mocks.config.activeFrameworks = ['SOC2', 'Team baseline'];
  render(
    <ClusterView
      workloadScanData={scans}
      customFrameworks={[{ name: 'Team baseline', controls: [] }]}
    />
  );

  expect(screen.getAllByRole('row').map(row => row.textContent)).toEqual([
    'Cluster: cluster-aSOC2: 50Team baseline: 100',
    'Cluster: cluster-bSOC2: 100Team baseline: 100',
  ]);
});
