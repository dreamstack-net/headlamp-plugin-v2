import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { loadAll } from 'js-yaml';
import { vi } from 'vitest';
import type { ClusterSecurityException } from '../softwarecomposition/SecurityException';
import { emptyCoverage, exceptionKey } from './coverage';
import { SecurityExceptions } from './SecurityExceptions';

const mocks = vi.hoisted(() => ({
  namespaced: [] as any[],
  clusterWide: [] as any[],
  remove: vi.fn(),
  post: vi.fn(),
  saveToFile: vi.fn(),
  checkCoverage: vi.fn(),
  enqueueSnackbar: vi.fn(),
}));

vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({
  remove: mocks.remove,
  post: mocks.post,
}));
vi.mock('@kinvolk/headlamp-plugin/lib/Utils', () => ({ getCluster: () => 'prd' }));
vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', () => ({
  Link: ({ children, activeCluster, params }: any) => (
    <a href={`#${activeCluster}/${params.namespace ?? ''}/${params.name}`}>{children}</a>
  ),
  SectionBox: ({ title, headerProps, children }: any) => (
    <section aria-label={title}>
      {headerProps?.actions}
      {children}
    </section>
  ),
  Table: ({ data = [], columns, getRowId, renderTopToolbarCustomActions }: any) => (
    <>
      {renderTopToolbarCustomActions?.()}
      <table>
        <thead>
          <tr>
            {columns.map((column: any, i: number) => (
              <th key={i}>{column.header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((item: any) => (
            <tr key={getRowId(item)}>
              {columns.map((column: any, cellIndex: number) => {
                const value = column.accessorFn?.(item) ?? item[column.accessorKey];
                return (
                  <td key={cellIndex}>
                    {column.Cell
                      ? column.Cell({ cell: { getValue: () => value }, row: { original: item } })
                      : value}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </>
  ),
}));
vi.mock('notistack', () => ({ useSnackbar: () => ({ enqueueSnackbar: mocks.enqueueSnackbar }) }));
vi.mock('../index', () => ({
  RoutingName: {
    SecurityExceptionDetail: 'Security Exception Detail',
    SecurityExceptionClusterDetail: 'Cluster Security Exception Detail',
  },
  useHLSelectedClusters: () => ['prd', 'tst'],
}));
vi.mock('../model', () => ({
  securityExceptionClass: { useList: () => ({ items: mocks.namespaced, errors: null }) },
  clusterSecurityExceptionClass: { useList: () => ({ items: mocks.clusterWide, errors: null }) },
}));
vi.mock('../common/SetupCheck', () => ({ SetupCheck: () => null }));
vi.mock('../common/clusterContext', () => ({ getAllowedNamespaces: () => [] }));
vi.mock('../common/filedialog', () => ({ saveToFile: mocks.saveToFile }));
vi.mock('./coverageCheck', () => ({ checkCoverage: mocks.checkCoverage }));
vi.mock('./SecurityExceptionForm', () => ({
  SecurityExceptionForm: ({ existing, cluster }: { existing?: any; cluster?: string }) => (
    <div role="dialog">{existing ? `Edit ${existing.metadata.name} in ${cluster}` : 'Create'}</div>
  ),
}));

const shared = (cluster: string): ClusterSecurityException & { _cluster: string } => ({
  apiVersion: 'kubescape.io/v1beta1',
  kind: 'ClusterSecurityException',
  metadata: { name: 'shared', uid: `${cluster}-1`, resourceVersion: '3' } as any,
  spec: { posture: [{ controlID: 'C-0017', action: 'ignore' }] },
  _cluster: cluster,
});
const namespacedException = {
  apiVersion: 'kubescape.io/v1beta1',
  kind: 'SecurityException',
  metadata: { name: 'cve-1', namespace: 'shop', uid: 'x' },
  spec: {
    expiresAt: '2020-01-01T00:00:00Z',
    vulnerabilities: [{ vulnerability: { id: 'CVE-1' }, status: 'fixed' }],
  },
};
// as Headlamp lists them, with the cluster they were read from
const kubeObject = (jsonData: any, cluster: string) => ({
  cluster,
  jsonData,
  metadata: jsonData.metadata,
});

beforeEach(() => {
  mocks.clusterWide = [kubeObject(shared('prd'), 'prd'), kubeObject(shared('tst'), 'tst')];
  mocks.namespaced = [kubeObject(namespacedException, 'prd')];
  mocks.post.mockReset().mockResolvedValue({ status: { allowed: true } });
  mocks.remove.mockReset().mockResolvedValue({});
  mocks.saveToFile.mockReset().mockResolvedValue(null);
  mocks.checkCoverage.mockReset();
  mocks.enqueueSnackbar.mockReset();
});
afterEach(cleanup);

const rows = () => screen.getAllByRole('row').slice(1);

it('lists the exceptions of the selected clusters and downloads them for a GitOps repository', async () => {
  render(<SecurityExceptions />);

  expect(rows().map(row => within(row).getAllByRole('cell')[1].textContent)).toEqual([
    'prd',
    'prd',
    'tst',
  ]);
  // the details are opened in the cluster of the exception
  expect(within(rows()[2]).getByRole('link').getAttribute('href')).toBe('#tst//shared');

  fireEvent.click(screen.getByRole('button', { name: 'Download all as YAML' }));
  await waitFor(() => expect(mocks.saveToFile).toHaveBeenCalled());
  const [content, fileName] = mocks.saveToFile.mock.calls[0];
  expect(fileName).toBe('security-exceptions.yaml');
  // the exception that is the same in both clusters once
  expect(content).toContain('# Clusters: prd, tst\n');
  const documents = loadAll(content) as any[];
  expect(documents.map(document => document.metadata)).toEqual([
    { name: 'shared' },
    { name: 'cve-1', namespace: 'shop' },
  ]);

  fireEvent.click(within(rows()[2]).getByRole('button', { name: 'Download YAML' }));
  await waitFor(() => expect(mocks.saveToFile).toHaveBeenCalledTimes(2));
  expect(mocks.saveToFile.mock.calls[1][1]).toBe('shared.yaml');
});

it('edits and deletes an exception in its own cluster', async () => {
  render(<SecurityExceptions />);

  fireEvent.click(within(rows()[2]).getByRole('button', { name: 'Edit' }));
  expect(screen.getByRole('dialog').textContent).toBe('Edit shared in tst');

  fireEvent.click(await within(rows()[2]).findByRole('button', { name: 'Delete' }));
  const dialog = await screen.findByRole('dialog', { name: /Delete/ });
  fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));
  await waitFor(() =>
    expect(mocks.remove).toHaveBeenCalledWith(
      '/apis/kubescape.io/v1beta1/clustersecurityexceptions/shared',
      { cluster: 'tst' }
    )
  );
  // hidden at once, before the list follows
  await waitFor(() => expect(rows()).toHaveLength(2));
});

it('checks what the exceptions cover and filters the stale ones', async () => {
  const covering = {
    ...emptyCoverage(),
    matched: new Set(['Deployment/shop/web']),
    workloads: new Set(['Deployment/shop/web']),
    controls: new Set(['C-0017']),
  };
  mocks.checkCoverage.mockResolvedValue({
    coverage: new Map([
      [exceptionKey('prd', shared('prd')), covering],
      [exceptionKey('tst', shared('tst')), emptyCoverage()],
      [exceptionKey('prd', namespacedException as any), emptyCoverage()],
    ]),
    incomplete: [],
  });
  render(<SecurityExceptions />);
  expect(screen.queryByRole('columnheader', { name: 'Coverage' })).toBeNull();

  fireEvent.click(screen.getByRole('button', { name: 'Check coverage' }));

  await screen.findByRole('columnheader', { name: 'Coverage' });
  const [exceptions, clusters] = mocks.checkCoverage.mock.calls[0];
  expect(exceptions).toHaveLength(3);
  expect(clusters).toEqual(['prd', 'tst']);
  const coverageColumn = screen
    .getAllByRole('columnheader')
    .findIndex(header => header.textContent === 'Coverage');
  const coverageOf = () =>
    rows().map(row => within(row).getAllByRole('cell')[coverageColumn].textContent);
  expect(coverageOf()).toEqual([
    'Expired',
    '1 workload: C-0017; covers findings only in prd',
    'Covers nothing: no scanned workload matches; covers findings only in prd',
  ]);
  expect(screen.getByText(/2 of 3 exceptions cover nothing/)).toBeTruthy();

  fireEvent.click(screen.getByLabelText('Only stale exceptions (2)'));
  expect(coverageOf()).toEqual([
    'Expired',
    'Covers nothing: no scanned workload matches; covers findings only in prd',
  ]);
});
