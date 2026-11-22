import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { vi } from 'vitest';
import { FrameworksPage } from './FrameworkList';

const mocks = vi.hoisted(() => ({
  // the default frameworks
  frameworks: [] as any[],
  configMaps: [] as any[],
  list: vi.fn(),
  remove: vi.fn(),
  // SelfSubjectAccessReviews
  post: vi.fn(),
  // permission answers are kept per cluster, so a test that needs others uses its own cluster
  cluster: 'cluster-a',
  enqueueSnackbar: vi.fn(),
  namespace: { kubeScapeNamespace: 'kubescape', error: null } as {
    kubeScapeNamespace?: string;
    error: string | null;
  },
}));

vi.mock('@kinvolk/headlamp-plugin/lib', () => ({
  Router: { createRouteURL: (route: string) => `/${route}` },
}));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({
  remove: mocks.remove,
  post: mocks.post,
}));
vi.mock('@kinvolk/headlamp-plugin/lib/Utils', () => ({ getCluster: () => mocks.cluster }));
vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', () => ({
  Link: ({ children, params, search }: any) => (
    <a href={`#${params.name}${search ? `?${new URLSearchParams(search)}` : ''}`}>{children}</a>
  ),
  Table: ({ data = [], columns }: any) => (
    <table>
      <tbody>
        {data.map((item: any, index: number) => (
          <tr key={index}>
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
  ),
}));
vi.mock('notistack', () => ({ useSnackbar: () => ({ enqueueSnackbar: mocks.enqueueSnackbar }) }));
vi.mock('../custom-objects/api-queries', () => ({
  getKubescapeNamespace: async () => mocks.namespace,
  listCustomObjectConfigMaps: mocks.list,
  useKubescapeNamespace: () => ({ ...mocks.namespace, loading: false }),
}));
vi.mock('../index', () => ({
  RoutingName: {
    FrameworkControls: 'Framework Controls',
    FrameworkNew: 'New Framework',
    FrameworkEdit: 'Edit Framework',
  },
}));
vi.mock('../model', () => ({ customObjectLabel: 'kubescape.io/custom-object' }));
vi.mock('../rego', () => ({
  useRegoData: () => ({ controls: [{ controlID: 'C-0016' }], frameworks: mocks.frameworks }),
}));

beforeEach(() => {
  mocks.frameworks = [];
  // as the API returns them, in the Kubescape namespace
  mocks.configMaps = [
    {
      metadata: { name: 'framework-team-baseline', namespace: 'kubescape' },
      data: { name: 'Team baseline', description: 'Ours', controlsIDs: '["C-0016"]' },
    },
  ];
  mocks.list.mockReset().mockImplementation(async () => mocks.configMaps);
  mocks.namespace = { kubeScapeNamespace: 'kubescape', error: null };
  mocks.cluster = 'cluster-a';
  mocks.post.mockReset().mockResolvedValue({ status: { allowed: true } });
  mocks.remove.mockReset().mockResolvedValue({});
  mocks.enqueueSnackbar.mockReset();
});
afterEach(cleanup);

async function renderPage() {
  render(
    <MemoryRouter>
      <FrameworksPage />
    </MemoryRouter>
  );
  await screen.findAllByRole('button', { name: /^Delete / });
}

it('deletes a custom framework only after a confirmation that names it', async () => {
  mocks.remove.mockRejectedValueOnce(
    new Error('configmaps "framework-team-baseline" is forbidden')
  );
  await renderPage();
  fireEvent.click(screen.getByRole('button', { name: 'Delete Team baseline' }));

  const dialog = await screen.findByRole('dialog', { name: 'Delete custom framework?' });
  expect(dialog.textContent).toBe(
    'Delete custom framework?Deletes the custom framework Team baseline in namespace kubescape of ' +
      'cluster cluster-a. Its ConfigMap framework-team-baseline is deleted, and the Compliance ' +
      'page no longer offers it.CancelDelete'
  );
  // nothing is deleted until the user confirms
  fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  expect(mocks.remove).not.toHaveBeenCalled();

  // a failed delete keeps the dialog open with the error
  fireEvent.click(screen.getByRole('button', { name: 'Delete Team baseline' }));
  fireEvent.click(
    within(await screen.findByRole('dialog')).getByRole('button', { name: 'Delete' })
  );
  expect(await screen.findByText('configmaps "framework-team-baseline" is forbidden')).toBeTruthy();
  fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }));
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  expect(mocks.remove).toHaveBeenLastCalledWith(
    '/api/v1/namespaces/kubescape/configmaps/framework-team-baseline'
  );
  expect(mocks.enqueueSnackbar).toHaveBeenCalledWith('Team baseline deleted successfully', {
    variant: 'success',
  });
});

it('lists the custom frameworks in the Kubescape namespace, and again after a delete', async () => {
  mocks.remove.mockImplementation(async () => {
    mocks.configMaps = [];
  });
  await renderPage();
  expect(mocks.list).toHaveBeenCalledWith('framework', 'cluster-a');
  expect(screen.getByText('Team baseline')).toBeTruthy();

  fireEvent.click(screen.getByRole('button', { name: 'Delete Team baseline' }));
  fireEvent.click(
    within(await screen.findByRole('dialog')).getByRole('button', { name: 'Delete' })
  );

  await waitFor(() => expect(screen.queryByText('Team baseline')).toBeNull());
  expect(mocks.list).toHaveBeenCalledTimes(2);
});

it('deletes and edits a framework in the namespace its ConfigMap was found in', async () => {
  // listed in all namespaces, as the Kubescape namespace was not known
  mocks.configMaps[0].metadata.namespace = 'security';
  await renderPage();

  expect(screen.getByText('Team baseline').closest('a')?.getAttribute('href')).toBe(
    '#framework-team-baseline?namespace=security'
  );
  fireEvent.click(screen.getByRole('button', { name: 'Delete Team baseline' }));
  const dialog = await screen.findByRole('dialog');
  expect(dialog.textContent).toContain('in namespace security of cluster cluster-a');
  fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));

  await waitFor(() =>
    expect(mocks.remove).toHaveBeenCalledWith(
      '/api/v1/namespaces/security/configmaps/framework-team-baseline'
    )
  );
});

it('gives the default frameworks no empty column where the custom ones have their actions', async () => {
  mocks.frameworks = [{ name: 'NSA', description: 'Hardening guidance', controls: [] }];
  await renderPage();

  expect(screen.getByText('NSA').closest('tr')?.querySelectorAll('td')).toHaveLength(3);
  expect(screen.getByText('Team baseline').closest('tr')?.querySelectorAll('td')).toHaveLength(4);
});

it('shows why the custom frameworks could not be read', async () => {
  mocks.list.mockRejectedValue(new Error('configmaps is forbidden'));
  render(
    <MemoryRouter>
      <FrameworksPage />
    </MemoryRouter>
  );

  expect(
    await screen.findByText('Unable to read the custom frameworks: configmaps is forbidden')
  ).toBeTruthy();
});

it('asks nothing when the namespace of a ConfigMap and the Kubescape namespace are not known', async () => {
  delete mocks.configMaps[0].metadata.namespace;
  mocks.namespace = { error: 'Kubescape is not installed', kubeScapeNamespace: undefined };
  await renderPage();
  fireEvent.click(screen.getByRole('button', { name: 'Delete Team baseline' }));

  await waitFor(() =>
    expect(mocks.enqueueSnackbar).toHaveBeenCalledWith('Kubescape is not installed', {
      variant: 'error',
    })
  );
  expect(screen.queryByRole('dialog')).toBeNull();
  expect(mocks.remove).not.toHaveBeenCalled();
});

it('offers no add or delete without permission for the ConfigMaps of the Kubescape namespace', async () => {
  mocks.cluster = 'cluster-without-configmaps';
  mocks.post.mockImplementation(async (_url: string, review: any) => ({
    status: { allowed: review.spec.resourceAttributes.resource !== 'configmaps' },
  }));
  await renderPage();

  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Delete Team baseline' })).toHaveProperty(
      'disabled',
      true
    )
  );
  expect(screen.getByRole('button', { name: 'Add custom framework' })).toHaveProperty(
    'disabled',
    true
  );
  expect(
    screen.getByLabelText(
      'You are not allowed to delete configmaps framework-team-baseline in namespace kubescape.'
    )
  ).toBeTruthy();
  expect(
    screen.getByLabelText('You are not allowed to create configmaps in namespace kubescape.')
  ).toBeTruthy();
});
