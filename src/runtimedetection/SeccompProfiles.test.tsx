// Renders the list of seccomp profiles of the storage in Headlamp's real table
import { lightTheme } from '@kinvolk/headlamp-plugin/lib/components/App/defaultAppThemes';
import { createMuiTheme } from '@kinvolk/headlamp-plugin/lib/lib/themes';
import store from '@kinvolk/headlamp-plugin/lib/redux/stores/store';
import { ThemeProvider } from '@mui/material/styles';
import { cleanup, render, screen, within } from '@testing-library/react';
import { ReactNode } from 'react';
import { Provider } from 'react-redux';
import { MemoryRouter } from 'react-router-dom';
import { vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  request: vi.fn(),
  allowedNamespaces: [] as string[],
}));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ request: mocks.request }));
vi.mock('../index', () => ({
  RoutingName: { SeccompProfileDetail: 'seccomp' },
  useHLSelectedClusters: () => ['cluster-a'],
}));
vi.mock('../model', () => ({
  fetchObject: vi.fn(),
  listQueryWithErrors: vi.fn(),
  seccompProfileClass: { pluralName: 'seccompprofiles' },
  seccompProfileStorageClass: {
    apiEndpoint: {
      apiInfo: [{ group: 'spdx.softwarecomposition.kubescape.io', version: 'v1beta1' }],
    },
    pluralName: 'seccompprofiles',
  },
}));
vi.mock('../common/clusterContext', () => ({
  getAllowedNamespaces: () => mocks.allowedNamespaces,
}));
vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', async importOriginal => ({
  ...(await importOriginal<typeof import('@kinvolk/headlamp-plugin/lib/CommonComponents')>()),
  Link: ({ children, params }: any) => (
    <a href={`/seccomp/${params.namespace}/${params.name}`}>{children as ReactNode}</a>
  ),
}));

import { SeccompProfilesTab } from './SeccompProfiles';

function profile(namespace: string, name: string) {
  return {
    metadata: {
      name: `deployment-${name}`,
      namespace,
      labels: { 'kubescape.io/workload-name': name, 'kubescape.io/workload-kind': 'Deployment' },
    },
    spec: {
      containers: [
        {
          name: 'app',
          spec: {
            defaultAction: 'SCMP_ACT_ERRNO',
            syscalls: [{ names: ['read', 'write'], action: 'SCMP_ACT_ALLOW' }],
          },
        },
      ],
    },
  };
}

const storage = '/apis/spdx.softwarecomposition.kubescape.io/v1beta1';

// the storage serves the profiles; the namespaces of `forbidden` cannot be read
function serveFromStorage(forbidden: string[]) {
  mocks.request.mockImplementation(async (url: string) => {
    if (url === storage) return { resources: [{ name: 'seccompprofiles' }] };
    const namespace = /\/namespaces\/([^/]+)\/seccompprofiles\?/.exec(url)?.[1];
    if (namespace && forbidden.includes(namespace)) throw new Error('forbidden');
    if (namespace && url.includes('resourceVersion=fullSpec')) {
      return { items: [profile(namespace, 'web')], metadata: {} };
    }
    // the CRD of the operator is not installed
    throw new Error('not found');
  });
}

function renderTab() {
  render(
    <Provider store={store}>
      <ThemeProvider theme={createMuiTheme(lightTheme)}>
        <MemoryRouter>
          <SeccompProfilesTab />
        </MemoryRouter>
      </ThemeProvider>
    </Provider>
  );
}

beforeEach(() => {
  window.sessionStorage.clear();
  mocks.request.mockReset();
  mocks.allowedNamespaces = [];
});
afterEach(cleanup);

it('lists the profiles of the storage that were read when a namespace could not be', async () => {
  mocks.allowedNamespaces = ['shop', 'secret'];
  serveFromStorage(['secret']);
  renderTab();

  expect(
    await screen.findByText(
      'Unable to read the seccomp profiles of cluster cluster-a: namespace secret: forbidden'
    )
  ).toBeTruthy();
  const link = screen.getByRole('link', { name: 'web' });
  expect(link.getAttribute('href')).toBe('/seccomp/shop/deployment-web');
  const row = link.closest('tr')!;
  expect(within(row).getByText('shop')).toBeTruthy();
  expect(within(row).getByText('0 of 1')).toBeTruthy();
});

it('shows only the error when no namespace could be read', async () => {
  mocks.allowedNamespaces = ['shop', 'secret'];
  serveFromStorage(['shop', 'secret']);
  renderTab();

  expect(
    await screen.findByText('Unable to read the seccomp profiles of cluster cluster-a: forbidden')
  ).toBeTruthy();
  expect(screen.queryByRole('table')).toBeNull();
  expect(screen.queryByText('No seccomp profiles found.')).toBeNull();
});
