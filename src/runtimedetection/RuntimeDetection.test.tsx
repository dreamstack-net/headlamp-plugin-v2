import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import type { ReactNode } from 'react';
import { MemoryRouter } from 'react-router-dom';
import { vi } from 'vitest';
import { RuntimeDetection } from './RuntimeDetection';
import { SeccompProfileDetail } from './SeccompProfiles';

const mocks = vi.hoisted(() => ({
  containerProfileClass: { pluralName: 'containerprofiles' },
  applicationProfileClass: { pluralName: 'applicationprofiles' },
  discoverProfileResource: vi.fn(),
  listQuery: vi.fn(),
  namespaceErrors: [] as string[],
  fetchObject: vi.fn(),
  seccompProfileClass: { pluralName: 'seccompprofiles' },
  request: vi.fn(),
  patch: vi.fn(),
  remove: vi.fn(),
  post: vi.fn(),
  updateConfig: vi.fn(),
  clusters: ['cluster-a'],
  alertmanagerUrl: '',
  ruleObjects: [] as any[],
  // the current cluster when a test needs its own, as permission answers are kept per cluster
  currentCluster: undefined as string | undefined,
}));

vi.mock('@kinvolk/headlamp-plugin/lib/Utils', async importOriginal => {
  const original = await importOriginal<typeof import('@kinvolk/headlamp-plugin/lib/Utils')>();
  return { ...original, getCluster: () => mocks.currentCluster ?? original.getCluster() };
});

vi.mock('../index', () => ({
  RoutingName: {
    RuntimeDetection: 'Runtime Detection',
    RuleNew: 'New Rule',
    RuleEdit: 'Edit Rule',
    RuleBindingNew: 'New Rule Binding',
    RuleBindingEdit: 'Edit Rule Binding',
    SeccompProfileDetail: 'Seccomp Profile',
  },
  useHLSelectedClusters: () => mocks.clusters,
}));
vi.mock('../model', () => ({
  containerProfileClass: mocks.containerProfileClass,
  applicationProfileClass: mocks.applicationProfileClass,
  listQuery: mocks.listQuery,
  // the namespaces that could not be read are named by mocks.namespaceErrors
  listQueryWithErrors: async (...args: unknown[]) => ({
    items: await mocks.listQuery(...args),
    errors: mocks.namespaceErrors,
  }),
  fetchObject: mocks.fetchObject,
  seccompProfileClass: mocks.seccompProfileClass,
  seccompProfileStorageClass: {
    apiEndpoint: {
      apiInfo: [{ group: 'spdx.softwarecomposition.kubescape.io', version: 'v1beta1' }],
    },
    pluralName: 'seccompprofiles',
  },
  rulesClass: { useList: () => [mocks.ruleObjects] },
}));
vi.mock('../common/clusterContext', () => ({ getAllowedNamespaces: () => [] }));
vi.mock('../softwarecomposition/profileApi', () => ({
  discoverProfileResource: mocks.discoverProfileResource,
}));
vi.mock('../common/config-store', () => ({
  getAlertmanagerUrl: () => mocks.alertmanagerUrl,
  isValidAlertmanagerAddress: () => true,
  kubescapeConfigStore: {
    useConfig: () => () => ({}),
    update: mocks.updateConfig,
    get: () => ({ alertmanagerUrl: 'monitoring/alertmanager:9093' }),
  },
}));
vi.mock('../common/currentUser', () => ({
  getCurrentUser: async () => 'jane',
  useCurrentUser: () => 'jane',
}));
vi.mock('@kinvolk/headlamp-plugin/lib', () => ({
  Router: { createRouteURL: (route: string) => `/${route}` },
}));
// The setup check has its own tests
vi.mock('../common/SetupCheck', () => ({ SetupCheck: () => null }));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({
  request: mocks.request,
  remove: mocks.remove,
  patch: mocks.patch,
  post: mocks.post,
}));
vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', () => {
  // the values of the rows of each data array
  const tableValues = new WeakMap<object, unknown[][]>();
  return {
    NameValueTable: ({ rows }: any) => (
      <dl>
        {rows.map((row: any) => (
          <div key={row.name}>
            <dt>{row.name}</dt>
            <dd>{row.value}</dd>
          </div>
        ))}
      </dl>
    ),
    SectionBox: ({ title, children }: { title: string; children: ReactNode }) => (
      <section>
        <h1>{title}</h1>
        {children}
      </section>
    ),
    ShowHideLabel: ({ children }: { children: ReactNode }) => <>{children}</>,
    Link: ({ children, routeName, params, activeCluster }: any) => (
      <a
        href={`${activeCluster ? `/${activeCluster}` : ''}/${routeName}/${params.namespace}/${
          params.name
        }`}
      >
        {children}
      </a>
    ),
    // like Headlamp's table, it keeps the values of the rows until the data changes
    Table: ({ data = [], columns }: any) => {
      const values: any[][] =
        tableValues.get(data) ??
        data.map((item: any) =>
          columns.map((column: any) => column.accessorFn?.(item) ?? item[column.accessorKey])
        );
      tableValues.set(data, values);
      return (
        <table data-testid={`table-${columns.map((column: any) => column.header).join('-')}`}>
          <thead>
            <tr>
              {columns.map((column: any, index: number) => (
                <th key={index}>{column.header}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.map((item: any, index: number) => (
              <tr key={index}>
                {columns.map((column: any, cellIndex: number) => {
                  const value = values[index]?.[cellIndex];
                  const cell = { getValue: () => value };
                  // the cell props of the column; Headlamp replaces those of the table
                  const props =
                    typeof column.muiTableBodyCellProps === 'function'
                      ? column.muiTableBodyCellProps({ cell, row: { original: item } })
                      : {};
                  return (
                    <td
                      key={cellIndex}
                      onClick={props.onClick}
                      onKeyDown={props.onKeyDown}
                      tabIndex={props.tabIndex}
                    >
                      {column.Cell ? column.Cell({ cell, row: { original: item } }) : value}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      );
    },
  };
});

const profile = {
  kind: 'ContainerProfile',
  metadata: {
    name: 'deployment-web-app',
    namespace: 'workloads',
    labels: {
      'kubescape.io/workload-name': 'web-app',
      'kubescape.io/workload-kind': 'Deployment',
    },
    annotations: { 'kubescape.io/status': 'completed' },
  },
  spec: { execs: [{ path: '/bin/web' }], egress: [{ dns: 'api.example.test' }] },
};

beforeEach(() => {
  mocks.discoverProfileResource.mockReset();
  mocks.discoverProfileResource.mockResolvedValue({ plural: 'containerprofiles', modern: true });
  mocks.listQuery.mockReset();
  mocks.namespaceErrors = [];
  mocks.request.mockReset();
  mocks.request.mockResolvedValue({ items: [] });
  mocks.remove.mockReset();
  mocks.patch.mockReset();
  mocks.post.mockReset();
  mocks.updateConfig.mockReset();
  mocks.clusters = ['cluster-a'];
  mocks.alertmanagerUrl = '';
  mocks.ruleObjects = [];
  mocks.currentCluster = undefined;
});
afterEach(cleanup);

function renderRuntimeDetection() {
  return render(
    <MemoryRouter>
      <RuntimeDetection />
    </MemoryRouter>
  );
}

function openProfileTab() {
  fireEvent.click(screen.getByRole('tab', { name: 'Application Profiles' }));
}

it('relearns a workload: restarts it and deletes the profiles it recorded', async () => {
  const workloadProfile = (name: string, workload = 'web-app') => ({
    kind: 'ContainerProfile',
    metadata: {
      name,
      namespace: 'workloads',
      cluster: 'cluster-a',
      labels: {
        'kubescape.io/workload-name': workload,
        'kubescape.io/workload-kind': 'Deployment',
      },
      annotations: { 'kubescape.io/status': 'completed', 'kubescape.io/completion': 'partial' },
    },
  });
  const current = workloadProfile('replicaset-web-app-6d4cf56db6-web-1a2b-3c4d');
  mocks.listQuery.mockResolvedValue([current]);
  mocks.request.mockImplementation(async (url: string) =>
    url.endsWith('/namespaces/workloads/containerprofiles')
      ? {
          items: [
            current,
            workloadProfile('replicaset-web-app-5b7d9c8f6-web-5e6f-7a8b'),
            workloadProfile('replicaset-api-7c9b8d6f5-api-9c0d-1e2f', 'api'),
          ],
        }
      : url === '/apis/apps/v1/namespaces/workloads/deployments/web-app'
      ? { spec: { replicas: 1, strategy: { type: 'Recreate' } } }
      : { items: [] }
  );
  mocks.patch.mockResolvedValue({});
  mocks.remove.mockResolvedValue({});

  renderRuntimeDetection();
  openProfileTab();
  // the profile missed the start of its container
  expect(await screen.findByText('completed (partial)')).toBeTruthy();

  fireEvent.click(screen.getByRole('button', { name: 'Relearn' }));
  const dialog = screen.getByRole('dialog', { name: 'Relearn Deployment web-app' });
  expect(within(dialog).getByText(/did not learn the start/)).toBeTruthy();
  expect(
    await within(dialog).findByText('Delete the 2 recorded profiles of this workload')
  ).toBeTruthy();
  // the restart is spelled out, with what it does to this workload
  expect(
    within(dialog).getByText('This restarts Deployment web-app in cluster cluster-a')
  ).toBeTruthy();
  expect(
    await within(dialog).findByText(
      /its pod stops before the new one starts, so the workload is down/
    )
  ).toBeTruthy();
  const listsBefore = mocks.listQuery.mock.calls.length;
  fireEvent.click(within(dialog).getByRole('button', { name: 'Restart and relearn' }));

  await waitFor(() => expect(mocks.remove).toHaveBeenCalledTimes(2));
  expect(mocks.patch).toHaveBeenCalledWith(
    '/apis/apps/v1/namespaces/workloads/deployments/web-app',
    {
      spec: {
        template: {
          metadata: {
            annotations: { 'kubectl.kubernetes.io/restartedAt': expect.any(String) },
          },
        },
      },
    },
    false,
    { cluster: 'cluster-a' }
  );
  expect(mocks.remove.mock.calls.map(([url]) => url.split('/').pop())).toEqual([
    'replicaset-web-app-6d4cf56db6-web-1a2b-3c4d',
    'replicaset-web-app-5b7d9c8f6-web-5e6f-7a8b',
  ]);
  // the list is read again
  await waitFor(() => expect(mocks.listQuery.mock.calls.length).toBeGreaterThan(listsBefore));
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
});

it('only deletes the profiles when it tries again after the restart', async () => {
  const workloadProfile = {
    kind: 'ContainerProfile',
    metadata: {
      name: 'replicaset-web-app-6d4cf56db6-web-1a2b-3c4d',
      namespace: 'workloads',
      cluster: 'cluster-a',
      labels: {
        'kubescape.io/workload-name': 'web-app',
        'kubescape.io/workload-kind': 'Deployment',
      },
    },
  };
  mocks.listQuery.mockResolvedValue([workloadProfile]);
  mocks.request.mockImplementation(async (url: string) =>
    url.endsWith('/namespaces/workloads/containerprofiles')
      ? { items: [workloadProfile] }
      : url === '/apis/apps/v1/namespaces/workloads/deployments/web-app'
      ? { spec: { replicas: 3 } }
      : { items: [] }
  );
  mocks.patch.mockResolvedValue({});
  mocks.remove.mockRejectedValueOnce(new Error('storage unavailable')).mockResolvedValue({});

  renderRuntimeDetection();
  openProfileTab();
  fireEvent.click(await screen.findByRole('button', { name: 'Relearn' }));
  const dialog = screen.getByRole('dialog', { name: 'Relearn Deployment web-app' });
  await within(dialog).findByText('Delete the 1 recorded profile of this workload');
  fireEvent.click(within(dialog).getByRole('button', { name: 'Restart and relearn' }));

  expect(
    await within(dialog).findByText(
      'Restarted Deployment web-app: its new pods are learned from their start. Then failed: storage unavailable'
    )
  ).toBeTruthy();
  // the restart is done, so trying again does not roll the workload out once more
  expect(within(dialog).queryByText(/^This restarts/)).toBeNull();
  expect(within(dialog).getByText('Restarted the Deployment')).toBeTruthy();
  fireEvent.click(within(dialog).getByRole('button', { name: 'Retry deleting profiles' }));

  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  expect(mocks.patch).toHaveBeenCalledTimes(1);
  expect(mocks.remove).toHaveBeenCalledTimes(2);
});

// the only profile of the Deployment web-app, whose spec the tests give
const webAppProfile = {
  kind: 'ContainerProfile',
  metadata: {
    name: 'replicaset-web-app-6d4cf56db6-web-1a2b-3c4d',
    namespace: 'workloads',
    cluster: 'cluster-a',
    labels: {
      'kubescape.io/workload-name': 'web-app',
      'kubescape.io/workload-kind': 'Deployment',
    },
  },
};

it('does not propose to delete the profiles of pods that a restart leaves running', async () => {
  mocks.listQuery.mockResolvedValue([webAppProfile]);
  mocks.request.mockImplementation(async (url: string) =>
    url.endsWith('/namespaces/workloads/containerprofiles')
      ? { items: [webAppProfile] }
      : url === '/apis/apps/v1/namespaces/workloads/deployments/web-app'
      ? { spec: { replicas: 2, paused: true } }
      : { items: [] }
  );
  mocks.patch.mockResolvedValue({});

  renderRuntimeDetection();
  openProfileTab();
  fireEvent.click(await screen.findByRole('button', { name: 'Relearn' }));
  const dialog = screen.getByRole('dialog', { name: 'Relearn Deployment web-app' });
  // a paused Deployment rolls nothing out, so its pods go on with the profile they have
  expect(await within(dialog).findByText(/Its rollouts are paused/)).toBeTruthy();
  expect(within(dialog).queryByText(/Every pod of the workload is replaced/)).toBeNull();
  const cleanup = await within(dialog).findByRole('checkbox', {
    name: /Delete the 1 recorded profile of this workload/,
  });
  expect(cleanup).toHaveProperty('checked', false);
  // the user may still choose it, and is told what it does
  fireEvent.click(cleanup);
  expect(within(dialog).getByText(/The pods that keep running lose their profile/)).toBeTruthy();
  fireEvent.click(cleanup);

  fireEvent.click(within(dialog).getByRole('button', { name: 'Restart and relearn' }));
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  expect(mocks.patch).toHaveBeenCalledTimes(1);
  expect(mocks.remove).not.toHaveBeenCalled();
});

it('waits for the workload and its profiles before it restarts anything', async () => {
  mocks.listQuery.mockResolvedValue([webAppProfile]);
  let answerProfiles: (list: unknown) => void = () => {};
  mocks.request.mockImplementation((url: string) =>
    url.endsWith('/namespaces/workloads/containerprofiles')
      ? new Promise(resolve => {
          answerProfiles = resolve;
        })
      : Promise.resolve(
          url === '/apis/apps/v1/namespaces/workloads/deployments/web-app'
            ? { spec: { replicas: 3 } }
            : { items: [] }
        )
  );
  mocks.patch.mockResolvedValue({});
  mocks.remove.mockResolvedValue({});

  renderRuntimeDetection();
  openProfileTab();
  fireEvent.click(await screen.findByRole('button', { name: 'Relearn' }));
  const dialog = screen.getByRole('dialog', { name: 'Relearn Deployment web-app' });
  // the workload is read, the profiles that the checked cleanup deletes are not yet
  expect(await within(dialog).findByText(/Its 3 pods are replaced a few at a time/)).toBeTruthy();
  const button = within(dialog).getByRole('button', { name: 'Restart and relearn' });
  expect(button).toHaveProperty('disabled', true);
  expect(mocks.patch).not.toHaveBeenCalled();

  answerProfiles({ items: [webAppProfile] });
  await waitFor(() => expect(button).toHaveProperty('disabled', false));
  fireEvent.click(button);
  await waitFor(() => expect(mocks.remove).toHaveBeenCalledTimes(1));
  expect(mocks.patch).toHaveBeenCalledTimes(1);
});

it('lists the ContainerProfiles with links to their pages and their status', async () => {
  mocks.listQuery.mockImplementation(async resourceClass => {
    if (resourceClass !== mocks.containerProfileClass) {
      throw new Error(`Unsupported resource ${resourceClass.pluralName}`);
    }
    return [profile];
  });

  renderRuntimeDetection();

  expect(mocks.discoverProfileResource).not.toHaveBeenCalled();
  expect(mocks.listQuery).not.toHaveBeenCalled();
  openProfileTab();
  await waitFor(() => expect(mocks.listQuery).toHaveBeenCalledTimes(1));
  expect(mocks.discoverProfileResource.mock.calls.map(([view]) => view)).toEqual(['behavior']);

  const table = screen.getByTestId('table-Name-Kind-Namespace-Container-Status-');
  await waitFor(() => expect(within(table).getByText('completed')).toBeTruthy());
  expect(within(table).getByText('web-app', { selector: 'a' }).getAttribute('href')).toBe(
    '/Runtime Detection/workloads/deployment-web-app'
  );
  // the network traffic is on the profile page, not on a tab of its own
  expect(screen.queryByRole('tab', { name: 'Network Neighborhoods' })).toBeNull();
});

it('lists legacy profile resources on an older Storage API without changing detail links', async () => {
  mocks.discoverProfileResource.mockResolvedValue({
    plural: 'applicationprofiles',
    modern: false,
  });
  mocks.listQuery.mockImplementation(async () => [{ ...profile, kind: 'ApplicationProfile' }]);

  renderRuntimeDetection();

  openProfileTab();
  await waitFor(() => expect(mocks.listQuery).toHaveBeenCalledTimes(1));
  expect(mocks.listQuery.mock.calls.map(([resourceClass]) => resourceClass)).toEqual([
    mocks.applicationProfileClass,
  ]);
  const table = screen.getByTestId('table-Name-Kind-Namespace-Container-Status-');
  expect(within(table).getByText('web-app', { selector: 'a' }).getAttribute('href')).toBe(
    '/Runtime Detection/workloads/deployment-web-app'
  );
});

it('shows API discovery failures without querying an assumed legacy resource', async () => {
  mocks.discoverProfileResource.mockRejectedValue(new Error('Discovery forbidden'));

  renderRuntimeDetection();

  openProfileTab();
  expect(await screen.findByText('Discovery forbidden')).toBeTruthy();
  expect(mocks.listQuery).not.toHaveBeenCalled();
  expect(screen.queryByText('No profiles found.')).toBeNull();
});

it('shows retrieval errors instead of a misleading empty result', async () => {
  mocks.listQuery.mockRejectedValue(new Error('Storage temporarily unavailable'));

  renderRuntimeDetection();

  openProfileTab();
  expect(await screen.findByText('Storage temporarily unavailable')).toBeTruthy();
  expect(mocks.listQuery).toHaveBeenCalledTimes(1);
  expect(screen.queryAllByTestId('table-Name-Kind-Namespace-Container-Status-')).toHaveLength(0);
  expect(screen.queryByText('No profiles found.')).toBeNull();
});

it('accepts an empty ContainerProfile list without showing an API error', async () => {
  mocks.listQuery.mockResolvedValue([]);

  renderRuntimeDetection();

  openProfileTab();
  expect(await screen.findByText('No profiles found.')).toBeTruthy();
  expect(
    screen.getByTestId('table-Name-Kind-Namespace-Container-Status-').querySelectorAll('tbody tr')
  ).toHaveLength(0);
  expect(screen.queryByText('Storage temporarily unavailable')).toBeNull();
});

it('lists the profiles of all selected clusters and names the clusters that fail', async () => {
  mocks.clusters = ['cluster-a', 'cluster-b', 'cluster-c'];
  mocks.listQuery.mockImplementation(async (_resourceClass, cluster) => {
    if (cluster === 'cluster-b') throw new Error('forbidden');
    return [{ ...profile, metadata: { ...profile.metadata, cluster } }];
  });

  renderRuntimeDetection();
  openProfileTab();

  expect(
    await screen.findByText('Unable to read the profiles of cluster cluster-b: forbidden')
  ).toBeTruthy();
  expect(mocks.discoverProfileResource.mock.calls).toEqual([
    ['behavior', 'cluster-a'],
    ['behavior', 'cluster-b'],
    ['behavior', 'cluster-c'],
  ]);
  const table = screen.getByTestId('table-Name-Cluster-Kind-Namespace-Container-Status-');
  expect(
    within(table)
      .getAllByText('web-app', { selector: 'a' })
      .map(link => link.getAttribute('href'))
  ).toEqual([
    '/cluster-a/Runtime Detection/workloads/deployment-web-app',
    '/cluster-c/Runtime Detection/workloads/deployment-web-app',
  ]);
});

it('names the namespaces whose profiles could not be read', async () => {
  mocks.listQuery.mockResolvedValue([profile]);
  mocks.namespaceErrors = ['namespace secret: forbidden'];

  renderRuntimeDetection();
  openProfileTab();

  expect(await screen.findByText(/namespace secret: forbidden/)).toBeTruthy();
  expect(await screen.findAllByText('web-app', { selector: 'a' })).toHaveLength(1);
});

it('offers the Alertmanager found in the cluster while none is configured', async () => {
  mocks.request.mockImplementation(async (url: string) =>
    url === '/api/v1/services'
      ? {
          items: [
            {
              metadata: { name: 'alertmanager', namespace: 'monitoring' },
              spec: { ports: [{ port: 9093 }] },
            },
          ],
        }
      : { items: [] }
  );

  renderRuntimeDetection();

  fireEvent.click(await screen.findByText('Use monitoring/alertmanager:9093'));
  expect(mocks.updateConfig).toHaveBeenCalledWith({
    alertmanagerUrl: 'monitoring/alertmanager:9093',
  });
  expect(mocks.request).toHaveBeenCalledWith('/api/v1/services', { cluster: 'cluster-a' });
});

it('silences an alert as the current user and ends silences', async () => {
  const proxy = '/api/v1/namespaces/monitoring/services/alertmanager:9093/proxy';
  mocks.alertmanagerUrl = proxy;
  mocks.request.mockImplementation(async (url: string) => {
    if (url.startsWith(`${proxy}/api/v2/alerts`)) {
      return [
        {
          labels: {
            alertname: 'KubescapeRuleViolated',
            rule_name: 'Unexpected process launched',
            workload_name: 'web',
            namespace: 'shop',
          },
          annotations: {},
          startsAt: '2026-10-30T10:00:00Z',
          status: { state: 'active' },
          fingerprint: 'abc',
        },
      ];
    }
    if (url.startsWith(`${proxy}/api/v2/silences`)) {
      return [
        {
          id: 'silence-1',
          status: { state: 'active' },
          matchers: [{ name: 'workload_name', value: 'db', isRegex: false, isEqual: true }],
          startsAt: '2026-10-30T09:00:00Z',
          endsAt: '2026-10-31T09:00:00Z',
          createdBy: 'bob',
          comment: 'Silenced for 24 hours in Headlamp',
        },
      ];
    }
    return { items: [] };
  });
  mocks.post.mockImplementation(async (url: string) =>
    url.includes('selfsubjectaccessreviews') ? { status: { allowed: true } } : { silenceID: 's2' }
  );

  renderRuntimeDetection();

  fireEvent.click(await screen.findByRole('button', { name: 'Silence' }));
  const dialog = screen.getByRole('dialog', { name: 'Silence an alert' });
  expect(within(dialog).getByText('The silence is recorded in Alertmanager as jane.')).toBeTruthy();
  // the workload is the scope unless another is chosen
  expect(within(dialog).getByRole('radio', { name: /This workload/ })).toHaveProperty(
    'checked',
    true
  );
  fireEvent.click(within(dialog).getByRole('radio', { name: /All workloads in namespace/ }));
  fireEvent.click(within(dialog).getByRole('button', { name: '1 hour' }));
  // a silence needs a reason
  const silenceButton = within(dialog).getByRole('button', { name: 'Silence' });
  expect(silenceButton).toHaveProperty('disabled', true);
  fireEvent.change(within(dialog).getByRole('textbox', { name: /Reason/ }), {
    target: { value: 'Expected during the migration' },
  });
  fireEvent.click(silenceButton);

  expect(
    await screen.findByText('Silenced Unexpected process launched in namespace shop for 1 hour.')
  ).toBeTruthy();
  expect(screen.queryByRole('dialog')).toBeNull();
  const [url, silence, , options] = mocks.post.mock.calls.find(([url]) =>
    url.endsWith('/api/v2/silences')
  )!;
  expect(url).toBe(`${proxy}/api/v2/silences`);
  expect(silence.createdBy).toBe('jane');
  expect(silence.comment).toBe('Expected during the migration');
  expect(silence.matchers.map((matcher: any) => matcher.name)).toEqual([
    'alertname',
    'rule_name',
    'namespace',
  ]);
  expect(options).toEqual({ cluster: 'cluster-a' });

  expect(screen.getByText('workload_name=db')).toBeTruthy();
  expect(screen.getByText(/Silenced by bob until/)).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'End silence' }));
  await waitFor(() =>
    expect(mocks.remove).toHaveBeenCalledWith(`${proxy}/api/v2/silence/silence-1`, {
      cluster: 'cluster-a',
      autoLogoutOnAuthError: false,
      isJSON: false,
    })
  );
  // the proxy of the service itself is what the user must be allowed
  expect(
    mocks.post.mock.calls
      .filter(([url]) => url.includes('selfsubjectaccessreviews'))
      .map(([, review]) => review.spec.resourceAttributes)
      .filter(attributes => attributes.subresource === 'proxy')
      .map(({ verb, namespace, name }) => [verb, namespace, name])
  ).toEqual(
    expect.arrayContaining([
      ['create', 'monitoring', 'alertmanager:9093'],
      ['delete', 'monitoring', 'alertmanager:9093'],
    ])
  );
});

it('keeps the silence dialog and its reason when the alert leaves the list', async () => {
  const proxy = '/api/v1/namespaces/monitoring/services/alertmanager:9093/proxy';
  mocks.alertmanagerUrl = proxy;
  let alerts: unknown[] = [
    {
      labels: {
        alertname: 'KubescapeRuleViolated',
        rule_name: 'Unexpected process launched',
        namespace: 'shop',
        pod_name: 'web-0',
      },
      annotations: {},
      startsAt: '2026-10-30T10:00:00Z',
      status: { state: 'active' },
      fingerprint: 'abc',
    },
  ];
  mocks.request.mockImplementation(async (url: string) => {
    if (url.startsWith(`${proxy}/api/v2/alerts`)) return alerts;
    if (url.startsWith(`${proxy}/api/v2/silences`)) return [];
    return { items: [] };
  });
  mocks.post.mockImplementation(async (url: string) =>
    url.includes('selfsubjectaccessreviews') ? { status: { allowed: true } } : { silenceID: 's3' }
  );

  renderRuntimeDetection();
  fireEvent.click(await screen.findByRole('button', { name: 'Silence' }));
  const dialog = screen.getByRole('dialog', { name: 'Silence an alert' });
  fireEvent.change(within(dialog).getByRole('textbox', { name: /Reason/ }), {
    target: { value: 'Known behaviour of the migration' },
  });

  // a refresh no longer has the alert on the page: it ended, or newer alerts took its place
  alerts = [];
  const table = screen.getByTestId('table-Time-Rule-Severity-Pod-Workload-Namespace-Message-');
  fireEvent.click(screen.getByRole('button', { name: 'Refresh', hidden: true }));
  await waitFor(() => expect(table.querySelectorAll('tbody tr')).toHaveLength(0));

  // the dialog is not part of the row, so it is still there with what was typed
  expect(screen.getByRole('dialog', { name: 'Silence an alert' })).toBe(dialog);
  expect(within(dialog).getByRole('textbox', { name: /Reason/ })).toHaveProperty(
    'value',
    'Known behaviour of the migration'
  );
  fireEvent.click(within(dialog).getByRole('button', { name: 'Silence' }));
  expect(await screen.findByText(/^Silenced Unexpected process launched for web /)).toBeTruthy();
  expect(screen.queryByRole('dialog')).toBeNull();
});

it('shows an alert of the node-agent by severity, workload and finding, with its details', async () => {
  const proxy = '/api/v1/namespaces/monitoring/services/alertmanager:9093/proxy';
  mocks.alertmanagerUrl = proxy;
  mocks.request.mockImplementation(async (url: string) =>
    url.startsWith(`${proxy}/api/v2/alerts`)
      ? [
          {
            labels: {
              alertname: 'KubescapeRuleViolated',
              rule_name: 'DNS Anomalies in container',
              rule_id: 'R0005',
              severity: '1',
              namespace: 'certificates',
              pod_name: 'cert-watch-b576bb668-5f2s6',
              container_name: 'watcher',
              node_name: 'node-1',
              comm: 'python3',
              pid: '9635',
              pcomm: 'containerd-shim',
              ppid: '7476',
              // node-agent v0.3 sends memory addresses as ids
              uid: '824701441376',
              gid: '0',
              trace: '{}',
              profile_status: 'completed',
            },
            annotations: {
              description:
                'Unexpected domain communication: _acme-challenge.example.com. from: watcher',
              summary:
                "Rule 'DNS Anomalies in container' in 'cert-watch-b576bb668-5f2s6' namespace 'certificates' failed",
              fix: '',
            },
            startsAt: '2026-10-31T17:19:17Z',
            endsAt: '2026-10-31T18:19:17Z',
            status: { state: 'active' },
            fingerprint: 'abc',
          },
        ]
      : url.endsWith('/namespaces/certificates/containerprofiles')
      ? {
          items: [
            {
              metadata: {
                name: 'replicaset-cert-watch-b576bb668-watcher-1a2b-3c4d',
                namespace: 'certificates',
                labels: { 'kubescape.io/workload-name': 'cert-watch' },
                annotations: {
                  'kubescape.io/instance-id':
                    'apiVersion-apps/v1/namespace-certificates/kind-ReplicaSet/name-cert-watch-b576bb668/containerName-watcher',
                },
              },
            },
          ],
        }
      : url.endsWith('/containerprofiles/replicaset-cert-watch-b576bb668-watcher-1a2b-3c4d')
      ? {
          metadata: {
            name: 'replicaset-cert-watch-b576bb668-watcher-1a2b-3c4d',
            namespace: 'certificates',
          },
          spec: { egress: [{ dns: 'acme-v02.api.letsencrypt.org.' }, { dns: 'example.com.' }] },
        }
      : url.endsWith('/pods/cert-watch-b576bb668-5f2s6')
      ? {
          metadata: {
            ownerReferences: [
              { kind: 'ReplicaSet', name: 'cert-watch-b576bb668', controller: true },
            ],
          },
        }
      : { items: [] }
  );
  mocks.post.mockResolvedValue({ status: { allowed: true } });
  mocks.ruleObjects = [
    {
      cluster: 'cluster-a',
      jsonData: {
        metadata: { name: 'default-rules', namespace: 'kubescape' },
        spec: {
          rules: [
            {
              id: 'R0005',
              name: 'DNS Anomalies in container',
              description:
                'Detects unexpected domain requests that are not whitelisted by the learned profile',
              mitreTactic: 'TA0011',
              mitreTechnique: 'T1071.004',
              profileDependency: 0,
            },
          ],
        },
      },
    },
  ];

  renderRuntimeDetection();

  expect(await screen.findByText('cert-watch')).toBeTruthy();
  expect(screen.getByText('Low')).toBeTruthy();
  expect(
    screen.getByText('Unexpected domain communication: _acme-challenge.example.com. from: watcher')
  ).toBeTruthy();

  // the silence button of the row opens only the silence dialog, and clicks in that dialog do
  // not reach the row
  fireEvent.click(screen.getByRole('button', { name: 'Silence' }));
  const silenceDialog = screen.getByRole('dialog', { name: 'Silence an alert' });
  expect(
    within(silenceDialog).getByText(/pod_name=~cert-watch-\[bcdfghjklmnpqrstvwxz2456789\]/)
  ).toBeTruthy();
  fireEvent.click(within(silenceDialog).getByText('The whole cluster'));
  expect(screen.getAllByRole('dialog')).toHaveLength(1);
  fireEvent.click(within(silenceDialog).getByRole('button', { name: 'Cancel' }));
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());

  // a click anywhere else on the row does
  fireEvent.click(screen.getByText('cert-watch'));
  const dialog = screen.getByRole('dialog');
  expect(within(dialog).getByText('python3 (PID 9635)')).toBeTruthy();
  expect(within(dialog).getByText('containerd-shim (PID 7476)')).toBeTruthy();
  expect(within(dialog).getByText('DNS Anomalies in container (R0005)')).toBeTruthy();
  expect(within(dialog).getByText('Low (priority 1)')).toBeTruthy();
  // what the rule detects, from the rules of the cluster
  expect(
    within(dialog).getByText(
      'Detects unexpected domain requests that are not whitelisted by the learned profile.'
    )
  ).toBeTruthy();
  expect(within(dialog).getByText('T1071.004').getAttribute('href')).toBe(
    'https://attack.mitre.org/techniques/T1071/004/'
  );
  expect(within(dialog).getByText(/^Required/)).toBeTruthy();
  expect(within(dialog).getByText('Group ID')).toBeTruthy();
  expect(within(dialog).queryByText('User ID')).toBeNull();
  expect(within(dialog).queryByText('Fix')).toBeNull();
  expect(within(dialog).queryByText('Trace')).toBeNull();
  expect(
    within(dialog).getByText('cert-watch-b576bb668-5f2s6').closest('a')?.getAttribute('href')
  ).toBe('/cluster-a/pod/certificates/cert-watch-b576bb668-5f2s6');
  // the profile the container was checked against, of the version of the pod
  const profileLink = await within(dialog).findByText('ReplicaSet cert-watch-b576bb668, watcher');
  expect(profileLink.closest('a')?.getAttribute('href')).toBe(
    '/cluster-a/Runtime Detection/certificates/replicaset-cert-watch-b576bb668-watcher-1a2b-3c4d'
  );

  // the domain of the DNS rule, below the rule, and what the profile learned
  const names = within(dialog)
    .getAllByRole('term')
    .map(term => term.textContent);
  expect(names.indexOf('Domain')).toBe(names.indexOf('Rule') + 1);
  expect(names.indexOf('Severity')).toBe(names.indexOf('Domain') + 1);
  expect(within(dialog).getByText('_acme-challenge.example.com')).toBeTruthy();
  expect(
    await within(dialog).findByText('2, and _acme-challenge.example.com is not one of them')
  ).toBeTruthy();
  expect(within(dialog).getByText('Under example.com it learned example.com')).toBeTruthy();
  fireEvent.click(within(dialog).getByText('Show all 2'));
  expect(within(dialog).getByText(/acme-v02\.api\.letsencrypt\.org/)).toBeTruthy();

  fireEvent.click(within(dialog).getByText('Close'));
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());

  // and so does Enter on the rule
  fireEvent.keyDown(screen.getByText('DNS Anomalies in container'), { key: 'Enter' });
  const reopened = screen.getByRole('dialog');
  // which looks up the profile and its domains again
  expect(
    await within(reopened).findByText('ReplicaSet cert-watch-b576bb668, watcher')
  ).toBeTruthy();
  expect(
    await within(reopened).findByText('2, and _acme-challenge.example.com is not one of them')
  ).toBeTruthy();
});

it('describes the rule of an alert when the rules are read after the alerts', async () => {
  const proxy = '/api/v1/namespaces/monitoring/services/alertmanager:9093/proxy';
  mocks.alertmanagerUrl = proxy;
  mocks.request.mockImplementation(async (url: string) =>
    url.startsWith(`${proxy}/api/v2/alerts`)
      ? [
          {
            labels: {
              alertname: 'KubescapeRuleViolated',
              rule_name: 'Unexpected process launched',
            },
            annotations: {},
            startsAt: '2026-10-30T10:00:00Z',
            status: { state: 'active' },
            fingerprint: 'abc',
            cluster: 'cluster-a',
          },
        ]
      : { items: [] }
  );
  const { rerender } = renderRuntimeDetection();
  const rule = await screen.findByText('Unexpected process launched');
  fireEvent.mouseOver(rule);
  await new Promise(resolve => setTimeout(resolve, 200));
  expect(screen.queryByRole('tooltip')).toBeNull();

  // the rules arrive; the alerts stay the same
  mocks.ruleObjects = [
    {
      cluster: 'cluster-a',
      jsonData: {
        metadata: { name: 'default-rules', namespace: 'kubescape' },
        spec: {
          rules: [
            {
              id: 'R0001',
              name: 'Unexpected process launched',
              description: 'Detects processes that are not in the baseline',
            },
          ],
        },
      },
    },
  ];
  rerender(
    <MemoryRouter>
      <RuntimeDetection />
    </MemoryRouter>
  );
  fireEvent.mouseOver(screen.getByText('Unexpected process launched'));
  expect((await screen.findByRole('tooltip')).textContent).toMatch(
    /^Detects processes that are not in the baseline/
  );
});

it('checks whether new Rules objects may be created in the namespace of Kubescape', async () => {
  // a cluster of its own, as the namespace and the answers are kept per cluster
  mocks.currentCluster = 'cluster-security';
  mocks.request.mockImplementation(async (url: string) =>
    url.startsWith('/api/v1/pods?')
      ? { items: [{ metadata: { namespace: 'security' } }] }
      : { items: [] }
  );
  mocks.post.mockResolvedValue({ status: { allowed: true } });

  renderRuntimeDetection();
  fireEvent.click(screen.getByRole('tab', { name: 'Rules' }));

  await waitFor(() =>
    expect(mocks.post).toHaveBeenCalledWith(
      '/apis/authorization.k8s.io/v1/selfsubjectaccessreviews',
      expect.objectContaining({
        spec: {
          resourceAttributes: {
            group: 'kubescape.io',
            resource: 'rules',
            verb: 'create',
            namespace: 'security',
          },
        },
      }),
      false,
      { cluster: 'cluster-security' }
    )
  );
});

it('lists and deletes the rule bindings of each selected cluster', async () => {
  mocks.clusters = ['cluster-a', 'cluster-b'];
  mocks.request.mockImplementation(async (url: string, { cluster }: { cluster: string }) =>
    url === '/apis/kubescape.io/v1/runtimerulealertbindings'
      ? { items: [{ metadata: { name: `binding-${cluster}` }, spec: { rules: [] } }] }
      : { items: [] }
  );

  renderRuntimeDetection();
  fireEvent.click(screen.getByRole('tab', { name: 'Rule Bindings' }));

  expect(await screen.findByText('binding-cluster-b')).toBeTruthy();
  expect(screen.getByText('binding-cluster-a')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Delete binding-cluster-b' }));
  // after a confirmation that names the binding and its cluster
  const dialog = screen.getByRole('dialog', { name: 'Delete rule binding?' });
  expect(dialog.textContent).toMatch(
    /Deletes the rule binding binding-cluster-b of cluster cluster-b/
  );
  fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));
  await waitFor(() =>
    expect(mocks.remove).toHaveBeenCalledWith(
      '/apis/kubescape.io/v1/runtimerulealertbindings/binding-cluster-b',
      { cluster: 'cluster-b' }
    )
  );
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
});

it('deletes a Rules object only after a confirmation that names it', async () => {
  mocks.clusters = ['cluster-a', 'cluster-b'];
  mocks.ruleObjects = [
    {
      cluster: 'cluster-b',
      jsonData: {
        metadata: { name: 'default-rules', namespace: 'kubescape' },
        spec: { rules: [{ id: 'R0001' }, { id: 'R0005' }] },
      },
    },
  ];
  mocks.remove.mockRejectedValueOnce(new Error('rules.kubescape.io is forbidden'));

  renderRuntimeDetection();
  fireEvent.click(screen.getByRole('tab', { name: 'Rules' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Delete default-rules' }));

  const dialog = screen.getByRole('dialog', { name: 'Delete Rules object?' });
  expect(dialog.textContent).toBe(
    'Delete Rules object?Deletes the Rules object default-rules in namespace kubescape of cluster ' +
      'cluster-b. Runtime detection no longer uses the 2 rules it holds.CancelDelete'
  );
  // nothing is deleted until the user confirms
  fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  expect(mocks.remove).not.toHaveBeenCalled();

  // a failed delete keeps the dialog open with the error
  fireEvent.click(screen.getByRole('button', { name: 'Delete default-rules' }));
  fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }));
  expect(await screen.findByText('rules.kubescape.io is forbidden')).toBeTruthy();
  fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }));
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  expect(mocks.remove).toHaveBeenLastCalledWith(
    '/apis/kubescape.io/v1/namespaces/kubescape/rules/default-rules',
    { cluster: 'cluster-b' }
  );
});

it('asks before deleting a Rules object with the rules it holds now', async () => {
  const rulesObject = (rules: object[]) => ({
    cluster: 'cluster-a',
    jsonData: { metadata: { name: 'custom-rules', namespace: 'kubescape' }, spec: { rules } },
  });
  mocks.ruleObjects = [rulesObject([{ id: 'R9001' }, { id: 'R9002' }])];

  const { rerender } = renderRuntimeDetection();
  fireEvent.click(screen.getByRole('tab', { name: 'Rules' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Delete custom-rules' }));
  expect(screen.getByRole('dialog').textContent).toContain('the 2 rules it holds');

  // the list is watched: a rule was added, which the row that opened the dialog does not have
  mocks.ruleObjects = [rulesObject([{ id: 'R9001' }, { id: 'R9002' }, { id: 'R9003' }])];
  rerender(
    <MemoryRouter>
      <RuntimeDetection />
    </MemoryRouter>
  );
  expect(screen.getByRole('dialog').textContent).toContain('the 3 rules it holds');
});

const seccompProfile = {
  metadata: {
    name: 'deployment-web',
    namespace: 'shop',
    labels: { 'kubescape.io/workload-name': 'web', 'kubescape.io/workload-kind': 'Deployment' },
  },
  spec: {
    containers: [
      {
        name: 'web',
        spec: {
          defaultAction: 'SCMP_ACT_ERRNO',
          syscalls: [{ names: ['read', 'write', 'openat'], action: 'SCMP_ACT_ALLOW' }],
        },
      },
      { name: 'sidecar', spec: { defaultAction: 'SCMP_ACT_ERRNO', syscalls: [] } },
    ],
  },
  status: {
    containers: {
      web: { status: 'Installed', localhostProfile: 'kubescape/shop/deployment-web/web.json' },
    },
  },
};

function serveSeccompProfilesFromCrd() {
  mocks.request.mockImplementation(async (url: string) =>
    url === '/apis/kubescape.io/v1' ? { resources: [{ name: 'seccompprofiles' }] } : { items: [] }
  );
}

it('lists the seccomp profiles that Kubescape generated', async () => {
  serveSeccompProfilesFromCrd();
  mocks.listQuery.mockResolvedValue([seccompProfile]);

  renderRuntimeDetection();
  fireEvent.click(screen.getByRole('tab', { name: 'Seccomp Profiles' }));

  const link = await screen.findByText('web', { selector: 'a' });
  expect(link.getAttribute('href')).toBe('/Seccomp Profile/shop/deployment-web');
  expect(mocks.listQuery).toHaveBeenCalledWith(mocks.seccompProfileClass, 'cluster-a');
  const row = link.closest('tr')!;
  expect(within(row).getByText('web, sidecar')).toBeTruthy();
  expect(within(row).getByText('1 of 2')).toBeTruthy();
});

it('lists the seccomp profiles that were read when a namespace could not be', async () => {
  serveSeccompProfilesFromCrd();
  mocks.listQuery.mockResolvedValue([seccompProfile]);
  mocks.namespaceErrors = ['namespace secret: forbidden'];

  renderRuntimeDetection();
  fireEvent.click(screen.getByRole('tab', { name: 'Seccomp Profiles' }));

  expect(await screen.findByText(/namespace secret: forbidden/)).toBeTruthy();
  expect(screen.getByText('web', { selector: 'a' })).toBeTruthy();
});

it('reads the seccomp profiles of the storage with their spec', async () => {
  mocks.request.mockImplementation(async (url: string) => {
    if (url === '/apis/spdx.softwarecomposition.kubescape.io/v1beta1') {
      return { resources: [{ name: 'seccompprofiles' }] };
    }
    // the storage only returns the spec of a list that asks for it
    if (url.includes('/seccompprofiles?')) {
      return url.includes('resourceVersion=fullSpec')
        ? { items: [structuredClone(seccompProfile)], metadata: {} }
        : { items: [{ metadata: seccompProfile.metadata }], metadata: {} };
    }
    return { resources: [] };
  });

  renderRuntimeDetection();
  fireEvent.click(screen.getByRole('tab', { name: 'Seccomp Profiles' }));

  const link = await screen.findByText('web', { selector: 'a' });
  const row = link.closest('tr')!;
  expect(within(row).getByText('web, sidecar')).toBeTruthy();
  expect(within(row).getByText('1 of 2')).toBeTruthy();
  expect(mocks.listQuery).not.toHaveBeenCalled();
});

it('shows how to apply an installed seccomp profile and explains a missing one', async () => {
  serveSeccompProfilesFromCrd();
  mocks.fetchObject.mockResolvedValue(seccompProfile);

  render(
    <MemoryRouter initialEntries={['/kubescape/seccompprofiles/shop/deployment-web']}>
      <SeccompProfileDetail />
    </MemoryRouter>
  );

  expect(await screen.findByText('openat, read, write')).toBeTruthy();
  expect(mocks.fetchObject.mock.calls[0].slice(0, 2)).toEqual(['deployment-web', 'shop']);
  expect(
    screen.getByText(/localhostProfile: kubescape\/shop\/deployment-web\/web\.json/)
  ).toBeTruthy();
  expect(screen.getByText(/has not installed this profile on the nodes yet/)).toBeTruthy();
});

it('offers no new rule without permission to create Rules objects', async () => {
  mocks.currentCluster = 'cluster-without-rules';
  mocks.post.mockImplementation(async (url: string, review: any) =>
    url.includes('selfsubjectaccessreviews')
      ? { status: { allowed: review.spec.resourceAttributes.resource !== 'rules' } }
      : {}
  );
  renderRuntimeDetection();
  fireEvent.click(screen.getByRole('tab', { name: 'Rules' }));

  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Add new rule' })).toHaveProperty('disabled', true)
  );
  expect(
    screen.getByLabelText('You are not allowed to create rules in namespace kubescape.')
  ).toBeTruthy();
});
