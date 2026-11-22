import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { vi } from 'vitest';
import { FrameworkEdit, FrameworkNew } from './FrameworkEdit';

const mocks = vi.hoisted(() => ({
  // SelfSubjectAccessReviews and ConfigMap creation
  post: vi.fn(),
  put: vi.fn(),
  saveConfigMap: vi.fn(),
  enqueueSnackbar: vi.fn(),
  existing: {} as any,
  // why the ConfigMap could not be read
  getError: null as (Error & { status?: number }) | null,
  useGet: vi.fn(),
  // the namespace parameter of the URL
  namespace: null as string | null,
  saveToFile: vi.fn(),
  // the controls of the plugin's data, which the pages share
  controls: [
    {
      controlID: 'C-0016',
      name: 'Allow privilege escalation',
      baseScore: 6,
      rulesNames: ['rule-allow-privilege-escalation'],
    },
    // a control that is in none of the frameworks the editor shows by default
    { controlID: 'C-0099', name: 'Another control', baseScore: 3 },
  ],
}));

vi.mock('@kinvolk/headlamp-plugin/lib', () => ({
  K8s: {
    ResourceClasses: {
      ConfigMap: {
        useGet: (...args: any[]) => {
          mocks.useGet(...args);
          return mocks.getError ? [null, mocks.getError] : [{ jsonData: mocks.existing }];
        },
      },
    },
  },
}));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({
  ApiError: Error,
  post: mocks.post,
  put: mocks.put,
}));
vi.mock('@kinvolk/headlamp-plugin/lib/Utils', () => ({ getCluster: () => 'cluster-a' }));
vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', () => ({
  SectionBox: ({ children }: any) => <section>{children}</section>,
  NameValueTable: ({ rows }: any) => (
    <div>
      {rows.map((row: any) => (
        <div key={row.name}>{row.value}</div>
      ))}
    </div>
  ),
}));
vi.mock('notistack', () => ({ useSnackbar: () => ({ enqueueSnackbar: mocks.enqueueSnackbar }) }));
vi.mock('../custom-objects/api-queries', () => ({
  checkUniqueness: async () => true,
  useKubescapeNamespace: () => ({ kubeScapeNamespace: 'kubescape', error: null, loading: false }),
}));
vi.mock('../common/filedialog', () => ({ saveToFile: mocks.saveToFile }));
vi.mock('../common/PluginHelper', () => ({ getKubescapePluginUrl: async () => '' }));
vi.mock('../compliance/Compliance', () => ({ complianceSeverity: () => 'High' }));
vi.mock('../common/url', () => ({
  getURLSegments: () => ['dev-framework-abc123'],
  useURLSearchParam: () => [mocks.namespace, () => {}],
}));
vi.mock('../model', () => ({ customObjectLabel: 'kubescape.io/custom-object' }));
vi.mock('../rego', () => ({
  defaultFrameworkNames: ['NSA'],
  useRegoData: () => ({
    controls: mocks.controls,
    frameworks: [{ name: 'NSA', controls: [{ controlID: 'C-0016' }] }],
    loading: false,
  }),
}));

// Validation of the API server for metadata.name of a ConfigMap and for label values
const dns1123Subdomain = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$/;
const labelValue = /^(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?$/;

beforeEach(() => {
  mocks.enqueueSnackbar.mockReset();
  mocks.saveConfigMap
    .mockReset()
    .mockImplementation((_url: string, body: any) =>
      Promise.resolve({ ...body, metadata: { ...body.metadata, uid: 'new-uid' } })
    );
  mocks.post
    .mockReset()
    .mockImplementation((url: string, body: any) =>
      url.includes('selfsubjectaccessreviews')
        ? Promise.resolve({ status: { allowed: true } })
        : mocks.saveConfigMap(url, body)
    );
  mocks.put.mockReset();
  mocks.useGet.mockReset();
  mocks.saveToFile.mockReset();
  mocks.getError = null;
  mocks.namespace = null;
  mocks.existing = {
    apiVersion: 'v1',
    kind: 'ConfigMap',
    metadata: { name: 'dev-framework-abc123', namespace: 'kubescape', uid: 'u1', labels: {} },
    data: { name: 'Dev', description: '', controlsIDs: '["C-0016"]' },
  };
});
afterEach(cleanup);

const saveButton = () =>
  screen.findByRole('button', { name: 'Save policy as a Configmap in k8s cluster' });

async function createFramework(name: string) {
  render(
    <MemoryRouter>
      <FrameworkNew />
    </MemoryRouter>
  );
  fireEvent.change(screen.getByPlaceholderText('Enter Framework Name'), {
    target: { value: name },
  });
  // the first checkboxes select all controls, the next one is C-0016
  fireEvent.click(screen.getAllByRole('checkbox')[2]);
  fireEvent.click(await saveButton());
}

it.each([
  ['Dev', 'dev'],
  ['Dev Framework', 'dev-framework'],
  ['My Dev Framework', 'my-dev-framework'],
  ['My  Dev Framework', 'my-dev-framework'],
])('creates a ConfigMap that Kubernetes accepts for %j', async (name, kubernetesName) => {
  await createFramework(name);

  await waitFor(() => expect(mocks.saveConfigMap).toHaveBeenCalledTimes(1));
  const [url, configMap] = mocks.saveConfigMap.mock.calls[0];
  expect(url).toBe('/api/v1/namespaces/kubescape/configmaps');
  expect(configMap.metadata.name).toMatch(new RegExp(`^${kubernetesName}-framework-[a-z0-9]+$`));
  expect(configMap.metadata.name).toMatch(dns1123Subdomain);
  expect(configMap.metadata.labels['app.kubernetes.io/name']).toBe(kubernetesName);
  expect(configMap.metadata.labels['kubescape.io/custom-object']).toBe('framework');
  expect(configMap.data.name).toBe(name);
  await waitFor(() =>
    expect(mocks.enqueueSnackbar).toHaveBeenCalledWith(`${name} saved successfully`, {
      variant: 'success',
    })
  );
});

it('keeps the label of a long name within 63 characters and the full name in the data', async () => {
  // 64 characters, and the cut at 63 would end with a dash
  const name = `${'a'.repeat(62)} ${'b'.repeat(70)}`;
  await createFramework(name);

  await waitFor(() => expect(mocks.saveConfigMap).toHaveBeenCalledTimes(1));
  const configMap = mocks.saveConfigMap.mock.calls[0][1];
  const label = configMap.metadata.labels['app.kubernetes.io/name'];
  expect(label).toBe('a'.repeat(62));
  expect(label).toMatch(labelValue);
  expect(configMap.metadata.name).toMatch(dns1123Subdomain);
  expect(configMap.metadata.name.length).toBeLessThanOrEqual(253);
  expect(configMap.data.name).toBe(name);
});

it('accepts a name with a capital I where the language of the user lowers it to a dotless i', async () => {
  // as in a Turkish browser
  const lower = vi
    .spyOn(String.prototype, 'toLocaleLowerCase')
    .mockImplementation(function (this: string) {
      return this.replace(/I/g, 'ı').toLowerCase();
    });
  try {
    await createFramework('Internal');

    await waitFor(() => expect(mocks.saveConfigMap).toHaveBeenCalledTimes(1));
    const configMap = mocks.saveConfigMap.mock.calls[0][1];
    expect(configMap.metadata.labels['app.kubernetes.io/name']).toBe('internal');
    expect(configMap.metadata.name).toMatch(dns1123Subdomain);
  } finally {
    lower.mockRestore();
  }
});

it('refuses the name of a default framework, whatever its case', async () => {
  // the pages would always show the default framework of that name
  await createFramework('nsa');

  expect(
    await screen.findByText('nsa is the name of a default framework. Please provide another name.')
  ).toBeTruthy();
  expect(mocks.saveConfigMap).not.toHaveBeenCalled();
});

it('downloads the controls selected now with their rules, and leaves the shared controls alone', async () => {
  const rules = [{ name: 'rule-allow-privilege-escalation' }, { name: 'another-rule' }];
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => ({ ok: true, text: async () => JSON.stringify(rules) }))
  );
  try {
    render(
      <MemoryRouter>
        <FrameworkNew />
      </MemoryRouter>
    );
    fireEvent.change(screen.getByPlaceholderText('Enter Framework Name'), {
      target: { value: 'Dev' },
    });
    // C-0016, as in createFramework
    fireEvent.click(screen.getAllByRole('checkbox')[2]);
    fireEvent.click(screen.getByRole('button', { name: 'Download custom framework file' }));

    await waitFor(() => expect(mocks.saveToFile).toHaveBeenCalledTimes(1));
    const [json, fileName] = mocks.saveToFile.mock.calls[0];
    expect(fileName).toBe('Dev.json');
    const downloaded = JSON.parse(json);
    expect(downloaded.controlsIDs).toEqual(['C-0016']);
    expect(downloaded.controls).toEqual([
      { ...mocks.controls[0], rules: [{ name: 'rule-allow-privilege-escalation' }] },
    ]);
    expect(mocks.controls[0]).not.toHaveProperty('rules');
  } finally {
    vi.unstubAllGlobals();
  }
});

it('selects every framework with the first entry of the filter, unless all are selected', async () => {
  render(
    <MemoryRouter>
      <FrameworkNew />
    </MemoryRouter>
  );
  const options = () => screen.getAllByRole('option');
  fireEvent.mouseDown(screen.getByRole('combobox'));
  expect(screen.getByText('C-0016')).toBeTruthy();

  // without NSA, the only framework, no controls are shown
  fireEvent.click(options()[1]);
  expect(screen.queryByText('C-0016')).toBeNull();
  fireEvent.click(options()[0]);
  expect(screen.getByText('C-0016')).toBeTruthy();
  // all are selected: the entry deselects them
  fireEvent.click(options()[0]);
  expect(screen.queryByText('C-0016')).toBeNull();
});

it('says why the ConfigMap of a framework could not be read', async () => {
  mocks.getError = Object.assign(new Error('configmaps "dev-framework-abc123" not found'), {
    status: 404,
  });
  render(
    <MemoryRouter>
      <FrameworkEdit />
    </MemoryRouter>
  );

  expect(screen.getByText('Resource not found')).toBeTruthy();
  expect(screen.getByText('configmaps "dev-framework-abc123" not found')).toBeTruthy();
  expect(screen.queryByPlaceholderText('Enter Framework Name')).toBeNull();
});

it('shows a failed creation and keeps the form usable', async () => {
  mocks.saveConfigMap.mockRejectedValueOnce(
    new Error('Unprocessable Entity - ConfigMap "dev-framework-x" is invalid')
  );
  await createFramework('Dev Framework');

  expect(
    await screen.findByText(
      'Failed to save Dev Framework: Unprocessable Entity - ConfigMap "dev-framework-x" is invalid'
    )
  ).toBeTruthy();
  expect(mocks.enqueueSnackbar).not.toHaveBeenCalled();
  expect((screen.getByPlaceholderText('Enter Framework Name') as HTMLInputElement).value).toBe(
    'Dev Framework'
  );

  // a second attempt goes through
  fireEvent.click(await saveButton());
  await waitFor(() =>
    expect(mocks.enqueueSnackbar).toHaveBeenCalledWith('Dev Framework saved successfully', {
      variant: 'success',
    })
  );
  expect(screen.queryByText(/Failed to save/)).toBeNull();
});

it('shows a failed update of an existing framework', async () => {
  mocks.put.mockRejectedValueOnce(new Error('Conflict - the object has been modified'));
  render(
    <MemoryRouter>
      <FrameworkEdit />
    </MemoryRouter>
  );
  fireEvent.change(screen.getByPlaceholderText('Enter Framework Name'), {
    target: { value: 'Dev Framework' },
  });
  fireEvent.click(await saveButton());

  expect(
    await screen.findByText('Failed to save Dev Framework: Conflict - the object has been modified')
  ).toBeTruthy();
  expect(mocks.put).toHaveBeenCalledWith(
    '/api/v1/namespaces/kubescape/configmaps/dev-framework-abc123',
    expect.objectContaining({ data: expect.objectContaining({ name: 'Dev Framework' }) })
  );
  expect(mocks.enqueueSnackbar).not.toHaveBeenCalled();
  expect((screen.getByPlaceholderText('Enter Framework Name') as HTMLInputElement).value).toBe(
    'Dev Framework'
  );
});

it('keeps the selected controls that the filter hides when the shown ones are deselected', async () => {
  mocks.existing.data.controlsIDs = '["C-0016","C-0099"]';
  mocks.put.mockImplementation((_url: string, body: any) => Promise.resolve(body));
  render(
    <MemoryRouter>
      <FrameworkEdit />
    </MemoryRouter>
  );
  const selectShown = screen.getByRole('checkbox', { name: 'Select the controls shown' });
  expect((selectShown as HTMLInputElement).checked).toBe(true);

  fireEvent.click(selectShown);
  fireEvent.click(await saveButton());

  await waitFor(() => expect(mocks.put).toHaveBeenCalled());
  expect(JSON.parse(mocks.put.mock.calls[0][1].data.controlsIDs)).toEqual(['C-0099']);
});

it('edits a ConfigMap in the namespace the list found it in', async () => {
  mocks.namespace = 'security';
  mocks.existing.metadata.namespace = 'security';
  mocks.put.mockImplementation((_url: string, body: any) => Promise.resolve(body));
  render(
    <MemoryRouter>
      <FrameworkEdit />
    </MemoryRouter>
  );

  expect(mocks.useGet).toHaveBeenCalledWith('dev-framework-abc123', 'security');
  fireEvent.click(await saveButton());
  await waitFor(() =>
    expect(mocks.put).toHaveBeenCalledWith(
      '/api/v1/namespaces/security/configmaps/dev-framework-abc123',
      expect.anything()
    )
  );
});

it.each([['not json'], ['{"C-0016": true}'], [undefined]])(
  'opens a hand-edited ConfigMap with controlsIDs %j as a framework without controls',
  async controlsIDs => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    mocks.existing.data.controlsIDs = controlsIDs;
    render(
      <MemoryRouter>
        <FrameworkEdit />
      </MemoryRouter>
    );
    // the save button asks whether the user may change the framework
    await act(async () => {});

    expect(mocks.useGet).toHaveBeenCalledWith('dev-framework-abc123', 'kubescape');
    expect((screen.getByPlaceholderText('Enter Framework Name') as HTMLInputElement).value).toBe(
      'Dev'
    );
    const selectShown = screen.getByRole('checkbox', { name: 'Select the controls shown' });
    expect((selectShown as HTMLInputElement).checked).toBe(false);
    error.mockRestore();
  }
);
