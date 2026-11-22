import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { vi } from 'vitest';
import { ChoosePolicyButton } from './ChoosePolicyButton';
import { ChooseTestResource } from './ChooseTestResource';
import { CurrentEvalContext } from './ValidatingAdmissionPolicy';

const mocks = vi.hoisted(() => ({ request: vi.fn(), setResource: vi.fn(), fetch: vi.fn() }));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ request: mocks.request }));
vi.mock('@kinvolk/headlamp-plugin/lib/Utils', () => ({ getCluster: () => 'cluster-a' }));
vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', () => ({ ShowHideLabel: () => null }));
vi.mock('@monaco-editor/react', () => ({ default: () => null }));
vi.mock('../wasm/initWasmModule', () => ({ loadWasm: vi.fn(), useWasm: () => ({}) }));
vi.mock('../common/clusterContext', () => ({ getAllowedNamespaces: () => [] }));
vi.mock('../common/PluginHelper', () => ({ getKubescapePluginUrl: async () => '/plugin' }));

const context = {
  resource: null,
  setResource: mocks.setResource,
  setResourceForNamespace: vi.fn(),
  paramsObject: null,
  namespaceObject: null,
  validatingAdmissionPolicy: null,
  setValidatingAdmissionPolicy: vi.fn(),
};

function renderInContext(children: JSX.Element) {
  render(<CurrentEvalContext.Provider value={context}>{children}</CurrentEvalContext.Provider>);
}

beforeEach(() => {
  mocks.request.mockReset();
  mocks.setResource.mockReset();
  mocks.fetch.mockReset();
  vi.stubGlobal('fetch', mocks.fetch);
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function choose(label: string) {
  const input = screen.getByRole('combobox', { name: 'Namespace/name' });
  fireEvent.change(input, { target: { value: label } });
  fireEvent.click(screen.getByRole('option', { name: label }));
}

it('uses the resource chosen last, also when an earlier one is read later', async () => {
  const first = deferred<any>();
  const second = deferred<any>();
  const third = deferred<any>();
  mocks.request.mockImplementation((url: string) => {
    if (url === '/apis/apps/v1/deployments') {
      return Promise.resolve({
        items: [
          { metadata: { name: 'a', namespace: 'shop' } },
          { metadata: { name: 'b', namespace: 'shop' } },
          { metadata: { name: 'c', namespace: 'shop' } },
        ],
      });
    }
    if (url.endsWith('/deployments/a')) return first.promise;
    if (url.endsWith('/deployments/b')) return second.promise;
    if (url.endsWith('/deployments/c')) return third.promise;
    throw new Error(`unexpected ${url}`);
  });
  mocks.fetch.mockResolvedValue({ ok: true, text: async () => '' });
  renderInContext(<ChooseTestResource />);
  fireEvent.click(screen.getByRole('button', { name: 'From cluster' }));
  await waitFor(() => expect(mocks.request).toHaveBeenCalledWith('/apis/apps/v1/deployments'));

  choose('shop/a');
  choose('shop/b');
  await act(async () => second.resolve({ metadata: { name: 'b', namespace: 'shop' } }));
  await act(async () => first.resolve({ metadata: { name: 'a', namespace: 'shop' } }));
  expect(mocks.setResource.mock.calls.map(([object]) => object.metadata.name)).toEqual(['b']);

  // nor is the failure of an earlier read shown
  choose('shop/c');
  choose('shop/b');
  await act(async () => third.reject(new Error('gone')));
  expect(screen.queryByText(/Unable to read shop\/c/)).toBeNull();
  expect(mocks.setResource.mock.calls.map(([object]) => object.metadata.name)).toEqual(['b', 'b']);
});

it('offers the sample test resources of the index, without its last line break', async () => {
  mocks.fetch.mockImplementation(async (url: string) => ({
    ok: true,
    text: async () =>
      url.endsWith('index.yaml')
        ? 'deployment.yaml\npod.yaml\n'
        : '\n---\nkind: Deployment\n---\nkind: Pod\n',
  }));
  renderInContext(<ChooseTestResource />);
  await act(async () => {});

  fireEvent.mouseDown(screen.getByRole('combobox', { name: 'Choose Test Resource' }));
  expect(screen.getAllByRole('option').map(option => option.textContent)).toEqual([
    'deployment.yaml',
    'pod.yaml',
  ]);
  fireEvent.click(screen.getByRole('option', { name: 'pod.yaml' }));
  expect(mocks.setResource).toHaveBeenCalledWith({ kind: 'Pod' });
});

it('says when the sample test resources cannot be read', async () => {
  mocks.fetch.mockResolvedValue({ ok: false, status: 404, statusText: 'Not Found' });
  renderInContext(<ChooseTestResource />);

  expect(
    await screen.findByText(
      'Unable to read the test resources: vap-test-files.yaml answered 404 Not Found'
    )
  ).toBeTruthy();
});

it('says when the sample policies cannot be read', async () => {
  mocks.fetch.mockRejectedValue(new Error('offline'));
  renderInContext(<ChoosePolicyButton />);

  expect(await screen.findByText('Unable to read the sample policies: offline')).toBeTruthy();
  expect(mocks.fetch).toHaveBeenCalledWith('/plugin/validating-admission-policies.yaml');
});
