import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  post: vi.fn(),
  put: vi.fn(),
  request: vi.fn(),
  // the namespace of the pods of Kubescape, which the editor looks up
  kubescapeNamespace: undefined as string | undefined | Promise<string | undefined>,
  rulesObject: undefined as any,
  segments: [] as string[],
  checks: [] as any[],
}));

vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({
  post: mocks.post,
  put: mocks.put,
  request: mocks.request,
}));
vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', () => ({
  SectionBox: ({ children }: { children: ReactNode }) => <section>{children}</section>,
}));
vi.mock('@kinvolk/headlamp-plugin/lib/Utils', () => ({ getCluster: () => 'cluster-a' }));
vi.mock('@monaco-editor/react', () => ({ default: () => null }));
vi.mock('../common/url', () => ({ getURLSegments: () => mocks.segments }));
vi.mock('../common/clusterContext', () => ({ getAllowedNamespaces: () => [] }));
vi.mock('../model', () => ({ customObjectLabel: 'kubescape.io/custom-object' }));
vi.mock('../common/permissions', () => ({
  PermittedIconButton: ({ check, title, onClick, children }: any) => {
    mocks.checks.push(check);
    return (
      <button aria-label={title} onClick={onClick}>
        {children}
      </button>
    );
  },
}));
vi.mock('../wasm/initWasmModule', () => ({ useWasm: () => ({ ready: false }) }));
vi.mock('./PlaygroundDialog', () => ({ PlaygroundDialog: () => null }));

import { RuleEdit, RuleNew } from './RuleEditor';

const rule = {
  name: 'Unexpected shell',
  id: 'R9001',
  enabled: true,
  description: '',
  expressions: {
    message: "'shell'",
    uniqueId: 'event.comm',
    ruleExpression: [{ eventType: 'exec', expression: "event.comm == 'sh'" }],
  },
  profileDependency: 2,
  severity: 5,
  supportPolicy: false,
  isTriggerAlert: true,
  mitreTactic: 'TA0002',
  mitreTechnique: 'T1059',
  tags: [],
};

beforeEach(() => {
  mocks.post.mockReset();
  mocks.put.mockReset();
  mocks.request.mockReset();
  mocks.request.mockImplementation(async (url: string) => {
    if (url.startsWith('/api/v1/pods')) {
      const namespace = await mocks.kubescapeNamespace;
      return { items: namespace ? [{ metadata: { namespace } }] : [] };
    }
    return mocks.rulesObject;
  });
  mocks.kubescapeNamespace = 'security';
  mocks.rulesObject = undefined;
  // the namespace that was found is kept for the session
  window.sessionStorage.clear();
  mocks.segments = [];
  mocks.checks = [];
});
afterEach(cleanup);

const lookedUpNamespace = () =>
  waitFor(() =>
    expect(mocks.request).toHaveBeenCalledWith(expect.stringMatching(/^\/api\/v1\/pods\?/), {
      cluster: 'cluster-a',
    })
  );

const save = () => fireEvent.click(screen.getByRole('button', { name: 'Save to cluster' }));

// the field of this label, required (with an asterisk) or not
const field = (label: string, index = 0) =>
  screen.getAllByLabelText(new RegExp(String.raw`^${label}(\s*\*)?$`))[index] as HTMLInputElement;

function fill(label: string, value: string, index = 0) {
  fireEvent.change(field(label, index), { target: { value } });
}

it('creates a new Rules object in the namespace of Kubescape, then replaces what it wrote', async () => {
  mocks.post.mockImplementation(async (_url: string, body: any) => ({
    ...body,
    metadata: { ...body.metadata, uid: 'uid-1', resourceVersion: '7' },
  }));
  mocks.put.mockImplementation(async (_url: string, body: any) => ({
    ...body,
    metadata: { ...body.metadata, resourceVersion: '8' },
  }));
  render(<RuleNew />);

  // the namespace of the chart until the one of the cluster is found
  await waitFor(() => expect(field('Namespace').value).toBe('security'));
  await lookedUpNamespace();
  expect(mocks.checks.at(-1)).toMatchObject({ verb: 'create', namespace: 'security' });

  // a rule needs its name, id, tactic and technique
  save();
  expect(await screen.findByText('Name is required')).toBeTruthy();
  fill('Name', 'my-rules');
  fill('Name', 'Unexpected shell', 1);
  fill('ID', 'R9001');
  fill('Tactic', 'TA0002');
  fill('Technique', 'T1059');
  save();

  await waitFor(() => expect(mocks.post).toHaveBeenCalledTimes(1));
  const [url, body] = mocks.post.mock.calls[0];
  expect(url).toBe('/apis/kubescape.io/v1/namespaces/security/rules');
  expect(body).toMatchObject({
    apiVersion: 'kubescape.io/v1',
    kind: 'Rules',
    metadata: { name: 'my-rules', namespace: 'security' },
    spec: {
      rules: [
        {
          name: 'Unexpected shell',
          id: 'R9001',
          mitreTactic: 'TA0002',
          mitreTechnique: 'T1059',
        },
      ],
    },
  });
  expect(body.metadata.resourceVersion).toBeUndefined();
  expect(await screen.findByText('Saved successfully')).toBeTruthy();

  // the next save replaces the object it created, with the version it got back
  fill('Description', 'Shells in containers');
  save();
  await waitFor(() => expect(mocks.put).toHaveBeenCalledTimes(1));
  const [putUrl, putBody] = mocks.put.mock.calls[0];
  expect(putUrl).toBe('/apis/kubescape.io/v1/namespaces/security/rules/my-rules');
  expect(putBody.metadata).toEqual({
    name: 'my-rules',
    namespace: 'security',
    uid: 'uid-1',
    resourceVersion: '7',
  });
  expect(putBody.spec.rules[0].description).toBe('Shells in containers');
  expect(mocks.post).toHaveBeenCalledTimes(1);

  save();
  await waitFor(() => expect(mocks.put).toHaveBeenCalledTimes(2));
  expect(mocks.put.mock.calls[1][1].metadata.resourceVersion).toBe('8');
});

it('keeps the namespace the user chose for a new Rules object', async () => {
  let found: (namespace: string) => void = () => {};
  mocks.kubescapeNamespace = new Promise(resolve => (found = resolve));
  render(<RuleNew />);

  fill('Namespace', 'team');
  await lookedUpNamespace();
  // the lookup answers after the user chose
  await act(async () => {
    found('security');
    await new Promise(resolve => setTimeout(resolve, 10));
  });
  expect(field('Namespace').value).toBe('team');
});

it('replaces an edited Rules object with its labels, annotations and resourceVersion', async () => {
  mocks.segments = ['custom-rules', 'team'];
  const metadata = {
    name: 'custom-rules',
    namespace: 'team',
    resourceVersion: '3',
    labels: { 'app.kubernetes.io/managed-by': 'argocd' },
    annotations: { note: 'kept' },
  };
  mocks.rulesObject = { metadata, spec: { rules: [rule] } };
  mocks.put.mockImplementation(async (_url: string, body: any) => ({
    ...body,
    metadata: { ...body.metadata, resourceVersion: '4' },
  }));
  render(<RuleEdit />);

  await screen.findByText('Edit Rule');
  expect(mocks.request).toHaveBeenCalledWith(
    '/apis/kubescape.io/v1/namespaces/team/rules/custom-rules'
  );
  expect(mocks.checks.at(-1)).toMatchObject({
    verb: 'update',
    namespace: 'team',
    name: 'custom-rules',
  });
  // its name and namespace cannot change
  expect(field('Name').value).toBe('custom-rules');
  expect(field('Name').disabled).toBe(true);
  expect(field('Namespace').disabled).toBe(true);
  save();

  await waitFor(() => expect(mocks.put).toHaveBeenCalledTimes(1));
  const [url, body] = mocks.put.mock.calls[0];
  expect(url).toBe('/apis/kubescape.io/v1/namespaces/team/rules/custom-rules');
  expect(body.metadata).toEqual(metadata);
  expect(body.spec.rules).toEqual([rule]);
  expect(mocks.post).not.toHaveBeenCalled();

  save();
  await waitFor(() => expect(mocks.put).toHaveBeenCalledTimes(2));
  expect(mocks.put.mock.calls[1][1].metadata).toEqual({ ...metadata, resourceVersion: '4' });
});

it('shows why a save failed', async () => {
  mocks.segments = ['custom-rules', 'team'];
  mocks.rulesObject = {
    metadata: { name: 'custom-rules', namespace: 'team', resourceVersion: '3' },
    spec: { rules: [rule] },
  };
  mocks.put.mockRejectedValue(new Error('the object has been modified'));
  render(<RuleEdit />);

  await screen.findByText('Edit Rule');
  save();
  expect(await screen.findByText('the object has been modified')).toBeTruthy();
});

it.each([
  ['in the namespace of Kubescape', { name: 'default-rules', namespace: 'security' }, true],
  [
    'with the labels of the chart',
    {
      name: 'default-rules',
      namespace: 'elsewhere',
      labels: { 'app.kubernetes.io/managed-by': 'Helm', 'app.kubernetes.io/part-of': 'kubescape' },
    },
    true,
  ],
  ['of the user elsewhere', { name: 'default-rules', namespace: 'team' }, false],
  ['of another name', { name: 'my-rules', namespace: 'security' }, false],
])('locks the default-rules of the chart: a Rules object %s', async (_, metadata, locked) => {
  mocks.segments = [metadata.name, metadata.namespace];
  mocks.rulesObject = { metadata, spec: { rules: [rule] } };
  render(<RuleEdit />);

  await screen.findByText('Edit Rule');
  await lookedUpNamespace();
  if (locked) {
    expect(await screen.findByText(/is system-managed and cannot be edited here/)).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Save to cluster' })).toBeNull();
  } else {
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(screen.queryByText(/is system-managed/)).toBeNull();
    expect(screen.getByRole('button', { name: 'Save to cluster' })).toBeTruthy();
  }
});
