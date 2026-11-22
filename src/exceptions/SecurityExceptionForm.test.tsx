import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { load } from 'js-yaml';
import { vi } from 'vitest';
import type {
  ClusterSecurityException,
  SecurityException,
} from '../softwarecomposition/SecurityException';
import { historyAnnotation } from './history';
import { SecurityExceptionForm } from './SecurityExceptionForm';

const mocks = vi.hoisted(() => ({
  post: vi.fn(),
  put: vi.fn(),
  enqueueSnackbar: vi.fn(),
  saveToFile: vi.fn(),
}));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ post: mocks.post, put: mocks.put }));
vi.mock('../common/filedialog', () => ({ saveToFile: mocks.saveToFile }));
vi.mock('notistack', () => ({ useSnackbar: () => ({ enqueueSnackbar: mocks.enqueueSnackbar }) }));
vi.mock('../common/currentUser', () => ({ useCurrentUser: () => undefined }));
// the change is recorded as made by bob
vi.mock('./history', async importOriginal => {
  const actual = await importOriginal<typeof import('./history')>();
  return {
    ...actual,
    recordChangeByCurrentUser: async (exception: any, existing?: any) =>
      actual.recordChange(exception, existing, 'bob'),
  };
});

beforeEach(() => {
  mocks.put.mockReset().mockResolvedValue({});
  mocks.post.mockReset().mockResolvedValue({});
  mocks.enqueueSnackbar.mockReset();
  mocks.saveToFile.mockReset().mockResolvedValue(null);
});
afterEach(cleanup);

it('keeps the accepted risk and the fields it does not show when an exception is edited', async () => {
  const existing: SecurityException = {
    apiVersion: 'kubescape.io/v1beta1',
    kind: 'SecurityException',
    metadata: { name: 'accept-web', namespace: 'shop' },
    spec: {
      match: { resources: [{ kind: 'Deployment', name: 'web' }] },
      vulnerabilities: [
        {
          vulnerability: { id: 'CVE-1', aliases: ['GHSA-1'] },
          status: 'affected',
          response: ['can_not_fix'],
          actionStatement: 'No fix upstream',
          expiresAt: '2027-01-01T00:00:00Z',
          expiredOnFix: true,
        },
      ],
    },
  };
  render(<SecurityExceptionForm existing={existing} onClose={() => {}} />);
  expect((screen.getByLabelText(/Action statement/) as HTMLInputElement).value).toBe(
    'No fix upstream'
  );
  // the expiry of the entry overrides that of the exception, so the form names it
  expect(screen.getByText(/this entry expires on its own/)).toBeTruthy();

  fireEvent.click(screen.getByRole('button', { name: 'Save' }));

  await waitFor(() => expect(mocks.put).toHaveBeenCalled());
  expect(mocks.put.mock.calls[0][1].spec.vulnerabilities).toEqual(existing.spec.vulnerabilities);
});

it('keeps what the form does not show of an entry only while it is the entry of that CVE', async () => {
  const entry = {
    vulnerability: { id: 'CVE-1', aliases: ['GHSA-1'] },
    status: 'affected' as const,
    response: ['can_not_fix' as const],
    actionStatement: 'No fix upstream',
    // the form shows no impact statement for an affected entry
    impactStatement: 'Only reachable from inside the cluster',
    expiresAt: '2027-01-01T00:00:00Z',
    subcomponents: [{ '@id': 'pkg:deb/openssl' }],
  };
  const existing: SecurityException = {
    apiVersion: 'kubescape.io/v1beta1',
    kind: 'SecurityException',
    metadata: { name: 'accept-web', namespace: 'shop' },
    spec: { match: {}, vulnerabilities: [entry] },
  };
  render(<SecurityExceptionForm existing={existing} onClose={() => {}} />);

  fireEvent.click(screen.getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(mocks.put).toHaveBeenCalledTimes(1));
  expect(mocks.put.mock.calls[0][1].spec.vulnerabilities).toEqual([entry]);

  // the row now stands for another CVE: the aliases, packages, expiry and impact statement
  // of the entry it was do not go with it
  fireEvent.change(screen.getByLabelText('CVE ID'), { target: { value: 'CVE-2' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(mocks.put).toHaveBeenCalledTimes(2));
  expect(mocks.put.mock.calls[1][1].spec.vulnerabilities).toEqual([
    {
      vulnerability: { id: 'CVE-2' },
      status: 'affected',
      response: ['can_not_fix'],
      actionStatement: 'No fix upstream',
    },
  ]);
});

it('drops the API group of a resource whose kind is changed', async () => {
  const existing: SecurityException = {
    apiVersion: 'kubescape.io/v1beta1',
    kind: 'SecurityException',
    metadata: { name: 'web', namespace: 'shop' },
    spec: {
      match: { resources: [{ apiGroup: 'apps', kind: 'Deployment', name: 'web' }] },
      posture: [{ controlID: 'C-0017', action: 'ignore' }],
    },
  };
  render(<SecurityExceptionForm existing={existing} onClose={() => {}} />);

  // CronJob is not a kind of the group apps, so the entry would match nothing with it
  fireEvent.mouseDown(screen.getByText('Deployment'));
  fireEvent.click(screen.getByRole('option', { name: 'CronJob' }));
  fireEvent.click(screen.getByRole('button', { name: 'Save' }));

  await waitFor(() => expect(mocks.put).toHaveBeenCalled());
  expect(mocks.put.mock.calls[0][1].spec.match.resources).toEqual([
    { kind: 'CronJob', name: 'web' },
  ]);
});

it('does not leave out a resource or a namespace label that is half filled', async () => {
  const existing: ClusterSecurityException = {
    apiVersion: 'kubescape.io/v1beta1',
    kind: 'ClusterSecurityException',
    metadata: { name: 'all-web' },
    spec: { match: {}, posture: [{ controlID: 'C-0017', action: 'ignore' }] },
  };
  render(<SecurityExceptionForm existing={existing} onClose={() => {}} />);

  // a name without a kind: left out, the exception would be one for every workload
  fireEvent.click(screen.getByRole('button', { name: 'Add resource' }));
  const resourceName = screen.getByPlaceholderText('any (matches all)');
  fireEvent.change(resourceName, { target: { value: 'web' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save' }));
  await waitFor(() =>
    expect(mocks.enqueueSnackbar).toHaveBeenLastCalledWith(
      'A kind is required for the resource "web"',
      { variant: 'error' }
    )
  );

  // a label value without a key: left out, the exception would be one for every namespace
  fireEvent.change(resourceName, { target: { value: '' } });
  fireEvent.click(screen.getByRole('button', { name: 'Add namespace label' }));
  fireEvent.change(screen.getByLabelText('Label value'), { target: { value: 'dev' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save' }));
  await waitFor(() =>
    expect(mocks.enqueueSnackbar).toHaveBeenLastCalledWith(
      'A key is required for the namespace label with the value "dev"',
      { variant: 'error' }
    )
  );
  expect(mocks.put).not.toHaveBeenCalled();
});

it('keeps the parts of the match and the expiry that the form does not edit', async () => {
  const existing: ClusterSecurityException = {
    apiVersion: 'kubescape.io/v1beta1',
    kind: 'ClusterSecurityException',
    metadata: { name: 'dev-only' },
    spec: {
      reason: 'old reason',
      expiresAt: '2027-01-01T13:45:00Z',
      match: {
        namespaceSelector: {
          matchLabels: { team: 'web' },
          matchExpressions: [{ key: 'env', operator: 'In', values: ['dev'] }],
        },
        objectSelector: { matchLabels: { tier: 'frontend' } },
        resources: [{ apiGroup: 'apps', kind: 'Deployment', name: 'web' }],
      },
      posture: [{ controlID: 'C-0017', action: 'ignore' }],
    },
  };
  render(<SecurityExceptionForm existing={existing} onClose={() => {}} />);
  // the form says what it keeps
  expect(screen.getByText(/only workloads labelled tier=frontend/)).toBeTruthy();
  expect(screen.getByText(/Only namespaces where env in \(dev\)/)).toBeTruthy();

  fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'new reason' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save' }));

  await waitFor(() => expect(mocks.put).toHaveBeenCalled());
  const { spec } = mocks.put.mock.calls[0][1];
  expect(spec.reason).toBe('new reason');
  expect(spec.match).toEqual(existing.spec.match);
  // an expiry whose date was not changed is kept to the second
  expect(spec.expiresAt).toBe('2027-01-01T13:45:00Z');
});

it('downloads what Save would send without the fields the cluster sets, also where Save is denied', async () => {
  // the user may not update exceptions in this cluster
  mocks.post.mockImplementation(async (url: string) =>
    url.includes('selfsubjectaccessreviews') ? { status: { allowed: false } } : {}
  );
  const existing = {
    apiVersion: 'kubescape.io/v1beta1',
    kind: 'SecurityException',
    metadata: {
      name: 'accept-web',
      namespace: 'shop',
      uid: 'abc',
      resourceVersion: '7',
      creationTimestamp: '2026-10-30T10:00:00Z',
      managedFields: [],
      annotations: { [historyAnnotation]: '[]' },
    },
    spec: {
      author: 'alice',
      match: { resources: [{ kind: 'Deployment', name: 'web' }] },
      posture: [{ controlID: 'C-0017', action: 'ignore' }],
    },
    status: {},
  } as unknown as SecurityException;
  render(<SecurityExceptionForm existing={existing} cluster="read-only" onClose={() => {}} />);

  await waitFor(() =>
    expect((screen.getByRole('button', { name: 'Save' }) as HTMLButtonElement).disabled).toBe(true)
  );
  fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'Moved to Git' } });
  fireEvent.click(screen.getByRole('button', { name: 'Download YAML' }));

  await waitFor(() => expect(mocks.saveToFile).toHaveBeenCalled());
  const [content, fileName] = mocks.saveToFile.mock.calls[0];
  expect(fileName).toBe('accept-web.yaml');
  expect(load(content)).toEqual({
    apiVersion: 'kubescape.io/v1beta1',
    kind: 'SecurityException',
    metadata: { name: 'accept-web', namespace: 'shop' },
    spec: {
      author: 'alice',
      reason: 'Moved to Git',
      match: { resources: [{ kind: 'Deployment', name: 'web' }] },
      posture: [{ controlID: 'C-0017', action: 'ignore' }],
    },
  });
  expect(mocks.put).not.toHaveBeenCalled();
});

it('saves an exception in the cluster it was read from', async () => {
  const existing: ClusterSecurityException = {
    apiVersion: 'kubescape.io/v1beta1',
    kind: 'ClusterSecurityException',
    metadata: { name: 'shared' },
    spec: { posture: [{ controlID: 'C-0017', action: 'ignore' }] },
  };
  render(<SecurityExceptionForm existing={existing} cluster="tst" onClose={() => {}} />);

  fireEvent.click(screen.getByRole('button', { name: 'Save' }));

  await waitFor(() => expect(mocks.put).toHaveBeenCalled());
  expect(mocks.put.mock.calls[0][0]).toBe(
    '/apis/kubescape.io/v1beta1/clustersecurityexceptions/shared'
  );
  expect(mocks.put.mock.calls[0][3]).toEqual({ cluster: 'tst' });
});
