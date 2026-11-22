import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { load } from 'js-yaml';
import { vi } from 'vitest';
import { GuidedClusterComplianceExceptionForm } from './GuidedClusterComplianceExceptionForm';
import { GuidedComplianceExceptionForm } from './GuidedComplianceExceptionForm';

const mocks = vi.hoisted(() => ({ post: vi.fn(), enqueueSnackbar: vi.fn(), saveToFile: vi.fn() }));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ post: mocks.post }));
vi.mock('notistack', () => ({ useSnackbar: () => ({ enqueueSnackbar: mocks.enqueueSnackbar }) }));
vi.mock('../common/SetupCheck', () => ({ SetupCheck: () => null }));
vi.mock('../common/filedialog', () => ({ saveToFile: mocks.saveToFile }));
// the exception is created by bob
vi.mock('./history', async importOriginal => {
  const actual = await importOriginal<typeof import('./history')>();
  return {
    ...actual,
    recordChangeByCurrentUser: async (exception: any, existing?: any) =>
      actual.recordChange(exception, existing, 'bob'),
  };
});

beforeEach(() => {
  mocks.post.mockReset().mockResolvedValue({});
  mocks.enqueueSnackbar.mockReset();
  mocks.saveToFile.mockReset().mockResolvedValue(null);
});
afterEach(cleanup);

it('downloads the exception of a control for a namespace as Create would send it', async () => {
  render(
    <GuidedComplianceExceptionForm
      controlID="C-0017"
      workloadKind="Deployment"
      workloadName="web"
      workloadNamespace="shop"
      cluster="prd"
      onClose={() => {}}
    />
  );
  fireEvent.click(screen.getByLabelText(/All workloads in namespace/));
  fireEvent.click(screen.getByRole('button', { name: 'Download YAML' }));

  await waitFor(() => expect(mocks.saveToFile).toHaveBeenCalled());
  const [content, fileName] = mocks.saveToFile.mock.calls[0];
  expect(fileName).toBe('c-0017-web.yaml');
  expect(load(content)).toEqual({
    apiVersion: 'kubescape.io/v1beta1',
    kind: 'SecurityException',
    metadata: { name: 'c-0017-web', namespace: 'shop' },
    spec: { author: 'bob', match: {}, posture: [{ controlID: 'C-0017', action: 'ignore' }] },
  });

  // Create sends the same exception, with the history of its creation
  fireEvent.click(screen.getByRole('button', { name: 'Create' }));
  await waitFor(() =>
    expect(mocks.post).toHaveBeenCalledWith(
      '/apis/kubescape.io/v1beta1/namespaces/shop/securityexceptions',
      expect.anything(),
      true,
      { cluster: 'prd' }
    )
  );
  const created = mocks.post.mock.calls.find(([path]) => path.endsWith('/securityexceptions'))![1];
  expect(created.spec).toEqual((load(content) as any).spec);
  expect(Object.keys(created.metadata.annotations)).toEqual(['headlamp.kubescape.io/history']);
});

it('excepts a resource without a namespace with a cluster-wide exception that names it', async () => {
  render(
    <GuidedComplianceExceptionForm
      controlID="C-0035"
      workloadKind="ClusterRole"
      workloadName="admin"
      workloadNamespace=""
      onClose={() => {}}
    />
  );
  // there is no namespace to except
  expect(screen.queryByLabelText(/All workloads in namespace/)).toBeNull();
  expect(screen.getByLabelText(/This resource only/)).toBeTruthy();

  fireEvent.click(screen.getByRole('button', { name: 'Create' }));

  await waitFor(() => expect(mocks.post).toHaveBeenCalled());
  const [path, created] = mocks.post.mock.calls.find(([url]) =>
    url.includes('securityexceptions')
  )!;
  expect(path).toBe('/apis/kubescape.io/v1beta1/clustersecurityexceptions');
  expect(created.kind).toBe('ClusterSecurityException');
  expect(created.metadata.namespace).toBeUndefined();
  expect(created.spec.match).toEqual({ resources: [{ kind: 'ClusterRole', name: 'admin' }] });
});

it('downloads the cluster-wide exception of a control', async () => {
  render(<GuidedClusterComplianceExceptionForm controlID="C-0017" onClose={() => {}} />);
  fireEvent.click(screen.getByRole('button', { name: 'Download YAML' }));

  await waitFor(() => expect(mocks.saveToFile).toHaveBeenCalled());
  const [content, fileName] = mocks.saveToFile.mock.calls[0];
  expect(fileName).toBe('c-0017-cluster.yaml');
  expect(load(content)).toEqual({
    apiVersion: 'kubescape.io/v1beta1',
    kind: 'ClusterSecurityException',
    metadata: { name: 'c-0017-cluster' },
    spec: { author: 'bob', match: {}, posture: [{ controlID: 'C-0017', action: 'ignore' }] },
  });
  expect(mocks.post.mock.calls.filter(([path]) => path.includes('securityexceptions'))).toEqual([]);
});
