import { vi } from 'vitest';
import { GeneratedNetworkPolicy } from '../softwarecomposition/GeneratedNetworkPolicy';
import { applyNetworkPolicy, getExistingNetworkPolicy, toNetworkPolicy } from './apply';

const api = vi.hoisted(() => ({ request: vi.fn(), post: vi.fn(), put: vi.fn() }));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => api);

const generated = {
  metadata: {
    name: 'deployment-web',
    namespace: 'shop',
    cluster: 'cluster-a',
    creationTimestamp: '2026-10-01T00:00:00Z',
    resourceVersion: '7',
    labels: { 'kubescape.io/workload-name': 'web' },
    annotations: {},
  },
  spec: {
    apiVersion: 'networking.k8s.io/v1',
    kind: 'NetworkPolicy',
    metadata: {
      name: 'web',
      namespace: 'shop',
      annotations: { 'generated-by': 'kubescape' },
    },
    spec: { podSelector: { matchLabels: { app: 'web' } }, policyTypes: ['Ingress'] },
  },
  policyRef: [],
} as unknown as GeneratedNetworkPolicy;

const policyPath = '/apis/networking.k8s.io/v1/namespaces/shop/networkpolicies';

beforeEach(() => {
  api.request.mockReset();
  api.post.mockReset();
  api.put.mockReset();
});

it('turns the generated policy into a NetworkPolicy without storage metadata', () => {
  expect(toNetworkPolicy(generated)).toEqual({
    apiVersion: 'networking.k8s.io/v1',
    kind: 'NetworkPolicy',
    metadata: { name: 'web', namespace: 'shop', annotations: { 'generated-by': 'kubescape' } },
    spec: generated.spec.spec,
  });
});

it('creates the policy when none with its name exists', async () => {
  api.request.mockRejectedValue({ status: 404 });
  const policy = toNetworkPolicy(generated);

  const existing = await getExistingNetworkPolicy(policy);
  await applyNetworkPolicy(policy, existing);

  expect(api.request).toHaveBeenCalledWith(`${policyPath}/web`);
  expect(api.post).toHaveBeenCalledWith(policyPath, policy);
  expect(api.put).not.toHaveBeenCalled();
});

it('replaces an existing policy using its resource version', async () => {
  const policy = toNetworkPolicy(generated);
  api.request.mockResolvedValue({
    ...policy,
    metadata: { ...policy.metadata, resourceVersion: '42' },
  });

  await applyNetworkPolicy(policy, await getExistingNetworkPolicy(policy));

  expect(api.put).toHaveBeenCalledWith(`${policyPath}/web`, {
    ...policy,
    metadata: { ...policy.metadata, resourceVersion: '42' },
  });
  expect(api.post).not.toHaveBeenCalled();
});

it('does not hide other errors while looking for an existing policy', async () => {
  api.request.mockRejectedValue({ status: 403, message: 'forbidden' });
  await expect(getExistingNetworkPolicy(toNetworkPolicy(generated))).rejects.toEqual({
    status: 403,
    message: 'forbidden',
  });
});

it('leaves out the labels of a run, so the policy still matches after the next one', () => {
  const withRuns = {
    ...generated,
    spec: {
      ...generated.spec,
      spec: {
        podSelector: { matchLabels: { app: 'web' } },
        ingress: [
          {
            from: [
              { podSelector: { matchLabels: { app: 'backup', 'job-name': 'backup-29001' } } },
              { podSelector: { matchLabels: { app: 'backup', 'job-name': 'backup-29002' } } },
              {
                namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'shop' } },
                podSelector: { matchLabels: { app: 'api', 'pod-template-hash': '7d9f' } },
              },
              // without the label it would select every pod, so it is kept
              { podSelector: { matchLabels: { 'job-name': 'only-run' } } },
            ],
          },
        ],
      },
    },
  } as unknown as GeneratedNetworkPolicy;

  expect(toNetworkPolicy(withRuns).spec.ingress![0].from).toEqual([
    { podSelector: { matchLabels: { app: 'backup' } } },
    {
      namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'shop' } },
      podSelector: { matchLabels: { app: 'api' } },
    },
    { podSelector: { matchLabels: { 'job-name': 'only-run' } } },
  ]);
});

it('leaves out the name and index of the pods of a StatefulSet', () => {
  const withReplicas = {
    ...generated,
    spec: {
      ...generated.spec,
      spec: {
        podSelector: { matchLabels: { app: 'web' } },
        egress: [
          {
            to: [0, 1].map(index => ({
              podSelector: {
                matchLabels: {
                  app: 'db',
                  'statefulset.kubernetes.io/pod-name': `db-${index}`,
                  'apps.kubernetes.io/pod-index': `${index}`,
                },
              },
            })),
          },
        ],
      },
    },
  } as unknown as GeneratedNetworkPolicy;

  expect(toNetworkPolicy(withReplicas).spec.egress![0].to).toEqual([
    { podSelector: { matchLabels: { app: 'db' } } },
  ]);
});
