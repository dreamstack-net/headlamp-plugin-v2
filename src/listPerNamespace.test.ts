import { vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  request: vi.fn(),
  allowedNamespaces: [] as string[],
}));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ request: mocks.request }));

import { listPerNamespace } from './query';

const policies = {
  pluralName: 'generatednetworkpolicies',
  apiEndpoint: {
    apiInfo: [{ group: 'spdx.softwarecomposition.kubescape.io', version: 'v1beta1' }],
  },
} as any;
const api = '/apis/spdx.softwarecomposition.kubescape.io/v1beta1';
const policy = (namespace: string, name: string) => ({ metadata: { namespace, name } });

beforeEach(() => {
  mocks.request.mockReset();
  mocks.allowedNamespaces = [];
});

it('reads each namespace on its own and hands over the items as they arrive', async () => {
  mocks.request.mockImplementation(async (url: string) => {
    if (url === '/api/v1/namespaces') {
      return { items: ['shop', 'empty', 'secret'].map(name => ({ metadata: { name } })) };
    }
    if (url === `${api}/namespaces/shop/generatednetworkpolicies`) {
      return { items: [policy('shop', 'deployment-web')] };
    }
    if (url.includes('/namespaces/secret/')) throw new Error('forbidden');
    return { items: [] };
  });
  const handed: any[][] = [];

  const errors = await listPerNamespace(policies, 'cluster-a', mocks.allowedNamespaces, items =>
    handed.push(items)
  );

  expect(handed.flat()).toEqual([
    { metadata: { namespace: 'shop', name: 'deployment-web', cluster: 'cluster-a' } },
  ]);
  expect(errors).toEqual(['namespace secret: forbidden']);
  expect(mocks.request).toHaveBeenCalledWith(`${api}/namespaces/shop/generatednetworkpolicies`, {
    cluster: 'cluster-a',
  });
});

it('reads only the allowed namespaces when there are', async () => {
  mocks.allowedNamespaces = ['shop'];
  mocks.request.mockResolvedValue({ items: [policy('shop', 'deployment-web')] });

  await listPerNamespace(policies, 'cluster-a', mocks.allowedNamespaces, () => {});

  expect(mocks.request.mock.calls.map(([url]) => url)).toEqual([
    `${api}/namespaces/shop/generatednetworkpolicies`,
  ]);
});

it('lists the cluster at once without permission to list the namespaces', async () => {
  mocks.request.mockImplementation(async (url: string) => {
    if (url === '/api/v1/namespaces') throw Object.assign(new Error('forbidden'), { status: 403 });
    return { items: [policy('shop', 'deployment-web')] };
  });
  const handed: any[] = [];

  expect(
    await listPerNamespace(policies, 'cluster-a', mocks.allowedNamespaces, items =>
      handed.push(...items)
    )
  ).toEqual([]);
  expect(handed).toHaveLength(1);
  expect(mocks.request).toHaveBeenLastCalledWith(`${api}/generatednetworkpolicies`, {
    cluster: 'cluster-a',
  });
});

it('fails when no namespace could be read, and stops reading when told to', async () => {
  mocks.allowedNamespaces = ['a', 'b'];
  mocks.request.mockRejectedValue(new Error('storage unavailable'));
  await expect(
    listPerNamespace(policies, 'cluster-a', mocks.allowedNamespaces, () => {})
  ).rejects.toThrow('storage unavailable');

  mocks.request.mockReset().mockResolvedValue({ items: [] });
  await listPerNamespace(policies, 'cluster-a', mocks.allowedNamespaces, () => {}, {
    current: false,
  });
  expect(mocks.request).not.toHaveBeenCalled();
});
