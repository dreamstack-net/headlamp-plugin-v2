import { renderHook, waitFor } from '@testing-library/react';
import { vi } from 'vitest';
import { getCurrentUser, useCurrentUser } from './currentUser';

const post = vi.hoisted(() => vi.fn());
// the cluster of the address
const address = vi.hoisted(() => ({ cluster: 'current' }));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ post }));
vi.mock('@kinvolk/headlamp-plugin/lib/Utils', () => ({ getCluster: () => address.cluster }));

const review = (username: string) => ({ status: { userInfo: { username } } });

// a block body: a function that beforeEach returns is called after the test, as a cleanup
beforeEach(() => {
  post.mockReset();
  address.cluster = 'current';
});

it('asks the API server who the user is, once for the lookups of the moment', async () => {
  post.mockResolvedValue(review('alice@example.com'));

  const lookups = [getCurrentUser('cluster-a'), getCurrentUser('cluster-a')];
  expect(await Promise.all(lookups)).toEqual(['alice@example.com', 'alice@example.com']);

  expect(post).toHaveBeenCalledTimes(1);
  expect(post).toHaveBeenCalledWith(
    '/apis/authentication.k8s.io/v1/selfsubjectreviews',
    { apiVersion: 'authentication.k8s.io/v1', kind: 'SelfSubjectReview' },
    false,
    { cluster: 'cluster-a' }
  );
});

it('asks again later, as another user may have logged in meanwhile', async () => {
  // Headlamp does not reload the plugin when the user logs out and in with another token
  post.mockResolvedValue(review('viewer'));
  expect(await getCurrentUser('cluster-d')).toBe('viewer');

  post.mockResolvedValue(review('admin'));
  expect(await getCurrentUser('cluster-d')).toBe('admin');
  expect(post).toHaveBeenCalledTimes(2);
});

it('uses the beta API of Kubernetes 1.27', async () => {
  post
    .mockRejectedValueOnce({ status: 404 })
    .mockResolvedValueOnce(review('system:serviceaccount:headlamp:headlamp'));

  expect(await getCurrentUser('cluster-b')).toBe('system:serviceaccount:headlamp:headlamp');
  expect(post.mock.calls[1][0]).toBe('/apis/authentication.k8s.io/v1beta1/selfsubjectreviews');
});

it('asks again later when the cluster does not tell', async () => {
  post.mockRejectedValue({ status: 403 });
  expect(await getCurrentUser('cluster-c')).toBeUndefined();

  post.mockReset().mockResolvedValue(review('bob'));
  expect(await getCurrentUser('cluster-c')).toBe('bob');
});

it('uses the current cluster by default', async () => {
  post.mockResolvedValue(review('dave'));
  expect(await getCurrentUser()).toBe('dave');
  expect(post.mock.calls[0][3]).toEqual({ cluster: 'current' });
});

it('follows the cluster of the address, without the user of the cluster before', async () => {
  address.cluster = 'address-a';
  post.mockResolvedValue(review('erin'));
  const { result, rerender } = renderHook(() => useCurrentUser());
  await waitFor(() => expect(result.current).toBe('erin'));

  // Headlamp keeps a page when the selected clusters change, and with them the first cluster
  address.cluster = 'address-b';
  let answer: (answered: unknown) => void = () => {};
  post.mockReset().mockReturnValue(new Promise(resolve => (answer = resolve)));
  rerender();
  expect(result.current).toBeUndefined();

  answer(review('frank'));
  await waitFor(() => expect(result.current).toBe('frank'));
  expect(post.mock.calls[0][3]).toEqual({ cluster: 'address-b' });
});
