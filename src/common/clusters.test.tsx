import { renderHook, waitFor } from '@testing-library/react';
import { vi } from 'vitest';
import { useItemsInClusters } from './clusters';

const mocks = vi.hoisted(() => ({ clusters: ['cluster-a', 'cluster-b', 'cluster-c'] }));
vi.mock('../index', () => ({ useHLSelectedClusters: () => mocks.clusters }));

it('shows the items of every cluster, and what could not be read in each', async () => {
  const read = async (cluster: string) => {
    if (cluster === 'cluster-a') return [`${cluster}/web`];
    if (cluster === 'cluster-b') {
      return { items: [`${cluster}/shop`], errors: ['namespace secret: forbidden'] };
    }
    throw new Error('unreachable');
  };

  const { result } = renderHook(() => useItemsInClusters<string>(read));

  await waitFor(() => expect(result.current.loading).toBe(false));
  expect(result.current.items).toEqual(['cluster-a/web', 'cluster-b/shop']);
  expect(result.current.errors).toEqual([
    { cluster: 'cluster-b', message: 'namespace secret: forbidden' },
    { cluster: 'cluster-c', message: 'unreachable' },
  ]);
});
