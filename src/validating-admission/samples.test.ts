import { act, renderHook, waitFor } from '@testing-library/react';
import { vi } from 'vitest';
import { useSampleParams } from './samples';

const mocks = vi.hoisted(() => ({ fetch: vi.fn() }));
vi.mock('../common/PluginHelper', () => ({ getKubescapePluginUrl: async () => '/plugin' }));

beforeEach(() => {
  mocks.fetch.mockReset();
  vi.stubGlobal('fetch', mocks.fetch);
});
afterEach(() => vi.unstubAllGlobals());

const withParams = {
  spec: { paramKind: { apiVersion: 'kubescape.io/v1', kind: 'ControlConfiguration' } },
};

it('reads the sample parameters of a policy that reads parameters', async () => {
  mocks.fetch.mockResolvedValue({ ok: true, text: async () => 'settings:\n  a: 1\n' });
  const { result } = renderHook(() => useSampleParams(withParams));

  await waitFor(() => expect(result.current.params).toEqual({ settings: { a: 1 } }));
  expect(mocks.fetch).toHaveBeenCalledWith('/plugin/basic-control-configuration.yaml');
  expect(result.current.error).toBe('');
});

it('does not give the parameters of a policy chosen before', async () => {
  let answer!: (response: unknown) => void;
  mocks.fetch.mockReturnValue(new Promise(resolve => (answer = resolve)));
  const { result, rerender } = renderHook(({ policy }) => useSampleParams(policy), {
    initialProps: { policy: withParams as typeof withParams | null },
  });
  await waitFor(() => expect(mocks.fetch).toHaveBeenCalled());

  // a policy without parameters is chosen before the answer arrives
  rerender({ policy: { spec: {} } as any });
  await act(async () => answer({ ok: true, text: async () => 'settings: {}\n' }));

  expect(result.current.params).toBeNull();
});

it('says when the sample parameters cannot be read', async () => {
  mocks.fetch.mockResolvedValue({ ok: false, status: 500, statusText: 'Server Error' });
  const { result } = renderHook(() => useSampleParams(withParams));

  await waitFor(() =>
    expect(result.current.error).toBe(
      'Unable to read the sample parameters: basic-control-configuration.yaml answered 500 Server Error'
    )
  );
  expect(result.current.params).toBeNull();
});
