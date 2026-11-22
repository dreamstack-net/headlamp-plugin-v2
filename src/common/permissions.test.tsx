import { render, renderHook, screen, waitFor } from '@testing-library/react';
import { vi } from 'vitest';
import { AccessCheck, canI, deniedMessage, Permitted, useCanI } from './permissions';

const post = vi.hoisted(() => vi.fn());
// the cluster of the address
const address = vi.hoisted(() => ({ cluster: 'current' }));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ post }));
vi.mock('@kinvolk/headlamp-plugin/lib/Utils', () => ({ getCluster: () => address.cluster }));

const createCommand: AccessCheck = {
  group: 'kubescape.io',
  resource: 'operatorcommands',
  verb: 'create',
  namespace: 'kubescape',
};

// a function returned here would be called as a cleanup after each test
beforeEach(() => {
  post.mockReset();
  address.cluster = 'current';
});

it('asks the API server once per check and cluster', async () => {
  post.mockResolvedValue({ status: { allowed: true } });

  expect(await canI(createCommand, 'cluster-a')).toBe(true);
  expect(await canI(createCommand, 'cluster-a')).toBe(true);

  expect(post).toHaveBeenCalledTimes(1);
  expect(post).toHaveBeenCalledWith(
    '/apis/authorization.k8s.io/v1/selfsubjectaccessreviews',
    {
      apiVersion: 'authorization.k8s.io/v1',
      kind: 'SelfSubjectAccessReview',
      spec: { resourceAttributes: createCommand },
    },
    false,
    { cluster: 'cluster-a' }
  );
});

it('asks again after ten seconds, as another user may have logged in meanwhile', async () => {
  // Headlamp does not reload the plugin when the user logs out and in with another token
  vi.useFakeTimers({ toFake: ['Date'] });
  try {
    post.mockResolvedValue({ status: { allowed: false } });
    expect(await canI(createCommand, 'cluster-relogin')).toBe(false);

    post.mockResolvedValue({ status: { allowed: true } });
    vi.advanceTimersByTime(9_000);
    expect(await canI(createCommand, 'cluster-relogin')).toBe(false);
    vi.advanceTimersByTime(1_000);
    expect(await canI(createCommand, 'cluster-relogin')).toBe(true);
    expect(post).toHaveBeenCalledTimes(2);
  } finally {
    vi.useRealTimers();
  }
});

it('keeps a check that is asked, also when it takes long', async () => {
  vi.useFakeTimers({ toFake: ['Date'] });
  try {
    let answer: (review: unknown) => void = () => {};
    post.mockReturnValueOnce(new Promise(resolve => (answer = resolve)));
    const first = canI(createCommand, 'cluster-slow');
    vi.advanceTimersByTime(60_000);
    const second = canI(createCommand, 'cluster-slow');

    answer({ status: { allowed: true } });
    expect(await Promise.all([first, second])).toEqual([true, true]);
    expect(post).toHaveBeenCalledTimes(1);
  } finally {
    vi.useRealTimers();
  }
});

it('does not know the answer when the cluster does not tell, and asks again later', async () => {
  post.mockRejectedValueOnce(new Error('forbidden'));
  expect(await canI(createCommand, 'cluster-b')).toBeUndefined();

  post.mockResolvedValueOnce({ status: { allowed: false } });
  expect(await canI(createCommand, 'cluster-b')).toBe(false);
});

it('explains the missing permission', () => {
  expect(deniedMessage(createCommand)).toBe(
    'You are not allowed to create operatorcommands in namespace kubescape.'
  );
  expect(
    deniedMessage({
      group: '',
      resource: 'services',
      subresource: 'proxy',
      verb: 'create',
      namespace: 'monitoring',
      name: 'alertmanager',
    })
  ).toBe('You are not allowed to create services/proxy alertmanager in namespace monitoring.');
});

it('disables an action the user may not do, and leaves unknown ones enabled', async () => {
  post.mockResolvedValueOnce({ status: { allowed: false } });
  render(
    <Permitted check={{ ...createCommand, namespace: 'denied' }}>
      {allowed => <button disabled={!allowed}>Scan</button>}
    </Permitted>
  );
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Scan' })).toHaveProperty('disabled', true)
  );
  expect(screen.getByLabelText(/not allowed to create operatorcommands/)).toBeTruthy();

  post.mockRejectedValueOnce(new Error('no SelfSubjectAccessReview'));
  render(
    <Permitted check={{ ...createCommand, namespace: 'unknown' }}>
      {allowed => <button disabled={!allowed}>Delete</button>}
    </Permitted>
  );
  await waitFor(() => expect(post).toHaveBeenCalledTimes(2));
  expect(screen.getByRole('button', { name: 'Delete' })).toHaveProperty('disabled', false);
});

it('names the first missing permission of an action that needs several', async () => {
  const listCommands = { ...createCommand, verb: 'list', namespace: 'several' };
  post.mockImplementation(async (_url: string, review: any) => ({
    status: { allowed: review.spec.resourceAttributes.verb !== 'list' },
  }));
  render(
    <Permitted check={[{ ...createCommand, namespace: 'several' }, listCommands]}>
      {allowed => <button disabled={!allowed}>Install</button>}
    </Permitted>
  );
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Install' })).toHaveProperty('disabled', true)
  );
  expect(
    screen.getByLabelText('You are not allowed to list operatorcommands in namespace several.')
  ).toBeTruthy();
  expect(post).toHaveBeenCalledTimes(2);
});

it('does not keep the answer of the check before while the new one is asked', async () => {
  post.mockResolvedValueOnce({ status: { allowed: false } });
  const { result, rerender } = renderHook(
    ({ namespace }) => useCanI({ ...createCommand, namespace }),
    {
      initialProps: { namespace: 'switch-a' },
    }
  );
  await waitFor(() => expect(result.current).toBe(false));

  // the next answer is pending
  let answer: (review: unknown) => void = () => {};
  post.mockReturnValueOnce(new Promise(resolve => (answer = resolve)));
  rerender({ namespace: 'switch-b' });
  expect(result.current).toBeUndefined();

  answer({ status: { allowed: true } });
  await waitFor(() => expect(result.current).toBe(true));
});

it('asks the cluster of the address again when that changes while the page stays', async () => {
  address.cluster = 'address-a';
  post.mockResolvedValueOnce({ status: { allowed: false } });
  const { result, rerender } = renderHook(() => useCanI(createCommand));
  await waitFor(() => expect(result.current).toBe(false));

  // Headlamp keeps a page when the selected clusters change, and with them the first cluster
  address.cluster = 'address-b';
  post.mockResolvedValueOnce({ status: { allowed: true } });
  rerender();
  expect(result.current).toBeUndefined();
  await waitFor(() => expect(result.current).toBe(true));
  expect(post.mock.calls.map(call => call[3])).toEqual([
    { cluster: 'address-a' },
    { cluster: 'address-b' },
  ]);
});

it('enables an action again while the cluster that the address now names is asked', async () => {
  address.cluster = 'address-denied';
  post.mockResolvedValueOnce({ status: { allowed: false } });
  const action = () => (
    <Permitted check={createCommand}>
      {allowed => <button disabled={!allowed}>Relearn</button>}
    </Permitted>
  );
  const { rerender } = render(action());
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Relearn' })).toHaveProperty('disabled', true)
  );

  address.cluster = 'address-pending';
  post.mockReturnValueOnce(new Promise(() => {}));
  rerender(action());
  expect(screen.getByRole('button', { name: 'Relearn' })).toHaveProperty('disabled', false);
});

it('enables an action again while the check of another cluster is asked', async () => {
  post.mockResolvedValueOnce({ status: { allowed: false } });
  const { rerender } = render(
    <Permitted check={createCommand} cluster="switch-denied">
      {allowed => <button disabled={!allowed}>Rescan</button>}
    </Permitted>
  );
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Rescan' })).toHaveProperty('disabled', true)
  );

  post.mockReturnValueOnce(new Promise(() => {}));
  rerender(
    <Permitted check={createCommand} cluster="switch-pending">
      {allowed => <button disabled={!allowed}>Rescan</button>}
    </Permitted>
  );
  expect(screen.getByRole('button', { name: 'Rescan' })).toHaveProperty('disabled', false);
});
