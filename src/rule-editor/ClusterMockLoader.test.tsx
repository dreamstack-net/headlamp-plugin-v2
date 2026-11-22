import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ClusterMockLoader } from './ClusterMockLoader';

const mocks = vi.hoisted(() => ({ request: vi.fn() }));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ request: mocks.request }));
// one namespace, which is then chosen
vi.mock('../common/clusterContext', () => ({ getAllowedNamespaces: () => ['shop'] }));
vi.mock('../softwarecomposition/profileApi', () => ({
  discoverProfileResource: async () => ({ plural: 'containerprofiles', modern: true }),
}));

const profileName = 'replicaset-web-6d4cf56db6-web-1a2b-3c4d';
const profile = {
  metadata: {
    name: profileName,
    namespace: 'shop',
    labels: { 'kubescape.io/workload-container-name': 'web' },
  },
  spec: { execs: [{ path: '/bin/web' }] },
};

// answers the read of the profile, which the tests decide when
let answerProfile: (profile: unknown) => void;

beforeEach(() => {
  mocks.request.mockReset();
  mocks.request.mockImplementation((url: string) =>
    url.endsWith(`/containerprofiles/${profileName}`)
      ? new Promise(resolve => {
          answerProfile = resolve;
        })
      : Promise.resolve({ items: [{ metadata: { name: profileName } }], metadata: {} })
  );
});
afterEach(cleanup);

function profileReads() {
  return mocks.request.mock.calls.filter(([url]) => url.endsWith(`/${profileName}`)).length;
}

/** Opens the loader, chooses the profile and asks to load it. */
async function loadProfile() {
  fireEvent.click(screen.getByRole('button', { name: 'Load from cluster' }));
  const profiles = await screen.findByRole('combobox', { name: 'Profile' });
  await waitFor(() => expect(profiles.getAttribute('aria-disabled')).not.toBe('true'));
  fireEvent.mouseDown(profiles);
  fireEvent.click(await screen.findByRole('option', { name: profileName }));
  const reads = profileReads();
  fireEvent.click(screen.getByRole('button', { name: 'Load' }));
  await waitFor(() => expect(profileReads()).toBe(reads + 1));
}

it('loads the mock of a profile of the cluster, with the container it is about', async () => {
  const onLoad = vi.fn();
  render(<ClusterMockLoader baselineKind="application" onLoad={onLoad} />);
  await loadProfile();
  answerProfile(profile);

  await waitFor(() => expect(onLoad).toHaveBeenCalledTimes(1));
  const [mock, meta] = onLoad.mock.calls[0];
  expect(mock).toContain('path: /bin/web');
  expect(meta).toEqual({ namespace: 'shop', workload: profileName, containerName: 'web' });
  // and closes
  expect(await screen.findByRole('button', { name: 'Load from cluster' })).toBeTruthy();
});

it('drops the answer to a load that was cancelled', async () => {
  const onLoad = vi.fn();
  render(<ClusterMockLoader baselineKind="application" onLoad={onLoad} />);
  await loadProfile();
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  const answerCancelled = answerProfile;

  // the profile can be loaded again at once, without waiting for the answer that was dropped
  await loadProfile();
  answerCancelled(profile);
  await new Promise(resolve => setTimeout(resolve, 0));
  expect(onLoad).not.toHaveBeenCalled();
  expect(screen.getByRole('button', { name: 'Cancel' })).toBeTruthy();

  answerProfile(profile);
  await waitFor(() => expect(onLoad).toHaveBeenCalledTimes(1));
});
