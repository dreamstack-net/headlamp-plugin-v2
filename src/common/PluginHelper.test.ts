import { vi } from 'vitest';
import { loadedPlugin, pluginEntries, preferredPlugin } from './PluginHelper';

const fetchMock = vi.fn();

// a module of its own, without the URL remembered by the tests before
const freshPluginHelper = () => vi.importActual<typeof import('./PluginHelper')>('./PluginHelper');

beforeEach(() => {
  vi.resetModules();
  fetchMock.mockReset();
  vi.stubGlobal('fetch', fetchMock);
  window.localStorage.clear();
  delete (window as any).headlampBaseUrl;
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function json(body: unknown, ok = true) {
  return Promise.resolve({ ok, status: ok ? 200 : 404, json: () => Promise.resolve(body) });
}

const listed = [
  { path: 'static-plugins/kubescape-plugin', type: 'shipped', name: 'kubescape-plugin' },
  { path: 'user-plugins/headlamp_kubescape', type: 'user', name: 'headlamp_kubescape' },
  { path: 'plugins/kubescape-plugin', type: 'development', name: 'kubescape-plugin' },
  { path: 'plugins/kubescape-extras', type: 'development', name: 'kubescape-extras' },
];

it('reads the plugin list of Headlamp releases with and without plugin types', () => {
  expect(pluginEntries(['plugins\\kubescape-plugin', 'user-plugins/headlamp_kubescape'])).toEqual([
    { path: 'plugins/kubescape-plugin', name: 'kubescape-plugin' },
    { path: 'user-plugins/headlamp_kubescape', name: 'headlamp_kubescape' },
  ]);
  expect(pluginEntries(listed)[1]).toEqual({
    path: 'user-plugins/headlamp_kubescape',
    name: 'headlamp_kubescape',
    type: 'user',
  });
  expect(pluginEntries({ error: 'not a list' })).toEqual([]);
});

it('takes the copy that Headlamp loaded, as its plugin settings record it', () => {
  const entries = pluginEntries(listed);
  const settings = [
    { name: 'kubescape-plugin', folderName: 'kubescape-plugin', type: 'development' as const },
    {
      name: 'kubescape-plugin',
      folderName: 'headlamp_kubescape',
      type: 'user' as const,
      isLoaded: true,
    },
  ];
  expect(loadedPlugin(entries, settings)?.path).toBe('user-plugins/headlamp_kubescape');
  // settings of an older Headlamp, which do not say which copy runs
  expect(loadedPlugin(entries, [{ name: 'kubescape-plugin', isEnabled: true }])).toBeUndefined();
});

it('otherwise prefers the copy Headlamp prefers: development, user, shipped, not disabled', async () => {
  const entries = pluginEntries(listed);
  const names: Record<string, string> = {
    'static-plugins/kubescape-plugin': 'kubescape-plugin',
    'user-plugins/headlamp_kubescape': 'kubescape-plugin',
    'plugins/kubescape-plugin': 'kubescape-plugin',
    'plugins/kubescape-extras': 'kubescape-extras',
  };
  const readName = async (path: string) => names[path];

  expect((await preferredPlugin(entries, [], readName))?.path).toBe('plugins/kubescape-plugin');
  const developmentDisabled = [
    {
      name: 'kubescape-plugin',
      folderName: 'kubescape-plugin',
      type: 'development' as const,
      isEnabled: false,
    },
  ];
  expect((await preferredPlugin(entries, developmentDisabled, readName))?.path).toBe(
    'user-plugins/headlamp_kubescape'
  );
  // a folder named after Kubescape that holds another plugin is not taken
  expect(
    await preferredPlugin([entries[3]], [], async () => {
      throw new Error('no package.json');
    })
  ).toBeUndefined();
});

it('reads the plugin list and the files under the base URL of Headlamp', async () => {
  (window as any).headlampBaseUrl = '/headlamp';
  window.localStorage.setItem(
    'headlampPluginSettings',
    JSON.stringify([
      { name: 'kubescape-plugin', folderName: 'kubescape-plugin', type: 'shipped', isLoaded: true },
    ])
  );
  fetchMock.mockImplementation((url: string) =>
    url.endsWith('/plugins') ? json(listed.slice(0, 1)) : json({}, false)
  );
  const { getKubescapePluginUrl } = await freshPluginHelper();

  expect(await getKubescapePluginUrl()).toBe(
    `${window.location.origin}/headlamp/static-plugins/kubescape-plugin`
  );
  expect(fetchMock).toHaveBeenCalledWith(`${window.location.origin}/headlamp/plugins`);
  // found in the list, so it is remembered
  await getKubescapePluginUrl();
  expect(fetchMock).toHaveBeenCalledTimes(1);
});

it('does not remember the default URL when the plugin list cannot be read', async () => {
  fetchMock.mockRejectedValueOnce(new Error('offline'));
  const { getKubescapePluginUrl } = await freshPluginHelper();

  expect(await getKubescapePluginUrl()).toBe(`${window.location.origin}/plugins/kubescape-plugin`);

  fetchMock.mockImplementation((url: string) =>
    url.endsWith('/plugins')
      ? json([{ path: 'plugins/ks', type: 'development', name: 'ks' }])
      : json({ name: 'kubescape-plugin' })
  );
  expect(await getKubescapePluginUrl()).toBe(`${window.location.origin}/plugins/ks`);
  expect(fetchMock).toHaveBeenCalledWith(`${window.location.origin}/plugins/ks/package.json`);
});
