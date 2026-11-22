/*
  Where Headlamp serves the files of this plugin, such as the Kubescape data in public/ and
  main.wasm. Headlamp may hold several copies of a plugin (development, user and shipped plugins)
  and serves everything under its base URL, so the copy is the one Headlamp loaded.
*/

// the name in package.json, by which Headlamp tells the copies of a plugin apart
const packageName = 'kubescape-plugin';

type PluginType = 'development' | 'user' | 'shipped';

/** A plugin as Headlamp's /plugins lists it: the URL path and the folder name. */
export interface PluginEntry {
  path: string;
  name: string;
  type?: PluginType;
}

/** What Headlamp keeps in localStorage about a plugin. */
export interface StoredPluginSetting {
  name?: string;
  folderName?: string;
  type?: PluginType;
  isEnabled?: boolean;
  isLoaded?: boolean;
}

// Headlamp loads the copy of a plugin of the first type of these that is not disabled
const priority: PluginType[] = ['development', 'user', 'shipped'];

let cachedUrl: Promise<string> | null = null;

/**
 * The URL of the folder of the plugin, without a trailing slash. It is remembered once the plugin
 * was found in Headlamp's list; a default URL, used when the list cannot be read, is not.
 */
export function getKubescapePluginUrl(): Promise<string> {
  if (!cachedUrl) {
    const lookup = fetchPluginUrl().then(({ url, found }) => {
      if (!found && cachedUrl === lookup) cachedUrl = null;
      return url;
    });
    cachedUrl = lookup;
  }
  return cachedUrl;
}

/**
 * The path under which Headlamp serves its pages and backend, such as /headlamp for a Headlamp in
 * a cluster behind a path prefix, or '' (like Headlamp's getBaseUrl, which plugins cannot import).
 */
export function headlampBaseUrl(): string {
  // Headlamp desktop serves no base URL
  if (isElectron()) return '';
  const baseUrl: unknown = (window as any)?.headlampBaseUrl;
  if (typeof baseUrl !== 'string' || baseUrl === './' || baseUrl === '.') return '';
  return baseUrl.replace(/\/+$/, '');
}

/** The URL of Headlamp's backend with its base URL and a trailing slash, like Headlamp's getAppUrl. */
export function headlampAppUrl(): string {
  if (isElectron()) {
    return `http://localhost:${(window as any)?.headlampBackendPort ?? 4466}/`;
  }
  const origin = isDockerDesktop() ? 'http://localhost:64446' : window.location.origin;
  return `${origin}${headlampBaseUrl()}/`;
}

async function fetchPluginUrl(): Promise<{ url: string; found: boolean }> {
  const appUrl = headlampAppUrl();
  try {
    const response = await fetch(`${appUrl}plugins`);
    if (response.ok) {
      const entries = pluginEntries(await response.json());
      const entry =
        loadedPlugin(entries, storedPluginSettings()) ??
        (await preferredPlugin(entries, storedPluginSettings(), path =>
          readPackageName(appUrl, path)
        ));
      if (entry) return { url: `${appUrl}${entry.path}`, found: true };
    }
  } catch {
    // fall through to the default
  }
  // where the Plugin Catalog of Headlamp desktop and the plugin's container image put the plugin
  return {
    url: isElectron()
      ? `${appUrl}user-plugins/headlamp_kubescape`
      : `${appUrl}plugins/kubescape-plugin`,
    found: false,
  };
}

/**
 * The entries of Headlamp's /plugins: objects with the path, type and folder name, or, from
 * Headlamp releases before plugin types, paths.
 */
export function pluginEntries(list: unknown): PluginEntry[] {
  if (!Array.isArray(list)) return [];
  return list.flatMap((item): PluginEntry[] => {
    if (typeof item === 'string') {
      const path = item.replaceAll('\\', '/');
      return [{ path, name: path.split('/').pop() ?? path }];
    }
    if (typeof item?.path !== 'string') return [];
    const path = item.path.replaceAll('\\', '/');
    const name = typeof item.name === 'string' ? item.name : path.split('/').pop() ?? path;
    return [{ path, name, type: priority.includes(item.type) ? item.type : undefined }];
  });
}

function storedPluginSettings(): StoredPluginSetting[] {
  try {
    const settings = JSON.parse(window.localStorage.getItem('headlampPluginSettings') ?? '[]');
    return Array.isArray(settings) ? settings : [];
  } catch {
    return [];
  }
}

/**
 * The copy of the plugin that Headlamp loaded, which it records in its plugin settings before it
 * runs the plugins.
 */
export function loadedPlugin(
  entries: PluginEntry[],
  settings: StoredPluginSetting[]
): PluginEntry | undefined {
  const loaded = settings.find(
    setting => setting?.name === packageName && setting.isLoaded === true && setting.folderName
  );
  if (!loaded) return undefined;
  return entries.find(
    entry =>
      entry.name === loaded.folderName &&
      (!loaded.type || !entry.type || entry.type === loaded.type)
  );
}

/**
 * The copy of the plugin that Headlamp loads when its settings do not say: of the plugins whose
 * package.json names this plugin, the first that is not disabled of the development, user and
 * shipped plugins.
 */
export async function preferredPlugin(
  entries: PluginEntry[],
  settings: StoredPluginSetting[],
  readName: (path: string) => Promise<string | undefined>
): Promise<PluginEntry | undefined> {
  const names = await Promise.all(
    entries.map(entry => readName(entry.path).catch(() => undefined))
  );
  const disabled = (entry: PluginEntry) =>
    settings.some(
      setting =>
        setting?.name === packageName &&
        setting.isEnabled === false &&
        setting.folderName === entry.name &&
        (!setting.type || !entry.type || setting.type === entry.type)
    );
  const rank = (entry: PluginEntry) => priority.indexOf(entry.type ?? 'shipped');
  return entries
    .filter((entry, i) => names[i] === packageName && !disabled(entry))
    .sort((a, b) => rank(a) - rank(b))[0];
}

async function readPackageName(appUrl: string, path: string): Promise<string | undefined> {
  const response = await fetch(`${appUrl}${path}/package.json`);
  if (!response.ok) return undefined;
  const info = await response.json();
  return typeof info?.name === 'string' ? info.name : undefined;
}

/**
 * Determines whether app is running in electron environment.
 * Note: The isElectron code (Licence: MIT) is taken from
 *   https://github.com/cheton/is-electron/blob/master/index.js
 */
export function isElectron(): boolean {
  // Renderer process
  if (
    typeof window !== 'undefined' &&
    typeof window.process === 'object' &&
    (window.process as any).type === 'renderer'
  ) {
    return true;
  }

  // Main process
  if (
    typeof process !== 'undefined' &&
    typeof process.versions === 'object' &&
    !!(process.versions as any).electron
  ) {
    return true;
  }

  // Detect the user agent when the `nodeIntegration` option is set to true
  if (
    typeof navigator === 'object' &&
    typeof navigator.userAgent === 'string' &&
    navigator.userAgent.indexOf('Electron') >= 0
  ) {
    return true;
  }

  return false;
}

function isDockerDesktop(): boolean {
  return (window as any)?.ddClient !== undefined;
}
