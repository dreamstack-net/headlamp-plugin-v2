import { vi } from 'vitest';
import { FakeIndexedDB, installFakeIndexedDB, removeFakeIndexedDB } from '../common/fakeIndexedDB';
import { pluginDatabaseName, pluginStores, resetPluginDatabase } from '../common/pluginDatabase';
import {
  clearReportCache,
  clusterIdentity,
  openReportCache,
  pruneReportCache,
  reportCacheEnabled,
  reportCacheLimits,
  ReportVersion,
  resetReportCacheState,
} from './reportCache';
import { ImageScan, toImageScan } from './scanData';
import { manifest, match } from './testFixtures';

const mocks = vi.hoisted(() => ({ request: vi.fn() }));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ request: mocks.request }));

const day = 24 * 60 * 60 * 1000;
let db: FakeIndexedDB;

function scan(name: string, findings = 1): ImageScan {
  const image = toImageScan(manifest());
  return {
    ...image,
    manifestName: name,
    namespace: 'kubescape',
    matches: Array.from({ length: findings }, (_, i) => match(`CVE-${i}`)),
  };
}

function version(name: string, resourceVersion = '1', uid = `uid-${name}`): ReportVersion {
  return { namespace: 'kubescape', name, uid, resourceVersion };
}

/** The kube-system namespace of each cluster has its own uid. */
function clusters(uids: Record<string, string>) {
  mocks.request.mockImplementation(async (url: string, { cluster }: { cluster: string }) => {
    if (url !== '/api/v1/namespaces/kube-system') throw new Error(`unexpected ${url}`);
    if (!uids[cluster]) throw Object.assign(new Error('forbidden'), { status: 403 });
    return { metadata: { uid: uids[cluster] } };
  });
}

/** Another Headlamp session: the database and the cluster identities are opened again. */
function newSession() {
  resetPluginDatabase();
  resetReportCacheState();
}

beforeEach(() => {
  db = installFakeIndexedDB();
  newSession();
  mocks.request.mockReset();
  clusters({ 'cluster-a': 'uid-a', 'cluster-b': 'uid-b' });
});
afterEach(() => {
  newSession();
  removeFakeIndexedDB();
});

it('is on unless switched off', () => {
  expect(reportCacheEnabled(undefined)).toBe(true);
  expect(reportCacheEnabled({})).toBe(true);
  expect(reportCacheEnabled({ keepVulnerabilityReports: true })).toBe(true);
  expect(reportCacheEnabled({ keepVulnerabilityReports: false })).toBe(false);
});

it('gives back the stored reports whose uid and resourceVersion did not change', async () => {
  const cache = (await openReportCache('cluster-a'))!;
  await cache.write([
    { version: version('nginx'), scan: scan('nginx') },
    { version: version('redis'), scan: scan('redis') },
    { version: version('postgres'), scan: scan('postgres') },
  ]);

  newSession();
  const later = (await openReportCache('cluster-a'))!;
  const found = await later.read([
    version('nginx'),
    // saved again since
    version('redis', '2'),
    // deleted and created again with the same name
    version('postgres', '1', 'other-uid'),
    version('unknown'),
  ]);

  expect(found.map(image => image.manifestName)).toEqual(['nginx']);
  expect(found[0].cluster).toBe('cluster-a');
  expect(found[0].matches).toEqual(scan('nginx').matches);
});

it('keeps the reports of clusters apart by the uid of their kube-system namespace', async () => {
  await (await openReportCache('cluster-a'))!.write([
    { version: version('nginx'), scan: scan('nginx') },
  ]);

  // another cluster under the same context name
  newSession();
  clusters({ 'cluster-a': 'uid-other' });
  expect(await (await openReportCache('cluster-a'))!.read([version('nginx')])).toEqual([]);

  // the same cluster under another name, whose reports are named by that name
  newSession();
  clusters({ renamed: 'uid-a' });
  const found = await (await openReportCache('renamed'))!.read([version('nginx')]);
  expect(found.map(image => `${image.cluster}/${image.manifestName}`)).toEqual(['renamed/nginx']);
});

it('identifies a cluster by its name when its kube-system namespace cannot be read', async () => {
  clusters({});
  expect(await clusterIdentity('cluster-a')).toBe('name:cluster-a');
  // asked once per session
  expect(await clusterIdentity('cluster-a')).toBe('name:cluster-a');
  expect(mocks.request).toHaveBeenCalledTimes(1);
});

it.each([
  ['without IndexedDB', () => removeFakeIndexedDB()],
  ['when the browser refuses it', () => (db.failOpen = true)],
  ['when an older version is open elsewhere', () => (db.blockOpen = true)],
])('keeps nothing %s, without errors', async (_case, refuse) => {
  refuse();
  expect(await openReportCache('cluster-a')).toBeUndefined();
  await expect(pruneReportCache({ force: true })).resolves.toBeUndefined();
  await expect(clearReportCache()).resolves.toBeUndefined();
  expect(mocks.request).not.toHaveBeenCalled();
});

it('stops storing when the storage is full, and still reads what it holds', async () => {
  const cache = (await openReportCache('cluster-a'))!;
  await cache.write([{ version: version('nginx'), scan: scan('nginx') }]);
  const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});

  db.failWrites = true;
  await expect(
    cache.write([{ version: version('redis'), scan: scan('redis') }])
  ).resolves.toBeUndefined();
  db.failWrites = false;
  await cache.write([{ version: version('postgres'), scan: scan('postgres') }]);

  expect(warn).toHaveBeenCalledTimes(1);
  warn.mockRestore();
  const found = await cache.read([version('nginx'), version('redis'), version('postgres')]);
  expect(found.map(image => image.manifestName)).toEqual(['nginx']);
});

it('prunes the reports not used for a week, also after they were used', async () => {
  const start = Date.UTC(2026, 10, 1);
  let now = start;
  const cache = (await openReportCache('cluster-a', () => now))!;
  await cache.write([
    { version: version('nginx'), scan: scan('nginx') },
    { version: version('redis'), scan: scan('redis') },
  ]);

  // nginx is used on day 5, redis not
  now = start + 5 * day;
  expect((await cache.read([version('nginx')])).map(image => image.manifestName)).toEqual([
    'nginx',
  ]);

  await pruneReportCache({ now: start + 8 * day, force: true });

  expect([...db.records(pluginDatabaseName, pluginStores.reports).values()].length).toBe(1);
  expect((await cache.read([version('nginx'), version('redis')])).length).toBe(1);
});

it('removes the least recently used reports beyond its bounds', async () => {
  const limits = { ...reportCacheLimits };
  reportCacheLimits.maxReports = 4;
  reportCacheLimits.maxFindings = 15;
  try {
    let now = Date.now();
    const cache = (await openReportCache('cluster-a', () => now))!;
    for (const [name, findings] of [
      ['oldest', 1],
      ['old', 1],
      ['big', 9],
      ['new', 1],
      ['newest', 1],
    ] as const) {
      now += 1000;
      await cache.write([{ version: version(name), scan: scan(name, findings) }]);
    }

    await pruneReportCache({ now, force: true });

    // four reports at most, and 15 findings (each report counts one more): old is one too many
    // findings, oldest one too many reports
    const kept = await cache.read(['oldest', 'old', 'big', 'new', 'newest'].map(n => version(n)));
    expect(kept.map(image => image.manifestName).sort()).toEqual(['big', 'new', 'newest']);

    // without force, pruning runs once an hour
    await cache.write([{ version: version('oldest'), scan: scan('oldest') }]);
    await pruneReportCache({ now: now + 1000 });
    expect(db.records(pluginDatabaseName, pluginStores.reports).size).toBe(4);
  } finally {
    Object.assign(reportCacheLimits, limits);
  }
});

it('removes all reports when cleared, also ones a read in progress would store', async () => {
  const cache = (await openReportCache('cluster-a'))!;
  await cache.write([{ version: version('nginx'), scan: scan('nginx') }]);

  await clearReportCache();
  await cache.write([{ version: version('redis'), scan: scan('redis') }]);

  expect(db.records(pluginDatabaseName, pluginStores.reports).size).toBe(0);
  expect(db.records(pluginDatabaseName, pluginStores.reportVersions).size).toBe(0);
  // a read that begins after it stores again
  const next = (await openReportCache('cluster-a'))!;
  await next.write([{ version: version('redis'), scan: scan('redis') }]);
  expect(db.records(pluginDatabaseName, pluginStores.reports).size).toBe(1);
});

it('reads a report again that an older version of the plugin stored in another form', async () => {
  const cache = (await openReportCache('cluster-a'))!;
  await cache.write([{ version: version('nginx'), scan: scan('nginx') }]);
  for (const record of db.records(pluginDatabaseName, pluginStores.reportVersions).values()) {
    record.format = 0;
  }

  expect(await cache.read([version('nginx')])).toEqual([]);
});
