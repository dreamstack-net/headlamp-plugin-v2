import { vi } from 'vitest';
import { manifest } from './testFixtures';

const mocks = vi.hoisted(() => ({
  request: vi.fn(),
  getKubescapeNamespace: vi.fn(),
}));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ request: mocks.request }));
vi.mock('../custom-objects/api-queries', () => ({
  getKubescapeNamespace: mocks.getKubescapeNamespace,
}));

import { installFakeIndexedDB, removeFakeIndexedDB } from '../common/fakeIndexedDB';
import { resetPluginDatabase } from '../common/pluginDatabase';
import {
  listReportVersions,
  openStoredReports,
  readManifests,
  readReports,
  referencedVersion,
} from './manifestReader';
import { resetReportCacheState } from './reportCache';
import { toImageScan } from './scanData';

const base = '/apis/spdx.softwarecomposition.kubescape.io/v1beta1/namespaces';
const notFound = () => Object.assign(new Error('not found'), { status: 404 });

function report(namespace: string, name: string) {
  const found = manifest();
  found.metadata = { ...found.metadata, namespace, name };
  return found;
}

beforeEach(() => {
  mocks.request.mockReset();
  mocks.getKubescapeNamespace.mockReset().mockResolvedValue({ kubeScapeNamespace: 'kubescape' });
});

it('reads each report where its reference points, and in the operator namespace otherwise', async () => {
  const stored: Record<string, ReturnType<typeof report>> = {
    [`${base}/shop/vulnerabilitymanifests/web`]: report('shop', 'web'),
    [`${base}/kubescape/vulnerabilitymanifests/api`]: report('kubescape', 'api'),
  };
  mocks.request.mockImplementation(async (url: string) => {
    if (stored[url]) return structuredClone(stored[url]);
    throw notFound();
  });
  const received: string[] = [];

  const result = await readManifests(
    'cluster-a',
    [
      { name: 'web', namespace: 'shop' },
      // the storage keeps the report in the operator namespace
      { name: 'api', namespace: 'shop' },
      { name: 'gone', namespace: 'shop' },
    ],
    {
      continueReading: { current: true },
      onManifest: found => received.push(`${found.metadata.cluster}/${found.metadata.name}`),
    }
  );

  expect(received.sort()).toEqual(['cluster-a/api', 'cluster-a/web']);
  expect(result.missing).toEqual([{ name: 'gone', namespace: 'shop' }]);
  expect(result.errors).toEqual([]);
  expect(result.stopped).toBe(false);
  // the operator namespace is looked up once
  expect(mocks.getKubescapeNamespace).toHaveBeenCalledTimes(1);
  expect(mocks.request).toHaveBeenCalledWith(`${base}/shop/vulnerabilitymanifests/web`, {
    cluster: 'cluster-a',
  });
});

it('reads at most six reports at a time', async () => {
  let running = 0;
  let most = 0;
  mocks.request.mockImplementation(async (url: string) => {
    running++;
    most = Math.max(most, running);
    await new Promise(resolve => setTimeout(resolve, 1));
    running--;
    return report('shop', url.split('/').pop()!);
  });
  const references = Array.from({ length: 20 }, (_, i) => ({ name: `r${i}`, namespace: 'shop' }));
  let progress = 0;

  await readManifests('cluster-a', references, {
    continueReading: { current: true },
    onManifest: () => {},
    onProgress: read => (progress = read),
  });

  expect(mocks.request).toHaveBeenCalledTimes(20);
  expect(most).toBe(6);
  expect(progress).toBe(20);
});

it('reports the reports that could not be read, and stops when reading is cancelled', async () => {
  const continueReading = { current: true };
  mocks.request.mockImplementation(async (url: string) => {
    if (url.endsWith('/broken')) throw Object.assign(new Error('timeout'), { status: 504 });
    // cancelled while the first report is read
    continueReading.current = false;
    return report('shop', 'first');
  });

  const result = await readManifests(
    'cluster-a',
    [
      { name: 'broken', namespace: 'shop' },
      { name: 'first', namespace: 'shop' },
      { name: 'never', namespace: 'shop' },
    ],
    { continueReading, onManifest: () => {}, concurrency: 1 }
  );

  expect(result.errors).toEqual(['shop/broken: timeout']);
  expect(result.stopped).toBe(true);
  expect(mocks.request).toHaveBeenCalledTimes(2);
});

const version = (namespace: string, name: string, resourceVersion = '1') => ({
  namespace,
  name,
  uid: `uid-${name}`,
  resourceVersion,
});

it('lists the versions of the reports page by page, per namespace when given', async () => {
  mocks.request.mockImplementation(async (url: string) => {
    if (url.includes('/namespaces/secret/'))
      throw Object.assign(new Error('forbidden'), { status: 403 });
    const namespace = url.split('/')[5];
    const page = url.includes('continue=') ? 2 : 1;
    return {
      items: [
        {
          metadata: { namespace, name: `${namespace}-${page}`, uid: 'u', resourceVersion: '7' },
        },
      ],
      metadata: { continue: page === 1 ? 'next' : '' },
    };
  });

  const versions = await listReportVersions('cluster-a', ['shop', 'secret']);

  expect(versions.map(found => found.name)).toEqual(['shop-1', 'shop-2']);
  expect(mocks.request.mock.calls.map(([url]) => url)).toContain(
    `${base}/shop/vulnerabilitymanifests?limit=1000&continue=next`
  );
  // the metadata only: no fullSpec
  expect(mocks.request.mock.calls.every(([url]) => !url.includes('fullSpec'))).toBe(true);
  await expect(listReportVersions('cluster-a', ['secret'])).rejects.toThrow('forbidden');
});

it('lists the allowed namespaces and the operator namespace for the stored reports', async () => {
  installFakeIndexedDB();
  resetPluginDatabase();
  resetReportCacheState();
  mocks.request.mockImplementation(async (url: string) => {
    if (url === '/api/v1/namespaces/kube-system') throw notFound();
    return {
      items: [
        { metadata: { namespace: 'kubescape', name: 'nginx', uid: 'u', resourceVersion: '1' } },
      ],
    };
  });

  const stored = await openStoredReports('cluster-a', ['shop']);

  expect(stored?.versions.get('nginx')?.length).toBe(2);
  expect(
    mocks.request.mock.calls.map(([url]) => url).filter(url => url.includes('manifests'))
  ).toEqual([
    `${base}/shop/vulnerabilitymanifests?limit=1000`,
    `${base}/kubescape/vulnerabilitymanifests?limit=1000`,
  ]);
  removeFakeIndexedDB();
  resetPluginDatabase();
});

it('finds the version of a referenced report where it points, or by its name', () => {
  const versions = new Map([
    ['web', [version('shop', 'web'), version('kubescape', 'web')]],
    ['api', [version('kubescape', 'api')]],
    ['twice', [version('a', 'twice'), version('b', 'twice')]],
    ['unversioned', [{ ...version('kubescape', 'unversioned'), resourceVersion: '' }]],
  ]);

  expect(referencedVersion(versions, { name: 'web', namespace: 'kubescape' })?.namespace).toBe(
    'kubescape'
  );
  expect(referencedVersion(versions, { name: 'api', namespace: 'shop' })?.namespace).toBe(
    'kubescape'
  );
  expect(referencedVersion(versions, { name: 'twice', namespace: 'shop' })).toBeUndefined();
  expect(referencedVersion(versions, { name: 'unversioned' })).toBeUndefined();
  expect(referencedVersion(versions, { name: 'gone' })).toBeUndefined();
});

it('reads the changed reports where the metadata says, and stops between stored batches', async () => {
  const stored = new Map([['nginx', toImageScan(report('kubescape', 'nginx'))]]);
  const cache = {
    read: vi.fn(async (versions: Array<{ name: string }>) =>
      versions.flatMap(found => (stored.has(found.name) ? [stored.get(found.name)!] : []))
    ),
    write: vi.fn(async () => {}),
  };
  const versions = new Map([
    ['nginx', [version('kubescape', 'nginx')]],
    ['redis', [version('kubescape', 'redis', '2')]],
  ]);
  mocks.request.mockImplementation(async (url: string) =>
    report('kubescape', url.split('/').pop()!)
  );
  const received: string[] = [];

  const result = await readReports(
    'cluster-a',
    [
      { name: 'nginx', namespace: 'shop' },
      { name: 'redis', namespace: 'shop' },
    ],
    {
      continueReading: { current: true },
      stored: { cache, versions },
      onImageScan: scan => received.push(scan.manifestName),
    }
  );

  expect(result.errors).toEqual([]);
  expect(received).toEqual(['nginx', 'redis']);
  // read directly in the namespace the metadata names, and stored at its version
  expect(mocks.request.mock.calls.map(([url]) => url)).toEqual([
    `${base}/kubescape/vulnerabilitymanifests/redis`,
  ]);
  expect(cache.write).toHaveBeenCalledWith([
    {
      version: version('kubescape', 'redis', '2'),
      scan: expect.objectContaining({ manifestName: 'redis' }),
    },
  ]);

  mocks.request.mockClear();
  const stopped = await readReports('cluster-a', [{ name: 'nginx' }], {
    continueReading: { current: false },
    stored: { cache, versions },
    onImageScan: () => {},
  });
  expect(stopped.stopped).toBe(true);
  expect(mocks.request).not.toHaveBeenCalled();
});
