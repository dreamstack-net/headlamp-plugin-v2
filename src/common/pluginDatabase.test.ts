import { installFakeIndexedDB, removeFakeIndexedDB } from './fakeIndexedDB';
import {
  inTransaction,
  openPluginDatabase,
  pluginDatabaseName,
  pluginStores,
  resetPluginDatabase,
} from './pluginDatabase';

beforeEach(() => {
  resetPluginDatabase();
});
afterEach(() => {
  resetPluginDatabase();
  removeFakeIndexedDB();
});

it('opens one database for the plugin with its stores, once per session', async () => {
  const factory = installFakeIndexedDB();

  const db = await openPluginDatabase();

  expect(db).toBeDefined();
  expect(await openPluginDatabase()).toBe(db);
  expect([...factory.databases.keys()]).toEqual([pluginDatabaseName]);
  expect([...factory.databases.get(pluginDatabaseName)!.stores.keys()].sort()).toEqual(
    Object.values(pluginStores).sort()
  );
});

it('goes on without a database where the browser refuses one', async () => {
  removeFakeIndexedDB();
  expect(await openPluginDatabase()).toBeUndefined();

  resetPluginDatabase();
  installFakeIndexedDB().failOpen = true;
  expect(await openPluginDatabase()).toBeUndefined();

  resetPluginDatabase();
  installFakeIndexedDB().blockOpen = true;
  expect(await openPluginDatabase()).toBeUndefined();

  // reading indexedDB throws where storage is blocked
  resetPluginDatabase();
  Object.defineProperty(globalThis, 'indexedDB', {
    configurable: true,
    get() {
      throw new DOMException('Access is denied', 'SecurityError');
    },
  });
  expect(await openPluginDatabase()).toBeUndefined();
});

it('resolves a transaction once it completed, and rejects one that failed', async () => {
  const factory = installFakeIndexedDB();
  const db = (await openPluginDatabase())!;

  const read = await inTransaction(db, [pluginStores.reports], 'readwrite', transaction => {
    const store = transaction.objectStore(pluginStores.reports);
    store.put({ key: 'a', value: 1 });
    const result: { value?: unknown } = {};
    const request = store.get('a');
    request.onsuccess = () => (result.value = request.result);
    return result;
  });
  expect(read.value).toEqual({ key: 'a', value: 1 });

  factory.failWrites = true;
  await expect(
    inTransaction(db, [pluginStores.reports], 'readwrite', transaction => {
      transaction.objectStore(pluginStores.reports).put({ key: 'b' });
    })
  ).rejects.toThrow('quota');
  await expect(
    inTransaction(db, ['unknown'], 'readonly', transaction => transaction.objectStore('unknown'))
  ).rejects.toThrow('No store');
});

it('adds the stores of a newer version to a database of an older one, keeping its records', async () => {
  const factory = installFakeIndexedDB();
  // the database as version 1 of the plugin created it, with a stored report
  factory.databases.set(pluginDatabaseName, {
    version: 1,
    stores: new Map([
      [pluginStores.reports, new Map([['a', { key: 'a' }]])],
      [pluginStores.reportVersions, new Map()],
    ]),
    keyPaths: new Map([
      [pluginStores.reports, 'key'],
      [pluginStores.reportVersions, 'key'],
    ]),
  });

  const db = await openPluginDatabase();

  expect(db).toBeDefined();
  expect([...factory.databases.get(pluginDatabaseName)!.stores.keys()].sort()).toEqual(
    Object.values(pluginStores).sort()
  );
  expect(factory.records(pluginDatabaseName, pluginStores.reports).get('a')).toEqual({ key: 'a' });
});
