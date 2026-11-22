/*
  The IndexedDB database of the plugin, which keeps data between Headlamp sessions in Headlamp's
  browser storage on this computer. Browsers may refuse it: in a private window, when storage is
  blocked or full, or when another tab holds an older version open. Every use therefore falls back
  to working without it, and nothing here throws.
*/

export const pluginDatabaseName = 'kubescape-plugin';
// raise it to add object stores, and create them in createStores; 2 added the exploit data
const databaseVersion = 2;

/** The object stores of the database, each keyed by the `key` field of its records. */
export const pluginStores = {
  // the vulnerability reports, as the pages keep them
  reports: 'vulnerabilityReports',
  // which version of a report a record holds and when it was last used, kept apart from the
  // reports so that they can be compared and pruned without reading the reports
  reportVersions: 'vulnerabilityReportVersions',
  // CISA's catalog of known exploited vulnerabilities and the EPSS scores of CVEs, each kept a
  // day (exploitData.ts)
  exploitData: 'exploitData',
} as const;

// how long the database may take to open before the plugin goes on without it
const openTimeoutMs = 5000;

let opening: Promise<IDBDatabase | undefined> | undefined;

function createStores(db: IDBDatabase) {
  for (const name of Object.values(pluginStores)) {
    if (!db.objectStoreNames.contains(name)) db.createObjectStore(name, { keyPath: 'key' });
  }
}

function indexedDBFactory(): IDBFactory | undefined {
  try {
    // reading it throws where the browser blocks storage
    return globalThis.indexedDB ?? undefined;
  } catch {
    return undefined;
  }
}

/**
 * The database, opened once per session; undefined when the browser refuses it. A database that
 * could not be opened is not asked again in the session.
 */
export function openPluginDatabase(): Promise<IDBDatabase | undefined> {
  opening ??= new Promise<IDBDatabase | undefined>(resolve => {
    const factory = indexedDBFactory();
    if (!factory) {
      resolve(undefined);
      return;
    }
    let settled = false;
    const settle = (db: IDBDatabase | undefined) => {
      if (settled) {
        // opened after the plugin went on without it
        db?.close();
        return;
      }
      settled = true;
      clearTimeout(timer);
      resolve(db);
    };
    const timer = setTimeout(() => settle(undefined), openTimeoutMs);
    let request: IDBOpenDBRequest;
    try {
      request = factory.open(pluginDatabaseName, databaseVersion);
    } catch {
      settle(undefined);
      return;
    }
    request.onupgradeneeded = () => {
      try {
        createStores(request.result);
      } catch {
        // the open fails, and onerror goes on without the database
      }
    };
    request.onsuccess = () => {
      const db = request.result;
      // another tab opens a newer version, or the browser closes the database: the next use
      // opens it again
      const forget = () => {
        db.close();
        if (opening === current) opening = undefined;
      };
      db.onversionchange = forget;
      db.onclose = forget;
      settle(db);
    };
    request.onerror = () => settle(undefined);
    request.onblocked = () => settle(undefined);
  });
  const current = opening;
  return current;
}

/** Forgets the open database, for tests. */
export function resetPluginDatabase() {
  const closing = opening;
  opening = undefined;
  closing?.then(db => db?.close()).catch(() => {});
}

/**
 * Runs `work` in a transaction of the stores; resolves with what it returns once the transaction
 * completed, as only then are its requests answered and written; rejects when it fails.
 */
export function inTransaction<T>(
  db: IDBDatabase,
  stores: string[],
  mode: IDBTransactionMode,
  work: (transaction: IDBTransaction) => T
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let transaction: IDBTransaction;
    let result: T;
    try {
      transaction = db.transaction(stores, mode);
      result = work(transaction);
    } catch (error) {
      reject(error);
      return;
    }
    transaction.oncomplete = () => resolve(result);
    transaction.onerror = () =>
      reject(transaction.error ?? new Error('IndexedDB transaction failed'));
    transaction.onabort = () =>
      reject(transaction.error ?? new Error('IndexedDB transaction aborted'));
  });
}
