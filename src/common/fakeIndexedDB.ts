/*
  An IndexedDB in memory for tests, as jsdom has none: the part of the API that the plugin uses
  (open with upgrade, object stores keyed by a key path, get, getAll, put, delete and clear in
  transactions). Requests answer asynchronously, in order, and a transaction completes once its
  requests and the requests made in their callbacks are answered. It can fail like a browser
  that refuses storage.
*/

type Handler = ((event: { target: unknown }) => void) | null;

class FakeRequest<T = unknown> {
  result: T | undefined;
  error: DOMException | null = null;
  onsuccess: Handler = null;
  onerror: Handler = null;
}

class FakeOpenRequest extends FakeRequest<FakeDatabase> {
  onupgradeneeded: Handler = null;
  onblocked: Handler = null;
}

type Records = Map<string, unknown>;

class FakeObjectStore {
  constructor(
    private readonly transaction: FakeTransaction,
    private readonly records: Records,
    private readonly keyPath: string
  ) {}

  get(key: string) {
    return this.transaction.request(() => structuredClone(this.records.get(key)));
  }

  getAll() {
    return this.transaction.request(() => [...this.records.values()].map(v => structuredClone(v)));
  }

  put(value: Record<string, unknown>) {
    return this.transaction.request(() => {
      if (this.transaction.factory.failWrites) {
        throw new DOMException('The quota has been exceeded.', 'QuotaExceededError');
      }
      const key = value[this.keyPath] as string;
      this.records.set(key, structuredClone(value));
      return key;
    });
  }

  delete(key: string) {
    return this.transaction.request(() => {
      this.records.delete(key);
      return undefined;
    });
  }

  clear() {
    return this.transaction.request(() => {
      this.records.clear();
      return undefined;
    });
  }
}

class FakeTransaction {
  oncomplete: Handler = null;
  onerror: Handler = null;
  onabort: Handler = null;
  error: DOMException | null = null;
  private pending = 0;
  private finished = false;

  constructor(
    readonly factory: FakeIndexedDB,
    private readonly data: FakeDatabaseData,
    private readonly names: string[]
  ) {
    // a transaction without requests completes too
    setTimeout(() => this.settle(), 0);
  }

  objectStore(name: string) {
    if (!this.names.includes(name)) throw new DOMException(`No store ${name}`, 'NotFoundError');
    return new FakeObjectStore(this, this.data.stores.get(name)!, this.data.keyPaths.get(name)!);
  }

  request<T>(operation: () => T): FakeRequest<T> {
    if (this.finished)
      throw new DOMException('The transaction finished.', 'TransactionInactiveError');
    const request = new FakeRequest<T>();
    this.pending++;
    setTimeout(() => {
      if (this.finished) return;
      try {
        request.result = operation();
        request.onsuccess?.({ target: request });
      } catch (error) {
        request.error = error as DOMException;
        request.onerror?.({ target: request });
        this.error = request.error;
        this.finished = true;
        this.onerror?.({ target: this });
        this.onabort?.({ target: this });
        return;
      }
      this.pending--;
      this.settle();
    }, 0);
    return request;
  }

  private settle() {
    setTimeout(() => {
      if (this.finished || this.pending > 0) return;
      this.finished = true;
      this.oncomplete?.({ target: this });
    }, 0);
  }
}

interface FakeDatabaseData {
  version: number;
  stores: Map<string, Records>;
  keyPaths: Map<string, string>;
}

class FakeDatabase {
  onversionchange: Handler = null;
  onclose: Handler = null;
  closed = false;

  constructor(private readonly factory: FakeIndexedDB, private readonly data: FakeDatabaseData) {}

  get objectStoreNames() {
    const names = [...this.data.stores.keys()];
    return { contains: (name: string) => names.includes(name), length: names.length };
  }

  createObjectStore(name: string, options: { keyPath: string }) {
    this.data.stores.set(name, new Map());
    this.data.keyPaths.set(name, options.keyPath);
  }

  transaction(names: string | string[]) {
    if (this.closed) throw new DOMException('The database is closed.', 'InvalidStateError');
    const stores = typeof names === 'string' ? [names] : names;
    const unknown = stores.find(name => !this.data.stores.has(name));
    if (unknown) throw new DOMException(`No store ${unknown}`, 'NotFoundError');
    return new FakeTransaction(this.factory, this.data, stores);
  }

  close() {
    this.closed = true;
  }
}

/** An IndexedDB factory in memory; `failOpen`, `blockOpen` and `failWrites` make it refuse. */
export class FakeIndexedDB {
  readonly databases = new Map<string, FakeDatabaseData>();
  failOpen = false;
  blockOpen = false;
  failWrites = false;

  open(name: string, version = 1) {
    const request = new FakeOpenRequest();
    setTimeout(() => {
      if (this.blockOpen) {
        request.onblocked?.({ target: request });
        return;
      }
      if (this.failOpen) {
        request.error = new DOMException('The operation is insecure.', 'InvalidStateError');
        request.onerror?.({ target: request });
        return;
      }
      let data = this.databases.get(name);
      const upgrade = !data || data.version < version;
      data ??= { version, stores: new Map(), keyPaths: new Map() };
      data.version = version;
      this.databases.set(name, data);
      const db = new FakeDatabase(this, data);
      request.result = db;
      if (upgrade) request.onupgradeneeded?.({ target: request });
      request.onsuccess?.({ target: request });
    }, 0);
    return request;
  }

  /** The records of a store of a database, for tests to look at. */
  records(database: string, store: string): Map<string, any> {
    return (this.databases.get(database)?.stores.get(store) as Map<string, any>) ?? new Map();
  }
}

/** Installs a fake IndexedDB as the browser's, and returns it. */
export function installFakeIndexedDB(): FakeIndexedDB {
  const factory = new FakeIndexedDB();
  Object.defineProperty(globalThis, 'indexedDB', {
    value: factory,
    configurable: true,
    writable: true,
  });
  return factory;
}

/** Removes the fake IndexedDB, as in a browser without one. */
export function removeFakeIndexedDB() {
  Reflect.deleteProperty(globalThis, 'indexedDB');
}
