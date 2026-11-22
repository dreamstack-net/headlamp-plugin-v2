// The answers of the lookups of image versions, kept a day: in memory, and in localStorage when
// they are small.
import { LookupStopped } from './versionRequests';

const day = 24 * 3600 * 1000;
// a service that failed is asked again after an hour
const retryAfter = 3600 * 1000;
const storageName = 'kubescape-plugin.image-versions.';
// raised when lookups change, so that answers of the old lookups are not used
const storageVersion = 11;
const storagePrefix = `${storageName}${storageVersion}.`;

const memory = new Map<string, { expires: number; value: Promise<unknown> }>();
let pruned = false;

/** Forgets the answers kept in memory; the tests start from nothing. */
export function clearCachedLookups() {
  memory.clear();
  pruned = false;
}

function storage(): Storage | undefined {
  try {
    return window.localStorage;
  } catch {
    return undefined;
  }
}

function pruneStorage(now: number) {
  const store = storage();
  if (!store) return;
  try {
    for (let i = store.length - 1; i >= 0; i--) {
      const key = store.key(i);
      if (!key?.startsWith(storageName)) continue;
      const at = key.startsWith(storagePrefix) && JSON.parse(store.getItem(key) ?? '{}')?.at;
      if (typeof at !== 'number' || now - at >= day || at > now) store.removeItem(key);
    }
  } catch {
    // nothing to clean up in a full or blocked storage
  }
}

function readStored(key: string, now: number): { at: number; value: unknown } | undefined {
  try {
    const stored = JSON.parse(storage()?.getItem(storagePrefix + key) ?? 'null');
    if (typeof stored?.at !== 'number' || now - stored.at >= day || stored.at > now) {
      return undefined;
    }
    return { at: stored.at, value: stored.value ?? null };
  } catch {
    return undefined;
  }
}

function writeStored(key: string, value: unknown, now: number) {
  try {
    storage()?.setItem(storagePrefix + key, JSON.stringify({ at: now, value }));
  } catch {
    // the answer is still kept in memory
  }
}

/**
 * The answer of a lookup, kept a day: in memory, and in localStorage when it is small. A lookup
 * that throws keeps throwing for an hour, without asking the service again, so that lookups
 * built on it are not stored either.
 */
export function cached<T>(
  key: string,
  load: () => Promise<T | null>,
  options: { persist?: boolean; now?: number } = {}
): Promise<T | null> {
  const now = options.now ?? Date.now();
  const entry = memory.get(key);
  if (entry && now < entry.expires) return entry.value as Promise<T | null>;
  if (options.persist) {
    if (!pruned) {
      pruned = true;
      pruneStorage(now);
    }
    const stored = readStored(key, now);
    if (stored) {
      const value = Promise.resolve(stored.value as T | null);
      memory.set(key, { expires: stored.at + day, value });
      return value;
    }
  }
  const value = load().then(
    result => {
      if (options.persist) writeStored(key, result ?? null, now);
      return result ?? null;
    },
    error => {
      if (error instanceof LookupStopped) {
        // nothing failed, so the next lookup asks again
        if (memory.get(key)?.value === value) memory.delete(key);
      } else {
        // the failure is not stored, nor an answer built on it
        memory.set(key, { expires: now + retryAfter, value });
      }
      throw error;
    }
  );
  value.catch(() => {});
  memory.set(key, { expires: now + day, value });
  return value;
}
