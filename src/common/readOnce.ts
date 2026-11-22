/*
  Reads data once, instead of watching it. Headlamp's useApiGet and useGet read an object and then
  watch it, and the Kubescape storage (spdx.softwarecomposition.kubescape.io) does not watch like
  the API server: its watch events carry the objects without the data of their spec, which then
  replaces what was read, and it refuses to watch the summaries of a namespace (405), after which
  Headlamp opens the watch again and again.
*/
import { KubeObjectClass } from '@kinvolk/headlamp-plugin/lib/k8s/KubeObject';
import { getCluster } from '@kinvolk/headlamp-plugin/lib/Utils';
import { useCallback, useEffect, useRef, useState } from 'react';
import { fetchObject } from '../model';

export interface ReadOnce<T> {
  /** What was read, null until it is read and after an error. */
  data: T | null;
  /** Why it could not be read, null when it was read or is being read for the first time. */
  error: unknown;
  /** Whether it is being read, also when it is read again. */
  loading: boolean;
  /** Reads it again; the data that was read stays until the new data arrives. */
  reload: () => void;
}

/**
 * Reads data with read, once for each key, and again when reload is called. A null key reads
 * nothing. What was read for another key is never returned, so a page does not show the object
 * of the URL it showed before. A read that finishes after the key changed, or after the
 * component was unmounted, is ignored.
 */
export function useReadOnce<T>(key: string | null, read: () => Promise<T>): ReadOnce<T> {
  // the read of the render that changed the key; it is not a reason to read again
  const readRef = useRef(read);
  readRef.current = read;
  const [reloads, setReloads] = useState(0);
  const [result, setResult] = useState<{
    key: string | null;
    data: T | null;
    error: unknown;
    loading: boolean;
  }>({ key: null, data: null, error: null, loading: false });

  useEffect(() => {
    if (key === null) return;
    let active = true;
    // the data and error of the same key stay while it is read again
    setResult(previous =>
      previous.key === key
        ? { ...previous, loading: true }
        : { key, data: null, error: null, loading: true }
    );
    let reading: Promise<T>;
    try {
      reading = Promise.resolve(readRef.current());
    } catch (error) {
      reading = Promise.reject(error);
    }
    reading.then(
      data => {
        if (active) setResult({ key, data, error: null, loading: false });
      },
      error => {
        if (active) setResult({ key, data: null, error, loading: false });
      }
    );
    return () => {
      active = false;
    };
  }, [key, reloads]);

  const reload = useCallback(() => setReloads(count => count + 1), []);
  if (key === null) return { data: null, error: null, loading: false, reload };
  if (result.key !== key) return { data: null, error: null, loading: true, reload };
  return { data: result.data, error: result.error, loading: result.loading, reload };
}

/**
 * Reads an object of the Kubescape storage once with a GET, in the given cluster (the current
 * one when undefined); see useReadOnce. Use this instead of useApiGet and useGet of the classes
 * of the storage, which watch the object after reading it. A null class reads nothing.
 */
export function useStorageObject<T = any>(
  objectClass: KubeObjectClass | null,
  name: string,
  namespace: string | undefined,
  cluster: string | undefined
): ReadOnce<T> {
  // a request without a cluster would not go to a cluster at all
  const target = cluster || getCluster() || '';
  const key = objectClass
    ? JSON.stringify([objectClass.pluralName, target, namespace ?? '', name])
    : null;
  return useReadOnce<T>(key, () =>
    fetchObject(name, namespace ?? '', target, objectClass as KubeObjectClass)
  );
}
