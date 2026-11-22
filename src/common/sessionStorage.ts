import { Dispatch, SetStateAction, useEffect, useState } from 'react';

export enum KubescapeSettings {
  ClusterComparisonFilter,
  ClusterComparisonTab,
  ComplianceTab,
  FailedControls,
  FixedCVEs,
  KubescapeNamespace,
  RelevantCVEs,
  VulnerabilityTab,
}

export function useSessionStorage<T>(
  key: KubescapeSettings,
  defaultValue: T
): [T, Dispatch<SetStateAction<T>>] {
  const [value, setValue] = useState<T>(() => {
    return getItemFromSessionStorage(key) ?? defaultValue;
  });

  useEffect(() => {
    setItemInSessionStorage(key, value);
  }, [key, value]);

  return [value, setValue];
}

/**
 * Keeps a setting for the session. false and 0 are kept too, as they differ from the default of
 * settings such as the Failed controls switch, which is on unless the user switched it off.
 */
export function setItemInSessionStorage<T>(key: KubescapeSettings, value: T) {
  const storageKey = `kubescape.${KubescapeSettings[key]}`;
  try {
    if (value === null || value === undefined) {
      window.sessionStorage.removeItem(storageKey);
    } else {
      window.sessionStorage.setItem(storageKey, JSON.stringify(value));
    }
  } catch {
    // the setting is not kept when the storage is not available
  }
}

export function getItemFromSessionStorage<T>(key: KubescapeSettings): T | null {
  const storageKey = `kubescape.${KubescapeSettings[key]}`;
  try {
    const saved = window.sessionStorage.getItem(storageKey);
    return saved === null ? null : (JSON.parse(saved) as T);
  } catch {
    return null;
  }
}
