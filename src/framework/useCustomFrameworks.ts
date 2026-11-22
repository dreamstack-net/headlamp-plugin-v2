/*
  The custom frameworks of a cluster, with their controls: the ConfigMaps the plugin keeps in the
  Kubescape namespace, made in its framework editor or provided by the cluster's GitOps repository.
*/
import { useEffect, useState } from 'react';
import { listCustomObjectConfigMaps } from '../custom-objects/api-queries';
import type { Control, FrameWork } from '../rego';
import { customFrameworkOf } from './customFrameworks';

/** Reads the custom frameworks of a cluster, the current one by default. */
export async function fetchCustomFrameworks(
  controls: Control[],
  cluster?: string
): Promise<FrameWork[]> {
  const configMaps = await listCustomObjectConfigMaps('framework', cluster);
  return configMaps.flatMap(configMap => {
    const framework = customFrameworkOf(configMap, controls);
    return framework ? [framework] : [];
  });
}

/**
 * The custom frameworks of the current cluster, null while they are read. A cluster whose
 * frameworks cannot be read has none, as for the pages that only show their scores.
 */
export function useCustomFrameworks(controls: Control[]): FrameWork[] | null {
  const [found, setFound] = useState<FrameWork[] | null>(null);
  useEffect(() => {
    // the controls of the plugin are not read yet
    if (!controls?.length) return;
    let active = true;
    fetchCustomFrameworks(controls)
      .then(frameworks => active && setFound(frameworks))
      .catch(error => {
        console.error(error);
        if (active) setFound([]);
      });
    return () => {
      active = false;
    };
  }, [controls]);
  return found;
}
