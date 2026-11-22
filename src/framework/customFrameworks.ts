/*
  Custom frameworks, which the plugin keeps as ConfigMaps in the Kubescape namespace.
*/
import type { Control, FrameWork } from '../rego';

/** The data of a ConfigMap of a custom framework, as the API returns it. */
interface CustomFrameworkConfigMap {
  metadata: { name: string; namespace?: string; labels?: Record<string, string> };
  data?: { name?: string; description?: string; controlsIDs?: string };
}

/**
 * The label that makes a custom framework one of the frameworks its cluster shows while the user
 * chose none, such as the frameworks an organisation provides through its GitOps repository.
 */
export const defaultFrameworkLabel = 'kubescape.io/default-framework';

export function isDefaultFramework(configMap: {
  metadata?: { labels?: Record<string, string> };
}): boolean {
  return configMap.metadata?.labels?.[defaultFrameworkLabel] === 'true';
}

/**
 * The control IDs of a custom framework. A ConfigMap edited by hand may hold anything, which
 * then gives a framework without controls instead of an error.
 */
export function parseControlIDs(controlsIDs: string | undefined, configMapName?: string): string[] {
  try {
    const parsed: unknown = JSON.parse(controlsIDs ?? '[]');
    if (Array.isArray(parsed)) return parsed.filter((id): id is string => typeof id === 'string');
  } catch {
    // reported below
  }
  console.error('Failed to parse controlsIDs for framework', configMapName);
  return [];
}

/** The custom framework of a ConfigMap, or undefined for a ConfigMap without a name. */
export function customFrameworkOf(
  configMap: CustomFrameworkConfigMap,
  controls: Control[]
): FrameWork | undefined {
  const data = configMap.data;
  if (!data?.name) return undefined;
  const ids = new Set(parseControlIDs(data.controlsIDs, configMap.metadata.name));
  return {
    name: data.name,
    description: data.description,
    controls: controls.filter(control => ids.has(control.controlID)),
    configmapManifestName: configMap.metadata.name,
    configmapNamespace: configMap.metadata.namespace,
    ...(isDefaultFramework(configMap) ? { isDefault: true } : {}),
  };
}
