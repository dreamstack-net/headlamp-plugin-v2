export * from './FrameWork';
import type { FrameWork } from './FrameWork';
export * from './Control';
export * from './Rule';

export { useRegoData, RegoDataProvider } from './RegoDataProvider';

export const defaultFrameworkNames = ['cis-v1.10.0', 'MITRE', 'NSA'];

/**
 * The frameworks whose scores the Compliance page and the Overview show: the ones chosen in the
 * settings or the Frameworks menu. While none are chosen, as on a fresh install, the custom
 * frameworks the cluster marks as its defaults, or else Kubescape's defaults.
 */
export function activeFrameworkNames(
  activeFrameworks: string[] | undefined | null,
  customFrameworks?: FrameWork[] | null
): string[] {
  if (activeFrameworks && activeFrameworks.length > 0) return activeFrameworks;
  const clusterDefaults = (customFrameworks ?? [])
    .filter(framework => framework.isDefault)
    .map(framework => framework.name);
  return clusterDefaults.length > 0 ? clusterDefaults : defaultFrameworkNames;
}
