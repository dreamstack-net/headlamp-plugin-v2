// The namespace of Kubescape, where the chart installs its default rules and where new Rules
// objects go by default.
import { useKubescapeNamespace } from '../custom-objects/api-queries';
import { DEFAULT_NAMESPACE } from './ruleDefaults';

/**
 * The namespace Kubescape runs in, in a cluster, the current one by default: the chart's default
 * namespace until it is found, or when it cannot be found. It is looked up once per session.
 */
export function useRulesNamespace(cluster?: string | null): string {
  return useKubescapeNamespace(cluster).kubeScapeNamespace || DEFAULT_NAMESPACE;
}

export interface RulesMetadata {
  name?: string;
  namespace?: string;
  labels?: Record<string, string>;
}

/**
 * Whether a Rules object is the default-rules of the Kubescape chart, which Helm manages: it is
 * installed in the namespace of Kubescape, with the labels of the chart.
 */
export function isChartDefaultRules(
  metadata: RulesMetadata | undefined,
  kubescapeNamespace: string
): boolean {
  if (metadata?.name !== 'default-rules') return false;
  return (
    metadata.namespace === kubescapeNamespace ||
    (metadata.labels?.['app.kubernetes.io/managed-by'] === 'Helm' &&
      metadata.labels?.['app.kubernetes.io/part-of'] === 'kubescape')
  );
}
