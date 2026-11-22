import { post, put, request } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import { errorStatus } from '../common/errors';
import {
  GeneratedNetworkPolicy,
  NetworkPolicy,
} from '../softwarecomposition/GeneratedNetworkPolicy';
import { withoutPerPodSelectorLabels } from './layout';

export interface NetworkPolicyObject {
  apiVersion: 'networking.k8s.io/v1';
  kind: 'NetworkPolicy';
  metadata: {
    name: string;
    namespace: string;
    labels?: { [key: string]: string };
    annotations?: { [key: string]: string };
    resourceVersion?: string;
  };
  spec: GeneratedNetworkPolicy['spec']['spec'];
}

/*
  Kubescape copies the labels that differ per run, rollout or pod (job-name, pod-template-hash,
  the zone, the pod name of a StatefulSet) from the pods it saw: a policy that keeps them stops
  matching after the next run of a Job or rollout, so selectors are created without them
  (withoutPerPodSelectorLabels). A selector that would select every pod without them keeps them,
  as the policy would otherwise allow more.
*/

// The peers of a rule without the labels of a run; peers that are then the same are kept once
function stablePeers(peers: NetworkPolicy.Peer[] | undefined): NetworkPolicy.Peer[] | undefined {
  if (!peers) return peers;
  const unique = new Map<string, NetworkPolicy.Peer>();
  for (const peer of peers) {
    const stable = peer.podSelector
      ? { ...peer, podSelector: withoutPerPodSelectorLabels(peer.podSelector) }
      : peer;
    unique.set(JSON.stringify(stable), stable);
  }
  return [...unique.values()];
}

/** The NetworkPolicy that Kubescape generated, ready to create in the cluster. */
export function toNetworkPolicy(generated: GeneratedNetworkPolicy): NetworkPolicyObject {
  const metadata = generated.spec.metadata ?? {};
  return {
    apiVersion: 'networking.k8s.io/v1',
    kind: 'NetworkPolicy',
    metadata: {
      name: metadata.name ?? generated.metadata.name,
      namespace: metadata.namespace ?? generated.metadata.namespace,
      ...(metadata.labels && { labels: metadata.labels }),
      ...(metadata.annotations && { annotations: metadata.annotations }),
    },
    spec: stableSpec(generated.spec.spec),
  };
}

function stableSpec(spec: NetworkPolicy.NetworkPolicySpec): NetworkPolicy.NetworkPolicySpec {
  return {
    ...spec,
    ...(spec.podSelector && { podSelector: withoutPerPodSelectorLabels(spec.podSelector)! }),
    ...(spec.ingress && {
      ingress: spec.ingress.map(rule => ({ ...rule, from: stablePeers(rule.from) })),
    }),
    ...(spec.egress && {
      egress: spec.egress.map(rule => ({ ...rule, to: stablePeers(rule.to) })),
    }),
  };
}

function policyPath(namespace: string) {
  return `/apis/networking.k8s.io/v1/namespaces/${namespace}/networkpolicies`;
}

/** Returns the NetworkPolicy with the name of the given one, or null if there is none. */
export async function getExistingNetworkPolicy(
  policy: NetworkPolicyObject
): Promise<NetworkPolicyObject | null> {
  try {
    return await request(`${policyPath(policy.metadata.namespace)}/${policy.metadata.name}`);
  } catch (error) {
    if (errorStatus(error) === 404) return null;
    throw error;
  }
}

/** Creates the NetworkPolicy, or replaces the existing one with the same name. */
export async function applyNetworkPolicy(
  policy: NetworkPolicyObject,
  existing: NetworkPolicyObject | null
): Promise<void> {
  const path = policyPath(policy.metadata.namespace);
  if (existing) {
    const replacement = {
      ...policy,
      metadata: { ...policy.metadata, resourceVersion: existing.metadata.resourceVersion },
    };
    await put(`${path}/${policy.metadata.name}`, replacement as any);
  } else {
    await post(path, policy);
  }
}
