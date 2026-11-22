/*
  Reads what is needed to compare a generated network policy with the NetworkPolicies of the
  cluster: those policies, the labels of the workload's pods and of the pods it talks to.
*/
import { request } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import { useEffect, useRef, useState } from 'react';
import { errorMessage } from '../common/errors';
import { formatLabelSelector } from '../exceptions/apply-security-exceptions';
import {
  GeneratedNetworkPolicy,
  NetworkPolicy,
} from '../softwarecomposition/GeneratedNetworkPolicy';
import {
  ComparedWorkload,
  comparePolicies,
  Endpoint,
  namedPortKey,
  NamedPorts,
  namespaceNameLabel,
  ObservedFlow,
  PolicyComparison,
  selectorMatches,
} from './compare';
import { isAllPeers, policyPeers, sharedLabels, withoutPerPodLabels } from './layout';

// The paths of the workload kinds, with where their pod template is
const workloadPaths: Record<string, string> = {
  deployment: '/apis/apps/v1/namespaces/{namespace}/deployments/{name}',
  statefulset: '/apis/apps/v1/namespaces/{namespace}/statefulsets/{name}',
  daemonset: '/apis/apps/v1/namespaces/{namespace}/daemonsets/{name}',
  replicaset: '/apis/apps/v1/namespaces/{namespace}/replicasets/{name}',
  job: '/apis/batch/v1/namespaces/{namespace}/jobs/{name}',
  cronjob: '/apis/batch/v1/namespaces/{namespace}/cronjobs/{name}',
  pod: '/api/v1/namespaces/{namespace}/pods/{name}',
};

// Queries for the pods of peers; peers beyond them are matched with the labels of the
// generated policy
const maxPodQueries = 50;

interface PodLike {
  metadata?: { labels?: Record<string, string> };
  spec?: {
    containers?: { ports?: { name?: string; containerPort: number; protocol?: string }[] }[];
  };
  status?: { phase?: string };
}

/**
 * The numbers of the named ports of a pod by protocol and name, added to the ports given: two
 * containers, or the replicas of a rollout, may give a name other numbers.
 */
function namedPortsOf(pod: PodLike | undefined, ports: NamedPorts = {}): NamedPorts {
  for (const container of pod?.spec?.containers ?? []) {
    for (const port of container.ports ?? []) {
      if (!port.name) continue;
      const numbers = (ports[namedPortKey(port.protocol, port.name)] ??= []);
      if (!numbers.includes(port.containerPort)) numbers.push(port.containerPort);
    }
  }
  return ports;
}

/** The pod template of a workload, or the pod itself. */
function podTemplateOf(kind: string, object: any): PodLike | undefined {
  if (kind === 'pod') return object;
  if (kind === 'cronjob') return object?.spec?.jobTemplate?.spec?.template;
  return object?.spec?.template;
}

export function workloadOf(policy: GeneratedNetworkPolicy) {
  const labels = policy.metadata.labels ?? {};
  return {
    kind: (labels['kubescape.io/workload-kind'] ?? '').toLowerCase(),
    name: labels['kubescape.io/workload-name'] ?? '',
    namespace: labels['kubescape.io/workload-namespace'] ?? policy.metadata.namespace,
  };
}

/**
 * The traffic of the generated policy: one flow per peer and direction, without per-pod
 * labels, with the ports of all rules the peer is in, as the diagram shows the peers.
 */
export function observedFlows(policy: GeneratedNetworkPolicy): ObservedFlow[] {
  return policyPeers(policy).map(({ direction, peer, ports }) => ({
    direction,
    peer,
    ports,
    endpoints: [],
  }));
}

/**
 * The names of the namespaces of a peer: those its selector selects, or the workload's. Where
 * the namespaces could not be listed, only the namespace that the peer names is known, with its
 * labels when it could be read by name.
 */
function peerNamespaces(
  peer: NetworkPolicy.Peer,
  workloadNamespace: string,
  namespaceLabels: Map<string, Record<string, string>>,
  namespacesListed: boolean
): string[] {
  if (!peer.namespaceSelector) return [workloadNamespace];
  if (!namespacesListed) {
    const name = peer.namespaceSelector.matchLabels?.[namespaceNameLabel];
    if (!name) return [];
    const labels = namespaceLabels.get(name);
    return !labels || selectorMatches(peer.namespaceSelector, labels) ? [name] : [];
  }
  return [...namespaceLabels]
    .filter(([, labels]) => selectorMatches(peer.namespaceSelector, labels))
    .map(([namespace]) => namespace);
}

// The pods of a peer are looked up without the labels that differ per run or placement, unless
// the peer has no other labels, which would look up every pod of the namespace
function podQueryKey(namespace: string, peer: NetworkPolicy.Peer) {
  return JSON.stringify([namespace, withoutPerPodLabels(peer).podSelector]);
}

/**
 * The namespaces and label selectors to find the pods of the peers with. namespaceLabels holds
 * all namespaces, or, when they could not be listed, those that could be read by name.
 */
export function podQueries(
  flows: ObservedFlow[],
  workloadNamespace: string,
  namespaceLabels: Map<string, Record<string, string>>,
  namespacesListed = true
) {
  const queries = new Map<string, { namespace: string; selector: NetworkPolicy.LabelSelector }>();
  for (const { peer } of flows) {
    if (peer.ipBlock || !peer.podSelector) continue;
    const namespaces = peerNamespaces(peer, workloadNamespace, namespaceLabels, namespacesListed);
    for (const namespace of namespaces) {
      queries.set(podQueryKey(namespace, peer), {
        namespace,
        selector: withoutPerPodLabels(peer).podSelector!,
      });
    }
  }
  return queries;
}

/**
 * The pods or IP range of each flow. Pods are those that now have the labels of the peer,
 * without the labels that differ per run or placement; their own labels decide which policies
 * select them, as the generated policy names only some of them.
 */
export function resolveEndpoints(
  flows: ObservedFlow[],
  workloadNamespace: string,
  namespaceLabels: Map<string, Record<string, string>>,
  // the pods found per podQueryKey, null where they could not be read
  podsByQuery: Map<string, PodLike[] | null>,
  // whether namespaceLabels holds all namespaces, or else those that could be read by name
  namespacesListed = true
): ObservedFlow[] {
  // a namespace that could not be read is only known by its name, while a policy may select
  // namespaces by other labels: comparePolicies says when such a selector was compared
  const namespaceEndpoint = (namespace: string): Endpoint => ({
    namespace,
    namespaceLabels: namespaceLabels.get(namespace) ?? { [namespaceNameLabel]: namespace },
    ...(!namespacesListed && !namespaceLabels.has(namespace) && { namespaceLabelsUnknown: true }),
  });
  return flows.map(flow => {
    const { peer } = flow;
    if (isAllPeers(peer)) return { ...flow, endpoints: [{ anyPeer: true }] };
    if (peer.ipBlock) return { ...flow, endpoints: [{ cidr: peer.ipBlock.cidr }] };
    const namespaces = peerNamespaces(peer, workloadNamespace, namespaceLabels, namespacesListed);
    // no namespace has the labels of the peer now, or the namespaces cannot be listed: a
    // namespace with the labels of the generated policy is compared
    if (namespaces.length === 0 && peer.namespaceSelector) {
      return {
        ...flow,
        approximate: true,
        approximateReason: 'namespace',
        endpoints: [
          {
            namespaceLabels: peer.namespaceSelector.matchLabels ?? {},
            ...(peer.podSelector && { podLabels: peer.podSelector.matchLabels ?? {} }),
          },
        ],
      };
    }
    if (!peer.podSelector) return { ...flow, endpoints: namespaces.map(namespaceEndpoint) };
    const endpoints = new Map<string, Endpoint>();
    for (const namespace of namespaces) {
      for (const pod of podsByQuery.get(podQueryKey(namespace, peer)) ?? []) {
        const podLabels = pod.metadata?.labels ?? {};
        // replicas with the same labels count once, with the named ports of all of them, as
        // the replicas of a rollout may name other ports
        const key = JSON.stringify([namespace, sharedLabels(podLabels)]);
        const replica = endpoints.get(key);
        if (replica) {
          replica.namedPorts = namedPortsOf(pod, replica.namedPorts);
          continue;
        }
        endpoints.set(key, {
          ...namespaceEndpoint(namespace),
          podLabels,
          namedPorts: namedPortsOf(pod),
        });
      }
    }
    if (endpoints.size > 0) return { ...flow, endpoints: [...endpoints.values()] };
    // No pod was found: the pods of only so many peers are looked up, and a user may not read
    // the pods of every namespace, which is not the same as no pod having the labels
    const lookups = namespaces.map(namespace => podsByQuery.get(podQueryKey(namespace, peer)));
    let reason: ObservedFlow['approximateReason'];
    if (lookups.every(pods => pods === undefined)) reason = 'not-looked-up';
    else if (lookups.includes(null)) reason = 'pods-unreadable';
    return {
      ...flow,
      approximate: true,
      ...(reason && { approximateReason: reason }),
      endpoints: namespaces.map(namespace => ({
        ...namespaceEndpoint(namespace),
        podLabels: peer.podSelector?.matchLabels ?? {},
      })),
    };
  });
}

async function readItems(path: string, cluster: string): Promise<any[]> {
  const list = await request(path, cluster ? { cluster } : {});
  return list?.items ?? [];
}

/**
 * The namespaces that a user who may not list the namespaces can read by name, of the ones the
 * comparison needs the labels of: the workload's and those the peers name. A user of some
 * namespaces may read their own.
 */
async function readNamedNamespaces(
  flows: ObservedFlow[],
  workloadNamespace: string,
  cluster: string
): Promise<any[]> {
  const names = new Set([workloadNamespace]);
  for (const { peer } of flows) {
    const name = peer.namespaceSelector?.matchLabels?.[namespaceNameLabel];
    if (name) names.add(name);
  }
  const found = await Promise.all(
    [...names].map(name =>
      request(`/api/v1/namespaces/${encodeURIComponent(name)}`, cluster ? { cluster } : {}).catch(
        () => undefined
      )
    )
  );
  return found.filter(namespace => namespace?.metadata?.name);
}

/**
 * The pods of a workload that run now, read with its selector: their distinct labels, and the
 * named ports of their containers, which may be more than those of the template, such as the
 * ports of a sidecar that a webhook injects. 'no-selector' for a workload without a selector,
 * as a CronJob, and 'unreadable' when its pods cannot be read: its pod template is then all that
 * the policies are matched against.
 */
async function readLivePods(
  workloadObject: any,
  namespace: string,
  cluster: string
): Promise<
  { labels: Record<string, string>[]; namedPorts: NamedPorts } | 'no-selector' | 'unreadable'
> {
  const selector: NetworkPolicy.LabelSelector | undefined = workloadObject?.spec?.selector;
  const labelSelector = selector ? formatLabelSelector(selector) : '';
  // an empty selector would read every pod of the namespace
  if (!labelSelector) return 'no-selector';
  const pods: PodLike[] | undefined = await readItems(
    `/api/v1/namespaces/${namespace}/pods?labelSelector=${encodeURIComponent(labelSelector)}`,
    cluster
  ).catch(() => undefined);
  if (!pods) return 'unreadable';
  const distinct = new Map<string, Record<string, string>>();
  const namedPorts: NamedPorts = {};
  for (const pod of pods) {
    // a pod that ended has no traffic for a policy to restrict
    if (pod.status?.phase === 'Succeeded' || pod.status?.phase === 'Failed') continue;
    const labels = pod.metadata?.labels ?? {};
    distinct.set(JSON.stringify(Object.entries(labels).sort()), labels);
    namedPortsOf(pod, namedPorts);
  }
  return { labels: [...distinct.values()], namedPorts };
}

export interface ComparisonResult {
  comparison?: PolicyComparison;
  error?: string;
  // the workload's labels were taken from the generated policy
  approximateWorkload?: boolean;
  // the pods of the workload were not read, as a CronJob has no selector, or could not be read,
  // so the policies were matched against its pod template only
  podsNotRead?: 'no-selector' | 'unreadable';
}

/** Compares the generated policy with the NetworkPolicies of the workload's namespace. */
export async function readPolicyComparison(
  policy: GeneratedNetworkPolicy,
  cluster: string
): Promise<ComparisonResult> {
  const { kind, name, namespace } = workloadOf(policy);
  const path = workloadPaths[kind]
    ?.replace('{namespace}', encodeURIComponent(namespace))
    .replace('{name}', encodeURIComponent(name));
  const flows = observedFlows(policy);

  const [policies, allNamespaces, workloadObject] = await Promise.all([
    readItems(`/apis/networking.k8s.io/v1/namespaces/${namespace}/networkpolicies`, cluster),
    readItems('/api/v1/namespaces', cluster).catch(() => undefined),
    path ? request(path, cluster ? { cluster } : {}).catch(() => undefined) : undefined,
  ]);
  // without permission to list the namespaces, those of the comparison are read by name; a
  // namespace that cannot be read either is matched by its name only, which the flows say
  const namespacesListed = allNamespaces !== undefined;
  const namespaces = allNamespaces ?? (await readNamedNamespaces(flows, namespace, cluster));
  const namespaceLabels = new Map<string, Record<string, string>>(
    namespaces.map((ns: any) => [ns.metadata.name, ns.metadata.labels ?? {}])
  );
  const template = podTemplateOf(kind, workloadObject);

  const queries = [...podQueries(flows, namespace, namespaceLabels, namespacesListed)].slice(
    0,
    maxPodQueries
  );
  const [livePods, podLists] = await Promise.all([
    // a pod is its own template
    kind === 'pod' ? undefined : readLivePods(workloadObject, namespace, cluster),
    Promise.all(
      queries.map(([, query]) => {
        const labelSelector = encodeURIComponent(formatLabelSelector(query.selector));
        // null for pods that cannot be read, such as those of a namespace without access
        return readItems(
          `/api/v1/namespaces/${query.namespace}/pods?labelSelector=${labelSelector}`,
          cluster
        ).catch(() => null);
      })
    ),
  ]);
  const podsByQuery = new Map(queries.map(([key], index) => [key, podLists[index]]));
  const running = typeof livePods === 'object' ? livePods : undefined;
  const workload: ComparedWorkload = {
    namespace,
    podLabels: template?.metadata?.labels ?? policy.spec.spec.podSelector?.matchLabels ?? {},
    livePodLabels: running?.labels,
    namedPorts: namedPortsOf(template, running?.namedPorts),
  };

  return {
    comparison: comparePolicies(
      policies,
      workload,
      resolveEndpoints(flows, namespace, namespaceLabels, podsByQuery, namespacesListed)
    ),
    approximateWorkload: !template?.metadata?.labels,
    // said only of a workload that was read; else approximateWorkload says more
    ...(template?.metadata?.labels && typeof livePods === 'string' && { podsNotRead: livePods }),
  };
}

/**
 * The comparison of the generated policy with the NetworkPolicies, read once per policy, and
 * again when reload changes, such as after a NetworkPolicy was created; the comparison read
 * before is kept until then.
 */
export function usePolicyComparison(policy: GeneratedNetworkPolicy, cluster: string, reload = 0) {
  const [result, setResult] = useState<ComparisonResult | null>(null);
  // the policy and cluster of the comparison shown
  const shown = useRef<{ policy: GeneratedNetworkPolicy; cluster: string } | null>(null);
  useEffect(() => {
    let active = true;
    if (shown.current?.policy !== policy || shown.current?.cluster !== cluster) setResult(null);
    shown.current = { policy, cluster };
    readPolicyComparison(policy, cluster)
      .then(found => {
        if (active) setResult(found);
      })
      .catch(err => {
        if (active) setResult({ error: errorMessage(err) });
      });
    return () => {
      active = false;
    };
  }, [policy, cluster, reload]);
  return result;
}
