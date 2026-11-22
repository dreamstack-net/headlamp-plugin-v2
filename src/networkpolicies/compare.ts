/*
  Compares the traffic that Kubescape saw a workload use, which its generated network policy
  allows, with the NetworkPolicies in the cluster that select the workload.
*/
import { NetworkPolicy } from '../softwarecomposition/GeneratedNetworkPolicy';

export type Direction = 'ingress' | 'egress';

/**
 * The numbers of the named container ports of pods, by protocol and name (namedPortKey): a
 * rule names a port on its protocol, and containers or replicas may give a name other numbers.
 */
export type NamedPorts = Record<string, number[]>;

export function namedPortKey(protocol: string | undefined, name: string) {
  return `${protocol ?? 'TCP'}/${name}`;
}

export const namespaceNameLabel = 'kubernetes.io/metadata.name';

/**
 * One side of observed traffic: a pod, all pods of a namespace, an IP range, or any peer, for a
 * rule of the generated policy without peers.
 */
export interface Endpoint {
  namespace?: string;
  namespaceLabels?: Record<string, string>;
  // the labels of the namespace could not be read, so namespaceLabels only holds its name
  namespaceLabelsUnknown?: boolean;
  // the labels of the pod; without them, any pod of the namespace
  podLabels?: Record<string, string>;
  // the named container ports of the pod
  namedPorts?: NamedPorts;
  cidr?: string;
  // a peer that is not known: only a rule without peers surely allows it
  anyPeer?: boolean;
}

export interface ExistingPolicy {
  metadata: { name: string; namespace: string };
  spec: NetworkPolicy.NetworkPolicySpec;
}

export interface ComparedWorkload {
  namespace: string;
  // the labels of the pod template
  podLabels: Record<string, string>;
  // the distinct labels of the pods that run now, which also have the labels that controllers
  // and admission webhooks add; none when the pods were not read
  livePodLabels?: Record<string, string>[];
  namedPorts?: NamedPorts;
}

/** Traffic of the generated policy: one peer with the ports of all its rules. */
export interface ObservedFlow {
  direction: Direction;
  peer: NetworkPolicy.Peer;
  ports: NetworkPolicy.Port[];
  endpoints: Endpoint[];
  // the labels of the generated policy are used, as no pod has the labels of the peer anymore,
  // or for the reason given
  approximate?: boolean;
  // no namespace the peer selects could be found, its pods were not looked up or could not be
  // read, or the labels of its namespace could not be read, so only its name is compared with
  // namespace selectors that read other labels (set by comparePolicies)
  approximateReason?: 'namespace' | 'not-looked-up' | 'pods-unreadable' | 'namespace-labels';
}

// allowed by the policies that restrict the direction, by some of them, by none, the direction
// is not restricted, so all traffic is allowed, or the peer could not be resolved
export type FlowStatus = 'allowed' | 'partly' | 'blocked' | 'unrestricted' | 'unknown';

export interface FlowResult extends ObservedFlow {
  status: FlowStatus;
  // the names of the policies with a rule that allows the traffic
  allowedBy: string[];
}

export interface PolicyComparison {
  // the policies that select the pod template of the workload, or one of its pods
  selecting: ExistingPolicy[];
  // of those, the policies that do not select every pod of the workload that runs now
  selectingSomePods: ExistingPolicy[];
  // of the selecting policies, those that restrict each direction
  restricting: Record<Direction, ExistingPolicy[]>;
  flows: FlowResult[];
  // how many flows each rule allows, by ruleKey
  ruleUse: Map<string, number>;
}

export function ruleKey(policy: string, direction: Direction, index: number) {
  return JSON.stringify([policy, direction, index]);
}

/** Whether labels meet a label selector; an empty selector selects everything. */
export function selectorMatches(
  selector: NetworkPolicy.LabelSelector | undefined,
  labels: Record<string, string>
): boolean {
  for (const [key, value] of Object.entries(selector?.matchLabels ?? {})) {
    if (labels[key] !== value) return false;
  }
  for (const { key, operator, values = [] } of selector?.matchExpressions ?? []) {
    const has = key in labels;
    if (operator === 'In' && !(has && values.includes(labels[key]))) return false;
    if (operator === 'NotIn' && has && values.includes(labels[key])) return false;
    if (operator === 'Exists' && !has) return false;
    if (operator === 'DoesNotExist' && has) return false;
  }
  return true;
}

function isEmptySelector(selector: NetworkPolicy.LabelSelector) {
  return (
    Object.keys(selector.matchLabels ?? {}).length === 0 &&
    (selector.matchExpressions ?? []).length === 0
  );
}

/** The directions a policy restricts; without policyTypes, Egress only when it has rules. */
export function policyDirections(spec: NetworkPolicy.NetworkPolicySpec): Direction[] {
  const types = spec.policyTypes ?? ['Ingress', ...(spec.egress ? ['Egress' as const] : [])];
  return types.map(type => (type === 'Ingress' ? 'ingress' : 'egress'));
}

// an address range: the family, its first address and the number of bits of its prefix
interface ParsedCidr {
  family: 4 | 6;
  base: bigint;
  bits: number;
}

function parseIPv4Address(text: string): bigint | undefined {
  const match = text.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!match) return undefined;
  const octets = match.slice(1, 5).map(Number);
  if (octets.some(octet => octet > 255)) return undefined;
  return octets.reduce((value, octet) => value * BigInt(256) + BigInt(octet), BigInt(0));
}

function parseIPv6Address(text: string): bigint | undefined {
  let address = text.toLowerCase();
  // an IPv4 address in the last 32 bits, as in ::ffff:192.0.2.1
  const embedded = address.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (embedded) {
    const ipv4 = parseIPv4Address(embedded[2]);
    if (ipv4 === undefined) return undefined;
    const high = ipv4 / BigInt(65536);
    const low = ipv4 % BigInt(65536);
    address = `${embedded[1]}${high.toString(16)}:${low.toString(16)}`;
  }
  const halves = address.split('::');
  if (halves.length > 2) return undefined;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return undefined;
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...tail];
  let value = BigInt(0);
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return undefined;
    value = value * BigInt(65536) + BigInt(parseInt(group, 16));
  }
  return value;
}

/** An IPv4 or IPv6 range in CIDR notation; an address without a prefix is a range of one. */
export function parseCidr(cidr: string): ParsedCidr | undefined {
  const [address, prefix, ...rest] = cidr.trim().split('/');
  if (rest.length > 0 || (prefix !== undefined && !/^\d{1,3}$/.test(prefix))) return undefined;
  const ipv4 = parseIPv4Address(address);
  const family = ipv4 !== undefined ? 4 : 6;
  const value = ipv4 ?? parseIPv6Address(address);
  if (value === undefined) return undefined;
  const width = family === 4 ? 32 : 128;
  const bits = prefix === undefined ? width : Number(prefix);
  if (bits > width) return undefined;
  const size = BigInt(2) ** BigInt(width - bits);
  return { family, base: value - (value % size), bits };
}

/**
 * Whether the outer range holds all of the inner one. Ranges of the two address families never
 * hold each other: ::/0 is all of IPv6, not of IPv4.
 */
export function cidrContains(outer: string, inner: string): boolean {
  const a = parseCidr(outer);
  const b = parseCidr(inner);
  if (!a || !b) return outer === inner;
  if (a.family !== b.family || a.bits > b.bits) return false;
  const width = a.family === 4 ? 32 : 128;
  const size = BigInt(2) ** BigInt(width - a.bits);
  return b.base - (b.base % size) === a.base;
}

function cidrOverlaps(first: string, second: string) {
  return cidrContains(first, second) || cidrContains(second, first);
}

function ipBlockContains(ipBlock: NetworkPolicy.IPBlock, cidr: string) {
  return (
    cidrContains(ipBlock.cidr, cidr) &&
    !(ipBlock.except ?? []).some(excepted => cidrOverlaps(excepted, cidr))
  );
}

/**
 * Whether a peer of a policy in the namespace selects the endpoint. IP blocks are not matched
 * against pods: whether they apply to pod addresses depends on the network plugin.
 */
export function peerSelects(
  peer: NetworkPolicy.Peer,
  endpoint: Endpoint,
  policyNamespace: string
): boolean {
  if (peer.ipBlock) return !!endpoint.cidr && ipBlockContains(peer.ipBlock, endpoint.cidr);
  if (endpoint.cidr) return false;
  const inNamespace = peer.namespaceSelector
    ? selectorMatches(peer.namespaceSelector, endpoint.namespaceLabels ?? {})
    : endpoint.namespace === policyNamespace;
  if (!inNamespace) return false;
  if (!peer.podSelector) return true;
  return endpoint.podLabels
    ? selectorMatches(peer.podSelector, endpoint.podLabels)
    : isEmptySelector(peer.podSelector);
}

/**
 * Whether a port of a rule allows a port of the generated policy; a generated rule without a
 * port allows all ports. Named ports are those of the pod the traffic goes to, with the name on
 * the protocol of the rule: a port named dns for UDP is not one for TCP.
 */
export function portAllows(
  rulePort: NetworkPolicy.Port,
  observed: NetworkPolicy.Port | undefined,
  namedPorts: NamedPorts = {}
): boolean {
  if (!observed) return false;
  if ((rulePort.protocol ?? 'TCP') !== (observed.protocol ?? 'TCP')) return false;
  const allowed = rulePort.port as string | number | undefined;
  if (allowed === undefined) return true;
  if (observed.port === undefined) return false;
  const port = Number(observed.port);
  const number = typeof allowed === 'number' || /^\d+$/.test(allowed) ? Number(allowed) : undefined;
  if (number === undefined) {
    // a name, as a port that is no number
    return (namedPorts[namedPortKey(rulePort.protocol, String(allowed))] ?? []).includes(port);
  }
  return rulePort.endPort ? number <= port && port <= rulePort.endPort : number === port;
}

interface Rule {
  ports?: NetworkPolicy.Port[];
  peers?: NetworkPolicy.Peer[];
}

function rulesOf(spec: NetworkPolicy.NetworkPolicySpec, direction: Direction): Rule[] {
  return direction === 'ingress'
    ? (spec.ingress ?? []).map(rule => ({ ports: rule.ports, peers: rule.from }))
    : (spec.egress ?? []).map(rule => ({ ports: rule.ports, peers: rule.to }));
}

/**
 * Whether a namespace selector only reads the name of a namespace, which is known when its
 * other labels are not; an empty selector selects every namespace.
 */
function selectsByName(selector: NetworkPolicy.LabelSelector) {
  return [
    ...Object.keys(selector.matchLabels ?? {}),
    ...(selector.matchExpressions ?? []).map(({ key }) => key),
  ].every(key => key === namespaceNameLabel);
}

/** Compares the observed traffic of the workload with the policies of its namespace. */
export function comparePolicies(
  policies: ExistingPolicy[],
  workload: ComparedWorkload,
  flows: ObservedFlow[]
): PolicyComparison {
  // A policy selects the workload when it selects its pod template or one of its pods: pods also
  // have the labels that controllers and admission webhooks add, such as the pod name of a
  // StatefulSet or the labels of a service mesh, which a policy may select
  const livePods = workload.livePodLabels ?? [];
  const selects = (policy: ExistingPolicy, podLabels: Record<string, string>) =>
    selectorMatches(policy.spec.podSelector, podLabels);
  const selecting = policies.filter(
    policy =>
      policy.metadata.namespace === workload.namespace &&
      (selects(policy, workload.podLabels) || livePods.some(labels => selects(policy, labels)))
  );
  // of those, the policies that leave out some of the pods that run now: they count for the
  // whole workload, though they restrict only the pods they select
  const selectingSomePods = selecting.filter(
    policy => !livePods.every(labels => selects(policy, labels))
  );
  const restricting: Record<Direction, ExistingPolicy[]> = {
    ingress: selecting.filter(policy => policyDirections(policy.spec).includes('ingress')),
    egress: selecting.filter(policy => policyDirections(policy.spec).includes('egress')),
  };
  const ruleUse = new Map<string, number>();
  // whether a namespace selector of the policies of a direction reads labels other than the
  // name of a namespace
  const selectsByLabels = (direction: Direction) =>
    restricting[direction].some(policy =>
      rulesOf(policy.spec, direction).some(rule =>
        rule.peers?.some(
          peer => !peer.ipBlock && peer.namespaceSelector && !selectsByName(peer.namespaceSelector)
        )
      )
    );

  const results = flows.map((flow): FlowResult => {
    const policiesOfDirection = restricting[flow.direction];
    if (policiesOfDirection.length === 0) return { ...flow, status: 'unrestricted', allowedBy: [] };

    const allowedBy = new Set<string>();
    const usedRules = new Set<string>();
    // every port of every endpoint of the flow has to be allowed
    const ports: (NetworkPolicy.Port | undefined)[] = flow.ports.length ? flow.ports : [undefined];
    let allowed = 0;
    // ports of a peer that is not known, which only rules with peers allow
    let unsure = 0;
    let total = 0;
    for (const endpoint of flow.endpoints) {
      const namedPorts = flow.direction === 'ingress' ? workload.namedPorts : endpoint.namedPorts;
      for (const port of ports) {
        total++;
        let isAllowed = false;
        let mayBeAllowed = false;
        for (const policy of policiesOfDirection) {
          rulesOf(policy.spec, flow.direction).forEach((rule, index) => {
            const portAllowed =
              !rule.ports?.length ||
              rule.ports.some(rulePort => portAllows(rulePort, port, namedPorts));
            if (!portAllowed) return;
            if (endpoint.anyPeer && rule.peers?.length) {
              mayBeAllowed = true;
              return;
            }
            // a rule without peers or ports allows all of them
            const peerAllowed =
              !rule.peers?.length ||
              rule.peers.some(peer => peerSelects(peer, endpoint, policy.metadata.namespace));
            if (peerAllowed) {
              isAllowed = true;
              allowedBy.add(policy.metadata.name);
              usedRules.add(ruleKey(policy.metadata.name, flow.direction, index));
            }
          });
        }
        if (isAllowed) allowed++;
        else if (mayBeAllowed) unsure++;
      }
    }
    for (const key of usedRules) ruleUse.set(key, (ruleUse.get(key) ?? 0) + 1);
    // a peer without endpoints was not resolved, and one that is not known may be a peer of the
    // rules, which does not show that it is blocked
    let status: FlowStatus = 'unknown';
    if (total > 0 && unsure === 0) {
      status = allowed === total ? 'allowed' : allowed > 0 ? 'partly' : 'blocked';
    }
    // a namespace whose labels could not be read is known by its name only, which decides the
    // namespace selectors that select by name, but not the others
    const namespaceGuessed =
      !flow.approximateReason &&
      flow.endpoints.some(endpoint => endpoint.namespaceLabelsUnknown) &&
      selectsByLabels(flow.direction);
    return {
      ...flow,
      ...(namespaceGuessed && { approximate: true, approximateReason: 'namespace-labels' }),
      status,
      allowedBy: [...allowedBy],
    };
  });

  return { selecting, selectingSomePods, restricting, flows: results, ruleUse };
}
