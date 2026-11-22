import { describe, expect, it } from 'vitest';
import { NetworkPolicy } from '../softwarecomposition/GeneratedNetworkPolicy';
import {
  cidrContains,
  comparePolicies,
  ExistingPolicy,
  ObservedFlow,
  peerSelects,
  policyDirections,
  portAllows,
  ruleKey,
  selectorMatches,
} from './compare';

const In = NetworkPolicy.LabelSelectorOperator.In;
const NotIn = NetworkPolicy.LabelSelectorOperator.NotIn;
const Exists = NetworkPolicy.LabelSelectorOperator.Exists;
const DoesNotExist = NetworkPolicy.LabelSelectorOperator.DoesNotExist;

describe('selectorMatches', () => {
  const labels = { app: 'db', role: 'primary' };
  it('matches labels and expressions', () => {
    expect(selectorMatches({}, labels)).toBe(true);
    expect(selectorMatches({ matchLabels: { app: 'db' } }, labels)).toBe(true);
    expect(selectorMatches({ matchLabels: { app: 'web' } }, labels)).toBe(false);
    expect(
      selectorMatches(
        { matchExpressions: [{ key: 'role', operator: In, values: ['primary'] }] },
        labels
      )
    ).toBe(true);
    expect(
      selectorMatches(
        { matchExpressions: [{ key: 'role', operator: NotIn, values: ['primary'] }] },
        labels
      )
    ).toBe(false);
    expect(
      selectorMatches(
        { matchExpressions: [{ key: 'zone', operator: NotIn, values: ['a'] }] },
        labels
      )
    ).toBe(true);
    expect(selectorMatches({ matchExpressions: [{ key: 'app', operator: Exists }] }, labels)).toBe(
      true
    );
    expect(
      selectorMatches({ matchExpressions: [{ key: 'app', operator: DoesNotExist }] }, labels)
    ).toBe(false);
  });
});

describe('cidrContains', () => {
  it('compares IPv4 ranges', () => {
    expect(cidrContains('203.0.113.0/24', '203.0.113.20/32')).toBe(true);
    expect(cidrContains('203.0.113.0/24', '203.0.114.1/32')).toBe(false);
    expect(cidrContains('0.0.0.0/0', '10.0.0.1/32')).toBe(true);
    expect(cidrContains('10.0.0.0/24', '10.0.0.0/16')).toBe(false);
    expect(cidrContains('10.0.0.1', '10.0.0.1/32')).toBe(true);
  });

  it('compares IPv6 ranges', () => {
    expect(cidrContains('2001:db8::/32', '2001:db8::/32')).toBe(true);
    expect(cidrContains('::/0', '2001:db8::1/128')).toBe(true);
    expect(cidrContains('2001:db8::/32', '2001:db8::1/128')).toBe(true);
    expect(cidrContains('2001:db8::/32', '2001:db9::1/128')).toBe(false);
    expect(cidrContains('2001:0db8:0000::/48', '2001:db8:0:ffff::/64')).toBe(true);
    expect(cidrContains('fd00::/8', 'fdab:1234::5')).toBe(true);
    expect(cidrContains('::ffff:0:0/96', '::ffff:192.0.2.1')).toBe(true);
  });

  it('never matches ranges of the other address family', () => {
    expect(cidrContains('::/0', '203.0.113.20/32')).toBe(false);
    expect(cidrContains('0.0.0.0/0', '2001:db8::1/128')).toBe(false);
  });

  it('compares text it cannot read only with itself', () => {
    expect(cidrContains('not-a-range', 'not-a-range')).toBe(true);
    expect(cidrContains('10.0.0.0/33', '10.0.0.1')).toBe(false);
    expect(cidrContains('1:2:3:4:5:6:7:8::/64', '1::1')).toBe(false);
  });
});

describe('portAllows', () => {
  it('matches protocols, ports, ranges and named ports', () => {
    const tcp5432 = { protocol: 'TCP', port: 5432 as unknown as string };
    expect(portAllows({ port: 5432 as unknown as string }, tcp5432)).toBe(true);
    expect(portAllows({ protocol: 'UDP', port: '5432' }, tcp5432)).toBe(false);
    expect(portAllows({ protocol: 'TCP' }, tcp5432)).toBe(true);
    expect(portAllows({ port: '5000', endPort: 6000 }, tcp5432)).toBe(true);
    expect(portAllows({ port: '5000', endPort: 5400 }, tcp5432)).toBe(false);
    expect(portAllows({ port: 'postgresql' }, tcp5432, { 'TCP/postgresql': [5432] })).toBe(true);
    expect(portAllows({ port: 'postgresql' }, tcp5432)).toBe(false);
    // a generated rule without ports needs a rule without ports
    expect(portAllows({ port: '5432' }, undefined)).toBe(false);
  });

  it('resolves a named port on the protocol of the rule', () => {
    // CoreDNS names port 53 dns for UDP and dns-tcp for TCP
    const coreDns = { 'UDP/dns': [53], 'TCP/dns-tcp': [53] };
    const tcp53 = { protocol: 'TCP', port: 53 as unknown as string };
    const udp53 = { protocol: 'UDP', port: 53 as unknown as string };
    expect(portAllows({ protocol: 'UDP', port: 'dns' }, udp53, coreDns)).toBe(true);
    // without a protocol the rule is for TCP, which has no port named dns
    expect(portAllows({ port: 'dns' }, tcp53, coreDns)).toBe(false);
    expect(portAllows({ protocol: 'TCP', port: 'dns' }, tcp53, coreDns)).toBe(false);
    expect(portAllows({ protocol: 'TCP', port: 'dns-tcp' }, tcp53, coreDns)).toBe(true);
  });

  it('allows every number that containers or replicas give a named port', () => {
    const http8080 = { protocol: 'TCP', port: 8080 as unknown as string };
    const http9090 = { protocol: 'TCP', port: 9090 as unknown as string };
    const ports = { 'TCP/http': [8080, 9090] };
    expect(portAllows({ port: 'http' }, http8080, ports)).toBe(true);
    expect(portAllows({ port: 'http' }, http9090, ports)).toBe(true);
  });
});

describe('peerSelects', () => {
  const pod = {
    namespace: 'shop',
    namespaceLabels: { 'kubernetes.io/metadata.name': 'shop', purpose: 'monitoring' },
    podLabels: { app: 'prometheus' },
  };
  it('selects pods of the namespace of the policy, or of selected namespaces', () => {
    expect(peerSelects({ podSelector: {} }, pod, 'shop')).toBe(true);
    expect(peerSelects({ podSelector: {} }, pod, 'other')).toBe(false);
    expect(
      peerSelects({ namespaceSelector: { matchLabels: { purpose: 'monitoring' } } }, pod, 'other')
    ).toBe(true);
    expect(
      peerSelects(
        { namespaceSelector: {}, podSelector: { matchLabels: { app: 'grafana' } } },
        pod,
        'other'
      )
    ).toBe(false);
  });

  it('matches IP blocks against IP ranges only', () => {
    expect(peerSelects({ ipBlock: { cidr: '0.0.0.0/0' } }, pod, 'shop')).toBe(false);
    expect(peerSelects({ ipBlock: { cidr: '10.0.0.0/8' } }, { cidr: '10.1.2.3/32' }, 'shop')).toBe(
      true
    );
    expect(
      peerSelects(
        { ipBlock: { cidr: '10.0.0.0/8', except: ['10.1.0.0/16'] } },
        { cidr: '10.1.2.3/32' },
        'shop'
      )
    ).toBe(false);
    expect(peerSelects({ podSelector: {} }, { cidr: '10.1.2.3/32' }, 'shop')).toBe(false);
  });

  it('selects all pods of a namespace only with an empty pod selector', () => {
    const anyPod = { namespace: 'shop', namespaceLabels: {} };
    expect(peerSelects({ podSelector: {} }, anyPod, 'shop')).toBe(true);
    expect(peerSelects({ podSelector: { matchLabels: { app: 'x' } } }, anyPod, 'shop')).toBe(false);
  });
});

describe('policyDirections', () => {
  it('defaults to Ingress, and Egress when the policy has egress rules', () => {
    expect(policyDirections({ podSelector: {} })).toEqual(['ingress']);
    expect(policyDirections({ podSelector: {}, egress: [] })).toEqual(['ingress', 'egress']);
    expect(policyDirections({ podSelector: {}, policyTypes: ['Egress'] })).toEqual(['egress']);
  });
});

// The policies of a namespace with a database, after a real cluster
const policies: ExistingPolicy[] = [
  {
    metadata: { name: 'default-ingress', namespace: 'shop' },
    spec: {
      podSelector: {},
      policyTypes: ['Ingress'],
      ingress: [
        { from: [{ podSelector: {} }] },
        { from: [{ namespaceSelector: { matchLabels: { purpose: 'monitoring' } } }] },
      ],
    },
  },
  {
    metadata: { name: 'db-allow-operator', namespace: 'shop' },
    spec: {
      podSelector: { matchLabels: { 'cnpg.io/cluster': 'db' } },
      policyTypes: ['Ingress'],
      ingress: [
        {
          from: [
            {
              namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'cnpg-system' } },
            },
          ],
          ports: [{ protocol: 'TCP', port: 8000 as unknown as string }],
        },
        {
          from: [{ ipBlock: { cidr: '203.0.113.0/24' } }],
        },
      ],
    },
  },
  {
    metadata: { name: 'web-only', namespace: 'shop' },
    spec: { podSelector: { matchLabels: { app: 'web' } }, policyTypes: ['Ingress', 'Egress'] },
  },
];

const namespaceOf = (name: string, labels: Record<string, string> = {}) => ({
  namespace: name,
  namespaceLabels: { 'kubernetes.io/metadata.name': name, ...labels },
});

const flow = (
  direction: 'ingress' | 'egress',
  endpoints: ObservedFlow['endpoints'],
  port?: number
): ObservedFlow => ({
  direction,
  peer: {},
  ports: port ? [{ protocol: 'TCP', port: port as unknown as string }] : [],
  endpoints,
});

describe('comparePolicies', () => {
  const workload = { namespace: 'shop', podLabels: { 'cnpg.io/cluster': 'db' } };
  const flows = [
    flow('ingress', [{ ...namespaceOf('shop'), podLabels: { app: 'api' } }], 5432),
    flow('ingress', [{ ...namespaceOf('cnpg-system'), podLabels: { app: 'cnpg' } }], 8000),
    flow(
      'ingress',
      [{ ...namespaceOf('monitoring', { purpose: 'monitoring' }), podLabels: {} }],
      9187
    ),
    flow('ingress', [{ ...namespaceOf('other'), podLabels: { job: 'x' } }], 5432),
    flow(
      'ingress',
      [
        { ...namespaceOf('shop'), podLabels: { app: 'a' } },
        { ...namespaceOf('other'), podLabels: { app: 'b' } },
      ],
      5432
    ),
    flow('ingress', [{ cidr: '203.0.113.20/32' }], 8080),
    flow('egress', [{ ...namespaceOf('kube-system'), podLabels: { 'k8s-app': 'kube-dns' } }], 53),
  ];

  it('finds the policies that select the workload, per direction', () => {
    const result = comparePolicies(policies, workload, flows);
    expect(result.selecting.map(p => p.metadata.name)).toEqual([
      'default-ingress',
      'db-allow-operator',
    ]);
    expect(result.restricting.egress).toEqual([]);
  });

  it('tells which observed traffic the policies allow, and with which rules', () => {
    const result = comparePolicies(policies, workload, flows);
    expect(result.flows.map(f => [f.status, f.allowedBy])).toEqual([
      ['allowed', ['default-ingress']],
      ['allowed', ['db-allow-operator']],
      ['allowed', ['default-ingress']],
      ['blocked', []],
      ['partly', ['default-ingress']],
      ['allowed', ['db-allow-operator']],
      ['unrestricted', []],
    ]);
    expect(Object.fromEntries(result.ruleUse)).toEqual({
      '["default-ingress","ingress",0]': 2,
      '["default-ingress","ingress",1]': 1,
      '["db-allow-operator","ingress",0]': 1,
      '["db-allow-operator","ingress",1]': 1,
    });
  });

  it('denies all traffic of a direction that a policy without rules restricts', () => {
    const result = comparePolicies(
      policies,
      { namespace: 'shop', podLabels: { app: 'web' } },
      flows
    );
    expect(result.restricting.egress.map(p => p.metadata.name)).toEqual(['web-only']);
    expect(result.flows[6].status).toBe('blocked');
    // its ingress is still allowed by the rules of the other policies
    expect(result.flows[0]).toMatchObject({ status: 'allowed', allowedBy: ['default-ingress'] });
  });

  it('does not call traffic of a peer that could not be resolved blocked', () => {
    const result = comparePolicies(policies, workload, [flow('ingress', [], 5432)]);
    expect(result.flows[0].status).toBe('unknown');
  });

  it('leaves the traffic unrestricted without policies that select the workload', () => {
    const result = comparePolicies(policies, { namespace: 'other', podLabels: {} }, flows);
    expect(result.selecting).toEqual([]);
    expect(new Set(result.flows.map(f => f.status))).toEqual(new Set(['unrestricted']));
  });
});

describe('comparePolicies with the labels of the pods that run', () => {
  // the pods of a StatefulSet in a service mesh: the controller and the mesh add labels that
  // its pod template does not have
  const template = { app: 'db' };
  const pod = (index: number) => ({
    ...template,
    'security.istio.io/tlsMode': 'istio',
    'statefulset.kubernetes.io/pod-name': `db-${index}`,
  });
  const policy = (name: string, podSelector: NetworkPolicy.LabelSelector): ExistingPolicy => ({
    metadata: { name, namespace: 'shop' },
    spec: { podSelector, policyTypes: ['Ingress'] },
  });
  const meshed = policy('meshed', { matchLabels: { 'security.istio.io/tlsMode': 'istio' } });
  const firstPod = policy('db-0-only', {
    matchLabels: { 'statefulset.kubernetes.io/pod-name': 'db-0' },
  });
  const notMeshed = policy('not-meshed', {
    matchExpressions: [{ key: 'security.istio.io/tlsMode', operator: DoesNotExist }],
  });
  const other = policy('other', { matchLabels: { app: 'web' } });
  const ingress = [flow('ingress', [{ ...namespaceOf('shop'), podLabels: { app: 'api' } }], 5432)];

  it('finds the policies that select a label only the pods have', () => {
    const result = comparePolicies(
      [meshed, firstPod, other],
      { namespace: 'shop', podLabels: template, livePodLabels: [pod(0), pod(1)] },
      ingress
    );
    expect(result.selecting.map(p => p.metadata.name)).toEqual(['meshed', 'db-0-only']);
    // neither policy has a rule, so the ingress of the pods they select is denied
    expect(result.flows[0].status).toBe('blocked');
  });

  it('names the policies that do not select every pod that runs', () => {
    const result = comparePolicies(
      [meshed, firstPod, notMeshed],
      { namespace: 'shop', podLabels: template, livePodLabels: [pod(0), pod(1)] },
      ingress
    );
    // one selects only db-0, the other the pod template but no pod of the mesh
    expect(result.selectingSomePods.map(p => p.metadata.name)).toEqual(['db-0-only', 'not-meshed']);
  });

  it('matches the pod template alone when the pods were not read', () => {
    const result = comparePolicies(
      [meshed, firstPod, notMeshed],
      { namespace: 'shop', podLabels: template },
      ingress
    );
    expect(result.selecting.map(p => p.metadata.name)).toEqual(['not-meshed']);
    expect(result.selectingSomePods).toEqual([]);
  });
});

describe('comparePolicies with traffic whose peer the generated policy does not name', () => {
  const restrict = (
    name: string,
    ingress: NetworkPolicy.NetworkPolicySpec['ingress']
  ): ExistingPolicy => ({
    metadata: { name, namespace: 'shop' },
    spec: { podSelector: {}, policyTypes: ['Ingress'], ingress },
  });
  const tcp = (port: number) => ({ protocol: 'TCP', port: port as unknown as string });
  const workload = { namespace: 'shop', podLabels: { app: 'db' } };
  const anyPeer = [flow('ingress', [{ anyPeer: true }], 5432)];

  it('calls it allowed by a rule without peers', () => {
    const result = comparePolicies(
      [restrict('open-db', [{ ports: [tcp(5432)] }])],
      workload,
      anyPeer
    );
    expect(result.flows[0]).toMatchObject({ status: 'allowed', allowedBy: ['open-db'] });
    expect(result.ruleUse.get(ruleKey('open-db', 'ingress', 0))).toBe(1);
  });

  it('does not know whether a rule with peers allows it', () => {
    const fromApi = { podSelector: { matchLabels: { app: 'api' } } };
    const result = comparePolicies(
      [restrict('from-api', [{ from: [fromApi], ports: [tcp(5432)] }])],
      workload,
      anyPeer
    );
    expect(result.flows[0]).toMatchObject({ status: 'unknown', allowedBy: [] });
  });

  it('calls it blocked when no rule allows its ports', () => {
    const result = comparePolicies(
      [restrict('web', [{ ports: [tcp(80)] }, { from: [{ podSelector: {} }], ports: [tcp(443)] }])],
      workload,
      anyPeer
    );
    expect(result.flows[0].status).toBe('blocked');
  });
});

describe('comparePolicies with a namespace whose labels could not be read', () => {
  const restrictFrom = (...from: NetworkPolicy.Peer[]): ExistingPolicy => ({
    metadata: { name: 'restrict', namespace: 'shop' },
    spec: { podSelector: {}, policyTypes: ['Ingress'], ingress: [{ from }] },
  });
  const workload = { namespace: 'shop', podLabels: { app: 'db' } };
  const monitoring = { ...namespaceOf('monitoring'), namespaceLabelsUnknown: true };
  const flows = [flow('ingress', [monitoring], 9090)];

  it('says so when a namespace selector reads other labels than the name', () => {
    const result = comparePolicies(
      [restrictFrom({ namespaceSelector: { matchLabels: { purpose: 'monitoring' } } })],
      workload,
      flows
    );
    expect(result.flows[0]).toMatchObject({
      status: 'blocked',
      approximate: true,
      approximateReason: 'namespace-labels',
    });
  });

  it('does not when the selectors read only the name, or no selector reads namespaces', () => {
    for (const [peer, status] of [
      [
        { namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'monitoring' } } },
        'allowed',
      ],
      [
        {
          namespaceSelector: {
            matchExpressions: [
              { key: 'kubernetes.io/metadata.name', operator: In, values: ['monitoring'] },
            ],
          },
        },
        'allowed',
      ],
      // every namespace
      [{ namespaceSelector: {} }, 'allowed'],
      // pods of the namespace of the policy
      [{ podSelector: {} }, 'blocked'],
      [{ ipBlock: { cidr: '10.0.0.0/8' } }, 'blocked'],
    ] as [NetworkPolicy.Peer, string][]) {
      const [result] = comparePolicies([restrictFrom(peer)], workload, flows).flows;
      expect(result.status).toBe(status);
      expect(result.approximate).toBeUndefined();
    }
  });

  it('keeps the reason a flow is compared approximately for', () => {
    const byLabels = restrictFrom({ namespaceSelector: { matchLabels: { purpose: 'x' } } });
    const unreadable: ObservedFlow = {
      ...flows[0],
      approximate: true,
      approximateReason: 'pods-unreadable',
    };
    // no pod has the labels now, which says less than that the namespace was guessed
    const noPod: ObservedFlow = { ...flows[0], approximate: true };
    const result = comparePolicies([byLabels], workload, [unreadable, noPod]);
    expect(result.flows.map(f => f.approximateReason)).toEqual([
      'pods-unreadable',
      'namespace-labels',
    ]);
  });
});
