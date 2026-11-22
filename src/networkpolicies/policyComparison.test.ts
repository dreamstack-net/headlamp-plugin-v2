import { act, renderHook, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { GeneratedNetworkPolicy } from '../softwarecomposition/GeneratedNetworkPolicy';
import {
  observedFlows,
  podQueries,
  readPolicyComparison,
  resolveEndpoints,
  usePolicyComparison,
} from './policyComparison';

const mocks = vi.hoisted(() => ({ request: vi.fn() }));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ request: mocks.request }));

const prometheus = {
  namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'monitoring' } },
  podSelector: {
    matchLabels: { 'app.kubernetes.io/name': 'prometheus', 'topology.kubernetes.io/zone': 'a' },
  },
};
const api = { podSelector: { matchLabels: { app: 'api' } } };
const gone = { podSelector: { matchLabels: { 'job-name': 'x-1', app: 'cleanup' } } };

const policy = {
  metadata: {
    name: 'deployment-db',
    namespace: 'shop',
    labels: {
      'kubescape.io/workload-kind': 'Deployment',
      'kubescape.io/workload-name': 'db',
      'kubescape.io/workload-namespace': 'shop',
    },
  },
  spec: {
    spec: {
      podSelector: { matchLabels: { app: 'db' } },
      ingress: [
        { from: [prometheus], ports: [{ protocol: 'TCP', port: 9187 }] },
        { from: [api, gone], ports: [{ protocol: 'TCP', port: 5432 }] },
      ],
      egress: [
        { to: [{ ipBlock: { cidr: '10.9.8.7/32' } }], ports: [{ protocol: 'TCP', port: 443 }] },
      ],
    },
  },
  policyRef: [],
} as unknown as GeneratedNetworkPolicy;

const namespaceLabels = new Map<string, Record<string, string>>([
  ['shop', { 'kubernetes.io/metadata.name': 'shop' }],
  ['monitoring', { 'kubernetes.io/metadata.name': 'monitoring', purpose: 'monitoring' }],
]);

const pod = (
  labels: Record<string, string>,
  ports: { name: string; containerPort: number; protocol?: string }[] = []
) => ({
  metadata: { labels },
  spec: { containers: [{ ports }] },
});

describe('resolveEndpoints', () => {
  const flows = observedFlows(policy);

  it('looks up the pods of peers without the labels that differ per placement', () => {
    expect([...podQueries(flows, 'shop', namespaceLabels).values()]).toEqual([
      {
        namespace: 'monitoring',
        selector: { matchLabels: { 'app.kubernetes.io/name': 'prometheus' } },
      },
      { namespace: 'shop', selector: { matchLabels: { app: 'api' } } },
      { namespace: 'shop', selector: { matchLabels: { app: 'cleanup' } } },
    ]);
  });

  it('keeps the labels of a peer that has only labels per run', () => {
    // without them, the query would list every pod of the namespace
    const onlyRun = {
      ...policy,
      spec: {
        spec: {
          podSelector: {},
          ingress: [{ from: [{ podSelector: { matchLabels: { 'job-name': 'backup-1' } } }] }],
        },
      },
    } as unknown as GeneratedNetworkPolicy;
    expect([...podQueries(observedFlows(onlyRun), 'shop', namespaceLabels).values()]).toEqual([
      { namespace: 'shop', selector: { matchLabels: { 'job-name': 'backup-1' } } },
    ]);
  });

  it('uses the labels of the pods found, once per set of labels, or those of the policy', () => {
    const queries = [...podQueries(flows, 'shop', namespaceLabels).keys()];
    const replica = { 'app.kubernetes.io/name': 'prometheus', 'prometheus-shard': '0' };
    const resolved = resolveEndpoints(
      flows,
      'shop',
      namespaceLabels,
      new Map([
        [
          queries[0],
          [
            pod({ ...replica, 'pod-template-hash': 'a' }, [
              { name: 'metrics', containerPort: 9090 },
            ]),
            // the replica of the next rollout gives the name another number, and names a port
            // for UDP
            pod({ ...replica, 'pod-template-hash': 'b' }, [
              { name: 'metrics', containerPort: 9091 },
              { name: 'metrics', containerPort: 9090 },
              { name: 'gossip', containerPort: 7946, protocol: 'UDP' },
            ]),
          ],
        ],
        [queries[1], [pod({ app: 'api', tier: 'backend' })]],
        // looked up, but no pod has the labels anymore
        [queries[2], []],
      ])
    );
    // the replicas of a rollout count once, with the named ports of all of them by protocol
    expect(resolved[0].endpoints).toEqual([
      {
        namespace: 'monitoring',
        namespaceLabels: namespaceLabels.get('monitoring'),
        podLabels: { ...replica, 'pod-template-hash': 'a' },
        namedPorts: { 'TCP/metrics': [9090, 9091], 'UDP/gossip': [7946] },
      },
    ]);
    expect(resolved[1].endpoints[0].podLabels).toEqual({ app: 'api', tier: 'backend' });
    // compared without the labels of its run, which no pod has anymore
    expect(resolved[2]).toMatchObject({
      approximate: true,
      endpoints: [{ namespace: 'shop', podLabels: { app: 'cleanup' } }],
    });
    expect(resolved[2].approximateReason).toBeUndefined();
    expect(resolved[3].endpoints).toEqual([{ cidr: '10.9.8.7/32' }]);
  });
});

describe('resolveEndpoints of peers it cannot find', () => {
  const flows = observedFlows(policy);

  it('says when the pods of a peer were not looked up', () => {
    const resolved = resolveEndpoints(flows, 'shop', namespaceLabels, new Map());
    expect(resolved[1]).toMatchObject({ approximate: true, approximateReason: 'not-looked-up' });
  });

  it('says when the pods of a peer could not be read, which is not that none has the labels', () => {
    const queries = [...podQueries(flows, 'shop', namespaceLabels).keys()];
    const resolved = resolveEndpoints(
      flows,
      'shop',
      namespaceLabels,
      // the pods of monitoring may not be read; no pod of shop has the labels of the Job now
      new Map([
        [queries[0], null],
        [queries[1], [pod({ app: 'api' })]],
        [queries[2], []],
      ])
    );
    expect(resolved[0]).toMatchObject({
      approximate: true,
      approximateReason: 'pods-unreadable',
      endpoints: [
        { namespace: 'monitoring', podLabels: { 'app.kubernetes.io/name': 'prometheus' } },
      ],
    });
    expect(resolved[1].approximate).toBeUndefined();
    expect(resolved[2]).toMatchObject({ approximate: true });
    expect(resolved[2].approximateReason).toBeUndefined();
  });

  it('knows a namespace only by its name when the namespaces cannot be listed', () => {
    // the namespace of the workload could be read by name, that of Prometheus could not
    const readByName = new Map([['shop', { 'kubernetes.io/metadata.name': 'shop', team: 'shop' }]]);
    expect(
      [...podQueries(flows, 'shop', readByName, false).values()].map(q => q.namespace)
    ).toEqual(['monitoring', 'shop', 'shop']);
    const queries = [...podQueries(flows, 'shop', readByName, false).keys()];
    const resolved = resolveEndpoints(
      flows,
      'shop',
      readByName,
      new Map([
        [queries[0], [pod({ 'app.kubernetes.io/name': 'prometheus' })]],
        [queries[1], [pod({ app: 'api' })]],
        [queries[2], []],
      ]),
      false
    );
    // a policy may select the namespace by labels that are not known; comparePolicies says
    // when one does
    expect(resolved[0]).toMatchObject({
      endpoints: [
        {
          namespace: 'monitoring',
          namespaceLabels: { 'kubernetes.io/metadata.name': 'monitoring' },
          namespaceLabelsUnknown: true,
          podLabels: { 'app.kubernetes.io/name': 'prometheus' },
        },
      ],
    });
    expect(resolved[0].approximate).toBeUndefined();
    // the labels of the workload's namespace are known
    expect(resolved[1].approximate).toBeUndefined();
    expect(resolved[1].endpoints[0].namespaceLabels).toEqual(readByName.get('shop'));
    expect(resolved[1].endpoints[0].namespaceLabelsUnknown).toBeUndefined();
  });

  it('does not take a namespace that was read by name and has other labels than the peer', () => {
    const peer = {
      namespaceSelector: {
        matchLabels: { 'kubernetes.io/metadata.name': 'monitoring', purpose: 'monitoring' },
      },
    };
    const renamed = {
      ...policy,
      spec: { spec: { podSelector: {}, ingress: [{ from: [peer] }] } },
    } as unknown as GeneratedNetworkPolicy;
    const readByName = new Map([['monitoring', { 'kubernetes.io/metadata.name': 'monitoring' }]]);
    const [resolved] = resolveEndpoints(
      observedFlows(renamed),
      'shop',
      readByName,
      new Map(),
      false
    );
    expect(resolved).toMatchObject({ approximate: true, approximateReason: 'namespace' });
  });

  it('compares the traffic of a rule without peers as that of a peer that is not known', () => {
    const noPeers = {
      ...policy,
      spec: { spec: { podSelector: {}, ingress: [{ ports: [{ protocol: 'TCP', port: 80 }] }] } },
    } as unknown as GeneratedNetworkPolicy;
    const flows = observedFlows(noPeers);
    expect(podQueries(flows, 'shop', namespaceLabels).size).toBe(0);
    expect(resolveEndpoints(flows, 'shop', namespaceLabels, new Map())).toEqual([
      {
        direction: 'ingress',
        peer: {},
        ports: [{ protocol: 'TCP', port: 80 }],
        endpoints: [{ anyPeer: true }],
      },
    ]);
  });

  it('compares a namespace with the labels of the peer when none has them now', () => {
    // the namespaces cannot be listed, and the peer selects them by a label
    const byTeam = {
      ...policy,
      spec: {
        spec: {
          podSelector: {},
          ingress: [{ from: [{ namespaceSelector: { matchLabels: { team: 'data' } } }] }],
        },
      },
    } as unknown as GeneratedNetworkPolicy;
    const [flow] = resolveEndpoints(observedFlows(byTeam), 'shop', new Map(), new Map());
    expect(flow).toMatchObject({
      approximate: true,
      approximateReason: 'namespace',
      endpoints: [{ namespaceLabels: { team: 'data' } }],
    });
  });
});

describe('readPolicyComparison', () => {
  it('compares with the policies of the namespace, using the pod template of the workload', async () => {
    mocks.request.mockImplementation(async (path: string) => {
      if (path.endsWith('/networkpolicies')) {
        return {
          items: [
            {
              metadata: { name: 'default-ingress', namespace: 'shop' },
              spec: {
                podSelector: { matchLabels: { tier: 'data' } },
                policyTypes: ['Ingress'],
                ingress: [{ from: [{ podSelector: {} }] }],
              },
            },
          ],
        };
      }
      if (path === '/api/v1/namespaces') {
        return {
          items: [...namespaceLabels].map(([name, labels]) => ({ metadata: { name, labels } })),
        };
      }
      if (path === '/apis/apps/v1/namespaces/shop/deployments/db') {
        return { spec: { template: { metadata: { labels: { app: 'db', tier: 'data' } } } } };
      }
      if (path.startsWith('/api/v1/namespaces/shop/pods?labelSelector=app%3Dapi')) {
        return { items: [pod({ app: 'api' })] };
      }
      return { items: [] };
    });

    const result = await readPolicyComparison(policy, 'prd');
    expect(result.approximateWorkload).toBe(false);
    expect(result.comparison!.selecting.map(p => p.metadata.name)).toEqual(['default-ingress']);
    expect(result.comparison!.flows.map(f => f.status)).toEqual([
      'blocked',
      'allowed',
      'allowed',
      'unrestricted',
    ]);
    expect(mocks.request).toHaveBeenCalledWith(
      '/apis/networking.k8s.io/v1/namespaces/shop/networkpolicies',
      { cluster: 'prd' }
    );
  });

  it('counts the policies that select labels only the pods of the workload have', async () => {
    const selecting = (name: string, matchLabels: Record<string, string>) => ({
      metadata: { name, namespace: 'shop' },
      spec: { podSelector: { matchLabels }, policyTypes: ['Ingress'] },
    });
    mocks.request.mockReset().mockImplementation(async (path: string) => {
      if (path.endsWith('/networkpolicies')) {
        return {
          items: [
            // a label an admission webhook adds, and the label of one rollout
            selecting('meshed', { mesh: 'on' }),
            selecting('first-rollout', { 'pod-template-hash': 'a' }),
            selecting('web', { app: 'web' }),
          ],
        };
      }
      if (path === '/apis/apps/v1/namespaces/shop/deployments/db') {
        return {
          spec: {
            selector: { matchLabels: { app: 'db' } },
            template: { metadata: { labels: { app: 'db' } } },
          },
        };
      }
      if (path === '/api/v1/namespaces/shop/pods?labelSelector=app%3Ddb') {
        return {
          items: [
            pod({ app: 'db', mesh: 'on', 'pod-template-hash': 'a' }),
            pod({ app: 'db', mesh: 'on', 'pod-template-hash': 'b' }),
            pod({ app: 'db', mesh: 'on', 'pod-template-hash': 'b' }),
            // a pod that ended is not one a policy restricts
            { ...pod({ app: 'db', 'pod-template-hash': 'c' }), status: { phase: 'Failed' } },
          ],
        };
      }
      return { items: [] };
    });

    const { comparison } = await readPolicyComparison(policy, 'prd');

    expect(comparison!.selecting.map(p => p.metadata.name)).toEqual(['meshed', 'first-rollout']);
    expect(comparison!.selectingSomePods.map(p => p.metadata.name)).toEqual(['first-rollout']);
    // the policies have no rules, so they deny the ingress that without them was unrestricted
    expect(comparison!.flows.map(f => f.status)).toEqual([
      'blocked',
      'blocked',
      'blocked',
      'unrestricted',
    ]);
  });

  it('matches the pod template when the pods of the workload cannot be read', async () => {
    mocks.request.mockReset().mockImplementation(async (path: string) => {
      if (path.endsWith('/networkpolicies')) {
        return {
          items: [
            {
              metadata: { name: 'db', namespace: 'shop' },
              spec: { podSelector: { matchLabels: { app: 'db' } }, policyTypes: ['Ingress'] },
            },
          ],
        };
      }
      if (path === '/apis/apps/v1/namespaces/shop/deployments/db') {
        return {
          spec: {
            selector: { matchLabels: { app: 'db' } },
            template: { metadata: { labels: { app: 'db' } } },
          },
        };
      }
      if (path.includes('/pods?')) throw Object.assign(new Error('forbidden'), { status: 403 });
      return { items: [] };
    });

    const { comparison, podsNotRead } = await readPolicyComparison(policy, 'prd');

    // which the page says
    expect(podsNotRead).toBe('unreadable');
    expect(comparison!.selecting.map(p => p.metadata.name)).toEqual(['db']);
    expect(comparison!.selectingSomePods).toEqual([]);
    // the pods of the peers could not be read either, which the flows say
    expect(comparison!.flows[1]).toMatchObject({
      approximate: true,
      approximateReason: 'pods-unreadable',
    });
  });

  it('allows the named ports of the pods that run, such as those of an injected sidecar', async () => {
    mocks.request.mockReset().mockImplementation(async (path: string) => {
      if (path.endsWith('/networkpolicies')) {
        return {
          items: [
            {
              metadata: { name: 'scrape-sidecar', namespace: 'shop' },
              spec: {
                podSelector: {},
                policyTypes: ['Ingress'],
                ingress: [{ ports: [{ protocol: 'TCP', port: 'http-envoy-prom' }] }],
              },
            },
          ],
        };
      }
      if (path === '/apis/apps/v1/namespaces/shop/deployments/db') {
        return {
          spec: {
            selector: { matchLabels: { app: 'db' } },
            template: { metadata: { labels: { app: 'db' } } },
          },
        };
      }
      if (path === '/api/v1/namespaces/shop/pods?labelSelector=app%3Ddb') {
        return {
          items: [pod({ app: 'db' }, [{ name: 'http-envoy-prom', containerPort: 9187 }])],
        };
      }
      return { items: [] };
    });

    const result = await readPolicyComparison(policy, 'prd');

    expect(result.podsNotRead).toBeUndefined();
    // the ingress from Prometheus on 9187 goes to the port only the pods name
    expect(result.comparison!.flows[0]).toMatchObject({
      status: 'allowed',
      allowedBy: ['scrape-sidecar'],
    });
  });

  it('says that the pods of a CronJob are not read, and matches those of a pod as they are', async () => {
    const ofKind = (kind: string, name: string) =>
      ({
        ...policy,
        metadata: {
          ...policy.metadata,
          labels: {
            'kubescape.io/workload-kind': kind,
            'kubescape.io/workload-name': name,
            'kubescape.io/workload-namespace': 'shop',
          },
        },
      } as unknown as GeneratedNetworkPolicy);
    mocks.request.mockReset().mockImplementation(async (path: string) => {
      if (path === '/apis/batch/v1/namespaces/shop/cronjobs/report') {
        return {
          spec: {
            jobTemplate: { spec: { template: { metadata: { labels: { app: 'report' } } } } },
          },
        };
      }
      if (path === '/api/v1/namespaces/shop/pods/debug') {
        return { metadata: { labels: { app: 'debug' } } };
      }
      return { items: [] };
    });

    expect((await readPolicyComparison(ofKind('CronJob', 'report'), 'prd')).podsNotRead).toBe(
      'no-selector'
    );
    // a pod is its own template
    expect((await readPolicyComparison(ofKind('Pod', 'debug'), 'prd')).podsNotRead).toBeUndefined();
  });

  it('reads the namespaces by name when they cannot be listed, and says what stays unknown', async () => {
    const forbidden = () => Object.assign(new Error('forbidden'), { status: 403 });
    mocks.request.mockReset().mockImplementation(async (path: string) => {
      if (path.endsWith('/networkpolicies')) {
        return {
          items: [
            {
              metadata: { name: 'by-namespace-labels', namespace: 'shop' },
              spec: {
                podSelector: {},
                policyTypes: ['Ingress'],
                ingress: [
                  { from: [{ namespaceSelector: { matchLabels: { purpose: 'monitoring' } } }] },
                  { from: [{ namespaceSelector: { matchLabels: { team: 'shop' } } }] },
                ],
              },
            },
          ],
        };
      }
      // a user of the namespace shop, who may read the pods of monitoring but not the namespace
      if (path === '/api/v1/namespaces' || path === '/api/v1/namespaces/monitoring') {
        throw forbidden();
      }
      if (path === '/api/v1/namespaces/shop') {
        return {
          metadata: {
            name: 'shop',
            labels: { 'kubernetes.io/metadata.name': 'shop', team: 'shop' },
          },
        };
      }
      if (path.startsWith('/api/v1/namespaces/monitoring/pods?')) {
        return { items: [pod({ 'app.kubernetes.io/name': 'prometheus' })] };
      }
      if (path.startsWith('/api/v1/namespaces/shop/pods?labelSelector=app%3Dapi')) {
        return { items: [pod({ app: 'api' })] };
      }
      return { items: [] };
    });

    const { comparison } = await readPolicyComparison(policy, 'prd');

    expect(mocks.request).toHaveBeenCalledWith('/api/v1/namespaces/shop', { cluster: 'prd' });
    expect(mocks.request).toHaveBeenCalledWith('/api/v1/namespaces/monitoring', {
      cluster: 'prd',
    });
    const [prometheusFlow, apiFlow] = comparison!.flows;
    // the labels of shop were read, so the rule that selects them allows its pods
    expect(apiFlow.status).toBe('allowed');
    expect(apiFlow.approximate).toBeUndefined();
    // whether monitoring has the label of the other rule is not known, which the status says
    expect(prometheusFlow).toMatchObject({
      status: 'blocked',
      approximate: true,
      approximateReason: 'namespace-labels',
    });
  });
});

describe('usePolicyComparison', () => {
  it('reads the comparison again when asked to reload, keeping the one read before', async () => {
    let policies: any[] = [];
    mocks.request.mockReset().mockImplementation(async (path: string) => {
      if (path.endsWith('/networkpolicies')) return { items: policies };
      return { items: [] };
    });
    const { result, rerender } = renderHook(
      ({ reload }) => usePolicyComparison(policy, 'prd', reload),
      { initialProps: { reload: 0 } }
    );
    await waitFor(() => expect(result.current?.comparison?.selecting).toEqual([]));
    const before = result.current;

    // a NetworkPolicy that selects the workload was created
    policies = [
      {
        metadata: { name: 'deployment-db', namespace: 'shop' },
        spec: { podSelector: { matchLabels: { app: 'db' } }, policyTypes: ['Ingress'] },
      },
    ];
    let reading!: () => void;
    const read = new Promise<void>(resolve => (reading = resolve));
    const answer = mocks.request.getMockImplementation()!;
    mocks.request.mockImplementation(async (path: string, options: any) => {
      await read;
      return answer(path, options);
    });
    rerender({ reload: 1 });
    expect(result.current).toBe(before);

    await act(async () => reading());
    await waitFor(() =>
      expect(result.current?.comparison?.selecting.map(p => p.metadata.name)).toEqual([
        'deployment-db',
      ])
    );
  });
});
