import { cleanup, render, screen } from '@testing-library/react';
import type { ReactNode } from 'react';
import { vi } from 'vitest';
import type { GeneratedNetworkPolicy } from '../softwarecomposition/GeneratedNetworkPolicy';
import { comparePolicies, ExistingPolicy, ObservedFlow } from './compare';
import { ExistingPolicies, peerText } from './ExistingPolicies';
import { createNodes } from './layout';
import { nodeFlowStatuses } from './nodes';
import { portsText } from './ports';

vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', () => ({
  Link: ({ children, routeName, params }: any) => (
    <a href={`/${routeName}/${params.namespace}/${params.name}`}>{children}</a>
  ),
  Table: ({ data, columns }: any) => (
    <table>
      <tbody>
        {data.map((item: any, i: number) => (
          <tr key={i}>
            {columns.map((col: any, j: number) => (
              <td key={j}>
                {col.Cell
                  ? col.Cell({ row: { original: item } })
                  : (col.accessorFn(item) as ReactNode)}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  ),
}));
afterEach(cleanup);

const api = { podSelector: { matchLabels: { app: 'api' } } };
const job = {
  namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'jobs' } },
  podSelector: { matchLabels: { app: 'job' } },
};
const generated = {
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
      ingress: [{ from: [api, job], ports: [{ protocol: 'TCP', port: 5432 }] }],
    },
  },
  policyRef: [],
} as unknown as GeneratedNetworkPolicy;

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
];

const flows: ObservedFlow[] = [
  {
    direction: 'ingress',
    peer: api,
    ports: [{ protocol: 'TCP', port: '5432' }],
    endpoints: [{ namespace: 'shop', namespaceLabels: {}, podLabels: { app: 'api' } }],
  },
  {
    direction: 'ingress',
    peer: job,
    ports: [{ protocol: 'TCP', port: '5432' }],
    endpoints: [{ namespace: 'jobs', namespaceLabels: {}, podLabels: { app: 'job' } }],
    approximate: true,
  },
];
const comparison = comparePolicies(
  policies,
  { namespace: 'shop', podLabels: { app: 'db' } },
  flows
);

it('describes peers and ports as a policy selects them', () => {
  expect(peerText(api, 'shop')).toBe('pods with app=api in namespace shop');
  expect(peerText(job, 'shop')).toBe('pods with app=job in namespace jobs');
  expect(peerText({ namespaceSelector: { matchLabels: { purpose: 'monitoring' } } }, 'shop')).toBe(
    'all pods in namespaces with purpose=monitoring'
  );
  expect(peerText({ namespaceSelector: {}, podSelector: {} }, 'shop')).toBe(
    'all pods in all namespaces'
  );
  expect(peerText({ ipBlock: { cidr: '10.0.0.0/8', except: ['10.1.0.0/16'] } }, 'shop')).toBe(
    '10.0.0.0/8 except 10.1.0.0/16'
  );
  expect(portsText(undefined)).toBe('all ports');
  expect(
    portsText([
      { port: '8000', endPort: 8010 },
      { protocol: 'UDP', port: '53' },
    ])
  ).toBe('TCP:8000-8010, UDP:53');
});

it('shows which observed traffic the current policies allow, and the rules without traffic', () => {
  render(
    <ExistingPolicies generatedNetworkPolicy={generated} result={{ comparison }} cluster="prd" />
  );
  expect(
    screen.getByText('Ingress is restricted by default-ingress: 1 of 2 observed flows are allowed.')
  ).toBeTruthy();
  expect(screen.getByText('Egress is not restricted: no NetworkPolicy limits it.')).toBeTruthy();
  expect(screen.getByText('Allowed')).toBeTruthy();
  // the peer's pods were not found, so the labels of the generated policy were compared
  expect(screen.getByText('Not allowed *')).toBeTruthy();
  expect(screen.getAllByRole('link', { name: 'default-ingress' })[0].getAttribute('href')).toBe(
    '/networkpolicy/shop/default-ingress'
  );
  expect(screen.getByText('1 flow')).toBeTruthy();
  expect(screen.getByText('None')).toBeTruthy();
  // the policy selects the pod template, and no pods were read to say it leaves some out
  expect(screen.queryByText(/Not all pods of db/)).toBeNull();
});

it('says when no policy selects the workload', () => {
  render(
    <ExistingPolicies
      generatedNetworkPolicy={generated}
      result={{ comparison: comparePolicies([], { namespace: 'shop', podLabels: {} }, flows) }}
      cluster="prd"
    />
  );
  expect(
    screen.getByText(/No NetworkPolicy selects db, so all its traffic is allowed/)
  ).toBeTruthy();
  expect(screen.getAllByText('Not restricted')).toHaveLength(2);
});

it('says when a policy does not select every pod of the workload that runs', () => {
  // a policy for one pod of a StatefulSet, by a label that its pod template does not have
  const firstPodOnly: ExistingPolicy = {
    metadata: { name: 'db-0-only', namespace: 'shop' },
    spec: {
      podSelector: { matchLabels: { 'statefulset.kubernetes.io/pod-name': 'db-0' } },
      policyTypes: ['Ingress'],
    },
  };
  const livePodLabels = [0, 1].map(index => ({
    app: 'db',
    'statefulset.kubernetes.io/pod-name': `db-${index}`,
  }));
  render(
    <ExistingPolicies
      generatedNetworkPolicy={generated}
      result={{
        comparison: comparePolicies(
          [firstPodOnly],
          { namespace: 'shop', podLabels: { app: 'db' }, livePodLabels },
          flows
        ),
      }}
      cluster="prd"
    />
  );
  // it counts as a policy that selects the workload, with what that leaves out
  expect(screen.queryByText(/No NetworkPolicy selects db/)).toBeNull();
  expect(
    screen.getByText(/Not all pods of db that run now are selected by db-0-only\./)
  ).toBeTruthy();
  expect(screen.getAllByText('Not allowed')).toHaveLength(1);
});

it('gives each node of the diagram the status of the traffic of its peers', () => {
  const { nodes } = createNodes(generated);
  const statuses = nodeFlowStatuses(nodes, comparison.flows);
  const statusOf = (peer: object) =>
    statuses.get(nodes.find(node => (node.data.peers as object[] | undefined)?.includes(peer))!.id);
  expect(statusOf(api)).toEqual({ status: 'allowed', allowedBy: ['default-ingress'] });
  expect(statusOf(job)).toEqual({ status: 'blocked', allowedBy: [] });
  expect(statuses.has('main')).toBe(false);
});

it('says when the pods of the workload were not read, and names traffic without a peer', () => {
  const allSources: ObservedFlow = {
    direction: 'ingress',
    peer: {},
    ports: [{ protocol: 'TCP', port: '8080' }],
    endpoints: [{ anyPeer: true }],
  };
  const { rerender } = render(
    <ExistingPolicies
      generatedNetworkPolicy={generated}
      result={{
        comparison: comparePolicies(policies, { namespace: 'shop', podLabels: { app: 'db' } }, [
          allSources,
        ]),
        podsNotRead: 'unreadable',
      }}
      cluster="prd"
    />
  );
  expect(
    screen.getByText(/The pods of db could not be read, so the policies were matched against/)
  ).toBeTruthy();
  expect(screen.getByText('All sources')).toBeTruthy();
  // default-ingress allows 8080 from some peers only
  expect(screen.getByText('Unknown')).toBeTruthy();

  rerender(
    <ExistingPolicies
      generatedNetworkPolicy={generated}
      result={{ comparison, podsNotRead: 'no-selector' }}
      cluster="prd"
    />
  );
  expect(screen.getByText(/The pods of db are not read, as it has no selector, so/)).toBeTruthy();
});

it('shows a rule of the generated policy without peers as a node of all sources', () => {
  const withoutPeers = {
    ...generated,
    spec: {
      spec: { ...generated.spec.spec, ingress: [{ ports: [{ protocol: 'TCP', port: 80 }] }] },
    },
  } as unknown as GeneratedNetworkPolicy;
  const { nodes } = createNodes(withoutPeers);
  const flow: ObservedFlow = {
    direction: 'ingress',
    peer: {},
    ports: [{ protocol: 'TCP', port: '80' }],
    endpoints: [{ anyPeer: true }],
  };
  const open: ExistingPolicy = {
    metadata: { name: 'open-web', namespace: 'shop' },
    spec: { podSelector: {}, policyTypes: ['Ingress'], ingress: [{ ports: [{ port: '80' }] }] },
  };
  const statuses = nodeFlowStatuses(
    nodes,
    comparePolicies([open], { namespace: 'shop', podLabels: {} }, [flow]).flows
  );
  expect(statuses.get(nodes[1].id)).toEqual({ status: 'allowed', allowedBy: ['open-web'] });
});
