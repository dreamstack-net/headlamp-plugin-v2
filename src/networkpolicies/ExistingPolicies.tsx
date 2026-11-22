/*
  The NetworkPolicies that select the workload of a generated policy, and whether they allow
  the traffic Kubescape saw the workload use.
*/
import { Link as HeadlampLink } from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { Alert, Box, Chip, Stack, Tooltip, Typography } from '@mui/material';
import { useMemo } from 'react';
import { CompactTable } from '../common/CompactTable';
import HeadlampTable from '../common/Table';
import { formatLabelSelector } from '../exceptions/apply-security-exceptions';
import {
  GeneratedNetworkPolicy,
  NetworkPolicy,
} from '../softwarecomposition/GeneratedNetworkPolicy';
import {
  Direction,
  ExistingPolicy,
  FlowResult,
  FlowStatus,
  policyDirections,
  ruleKey,
} from './compare';
import { isAllPeers, withoutPerPodLabels } from './layout';
import { ComparisonResult, workloadOf } from './policyComparison';
import { compactPorts, portsText } from './ports';

export const flowStatusLabels: Record<FlowStatus, string> = {
  allowed: 'Allowed',
  partly: 'Partly allowed',
  blocked: 'Not allowed',
  unrestricted: 'Not restricted',
  unknown: 'Unknown',
};

// the palette colors of the statuses
export const flowStatusColors: Record<FlowStatus, 'success' | 'warning' | 'error' | 'default'> = {
  allowed: 'success',
  partly: 'warning',
  blocked: 'error',
  unrestricted: 'default',
  unknown: 'default',
};

export const flowStatusDescriptions: Record<FlowStatus, string> = {
  allowed: 'The current NetworkPolicies allow this traffic',
  partly: 'The current NetworkPolicies allow only part of this traffic',
  blocked: 'The current NetworkPolicies do not allow this traffic',
  unrestricted: 'No NetworkPolicy restricts this direction, so all traffic is allowed',
  unknown:
    'No pod or namespace of this peer could be found, or the generated policy names no peer and the current NetworkPolicies allow these ports only for some peers, so whether they allow this traffic is not known',
};

// blocked traffic first
const statusOrder: FlowStatus[] = ['blocked', 'partly', 'unknown', 'allowed', 'unrestricted'];

const directionLabels: Record<Direction, string> = { ingress: 'Ingress', egress: 'Egress' };

function selectorText(selector: NetworkPolicy.LabelSelector) {
  return formatLabelSelector(selector).replaceAll(',', ', ');
}

/** The peer of a rule without peers, which allows its ports from or to any peer. */
export function allPeersText(direction: Direction) {
  return direction === 'ingress' ? 'All sources' : 'All destinations';
}

/** A peer of a policy in words, as the policy in the namespace selects it. */
export function peerText(peer: NetworkPolicy.Peer, namespace: string): string {
  if (peer.ipBlock) {
    const except = peer.ipBlock.except?.length ? ` except ${peer.ipBlock.except.join(', ')}` : '';
    return `${peer.ipBlock.cidr}${except}`;
  }
  const namespaceName = peer.namespaceSelector?.matchLabels?.['kubernetes.io/metadata.name'];
  const namespaces = !peer.namespaceSelector
    ? `namespace ${namespace}`
    : namespaceName && Object.keys(peer.namespaceSelector.matchLabels!).length === 1
    ? `namespace ${namespaceName}`
    : selectorText(peer.namespaceSelector)
    ? `namespaces with ${selectorText(peer.namespaceSelector)}`
    : 'all namespaces';
  const pods =
    peer.podSelector && selectorText(peer.podSelector)
      ? `pods with ${selectorText(peer.podSelector)}`
      : 'all pods';
  return `${pods} in ${namespaces}`;
}

// Whether the labels of the generated policy decided the status, as no pod has them now, or the
// name of a namespace whose labels could not be read
function isApproximate(flow: FlowResult) {
  return flow.approximate && flow.status !== 'unrestricted';
}

const generatedLabels = 'so the labels of the generated policy were compared';

// Why the peer could not be compared as it is in the cluster, and what was compared instead
const approximateNotes = {
  labels: `No pod has these labels now, ${generatedLabels}`,
  namespace: `No namespace that the peer selects could be found, ${generatedLabels}`,
  'not-looked-up': `The pods of this peer were not looked up, as only those of the first 50 peers are, ${generatedLabels}`,
  // not the same as no pod having the labels: the user may not read the pods of the namespace
  'pods-unreadable': `The pods of this peer could not be read, ${generatedLabels}`,
  'namespace-labels':
    'The labels of the namespace of this peer could not be read, so the namespace selectors of the policies were compared with its name only',
};

function StatusChip(props: Readonly<{ flow: FlowResult }>) {
  const { flow } = props;
  const note = isApproximate(flow)
    ? `. ${approximateNotes[flow.approximateReason ?? 'labels']}.`
    : '';
  return (
    <Tooltip title={`${flowStatusDescriptions[flow.status]}${note}`}>
      <Chip
        size="small"
        color={flowStatusColors[flow.status]}
        variant={flow.status === 'unrestricted' ? 'outlined' : 'filled'}
        label={`${flowStatusLabels[flow.status]}${isApproximate(flow) ? ' *' : ''}`}
      />
    </Tooltip>
  );
}

function PolicyLink(props: Readonly<{ policy: ExistingPolicy; cluster: string }>) {
  const { policy, cluster } = props;
  return (
    <HeadlampLink
      routeName="networkpolicy"
      params={{ namespace: policy.metadata.namespace, name: policy.metadata.name }}
      activeCluster={cluster || undefined}
    >
      {policy.metadata.name}
    </HeadlampLink>
  );
}

function directionSummary(
  direction: Direction,
  policies: ExistingPolicy[],
  flows: FlowResult[]
): string {
  const observed = flows.filter(flow => flow.direction === direction);
  if (policies.length === 0) {
    return `${directionLabels[direction]} is not restricted: no NetworkPolicy limits it.`;
  }
  const allowed = observed.filter(flow => flow.status === 'allowed').length;
  return `${directionLabels[direction]} is restricted by ${policies
    .map(policy => policy.metadata.name)
    .join(', ')}: ${allowed} of ${observed.length} observed flows are allowed.`;
}

interface RuleRow {
  policy: ExistingPolicy;
  direction: Direction;
  // undefined for a policy that restricts the direction without rules: it denies all
  index?: number;
  peers?: NetworkPolicy.Peer[];
  ports?: NetworkPolicy.Port[];
}

function ruleRows(policies: ExistingPolicy[]): RuleRow[] {
  return policies.flatMap(policy =>
    policyDirections(policy.spec).flatMap((direction): RuleRow[] => {
      const rules =
        direction === 'ingress'
          ? (policy.spec.ingress ?? []).map(rule => ({ peers: rule.from, ports: rule.ports }))
          : (policy.spec.egress ?? []).map(rule => ({ peers: rule.to, ports: rule.ports }));
      if (rules.length === 0) return [{ policy, direction }];
      return rules.map((rule, index) => ({ policy, direction, index, ...rule }));
    })
  );
}

export function ExistingPolicies(
  props: Readonly<{
    generatedNetworkPolicy: GeneratedNetworkPolicy;
    result: ComparisonResult | null;
    cluster: string;
  }>
) {
  const { generatedNetworkPolicy, result, cluster } = props;
  const { namespace, name } = workloadOf(generatedNetworkPolicy);
  const comparison = result?.comparison;
  const rules = useMemo(() => ruleRows(comparison?.selecting ?? []), [comparison]);

  if (!result) {
    return (
      <Typography color="text.secondary" sx={{ mt: 2 }}>
        Reading the NetworkPolicies of namespace {namespace}…
      </Typography>
    );
  }
  if (!comparison) {
    return (
      <Alert severity="error" sx={{ mt: 2 }}>
        Unable to read the NetworkPolicies of namespace {namespace}: {result.error}
      </Alert>
    );
  }

  const { flows, selecting, selectingSomePods, restricting, ruleUse } = comparison;
  const notAllowed = flows.filter(flow => flow.status === 'blocked' || flow.status === 'partly');
  const approximate = flows.some(isApproximate);

  return (
    <Stack spacing={2} sx={{ mt: 2 }}>
      {selecting.length === 0 ? (
        <Alert severity="info">
          No NetworkPolicy selects {name}, so all its traffic is allowed. Creating the generated
          policy would limit it to the traffic below.
        </Alert>
      ) : (
        <Alert severity={notAllowed.length > 0 ? 'warning' : 'success'}>
          <div>{directionSummary('ingress', restricting.ingress, flows)}</div>
          <div>{directionSummary('egress', restricting.egress, flows)}</div>
          {notAllowed.length > 0 && (
            <div>
              Traffic that Kubescape saw but the policies do not allow was blocked, or was seen
              before the policies existed.
            </div>
          )}
        </Alert>
      )}
      {selectingSomePods.length > 0 && (
        <Alert severity="warning">
          Not all pods of {name} that run now are selected by{' '}
          {selectingSomePods.map(policy => policy.metadata.name).join(', ')}. The comparison counts
          such a policy for the whole workload, so the pods it leaves out are less restricted than
          shown.
        </Alert>
      )}
      {result.approximateWorkload && (
        <Alert severity="info">
          The {name} workload could not be read, so the policies were matched against the pod labels
          of the generated policy.
        </Alert>
      )}
      {result.podsNotRead && (
        <Alert severity="info">
          {result.podsNotRead === 'no-selector'
            ? `The pods of ${name} are not read, as it has no selector,`
            : `The pods of ${name} could not be read,`}{' '}
          so the policies were matched against its pod template only: labels and named ports that
          controllers or admission webhooks give its pods are not compared.
        </Alert>
      )}

      <Box>
        <Typography variant="h6">Observed traffic</Typography>
        <HeadlampTable
          data={flows}
          sortingKey="networkpolicy-observed-traffic"
          columns={[
            {
              id: 'Direction',
              header: 'Direction',
              accessorFn: (flow: FlowResult) => directionLabels[flow.direction],
              gridTemplate: 'min-content',
            },
            {
              header: 'Peer',
              accessorFn: (flow: FlowResult) =>
                isAllPeers(flow.peer)
                  ? allPeersText(flow.direction)
                  : peerText(withoutPerPodLabels(flow.peer), namespace),
              gridTemplate: 'auto',
            },
            {
              header: 'Ports',
              accessorFn: (flow: FlowResult) => portsText(compactPorts(flow.ports)),
              gridTemplate: 'min-content',
            },
            {
              id: 'Status',
              header: 'Current policies',
              accessorFn: (flow: FlowResult) => statusOrder.indexOf(flow.status),
              Cell: ({ row }) => <StatusChip flow={row.original} />,
              gridTemplate: 'min-content',
            },
            {
              header: 'Allowed by',
              accessorFn: (flow: FlowResult) => flow.allowedBy.join(', '),
              gridTemplate: 'auto',
            },
          ]}
          initialState={{ sorting: [{ id: 'Status', desc: false }] }}
        />
        {approximate && (
          <Typography variant="caption" color="text.secondary">
            * These peers were compared by the labels of the generated policy, or by the name of
            their namespace, as their pods or namespaces could not be found or read; the status says
            why.
          </Typography>
        )}
      </Box>

      {selecting.length > 0 && (
        <Box>
          <Typography variant="h6">Policies that select {name}</Typography>
          <CompactTable
            rows={rules}
            rowKey={rule =>
              JSON.stringify([rule.policy.metadata.name, rule.direction, rule.index ?? -1])
            }
            columns={[
              {
                header: 'Policy',
                cell: rule => <PolicyLink policy={rule.policy} cluster={cluster} />,
              },
              { header: 'Direction', cell: rule => directionLabels[rule.direction] },
              {
                header: 'Allows',
                cell: rule =>
                  rule.index === undefined
                    ? `No ${rule.direction} at all`
                    : rule.peers?.length
                    ? rule.peers.map((peer, index) => (
                        <div key={index}>{peerText(peer, rule.policy.metadata.namespace)}</div>
                      ))
                    : `All ${rule.direction === 'ingress' ? 'sources' : 'destinations'}`,
              },
              {
                header: 'Ports',
                cell: rule => (rule.index === undefined ? '' : portsText(rule.ports)),
              },
              {
                header: 'Observed traffic',
                cell: rule => {
                  if (rule.index === undefined) return '';
                  const used =
                    ruleUse.get(ruleKey(rule.policy.metadata.name, rule.direction, rule.index)) ??
                    0;
                  return used > 0 ? (
                    `${used} ${used === 1 ? 'flow' : 'flows'}`
                  ) : (
                    <Tooltip title="Kubescape saw no traffic of the workload that this rule allows; it may be broader than needed">
                      <Chip size="small" variant="outlined" label="None" />
                    </Tooltip>
                  );
                },
              },
            ]}
          />
        </Box>
      )}
    </Stack>
  );
}
