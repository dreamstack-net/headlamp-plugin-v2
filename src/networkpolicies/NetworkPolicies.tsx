/* 
  List generated network policies. 
*/
import './style.css';
import {
  Link as HeadlampLink,
  SectionBox,
  Tabs as HeadlampTabs,
} from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { KubeObjectClass } from '@kinvolk/headlamp-plugin/lib/k8s/KubeObject';
import { Typography } from '@mui/material';
import { useEffect, useMemo, useState } from 'react';
import { getAllowedNamespaces } from '../common/clusterContext';
import { ClusterErrors } from '../common/ClusterErrors';
import { clusterColumns, useItemsInClusters } from '../common/clusters';
import { errorMessage } from '../common/errors';
import { SetupCheck } from '../common/SetupCheck';
import HeadlampTable from '../common/Table';
import { RoutingName, useHLSelectedClusters } from '../index';
import {
  ClusterError,
  generatedNetworkPolicyClass,
  knownServersClass,
  listQueryWithErrors,
} from '../model';
import { listPerNamespace } from '../query';
import { GeneratedNetworkPolicy } from '../softwarecomposition/GeneratedNetworkPolicy';
import { KnownServer } from '../softwarecomposition/KnownServer';

export default function KubescapeNetworkPolicies() {
  return (
    <>
      <h1>Generated Network Policies</h1>
      <SetupCheck features={['networkPolicies']} />
      <HeadlampTabs
        tabs={[
          {
            label: 'Policies',
            component: <NetworkPolicyList />,
          },
          {
            label: 'Known Servers',
            component: <KnownServerList />,
          },
        ]}
        ariaLabel="Navigation Tabs"
      />
    </>
  );
}

// Lists the objects of the class in all selected clusters
function useListInClusters<T>(objectClass: KubeObjectClass) {
  // namespaces that could not be read are shown with the cluster errors
  return useItemsInClusters<T>(
    cluster => listQueryWithErrors(objectClass, cluster),
    objectClass.pluralName
  );
}

/**
 * The generated network policies of the selected clusters, read a namespace at a time so the
 * storage builds them in parallel, and shown as the namespaces arrive.
 */
function useGeneratedPolicies() {
  const clusters = useHLSelectedClusters();
  const clustersKey = clusters.join(',');
  const [items, setItems] = useState<GeneratedNetworkPolicy[]>([]);
  const [errors, setErrors] = useState<ClusterError[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    // a page that is left starts no more reads
    const continueReading = { current: true };
    const found: GeneratedNetworkPolicy[] = [];
    let timer: ReturnType<typeof setTimeout> | undefined;
    const show = () => {
      timer = undefined;
      if (active) setItems([...found]);
    };
    setItems([]);
    setErrors([]);
    setLoading(true);
    Promise.all(
      clusters.map(cluster =>
        listPerNamespace(
          generatedNetworkPolicyClass,
          cluster,
          getAllowedNamespaces(cluster),
          policies => {
            found.push(...policies);
            // the table is drawn again a few times a second at most
            timer ??= setTimeout(show, 300);
          },
          continueReading
        ).then(
          namespaceErrors =>
            namespaceErrors.length > 0 ? [{ cluster, message: namespaceErrors.join('; ') }] : [],
          error => [{ cluster, message: errorMessage(error) }]
        )
      )
    ).then(clusterErrors => {
      if (!active) return;
      if (timer) clearTimeout(timer);
      show();
      setErrors(clusterErrors.flat());
      setLoading(false);
    });
    return () => {
      active = false;
      continueReading.current = false;
      if (timer) clearTimeout(timer);
    };
    // clustersKey covers clusters, which is a new array on every render
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clustersKey]);

  return { items, errors, loading, clusters };
}

function NetworkPolicyList() {
  const { items: networkPolicies, errors, loading, clusters } = useGeneratedPolicies();

  return (
    <SectionBox>
      <ClusterErrors errors={errors} what="generated network policies" />
      {loading && networkPolicies.length > 0 && (
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
          Reading the policies of the other namespaces…
        </Typography>
      )}
      <HeadlampTable
        data={networkPolicies}
        loading={loading && networkPolicies.length === 0}
        getRowId={(networkPolicy: GeneratedNetworkPolicy) =>
          JSON.stringify([
            networkPolicy.metadata.cluster,
            networkPolicy.metadata.namespace,
            networkPolicy.metadata.name,
          ])
        }
        columns={[
          {
            id: 'Name',
            header: 'Name',
            // the name sorts and searches; the link is drawn in the cell
            accessorFn: (networkPolicy: GeneratedNetworkPolicy) =>
              networkPolicy.metadata.labels?.['kubescape.io/workload-name'] ??
              networkPolicy.metadata.name,
            Cell: ({ cell, row }) => (
              <HeadlampLink
                routeName={RoutingName.KubescapeNetworkPolicyDiagram}
                activeCluster={row.original.metadata.cluster}
                params={{
                  name: row.original.metadata.name,
                  namespace: row.original.metadata.namespace,
                }}
              >
                {cell.getValue()}
              </HeadlampLink>
            ),
            gridTemplate: 'auto',
          },
          ...clusterColumns<GeneratedNetworkPolicy>(clusters, policy => policy.metadata.cluster),
          {
            header: 'Kind',
            accessorFn: (networkPolicy: GeneratedNetworkPolicy) =>
              networkPolicy.metadata.labels?.['kubescape.io/workload-kind'],
            gridTemplate: 'auto',
          },
          {
            header: 'Namespace',
            accessorFn: (networkPolicy: GeneratedNetworkPolicy) =>
              networkPolicy.metadata.labels?.['kubescape.io/workload-namespace'] ??
              networkPolicy.metadata.namespace,
            gridTemplate: 'auto',
          },
          {
            header: 'Ingresses',
            // the storage generates the listed policies from the full container profiles, also
            // without fullSpec; older releases, which listed network neighborhoods, may leave
            // the spec out
            accessorFn: (networkPolicy: GeneratedNetworkPolicy) =>
              networkPolicy.spec?.spec?.ingress?.length,
            gridTemplate: 'min-content',
          },
          {
            header: 'Egresses',
            accessorFn: (networkPolicy: GeneratedNetworkPolicy) =>
              networkPolicy.spec?.spec?.egress?.length,
            gridTemplate: 'min-content',
          },
        ]}
      />
    </SectionBox>
  );
}

class KnownServerEntry {
  knownServer: KnownServer;
  entry: KnownServer.Entry;

  constructor(knownServer: KnownServer, entry: KnownServer.Entry) {
    this.knownServer = knownServer;
    this.entry = entry;
  }
}

function KnownServerList() {
  const {
    items: knownServers,
    errors,
    loading,
    clusters,
  } = useListInClusters<KnownServer>(knownServersClass);

  // the same rows on every render, so the table does not compute its cells again
  const serverEntries = useMemo(
    () => knownServers.flatMap(ks => (ks.spec ?? []).map(entry => new KnownServerEntry(ks, entry))),
    [knownServers]
  );

  return (
    <SectionBox>
      <ClusterErrors errors={errors} what="known servers" />
      <HeadlampTable
        data={serverEntries}
        loading={loading}
        columns={[
          {
            header: 'Item',
            accessorFn: (item: KnownServerEntry) => item.knownServer.metadata.name,
            gridTemplate: 'auto',
          },
          ...clusterColumns<KnownServerEntry>(clusters, item => item.knownServer.metadata.cluster),
          {
            header: 'Name',
            accessorFn: (item: KnownServerEntry) => item.entry.name,
            gridTemplate: 'auto',
          },
          {
            header: 'Server',
            accessorFn: (item: KnownServerEntry) => item.entry.server,
            gridTemplate: 'auto',
          },
          {
            header: 'IPBlock',
            accessorFn: (item: KnownServerEntry) => item.entry.ipBlock,
            gridTemplate: 'auto',
          },
        ]}
      />
    </SectionBox>
  );
}
