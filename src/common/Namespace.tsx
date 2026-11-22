import { Link as HeadlampLink } from '@kinvolk/headlamp-plugin/lib/CommonComponents';

/** A link to the page of a namespace, in the cluster of the row when the table has several. */
export function makeNamespaceLink(namespace: string, cluster?: string) {
  return (
    <HeadlampLink
      routeName="namespace"
      activeCluster={cluster}
      params={{
        name: namespace,
      }}
    >
      {namespace}
    </HeadlampLink>
  );
}
