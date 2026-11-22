/* 
  Kubescape definitions for resources with basic methods for querying. 
*/
import { request } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import { makeCustomResourceClass } from '@kinvolk/headlamp-plugin/lib/k8s/crd';
import { KubeObjectClass } from '@kinvolk/headlamp-plugin/lib/k8s/KubeObject';
import { getCluster } from '@kinvolk/headlamp-plugin/lib/Utils';
import { getAllowedNamespaces } from './common/clusterContext';
import { listInNamespaces, NamespacedList } from './query';

const spdxGroup = 'spdx.softwarecomposition.kubescape.io';
const spdxVersion = 'v1beta1';
const spdxGroupVersions = [{ group: spdxGroup, version: spdxVersion }];

export const customObjectLabel = 'kubescape.io/custom-object';

export const vulnerabilityManifestClass = makeCustomResourceClass({
  apiInfo: spdxGroupVersions,
  isNamespaced: true,
  singularName: 'vulnerabilitymanifest',
  pluralName: 'vulnerabilitymanifests',
  kind: 'VulnerabilityManifest',
});

export const vulnerabilityManifestSummaryClass = makeCustomResourceClass({
  apiInfo: spdxGroupVersions,
  isNamespaced: true,
  singularName: 'vulnerabilitymanifestsummary',
  pluralName: 'vulnerabilitymanifestsummaries',
  kind: 'VulnerabilityManifestSummary',
});

export const vulnerabilitySummaryClass = makeCustomResourceClass({
  apiInfo: spdxGroupVersions,
  isNamespaced: false,
  singularName: 'vulnerabilitysummary',
  pluralName: 'vulnerabilitysummaries',
  kind: 'VulnerabilitySummary',
});

export const openVulnerabilityExchangeContainerClass = makeCustomResourceClass({
  apiInfo: spdxGroupVersions,
  isNamespaced: true, // kubescape
  singularName: 'openvulnerabilityexchangecontainer',
  pluralName: 'openvulnerabilityexchangecontainers',
  kind: 'OpenVulnerabilityExchangeContainer',
});

export const workloadConfigurationScanSummaryClass = makeCustomResourceClass({
  apiInfo: spdxGroupVersions,
  isNamespaced: true,
  singularName: 'workloadconfigurationscansummary',
  pluralName: 'workloadconfigurationscansummaries',
  kind: 'WorkloadConfigurationScanSummary',
});

export const workloadConfigurationScanClass = makeCustomResourceClass({
  apiInfo: spdxGroupVersions,
  isNamespaced: true,
  singularName: 'workloadconfigurationscan',
  pluralName: 'workloadconfigurationscans',
  kind: 'WorkloadConfigurationScan',
});

export const configurationScanSummariesClass = makeCustomResourceClass({
  apiInfo: spdxGroupVersions,
  isNamespaced: false,
  singularName: 'configurationscansummary',
  pluralName: 'configurationscansummaries',
  kind: 'ConfigurationScanSummary',
});

export const generatedNetworkPolicyClass = makeCustomResourceClass({
  apiInfo: spdxGroupVersions,
  isNamespaced: true,
  singularName: 'generatednetworkpolicy',
  pluralName: 'generatednetworkpolicies',
  kind: 'GeneratedNetworkPolicy',
});

export const containerProfileClass = makeCustomResourceClass({
  apiInfo: spdxGroupVersions,
  isNamespaced: true,
  singularName: 'containerprofile',
  pluralName: 'containerprofiles',
  kind: 'ContainerProfile',
});

// Older supported Storage releases serve the separate resources. Keep these
// classes for installations where ContainerProfile is not yet available.
export const networkNeighborhoodsClass = makeCustomResourceClass({
  apiInfo: spdxGroupVersions,
  isNamespaced: true,
  singularName: 'networkneighborhood',
  pluralName: 'networkneighborhoods',
  kind: 'NetworkNeighborhood',
});

export const sbomSyftClass = makeCustomResourceClass({
  apiInfo: spdxGroupVersions,
  isNamespaced: true,
  singularName: 'sbomsyft',
  pluralName: 'sbomsyfts',
  kind: 'SBOMSyft',
});

export const sbomSyftFilteredClass = makeCustomResourceClass({
  apiInfo: spdxGroupVersions,
  isNamespaced: true,
  singularName: 'sbomsyftfiltered',
  pluralName: 'sbomsyftfiltereds',
  kind: 'SBOMSyftFiltered',
});

export const applicationProfileClass = makeCustomResourceClass({
  apiInfo: spdxGroupVersions,
  isNamespaced: true,
  singularName: 'applicationprofile',
  pluralName: 'applicationprofiles',
  kind: 'ApplicationProfile',
});

export const knownServersClass = makeCustomResourceClass({
  apiInfo: spdxGroupVersions,
  isNamespaced: true,
  singularName: 'knownserver',
  pluralName: 'knownservers',
  kind: 'KnownServer',
});

// Kubescape stores seccomp profiles in a CRD or in its storage, depending on the
// seccompProfileBackend setting of the operator chart (src/runtimedetection/seccomp.ts).
export const seccompProfileClass = makeCustomResourceClass({
  apiInfo: [{ group: 'kubescape.io', version: 'v1' }],
  isNamespaced: true,
  singularName: 'seccompprofile',
  pluralName: 'seccompprofiles',
  kind: 'SeccompProfile',
});

export const seccompProfileStorageClass = makeCustomResourceClass({
  apiInfo: spdxGroupVersions,
  isNamespaced: true,
  singularName: 'seccompprofile',
  pluralName: 'seccompprofiles',
  kind: 'SeccompProfile',
});

export const rulesClass = makeCustomResourceClass({
  apiInfo: [{ group: 'kubescape.io', version: 'v1' }],
  isNamespaced: true,
  singularName: 'rules',
  pluralName: 'rules',
  kind: 'Rules',
});

export const runtimeRuleAlertBindingClass = makeCustomResourceClass({
  apiInfo: [{ group: 'kubescape.io', version: 'v1' }],
  isNamespaced: false,
  singularName: 'runtimerulealertbinding',
  pluralName: 'runtimerulealertbindings',
  kind: 'RuntimeRuleAlertBinding',
});

const kubescapeGroup = 'kubescape.io';
const kubescapeVersion = 'v1beta1';
const kubescapeGroupVersions = [{ group: kubescapeGroup, version: kubescapeVersion }];

export const securityExceptionClass = makeCustomResourceClass({
  apiInfo: kubescapeGroupVersions,
  isNamespaced: true,
  singularName: 'securityexception',
  pluralName: 'securityexceptions',
  kind: 'SecurityException',
});

export const clusterSecurityExceptionClass = makeCustomResourceClass({
  apiInfo: kubescapeGroupVersions,
  isNamespaced: false,
  singularName: 'clustersecurityexception',
  pluralName: 'clustersecurityexceptions',
  kind: 'ClusterSecurityException',
});

/**
 * Lists all objects of the given class in one cluster, restricted to the allowed namespaces of
 * that cluster when those are configured. A namespace that cannot be read does not take the
 * others with it: the errors say why namespaces could not be read, for pages to show, such as
 * with useItemsInClusters. When none can be read, it rejects.
 *
 * @param objectClass - The class of objects to list.
 * @param cluster - The cluster to query, the current cluster by default.
 */
export function listQueryWithErrors(
  objectClass: KubeObjectClass,
  cluster: string | null = getCluster()
): Promise<NamespacedList> {
  return listInNamespaces(objectClass, cluster, getAllowedNamespaces(cluster) ?? []);
}

/**
 * The items of {@link listQueryWithErrors}; namespaces that could not be read are only logged,
 * so a page that can show them uses listQueryWithErrors.
 */
export async function listQuery(
  objectClass: KubeObjectClass,
  cluster: string | null = getCluster()
): Promise<any[]> {
  const { items, errors } = await listQueryWithErrors(objectClass, cluster);
  if (errors.length > 0) {
    console.warn(
      `Not all ${objectClass.pluralName} of ${cluster ?? 'the cluster'} were read:`,
      errors
    );
  }
  return items;
}

export type ClusterError = { cluster: string; message: string };

export function fetchObject(
  name: string,
  namespace: string,
  cluster: string,
  objectClass: KubeObjectClass
): Promise<any> {
  const group = objectClass.apiEndpoint.apiInfo[0].group;
  const version = objectClass.apiEndpoint.apiInfo[0].version;
  const namespacePath = namespace ? `namespaces/${namespace}/` : '';

  return request(`/apis/${group}/${version}/${namespacePath}${objectClass.pluralName}/${name}`, {
    cluster: cluster,
  });
}
