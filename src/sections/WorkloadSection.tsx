/*
  Provide a panel on the Headlamp resource pages (for deployments, statefulsets, pods, etc).
*/
import { Link, NameValueTable, SectionBox } from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { KubeObject } from '@kinvolk/headlamp-plugin/lib/k8s/KubeObject';
import { useEffect, useState } from 'react';
import { useStorageObject } from '../common/readOnce';
import { getControlsSummary } from '../compliance/ControlsSummary';
import { RoutingName } from '../index';
import {
  fetchObject,
  vulnerabilityManifestSummaryClass,
  workloadConfigurationScanSummaryClass,
} from '../model';
import { getCVESummary } from '../vulnerabilities/CVESummary';
import { ExceptionsNote } from './ExceptionsNote';
import { findScannedWorkload, scannedWorkloadCandidates, WorkloadRef } from './scannedWorkload';
import { useFailedControlCounts } from './workloadSummaries';

// Workload kinds with Kubescape results, with the location of their pod spec. Pods show the
// results of the workload that runs them.
const podSpecGetters: Record<string, (spec: any) => any> = {
  Deployment: spec => spec?.template?.spec,
  StatefulSet: spec => spec?.template?.spec,
  DaemonSet: spec => spec?.template?.spec,
  Job: spec => spec?.template?.spec,
  CronJob: spec => spec?.jobTemplate?.spec?.template?.spec,
  Pod: spec => spec,
};

export default function addKubescapeWorkloadSection(resource: any, sections: any) {
  if (!resource) {
    return sections;
  }

  if (!podSpecGetters[resource.kind]) {
    // Return early if we're not on a workload page
    return sections;
  }

  // Check if we already have added our custom section (this function may be called multiple times).
  const customSectionId = 'kubescape-resources';
  if (sections.findIndex((section: any) => section.id === customSectionId) !== -1) {
    return sections;
  }

  const metadataIdx = sections.findIndex((section: any) => section.id === 'METADATA');
  // If there is no metadata section, the resource has not loaded yet, so we do nothing.
  if (metadataIdx === -1) {
    return sections;
  }

  // We place our custom section after the metadata.
  sections.splice(metadataIdx + 1, 0, {
    id: customSectionId,
    section: <KubescapeInfo resource={resource} />,
  });

  return sections;
}

function KubescapeInfo(props: Readonly<{ resource: KubeObject }>) {
  const { resource } = props;
  const isPod = resource.kind === 'Pod';
  const [podWorkload, setPodWorkload] = useState<WorkloadRef | null>(null);
  // the workload of a pod follows from its name and owners, which stay the same while the pod
  // is watched and its status changes
  const metadata = resource.jsonData.metadata;
  const ownerKey = isPod
    ? JSON.stringify([metadata.namespace, metadata.name, metadata.ownerReferences ?? []])
    : '';

  useEffect(() => {
    if (!isPod) return;
    let active = true;
    findScannedWorkload(resource.jsonData, resource.cluster).then(workload => {
      if (active) setPodWorkload(workload);
    });
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isPod, ownerKey, resource.cluster]);

  if (isPod && !podWorkload) {
    return <></>;
  }
  // the workload itself, or for a Job of a CronJob the CronJob, which its owner names
  return (
    <ScanResults
      resource={resource}
      workload={podWorkload ?? scannedWorkloadCandidates({ kind: resource.kind, metadata })[0]}
    />
  );
}

function ScanResults(props: Readonly<{ resource: KubeObject; workload: WorkloadRef }>) {
  const { resource, workload } = props;
  const namespace = resource.jsonData.metadata.namespace;
  const kind = resource.kind;

  const scanName = `${workload.kind.toLowerCase()}-${workload.name.toLowerCase()}`;
  const [vulnerabilityScans, setVulnerabilityScans] = useState<any[] | null>(null);

  // read once: a watch of the storage would replace the summary with one without its controls
  const { data: configurationScan } = useStorageObject(
    workloadConfigurationScanSummaryClass,
    scanName,
    namespace,
    resource.cluster
  );
  // the failed controls without those that exceptions exclude, also where the plugin applies
  // the exceptions itself
  const { counts: controlCounts, exceptionsError } = useFailedControlCounts(
    resource.cluster,
    configurationScan
  );

  const podSpec = podSpecGetters[kind]?.(resource.jsonData.spec);
  const manifestNames: string[] = [
    ...(podSpec?.containers ?? []),
    ...(podSpec?.initContainers ?? []),
  ].map((container: any) => `${scanName}-${container.name}`);
  const manifestNamesKey = manifestNames.join(',');

  useEffect(() => {
    let active = true;
    // A container that has not been scanned yet has no summary; show the ones that exist.
    Promise.allSettled(
      manifestNames.map(name =>
        fetchObject(name, namespace, resource.cluster, vulnerabilityManifestSummaryClass)
      )
    ).then(results => {
      if (!active) return;
      setVulnerabilityScans(
        results
          .filter((result): result is PromiseFulfilledResult<any> => result.status === 'fulfilled')
          .map(result => result.value)
      );
    });
    return () => {
      active = false;
    };
    // manifestNamesKey covers manifestNames, which is rebuilt on every render
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [manifestNamesKey, namespace, resource.cluster]);

  const tableRows: { name: JSX.Element | string; value: JSX.Element | string }[] = [];

  if (workload.kind !== kind) {
    tableRows.push({ name: 'Results of', value: `${workload.kind} ${workload.name}` });
  }

  if (configurationScan) {
    //if (configurationScan.jsonData.spec.severities.critical > 0)
    tableRows.push({
      name: (
        <Link
          routeName={RoutingName.KubescapeWorkloadConfigurationScanDetails}
          params={{
            cluster: resource.cluster,
            name: scanName,
            namespace: namespace,
          }}
        >
          Compliance
        </Link>
      ),
      value: controlCounts ? (
        <>
          {getControlsSummary(controlCounts)}
          <ExceptionsNote error={exceptionsError} />
        </>
      ) : (
        'Reading the security exceptions…'
      ),
    });
  }

  if (vulnerabilityScans) {
    for (const vulnerabilityScan of vulnerabilityScans) {
      tableRows.push({
        name: (
          <Link
            routeName={RoutingName.KubescapeVulnerabilityDetails}
            params={{
              name: vulnerabilityScan.metadata.name,
              namespace: namespace,
            }}
            // the page reads the first cluster of the address, which in Headlamp's details drawer
            // is not the cluster of the workload
            activeCluster={resource.cluster}
          >
            {`Vulnerabilities / ${
              vulnerabilityScan.metadata.labels
                ? vulnerabilityScan.metadata.labels['kubescape.io/workload-container-name']
                : ''
            }`}
          </Link>
        ),
        value: getCVESummary(vulnerabilityScan, false, false),
      });
    }
  }

  return (
    <SectionBox title="Kubescape">
      <NameValueTable rows={tableRows} />
    </SectionBox>
  );
}
