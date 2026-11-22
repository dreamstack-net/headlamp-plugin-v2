/* 
  Provide a panel on the Headlamp namespace page. 
*/

import { Link, NameValueTable, SectionBox } from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { KubeObject } from '@kinvolk/headlamp-plugin/lib/k8s/KubeObject';
import { Typography } from '@mui/material';
import { useStorageObject } from '../common/readOnce';
import { getControlsSummary } from '../compliance/ControlsSummary';
import { RoutingName } from '../index';
import { configurationScanSummariesClass, vulnerabilitySummaryClass } from '../model';
import { VulnerabilitySummary } from '../softwarecomposition/VulnerabilitySummary';
import { getCVESummary } from '../vulnerabilities/CVESummary';
import { ExceptionsNote } from './ExceptionsNote';
import { useNamespaceFailedControls } from './workloadSummaries';

export default function addKubescapeNamespaceSection(resource: any, sections: any) {
  // Ignore if there is no resource.
  if (!resource) {
    return sections;
  }

  if (resource.kind !== 'Namespace') {
    // Return early if we're not on the Namespace page
    return sections;
  }

  // Check if we already have added our custom section (this function may be called multiple times).
  const customSectionId = 'kubescape-configuration-scan-summaries';
  if (sections.findIndex((section: any) => section.id === customSectionId) !== -1) {
    return sections;
  }

  const detailsHeaderIdx = sections.findIndex((section: any) => section.id === 'EVENTS');
  // There is no EVENTS section, so we do nothing.
  if (detailsHeaderIdx === -1) {
    return sections;
  }
  // We place our custom section before the EVENTS.
  sections.splice(detailsHeaderIdx, 0, {
    id: customSectionId,
    section: <KubescapeInfo resource={resource} />,
  });

  return sections;
}

function KubescapeInfo(props: { resource: KubeObject }) {
  const { resource } = props;
  const resourceName = resource.jsonData.metadata.name;

  // the summaries are named after the namespace and are not namespaced; they are read once in
  // the cluster of the namespace, as the storage refuses to watch them (405), and a namespace
  // without scans has none
  const { data: configurationScanSummary } = useStorageObject(
    configurationScanSummariesClass,
    resourceName,
    undefined,
    resource.cluster
  );
  const { data: vulnerabilitySummary } = useStorageObject<VulnerabilitySummary>(
    vulnerabilitySummaryClass,
    resourceName,
    undefined,
    resource.cluster
  );

  // the failed controls of the workloads of the namespace, without those that exceptions exclude,
  // also where the plugin applies the exceptions itself; the summary of the storage counts them
  // as the scanners applied them
  const failedControls = useNamespaceFailedControls(
    resource.cluster ?? '',
    resourceName,
    !!configurationScanSummary
  );

  // each summary is shown on its own: a cluster may only scan configurations or vulnerabilities
  const rows = [
    ...(configurationScanSummary
      ? [
          {
            name: (
              <Link
                routeName={RoutingName.KubescapeConfigurationScanNamespaceSummary}
                params={{ namespace: resourceName }}
                activeCluster={resource.cluster}
              >
                Configuration scan
              </Link>
            ),
            value: namespaceControlsSummary(
              failedControls,
              configurationScanSummary.spec?.severities
            ),
          },
        ]
      : []),
    ...(vulnerabilitySummary
      ? [
          {
            name: (
              <Link
                routeName={RoutingName.VulnerabilitiesNamespaceSummary}
                params={{ namespace: resourceName }}
                activeCluster={resource.cluster}
              >
                Vulnerabilities
              </Link>
            ),
            value: getCVESummary(vulnerabilitySummary, false, false),
          },
        ]
      : []),
  ];

  return (
    rows.length > 0 && (
      <SectionBox title="Kubescape">
        <NameValueTable rows={rows} />
      </SectionBox>
    )
  );
}

function namespaceControlsSummary(
  failedControls: ReturnType<typeof useNamespaceFailedControls>,
  scannerCounts: any
) {
  const { counts, error, exceptionsError } = failedControls;
  if (counts) {
    return (
      <>
        {getControlsSummary(counts)}
        <ExceptionsNote error={exceptionsError} />
      </>
    );
  }
  if (!error) return 'Reading the workload results…';
  // the counts of the storage, which leave out the exceptions that the plugin applies
  return (
    <>
      {getControlsSummary({
        critical: scannerCounts?.critical ?? 0,
        high: scannerCounts?.high ?? 0,
        medium: scannerCounts?.medium ?? 0,
        low: scannerCounts?.low ?? 0,
      })}
      <Typography variant="caption" color="text.secondary">
        As counted by the scanner, without the exceptions that the plugin applies: unable to read
        the results of the workloads: {error}
      </Typography>
    </>
  );
}
