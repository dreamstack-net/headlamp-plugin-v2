/*
  Provide information on a CVE and the workloads vulnerable for this CVE.
*/
import { Icon } from '@iconify/react';
import {
  Link as HeadlampLink,
  NameValueTable,
  SectionBox,
} from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { Alert, IconButton, Tooltip } from '@mui/material';
import { MutableRefObject, useEffect, useMemo, useRef, useState } from 'react';
import { KubescapeConfig, kubescapeConfigStore } from '../common/config-store';
import { errorMessage } from '../common/errors';
import { ProgressIndicator, useCurrentReadFlag } from '../common/ProgressIndicator';
import HeadlampTable from '../common/Table';
import { getURLSegments } from '../common/url';
import { GuidedVulnerabilityExceptionForm } from '../exceptions/GuidedVulnerabilityExceptionForm';
import { RoutingName, useHLSelectedClusters } from '../index';
import { DataSourceLink } from './CVESummary';
import { getWorkloadScanKey } from './scanData';
import { readVulnerabilityScans, vulnerabilityContext, WorkloadScan } from './Vulnerabilities';

export default function KubescapeCVEResults() {
  const [cve] = getURLSegments(-1);
  const clusters = useHLSelectedClusters();
  const clusterKey = clusters.join(',');
  // the scans the other pages read of the selected clusters; this page reads them itself when
  // opened directly
  const [scans, setScans] = useState<WorkloadScan[]>(() =>
    vulnerabilityContext.workloadScans.filter(scan => clusters.includes(scan.cluster))
  );
  const [loading, setLoading] = useState(false);
  const [progressMessage, setProgressMessage] = useState('Reading Kubescape scans');
  const [error, setError] = useState<string | null>(null);
  // the flag of the current read, which the Cancel button of the progress indicator clears
  const reading = useRef<MutableRefObject<boolean>>({ current: true });
  // what the Cancel button of the progress stops
  const currentRead = useCurrentReadFlag(reading);

  useEffect(() => {
    // the scans of clusters that are no longer selected, and the error of the read for them, are
    // not shown for the clusters selected now
    setScans(previous => {
      const selected = previous.filter(scan => clusters.includes(scan.cluster));
      return selected.length === previous.length ? previous : selected;
    });
    setError(null);
    if (clusters.length === 0) return;
    let active = true;
    // each read has a flag of its own, so a read for other clusters stops when this one starts
    const continueReading = { current: true };
    reading.current = continueReading;
    readVulnerabilityScans(
      clusters,
      (kubescapeConfigStore.get() ?? {}) as KubescapeConfig,
      continueReading,
      loading => active && setLoading(loading),
      message => active && setProgressMessage(message)
    )
      .then(result => active && setScans(result))
      .catch(err => {
        if (!active) return;
        setError(errorMessage(err));
        setLoading(false);
      });
    return () => {
      active = false;
      continueReading.current = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clusterKey]);

  const workloadScansFiltered = useMemo(
    () =>
      scans.filter(workloadScan =>
        workloadScan.imageScan?.matches.some(match => match.vulnerability.id === cve)
      ),
    [scans, cve]
  );
  const firstCVE = workloadScansFiltered[0]?.imageScan?.matches?.find(
    match => match.vulnerability.id === cve
  );

  return (
    <SectionBox title={cve} backLink>
      {error && (
        <Alert severity="error" sx={{ mb: 1 }}>
          Unable to read the vulnerability reports: {error}
        </Alert>
      )}
      {loading && (
        <ProgressIndicator continueReading={currentRead} progressMessage={progressMessage} />
      )}
      {!loading && !firstCVE && !error && (
        <Alert severity="info">No scanned workload of the selected clusters has {cve}.</Alert>
      )}
      {firstCVE && (
        <>
          <NameValueTable
            rows={[
              {
                name: 'CVE ID',
                value: (
                  <DataSourceLink href={firstCVE.vulnerability.dataSource}>{cve}</DataSourceLink>
                ),
              },
              {
                name: 'Severity',
                value: firstCVE.vulnerability.severity,
              },
              {
                name: 'Description',
                value: firstCVE.vulnerability.description,
              },
            ]}
          />

          <Workloads cve={cve} workloads={workloadScansFiltered} clusters={clusters} />
        </>
      )}
    </SectionBox>
  );
}

function Workloads(
  props: Readonly<{ cve: string; workloads: WorkloadScan[]; clusters: string[] }>
) {
  const { cve, workloads, clusters } = props;
  const [exceptionFormWorkload, setExceptionFormWorkload] = useState<WorkloadScan | null>(null);
  const matchesOf = (workload: WorkloadScan) =>
    workload.imageScan?.matches.filter(v => v.vulnerability.id === cve) ?? [];

  return (
    <SectionBox title="Workloads">
      <HeadlampTable
        data={workloads}
        getRowId={getWorkloadScanKey}
        columns={[
          {
            id: 'Workload',
            header: 'Workload',
            accessorKey: 'name',
            Cell: ({ row }) => {
              const workload: WorkloadScan = row.original;
              return (
                <HeadlampLink
                  routeName={RoutingName.KubescapeVulnerabilityDetails}
                  activeCluster={workload.cluster}
                  params={{
                    name: workload.manifestName,
                    namespace: workload.namespace,
                  }}
                >
                  {workload.name}
                </HeadlampLink>
              );
            },
            gridTemplate: 'auto',
          },
          {
            header: 'Kind',
            accessorKey: 'kind',
            gridTemplate: 'auto',
          },
          {
            header: 'Namespace',
            accessorKey: 'namespace',
            gridTemplate: 'auto',
          },
          ...(clusters.length > 1
            ? [{ header: 'Cluster', accessorKey: 'cluster', gridTemplate: 'auto' }]
            : []),
          {
            header: 'Container',
            accessorKey: 'container',
            gridTemplate: 'auto',
          },
          {
            header: 'Component',
            accessorFn: (workload: WorkloadScan) =>
              [
                ...new Set(
                  matchesOf(workload).map(v => `${v.artifact.name} ${v.artifact.version}`)
                ),
              ].join(', '),
            gridTemplate: 'auto',
          },
          {
            header: 'Fix',
            accessorFn: (workload: WorkloadScan) =>
              [
                ...new Set(
                  matchesOf(workload)
                    .filter(v => v.vulnerability.fix?.versions?.length)
                    .map(v => v.vulnerability.fix.versions.join(', '))
                ),
              ].join('; '),
            gridTemplate: 'auto',
          },
          {
            header: 'Image',
            accessorFn: (workload: WorkloadScan) => workload.imageScan?.imageName,
            gridTemplate: 'auto',
          },
          {
            id: 'actions',
            header: '',
            // a value per workload, so that the button of each row is its own
            accessorFn: (workload: WorkloadScan) => getWorkloadScanKey(workload),
            // the form also offers the exception as YAML, so it opens without the permission
            // to create one
            Cell: ({ row }) => {
              const workload: WorkloadScan = row.original;
              return (
                <Tooltip title="Create Security Exception">
                  <IconButton
                    size="small"
                    aria-label="Create Security Exception"
                    onClick={() => setExceptionFormWorkload(workload)}
                  >
                    <Icon icon="mdi:shield-plus-outline" />
                  </IconButton>
                </Tooltip>
              );
            },
            gridTemplate: 'auto',
          },
        ]}
      />
      {exceptionFormWorkload && (
        <GuidedVulnerabilityExceptionForm
          cveIds={[cve]}
          imageRef={exceptionFormWorkload.imageScan?.imageName}
          workloadName={exceptionFormWorkload.name}
          workloadNamespace={exceptionFormWorkload.namespace}
          workloadKind={exceptionFormWorkload.kind}
          cluster={exceptionFormWorkload.cluster}
          onClose={() => setExceptionFormWorkload(null)}
        />
      )}
    </SectionBox>
  );
}
