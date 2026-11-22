/* 
  Show vulnerability scan results for a container image. 
*/
import { ApiError } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import {
  DateLabel,
  Link as HeadlampLink,
  NameValueTable,
  SectionBox,
  ShowHideLabel,
} from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { getCluster } from '@kinvolk/headlamp-plugin/lib/Utils';
import { Alert, Chip, Stack, Typography } from '@mui/material';
import { useEffect, useMemo, useState } from 'react';
import { CompactTable } from '../common/CompactTable';
import { ErrorMessage } from '../common/ErrorMessage';
import { errorMessage } from '../common/errors';
import { useStorageObject } from '../common/readOnce';
import makeSeverityLabel from '../common/SeverityLabel';
import HeadlampTable from '../common/Table';
import { getURLSegments, useURLSearchParam } from '../common/url';
import { GuidedVulnerabilityExceptionForm } from '../exceptions/GuidedVulnerabilityExceptionForm';
import {
  CveException,
  exceptionStateLabels,
  findingException,
  imageCveExceptions,
  isSuppressing,
  summarizeWorkloadExceptions,
} from '../exceptions/vulnerabilityExceptions';
import { RoutingName } from '../index';
import { vulnerabilityManifestClass } from '../model';
import { VulnerabilityManifest } from '../softwarecomposition/VulnerabilityManifest';
import { DataSourceLink } from './CVESummary';
import {
  AcceptRiskButton,
  ExceptionChip,
  exceptionChipValue,
  ExceptionReadErrors,
  useSecurityExceptions,
} from './exceptionChips';
import { matchExploitIds } from './exploitData';
import { ImageReference } from './ImageReference';
import { imageSourceLabel } from './imageSource';
import { imageVersionRows, useImageVersion, useImageVersionSettings } from './ImageVersion';
import { fetchImageWorkloads, ImageWorkload, latestScan } from './imageWorkloads';
import {
  exploitColumns,
  exploitCsvHeader,
  exploitCsvValues,
  ExploitDataErrors,
  knownExploitedEmptyMessage,
  KnownExploitedSwitch,
  useExploitData,
  withExploits,
} from './KnownExploited';
import { uniqueFindingIds } from './relevance';
import { getVulnerabilityReportCreatedAt } from './reportTimestamp';

export default function ImageVulnerabilityDetails() {
  const [name, namespace] = getURLSegments(-1, -2);
  const cluster = getCluster() ?? '';
  // read once: a watch of the storage would replace the report with one without its matches
  const { data: manifestVulnerability, error } = useStorageObject<VulnerabilityManifest>(
    vulnerabilityManifestClass,
    name,
    namespace,
    cluster || undefined
  );

  // the workloads that run the image, whose summaries carry its image-id label
  const imageId = manifestVulnerability?.metadata.labels?.['kubescape.io/image-id'];
  const [workloads, setWorkloads] = useState<ImageWorkload[] | null>(null);
  const [workloadsError, setWorkloadsError] = useState('');
  // the allowed namespaces whose workloads could not be read
  const [namespaceErrors, setNamespaceErrors] = useState<string[]>([]);
  useEffect(() => {
    // the workloads of the image shown before, or of the cluster shown before, are not of this one
    setWorkloads(null);
    setWorkloadsError('');
    setNamespaceErrors([]);
    if (!imageId) return;
    let active = true;
    fetchImageWorkloads(imageId, cluster)
      .then(found => {
        if (!active) return;
        setWorkloads(found.workloads);
        setNamespaceErrors(found.errors);
      })
      .catch(err => {
        if (active) setWorkloadsError(errorMessage(err));
      });
    return () => {
      active = false;
    };
  }, [imageId, cluster]);

  // the exceptions for the image in the whole cluster; those of a workload do not cover it
  // wherever it runs
  const image: string | undefined =
    manifestVulnerability?.metadata.annotations?.['kubescape.io/image-tag'];
  const versionSettings = useImageVersionSettings();
  const imageVersion = useImageVersion(
    image,
    cluster,
    imageSourceLabel(manifestVulnerability?.spec.payload.source?.target?.config)
  );
  const { exceptions, errors: exceptionErrors, reload } = useSecurityExceptions([cluster], []);
  const exceptionData = exceptions.get(cluster);
  const covered = useMemo(
    () =>
      exceptionData && image
        ? imageCveExceptions(exceptionData, image)
        : new Map<string, CveException>(),
    [exceptionData, image]
  );
  const matches: VulnerabilityManifest.Match[] | null | undefined =
    manifestVulnerability?.spec.payload.matches;
  const openCves = useMemo(
    () => summarizeWorkloadExceptions(covered, matches ?? []).open,
    [covered, matches]
  );
  const [accepting, setAccepting] = useState(false);

  if (manifestVulnerability) {
    const evaluatedAt = getVulnerabilityReportCreatedAt(manifestVulnerability);
    // recent kubevuln versions only record when they scanned, on the summaries of the workloads
    const scannedAt = latestScan(workloads ?? []);
    return (
      <>
        <SectionBox title="Image Vulnerabilities" backLink>
          <ExceptionReadErrors errors={exceptionErrors} />
          {image && openCves.length > 0 && (
            <Stack direction="row" spacing={1} sx={{ mb: 1 }}>
              <AcceptRiskButton cveIds={openCves} onClick={() => setAccepting(true)} />
            </Stack>
          )}
          <NameValueTable
            rows={[
              {
                name: 'Image',
                value: <ImageReference image={image} />,
              },
              ...imageVersionRows(imageVersion, versionSettings),
              evaluatedAt || !scannedAt
                ? {
                    name: 'Last evaluated',
                    value: evaluatedAt ? <DateLabel date={evaluatedAt} /> : 'Unknown',
                  }
                : { name: 'Last scanned', value: <DateLabel date={scannedAt} /> },
              {
                name: 'Scan record created',
                value: manifestVulnerability.metadata.creationTimestamp,
              },
            ]}
          />
        </SectionBox>

        <SectionBox title="Workloads">
          {namespaceErrors.length > 0 && (
            <Alert severity="warning" sx={{ mb: 1 }}>
              Unable to read all workloads that run the image: {namespaceErrors.join('; ')}
            </Alert>
          )}
          {workloadsError ? (
            <Alert severity="error">
              Unable to read the workloads that run the image: {workloadsError}
            </Alert>
          ) : !imageId ? (
            <Typography variant="body2">
              Kubescape did not record which workloads run this image.
            </Typography>
          ) : workloads === null ? (
            <Typography variant="body2" color="text.secondary">
              Reading workloads…
            </Typography>
          ) : workloads.length === 0 ? (
            <Typography variant="body2">
              {namespaceErrors.length > 0
                ? 'No workload of the namespaces that could be read runs this image.'
                : 'No workload runs this image anymore.'}
            </Typography>
          ) : (
            <ImageWorkloads workloads={workloads} cluster={cluster} />
          )}
        </SectionBox>

        <Matches
          manifestVulnerability={manifestVulnerability}
          covered={covered}
          cluster={cluster}
        />

        {accepting && image && (
          <GuidedVulnerabilityExceptionForm
            acceptRisk
            cveIds={openCves}
            imageRef={image}
            cluster={cluster || undefined}
            onClose={() => setAccepting(false)}
            onCreated={reload}
          />
        )}
      </>
    );
  }
  return (
    <SectionBox title="Image Vulnerabilities" backLink>
      {error ? (
        <ErrorMessage error={error as ApiError} />
      ) : (
        <Typography variant="body2" color="text.secondary">
          Reading the vulnerabilities of the image…
        </Typography>
      )}
    </SectionBox>
  );
}

function ImageWorkloads(props: Readonly<{ workloads: ImageWorkload[]; cluster: string }>) {
  const { workloads, cluster } = props;
  return (
    <CompactTable
      rows={workloads}
      rowKey={workload => `${workload.summaryNamespace}/${workload.summaryName}`}
      columns={[
        {
          header: 'Workload',
          // Headlamp names the routes of its resource pages after their kind
          cell: workload => (
            <HeadlampLink
              routeName={workload.kind}
              params={{ namespace: workload.namespace, name: workload.name }}
              activeCluster={cluster}
            >
              {workload.name}
            </HeadlampLink>
          ),
        },
        { header: 'Kind', cell: workload => workload.kind },
        { header: 'Namespace', cell: workload => workload.namespace },
        { header: 'Container', cell: workload => workload.container },
        {
          header: 'Vulnerabilities',
          cell: workload => (
            <HeadlampLink
              routeName={RoutingName.KubescapeVulnerabilityDetails}
              params={{ namespace: workload.summaryNamespace, name: workload.summaryName }}
              activeCluster={cluster}
            >
              Findings
            </HeadlampLink>
          ),
        },
      ]}
    />
  );
}

// what the chip of an exception of the image says about counting the finding
function exceptionNote(exception: CveException | undefined): string | undefined {
  return exception && isSuppressing(exception.state)
    ? 'Kubescape stops counting this finding at its next scan, when the riskAcceptance capability is enabled.'
    : undefined;
}

function Matches(
  props: Readonly<{
    manifestVulnerability: VulnerabilityManifest;
    // the exceptions for the image in the whole cluster, by CVE id
    covered: Map<string, CveException>;
    cluster: string;
  }>
) {
  const { manifestVulnerability, covered, cluster } = props;
  const [severity, clearSeverity] = useURLSearchParam('severity');
  const findings = useMemo(() => {
    const matches = (manifestVulnerability.spec.payload.matches ?? []).filter(
      match => !severity || match.vulnerability.severity === severity
    );
    // the rows are keyed by these ids, which are unique also for a package at several paths
    const rowIds = uniqueFindingIds(matches);
    return matches.map((match, i) => ({
      ...match,
      exception: findingException(covered, match),
      rowId: rowIds[i],
    }));
  }, [manifestVulnerability, severity, covered]);
  // the EPSS scores of the findings with the highest CVSS score first
  const cveIds = useMemo(
    () =>
      [...findings]
        .sort((a, b) => cvssScore(b) - cvssScore(a))
        .flatMap(finding => matchExploitIds(finding)),
    [findings]
  );
  const exploitData = useExploitData(cveIds);
  const { settings: exploitSettings } = exploitData;
  const [exploitedOnly, setExploitedOnly] = useState(false);
  const showExploitedOnly = exploitSettings.knownExploited && exploitedOnly;
  // new rows when the exploit data arrives, so that the table draws them again
  const rows = useMemo(
    () => withExploits(findings, matchExploitIds, exploitData),
    [findings, exploitData]
  );
  const results = useMemo(
    () => (showExploitedOnly ? rows.filter(finding => finding.exploit?.kev) : rows),
    [rows, showExploitedOnly]
  );
  const exceptionLabel = (match: (typeof results)[number]) =>
    match.exception ? exceptionStateLabels[match.exception.state] : '';

  const fixVersions = (match: VulnerabilityManifest.Match) =>
    Array.isArray(match.vulnerability.fix?.versions)
      ? match.vulnerability.fix.versions.join(', ')
      : '';
  const description = (match: VulnerabilityManifest.Match) =>
    match.vulnerability.description ??
    match.relatedVulnerabilities?.find(related => related.id === match.vulnerability.id)
      ?.description ??
    '';
  const imageName =
    manifestVulnerability.metadata.annotations?.['kubescape.io/image-tag'] ??
    manifestVulnerability.metadata.name;

  const emptyMessage =
    results.length === 0 && rows.length > 0
      ? knownExploitedEmptyMessage(exploitData, 'findings')
      : undefined;

  return (
    <SectionBox title="Findings">
      <ExploitDataErrors data={exploitData} />
      <HeadlampTable
        toolbarStart={
          (severity || exploitSettings.knownExploited) && (
            <>
              <KnownExploitedSwitch
                settings={exploitSettings}
                checked={exploitedOnly}
                onChange={setExploitedOnly}
              />
              {severity && (
                <Chip label={`Only ${severity} findings`} onDelete={clearSeverity} size="small" />
              )}
            </>
          )
        }
        emptyMessage={emptyMessage}
        csvExport={{
          fileName: `kubescape-${manifestVulnerability.metadata.name}-cves.csv`,
          header: [
            'Image',
            'Severity',
            'CVE',
            'CVSS',
            ...exploitCsvHeader(exploitSettings),
            'Artifact',
            'Version',
            'Fix',
            'Fix in version',
            'Exception',
            'Description',
          ],
          rows: () =>
            results.map(match => [
              imageName,
              match.vulnerability.severity,
              match.vulnerability.id,
              match.vulnerability.cvss?.[0]?.metrics?.baseScore,
              ...exploitCsvValues(match.exploit, exploitSettings),
              match.artifact.name,
              match.artifact.version,
              match.vulnerability.fix?.state,
              fixVersions(match),
              match.exception && `${exceptionLabel(match)}: ${match.exception.name}`,
              description(match),
            ]),
        }}
        data={results}
        getRowId={match => match.rowId}
        columns={[
          {
            header: 'Severity',
            accessorKey: 'vulnerability.severity',
            Cell: ({ cell }) => makeSeverityLabel(cell.getValue()),
            gridTemplate: 'auto',
          },
          {
            header: 'CVE',
            accessorKey: 'vulnerability.id',
            Cell: ({ cell }) => {
              return (
                <DataSourceLink href={cell.row.original.vulnerability.dataSource}>
                  {cell.getValue()}
                </DataSourceLink>
              );
            },
            gridTemplate: 'auto',
          },
          {
            id: 'Score',
            header: 'CVSS',
            accessorFn: cvssScore,
            gridTemplate: 'auto',
          },
          ...exploitColumns<(typeof results)[number]>(exploitSettings),
          {
            header: 'Artifact',
            accessorKey: 'artifact.name',
            gridTemplate: 'auto',
          },
          {
            header: 'Version',
            accessorKey: 'artifact.version',
            gridTemplate: 'auto',
          },
          {
            header: 'Fix',
            accessorKey: 'vulnerability.fix.state',
            gridTemplate: 'auto',
          },
          {
            header: 'Fix in version',
            accessorFn: fixVersions,
            gridTemplate: 'auto',
          },
          {
            id: 'Exception',
            header: 'Exception',
            // the label, the name and the rest of what the chip shows, so that the chip is
            // drawn again for another exception
            accessorFn: (match: (typeof results)[number]) =>
              exceptionChipValue(match.exception, exceptionNote(match.exception)),
            Cell: ({ row }) =>
              row.original.exception ? (
                <ExceptionChip
                  exception={row.original.exception}
                  cluster={cluster || undefined}
                  note={exceptionNote(row.original.exception)}
                />
              ) : null,
            gridTemplate: 'auto',
          },
          {
            header: 'Description',
            accessorFn: description,
            Cell: ({ cell }) => <ShowHideLabel>{cell.getValue()}</ShowHideLabel>,
          },
        ]}
        initialState={{
          sorting: [
            {
              id: 'Score',
              desc: true,
            },
          ],
        }}
      />
    </SectionBox>
  );
}

function cvssScore(match: VulnerabilityManifest.Match): number {
  return match.vulnerability.cvss?.[0]?.metrics?.baseScore ?? 0;
}
