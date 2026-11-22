/* 
  Show vulnerability scan results for a workload. 
*/
import { Icon } from '@iconify/react';
import { ApiError, request } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import {
  DateLabel,
  NameValueTable,
  SectionBox,
  ShowHideLabel,
} from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { getCluster } from '@kinvolk/headlamp-plugin/lib/Utils';
import {
  Alert,
  Button,
  Chip,
  FormControlLabel,
  IconButton,
  Stack,
  Switch,
  Tooltip,
} from '@mui/material';
import { ReactNode, useEffect, useMemo, useRef, useState } from 'react';
import { ErrorMessage } from '../common/ErrorMessage';
import { errorMessage, errorStatus } from '../common/errors';
import { vulnerabilityScanCommand } from '../common/operatorCommands';
import { ScanNowButton } from '../common/ScanNowButton';
import makeSeverityLabel from '../common/SeverityLabel';
import HeadlampTable from '../common/Table';
import { getURLSegments, useURLSearchParam } from '../common/url';
import { getKubescapeNamespace } from '../custom-objects/api-queries';
import { GuidedVulnerabilityExceptionForm } from '../exceptions/GuidedVulnerabilityExceptionForm';
import {
  CveException,
  exceptionStateLabels,
  findingException,
  ignoredMatchException,
  isSuppressing,
  ScannedWorkload,
  workloadCveExceptions,
} from '../exceptions/vulnerabilityExceptions';
import { VulnerabilityManifest } from '../softwarecomposition/VulnerabilityManifest';
import { VulnerabilityManifestSummary } from '../softwarecomposition/VulnerabilityManifestSummary';
import { DataSourceLink, getCVESummary } from './CVESummary';
import {
  AcceptRiskButton,
  ExceptionChip,
  exceptionChipValue,
  ExceptionReadErrors,
  useSecurityExceptions,
} from './exceptionChips';
import { ExploitInfo, matchExploitIds } from './exploitData';
import { ImageReference } from './ImageReference';
import { imageSourceLabel } from './imageSource';
import { imageVersionRows, useImageVersion, useImageVersionSettings } from './ImageVersion';
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
import { findingKey, relevantFindingKeys, uniqueFindingIds } from './relevance';
import { getScanTime, getVulnerabilityReportCreatedAt } from './reportTimestamp';
import { getManifestNamespace } from './scanData';

export default function KubescapeVulnerabilityDetails() {
  const [name, namespace] = getURLSegments(-1, -2);
  const cluster = getCluster() ?? undefined;

  const [summary, setSummary] = useState<VulnerabilityManifestSummary | null>(null);
  const [manifestAll, setManifestAll] = useState<VulnerabilityManifest | null>(null);
  const [manifestRelevant, setManifestRelevant] = useState<VulnerabilityManifest | null>(null);
  // the reports that could not be read, and why
  const [reportErrors, setReportErrors] = useState<string[]>([]);
  const [scanStarted, setScanStarted] = useState(false);
  // changed to read the scan results again
  const [reloadKey, setReloadKey] = useState(0);
  const [error, setError] = useState<ApiError | null>(null);

  useEffect(() => {
    let cancelled = false;
    setSummary(null);
    setManifestAll(null);
    setManifestRelevant(null);
    setReportErrors([]);
    setError(null);
    fetchVulnerabilityManifest(name, namespace, cluster)
      .then(([summary, all, relevant, errors]) => {
        if (cancelled) return;
        setSummary(summary);
        setManifestAll(all);
        setManifestRelevant(relevant);
        setReportErrors(errors);
      })
      .catch(error => {
        console.error(error);
        if (!cancelled) setError(error);
      });
    return () => {
      cancelled = true;
    };
  }, [name, namespace, cluster, reloadKey]);

  const wlid = summary?.metadata.annotations?.['kubescape.io/wlid'];

  if (error) {
    return (
      <SectionBox title="Vulnerabilities" backLink>
        <ErrorMessage error={error} />
      </SectionBox>
    );
  }

  return (
    summary && (
      <WorkloadVulnerabilities
        summary={summary}
        manifestAll={manifestAll}
        manifestRelevant={manifestRelevant}
        reportErrors={reportErrors}
        cluster={cluster}
        scanActions={
          wlid &&
          cluster && (
            <>
              <ScanNowButton
                clusters={[cluster]}
                command={scanCluster => vulnerabilityScanCommand(wlid, scanCluster)}
                label="Rescan"
                tooltip="Ask Kubescape to scan the images of this workload for vulnerabilities now"
                onStarted={() => setScanStarted(true)}
              />
              {scanStarted && (
                <Button variant="outlined" size="small" onClick={() => setReloadKey(k => k + 1)}>
                  Reload results
                </Button>
              )}
            </>
          )
        }
      />
    )
  );
}

// A finding with the exception that covers it; hidden when kubevuln no longer counts it. The
// rowId is unique in the list, also for copies of a package at other paths. The exploit data
// arrives later, with new rows.
type Finding = VulnerabilityManifest.Match & {
  exception?: CveException;
  hidden?: boolean;
  rowId: string;
  exploit?: ExploitInfo;
};

// what the chip of the exception of a finding says about counting it
function exceptionNote(finding: Finding): string | undefined {
  if (!finding.exception) return undefined;
  if (finding.hidden) return 'Kubescape no longer counts this finding.';
  return isSuppressing(finding.exception.state)
    ? 'Kubescape stops counting this finding at its next scan, when the riskAcceptance capability is enabled.'
    : undefined;
}

function WorkloadVulnerabilities(
  props: Readonly<{
    summary: VulnerabilityManifestSummary;
    manifestAll: VulnerabilityManifest | null;
    manifestRelevant: VulnerabilityManifest | null;
    // the reports that could not be read, and why
    reportErrors: string[];
    cluster?: string;
    scanActions: ReactNode;
  }>
) {
  const { summary, manifestAll, manifestRelevant, reportErrors, cluster, scanActions } = props;
  const workload = useMemo<ScannedWorkload>(
    () => ({
      kind: summary.metadata.labels['kubescape.io/workload-kind'],
      name: summary.metadata.labels['kubescape.io/workload-name'],
      namespace: summary.metadata.labels['kubescape.io/workload-namespace'],
      image: summary.metadata.annotations['kubescape.io/image-tag'],
    }),
    [summary]
  );
  const {
    exceptions,
    errors: exceptionErrors,
    reload,
  } = useSecurityExceptions([cluster ?? ''], [workload.kind]);
  const exceptionData = exceptions.get(cluster ?? '');
  const [accepting, setAccepting] = useState(false);
  const versionSettings = useImageVersionSettings();
  const imageVersion = useImageVersion(
    workload.image,
    cluster,
    imageSourceLabel(manifestAll?.spec.payload.source?.target?.config)
  );

  // the findings, with those that an exception hid from the report
  const findings = useMemo(() => {
    if (!manifestAll) return [];
    const covered = exceptionData
      ? workloadCveExceptions(exceptionData, workload)
      : new Map<string, CveException>();
    const list: Omit<Finding, 'rowId'>[] = [
      ...(manifestAll.spec.payload.matches ?? []).map(match => ({
        ...match,
        exception: findingException(covered, match),
      })),
      ...(manifestAll.spec.payload.ignoredMatches ?? []).map(match => ({
        ...match,
        hidden: true,
        exception: findingException(covered, match) ?? ignoredMatchException(match),
      })),
    ];
    const rowIds = uniqueFindingIds(list);
    return list.map((finding, i): Finding => ({ ...finding, rowId: rowIds[i] }));
  }, [manifestAll, exceptionData, workload]);
  // the CVEs that kubevuln counts, which no exception hides
  const openCves = useMemo(
    () => [
      ...new Set(
        findings
          .filter(
            finding =>
              !finding.hidden && !(finding.exception && isSuppressing(finding.exception.state))
          )
          .map(finding => finding.vulnerability.id)
      ),
    ],
    [findings]
  );

  const imageEvaluatedAt = getVulnerabilityReportCreatedAt(manifestAll);
  const relevantEvaluatedAt = getVulnerabilityReportCreatedAt(manifestRelevant);
  // recent kubevuln versions only record when they scanned, on the summary
  const scannedAt = getScanTime(summary);
  const evaluationRows =
    imageEvaluatedAt || relevantEvaluatedAt || !scannedAt
      ? [
          {
            name: 'Image last evaluated',
            value: imageEvaluatedAt ? <DateLabel date={imageEvaluatedAt} /> : 'Unknown',
          },
          {
            name: 'Relevant findings last evaluated',
            value: relevantEvaluatedAt ? <DateLabel date={relevantEvaluatedAt} /> : 'Unknown',
          },
        ]
      : [{ name: 'Last scanned', value: <DateLabel date={scannedAt} /> }];

  return (
    <>
      <SectionBox title="Vulnerabilities" backLink>
        <ExceptionReadErrors errors={exceptionErrors} />
        {reportErrors.map(message => (
          <Alert key={message} severity="error" sx={{ mb: 1 }}>
            Unable to read {message}
          </Alert>
        ))}
        {(scanActions || openCves.length > 0) && (
          <Stack direction="row" spacing={1} sx={{ mb: 1 }}>
            {scanActions}
            {openCves.length > 0 && (
              <AcceptRiskButton cveIds={openCves} onClick={() => setAccepting(true)} />
            )}
          </Stack>
        )}
        <NameValueTable
          rows={[
            {
              name: 'Workload',
              value: summary.metadata.labels['kubescape.io/workload-name'],
            },
            {
              name: 'Namespace',
              value: summary.metadata.labels['kubescape.io/workload-namespace'],
            },
            {
              name: 'Container',
              value: summary.metadata.labels['kubescape.io/workload-container-name'],
            },
            {
              name: 'Kind',
              value: summary.metadata.labels['kubescape.io/workload-kind'],
            },
            {
              name: 'Image',
              value: (
                <ImageReference
                  image={summary.metadata.annotations['kubescape.io/image-tag']}
                  report={
                    manifestAll
                      ? {
                          name: manifestAll.metadata.name,
                          namespace: manifestAll.metadata.namespace,
                          cluster,
                        }
                      : undefined
                  }
                />
              ),
            },
            ...imageVersionRows(imageVersion, versionSettings),
            ...evaluationRows,
            {
              name: 'Scan record created',
              value: summary.metadata.creationTimestamp,
            },
            {
              name: 'Type',
              value: manifestAll?.spec.payload.source?.type,
            },
            {
              name: 'CVE',
              value: getCVESummary(summary, true, true),
            },
            {
              name: 'Relevant CVE',
              value: getCVESummary(summary, true, true, true),
            },
          ]}
        />

        {manifestAll && (
          <Matches
            findings={findings}
            relevant={manifestRelevant}
            workloadName={workload.name}
            workloadNamespace={workload.namespace}
            workloadKind={workload.kind}
            imageRef={workload.image}
            cluster={cluster}
            onExceptionCreated={reload}
          />
        )}
      </SectionBox>

      {accepting && (
        <GuidedVulnerabilityExceptionForm
          acceptRisk
          cveIds={openCves}
          imageRef={workload.image}
          workloadName={workload.name}
          workloadNamespace={workload.namespace}
          workloadKind={workload.kind}
          cluster={cluster}
          onClose={() => setAccepting(false)}
          onCreated={reload}
        />
      )}
    </>
  );
}

function Matches(
  props: Readonly<{
    findings: Finding[];
    relevant: VulnerabilityManifest | null;
    workloadName: string;
    workloadNamespace: string;
    workloadKind: string;
    imageRef?: string;
    cluster?: string;
    onExceptionCreated: () => void;
  }>
) {
  const {
    findings,
    relevant,
    workloadName,
    workloadNamespace,
    workloadKind,
    imageRef,
    cluster,
    onExceptionCreated: reload,
  } = props;

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

  // Severity links count all findings, so they open with the Relevant CVE switch off
  const [severity, clearSeverity] = useURLSearchParam('severity');
  const results = rows.filter(match => !severity || match.vulnerability.severity === severity);
  const [isRelevantCVESwitchChecked, setIsRelevantCVESwitchChecked] = useState(!severity);
  const [selectedCve, setSelectedCve] = useState<string | null>(null);
  const [acceptedCves, setAcceptedCves] = useState<string[] | null>(null);
  const clearSelection = useRef<() => void>(() => {});

  // Without a relevant manifest all findings are shown. A relevant manifest without matches
  // means that none of the findings is relevant. Relevance is per CVE and package, as a CVE of
  // several packages can be relevant for only some of them.
  const relevantKeys = useMemo(
    () =>
      relevant
        ? relevantFindingKeys(relevant.spec.payload.matches, relevant.spec.payload.ignoredMatches)
        : undefined,
    [relevant]
  );
  const isRelevant = (match: VulnerabilityManifest.Match) =>
    !relevantKeys ? 'Unknown' : relevantKeys.has(findingKey(match)) ? 'Yes' : 'No';
  const relevantShown =
    isRelevantCVESwitchChecked && relevantKeys
      ? results.filter(r => relevantKeys.has(findingKey(r)))
      : results;
  const shown = showExploitedOnly
    ? relevantShown.filter(finding => finding.exploit?.kev)
    : relevantShown;
  const fixVersions = (match: VulnerabilityManifest.Match) =>
    Array.isArray(match.vulnerability.fix?.versions)
      ? match.vulnerability.fix.versions.join(', ')
      : '';
  const exceptionLabel = (finding: Finding) =>
    finding.exception ? exceptionStateLabels[finding.exception.state] : '';

  let emptyMessage: string | undefined;
  if (shown.length === 0 && relevantShown.length > 0) {
    emptyMessage = knownExploitedEmptyMessage(exploitData, 'findings');
  } else if (shown.length === 0 && results.length > 0) {
    emptyMessage = `None of the ${results.length} findings is relevant: Kubescape did not see the workload use the vulnerable packages. Switch off Relevant CVE to show them all.`;
  }

  return (
    <SectionBox title="Findings">
      <ExploitDataErrors data={exploitData} />
      <HeadlampTable
        toolbarStart={
          <>
            <FormControlLabel
              checked={isRelevantCVESwitchChecked}
              control={<Switch color="primary" />}
              label={'Relevant CVE'}
              onChange={(_event, checked) => {
                setIsRelevantCVESwitchChecked(checked);
              }}
            />
            <KnownExploitedSwitch
              settings={exploitSettings}
              checked={exploitedOnly}
              onChange={setExploitedOnly}
            />
            {severity && (
              <Chip label={`Only ${severity} findings`} onDelete={clearSeverity} size="small" />
            )}
          </>
        }
        csvExport={{
          fileName: `kubescape-${workloadNamespace}-${workloadName}-cves.csv`,
          header: [
            'Severity',
            'CVE',
            'CVSS',
            ...exploitCsvHeader(exploitSettings),
            'Artifact',
            'Version',
            'Relevant',
            'Fix',
            'Fix in version',
            'Exception',
            'Description',
          ],
          rows: () =>
            shown.map(match => [
              match.vulnerability.severity,
              match.vulnerability.id,
              match.vulnerability.cvss?.[0]?.metrics?.baseScore,
              ...exploitCsvValues(match.exploit, exploitSettings),
              match.artifact.name,
              match.artifact.version,
              isRelevant(match),
              match.vulnerability.fix?.state,
              fixVersions(match),
              match.exception && `${exceptionLabel(match)}: ${match.exception.name}`,
              match.vulnerability.description,
            ]),
        }}
        data={shown}
        emptyMessage={emptyMessage}
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
            Cell: ({ cell }) => (
              <DataSourceLink href={cell.row.original.vulnerability.dataSource}>
                {cell.getValue()}
              </DataSourceLink>
            ),
            gridTemplate: 'auto',
          },
          {
            id: 'Score',
            header: 'CVSS',
            accessorFn: cvssScore,
            gridTemplate: 'auto',
          },
          ...exploitColumns<Finding>(exploitSettings),
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
            header: 'Relevant',
            accessorFn: isRelevant,
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
            // the label, the name and the rest of what the chip shows, so that the chip is drawn
            // again for another exception
            accessorFn: (finding: Finding) =>
              exceptionChipValue(finding.exception, exceptionNote(finding)),
            Cell: ({ row }) => {
              const finding = row.original as Finding;
              if (!finding.exception) return null;
              return (
                <ExceptionChip
                  exception={finding.exception}
                  cluster={cluster}
                  note={exceptionNote(finding)}
                />
              );
            },
            gridTemplate: 'auto',
          },
          {
            header: 'Description',
            accessorKey: 'vulnerability.description',
            Cell: ({ cell }) => <ShowHideLabel>{cell.getValue()}</ShowHideLabel>,
          },
          {
            id: 'actions',
            header: '',
            // a value per finding, so that the button of each row is its own
            accessorFn: (finding: Finding) => finding.rowId,
            // rendered for the rows on the page only; the form also offers the exception as
            // YAML, so it opens without the permission to create one
            Cell: ({ row }) => (
              <Tooltip title="Create Vulnerability Exception">
                <IconButton
                  size="small"
                  aria-label="Create Vulnerability Exception"
                  onClick={() => setSelectedCve(row.original.vulnerability.id)}
                >
                  <Icon icon="mdi:shield-plus-outline" />
                </IconButton>
              </Tooltip>
            ),
            gridTemplate: 'min-content',
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
        enableRowSelection
        getRowId={finding => finding.rowId}
        renderRowSelectionToolbar={({ table }) => {
          const selected = [
            ...new Set(table.getSelectedRowModel().rows.map(row => row.original.vulnerability.id)),
          ];
          clearSelection.current = () => table.resetRowSelection();
          return (
            <Button
              variant="contained"
              size="small"
              startIcon={<Icon icon="mdi:shield-check-outline" />}
              onClick={() => setAcceptedCves(selected)}
            >
              Accept the risk of {selected.length} {selected.length === 1 ? 'CVE' : 'CVEs'}
            </Button>
          );
        }}
      />

      {acceptedCves && (
        <GuidedVulnerabilityExceptionForm
          acceptRisk
          cveIds={acceptedCves}
          imageRef={imageRef}
          workloadName={workloadName}
          workloadNamespace={workloadNamespace}
          workloadKind={workloadKind}
          cluster={cluster}
          onClose={() => setAcceptedCves(null)}
          onCreated={() => {
            clearSelection.current();
            reload();
          }}
        />
      )}

      {selectedCve && (
        <GuidedVulnerabilityExceptionForm
          cveIds={[selectedCve]}
          imageRef={imageRef}
          workloadName={workloadName}
          workloadNamespace={workloadNamespace}
          workloadKind={workloadKind}
          cluster={cluster}
          onClose={() => setSelectedCve(null)}
          onCreated={reload}
        />
      )}
    </SectionBox>
  );
}

function cvssScore(match: VulnerabilityManifest.Match): number {
  return match.vulnerability.cvss?.[0]?.metrics?.baseScore ?? 0;
}

// Full reports carry evaluation times; the summary only supplies their references. The last
// item says which of the reports could not be read, and why, for the page to show.
export async function fetchVulnerabilityManifest(
  name: string,
  namespace: string,
  cluster?: string
): Promise<
  [
    VulnerabilityManifestSummary,
    VulnerabilityManifest | null,
    VulnerabilityManifest | null,
    string[]
  ]
> {
  const summary: VulnerabilityManifestSummary = await request(
    `/apis/spdx.softwarecomposition.kubescape.io/v1beta1/namespaces/${namespace}/vulnerabilitymanifestsummaries/${name}`,
    { cluster }
  );
  const errors: string[] = [];

  async function getManifest(
    what: string,
    reference?: {
      name?: string;
      namespace?: string;
    }
  ): Promise<VulnerabilityManifest | null> {
    if (!reference?.name) return null;
    const read = (namespace: string) =>
      request(
        `/apis/spdx.softwarecomposition.kubescape.io/v1beta1/namespaces/${namespace}/vulnerabilitymanifests/${reference.name}`,
        { cluster }
      );
    const failed = (error: unknown) => {
      console.error(error);
      errors.push(`${what} (${reference.name}): ${errorMessage(error)}`);
      return null;
    };
    const referenced = getManifestNamespace(reference);
    try {
      return await read(referenced);
    } catch (error) {
      if (errorStatus(error) !== 404) return failed(error);
      // the storage may keep the report in the operator namespace instead of the referenced one;
      // like the list of the workloads, it looks in the default namespace of Kubescape while the
      // operator namespace cannot be looked up
      const operator = await getKubescapeNamespace(cluster ?? getCluster()).then(
        found => found.kubeScapeNamespace,
        () => undefined
      );
      const fallback = operator || getManifestNamespace({});
      if (fallback === referenced) return failed(error);
      try {
        return await read(fallback);
      } catch (fallbackError) {
        return failed(fallbackError);
      }
    }
  }

  const all = await getManifest('the report of the image', summary.spec.vulnerabilitiesRef?.all);
  const relevant = await getManifest(
    'the report of the relevant findings',
    summary.spec.vulnerabilitiesRef?.relevant
  );
  return [summary, all, relevant, errors];
}
