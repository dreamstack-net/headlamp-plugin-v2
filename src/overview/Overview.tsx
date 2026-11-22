/*
  Landing page with a summary of compliance, vulnerabilities, runtime alerts and exceptions.
*/
import {
  DateLabel,
  Link as HeadlampLink,
  NameValueTable,
  SectionBox,
} from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { Box, Typography } from '@mui/material';
import { ReactNode, useEffect, useMemo, useState } from 'react';
import { getAllowedNamespaces } from '../common/clusterContext';
import { ClusterErrors } from '../common/ClusterErrors';
import { CompactTable } from '../common/CompactTable';
import { getAlertmanagerUrl, KubescapeConfig, kubescapeConfigStore } from '../common/config-store';
import { errorMessage } from '../common/errors';
import { SetupCheck } from '../common/SetupCheck';
import { SeverityCountStack } from '../common/SeverityCountBox';
import { configurationScanContext, readConfigurationScans } from '../compliance/Compliance';
import { ControlExceptionErrors } from '../compliance/ControlExceptionErrors';
import { countFailedScans } from '../compliance/workload-scanning';
import { fetchSecurityExceptions } from '../exceptions/apply-security-exceptions';
import { useCustomFrameworks } from '../framework/useCustomFrameworks';
import { RoutingName, useHLSelectedClusters } from '../index';
import type { ClusterError } from '../model';
import { QueryTask, queryTaskErrors } from '../query';
import { activeFrameworkNames, useRegoData } from '../rego';
import { alertNamespace, alertWorkload } from '../runtimedetection/alertFields';
import { AlertmanagerAlert, fetchKubescapeAlerts } from '../runtimedetection/alertmanager';
import { WorkloadConfigurationScanSummary } from '../softwarecomposition/WorkloadConfigurationScanSummary';
import { useExploitData } from '../vulnerabilities/KnownExploited';
import { getImageScanKey, WorkloadScan } from '../vulnerabilities/scanData';
import { countBySeverity, getImageUpgrades, ImageUpgrade } from '../vulnerabilities/upgrades';
import {
  readVulnerabilityScans,
  vulnerabilityContext,
  vulnerabilityTabSearch,
} from '../vulnerabilities/Vulnerabilities';
import {
  countCves,
  countKnownExploited,
  ExceptionExpiry,
  expiringExceptions,
  frameworkScores,
} from './summaries';
import { TrendsSection } from './Trends';

export default function KubescapeOverview() {
  return (
    <>
      <h1>Kubescape</h1>
      <SetupCheck
        features={['compliance', 'vulnerabilities', 'networkPolicies', 'runtime', 'exceptions']}
      />
      <ComplianceSummary />
      <VulnerabilitySummary />
      <TrendsSection />
      <RuntimeAlertSummary />
      <ExceptionSummary />
    </>
  );
}

/**
 * Reads data with a loader that reports progress, again when the selected clusters change.
 * Reading stops when the page is left or the clusters change: each read has a flag of its own,
 * so a read for the clusters selected before does not go on. The errors name the clusters that
 * could not be read completely.
 */
function useScans<T>(
  read: (
    clusters: string[],
    config: KubescapeConfig,
    continueReading: React.MutableRefObject<boolean>,
    setLoading: (loading: boolean) => void,
    setProgress: React.Dispatch<React.SetStateAction<string>>
  ) => Promise<T[]>,
  queryTasks: () => QueryTask[]
) {
  const clusters = useHLSelectedClusters();
  const config = kubescapeConfigStore.useConfig()() as KubescapeConfig;
  const [scans, setScans] = useState<T[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState('');
  const [errors, setErrors] = useState<ClusterError[]>([]);
  const clustersKey = clusters.join(',');

  useEffect(() => {
    let active = true;
    const continueReading = { current: true };
    read(
      clusters,
      config,
      continueReading,
      loading => active && setLoading(loading),
      message => active && setProgress(message)
    )
      .then(found => {
        if (!active) return;
        setScans(found);
        setErrors(queryTaskErrors(queryTasks()));
      })
      .catch(error => {
        console.error(error);
        if (!active) return;
        setScans([]);
        setErrors(clusters.map(cluster => ({ cluster, message: errorMessage(error) })));
      });
    return () => {
      active = false;
      continueReading.current = false;
    };
    // clustersKey covers clusters, which is a new array on every render
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clustersKey]);

  return { scans, loading: loading || scans === null, progress, errors };
}

function Loading(props: Readonly<{ progress: string }>) {
  return (
    <Typography variant="body2" color="text.secondary">
      {props.progress || 'Reading Kubescape scans…'}
    </Typography>
  );
}

function ComplianceSummary() {
  const { scans, loading, progress, errors } = useScans<WorkloadConfigurationScanSummary>(
    readConfigurationScans,
    () => configurationScanContext.queryTasks
  );
  const { frameworks, controls } = useRegoData();
  // the custom frameworks of the cluster count too, such as those chosen in the settings
  const customFrameworks = useCustomFrameworks(controls);
  const allFrameworks = useMemo(
    () => [...frameworks, ...(customFrameworks ?? [])],
    [frameworks, customFrameworks]
  );
  const config = kubescapeConfigStore.useConfig()() as KubescapeConfig;
  const names = activeFrameworkNames(config?.activeFrameworks, customFrameworks);

  return (
    <SectionBox title="Compliance">
      <ClusterErrors errors={errors} what="all configuration scans" />
      {!loading && <ControlExceptionErrors errors={configurationScanContext.exceptionErrors} />}
      {loading || !scans ? (
        <Loading progress={progress} />
      ) : (
        <NameValueTable
          rows={[
            {
              name: 'Resources scanned',
              value: (
                <HeadlampLink routeName={RoutingName.ComplianceView}>{scans.length}</HeadlampLink>
              ),
            },
            {
              name: 'Failed checks',
              // of all controls, as the row names no framework: the framework chosen on the
              // Compliance page would only apply its exceptions, to the controls of every framework
              value: String(countFailedScans(scans)),
            },
            ...(scans.length > 0
              ? frameworkScores(scans, allFrameworks, names).map(({ name, score }) => ({
                  name: `${name} compliance`,
                  value: `${score}%`,
                }))
              : []),
          ]}
        />
      )}
    </SectionBox>
  );
}

// The packages to upgrade in an image, the two that fix the most CVEs by name
function packagesToUpgrade(image: ImageUpgrade) {
  const named = image.packages
    .slice(0, 2)
    .map(upgrade => `${upgrade.packageName} → ${upgrade.fixVersion}`)
    .join(', ');
  const more = image.packages.length - 2;
  return more > 0 ? `${named} and ${more} more ${more === 1 ? 'package' : 'packages'}` : named;
}

// the overview counts the known exploited CVEs, without their EPSS scores
const noCveIds: string[] = [];

function VulnerabilitySummary() {
  const { scans, loading, progress, errors } = useScans<WorkloadScan>(
    readVulnerabilityScans,
    () => vulnerabilityContext.queryTasks
  );
  // counted once per read, not on every render
  const cves = useMemo(() => (scans ? countCves(scans) : {}), [scans]);
  const images = useMemo(() => (scans ? getImageUpgrades(scans).slice(0, 5) : []), [scans]);
  const exploitData = useExploitData(noCveIds);
  const knownExploited = useMemo(
    () => (scans && exploitData.kev ? countKnownExploited(scans, exploitData.kev) : undefined),
    [scans, exploitData.kev]
  );

  if (loading || !scans) {
    return (
      <SectionBox title="Vulnerabilities">
        <Loading progress={progress} />
      </SectionBox>
    );
  }

  const cveRow = (severity: string) => {
    const { total, fixable } = cves[severity] ?? { total: 0, fixable: 0 };
    return { name: `${severity} CVEs`, value: `${total} (${fixable} with a fix)` };
  };
  const clusterCount = new Set(scans.map(scan => scan.cluster)).size;
  let knownExploitedValue: ReactNode;
  if (knownExploited !== undefined) {
    knownExploitedValue = (
      <HeadlampLink
        routeName={RoutingName.KubescapeVulnerabilities}
        search={vulnerabilityTabSearch('cves')}
      >
        {knownExploited}
      </HeadlampLink>
    );
  } else if (exploitData.kevError) {
    knownExploitedValue = `Unknown: the catalog could not be read (${exploitData.kevError})`;
  } else {
    knownExploitedValue = 'Reading the catalog of known exploited vulnerabilities…';
  }

  return (
    <SectionBox title="Vulnerabilities">
      <ClusterErrors errors={errors} what="all vulnerability scans" />
      <NameValueTable
        rows={[
          {
            name: 'Workloads scanned',
            value: (
              <HeadlampLink routeName={RoutingName.KubescapeVulnerabilities}>
                {scans.length}
              </HeadlampLink>
            ),
          },
          cveRow('Critical'),
          cveRow('High'),
          ...(exploitData.settings.knownExploited
            ? [{ name: 'Known exploited CVEs', value: knownExploitedValue }]
            : []),
        ]}
      />
      {images.length > 0 && (
        <>
          <Typography variant="h6" sx={{ mt: 2, mb: 1 }}>
            Images whose upgrades fix the most CVEs
          </Typography>
          <CompactTable
            rows={images}
            rowKey={image => getImageScanKey(image.imageScan)}
            columns={[
              {
                header: 'Image',
                cell: image => (
                  <HeadlampLink
                    routeName={RoutingName.ImageVulnerabilityDetails}
                    activeCluster={image.imageScan.cluster}
                    params={{
                      namespace: image.imageScan.namespace,
                      name: image.imageScan.manifestName,
                    }}
                  >
                    {image.imageScan.imageName}
                  </HeadlampLink>
                ),
              },
              ...(clusterCount > 1
                ? [{ header: 'Cluster', cell: (image: ImageUpgrade) => image.imageScan.cluster }]
                : []),
              { header: 'Upgrade', cell: packagesToUpgrade },
              {
                header: 'Fixes',
                cell: image => (
                  <SeverityCountStack count={severity => countBySeverity(image, severity)} />
                ),
              },
            ]}
          />
          <Box sx={{ mt: 1 }}>
            {/* Headlamp's link drops a click handler, so the tab is in the address */}
            <HeadlampLink
              routeName={RoutingName.KubescapeVulnerabilities}
              search={vulnerabilityTabSearch('upgrades')}
            >
              All upgrades
            </HeadlampLink>
          </Box>
        </>
      )}
    </SectionBox>
  );
}

function RuntimeAlertSummary() {
  const clusters = useHLSelectedClusters();
  const clustersKey = clusters.join(',');
  kubescapeConfigStore.useConfig()();
  const configured = !!getAlertmanagerUrl();
  const [alerts, setAlerts] = useState<AlertmanagerAlert[] | null>(null);
  // the clusters whose Alertmanager could not be asked, which may have alerts
  const [errors, setErrors] = useState<ClusterError[]>([]);

  useEffect(() => {
    if (!configured) return;
    let active = true;
    Promise.allSettled(clusters.map(cluster => fetchKubescapeAlerts(cluster))).then(results => {
      if (!active) return;
      setErrors(
        results.flatMap((result, i) =>
          result.status === 'rejected'
            ? [{ cluster: clusters[i], message: result.reason?.message ?? String(result.reason) }]
            : []
        )
      );
      setAlerts(
        results
          .flatMap(result => (result.status === 'fulfilled' ? result.value : []))
          .sort((a, b) => new Date(b.startsAt).getTime() - new Date(a.startsAt).getTime())
      );
    });
    return () => {
      active = false;
    };
    // clustersKey covers clusters, which is a new array on every render
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [configured, clustersKey]);

  return (
    <SectionBox title="Runtime alerts">
      {!configured ? (
        <Typography variant="body2">
          Alertmanager is not configured. Set it up on the{' '}
          <HeadlampLink routeName={RoutingName.ApplicationProfiles}>Runtime Detection</HeadlampLink>{' '}
          page.
        </Typography>
      ) : alerts === null ? (
        <Typography variant="body2" color="text.secondary">
          Reading alerts…
        </Typography>
      ) : alerts.length === 0 ? (
        <>
          <ClusterErrors errors={errors} what="the runtime alerts" />
          {errors.length < clusters.length && (
            <Typography variant="body2">
              No active runtime alerts
              {errors.length > 0 ? ' in the other clusters' : ''}.
            </Typography>
          )}
        </>
      ) : (
        <>
          <ClusterErrors errors={errors} what="the runtime alerts" />
          <>
            <CompactTable
              rows={alerts.slice(0, 5)}
              rowKey={(alert, index) => `${alert.cluster}/${alert.fingerprint}/${index}`}
              columns={[
                { header: 'Time', cell: alert => <DateLabel date={alert.startsAt} /> },
                { header: 'Rule', cell: alert => alert.labels.rule_name ?? alert.labels.alertname },
                {
                  header: 'Workload',
                  cell: alert =>
                    [alertNamespace(alert), alertWorkload(alert)].filter(Boolean).join('/'),
                },
                ...(clusters.length > 1
                  ? [{ header: 'Cluster', cell: (alert: AlertmanagerAlert) => alert.cluster }]
                  : []),
              ]}
            />
            <Box sx={{ mt: 1 }}>
              <HeadlampLink routeName={RoutingName.ApplicationProfiles}>
                All {alerts.length} alerts
              </HeadlampLink>
            </Box>
          </>
        </>
      )}
    </SectionBox>
  );
}

function ExceptionSummary() {
  const clusters = useHLSelectedClusters();
  const clustersKey = clusters.join(',');
  const [expiring, setExpiring] = useState<ExceptionExpiry[] | null>(null);
  // the clusters whose exceptions could not be read, which may have expiring ones
  const [errors, setErrors] = useState<ClusterError[]>([]);

  useEffect(() => {
    let active = true;
    Promise.allSettled(
      clusters.map(cluster =>
        fetchSecurityExceptions(cluster, [], [], getAllowedNamespaces(cluster))
      )
    )
      .then(results => {
        if (!active) return;
        setErrors(
          results.flatMap((result, i) => {
            const messages =
              result.status === 'rejected'
                ? [result.reason?.message ?? String(result.reason)]
                : result.value.errors ?? [];
            return messages.length > 0
              ? [{ cluster: clusters[i], message: messages.join('; ') }]
              : [];
          })
        );
        setExpiring(
          results.flatMap((result, i) =>
            result.status === 'fulfilled' ? expiringExceptions(result.value, clusters[i]) : []
          )
        );
      })
      // an answer that cannot be read leaves the section with the error, not reading forever
      .catch(error => {
        if (!active) return;
        setErrors([{ cluster: clusters.join(', '), message: errorMessage(error) }]);
        setExpiring([]);
      });
    return () => {
      active = false;
    };
    // clustersKey covers clusters, which is a new array on every render
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clustersKey]);

  return (
    <SectionBox title="Expiring exceptions">
      <ClusterErrors errors={errors} what="the security exceptions" />
      {expiring === null ? (
        <Typography variant="body2" color="text.secondary">
          Reading exceptions…
        </Typography>
      ) : expiring.length === 0 ? (
        errors.length < clusters.length && (
          <Typography variant="body2">
            No exceptions have expired or expire in the next 14 days
            {errors.length > 0 ? ' in the other clusters' : ''}.
          </Typography>
        )
      ) : (
        <CompactTable
          rows={expiring}
          rowKey={exception =>
            `${exception.cluster}/${exception.namespace}/${exception.name}/${exception.expiresAt}`
          }
          columns={[
            {
              header: 'Exception',
              cell: exception =>
                exception.namespace ? (
                  <HeadlampLink
                    routeName={RoutingName.SecurityExceptionDetail}
                    activeCluster={exception.cluster}
                    params={{ namespace: exception.namespace, name: exception.name }}
                  >
                    {exception.name}
                  </HeadlampLink>
                ) : (
                  <HeadlampLink
                    routeName={RoutingName.SecurityExceptionClusterDetail}
                    activeCluster={exception.cluster}
                    params={{ name: exception.name }}
                  >
                    {exception.name}
                  </HeadlampLink>
                ),
            },
            { header: 'Scope', cell: exception => exception.namespace ?? 'Cluster' },
            { header: 'Expires', cell: exception => <DateLabel date={exception.expiresAt} /> },
            {
              header: 'Status',
              cell: exception => {
                if (exception.entries) {
                  const entries = exception.entries.join(', ');
                  return exception.expired
                    ? `${entries} expired, no longer applied`
                    : `${entries} expire soon`;
                }
                return exception.expired ? 'Expired, no longer applied' : 'Expires soon';
              },
            },
            ...(clusters.length > 1
              ? [{ header: 'Cluster', cell: (e: ExceptionExpiry) => e.cluster }]
              : []),
          ]}
        />
      )}
    </SectionBox>
  );
}
