/*
  Package upgrades that fix CVEs, the most effective first. This view is part of the main
  Vulnerabilities page.
*/
import { Link as HeadlampLink, SectionBox } from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { FormControlLabel, Switch, Typography } from '@mui/material';
import { useMemo } from 'react';
import { KubescapeSettings, useSessionStorage } from '../common/sessionStorage';
import { severityColors, SeverityCountStack } from '../common/SeverityCountBox';
import HeadlampTable from '../common/Table';
import { RoutingName } from '../index';
import { getImageScanKey, WorkloadScan } from './scanData';
import { countBySeverity, getPackageUpgrades, PackageUpgrade } from './upgrades';

export default function UpgradeListView(props: Readonly<{ workloadScans: WorkloadScan[] }>) {
  const { workloadScans } = props;
  const [relevantOnly, setRelevantOnly] = useSessionStorage<boolean>(
    KubescapeSettings.RelevantCVEs,
    false
  );
  const upgrades = useMemo(
    () => getPackageUpgrades(workloadScans, relevantOnly),
    [workloadScans, relevantOnly]
  );

  return (
    <>
      <h5>{upgrades.length} package upgrades fix CVEs</h5>
      <Typography variant="body2" color="text.secondary">
        Upgrading a package to the fix version removes the listed CVEs from the image. The upgrades
        that remove the most critical and high CVEs come first.
      </Typography>
      <SectionBox>
        <HeadlampTable
          toolbarStart={
            <FormControlLabel
              checked={relevantOnly}
              control={<Switch color="primary" />}
              label="Relevant"
              onChange={(_event, checked) => setRelevantOnly(checked)}
            />
          }
          csvExport={{
            fileName: 'kubescape-upgrades.csv',
            header: [
              'Image',
              'Cluster',
              'Package',
              'Installed version',
              'Fix version',
              ...Object.keys(severityColors),
              'CVEs',
              'Workloads',
            ],
            rows: () =>
              upgrades.map(upgrade => [
                upgrade.imageScan.imageName,
                upgrade.imageScan.cluster,
                upgrade.packageName,
                upgrade.installedVersion,
                upgrade.fixVersion,
                ...Object.keys(severityColors).map(severity => countBySeverity(upgrade, severity)),
                [...upgrade.cves.keys()].join('; '),
                upgrade.workloads.join('; '),
              ]),
          }}
          data={upgrades}
          columns={[
            {
              header: 'Image',
              accessorFn: (upgrade: PackageUpgrade) => upgrade.imageScan.imageName,
              // the report the link opens is part of the id of the row
              Cell: ({ cell, row }) => (
                <HeadlampLink
                  routeName={RoutingName.ImageVulnerabilityDetails}
                  activeCluster={row.original.imageScan.cluster}
                  params={{
                    name: row.original.imageScan.manifestName,
                    namespace: row.original.imageScan.namespace,
                  }}
                >
                  {cell.getValue()}
                </HeadlampLink>
              ),
              gridTemplate: 'auto',
            },
            {
              header: 'Package',
              accessorKey: 'packageName',
              gridTemplate: 'auto',
            },
            {
              header: 'Installed',
              accessorKey: 'installedVersion',
              gridTemplate: 'auto',
            },
            {
              header: 'Fix version',
              accessorKey: 'fixVersion',
              gridTemplate: 'auto',
            },
            {
              id: 'Fixes',
              header: 'Fixes',
              // sorts like the list: by critical, then high, ... CVEs fixed; then the CVEs of the
              // tooltips, so that they are drawn again when they change
              accessorFn: fixesValue,
              Cell: ({ row }) => (
                <SeverityCountStack
                  count={severity => countBySeverity(row.original, severity)}
                  tooltip={severity => cveList(row.original, severity)}
                />
              ),
              gridTemplate: 'auto',
            },
            {
              header: 'Workloads',
              accessorFn: (upgrade: PackageUpgrade) => upgrade.workloads.join('\n'),
              Cell: ({ cell }) => <div style={{ whiteSpace: 'pre-line' }}>{cell.getValue()}</div>,
              gridTemplate: 'auto',
            },
          ]}
          initialState={{ sorting: [{ id: 'Fixes', desc: true }] }}
          // the cells of a row draw the image and the CVEs of the upgrade of the row
          getRowId={upgradeRowId}
          reflectInURL="upgrades"
        />
      </SectionBox>
    </>
  );
}

/** Identifies the upgrade of a package in an image, of which an image has one per version. */
export function upgradeRowId(upgrade: PackageUpgrade): string {
  return JSON.stringify([
    getImageScanKey(upgrade.imageScan),
    upgrade.packageName,
    upgrade.installedVersion,
  ]);
}

// the counts of the CVEs fixed, most severe first and padded to sort as text, then the CVEs
// with their severity, which the tooltips list
function fixesValue(upgrade: PackageUpgrade): string {
  const counts = Object.keys(severityColors)
    .map(severity => String(countBySeverity(upgrade, severity)).padStart(5, '0'))
    .join('.');
  const cves = [...upgrade.cves].map(([id, severity]) => `${id} (${severity})`);
  return `${counts} ${cves.join(' ')}`;
}

function cveList(upgrade: PackageUpgrade, severity: string) {
  const cves = [...upgrade.cves.entries()].filter(([, s]) => s === severity).map(([id]) => id);
  if (cves.length === 0) return severity;
  return (
    <div>
      <div style={{ fontSize: 'smaller' }}>{severity}</div>
      {cves.map(cve => (
        <div key={cve}>{cve}</div>
      ))}
    </div>
  );
}
