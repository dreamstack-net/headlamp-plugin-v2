/* 
  Show container image scans. This view is part of the main Vulnerabilities page.  
*/
import {
  DateLabel,
  Link as HeadlampLink,
  SectionBox,
  TableColumn,
} from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { Stack } from '@mui/material';
import { useMemo } from 'react';
import { severityColors, SeverityCountStack } from '../common/SeverityCountBox';
import HeadlampTable from '../common/Table';
import { RoutingName } from '../index';
import {
  EndOfLifeLabel,
  ImageVersion,
  imageVersionMapKey,
  latestRank,
  LatestVersionLabel,
  useImageVersions,
  useImageVersionSettings,
} from './ImageVersion';
import { imageTag } from './registry';
import {
  getImageScanKey,
  getImageScans,
  ImageScan,
  ofSeveralClusters,
  workloadLabel,
  WorkloadScan,
} from './scanData';

// an image with the workload containers that run it and, once found, its versions
type ImageRow = ImageScan & { version?: ImageVersion; workloads: string[] };

export default function ImageListView(props: Readonly<{ workloadScans: WorkloadScan[] | null }>) {
  const { workloadScans } = props;
  const imageScans = useMemo(
    () => (workloadScans ? getImageScans(workloadScans) : []),
    [workloadScans]
  );
  const settings = useImageVersionSettings();
  const images = useMemo(
    () =>
      imageScans.map(scan => ({
        image: scan.imageName,
        cluster: scan.cluster,
        source: scan.source,
      })),
    [imageScans]
  );
  const versions = useImageVersions(images);
  // the workloads of each image and when kubevuln last scanned them, in one pass over the
  // workloads: recent kubevuln versions only record when they scanned the workloads of an image
  const { workloadsByImage, scannedAt } = useMemo(() => {
    const workloadsByImage = new Map<string, Set<string>>();
    const scannedAt = new Map<string, string>();
    const scans = workloadScans ?? [];
    const withCluster = ofSeveralClusters(scans);
    for (const workloadScan of scans) {
      if (!workloadScan.imageScan) continue;
      const key = getImageScanKey(workloadScan.imageScan);
      let workloads = workloadsByImage.get(key);
      if (!workloads) {
        workloads = new Set();
        workloadsByImage.set(key, workloads);
      }
      workloads.add(workloadLabel(workloadScan, withCluster));
      const latest = scannedAt.get(key);
      if (workloadScan.scannedAt && (!latest || workloadScan.scannedAt > latest)) {
        scannedAt.set(key, workloadScan.scannedAt);
      }
    }
    return { workloadsByImage, scannedAt };
  }, [workloadScans]);
  // the table reads the values of a row again only when the rows change, so the versions that
  // are found are part of the rows
  const rows = useMemo<ImageRow[]>(
    () =>
      imageScans.map(scan => ({
        ...scan,
        workloads: [...(workloadsByImage.get(getImageScanKey(scan)) ?? [])],
        version: versions.get(imageVersionMapKey({ image: scan.imageName, cluster: scan.cluster })),
      })),
    [imageScans, versions, workloadsByImage]
  );

  if (!workloadScans) {
    return <></>;
  }

  const evaluatedAt = (imageScan: ImageScan) =>
    imageScan.reportCreatedAt ?? scannedAt.get(getImageScanKey(imageScan));

  return (
    <>
      <h5>{imageScans.length} image scans</h5>
      <SectionBox>
        <HeadlampTable
          csvExport={{
            fileName: 'kubescape-images.csv',
            header: [
              'Image',
              'Cluster',
              'Workloads',
              ...(settings.enabled ? ['Tag', 'Latest version', 'Newer version available'] : []),
              ...(settings.endOfLife ? ['End of life'] : []),
              'Last evaluated',
              ...Object.keys(severityColors),
              'Total',
            ],
            rows: () =>
              rows.map(imageScan => {
                const version = imageScan.version;
                return [
                  imageScan.imageName,
                  imageScan.cluster,
                  imageScan.workloads.join('; '),
                  ...(settings.enabled
                    ? [
                        imageTag(imageScan.imageName),
                        version?.latest?.latest,
                        version?.latest ? (version.newer ? 'yes' : 'no') : undefined,
                      ]
                    : []),
                  ...(settings.endOfLife
                    ? [
                        version?.line &&
                          (version.line.eol
                            ? `ended ${version.line.eolFrom ?? ''}`.trim()
                            : version.line.eolFrom),
                      ]
                    : []),
                  evaluatedAt(imageScan),
                  ...countImageScans(imageScan),
                  imageScan.matches.length,
                ];
              }),
          }}
          data={rows}
          // a cell keeps what it showed for the row it first showed
          getRowId={getImageScanKey}
          columns={[
            {
              header: 'Image',
              accessorKey: 'manifestName',
              Cell: ({ cell, row }) => {
                return (
                  <HeadlampLink
                    routeName={RoutingName.ImageVulnerabilityDetails}
                    activeCluster={row.original.cluster}
                    params={{
                      name: cell.getValue(),
                      namespace: row.original.namespace,
                    }}
                  >
                    {row.original.imageName}
                  </HeadlampLink>
                );
              },
              gridTemplate: 'auto',
            },
            ...(settings.enabled
              ? ([
                  {
                    id: 'Tag',
                    header: 'Tag',
                    accessorFn: (imageScan: ImageScan) => imageTag(imageScan.imageName) ?? '',
                    gridTemplate: 'auto',
                  },
                  {
                    id: 'Latest',
                    header: 'Latest',
                    // the value changes when the version is found, which redraws the cell
                    accessorFn: (row: ImageRow) => row.version?.latest?.latest ?? '',
                    sortingFn: (a, b) =>
                      latestRank(a.original.version) - latestRank(b.original.version),
                    sortDescFirst: true,
                    Cell: ({ row }) => <LatestVersionLabel version={row.original.version} />,
                    gridTemplate: 'auto',
                  },
                ] satisfies TableColumn<ImageRow>[])
              : []),
            ...(settings.endOfLife
              ? ([
                  {
                    id: 'End of life',
                    header: 'End of life',
                    // released lines without an announced end sort after the dated ones
                    accessorFn: (row: ImageRow) => {
                      const line = row.version?.line;
                      return line ? line.eolFrom ?? (line.eol ? '0' : 'none') : undefined;
                    },
                    // compared as text, which puts none after the dates; left to the table, a
                    // list of more than ten rows compares the numbers in the values, none first
                    sortingFn: 'basic' as const,
                    sortUndefined: 'last' as const,
                    Cell: ({ row }) => <EndOfLifeLabel line={row.original.version?.line} />,
                    gridTemplate: 'auto',
                  },
                ] satisfies TableColumn<ImageRow>[])
              : []),
            {
              id: 'Workload',
              header: 'Workload',
              accessorFn: (row: ImageRow) => row.workloads.join('\n'),
              Cell: ({ cell }) => <div style={{ whiteSpace: 'pre-line' }}>{cell.getValue()}</div>,
              gridTemplate: 'auto',
            },
            {
              id: 'Last evaluated',
              header: 'Last evaluated',
              accessorFn: evaluatedAt,
              sortingFn: 'basic',
              sortUndefined: 'last',
              sortDescFirst: false,
              Cell: ({ cell }) =>
                cell.getValue() ? <DateLabel date={cell.getValue()} /> : 'Unknown',
              gridTemplate: 'auto',
            },
            {
              id: 'Scan record created',
              header: 'Scan record created',
              accessorKey: 'creationTimestamp',
              Cell: ({ cell }) => <DateLabel date={cell.getValue()} />,
              gridTemplate: 'auto',
            },
            {
              id: 'Vulnerabilities',
              header: 'Vulnerabilities',
              accessorFn: (imageScan: ImageScan) => countImageScans(imageScan).join('.'),
              // by the numbers of the counts: the table picks how to sort from the rows after
              // the tenth, so that ten rows or fewer would sort as text, 9 above 12
              sortingFn: 'alphanumeric',
              Cell: ({ row }) => resultStack(row.original),
              gridTemplate: 'auto',
            },
            {
              id: 'SBOM',
              header: 'SBOM',
              accessorFn: (imageScan: ImageScan) => imageScan.manifestName,
              enableSorting: false,
              Cell: ({ row }) => (
                <HeadlampLink
                  routeName={RoutingName.KubescapeSBOMDetails}
                  activeCluster={row.original.cluster}
                  params={{
                    name: row.original.manifestName,
                    namespace: row.original.namespace,
                  }}
                >
                  SBOM
                </HeadlampLink>
              ),
              gridTemplate: 'min-content',
            },
          ]}
          initialState={{
            sorting: [
              {
                id: 'Vulnerabilities',
                desc: true,
              },
            ],
          }}
          reflectInURL="images"
        />
      </SectionBox>
    </>
  );
}

function resultStack(imageScan: ImageScan) {
  return (
    <SeverityCountStack
      count={severity =>
        imageScan.matches.filter(match => match.vulnerability.severity === severity).length
      }
      tooltip={severity => cveList(imageScan, severity)}
      link={{
        routeName: RoutingName.ImageVulnerabilityDetails,
        params: { name: imageScan.manifestName, namespace: imageScan.namespace },
        activeCluster: imageScan.cluster,
      }}
    />
  );
}

function countImageScans(imageScan: ImageScan) {
  const counters: number[] = [];
  const severities = ['Critical', 'High', 'Medium', 'Low'];

  severities.forEach(severity => {
    const count = imageScan.matches.filter(
      match => match.vulnerability.severity === severity
    ).length;
    counters.push(count);
  });

  return counters;
}

function cveList(imageScan: ImageScan, severity: string) {
  const cves = imageScan.matches
    .filter(match => match.vulnerability.severity === severity)
    .map(match => match.vulnerability.id);

  if (cves.length > 0) {
    return (
      <>
        <div style={{ fontSize: 'smaller' }}>{severity}</div>
        <br />
        <div style={{ whiteSpace: 'normal', textAlign: 'left', fontSize: 'small' }}>
          <Stack spacing={1}>
            {cves.map(cve => (
              <div key={cve}>{cve} </div>
            ))}
          </Stack>
        </div>
      </>
    );
  }
}
