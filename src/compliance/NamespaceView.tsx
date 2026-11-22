/* 
  Information about a namespace and failed workloads. 
*/
import {
  Link as HeadlampLink,
  SectionBox,
  TableColumn,
} from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { useMemo } from 'react';
import Table from '../common/Table';
import { RoutingName, useHLSelectedClusters } from '../index';
import { WorkloadConfigurationScanSummary } from '../softwarecomposition/WorkloadConfigurationScanSummary';
import { isControlExcepted } from './workload-scanning';

export class NamespaceResult {
  namespace: string;
  cluster: string;
  criticalCount: number = 0;
  highCount: number = 0;
  mediumCount: number = 0;
  lowCount: number = 0;
  total: number = 0;
  unknownCount: number = 0;
  passed: number = 0;
  failed: number = 0;
  exceptedControls: number = 0;
  exceptedNamespace: boolean = false;

  constructor(namespace: string, cluster: string) {
    this.namespace = namespace;
    this.cluster = cluster;
  }

  // the share of the checks that passed or that an exception excludes, as the compliance score
  // of a control counts them
  get passedShare(): number {
    return this.total === 0 ? 1 : (this.passed + this.exceptedControls) / this.total;
  }
}

export default function NamespaceView(
  props: Readonly<{
    workloadScanData: WorkloadConfigurationScanSummary[] | null;
    // the framework whose exceptions limited to a framework apply
    frameworkName?: string;
    // the controls of the chosen framework, which the counts are limited to; undefined for the
    // combined view of all controls
    controlIDs?: Set<string>;
  }>
) {
  const clusters = useHLSelectedClusters();
  const { workloadScanData, frameworkName, controlIDs } = props;
  const namespaceResults = useMemo(
    () =>
      workloadScanData ? getNamespaceResults(workloadScanData, frameworkName, controlIDs) : [],
    [workloadScanData, frameworkName, controlIDs]
  );
  if (!workloadScanData) {
    return <></>;
  }

  return (
    <SectionBox>
      <Table
        data={namespaceResults}
        getRowId={(result: NamespaceResult) => `${result.cluster}/${result.namespace}`}
        columns={[
          {
            id: 'Namespace',
            header: 'Namespace',
            accessorKey: 'namespace',
            Cell: ({ cell }) => (
              <HeadlampLink
                routeName={RoutingName.KubescapeConfigurationScanNamespaceSummary}
                params={{
                  namespace: cell.getValue(),
                }}
                activeCluster={cell.row.original.cluster}
              >
                {cell.getValue()}
              </HeadlampLink>
            ),
          },
          // no column without clusters to tell apart: an empty one would take its width
          ...(clusters.length > 1
            ? [
                {
                  header: 'Cluster',
                  accessorKey: 'cluster',
                } as TableColumn<NamespaceResult>,
              ]
            : []),
          {
            id: 'Passed',
            header: 'Passed',
            accessorFn: (namespaceResult: NamespaceResult) => namespaceResult.passedShare,
            Cell: ({ cell }) => <progress value={cell.getValue()} />,
          },
          {
            header: 'Excluded Namespace',
            accessorKey: 'exceptedNamespace',
            Cell: ({ cell }) => (cell.getValue() ? 'Yes' : 'No'),
            gridTemplate: 'auto',
          },
          {
            id: 'Compliance',
            header: 'Compliance',
            accessorFn: (namespaceResult: NamespaceResult) =>
              Math.trunc(namespaceResult.passedShare * 100),
            Cell: ({ cell }) => cell.getValue() + '%',
            gridTemplate: 'auto',
          },
          {
            // the results of controls in the workloads of the namespace that exceptions exclude
            header: 'Excluded Control Results',
            accessorKey: 'exceptedControls',
            gridTemplate: 'min-content',
          },
          {
            header: 'Critical',
            accessorKey: 'criticalCount',
            gridTemplate: 'min-content',
          },
          {
            header: 'High',
            accessorKey: 'highCount',
            gridTemplate: 'min-content',
          },
          {
            header: 'Medium',
            accessorKey: 'mediumCount',
            gridTemplate: 'min-content',
          },
          {
            header: 'Low',
            accessorKey: 'lowCount',
            gridTemplate: 'min-content',
          },
          {
            header: 'Unknown',
            accessorKey: 'unknownCount',
            gridTemplate: 'min-content',
          },
          {
            header: 'Total',
            accessorKey: 'total',
            gridTemplate: 'min-content',
          },
        ]}
        initialState={{
          sorting: [
            {
              id: 'Namespace',
              desc: false,
            },
          ],
        }}
        reflectInURL="namespaces"
      />
    </SectionBox>
  );
}

/**
 * The results per namespace of each cluster, with the exceptions that apply in the framework;
 * of the controls of the framework when given, else of all controls.
 */
export function getNamespaceResults(
  workloadScanData: WorkloadConfigurationScanSummary[],
  frameworkName?: string,
  controlIDs?: Set<string>
): NamespaceResult[] {
  // the same namespace in two clusters is two rows
  const namespaces = new Map<string, NamespaceResult>();

  for (const scan of workloadScanData) {
    const key = `${scan.metadata.cluster}/${scan.metadata.namespace}`;
    let namespaceResult = namespaces.get(key);
    if (!namespaceResult) {
      namespaceResult = new NamespaceResult(scan.metadata.namespace, scan.metadata.cluster);
      // excepted while all its workloads are
      namespaceResult.exceptedNamespace = true;
      namespaces.set(key, namespaceResult);
    }
    if (!scan.exceptedByPolicy) namespaceResult.exceptedNamespace = false;

    for (const controlResult of Object.values(scan.spec.controls)) {
      if (controlIDs && !controlIDs.has(controlResult.controlID)) continue;
      namespaceResult.total++;

      if (scan.exceptedByPolicy || isControlExcepted(controlResult, frameworkName)) {
        namespaceResult.exceptedControls++;
      } else if (controlResult.status.status === WorkloadConfigurationScanSummary.Status.Failed) {
        namespaceResult.failed++;
        switch (controlResult.severity?.severity?.toLowerCase()) {
          case 'critical': {
            namespaceResult.criticalCount++;
            break;
          }
          case 'high': {
            namespaceResult.highCount++;
            break;
          }
          case 'medium': {
            namespaceResult.mediumCount++;
            break;
          }
          case 'low': {
            namespaceResult.lowCount++;
            break;
          }
          case 'unknown': {
            namespaceResult.unknownCount++;
            break;
          }
        }
      } else if (controlResult.status.status === WorkloadConfigurationScanSummary.Status.Passed) {
        namespaceResult.passed++;
      }
    }
  }

  return [...namespaces.values()];
}
