/* 
  Show the vulnerability issues for workloads in a single namespace.  
*/
import { ApiError } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import {
  Link as HeadlampLink,
  NameValueTable,
  SectionBox,
} from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { Typography } from '@mui/material';
import { ErrorMessage } from '../common/ErrorMessage';
import { useStorageObject } from '../common/readOnce';
import HeadlampTable from '../common/Table';
import { getLastURLSegment } from '../common/url';
import { RoutingName } from '../index';
import { vulnerabilitySummaryClass } from '../model';
import { VulnerabilitySummary } from '../softwarecomposition/VulnerabilitySummary';

export default function VulnerabilitiesNamespaceSummary() {
  const namespace = getLastURLSegment();
  // read once, as the storage refuses to watch the summaries of a namespace (405)
  const { data: vulnerabilitySummary, error } = useStorageObject<VulnerabilitySummary>(
    vulnerabilitySummaryClass,
    namespace,
    undefined,
    undefined
  );

  if (!vulnerabilitySummary) {
    return (
      <SectionBox title="Namespace Vulnerabilities" backLink>
        {error ? (
          <ErrorMessage error={error as ApiError} />
        ) : (
          <Typography variant="body2" color="text.secondary">
            Reading the vulnerability summary of the namespace…
          </Typography>
        )}
      </SectionBox>
    );
  }

  return (
    <>
      <SectionBox title="Namespace Vulnerabilities">
        <NameValueTable
          rows={[
            {
              name: 'Namespace',
              value: vulnerabilitySummary.metadata.name,
            },
          ]}
        />
      </SectionBox>
      <VulnerabilityScans vulnerabilityScans={vulnerabilitySummary.spec.vulnerabilitiesRef} />
    </>
  );
}

function VulnerabilityScans(
  props: Readonly<{
    vulnerabilityScans: VulnerabilitySummary.VulnerabilityReference[];
  }>
) {
  const { vulnerabilityScans } = props;

  return (
    <SectionBox title="Image scans">
      <HeadlampTable
        data={vulnerabilityScans}
        columns={[
          {
            header: 'Workload',
            accessorFn: (item: VulnerabilitySummary.VulnerabilityReference) =>
              item.name.split('-')?.slice(1).join('-'),
            Cell: ({ cell }) => {
              return (
                <HeadlampLink
                  routeName={RoutingName.KubescapeVulnerabilityDetails}
                  params={{
                    name: cell.row.original.name,
                    namespace: cell.row.original.namespace,
                  }}
                >
                  {cell.getValue()}
                </HeadlampLink>
              );
            },
          },
          {
            header: 'Kind',
            accessorFn: (item: VulnerabilitySummary.VulnerabilityReference) => {
              const kind = item.name.split('-')?.[0];
              return kind[0].toUpperCase() + kind.slice(1);
            },
          },
        ]}
      />
    </SectionBox>
  );
}
