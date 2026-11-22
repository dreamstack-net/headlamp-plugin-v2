import { Icon } from '@iconify/react';
import { ApiError } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import { NameValueTable, SectionBox } from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { Button, Stack, Typography } from '@mui/material';
import { useSnackbar } from 'notistack';
import { useLocation } from 'react-router';
import { ErrorMessage } from '../common/ErrorMessage';
import { saveToFile } from '../common/filedialog';
import { useStorageObject } from '../common/readOnce';
import HeadlampTable from '../common/Table';
import { getURLSegments } from '../common/url';
import { newGuid } from '../common/uuid';
import { sbomSyftClass, sbomSyftFilteredClass } from '../model';
import { SBOMSyft } from '../softwarecomposition/SBOMSyft';
import { toCycloneDx, toSyftJson } from './sbomExport';

export default function SBOMDetail() {
  const [name, namespace] = getURLSegments(-1, -2);
  // The query is read from the router, as Headlamp desktop keeps it in the URL hash
  const urlParams = new URLSearchParams(useLocation().search);
  const filtered = urlParams.has('filtered');

  const { enqueueSnackbar } = useSnackbar();

  // read once: a watch of the storage would replace the SBOM with one without its packages
  const { data: sbomSyft, error } = useStorageObject<SBOMSyft>(
    filtered ? sbomSyftFilteredClass : sbomSyftClass,
    name,
    namespace,
    undefined
  );

  if (!sbomSyft) {
    return (
      <SectionBox title={'SBOM' + (filtered ? ' Filtered' : '')} backLink>
        {error ? (
          <ErrorMessage error={error as ApiError} />
        ) : (
          <Typography variant="body2" color="text.secondary">
            Reading the SBOM…
          </Typography>
        )}
      </SectionBox>
    );
  }

  const artifacts = sbomSyft.spec.syft.artifacts ?? [];
  const message = filtered ? 'Showing in use artifacts only' : 'Showing all artifacts';
  // the name of the SBOM is the image with its digest, made safe for file names
  const fileName = sbomSyft.metadata.name + (filtered ? '-in-use' : '');
  return (
    <>
      <SectionBox title={'SBOM' + (filtered ? ' Filtered' : '')} backLink>
        <Stack direction="row" spacing={1} sx={{ mb: 1 }}>
          <Button
            size="small"
            variant="outlined"
            startIcon={<Icon icon="mdi:download" />}
            onClick={() =>
              saveToFile(toSyftJson(sbomSyft), `${fileName}.syft.json`, enqueueSnackbar)
            }
          >
            Download Syft JSON
          </Button>
          <Button
            size="small"
            variant="outlined"
            startIcon={<Icon icon="mdi:download" />}
            onClick={() =>
              saveToFile(
                JSON.stringify(toCycloneDx(sbomSyft, newGuid()), null, 2),
                `${fileName}.cdx.json`,
                enqueueSnackbar
              )
            }
          >
            Download CycloneDX
          </Button>
        </Stack>
        <p>{message}</p>
        <NameValueTable
          rows={[
            {
              name: 'Image',
              value: sbomSyft.metadata.annotations['kubescape.io/image-tag'],
            },
            {
              name: 'Last scan',
              value: sbomSyft.spec.metadata.report.createdAt,
            },
            {
              name: 'Distro',
              value: distroLabel(sbomSyft.spec.syft.distro),
            },
            {
              name: 'Components',
              value: String(artifacts.length),
            },
          ]}
        />
      </SectionBox>

      <Artifacts artifacts={artifacts} fileName={fileName} />
    </>
  );
}

/**
 * The distribution of the image with its version, such as Debian GNU/Linux 11 (bullseye); an
 * image without one, such as a distroless image, has none.
 */
export function distroLabel(distro: Partial<SBOMSyft.Distro> | null | undefined): string {
  if (!distro) return '';
  return distro.prettyName || [distro.name, distro.versionID].filter(Boolean).join(' ');
}

function licenses(artifact: SBOMSyft.Artifact) {
  return artifact.licenses?.map(license => license.value).join(', ');
}

function Artifacts(props: { artifacts: SBOMSyft.Artifact[]; fileName: string }) {
  const { artifacts, fileName } = props;

  return (
    <SectionBox title="Artifacts">
      <HeadlampTable
        csvExport={{
          fileName: `${fileName}-packages.csv`,
          header: ['Package', 'Name', 'Version', 'Type', 'Licenses'],
          rows: () =>
            artifacts.map(artifact => [
              artifact.purl,
              artifact.name,
              artifact.version,
              artifact.type,
              licenses(artifact),
            ]),
        }}
        data={artifacts}
        columns={[
          {
            header: 'Package',
            accessorKey: 'purl',
          },
          {
            header: 'Name',
            accessorKey: 'name',
          },
          {
            header: 'Version',
            accessorKey: 'version',
          },
          {
            header: 'Type',
            accessorKey: 'type',
          },
          {
            header: 'Licenses',
            accessorFn: licenses,
            gridTemplate: 0.5,
          },
        ]}
      />
    </SectionBox>
  );
}
