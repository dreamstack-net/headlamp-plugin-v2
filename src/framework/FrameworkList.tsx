import { Icon } from '@iconify/react';
import { Router } from '@kinvolk/headlamp-plugin/lib';
import { remove } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import { Link, TableColumn } from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import type { KubeConfigMap } from '@kinvolk/headlamp-plugin/lib/k8s/configMap';
import { getCluster } from '@kinvolk/headlamp-plugin/lib/Utils';
import { Alert, Stack, Typography } from '@mui/material';
import { useSnackbar } from 'notistack';
import { useEffect, useMemo, useState } from 'react';
import { useHistory } from 'react-router-dom';
import { ConfirmDeleteDialog } from '../common/ConfirmDeleteDialog';
import { errorMessage } from '../common/errors';
import { frameworkCheck, PermittedIconButton } from '../common/permissions';
import HeadlampTable from '../common/Table';
import {
  getKubescapeNamespace,
  listCustomObjectConfigMaps,
  useKubescapeNamespace,
} from '../custom-objects/api-queries';
import { RoutingName } from '../index';
import { FrameWork, useRegoData } from '../rego';
import { customFrameworkOf } from './customFrameworks';

const { createRouteURL } = Router;

export function FrameworksPage() {
  const cluster = getCluster();
  // the ConfigMaps of the custom frameworks in the Kubescape namespace, where a user who may
  // change them can list them; read again after a delete
  const [configMaps, setConfigMaps] = useState<KubeConfigMap[] | null>(null);
  const [listError, setListError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const history = useHistory();
  const { controls, frameworks } = useRegoData();
  // where the ConfigMaps of new custom frameworks are written
  const { kubeScapeNamespace } = useKubescapeNamespace();

  useEffect(() => {
    let active = true;
    listCustomObjectConfigMaps('framework', cluster)
      .then(items => {
        if (!active) return;
        setConfigMaps(items);
        setListError(null);
      })
      .catch(error => {
        if (active) setListError(errorMessage(error));
      });
    return () => {
      active = false;
    };
  }, [cluster, reloadKey]);

  const customFrameworks = useMemo(
    () =>
      (configMaps ?? []).flatMap(configMap => {
        const framework = customFrameworkOf(configMap, controls);
        return framework ? [framework] : [];
      }),
    [configMaps, controls]
  );

  return (
    <Stack direction="column" sx={{ marginTop: '20px' }} spacing={0}>
      <Typography variant="h4" sx={{ marginRight: 4, fontWeight: 'bold' }}>
        Default Frameworks
      </Typography>
      <FrameworksTable
        frameworks={frameworks}
        routeName={RoutingName.FrameworkControls}
        allowDelete={false}
      />

      <Stack direction="row" sx={{ marginTop: '20px' }} spacing={0}>
        <Typography variant="h4" sx={{ marginRight: 4, fontWeight: 'bold' }}>
          Custom Frameworks
        </Typography>
        <PermittedIconButton
          check={frameworkCheck('create', kubeScapeNamespace)}
          title="Add custom framework"
          size="medium"
          onClick={() => history.push(createRouteURL(RoutingName.FrameworkNew))}
        >
          <Icon icon="mdi:add-circle" />
        </PermittedIconButton>
      </Stack>
      {listError && (
        <Alert severity="error" sx={{ mb: 1 }}>
          Unable to read the custom frameworks: {listError}
        </Alert>
      )}
      <FrameworksTable
        frameworks={customFrameworks}
        routeName={RoutingName.FrameworkEdit}
        allowDelete
        onDeleted={() => setReloadKey(key => key + 1)}
      />
    </Stack>
  );
}

function FrameworksTable(
  props: Readonly<{
    frameworks: FrameWork[];
    routeName: string;
    allowDelete: boolean;
    onDeleted?: () => void;
  }>
) {
  const { frameworks, routeName, allowDelete, onDeleted } = props;
  const { enqueueSnackbar } = useSnackbar();
  // the framework to delete once the user confirms, with the namespace of its ConfigMap
  const [deleting, setDeleting] = useState<{ framework: FrameWork; namespace: string } | null>(
    null
  );

  // the ConfigMap is deleted where it was found; the Kubescape namespace is only a fallback
  const askToDelete = async (framework: FrameWork) => {
    if (framework.configmapNamespace) {
      setDeleting({ framework, namespace: framework.configmapNamespace });
      return;
    }
    const { kubeScapeNamespace, error } = await getKubescapeNamespace();
    if (!kubeScapeNamespace) {
      enqueueSnackbar(error ?? 'Kubescape namespace not found', { variant: 'error' });
      return;
    }
    setDeleting({ framework, namespace: kubeScapeNamespace });
  };

  const deleteFramework = async ({
    framework,
    namespace,
  }: {
    framework: FrameWork;
    namespace: string;
  }) => {
    await remove(
      `/api/v1/namespaces/${encodeURIComponent(namespace)}/configmaps/${encodeURIComponent(
        framework.configmapManifestName
      )}`
    );
    enqueueSnackbar(`${framework.name} deleted successfully`, { variant: 'success' });
    onDeleted?.();
  };

  return (
    <>
      {deleting && (
        <ConfirmDeleteDialog
          target={{
            kind: 'custom framework',
            name: deleting.framework.name,
            namespace: deleting.namespace,
            cluster: getCluster() ?? undefined,
          }}
          consequence={`Its ConfigMap ${deleting.framework.configmapManifestName} is deleted, and the Compliance page no longer offers it.`}
          onDelete={() => deleteFramework(deleting)}
          onClose={() => setDeleting(null)}
        />
      )}
      <HeadlampTable
        columns={[
          {
            id: 'name',
            header: 'Name',
            accessorKey: 'name',
            Cell: ({ cell, row }) => (
              <Link
                routeName={routeName}
                params={{
                  name: row.original.configmapManifestName ?? row.original.name,
                }}
                // the editor reads the ConfigMap in the namespace it was found in
                search={
                  row.original.configmapNamespace
                    ? { namespace: row.original.configmapNamespace }
                    : undefined
                }
              >
                {cell.getValue()}
              </Link>
            ),
            gridTemplate: 'auto',
          },
          {
            header: 'Description',
            accessorKey: 'description',
            gridTemplate: 'auto',
          },
          {
            header: 'Controls',
            accessorFn: (framework: FrameWork) => framework.controls.length,
          },
          // no column without actions: an empty one would take its width
          ...(allowDelete
            ? [
                {
                  header: 'Actions',
                  accessorFn: (framework: FrameWork) => (
                    <PermittedIconButton
                      check={frameworkCheck(
                        'delete',
                        framework.configmapNamespace,
                        framework.configmapManifestName
                      )}
                      title="Delete"
                      ariaLabel={`Delete ${framework.name}`}
                      size="medium"
                      onClick={() => askToDelete(framework)}
                    >
                      <Icon icon="mdi:delete" />
                    </PermittedIconButton>
                  ),
                  gridTemplate: 'min-content',
                } as TableColumn<FrameWork>,
              ]
            : []),
        ]}
        data={frameworks}
        initialState={{
          sorting: [
            {
              id: 'name',
              desc: false,
            },
          ],
        }}
      />
    </>
  );
}
