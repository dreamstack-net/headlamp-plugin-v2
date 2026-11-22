/* 
  Show fix suggestion for a workload. 
*/
import { Icon } from '@iconify/react';
import { K8s } from '@kinvolk/headlamp-plugin/lib';
import { put, request } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import { NameValueTable, SectionBox } from '@kinvolk/headlamp-plugin/lib/CommonComponents';
import { DiffEditor } from '@monaco-editor/react';
import {
  Alert,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Link,
  Stack,
  Typography,
} from '@mui/material';
import * as yaml from 'js-yaml';
import { cloneDeep } from 'lodash';
import { useSnackbar } from 'notistack';
import { useEffect, useState } from 'react';
import { errorMessage, errorStatus } from '../common/errors';
import { saveToFile } from '../common/filedialog';
import { configurationScanCommand } from '../common/operatorCommands';
import { AccessCheck, Permitted } from '../common/permissions';
import { ScanNowButton } from '../common/ScanNowButton';
import { useEditorTheme } from '../common/theme';
import { getURLSegments } from '../common/url';
import { fetchObject, workloadConfigurationScanClass } from '../model';
import { useRegoData } from '../rego';
import { WorkloadConfigurationScan } from '../softwarecomposition/WorkloadConfigurationScan';

export default function KubescapeWorkloadConfigurationScanFixes() {
  const [controlID, name, namespace, cluster] = getURLSegments(-1, -2, -3, -5);
  const { controls } = useRegoData();

  const [workloadConfigurationScan, setWorkloadConfigurationScan] =
    useState<WorkloadConfigurationScan | null>(null);
  const [readError, setReadError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    setReadError(null);
    fetchObject(name, namespace, cluster, workloadConfigurationScanClass)
      .then((result: WorkloadConfigurationScan) => {
        if (active) setWorkloadConfigurationScan(result);
      })
      .catch(error => {
        if (active) setReadError(errorMessage(error));
      });
    return () => {
      active = false;
    };
  }, [name, namespace, cluster]);

  const control = controls.find(element => element.controlID === controlID);

  if (readError) {
    return (
      <SectionBox title={control?.name ?? controlID} backLink>
        <Alert severity="error">Unable to read the configuration scan: {readError}</Alert>
      </SectionBox>
    );
  }
  if (!workloadConfigurationScan) {
    return <></>;
  }

  return (
    <>
      <SectionBox title={control?.name} backLink>
        <NameValueTable
          rows={[
            {
              name: 'Name',
              value: workloadConfigurationScan.metadata.labels['kubescape.io/workload-name'],
            },
            {
              name: 'Namespace',
              value: workloadConfigurationScan.metadata.labels['kubescape.io/workload-namespace'],
            },
            {
              name: 'Kind',
              value: workloadConfigurationScan.metadata.labels['kubescape.io/workload-kind'],
            },
            {
              name: 'Control',
              value: (
                <Link
                  target="_blank"
                  href={'https://kubescape.io/docs/controls/' + control?.controlID.toLowerCase()}
                >
                  {control?.controlID} {control?.name}
                </Link>
              ),
            },
            {
              name: 'Explain',
              value: control?.description,
            },
            {
              name: 'Category',
              value: control?.category?.name,
            },
            {
              name: 'Remediation',
              value: control?.remediation,
            },
            // {
            //   name: 'Scan',
            //   value: workloadConfigurationScan.metadata.name,
            // },
            {
              name: 'Related objects',
              value: workloadConfigurationScan.spec.relatedObjects
                ? workloadConfigurationScan.spec.relatedObjects
                    .map(object => `${object.name}: ${object.kind}`)
                    .join(', ')
                : '',
            },
          ]}
        />
      </SectionBox>

      {fixes(workloadConfigurationScan, controlID, cluster, !!control?.remediation)}
    </>
  );
}

function fixes(
  workloadConfigurationScan: WorkloadConfigurationScan,
  controlID: string,
  cluster: string,
  hasRemediation: boolean
): JSX.Element[] {
  const fixes: JSX.Element[] = [];
  const control = Object.values(workloadConfigurationScan.spec.controls).find(
    item => item.controlID === controlID
  );

  if (!control) {
    return fixes;
  }

  const labels = workloadConfigurationScan.metadata.labels;
  const scannedAt = scanTime(workloadConfigurationScan);
  const primaryFix = (
    <Fix
      key="primary-fix"
      control={control}
      kind={labels['kubescape.io/workload-kind']}
      apiGroup={labels['kubescape.io/workload-api-group']}
      apiVersion={labels['kubescape.io/workload-api-version']}
      name={labels['kubescape.io/workload-name']}
      namespace={labels['kubescape.io/workload-namespace']}
      cluster={cluster}
      scannedAt={scannedAt}
      hasRemediation={hasRemediation}
    />
  );
  if (primaryFix) {
    fixes.push(primaryFix);
  }
  if (workloadConfigurationScan.spec.relatedObjects) {
    workloadConfigurationScan.spec.relatedObjects.forEach((obj, index) => {
      const fix = (
        <Fix
          key={`fix-${index}`}
          control={control}
          kind={obj.kind}
          apiGroup={obj.apiGroup}
          apiVersion={obj.apiVersion}
          name={obj.name}
          namespace={obj.namespace}
          cluster={cluster}
          scannedAt={scannedAt}
          hasRemediation={hasRemediation}
          rulePathPrefix={`relatedObjects[${index}].`}
        />
      );
      if (fix) {
        fixes.push(fix);
      }
    });
  }

  return fixes;
}

function Fix(
  props: Readonly<{
    control: WorkloadConfigurationScan.Control;
    kind: string;
    // the API group and version of the scanned object, when Kubescape names them
    apiGroup?: string;
    apiVersion?: string;
    name: string;
    namespace: string;
    cluster: string;
    // when Kubescape scanned the object, in milliseconds, if the scan says
    scannedAt?: number;
    // whether the page shows the remediation of the control
    hasRemediation: boolean;
    rulePathPrefix?: string; // to filter rules for relatedObjects
  }>
) {
  const { control, kind, apiGroup, apiVersion, name, namespace, cluster } = props;
  const { scannedAt, hasRemediation, rulePathPrefix } = props;
  const editorTheme = useEditorTheme();
  const [target, setTarget] = useState<{ location: ResourceLocation; resource: any } | null>(null);
  const [readError, setReadError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    setReadError(null);
    setTarget(null);
    resourceLocation(kind, apiGroup, apiVersion, cluster)
      .then(async location => {
        if (!location) {
          throw new Error(
            apiVersion
              ? `the cluster serves no ${kind} in ${apiGroup ? `${apiGroup}/` : ''}${apiVersion}`
              : `${kind} is not a kind this page can read`
          );
        }
        const resource = await request(objectPath(location, namespace, name), { cluster });
        if (active) setTarget({ location, resource });
      })
      .catch(error => active && setReadError(errorMessage(error)));
    return () => {
      active = false;
    };
  }, [kind, apiGroup, apiVersion, name, namespace, cluster]);

  if (readError) {
    return (
      <Alert severity="error">
        Unable to read {name}: {readError}
      </Alert>
    );
  }

  if (!target) {
    return <></>;
  }
  const { location, resource } = target;
  const path = objectPath(location, namespace, name);
  const changedAt = lastChanged(resource);
  // the fix paths are of the object the scan saw: an index into its containers may now point at
  // another container, or one past the end, where the fix would add a container
  const changedSinceScan =
    scannedAt !== undefined && changedAt !== undefined && changedAt > scannedAt;

  // strip status
  const strippedResource: any = Object.fromEntries(
    Object.entries(resource).filter(([key]) => key !== 'status')
  );
  // strip managedFields
  strippedResource.metadata = Object.fromEntries(
    Object.entries(strippedResource.metadata).filter(([key]) => key !== 'managedFields')
  );

  const original = yaml.dump(strippedResource);

  const { fixes, review } = resourcePaths(control, rulePathPrefix ?? '');
  const fixedYAML = fixResource(cloneDeep(strippedResource), control, rulePathPrefix ?? '');
  const lines = fixedYAML.match(/\n/g)?.length ?? 10;

  // Kubescape gives some controls no path to fix, such as C-0057 (privileged containers): a
  // diff without changes and an Apply that cannot be used would not say so
  if (fixedYAML === original) {
    return (
      <>
        <Alert severity="info" sx={{ my: 1 }}>
          Kubescape gives no automatic fix for this control in {kind}{' '}
          {namespace ? `${namespace}/${name}` : name}: change it by hand, as{' '}
          {hasRemediation
            ? 'the remediation above describes'
            : 'the documentation of the control describes'}
          .
        </Alert>
        <ReviewPaths paths={review} />
      </>
    );
  }

  return (
    <>
      {changedSinceScan && (
        <Alert
          severity="warning"
          sx={{ my: 1 }}
          action={
            <ScanNowButton
              clusters={[cluster]}
              command={configurationScanCommand}
              tooltip={`Ask Kubescape to scan again, so this page shows the fix of the ${kind} as it is now`}
            />
          }
        >
          The {kind} {namespace ? `${namespace}/${name}` : name} changed at{' '}
          {new Date(changedAt).toLocaleString()}, after Kubescape scanned it at{' '}
          {new Date(scannedAt).toLocaleString()}. The paths of this fix are of the {kind} the scan
          saw and may point elsewhere now, such as at another container, so it cannot be applied
          from here. Scan again, and reload this page when the scan is done.
        </Alert>
      )}
      <FixActions
        kind={kind}
        name={name}
        namespace={namespace}
        cluster={cluster}
        path={path}
        updateCheck={{
          group: location.group,
          resource: location.plural,
          verb: 'update',
          namespace: namespace || undefined,
          name,
        }}
        fixedYAML={fixedYAML}
        placeholders={[...new Set(fixes.map(fix => fix.value).filter(isPlaceholder))]}
        changedSinceScan={changedSinceScan}
      />
      <ReviewPaths paths={review} />
      <DiffEditor
        theme={editorTheme}
        language="yaml"
        original={original}
        modified={fixedYAML}
        height={lines * 30}
        options={{
          renderSideBySide: true,
          // Apply fix and the download take the fix as it was made, not what is typed here
          readOnly: true,
        }}
      />
    </>
  );
}

// The paths where the control failed for which Kubescape gives no value to set: they are named,
// and nothing is changed for them
function ReviewPaths(props: Readonly<{ paths: string[] }>) {
  const { paths } = props;
  if (paths.length === 0) {
    return null;
  }

  return (
    <Alert severity="info" sx={{ my: 1 }}>
      Kubescape names where the control failed, without a value to set. Review{' '}
      {paths.length === 1 ? 'this path' : 'these paths'}, which no fix changes:
      <ul style={{ margin: 0 }}>
        {paths.map(path => (
          <li key={path}>
            <code>{path}</code>
          </li>
        ))}
      </ul>
    </Alert>
  );
}

// Download the fixed resource, or replace the resource in the cluster with it
function FixActions(
  props: Readonly<{
    kind: string;
    name: string;
    namespace: string;
    cluster: string;
    path: string;
    updateCheck: AccessCheck;
    fixedYAML: string;
    // the values of the fix that stand for a value the user has to choose, such as YOUR_VALUE
    placeholders: string[];
    // whether the resource changed since the scan, which the page says above the fix
    changedSinceScan: boolean;
  }>
) {
  const { kind, name, namespace, cluster, path, updateCheck, fixedYAML, placeholders } = props;
  const { changedSinceScan } = props;
  const { enqueueSnackbar } = useSnackbar();
  const [confirming, setConfirming] = useState(false);
  const [applying, setApplying] = useState(false);
  const [applied, setApplied] = useState(false);
  const [error, setError] = useState('');
  const fullName = namespace ? `${namespace}/${name}` : name;

  const apply = async () => {
    setApplying(true);
    setError('');
    try {
      // the resource version makes the update fail when the resource changed meanwhile
      await put(path, yaml.load(fixedYAML) as any, true, { cluster });
      setConfirming(false);
      setApplied(true);
      enqueueSnackbar(`Fix applied to ${kind} ${fullName}`, { variant: 'success' });
    } catch (err) {
      setError(
        errorStatus(err) === 409
          ? `The ${kind} changed since this page was opened. Reload the page to see the current fix.`
          : errorMessage(err)
      );
    } finally {
      setApplying(false);
    }
  };

  return (
    <>
      <Stack direction="row" spacing={1} sx={{ my: 1 }} alignItems="center">
        <Button
          size="small"
          variant="outlined"
          startIcon={<Icon icon="mdi:download" />}
          onClick={() => saveToFile(fixedYAML, `${name}-fixed.yaml`, enqueueSnackbar)}
        >
          Download fixed YAML
        </Button>
        {placeholders.length > 0 ? (
          // the cluster would refuse the placeholder, or take it as the value
          <Typography variant="body2" color="text.secondary">
            This fix cannot be applied from here: it holds{' '}
            {placeholders.length === 1 ? 'the placeholder' : 'the placeholders'}{' '}
            {placeholders.join(', ')}, to replace with a value of your own in the downloaded YAML.
          </Typography>
        ) : (
          // the warning above the fix says why the fix of a changed resource is not applied
          !changedSinceScan && (
            <Permitted check={updateCheck} cluster={cluster}>
              {allowed => (
                <Button
                  size="small"
                  variant="outlined"
                  color="warning"
                  disabled={!allowed || applied}
                  startIcon={<Icon icon="mdi:wrench-check-outline" />}
                  onClick={() => setConfirming(true)}
                >
                  {applied ? 'Fix applied' : 'Apply fix'}
                </Button>
              )}
            </Permitted>
          )
        )}
        {applied && (
          <ScanNowButton
            clusters={[cluster]}
            command={configurationScanCommand}
            tooltip="Ask Kubescape to scan again, so the compliance results show the fix"
          />
        )}
      </Stack>

      <Dialog open={confirming} onClose={() => setConfirming(false)}>
        <DialogTitle>
          Apply fix to {kind} {fullName}
        </DialogTitle>
        <DialogContent>
          <Alert severity="warning" sx={{ mb: 1 }}>
            This replaces the {kind} in cluster {cluster} with the fixed version shown on this page.
            Kubernetes then rolls out the change, which restarts the pods of a workload. Check that
            the fix suits the workload before you apply it.
          </Alert>
          {error && <Alert severity="error">{error}</Alert>}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirming(false)}>Cancel</Button>
          <Button variant="contained" color="warning" disabled={applying} onClick={apply}>
            Apply
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}

/** The resource of the API server that holds the objects of a kind. */
export interface ResourceLocation {
  // '' for the core group
  group: string;
  version: string;
  plural: string;
}

/**
 * Where the objects of a kind of an API group and version are read and replaced: Headlamp's
 * class of the kind when it is of that group, else the resource that the API server names for the
 * kind in that group and version. Kinds of other groups share names (the Gateway of Istio and that
 * of the Gateway API), so the kind alone may name another resource. Without a group and version,
 * which an older Kubescape leaves out, as Kubescape does for the ServiceAccount of a role binding,
 * the class of the kind. Undefined for a kind it cannot find.
 */
export async function resourceLocation(
  kind: string,
  apiGroup: string | undefined,
  apiVersion: string | undefined,
  cluster: string
): Promise<ResourceLocation | undefined> {
  // @ts-ignore
  const kubeObjectClass = K8s.ResourceClasses[kind];
  const apiInfo: Array<{ group: string; version: string }> =
    kubeObjectClass?.apiEndpoint.apiInfo ?? [];
  const named = !!(apiGroup || apiVersion);
  const info = named ? apiInfo.find(element => element.group === (apiGroup ?? '')) : apiInfo[0];
  if (info) {
    return {
      group: info.group,
      version: apiVersion || info.version,
      plural: kubeObjectClass.pluralName,
    };
  }
  if (!apiVersion) return undefined;

  const group = apiGroup ?? '';
  const resources = await request(group ? `/apis/${group}/${apiVersion}` : `/api/${apiVersion}`, {
    cluster,
  });
  // subresources, such as gateways/status, name the kind of their object too
  const resource = resources?.resources?.find(
    (element: { name: string; kind: string }) =>
      element.kind === kind && !element.name.includes('/')
  );
  return resource ? { group, version: apiVersion, plural: resource.name } : undefined;
}

/** The path of an object of the API server. */
export function objectPath(location: ResourceLocation, namespace: string, name: string): string {
  // the core API group has no group in the path
  const group = location.group ? `/apis/${location.group}` : '/api';
  const inNamespace = namespace ? `namespaces/${namespace}/` : '';
  return `${group}/${location.version}/${inNamespace}${location.plural}/${name}`;
}

/**
 * When Kubescape scanned the workload, in milliseconds: the time of its report, which the
 * annotation gives to the nanosecond and the spec to the second. Kubescape takes that time when
 * the scan ends, after it read the resources.
 */
export function scanTime(scan: WorkloadConfigurationScan): number | undefined {
  const time =
    scan.metadata.annotations?.['kubescape.io/report-created-at'] ||
    scan.spec.metadata?.report?.createdAt;
  const parsed = time ? Date.parse(time) : NaN;
  return Number.isNaN(parsed) ? undefined : parsed;
}

/**
 * When the resource last changed, in milliseconds, as far as the API server records it: the
 * newest time of its managed fields, apart from those of a subresource (status, scale), which a
 * fix does not change, or else its creation. A manager's time also moves when it changes a label
 * or an annotation.
 */
export function lastChanged(resource: any): number | undefined {
  const fields: Array<{ subresource?: string; time?: string }> =
    resource?.metadata?.managedFields ?? [];
  const times = [
    resource?.metadata?.creationTimestamp,
    ...fields.filter(field => !field.subresource).map(field => field.time),
  ]
    .map(time => (time ? Date.parse(time) : NaN))
    .filter(time => !Number.isNaN(time));
  return times.length > 0 ? Math.max(...times) : undefined;
}

/**
 * The paths of the rules of a control within a resource: the fixes, which set a value at a path,
 * and the paths to review, for which Kubescape gives no value to set. Such a path says where the
 * control failed, not what to change (spec.podSelector of a network policy that selects no pods,
 * the data of the kube-proxy ConfigMap), so no fix changes it. The paths of a related object
 * start with its prefix (relatedObjects[0].), which is left out; the others are of the workload.
 */
export function resourcePaths(
  control: WorkloadConfigurationScan.Control,
  prefix: string
): { fixes: Array<{ path: string; value: unknown }>; review: string[] } {
  const fixes: Array<{ path: string; value: unknown }> = [];
  const review = new Set<string>();
  const inResource = (path: string | undefined) => {
    if (!path) return undefined;
    if (prefix) return path.startsWith(prefix) ? path.replace(prefix, '') : undefined;
    return path.startsWith('relatedObjects') ? undefined : path;
  };

  if (control.rules) {
    for (const rule of control.rules) {
      if (!rule.paths) {
        continue;
      }
      for (const rulePath of rule.paths) {
        const fixPath = inResource(rulePath.fixPath);
        const value = parseFixValue(rulePath.fixPathValue);
        if (fixPath !== undefined && value !== undefined) {
          fixes.push({ path: fixPath, value });
          continue;
        }
        const failedPath = fixPath ?? inResource(rulePath.failedPath);
        if (failedPath !== undefined) review.add(failedPath);
      }
    }
  }

  // a path that a fix sets needs no review
  const fixed = new Set(fixes.map(fix => fix.path));
  return { fixes, review: [...review].filter(path => !fixed.has(path)) };
}

// what Kubescape puts in a fix where the user has to choose: YOUR_VALUE, YOUR_NAMESPACE,
// REMOVE_GROUP_0, <your-tls-definition>, --audit-log-maxsize=YOUR_VALUE
const placeholderPattern = /YOUR_[A-Z_]+|REMOVE_[A-Z0-9_]+|<[^<>]+>/;

/** Whether the value of a fix is a placeholder for a value that the user has to choose. */
export function isPlaceholder(value: unknown): value is string {
  return typeof value === 'string' && placeholderPattern.test(value);
}

// Amend the resource as per fixPath recommendations
export function fixResource(
  resource: any,
  control: WorkloadConfigurationScan.Control,
  prefix: string
): string {
  for (const { path, value } of resourcePaths(control, prefix).fixes) {
    applyFixPath(resource, path, value);
  }

  return yaml.dump(resource);
}

/**
 * The value of a fix path, which Kubescape gives as text, as the type the field has: "false"
 * is a boolean and "1000" a number, while "RuntimeDefault" stays text.
 */
export function parseFixValue(fixPathValue: string | undefined): unknown {
  // the storage leaves the value out of a path without one
  if (fixPathValue === undefined) return undefined;
  try {
    const value = yaml.load(fixPathValue, { schema: yaml.JSON_SCHEMA });
    return value === undefined ? fixPathValue : value;
  } catch {
    return fixPathValue;
  }
}

/**
 * Sets the value at a path of Kubescape, such as
 * spec.template.spec.containers[0].securityContext.capabilities.drop[1], in the resource. Missing
 * objects and arrays on the way are created; an index one past the end of an array appends,
 * which is how Kubescape adds to a list (drop[count(drop_list)]). A path that does not fit the
 * resource, such as an index beyond the end, changes nothing.
 */
export function applyFixPath(resource: any, path: string, value: unknown) {
  const steps: Array<string | number> = [];
  for (const part of path.split('.')) {
    const match = part.match(/^([^[\]]+)((?:\[\d+\])*)$/);
    if (!match) return;
    steps.push(match[1]);
    for (const index of match[2].matchAll(/\[(\d+)\]/g)) steps.push(Number(index[1]));
  }

  let element: any = resource;
  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    const last = i === steps.length - 1;
    if (typeof step === 'number') {
      if (!Array.isArray(element) || step > element.length) return;
    } else if (element === null || typeof element !== 'object' || Array.isArray(element)) {
      return;
    }
    if (last) {
      element[step] = value;
      return;
    }
    if (element[step] === undefined || element[step] === null) {
      element[step] = typeof steps[i + 1] === 'number' ? [] : {};
    }
    element = element[step];
  }
}
