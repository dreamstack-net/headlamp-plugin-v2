import {
  Alert,
  Button,
  Checkbox,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  FormGroup,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import * as yaml from 'js-yaml';
import { useEffect, useState } from 'react';
import { errorMessage } from '../common/errors';
import { Permitted } from '../common/permissions';
import {
  bindingFor,
  bindingName,
  checkInstall,
  checkPolicy,
  installPolicy,
  isInstalled,
  paramsCreationProblem,
  paramsName,
  ParamsState,
  paramsState,
  PartlyInstalledError,
  PolicyObject,
  ValidationAction,
} from './install';

const createCheck = (resource: string) => ({
  group: 'admissionregistration.k8s.io',
  resource,
  verb: 'create',
});

// installing reads every binding first, to find those that would enforce the policy
// (installProblem)
const listBindingsCheck = {
  group: 'admissionregistration.k8s.io',
  resource: 'validatingadmissionpolicybindings',
  verb: 'list',
};

function errorText(error: any) {
  return errorMessage(error);
}

function parse(text: string | undefined): any {
  try {
    return text ? yaml.load(text) : null;
  } catch {
    return null;
  }
}

/** The policy of the editor, or why the editor holds none that can be read. */
function readPolicy(text: string | undefined): { policy: any; unreadable?: string } {
  if (!text?.trim()) return { policy: null, unreadable: 'The policy editor is empty.' };
  try {
    return { policy: yaml.load(text) };
  } catch (error) {
    return {
      policy: null,
      unreadable: `The policy editor does not hold valid YAML: ${errorText(error)}`,
    };
  }
}

const paramsProblems: Partial<Record<ParamsState, string>> = {
  'not-served':
    'This policy reads its parameters from a kubescape.io/v1 ControlConfiguration, which this ' +
    'cluster does not serve. Install the ControlConfiguration CRD of the Kubescape CEL ' +
    'admission library first.',
  namespaced:
    'This cluster serves ControlConfigurations per namespace; the playground only installs ' +
    'policies whose parameters are cluster-wide.',
};

/** Installs the policy of the editor in the cluster, with a binding that never rejects. */
export function InstallPolicyButton(
  props: Readonly<{
    getPolicyYaml: () => string | undefined;
    getParamsYaml: () => string | undefined;
    disabled: boolean;
  }>
) {
  const { getPolicyYaml, getParamsYaml, disabled } = props;
  // what the policy editor held when the dialog was opened, null while it is closed
  const [opened, setOpened] = useState<ReturnType<typeof readPolicy> | null>(null);

  return (
    <>
      <Permitted check={[createCheck('validatingadmissionpolicies'), listBindingsCheck]}>
        {allowed => (
          <Button
            variant="outlined"
            disabled={disabled || !allowed}
            onClick={() => setOpened(readPolicy(getPolicyYaml()))}
          >
            Install in cluster
          </Button>
        )}
      </Permitted>
      {opened !== null && (
        <InstallDialog
          policy={opened.policy}
          unreadable={opened.unreadable}
          params={parse(getParamsYaml())}
          onClose={() => setOpened(null)}
        />
      )}
    </>
  );
}

function InstallDialog(
  props: Readonly<{
    policy: PolicyObject;
    // why the editor holds no policy to read: it is empty, or not YAML
    unreadable?: string;
    params: any;
    onClose: () => void;
  }>
) {
  const { policy, unreadable, params, onClose } = props;
  const problem = unreadable ?? checkPolicy(policy);
  const [actions, setActions] = useState<Record<ValidationAction, boolean>>({
    Warn: true,
    Audit: true,
  });
  const [namespace, setNamespace] = useState('');
  const [paramsStatus, setParamsStatus] = useState<ParamsState | null>(null);
  const [createParams, setCreateParams] = useState(true);
  // why creating the missing parameters could reject requests, null when it cannot or they are
  // not created, undefined while it is checked
  const [paramsConflict, setParamsConflict] = useState<string | null | undefined>(undefined);
  const [installed, setInstalled] = useState<boolean | null>(null);
  // why installing could reject requests, null when it cannot, undefined while it is checked
  const [conflict, setConflict] = useState<string | null | undefined>(undefined);
  // whether the plugin's binding exists, which installing replaces rather than creates
  const [bindingInstalled, setBindingInstalled] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{
    severity: 'success' | 'warning' | 'error';
    text: string;
  } | null>(null);

  useEffect(() => {
    if (problem) return;
    paramsState(policy)
      .then(status => {
        setParamsStatus(status);
        if (status !== 'missing' || !params) return setParamsConflict(null);
        return paramsCreationProblem(policy).then(setParamsConflict, error =>
          setParamsConflict(
            `Unable to check the bindings that read ${paramsName}: ${errorText(error)}`
          )
        );
      })
      .catch(error =>
        setResult({
          severity: 'error',
          text: `Unable to check the parameters: ${errorText(error)}`,
        })
      );
    isInstalled(policy)
      .then(setInstalled)
      .catch(() => setInstalled(null));
    checkInstall(policy)
      .then(found => {
        setBindingInstalled(found.bindingInstalled);
        setConflict(found.problem);
      })
      .catch(error =>
        setConflict(`Unable to check the bindings of the policy: ${errorText(error)}`)
      );
    // the dialog is opened for one policy
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const chosen = (Object.keys(actions) as ValidationAction[]).filter(action => actions[action]);
  const paramsProblem = paramsStatus ? paramsProblems[paramsStatus] : undefined;
  const willCreateParams =
    paramsStatus === 'missing' && createParams && !!params && paramsConflict === null;
  const ready =
    !problem &&
    paramsStatus !== null &&
    !paramsProblem &&
    paramsConflict !== undefined &&
    conflict === null &&
    chosen.length > 0 &&
    !busy &&
    !result;

  // what installing reads and writes: it reads the policy and its binding to tell whether they
  // exist, creates them or replaces those that exist, and creates the parameters when asked
  const namedCheck = (resource: string, verb: string, name: string) => ({
    group: 'admissionregistration.k8s.io',
    resource,
    verb,
    name,
  });
  // a policy without a name (problem) installs nothing
  const installChecks = problem
    ? []
    : [
        namedCheck('validatingadmissionpolicies', 'get', policy.metadata.name),
        namedCheck('validatingadmissionpolicybindings', 'get', bindingName(policy)),
        installed
          ? namedCheck('validatingadmissionpolicies', 'update', policy.metadata.name)
          : createCheck('validatingadmissionpolicies'),
        bindingInstalled
          ? namedCheck('validatingadmissionpolicybindings', 'update', bindingName(policy))
          : createCheck('validatingadmissionpolicybindings'),
        ...(willCreateParams
          ? [{ group: 'kubescape.io', resource: 'controlconfigurations', verb: 'create' }]
          : []),
      ];
  const auditAnnotations: unknown[] = Array.isArray(policy?.spec?.auditAnnotations)
    ? policy.spec!.auditAnnotations
    : [];

  const install = async () => {
    setBusy(true);
    const binding = bindingFor(policy, chosen, namespace.trim() || undefined);
    try {
      await installPolicy(policy, binding, willCreateParams ? params : null);
      setResult({
        severity: 'success',
        text:
          `Installed ${policy.metadata.name} with binding ${binding.metadata.name} ` +
          `(${chosen.join(', ')}). Requests that violate it are allowed` +
          (actions.Warn ? ' and get a warning' : '') +
          (actions.Audit ? ', and are recorded in the audit log' : '') +
          '.',
      });
    } catch (error) {
      setResult(
        error instanceof PartlyInstalledError
          ? {
              severity: 'warning',
              text: `${error.message}. Close this dialog and install again to add the rest.`,
            }
          : { severity: 'error', text: `Unable to install the policy: ${errorText(error)}` }
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Install policy in cluster</DialogTitle>
      <DialogContent>
        {problem ? (
          <Alert severity="error">{problem}</Alert>
        ) : (
          <Stack spacing={2} sx={{ mt: 1 }}>
            <Typography>
              Installs <b>{policy.metadata.name}</b> as it is in the policy editor, but with
              failurePolicy Ignore, and the binding <b>{bindingName(policy)}</b>, which only warns
              or audits. With failurePolicy Ignore the API server admits a request when the
              parameters of the policy cannot be read or an audit annotation fails, which it would
              otherwise reject whatever the binding does, so the policy rejects no request. A
              validation or match condition that fails is then no violation either, which the
              binding would otherwise warn about or audit. Deny is not offered here: change the
              binding and the failurePolicy with kubectl once the warnings show that the policy is
              right.
            </Typography>
            {auditAnnotations.length > 0 && (
              <Alert severity="info">
                The values of the audit annotations are installed converted with string(): the API
                server rejects a request for a value that is not a string or null, also with
                failurePolicy Ignore. A value without a string form, such as null, is left out.
              </Alert>
            )}
            {conflict && <Alert severity="error">{conflict}</Alert>}
            {installed && !conflict && (
              <Alert severity="info">
                The policy is installed already; installing replaces it and its binding.
              </Alert>
            )}
            <FormGroup row>
              {(['Warn', 'Audit'] as ValidationAction[]).map(action => (
                <FormControlLabel
                  key={action}
                  control={
                    <Checkbox
                      checked={actions[action]}
                      onChange={(_, checked) => setActions({ ...actions, [action]: checked })}
                    />
                  }
                  label={action}
                />
              ))}
            </FormGroup>
            <TextField
              label="Namespace"
              size="small"
              value={namespace}
              onChange={event => setNamespace(event.target.value)}
              helperText="Only check requests for objects in this namespace; cluster-scoped objects, such as ClusterRoles, and the Namespace itself are then not checked. Empty for all requests."
            />
            {paramsProblem && <Alert severity="warning">{paramsProblem}</Alert>}
            {paramsStatus === 'missing' && paramsConflict && (
              <Alert severity="warning">{paramsConflict}</Alert>
            )}
            {paramsStatus === 'missing' && (
              <FormControlLabel
                control={
                  <Checkbox
                    checked={createParams && !!params && !paramsConflict}
                    disabled={!params || !!paramsConflict}
                    onChange={(_, checked) => setCreateParams(checked)}
                  />
                }
                label={`Create the ControlConfiguration ${paramsName} from the Params tab; without it the policy checks no request until the parameters exist.`}
              />
            )}
          </Stack>
        )}
        {result && (
          <Alert severity={result.severity} sx={{ mt: 2 }}>
            {result.text}
          </Alert>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>
          {result && result.severity !== 'error' ? 'Close' : 'Cancel'}
        </Button>
        {!problem && (
          <Permitted check={installChecks}>
            {allowed => (
              <Button variant="contained" disabled={!ready || !allowed} onClick={install}>
                {busy ? 'Installing…' : 'Install'}
              </Button>
            )}
          </Permitted>
        )}
      </DialogActions>
    </Dialog>
  );
}
