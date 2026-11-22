/*
  Installing a playground policy in the cluster with a binding that only warns or audits, so
  it can be tried on real requests without rejecting any. A binding that denies may already refer
  to the name of the policy, also before the policy exists, and would then enforce the policy of
  the editor as soon as it is installed; such a policy is not installed.

  The API server also rejects requests, whatever the validationActions of the bindings, when the
  failurePolicy is Fail, for errors of the configuration (parameters that a binding requires and
  that are missing, a paramKind whose CRD is gone) and for an audit annotation that fails; a
  validation or match condition that fails is a violation, which the validationActions decide
  about. The copy that is installed therefore has failurePolicy Ignore, its binding allows
  requests while the parameters are missing, and its audit annotations always give a string, as
  any other value rejects the request even with failurePolicy Ignore.

  The API server refuses a policy whose expressions do not compile, which the playground does not
  check. The policy is therefore sent as a dry run before anything is written, so that a policy
  it refuses leaves nothing behind, such as a binding that would bind any later policy of its
  name.
*/
import { post, put, request } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import { errorMessage, errorStatus } from '../common/errors';

export type ValidationAction = 'Warn' | 'Audit';

// The parameters that the Kubescape library policies are written for
export const paramsName = 'basic-control-configuration';
const paramsCollection = '/apis/kubescape.io/v1/controlconfigurations';
const managedByLabel = 'app.kubernetes.io/managed-by';
const managedBy = { [managedByLabel]: 'headlamp-kubescape-plugin' };

export interface PolicyObject {
  apiVersion: string;
  kind: string;
  metadata: { name: string; [key: string]: any };
  spec?: { paramKind?: { apiVersion: string; kind: string }; [key: string]: any };
}

/** Reads the policy from the editor, or explains why it cannot be installed. */
export function checkPolicy(policy: any): string | null {
  if (!policy || policy.kind !== 'ValidatingAdmissionPolicy') {
    return 'The policy editor does not hold a ValidatingAdmissionPolicy.';
  }
  if (!/^admissionregistration\.k8s\.io\/v1(beta1)?$/.test(policy.apiVersion ?? '')) {
    return `Policies of apiVersion ${policy.apiVersion} cannot be installed.`;
  }
  if (!policy.metadata?.name) return 'The policy has no name.';
  return null;
}

export function bindingName(policy: PolicyObject) {
  return `${policy.metadata.name}-binding`;
}

/**
 * A binding that only warns or audits. Never Deny: the policy is being tried, and switching
 * to Deny is a decision to take with kubectl, knowing what it rejects.
 *
 * While the parameters are missing, the binding allows every request: with
 * parameterNotFoundAction Deny the API server would count each request as an error of the
 * configuration, which it rejects whatever the validationActions unless the failurePolicy is
 * Ignore.
 *
 * A namespace limits the binding to the requests for namespaced resources in that namespace: a
 * namespaceSelector never leaves out cluster-scoped objects other than Namespaces, such as the
 * ClusterRoles that library policies check, and selects the Namespace itself. The rule with scope
 * Namespaced matches every resource and subresource that has a namespace ('*' + '/*' is all
 * resources and their subresources), and no Namespace object.
 */
export function bindingFor(policy: PolicyObject, actions: ValidationAction[], namespace?: string) {
  return {
    apiVersion: policy.apiVersion,
    kind: 'ValidatingAdmissionPolicyBinding',
    metadata: { name: bindingName(policy), labels: managedBy },
    spec: {
      policyName: policy.metadata.name,
      validationActions: actions.filter(action => action === 'Warn' || action === 'Audit'),
      ...(policy.spec?.paramKind && {
        paramRef: { name: paramsName, parameterNotFoundAction: 'Allow' },
      }),
      ...(namespace && {
        matchResources: {
          namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': namespace } },
          resourceRules: [
            {
              apiGroups: ['*'],
              apiVersions: ['*'],
              operations: ['*'],
              resources: ['*/*'],
              scope: 'Namespaced',
            },
          ],
        },
      }),
    },
  };
}

function collectionOf(apiVersion: string, plural: string) {
  return `/apis/${apiVersion}/${plural}`;
}

export type ParamsState = 'unneeded' | 'not-served' | 'namespaced' | 'missing' | 'present';

/**
 * Whether the cluster has the ControlConfiguration that a policy with parameters reads: the
 * resource is served by the Kubescape CEL admission library's CRD, and the object exists.
 */
export async function paramsState(policy: PolicyObject, cluster?: string): Promise<ParamsState> {
  const paramKind = policy.spec?.paramKind;
  if (!paramKind) return 'unneeded';
  if (paramKind.apiVersion !== 'kubescape.io/v1' || paramKind.kind !== 'ControlConfiguration') {
    return 'not-served';
  }
  const options = cluster ? { cluster } : {};
  const discovery = await request('/apis/kubescape.io/v1', options).catch(() => null);
  const resource = discovery?.resources?.find((r: any) => r.name === 'controlconfigurations');
  if (!resource) return 'not-served';
  if (resource.namespaced) return 'namespaced';
  try {
    await request(`${paramsCollection}/${paramsName}`, options);
    return 'present';
  } catch (error) {
    if (errorStatus(error) === 404) return 'missing';
    throw error;
  }
}

/** Whether an object exists, with the resource version to replace it; null when it does not. */
async function existing(path: string, cluster?: string): Promise<string | null> {
  try {
    const object = await request(path, cluster ? { cluster } : {});
    return object?.metadata?.resourceVersion ?? '';
  } catch (error) {
    if (errorStatus(error) === 404) return null;
    throw error;
  }
}

export async function isInstalled(policy: PolicyObject, cluster?: string) {
  const path = `${collectionOf(policy.apiVersion, 'validatingadmissionpolicies')}/${
    policy.metadata.name
  }`;
  return (await existing(path, cluster)) !== null;
}

/**
 * Creates the object, or replaces it when it exists with the given resource version. As a dry
 * run, the API server checks the object as it would and writes nothing.
 */
function createOrReplace(
  collection: string,
  object: any,
  resourceVersion: string | null,
  cluster?: string,
  dryRun = false
) {
  const options = cluster ? { cluster } : undefined;
  const query = dryRun ? '?dryRun=All' : '';
  if (resourceVersion === null) {
    return post(`${collection}${query}`, object, true, options);
  }
  return put(
    `${collection}/${object.metadata.name}${query}`,
    { ...object, metadata: { ...object.metadata, resourceVersion } },
    true,
    options
  );
}

/**
 * An audit annotation whose value is not a string or null makes the API server reject the
 * request, whatever the failurePolicy and the validationActions. Converted to a string, the value
 * is a string, or an error for a value without a string form, such as null or a list, which
 * failurePolicy Ignore leaves out.
 */
export function stringValueExpression(valueExpression: string) {
  // on a line of its own, so that a comment at the end of the expression ends there
  return `string(\n${valueExpression}\n)`;
}

/**
 * The policy that is installed: as the user wrote it, also when it was copied from a cluster,
 * without the fields of the server, but with failurePolicy Ignore and audit annotations that
 * always give a string, so that no error of the policy rejects a request.
 */
export function installedPolicy(policy: PolicyObject) {
  const metadata = Object.fromEntries(
    Object.entries(policy.metadata).filter(
      ([key]) =>
        !['resourceVersion', 'uid', 'creationTimestamp', 'generation', 'managedFields'].includes(
          key
        )
    )
  );
  const spec = policy.spec ?? {};
  return {
    apiVersion: policy.apiVersion,
    kind: policy.kind,
    metadata: { ...metadata, labels: { ...policy.metadata.labels, ...managedBy } },
    spec: {
      ...spec,
      failurePolicy: 'Ignore',
      ...(Array.isArray(spec.auditAnnotations) && {
        auditAnnotations: spec.auditAnnotations.map((annotation: any) =>
          typeof annotation?.valueExpression === 'string'
            ? { ...annotation, valueExpression: stringValueExpression(annotation.valueExpression) }
            : annotation
        ),
      }),
    },
  };
}

function plural(count: number, one: string, more: string) {
  return count === 1 ? one : more;
}

/** Every ValidatingAdmissionPolicyBinding of the cluster. */
async function listBindings(policy: PolicyObject, cluster?: string): Promise<any[]> {
  try {
    const list = await request(
      collectionOf(policy.apiVersion, 'validatingadmissionpolicybindings'),
      cluster ? { cluster } : {}
    );
    return list?.items ?? [];
  } catch (error) {
    // a cluster that does not serve the bindings has none
    if (errorStatus(error) !== 404) throw error;
    return [];
  }
}

// Whether the binding is the one the plugin installed for the policy, which installing replaces
function isOwnBinding(policy: PolicyObject, binding: any) {
  return (
    binding?.metadata?.name === bindingName(policy) &&
    binding.spec?.policyName === policy.metadata.name &&
    binding.metadata?.labels?.[managedByLabel] === managedBy[managedByLabel]
  );
}

function policyProblem(policy: PolicyObject, bindings: any[]): string | null {
  const name = policy.metadata.name;
  const denying = bindings
    .filter(
      binding =>
        binding?.spec?.policyName === name &&
        (binding.spec.validationActions ?? []).includes('Deny')
    )
    .map(binding => binding.metadata?.name);
  if (denying.length) {
    return (
      `${plural(denying.length, 'The binding', 'The bindings')} ${denying.join(', ')} ` +
      `${plural(denying.length, 'rejects', 'reject')} requests that violate ${name}, so ` +
      'installing would change what it enforces. Give the policy another name in the editor to ' +
      'try it.'
    );
  }
  // the API server ignores the paramRef of the bindings of a policy without paramKind
  const denyingWithoutParams = policy.spec?.paramKind
    ? bindings
        .filter(
          binding =>
            binding?.spec?.policyName === name &&
            binding.spec.paramRef?.parameterNotFoundAction === 'Deny' &&
            !isOwnBinding(policy, binding)
        )
        .map(binding => binding.metadata?.name)
    : [];
  if (denyingWithoutParams.length) {
    const count = denyingWithoutParams.length;
    return (
      `${plural(count, 'The binding', 'The bindings')} ${denyingWithoutParams.join(', ')} of ` +
      `${name} ${plural(count, 'has', 'have')} parameterNotFoundAction Deny, which makes every ` +
      'request it matches an error of the policy while its parameters are missing; with ' +
      'failurePolicy Fail the API server rejects those requests. Give the policy another name ' +
      'in the editor to try it.'
    );
  }
  const own = bindings.find(binding => binding?.metadata?.name === bindingName(policy));
  if (own && !isOwnBinding(policy, own)) {
    return (
      `The binding ${bindingName(policy)} exists and was not installed for this policy by the ` +
      'plugin, so installing would replace it. Give the policy another name in the editor to try ' +
      'it.'
    );
  }
  return null;
}

/**
 * Why installing the policy could reject requests or replace a binding that the plugin did not
 * install, or null. A binding that denies with the name of the policy would enforce the policy of
 * the editor, also outside the namespace chosen here; the plugin's own binding is one of them once
 * it is switched to Deny with kubectl. A binding of the policy with parameterNotFoundAction Deny
 * makes requests errors of the policy while its parameters are missing. A binding with the name
 * of the plugin's binding that the plugin did not install, or that binds another policy, would be
 * replaced.
 */
export async function installProblem(
  policy: PolicyObject,
  cluster?: string
): Promise<string | null> {
  return (await checkInstall(policy, cluster)).problem;
}

/**
 * What installing would find: why it could reject requests or replace a binding the plugin did
 * not install (installProblem), and whether the plugin's binding exists, which installing then
 * replaces rather than creates.
 */
export async function checkInstall(
  policy: PolicyObject,
  cluster?: string
): Promise<{ problem: string | null; bindingInstalled: boolean }> {
  const bindings = await listBindings(policy, cluster);
  return {
    problem: policyProblem(policy, bindings),
    bindingInstalled: bindings.some(binding => binding?.metadata?.name === bindingName(policy)),
  };
}

function paramsProblem(bindings: any[]): string | null {
  const reading = bindings
    .filter(
      binding =>
        (binding?.spec?.validationActions ?? []).includes('Deny') &&
        (binding.spec.paramRef?.name === paramsName || binding.spec.paramRef?.selector)
    )
    .map(binding => binding.metadata?.name);
  if (!reading.length) return null;
  return (
    `${plural(reading.length, 'The binding', 'The bindings')} ${reading.join(', ')} ` +
    `${plural(reading.length, 'rejects', 'reject')} requests and may read the parameters ` +
    `${paramsName}, so creating them here could change what ` +
    `${plural(reading.length, 'it enforces', 'they enforce')}. Create them with kubectl when ` +
    'that is intended.'
  );
}

/**
 * Why creating the missing parameters could reject requests, or null. The parameters are shared
 * with the policies of the Kubescape library, so a binding that denies and reads them, by their
 * name or by a selector, would start to enforce its policy with them.
 */
export async function paramsCreationProblem(
  policy: PolicyObject,
  cluster?: string
): Promise<string | null> {
  return paramsProblem(await listBindings(policy, cluster));
}

/** Part of the policy was installed: what was written only warns or audits, or checks nothing. */
export class PartlyInstalledError extends Error {}

/**
 * Installs the policy (installedPolicy), its warn or audit binding and, when given, the
 * parameters it reads. Objects that exist are replaced. Nothing is written when installProblem,
 * or for the parameters paramsCreationProblem, finds a problem, which is checked again here, as
 * the bindings may have changed since the dialog opened, nor when the policy or the binding
 * cannot be read to tell whether they exist, nor when the API server refuses the policy, which
 * it is asked with a dry run.
 */
export async function installPolicy(
  policy: PolicyObject,
  binding: ReturnType<typeof bindingFor>,
  params: any | null,
  cluster?: string
) {
  const bindings = await listBindings(policy, cluster);
  const problem = policyProblem(policy, bindings) ?? (params ? paramsProblem(bindings) : null);
  if (problem) throw new Error(problem);
  const policies = collectionOf(policy.apiVersion, 'validatingadmissionpolicies');
  const bindingCollection = collectionOf(policy.apiVersion, 'validatingadmissionpolicybindings');
  // read before anything is written, so that a policy or binding that cannot be read leaves
  // nothing behind
  const [policyVersion, bindingVersion] = await Promise.all([
    existing(`${policies}/${policy.metadata.name}`, cluster),
    existing(`${bindingCollection}/${binding.metadata.name}`, cluster),
  ]);
  // the binding is written at the version that was checked above for Deny
  const listed = bindings.find(other => other.metadata?.name === binding.metadata.name);
  const checkedVersion: string | null = listed?.metadata?.resourceVersion || null;
  if ((bindingVersion || null) !== checkedVersion) {
    throw new Error(
      `The binding ${binding.metadata.name} changed while installing; install again to check it`
    );
  }
  // the API server only says whether it accepts the policy when it gets it, such as whether its
  // expressions compile: asked as a dry run, a policy it refuses leaves nothing behind
  await createOrReplace(policies, installedPolicy(policy), policyVersion, cluster, true);
  const steps: Array<[string, () => Promise<unknown>]> = [
    [
      `binding ${binding.metadata.name}`,
      () => createOrReplace(bindingCollection, binding, checkedVersion, cluster),
    ],
    [
      `policy ${policy.metadata.name}`,
      () => createOrReplace(policies, installedPolicy(policy), policyVersion, cluster),
    ],
  ];
  // The binding comes first: a binding changed since the check, such as to Deny, then fails with
  // a conflict before the policy of the editor is written. Only a policy that exists without the
  // binding of the plugin, such as one of the Kubescape library with failurePolicy Fail, whose
  // configuration errors reject requests whatever the binding's validationActions, is first
  // replaced by the copy that ignores them, so that a new binding of the plugin never binds a
  // policy the plugin did not write. A binding of the plugin that exists binds the policy as it
  // is already.
  if (policyVersion !== null && checkedVersion === null) steps.reverse();
  const installed: string[] = [];
  const partly = (what: string, error: unknown) =>
    new PartlyInstalledError(
      `Installed the ${installed.join(' and the ')}, but not ${what}: ${errorMessage(error)}`
    );
  for (const [what, write] of steps) {
    try {
      await write();
    } catch (error) {
      if (installed.length === 0) throw error;
      throw partly(`the ${what}`, error);
    }
    installed.push(what);
  }
  // the parameters last, so that a policy the API server refuses leaves no shared parameters
  // behind; until they exist the binding lets the policy check nothing (parameterNotFoundAction)
  if (params) {
    try {
      await post(
        paramsCollection,
        { ...params, metadata: { ...params.metadata, name: paramsName } },
        true,
        cluster ? { cluster } : undefined
      );
    } catch (error) {
      throw partly(`its parameters ${paramsName}, so it checks nothing yet`, error);
    }
  }
}
