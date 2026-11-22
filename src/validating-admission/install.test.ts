import { vi } from 'vitest';
import { fetchResource, listResources } from './clusterResources';
import {
  bindingFor,
  checkInstall,
  checkPolicy,
  installedPolicy,
  installPolicy,
  installProblem,
  paramsCreationProblem,
  paramsState,
  PartlyInstalledError,
  PolicyObject,
} from './install';

const mocks = vi.hoisted(() => ({ request: vi.fn(), post: vi.fn(), put: vi.fn() }));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({
  request: mocks.request,
  post: mocks.post,
  put: mocks.put,
}));

const notFound = Object.assign(new Error('not found'), { status: 404 });

const policies = '/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies';
const bindings = '/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings';
const paramsCollection = '/apis/kubescape.io/v1/controlconfigurations';
const policyName = 'kubescape-c-0016-allow-privilege-escalation';
const ownBindingName = `${policyName}-binding`;
const managed = { 'app.kubernetes.io/managed-by': 'headlamp-kubescape-plugin' };
const params = { apiVersion: 'kubescape.io/v1', kind: 'ControlConfiguration', metadata: {} };

// the requests that write in the order they were made, posts and puts together
function requests(): { method: 'post' | 'put'; url: string; object: any; order: number }[] {
  const of = (method: 'post' | 'put', mock: typeof mocks.post) =>
    mock.mock.calls.map(([url, object], index) => ({
      method,
      url,
      object,
      order: mock.mock.invocationCallOrder[index],
    }));
  return [...of('post', mocks.post), ...of('put', mocks.put)].sort((a, b) => a.order - b.order);
}

// the dry run of the policy, which writes nothing, and the writes after it
const dryRun = '?dryRun=All';
const writes = () => requests().filter(({ url }) => !url.endsWith(dryRun));

const policy: PolicyObject = {
  apiVersion: 'admissionregistration.k8s.io/v1',
  kind: 'ValidatingAdmissionPolicy',
  metadata: { name: 'kubescape-c-0016-allow-privilege-escalation' },
  spec: { paramKind: { apiVersion: 'kubescape.io/v1', kind: 'ControlConfiguration' } },
};

beforeEach(() => {
  mocks.request.mockReset();
  mocks.post.mockReset().mockResolvedValue({});
  mocks.put.mockReset().mockResolvedValue({});
});

it('binds a policy only to warn or audit', () => {
  const binding = bindingFor(policy, ['Warn', 'Deny' as any, 'Audit'], 'shop');
  expect(binding).toEqual({
    apiVersion: 'admissionregistration.k8s.io/v1',
    kind: 'ValidatingAdmissionPolicyBinding',
    metadata: {
      name: 'kubescape-c-0016-allow-privilege-escalation-binding',
      labels: { 'app.kubernetes.io/managed-by': 'headlamp-kubescape-plugin' },
    },
    spec: {
      policyName: 'kubescape-c-0016-allow-privilege-escalation',
      validationActions: ['Warn', 'Audit'],
      // with Deny, the API server would reject every request while the parameters are missing,
      // whatever the validationActions
      paramRef: { name: 'basic-control-configuration', parameterNotFoundAction: 'Allow' },
      // a namespaceSelector does not leave out cluster-scoped objects, the rule does
      matchResources: {
        namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'shop' } },
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
    },
  });
  const withoutParams = bindingFor({ ...policy, spec: {} }, ['Warn']);
  expect(withoutParams.spec).toEqual({
    policyName: 'kubescape-c-0016-allow-privilege-escalation',
    validationActions: ['Warn'],
  });
});

it('installs the policy with failurePolicy Ignore and audit annotations that give strings', () => {
  const withAnnotations: PolicyObject = {
    ...policy,
    metadata: { ...policy.metadata, uid: 'x', labels: { team: 'a' } },
    spec: {
      ...policy.spec,
      failurePolicy: 'Fail',
      validations: [{ expression: 'true' }],
      auditAnnotations: [{ key: 'replicas', valueExpression: 'object.spec.replicas // the count' }],
    },
  };

  expect(installedPolicy(withAnnotations)).toEqual({
    apiVersion: 'admissionregistration.k8s.io/v1',
    kind: 'ValidatingAdmissionPolicy',
    metadata: {
      name: 'kubescape-c-0016-allow-privilege-escalation',
      labels: { team: 'a', 'app.kubernetes.io/managed-by': 'headlamp-kubescape-plugin' },
    },
    spec: {
      paramKind: { apiVersion: 'kubescape.io/v1', kind: 'ControlConfiguration' },
      failurePolicy: 'Ignore',
      validations: [{ expression: 'true' }],
      auditAnnotations: [
        { key: 'replicas', valueExpression: 'string(\nobject.spec.replicas // the count\n)' },
      ],
    },
  });
  expect(installedPolicy({ ...policy, spec: undefined }).spec).toEqual({
    failurePolicy: 'Ignore',
  });
});

it('only installs ValidatingAdmissionPolicies', () => {
  expect(checkPolicy(policy)).toBeNull();
  expect(checkPolicy({ ...policy, kind: 'Deployment' })).toMatch(/does not hold/);
  expect(checkPolicy({ ...policy, apiVersion: 'v1' })).toMatch(/cannot be installed/);
  expect(checkPolicy(null)).toMatch(/does not hold/);
});

it('tells whether the cluster has the parameters of a policy', async () => {
  mocks.request.mockImplementation(async (url: string) => {
    if (url === '/apis/kubescape.io/v1') {
      return { resources: [{ name: 'controlconfigurations', namespaced: false }] };
    }
    throw notFound;
  });
  expect(await paramsState(policy)).toBe('missing');
  expect(await paramsState({ ...policy, spec: {} })).toBe('unneeded');

  mocks.request.mockResolvedValue({ resources: [{ name: 'controlconfigurations' }] });
  expect(await paramsState(policy)).toBe('present');

  mocks.request.mockResolvedValue({ resources: [{ name: 'runtimerules' }] });
  expect(await paramsState(policy)).toBe('not-served');

  mocks.request.mockResolvedValue({
    resources: [{ name: 'controlconfigurations', namespaced: true }],
  });
  expect(await paramsState(policy)).toBe('namespaced');
});

it('creates the binding of a new policy, then the policy, then its parameters', async () => {
  mocks.request.mockRejectedValue(notFound);
  const binding = bindingFor(policy, ['Warn']);

  await installPolicy(
    { ...policy, metadata: { ...policy.metadata, uid: 'x', resourceVersion: '1' } },
    binding,
    { apiVersion: 'kubescape.io/v1', kind: 'ControlConfiguration', metadata: { name: 'other' } }
  );

  // the binding first, as checked for Deny, while it binds no policy; the shared parameters last,
  // so that a policy the API server refuses leaves none behind
  const written = writes();
  expect(written.map(({ method, url, object }) => [method, url, object.metadata])).toEqual([
    ['post', bindings, binding.metadata],
    ['post', policies, { name: policyName, labels: managed }],
    ['post', paramsCollection, { name: 'basic-control-configuration' }],
  ]);
  expect(written[0].object.spec).toEqual({
    policyName,
    validationActions: ['Warn'],
    paramRef: { name: 'basic-control-configuration', parameterNotFoundAction: 'Allow' },
  });
  expect(written[1].object.spec.failurePolicy).toBe('Ignore');
  // before them, the API server was asked whether it accepts the policy
  expect(requests()[0]).toMatchObject({ method: 'post', url: `${policies}${dryRun}` });
  expect(requests()[0].object).toEqual(written[1].object);
});

it('writes nothing when it cannot read the policy or its binding', async () => {
  // both are read before anything is written
  const forbidden = Object.assign(new Error('forbidden'), { status: 403 });
  for (const unreadable of ['validatingadmissionpolicies/', 'validatingadmissionpolicybindings/']) {
    mocks.request.mockImplementation(async (url: string) => {
      if (url.includes(unreadable)) throw forbidden;
      throw notFound;
    });

    await expect(installPolicy(policy, bindingFor(policy, ['Warn']), params)).rejects.toThrow(
      'forbidden'
    );
    expect(mocks.post).not.toHaveBeenCalled();
    expect(mocks.put).not.toHaveBeenCalled();
  }
});

// the binding of the plugin, which the cluster lists and returns at resource version 5
const ownBinding = (validationActions: string[]) => ({
  metadata: { name: ownBindingName, labels: managed, resourceVersion: '5' },
  spec: { policyName, validationActions },
});

// The bindings in the cluster, each read as it is listed; the policy is installed with resource
// version 7, or not at all with null
function serveBindings(items: any[], policyVersion: string | null = '7') {
  mocks.request.mockImplementation(async (url: string) => {
    if (url === bindings) return { items };
    if (url.startsWith(`${bindings}/`)) {
      const binding = items.find(item => url === `${bindings}/${item.metadata.name}`);
      if (!binding) throw notFound;
      return binding;
    }
    if (policyVersion === null) throw notFound;
    return { metadata: { resourceVersion: policyVersion } };
  });
}

it('replaces the binding of an installed policy at the version it checked, then the policy, then the parameters', async () => {
  // the binding of the plugin binds the policy already: written first, a binding that changed
  // since it was checked, such as to Deny, fails before the policy of the editor is written
  serveBindings([ownBinding(['Warn'])]);

  await installPolicy(policy, bindingFor(policy, ['Audit']), params);

  const written = writes();
  expect(
    written.map(({ method, url, object }) => [method, url, object.metadata.resourceVersion])
  ).toEqual([
    ['put', `${bindings}/${ownBindingName}`, '5'],
    ['put', `${policies}/${policyName}`, '7'],
    ['post', paramsCollection, undefined],
  ]);
  expect(written[0].object.spec.validationActions).toEqual(['Audit']);
  expect(written[0].object.spec.paramRef.parameterNotFoundAction).toBe('Allow');
  expect(written[1].object.spec.failurePolicy).toBe('Ignore');
});

it('replaces an installed policy without the binding of the plugin before it creates the binding', async () => {
  // the policy in the cluster, such as one of the Kubescape library with failurePolicy Fail, is
  // replaced by the copy that ignores errors before the binding of the plugin binds it
  serveBindings([]);

  await installPolicy(policy, bindingFor(policy, ['Warn']), params);

  const written = writes();
  expect(
    written.map(({ method, url, object }) => [method, url, object.metadata.resourceVersion])
  ).toEqual([
    ['put', `${policies}/${policyName}`, '7'],
    ['post', bindings, undefined],
    ['post', paramsCollection, undefined],
  ]);
  expect(written[0].object.spec.failurePolicy).toBe('Ignore');
});

it('writes nothing when the API server refuses the policy', async () => {
  // such as for an expression that does not compile, which the playground does not check
  const refused = Object.assign(
    new Error('Unprocessable Entity - spec.validations[0].expression: Invalid value'),
    { status: 422 }
  );
  mocks.request.mockRejectedValue(notFound);
  mocks.post.mockImplementation(async (url: string) => {
    if (url === `${policies}${dryRun}`) throw refused;
    return {};
  });

  const installing = installPolicy(policy, bindingFor(policy, ['Warn']), params);
  await expect(installing).rejects.toBe(refused);
  await expect(installing).rejects.not.toBeInstanceOf(PartlyInstalledError);
  expect(requests().map(({ url }) => url)).toEqual([`${policies}${dryRun}`]);

  // nor when it refuses the copy that would replace an installed policy
  mocks.post.mockClear();
  serveBindings([ownBinding(['Warn'])]);
  mocks.put.mockImplementation(async (url: string) => {
    if (url.endsWith(dryRun)) throw refused;
    return {};
  });

  await expect(installPolicy(policy, bindingFor(policy, ['Warn']), params)).rejects.toBe(refused);
  const asked = requests();
  expect(asked.map(({ method, url }) => [method, url])).toEqual([
    ['put', `${policies}/${policyName}${dryRun}`],
  ]);
  expect(asked[0].object.metadata.resourceVersion).toBe('7');
  expect(asked[0].object.spec.failurePolicy).toBe('Ignore');
});

it('installs nothing when the binding changed after it was checked', async () => {
  const checked = ownBinding(['Warn']);
  // such as switched to Deny with kubectl
  const changed = {
    metadata: { ...checked.metadata, resourceVersion: '6' },
    spec: { ...checked.spec, validationActions: ['Deny'] },
  };
  // changed between the list and the read, created after the list, or deleted after it
  const cases: [any, any][] = [
    [checked, changed],
    [null, changed],
    [checked, null],
  ];
  for (const [listed, read] of cases) {
    mocks.request.mockImplementation(async (url: string) => {
      if (url === bindings) return { items: listed ? [listed] : [] };
      if (url === `${bindings}/${ownBindingName}`) {
        if (!read) throw notFound;
        return read;
      }
      return { metadata: { resourceVersion: '7' } };
    });

    const installing = installPolicy(policy, bindingFor(policy, ['Warn']), params);
    await expect(installing).rejects.not.toBeInstanceOf(PartlyInstalledError);
    await expect(installing).rejects.toHaveProperty(
      'message',
      `The binding ${ownBindingName} changed while installing; install again to check it`
    );
    expect(mocks.post).not.toHaveBeenCalled();
    expect(mocks.put).not.toHaveBeenCalled();
  }
});

it('does not install a policy that a binding denies with', async () => {
  // also when the policy is not installed: the binding would enforce it once it is
  mocks.request.mockImplementation(async (url: string) => {
    if (url !== bindings) throw notFound;
    return {
      items: [
        {
          metadata: { name: 'enforce-c-0016' },
          spec: {
            policyName: 'kubescape-c-0016-allow-privilege-escalation',
            validationActions: ['Deny', 'Audit'],
          },
        },
        {
          metadata: { name: 'enforce-other' },
          spec: { policyName: 'other', validationActions: ['Deny'] },
        },
      ],
    };
  });

  await expect(installPolicy(policy, bindingFor(policy, ['Warn']), params)).rejects.toThrow(
    'The binding enforce-c-0016 rejects requests that violate kubescape-c-0016-allow-privilege-escalation'
  );
  expect(mocks.post).not.toHaveBeenCalled();
  expect(mocks.put).not.toHaveBeenCalled();

  // nor when its own binding was switched to Deny with kubectl
  serveBindings([ownBinding(['Deny'])]);
  expect(await installProblem(policy)).toMatch(
    /^The binding kubescape-c-0016-allow-privilege-escalation-binding rejects/
  );
  serveBindings([ownBinding(['Warn', 'Audit'])]);
  expect(await installProblem(policy)).toBeNull();
});

it('does not install a policy that a binding makes reject requests without its parameters', async () => {
  // the binding only warns, but the API server rejects every request it matches while the
  // parameters are missing when the failurePolicy is Fail
  const warnWithoutParams = {
    metadata: { name: 'warn-c-0016' },
    spec: {
      policyName: 'kubescape-c-0016-allow-privilege-escalation',
      validationActions: ['Warn'],
      paramRef: { name: 'basic-control-configuration', parameterNotFoundAction: 'Deny' },
    },
  };
  serveBindings([warnWithoutParams]);

  expect(await installProblem(policy)).toBe(
    'The binding warn-c-0016 of kubescape-c-0016-allow-privilege-escalation has ' +
      'parameterNotFoundAction Deny, which makes every request it matches an error of the ' +
      'policy while its parameters are missing; with failurePolicy Fail the API server rejects ' +
      'those requests. Give the policy another name in the editor to try it.'
  );
  await expect(installPolicy(policy, bindingFor(policy, ['Warn']), null)).rejects.toThrow(
    /^The binding warn-c-0016 of/
  );
  expect(mocks.post).not.toHaveBeenCalled();
  expect(mocks.put).not.toHaveBeenCalled();

  // the API server ignores the paramRef of a policy without paramKind
  expect(await installProblem({ ...policy, spec: {} })).toBeNull();

  // the plugin's own binding of an earlier release is replaced by one that allows
  const own = ownBinding(['Warn']);
  serveBindings([{ ...own, spec: { ...own.spec, paramRef: warnWithoutParams.spec.paramRef } }]);
  expect(await installProblem(policy)).toBeNull();
  await installPolicy(policy, bindingFor(policy, ['Warn']), null);
  const replaced = writes().find(({ url }) => url === `${bindings}/${ownBindingName}`);
  expect(replaced?.object.spec.paramRef.parameterNotFoundAction).toBe('Allow');
});

it('tells whether the binding of the plugin exists', async () => {
  serveBindings([ownBinding(['Warn'])]);
  expect(await checkInstall(policy)).toEqual({ problem: null, bindingInstalled: true });
  serveBindings([]);
  expect(await checkInstall(policy)).toEqual({ problem: null, bindingInstalled: false });
});

it('does not replace a binding with its name that the plugin did not install', async () => {
  serveBindings([{ ...ownBinding(['Warn']), metadata: { name: ownBinding([]).metadata.name } }]);
  await expect(installPolicy(policy, bindingFor(policy, ['Warn']), null)).rejects.toThrow(
    /was not installed for this policy by the plugin/
  );

  // or that binds another policy
  serveBindings([
    { ...ownBinding(['Warn']), spec: { policyName: 'other', validationActions: ['Warn'] } },
  ]);
  expect(await installProblem(policy)).toMatch(/was not installed for this policy/);
  expect(mocks.post).not.toHaveBeenCalled();
  expect(mocks.put).not.toHaveBeenCalled();
});

it('does not create parameters that a binding denies with', async () => {
  // the library policies share the parameters; this one allows everything while they are missing
  const libraryBinding = {
    metadata: { name: 'kubescape-library-deny' },
    spec: {
      policyName: 'kubescape-c-0017-immutable-container-filesystem',
      validationActions: ['Deny'],
      paramRef: { name: 'basic-control-configuration', parameterNotFoundAction: 'Allow' },
    },
  };
  serveBindings([libraryBinding]);

  expect(await paramsCreationProblem(policy)).toBe(
    'The binding kubescape-library-deny rejects requests and may read the parameters ' +
      'basic-control-configuration, so creating them here could change what it enforces. ' +
      'Create them with kubectl when that is intended.'
  );
  await expect(installPolicy(policy, bindingFor(policy, ['Warn']), params)).rejects.toThrow(
    /^The binding kubescape-library-deny rejects requests and may read the parameters/
  );
  expect(mocks.post).not.toHaveBeenCalled();
  expect(mocks.put).not.toHaveBeenCalled();

  // the policy can still be installed without them: its binding allows every request while they
  // are missing
  expect(await installProblem(policy)).toBeNull();
  await installPolicy(policy, bindingFor(policy, ['Warn']), null);
  const written = writes();
  expect(written.map(({ method, url }) => [method, url])).toEqual([
    ['put', `${policies}/${policyName}`],
    ['post', bindings],
  ]);
  expect(written[1].object.spec.paramRef).toEqual({
    name: 'basic-control-configuration',
    parameterNotFoundAction: 'Allow',
  });

  // a binding that selects its parameters may read them too, one that warns does not count
  serveBindings([
    {
      metadata: { name: 'select-params' },
      spec: { policyName: 'other', validationActions: ['Deny'], paramRef: { selector: {} } },
    },
    { ...libraryBinding, spec: { ...libraryBinding.spec, validationActions: ['Warn'] } },
  ]);
  expect(await paramsCreationProblem(policy)).toMatch(/^The binding select-params rejects/);
  serveBindings([ownBinding(['Warn'])]);
  expect(await paramsCreationProblem(policy)).toBeNull();
});

it('installs nothing when it cannot read the bindings', async () => {
  mocks.request.mockRejectedValue(Object.assign(new Error('forbidden'), { status: 403 }));
  await expect(installPolicy(policy, bindingFor(policy, ['Warn']), null)).rejects.toThrow(
    'forbidden'
  );
  expect(mocks.post).not.toHaveBeenCalled();
  expect(mocks.put).not.toHaveBeenCalled();
});

// makes the write to the url fail
function failWrite(method: 'post' | 'put', failing: string, error: Error) {
  mocks[method].mockImplementation(async (url: string) => {
    if (url === failing) throw error;
    return {};
  });
}

it('writes nothing else when the binding of a new policy fails', async () => {
  mocks.request.mockRejectedValue(notFound);
  failWrite('post', bindings, new Error('admission webhook denied the request'));

  const installing = installPolicy(policy, bindingFor(policy, ['Warn']), params);
  await expect(installing).rejects.not.toBeInstanceOf(PartlyInstalledError);
  await expect(installing).rejects.toHaveProperty(
    'message',
    'admission webhook denied the request'
  );
  expect(writes().map(({ url }) => url)).toEqual([bindings]);

  // a binding changed after it was read, such as to Deny, is not replaced, nor is the policy
  // written; here the binding was left when the policy was deleted
  mocks.post.mockClear();
  serveBindings([ownBinding(['Warn'])], null);
  const conflict = Object.assign(new Error('the object has been modified'), { status: 409 });
  failWrite('put', `${bindings}/${ownBindingName}`, conflict);

  await expect(installPolicy(policy, bindingFor(policy, ['Warn']), params)).rejects.toBe(conflict);
  expect(writes().map(({ url }) => url)).toEqual([`${bindings}/${ownBindingName}`]);
});

it('writes nothing else when an installed policy cannot be replaced', async () => {
  // such as one of the Kubescape library without a binding: the binding of the plugin would bind
  // it as it is, with failurePolicy Fail
  serveBindings([]);
  const refused = new Error('admission webhook denied the request');
  failWrite('put', `${policies}/${policyName}`, refused);

  const installing = installPolicy(policy, bindingFor(policy, ['Warn']), params);
  await expect(installing).rejects.toBe(refused);
  await expect(installing).rejects.not.toBeInstanceOf(PartlyInstalledError);
  expect(writes().map(({ url }) => url)).toEqual([`${policies}/${policyName}`]);
});

it('does not replace an installed policy when its binding changed after it was read', async () => {
  // such as to Deny: the binding is written first, so the policy of the editor is not written
  serveBindings([ownBinding(['Warn'])]);
  const conflict = Object.assign(new Error('the object has been modified'), { status: 409 });
  failWrite('put', `${bindings}/${ownBindingName}`, conflict);

  const installing = installPolicy(policy, bindingFor(policy, ['Warn']), params);
  await expect(installing).rejects.toBe(conflict);
  await expect(installing).rejects.not.toBeInstanceOf(PartlyInstalledError);
  expect(writes().map(({ url }) => url)).toEqual([`${bindings}/${ownBindingName}`]);
});

it('says that an installed policy was replaced when its binding fails after it', async () => {
  // the policy had no binding of the plugin, so it was replaced first
  serveBindings([]);
  failWrite('post', bindings, new Error('admission webhook denied the request'));

  const installing = installPolicy(policy, bindingFor(policy, ['Warn']), params);
  await expect(installing).rejects.toBeInstanceOf(PartlyInstalledError);
  await expect(installing).rejects.toHaveProperty(
    'message',
    `Installed the policy ${policyName}, but not the binding ${ownBindingName}: ` +
      'admission webhook denied the request'
  );
  // no parameters for a policy without its binding
  expect(writes().map(({ url }) => url)).toEqual([`${policies}/${policyName}`, bindings]);
  expect(writes()[0].object.spec.failurePolicy).toBe('Ignore');
});

it('says that the binding of a new policy was installed when the policy fails, and creates no parameters', async () => {
  mocks.request.mockRejectedValue(notFound);
  failWrite('post', policies, new Error('admission webhook denied the request'));

  const installing = installPolicy(policy, bindingFor(policy, ['Warn']), params);
  await expect(installing).rejects.toBeInstanceOf(PartlyInstalledError);
  await expect(installing).rejects.toHaveProperty(
    'message',
    `Installed the binding ${ownBindingName}, but not the policy ${policyName}: ` +
      'admission webhook denied the request'
  );
  expect(writes().map(({ url }) => url)).toEqual([bindings, policies]);
});

it('says that the binding and the policy were installed when the parameters fail', async () => {
  mocks.request.mockRejectedValue(notFound);
  failWrite(
    'post',
    paramsCollection,
    Object.assign(new Error('controlconfigurations is forbidden'), { status: 403 })
  );

  const installing = installPolicy(policy, bindingFor(policy, ['Warn']), params);
  await expect(installing).rejects.toBeInstanceOf(PartlyInstalledError);
  await expect(installing).rejects.toHaveProperty(
    'message',
    `Installed the binding ${ownBindingName} and the policy ${policyName}, but not its ` +
      'parameters basic-control-configuration, so it checks nothing yet: ' +
      'controlconfigurations is forbidden'
  );
  expect(writes().map(({ url }) => url)).toEqual([bindings, policies, paramsCollection]);

  // in the order they were written, for a policy that was installed without the binding
  mocks.post.mockClear();
  serveBindings([]);
  await expect(installPolicy(policy, bindingFor(policy, ['Warn']), params)).rejects.toHaveProperty(
    'message',
    `Installed the policy ${policyName} and the binding ${ownBindingName}, but not its ` +
      'parameters basic-control-configuration, so it checks nothing yet: ' +
      'controlconfigurations is forbidden'
  );
});

it('lists cluster resources in the allowed namespaces', async () => {
  mocks.request.mockImplementation(async (url: string) => ({
    items: [{ metadata: { name: 'web', namespace: url.split('/')[5] } }],
  }));

  expect(await listResources('Deployment', ['shop', 'blog'])).toEqual([
    { namespace: 'blog', name: 'web' },
    { namespace: 'shop', name: 'web' },
  ]);
  expect(mocks.request.mock.calls.map(call => call[0])).toEqual([
    '/apis/apps/v1/namespaces/shop/deployments',
    '/apis/apps/v1/namespaces/blog/deployments',
  ]);

  mocks.request.mockClear();
  await listResources('ClusterRole', ['shop']);
  expect(mocks.request.mock.calls[0][0]).toBe('/apis/rbac.authorization.k8s.io/v1/clusterroles');
});

it('reads a resource with its kind, which lists leave out', async () => {
  mocks.request.mockResolvedValue({ metadata: { name: 'web', namespace: 'shop' } });

  expect(await fetchResource('Pod', { namespace: 'shop', name: 'web' })).toEqual({
    apiVersion: 'v1',
    kind: 'Pod',
    metadata: { name: 'web', namespace: 'shop' },
  });
  expect(mocks.request).toHaveBeenCalledWith('/api/v1/namespaces/shop/pods/web');
});
