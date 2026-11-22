import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import * as yaml from 'js-yaml';
import { vi } from 'vitest';
import { InstallPolicyButton } from './InstallPolicyButton';

const mocks = vi.hoisted(() => ({ request: vi.fn(), post: vi.fn(), put: vi.fn() }));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({
  request: mocks.request,
  post: mocks.post,
  put: mocks.put,
}));
// permission answers are kept per cluster, so each test asks about its own cluster
const cluster = vi.hoisted(() => ({ name: 'cluster-a' }));
vi.mock('@kinvolk/headlamp-plugin/lib/Utils', () => ({ getCluster: () => cluster.name }));

const notFound = Object.assign(new Error('not found'), { status: 404 });

const policies = '/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies';
const bindings = '/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings';
const paramsCollection = '/apis/kubescape.io/v1/controlconfigurations';

// the objects that were created, in order, without the permission checks and the dry run of
// the policy, which creates nothing
const dryRun = '?dryRun=All';
const created = () =>
  mocks.post.mock.calls
    .map(([url]) => url as string)
    .filter(url => !url.includes('selfsubjectaccessreviews') && !url.endsWith(dryRun));

const policyYaml = yaml.dump({
  apiVersion: 'admissionregistration.k8s.io/v1',
  kind: 'ValidatingAdmissionPolicy',
  metadata: { name: 'kubescape-c-0016' },
  spec: { paramKind: { apiVersion: 'kubescape.io/v1', kind: 'ControlConfiguration' } },
});
const paramsYaml = yaml.dump({
  apiVersion: 'kubescape.io/v1',
  kind: 'ControlConfiguration',
  metadata: { name: 'basic-control-configuration' },
  settings: {},
});

let allowed = true;
let servesParams = true;

beforeEach(() => {
  allowed = true;
  servesParams = true;
  mocks.request.mockReset().mockImplementation(async (url: string) => {
    if (url === '/apis/kubescape.io/v1') {
      return { resources: servesParams ? [{ name: 'controlconfigurations' }] : [] };
    }
    throw notFound;
  });
  mocks.post
    .mockReset()
    .mockImplementation(async (url: string) =>
      url.includes('selfsubjectaccessreviews') ? { status: { allowed } } : {}
    );
  mocks.put.mockReset().mockResolvedValue({});
});
afterEach(cleanup);

function renderButton() {
  render(
    <InstallPolicyButton
      disabled={false}
      getPolicyYaml={() => policyYaml}
      getParamsYaml={() => paramsYaml}
    />
  );
}

// opens the dialog and installs once it checked the cluster
async function openAndInstall() {
  renderButton();
  fireEvent.click(screen.getByRole('button', { name: 'Install in cluster' }));
  const button = screen.getByRole('button', { name: 'Install' });
  await waitFor(() => expect(button).toHaveProperty('disabled', false));
  fireEvent.click(button);
}

// makes creating objects in the collection fail
function failCreating(collection: string, error: Error) {
  mocks.post.mockImplementation(async (url: string) => {
    if (url.includes('selfsubjectaccessreviews')) return { status: { allowed } };
    if (url === collection) throw error;
    return {};
  });
}

it('installs the policy in warn mode, with its parameters', async () => {
  renderButton();
  fireEvent.click(screen.getByRole('button', { name: 'Install in cluster' }));
  fireEvent.click(screen.getByRole('checkbox', { name: 'Audit' }));
  const createParams = await screen.findByRole('checkbox', {
    name: /Create the ControlConfiguration basic-control-configuration/,
  });
  expect(createParams).toHaveProperty('checked', true);

  fireEvent.click(screen.getByRole('button', { name: 'Install' }));

  expect(
    await screen.findByText(
      'Installed kubescape-c-0016 with binding kubescape-c-0016-binding (Warn). Requests that violate it are allowed and get a warning.'
    )
  ).toBeTruthy();
  // the policy as a dry run, then the binding first and the shared parameters last
  const objects = mocks.post.mock.calls
    .filter(([url]) => !url.includes('selfsubjectaccessreviews'))
    .map(([url, object]) => [url, object.spec?.validationActions]);
  expect(objects).toEqual([
    [`${policies}${dryRun}`, undefined],
    [bindings, ['Warn']],
    [policies, undefined],
    [paramsCollection, undefined],
  ]);
});

it('installs nothing when the API server refuses the policy, and says why', async () => {
  failCreating(
    `${policies}${dryRun}`,
    new Error('Unprocessable Entity - spec.validations[0].expression: compilation failed')
  );
  await openAndInstall();

  expect(
    await screen.findByText(
      'Unable to install the policy: Unprocessable Entity - spec.validations[0].expression: compilation failed'
    )
  ).toBeTruthy();
  expect(created()).toEqual([]);
  expect(mocks.put).not.toHaveBeenCalled();
  expect(screen.getByRole('button', { name: 'Cancel' })).toBeTruthy();
});

it('explains that a policy with parameters needs the ControlConfiguration CRD', async () => {
  servesParams = false;
  renderButton();
  fireEvent.click(screen.getByRole('button', { name: 'Install in cluster' }));

  expect(await screen.findByText(/which this cluster does not serve/)).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Install' })).toHaveProperty('disabled', true);
});

it('says that nothing was installed when the binding fails', async () => {
  failCreating(bindings, new Error('admission webhook denied the request'));
  await openAndInstall();

  expect(
    await screen.findByText('Unable to install the policy: admission webhook denied the request')
  ).toBeTruthy();
  expect(created()).toEqual([bindings]);
  expect(screen.getByRole('button', { name: 'Cancel' })).toBeTruthy();
});

it('says that the binding was installed when the policy fails', async () => {
  failCreating(policies, new Error('admission webhook denied the request'));
  await openAndInstall();

  expect(
    await screen.findByText(
      'Installed the binding kubescape-c-0016-binding, but not the policy kubescape-c-0016: admission webhook denied the request. Close this dialog and install again to add the rest.'
    )
  ).toBeTruthy();
  expect(screen.queryByText(/Unable to install/)).toBeNull();
  expect(screen.getByRole('button', { name: 'Close' })).toBeTruthy();
  // no shared parameters for a policy that is not installed
  expect(created()).toEqual([bindings, policies]);
});

it('says that the parameters are missing when they fail', async () => {
  failCreating(paramsCollection, new Error('controlconfigurations is forbidden'));
  await openAndInstall();

  expect(
    await screen.findByText(
      'Installed the binding kubescape-c-0016-binding and the policy kubescape-c-0016, but not its parameters basic-control-configuration, so it checks nothing yet: controlconfigurations is forbidden. Close this dialog and install again to add the rest.'
    )
  ).toBeTruthy();
  expect(screen.queryByText(/Unable to install/)).toBeNull();
  expect(created()).toEqual([bindings, policies, paramsCollection]);
});

it('installs nothing when the binding changed after it was checked', async () => {
  const discovery = mocks.request.getMockImplementation()!;
  const binding = {
    metadata: {
      name: 'kubescape-c-0016-binding',
      labels: { 'app.kubernetes.io/managed-by': 'headlamp-kubescape-plugin' },
      resourceVersion: '5',
    },
    spec: { policyName: 'kubescape-c-0016', validationActions: ['Warn'] },
  };
  // listed as it was checked, read after it was switched to Deny
  mocks.request.mockImplementation(async (url: string, options: any) => {
    if (url === bindings) return { items: [binding] };
    if (url === `${bindings}/kubescape-c-0016-binding`) {
      return {
        metadata: { ...binding.metadata, resourceVersion: '6' },
        spec: { ...binding.spec, validationActions: ['Deny'] },
      };
    }
    return discovery(url, options);
  });
  await openAndInstall();

  expect(
    await screen.findByText(
      'Unable to install the policy: The binding kubescape-c-0016-binding changed while installing; install again to check it'
    )
  ).toBeTruthy();
  expect(created()).toEqual([]);
  expect(mocks.put).not.toHaveBeenCalled();
});

it('does not install a policy that a binding in the cluster denies with', async () => {
  const discovery = mocks.request.getMockImplementation()!;
  mocks.request.mockImplementation(async (url: string, options: any) =>
    url === '/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings'
      ? {
          items: [
            {
              metadata: { name: 'enforce-c-0016' },
              spec: { policyName: 'kubescape-c-0016', validationActions: ['Deny'] },
            },
          ],
        }
      : discovery(url, options)
  );
  renderButton();
  fireEvent.click(screen.getByRole('button', { name: 'Install in cluster' }));

  expect(
    await screen.findByText(/^The binding enforce-c-0016 rejects requests that violate/)
  ).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Install' })).toHaveProperty('disabled', true);
});

it('does not create parameters that a binding in the cluster denies with', async () => {
  const discovery = mocks.request.getMockImplementation()!;
  mocks.request.mockImplementation(async (url: string, options: any) =>
    url === '/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings'
      ? {
          items: [
            {
              metadata: { name: 'kubescape-library-deny' },
              spec: {
                policyName: 'kubescape-c-0017',
                validationActions: ['Deny'],
                paramRef: { name: 'basic-control-configuration', parameterNotFoundAction: 'Allow' },
              },
            },
          ],
        }
      : discovery(url, options)
  );
  renderButton();
  fireEvent.click(screen.getByRole('button', { name: 'Install in cluster' }));

  expect(
    await screen.findByText(/^The binding kubescape-library-deny rejects requests and may read/)
  ).toBeTruthy();
  const createParams = screen.getByRole('checkbox', {
    name: /Create the ControlConfiguration basic-control-configuration/,
  });
  expect(createParams).toHaveProperty('checked', false);
  expect(createParams).toHaveProperty('disabled', true);

  // the policy is installed without them
  const install = screen.getByRole('button', { name: 'Install' });
  await waitFor(() => expect(install).toHaveProperty('disabled', false));
  fireEvent.click(install);
  expect(await screen.findByText(/^Installed kubescape-c-0016 with binding/)).toBeTruthy();
  expect(created()).toEqual([bindings, policies]);
});

it('is not offered without permission to list the bindings it checks', async () => {
  cluster.name = 'cluster-without-list';
  mocks.post.mockImplementation(async (url: string, review: any) =>
    url.includes('selfsubjectaccessreviews')
      ? { status: { allowed: review.spec.resourceAttributes.verb !== 'list' } }
      : {}
  );
  renderButton();
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Install in cluster' })).toHaveProperty(
      'disabled',
      true
    )
  );
  expect(
    screen.getByLabelText('You are not allowed to list validatingadmissionpolicybindings.')
  ).toBeTruthy();
});

it('is not offered without permission to create policies', async () => {
  cluster.name = 'cluster-without-permission';
  allowed = false;
  renderButton();
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Install in cluster' })).toHaveProperty(
      'disabled',
      true
    )
  );
});

it('says that the policy is installed with failurePolicy Ignore and what the namespace limits', async () => {
  renderButton();
  fireEvent.click(screen.getByRole('button', { name: 'Install in cluster' }));

  expect(screen.getByText(/but with failurePolicy Ignore/)).toBeTruthy();
  expect(screen.getByText(/so the policy rejects no request/)).toBeTruthy();
  expect(
    screen.getByText(/cluster-scoped objects, such as ClusterRoles, and the Namespace itself/)
  ).toBeTruthy();
  expect(
    await screen.findByRole('checkbox', {
      name: /without it the policy checks no request until the parameters exist/,
    })
  ).toBeTruthy();
  // the policy has no audit annotations to convert
  expect(screen.queryByText(/converted with string\(\)/)).toBeNull();
});

it('creates the binding of an installed policy when the binding is missing', async () => {
  cluster.name = 'cluster-without-binding';
  const reviews: any[] = [];
  mocks.post.mockImplementation(async (url: string, review: any) => {
    if (!url.includes('selfsubjectaccessreviews')) return {};
    reviews.push(review.spec.resourceAttributes);
    return { status: { allowed: true } };
  });
  const discovery = mocks.request.getMockImplementation()!;
  mocks.request.mockImplementation(async (url: string, options: any) => {
    if (
      url === '/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/kubescape-c-0016'
    ) {
      return { metadata: { name: 'kubescape-c-0016', resourceVersion: '3' } };
    }
    return discovery(url, options);
  });
  renderButton();
  fireEvent.click(screen.getByRole('button', { name: 'Install in cluster' }));
  const install = screen.getByRole('button', { name: 'Install' });
  await waitFor(() => expect(install).toHaveProperty('disabled', false));

  const checked = reviews.map(({ verb, resource, name }) => [verb, resource, name]);
  expect(checked).toEqual(
    expect.arrayContaining([
      ['get', 'validatingadmissionpolicies', 'kubescape-c-0016'],
      ['get', 'validatingadmissionpolicybindings', 'kubescape-c-0016-binding'],
      ['update', 'validatingadmissionpolicies', 'kubescape-c-0016'],
      ['create', 'validatingadmissionpolicybindings', undefined],
    ])
  );
  expect(checked).not.toContainEqual([
    'update',
    'validatingadmissionpolicybindings',
    'kubescape-c-0016-binding',
  ]);

  fireEvent.click(install);
  expect(await screen.findByText(/^Installed kubescape-c-0016 with binding/)).toBeTruthy();
  expect(mocks.put.mock.calls.map(([url]) => url)).toEqual([
    `${policies}/kubescape-c-0016${dryRun}`,
    `${policies}/kubescape-c-0016`,
  ]);
  expect(created()).toEqual([bindings, paramsCollection]);
  // the installed policy is replaced before the binding of the plugin binds it, and the
  // parameters come last
  const createdAt = (collection: string) =>
    mocks.post.mock.invocationCallOrder[
      mocks.post.mock.calls.findIndex(([url]) => url === collection)
    ];
  const replacedAt = mocks.put.mock.invocationCallOrder[1];
  expect(replacedAt).toBeLessThan(createdAt(bindings));
  expect(createdAt(bindings)).toBeLessThan(createdAt(paramsCollection));
});

it('is not installed without permission to read the policy', async () => {
  cluster.name = 'cluster-without-get';
  mocks.post.mockImplementation(async (url: string, review: any) =>
    url.includes('selfsubjectaccessreviews')
      ? { status: { allowed: review.spec.resourceAttributes.verb !== 'get' } }
      : {}
  );
  renderButton();
  fireEvent.click(screen.getByRole('button', { name: 'Install in cluster' }));

  expect(
    await screen.findByLabelText(
      'You are not allowed to get validatingadmissionpolicies kubescape-c-0016.'
    )
  ).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Install' })).toHaveProperty('disabled', true);
});

it('says that audit annotations are installed converted to strings', async () => {
  cluster.name = 'cluster-with-audit-annotations';
  const withAnnotations = yaml.dump({
    ...(yaml.load(policyYaml) as object),
    spec: { auditAnnotations: [{ key: 'replicas', valueExpression: 'object.spec.replicas' }] },
  });
  render(
    <InstallPolicyButton
      disabled={false}
      getPolicyYaml={() => withAnnotations}
      getParamsYaml={() => ''}
    />
  );
  fireEvent.click(screen.getByRole('button', { name: 'Install in cluster' }));

  expect(screen.getByText(/converted with string\(\)/)).toBeTruthy();
  // they do not keep the policy from being installed, once the dialog checked the cluster
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Install' })).toHaveProperty('disabled', false)
  );
});

it('explains why the editor does not hold a policy it can install', async () => {
  render(
    <InstallPolicyButton
      disabled={false}
      getPolicyYaml={() => 'kind: Deployment'}
      getParamsYaml={() => ''}
    />
  );
  // the button asks whether the user may install policies
  await act(async () => {});
  fireEvent.click(screen.getByRole('button', { name: 'Install in cluster' }));

  expect(
    screen.getByText('The policy editor does not hold a ValidatingAdmissionPolicy.')
  ).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Install' })).toBeNull();
});

it('says that the policy editor is empty or does not hold YAML', async () => {
  for (const [text, problem] of [
    [undefined, 'The policy editor is empty.'],
    [' \n', 'The policy editor is empty.'],
    ['spec: [unclosed', /^The policy editor does not hold valid YAML: /],
  ] as const) {
    render(
      <InstallPolicyButton disabled={false} getPolicyYaml={() => text} getParamsYaml={() => ''} />
    );
    await act(async () => {});
    fireEvent.click(screen.getByRole('button', { name: 'Install in cluster' }));

    expect(screen.getByText(problem)).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Install' })).toBeNull();
    // nothing of the cluster is read for it
    expect(mocks.request).not.toHaveBeenCalled();
    cleanup();
  }
});
