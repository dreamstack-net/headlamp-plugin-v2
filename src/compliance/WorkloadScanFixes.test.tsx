import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { load } from 'js-yaml';
import type { ReactNode } from 'react';
import { vi } from 'vitest';
import KubescapeWorkloadConfigurationScanFixes, {
  applyFixPath,
  fixResource,
  isPlaceholder,
  lastChanged,
  objectPath,
  parseFixValue,
  resourceLocation,
  resourcePaths,
  scanTime,
} from './WorkloadScanFixes';

const mocks = vi.hoisted(() => ({
  request: vi.fn(),
  put: vi.fn(),
  post: vi.fn(),
  saveToFile: vi.fn(),
  controls: [] as object[],
}));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({
  request: mocks.request,
  put: mocks.put,
  post: mocks.post,
}));
vi.mock('@kinvolk/headlamp-plugin/lib', () => ({
  K8s: {
    ResourceClasses: {
      Deployment: {
        apiEndpoint: { apiInfo: [{ group: 'apps', version: 'v1' }] },
        pluralName: 'deployments',
      },
      Pod: { apiEndpoint: { apiInfo: [{ group: '', version: 'v1' }] }, pluralName: 'pods' },
      ServiceAccount: {
        apiEndpoint: { apiInfo: [{ group: '', version: 'v1' }] },
        pluralName: 'serviceaccounts',
      },
      // the Gateway API; Istio has a Gateway too
      Gateway: {
        apiEndpoint: {
          apiInfo: [
            { group: 'gateway.networking.k8s.io', version: 'v1' },
            { group: 'gateway.networking.k8s.io', version: 'v1beta1' },
          ],
        },
        pluralName: 'gateways',
      },
    },
  },
}));
vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', () => ({
  NameValueTable: () => null,
  SectionBox: ({ children }: { children: ReactNode }) => <section>{children}</section>,
}));
vi.mock('@monaco-editor/react', () => ({
  DiffEditor: ({ modified, options }: { modified: string; options?: { readOnly?: boolean } }) => (
    <pre data-testid="fixed" data-read-only={String(!!options?.readOnly)}>
      {modified}
    </pre>
  ),
}));
vi.mock('../common/url', () => ({
  // control, name, namespace, (unused), cluster
  getURLSegments: () => ['C-0016', 'deployment-web', 'shop', 'cluster-a'],
}));
vi.mock('../common/filedialog', () => ({ saveToFile: mocks.saveToFile }));
vi.mock('../common/clusterContext', () => ({ getAllowedNamespaces: () => [] }));
vi.mock('../common/ScanNowButton', () => ({ ScanNowButton: () => <button>Scan now</button> }));
vi.mock('../rego', () => ({ useRegoData: () => ({ controls: mocks.controls }) }));

let scanKind = 'Deployment';
const allowPrivilegeEscalation = [
  {
    fixPath: 'spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation',
    fixPathValue: 'false',
    failedPath: '',
  },
];
// the paths of the rule of the control
let scanPaths: object[] = allowPrivilegeEscalation;
let scanAnnotations: Record<string, string> | undefined;
let relatedObjects: object[] | undefined;
vi.mock('../model', () => ({
  workloadConfigurationScanClass: {},
  fetchObject: async () => ({
    metadata: {
      name: 'deployment-web',
      annotations: scanAnnotations,
      labels: {
        'kubescape.io/workload-kind': scanKind,
        'kubescape.io/workload-name': 'web',
        'kubescape.io/workload-namespace': 'shop',
      },
    },
    spec: {
      controls: {
        'C-0016': {
          controlID: 'C-0016',
          rules: [{ paths: scanPaths }],
        },
      },
      relatedObjects,
    },
  }),
}));

const deployment = {
  apiVersion: 'apps/v1',
  kind: 'Deployment',
  metadata: { name: 'web', namespace: 'shop', resourceVersion: '42', managedFields: [{}] },
  spec: { template: { spec: { containers: [{ name: 'web', image: 'nginx' }] } } },
  status: { replicas: 1 },
};

beforeEach(() => {
  scanKind = 'Deployment';
  scanPaths = allowPrivilegeEscalation;
  scanAnnotations = undefined;
  relatedObjects = undefined;
  mocks.controls = [];
  mocks.request.mockReset().mockResolvedValue(structuredClone(deployment));
  mocks.put.mockReset().mockResolvedValue({});
  // the permission check of Apply fix does not get an answer, so it stays enabled
  mocks.post.mockReset();
});
afterEach(cleanup);

it('applies the fixed resource with its resource version, after confirmation', async () => {
  render(<KubescapeWorkloadConfigurationScanFixes />);

  fireEvent.click(await screen.findByRole('button', { name: 'Apply fix' }));
  expect(screen.getByText(/rolls out the change/)).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Apply' }));

  await waitFor(() => expect(mocks.put).toHaveBeenCalledTimes(1));
  const [path, applied, , options] = mocks.put.mock.calls[0];
  expect(path).toBe('/apis/apps/v1/namespaces/shop/deployments/web');
  expect(options).toEqual({ cluster: 'cluster-a' });
  expect(applied.metadata.resourceVersion).toBe('42');
  expect(applied.metadata.managedFields).toBeUndefined();
  expect(applied.status).toBeUndefined();
  expect(applied.spec.template.spec.containers[0].securityContext).toEqual({
    allowPrivilegeEscalation: false,
  });
  expect(await screen.findByRole('button', { name: 'Fix applied' })).toHaveProperty(
    'disabled',
    true
  );
});

it('explains that the resource changed when the update conflicts', async () => {
  mocks.put.mockRejectedValue({ status: 409, message: 'conflict' });
  render(<KubescapeWorkloadConfigurationScanFixes />);

  fireEvent.click(await screen.findByRole('button', { name: 'Apply fix' }));
  fireEvent.click(screen.getByRole('button', { name: 'Apply' }));

  expect(await screen.findByText(/changed since this page was opened/)).toBeTruthy();
});

it('downloads the fixed YAML, and does not offer to apply without permission', async () => {
  mocks.post.mockResolvedValue({ status: { allowed: false } });
  render(<KubescapeWorkloadConfigurationScanFixes />);

  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Apply fix' })).toHaveProperty('disabled', true)
  );
  fireEvent.click(screen.getByRole('button', { name: 'Download fixed YAML' }));
  expect(mocks.saveToFile.mock.calls[0][1]).toBe('web-fixed.yaml');
  expect(mocks.saveToFile.mock.calls[0][0]).toContain('allowPrivilegeEscalation: false');
});

it('reads core resources from the core API path', async () => {
  scanKind = 'Pod';
  render(<KubescapeWorkloadConfigurationScanFixes />);
  await screen.findByRole('button', { name: 'Apply fix' });
  expect(mocks.request.mock.calls[0][0]).toBe('/api/v1/namespaces/shop/pods/web');
});

it('does not apply the fix to a resource that changed after the scan, and says so', async () => {
  // the containers may have been added, removed or reordered since: containers[0] of the scan
  // need not be containers[0] now
  scanAnnotations = { 'kubescape.io/report-created-at': '2026-11-22T01:12:30.357675365Z' };
  mocks.request.mockResolvedValue({
    ...structuredClone(deployment),
    metadata: {
      ...deployment.metadata,
      creationTimestamp: '2026-11-21T13:47:32Z',
      managedFields: [
        { manager: 'kubectl-client-side-apply', operation: 'Update', time: '2026-11-21T13:47:32Z' },
        { manager: 'kubectl-edit', operation: 'Update', time: '2026-11-22T09:30:00Z' },
      ],
    },
  });
  render(<KubescapeWorkloadConfigurationScanFixes />);

  expect(
    (await screen.findByText(/after Kubescape scanned it/)).textContent?.startsWith(
      'The Deployment shop/web changed at '
    )
  ).toBe(true);
  expect(screen.getByText(/so it cannot be applied from here/)).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Apply fix' })).toBeNull();
  expect(screen.getByRole('button', { name: 'Scan now' })).toBeTruthy();
  // the fix can still be looked at and downloaded
  expect(screen.getByTestId('fixed').textContent).toContain('allowPrivilegeEscalation: false');
  expect(screen.getByRole('button', { name: 'Download fixed YAML' })).toBeTruthy();
});

it('applies the fix to a resource whose status alone changed after the scan', async () => {
  scanAnnotations = { 'kubescape.io/report-created-at': '2026-11-22T01:12:30.357675365Z' };
  mocks.request.mockResolvedValue({
    ...structuredClone(deployment),
    metadata: {
      ...deployment.metadata,
      creationTimestamp: '2026-11-21T13:47:32Z',
      managedFields: [
        { manager: 'kubectl-client-side-apply', operation: 'Update', time: '2026-11-21T13:47:32Z' },
        {
          manager: 'kube-controller-manager',
          operation: 'Update',
          subresource: 'status',
          time: '2026-11-22T09:30:00Z',
        },
      ],
    },
  });
  render(<KubescapeWorkloadConfigurationScanFixes />);

  expect(await screen.findByRole('button', { name: 'Apply fix' })).toBeTruthy();
  expect(screen.queryByText(/after Kubescape scanned it/)).toBeNull();
});

it('reads and replaces a related object in its own API group, not that of its kind in Headlamp', async () => {
  // Headlamp's Gateway is the one of the Gateway API; this one is Istio's
  relatedObjects = [
    {
      apiGroup: 'networking.istio.io',
      apiVersion: 'v1',
      kind: 'Gateway',
      name: 'public',
      namespace: 'shop',
    },
  ];
  scanPaths = [{ fixPath: 'relatedObjects[0].spec.selector.istio', fixPathValue: 'ingress' }];
  const gateway = {
    apiVersion: 'networking.istio.io/v1',
    kind: 'Gateway',
    metadata: { name: 'public', namespace: 'shop', resourceVersion: '7' },
    spec: { selector: { istio: 'egress' } },
  };
  mocks.request.mockImplementation(async (path: string) => {
    if (path === '/apis/networking.istio.io/v1') {
      return {
        resources: [
          { name: 'gateways/status', kind: 'Gateway' },
          { name: 'gateways', kind: 'Gateway' },
          { name: 'virtualservices', kind: 'VirtualService' },
        ],
      };
    }
    if (path === '/apis/networking.istio.io/v1/namespaces/shop/gateways/public') {
      return structuredClone(gateway);
    }
    return structuredClone(deployment);
  });
  render(<KubescapeWorkloadConfigurationScanFixes />);

  fireEvent.click(await screen.findByRole('button', { name: 'Apply fix' }));
  fireEvent.click(screen.getByRole('button', { name: 'Apply' }));

  await waitFor(() => expect(mocks.put).toHaveBeenCalledTimes(1));
  const [path, applied] = mocks.put.mock.calls[0];
  expect(path).toBe('/apis/networking.istio.io/v1/namespaces/shop/gateways/public');
  expect(applied.spec.selector).toEqual({ istio: 'ingress' });
  // the permission to replace it is asked of its own group
  expect(
    mocks.post.mock.calls
      .map(call => call[1].spec.resourceAttributes)
      .find(check => check.name === 'public')
  ).toMatchObject({ group: 'networking.istio.io', resource: 'gateways', verb: 'update' });
  expect(mocks.request.mock.calls.map(call => call[0])).not.toContain(
    '/apis/gateway.networking.k8s.io/v1/namespaces/shop/gateways/public'
  );
});

describe('resourceLocation', () => {
  it('takes the class of the kind when it is of the group, with the version of the scan', async () => {
    expect(await resourceLocation('Deployment', 'apps', 'v1', 'cluster-a')).toEqual({
      group: 'apps',
      version: 'v1',
      plural: 'deployments',
    });
    expect(
      await resourceLocation('Gateway', 'gateway.networking.k8s.io', 'v1beta1', 'cluster-a')
    ).toEqual({ group: 'gateway.networking.k8s.io', version: 'v1beta1', plural: 'gateways' });
    // Kubescape gives the ServiceAccount of a role binding no version
    expect(await resourceLocation('ServiceAccount', '', '', 'cluster-a')).toEqual({
      group: '',
      version: 'v1',
      plural: 'serviceaccounts',
    });
    // a scan that does not name the group
    expect(await resourceLocation('Pod', undefined, undefined, 'cluster-a')).toEqual({
      group: '',
      version: 'v1',
      plural: 'pods',
    });
    expect(await resourceLocation('Deployment', '', '', 'cluster-a')).toEqual({
      group: 'apps',
      version: 'v1',
      plural: 'deployments',
    });
    expect(mocks.request).not.toHaveBeenCalled();
  });

  it('asks the API server for a kind that Headlamp has not in that group', async () => {
    mocks.request.mockResolvedValue({
      resources: [
        { name: 'validatingwebhookconfigurations', kind: 'ValidatingWebhookConfiguration' },
      ],
    });
    expect(
      await resourceLocation(
        'ValidatingWebhookConfiguration',
        'admissionregistration.k8s.io',
        'v1',
        'cluster-a'
      )
    ).toEqual({
      group: 'admissionregistration.k8s.io',
      version: 'v1',
      plural: 'validatingwebhookconfigurations',
    });
    expect(mocks.request).toHaveBeenCalledWith('/apis/admissionregistration.k8s.io/v1', {
      cluster: 'cluster-a',
    });

    // a kind the API server does not name, and one without a version to ask about
    expect(await resourceLocation('Widget', 'example.com', 'v1', 'cluster-a')).toBeUndefined();
    expect(await resourceLocation('Widget', undefined, undefined, 'cluster-a')).toBeUndefined();
    expect(objectPath({ group: '', version: 'v1', plural: 'nodes' }, '', 'node-1')).toBe(
      '/api/v1/nodes/node-1'
    );
  });

  it('says which kind it cannot read', async () => {
    scanKind = 'Widget';
    mocks.request.mockResolvedValue({ resources: [] });
    render(<KubescapeWorkloadConfigurationScanFixes />);
    expect(
      await screen.findByText('Unable to read web: Widget is not a kind this page can read')
    ).toBeTruthy();
  });
});

describe('the times of the scan and of the last change', () => {
  it('reads the time of the scan to the nanosecond, else to the second', () => {
    const scan = (annotations?: object, createdAt?: string) =>
      ({ metadata: { annotations }, spec: { metadata: { report: { createdAt } } } } as any);
    expect(
      scanTime(
        scan(
          { 'kubescape.io/report-created-at': '2026-11-22T01:12:30.357675365Z' },
          '2026-11-22T01:12:30Z'
        )
      )
    ).toBe(Date.parse('2026-11-22T01:12:30.357Z'));
    expect(scanTime(scan(undefined, '2026-11-22T01:12:30Z'))).toBe(
      Date.parse('2026-11-22T01:12:30Z')
    );
    expect(scanTime({ metadata: {}, spec: {} } as any)).toBeUndefined();
  });

  it('takes the last change of a resource from its managed fields, apart from subresources', () => {
    expect(
      lastChanged({
        metadata: {
          creationTimestamp: '2026-11-21T13:47:32Z',
          managedFields: [
            { manager: 'helm', time: '2026-11-21T14:00:00Z' },
            {
              manager: 'kube-controller-manager',
              subresource: 'status',
              time: '2026-11-22T09:00:00Z',
            },
            { manager: 'hpa', subresource: 'scale', time: '2026-11-22T09:30:00Z' },
          ],
        },
      })
    ).toBe(Date.parse('2026-11-21T14:00:00Z'));
    // a resource created again after the scan
    expect(lastChanged({ metadata: { creationTimestamp: '2026-11-22T10:00:00Z' } })).toBe(
      Date.parse('2026-11-22T10:00:00Z')
    );
    expect(lastChanged({ metadata: {} })).toBeUndefined();
  });
});

it('says that Kubescape gives no fix for a control without fix paths, instead of an empty diff', async () => {
  // as Kubescape reports C-0057 (privileged container)
  scanPaths = [{ failedPath: '', fixPath: '', fixPathValue: '', fixCommand: '' }];
  mocks.controls = [{ controlID: 'C-0016', name: 'Allow privilege escalation', remediation: 'x' }];
  render(<KubescapeWorkloadConfigurationScanFixes />);

  expect(
    (await screen.findByText(/Kubescape gives no automatic fix for this control/)).textContent
  ).toBe(
    'Kubescape gives no automatic fix for this control in Deployment shop/web: change it by hand, as the remediation above describes.'
  );
  expect(screen.queryByTestId('fixed')).toBeNull();
  expect(screen.queryByRole('button', { name: 'Apply fix' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Download fixed YAML' })).toBeNull();
});

it('points to the documentation of a control without fix paths and without a remediation', async () => {
  scanPaths = [];
  render(<KubescapeWorkloadConfigurationScanFixes />);

  expect(await screen.findByText(/as the documentation of the control describes\.$/)).toBeTruthy();
  expect(screen.queryByText(/Kubescape names where the control failed/)).toBeNull();
});

it('names a path that only failed to review, and changes nothing for it', async () => {
  // as C-0299 reports a network policy that selects no pods: without its podSelector, the
  // policy would select every pod of the namespace
  scanPaths = [{ failedPath: 'spec.template.spec.containers' }];
  render(<KubescapeWorkloadConfigurationScanFixes />);

  expect(await screen.findByText(/Kubescape gives no automatic fix for this control/)).toBeTruthy();
  expect(screen.getByText(/Review this path, which no fix changes/)).toBeTruthy();
  expect(screen.getByText('spec.template.spec.containers')).toBeTruthy();
  expect(screen.queryByTestId('fixed')).toBeNull();
  expect(screen.queryByRole('button', { name: 'Apply fix' })).toBeNull();
});

it('shows the paths to review next to a fix, which does not change them', async () => {
  scanPaths = [
    ...allowPrivilegeEscalation,
    { failedPath: 'spec.template.spec.containers[0].image' },
  ];
  render(<KubescapeWorkloadConfigurationScanFixes />);

  const fixed = load((await screen.findByTestId('fixed')).textContent ?? '') as any;
  expect(fixed.spec.template.spec.containers[0]).toEqual({
    name: 'web',
    image: 'nginx',
    securityContext: { allowPrivilegeEscalation: false },
  });
  expect(screen.getByText('spec.template.spec.containers[0].image')).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Apply fix' })).toBeTruthy();
});

it('shows the fix read-only, as Apply fix and the download take the fix as it was made', async () => {
  render(<KubescapeWorkloadConfigurationScanFixes />);

  expect((await screen.findByTestId('fixed')).getAttribute('data-read-only')).toBe('true');
});

it('does not offer to apply a fix with a placeholder, and says why', async () => {
  // as C-0055 (Linux hardening) fixes a container without a seccomp profile
  scanPaths = [
    {
      fixPath: 'spec.template.spec.containers[0].securityContext.seccompProfile',
      fixPathValue: 'YOUR_VALUE',
      failedPath: '',
    },
  ];
  render(<KubescapeWorkloadConfigurationScanFixes />);

  expect((await screen.findByTestId('fixed')).textContent).toContain('seccompProfile: YOUR_VALUE');
  expect(
    screen.getByText(
      'This fix cannot be applied from here: it holds the placeholder YOUR_VALUE, to replace with a value of your own in the downloaded YAML.'
    )
  ).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Apply fix' })).toBeNull();

  fireEvent.click(screen.getByRole('button', { name: 'Download fixed YAML' }));
  expect(mocks.saveToFile.mock.calls.at(-1)?.[0]).toContain('seccompProfile: YOUR_VALUE');
});

it('knows the placeholders of Kubescape from values to set', () => {
  for (const placeholder of [
    'YOUR_VALUE',
    'YOUR_NAMESPACE',
    'REMOVE_GROUP_0',
    'REMOVE_UNSAFE_SYSCTLS',
    '<your-tls-definition>',
    '<your encrypted storage class>',
    '--audit-log-maxsize=YOUR_VALUE',
    '--etcd-cafile=<path/to/ca-file.crt>',
  ]) {
    expect(isPlaceholder(placeholder)).toBe(true);
  }
  for (const value of ['RuntimeDefault', 'NET_RAW', 'ALL', 'Always', false, 1000, null]) {
    expect(isPlaceholder(value)).toBe(false);
  }
});

it('gives fix values the type of the field', () => {
  expect(parseFixValue('false')).toBe(false);
  expect(parseFixValue('1000')).toBe(1000);
  expect(parseFixValue('RuntimeDefault')).toBe('RuntimeDefault');
  expect(parseFixValue('')).toBe('');
});

describe('applyFixPath', () => {
  const container = (securityContext?: object) => ({
    spec: { template: { spec: { containers: [{ name: 'app', ...securityContext }] } } },
  });
  const drop = 'spec.template.spec.containers[0].securityContext.capabilities.drop';

  it('creates the list that a fix adds the first value to', () => {
    const resource: any = container();
    applyFixPath(resource, `${drop}[0]`, 'NET_RAW');
    expect(resource.spec.template.spec.containers[0].securityContext).toEqual({
      capabilities: { drop: ['NET_RAW'] },
    });
  });

  it('appends at the index one past the end, as Kubescape adds to a list', () => {
    const resource: any = container({ securityContext: { capabilities: { drop: ['ALL'] } } });
    applyFixPath(resource, `${drop}[1]`, 'NET_RAW');
    expect(resource.spec.template.spec.containers[0].securityContext.capabilities.drop).toEqual([
      'ALL',
      'NET_RAW',
    ]);
  });

  it('replaces a value in a list and changes nothing for a path that does not fit', () => {
    const resource: any = container({ securityContext: { capabilities: { drop: ['ALL'] } } });
    applyFixPath(resource, `${drop}[0]`, 'NET_RAW');
    applyFixPath(resource, `${drop}[5]`, 'SYS_ADMIN');
    applyFixPath(resource, 'spec.template.spec.containers.name', 'x');
    expect(resource).toEqual(
      container({ securityContext: { capabilities: { drop: ['NET_RAW'] } } })
    );
  });

  it('sets a field whose name is also earlier in the path', () => {
    const resource: any = { spec: { template: { spec: {} } } };
    applyFixPath(resource, 'spec.template.spec', { hostNetwork: false });
    expect(resource.spec.template.spec).toEqual({ hostNetwork: false });
  });

  it('writes the fixes of a control into the YAML', () => {
    const yaml = fixResource(
      container(),
      {
        rules: [
          {
            paths: [
              { fixPath: `${drop}[0]`, failedPath: '', fixPathValue: 'NET_RAW' },
              {
                fixPath: 'spec.template.spec.containers[0].securityContext.runAsNonRoot',
                failedPath: '',
                fixPathValue: 'true',
              },
            ],
          },
        ],
      } as any,
      ''
    );
    expect((load(yaml) as any).spec.template.spec.containers[0].securityContext).toEqual({
      capabilities: { drop: ['NET_RAW'] },
      runAsNonRoot: true,
    });
  });

  it('changes nothing for the paths without a value to set, which are to review', () => {
    // C-0299 names the selector of a network policy that selects no pods: without it, the
    // policy would select every pod of the namespace
    const policy = {
      spec: { podSelector: { matchLabels: { app: 'old' } }, policyTypes: ['Ingress'] },
    };
    const control = {
      rules: [
        {
          paths: [
            // the storage leaves out the fix of a path that only failed
            { failedPath: 'spec.podSelector' },
            // a delete or review path of Kubescape arrives without any path
            { failedPath: '', fixPath: '', fixPathValue: '' },
            // a fix without its value
            { fixPath: 'spec.policyTypes[1]' },
            { failedPath: 'spec.podSelector' },
          ],
        },
        // a rule without paths
        {},
      ],
    } as any;

    expect(load(fixResource(structuredClone(policy), control, ''))).toEqual(policy);
    expect(resourcePaths(control, '')).toEqual({
      fixes: [],
      review: ['spec.podSelector', 'spec.policyTypes[1]'],
    });
    expect(parseFixValue(undefined)).toBeUndefined();
    // a control without rules
    expect(resourcePaths({} as any, '')).toEqual({ fixes: [], review: [] });
  });

  it('gives a related object the paths with its prefix, and the workload the others', () => {
    const control = {
      rules: [
        {
          paths: [
            { fixPath: 'spec.automountServiceAccountToken', fixPathValue: 'false' },
            { fixPath: 'relatedObjects[1].automountServiceAccountToken', fixPathValue: 'false' },
            { failedPath: 'relatedObjects[1].secrets' },
            { failedPath: 'relatedObjects[10].subjects[0]' },
            // a path that a fix sets needs no review
            { failedPath: 'spec.automountServiceAccountToken' },
          ],
        },
      ],
    } as any;

    expect(resourcePaths(control, '')).toEqual({
      fixes: [{ path: 'spec.automountServiceAccountToken', value: false }],
      review: [],
    });
    expect(resourcePaths(control, 'relatedObjects[1].')).toEqual({
      fixes: [{ path: 'automountServiceAccountToken', value: false }],
      review: ['secrets'],
    });
  });
});
