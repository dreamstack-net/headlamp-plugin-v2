import { vi } from 'vitest';
import { isControlExcepted } from '../compliance/workload-scanning';
import {
  ClusterSecurityException,
  SecurityException,
  SecurityExceptionSpec,
} from '../softwarecomposition/SecurityException';
import { WorkloadConfigurationScanSummary } from '../softwarecomposition/WorkloadConfigurationScanSummary';
import {
  applySecurityExceptionsToWorkloadScans,
  countExcludedControls,
  fetchSecurityExceptions,
  formatLabelSelector,
  markScannerExceptions,
  SecurityExceptionData,
  workloadExceptionMarks,
} from './apply-security-exceptions';

const request = vi.hoisted(() => vi.fn());
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ request }));

function scan(kind: string, namespace: string, name: string) {
  const control = (controlID: string) => ({
    controlID,
    severity: { scoreFactor: 7, severity: 'High' },
    status: { status: 'failed' },
    exceptedByPolicy: false,
  });
  return {
    metadata: {
      name: `${kind.toLowerCase()}-${name}`,
      namespace,
      cluster: 'cluster-a',
      creationTimestamp: '',
      annotations: {},
      labels: {
        'kubescape.io/workload-kind': kind,
        'kubescape.io/workload-name': name,
        'kubescape.io/workload-namespace': namespace,
      },
    },
    spec: {
      controls: { 'C-0001': control('C-0001'), 'C-0002': control('C-0002') },
      severities: { critical: 0, high: 2, medium: 0, low: 0, unknown: 0 },
    },
    exceptedByPolicy: false,
  } as unknown as WorkloadConfigurationScanSummary;
}

function namespacedException(namespace: string, spec: SecurityExceptionSpec): SecurityException {
  return {
    apiVersion: 'kubescape.io/v1beta1',
    kind: 'SecurityException',
    metadata: { name: 'exception', namespace },
    spec,
  };
}

function clusterException(spec: SecurityExceptionSpec): ClusterSecurityException {
  return {
    apiVersion: 'kubescape.io/v1beta1',
    kind: 'ClusterSecurityException',
    metadata: { name: 'cluster-exception' },
    spec,
  };
}

function exceptionData(
  exceptions: Array<SecurityException | ClusterSecurityException>,
  namespaceLabels: Record<string, Record<string, string>> = {}
): SecurityExceptionData {
  return {
    namespaced: exceptions.filter((e): e is SecurityException => e.kind === 'SecurityException'),
    cluster: exceptions.filter(
      (e): e is ClusterSecurityException => e.kind === 'ClusterSecurityException'
    ),
    namespaceLabelsByName: new Map(Object.entries(namespaceLabels)),
  };
}

function exceptedControls(w: WorkloadConfigurationScanSummary) {
  return Object.values(w.spec.controls)
    .filter(control => control.exceptedByPolicy)
    .map(control => control.controlID);
}

const posture = (controlID: string) => ({ controlID, action: 'ignore' as const });

it('excludes whole workloads in the namespace of a resource-level SecurityException', () => {
  const inScope = scan('Deployment', 'shop', 'web');
  const otherNamespace = scan('Deployment', 'billing', 'web');

  applySecurityExceptionsToWorkloadScans(
    [inScope, otherNamespace],
    exceptionData([namespacedException('shop', {})])
  );

  expect(inScope.exceptedByPolicy).toBe(true);
  expect(otherNamespace.exceptedByPolicy).toBe(false);
});

it('does not let vulnerability-only exceptions exclude compliance results', () => {
  const w = scan('Deployment', 'shop', 'web');
  const vulnerabilities = [
    { vulnerability: { id: 'CVE-2024-0001' }, status: 'not_affected' as const },
  ];

  applySecurityExceptionsToWorkloadScans(
    [w],
    exceptionData([namespacedException('shop', { vulnerabilities })])
  );

  expect(w.exceptedByPolicy).toBe(false);
  expect(exceptedControls(w)).toEqual([]);
});

it('excepts only the controls listed in posture entries', () => {
  const w = scan('Deployment', 'shop', 'web');

  applySecurityExceptionsToWorkloadScans(
    [w],
    exceptionData([namespacedException('shop', { posture: [posture('C-0002')] })])
  );

  expect(w.exceptedByPolicy).toBe(false);
  expect(exceptedControls(w)).toEqual(['C-0002']);
});

it('keeps a control that an alert_only entry acknowledges failed in scoring', () => {
  const w = scan('Deployment', 'shop', 'web');

  applySecurityExceptionsToWorkloadScans(
    [w],
    exceptionData([
      namespacedException('shop', {
        posture: [posture('C-0002'), { controlID: 'C-0001', action: 'alert_only' }],
      }),
    ])
  );

  expect(exceptedControls(w)).toEqual(['C-0002']);
});

it('applies an entry limited to a framework only in that framework', () => {
  const w = scan('Deployment', 'shop', 'web');

  applySecurityExceptionsToWorkloadScans(
    [w],
    exceptionData([
      namespacedException('shop', {
        posture: [
          { controlID: 'C-0001', frameworkName: 'NSA', action: 'ignore' },
          { controlID: 'C-0001', frameworkName: 'mitre', action: 'ignore' },
          { controlID: 'C-0002', frameworkName: 'NSA', action: 'alert_only' },
        ],
      }),
    ])
  );

  const [c1, c2] = [w.spec.controls['C-0001'], w.spec.controls['C-0002']];
  expect(c1.exceptedByPolicy).toBe(false);
  expect(c1.exceptedInFrameworks).toEqual(['NSA', 'mitre']);
  expect(isControlExcepted(c1, 'nsa')).toBe(true);
  expect(isControlExcepted(c1, 'MITRE')).toBe(true);
  expect(isControlExcepted(c1, 'cis-v1.10.0')).toBe(false);
  expect(isControlExcepted(c1, undefined)).toBe(false);
  expect(c2.exceptedInFrameworks).toBeUndefined();
  expect(countExcludedControls([w], 'NSA')).toBe(1);
  expect(countExcludedControls([w])).toBe(0);
});

it('reads the framework of an entry as a pattern of the whole name, without case', () => {
  const marks = { exceptedByPolicy: false, exceptedInFrameworks: ['cis-.*', 'Acme \\S+ v1'] };
  expect(isControlExcepted(marks, 'cis-v1.10.0')).toBe(true);
  expect(isControlExcepted(marks, 'CIS-v1.12.0')).toBe(true);
  expect(isControlExcepted(marks, 'acme Security-Baseline v1')).toBe(true);
  // the whole name: a pattern does not match part of it
  expect(isControlExcepted(marks, 'my-cis-v1.10.0')).toBe(false);
  expect(isControlExcepted(marks, 'Acme Security Baseline v1')).toBe(false);
  // a pattern that does not compile matches nothing, also not a framework of that name
  expect(isControlExcepted({ exceptedByPolicy: false, exceptedInFrameworks: ['('] }, 'NSA')).toBe(
    false
  );
});

it('lets an entry for every framework cover the framework-limited ones', () => {
  const w = scan('Deployment', 'shop', 'web');

  applySecurityExceptionsToWorkloadScans(
    [w],
    exceptionData([
      namespacedException('shop', {
        posture: [{ controlID: 'C-0001', frameworkName: 'NSA', action: 'ignore' }],
      }),
      namespacedException('shop', { posture: [posture('C-0001')] }),
    ])
  );

  expect(w.spec.controls['C-0001'].exceptedByPolicy).toBe(true);
  expect(w.spec.controls['C-0001'].exceptedInFrameworks).toBeUndefined();

  // applying again without the exceptions clears the marks
  applySecurityExceptionsToWorkloadScans([w], exceptionData([]));
  expect(w.spec.controls['C-0001'].exceptedByPolicy).toBe(false);
  expect(w.spec.controls['C-0001'].exceptedInFrameworks).toBeUndefined();
});

it('restricts matching to the listed resources, by kind and optional name', () => {
  const web = scan('Deployment', 'shop', 'web');
  const api = scan('Deployment', 'shop', 'api');
  const db = scan('StatefulSet', 'shop', 'db');

  applySecurityExceptionsToWorkloadScans(
    [web, api, db],
    exceptionData([
      namespacedException('shop', {
        match: { resources: [{ kind: 'Deployment', name: 'web' }, { kind: 'StatefulSet' }] },
      }),
    ])
  );

  expect([web, api, db].map(w => w.exceptedByPolicy)).toEqual([true, false, true]);
});

describe('posture entries, as Kubescape matches them', () => {
  const excepted = (
    scans: WorkloadConfigurationScanSummary[],
    exception: SecurityException | ClusterSecurityException
  ) => {
    applySecurityExceptionsToWorkloadScans(scans, exceptionData([exception]));
    return scans.map(w => w.exceptedByPolicy);
  };
  const withApiGroup = (w: WorkloadConfigurationScanSummary, group: string) => {
    w.metadata.labels['kubescape.io/workload-api-group'] = group;
    return w;
  };

  it('compares kinds and names as regular expressions of the whole value, with case', () => {
    const scans = [
      scan('Deployment', 'shop', 'web-1'),
      scan('Deployment', 'shop', 'web'),
      scan('Deployment', 'shop', 'old-web-1'),
      scan('StatefulSet', 'shop', 'web-1'),
    ];
    expect(
      excepted(
        scans,
        namespacedException('shop', {
          match: { resources: [{ kind: 'Deployment', name: 'web-.*' }] },
        })
      )
    ).toEqual([true, false, false, false]);
    expect(
      excepted(
        scans,
        namespacedException('shop', { match: { resources: [{ kind: 'deployment' }] } })
      )
    ).toEqual([false, false, false, false]);
    // Kubescape reads a leading * as the start of the text, so * matches every kind
    expect(
      excepted(scans, namespacedException('shop', { match: { resources: [{ kind: '*' }] } }))
    ).toEqual([true, true, true, true]);
  });

  it('matches nothing with a name that is not a regular expression', () => {
    const w = scan('Deployment', 'shop', 'web[');
    expect(
      excepted(
        [w],
        namespacedException('shop', {
          match: { resources: [{ kind: 'Deployment', name: 'web[' }] },
        })
      )
    ).toEqual([false]);
  });

  it('compares a given API group with that of the scan, also the empty core group', () => {
    const scans = [
      withApiGroup(scan('Deployment', 'shop', 'web'), 'apps'),
      withApiGroup(scan('Pod', 'shop', 'web'), ''),
      withApiGroup(scan('Rollout', 'shop', 'web'), 'argoproj.io'),
    ];
    const resources = (apiGroup: string) =>
      namespacedException('shop', {
        match: { resources: ['Deployment', 'Pod', 'Rollout'].map(kind => ({ kind, apiGroup })) },
      });
    expect(excepted(scans, resources(''))).toEqual([false, true, false]);
    expect(excepted(scans, resources('apps'))).toEqual([true, false, false]);
    expect(excepted(scans, resources('Apps'))).toEqual([false, false, false]);
    expect(excepted(scans, resources('argoproj\\.io'))).toEqual([false, false, true]);
  });

  it('takes a Namespace to be in the namespace of its name', () => {
    const shop = scan('Namespace', '', 'shop');
    const billing = scan('Namespace', '', 'billing');
    applySecurityExceptionsToWorkloadScans(
      [shop, billing],
      exceptionData(
        [
          namespacedException('shop', { posture: [posture('C-0001')] }),
          clusterException({
            match: { namespaceSelector: { matchLabels: { team: 'billing' } } },
            posture: [posture('C-0002')],
          }),
        ],
        { billing: { team: 'billing' } }
      )
    );
    expect([shop, billing].map(exceptedControls)).toEqual([['C-0001'], ['C-0002']]);
  });

  it('compares control ids without case and as regular expressions of the whole id', () => {
    const w = scan('Deployment', 'shop', 'web');
    const exceptionFor = (controlID: string) =>
      namespacedException('shop', { posture: [posture(controlID)] });

    excepted([w], exceptionFor('c-0001'));
    expect(exceptedControls(w)).toEqual(['C-0001']);
    excepted([w], exceptionFor('C-000[2-9]'));
    expect(exceptedControls(w)).toEqual(['C-0002']);
    excepted([w], exceptionFor('C-000'));
    expect(exceptedControls(w)).toEqual([]);
    excepted([w], exceptionFor('C-00(01'));
    expect(exceptedControls(w)).toEqual([]);

    const marks = workloadExceptionMarks(
      w,
      exceptionData([
        namespacedException('shop', {
          posture: [{ controlID: 'c-000.', frameworkName: 'NSA', action: 'ignore' }],
        }),
      ])
    );
    expect([...(marks.inFrameworks.get('C-0002') ?? [])]).toEqual(['NSA']);
    expect(marks.everywhere.has('C-0002')).toBe(false);
  });
});

it('ignores expired exceptions', () => {
  const w = scan('Deployment', 'shop', 'web');

  applySecurityExceptionsToWorkloadScans(
    [w],
    exceptionData([namespacedException('shop', { expiresAt: '2000-01-01T00:00:00Z' })])
  );

  expect(w.exceptedByPolicy).toBe(false);
});

it('matches ClusterSecurityExceptions on namespace labels', () => {
  const prod = scan('Deployment', 'shop', 'web');
  const dev = scan('Deployment', 'sandbox', 'web');
  const unlabeled = scan('Deployment', 'tools', 'web');

  applySecurityExceptionsToWorkloadScans(
    [prod, dev, unlabeled],
    exceptionData(
      [
        clusterException({
          match: {
            namespaceSelector: {
              matchLabels: { team: 'commerce' },
              matchExpressions: [{ key: 'env', operator: 'In', values: ['prod'] }],
            },
          },
        }),
      ],
      {
        shop: { team: 'commerce', env: 'prod' },
        sandbox: { team: 'commerce', env: 'dev' },
      }
    )
  );

  expect([prod, dev, unlabeled].map(w => w.exceptedByPolicy)).toEqual([true, false, false]);
});

it('formats label selectors in query parameter syntax', () => {
  expect(
    formatLabelSelector({
      matchLabels: { app: 'web' },
      matchExpressions: [
        { key: 'tier', operator: 'In', values: ['front', 'edge'] },
        { key: 'env', operator: 'NotIn', values: ['dev'] },
        { key: 'owner', operator: 'Exists' },
        { key: 'legacy', operator: 'DoesNotExist' },
      ],
    })
  ).toBe('app=web,tier in (front,edge),env notin (dev),owner,!legacy');
  expect(formatLabelSelector({})).toBe('');
});

it('reads the exceptions that the scanner applied from the control sub-status', () => {
  const passedByException = { status: 'passed', subStatus: 'w/exceptions' } as any;
  const partly = scan('Deployment', 'shop', 'web');
  partly.spec.controls['C-0002'].status = passedByException;
  const fully = scan('Deployment', 'shop', 'api');
  Object.values(fully.spec.controls).forEach(control => {
    control.status = passedByException;
  });

  markScannerExceptions([partly, fully]);

  expect(exceptedControls(partly)).toEqual(['C-0002']);
  expect(partly.exceptedByPolicy).toBe(false);
  expect(fully.exceptedByPolicy).toBe(true);
});

it('keeps a control failed that the scanner fails with the sub-status of an exception', () => {
  // an alert_only entry acknowledges the failure, or another rule of the control still fails
  const w = scan('Deployment', 'shop', 'web');
  Object.values(w.spec.controls).forEach(control => {
    control.status = { status: 'failed', subStatus: 'w/exceptions' } as any;
  });

  markScannerExceptions([w]);

  expect(exceptedControls(w)).toEqual([]);
  expect(w.exceptedByPolicy).toBe(false);
});

it('does not match a namespace whose labels are not known, whatever the selector', () => {
  const known = scan('Deployment', 'shop', 'web');
  const unknown = scan('Deployment', 'tools', 'web');
  const clusterScoped = scan('ClusterRole', '', 'admin');

  applySecurityExceptionsToWorkloadScans(
    [known, unknown, clusterScoped],
    exceptionData(
      [
        clusterException({
          match: {
            namespaceSelector: {
              matchExpressions: [
                { key: 'env', operator: 'NotIn', values: ['prod'] },
                { key: 'restricted', operator: 'DoesNotExist' },
              ],
            },
          },
        }),
      ],
      { shop: { env: 'dev' } }
    )
  );

  expect([known, unknown, clusterScoped].map(w => w.exceptedByPolicy)).toEqual([
    true,
    false,
    false,
  ]);
});

it('matches nothing with a selector that Kubernetes does not accept', () => {
  const w = scan('Deployment', 'shop', 'web');
  const selectors = [
    // an operator in the wrong case, which the CRD stores as it is
    { matchExpressions: [{ key: 'env', operator: 'in', values: ['prod'] }] },
    { matchExpressions: [{ key: 'env', operator: 'NotIn', values: [] }] },
    { matchExpressions: [{ key: 'env', operator: 'Exists', values: ['prod'] }] },
  ];

  for (const namespaceSelector of selectors) {
    applySecurityExceptionsToWorkloadScans(
      [w],
      exceptionData([clusterException({ match: { namespaceSelector } as any })], {
        shop: { env: 'dev' },
      })
    );
    expect(w.exceptedByPolicy).toBe(false);
  }
});

it('matches a resource that names an API group only for a kind of that group', () => {
  const deployment = scan('Deployment', 'shop', 'web');
  const cronJob = scan('CronJob', 'shop', 'web');
  const pod = scan('Pod', 'shop', 'web');
  const other = scan('Rollout', 'shop', 'web');

  applySecurityExceptionsToWorkloadScans(
    [deployment, cronJob, pod, other],
    exceptionData([
      namespacedException('shop', {
        match: {
          resources: [
            { apiGroup: 'apps', kind: 'Deployment' },
            // not the group of the kind
            { apiGroup: 'apps', kind: 'CronJob' },
            { kind: 'Pod' },
            // the group of a kind the plugin does not know is not verified
            { apiGroup: 'argoproj.io', kind: 'Rollout' },
          ],
        },
      }),
    ])
  );

  expect([deployment, cronJob, pod, other].map(w => w.exceptedByPolicy)).toEqual([
    true,
    false,
    true,
    false,
  ]);
});

describe('objectSelector', () => {
  const objectSelector = { matchLabels: { exempt: 'true' } };
  const selectedQuery = `?${new URLSearchParams({ labelSelector: 'exempt=true' })}`;

  function mockCluster(
    exceptions: { namespaced?: SecurityException[]; cluster?: ClusterSecurityException[] },
    workloads: Record<string, Array<{ namespace: string; name: string }>>
  ) {
    request.mockReset().mockImplementation(async (url: string) => {
      if (url === '/apis/kubescape.io/v1beta1/securityexceptions') {
        return { items: exceptions.namespaced ?? [] };
      }
      if (url === '/apis/kubescape.io/v1beta1/clustersecurityexceptions') {
        return { items: exceptions.cluster ?? [] };
      }
      if (url === '/api/v1/namespaces') return { items: [] };
      if (!(url in workloads)) throw new Error(`forbidden: ${url}`);
      return { items: workloads[url].map(metadata => ({ metadata })) };
    });
  }

  it('lets the API server select the workloads of a SecurityException', async () => {
    const selected = scan('Deployment', 'shop', 'web');
    const unselected = scan('Deployment', 'shop', 'api');
    const otherKind = scan('StatefulSet', 'shop', 'db');
    mockCluster(
      {
        namespaced: [
          namespacedException('shop', {
            match: { objectSelector, resources: [{ kind: 'Deployment' }] },
          }),
        ],
      },
      {
        [`/apis/apps/v1/namespaces/shop/deployments${selectedQuery}`]: [
          { namespace: 'shop', name: 'web' },
        ],
      }
    );

    const scans = [selected, unselected, otherKind];
    const data = await fetchSecurityExceptions('cluster-a', scans);
    applySecurityExceptionsToWorkloadScans(scans, data);

    expect(scans.map(w => w.exceptedByPolicy)).toEqual([true, false, false]);
    // Only kinds that are both scanned and listed in resources are looked up
    expect(request.mock.calls.map(([url]) => url)).not.toContainEqual(
      expect.stringContaining('statefulsets')
    );
    expect(request.mock.calls.every(([, options]) => options.cluster === 'cluster-a')).toBe(true);
  });

  it('looks up workloads cluster-wide for a ClusterSecurityException', async () => {
    const w = scan('DaemonSet', 'monitoring', 'agent');
    mockCluster(
      { cluster: [clusterException({ match: { objectSelector }, posture: [posture('C-0001')] })] },
      { [`/apis/apps/v1/daemonsets${selectedQuery}`]: [{ namespace: 'monitoring', name: 'agent' }] }
    );

    const data = await fetchSecurityExceptions('cluster-a', [w]);
    applySecurityExceptionsToWorkloadScans([w], data);

    expect(exceptedControls(w)).toEqual(['C-0001']);
  });

  it('does not match workloads whose labels cannot be looked up', async () => {
    const listable = scan('Deployment', 'shop', 'web');
    const unknownKind = scan('Service', 'shop', 'web');
    mockCluster({ namespaced: [namespacedException('shop', { match: { objectSelector } })] }, {});

    const scans = [listable, unknownKind];
    const data = await fetchSecurityExceptions('cluster-a', scans);
    applySecurityExceptionsToWorkloadScans(scans, data);

    expect(scans.map(w => w.exceptedByPolicy)).toEqual([false, false]);
    // the findings of these workloads are shown as open, which the pages say
    expect(data.errors).toEqual([
      expect.stringMatching(
        /^the workloads that the objectSelector of SecurityException exception selects \(deployments of namespace shop: forbidden/
      ),
    ]);
  });

  it('lists the workloads of a ClusterSecurityException in each allowed namespace', async () => {
    const inShop = scan('Deployment', 'shop', 'web');
    const inBlog = scan('Deployment', 'blog', 'web');
    mockCluster(
      { cluster: [clusterException({ match: { objectSelector } })] },
      {
        [`/apis/apps/v1/namespaces/shop/deployments${selectedQuery}`]: [
          { namespace: 'shop', name: 'web' },
        ],
        [`/apis/apps/v1/namespaces/blog/deployments${selectedQuery}`]: [],
      }
    );

    const scans = [inShop, inBlog];
    const data = await fetchSecurityExceptions('cluster-a', scans, [], ['shop', 'blog']);
    applySecurityExceptionsToWorkloadScans(scans, data);

    expect(scans.map(w => w.exceptedByPolicy)).toEqual([true, false]);
    // the lists of the workloads did not fail
    expect((data.errors ?? []).filter(error => error.includes('objectSelector'))).toEqual([]);
    expect(request.mock.calls.map(([url]) => url)).not.toContain(
      `/apis/apps/v1/deployments${selectedQuery}`
    );
  });

  it('selects nothing, and asks nothing, with a selector that Kubernetes does not accept', async () => {
    const w = scan('Deployment', 'shop', 'web');
    mockCluster(
      {
        namespaced: [
          namespacedException('shop', {
            match: {
              objectSelector: {
                matchLabels: { exempt: 'true' },
                matchExpressions: [{ key: 'tier', operator: 'in', values: ['front'] }],
              },
            } as any,
          }),
        ],
      },
      // without the requirement that is not valid, the selector would select the workload
      {
        [`/apis/apps/v1/namespaces/shop/deployments${selectedQuery}`]: [
          { namespace: 'shop', name: 'web' },
        ],
      }
    );

    const data = await fetchSecurityExceptions('cluster-a', [w]);
    applySecurityExceptionsToWorkloadScans([w], data);

    expect(w.exceptedByPolicy).toBe(false);
    expect(request.mock.calls.map(([url]) => url)).not.toContainEqual(
      expect.stringContaining('deployments')
    );
  });
});

it('tells what exceptions exclude of a workload without marking it', () => {
  const w = scan('Deployment', 'shop', 'web');

  const marks = workloadExceptionMarks(
    w,
    exceptionData([
      namespacedException('shop', {
        posture: [
          posture('C-0001'),
          { controlID: 'C-0002', frameworkName: 'NSA', action: 'ignore' },
        ],
      }),
    ])
  );

  expect(marks.workload).toBe(false);
  expect([...marks.everywhere]).toEqual(['C-0001']);
  expect([...(marks.inFrameworks.get('C-0002') ?? [])]).toEqual(['NSA']);
  expect(exceptedControls(w)).toEqual([]);
  expect(workloadExceptionMarks(w, exceptionData([namespacedException('shop', {})])).workload).toBe(
    true
  );
});

it('counts the excepted results of the controls of a framework only', () => {
  const w = scan('Deployment', 'shop', 'web');
  applySecurityExceptionsToWorkloadScans(
    [w],
    exceptionData([
      namespacedException('shop', { posture: [posture('C-0001'), posture('C-0002')] }),
    ])
  );

  expect(countExcludedControls([w], 'NSA')).toBe(2);
  expect(countExcludedControls([w], 'NSA', new Set(['C-0002', 'C-0099']))).toBe(1);
  expect(countExcludedControls([w], 'NSA', new Set())).toBe(0);
});

describe('fetchSecurityExceptions', () => {
  const statusError = (status: number, message: string) =>
    Object.assign(new Error(message), { status });

  it('reads no exceptions where the CRDs are not installed, and reports other errors', async () => {
    request.mockReset().mockImplementation(async (url: string) => {
      if (url === '/apis/kubescape.io/v1beta1/securityexceptions') {
        throw statusError(404, 'the server could not find the requested resource');
      }
      if (url === '/apis/kubescape.io/v1beta1/clustersecurityexceptions') {
        throw statusError(403, 'clustersecurityexceptions is forbidden');
      }
      return { items: [] };
    });

    const data = await fetchSecurityExceptions('cluster-a');

    expect(data.namespaced).toEqual([]);
    expect(data.cluster).toEqual([]);
    expect(data.errors).toEqual([
      'ClusterSecurityExceptions: clustersecurityexceptions is forbidden',
    ]);

    // without the CRDs at all, there are no exceptions and nothing to report
    request.mockReset().mockRejectedValue(statusError(404, 'not found'));
    const none = await fetchSecurityExceptions('cluster-a');
    expect(none.errors).toBeUndefined();
    expect([...none.namespaced, ...none.cluster]).toEqual([]);
  });

  it('reads the SecurityExceptions of each allowed namespace, reporting those that fail', async () => {
    const inShop = namespacedException('shop', { posture: [posture('C-0001')] });
    const inBlog = {
      ...namespacedException('blog', {}),
      metadata: { name: 'b', namespace: 'blog' },
    };
    request.mockReset().mockImplementation(async (url: string) => {
      if (url === '/apis/kubescape.io/v1beta1/namespaces/shop/securityexceptions') {
        return { items: [inShop] };
      }
      if (url === '/apis/kubescape.io/v1beta1/namespaces/blog/securityexceptions') {
        return { items: [inBlog] };
      }
      if (url === '/apis/kubescape.io/v1beta1/namespaces/billing/securityexceptions') {
        throw statusError(403, 'securityexceptions is forbidden in billing');
      }
      if (url === '/apis/kubescape.io/v1beta1/namespaces/empty/securityexceptions') {
        throw statusError(404, 'not found');
      }
      return { items: [] };
    });

    const data = await fetchSecurityExceptions(
      'cluster-a',
      [],
      [],
      ['shop', 'billing', 'blog', 'empty']
    );

    expect(data.namespaced).toEqual([inShop, inBlog]);
    expect(data.errors).toEqual([
      'SecurityExceptions of namespace billing: securityexceptions is forbidden in billing',
    ]);
    const urls = request.mock.calls.map(([url]) => url);
    expect(urls).not.toContain('/apis/kubescape.io/v1beta1/securityexceptions');
    expect(urls).toContain('/apis/kubescape.io/v1beta1/clustersecurityexceptions');
    expect(request.mock.calls.every(([, options]) => options.cluster === 'cluster-a')).toBe(true);
  });

  it('reads the labels of each allowed namespace when the namespaces cannot be listed', async () => {
    const selecting = clusterException({
      match: { namespaceSelector: { matchLabels: { team: 'commerce' } } },
    });
    request.mockReset().mockImplementation(async (url: string) => {
      if (url === '/apis/kubescape.io/v1beta1/clustersecurityexceptions') {
        return { items: [selecting] };
      }
      if (url === '/api/v1/namespaces') throw statusError(403, 'namespaces is forbidden');
      if (url === '/api/v1/namespaces/shop') {
        return { metadata: { name: 'shop', labels: { team: 'commerce' } } };
      }
      if (url === '/api/v1/namespaces/blog') throw statusError(403, 'namespaces is forbidden');
      return { items: [] };
    });

    const read = await fetchSecurityExceptions('cluster-a', [], [], ['shop']);
    expect(read.namespaceLabelsByName.get('shop')).toEqual({ team: 'commerce' });
    expect(read.errors).toBeUndefined();

    // the selector cannot be matched against a namespace whose labels stay unknown
    const partly = await fetchSecurityExceptions('cluster-a', [], [], ['shop', 'blog']);
    expect([...partly.namespaceLabelsByName.keys()]).toEqual(['shop']);
    expect(partly.errors).toEqual([
      'the labels of the namespaces, which namespace selectors match: namespaces is forbidden',
    ]);
  });
});
