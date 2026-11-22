import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import type { ReactNode } from 'react';
import { MemoryRouter } from 'react-router-dom';
import { vi } from 'vitest';
import KubescapeCVEResults from './CVEResults';
import ImageDetails from './ImageDetails';
import ImageList from './ImageList';
import { formatPercentile } from './KnownExploited';
import VulnerabilitiesNamespaceSummary from './NamespaceSummary';
import ResourceList from './ResourceList';
import SBOMDetail, { distroLabel } from './SBOMDetail';
import {
  getImageScanKey,
  invalidateScanClusters,
  toImageScan,
  toWorkloadScan,
  VulnerabilityContext,
  WorkloadScan,
} from './scanData';
import { manifest, match, sbom, summary, T0, T1, T2, unscoredMatch } from './testFixtures';
import WorkloadDetails, { fetchVulnerabilityManifest } from './WorkloadScanDetails';

const mocks = vi.hoisted(() => ({
  request: vi.fn(),
  // the GET of an object of the storage, which the image and SBOM pages read once
  fetchObject: vi.fn(),
  severity: null as string | null,
  cluster: 'cluster-a',
  name: 'workload-123',
  saveToFile: vi.fn(),
  lookupImageVersion: vi.fn(),
  post: vi.fn(),
  // the selected clusters
  clusters: ['cluster-a', 'cluster-b'],
  // the read of the scans by the page of a CVE, and the cache of the scans it starts from
  readVulnerabilityScans: vi.fn(),
  context: { workloadScans: [] as unknown[], queryTasks: [] as unknown[] },
  // the columns of the table that was drawn last, for what its rows do not show
  columns: [] as any[],
  // the namespaces a restricted user may read; none for a user who may read all
  allowedNamespaces: [] as string[],
}));
// the image versions and their end of life are off until they are switched on
vi.mock('../common/config-store', () => ({
  kubescapeConfigStore: {
    get: () => ({}),
    useConfig: () => () => ({ imageVersions: true, endOfLife: true }),
  },
}));
vi.mock('./Vulnerabilities', () => ({
  readVulnerabilityScans: mocks.readVulnerabilityScans,
  vulnerabilityContext: mocks.context,
}));
vi.mock('./imageVersionSources', async importOriginal => ({
  ...(await importOriginal<typeof import('./imageVersionSources')>()),
  lookupImageVersion: mocks.lookupImageVersion,
  versionCheckerResults: async () => new Map(),
}));
vi.mock('../common/filedialog', () => ({ saveToFile: mocks.saveToFile }));
vi.mock('../common/clusterContext', () => ({
  getAllowedNamespaces: () => mocks.allowedNamespaces,
}));
vi.mock('../index', () => ({
  RoutingName: {
    ImageVulnerabilityDetails: 'image',
    KubescapeSBOMDetails: 'sbom',
    KubescapeVulnerabilityDetails: 'workload',
  },
  useHLSelectedClusters: () => mocks.clusters,
}));
vi.mock('../model', () => ({
  fetchObject: mocks.fetchObject,
  vulnerabilityManifestClass: { pluralName: 'vulnerabilitymanifests' },
  vulnerabilityManifestSummaryClass: {},
  sbomSyftClass: { pluralName: 'sbomsyfts' },
  sbomSyftFilteredClass: { pluralName: 'sbomsyftfiltereds' },
  vulnerabilitySummaryClass: { pluralName: 'vulnerabilitysummaries' },
}));
vi.mock('../common/url', () => ({
  getURLSegments: () => [mocks.name, 'workloads'],
  getLastURLSegment: () => mocks.name,
  useURLSearchParam: (name: string) => [name === 'severity' ? mocks.severity : null, () => {}],
}));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({
  request: mocks.request,
  post: mocks.post,
}));
vi.mock('@kinvolk/headlamp-plugin/lib/Utils', () => ({ getCluster: () => mocks.cluster }));
vi.mock('../exceptions/GuidedVulnerabilityExceptionForm', () => ({
  GuidedVulnerabilityExceptionForm: ({ cveIds, acceptRisk }: any) => (
    <div>
      {acceptRisk ? 'Accept risk of' : 'Exception for'} {cveIds.join(', ')}
    </div>
  ),
}));
vi.mock('../exceptions/GuidedClusterVulnerabilityExceptionForm', () => ({
  GuidedClusterVulnerabilityExceptionForm: () => null,
}));
vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', () => ({
  DateLabel: ({ date }: { date: string }) => <time dateTime={date}>{date}</time>,
  SectionBox: ({ children }: { children: ReactNode }) => <section>{children}</section>,
  ShowHideLabel: ({ children }: { children: ReactNode }) => <>{children}</>,
  Tabs: () => null,
  Link: ({ children, activeCluster, routeName, params, search = '', ...rest }: any) => (
    <a
      {...rest}
      href={`/${activeCluster}/${routeName}/${params.namespace}/${params.name}${search}`}
    >
      {children}
    </a>
  ),
  NameValueTable: ({ rows }: any) => (
    <dl>
      {rows.map((row: any) => (
        <div key={row.name}>
          <dt>{row.name}</dt>
          <dd>{row.value}</dd>
        </div>
      ))}
    </dl>
  ),
  // like Headlamp's table: the toolbar with the filters and export of a view, and only a
  // message without the toolbar when there are no rows
  Table: ({ data = [], columns, renderTopToolbarCustomActions, emptyMessage }: any) => {
    // kept for the tests of what the rows do not show, such as how a column sorts
    mocks.columns = columns;
    return data.length === 0 ? (
      <div>{emptyMessage ?? 'No data to be shown.'}</div>
    ) : (
      <>
        {renderTopToolbarCustomActions?.({ table: {} })}
        <table>
          <tbody>
            {data.map((item: any, i: number) => (
              <tr key={i}>
                {columns
                  .filter((col: any) => col.header !== undefined)
                  .map((col: any, j: number) => {
                    const value = col.accessorFn
                      ? col.accessorFn(item)
                      : col.accessorKey?.split('.').reduce((v: any, k: string) => v?.[k], item);
                    return (
                      <td key={j}>
                        {col.Cell
                          ? col.Cell({
                              cell: { getValue: () => value, row: { original: item } },
                              row: { original: item },
                            })
                          : value}
                      </td>
                    );
                  })}
              </tr>
            ))}
          </tbody>
        </table>
      </>
    );
  },
}));

beforeEach(() => {
  mocks.saveToFile.mockReset();
  mocks.request.mockReset();
  mocks.fetchObject.mockReset();
  // still being read, unless a test gives the object
  mocks.fetchObject.mockReturnValue(new Promise(() => {}));
  mocks.lookupImageVersion.mockReset();
  mocks.lookupImageVersion.mockResolvedValue({});
  // a user who may not create exceptions, such as with GitOps
  mocks.post.mockReset();
  mocks.post.mockResolvedValue({ status: { allowed: false } });
  mocks.cluster = 'cluster-a';
  mocks.name = 'workload-123';
  mocks.severity = null;
  mocks.clusters = ['cluster-a', 'cluster-b'];
  mocks.allowedNamespaces = [];
  mocks.readVulnerabilityScans.mockReset();
  mocks.context.workloadScans = [];
});
afterEach(cleanup);

function valueFor(label: string) {
  return screen.getByText(label, { selector: 'dt' }).nextElementSibling!;
}

it('reads the report of an image once, in the cluster of the page', async () => {
  mocks.fetchObject.mockResolvedValue(manifest());
  const view = render(<ImageDetails />);
  expect(screen.getByText('Reading the vulnerabilities of the image…')).toBeTruthy();
  await waitFor(() => expect(valueFor('Last evaluated').textContent).toBe(T1));
  expect(valueFor('Scan record created').textContent).toBe(T0);
  expect(screen.getByText('CVE-1')).toBeTruthy();
  // a GET, not Headlamp's useApiGet, whose watch of the storage would replace the report with
  // one without its matches
  expect(mocks.fetchObject).toHaveBeenCalledWith('workload-123', 'workloads', 'cluster-a', {
    pluralName: 'vulnerabilitymanifests',
  });

  // drawn again, such as when exceptions are read, the page keeps the report it read
  view.rerender(<ImageDetails />);
  await act(async () => {});
  expect(mocks.fetchObject).toHaveBeenCalledTimes(1);
  expect(screen.getByText('CVE-1')).toBeTruthy();

  // another image of the URL is read, without the report of the image before
  mocks.name = 'image-456';
  const other = manifest(T2);
  other.spec.payload.matches = [match('CVE-9')];
  mocks.fetchObject.mockResolvedValue(other);
  view.rerender(<ImageDetails />);
  expect(screen.queryByText('CVE-1')).toBeNull();
  await waitFor(() => expect(screen.getByText('CVE-9')).toBeTruthy());
  expect(valueFor('Last evaluated').querySelector('time')?.dateTime).toBe(T2);
  expect(mocks.fetchObject).toHaveBeenCalledTimes(2);
});

it('says why the report of an image could not be read', async () => {
  mocks.fetchObject.mockRejectedValue({ status: 404, message: 'vulnerabilitymanifests not found' });
  render(<ImageDetails />);
  expect(await screen.findByText('Resource not found')).toBeTruthy();
  expect(screen.getByText('vulnerabilitymanifests not found')).toBeTruthy();
});

it('keeps legacy image findings readable beside Unknown evaluation time', async () => {
  const legacy = manifest();
  delete legacy.spec.metadata;
  mocks.fetchObject.mockResolvedValue(legacy);
  render(<ImageDetails />);
  await waitFor(() => expect(valueFor('Last evaluated').textContent).toBe('Unknown'));
  expect(screen.getByText('CVE-1')).toBeTruthy();
});

it.each(['all', 'relevant', 'both', 'neither'] as const)(
  'fetches independently with %s reference missing',
  async missing => {
    const s = summary();
    if (missing === 'all' || missing === 'both') s.spec.vulnerabilitiesRef.all = undefined;
    if (missing === 'relevant' || missing === 'both')
      s.spec.vulnerabilitiesRef.relevant = undefined;
    mocks.request.mockImplementation(async (url: string) =>
      url.includes('summaries/') ? s : manifest()
    );
    const [, all, relevant] = await fetchVulnerabilityManifest(
      'workload-123',
      'workloads',
      'cluster-b'
    );
    expect(Boolean(all)).toBe(missing !== 'all' && missing !== 'both');
    expect(Boolean(relevant)).toBe(missing !== 'relevant' && missing !== 'both');
    expect(mocks.request).toHaveBeenCalledTimes(
      1 + Number(Boolean(all)) + Number(Boolean(relevant))
    );
    for (const [url, options] of mocks.request.mock.calls) {
      expect(options).toEqual({ cluster: 'cluster-b' });
      if (url.includes('/vulnerabilitymanifests/'))
        expect(url).not.toContain('/namespaces/workloads/');
    }
  }
);

it('reads a report from the operator namespace when it is not where the summary refers to', async () => {
  window.sessionStorage.clear();
  const s = summary();
  s.spec.vulnerabilitiesRef.all = {
    kind: 'vulnerabilitymanifests',
    name: 'image-123',
    namespace: 'workloads',
  };
  s.spec.vulnerabilitiesRef.relevant = undefined;
  mocks.request.mockImplementation(async (url: string) => {
    if (url.includes('summaries/')) return s;
    if (url.replace(/^\//, '').startsWith('api/v1/pods?'))
      return { items: [{ metadata: { namespace: 'kubescape' } }] };
    if (url.includes('/namespaces/kubescape/vulnerabilitymanifests/image-123')) return manifest(T2);
    throw Object.assign(new Error('not found'), { status: 404 });
  });

  const [, all] = await fetchVulnerabilityManifest('workload-123', 'workloads', 'cluster-a');

  expect(all?.metadata.name).toBe('image-123');
  expect(mocks.request.mock.calls.map(([url]) => url.split('?')[0])).toContain(
    '/apis/spdx.softwarecomposition.kubescape.io/v1beta1/namespaces/workloads/vulnerabilitymanifests/image-123'
  );
});

it('reads a report from the default namespace of Kubescape while the operator namespace is unknown', async () => {
  window.sessionStorage.clear();
  const s = summary();
  s.spec.vulnerabilitiesRef.all = {
    kind: 'vulnerabilitymanifests',
    name: 'image-123',
    namespace: 'workloads',
  };
  s.spec.vulnerabilitiesRef.relevant = undefined;
  mocks.request.mockImplementation(async (url: string) => {
    if (url.includes('summaries/')) return s;
    // a user who may not list pods, so the namespace of the operator cannot be looked up
    if (url.includes('/pods?')) throw Object.assign(new Error('forbidden'), { status: 403 });
    if (url.includes('/namespaces/kubescape/vulnerabilitymanifests/image-123')) return manifest(T2);
    throw Object.assign(new Error('not found'), { status: 404 });
  });

  // like the list of the workloads, which reads the report there too
  const [, all, , errors] = await fetchVulnerabilityManifest(
    'workload-123',
    'workloads',
    'cluster-a'
  );

  expect(all?.metadata.name).toBe('image-123');
  expect(errors).toEqual([]);
});

it.each(['all', 'relevant'] as const)(
  'renders the available date when the %s reference is absent',
  async missing => {
    const s = summary();
    s.spec.vulnerabilitiesRef[missing] = undefined;
    mocks.request.mockImplementation(async (url: string) =>
      url.includes('summaries/') ? s : manifest(T2)
    );
    render(<WorkloadDetails />);
    await waitFor(() =>
      expect(
        valueFor(missing === 'all' ? 'Relevant findings last evaluated' : 'Image last evaluated')
          .textContent
      ).toBe(T2)
    );
    expect(
      valueFor(missing === 'all' ? 'Image last evaluated' : 'Relevant findings last evaluated')
        .textContent
    ).toBe('Unknown');
  }
);

it('isolates failed reports and uses kubescape only for legacy references without namespaces', async () => {
  const s = summary();
  Reflect.deleteProperty(s.spec.vulnerabilitiesRef.all!, 'namespace');
  const error = vi.spyOn(console, 'error').mockImplementation(() => {});
  mocks.request.mockImplementation(async (url: string) => {
    if (url.includes('summaries/')) return s;
    if (url.endsWith('/image-123')) throw new Error('not found');
    return manifest(T2);
  });
  const [, all, relevant, errors] = await fetchVulnerabilityManifest(
    'workload-123',
    'workloads',
    'cluster-a'
  );
  expect(all).toBeNull();
  expect(relevant?.spec.metadata?.report?.createdAt).toBe(T2);
  // which report could not be read, and why, for the page to show
  expect(errors).toEqual(['the report of the image (image-123): not found']);
  expect(mocks.request.mock.calls[1][0]).toContain('/namespaces/kubescape/');
  expect(mocks.request.mock.calls[2][0]).toContain('/namespaces/relevant-reports/');
  error.mockRestore();
});

it('says why a report of a workload could not be read, instead of showing no findings', async () => {
  const error = vi.spyOn(console, 'error').mockImplementation(() => {});
  mocks.request.mockImplementation(async (url: string) => {
    if (url.includes('summaries/')) return summary();
    if (url.endsWith('/image-123')) {
      throw Object.assign(new Error('the storage timed out'), { status: 504 });
    }
    return manifest(T2);
  });
  render(<WorkloadDetails />);

  expect(
    await screen.findByText(
      'Unable to read the report of the image (image-123): the storage timed out'
    )
  ).toBeTruthy();
  // what the summary says is shown
  expect(valueFor('Workload').textContent).toBe('workload');
  expect(screen.queryByText('CVE-1')).toBeNull();
  error.mockRestore();
});

it('shows the findings of a report that has no source', async () => {
  const all = manifest();
  (all.spec.payload as { source: unknown }).source = null;
  mocks.request.mockImplementation(async (url: string) =>
    url.includes('summaries/') ? summary() : url.endsWith('/image-123') ? all : manifest(T2)
  );
  render(<WorkloadDetails />);

  expect(await screen.findByText('CVE-1')).toBeTruthy();
  expect(valueFor('Type').textContent).toBe('');
});

it('links a finding to its data source only when that is a web address', async () => {
  const report = manifest();
  report.spec.payload.matches = [match('CVE-1'), match('CVE-2')];
  // the address is what the report says, which could be a script
  report.spec.payload.matches[1].vulnerability.dataSource = 'javascript:alert(1)';
  const expectLinks = async () => {
    expect((await screen.findByText('CVE-1')).closest('a')?.getAttribute('href')).toBe(
      'https://example.com/cve'
    );
    expect(screen.getByText('CVE-2').closest('a')).toBeNull();
  };

  // the report of the image and of the relevant findings
  mocks.request.mockImplementation(async (url: string) =>
    url.includes('summaries/') ? summary() : report
  );
  const workload = render(<WorkloadDetails />);
  await expectLinks();
  workload.unmount();

  mocks.fetchObject.mockResolvedValue(report);
  render(<ImageDetails />);
  await expectLinks();
});

it('shows independent workload dates and preserves relevancy filtering and exception controls', async () => {
  const all = manifest();
  all.spec.payload.matches!.push(match('CVE-2'));
  mocks.request.mockImplementation(async (url: string) =>
    url.includes('summaries/') ? summary() : url.endsWith('/image-123') ? all : manifest(T2)
  );
  render(<WorkloadDetails />);
  await waitFor(() => expect(valueFor('Image last evaluated').textContent).toBe(T1));
  expect(valueFor('Relevant findings last evaluated').textContent).toBe(T2);
  expect(valueFor('Scan record created').textContent).toBe(T0);
  expect(screen.queryByText('CVE-2')).toBeNull();
  fireEvent.click(screen.getByRole('checkbox'));
  expect(screen.getByText('CVE-2')).toBeTruthy();
  fireEvent.click(screen.getAllByRole('button', { name: 'Create Vulnerability Exception' })[0]);
  expect(screen.getByText('Exception for CVE-1')).toBeTruthy();
});

it('shows a CVE of several packages as relevant only for the packages the relevant report has', async () => {
  // busybox, busybox-binsh and ssl_client share the busybox CVEs; the workload was only seen
  // to use two of them, which Kubescape counts as 2 relevant findings
  const all = manifest();
  all.spec.payload.matches = ['busybox', 'busybox-binsh', 'ssl_client'].map(name => ({
    ...match('CVE-1'),
    artifact: { name, version: '1.37.0' },
  }));
  const relevant = manifest(T2);
  relevant.spec.payload.matches = ['busybox', 'ssl_client'].map(name => ({
    ...match('CVE-1'),
    artifact: { name, version: '1.37.0' },
  }));
  mocks.request.mockImplementation(async (url: string) =>
    url.includes('summaries/') ? summary() : url.endsWith('/image-123') ? all : relevant
  );
  render(<WorkloadDetails />);
  await waitFor(() => expect(screen.getByText('ssl_client')).toBeTruthy());

  expect(screen.getByText('busybox')).toBeTruthy();
  expect(screen.queryByText('busybox-binsh')).toBeNull();

  // switched off, the other package is listed as not relevant
  fireEvent.click(screen.getByRole('checkbox'));
  const row = screen.getByText('busybox-binsh').closest('tr')!;
  expect(within(row).getByText('No')).toBeTruthy();
});

it('exports the findings that are shown as CSV', async () => {
  const all = manifest();
  all.spec.payload.matches!.push(match('CVE-2'));
  mocks.request.mockImplementation(async (url: string) =>
    url.includes('summaries/') ? summary() : url.endsWith('/image-123') ? all : manifest(T2)
  );
  render(<WorkloadDetails />);
  await waitFor(() => expect(screen.getByText('CVE-1')).toBeTruthy());

  fireEvent.click(screen.getByRole('button', { name: 'Export CSV' }));

  // the relevant findings, as the Relevant CVE switch is on
  const [content, fileName] = mocks.saveToFile.mock.calls[0];
  expect(fileName).toBe('kubescape-workloads-workload-cves.csv');
  expect(content.split('\r\n')).toEqual([
    'Severity,CVE,CVSS,Artifact,Version,Relevant,Fix,Fix in version,Exception,Description',
    'High,CVE-1,8,package,1.0,Yes,fixed,2.0,,test finding',
    '',
  ]);
});

// A SecurityException that accepts the risk of CVEs of the workload of the summary fixture
function acceptance(entries: { id: string; expiredOnFix?: boolean }[]) {
  return {
    kind: 'SecurityException',
    metadata: { name: 'accept-it', namespace: 'workloads' },
    spec: {
      author: 'alice',
      match: { resources: [{ kind: 'Deployment', name: 'workload' }] },
      vulnerabilities: entries.map(({ id, expiredOnFix }) => ({
        vulnerability: { id },
        status: 'affected',
        response: ['can_not_fix'],
        actionStatement: 'No fix upstream',
        expiredOnFix,
      })),
    },
  };
}

it('marks the findings that exceptions cover and lists those that kubevuln hid', async () => {
  const all = manifest();
  all.spec.payload.matches!.push(match('CVE-2'));
  all.spec.payload.ignoredMatches = [
    {
      ...match('CVE-3'),
      appliedIgnoreRules: [
        {
          vulnerability: 'CVE-3',
          'fix-state': 'not_affected',
          sourceKind: 'ClusterSecurityException',
          sourceName: 'clustersecurityexception//old',
        },
      ],
    },
  ];
  mocks.request.mockImplementation(async (url: string) => {
    if (url.endsWith('/clustersecurityexceptions') || url === '/api/v1/namespaces') {
      return { items: [] };
    }
    if (url.endsWith('/securityexceptions')) {
      // CVE-1 has a fix, which ends its exception
      return { items: [acceptance([{ id: 'CVE-1', expiredOnFix: true }, { id: 'CVE-2' }])] };
    }
    return url.includes('summaries/') ? summary() : url.endsWith('/image-123') ? all : manifest(T2);
  });
  render(<WorkloadDetails />);
  await waitFor(() => expect(screen.getByText('CVE-1')).toBeTruthy());
  // all findings, also those that are not relevant
  fireEvent.click(screen.getByRole('checkbox'));
  await waitFor(() => expect(screen.getByText('Accepted')).toBeTruthy());
  expect(screen.getByText('Not affected')).toBeTruthy();

  fireEvent.click(screen.getByRole('button', { name: 'Export CSV' }));
  expect(mocks.saveToFile.mock.calls[0][0].split('\r\n').slice(1, 4)).toEqual([
    'High,CVE-1,8,package,1.0,Yes,fixed,2.0,,test finding',
    'High,CVE-2,8,package,1.0,No,fixed,2.0,Accepted: accept-it,test finding',
    'High,CVE-3,8,package,1.0,No,fixed,2.0,Not affected: old,test finding',
  ]);
});

it('counts the accepted CVEs of a resource and accepts the risk of the others', async () => {
  mocks.request.mockImplementation(async (url: string, options: { cluster?: string }) =>
    url.endsWith('/securityexceptions') && options.cluster === 'cluster-a'
      ? { items: [acceptance([{ id: 'CVE-2' }])] }
      : { items: [] }
  );
  const image = toImageScan(manifest());
  image.matches = [match('CVE-1'), match('CVE-2')];
  render(
    <ResourceList
      workloadScans={[toWorkloadScan(summary(), new Map([[getImageScanKey(image), image]]))]}
    />
  );
  expect(await screen.findByText('1 accepted')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Accept the risk of the open CVE' }));
  expect(screen.getByText('Accept risk of CVE-1')).toBeTruthy();
});

it('accepts the risk of the open CVEs of a workload from its page', async () => {
  const all = manifest();
  all.spec.payload.matches!.push(match('CVE-2'), match('CVE-3'));
  mocks.request.mockImplementation(async (url: string) => {
    if (url.endsWith('/clustersecurityexceptions') || url === '/api/v1/namespaces') {
      return { items: [] };
    }
    if (url.endsWith('/securityexceptions')) return { items: [acceptance([{ id: 'CVE-2' }])] };
    return url.includes('summaries/') ? summary() : url.endsWith('/image-123') ? all : manifest(T2);
  });
  render(<WorkloadDetails />);

  fireEvent.click(
    await screen.findByRole('button', { name: 'Accept the risk of the 2 open CVEs' })
  );
  expect(screen.getByText('Accept risk of CVE-1, CVE-3')).toBeTruthy();
});

it('accepts the risk of the open CVEs of an image in the whole cluster from its page', async () => {
  const imageException = (name: string, match: object) => ({
    kind: 'ClusterSecurityException',
    metadata: { name },
    spec: {
      match,
      vulnerabilities: [
        {
          vulnerability: { id: 'CVE-2' },
          status: 'affected',
          response: ['will_not_fix'],
          actionStatement: 'Replaced next quarter',
        },
      ],
    },
  });
  mocks.request.mockImplementation(async (url: string) =>
    url.endsWith('/clustersecurityexceptions')
      ? {
          items: [
            imageException('example-everywhere', { images: ['example:*'] }),
            // limited to a workload, so not for the image wherever it runs
            imageException('example-in-one-workload', {
              images: ['example:latest'],
              resources: [{ kind: 'Deployment', name: 'workload' }],
            }),
          ],
        }
      : { items: [] }
  );
  const report = manifest();
  report.spec.payload.matches = [match('CVE-1'), match('CVE-2')];
  mocks.fetchObject.mockResolvedValue(report);
  render(<ImageDetails />);

  expect(await screen.findByText('Accepted')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Accept the risk of the open CVE' }));
  expect(screen.getByText('Accept risk of CVE-1')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Export CSV' }));
  expect(mocks.saveToFile.mock.calls[0][0].split('\r\n').slice(0, 3)).toEqual([
    'Image,Severity,CVE,CVSS,Artifact,Version,Fix,Fix in version,Exception,Description',
    'example:latest,High,CVE-1,8,package,1.0,fixed,2.0,,test finding',
    'example:latest,High,CVE-2,8,package,1.0,fixed,2.0,Accepted: example-everywhere,test finding',
  ]);
});

it('shows no relevant findings when the relevant manifest has no matches', async () => {
  const relevant = manifest(T2);
  relevant.spec.payload.matches = null;
  mocks.request.mockImplementation(async (url: string) =>
    url.includes('summaries/') ? summary() : url.endsWith('/image-123') ? manifest() : relevant
  );
  render(<WorkloadDetails />);
  await waitFor(() => expect(valueFor('Relevant findings last evaluated').textContent).toBe(T2));
  expect(screen.queryByText('CVE-1')).toBeNull();
  expect(screen.getByText(/None of the 1 findings is relevant/)).toBeTruthy();
  // the switch stays, although the table without rows shows no toolbar
  fireEvent.click(screen.getByRole('checkbox'));
  expect(screen.getByText('CVE-1')).toBeTruthy();
});

it.each([
  { search: '?filtered', filtered: true },
  { search: '', filtered: false },
])(
  'reads the SBOM choice from the router location, which may differ from window.location ($search)',
  ({ search, filtered }) => {
    render(
      <MemoryRouter initialEntries={[`/sbom/relevant-reports/relevant-123${search}`]}>
        <SBOMDetail />
      </MemoryRouter>
    );
    expect(window.location.search).toBe('');
    expect(mocks.fetchObject).toHaveBeenCalledTimes(1);
    expect(mocks.fetchObject.mock.calls[0][3]).toEqual({
      pluralName: filtered ? 'sbomsyftfiltereds' : 'sbomsyfts',
    });
    expect(screen.getByText('Reading the SBOM…')).toBeTruthy();
  }
);

it('shows an SBOM without artifacts', async () => {
  const noPackagesInUse = {
    metadata: { annotations: { 'kubescape.io/image-tag': 'example:latest' } },
    spec: {
      metadata: { report: { createdAt: T1 } },
      syft: { distro: { name: 'debian' }, artifacts: null },
    },
  };
  mocks.fetchObject.mockResolvedValue(noPackagesInUse);
  render(
    <MemoryRouter initialEntries={['/sbom/relevant-reports/relevant-123?filtered']}>
      <SBOMDetail />
    </MemoryRouter>
  );
  expect(await screen.findByText('Showing in use artifacts only')).toBeTruthy();
  expect(valueFor('Components').textContent).toBe('0');
});

it('downloads the SBOM as Syft JSON, CycloneDX and a CSV of its packages', async () => {
  mocks.fetchObject.mockResolvedValue(sbom());
  render(
    <MemoryRouter initialEntries={['/sbom/kubescape/docker.io-velero-velero-v1.18.1-b55b90']}>
      <SBOMDetail />
    </MemoryRouter>
  );

  fireEvent.click(await screen.findByRole('button', { name: 'Download Syft JSON' }));
  expect(valueFor('Distro').textContent).toBe('Ubuntu 22.04.5 LTS');
  expect(valueFor('Components').textContent).toBe('2');
  fireEvent.click(screen.getByRole('button', { name: 'Download CycloneDX' }));
  fireEvent.click(screen.getByRole('button', { name: 'Export CSV' }));

  const [syft, cycloneDx, csv] = mocks.saveToFile.mock.calls;
  expect(syft[1]).toBe('docker.io-velero-velero-v1.18.1-b55b90.syft.json');
  expect(JSON.parse(syft[0]).artifacts).toHaveLength(2);
  expect(cycloneDx[1]).toBe('docker.io-velero-velero-v1.18.1-b55b90.cdx.json');
  expect(JSON.parse(cycloneDx[0]).bomFormat).toBe('CycloneDX');
  expect(csv[1]).toBe('docker.io-velero-velero-v1.18.1-b55b90-packages.csv');
  expect(csv[0]).toContain(
    'pkg:golang/golang.org/x/net@v0.38.0,golang.org/x/net,v0.38.0,go-module,'
  );
});

it('updates a mounted workload view on a new fetch and drops previous-cluster results', async () => {
  mocks.request.mockImplementation(async (url: string) =>
    url.includes('summaries/') ? summary() : manifest(mocks.cluster === 'cluster-a' ? T1 : T2)
  );
  const view = render(<WorkloadDetails />);
  await waitFor(() => expect(valueFor('Image last evaluated').textContent).toBe(T1));
  mocks.cluster = 'cluster-b';
  view.rerender(<WorkloadDetails />);
  await waitFor(() => expect(valueFor('Image last evaluated').textContent).toBe(T2));
  expect(valueFor('Scan record created').textContent).toBe(T0);
  const scanCalls = mocks.request.mock.calls.filter(call =>
    call[0].includes('softwarecomposition')
  );
  expect(scanCalls.slice(3).every(call => call[1].cluster === 'cluster-b')).toBe(true);
});

it('keeps colliding image records separate and associates only their own workloads and links', () => {
  const a = toImageScan(manifest());
  a.imageName = 'image-a';
  const b = { ...a, cluster: 'cluster-b', imageName: 'image-b', reportCreatedAt: T2 };
  const c = { ...a, namespace: 'other-reports', imageName: 'image-c' };
  const workloads = [a, b, c].map(
    (imageScan, i) => ({ imageScan, name: `workload-${i}`, container: 'app' } as WorkloadScan)
  );
  render(<ImageList workloadScans={workloads} />);
  expect(screen.getByText('3 image scans')).toBeTruthy();
  for (const [i, image] of [a, b, c].entries()) {
    const row = screen.getByText(image.imageName).closest('tr')!;
    expect(row.textContent).toContain(`workload-${i}/app`);
    expect(row.textContent).not.toContain(`workload-${(i + 1) % 3}/app`);
    expect(within(row).getByText(image.imageName).getAttribute('href')).toBe(
      `/${image.cluster}/image/${image.namespace}/${image.manifestName}`
    );
  }
});

it('resolves full manifests by cluster and reference namespace', () => {
  const images = new Map();
  const workloads = [];
  for (const cluster of ['cluster-a', 'cluster-b']) {
    const report = manifest(cluster === 'cluster-a' ? T1 : T2);
    report.metadata.cluster = cluster;
    const other = manifest();
    other.metadata = { ...report.metadata, namespace: 'elsewhere' };
    for (const item of [report, other]) {
      const scan = toImageScan(item);
      images.set(getImageScanKey(scan), scan);
    }
    const s = summary();
    s.metadata.cluster = cluster;
    s.spec.vulnerabilitiesRef.relevant = {
      kind: 'VulnerabilityManifest',
      namespace: 'elsewhere',
      name: report.metadata.name,
    };
    workloads.push(toWorkloadScan(s, images));
  }
  expect(images.size).toBe(4);
  expect(workloads.map(w => w.imageScan?.reportCreatedAt)).toEqual([T1, T2]);
  expect(workloads.every(w => w.relevant?.namespace === 'elsewhere')).toBe(true);
});

it.each(['removed', 'namespaces changed'])('invalidates only affected clusters when %s', reason => {
  const context: VulnerabilityContext = {
    imageScans: new Map(),
    workloadScans: [],
    queryTasks: [],
  };
  for (const cluster of ['cluster-a', 'cluster-b', 'cluster-c']) {
    const report = manifest();
    report.metadata.cluster = cluster;
    const image = toImageScan(report);
    context.imageScans.set(getImageScanKey(image), image);
    context.workloadScans.push({ cluster } as WorkloadScan);
    // Each cluster has a manifest query and a summary query.
    for (let i = 0; i < 2; i++)
      context.queryTasks.push({ cluster } as VulnerabilityContext['queryTasks'][number]);
  }
  const keep = context.queryTasks.filter(task => task.cluster === 'cluster-b');
  invalidateScanClusters(
    context,
    reason === 'removed' ? ['cluster-b'] : ['cluster-a', 'cluster-b', 'cluster-c'],
    task => reason === 'namespaces changed' && task.cluster !== 'cluster-b'
  );
  expect([...context.imageScans.values()].map(image => image.cluster)).toEqual(['cluster-b']);
  expect(context.workloadScans.map(w => w.cluster)).toEqual(['cluster-b']);
  expect(context.queryTasks).toEqual(keep);
});

it('retains legacy workload findings and shows Unknown for both evaluation times', async () => {
  const legacy = manifest();
  delete legacy.spec.metadata;
  mocks.request.mockImplementation(async (url: string) =>
    url.includes('summaries/') ? summary() : legacy
  );
  render(<WorkloadDetails />);
  await waitFor(() => expect(valueFor('Image last evaluated').textContent).toBe('Unknown'));
  expect(valueFor('Relevant findings last evaluated').textContent).toBe('Unknown');
  expect(valueFor('Scan record created').textContent).toBe(T0);
  expect(screen.getByText('CVE-1')).toBeTruthy();
});

it('shows when kubevuln scanned, where its reports have no evaluation time', async () => {
  const s = summary();
  s.metadata.annotations = { ...s.metadata.annotations, 'kubescape.io/timestamp': '1793384272' };
  mocks.request.mockImplementation(async (url: string) =>
    url.includes('summaries/') ? s : manifest(null)
  );
  render(<WorkloadDetails />);

  await waitFor(() =>
    expect(valueFor('Last scanned').textContent).toBe('2026-10-30T18:17:52.000Z')
  );
  expect(screen.queryByText('Image last evaluated')).toBeNull();
  expect(screen.queryByText('Relevant findings last evaluated')).toBeNull();
});

it('skips empty references and missing reference containers without fetching reports', async () => {
  const s = summary();
  s.spec.vulnerabilitiesRef.all!.name = '';
  s.spec.vulnerabilitiesRef.relevant!.name = '';
  mocks.request.mockResolvedValue(s);
  // no reports, and nothing that could not be read
  expect((await fetchVulnerabilityManifest('workload-123', 'workloads')).slice(1)).toEqual([
    null,
    null,
    [],
  ]);
  expect(mocks.request).toHaveBeenCalledTimes(1);
  Reflect.deleteProperty(s.spec, 'vulnerabilitiesRef');
  mocks.request.mockClear();
  expect((await fetchVulnerabilityManifest('workload-123', 'workloads')).slice(1)).toEqual([
    null,
    null,
    [],
  ]);
  expect(mocks.request).toHaveBeenCalledTimes(1);
});

it('keeps workload navigation on the source cluster and uses the relevant SBOM namespace', async () => {
  // no exceptions
  mocks.request.mockResolvedValue({ items: [] });
  const s = summary();
  s.metadata.cluster = 'cluster-b';
  const image = toImageScan(manifest());
  image.cluster = 'cluster-b';
  const relevant = { ...image, manifestName: 'relevant-123', namespace: 'relevant-reports' };
  const images = new Map([image, relevant].map(scan => [getImageScanKey(scan), scan]));
  render(<ResourceList workloadScans={[toWorkloadScan(s, images)]} />);
  // the exceptions are read
  await act(async () => {});
  expect(screen.queryByText(/Unable to read the security exceptions/)).toBeNull();
  expect(screen.getByText('workload').getAttribute('href')).toBe(
    '/cluster-b/workload/workloads/workload-123'
  );
  expect(screen.getByText('SBOM').getAttribute('href')).toBe(
    '/cluster-b/sbom/relevant-reports/relevant-123?filtered'
  );
  expect(screen.getByLabelText('1 High findings').getAttribute('href')).toBe(
    '/cluster-b/workload/workloads/workload-123?severity=High'
  );
});

it('counts a finding that an exception hid from the relevant report as relevant, like the page of the workload', async () => {
  // no exceptions are read here; kubevuln applied one when it scanned the workload
  mocks.request.mockResolvedValue({ items: [] });
  const image = toImageScan(manifest());
  image.matches = [match('CVE-1'), match('CVE-2')];
  const relevant = {
    ...image,
    manifestName: 'relevant-123',
    namespace: 'relevant-reports',
    matches: [match('CVE-1')],
    // the report of the image is shared with a workload without the exception
    ignoredMatches: [match('CVE-2')],
  };
  const images = new Map([image, relevant].map(scan => [getImageScanKey(scan), scan]));
  render(<ResourceList workloadScans={[toWorkloadScan(summary(), images)]} />);
  await act(async () => {});

  expect(screen.getByText('2 of 2')).toBeTruthy();
});

// the column of the table that was drawn last, by its id or header
function column(name: string) {
  return mocks.columns.find(found => (found.id ?? found.header) === name);
}

it('sorts the counts of workloads and images by their numbers, in a table of any size', async () => {
  mocks.request.mockResolvedValue({ items: [] });
  const image = toImageScan(manifest());
  const scans = [toWorkloadScan(summary(), new Map([[getImageScanKey(image), image]]))];
  const resources = render(<ResourceList workloadScans={scans} />);
  await act(async () => {});
  // Headlamp's table picks how to sort a column from the rows after the tenth, so that ten rows
  // or fewer would sort these counts as text: 9 findings above 12
  expect(column('CVE').sortingFn).toBe('alphanumeric');
  expect(column('Relevant').sortingFn).toBe('alphanumeric');
  resources.unmount();

  render(<ImageList workloadScans={scans} />);
  expect(column('Vulnerabilities').sortingFn).toBe('alphanumeric');
  // as text, which puts the lines without an announced end after the dated ones; by the numbers
  // in the values, as the table sorts more than ten rows by itself, they would come first
  expect(column('End of life').sortingFn).toBe('basic');
});

it('links the SBOM of a workload whose relevant report is read before the report of its image', async () => {
  mocks.request.mockResolvedValue({ items: [] });
  const image = toImageScan(manifest());
  const relevant = { ...image, manifestName: 'relevant-123', namespace: 'relevant-reports' };
  const scan = toWorkloadScan(summary(), new Map([[getImageScanKey(relevant), relevant]]));
  expect(scan.imageScan).toBeUndefined();
  render(<ResourceList workloadScans={[scan]} />);
  await act(async () => {});

  // the value of the cell names the relevant report, and stays the same when the report of the
  // image arrives, so Headlamp does not draw the cell again: the link has to be there by now
  expect(column('SBOM').accessorFn(scan)).toBe('relevant-123');
  expect(screen.getByText('SBOM').getAttribute('href')).toBe(
    '/cluster-a/sbom/relevant-reports/relevant-123?filtered'
  );
});

it('gives the image of a workload as text before its report is read, so the table searches it', async () => {
  mocks.request.mockResolvedValue({ items: [] });
  const reading = toWorkloadScan(summary(), new Map());
  render(<ResourceList workloadScans={[reading]} />);
  await act(async () => {});

  // Headlamp's table leaves a column out of its search when its value in the first row is
  // neither text nor a number
  expect(column('Image').accessorFn(reading)).toBe('');
});

it('has a column for the cluster only when several are selected, and no empty one otherwise', async () => {
  mocks.request.mockResolvedValue({ items: [] });
  const scans = [toWorkloadScan(summary(), new Map())];
  const headers = () => mocks.columns.map(found => found.header);
  const several = render(<ResourceList workloadScans={scans} />);
  await act(async () => {});
  expect(headers().slice(3, 6)).toEqual(['Namespace', 'Cluster', 'Image']);
  several.unmount();

  mocks.clusters = ['cluster-a'];
  render(<ResourceList workloadScans={scans} />);
  await act(async () => {});
  // the last column, of the action, has no title
  expect(headers()).toEqual([
    'Name',
    'Container',
    'Kind',
    'Namespace',
    'Image',
    'CVE',
    'Relevant',
    'Accepted',
    'SBOM',
    '',
  ]);
});

it('shows a whole EPSS percentile as it is', () => {
  // a hundred times 0.29 is 28.999999999999996
  expect([0.29, 0.57, 0.58].map(formatPercentile)).toEqual(['29th', '57th', '58th']);
});

// a workload with the CVE, for the page of a CVE
function scanWith(cluster: string, name: string, dataSource?: string): WorkloadScan {
  const image = toImageScan(manifest());
  image.cluster = cluster;
  if (dataSource) image.matches[0].vulnerability.dataSource = dataSource;
  const s = summary();
  s.metadata.cluster = cluster;
  s.metadata.labels['kubescape.io/workload-name'] = name;
  return toWorkloadScan(s, new Map([[getImageScanKey(image), image]]));
}

it('lists the workloads with a CVE of the selected clusters only, also before they are read', async () => {
  mocks.name = 'CVE-1';
  mocks.clusters = ['cluster-a'];
  // the cache of the other pages still has the scans of a cluster that is no longer selected
  mocks.context.workloadScans = [scanWith('cluster-a', 'web'), scanWith('cluster-old', 'left')];
  // still reading
  mocks.readVulnerabilityScans.mockReturnValue(new Promise(() => {}));
  render(<KubescapeCVEResults />);

  expect(await screen.findByText('web')).toBeTruthy();
  expect(screen.queryByText('left')).toBeNull();
  expect(valueFor('CVE ID').querySelector('a')?.getAttribute('href')).toBe(
    'https://example.com/cve'
  );
});

it('drops the workloads and the error of the clusters that are no longer selected from the page of a CVE', async () => {
  mocks.name = 'CVE-1';
  mocks.clusters = ['cluster-a', 'cluster-b'];
  mocks.readVulnerabilityScans.mockResolvedValue([
    scanWith('cluster-a', 'web'),
    scanWith('cluster-b', 'api'),
  ]);
  const view = render(<KubescapeCVEResults />);
  expect(await screen.findByText('web')).toBeTruthy();
  expect(screen.getByText('api')).toBeTruthy();

  // cluster-a is deselected: its workload goes at once, and the read of cluster-b fails
  mocks.clusters = ['cluster-b'];
  mocks.readVulnerabilityScans.mockRejectedValue(new Error('forbidden'));
  view.rerender(<KubescapeCVEResults />);
  expect(
    await screen.findByText('Unable to read the vulnerability reports: forbidden')
  ).toBeTruthy();
  expect(screen.queryByText('web')).toBeNull();
  expect(screen.getByText('api')).toBeTruthy();

  // cluster-a is selected again and read: the error of the read before is not shown for it
  mocks.clusters = ['cluster-a', 'cluster-b'];
  mocks.readVulnerabilityScans.mockResolvedValue([
    scanWith('cluster-a', 'web'),
    scanWith('cluster-b', 'api'),
  ]);
  view.rerender(<KubescapeCVEResults />);
  expect(await screen.findByText('web')).toBeTruthy();
  expect(screen.queryByText(/Unable to read the vulnerability reports/)).toBeNull();
});

it('names a CVE whose report gives a script as its source without a link', async () => {
  mocks.name = 'CVE-1';
  mocks.clusters = ['cluster-a'];
  mocks.readVulnerabilityScans.mockResolvedValue([
    scanWith('cluster-a', 'web', 'javascript:alert(1)'),
  ]);
  render(<KubescapeCVEResults />);

  expect(await screen.findByText('web')).toBeTruthy();
  expect(valueFor('CVE ID').textContent).toBe('CVE-1');
  expect(valueFor('CVE ID').querySelector('a')).toBeNull();
});

it('links image severity counts to the findings of that severity', () => {
  const image = toImageScan(manifest());
  image.matches = [match('CVE-1'), match('CVE-2')];
  image.matches[1].vulnerability.severity = 'Critical';
  const s = summary();
  render(
    <ImageList workloadScans={[toWorkloadScan(s, new Map([[getImageScanKey(image), image]]))]} />
  );
  expect(screen.getByLabelText('1 High findings').getAttribute('href')).toBe(
    '/cluster-a/image/reports/image-123?severity=High'
  );
  expect(screen.getByLabelText('0 Low findings').getAttribute('href')).toBe(
    '/cluster-a/image/reports/image-123?severity=Low'
  );
});

it('shows only findings of the linked severity, including irrelevant ones', async () => {
  const all = manifest();
  all.spec.payload.matches = [match('CVE-1'), match('CVE-2')];
  all.spec.payload.matches[1].vulnerability.severity = 'Low';
  mocks.severity = 'Low';
  mocks.request.mockImplementation(async (url: string) =>
    url.includes('summaries/') ? summary() : url.endsWith('/image-123') ? all : manifest(T2)
  );
  render(<WorkloadDetails />);
  // CVE-2 is not in the relevant manifest, so the Relevant CVE switch must start off
  await waitFor(() => expect(screen.getByText('CVE-2')).toBeTruthy());
  expect(screen.queryByText('CVE-1')).toBeNull();
  expect(screen.getByText('Only Low findings')).toBeTruthy();
  expect((screen.getByRole('checkbox') as HTMLInputElement).checked).toBe(false);
});

it('filters image findings by the linked severity', async () => {
  mocks.severity = 'Critical';
  const report = manifest();
  report.spec.payload.matches = [match('CVE-1'), match('CVE-2')];
  report.spec.payload.matches[1].vulnerability.severity = 'Critical';
  mocks.fetchObject.mockResolvedValue(report);
  render(<ImageDetails />);
  expect(await screen.findByText('CVE-2')).toBeTruthy();
  expect(screen.queryByText('CVE-1')).toBeNull();
});

it('lists the workloads that run the image, with when it was last scanned', async () => {
  mocks.request.mockImplementation(async (url: string) => ({
    items: url.includes('vulnerabilitymanifestsummaries?labelSelector=')
      ? [
          {
            metadata: {
              name: 'deployment-ci-ci',
              namespace: 'ci',
              labels: {
                'kubescape.io/workload-kind': 'deployment',
                'kubescape.io/workload-name': 'ci',
                'kubescape.io/workload-namespace': 'ci',
                'kubescape.io/workload-container-name': 'server',
              },
              annotations: { 'kubescape.io/timestamp': '1793384272' },
            },
          },
        ]
      : [],
  }));
  const report = manifest(null);
  report.metadata.labels = { 'kubescape.io/image-id': 'docker-io-ci-sha256-e62c' };
  mocks.fetchObject.mockResolvedValue(report);
  render(<ImageDetails />);

  const workload = await screen.findByText('ci', { selector: 'a' });
  expect(workload.getAttribute('href')).toBe('/cluster-a/deployment/ci/ci');
  expect(screen.getByText('Findings', { selector: 'a' }).getAttribute('href')).toBe(
    '/cluster-a/workload/ci/deployment-ci-ci'
  );
  expect(screen.getByText('server')).toBeTruthy();
  expect(mocks.request.mock.calls.map(([url]) => decodeURIComponent(url))).toContainEqual(
    expect.stringContaining('labelSelector=kubescape.io/image-id=docker-io-ci-sha256-e62c')
  );
  expect(valueFor('Last scanned').textContent).toBe('2026-10-30T18:17:52.000Z');
});

it('names the namespaces whose workloads of the image could not be read', async () => {
  mocks.allowedNamespaces = ['ci', 'secret'];
  mocks.request.mockImplementation(async (url: string) => {
    if (url.includes('/namespaces/secret/')) throw new Error('forbidden');
    return { items: [] };
  });
  const report = manifest(null);
  report.metadata.labels = { 'kubescape.io/image-id': 'docker-io-ci-sha256-e62c' };
  mocks.fetchObject.mockResolvedValue(report);
  render(<ImageDetails />);

  expect(
    await screen.findByText(
      'Unable to read all workloads that run the image: namespace secret: forbidden'
    )
  ).toBeTruthy();
  // the image may run in the namespace that could not be read
  expect(
    screen.getByText('No workload of the namespaces that could be read runs this image.')
  ).toBeTruthy();
  expect(screen.queryByText('No workload runs this image anymore.')).toBeNull();
});

it('links the image of a workload to its page and to the tags in its registry', async () => {
  mocks.request.mockImplementation(async (url: string) =>
    url.includes('summaries/') ? summary() : manifest()
  );
  render(<WorkloadDetails />);
  const image = await screen.findByText('example:latest', { selector: 'a' });
  expect(image.getAttribute('href')).toBe('/cluster-a/image/reports/image-123');
  expect(screen.getByRole('link', { name: /Docker Hub/ }).getAttribute('href')).toBe(
    'https://hub.docker.com/_/example/tags'
  );
});

it('shows the newest version of the image of a workload and the end of its release line', async () => {
  mocks.lookupImageVersion.mockResolvedValue({
    latest: { latest: '2.0.1', source: { name: 'GitHub', url: 'https://github.com/o/r/releases' } },
    line: {
      product: 'example',
      name: '1',
      latest: '1.9.0',
      eol: true,
      eolFrom: '2025-01-31',
      url: 'https://endoflife.date/example',
    },
  });
  const workload = summary();
  workload.metadata.annotations['kubescape.io/image-tag'] = 'example:1.2.3';
  mocks.request.mockImplementation(async (url: string) =>
    url.includes('summaries/') ? workload : manifest()
  );
  render(<WorkloadDetails />);

  await waitFor(() => expect(valueFor('Latest version').textContent).toContain('2.0.1'));
  expect(mocks.lookupImageVersion).toHaveBeenCalledWith('example:1.2.3', {
    latest: true,
    endOfLife: true,
    possiblyPrivate: undefined,
  });
  expect(valueFor('Latest version').textContent).toContain(
    'GitHub has 2.0.1, which is newer than 1.2.3. The newest of 1 is 1.9.0.'
  );
  expect(
    within(valueFor('Latest version') as HTMLElement)
      .getByRole('link')
      .getAttribute('href')
  ).toBe('https://github.com/o/r/releases');
  expect(valueFor('End of life').textContent).toContain('Ended 2025-01-31');
  expect(valueFor('End of life').textContent).toContain(
    'example 1 reached its end of life on 2025-01-31 and gets no more fixes.'
  );
});

it('offers a rescan only for workloads whose scan names the workload', async () => {
  const withWlid = summary();
  withWlid.metadata.annotations['kubescape.io/wlid'] =
    'wlid://cluster-prod/namespace-workloads/deployment-workload';
  mocks.request.mockImplementation(async (url: string) =>
    url.includes('summaries/') ? withWlid : manifest()
  );
  const view = render(<WorkloadDetails />);
  expect(await screen.findByRole('button', { name: 'Rescan' })).toBeTruthy();
  view.unmount();

  mocks.request.mockImplementation(async (url: string) =>
    url.includes('summaries/') ? summary() : manifest()
  );
  render(<WorkloadDetails />);
  await waitFor(() => expect(valueFor('Image last evaluated').textContent).toBe(T1));
  expect(screen.queryByRole('button', { name: 'Rescan' })).toBeNull();
});

it('shows the findings without a CVSS score of a workload as scored 0', async () => {
  const all = manifest();
  all.spec.payload.matches = [match('CVE-1'), unscoredMatch('CVE-2')];
  const relevant = manifest(T2);
  relevant.spec.payload.matches = [match('CVE-1'), unscoredMatch('CVE-2')];
  mocks.request.mockImplementation(async (url: string) =>
    url.includes('summaries/') ? summary() : url.endsWith('/image-123') ? all : relevant
  );
  render(<WorkloadDetails />);

  const row = (await screen.findByText('CVE-2')).closest('tr')!;
  expect(within(row).getByText('0')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Export CSV' }));
  // no score to export
  expect(mocks.saveToFile.mock.calls[0][0].split('\r\n')).toContain(
    'High,CVE-2,,package,1.0,Yes,fixed,2.0,,test finding'
  );
});

it('shows the findings without a CVSS score of an image as scored 0', async () => {
  const report = manifest();
  report.spec.payload.matches = [unscoredMatch('CVE-2')];
  mocks.fetchObject.mockResolvedValue(report);
  render(<ImageDetails />);

  const row = (await screen.findByText('CVE-2')).closest('tr')!;
  expect(within(row).getByText('0')).toBeTruthy();
});

it('forgets the workloads of the image shown before', async () => {
  mocks.request.mockImplementation(async (url: string) => {
    const selector = decodeURIComponent(url);
    if (selector.includes('kubescape.io/image-id=image-a')) {
      return {
        items: [
          {
            metadata: {
              name: 'deployment-ci-ci',
              namespace: 'ci',
              labels: {
                'kubescape.io/workload-kind': 'deployment',
                'kubescape.io/workload-name': 'ci',
                'kubescape.io/workload-namespace': 'ci',
                'kubescape.io/workload-container-name': 'server',
              },
            },
          },
        ],
      };
    }
    // still being read
    if (selector.includes('kubescape.io/image-id=image-b')) return new Promise(() => {});
    if (selector.includes('kubescape.io/image-id=image-c')) throw new Error('forbidden');
    return { items: [] };
  });
  // the report of the image of the URL, whose name is its image id here
  mocks.fetchObject.mockImplementation(async (name: string) => {
    const found = manifest();
    found.metadata.labels = { 'kubescape.io/image-id': name };
    return found;
  });
  const show = (imageId: string) => {
    mocks.name = imageId;
    view.rerender(<ImageDetails />);
  };
  mocks.name = 'image-a';
  const view = render(<ImageDetails />);
  expect(await screen.findByText('ci', { selector: 'a' })).toBeTruthy();

  // another image: its workloads are being read
  show('image-b');
  expect(await screen.findByText('Reading workloads…')).toBeTruthy();
  expect(screen.queryByText('ci', { selector: 'a' })).toBeNull();

  // the error of one image is not shown for the next
  show('image-c');
  expect(await screen.findByText(/Unable to read the workloads that run the image/)).toBeTruthy();
  show('image-a');
  expect(await screen.findByText('ci', { selector: 'a' })).toBeTruthy();
  expect(screen.queryByText(/Unable to read the workloads that run the image/)).toBeNull();
});

it('opens the exception forms for a user who may not create exceptions, as they offer YAML', async () => {
  const all = manifest();
  all.spec.payload.matches!.push(match('CVE-2'));
  mocks.request.mockImplementation(async (url: string) => {
    if (url.endsWith('securityexceptions') || url === '/api/v1/namespaces') return { items: [] };
    return url.includes('summaries/') ? summary() : url.endsWith('/image-123') ? all : manifest(T2);
  });
  render(<WorkloadDetails />);

  const accept = await screen.findByRole('button', { name: 'Accept the risk of the 2 open CVEs' });
  const create = screen.getAllByRole('button', { name: 'Create Vulnerability Exception' })[0];
  expect((accept as HTMLButtonElement).disabled).toBe(false);
  expect((create as HTMLButtonElement).disabled).toBe(false);
  fireEvent.click(create);
  expect(screen.getByText('Exception for CVE-1')).toBeTruthy();
  fireEvent.click(accept);
  expect(screen.getByText('Accept risk of CVE-1, CVE-2')).toBeTruthy();
  // the forms check the permission to create the exception themselves
  expect(mocks.post).not.toHaveBeenCalled();
});

it('reads the vulnerability summary of a namespace once, as the storage cannot watch it', async () => {
  mocks.name = 'shop';
  mocks.fetchObject.mockResolvedValue({
    metadata: { name: 'shop' },
    spec: {
      vulnerabilitiesRef: [
        { kind: 'VulnerabilityManifestSummary', name: 'deployment-web-nginx', namespace: 'shop' },
      ],
    },
  });
  render(<VulnerabilitiesNamespaceSummary />);
  expect(screen.getByText('Reading the vulnerability summary of the namespace…')).toBeTruthy();

  const workload = await screen.findByText('web-nginx', { selector: 'a' });
  expect(workload.getAttribute('href')).toContain('/workload/shop/deployment-web-nginx');
  expect(screen.getByText('Deployment')).toBeTruthy();
  expect(mocks.fetchObject).toHaveBeenCalledTimes(1);
  expect(mocks.fetchObject).toHaveBeenCalledWith('shop', '', 'cluster-a', {
    pluralName: 'vulnerabilitysummaries',
  });
});

it('says why the vulnerability summary of a namespace could not be read', async () => {
  mocks.name = 'empty';
  mocks.fetchObject.mockRejectedValue({ status: 404, message: 'vulnerabilitysummaries not found' });
  render(<VulnerabilitiesNamespaceSummary />);
  expect(await screen.findByText('Resource not found')).toBeTruthy();
  expect(screen.getByText('vulnerabilitysummaries not found')).toBeTruthy();
});

it('names the distribution of an image with its version', () => {
  expect(
    distroLabel({
      id: 'debian',
      name: 'Debian GNU/Linux',
      prettyName: 'Debian GNU/Linux 11 (bullseye)',
    })
  ).toBe('Debian GNU/Linux 11 (bullseye)');
  expect(distroLabel({ id: 'alpine', name: 'Alpine Linux', versionID: '3.19.1' })).toBe(
    'Alpine Linux 3.19.1'
  );
  // a distroless image
  expect(distroLabel({})).toBe('');
  expect(distroLabel(undefined)).toBe('');
});
