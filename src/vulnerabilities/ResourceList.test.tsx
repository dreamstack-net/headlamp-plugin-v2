// Renders the Resources tab in Headlamp's real table, which only draws a cell again when its
// value changes
import { lightTheme } from '@kinvolk/headlamp-plugin/lib/components/App/defaultAppThemes';
import { createMuiTheme } from '@kinvolk/headlamp-plugin/lib/lib/themes';
import store from '@kinvolk/headlamp-plugin/lib/redux/stores/store';
import { ThemeProvider } from '@mui/material/styles';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { ReactNode } from 'react';
import { Provider } from 'react-redux';
import { MemoryRouter } from 'react-router-dom';
import { vi } from 'vitest';
import { getImageScanKey, toImageScan, toWorkloadScan, WorkloadScan } from './scanData';
import { manifest, match, summary } from './testFixtures';

const mocks = vi.hoisted(() => ({ request: vi.fn(), post: vi.fn() }));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({
  request: mocks.request,
  post: mocks.post,
}));
vi.mock('@kinvolk/headlamp-plugin/lib/Utils', () => ({ getCluster: () => 'cluster-a' }));
vi.mock('../common/clusterContext', () => ({ getAllowedNamespaces: () => [] }));
vi.mock('../common/filedialog', () => ({ saveToFile: vi.fn() }));
vi.mock('../index', () => ({
  RoutingName: {
    KubescapeVulnerabilityDetails: 'workload',
    KubescapeSBOMDetails: 'sbom',
    SecurityExceptionDetail: 'exception',
  },
  useHLSelectedClusters: () => ['cluster-a'],
}));
vi.mock('../exceptions/GuidedVulnerabilityExceptionForm', () => ({
  GuidedVulnerabilityExceptionForm: ({ cveIds }: { cveIds: string[] }) => (
    <div>Accept risk of {cveIds.join(', ')}</div>
  ),
}));
vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', async importOriginal => ({
  ...(await importOriginal<typeof import('@kinvolk/headlamp-plugin/lib/CommonComponents')>()),
  Link: ({ children }: { children: ReactNode }) => <a href="/">{children}</a>,
}));

import ResourceList from './ResourceList';

// accepts the risk of CVE-2 in the workload of the summary fixture
const acceptance = {
  kind: 'SecurityException',
  metadata: { name: 'accept-cve-2', namespace: 'workloads' },
  spec: {
    match: { resources: [{ kind: 'Deployment', name: 'workload' }] },
    vulnerabilities: [
      {
        vulnerability: { id: 'CVE-2' },
        status: 'affected',
        response: ['can_not_fix'],
        actionStatement: 'No fix upstream',
      },
    ],
  },
};

function workloadScans(cveIds: string[]): WorkloadScan[] {
  const image = toImageScan(manifest());
  image.matches = cveIds.map(match);
  return [toWorkloadScan(summary(), new Map([[getImageScanKey(image), image]]))];
}

function view(scans: WorkloadScan[]) {
  return (
    <Provider store={store}>
      <ThemeProvider theme={createMuiTheme(lightTheme)}>
        <MemoryRouter>
          <ResourceList workloadScans={scans} />
        </MemoryRouter>
      </ThemeProvider>
    </Provider>
  );
}

beforeEach(() => {
  window.sessionStorage.clear();
  mocks.post.mockReset();
  mocks.post.mockResolvedValue({ status: { allowed: true } });
  mocks.request.mockReset();
  mocks.request.mockImplementation(async (url: string) =>
    url.endsWith('/securityexceptions') ? { items: [acceptance] } : { items: [] }
  );
});
afterEach(cleanup);

it('shows that all CVEs are accepted once the open ones are gone, at the same count', async () => {
  const shown = render(view(workloadScans(['CVE-1', 'CVE-2'])));
  expect(await screen.findByText('1 accepted')).toBeTruthy();

  // a new scan: CVE-1 was fixed, the accepted CVE remains
  await act(async () => shown.rerender(view(workloadScans(['CVE-2']))));

  expect(screen.getByText('All 1 accepted')).toBeTruthy();
  expect(screen.queryByText('1 accepted')).toBeNull();
});

it('shows the counts of the summary, marked, until the report arrives with the same counts', async () => {
  const [withReport] = workloadScans(['CVE-1', 'CVE-2']);
  // the summary of the fixture counts 2 High findings, 1 of them relevant
  const reading: WorkloadScan = { ...withReport, imageScan: undefined, relevant: undefined };
  const shown = render(view([reading]));

  // Critical, High, Medium and Low
  expect((await screen.findByTestId('summary-counts')).textContent).toBe('0200');
  expect(screen.getByText('1 of 2 (summary)')).toBeTruthy();

  // a new object once the report is read, with the same counts
  await act(async () => shown.rerender(view([withReport])));

  expect(screen.queryByTestId('summary-counts')).toBeNull();
  expect(screen.queryByText(/\(summary\)/)).toBeNull();
  expect(screen.getByText('? of 2')).toBeTruthy();
});

it('opens the acceptance of the risk for a user who may not create exceptions', async () => {
  // such as with GitOps: the form offers the exception as YAML
  mocks.post.mockResolvedValue({ status: { allowed: false } });
  render(view(workloadScans(['CVE-1', 'CVE-2'])));
  expect(await screen.findByText('1 accepted')).toBeTruthy();

  const accept = screen.getByRole('button', { name: 'Accept the risk of the open CVE' });
  expect((accept as HTMLButtonElement).disabled).toBe(false);
  fireEvent.click(accept);

  expect(screen.getByText('Accept risk of CVE-1')).toBeTruthy();
  // the form checks the permission to create the exception itself
  expect(mocks.post).not.toHaveBeenCalled();
});

// a workload with its own image, whose findings are all High and relevant
function scanned(name: string, highs: number): WorkloadScan {
  const image = toImageScan(manifest());
  image.manifestName = `image-${name}`;
  image.imageName = `registry.example/${name}:1.0`;
  image.matches = Array.from({ length: highs }, (_, i) => match(`CVE-${name}-${i}`));
  const [scan] = workloadScans([]);
  return { ...scan, name, manifestName: `workload-${name}`, imageScan: image, relevant: image };
}

function names() {
  return screen
    .getAllByRole('row')
    .slice(1)
    .map(row => within(row).getAllByRole('cell')[0].textContent);
}

it('sorts the counts by their numbers in a table of ten rows or fewer', async () => {
  // Headlamp's table picks how to sort from the rows after the tenth: with fewer, these values
  // would compare as text, 0.9.0.0 above 0.12.0.0
  render(view([scanned('nine', 9), scanned('twelve', 12)]));
  await act(async () => {});

  // the most findings first
  const cves = screen.getByRole('columnheader', { name: /CVE/ });
  expect(cves.getAttribute('aria-sort')).toBe('descending');
  expect(names()).toEqual(['twelve', 'nine']);

  // 9 of 9 before 12 of 12
  const relevant = screen.getByRole('columnheader', { name: /Relevant/ });
  fireEvent.click(within(relevant).getByRole('button', { name: /Relevant/ }));
  await waitFor(() => expect(relevant.getAttribute('aria-sort')).toBe('ascending'));
  expect(names()).toEqual(['nine', 'twelve']);
  fireEvent.click(within(relevant).getByRole('button', { name: /Relevant/ }));
  await waitFor(() => expect(relevant.getAttribute('aria-sort')).toBe('descending'));
  expect(names()).toEqual(['twelve', 'nine']);
});

it('searches the images also when the report of the first workload is not read yet', async () => {
  const [withReport] = workloadScans(['CVE-1']);
  // its counts come from the summary until the report is read
  const reading: WorkloadScan = { ...withReport, imageScan: undefined, relevant: undefined };
  render(view([reading, scanned('needle', 1)]));
  await act(async () => {});
  expect(names()).toHaveLength(2);

  // the table only searches a column whose value in the first row is text or a number
  fireEvent.click(screen.getByRole('button', { name: 'Show/Hide search' }));
  fireEvent.change(screen.getByPlaceholderText('Search'), {
    target: { value: 'registry.example/needle' },
  });
  // the search waits a moment for more typing
  await waitFor(() => expect(names()).toEqual(['needle']));
});

it('has no column for the cluster, also no empty one, while one cluster is selected', async () => {
  render(view([scanned('web', 1)]));
  await act(async () => {});

  // the titles, without the badges of the sorting
  const headers = screen
    .getAllByRole('columnheader')
    .map(header => header.querySelector('.Mui-TableHeadCell-Content-Wrapper')?.textContent ?? '');
  expect(headers).not.toContain('Cluster');
  expect(headers.slice(0, 7)).toEqual([
    'Name',
    'Container',
    'Kind',
    'Namespace',
    'Image',
    'CVE',
    'Relevant',
  ]);
  // only the column of the action has no title
  expect(headers.filter(header => !header)).toHaveLength(1);
});
