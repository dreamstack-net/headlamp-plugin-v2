// Renders the comparison of the images of the selected clusters in Headlamp's real table
import { lightTheme } from '@kinvolk/headlamp-plugin/lib/components/App/defaultAppThemes';
import { createMuiTheme } from '@kinvolk/headlamp-plugin/lib/lib/themes';
import store from '@kinvolk/headlamp-plugin/lib/redux/stores/store';
import { ThemeProvider } from '@mui/material/styles';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { ReactNode } from 'react';
import { Provider } from 'react-redux';
import { MemoryRouter } from 'react-router-dom';
import { vi } from 'vitest';
import type { VulnerabilityManifest } from '../softwarecomposition/VulnerabilityManifest';
import type { ImageScan, WorkloadScan } from './scanData';
import { match } from './testFixtures';

const mocks = vi.hoisted(() => ({
  clusters: ['tst'] as string[],
  readVulnerabilityScans: vi.fn(),
  context: { queryTasks: [] as Array<{ cluster: string; continuation?: string; error?: string }> },
  saveToFile: vi.fn(),
  // the setting of the image versions, off unless a test switches it on
  versionSettings: { enabled: false, endOfLife: false, possiblyPrivate: false },
  versions: new Map<string, unknown>(),
}));
vi.mock('../index', () => ({
  RoutingName: {
    ImageVulnerabilityDetails: 'image',
    KubescapeVulnerabilityDetails: 'workload',
    KubescapeCVEResults: 'cve',
  },
  useHLSelectedClusters: () => mocks.clusters,
}));
vi.mock('./Vulnerabilities', () => ({
  readVulnerabilityScans: mocks.readVulnerabilityScans,
  vulnerabilityContext: mocks.context,
}));
vi.mock('../common/config-store', () => ({
  kubescapeConfigStore: { get: () => ({}), useConfig: () => () => ({}) },
}));
// the lookups of the newest versions, as the other image pages make them
vi.mock('./ImageVersion', async importOriginal => ({
  ...(await importOriginal<typeof import('./ImageVersion')>()),
  useImageVersionSettings: () => mocks.versionSettings,
  useImageVersions: () => mocks.versions,
}));
vi.mock('../common/SetupCheck', () => ({ SetupCheck: () => null }));
vi.mock('../common/filedialog', () => ({ saveToFile: mocks.saveToFile }));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ request: vi.fn() }));
// like Headlamp's link, it names the cluster and the route of the page it opens
vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', async importOriginal => ({
  ...(await importOriginal<typeof import('@kinvolk/headlamp-plugin/lib/CommonComponents')>()),
  Link: ({ children, activeCluster, routeName, params }: any) => (
    <a
      href={
        params.cve
          ? `/${routeName}/${params.cve}`
          : `/${activeCluster}/${routeName}/${params.namespace}/${params.name}`
      }
    >
      {children as ReactNode}
    </a>
  ),
}));

import KubescapeClusterComparison from './ClusterComparison';

function cve(id: string, severity = 'High'): VulnerabilityManifest.Match {
  const finding = match(id);
  finding.vulnerability.severity = severity;
  return finding;
}

function report(cluster: string, imageName: string, matches: VulnerabilityManifest.Match[]) {
  const scan: ImageScan = {
    manifestName: `${imageName.replace(/[/:]/g, '-')}-${cluster}`,
    namespace: 'kubescape',
    cluster,
    imageName,
    creationTimestamp: '2026-11-01T00:00:00Z',
    matches,
  };
  return scan;
}

function workload(imageScan: ImageScan, name: string): WorkloadScan {
  return {
    manifestName: `deployment-${name}`,
    name,
    kind: 'Deployment',
    container: 'app',
    namespace: 'shop',
    cluster: imageScan.cluster,
    imageScan,
    relevant: undefined,
  };
}

const newer = [cve('CVE-A', 'Critical'), cve('CVE-B'), cve('CVE-NEW')];
const older = [
  cve('CVE-A', 'Critical'),
  cve('CVE-B'),
  cve('CVE-OLD1', 'Critical'),
  cve('CVE-OLD2'),
  cve('CVE-OLD3', 'Low'),
];

function scansOfThreeClusters(): WorkloadScan[] {
  return [
    workload(report('tst', 'nginx:1.25.3', newer), 'web'),
    workload(report('acc', 'nginx:1.25.3', newer), 'web'),
    workload(report('prd', 'nginx:1.25.1', older), 'web'),
    // the same in every cluster
    ...['tst', 'acc', 'prd'].map(cluster =>
      workload(report(cluster, 'redis:7.4.1', [cve('CVE-R')]), 'cache')
    ),
    // a new component that only tst runs
    workload(report('tst', 'busybox:1.37.0', []), 'debug'),
  ];
}

function view() {
  return (
    <Provider store={store}>
      <ThemeProvider theme={createMuiTheme(lightTheme)}>
        <MemoryRouter>
          <KubescapeClusterComparison />
        </MemoryRouter>
      </ThemeProvider>
    </Provider>
  );
}

beforeEach(() => {
  window.sessionStorage.clear();
  mocks.readVulnerabilityScans.mockReset();
  mocks.saveToFile.mockReset();
  mocks.context.queryTasks = [];
  mocks.versionSettings = { enabled: false, endOfLife: false, possiblyPrivate: false };
  mocks.versions = new Map();
});
afterEach(cleanup);

it('explains how to select several clusters when one is selected', () => {
  mocks.clusters = ['tst'];
  render(view());

  expect(screen.getByText(/Only tst is selected/)).toBeTruthy();
  expect(screen.getByText(/tick the clusters in the All Clusters table/)).toBeTruthy();
  // nothing to compare, so nothing is read
  expect(mocks.readVulnerabilityScans).not.toHaveBeenCalled();
});

it('compares the images of the selected clusters on tabs, with where they run', async () => {
  mocks.clusters = ['tst', 'acc', 'prd'];
  mocks.readVulnerabilityScans.mockResolvedValue(scansOfThreeClusters());
  render(view());

  expect(await screen.findByText('2 in more than one cluster')).toBeTruthy();
  expect(mocks.readVulnerabilityScans.mock.calls[0][0]).toEqual(['tst', 'acc', 'prd']);

  // the upgrade candidates first: prd could move to the version of tst and acc
  expect(
    screen.getByRole('tab', { name: 'Upgrade candidates' }).getAttribute('aria-selected')
  ).toBe('true');
  const candidate = within(screen.getByRole('table'));
  expect(candidate.getByText('3 CVEs')).toBeTruthy();
  expect(candidate.getByText('1 CVE')).toBeTruthy();
  // nginx runs in 2 versions, of which prd's can upgrade
  expect(candidate.getByText('1 of 2 versions can upgrade')).toBeTruthy();
  // the workload that runs the current version, by namespace, cluster and container
  expect(candidate.getByText('shop/')).toBeTruthy();
  expect(candidate.getByText('prd · app')).toBeTruthy();
  expect(
    candidate.getByTitle('Deployment web, container app, in namespace shop of prd')
  ).toBeTruthy();
  // the clusters open the report of their version, the workload its page
  const hrefs = candidate.getAllByRole('link').map(link => link.getAttribute('href'));
  expect(hrefs).toEqual([
    '/prd/image/kubescape/nginx-1.25.1-prd',
    '/prd/workload/shop/deployment-web',
    '/tst/image/kubescape/nginx-1.25.3-tst',
    '/acc/image/kubescape/nginx-1.25.3-acc',
  ]);

  // the images that differ: nginx, whose versions differ, and busybox, which only tst runs
  fireEvent.click(screen.getByRole('tab', { name: 'Images' }));
  const image = within(screen.getByRole('table'));
  expect(image.getByRole('button', { name: 'nginx' })).toBeTruthy();
  expect(image.getAllByText('docker.io/library')).toHaveLength(2);
  expect(image.getByText('Versions differ')).toBeTruthy();
  expect(image.getByText('Only in tst')).toBeTruthy();
  // a line per version over all clusters: 1.25.3 of tst and acc once, and prd's 1.25.1 with its
  // upgrade
  // the line of 1.25.3, once for tst and acc, and the upgrade of 1.25.1 to it
  expect(image.getAllByText('1.25.3')).toHaveLength(2);
  expect(image.getByText('2 workloads')).toBeTruthy();
  expect(image.getByLabelText('Upgrade to 1.25.3')).toBeTruthy();
  // the workloads of nginx in all clusters
  expect(image.getByText('3 workloads')).toBeTruthy();
  // the clusters open the report of their version
  expect(image.getAllByRole('link').map(link => link.getAttribute('href'))).toEqual([
    '/tst/image/kubescape/busybox-1.37.0-tst',
    '/tst/image/kubescape/nginx-1.25.3-tst',
    '/acc/image/kubescape/nginx-1.25.3-acc',
    '/prd/image/kubescape/nginx-1.25.1-prd',
  ]);
  expect(image.queryByRole('button', { name: 'redis' })).toBeNull();

  // all images, from the tile that counts them
  fireEvent.click(screen.getByRole('button', { name: /^3\s*Images/ }));
  expect(within(screen.getByRole('table')).getByRole('button', { name: 'redis' })).toBeTruthy();
  expect(screen.getByText('Same')).toBeTruthy();
  // and the images whose versions differ
  fireEvent.click(screen.getByRole('button', { name: /^1\s*Other versions/ }));
  const versions = within(screen.getByRole('table'));
  expect(versions.getByRole('button', { name: 'nginx' })).toBeTruthy();
  expect(versions.queryByRole('button', { name: 'busybox' })).toBeNull();

  // the tile of the candidates opens their tab again
  fireEvent.click(screen.getByRole('button', { name: /^1\s*Upgrade candidates/ }));
  expect(within(screen.getByRole('table')).getByText('3 CVEs')).toBeTruthy();
});

it('shows each version of an image with where it runs and its upgrade in a dialog', async () => {
  mocks.clusters = ['tst', 'acc', 'prd'];
  mocks.readVulnerabilityScans.mockResolvedValue(scansOfThreeClusters());
  render(view());
  await screen.findByText('2 in more than one cluster');

  fireEvent.click(screen.getByRole('button', { name: 'nginx' }));
  const dialog = within(screen.getByRole('dialog'));
  expect(dialog.getByRole('heading', { name: 'nginx' })).toBeTruthy();
  expect(dialog.getByText('docker.io/library/nginx')).toBeTruthy();
  expect(
    dialog.getByText(
      '2 versions in tst, acc and prd, run by 3 workloads; the newest version first.'
    )
  ).toBeTruthy();
  // a card per version, newest first
  expect(dialog.getAllByRole('heading', { level: 3 }).map(heading => heading.textContent)).toEqual([
    '1.25.3',
    '1.25.1',
  ]);
  expect(dialog.getByText('No newer version runs in another selected cluster.')).toBeTruthy();
  expect(dialog.getByText('5 CVEs, 5 fixable')).toBeTruthy();

  // the labels of the lines of the versions
  expect(['Version', 'Runs in', 'Open CVEs'].map(label => dialog.getByText(label))).toHaveLength(3);
  // prd's 1.25.1 can move to the version of tst and acc, which runs in 2 workloads
  expect(dialog.getByText('Upgrade to')).toBeTruthy();
  expect(dialog.getByText('2 workloads')).toBeTruthy();
  expect(dialog.getByText('Removes')).toBeTruthy();
  expect(dialog.getByText('3 CVEs')).toBeTruthy();
  // the CVEs of the move unfold, linking to their pages
  expect(dialog.queryByRole('link', { name: 'CVE-OLD1' })).toBeNull();
  fireEvent.click(dialog.getByRole('button', { name: 'CVEs' }));
  expect(dialog.getByRole('link', { name: 'CVE-OLD1' }).getAttribute('href')).toBe('/cve/CVE-OLD1');
  expect(dialog.getByRole('link', { name: 'CVE-NEW' }).getAttribute('href')).toBe('/cve/CVE-NEW');
  expect(dialog.getByText('and 1 CVE of lower severity, which the boxes list')).toBeTruthy();

  // the workloads of each version, opening their page in their cluster
  expect(
    dialog.getAllByRole('link', { name: 'web' }).map(link => link.getAttribute('href'))
  ).toEqual([
    '/tst/workload/shop/deployment-web',
    '/acc/workload/shop/deployment-web',
    '/prd/workload/shop/deployment-web',
  ]);

  fireEvent.click(dialog.getByRole('button', { name: 'Close' }));
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());

  // a row opens the dialog of its image too
  fireEvent.click(screen.getByRole('tab', { name: 'Images' }));
  fireEvent.click(screen.getByText('Only in tst'));
  expect(within(screen.getByRole('dialog')).getByRole('heading', { name: 'busybox' })).toBeTruthy();
});

it('names a CVE that exceptions hide in the reports without a link to its page', async () => {
  mocks.clusters = ['tst', 'prd'];
  // prd accepted the risk of CVE-HIDDEN, which kubevuln then hides in its report
  const old = report('prd', 'nginx:1.25.1', [cve('CVE-OPEN', 'Critical')]);
  old.ignoredMatches = [cve('CVE-HIDDEN', 'Critical')];
  mocks.readVulnerabilityScans.mockResolvedValue([
    workload(report('tst', 'nginx:1.25.3', []), 'web'),
    workload(old, 'web'),
  ]);
  render(view());
  await screen.findByText('1 in more than one cluster');

  fireEvent.click(screen.getByRole('button', { name: 'nginx' }));
  const dialog = within(screen.getByRole('dialog'));
  // the move to 1.25.3 removes both, as the comparison is of all CVEs of the reports
  expect(dialog.getByText('2 CVEs')).toBeTruthy();
  fireEvent.click(dialog.getByRole('button', { name: 'CVEs' }));
  expect(dialog.getByRole('link', { name: 'CVE-OPEN' }).getAttribute('href')).toBe('/cve/CVE-OPEN');
  // the page of a CVE lists the workloads whose reports count it, which would be none
  expect(dialog.getByText('CVE-HIDDEN')).toBeTruthy();
  expect(dialog.queryByRole('link', { name: 'CVE-HIDDEN' })).toBeNull();
});

it('merges the reports of one tag, and folds away the tags that cannot be ordered', async () => {
  mocks.clusters = ['tst', 'prd'];
  const rebuilt = report('prd', 'app:main', [cve('CVE-1', 'Critical'), cve('CVE-2')]);
  mocks.readVulnerabilityScans.mockResolvedValue([
    workload(report('tst', 'app:main', [cve('CVE-1', 'Critical')]), 'web'),
    workload(rebuilt, 'web'),
    workload(report('tst', 'app:feature-x', []), 'preview'),
  ]);
  render(view());
  await screen.findByText('1 in more than one cluster');

  // branch builds are no upgrade candidates
  expect(
    screen.getByText(
      'No cluster runs a version with CVEs that the version of another cluster does not have.'
    )
  ).toBeTruthy();
  fireEvent.click(screen.getByRole('tab', { name: 'Images' }));
  fireEvent.click(screen.getByRole('button', { name: 'app' }));
  const dialog = within(screen.getByRole('dialog'));
  // main of tst and prd is one version, whose reports differ
  expect(dialog.getAllByRole('heading', { level: 3 }).map(heading => heading.textContent)).toEqual([
    'feature-x',
    'main',
  ]);
  expect(dialog.getByText('reports differ')).toBeTruthy();
  expect(dialog.getAllByText('No newer version runs in another selected cluster.')).toHaveLength(2);
  // the other tag is compared on request
  expect(dialog.queryByText('Not comparable')).toBeNull();
  fireEvent.click(dialog.getAllByRole('button', { name: 'Compare with 1 other tag' })[1]);
  expect(dialog.getByText('Not comparable')).toBeTruthy();
  expect(dialog.getByText('2 CVEs')).toBeTruthy();
});

it('shows the newest upstream version of each tag only when the setting is on', async () => {
  mocks.clusters = ['tst', 'acc', 'prd'];
  mocks.readVulnerabilityScans.mockResolvedValue(scansOfThreeClusters());
  const { unmount } = render(view());
  await screen.findByText('2 in more than one cluster');

  // off: nothing is looked up, and the page says how to switch it on
  expect(screen.queryByText('Upstream')).toBeNull();
  // in the description of both tabs
  expect(screen.getAllByText(/switch on Show the newest version of images/)).toHaveLength(2);
  unmount();

  mocks.versionSettings = { enabled: true, endOfLife: false, possiblyPrivate: false };
  mocks.versions = new Map([
    [
      'prd|nginx:1.25.1',
      {
        tag: '1.25.1',
        latest: { latest: '1.27.3', source: { name: 'Docker Hub', url: 'https://hub.example' } },
        newer: true,
      },
    ],
  ]);
  render(view());
  await screen.findByText('2 in more than one cluster');

  // the candidates: the upstream version of prd's 1.25.1
  const candidates = within(screen.getByRole('table'));
  expect(candidates.getByText('Upstream')).toBeTruthy();
  expect(candidates.getByRole('link', { name: '1.27.3' }).getAttribute('href')).toBe(
    'https://hub.example'
  );
  // the Images tab, on the line of 1.25.1
  fireEvent.click(screen.getByRole('tab', { name: 'Images' }));
  expect(within(screen.getByRole('table')).getByRole('link', { name: '1.27.3' })).toBeTruthy();
  // and the card of 1.25.1 in the dialog
  fireEvent.click(within(screen.getByRole('table')).getByRole('button', { name: 'nginx' }));
  const dialog = within(screen.getByRole('dialog'));
  expect(dialog.getByText('Upstream')).toBeTruthy();
  expect(dialog.getByRole('link', { name: '1.27.3' }).getAttribute('href')).toBe(
    'https://hub.example'
  );
});

it('exports the upgrade candidates and the versions of the images as CSV', async () => {
  mocks.clusters = ['tst', 'acc', 'prd'];
  mocks.readVulnerabilityScans.mockResolvedValue(scansOfThreeClusters());
  render(view());
  await screen.findByText('2 in more than one cluster');

  fireEvent.click(screen.getByRole('button', { name: 'Export CSV' }));
  const [candidatesCsv, candidatesFile] = mocks.saveToFile.mock.calls[0];
  expect(candidatesFile).toBe('kubescape-upgrade-candidates.csv');
  expect(candidatesCsv).toContain(
    'docker.io/library/nginx,prd,1.25.1,1.25.3,tst; acc,3,1,1,1,0,1,' +
      'CVE-OLD1; CVE-OLD2; CVE-OLD3,CVE-NEW,'
  );
  expect(candidatesCsv).toContain('prd/shop/web/app');

  fireEvent.click(screen.getByRole('tab', { name: 'Images' }));
  fireEvent.click(screen.getByRole('button', { name: 'Export CSV' }));
  const [imagesCsv, imagesFile] = mocks.saveToFile.mock.calls[1];
  expect(imagesFile).toBe('kubescape-cluster-images.csv');
  const lines: string[] = imagesCsv.trim().split('\r\n');
  expect(lines[0]).toBe(
    'Image,Cluster,Version,Image names,Workloads,Critical,High,Relevant critical,Relevant high,' +
      'CVEs,Fixable,Status,Differences'
  );
  // the rows of the images shown: busybox and nginx, not redis
  expect(lines).toHaveLength(5);
  expect(lines).toContain(
    'docker.io/library/busybox,tst,1.37.0,busybox:1.37.0,shop/debug/app,0,0,,,0,0,Only in tst,'
  );
  expect(lines.find(line => line.startsWith('docker.io/library/nginx,prd'))).toContain(
    'docker.io/library/nginx,prd,1.25.1,nginx:1.25.1,shop/web/app,2,2,,,5,5,Versions differ,'
  );
});

it('reads on when reading stopped, as images may seem to be missing', async () => {
  mocks.clusters = ['tst', 'prd'];
  mocks.context.queryTasks = [{ cluster: 'prd', continuation: '' }];
  mocks.readVulnerabilityScans.mockResolvedValue(scansOfThreeClusters());
  render(view());

  expect(await screen.findByText(/Not all scans were read/)).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Read on' }));
  await waitFor(() => expect(mocks.readVulnerabilityScans).toHaveBeenCalledTimes(2));
});

it('leaves out a selected cluster of which no scans were read', async () => {
  mocks.clusters = ['tst', 'acc', 'prd'];
  mocks.readVulnerabilityScans.mockResolvedValue(
    scansOfThreeClusters().filter(scan => scan.cluster !== 'acc')
  );
  render(view());

  expect(
    await screen.findByText(
      'No vulnerability scans were read of acc, so the comparison leaves it out.'
    )
  ).toBeTruthy();
  // no column for acc: only the chip of the selected clusters names it
  expect(screen.getAllByText('acc')).toHaveLength(1);
  expect(screen.getAllByText('tst').length).toBeGreaterThan(1);
});

it('does not call an image missing in a cluster whose workloads lack a report', async () => {
  mocks.clusters = ['tst', 'acc', 'prd'];
  // the report of prd's debug workload gave 404: it may run busybox
  const debug = workload(report('prd', 'busybox:1.37.0', []), 'debug');
  mocks.readVulnerabilityScans.mockResolvedValue([
    ...scansOfThreeClusters(),
    { ...debug, imageScan: undefined },
  ]);
  render(view());

  const note = await screen.findByText(/No vulnerability report was read for 1 workload/);
  expect(note.textContent).toBe(
    'No vulnerability report was read for 1 workload (1 of prd), mostly Jobs and CronJobs: ' +
      'Kubescape removes the report of an image while no pod runs it. Their images count as ' +
      'possibly running in that cluster, not as missing.'
  );
  // the workloads are listed on request
  expect(screen.queryByText('prd: shop/debug/app')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Show workloads' }));
  expect(screen.getByText('prd: shop/debug/app')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Hide workloads' }));
  expect(screen.queryByText('prd: shop/debug/app')).toBeNull();
  expect(
    screen.getByText('A selected cluster does not run them, or has no report of them')
  ).toBeTruthy();
  fireEvent.click(screen.getByRole('tab', { name: 'Images' }));
  const images = within(screen.getByRole('table'));
  // acc runs no busybox; of prd that is not known
  expect(images.getByText('Not in acc')).toBeTruthy();
  expect(images.getByText("Not in prd's reports")).toBeTruthy();
  expect(images.queryByText('Only in tst')).toBeNull();
});

it('shows why the scans could not be read', async () => {
  mocks.clusters = ['tst', 'prd'];
  mocks.readVulnerabilityScans.mockRejectedValue(new Error('forbidden'));
  render(view());

  expect(await screen.findByText('Unable to read the vulnerability scans: forbidden')).toBeTruthy();
});
