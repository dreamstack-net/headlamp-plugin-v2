// Renders the Upgrades tab in Headlamp's real table, which only draws a cell again when its
// value changes
import { lightTheme } from '@kinvolk/headlamp-plugin/lib/components/App/defaultAppThemes';
import { createMuiTheme } from '@kinvolk/headlamp-plugin/lib/lib/themes';
import store from '@kinvolk/headlamp-plugin/lib/redux/stores/store';
import { ThemeProvider } from '@mui/material/styles';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { ReactNode } from 'react';
import { Provider } from 'react-redux';
import { MemoryRouter } from 'react-router-dom';
import { vi } from 'vitest';
import { ImageScan, WorkloadScan } from './scanData';
import { match } from './testFixtures';

vi.mock('../index', () => ({ RoutingName: { ImageVulnerabilityDetails: 'image' } }));
vi.mock('../common/filedialog', () => ({ saveToFile: vi.fn() }));
vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', async importOriginal => ({
  ...(await importOriginal<typeof import('@kinvolk/headlamp-plugin/lib/CommonComponents')>()),
  Link: ({ children, activeCluster, routeName, params }: any) => (
    <a href={`/${activeCluster}/${routeName}/${params.namespace}/${params.name}`}>
      {children as ReactNode}
    </a>
  ),
}));

import UpgradeListView, { upgradeRowId } from './UpgradeList';
import { getPackageUpgrades } from './upgrades';

function image(cluster: string, manifestName: string, cveIds: string[]): ImageScan {
  return {
    manifestName,
    namespace: 'kubescape',
    cluster,
    imageName: 'nginx:1.27.0',
    creationTimestamp: '2026-10-01T00:00:00Z',
    matches: cveIds.map(match),
  };
}

function workload(imageScan: ImageScan, relevant?: ImageScan): WorkloadScan {
  return {
    manifestName: `deployment-web-${imageScan.cluster}`,
    name: 'web',
    kind: 'Deployment',
    container: 'nginx',
    namespace: 'shop',
    cluster: imageScan.cluster,
    imageScan,
    relevant,
  };
}

function view(workloadScans: WorkloadScan[]) {
  return (
    <Provider store={store}>
      <ThemeProvider theme={createMuiTheme(lightTheme)}>
        <MemoryRouter>
          <UpgradeListView workloadScans={workloadScans} />
        </MemoryRouter>
      </ThemeProvider>
    </Provider>
  );
}

beforeEach(() => window.sessionStorage.clear());
afterEach(cleanup);

it('identifies each upgrade by its image, package and installed version', () => {
  const a = image('cluster-a', 'nginx-a', ['CVE-1']);
  const b = image('cluster-b', 'nginx-b', ['CVE-1']);
  // the same package at another version in the same image
  const other = match('CVE-2');
  other.artifact = { name: 'package', version: '1.1' };
  a.matches.push(other);

  const ids = getPackageUpgrades([workload(a), workload(b)]).map(upgradeRowId);

  expect(ids).toHaveLength(3);
  expect(new Set(ids).size).toBe(3);
});

it('links the image of each row to its own report when the rows change', () => {
  // the same image in two clusters; the upgrade in cluster-b fixes more CVEs, so it comes first
  const a = image('cluster-a', 'nginx-a', ['CVE-1']);
  const b = image('cluster-b', 'nginx-b', ['CVE-1', 'CVE-2']);
  // the workload in cluster-b was not seen to use the package
  const notUsed = { ...b, manifestName: 'nginx-b-relevant', matches: [] };
  render(view([workload(a), workload(b, notUsed)]));
  expect(
    screen.getAllByText('nginx:1.27.0').map(link => link.closest('a')?.getAttribute('href'))
  ).toEqual(['/cluster-b/image/kubescape/nginx-b', '/cluster-a/image/kubescape/nginx-a']);

  // only the relevant upgrades: the upgrade in cluster-a moves to the first row
  fireEvent.click(screen.getByRole('checkbox', { name: 'Relevant' }));

  const links = screen.getAllByText('nginx:1.27.0');
  expect(links.map(link => link.closest('a')?.getAttribute('href'))).toEqual([
    '/cluster-a/image/kubescape/nginx-a',
  ]);
});

it('lists the CVEs an upgrade fixes now, also when their counts stay the same', async () => {
  const before = image('cluster-a', 'nginx-a', ['CVE-1']);
  const view1 = render(view([workload(before)]));

  // a new scan: another CVE of the same severity in the same package
  const after = image('cluster-a', 'nginx-a', ['CVE-9']);
  view1.rerender(view([workload(after)]));

  const row = screen.getByText('nginx:1.27.0').closest('tr')!;
  fireEvent.mouseOver(within(row).getByText('1'));
  const tooltip = await screen.findByRole('tooltip');
  expect(tooltip.textContent).toContain('CVE-9');
  expect(tooltip.textContent).not.toContain('CVE-1');
});
