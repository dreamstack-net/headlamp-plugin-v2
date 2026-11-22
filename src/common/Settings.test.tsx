import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { useState } from 'react';
import { vi } from 'vitest';
import { epssPermit } from '../vulnerabilities/exploitData';
import { KubescapeSettings } from './Settings';

const mocks = vi.hoisted(() => ({
  request: vi.fn(),
  detectAlertmanager: vi.fn(),
  detectPrometheus: vi.fn(),
  clearReportCache: vi.fn(),
  clusters: { 'cluster-a': {} } as Record<string, object>,
  listCustomObjectConfigMaps: vi.fn(),
}));
vi.mock('@kinvolk/headlamp-plugin/lib', () => ({
  ConfigStore: class {
    get() {
      return {};
    }
    set() {}
  },
}));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ request: mocks.request }));
vi.mock('./clustersConf', () => ({ useClustersConf: () => mocks.clusters }));
vi.mock('../runtimedetection/alertmanager', () => ({
  detectAlertmanager: mocks.detectAlertmanager,
}));
vi.mock('../overview/prometheus', () => ({ detectPrometheus: mocks.detectPrometheus }));
vi.mock('../vulnerabilities/reportCache', () => ({ clearReportCache: mocks.clearReportCache }));
// Kubescape's frameworks, which the plugin reads from its files
vi.mock('../rego', () => ({
  RegoDataProvider: ({ children }: { children: React.ReactNode }) => children,
  useRegoData: () => ({
    frameworks: [{ name: 'cis-v1.10.0' }, { name: 'MITRE' }, { name: 'NSA' }],
    controls: [],
  }),
  defaultFrameworkNames: ['cis-v1.10.0', 'MITRE', 'NSA'],
}));
vi.mock('../custom-objects/api-queries', () => ({
  listCustomObjectConfigMaps: mocks.listCustomObjectConfigMaps,
}));
vi.mock('../vulnerabilities/ImageVersion', () => ({
  changeImageVersionSetting: (data: object | undefined, setting: string, on: boolean) => ({
    ...data,
    [setting]: on,
  }),
}));

beforeEach(() => {
  mocks.clusters = { 'cluster-a': {} };
  mocks.listCustomObjectConfigMaps.mockReset().mockResolvedValue([]);
  mocks.request.mockReset();
  mocks.detectAlertmanager.mockReset();
  mocks.detectPrometheus.mockReset();
});

// holds the settings like Headlamp's settings page, which replaces them with what it gets
function renderSettings(initial: { [key: string]: any }) {
  const current = { data: initial };
  function Host() {
    const [data, setData] = useState(initial);
    current.data = data;
    return <KubescapeSettings data={data} onDataChange={setData} />;
  }
  render(<Host />);
  return current;
}

it('keeps what the user changed while the Alertmanager was being detected', async () => {
  let answer: (addresses: string[]) => void = () => {};
  mocks.detectAlertmanager.mockReturnValue(new Promise(resolve => (answer = resolve)));
  const settings = renderSettings({ pageSize: 50, alertmanagerUrl: '' });
  await waitFor(() => expect(mocks.detectAlertmanager).toHaveBeenCalledWith('cluster-a'));

  fireEvent.click(screen.getByLabelText(/Notify about critical runtime alerts/));
  expect(settings.data.notifications).toBe(false);
  await act(async () => answer(['monitoring/alertmanager:9093']));

  expect(settings.data).toEqual({
    pageSize: 50,
    notifications: false,
    alertmanagerUrl: 'monitoring/alertmanager:9093',
  });
});

it('keeps both of two changes made before Headlamp renders again', async () => {
  mocks.detectAlertmanager.mockResolvedValue([]);
  mocks.detectPrometheus.mockResolvedValue(['monitoring/prometheus:9090']);
  const settings = renderSettings({ pageSize: 50, alertmanagerUrl: 'monitoring/am:9093' });

  fireEvent.click(screen.getAllByRole('button', { name: 'Detect' })[1]);
  fireEvent.click(screen.getByLabelText(/Show CVEs and failed controls/));
  await waitFor(() => expect(settings.data.prometheusUrl).toBe('monitoring/prometheus:9090'));

  expect(settings.data.tableColumns).toBe(false);
  expect(settings.data.alertmanagerUrl).toBe('monitoring/am:9093');
});

it('tests the Alertmanager through the service proxy of the chosen cluster', async () => {
  mocks.request.mockResolvedValue([]);
  renderSettings({ pageSize: 50, alertmanagerUrl: 'monitoring/alertmanager:9093' });

  fireEvent.click(screen.getByRole('button', { name: 'Test Connection' }));

  await screen.findByText('Connection successful!');
  expect(mocks.request).toHaveBeenCalledWith(
    '/api/v1/namespaces/monitoring/services/alertmanager:9093/proxy/api/v2/alerts',
    { cluster: 'cluster-a', autoLogoutOnAuthError: false }
  );

  mocks.request.mockRejectedValue(new Error('Unauthorized'));
  fireEvent.click(screen.getByRole('button', { name: 'Test Connection' }));
  await screen.findByText('Connection failed: Unauthorized');
});

it('shows what Detect found only for the cluster it was found in', async () => {
  mocks.clusters = { 'cluster-a': {}, 'cluster-b': {} };
  mocks.detectAlertmanager.mockResolvedValue(['monitoring/alertmanager:9093']);
  mocks.detectPrometheus.mockResolvedValue([]);
  renderSettings({ pageSize: 50, alertmanagerUrl: 'monitoring/am:9093' });
  const chooseCluster = async (from: string, to: string) => {
    fireEvent.mouseDown(screen.getAllByRole('combobox').find(box => box.textContent === from)!);
    fireEvent.click(await screen.findByRole('option', { name: to }));
  };

  const [detectAlertmanager, detectPrometheus] = screen.getAllByRole('button', { name: 'Detect' });
  fireEvent.click(detectAlertmanager);
  fireEvent.click(detectPrometheus);
  await screen.findByText('Found in cluster-a:');
  await screen.findByText('No Prometheus service found in cluster cluster-a.');

  // nothing was looked for in the other cluster
  await chooseCluster('cluster-a', 'cluster-b');
  expect(screen.queryByText(/Found in/)).toBeNull();
  expect(screen.queryByText(/No Prometheus service found/)).toBeNull();

  // an answer that arrives after another cluster was chosen is of the cluster that was asked
  let answer: (addresses: string[]) => void = () => {};
  mocks.detectAlertmanager.mockReturnValue(new Promise(resolve => (answer = resolve)));
  fireEvent.click(screen.getAllByRole('button', { name: 'Detect' })[0]);
  await waitFor(() => expect(mocks.detectAlertmanager).toHaveBeenLastCalledWith('cluster-b'));
  await chooseCluster('cluster-b', 'cluster-a');
  await act(async () => answer(['logging/alertmanager:9093']));
  expect(screen.queryByText('logging/alertmanager:9093')).toBeNull();

  await chooseCluster('cluster-a', 'cluster-b');
  expect(await screen.findByText('Found in cluster-b:')).toBeTruthy();
  expect(screen.getByText('logging/alertmanager:9093')).toBeTruthy();
});

it('keeps the vulnerability reports unless switched off, which removes them', async () => {
  mocks.detectAlertmanager.mockResolvedValue([]);
  const settings = renderSettings({ pageSize: 50, alertmanagerUrl: 'monitoring/am:9093' });
  const keep = screen.getByLabelText('Keep vulnerability reports between sessions');
  expect((keep as HTMLInputElement).checked).toBe(true);

  fireEvent.click(keep);

  expect(settings.data.keepVulnerabilityReports).toBe(false);
  expect(mocks.clearReportCache).toHaveBeenCalledTimes(1);

  fireEvent.click(keep);
  expect(settings.data.keepVulnerabilityReports).toBe(true);
  expect(mocks.clearReportCache).toHaveBeenCalledTimes(1);
});

it('switches the exploit data on, and stops the EPSS lookups that wait when switched off', () => {
  const settings = renderSettings({ pageSize: 50, alertmanagerUrl: 'monitoring/am:9093' });
  const kev = screen.getByLabelText(
    'Mark CVEs that are known to be exploited (CISA KEV)'
  ) as HTMLInputElement;
  const epss = screen.getByLabelText('Show the EPSS score of CVEs') as HTMLInputElement;
  // both ask services outside the cluster, so they are off until switched on
  expect(kev.checked).toBe(false);
  expect(epss.checked).toBe(false);
  expect(screen.getByText(/nothing about your clusters/)).toBeTruthy();
  expect(screen.getByText(/CVE ids found in your clusters/)).toBeTruthy();

  fireEvent.click(kev);
  fireEvent.click(epss);
  expect(settings.data).toMatchObject({ knownExploited: true, epss: true });

  const permit = epssPermit();
  fireEvent.click(epss);

  expect(settings.data.epss).toBe(false);
  expect(settings.data.knownExploited).toBe(true);
  expect(permit.aborted).toBe(true);
  expect(epssPermit().aborted).toBe(false);
});

it('chooses the frameworks to show, the custom frameworks of the clusters first', async () => {
  mocks.clusters = { prd: {}, tst: {} };
  mocks.listCustomObjectConfigMaps.mockImplementation(async (_type: string, cluster: string) =>
    cluster === 'prd'
      ? [
          { data: { name: 'Acme Security Baseline v1' } },
          { data: { name: 'Acme Security Baseline v2' } },
        ]
      : [{ data: { name: 'Acme Security Baseline v1' } }]
  );
  const settings = renderSettings({ pageSize: 50, framework: '', activeFrameworks: [] });
  await waitFor(() =>
    expect(mocks.listCustomObjectConfigMaps).toHaveBeenCalledWith('framework', 'tst')
  );

  // the defaults while none are chosen
  const input = screen.getByRole('combobox', { name: 'Frameworks to show' });
  expect(input.getAttribute('placeholder')).toBe('The defaults: cis-v1.10.0, MITRE, NSA');

  fireEvent.change(input, { target: { value: 'Acme' } });
  const v1 = await screen.findByRole('option', { name: /^Acme Security Baseline v1/ });
  // where each custom framework was found
  expect(within(v1).getByText('Custom framework in prd, tst')).toBeTruthy();
  fireEvent.click(v1);
  expect(settings.data.activeFrameworks).toEqual(['Acme Security Baseline v1']);
  // the page keeps opening with all controls
  expect(settings.data.framework).toBe('');

  // and opens with the Acme baseline
  fireEvent.mouseDown(screen.getByRole('combobox', { name: 'Open the Compliance page with' }));
  fireEvent.click(await screen.findByRole('option', { name: 'Acme Security Baseline v1' }));
  expect(settings.data.framework).toBe('Acme Security Baseline v1');
  expect(settings.data.pageSize).toBe(50);

  fireEvent.click(screen.getByRole('button', { name: 'Use the defaults' }));
  expect(settings.data.activeFrameworks).toEqual([]);
  expect(settings.data.framework).toBe('');
});

it('names the default frameworks of the clusters while none are chosen', async () => {
  mocks.clusters = { prd: {} };
  const label = { 'kubescape.io/default-framework': 'true' };
  mocks.listCustomObjectConfigMaps.mockResolvedValue([
    { metadata: { labels: label }, data: { name: 'Acme Security Baseline v1' } },
    { metadata: { labels: label }, data: { name: 'Acme Security Baseline v2' } },
  ]);
  renderSettings({ pageSize: 50, framework: '', activeFrameworks: [] });

  const input = screen.getByRole('combobox', { name: 'Frameworks to show' });
  await waitFor(() =>
    expect(input.getAttribute('placeholder')).toBe(
      'The defaults: Acme Security Baseline v1, Acme Security Baseline v2'
    )
  );
  fireEvent.change(input, { target: { value: 'Acme' } });
  const v1 = await screen.findByRole('option', { name: /^Acme Security Baseline v1/ });
  expect(within(v1).getByText('Custom framework in prd, a default there')).toBeTruthy();
});
