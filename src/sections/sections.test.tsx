// The Kubescape sections of Headlamp's pages of a namespace and a workload, which read the
// summaries of the storage once: a watch of the storage sends them without their data, or is
// refused (405) and opened again and again.
import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { vi } from 'vitest';
import addKubescapeNamespaceSection from './NamespaceSection';
import addKubescapeWorkloadSection from './WorkloadSection';

const mocks = vi.hoisted(() => ({
  fetchObject: vi.fn(),
  failedControlSummaries: [] as any[],
}));
vi.mock('../model', () => ({
  fetchObject: mocks.fetchObject,
  configurationScanSummariesClass: { pluralName: 'configurationscansummaries' },
  vulnerabilitySummaryClass: { pluralName: 'vulnerabilitysummaries' },
  vulnerabilityManifestSummaryClass: { pluralName: 'vulnerabilitymanifestsummaries' },
  workloadConfigurationScanSummaryClass: { pluralName: 'workloadconfigurationscansummaries' },
}));
vi.mock('./workloadSummaries', () => ({
  useNamespaceFailedControls: () => ({ counts: { critical: 2, high: 3, medium: 0, low: 0 } }),
  // one critical failed control per control of the summary, to show which summary it got
  useFailedControlCounts: (_cluster: string, summary: any) => {
    mocks.failedControlSummaries.push(summary);
    return summary
      ? {
          counts: {
            critical: Object.keys(summary.spec.controls ?? {}).length,
            high: 0,
            medium: 0,
            low: 0,
          },
        }
      : {};
  },
}));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ request: vi.fn() }));
vi.mock('./scannedWorkload', async importOriginal => ({
  ...(await importOriginal<typeof import('./scannedWorkload')>()),
  findScannedWorkload: async () => null,
}));
vi.mock('../index', () => ({
  RoutingName: {
    KubescapeConfigurationScanNamespaceSummary: 'namespace-compliance',
    VulnerabilitiesNamespaceSummary: 'namespace-vulnerabilities',
    KubescapeVulnerabilityDetails: 'workload-vulnerabilities',
    KubescapeWorkloadConfigurationScanDetails: 'workload-compliance',
  },
}));
vi.mock('@kinvolk/headlamp-plugin/lib/Utils', () => ({ getCluster: () => 'current' }));
vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', () => ({
  Link: ({ children, activeCluster }: { children: ReactNode; activeCluster?: string }) => (
    <a href="#link" data-active-cluster={activeCluster}>
      {children}
    </a>
  ),
  SectionBox: ({ title, children }: { title: string; children: ReactNode }) => (
    <section>
      <h2>{title}</h2>
      {children}
    </section>
  ),
  NameValueTable: ({ rows }: any) => (
    <dl>
      {rows.map((row: any, i: number) => (
        <div key={i}>
          <dt>{row.name}</dt>
          <dd>{row.value}</dd>
        </div>
      ))}
    </dl>
  ),
}));

const severities = (critical: number) => ({
  critical: { all: critical },
  high: { all: 1 },
  medium: { all: 0 },
  low: { all: 0 },
  negligible: { all: 0 },
  unknown: { all: 0 },
});

/** The storage, by the plural of the class, the cluster and the name of the object. */
function storage(objects: Record<string, any>) {
  mocks.fetchObject.mockImplementation(
    async (name: string, namespace: string, cluster: string, objectClass: any) => {
      const object = objects[`${objectClass.pluralName}/${cluster}/${namespace}/${name}`];
      if (!object) throw Object.assign(new Error('not found'), { status: 404 });
      return object;
    }
  );
}

function valueFor(label: string) {
  return screen.getByText(label, { selector: 'a' }).closest('div')!.querySelector('dd')!;
}

beforeEach(() => {
  mocks.fetchObject.mockReset();
  mocks.failedControlSummaries = [];
});
afterEach(cleanup);

describe('the section of a namespace', () => {
  const namespace = (labels?: object) => ({
    kind: 'Namespace',
    cluster: 'cluster-b',
    jsonData: { metadata: { name: 'shop', labels } },
  });
  const section = (resource: any) => {
    const sections = addKubescapeNamespaceSection(resource, [{ id: 'EVENTS' }]);
    expect(sections.map((s: any) => s.id)).toEqual([
      'kubescape-configuration-scan-summaries',
      'EVENTS',
    ]);
    return sections[0].section;
  };

  it('reads the summaries of the namespace once, in the cluster of the namespace', async () => {
    storage({
      'configurationscansummaries/cluster-b//shop': { spec: { severities: {} } },
      'vulnerabilitysummaries/cluster-b//shop': { spec: { severities: severities(7) } },
    });
    const view = render(section(namespace()));

    await waitFor(() => expect(valueFor('Vulnerabilities').textContent).toContain('7 Critical'));
    expect(valueFor('Configuration scan').textContent).toContain('2 Critical');
    expect(
      mocks.fetchObject.mock.calls.map(call => [...call.slice(0, 3), call[3].pluralName])
    ).toEqual([
      ['shop', '', 'cluster-b', 'configurationscansummaries'],
      ['shop', '', 'cluster-b', 'vulnerabilitysummaries'],
    ]);

    // Headlamp watches the namespace, and draws the section again with each new version of it
    view.rerender(section(namespace({ changed: 'yes' })));
    await act(async () => {});
    expect(mocks.fetchObject).toHaveBeenCalledTimes(2);
    expect(valueFor('Vulnerabilities').textContent).toContain('7 Critical');
  });

  it('shows the summary there is, and nothing for a namespace without scans', async () => {
    storage({ 'vulnerabilitysummaries/cluster-b//shop': { spec: { severities: severities(4) } } });
    const view = render(section(namespace()));
    await waitFor(() => expect(valueFor('Vulnerabilities').textContent).toContain('4 Critical'));
    expect(screen.queryByText('Configuration scan')).toBeNull();
    view.unmount();

    storage({});
    render(section(namespace()));
    await waitFor(() => expect(mocks.fetchObject).toHaveBeenCalledTimes(4));
    await act(async () => {});
    expect(screen.queryByRole('heading', { name: 'Kubescape' })).toBeNull();
  });
});

describe('the section of a workload', () => {
  const deployment = (generation = 1) => ({
    kind: 'Deployment',
    cluster: 'cluster-a',
    jsonData: {
      metadata: { name: 'web', namespace: 'shop', generation },
      spec: { template: { spec: { containers: [{ name: 'nginx' }] } } },
    },
  });
  const section = (resource: any) => {
    const sections = addKubescapeWorkloadSection(resource, [{ id: 'METADATA' }]);
    return sections[1].section;
  };

  it('reads the configuration scan summary once, with its controls', async () => {
    const configurationScan = {
      metadata: { name: 'deployment-web', namespace: 'shop' },
      spec: { controls: { 'C-0016': {}, 'C-0017': {}, 'C-0057': {} } },
    };
    storage({
      'workloadconfigurationscansummaries/cluster-a/shop/deployment-web': configurationScan,
      'vulnerabilitymanifestsummaries/cluster-a/shop/deployment-web-nginx': {
        metadata: {
          name: 'deployment-web-nginx',
          labels: { 'kubescape.io/workload-container-name': 'nginx' },
        },
        spec: { severities: severities(5) },
      },
    });
    const view = render(section(deployment()));

    await waitFor(() => expect(valueFor('Compliance').textContent).toContain('3 Critical'));
    expect(valueFor('Vulnerabilities / nginx').textContent).toContain('5 Critical');
    expect(mocks.failedControlSummaries).toContain(configurationScan);

    // Headlamp watches the deployment; the summary is not read again
    view.rerender(section(deployment(2)));
    await act(async () => {});
    const configurationReads = mocks.fetchObject.mock.calls.filter(
      call => call[3].pluralName === 'workloadconfigurationscansummaries'
    );
    expect(configurationReads.map(call => call.slice(0, 3))).toEqual([
      ['deployment-web', 'shop', 'cluster-a'],
    ]);
    expect(valueFor('Compliance').textContent).toContain('3 Critical');
  });

  it('links to the CVEs in the cluster of the workload', async () => {
    storage({
      'workloadconfigurationscansummaries/cluster-a/shop/deployment-web': {
        metadata: { name: 'deployment-web', namespace: 'shop' },
        spec: { controls: {} },
      },
      'vulnerabilitymanifestsummaries/cluster-a/shop/deployment-web-nginx': {
        metadata: {
          name: 'deployment-web-nginx',
          labels: { 'kubescape.io/workload-container-name': 'nginx' },
        },
        spec: { severities: severities(5) },
      },
    });
    render(section(deployment()));

    // in Headlamp's details drawer the address names another cluster first, which the page of
    // the CVEs would read
    const cves = await screen.findByText('Vulnerabilities / nginx', { selector: 'a' });
    expect(cves.getAttribute('data-active-cluster')).toBe('cluster-a');
    // the route of the configuration scan names the cluster in its path too, where an
    // activeCluster would put all selected clusters
    const compliance = await screen.findByText('Compliance', { selector: 'a' });
    expect(compliance.hasAttribute('data-active-cluster')).toBe(false);
  });

  it('shows the results of the CronJob for one of its Jobs', async () => {
    storage({
      'workloadconfigurationscansummaries/cluster-a/shop/cronjob-backup': {
        metadata: { name: 'cronjob-backup', namespace: 'shop' },
        spec: { controls: { 'C-0016': {} } },
      },
    });
    render(
      section({
        kind: 'Job',
        cluster: 'cluster-a',
        jsonData: {
          metadata: {
            name: 'backup-29123456',
            namespace: 'shop',
            ownerReferences: [{ kind: 'CronJob', name: 'backup', controller: true }],
          },
          spec: { template: { spec: { containers: [{ name: 'dump' }] } } },
        },
      })
    );

    await waitFor(() => expect(valueFor('Compliance').textContent).toContain('1 Critical'));
    expect(screen.getByText('CronJob backup')).toBeTruthy();
    expect(mocks.fetchObject.mock.calls.map(call => call[0]).sort()).toEqual([
      'cronjob-backup',
      'cronjob-backup-dump',
    ]);
  });
});
