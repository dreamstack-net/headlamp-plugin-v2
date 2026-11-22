import { render } from '@testing-library/react';
import { createElement } from 'react';
import { vi } from 'vitest';
import {
  alertNotifications,
  checkNotifications,
  clustersInUrl,
  expiryNotifications,
  notifiedClusters,
  readSent,
  SelectedClustersTracker,
} from './notifications';

const mocks = vi.hoisted(() => ({
  setNotificationsInStore: vi.fn(),
  request: vi.fn(),
  fetchKubescapeAlerts: vi.fn(),
  config: {} as any,
  alertmanagerUrl: '/proxy' as string | undefined,
  selectedClusters: [] as string[],
  allowedNamespaces: [] as string[],
}));
vi.mock('@kinvolk/headlamp-plugin/lib', () => ({
  Notification: { setNotificationsInStore: mocks.setNotificationsInStore },
  Router: {
    createRouteURL: (route: string, params: Record<string, string>) =>
      `/c/${params.cluster}/${route}${params.namespace ? `/${params.namespace}` : ''}${
        params.name ? `/${params.name}` : ''
      }`,
  },
}));
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ request: mocks.request }));
vi.mock('../index', () => ({
  useHLSelectedClusters: () => mocks.selectedClusters,
  RoutingName: {
    ApplicationProfiles: 'runtime',
    SecurityExceptionDetail: 'exception',
    SecurityExceptionClusterDetail: 'cluster-exception',
  },
}));
vi.mock('../runtimedetection/alertmanager', () => ({
  fetchKubescapeAlerts: mocks.fetchKubescapeAlerts,
}));
vi.mock('./config-store', () => ({
  getAlertmanagerUrl: () => mocks.alertmanagerUrl,
  kubescapeConfigStore: { get: () => mocks.config },
}));
vi.mock('./clusterContext', () => ({ getAllowedNamespaces: () => mocks.allowedNamespaces }));

const now = new Date('2026-10-30T12:00:00Z');

function alert(fingerprint: string, severity: string) {
  return {
    labels: {
      alertname: 'KubescapeRuleViolated',
      rule_name: 'Unexpected process launched',
      severity,
      namespace: 'shop',
      workload_name: 'web',
    },
    annotations: {},
    startsAt: '2026-10-30T11:00:00Z',
    endsAt: '',
    status: { state: 'active' },
    fingerprint,
  };
}

beforeEach(() => {
  window.localStorage.clear();
  mocks.setNotificationsInStore.mockReset();
  mocks.request.mockReset().mockResolvedValue({ items: [] });
  mocks.fetchKubescapeAlerts.mockReset().mockResolvedValue([]);
  mocks.config = {};
  mocks.alertmanagerUrl = '/proxy';
  mocks.allowedNamespaces = [];
});

it('notifies about each new critical alert', () => {
  const { notifications, ids } = alertNotifications(
    [alert('a', 'critical'), alert('b', 'high'), alert('c', 'Critical')],
    'cluster-a',
    id => !id.includes('-c-')
  );

  expect(ids).toEqual(['kubescape-alert-cluster-a-a-2026-10-30T11:00:00Z']);
  expect(notifications).toEqual([
    {
      id: 'kubescape-alert-cluster-a-a-2026-10-30T11:00:00Z',
      message: 'Critical Kubescape runtime alert: Unexpected process launched in shop/web',
      date: new Date('2026-10-30T11:00:00Z').getTime(),
      cluster: 'cluster-a',
      url: '/c/cluster-a/runtime',
    },
  ]);
});

it('reads the priority the node-agent sends as the severity', () => {
  const { ids } = alertNotifications(
    [alert('a', '10'), alert('b', '8'), alert('c', '5'), alert('d', '1')],
    'cluster-a',
    () => true
  );

  expect(ids).toEqual(['kubescape-alert-cluster-a-a-2026-10-30T11:00:00Z']);
});

it('notifies once about many new critical alerts', () => {
  const alerts = ['a', 'b', 'c', 'd'].map(fingerprint => alert(fingerprint, 'critical'));
  const { notifications, ids } = alertNotifications(alerts, 'cluster-a', () => true, 1000);

  expect(ids).toHaveLength(4);
  expect(notifications.map(notification => notification.message)).toEqual([
    '4 new critical Kubescape runtime alerts in cluster-a',
  ]);
});

it('notifies about exceptions that expire soon, and again when they expired', () => {
  const notifications = expiryNotifications(
    [
      {
        name: 'accept-cve',
        namespace: 'shop',
        cluster: 'cluster-a',
        expiresAt: '2026-11-02T00:00:00Z',
        expired: false,
      },
      { name: 'old', cluster: 'cluster-a', expiresAt: '2026-10-30T00:00:00Z', expired: true },
    ],
    () => true
  );

  expect(notifications.map(notification => [notification.message, notification.url])).toEqual([
    [
      `SecurityException shop/accept-cve expires on ${new Date(
        '2026-11-02T00:00:00Z'
      ).toLocaleDateString()}`,
      '/c/cluster-a/exception/shop/accept-cve',
    ],
    [
      `ClusterSecurityException old expired on ${new Date(
        '2026-10-30T00:00:00Z'
      ).toLocaleDateString()}; scans report its findings again`,
      '/c/cluster-a/cluster-exception/old',
    ],
  ]);
  expect(notifications[0].id).not.toBe(
    expiryNotifications([{ ...notifications[0], expired: true } as any], () => true)[0]?.id
  );
});

it('sends each notification once, and keeps what it sent for two months', async () => {
  mocks.fetchKubescapeAlerts.mockResolvedValue([alert('a', 'critical')]);
  mocks.request.mockImplementation(async (url: string) =>
    url.endsWith('/securityexceptions')
      ? {
          items: [
            {
              kind: 'SecurityException',
              metadata: { name: 'accept-cve', namespace: 'shop' },
              spec: { expiresAt: '2026-11-02T00:00:00Z' },
            },
            {
              kind: 'SecurityException',
              metadata: { name: 'later', namespace: 'shop' },
              spec: { expiresAt: '2026-12-31T00:00:00Z' },
            },
          ],
        }
      : { items: [] }
  );

  await checkNotifications(['cluster-a'], now);
  expect(mocks.setNotificationsInStore).toHaveBeenCalledTimes(1);
  const sent = mocks.setNotificationsInStore.mock.calls[0][0];
  expect(sent.map((notification: any) => notification.message)).toEqual([
    'Critical Kubescape runtime alert: Unexpected process launched in shop/web',
    `SecurityException shop/accept-cve expires on ${new Date(
      '2026-11-02T00:00:00Z'
    ).toLocaleDateString()}`,
  ]);
  expect(sent[0]).toMatchObject({ seen: false, deleted: false });
  expect(mocks.request).toHaveBeenCalledWith('/apis/kubescape.io/v1beta1/securityexceptions', {
    cluster: 'cluster-a',
  });

  // nothing new: Headlamp would mark the notifications unseen again if they were sent again
  await checkNotifications(['cluster-a'], now);
  expect(mocks.setNotificationsInStore).toHaveBeenCalledTimes(1);

  expect(Object.keys(readSent(now.getTime()))).toHaveLength(2);
  expect(readSent(now.getTime() + 61 * 24 * 60 * 60 * 1000)).toEqual({});
});

it('reads the exceptions of the allowed namespaces, and those it can when others cannot be read', async () => {
  mocks.allowedNamespaces = ['shop'];
  const expiring = (kind: string, name: string, namespace?: string) => ({
    kind,
    metadata: { name, namespace },
    spec: { expiresAt: '2026-11-02T00:00:00Z' },
  });
  mocks.request.mockImplementation(async (url: string) => {
    if (url === '/apis/kubescape.io/v1beta1/namespaces/shop/securityexceptions') {
      return { items: [expiring('SecurityException', 'accept-cve', 'shop')] };
    }
    if (url === '/apis/kubescape.io/v1beta1/clustersecurityexceptions') {
      return { items: [expiring('ClusterSecurityException', 'accept-everywhere')] };
    }
    // such a user may not list the exceptions or the namespaces of the whole cluster
    throw Object.assign(new Error('forbidden'), { status: 403 });
  });

  await checkNotifications(['cluster-a'], now);

  const sent = mocks.setNotificationsInStore.mock.calls[0][0];
  expect(sent.map((notification: any) => notification.message.split(' expires')[0])).toEqual([
    'SecurityException shop/accept-cve',
    'ClusterSecurityException accept-everywhere',
  ]);
  expect(mocks.request).not.toHaveBeenCalledWith(
    '/apis/kubescape.io/v1beta1/securityexceptions',
    expect.anything()
  );
});

it('does not start a check while one runs', async () => {
  // a cluster that takes minutes to time out
  let answer: (alerts: any[]) => void = () => {};
  mocks.fetchKubescapeAlerts.mockReturnValue(new Promise(resolve => (answer = resolve)));

  const first = checkNotifications(['cluster-a'], now);
  // the next tick
  await checkNotifications(['cluster-a'], now);
  expect(mocks.fetchKubescapeAlerts).toHaveBeenCalledTimes(1);

  answer([alert('a', 'critical')]);
  await first;
  expect(mocks.setNotificationsInStore).toHaveBeenCalledTimes(1);

  // and the check after it runs again
  mocks.fetchKubescapeAlerts.mockResolvedValue([alert('b', 'critical')]);
  await checkNotifications(['cluster-a'], now);
  expect(mocks.setNotificationsInStore).toHaveBeenCalledTimes(2);
});

it('does not wait for a cluster that does not answer with the notifications of the others', async () => {
  let answer: (alerts: any[]) => void = () => {};
  mocks.fetchKubescapeAlerts.mockImplementation((cluster: string) =>
    cluster === 'cluster-a'
      ? new Promise(resolve => (answer = resolve))
      : Promise.resolve([alert('b', 'critical')])
  );

  const check = checkNotifications(['cluster-a', 'cluster-b'], now);
  await vi.waitFor(() => expect(mocks.setNotificationsInStore).toHaveBeenCalledTimes(1));
  expect(mocks.setNotificationsInStore.mock.calls[0][0][0].cluster).toBe('cluster-b');
  // kept as sent, also when Headlamp is closed before the other cluster answers
  expect(Object.keys(readSent(now.getTime()))).toEqual([
    'kubescape-alert-cluster-b-b-2026-10-30T11:00:00Z',
  ]);

  answer([]);
  await check;
});

it('does nothing when turned off', async () => {
  mocks.config = { notifications: false };
  mocks.fetchKubescapeAlerts.mockResolvedValue([alert('a', 'critical')]);

  await checkNotifications(['cluster-a'], now);

  expect(mocks.fetchKubescapeAlerts).not.toHaveBeenCalled();
  expect(mocks.setNotificationsInStore).not.toHaveBeenCalled();
});

it('does not read alerts without Alertmanager, and survives clusters without Kubescape', async () => {
  mocks.alertmanagerUrl = undefined;
  mocks.request.mockRejectedValue(new Error('404'));

  await checkNotifications(['cluster-a'], now);

  expect(mocks.fetchKubescapeAlerts).not.toHaveBeenCalled();
  expect(mocks.setNotificationsInStore).not.toHaveBeenCalled();
});

it('reads every selected cluster from the URL, under the base URL of Headlamp', () => {
  expect(
    clustersInUrl({ pathname: '/c/cluster-a+cluster-b/kubescape/overview', hash: '' })
  ).toEqual(['cluster-a', 'cluster-b']);
  expect(clustersInUrl({ pathname: '/settings', hash: '' })).toEqual([]);

  (window as any).headlampBaseUrl = '/headlamp';
  try {
    expect(clustersInUrl({ pathname: '/headlamp/c/cluster-a+cluster-b/pods', hash: '' })).toEqual([
      'cluster-a',
      'cluster-b',
    ]);
  } finally {
    delete (window as any).headlampBaseUrl;
  }
});

it('checks the clusters selected in Headlamp while the tracker is mounted', () => {
  mocks.selectedClusters = ['cluster-a', 'cluster-b'];
  const { rerender, unmount } = render(createElement(SelectedClustersTracker));
  expect(notifiedClusters()).toEqual(['cluster-a', 'cluster-b']);

  mocks.selectedClusters = ['cluster-c'];
  rerender(createElement(SelectedClustersTracker));
  expect(notifiedClusters()).toEqual(['cluster-c']);

  // without the tracker, the clusters in the URL
  unmount();
  window.history.pushState({}, '', '/c/cluster-d+cluster-e/kubescape/overview');
  try {
    expect(notifiedClusters()).toEqual(['cluster-d', 'cluster-e']);
  } finally {
    window.history.pushState({}, '', '/');
  }
});
