/*
  Headlamp notifications for critical runtime alerts and for security exceptions that expire
  soon, checked every few minutes for the clusters being viewed.
*/
import { Notification, Router } from '@kinvolk/headlamp-plugin/lib';
import { useEffect } from 'react';
import { fetchSecurityExceptions } from '../exceptions/apply-security-exceptions';
import { RoutingName, useHLSelectedClusters } from '../index';
import { ExceptionExpiry, expiringExceptions } from '../overview/summaries';
import { alertNamespace, alertSeverity, alertWorkload } from '../runtimedetection/alertFields';
import { AlertmanagerAlert, fetchKubescapeAlerts } from '../runtimedetection/alertmanager';
import { getAllowedNamespaces } from './clusterContext';
import { getAlertmanagerUrl, kubescapeConfigStore } from './config-store';
import { headlampBaseUrl, isElectron } from './PluginHelper';

const { createRouteURL } = Router;

export interface KubescapeNotification {
  id: string;
  message: string;
  date: number;
  cluster: string;
  url: string;
}

// more new alerts than this are reported in one notification
const maxAlertNotifications = 3;
const expiryDays = 7;
const day = 24 * 60 * 60 * 1000;

function runtimeUrl(cluster: string) {
  return createRouteURL(RoutingName.ApplicationProfiles, { cluster });
}

export function alertId(alert: AlertmanagerAlert, cluster: string) {
  // an alert that ends and fires again is a new occurrence
  return `kubescape-alert-${cluster}-${alert.fingerprint}-${alert.startsAt}`;
}

/** Notifications for the critical alerts, one per alert or one for many. */
export function alertNotifications(
  alerts: AlertmanagerAlert[],
  cluster: string,
  isNew: (id: string) => boolean,
  now: number = Date.now()
): { notifications: KubescapeNotification[]; ids: string[] } {
  const critical = alerts.filter(
    alert => alertSeverity(alert) === 'Critical' && isNew(alertId(alert, cluster))
  );
  const ids = critical.map(alert => alertId(alert, cluster));
  if (critical.length > maxAlertNotifications) {
    return {
      ids,
      notifications: [
        {
          id: `kubescape-alerts-${cluster}-${now}`,
          message: `${critical.length} new critical Kubescape runtime alerts in ${cluster}`,
          date: now,
          cluster,
          url: runtimeUrl(cluster),
        },
      ],
    };
  }
  return {
    ids,
    notifications: critical.map(alert => {
      const labels = alert.labels;
      const workload = alertWorkload(alert);
      const namespace = alertNamespace(alert);
      const where = workload ? ` in ${namespace ? `${namespace}/` : ''}${workload}` : '';
      return {
        id: alertId(alert, cluster),
        message: `Critical Kubescape runtime alert: ${
          labels.rule_name ?? labels.alertname
        }${where}`,
        date: new Date(alert.startsAt).getTime() || now,
        cluster,
        url: runtimeUrl(cluster),
      };
    }),
  };
}

/** Notifications for exceptions that expire within a week, and again when they expired. */
export function expiryNotifications(
  expiries: ExceptionExpiry[],
  isNew: (id: string) => boolean,
  now: number = Date.now()
): KubescapeNotification[] {
  return expiries
    .map(expiry => {
      const kind = expiry.namespace ? 'SecurityException' : 'ClusterSecurityException';
      const name = expiry.namespace ? `${expiry.namespace}/${expiry.name}` : expiry.name;
      const url = expiry.namespace
        ? createRouteURL(RoutingName.SecurityExceptionDetail, {
            cluster: expiry.cluster,
            namespace: expiry.namespace,
            name: expiry.name,
          })
        : createRouteURL(RoutingName.SecurityExceptionClusterDetail, {
            cluster: expiry.cluster,
            name: expiry.name,
          });
      const date = new Date(expiry.expiresAt);
      const entries = expiry.entries ? expiry.entries.join(', ') : undefined;
      let message: string;
      if (entries) {
        message = expiry.expired
          ? `${kind} ${name}: ${entries} expired on ${date.toLocaleDateString()}; scans report these findings again`
          : `${kind} ${name}: ${entries} expire on ${date.toLocaleDateString()}`;
      } else {
        message = expiry.expired
          ? `${kind} ${name} expired on ${date.toLocaleDateString()}; scans report its findings again`
          : `${kind} ${name} expires on ${date.toLocaleDateString()}`;
      }
      return {
        id: `kubescape-exception-${expiry.cluster}-${name}-${expiry.expiresAt}-${
          expiry.expired ? 'expired' : 'expiring'
        }${entries ? `-${entries}` : ''}`,
        message,
        date: expiry.expired ? date.getTime() : now,
        cluster: expiry.cluster,
        url,
      };
    })
    .filter(notification => isNew(notification.id));
}

// ── Notified ids ─────────────────────────────────────────────────────────────

// Headlamp replaces a notification that is sent again, so it would show as unseen again
const sentKey = 'kubescape.notifications.sent';
const keepSent = 60 * day;

export function readSent(now: number = Date.now()): Record<string, number> {
  try {
    const sent: Record<string, number> = JSON.parse(window.localStorage.getItem(sentKey) ?? '{}');
    return Object.fromEntries(Object.entries(sent).filter(([, at]) => now - at < keepSent));
  } catch {
    return {};
  }
}

function writeSent(sent: Record<string, number>) {
  try {
    window.localStorage.setItem(sentKey, JSON.stringify(sent));
  } catch {
    // without storage, notifications may repeat after a restart
  }
}

async function fetchExpiries(cluster: string, now: Date): Promise<ExceptionExpiry[]> {
  // as the Overview reads them: with allowed namespaces the SecurityExceptions of each of them,
  // and the exceptions that can be read when others cannot
  const exceptions = await fetchSecurityExceptions(cluster, [], [], getAllowedNamespaces(cluster));
  return expiringExceptions(exceptions, cluster, now, expiryDays).filter(
    expiry => !expiry.expired || now.getTime() - new Date(expiry.expiresAt).getTime() < day
  );
}

// whether a check runs; the next one would send the same notifications again
let checking = false;

/**
 * Checks the clusters being viewed once, and sends the notifications that are new. It does
 * nothing while an earlier check runs, as of a cluster that takes minutes to time out. Each
 * cluster is checked on its own, so a cluster that does not answer does not keep back the
 * notifications of the others.
 */
export async function checkNotifications(clusters: string[], now: Date = new Date()) {
  if (kubescapeConfigStore.get()?.notifications === false || checking) return;

  checking = true;
  try {
    const sent = readSent(now.getTime());
    const isNew = (id: string) => sent[id] === undefined;

    await Promise.all(
      clusters.map(async cluster => {
        const [alerts, expiries] = await Promise.all([
          getAlertmanagerUrl() ? fetchKubescapeAlerts(cluster).catch(() => []) : [],
          // a cluster without the exception CRDs or permission to read them has no expiries
          fetchExpiries(cluster, now).catch(() => []),
        ]);
        const found = alertNotifications(alerts, cluster, isNew, now.getTime());
        const notifications = [
          ...found.notifications,
          ...expiryNotifications(expiries, isNew, now.getTime()),
        ];

        found.ids.forEach(id => (sent[id] = now.getTime()));
        notifications.forEach(notification => (sent[notification.id] = now.getTime()));
        writeSent(sent);
        // an empty list would delete all notifications
        if (notifications.length > 0) {
          Notification.setNotificationsInStore(
            notifications.map(notification => ({
              ...notification,
              seen: false,
              deleted: false,
            })) as any
          );
        }
      })
    );
  } finally {
    checking = false;
  }
}

// ── Selected clusters ────────────────────────────────────────────────────────

// the clusters selected in Headlamp, kept by SelectedClustersTracker while it is mounted
let trackedClusters: string[] | null = null;

/**
 * Keeps the clusters selected in Headlamp for the checks, which run outside React. It renders
 * nothing; it is mounted in the app bar, which every page shows.
 */
export function SelectedClustersTracker() {
  const clusters: (string | null)[] = useHLSelectedClusters() ?? [];
  const key = clusters.filter(Boolean).join('+');
  useEffect(() => {
    trackedClusters = key ? key.split('+') : [];
    return () => {
      trackedClusters = null;
    };
  }, [key]);
  return null;
}

/**
 * All clusters in the URL, as Headlamp reads them (getSelectedClusters, which plugins cannot
 * import): /c/cluster-a+cluster-b/... after the base URL, in the hash in Headlamp desktop.
 * Headlamp's getClusterGroup only returns the first of them.
 */
export function clustersInUrl(location: Pick<Location, 'pathname' | 'hash'> = window.location) {
  const path = isElectron()
    ? location.hash.substring(1)
    : location.pathname.slice(headlampBaseUrl().length);
  const match = /^\/c\/([^/]+)/.exec(path);
  return match ? match[1].split('+').filter(Boolean) : [];
}

/** The clusters the checks are for: the selected clusters, or those in the URL. */
export function notifiedClusters(): string[] {
  return trackedClusters ?? clustersInUrl();
}

let started = false;

/** Checks for notifications every five minutes, for the selected clusters. */
export function startNotifications() {
  if (started || typeof Notification?.setNotificationsInStore !== 'function') return;
  started = true;
  const check = () => {
    // the next check after Headlamp is shown again catches up
    if (document.hidden) return;
    const clusters = notifiedClusters();
    if (clusters.length > 0) checkNotifications(clusters).catch(() => {});
  };
  // give Headlamp time to load the clusters
  setTimeout(check, 30 * 1000);
  setInterval(check, 5 * 60 * 1000);
}
