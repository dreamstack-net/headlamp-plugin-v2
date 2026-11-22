import { loadAll } from 'js-yaml';
import { expect, it } from 'vitest';
import type {
  ClusterSecurityException,
  SecurityException,
} from '../softwarecomposition/SecurityException';
import {
  exceptionFileName,
  exceptionsFileName,
  exceptionsYaml,
  exceptionYaml,
  exportableException,
} from './exceptionYaml';
import { historyAnnotation } from './history';

// as the API server returns it
const live = {
  apiVersion: 'kubescape.io/v1beta1',
  kind: 'SecurityException',
  metadata: {
    name: 'accept-web',
    namespace: 'shop',
    uid: '1234',
    resourceVersion: '42',
    creationTimestamp: '2026-10-30T10:00:00Z',
    generation: 3,
    managedFields: [{ manager: 'headlamp' }],
    labels: { team: 'web' },
    annotations: {
      [historyAnnotation]: '[{"action":"created","user":"alice","time":"2026-10-30T10:00:00Z"}]',
      'kubectl.kubernetes.io/last-applied-configuration': '{}',
      'argocd.argoproj.io/tracking-id': 'security:kubescape.io/SecurityException:shop/accept-web',
      'example.com/ticket': 'SEC-1',
    },
  },
  spec: {
    author: 'alice',
    reason: 'No fix upstream',
    match: { resources: [{ kind: 'Deployment', name: 'web' }] },
    vulnerabilities: [{ vulnerability: { id: 'CVE-1' }, status: 'not_affected' }],
  },
  status: { conditions: [] },
} as unknown as SecurityException;

const clusterWide = (name: string, reason = 'shared'): ClusterSecurityException => ({
  apiVersion: 'kubescape.io/v1beta1',
  kind: 'ClusterSecurityException',
  metadata: { name, uid: name },
  spec: { reason, match: {}, posture: [{ controlID: 'C-0017', action: 'ignore' }] },
});

it('leaves out what the cluster and its tools set, and keeps the author and own annotations', () => {
  expect(exportableException(live)).toEqual({
    apiVersion: 'kubescape.io/v1beta1',
    kind: 'SecurityException',
    metadata: {
      name: 'accept-web',
      namespace: 'shop',
      labels: { team: 'web' },
      annotations: { 'example.com/ticket': 'SEC-1' },
    },
    spec: live.spec,
  });
  // without annotations of its own, the exception has none
  expect(exportableException(clusterWide('a')).metadata).toEqual({ name: 'a' });
});

it('writes the exception as YAML in the order of a manifest, named after it', () => {
  const text = exceptionYaml(live);
  expect(text.split('\n').slice(0, 4)).toEqual([
    'apiVersion: kubescape.io/v1beta1',
    'kind: SecurityException',
    'metadata:',
    '  name: accept-web',
  ]);
  expect(text).not.toContain('resourceVersion');
  expect(text).not.toContain(historyAnnotation);
  expect(exceptionFileName(live)).toBe('accept-web.yaml');
});

it('writes the exceptions of several clusters once each, naming their clusters', () => {
  const text = exceptionsYaml([
    { cluster: 'tst', exception: live },
    { cluster: 'prd', exception: clusterWide('b') },
    { cluster: 'tst', exception: clusterWide('b') },
    // differs in prd, so it is written for each cluster
    { cluster: 'prd', exception: clusterWide('a', 'prd only') },
    { cluster: 'tst', exception: clusterWide('a') },
  ]);

  expect(text.match(/^# .*$/gm)).toEqual([
    '# Cluster: prd',
    '# Cluster: tst',
    '# Clusters: prd, tst',
    '# Cluster: tst',
  ]);
  const documents = loadAll(text) as any[];
  expect(documents.map(document => [document.kind, document.metadata.name])).toEqual([
    ['ClusterSecurityException', 'a'],
    ['ClusterSecurityException', 'a'],
    ['ClusterSecurityException', 'b'],
    ['SecurityException', 'accept-web'],
  ]);
  expect(documents[0].spec.reason).toBe('prd only');
  expect(documents.every(document => !document.metadata.uid)).toBe(true);
});

it('writes the exceptions of one cluster without comments', () => {
  const text = exceptionsYaml([
    { cluster: 'prd', exception: clusterWide('b') },
    { cluster: 'prd', exception: clusterWide('a') },
  ]);
  expect(text).not.toContain('#');
  expect(text.split('---\n')).toHaveLength(2);
  expect(exceptionsFileName(['prd'])).toBe('security-exceptions-prd.yaml');
  expect(exceptionsFileName(['prd', 'tst'])).toBe('security-exceptions.yaml');
});
