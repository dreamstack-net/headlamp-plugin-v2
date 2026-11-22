import { vi } from 'vitest';
import { findScannedWorkload, scannedWorkloadCandidates } from './scannedWorkload';

const request = vi.hoisted(() => vi.fn());
vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ request }));

const owned = (kind: string, name: string) => ({
  ownerReferences: [
    { kind: 'Unrelated', name: 'not-the-controller' },
    { kind, name, controller: true },
  ],
});

function pod(owner?: ReturnType<typeof owned>) {
  return { metadata: { name: 'pod-1', namespace: 'shop', ...owner } };
}

// a block body: a function that beforeEach returns is called after the test, as a cleanup
beforeEach(() => {
  request.mockReset();
});

it('scans a Deployment pod as its Deployment', async () => {
  request.mockResolvedValue({ metadata: { name: 'web-6d4f', ...owned('Deployment', 'web') } });

  expect(await findScannedWorkload(pod(owned('ReplicaSet', 'web-6d4f')), 'cluster-a')).toEqual({
    kind: 'Deployment',
    name: 'web',
  });
  expect(request).toHaveBeenCalledWith('/apis/apps/v1/namespaces/shop/replicasets/web-6d4f', {
    cluster: 'cluster-a',
  });
});

it('scans a CronJob pod as its CronJob', async () => {
  request.mockResolvedValue({ metadata: { name: 'backup-123', ...owned('CronJob', 'backup') } });

  expect(await findScannedWorkload(pod(owned('Job', 'backup-123')))).toEqual({
    kind: 'CronJob',
    name: 'backup',
  });
  expect(request).toHaveBeenCalledWith('/apis/batch/v1/namespaces/shop/jobs/backup-123', {});
});

it('scans a StatefulSet pod as its StatefulSet without further lookups', async () => {
  expect(await findScannedWorkload(pod(owned('StatefulSet', 'db')))).toEqual({
    kind: 'StatefulSet',
    name: 'db',
  });
  expect(request).not.toHaveBeenCalled();
});

it('scans a pod without a controller as the pod', async () => {
  expect(await findScannedWorkload(pod())).toEqual({ kind: 'Pod', name: 'pod-1' });
});

it('scans a ReplicaSet without a controller, or one it cannot read, as the ReplicaSet', async () => {
  request.mockResolvedValueOnce({ metadata: { name: 'web-6d4f' } });
  expect(await findScannedWorkload(pod(owned('ReplicaSet', 'web-6d4f')))).toEqual({
    kind: 'ReplicaSet',
    name: 'web-6d4f',
  });

  request.mockRejectedValueOnce(new Error('forbidden'));
  expect(await findScannedWorkload(pod(owned('ReplicaSet', 'web-6d4f')))).toEqual({
    kind: 'ReplicaSet',
    name: 'web-6d4f',
  });
});

it('guesses the workload of a pod whose controller it cannot read, as the lists do', async () => {
  // a user who may read pods, but not ReplicaSets or Jobs
  request.mockRejectedValue(new Error('forbidden'));
  const deploymentPod = pod(owned('ReplicaSet', 'web-6d4f'));
  Object.assign(deploymentPod.metadata, { labels: { 'pod-template-hash': '6d4f' } });

  expect(await findScannedWorkload(deploymentPod)).toEqual({ kind: 'Deployment', name: 'web' });
  expect(await findScannedWorkload(pod(owned('Job', 'backup-29123456')))).toEqual({
    kind: 'CronJob',
    name: 'backup',
  });
});

it('scans a static pod, which its node owns, as the pod', async () => {
  expect(await findScannedWorkload(pod(owned('Node', 'control-plane')))).toEqual({
    kind: 'Pod',
    name: 'pod-1',
  });
  expect(request).not.toHaveBeenCalled();
});

it('guesses the workload that runs a pod from its controller, with the pod itself last', () => {
  const listed = (controller?: { kind: string; name: string }, hash?: string) => ({
    kind: 'Pod',
    metadata: {
      name: 'web-6d4cf56db6-abcde',
      labels: (hash ? { 'pod-template-hash': hash } : {}) as Record<string, string>,
      ownerReferences: controller ? [{ ...controller, controller: true }] : [],
    },
  });
  const itself = { kind: 'Pod', name: 'web-6d4cf56db6-abcde' };

  expect(
    scannedWorkloadCandidates(listed({ kind: 'ReplicaSet', name: 'web-6d4cf56db6' }, '6d4cf56db6'))
  ).toEqual([
    { kind: 'Deployment', name: 'web' },
    { kind: 'ReplicaSet', name: 'web-6d4cf56db6' },
    itself,
  ]);
  expect(scannedWorkloadCandidates(listed({ kind: 'Job', name: 'backup-29123456' }))).toEqual([
    { kind: 'CronJob', name: 'backup' },
    { kind: 'Job', name: 'backup-29123456' },
    itself,
  ]);
  expect(scannedWorkloadCandidates(listed({ kind: 'StatefulSet', name: 'db' }))).toEqual([
    { kind: 'StatefulSet', name: 'db' },
    itself,
  ]);
  expect(scannedWorkloadCandidates(listed())).toEqual([itself]);
  // a static pod
  expect(scannedWorkloadCandidates(listed({ kind: 'Node', name: 'control-plane' }))).toEqual([
    itself,
  ]);
});

it('takes a listed workload for itself, and a Job of a CronJob for the CronJob first', () => {
  expect(scannedWorkloadCandidates({ kind: 'Deployment', metadata: { name: 'web' } })).toEqual([
    { kind: 'Deployment', name: 'web' },
  ]);
  expect(
    scannedWorkloadCandidates({
      kind: 'Job',
      metadata: {
        name: 'backup-29123456',
        ownerReferences: [{ kind: 'CronJob', name: 'backup', controller: true }],
      },
    })
  ).toEqual([
    { kind: 'CronJob', name: 'backup' },
    { kind: 'Job', name: 'backup-29123456' },
  ]);
  // a Job that was started by hand, whatever its name
  expect(scannedWorkloadCandidates({ kind: 'Job', metadata: { name: 'migrate-42' } })).toEqual([
    { kind: 'Job', name: 'migrate-42' },
  ]);
});
