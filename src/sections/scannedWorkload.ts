import { request } from '@kinvolk/headlamp-plugin/lib/ApiProxy';

export interface WorkloadRef {
  kind: string;
  name: string;
}

interface ObjectMeta {
  name: string;
  labels?: Record<string, string>;
  ownerReferences?: Array<WorkloadRef & { controller?: boolean }>;
}

// Controllers whose own controller Kubescape scans instead, with their API path
const ownedControllerPaths: Record<string, (namespace: string, name: string) => string> = {
  ReplicaSet: (namespace, name) => `/apis/apps/v1/namespaces/${namespace}/replicasets/${name}`,
  Job: (namespace, name) => `/apis/batch/v1/namespaces/${namespace}/jobs/${name}`,
};

function controllerOf(metadata: ObjectMeta | undefined): WorkloadRef | undefined {
  const controller = metadata?.ownerReferences?.find(reference => reference.controller);
  // a static pod is owned by its node, and Kubescape scans it as the pod
  return controller?.kind === 'Node' ? undefined : controller;
}

/**
 * The workloads that Kubescape may have scanned for a listed object, the most likely first.
 * Pods are scanned as the workload that runs them; that is guessed from the name of their
 * controller, since a resource list cannot afford to look up the controllers of every pod, with
 * the pod itself last. A Job of a CronJob is scanned as the CronJob.
 */
export function scannedWorkloadCandidates(object: {
  kind: string;
  metadata: ObjectMeta;
}): WorkloadRef[] {
  const { name } = object.metadata;
  const controller = controllerOf(object.metadata);
  if (object.kind === 'Job' && controller?.kind === 'CronJob') {
    return [
      { kind: 'CronJob', name: controller.name },
      { kind: 'Job', name },
    ];
  }
  if (object.kind !== 'Pod') return [{ kind: object.kind, name }];

  // last the pod itself, for a controller whose pods Kubescape scans as pods
  const pod = { kind: 'Pod', name };
  if (!controller) return [pod];

  if (controller.kind === 'ReplicaSet') {
    const hash = object.metadata.labels?.['pod-template-hash'];
    const deployment =
      hash && controller.name.endsWith(`-${hash}`)
        ? controller.name.slice(0, -hash.length - 1)
        : undefined;
    return [
      ...(deployment ? [{ kind: 'Deployment', name: deployment }] : []),
      { kind: 'ReplicaSet', name: controller.name },
      pod,
    ];
  }
  if (controller.kind === 'Job') {
    // CronJobs name their Jobs after the scheduled time: <cronjob>-<minutes since epoch>
    const cronJob = /^(.+)-\d+$/.exec(controller.name)?.[1];
    return [
      ...(cronJob ? [{ kind: 'CronJob', name: cronJob }] : []),
      { kind: 'Job', name: controller.name },
      pod,
    ];
  }
  return [{ kind: controller.kind, name: controller.name }, pod];
}

/**
 * Finds the workload that Kubescape scans for a pod, by following its controllers: a pod of a
 * Deployment is scanned as the Deployment (Pod → ReplicaSet → Deployment), a pod of a CronJob
 * as the CronJob (Pod → Job → CronJob). A pod without a controller is scanned itself.
 */
export async function findScannedWorkload(
  pod: { metadata: ObjectMeta & { namespace: string } },
  cluster?: string
): Promise<WorkloadRef> {
  let workload: WorkloadRef = { kind: 'Pod', name: pod.metadata.name };
  let controller = controllerOf(pod.metadata);

  while (controller) {
    workload = { kind: controller.kind, name: controller.name };
    const path = ownedControllerPaths[controller.kind]?.(pod.metadata.namespace, controller.name);
    if (!path) break;

    const object = await request(path, cluster ? { cluster } : {}).catch(() => null);
    // a controller that cannot be read, as by a user who may only read pods: the workload that
    // the name of the controller tells, as in the lists
    if (!object) return scannedWorkloadCandidates({ kind: 'Pod', metadata: pod.metadata })[0];
    controller = controllerOf(object.metadata);
  }
  return workload;
}
