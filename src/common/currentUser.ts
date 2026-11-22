import { post } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import { getCluster } from '@kinvolk/headlamp-plugin/lib/Utils';
import { useEffect, useState } from 'react';

// the lookups in progress, which the callers of the moment share
const lookups = new Map<string, Promise<string | undefined>>();

// SelfSubjectReview is GA in Kubernetes 1.28 and beta, enabled by default, in 1.27
async function lookUpUsername(cluster?: string): Promise<string | undefined> {
  for (const version of ['v1', 'v1beta1']) {
    try {
      const review = await post(
        `/apis/authentication.k8s.io/${version}/selfsubjectreviews`,
        { apiVersion: `authentication.k8s.io/${version}`, kind: 'SelfSubjectReview' },
        false,
        cluster ? { cluster } : undefined
      );
      const username = review?.status?.userInfo?.username;
      if (username) return username;
    } catch {
      // try the next version
    }
  }
  return undefined;
}

/**
 * The name the Kubernetes API server knows the user of Headlamp as, like `kubectl auth whoami`.
 * Undefined when the cluster does not tell. Looked up on every call, as logging out and in as
 * another user does not reload the plugin: the forms ask when they open and when they are sent.
 */
export function getCurrentUser(cluster: string | null = getCluster()): Promise<string | undefined> {
  const key = cluster ?? '';
  let username = lookups.get(key);
  if (!username) {
    username = lookUpUsername(cluster ?? undefined).finally(() => lookups.delete(key));
    lookups.set(key, username);
  }
  return username;
}

/** Hook around {@link getCurrentUser}, for the current cluster unless another is given. */
export function useCurrentUser(cluster?: string): string | undefined {
  const [user, setUser] = useState<{ cluster: string | null; name: string | undefined }>();
  // without a cluster, the one of the address, which can change while the page stays
  const target = cluster ?? getCluster();
  useEffect(() => {
    let active = true;
    getCurrentUser(target).then(name => {
      if (active) setUser({ cluster: target, name });
    });
    return () => {
      active = false;
    };
  }, [target]);
  // not the user of the cluster shown before, while this one is asked
  return user?.cluster === target ? user.name : undefined;
}
