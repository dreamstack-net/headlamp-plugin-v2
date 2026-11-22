/*
  Asks Kubernetes whether the user may do something, so actions they cannot do are disabled
  with an explanation instead of failing with an API error.
*/
import { post } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import { getCluster } from '@kinvolk/headlamp-plugin/lib/Utils';
import { IconButton, Tooltip } from '@mui/material';
import { ReactElement, ReactNode, useEffect, useState } from 'react';

export interface AccessCheck {
  // the API group, '' for the core group
  group: string;
  resource: string;
  subresource?: string;
  verb: string;
  // undefined for cluster-scoped resources, or to ask about all namespaces
  namespace?: string;
  name?: string;
}

// Answers are kept briefly: logging out and in as another user, whose permissions differ, does
// not reload the plugin
const answerLifetime = 10_000;

// the answer, and until when it is kept (Infinity while it is asked)
const answers = new Map<string, { answer: Promise<boolean | undefined>; until: number }>();

/**
 * Whether the user may do it, or undefined when the cluster does not tell. Answers are
 * remembered for ten seconds.
 */
export function canI(
  check: AccessCheck,
  cluster: string | null = getCluster()
): Promise<boolean | undefined> {
  const key = JSON.stringify([cluster, check]);
  const kept = answers.get(key);
  if (kept && Date.now() < kept.until) return kept.answer;

  const entry = { answer: Promise.resolve<boolean | undefined>(undefined), until: Infinity };
  const forget = () => {
    if (answers.get(key) === entry) answers.delete(key);
  };
  // any failure, even a synchronous one, means that the answer is unknown
  entry.answer = Promise.resolve()
    .then(() =>
      post(
        '/apis/authorization.k8s.io/v1/selfsubjectaccessreviews',
        {
          apiVersion: 'authorization.k8s.io/v1',
          kind: 'SelfSubjectAccessReview',
          spec: { resourceAttributes: check },
        },
        false,
        cluster ? { cluster } : undefined
      )
    )
    .then((review: any) => {
      const allowed = review?.status?.allowed;
      if (typeof allowed === 'boolean') {
        entry.until = Date.now() + answerLifetime;
        return allowed;
      }
      forget();
      return undefined;
    })
    .catch(() => {
      forget();
      return undefined;
    });
  answers.set(key, entry);
  return entry.answer;
}

/**
 * Hook around {@link canI}; undefined while asking, or when there is nothing to check. The answer
 * to another check or cluster is never returned, also not while the new one is asked.
 */
export function useCanI(check: AccessCheck | null, cluster?: string | null): boolean | undefined {
  const [answer, setAnswer] = useState<{ key: string; allowed: boolean | undefined }>();
  // without a cluster, the one of the address, which can change while the page stays
  const target = cluster === undefined ? getCluster() : cluster;
  const key = JSON.stringify([target, check]);

  useEffect(() => {
    if (!check) return;
    let active = true;
    canI(check, target).then(allowed => {
      if (active) setAnswer({ key, allowed });
    });
    return () => {
      active = false;
    };
    // key covers check and cluster, which may be new objects on every render
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  return check && answer?.key === key ? answer.allowed : undefined;
}

/**
 * The first of the checks that the user is denied, or undefined while asking, or when every check
 * is allowed or unanswered. The answer to other checks or another cluster is never returned,
 * also not while the new ones are asked.
 */
export function useDeniedCheck(
  checks: AccessCheck[],
  cluster?: string | null
): AccessCheck | undefined {
  const [answer, setAnswer] = useState<{ key: string; denied: AccessCheck | undefined }>();
  // without a cluster, the one of the address, which can change while the page stays
  const target = cluster === undefined ? getCluster() : cluster;
  const key = JSON.stringify([target, checks]);

  useEffect(() => {
    let active = true;
    Promise.all(checks.map(check => canI(check, target))).then(answers => {
      if (active) setAnswer({ key, denied: checks[answers.indexOf(false)] });
    });
    return () => {
      active = false;
    };
    // key covers checks and cluster, which may be new objects on every render
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  return answer?.key === key ? answer.denied : undefined;
}

/** Explains which permission the user is missing. */
export function deniedMessage(check: AccessCheck): string {
  const resource = check.subresource ? `${check.resource}/${check.subresource}` : check.resource;
  const object = check.name ? ` ${check.name}` : '';
  const where = check.namespace ? ` in namespace ${check.namespace}` : '';
  return `You are not allowed to ${check.verb} ${resource}${object}${where}.`;
}

/**
 * Renders an action, disabled with an explanation when the user may not do it; an action that
 * needs several permissions names the first one missing. While the answer is unknown the action
 * stays enabled, so an unanswered check never blocks the user.
 */
export function Permitted(
  props: Readonly<{
    check: AccessCheck | AccessCheck[] | null;
    cluster?: string | null;
    children: (allowed: boolean) => ReactElement;
  }>
) {
  const { check, cluster, children } = props;
  let checks: AccessCheck[] = [];
  if (Array.isArray(check)) checks = check;
  else if (check) checks = [check];
  const denied = useDeniedCheck(checks, cluster);
  if (denied) {
    return (
      <Tooltip title={deniedMessage(denied)}>
        <span>{children(false)}</span>
      </Tooltip>
    );
  }
  return children(true);
}

/** An icon button with a tooltip, disabled with an explanation when the user may not use it. */
export function PermittedIconButton(
  props: Readonly<{
    check: AccessCheck | null;
    cluster?: string | null;
    title: string;
    ariaLabel?: string;
    // small in tables, medium next to a page title
    size?: 'small' | 'medium';
    onClick: () => void;
    children: ReactNode;
  }>
) {
  const { check, cluster, title, ariaLabel = title, size = 'small', onClick, children } = props;
  return (
    <Permitted check={check} cluster={cluster}>
      {allowed =>
        allowed ? (
          <Tooltip title={title}>
            <IconButton size={size} aria-label={ariaLabel} onClick={onClick}>
              {children}
            </IconButton>
          </Tooltip>
        ) : (
          <IconButton size={size} aria-label={ariaLabel} disabled>
            {children}
          </IconButton>
        )
      }
    </Permitted>
  );
}

/** Creating SecurityExceptions and ClusterSecurityExceptions. */
export function createExceptionCheck(namespace?: string): AccessCheck {
  return namespace
    ? { group: 'kubescape.io', resource: 'securityexceptions', verb: 'create', namespace }
    : { group: 'kubescape.io', resource: 'clustersecurityexceptions', verb: 'create' };
}

/**
 * Creating, changing or deleting a custom framework, a ConfigMap in the Kubescape namespace;
 * nothing to check while the namespace is not known.
 */
export function frameworkCheck(
  verb: string,
  namespace?: string,
  name?: string
): AccessCheck | null {
  if (!namespace) return null;
  return { group: '', resource: 'configmaps', verb, namespace, ...(name && { name }) };
}
