// This module applies SecurityException CRDs client-side to workload scan data, for clusters
// where the scanners do not apply them (the riskAcceptance capability is disabled). Where they
// do, markScannerExceptions reads the result of the scanner instead.

import { request } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import { errorMessage, errorStatus } from '../common/errors';
import { invalidateControlStats, isControlExcepted } from '../compliance/workload-scanning';
import {
  ClusterSecurityException,
  SecurityException,
  SecurityExceptionMatchSpec,
  VulnerabilityException,
} from '../softwarecomposition/SecurityException';
import { WorkloadConfigurationScanSummary } from '../softwarecomposition/WorkloadConfigurationScanSummary';
import { patternMatches } from './patterns';

type AnySecurityException = SecurityException | ClusterSecurityException;
type LabelSelector = NonNullable<SecurityExceptionMatchSpec['objectSelector']>;

export type SecurityExceptionData = {
  namespaced: SecurityException[];
  cluster: ClusterSecurityException[];
  namespaceLabelsByName: Map<string, Record<string, string>>;
  // Per exception with an objectSelector: keys (see workloadKey) of the workloads it selects
  objectSelectorMatches?: Map<AnySecurityException, Set<string>>;
  // what could not be read, so that pages do not show findings that exceptions may cover as
  // open without saying so; a cluster without the exception CRDs has no exceptions
  errors?: string[];
};

// List endpoints of the workload kinds whose labels an objectSelector is matched against, and
// their API group, which a resource of an exception may name.
const workloadListEndpoints: Record<string, { prefix: string; plural: string; group: string }> = {
  deployment: { prefix: '/apis/apps/v1', plural: 'deployments', group: 'apps' },
  statefulset: { prefix: '/apis/apps/v1', plural: 'statefulsets', group: 'apps' },
  daemonset: { prefix: '/apis/apps/v1', plural: 'daemonsets', group: 'apps' },
  replicaset: { prefix: '/apis/apps/v1', plural: 'replicasets', group: 'apps' },
  job: { prefix: '/apis/batch/v1', plural: 'jobs', group: 'batch' },
  cronjob: { prefix: '/apis/batch/v1', plural: 'cronjobs', group: 'batch' },
  pod: { prefix: '/api/v1', plural: 'pods', group: '' },
};

function workloadKey(kind: string, namespace: string, name: string) {
  return `${kind.toLowerCase()}/${namespace}/${name}`;
}

function scanWorkloadLabels(w: WorkloadConfigurationScanSummary) {
  return {
    workloadKind: w.metadata.labels['kubescape.io/workload-kind'] ?? '',
    workloadName: w.metadata.labels['kubescape.io/workload-name'] ?? '',
    workloadNamespace: w.metadata.labels['kubescape.io/workload-namespace'] ?? '',
    // '' for the core group
    workloadApiGroup: w.metadata.labels['kubescape.io/workload-api-group'],
  };
}

/**
 * Whether Kubernetes accepts the requirements of a selector. The selectors of an exception are
 * stored as they are written, and the scanners do not apply an exception whose selector is not
 * valid. Leaving such a requirement out would make the selector match more, and hide findings.
 */
function selectorIsValid(selector: LabelSelector): boolean {
  return (selector.matchExpressions ?? []).every(expr => {
    const values = expr?.values ?? [];
    switch (expr?.operator) {
      case 'In':
      case 'NotIn':
        return !!expr.key && values.length > 0;
      case 'Exists':
      case 'DoesNotExist':
        return !!expr.key && values.length === 0;
      default:
        return false;
    }
  });
}

/** Formats a label selector in the string syntax of the labelSelector query parameter. */
export function formatLabelSelector(selector: LabelSelector): string {
  const requirements = Object.entries(selector.matchLabels ?? {}).map(([k, v]) => `${k}=${v}`);
  for (const expr of selector.matchExpressions ?? []) {
    const values = (expr.values ?? []).join(',');
    if (expr.operator === 'In') requirements.push(`${expr.key} in (${values})`);
    if (expr.operator === 'NotIn') requirements.push(`${expr.key} notin (${values})`);
    if (expr.operator === 'Exists') requirements.push(expr.key);
    if (expr.operator === 'DoesNotExist') requirements.push(`!${expr.key}`);
  }
  return requirements.join(',');
}

/**
 * Lets the API server evaluate the objectSelector of each exception against the workloads
 * of the kinds found in the scans. Workloads that cannot be listed never match, which the
 * errors name, as their findings are then shown as open. With allowed namespaces, the workloads
 * of a ClusterSecurityException are listed in each of them, as a user who may only use those
 * may not list the workloads of the whole cluster.
 */
async function fetchObjectSelectorMatches(
  exceptions: AnySecurityException[],
  workloadKinds: string[],
  opts: { cluster?: string },
  allowedNamespaces: string[],
  errors: string[]
): Promise<Map<AnySecurityException, Set<string>>> {
  const matches = new Map<AnySecurityException, Set<string>>();

  await Promise.all(
    exceptions
      .filter(ex => ex.spec.match?.objectSelector && !isExceptionExpired(ex))
      .map(async ex => {
        const match = ex.spec.match!;
        const selected = new Set<string>();
        matches.set(ex, selected);
        // a selector that Kubernetes does not accept selects nothing
        if (!selectorIsValid(match.objectSelector!)) return;

        const resourceKinds = (match.resources ?? []).map(r => r.kind.toLowerCase());
        const kinds = workloadKinds.filter(
          kind =>
            workloadListEndpoints[kind] &&
            (resourceKinds.length === 0 || resourceKinds.includes(kind))
        );
        let namespaces = [''];
        if (ex.kind === 'SecurityException') namespaces = [ex.metadata.namespace];
        else if (allowedNamespaces.length > 0) namespaces = allowedNamespaces;
        const query = new URLSearchParams({
          labelSelector: formatLabelSelector(match.objectSelector!),
        });

        let failure: string | undefined;
        await Promise.all(
          kinds.flatMap(kind =>
            namespaces.map(async namespace => {
              const { prefix, plural } = workloadListEndpoints[kind];
              const namespacePath = namespace ? `/namespaces/${encodeURIComponent(namespace)}` : '';
              try {
                const list = await request(
                  `${prefix}${namespacePath}/${plural}?${query.toString()}`,
                  opts
                );
                for (const item of list.items ?? []) {
                  selected.add(workloadKey(kind, item.metadata.namespace, item.metadata.name));
                }
              } catch (error: unknown) {
                const where = namespace ? ` of namespace ${namespace}` : '';
                failure ??= `${plural}${where}: ${errorMessage(error)}`;
              }
            })
          )
        );
        if (failure) {
          errors.push(
            `the workloads that the objectSelector of ${ex.kind} ${ex.metadata.name} selects (${failure})`
          );
        }
      })
  );

  return matches;
}

/**
 * Fetches the security exceptions of a cluster, and what is needed to match them against
 * the given workload scans of that cluster, or workloads of the given kinds. With allowed
 * namespaces, the SecurityExceptions of each of them are read, as a user who may only use those
 * may not list them in the whole cluster.
 */
export async function fetchSecurityExceptions(
  cluster?: string,
  workloadScans: WorkloadConfigurationScanSummary[] = [],
  kinds: string[] = [],
  allowedNamespaces: string[] = []
): Promise<SecurityExceptionData> {
  const opts = cluster ? { cluster } : {};
  const errors: string[] = [];
  const read = (path: string, what: string) =>
    request(path, opts).catch((error: unknown) => {
      // the CRDs are not installed: there are no exceptions
      if (errorStatus(error) !== 404) errors.push(`${what}: ${errorMessage(error)}`);
      return { items: [] };
    });
  let namespacesError: string | undefined;
  // a user of allowed namespaces may not list the namespaces, but may read each of them
  const readNamespaces = () =>
    request('/api/v1/namespaces', opts).catch(async (error: unknown) => {
      namespacesError = errorMessage(error);
      const read = await Promise.all(
        allowedNamespaces.map(namespace =>
          request(`/api/v1/namespaces/${encodeURIComponent(namespace)}`, opts).catch(() => null)
        )
      );
      return { items: read.filter(namespace => namespace?.metadata?.name) };
    });
  const readNamespaced = () =>
    allowedNamespaces.length === 0
      ? read('/apis/kubescape.io/v1beta1/securityexceptions', 'SecurityExceptions')
      : Promise.all(
          allowedNamespaces.map(namespace =>
            read(
              `/apis/kubescape.io/v1beta1/namespaces/${encodeURIComponent(
                namespace
              )}/securityexceptions`,
              `SecurityExceptions of namespace ${namespace}`
            )
          )
        ).then(lists => ({ items: lists.flatMap(list => list.items ?? []) }));
  const [nsList, clList, nsObjs] = await Promise.all([
    readNamespaced(),
    read('/apis/kubescape.io/v1beta1/clustersecurityexceptions', 'ClusterSecurityExceptions'),
    readNamespaces(),
  ]);
  const namespaceLabelsByName = new Map<string, Record<string, string>>(
    (nsObjs.items ?? []).map((ns: any) => [ns.metadata.name, ns.metadata.labels ?? {}])
  );
  const namespaced: SecurityException[] = nsList.items ?? [];
  const clusterExceptions: ClusterSecurityException[] = clList.items ?? [];
  // the labels of the namespaces are only needed for the namespace selectors of exceptions
  const labelsUnknown =
    allowedNamespaces.length === 0 ||
    allowedNamespaces.some(namespace => !namespaceLabelsByName.has(namespace));
  if (
    namespacesError &&
    labelsUnknown &&
    clusterExceptions.some(ex => ex.spec.match?.namespaceSelector)
  ) {
    errors.push(
      `the labels of the namespaces, which namespace selectors match: ${namespacesError}`
    );
  }

  const workloadKinds = [
    ...new Set([
      ...workloadScans.map(w => scanWorkloadLabels(w).workloadKind.toLowerCase()),
      ...kinds.map(kind => kind.toLowerCase()),
    ]),
  ];
  const objectSelectorMatches = await fetchObjectSelectorMatches(
    [...namespaced, ...clusterExceptions],
    workloadKinds,
    opts,
    allowedNamespaces,
    errors
  );

  return {
    namespaced,
    cluster: clusterExceptions,
    namespaceLabelsByName,
    objectSelectorMatches,
    ...(errors.length > 0 ? { errors } : {}),
  };
}

export function isExpired(expiresAt?: string): boolean {
  if (!expiresAt) return false;
  return new Date(expiresAt) < new Date();
}

/**
 * When a vulnerability entry expires: its own expiry overrides that of the exception, as for
 * kubevuln, so an entry can outlast the exception or end before it.
 */
export function entryExpiresAt(
  exception: AnySecurityException,
  entry: VulnerabilityException
): string | undefined {
  return entry.expiresAt || exception.spec.expiresAt;
}

/**
 * Whether nothing of the exception applies any more. Its posture entries, and an exception of a
 * whole workload, end with the exception; each vulnerability entry ends at its own expiry.
 */
export function isExceptionExpired(exception: AnySecurityException): boolean {
  const { posture, vulnerabilities = [], expiresAt } = exception.spec;
  if ((posture?.length || vulnerabilities.length === 0) && !isExpired(expiresAt)) return false;
  return vulnerabilities.every(entry => isExpired(entryExpiresAt(exception, entry)));
}

function labelsMatchSelector(selector: LabelSelector, labels: Record<string, string>): boolean {
  if (!selectorIsValid(selector)) return false;
  if (selector.matchLabels) {
    for (const [k, v] of Object.entries(selector.matchLabels)) {
      if (labels[k] !== v) return false;
    }
  }
  for (const expr of selector.matchExpressions ?? []) {
    const has = expr.key in labels;
    const val = labels[expr.key];
    if (expr.operator === 'Exists' && !has) return false;
    if (expr.operator === 'DoesNotExist' && has) return false;
    if (expr.operator === 'In' && !expr.values?.includes(val)) return false;
    if (expr.operator === 'NotIn' && expr.values?.includes(val)) return false;
  }
  return true;
}

// the matcher of the patterns of posture exceptions, which the compliance scores share
export { patternMatches };

// Whether a control id pattern names a control, by control id and pattern
const controlIdMatchesCache = new Map<string, Map<string, boolean>>();

/**
 * Whether the control id of a posture entry names a control: Kubescape compares them without
 * case, and as a regular expression of the whole id, so c-0017 and C-001[0-9] name C-0017.
 */
export function controlIdMatches(pattern: string, controlID: string): boolean {
  let byId = controlIdMatchesCache.get(pattern);
  if (!byId) {
    byId = new Map();
    controlIdMatchesCache.set(pattern, byId);
  }
  let matched = byId.get(controlID);
  if (matched === undefined) {
    matched =
      pattern.toLowerCase() === controlID.toLowerCase() || patternMatches(pattern, controlID, true);
    byId.set(controlID, matched);
  }
  return matched;
}

/**
 * Whose rules decide whether an exception matches a workload. Kubescape applies the posture
 * entries (opa-utils' exception processor): it compares the kind, the name and an API group as
 * regular expressions of the whole value, with case; an API group that is given must match,
 * also an empty one, which names the core group; and a Namespace is in the namespace of its
 * name. kubevuln applies the vulnerability entries (matchResources): it compares the kind and
 * the API group without case and the name exactly.
 */
export interface MatchRules {
  scanner: 'kubescape' | 'kubevuln';
  // the API group of the workload, as Kubescape's scans name it; else that of a known kind
  apiGroup?: string;
}

export function matchesWorkload(
  exception: AnySecurityException,
  workloadKind: string,
  workloadName: string,
  workloadNamespace: string,
  namespaceLabelsByName: Map<string, Record<string, string>>,
  objectSelectorMatches: Map<AnySecurityException, Set<string>>,
  rules: MatchRules
): boolean {
  const isNamespaced = exception.kind === 'SecurityException';
  const match = exception.spec.match;
  const kubescape = rules.scanner === 'kubescape';
  const namespace = kubescape && workloadKind === 'Namespace' ? workloadName : workloadNamespace;

  // Implicit namespace scope for SecurityException
  if (isNamespaced && (exception as SecurityException).metadata.namespace !== namespace) {
    return false;
  }

  // namespaceSelector (ClusterSecurityException only) — AND with other selectors. A namespace
  // whose labels are not known does not match: a selector with NotIn or DoesNotExist matches
  // labels that are empty, which would hide findings, and the scanners do not apply the
  // exception either when they cannot read the labels.
  if (!isNamespaced && match?.namespaceSelector) {
    const nsLabels = namespaceLabelsByName.get(namespace);
    if (!nsLabels || !labelsMatchSelector(match.namespaceSelector, nsLabels)) return false;
  }

  // objectSelector — evaluated by the API server in fetchObjectSelectorMatches. Workloads
  // whose labels could not be looked up do not match.
  if (match?.objectSelector) {
    const selected = objectSelectorMatches.get(exception);
    if (!selected?.has(workloadKey(workloadKind, workloadNamespace, workloadName))) return false;
  }

  // resources[] — omitted or empty means no restriction (match all in scope). An entry that
  // names an API group only matches a kind of that group, as for the scanners; a kind whose
  // group is not known does not match it.
  if (match?.resources && match.resources.length > 0) {
    const group = rules.apiGroup ?? workloadListEndpoints[workloadKind.toLowerCase()]?.group;
    const matched = match.resources.some(r =>
      kubescape
        ? patternMatches(r.kind, workloadKind) &&
          (!r.name || patternMatches(r.name, workloadName)) &&
          (typeof r.apiGroup !== 'string' ||
            (group !== undefined && patternMatches(r.apiGroup, group)))
        : r.kind.toLowerCase() === workloadKind.toLowerCase() &&
          (!r.name || r.name === workloadName) &&
          (!r.apiGroup || r.apiGroup.toLowerCase() === group)
    );
    if (!matched) return false;
  }

  return true;
}

/**
 * The control ids of posture entries, which name the controls as Kubescape compares them
 * (controlIdMatches).
 */
export class ControlIds implements Iterable<string> {
  private readonly patterns = new Set<string>();

  add(pattern: string) {
    this.patterns.add(pattern);
  }

  /** Whether an entry names the control. */
  has(controlID: string): boolean {
    for (const pattern of this.patterns) {
      if (controlIdMatches(pattern, controlID)) return true;
    }
    return false;
  }

  [Symbol.iterator]() {
    return this.patterns.values();
  }
}

/** The frameworks (names or patterns, as written) of posture entries limited to them, by their control ids. */
export class FrameworksByControl {
  private readonly byPattern = new Map<string, Set<string>>();

  add(pattern: string, framework: string) {
    const frameworks = this.byPattern.get(pattern);
    if (frameworks) frameworks.add(framework);
    else this.byPattern.set(pattern, new Set([framework]));
  }

  /** The frameworks in which entries exclude the control; undefined when none do. */
  get(controlID: string): Set<string> | undefined {
    let found: Set<string> | undefined;
    for (const [pattern, frameworks] of this.byPattern) {
      if (!controlIdMatches(pattern, controlID)) continue;
      found ??= new Set();
      for (const framework of frameworks) found.add(framework);
    }
    return found;
  }
}

/** What the exceptions that apply to a workload exclude. */
export interface WorkloadExceptionMarks {
  // the whole workload
  workload: boolean;
  // controls in every framework
  everywhere: ControlIds;
  // per control, the frameworks (names or patterns) in which entries limited to them exclude it
  inFrameworks: FrameworksByControl;
}

/**
 * What the exceptions exclude of a workload scan, without marking the scan; see
 * applySecurityExceptionsToWorkloadScans.
 */
export function workloadExceptionMarks(
  w: WorkloadConfigurationScanSummary,
  exceptions: SecurityExceptionData
): WorkloadExceptionMarks {
  const allExceptions: AnySecurityException[] = [...exceptions.namespaced, ...exceptions.cluster];
  const objectSelectorMatches = exceptions.objectSelectorMatches ?? new Map();
  const { workloadKind, workloadName, workloadNamespace, workloadApiGroup } = scanWorkloadLabels(w);

  const matched = allExceptions.filter(
    ex =>
      !isExpired(ex.spec.expiresAt) &&
      matchesWorkload(
        ex,
        workloadKind,
        workloadName,
        workloadNamespace,
        exceptions.namespaceLabelsByName,
        objectSelectorMatches,
        { scanner: 'kubescape', apiGroup: workloadApiGroup }
      )
  );

  // Resource-level exception: exception with no posture AND no vulnerability entries excludes the whole workload.
  // Vulnerability-only exceptions must not suppress compliance results.
  const workload = matched.some(
    ex =>
      (!ex.spec.posture || ex.spec.posture.length === 0) &&
      (!ex.spec.vulnerabilities || ex.spec.vulnerabilities.length === 0)
  );

  // Control-level exceptions. An alert_only entry acknowledges a failed control, which still
  // fails in scoring. An entry limited to a framework only applies in that framework.
  const everywhere = new ControlIds();
  const inFrameworks = new FrameworksByControl();
  for (const ex of matched) {
    for (const entry of ex.spec.posture ?? []) {
      if (entry.action === 'alert_only') continue;
      // kept as written: a pattern, which lowercasing could change (\S is not \s)
      const framework = entry.frameworkName?.trim();
      if (framework) inFrameworks.add(entry.controlID, framework);
      else everywhere.add(entry.controlID);
    }
  }
  return { workload, everywhere, inFrameworks };
}

// TEMPORARY: Apply SecurityException posture entries to workload scan summaries.
export function applySecurityExceptionsToWorkloadScans(
  workloadScans: WorkloadConfigurationScanSummary[],
  exceptions: SecurityExceptionData
) {
  let frameworkLimited = false;

  for (const w of workloadScans) {
    const { workload, everywhere, inFrameworks } = workloadExceptionMarks(w, exceptions);
    w.exceptedByPolicy = workload;
    Object.values(w.spec.controls).forEach(value => {
      value.exceptedByPolicy = everywhere.has(value.controlID);
      const frameworks = value.exceptedByPolicy ? undefined : inFrameworks.get(value.controlID);
      if (frameworks) {
        value.exceptedInFrameworks = [...frameworks];
        frameworkLimited = true;
      } else {
        delete value.exceptedInFrameworks;
      }
    });
  }
  invalidateControlStats(frameworkLimited);
}

/**
 * Marks the controls that the scanner passed because of a SecurityException, for clusters where
 * the scanners apply the exceptions. A resource counts as excluded when all its controls are.
 * A control that fails with the sub-status of an exception has an alert_only entry, which
 * acknowledges the failure without excluding it, or another rule of the control still fails.
 */
export function markScannerExceptions(workloadScans: WorkloadConfigurationScanSummary[]) {
  for (const w of workloadScans) {
    const controls = Object.values(w.spec.controls);
    for (const control of controls) {
      control.exceptedByPolicy =
        control.status.subStatus === 'w/exceptions' && control.status.status !== 'failed';
      delete control.exceptedInFrameworks;
    }
    w.exceptedByPolicy = controls.length > 0 && controls.every(control => control.exceptedByPolicy);
  }
  invalidateControlStats();
}

export function countExcludedResources(workloadScanData: WorkloadConfigurationScanSummary[]) {
  return workloadScanData.filter(w => w.exceptedByPolicy).length;
}

/**
 * The excepted results of controls of resources that are not excepted as a whole; of the given
 * controls (of the framework), or of all controls when none are given.
 */
export function countExcludedControls(
  workloadScanData: WorkloadConfigurationScanSummary[],
  frameworkName?: string,
  controlIDs?: Set<string>
) {
  return workloadScanData
    .filter(w => !w.exceptedByPolicy)
    .reduce(
      (excluded, w) =>
        excluded +
        Object.values(w.spec.controls).filter(
          scan =>
            (!controlIDs || controlIDs.has(scan.controlID)) &&
            isControlExcepted(scan, frameworkName)
        ).length,
      0
    );
}

export { countExcludedWorkloadsForControl } from '../compliance/workload-scanning';
