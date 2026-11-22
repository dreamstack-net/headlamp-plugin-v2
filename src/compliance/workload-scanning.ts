import { patternMatches } from '../exceptions/patterns';
import { Control, FrameWork } from '../rego';
import { WorkloadConfigurationScanSummary } from '../softwarecomposition/WorkloadConfigurationScanSummary';

/** The results of one control over a set of workload scans. */
interface ControlStats {
  // workloads that were checked for the control
  affected: number;
  // of those, the workloads that passed it or are excepted from it
  passedOrExcluded: number;
  // results per status, without excepted workloads and results
  byStatus: Map<string, number>;
  // results of excepted workloads or excepted results
  excluded: number;
  // whether any result failed, excepted or not
  hasFailed: boolean;
}

interface ScanIndex {
  version: number;
  controls: Map<string, ControlStats>;
  failed: number;
}

/** The marks of a control result that say which exceptions cover it. */
export interface ExceptedMarks {
  // an exception covers the result in every framework
  exceptedByPolicy: boolean;
  // the frameworks, as the exception entries that cover the result in that framework only name
  // them: names or patterns
  exceptedInFrameworks?: string[];
}

/**
 * Whether an exception covers a control result where the control is checked as part of the
 * named framework. Like in Kubescape, an exception entry limited to a framework only applies in
 * that framework, which it names without case or as a pattern of the whole name (opa-utils'
 * `regexCompareI`); the combined view of all controls is not one.
 */
export function isControlExcepted(control: ExceptedMarks, frameworkName?: string): boolean {
  if (control.exceptedByPolicy) return true;
  if (!frameworkName || !control.exceptedInFrameworks) return false;
  const name = frameworkName.toLowerCase();
  return control.exceptedInFrameworks.some(
    framework => framework.toLowerCase() === name || patternMatches(framework, frameworkName, true)
  );
}

// The pages ask for the results of every control, of every framework, on every render. Each
// set of scans is indexed once per framework, so asking is a lookup instead of a pass over all
// scans. While no exception is limited to a framework, all frameworks share one index.
const indexes = new WeakMap<WorkloadConfigurationScanSummary[], Map<string, ScanIndex>>();
// Applying exceptions changes the scans in place, which makes the indexes outdated
let exceptionsVersion = 0;
let frameworkLimitedMarks = false;

/**
 * To call after the excepted marks of scans changed, saying whether a mark is limited to
 * frameworks (`exceptedInFrameworks`).
 */
export function invalidateControlStats(frameworkLimited = false) {
  exceptionsVersion++;
  if (frameworkLimited) frameworkLimitedMarks = true;
}

function statsOf(controls: Map<string, ControlStats>, controlID: string): ControlStats {
  let stats = controls.get(controlID);
  if (!stats) {
    stats = {
      affected: 0,
      passedOrExcluded: 0,
      byStatus: new Map(),
      excluded: 0,
      hasFailed: false,
    };
    controls.set(controlID, stats);
  }
  return stats;
}

function indexScans(
  workloadScanData: WorkloadConfigurationScanSummary[],
  frameworkName?: string
): ScanIndex {
  const key = frameworkLimitedMarks ? frameworkName?.toLowerCase() ?? '' : '';
  let perFramework = indexes.get(workloadScanData);
  if (!perFramework) {
    perFramework = new Map();
    indexes.set(workloadScanData, perFramework);
  }
  const cached = perFramework.get(key);
  if (cached && cached.version === exceptionsVersion) return cached;

  const controls = new Map<string, ControlStats>();
  let failed = 0;
  for (const w of workloadScanData) {
    // per control of this workload: whether it passed or is excepted
    const passedOrExcluded = new Map<string, boolean>();
    for (const scan of Object.values(w.spec.controls)) {
      const stats = statsOf(controls, scan.controlID);
      const status = scan.status.status;
      const excepted = w.exceptedByPolicy || isControlExcepted(scan, frameworkName);
      const ok = excepted || status === WorkloadConfigurationScanSummary.Status.Passed;
      passedOrExcluded.set(scan.controlID, (passedOrExcluded.get(scan.controlID) ?? false) || ok);

      if (status === 'failed') stats.hasFailed = true;
      if (excepted) {
        stats.excluded++;
      } else {
        stats.byStatus.set(status, (stats.byStatus.get(status) ?? 0) + 1);
        if (status === 'failed') failed++;
      }
    }
    for (const [controlID, ok] of passedOrExcluded) {
      const stats = statsOf(controls, controlID);
      stats.affected++;
      if (ok) stats.passedOrExcluded++;
    }
  }

  const index = { version: exceptionsVersion, controls, failed };
  perFramework.set(key, index);
  return index;
}

function controlStats(
  workloadScanData: WorkloadConfigurationScanSummary[],
  control: Control,
  frameworkName?: string
) {
  return indexScans(workloadScanData, frameworkName).controls.get(control.controlID);
}

// The framework compliance score provides an overall assessment of your cluster's compliance with a specific framework.
// It is calculated by averaging the Control Compliance Scores of all controls within the framework.
// https://kubescape.io/docs/frameworks-and-controls/frameworks/
// A framework without controls, such as a custom framework whose controls are not known, fails
// nothing and scores 100, like a control that checked no workload.
export function frameworkComplianceScore(
  workloadScanData: WorkloadConfigurationScanSummary[],
  framework: FrameWork
) {
  if (framework.controls.length === 0) return 100;
  const controlComplianceScores = framework.controls.map(control =>
    controlComplianceScore(workloadScanData, control, framework.name)
  );

  return controlComplianceScores.reduce((a, b) => a + b, 0) / controlComplianceScores.length;
}

/**
 * Calculate the compliance score for a given control across all scans.
 *
 * The control compliance score measures the compliance of individual controls within a framework.
 * It is calculated by evaluating the ratio of resources that passed to the total number of resources evaluated against that control.
 *
 * See also https://github.com/kubescape/opa-utils/blob/main/score/score.go for method used in kubescape-cli.
 *
 * @param {WorkloadConfigurationScanSummary[]} workloadScanData - The list of scans to calculate the score for.
 * @param {Control} control - The control to calculate the score for.
 * @param {string} frameworkName - The framework the control is checked in, for the exceptions limited to it.
 * @returns {number} The compliance score for the control, as a percentage.
 */
export function controlComplianceScore(
  workloadScanData: WorkloadConfigurationScanSummary[],
  control: Control,
  frameworkName?: string
) {
  const [passedCount, workloadsAffected] = passedOrExcludedCount(
    workloadScanData,
    control,
    frameworkName
  );
  if (workloadsAffected === 0) {
    return 100;
  }
  return (passedCount / workloadsAffected) * 100;
}

/** The workloads that passed or are excepted from the control, and all workloads checked. */
export function passedOrExcludedCount(
  workloadScanData: WorkloadConfigurationScanSummary[],
  control: Control,
  frameworkName?: string
) {
  const stats = controlStats(workloadScanData, control, frameworkName);
  return [stats?.passedOrExcluded ?? 0, stats?.affected ?? 0];
}

/**
 * Count the number of scans that match the given control ID and status.
 *
 * @param {WorkloadConfigurationScanSummary[]} workloadScanData
 * @param {Control} control
 * @param {string} status
 * @param {string} frameworkName - The framework the control is checked in, for the exceptions limited to it.
 * @returns {number}
 */
export function countScans(
  workloadScanData: WorkloadConfigurationScanSummary[],
  control: Control,
  status: string,
  frameworkName?: string
): number {
  return controlStats(workloadScanData, control, frameworkName)?.byStatus.get(status) ?? 0;
}

/**
 * Count the number of failed scans across all workloads.
 *
 * @param {WorkloadConfigurationScanSummary[]} workloadScanData
 * @param {string} frameworkName - The framework of the exceptions limited to one.
 * @param {Set<string>} controlIDs - The controls of the framework to count, all controls when undefined.
 * @returns {number}
 */
export function countFailedScans(
  workloadScanData: WorkloadConfigurationScanSummary[],
  frameworkName?: string,
  controlIDs?: Set<string>
): number {
  const index = indexScans(workloadScanData, frameworkName);
  if (!controlIDs) return index.failed;
  let failed = 0;
  for (const controlID of controlIDs) {
    failed += index.controls.get(controlID)?.byStatus.get('failed') ?? 0;
  }
  return failed;
}

/** The workloads excepted from the control, and the excepted results of the control. */
export function countExcludedWorkloadsForControl(
  workloadScanData: WorkloadConfigurationScanSummary[],
  control: Control,
  frameworkName?: string
) {
  return controlStats(workloadScanData, control, frameworkName)?.excluded ?? 0;
}

/**
 * Retrieves controls from the specified framework that have associated findings
 * marked as 'failed' in the given workload scan data.
 *
 * This function filters the controls within the provided framework to identify
 * those that match any control ID in the workload scan data where the status
 * is marked as 'failed'.
 *
 * @param workloadScanData - An array of workload scan summaries to check for failed controls.
 * @param frameWork - The framework containing the controls to be filtered.
 * @returns An array of controls that have failed findings in the workload scan data.
 */

export function getControlsWithFindings(
  workloadScanData: WorkloadConfigurationScanSummary[],
  frameWork: FrameWork
) {
  if (!workloadScanData) return [];
  return frameWork.controls.filter(
    control => countScans(workloadScanData, control, 'failed', frameWork.name) > 0
  );
}

/**
 * Checks if there are any failed scans for the given control.
 *
 * This function will return true if any of the scans in the workload scan data
 * have a status of 'failed' for the given control, and false otherwise.
 *
 * @param {WorkloadConfigurationScanSummary[]} workloadScanData
 * @param {Control} control
 * @returns {boolean}
 */
export function hasFailedScans(
  workloadScanData: WorkloadConfigurationScanSummary[],
  control: Control
) {
  if (!workloadScanData) return false;
  return controlStats(workloadScanData, control)?.hasFailed ?? false;
}
