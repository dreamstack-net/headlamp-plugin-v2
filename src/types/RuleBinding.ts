// The RuntimeRuleAlertBinding of the node-agent (kubescape.io/v1), which binds runtime rules to
// the pods its selectors choose. Only the fields the plugin uses are declared.
import type { LabelSelectorRequirement } from '../softwarecomposition/SecurityException';
import type { Rule } from './Rules';

export interface LabelSelector {
  matchLabels?: Record<string, string>;
  matchExpressions?: LabelSelectorRequirement[];
}

/** A rule of a binding: by its name, its id or its tags, with the parameters it gets. */
export interface BoundRule {
  ruleName?: string;
  ruleID?: string;
  ruleTags?: string[];
  severity?: string;
  parameters?: Record<string, unknown>;
}

export interface RuntimeRuleAlertBinding {
  apiVersion?: string;
  kind?: string;
  metadata: {
    name: string;
    resourceVersion?: string;
    labels?: Record<string, string>;
    annotations?: Record<string, string>;
  };
  spec?: {
    namespaceSelector?: LabelSelector;
    podSelector?: LabelSelector;
    rules?: BoundRule[];
  };
}

/** The Rules objects that the list of the rules class gives, per cluster. */
export interface RulesObject {
  cluster: string;
  jsonData: {
    metadata: { name: string; namespace: string };
    spec?: { rules?: Rule[] };
  };
}
