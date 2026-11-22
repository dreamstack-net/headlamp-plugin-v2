/*
  Checks the CEL expressions of a rule with the RuleEval function of the WASM module, which
  evaluates the expressions of one event type at a time.
*/
import * as yaml from 'js-yaml';
import { defaultEventData, EventType, Rule, RuleEvalResults } from '../types/Rules';

export interface RuleSyntaxErrors {
  message?: string;
  uniqueId?: string;
  // by the index of the expression in the rule
  expressions: (string | undefined)[];
  // the rule could not be evaluated at all
  rule?: string;
}

// How the note starts for an expression that compiles and failed for the sample event it was
// tried with, such as event.args[1] for an event with one argument: another event may not fail
// it, so it is no error of the expression
const sampleEventNote = 'With the sample ';

/** Whether the text names an error of the expression itself, and not one of the sample event. */
export function isExpressionError(text: string | undefined): boolean {
  return !!text && !text.startsWith(sampleEventNote);
}

// What to show for the answer to an expression: its error when it does not compile, a note
// when it only failed for the sample event
function shownError(
  answer: { error?: string; compileError?: boolean } | undefined,
  eventType: string
): string | undefined {
  if (!answer?.error) return undefined;
  return answer.compileError
    ? answer.error
    : `${sampleEventNote}${eventType} event: ${answer.error}`;
}

// the RuleEval function of the WASM module; main.wasm also takes the Kubernetes mock
export type RuleEvaluator = (
  ruleYAML: string,
  eventType: string,
  eventData: string,
  profileYAML: string,
  networkYAML: string,
  k8sYAML?: string
) => string;

/**
 * The errors of the expressions of a rule, evaluated against the default event of each event
 * type the rule has expressions for. The evaluator answers the expressions of the event type it
 * evaluates, in their order in the rule, so their answers are mapped back to their place. It
 * compiles every expression, message and unique id, which reports syntax errors and functions
 * that do not exist, but only evaluates the message and the unique id when the rule fires. An
 * expression that compiles and fails for the sample event gets a note, not an error
 * (isExpressionError).
 */
export function ruleSyntaxErrors(rule: Rule, evaluate: RuleEvaluator): RuleSyntaxErrors {
  const ruleYAML = yaml.dump({
    apiVersion: 'kubescape.io/v1',
    kind: 'Rules',
    metadata: { name: 'validate', namespace: 'kubescape' },
    spec: { rules: [rule] },
  });
  const expressions = rule.expressions.ruleExpression;
  const errors: RuleSyntaxErrors = { expressions: expressions.map(() => undefined) };
  const eventTypes = [...new Set(expressions.map(expression => expression.eventType))];

  for (const eventType of eventTypes) {
    const result: RuleEvalResults = JSON.parse(
      evaluate(
        ruleYAML,
        eventType,
        JSON.stringify(defaultEventData[eventType as EventType] ?? {}),
        '',
        ''
      )
    );
    if (result.error) {
      errors.rule ??= result.error;
      continue;
    }

    const indices = expressions
      .map((expression, index) => (expression.eventType === eventType ? index : -1))
      .filter(index => index !== -1);
    (result.ruleExpression ?? []).forEach((answer, position) => {
      const index = indices[position];
      if (index !== undefined && expressions[index].expression) {
        errors.expressions[index] = shownError(answer, eventType);
      }
    });

    if (!errors.message && rule.expressions.message) {
      errors.message = shownError(result.message, eventType);
    }
    if (!errors.uniqueId && rule.expressions.uniqueId) {
      errors.uniqueId = shownError(result.uniqueId, eventType);
    }
  }
  return errors;
}
