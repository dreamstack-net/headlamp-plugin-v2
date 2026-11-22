import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EMPTY_RULE } from './ruleDefaults';

const mocks = vi.hoisted(() => ({ wasm: { ready: true } as { ready: boolean; error?: string } }));
vi.mock('../wasm/initWasmModule', () => ({ useWasm: () => mocks.wasm }));
// the editors are text areas, named by their language and position
vi.mock('./MonacoEditor', () => ({
  MonacoEditor: ({ defaultValue, onChange }: any) => (
    <textarea
      aria-label="editor"
      defaultValue={defaultValue}
      onChange={event => onChange(event.target.value)}
    />
  ),
}));
vi.mock('./ClusterMockLoader', () => ({ ClusterMockLoader: () => null }));

import type { Rule, RuleEvalResults } from '../types/Rules';
import { firedMessage, PlaygroundDialog, ruleOutcome, RuleTestResult } from './PlaygroundDialog';

function result(rule: Partial<Rule>, evalResult: Partial<RuleEvalResults> | null): RuleTestResult {
  return {
    rule: { ...EMPTY_RULE, ...rule },
    evalResult: evalResult && {
      ruleExpression: [],
      message: { result: '' },
      uniqueId: { result: '' },
      ...evalResult,
    },
    evalError: '',
  };
}

const answer = (value: boolean | null) => ({ eventType: 'exec', expression: '', result: value });

describe('ruleOutcome', () => {
  it('fires only when every expression of the event type is true', () => {
    // as the evaluator answers it
    expect(ruleOutcome(result({}, { fired: true }))).toBe('fired');
    expect(ruleOutcome(result({}, { fired: false, ruleExpression: [answer(true)] }))).toBe(
      'not fired'
    );
    // and, from an evaluator that does not answer it, from the expressions
    expect(ruleOutcome(result({}, { ruleExpression: [answer(true), answer(false)] }))).toBe(
      'not fired'
    );
    expect(ruleOutcome(result({}, { ruleExpression: [answer(true), answer(true)] }))).toBe('fired');
    expect(ruleOutcome(result({}, { ruleExpression: [answer(true), answer(null)] }))).toBe(
      'not fired'
    );
  });

  it('tells disabled rules, errors and other event types apart', () => {
    expect(ruleOutcome(result({ enabled: false }, null))).toBe('disabled');
    expect(ruleOutcome(result({}, { error: 'failed to parse rule YAML' }))).toBe('error');
    expect(ruleOutcome({ ...result({}, null), evalError: 'not JSON' })).toBe('error');
    expect(ruleOutcome(result({}, { eventTypeMismatch: 'handles open' }))).toBe('N/A');
    expect(ruleOutcome(result({}, null))).toBeNull();
  });

  it('shows the message of a rule that fired only', () => {
    const message = { result: 'Unexpected process: sh' };
    expect(firedMessage(result({}, { fired: true, message }))).toBe('Unexpected process: sh');
    expect(firedMessage(result({}, { fired: false, message }))).toBe('');
    expect(
      firedMessage(result({}, { fired: true, message: { result: '', error: 'no such key: x' } }))
    ).toBe('The message failed: no such key: x');
  });

  it('says that a rule does not alert because its unique id failed', () => {
    const uniqueId = { result: '', error: 'expression returned int64, expected string' };
    expect(
      firedMessage(result({}, { fired: false, ruleExpression: [answer(true)], uniqueId }))
    ).toBe('No alert, as the unique id failed: expression returned int64, expected string');
    // an expression that is not true is the reason, not the unique id
    expect(
      firedMessage(result({}, { fired: false, ruleExpression: [answer(false)], uniqueId }))
    ).toBe('');
  });

  it('says why the node-agent skips the event before evaluating the rule', () => {
    const prefiltered =
      'The node-agent skips this event before evaluating the rule: the path is not under /etc/';
    expect(
      firedMessage(result({}, { fired: false, ruleExpression: [answer(true)], prefiltered }))
    ).toBe(prefiltered);
  });
});

describe('PlaygroundDialog', () => {
  const rules: Rule[] = [
    { ...EMPTY_RULE, name: 'Both true', id: 'R1' },
    { ...EMPTY_RULE, name: 'One true', id: 'R2' },
    { ...EMPTY_RULE, name: 'Switched off', id: 'R3', enabled: false },
  ];

  beforeEach(() => {
    mocks.wasm = { ready: true };
    window.RuleEval = vi.fn((ruleYAML: string) => {
      const both = ruleYAML.includes('Both true');
      return JSON.stringify({
        ruleExpression: [answer(true), answer(both)],
        fired: both,
        message: { result: both ? 'both fired' : 'one fired' },
        uniqueId: { result: '' },
      });
    }) as typeof window.RuleEval;
  });
  afterEach(cleanup);

  it('evaluates the enabled rules with the mocks and shows the message of those that fired', async () => {
    render(
      <PlaygroundDialog
        open
        onClose={() => {}}
        rules={rules}
        ruleMeta={{ name: 'test', namespace: 'kubescape' }}
      />
    );

    const table = await screen.findByRole('table');
    const row = (name: string) => within(table).getByText(name).closest('tr')!;
    expect(within(row('Both true')).getByText('fired')).toBeTruthy();
    expect(within(row('Both true')).getByText('both fired')).toBeTruthy();
    // a rule with one expression that is not true does not fire, and has no message
    expect(within(row('One true')).getByText('not fired')).toBeTruthy();
    expect(within(row('One true')).queryByText('one fired')).toBeNull();
    expect(within(row('Switched off')).getByText('disabled')).toBeTruthy();
    // which is not evaluated
    const evaluated = vi.mocked(window.RuleEval).mock.calls.map(([ruleYAML]) => ruleYAML);
    expect(evaluated.some(ruleYAML => ruleYAML.includes('Switched off'))).toBe(false);

    // the Kubernetes mock is passed to the evaluator
    fireEvent.click(screen.getByRole('tab', { name: 'Kubernetes mock' }));
    const editors = screen.getAllByLabelText('editor');
    fireEvent.change(editors[editors.length - 1], {
      target: { value: 'apiServerAddress: 10.96.0.1' },
    });
    vi.mocked(window.RuleEval).mockClear();
    fireEvent.click(screen.getByRole('button', { name: 'Evaluate' }));
    await waitFor(() => expect(window.RuleEval).toHaveBeenCalledTimes(2));
    const [, eventType, , , , k8sYAML] = vi.mocked(window.RuleEval).mock.calls[0] as any[];
    expect(eventType).toBe('exec');
    expect(k8sYAML).toBe('apiServerAddress: 10.96.0.1');
  });

  it('shows what was entered, which it evaluates, when it is opened again', async () => {
    const dialog = (open: boolean) => (
      <PlaygroundDialog
        open={open}
        onClose={() => {}}
        rules={rules}
        ruleMeta={{ name: 'test', namespace: 'kubescape' }}
      />
    );
    const { rerender } = render(dialog(true));
    await screen.findByRole('table');
    const event = '{ "comm": "nslookup" }';
    fireEvent.change(screen.getAllByLabelText('editor')[0], { target: { value: event } });
    fireEvent.click(screen.getByRole('tab', { name: 'Kubernetes mock' }));
    const editors = screen.getAllByLabelText('editor');
    fireEvent.change(editors[editors.length - 1], {
      target: { value: 'apiServerAddress: 10.96.0.1' },
    });

    // a closed dialog takes its editors with it
    rerender(dialog(false));
    await waitFor(() => expect(screen.queryAllByLabelText('editor')).toHaveLength(0));
    vi.mocked(window.RuleEval).mockClear();
    rerender(dialog(true));

    // it evaluates what was entered before, so that is what its new editors show
    await waitFor(() => expect(window.RuleEval).toHaveBeenCalled());
    const [, , eventData, , , k8sYAML] = vi.mocked(window.RuleEval).mock.calls[0] as any[];
    expect(eventData).toBe(event);
    expect(k8sYAML).toBe('apiServerAddress: 10.96.0.1');
    const reopened = screen.getAllByLabelText('editor') as HTMLTextAreaElement[];
    expect(reopened[0].value).toBe(event);
    expect(reopened[reopened.length - 1].value).toBe('apiServerAddress: 10.96.0.1');
  });

  it('says why it cannot evaluate when the evaluator could not be loaded', async () => {
    mocks.wasm = { ready: false, error: 'main.wasm could not be read: 404 Not Found' };
    (window as any).RuleEval = undefined;
    render(
      <PlaygroundDialog
        open
        onClose={() => {}}
        rules={rules}
        ruleMeta={{ name: 'test', namespace: 'kubescape' }}
      />
    );

    expect(
      await screen.findByText(
        'The rules cannot be evaluated: main.wasm could not be read: 404 Not Found'
      )
    ).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Evaluate' })).toHaveProperty('disabled', true);
    expect(screen.queryByRole('table')).toBeNull();
  });
});
