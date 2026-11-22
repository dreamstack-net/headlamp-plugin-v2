import { describe, expect, it } from 'vitest';
import type { Rule } from '../types/Rules';
import { isExpressionError, ruleSyntaxErrors } from './ruleValidation';

function rule(expressions: Array<{ eventType: string; expression: string }>): Rule {
  return {
    name: 'test',
    id: 'R0001',
    expressions: {
      message: "'message'",
      uniqueId: "'id'",
      ruleExpression: expressions,
    },
  } as unknown as Rule;
}

describe('ruleSyntaxErrors', () => {
  it('maps the answers for each event type back to the place of their expression', () => {
    const asked: string[] = [];
    // the evaluator answers the expressions of the event type it evaluates, in their order
    const evaluate = (_yaml: string, eventType: string) => {
      asked.push(eventType);
      return JSON.stringify({
        ruleExpression:
          eventType === 'exec'
            ? [{ error: '' }, { error: 'undeclared reference to event.bad', compileError: true }]
            : [{ error: 'syntax error', compileError: true }],
        message: { error: '' },
        uniqueId: { error: '' },
      });
    };

    const errors = ruleSyntaxErrors(
      rule([
        { eventType: 'exec', expression: 'event.comm == "sh"' },
        { eventType: 'open', expression: 'event.path ==' },
        { eventType: 'exec', expression: 'event.bad' },
      ]),
      evaluate
    );

    expect(asked).toEqual(['exec', 'open']);
    expect(errors.expressions).toEqual([
      undefined,
      'syntax error',
      'undeclared reference to event.bad',
    ]);
  });

  it('reports an error of the whole rule instead of failing', () => {
    const errors = ruleSyntaxErrors(rule([{ eventType: 'exec', expression: 'true' }]), () =>
      JSON.stringify({ error: 'failed to parse rule YAML' })
    );
    expect(errors.rule).toBe('failed to parse rule YAML');
    expect(errors.expressions).toEqual([undefined]);
  });

  it('reports the errors of the message and the unique id once', () => {
    const errors = ruleSyntaxErrors(
      rule([
        { eventType: 'exec', expression: 'true' },
        { eventType: 'open', expression: 'true' },
      ]),
      () =>
        JSON.stringify({
          ruleExpression: [{ error: '' }],
          message: { error: 'Syntax error: mismatched input', compileError: true },
          uniqueId: { error: '' },
        })
    );
    expect(errors.message).toBe('Syntax error: mismatched input');
    expect(errors.uniqueId).toBeUndefined();
  });

  it('notes, but does not call wrong, an expression that only fails for the sample event', () => {
    const errors = ruleSyntaxErrors(
      rule([
        { eventType: 'exec', expression: "event.args[1] == '-c'" },
        { eventType: 'exec', expression: 'event.args[1] ==' },
      ]),
      () =>
        JSON.stringify({
          ruleExpression: [
            // the sample exec event has one argument
            { error: 'index out of bounds: 1' },
            { error: 'Syntax error: mismatched input', compileError: true },
          ],
          message: { error: '' },
          uniqueId: { error: 'no such key: name' },
        })
    );

    expect(errors.expressions).toEqual([
      'With the sample exec event: index out of bounds: 1',
      'Syntax error: mismatched input',
    ]);
    expect(errors.expressions.map(isExpressionError)).toEqual([false, true]);
    expect(errors.uniqueId).toBe('With the sample exec event: no such key: name');
    expect(isExpressionError(errors.uniqueId)).toBe(false);
    expect(isExpressionError(undefined)).toBe(false);
  });

  it('evaluates the expressions of DNS queries and admission requests against their samples', () => {
    const events: Record<string, any> = {};
    ruleSyntaxErrors(
      rule([
        { eventType: 'dnsQuery', expression: "event.qr == 'Q'" },
        { eventType: 'k8s-admission', expression: "event.Kind == 'Pod'" },
      ]),
      (_yaml, eventType, eventData) => {
        events[eventType] = JSON.parse(eventData);
        return JSON.stringify({ ruleExpression: [{ error: '' }], message: {}, uniqueId: {} });
      }
    );
    expect(events.dnsQuery).toMatchObject({ qr: 'Q', qtype: 'TXT', numAnswers: 0 });
    expect(events.dnsQuery.rcode).toBeUndefined();
    expect(events['k8s-admission']).toMatchObject({
      Kind: 'Pod',
      Operation: 'CREATE',
      UserInfo: { Username: 'jane' },
      Object: { spec: { hostNetwork: true } },
    });
  });
});
