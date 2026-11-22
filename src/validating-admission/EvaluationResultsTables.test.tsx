import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { ReactNode } from 'react';
import { vi } from 'vitest';
import { EvaluationResults, EvaluationResultsTables } from './EvaluationResultsTables';

vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', () => ({
  ShowHideLabel: ({ children }: { children: ReactNode }) => <span>{children}</span>,
}));

afterEach(cleanup);

function renderResults(results: EvaluationResults) {
  render(<EvaluationResultsTables evaluationResult={results} />);
}

const selectedTab = () => screen.getByRole('tab', { selected: true }).textContent;

it('shows the audit annotations of a policy without validations', () => {
  renderResults({
    matchConstraints: true,
    matchConditionsMatched: true,
    matchConditions: [{ name: 'in-shop', result: true }],
    auditAnnotations: [
      { name: 'replicas', expression: 'string(object.spec.replicas)', result: '5' },
    ],
  });

  expect(screen.getByText('The resource is valid.')).toBeTruthy();
  expect(screen.queryByText(/A match condition is false/)).toBeNull();
  expect(selectedTab()).toBe('Audit Annotations');
  expect(screen.getByText('string(object.spec.replicas)')).toBeTruthy();
  expect(screen.getByRole('tab', { name: 'Validations' })).toHaveProperty('disabled', true);
});

it('says when a match condition is false', () => {
  renderResults({
    matchConstraints: true,
    matchConditionsMatched: false,
    matchConditions: [{ name: 'in-billing', result: false }],
  });

  expect(
    screen.getByText('A match condition is false, so the policy does not apply to the resource.')
  ).toBeTruthy();
  expect(selectedTab()).toBe('Match Conditions');
  expect(screen.queryByText('The resource is valid.')).toBeNull();
});

it('explains that a failed match condition goes through the validationActions', () => {
  renderResults({
    matchConstraints: true,
    matchConditionsMatched: true,
    matchConditionError: 'in-shop: no such key: metadata',
    matchConditions: [{ name: 'in-shop', error: 'no such key: metadata' }],
  });

  const alert = screen.getByRole('alert');
  expect(alert.textContent).toBe(
    'The match condition in-shop: no such key: metadata. The failurePolicy of the policy is ' +
      'Fail, the default, so the API server treats the request as a violation: a binding with ' +
      'Deny rejects the request, Warn returns a warning and Audit records it in the audit log.'
  );

  cleanup();
  renderResults({
    matchConstraints: true,
    matchConditionsMatched: true,
    matchConditionError: 'in-shop: no such key: metadata',
    failurePolicyIgnore: true,
  });
  expect(screen.getByRole('alert').textContent).toMatch(/is Ignore, so the API server admits/);
});

it('says that an audit annotation rejects the request whatever the binding does', () => {
  renderResults({
    matchConstraints: true,
    matchConditionsMatched: true,
    validations: [{ name: '1', expression: 'true', result: true }],
    auditAnnotations: [
      {
        name: 'replicas',
        expression: 'object.spec.replicas',
        result: 5,
        error: 'unsupported return type',
      },
    ],
    auditAnnotationError: 'replicas: unsupported return type',
  });

  expect(screen.getByRole('alert').textContent).toBe(
    'The audit annotation replicas: unsupported return type. The API server rejects the ' +
      'request for it, whatever the validationActions of the binding.'
  );
  expect(screen.getByText('The resource is valid.')).toBeTruthy();
  fireEvent.click(screen.getByRole('tab', { name: 'Audit Annotations' }));
  expect(selectedTab()).toBe('Audit Annotations');
});

it('tells violations from validations that failed', () => {
  renderResults({
    matchConstraints: true,
    matchConditionsMatched: true,
    validations: [
      { name: '1', expression: 'object.spec.replicas < 3', result: false, message: 'too many' },
      { name: '2', expression: 'object.missing', error: 'no such key: missing' },
    ],
  });

  expect(
    screen.getByText(
      'The resource violates the policy: a binding with Deny rejects the request, Warn returns ' +
        'a warning and Audit records it in the audit log.'
    )
  ).toBeTruthy();
  expect(screen.getByRole('alert').textContent).toMatch(
    /^A validation failed\. The failurePolicy of the policy is Fail/
  );
  expect(screen.getByText('too many')).toBeTruthy();
  expect(selectedTab()).toBe('Validations');
});
