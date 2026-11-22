import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import type { ReactNode } from 'react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  post: vi.fn(),
  put: vi.fn(),
  request: vi.fn(),
  segments: [] as string[],
}));

vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({
  post: mocks.post,
  put: mocks.put,
  request: mocks.request,
}));
vi.mock('@kinvolk/headlamp-plugin/lib/CommonComponents', () => ({
  SectionBox: ({ children }: { children: ReactNode }) => <section>{children}</section>,
}));
vi.mock('../common/permissions', () => ({
  Permitted: ({ children }: { children: (allowed: boolean) => ReactNode }) => children(true),
}));
vi.mock('../common/url', () => ({ getURLSegments: () => mocks.segments }));

import { bindingToSave, RuleBindingEdit, RuleBindingNew, ruleToSave } from './RuleBindingEditor';

describe('ruleToSave', () => {
  it('keeps the parameters and other fields of a rule that still has its name', () => {
    const original = {
      ruleName: 'Unexpected file access',
      severity: 'Low',
      parameters: { ignoreMounts: true, ignorePrefixes: ['/proc', '/sys'] },
    };
    expect(ruleToSave({ ruleName: 'Unexpected file access', severity: 'High', original })).toEqual({
      ruleName: 'Unexpected file access',
      severity: 'High',
      parameters: { ignoreMounts: true, ignorePrefixes: ['/proc', '/sys'] },
    });
    // the default severity
    expect(ruleToSave({ ruleName: 'Unexpected file access', severity: '', original })).toEqual({
      ruleName: 'Unexpected file access',
      parameters: original.parameters,
    });
  });

  it('keeps a rule that is bound by its id or tags', () => {
    expect(ruleToSave({ ruleName: '', severity: '', original: { ruleID: 'R0002' } })).toEqual({
      ruleID: 'R0002',
    });
    expect(
      ruleToSave({ ruleName: '', severity: 'High', original: { ruleTags: ['exec'] } })
    ).toEqual({ ruleTags: ['exec'], severity: 'High' });
  });

  it('keeps nothing of a rule that was replaced by another', () => {
    expect(
      ruleToSave({
        ruleName: 'Unexpected process launched',
        severity: '',
        original: { ruleName: 'Unexpected file access', parameters: { ignoreMounts: true } },
      })
    ).toEqual({ ruleName: 'Unexpected process launched' });
  });
});

describe('bindingToSave', () => {
  const form = {
    name: ' web-binding ',
    nsLabels: [
      { key: 'team', value: 'shop' },
      // a row whose key is empty is left out
      { key: '', value: 'ignored' },
    ],
    nsExpressions: [
      { key: 'env', operator: 'In', values: 'prod, staging,' },
      { key: 'kubescape.io/ignore', operator: 'DoesNotExist', values: 'left, over' },
    ],
    podLabels: [],
    podExpressions: [{ key: 'app', operator: 'Exists', values: '' }],
    rules: [{ ruleName: 'Unexpected process launched', severity: 'High' }],
  };

  it('builds the selectors, with values only for In and NotIn', () => {
    expect(bindingToSave(undefined, form)).toEqual({
      apiVersion: 'kubescape.io/v1',
      kind: 'RuntimeRuleAlertBinding',
      metadata: { name: 'web-binding' },
      spec: {
        namespaceSelector: {
          matchLabels: { team: 'shop' },
          matchExpressions: [
            { key: 'env', operator: 'In', values: ['prod', 'staging'] },
            { key: 'kubescape.io/ignore', operator: 'DoesNotExist' },
          ],
        },
        podSelector: {
          matchLabels: {},
          matchExpressions: [{ key: 'app', operator: 'Exists' }],
        },
        rules: [{ ruleName: 'Unexpected process launched', severity: 'High' }],
      },
    });
  });

  it('keeps the metadata, resourceVersion and other fields of the binding that was read', () => {
    const existing = {
      apiVersion: 'kubescape.io/v1',
      kind: 'RuntimeRuleAlertBinding',
      metadata: {
        name: 'web-binding',
        resourceVersion: '41',
        labels: { 'app.kubernetes.io/managed-by': 'Helm' },
        annotations: { 'meta.helm.sh/release-name': 'kubescape' },
      },
      spec: {
        namespaceSelector: { matchLabels: { old: 'yes' } },
        podSelector: { matchExpressions: [{ key: 'old', operator: 'Exists' }] },
        rules: [],
        futureField: { kept: true },
      },
      status: { observed: 1 },
    };
    const body = bindingToSave(existing, { ...form, nsExpressions: [], podExpressions: [] });
    expect(body.metadata).toEqual({ ...existing.metadata, name: 'web-binding' });
    expect(body.status).toEqual({ observed: 1 });
    expect(body.spec.futureField).toEqual({ kept: true });
    // the selectors are those of the form, also when they are empty
    expect(body.spec.namespaceSelector).toEqual({ matchLabels: { team: 'shop' } });
    expect(body.spec.podSelector).toEqual({ matchLabels: {} });
  });
});

describe('the rule binding form', () => {
  beforeEach(() => {
    mocks.post.mockReset();
    mocks.put.mockReset();
    mocks.request.mockReset();
    mocks.segments = [];
  });
  afterEach(cleanup);

  const renderPage = (page: ReactNode) =>
    render(<MemoryRouter initialEntries={['/bindings', '/binding']}>{page}</MemoryRouter>);

  it('creates a new binding with POST', async () => {
    mocks.request.mockResolvedValue({ items: [] });
    mocks.post.mockResolvedValue({});
    renderPage(<RuleBindingNew />);

    fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'web-binding' } });
    // a pod label and an Exists expression on the namespaces
    const [namespaceSelector, podSelector] = screen
      .getAllByText(/Selector$/)
      .map(label => label.parentElement!);
    fireEvent.click(within(podSelector).getByRole('button', { name: 'Add matchLabel' }));
    fireEvent.change(within(podSelector).getByLabelText('Key'), { target: { value: 'app' } });
    fireEvent.change(within(podSelector).getByLabelText('Value'), { target: { value: 'web' } });
    fireEvent.click(within(namespaceSelector).getByRole('button', { name: 'Add matchExpression' }));
    fireEvent.change(within(namespaceSelector).getByLabelText('Key'), {
      target: { value: 'team' },
    });
    fireEvent.mouseDown(within(namespaceSelector).getByRole('combobox'));
    fireEvent.click(screen.getByRole('option', { name: 'Exists' }));
    fireEvent.click(screen.getByRole('button', { name: 'Add rule' }));
    fireEvent.change(screen.getByLabelText(/^Rule Name/), {
      target: { value: 'Unexpected process launched' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => expect(mocks.post).toHaveBeenCalledTimes(1));
    expect(mocks.put).not.toHaveBeenCalled();
    expect(mocks.post).toHaveBeenCalledWith('/apis/kubescape.io/v1/runtimerulealertbindings', {
      apiVersion: 'kubescape.io/v1',
      kind: 'RuntimeRuleAlertBinding',
      metadata: { name: 'web-binding' },
      spec: {
        namespaceSelector: {
          matchLabels: {},
          matchExpressions: [{ key: 'team', operator: 'Exists' }],
        },
        podSelector: { matchLabels: { app: 'web' } },
        rules: [{ ruleName: 'Unexpected process launched' }],
      },
    });
  });

  it('replaces an edited binding with PUT, with its resourceVersion', async () => {
    mocks.segments = ['web-binding'];
    const binding = {
      apiVersion: 'kubescape.io/v1',
      kind: 'RuntimeRuleAlertBinding',
      metadata: { name: 'web-binding', resourceVersion: '41', labels: { team: 'shop' } },
      spec: {
        namespaceSelector: {
          matchExpressions: [{ key: 'env', operator: 'NotIn', values: ['dev'] }],
        },
        podSelector: { matchLabels: { app: 'web' } },
        rules: [{ ruleID: 'R0002', parameters: { ignoreMounts: true } }],
      },
    };
    mocks.request.mockImplementation(async (url: string) =>
      url.endsWith('/web-binding') ? binding : { items: [] }
    );
    mocks.put.mockResolvedValue({});
    renderPage(<RuleBindingEdit />);

    fireEvent.click(await screen.findByRole('button', { name: 'Save' }));

    await waitFor(() => expect(mocks.put).toHaveBeenCalledTimes(1));
    expect(mocks.post).not.toHaveBeenCalled();
    expect(mocks.put).toHaveBeenCalledWith(
      '/apis/kubescape.io/v1/runtimerulealertbindings/web-binding',
      {
        ...binding,
        spec: {
          namespaceSelector: {
            matchLabels: {},
            matchExpressions: [{ key: 'env', operator: 'NotIn', values: ['dev'] }],
          },
          podSelector: { matchLabels: { app: 'web' } },
          rules: [{ ruleID: 'R0002', parameters: { ignoreMounts: true } }],
        },
      }
    );
  });

  it('asks for a value of In and NotIn expressions', async () => {
    mocks.segments = ['web-binding'];
    mocks.request.mockImplementation(async (url: string) =>
      url.endsWith('/web-binding')
        ? {
            metadata: { name: 'web-binding' },
            spec: { podSelector: { matchExpressions: [{ key: 'app', operator: 'In' }] } },
          }
        : { items: [] }
    );
    renderPage(<RuleBindingEdit />);

    fireEvent.click(await screen.findByRole('button', { name: 'Save' }));
    expect(await screen.findByText('In/NotIn expressions require at least one value')).toBeTruthy();
    expect(mocks.put).not.toHaveBeenCalled();
  });
});
