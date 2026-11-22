import { vi } from 'vitest';
import type { CveException, WorkloadExceptions } from '../exceptions/vulnerabilityExceptions';

vi.mock('@kinvolk/headlamp-plugin/lib/ApiProxy', () => ({ request: vi.fn(), post: vi.fn() }));
vi.mock('@kinvolk/headlamp-plugin/lib/Utils', () => ({ getCluster: () => 'cluster-a' }));
vi.mock('../common/clusterContext', () => ({ getAllowedNamespaces: () => [] }));
vi.mock('../index', () => ({ RoutingName: {} }));

import { acceptedChipValue, exceptionChipValue } from './exceptionChips';

const exception: CveException = {
  state: 'accepted',
  kind: 'SecurityException',
  name: 'accept-it',
  namespace: 'shop',
  author: 'alice',
  reason: 'No fix upstream',
  statement: 'Replaced next quarter',
  expiresAt: '2026-12-31T23:59:59Z',
};

it('gives a cell with an exception chip the label and the name to sort and search by', () => {
  expect(exceptionChipValue(undefined)).toBe('');
  expect(exceptionChipValue(exception).startsWith('Accepted: accept-it ')).toBe(true);
});

it('changes the value of an exception chip with everything the chip shows', () => {
  const value = exceptionChipValue(exception);
  const changes: Partial<CveException>[] = [
    { state: 'planned' },
    { name: 'other' },
    { namespace: 'other' },
    { kind: 'ClusterSecurityException' },
    { author: 'bob' },
    { reason: 'Not reachable' },
    { statement: 'Upgrade planned' },
    { expiresAt: '2027-01-31T23:59:59Z' },
    { expiredOnFix: true },
  ];
  for (const change of changes) {
    expect(exceptionChipValue({ ...exception, ...change })).not.toBe(value);
  }
  // the note of a finding that kubevuln hid
  expect(exceptionChipValue(exception, 'Kubescape no longer counts this finding.')).not.toBe(value);
});

it('changes the value of an accepted chip with the open CVEs and the exceptions', () => {
  const summary: WorkloadExceptions = {
    accepted: new Set(['CVE-2']),
    open: ['CVE-1'],
    exceptions: [exception],
  };
  expect(acceptedChipValue(undefined)).toBe('');
  expect(acceptedChipValue({ ...summary, accepted: new Set() })).toBe('');

  const value = acceptedChipValue(summary);
  expect(value.startsWith('1 accepted, 1 open: accept-it ')).toBe(true);
  // all accepted
  expect(acceptedChipValue({ ...summary, open: [] })).not.toBe(value);
  // another exception, or the same one with another reason
  expect(acceptedChipValue({ ...summary, exceptions: [{ ...exception, name: 'other' }] })).not.toBe(
    value
  );
  expect(
    acceptedChipValue({ ...summary, exceptions: [{ ...exception, reason: 'Not reachable' }] })
  ).not.toBe(value);
  // more exceptions than the tooltip lists
  const many = Array.from({ length: 7 }, (_, i) => ({ ...exception, name: `accept-${i}` }));
  expect(acceptedChipValue({ ...summary, exceptions: many })).not.toBe(
    acceptedChipValue({ ...summary, exceptions: many.slice(0, 6) })
  );
});
