import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { useState } from 'react';
import { vi } from 'vitest';
import {
  dateInDays,
  expiresAtFor,
  expiryDate,
  expiryTimestamp,
  MetadataFields,
  toImageGlob,
} from './shared';
import { imageMatches } from './vulnerabilityExceptions';

vi.mock('../common/currentUser', () => ({ useCurrentUser: () => 'jane' }));

afterEach(cleanup);

function Fields(props: Readonly<{ initialExpiry: string; onExpiry: (date: string) => void }>) {
  const [expiresDate, setExpiresDate] = useState(props.initialExpiry);
  return (
    <MetadataFields
      name="accept-cve"
      onNameChange={() => {}}
      reason=""
      onReasonChange={() => {}}
      expiresDate={expiresDate}
      onExpiresDateChange={date => {
        setExpiresDate(date);
        props.onExpiry(date);
      }}
    />
  );
}

function dateInput() {
  return screen.getByLabelText('Expires at') as HTMLInputElement;
}

it('never expires without a date, and proposes one a month ahead to expire', () => {
  const onExpiry = vi.fn();
  render(<Fields initialExpiry="" onExpiry={onExpiry} />);
  const never = screen.getByRole('checkbox', { name: 'Never expires' }) as HTMLInputElement;

  expect(never.checked).toBe(true);
  expect(dateInput().disabled).toBe(true);
  expect(screen.getByText('The exception applies until it is deleted.')).toBeTruthy();

  fireEvent.click(never);
  const proposed = onExpiry.mock.calls[0][0];
  const days = (new Date(proposed).getTime() - Date.now()) / (24 * 60 * 60 * 1000);
  expect(days).toBeGreaterThan(28);
  expect(days).toBeLessThan(31);
  expect(dateInput().disabled).toBe(false);
  expect(dateInput().value).toBe(proposed);

  fireEvent.click(never);
  expect(onExpiry).toHaveBeenLastCalledWith('');
  expect(dateInput().disabled).toBe(true);
});

it('shows the expiry of an exception that has one', () => {
  render(<Fields initialExpiry="2027-01-31" onExpiry={() => {}} />);
  expect(
    (screen.getByRole('checkbox', { name: 'Never expires' }) as HTMLInputElement).checked
  ).toBe(false);
  expect(dateInput().value).toBe('2027-01-31');
});

it('does not take a date that is being typed for never', () => {
  const onExpiry = vi.fn();
  render(<Fields initialExpiry="2027-01-31" onExpiry={onExpiry} />);

  // a date input reports an empty value while a part of its date is cleared
  fireEvent.change(dateInput(), { target: { value: '' } });
  expect(onExpiry).not.toHaveBeenCalled();
  expect(dateInput().disabled).toBe(false);
  expect(
    (screen.getByRole('checkbox', { name: 'Never expires' }) as HTMLInputElement).checked
  ).toBe(false);

  fireEvent.change(dateInput(), { target: { value: '2027-02-15' } });
  expect(onExpiry).toHaveBeenLastCalledWith('2027-02-15');
});

it('makes the pattern for all tags of an image the bare repository when it has no tag', () => {
  expect(toImageGlob('docker.io/library/nginx:1.27')).toBe('docker.io/library/nginx:*');
  expect(toImageGlob('docker.io/library/nginx:1.27@sha256:abc')).toBe('docker.io/library/nginx:*');
  expect(toImageGlob('registry.local:5000/team/app:v1')).toBe('registry.local:5000/team/app:*');
  // deployed by its digest alone: `:*` would match no form of the reference
  expect(toImageGlob('registry.k8s.io/kube-proxy@sha256:abc')).toBe('registry.k8s.io/kube-proxy');
  expect(imageMatches('registry.k8s.io/kube-proxy', 'registry.k8s.io/kube-proxy@sha256:abc')).toBe(
    true
  );
});

describe('expiry', () => {
  it('ends an exception at the end of the chosen day where the user is', () => {
    const at = new Date(expiryTimestamp('2027-03-04'));
    expect([at.getFullYear(), at.getMonth() + 1, at.getDate()]).toEqual([2027, 3, 4]);
    expect([at.getHours(), at.getMinutes(), at.getSeconds()]).toEqual([23, 59, 59]);
    expect(expiryDate(expiryTimestamp('2027-03-04'))).toBe('2027-03-04');
  });

  it('keeps an expiry whose date did not change', () => {
    const previous = expiryTimestamp('2027-03-04').replace(/T.*/, 'T12:00:00Z');
    expect(expiresAtFor(expiryDate(previous), previous)).toBe(previous);
    expect(expiresAtFor('2027-03-05', previous)).toBe(expiryTimestamp('2027-03-05'));
    expect(expiresAtFor('', previous)).toBeUndefined();
  });

  it('does not expire an exception that expires today before the day ends', () => {
    const today = dateInDays(0);
    expect(new Date(expiryTimestamp(today)).getTime()).toBeGreaterThan(Date.now());
  });
});
