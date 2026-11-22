import { act, renderHook } from '@testing-library/react';
import {
  getItemFromSessionStorage,
  KubescapeSettings,
  setItemInSessionStorage,
  useSessionStorage,
} from './sessionStorage';

beforeEach(() => {
  window.sessionStorage.clear();
});

it('keeps a switch that was turned off, which is on by default', () => {
  const first = renderHook(() => useSessionStorage(KubescapeSettings.FailedControls, true));
  expect(first.result.current[0]).toBe(true);
  act(() => first.result.current[1](false));
  first.unmount();

  // back on the page
  const again = renderHook(() => useSessionStorage(KubescapeSettings.FailedControls, true));
  expect(again.result.current[0]).toBe(false);
});

it('keeps 0 and removes a setting set to null', () => {
  setItemInSessionStorage(KubescapeSettings.ComplianceTab, 0);
  expect(getItemFromSessionStorage(KubescapeSettings.ComplianceTab)).toBe(0);
  setItemInSessionStorage(KubescapeSettings.ComplianceTab, null);
  expect(getItemFromSessionStorage(KubescapeSettings.ComplianceTab)).toBeNull();
});

it('ignores a value that is not JSON', () => {
  window.sessionStorage.setItem('kubescape.VulnerabilityTab', '{not json');
  expect(getItemFromSessionStorage(KubescapeSettings.VulnerabilityTab)).toBeNull();
});
