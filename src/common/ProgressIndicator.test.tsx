import { renderHook } from '@testing-library/react';
import { MutableRefObject } from 'react';
import { useCurrentReadFlag } from './ProgressIndicator';

it('stops the read that is current when the flag is cleared, also after a new read began', () => {
  const reading: MutableRefObject<MutableRefObject<boolean>> = { current: { current: true } };
  const { result } = renderHook(() => useCurrentReadFlag(reading));
  const first = reading.current;

  // a new read replaces the flag without drawing the page again
  const second = { current: true };
  reading.current = second;
  result.current.current = false;

  expect(second.current).toBe(false);
  expect(first.current).toBe(true);
  expect(result.current.current).toBe(false);
});
