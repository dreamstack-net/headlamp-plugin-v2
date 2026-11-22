import { vi } from 'vitest';
import { throttle } from './throttle';

afterEach(() => {
  vi.useRealTimers();
});

it('updates at once, then at most once per interval with all changes since', () => {
  vi.useFakeTimers();
  const update = vi.fn();
  const updates = throttle(update, 500);

  updates.schedule();
  expect(update).toHaveBeenCalledTimes(1);

  // three changes within the interval give one update at its end
  updates.schedule();
  vi.advanceTimersByTime(100);
  updates.schedule();
  updates.schedule();
  expect(update).toHaveBeenCalledTimes(1);
  vi.advanceTimersByTime(400);
  expect(update).toHaveBeenCalledTimes(2);

  // after a quiet interval, at once again
  vi.advanceTimersByTime(1000);
  updates.schedule();
  expect(update).toHaveBeenCalledTimes(3);
});

it('drops the update it waits for when cancelled', () => {
  vi.useFakeTimers();
  const update = vi.fn();
  const updates = throttle(update, 500);
  updates.schedule();
  updates.schedule();

  updates.cancel();
  vi.advanceTimersByTime(1000);

  expect(update).toHaveBeenCalledTimes(1);
});
