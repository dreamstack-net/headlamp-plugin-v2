/**
 * Calls `update` at most once per interval: at once when it last ran longer ago, otherwise once
 * at the end of the interval, for all that changed meanwhile. Pages update their state with it
 * while data arrives, so that the tables are not drawn again for every object.
 */
export function throttle(
  update: () => void,
  intervalMs: number,
  now: () => number = Date.now
): { schedule: () => void; cancel: () => void } {
  let last = -Infinity;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const run = () => {
    timer = undefined;
    last = now();
    update();
  };
  return {
    schedule() {
      if (timer !== undefined) return;
      const wait = last + intervalMs - now();
      if (wait <= 0) run();
      else timer = setTimeout(run, wait);
    },
    cancel() {
      if (timer !== undefined) clearTimeout(timer);
      timer = undefined;
    },
  };
}
