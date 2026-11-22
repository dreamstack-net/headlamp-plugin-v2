/**
 * Runs the work for each item, at most `concurrency` at a time, in the order of the items. No
 * new work starts once `shouldContinue` says no.
 *
 * @returns Whether it stopped before all items were done.
 */
export async function runConcurrently<T>(
  items: readonly T[],
  concurrency: number,
  work: (item: T) => Promise<void>,
  shouldContinue: () => boolean = () => true
): Promise<boolean> {
  let next = 0;
  let stopped = false;
  const worker = async () => {
    while (next < items.length) {
      if (!shouldContinue()) {
        stopped = true;
        return;
      }
      await work(items[next++]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
  return stopped;
}
