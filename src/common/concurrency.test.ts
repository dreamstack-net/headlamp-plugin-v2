import { runConcurrently } from './concurrency';

it('runs the work at most the given number at a time, for every item', async () => {
  let running = 0;
  let most = 0;
  const done: number[] = [];

  const stopped = await runConcurrently([1, 2, 3, 4, 5, 6, 7], 3, async item => {
    running++;
    most = Math.max(most, running);
    await new Promise(resolve => setTimeout(resolve, 1));
    done.push(item);
    running--;
  });

  expect(stopped).toBe(false);
  expect(most).toBe(3);
  expect(done.sort()).toEqual([1, 2, 3, 4, 5, 6, 7]);
});

it('starts no new work once it should stop', async () => {
  const started: number[] = [];
  let go = true;

  const stopped = await runConcurrently(
    [1, 2, 3, 4],
    1,
    async item => {
      started.push(item);
      if (item === 2) go = false;
    },
    () => go
  );

  expect(stopped).toBe(true);
  expect(started).toEqual([1, 2]);
});

it('does nothing for no items', async () => {
  expect(await runConcurrently([], 4, async () => {})).toBe(false);
});
