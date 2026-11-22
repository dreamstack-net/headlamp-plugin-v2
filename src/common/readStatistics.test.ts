import { vi } from 'vitest';
import { formatDuration, ReadRecorder, readSummary } from './readStatistics';

const parts = [
  { noun: 'workloads', one: 'workload', phases: ['summaries'] },
  { noun: 'image reports', one: 'image report', phases: ['cached reports', 'reports'] },
];

function clock() {
  const time = { now: 1000 };
  return { time, recorder: new ReadRecorder(() => time.now) };
}

it('counts each phase per cluster for every read in progress, from its own start', () => {
  const { time, recorder } = clock();
  const first = recorder.start('vulnerability scans');
  const summaries = recorder.phase('cluster-a', 'summaries');
  summaries.request(2);
  summaries.items(850);

  // a second page starts reading while the summaries are read
  time.now = 3000;
  const second = recorder.start('vulnerability scans');
  summaries.request();
  time.now = 4000;
  summaries.end();
  // ending twice counts once
  summaries.end();
  recorder.finish(first, false);

  // the first read has ended, so only the second counts the reports
  const reports = recorder.phase('cluster-a', 'reports');
  reports.items(3);
  reports.failure();
  reports.end();
  recorder.finish(second, false);

  expect(first.phase('cluster-a', 'summaries')).toMatchObject({
    requests: 3,
    items: 850,
    durationMs: 3000,
  });
  expect(first.phases.map(phase => phase.phase)).toEqual(['summaries']);
  expect(second.phase('cluster-a', 'summaries')).toMatchObject({ requests: 1, durationMs: 1000 });
  expect(second.total()).toEqual({ items: 3, fromCache: 0, requests: 1, failures: 1 });
  expect(first.durationMs()).toBe(3000);
});

it('says what a read read in one line', () => {
  const { time, recorder } = clock();
  const read = recorder.start('vulnerability scans');
  const summaries = recorder.phase('cluster-a', 'summaries');
  summaries.items(850);
  summaries.request(12);
  const cached = recorder.phase('cluster-a', 'cached reports');
  cached.items(310);
  cached.fromCache(310);
  const reports = recorder.phase('cluster-b', 'reports');
  reports.items(110);
  time.now += 12_345;
  recorder.finish(read, false);

  expect(readSummary(read, parts)).toBe(
    'Read 850 workloads and 420 image reports (310 from the cache) in 12.3 s'
  );

  const failing = recorder.start('vulnerability scans');
  recorder.phase('cluster-a', 'reports').items(3);
  recorder.phase('cluster-a', 'reports').failure(2);
  recorder.finish(failing, false);
  expect(readSummary(failing, parts)).toBe('Read 3 image reports in 0.0 s; 2 requests failed');
});

it('names one object, leaves out what it did not read, and says nothing when nothing was read', () => {
  const { recorder } = clock();
  const read = recorder.start('vulnerability scans');
  const summaries = recorder.phase('cluster-a', 'summaries');
  expect(readSummary(read, parts)).toBeUndefined();

  summaries.request();
  expect(readSummary(read, parts)).toBe('Read 0 workloads in 0.0 s');
  summaries.items(1);
  expect(readSummary(read, parts)).toBe('Read 1 workload in 0.0 s');
});

it('logs each phase of a read that read anything', () => {
  const info = vi.spyOn(console, 'info').mockImplementation(() => {});
  const { time, recorder } = clock();
  recorder.finish(recorder.start('vulnerability scans'));
  expect(info).not.toHaveBeenCalled();

  const read = recorder.start('vulnerability scans');
  const cached = recorder.phase('cluster-a', 'cached reports');
  cached.items(310);
  cached.fromCache(310);
  time.now += 400;
  cached.end();
  recorder.finish(read);

  expect(info.mock.calls.map(([line]) => line)).toEqual([
    'Kubescape vulnerability scans: 310 objects (310 from the cache) in 0.4 s',
    'Kubescape vulnerability scans, cluster-a, cached reports: 310 objects (310 from the cache) in 0.4 s',
  ]);
  info.mockRestore();
});

it('times a phase until its work settles, also when it fails', async () => {
  const { time, recorder } = clock();
  const read = recorder.start('configuration scans');

  await expect(
    recorder.time('cluster-a', 'configuration scans', async counter => {
      counter.request();
      time.now += 2000;
      throw new Error('timeout');
    })
  ).rejects.toThrow('timeout');

  expect(read.phase('cluster-a', 'configuration scans')).toMatchObject({
    requests: 1,
    durationMs: 2000,
  });
});

it.each([
  [400, '0.4 s'],
  [12_345, '12.3 s'],
  [125_000, '2 min 5 s'],
  [-5, '0.0 s'],
  // rounded up to a whole minute
  [59_940, '59.9 s'],
  [59_960, '1 min 0 s'],
  [119_600, '2 min 0 s'],
])('formats %d ms as %s', (ms, text) => {
  expect(formatDuration(ms)).toBe(text);
});
