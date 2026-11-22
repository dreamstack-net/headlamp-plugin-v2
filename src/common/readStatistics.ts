/*
  Statistics of the reads of the scan caches, so that a slow cluster can be measured: per cluster
  and phase of a read (summaries, reports, configuration scans, ...) the objects read, the ones
  taken from the cache, the requests, the failures and how long the phase took. A page shows one
  line after a read, and the details per phase go to the console.

  Pages share the tasks of a cache, so a request made for one read counts for every read in
  progress at that time. Recording only adds numbers: nothing is copied or serialized.
*/

/** What one phase of a read did in one cluster. */
export interface PhaseStatistics {
  cluster: string;
  phase: string;
  // the objects read, including the ones taken from the cache
  items: number;
  fromCache: number;
  requests: number;
  failures: number;
  durationMs: number;
}

/** The counts of a phase that a reader adds to while it reads. */
export interface ReadCounter {
  request(count?: number): void;
  items(count: number): void;
  fromCache(count: number): void;
  failure(count?: number): void;
}

/** A run of a phase, which counts until it ends. */
export interface PhaseRun extends ReadCounter {
  end(): void;
}

/** A counter that counts nothing, for reads without statistics. */
export const noCounter: ReadCounter = {
  request: () => {},
  items: () => {},
  fromCache: () => {},
  failure: () => {},
};

/** The statistics of one read of a page. */
export class ReadStatistics {
  private readonly byKey = new Map<string, PhaseStatistics>();
  finishedAt: number | undefined;

  constructor(readonly what: string, readonly startedAt: number) {}

  /** The statistics of a phase in a cluster, created at the first use. */
  phase(cluster: string, phase: string): PhaseStatistics {
    const key = `${cluster}\u0000${phase}`;
    let found = this.byKey.get(key);
    if (!found) {
      found = { cluster, phase, items: 0, fromCache: 0, requests: 0, failures: 0, durationMs: 0 };
      this.byKey.set(key, found);
    }
    return found;
  }

  get phases(): PhaseStatistics[] {
    return [...this.byKey.values()];
  }

  /** The sums of the phases with these names, over all clusters; all phases without names. */
  total(phases?: string[]): Omit<PhaseStatistics, 'cluster' | 'phase' | 'durationMs'> {
    const sum = { items: 0, fromCache: 0, requests: 0, failures: 0 };
    for (const stats of this.byKey.values()) {
      if (phases && !phases.includes(stats.phase)) continue;
      sum.items += stats.items;
      sum.fromCache += stats.fromCache;
      sum.requests += stats.requests;
      sum.failures += stats.failures;
    }
    return sum;
  }

  /** How long the read took, or has taken until `now`. */
  durationMs(now: number = this.finishedAt ?? this.startedAt): number {
    return (this.finishedAt ?? now) - this.startedAt;
  }

  /** Whether the read asked anything or took anything from the cache. */
  get readAnything(): boolean {
    const { requests, items } = this.total();
    return requests > 0 || items > 0;
  }
}

const defaultNow = () =>
  typeof performance !== 'undefined' && typeof performance.now === 'function'
    ? performance.now()
    : Date.now();

/**
 * The reads in progress of a cache. Phases record into every read in progress, as the reads
 * share their tasks; a read that began during a phase counts its duration from its own start.
 */
export class ReadRecorder {
  private readonly reads = new Set<ReadStatistics>();

  constructor(private readonly now: () => number = defaultNow) {}

  start(what: string): ReadStatistics {
    const read = new ReadStatistics(what, this.now());
    this.reads.add(read);
    return read;
  }

  /** Ends the read and logs its details, when it read anything. */
  finish(read: ReadStatistics, log: boolean = true): ReadStatistics {
    if (read.finishedAt === undefined) read.finishedAt = this.now();
    this.reads.delete(read);
    if (log) logReadStatistics(read);
    return read;
  }

  /** Starts a run of a phase in a cluster. */
  phase(cluster: string, phase: string): PhaseRun {
    const startedAt = this.now();
    const add = (field: 'items' | 'fromCache' | 'requests' | 'failures', count: number) => {
      for (const read of this.reads) read.phase(cluster, phase)[field] += count;
    };
    let ended = false;
    return {
      request: (count = 1) => add('requests', count),
      items: count => add('items', count),
      fromCache: count => add('fromCache', count),
      failure: (count = 1) => add('failures', count),
      end: () => {
        if (ended) return;
        ended = true;
        const now = this.now();
        for (const read of this.reads) {
          read.phase(cluster, phase).durationMs += now - Math.max(startedAt, read.startedAt);
        }
      },
    };
  }

  /** Runs a phase in a cluster, which ends when `run` settles. */
  async time<T>(
    cluster: string,
    phase: string,
    run: (counter: PhaseRun) => Promise<T>
  ): Promise<T> {
    const counter = this.phase(cluster, phase);
    try {
      return await run(counter);
    } finally {
      counter.end();
    }
  }
}

/** A duration as people read it: 0.4 s, 12.3 s, 2 min 5 s. */
export function formatDuration(ms: number): string {
  const seconds = Math.max(0, ms) / 1000;
  // rounded before the minutes are taken out, so that there is no 60.0 s and no 1 min 60 s
  const tenths = Math.round(seconds * 10) / 10;
  if (tenths < 60) return `${tenths.toFixed(1)} s`;
  const whole = Math.round(seconds);
  return `${Math.floor(whole / 60)} min ${whole % 60} s`;
}

/** What a line of the summary counts: the objects of these phases, named by the noun. */
export type SummaryPart = { noun: string; one: string; phases: string[] };

/**
 * One line about a read for the page, such as "Read 850 workloads and 420 image reports (310 from
 * the cache) in 12.3 s"; undefined when the read asked nothing.
 */
export function readSummary(read: ReadStatistics, parts: SummaryPart[]): string | undefined {
  if (!read.readAnything) return undefined;
  const counted = parts.map(part => ({ ...part, ...read.total(part.phases) }));
  const shown = counted.filter(part => part.items > 0);
  const named = (shown.length > 0 ? shown : counted.slice(0, 1)).map(
    part =>
      `${part.items} ${part.items === 1 ? part.one : part.noun}${
        part.fromCache > 0 ? ` (${part.fromCache} from the cache)` : ''
      }`
  );
  const list =
    named.length > 1 ? `${named.slice(0, -1).join(', ')} and ${named[named.length - 1]}` : named[0];
  const { failures } = read.total();
  const failed =
    failures > 0 ? `; ${failures} ${failures === 1 ? 'request' : 'requests'} failed` : '';
  return `Read ${list ?? 'nothing'} in ${formatDuration(read.durationMs())}${failed}`;
}

/** The counts of a phase or a read for the console: 420 objects (310 from the cache), 112 requests. */
function describeCounts(counts: Omit<PhaseStatistics, 'cluster' | 'phase' | 'durationMs'>) {
  return [
    `${counts.items} objects${counts.fromCache > 0 ? ` (${counts.fromCache} from the cache)` : ''}`,
    ...(counts.requests > 0 ? [`${counts.requests} requests`] : []),
    ...(counts.failures > 0 ? [`${counts.failures} failed`] : []),
  ].join(', ');
}

/** Logs a read and its phases, one line each, when it read anything. */
export function logReadStatistics(read: ReadStatistics) {
  if (!read.readAnything) return;
  console.info(
    `Kubescape ${read.what}: ${describeCounts(read.total())} in ${formatDuration(
      read.durationMs()
    )}`
  );
  for (const phase of read.phases) {
    console.info(
      `Kubescape ${read.what}, ${phase.cluster}, ${phase.phase}: ${describeCounts(
        phase
      )} in ${formatDuration(phase.durationMs)}`
    );
  }
}
