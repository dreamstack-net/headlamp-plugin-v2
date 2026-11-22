// The requests of the lookups of image versions: at most four at a time, the lookups of the view
// that opened last first, and each only with the permit of the setting that allows it.

/*
  The names of images that may be private are only sent with a permit, which switching the setting
  off revokes: the requests that wait their turn and those that lookups have yet to make are then
  not sent.
*/
let privateNames = new AbortController();

/** The permit to send the names of images that may be private, while the settings allow it. */
export function possiblyPrivatePermit(): AbortSignal {
  return privateNames.signal;
}

/** Revokes the permit, when the settings no longer allow names that may be private. */
export function stopPossiblyPrivateLookups() {
  privateNames.abort();
  privateNames = new AbortController();
}

/*
  The other requests of the lookups take a permit too, one for the newest versions and one for
  the end of life, so that switching either off also stops what its lookups have yet to ask.
*/
let newestVersions = new AbortController();
let endOfLifeDates = new AbortController();

/** The permit of the lookups of the newest versions, while the settings show them. */
export function imageVersionsPermit(): AbortSignal {
  return newestVersions.signal;
}

/** Revokes the permit, when the newest versions are switched off. */
export function stopImageVersionLookups() {
  newestVersions.abort();
  newestVersions = new AbortController();
}

/** The permit to ask endoflife.date, while the settings show the end of life. */
export function endOfLifePermit(): AbortSignal {
  return endOfLifeDates.signal;
}

/** Revokes the permit, when the end of life is switched off. */
export function stopEndOfLifeLookups() {
  endOfLifeDates.abort();
  endOfLifeDates = new AbortController();
}

/** A request that was not sent, as its permit was revoked. */
export class LookupStopped extends Error {}

// at most four requests at a time, so that a list of images does not flood the services
const maxRequests = 4;
let running = 0;
// the requests that wait, with the generation of the lookups that made them
const waiting: Array<{ turn: () => void; generation: number }> = [];
let generation = 0;

/**
 * Puts the requests of the lookups that start from now on before the requests that wait for
 * earlier ones. A view that opens starts its lookups after this, so it is not kept waiting
 * behind the lookups of a page that was left, such as the image list of a hidden tab.
 */
export function preferNewLookups() {
  generation++;
}

/** Gives a free request to the newest waiting one, in the order of their generation. */
function nextTurn() {
  if (waiting.length === 0) return;
  let next = 0;
  for (let i = 1; i < waiting.length; i++) {
    if (waiting[i].generation > waiting[next].generation) next = i;
  }
  const [entry] = waiting.splice(next, 1);
  entry.turn();
}

/** Waits for a free request; a revoked permit takes the request out of the queue. */
function waitTurn(priority: number, permit?: AbortSignal) {
  return new Promise<void>((resolve, reject) => {
    const entry = {
      generation: priority,
      turn: () => {
        permit?.removeEventListener('abort', stop);
        resolve();
      },
    };
    const stop = () => {
      const index = waiting.indexOf(entry);
      if (index >= 0) waiting.splice(index, 1);
      reject(new LookupStopped());
    };
    if (permit?.aborted) return stop();
    waiting.push(entry);
    permit?.addEventListener('abort', stop, { once: true });
  });
}

/**
 * The JSON of a public service; null for a repository it does not know or may not show, which it
 * says with one of the missing statuses. A request with a permit is only sent while it holds.
 */
export async function fetchBody(
  url: string,
  as: 'json' | 'text',
  missing: number[] = [401, 403, 404],
  permit?: AbortSignal
): Promise<any> {
  const priority = generation;
  while (running >= maxRequests) {
    await waitTurn(priority, permit);
  }
  if (permit?.aborted) {
    // the turn goes to the next request
    nextTurn();
    throw new LookupStopped();
  }
  running++;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(url, { signal: controller.signal, credentials: 'omit' });
    if (missing.includes(response.status)) return null;
    if (!response.ok) throw new Error(`${url} answered ${response.status}`);
    return as === 'json' ? await response.json() : await response.text();
  } finally {
    clearTimeout(timer);
    running--;
    nextTurn();
  }
}

export function fetchJson(url: string, permit?: AbortSignal): Promise<any> {
  return fetchBody(url, 'json', undefined, permit);
}

export function strings(values: unknown[]): string[] {
  return values.filter((value): value is string => typeof value === 'string');
}
