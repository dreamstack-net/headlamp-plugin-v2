// What a caught error says. Anything can be thrown, so a catch gets an unknown value.

/** The message of an error, or the text of anything else that was thrown. */
export function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === 'object' && error !== null) {
    const message = (error as { message?: unknown }).message;
    if (typeof message === 'string') return message;
  }
  return String(error);
}

/** The HTTP status of an error of Headlamp's API proxy, which carries the status of the answer. */
export function errorStatus(error: unknown): number | undefined {
  if (typeof error !== 'object' || error === null) return undefined;
  const status = (error as { status?: unknown }).status;
  return typeof status === 'number' ? status : undefined;
}

/** The name of an error, such as AbortError for a dialog that was closed. */
export function errorName(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null) return undefined;
  const name = (error as { name?: unknown }).name;
  return typeof name === 'string' ? name : undefined;
}
