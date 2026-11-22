// Compiled patterns of posture exceptions, by flags and pattern; null for one that matches nothing
const compiledPatterns = new Map<string, RegExp | null>();

function compilePattern(pattern: string, flags: string): RegExp | null {
  try {
    return new RegExp(`^(?:${pattern})$`, flags);
  } catch {
    // Kubescape compiles a pattern that does not compile in a group without it. Go then reads a
    // leading * as any number of starts of the text, so * matches every value and *-web every
    // value that ends with -web.
    if (!pattern.startsWith('*')) return null;
    try {
      return new RegExp(`${pattern.slice(1)}$`, flags);
    } catch {
      return null;
    }
  }
}

/**
 * Whether a pattern of a posture exception matches the whole value, as Kubescape compares kinds,
 * names and API groups (opa-utils' comparator): as a regular expression, which Go and
 * JavaScript mostly read alike. A pattern that does not compile matches nothing.
 */
export function patternMatches(pattern: string, value: string, ignoreCase = false): boolean {
  const flags = ignoreCase ? 'i' : '';
  const key = `${flags}/${pattern}`;
  let compiled = compiledPatterns.get(key);
  if (compiled === undefined) {
    compiled = compilePattern(pattern, flags);
    compiledPatterns.set(key, compiled);
  }
  return !!compiled && compiled.test(value);
}
