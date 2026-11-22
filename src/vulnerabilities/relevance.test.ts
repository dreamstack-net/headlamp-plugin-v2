import { findingKey, relevantFindingKeys, uniqueFindingIds } from './relevance';
import { match } from './testFixtures';

function finding(id: string, name: string, version = '1.0', artifactId?: string) {
  const m = match(id);
  m.artifact = { name, version, ...(artifactId ? { id: artifactId } : {}) };
  return m;
}

it('tells findings of a CVE in other packages apart', () => {
  const relevant = relevantFindingKeys([
    finding('CVE-1', 'busybox'),
    finding('CVE-1', 'ssl_client'),
  ]);

  expect(relevant.has(findingKey(finding('CVE-1', 'busybox')))).toBe(true);
  expect(relevant.has(findingKey(finding('CVE-1', 'busybox-binsh')))).toBe(false);
  expect(relevant.has(findingKey(finding('CVE-1', 'busybox', '2.0')))).toBe(false);
});

it('reads the findings of several lists, which may be missing', () => {
  const relevant = relevantFindingKeys(null, [finding('CVE-1', 'a')], undefined, [
    finding('CVE-2', 'b'),
  ]);
  expect(relevant.size).toBe(2);
});

it('gives each finding an id of its own, also for a package at several paths', () => {
  const ids = uniqueFindingIds([
    finding('CVE-1', 'undici', '6.28.0'),
    finding('CVE-1', 'undici', '6.28.0'),
    finding('CVE-1', 'undici', '6.28.0', 'pkg-a'),
    finding('CVE-1', 'undici', '6.28.0', 'pkg-b'),
    { ...finding('CVE-1', 'undici', '6.28.0'), hidden: true },
  ]);

  expect(new Set(ids).size).toBe(5);
  // the first of each keeps the id it had, so selections survive new findings at the end
  expect(ids[0]).toBe(uniqueFindingIds([finding('CVE-1', 'undici', '6.28.0')])[0]);
});
