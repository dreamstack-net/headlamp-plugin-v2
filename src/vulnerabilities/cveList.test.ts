import { VulnerabilityManifest } from '../softwarecomposition/VulnerabilityManifest';
import { getCVEList } from './cveList';
import { ImageScan, WorkloadScan } from './scanData';
import { match, unscoredMatch } from './testFixtures';

function image(name: string, ids: string[]): ImageScan {
  return {
    manifestName: name,
    namespace: 'kubescape',
    cluster: 'cluster-a',
    imageName: `${name}:1.0`,
    creationTimestamp: '',
    matches: ids.map(id => {
      const m: VulnerabilityManifest.Match = match(id);
      m.artifact = { name: `pkg-${id}`, version: '1.0' };
      return m;
    }),
  };
}

function workload(
  name: string,
  imageScan: ImageScan,
  relevantIds?: string[],
  namespace = 'shop',
  cluster = 'cluster-a'
): WorkloadScan {
  return {
    manifestName: name,
    name,
    kind: 'Deployment',
    container: 'app',
    namespace,
    cluster,
    imageScan,
    relevant: relevantIds ? image(`${name}-relevant`, relevantIds) : undefined,
  };
}

it('lists each CVE once with all its workloads and images', () => {
  const web = image('web', ['CVE-1', 'CVE-2']);
  const db = image('db', ['CVE-2']);

  const cves = getCVEList([workload('web', web), workload('api', web), workload('db', db)]);

  expect(cves.map(cve => cve.CVE)).toEqual(['CVE-1', 'CVE-2']);
  expect([...cves[1].workloads]).toEqual(['shop/web/app', 'shop/api/app', 'shop/db/app']);
  expect([...cves[1].images]).toEqual(['web:1.0', 'db:1.0']);
});

it('finds a CVE relevant when any workload with relevancy data uses it', () => {
  const web = image('web', ['CVE-1', 'CVE-2', 'CVE-3']);

  const cves = getCVEList([
    // the first workload that has a CVE decides as much as the others
    workload('web', web, ['CVE-1']),
    workload('api', web, ['CVE-2']),
    workload('batch', web),
  ]);

  expect(cves.map(cve => [cve.CVE, cve.relevant])).toEqual([
    ['CVE-1', true],
    ['CVE-2', true],
    ['CVE-3', false],
  ]);
});

it('does not know the relevance without relevancy data', () => {
  const cves = getCVEList([workload('web', image('web', ['CVE-1']))]);
  expect(cves[0].relevant).toBeUndefined();
});

it('counts workloads of the same name in other namespaces and clusters apart', () => {
  const web = image('web', ['CVE-1']);

  const [cve] = getCVEList([
    workload('api', web, undefined, 'team-a'),
    workload('api', web, undefined, 'team-b'),
    workload('api', web, undefined, 'team-a', 'cluster-b'),
  ]);

  expect([...cve.workloads]).toEqual([
    'cluster-a/team-a/api/app',
    'cluster-a/team-b/api/app',
    'cluster-b/team-a/api/app',
  ]);
});

it('finds a CVE fixed only when a finding of it has a fix', () => {
  const web = image('web', ['CVE-1', 'CVE-2']);
  // a finding without a fix also has a list of versions, which is empty
  web.matches[0].vulnerability.fix = { state: 'not-fixed', versions: [] };

  const cves = getCVEList([workload('web', web)]);

  expect(cves.map(cve => [cve.CVE, cve.fixed])).toEqual([
    ['CVE-1', false],
    ['CVE-2', true],
  ]);
});

it('scores a CVE without a CVSS score as 0', () => {
  const web = image('web', ['CVE-1']);
  web.matches.push(unscoredMatch('CVE-2'));
  const unscored = unscoredMatch('CVE-3');
  // the cache keeps the scores without their metrics when a report has none
  unscored.vulnerability.cvss = [{}] as any;
  web.matches.push(unscored);

  const cves = getCVEList([workload('web', web)]);

  expect(cves.map(cve => [cve.CVE, cve.baseScore])).toEqual([
    ['CVE-1', 8],
    ['CVE-2', 0],
    ['CVE-3', 0],
  ]);
});

it('keeps the related ids of a CVE, such as the CVE of a GHSA', () => {
  const web = image('web', ['GHSA-1']);
  web.matches[0].relatedVulnerabilities = [
    { id: 'GHSA-1', description: 'the advisory' },
    { id: 'CVE-2024-1234', description: '' },
  ];

  const [cve] = getCVEList([workload('web', web)]);

  expect([...cve.relatedIds]).toEqual(['CVE-2024-1234']);
});
