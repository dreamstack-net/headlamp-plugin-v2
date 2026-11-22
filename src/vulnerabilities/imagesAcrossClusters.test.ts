import type { VulnerabilityManifest } from '../softwarecomposition/VulnerabilityManifest';
import {
  candidateOrderText,
  candidateWorkloads,
  compareClusters,
  compareTags,
  describeCandidate,
  describeDifference,
  filterRepositories,
  hasDifferences,
  imageRepository,
  imageVersion,
  listClusters,
  newestFirst,
  repositoryStatus,
  repositoryStatusParts,
  severityCount,
  severityText,
  splitRepository,
  variantWorkloads,
} from './imagesAcrossClusters';
import type { ImageScan, WorkloadScan } from './scanData';
import { match } from './testFixtures';

type Finding = VulnerabilityManifest.Match;

function cve(id: string, severity = 'High', fixed = true, packageName = 'package'): Finding {
  const finding = match(id);
  finding.vulnerability.severity = severity;
  finding.vulnerability.fix = fixed
    ? { state: 'fixed', versions: ['2.0'] }
    : { state: 'not-fixed', versions: [] };
  finding.artifact = { name: packageName, version: '1.0' };
  return finding;
}

function report(
  cluster: string,
  imageName: string,
  matches: Finding[],
  ignoredMatches?: Finding[]
): ImageScan {
  return {
    manifestName: `${imageName.replace(/[/:@]/g, '-')}-${cluster}`,
    namespace: 'kubescape',
    cluster,
    imageName,
    creationTimestamp: '2026-11-01T00:00:00Z',
    matches,
    ignoredMatches,
  };
}

function workload(imageScan: ImageScan, name = 'web', relevant?: ImageScan): WorkloadScan {
  return {
    manifestName: `deployment-${name}-${imageScan.cluster}`,
    name,
    kind: 'Deployment',
    container: 'app',
    namespace: 'shop',
    cluster: imageScan.cluster,
    imageScan,
    relevant,
  };
}

const ids = (delta: { cves: Array<{ id: string }> }) => delta.cves.map(found => found.id);

describe('image repositories and versions', () => {
  it('names a repository the same however the image is written', () => {
    expect(imageRepository('nginx:1.25.3')).toBe('docker.io/library/nginx');
    expect(imageRepository('docker.io/library/nginx:1.25.1')).toBe('docker.io/library/nginx');
    expect(imageRepository('index.docker.io/library/nginx')).toBe('docker.io/library/nginx');
    expect(imageRepository('registry.example.com:5000/team/app:v2')).toBe(
      'registry.example.com:5000/team/app'
    );
  });

  it('takes the tag as the version, latest without one, or the start of the digest', () => {
    expect(imageVersion('nginx:1.25.3')).toBe('1.25.3');
    expect(imageVersion('registry.example.com:5000/team/app')).toBe('latest');
    expect(imageVersion('quay.io/org/app:v1.2@sha256:' + 'a'.repeat(64))).toBe('v1.2');
    expect(imageVersion('ghcr.io/org/app@sha256:0123456789abcdef' + 'f'.repeat(48))).toBe(
      '@sha256:0123456789ab'
    );
  });
});

describe('compareTags', () => {
  it('orders versions of one format', () => {
    expect(compareTags('1.25.3', '1.25.1')).toBeGreaterThan(0);
    expect(compareTags('1.25.1', '1.25.3')).toBeLessThan(0);
    expect(compareTags('1.26', '1.25.3')).toBeGreaterThan(0);
    // a prefix v is the same format
    expect(compareTags('v1.2.3', '1.2.4')).toBeLessThan(0);
    expect(compareTags('1.25.3-alpine3.20', '1.25.3-alpine3.19')).toBeGreaterThan(0);
    // a release comes after its pre-releases
    expect(compareTags('2.0.0-rc.1', '2.0.0')).toBeLessThan(0);
  });

  it('calls variants of one version the same version', () => {
    expect(compareTags('1.25.3-alpine', '1.25.3')).toBe(0);
    expect(compareTags('1.25.3-alpine', '1.25.3-bookworm')).toBe(0);
  });

  it('does not order tags that are not versions of one format, or a line and its release', () => {
    expect(compareTags('latest', '1.25.3')).toBeUndefined();
    expect(compareTags('main', 'stable')).toBeUndefined();
    // the release line 1.25 holds 1.25.3
    expect(compareTags('1.25', '1.25.3')).toBeUndefined();
    expect(compareTags('distroless-v1.2', 'v1.3')).toBeUndefined();
    // a date tags a build
    expect(compareTags('20240101', '1.2.3')).toBeUndefined();
    // also next to a release line of one number, as alpine tags 3 and 20260805
    expect(compareTags('20260805', '3')).toBeUndefined();
    expect(compareTags('3', '20260805')).toBeUndefined();
    // builds of two dates are ordered
    expect(compareTags('20260805', '20240101')).toBeGreaterThan(0);
  });

  it('sorts tags newest first, with the tags that are not versions last', () => {
    expect(['latest', '1.9', '1.10', 'main', '1.2'].sort(newestFirst)).toEqual([
      '1.10',
      '1.9',
      '1.2',
      'latest',
      'main',
    ]);
  });
});

describe('compareClusters', () => {
  it('compares the versions of the clusters and offers the newer one without CVEs', () => {
    const newer = [cve('CVE-A', 'Critical'), cve('CVE-B'), cve('CVE-NEW', 'High', false)];
    const older = [
      cve('CVE-A', 'Critical'),
      cve('CVE-B'),
      cve('CVE-OLD3', 'Low'),
      cve('CVE-OLD2', 'High'),
      cve('CVE-OLD1', 'Critical'),
    ];
    const comparison = compareClusters(
      [
        workload(report('tst', 'nginx:1.25.3', newer)),
        workload(report('acc', 'docker.io/library/nginx:1.25.3', newer)),
        workload(report('prd', 'nginx:1.25.1', older)),
      ],
      ['tst', 'acc', 'prd']
    );

    expect(comparison.clusters).toEqual(['tst', 'acc', 'prd']);
    expect(comparison.withoutScans).toEqual([]);
    const [nginx] = comparison.repositories;
    expect(nginx.repository).toBe('docker.io/library/nginx');
    expect(nginx.runningIn).toEqual(['tst', 'acc', 'prd']);
    expect(nginx.missingIn).toEqual([]);
    expect(nginx.versionsDiffer).toBe(true);
    expect(nginx.reportsDiffer).toBe(false);
    expect([...nginx.versions.keys()]).toEqual(['tst', 'acc', 'prd']);
    expect(nginx.versions.get('acc')?.[0].imageNames).toEqual(['docker.io/library/nginx:1.25.3']);
    expect(repositoryStatus(nginx)).toBe('Versions differ');

    // tst and acc run the same version with the same CVEs, so they are compared with prd once
    expect(nginx.differences).toHaveLength(1);
    const [difference] = nginx.differences;
    expect(difference.order).toBe('newer');
    expect(difference.a.clusters).toEqual(['tst', 'acc']);
    expect(difference.b.clusters).toEqual(['prd']);
    expect(ids(difference.onlyInB)).toEqual(['CVE-OLD1', 'CVE-OLD2', 'CVE-OLD3']);
    expect(ids(difference.onlyInA)).toEqual(['CVE-NEW']);
    expect(describeDifference(difference)).toBe(
      'tst and acc run 1.25.3, prd runs 1.25.1: 3 CVEs of prd are not in the reports of tst and ' +
        'acc (1 critical, 1 high); the newer 1.25.3 adds 1 CVE (1 high)'
    );

    expect(comparison.upgradeCandidates).toHaveLength(1);
    const [candidate] = comparison.upgradeCandidates;
    expect(candidate.from.clusters).toEqual(['prd']);
    expect(candidate.from.version).toBe('1.25.1');
    expect(candidate.to.clusters).toEqual(['tst', 'acc']);
    expect(candidate.order).toBe('newer');
    expect(candidateOrderText(candidate.order)).toBe('Newer version');
    expect(severityText(candidate.removed)).toBe('1 critical, 1 high');
    expect(describeCandidate(candidate)).toBe(
      'prd runs 1.25.1: moving to 1.25.3, which tst and acc run, removes 3 CVEs (1 critical, ' +
        '1 high) and adds 1 (1 high)'
    );

    expect(comparison.summary).toEqual({
      images: 1,
      inSeveralClusters: 1,
      differ: 1,
      versionsDiffer: 1,
      reportsDiffer: 0,
      notInEveryCluster: 0,
      newerAddCves: 1,
    });
  });

  it('says how many CVEs of a cluster the report of another does not have', () => {
    const shared = [cve('CVE-1')];
    const old = [cve('CVE-2', 'Critical'), cve('CVE-3', 'Critical'), cve('CVE-4', 'Medium')];
    const comparison = compareClusters(
      [
        workload(report('tst', 'nginx:1.25.3', shared)),
        workload(report('prd', 'nginx:1.25.1', [...shared, ...old])),
      ],
      ['tst', 'prd']
    );

    expect(describeDifference(comparison.repositories[0].differences[0])).toBe(
      "tst runs 1.25.3, prd runs 1.25.1: 3 CVEs of prd are not in tst's report (2 critical)"
    );
    expect(describeCandidate(comparison.upgradeCandidates[0])).toBe(
      'prd runs 1.25.1: moving to 1.25.3, which tst runs, removes 3 CVEs (2 critical)'
    );
    expect(comparison.summary.newerAddCves).toBe(0);
  });

  it('never offers an older version, and reports what a newer version adds', () => {
    const comparison = compareClusters(
      [
        workload(report('tst', 'app:2.0.0', [cve('CVE-1'), cve('CVE-2', 'Critical')])),
        workload(report('prd', 'app:1.9.0', [cve('CVE-1')])),
      ],
      ['tst', 'prd']
    );

    expect(comparison.upgradeCandidates).toEqual([]);
    const [difference] = comparison.repositories[0].differences;
    expect(difference.a.version).toBe('2.0.0');
    expect(describeDifference(difference)).toBe(
      'tst runs 2.0.0, prd runs 1.9.0: the newer 2.0.0 adds 1 CVE (1 critical)'
    );
    expect(comparison.summary.newerAddCves).toBe(1);
  });

  it('orders by version, not by the order of the clusters', () => {
    // prd runs the newer version, as after a hotfix
    const comparison = compareClusters(
      [
        workload(report('tst', 'app:1.0.0', [cve('CVE-1'), cve('CVE-2')])),
        workload(report('prd', 'app:1.0.1', [cve('CVE-1')])),
      ],
      ['tst', 'prd']
    );

    const [candidate] = comparison.upgradeCandidates;
    expect(candidate.from.clusters).toEqual(['tst']);
    expect(candidate.to.clusters).toEqual(['prd']);
    expect(describeDifference(comparison.repositories[0].differences[0])).toBe(
      "prd runs 1.0.1, tst runs 1.0.0: 1 CVE of tst is not in prd's report (1 high)"
    );
  });

  it('tells a tag with other reports apart, which is not a version to move to', () => {
    const comparison = compareClusters(
      [
        workload(report('tst', 'app:latest', [cve('CVE-1')])),
        workload(report('prd', 'app:latest', [cve('CVE-1'), cve('CVE-2', 'Critical')])),
      ],
      ['tst', 'prd']
    );

    const [repository] = comparison.repositories;
    expect(repository.versionsDiffer).toBe(false);
    expect(repository.reportsDiffer).toBe(true);
    expect(repositoryStatus(repository)).toBe('Reports differ');
    expect(hasDifferences(repository)).toBe(true);
    expect(repository.differences[0].order).toBe('same tag');
    expect(describeDifference(repository.differences[0])).toBe(
      "tst and prd run latest with other reports: 1 CVE of prd is not in tst's report (1 critical)"
    );
    expect(comparison.upgradeCandidates).toEqual([]);
    expect(comparison.summary.reportsDiffer).toBe(1);
  });

  it('compares tags that cannot be ordered both ways, but offers them as no upgrade', () => {
    const comparison = compareClusters(
      [
        workload(report('tst', 'app:main', [cve('CVE-1'), cve('CVE-2')])),
        workload(report('prd', 'app:stable', [cve('CVE-1'), cve('CVE-3', 'Critical')])),
      ],
      ['tst', 'prd']
    );

    expect(comparison.repositories[0].differences[0].order).toBe('unordered');
    // branch builds are no upgrades of each other
    expect(comparison.upgradeCandidates).toEqual([]);
    const [main, stable] = comparison.repositories[0].tags;
    expect([main.version, stable.version]).toEqual(['main', 'stable']);
    expect(main.upgrades).toEqual([]);
    expect(
      [main, stable].map(tag =>
        tag.others.map(option => [
          option.to.version,
          candidateOrderText(option.order),
          option.removed.cves.map(found => found.id),
          option.added.cves.map(found => found.id),
        ])
      )
    ).toEqual([
      [['stable', 'Not comparable', ['CVE-2'], ['CVE-3']]],
      [['main', 'Not comparable', ['CVE-3'], ['CVE-2']]],
    ]);
    expect(describeDifference(comparison.repositories[0].differences[0])).toBe(
      "tst runs main, prd runs stable: 1 CVE of prd is not in tst's report (1 critical); " +
        "1 CVE of tst is not in prd's report (1 high)"
    );
  });

  it('offers another variant of a version', () => {
    const comparison = compareClusters(
      [
        workload(report('tst', 'app:1.2.0-alpine', [cve('CVE-1')])),
        workload(report('prd', 'app:1.2.0', [cve('CVE-1'), cve('CVE-2')])),
      ],
      ['tst', 'prd']
    );

    // another variant is no upgrade, but an option of the tag
    expect(comparison.upgradeCandidates).toEqual([]);
    const plain = comparison.repositories[0].tags.find(tag => tag.version === '1.2.0')!;
    expect(plain.others.map(option => [option.to.version, option.order])).toEqual([
      ['1.2.0-alpine', 'same version'],
    ]);
    expect(candidateOrderText('same version')).toBe('Other variant');
  });

  it('compares versions without other CVEs too, as their tags differ', () => {
    const comparison = compareClusters(
      [
        workload(report('tst', 'app:1.1.0', [cve('CVE-1')])),
        workload(report('prd', 'app:1.0.0', [cve('CVE-1')])),
      ],
      ['tst', 'prd']
    );

    expect(describeDifference(comparison.repositories[0].differences[0])).toBe(
      'tst runs 1.1.0, prd runs 1.0.0: the reports have the same CVEs'
    );
    expect(comparison.upgradeCandidates).toEqual([]);
  });

  it('names the clusters that do not run an image, leaving out clusters without scans', () => {
    const comparison = compareClusters(
      [
        workload(report('tst', 'redis:7.4.1', [])),
        workload(report('tst', 'nginx:1.25.3', [])),
        workload(report('prd', 'nginx:1.25.3', [])),
        workload(report('dev', 'nginx:1.25.3', [])),
      ],
      ['tst', 'acc', 'prd']
    );

    // dev is not selected, and of acc no scans were read
    expect(comparison.clusters).toEqual(['tst', 'prd']);
    expect(comparison.withoutScans).toEqual(['acc']);
    const [nginx, redis] = comparison.repositories;
    expect(nginx.runningIn).toEqual(['tst', 'prd']);
    expect(repositoryStatus(nginx)).toBe('Same');
    expect(hasDifferences(nginx)).toBe(false);
    expect(redis.missingIn).toEqual(['prd']);
    expect(repositoryStatus(redis)).toBe('Only in tst');
    expect(hasDifferences(redis)).toBe(true);
    expect(comparison.summary).toMatchObject({
      images: 2,
      inSeveralClusters: 1,
      versionsDiffer: 0,
      notInEveryCluster: 1,
    });
  });

  it('names the clusters without an image when it runs in several', () => {
    const comparison = compareClusters(
      [
        workload(report('tst', 'app:2.0.0', [])),
        workload(report('acc', 'app:1.0.0', [])),
        workload(report('prd', 'other:1.0.0', [])),
      ],
      ['tst', 'acc', 'prd']
    );

    expect(repositoryStatus(comparison.repositories[0])).toBe('Versions differ; Not in prd');
    expect(repositoryStatusParts(comparison.repositories[0])).toEqual([
      { label: 'Versions differ', kind: 'versions' },
      { label: 'Not in prd', kind: 'missing' },
    ]);
  });

  it('does not call an image missing in a cluster with workloads whose report was not read', () => {
    const tool = report('tst', 'tool:1.0.0', []);
    // the report of prd's tool gave 404, so the workload is known without its image
    const withoutReport: WorkloadScan = {
      ...workload(report('prd', 'tool:0.9.0', []), 'tool'),
      imageScan: undefined,
    };
    const comparison = compareClusters(
      [
        workload(tool, 'tool'),
        withoutReport,
        workload(report('tst', 'app:1.0.0', [])),
        workload(report('acc', 'app:1.0.0', [])),
        workload(report('prd', 'app:1.0.0', [])),
      ],
      ['tst', 'acc', 'prd']
    );

    expect(comparison.clusters).toEqual(['tst', 'acc', 'prd']);
    expect(comparison.withoutReports).toEqual([
      {
        cluster: 'prd',
        workloads: [
          {
            cluster: 'prd',
            namespace: 'shop',
            kind: 'Deployment',
            name: 'tool',
            container: 'app',
            manifestName: 'deployment-tool-prd',
          },
        ],
      },
    ]);
    const [app, toolImage] = comparison.repositories;
    expect(app.unknownIn).toEqual([]);
    expect(repositoryStatus(app)).toBe('Same');
    // acc runs no tool, prd may
    expect(toolImage.missingIn).toEqual(['acc']);
    expect(toolImage.unknownIn).toEqual(['prd']);
    expect(repositoryStatusParts(toolImage)).toEqual([
      { label: 'Not in acc', kind: 'missing' },
      { label: "Not in prd's reports", kind: 'unknown' },
    ]);
    expect(hasDifferences(toolImage)).toBe(true);
    expect(comparison.summary.notInEveryCluster).toBe(1);
  });

  it('calls only the image a workload without a report runs unknown, when its summary names it', () => {
    const withoutReport: WorkloadScan = {
      ...workload(report('prd', 'tool:0.9.0', []), 'tool'),
      imageScan: undefined,
      image: 'docker.io/library/tool:0.9.0',
    };
    const comparison = compareClusters(
      [
        workload(report('tst', 'tool:1.0.0', []), 'tool'),
        withoutReport,
        workload(report('tst', 'app:1.0.0', [])),
      ],
      ['tst', 'prd']
    );

    const [app, toolImage] = comparison.repositories;
    expect(toolImage.unknownIn).toEqual(['prd']);
    expect(toolImage.missingIn).toEqual([]);
    // prd's reports lack app, and no workload of prd without a report runs it
    expect(app.missingIn).toEqual(['prd']);
    expect(app.unknownIn).toEqual([]);
  });

  it('names the clusters whose reports lack an image rather than the one that has it', () => {
    const without = (cluster: string): WorkloadScan => ({
      ...workload(report(cluster, 'other:1.0.0', []), 'other'),
      imageScan: undefined,
    });
    const comparison = compareClusters(
      [workload(report('tst', 'tool:1.0.0', [])), without('acc'), without('prd')],
      ['tst', 'acc', 'prd']
    );

    const [tool] = comparison.repositories;
    expect(tool.missingIn).toEqual([]);
    expect(repositoryStatus(tool)).toBe('Not in the reports of acc and prd');
    expect(filterRepositories(comparison.repositories, 'missing')).toEqual([tool]);
  });

  it('compares the CVEs that exceptions hid too, and counts only the open ones', () => {
    const comparison = compareClusters(
      [
        workload(report('tst', 'app:1.0.0', [cve('CVE-1', 'Critical'), cve('CVE-2')])),
        // prd accepted the risk of CVE-1
        workload(report('prd', 'app:1.0.0', [cve('CVE-2')], [cve('CVE-1', 'Critical')])),
      ],
      ['tst', 'prd']
    );

    const [repository] = comparison.repositories;
    expect(repository.differences).toEqual([]);
    expect(hasDifferences(repository)).toBe(false);
    expect(repository.versions.get('tst')?.[0].counts).toMatchObject({ total: 2, critical: 1 });
    expect(repository.versions.get('prd')?.[0].counts).toMatchObject({ total: 1, critical: 0 });
  });

  it('counts the CVEs of a report once, and those that workloads were seen to use', () => {
    const image = report('tst', 'app:1.0.0', [
      cve('CVE-1', 'Critical'),
      cve('CVE-2', 'Critical', false),
      cve('CVE-3', 'High', false),
      // CVE-3 of another package, and of medium severity there
      cve('CVE-3', 'Medium', true, 'other-package'),
      cve('CVE-4', 'Low'),
    ]);
    const relevantOfWeb = report('tst', 'app:1.0.0', [cve('CVE-1', 'Critical')]);
    // the relevant report has CVE-3 only in the other package
    const relevantOfWorker = report('tst', 'app:1.0.0', [
      cve('CVE-3', 'Medium', true, 'other-package'),
    ]);
    relevantOfWeb.manifestName = 'web-relevant';
    relevantOfWorker.manifestName = 'worker-relevant';
    const unscanned = report('prd', 'app:1.0.0', [cve('CVE-1', 'Critical')]);
    const comparison = compareClusters(
      [
        workload(image, 'web', relevantOfWeb),
        workload(image, 'worker', relevantOfWorker),
        workload(unscanned),
        // a cluster that is not selected
        workload(report('dev', 'app:1.0.0', [cve('CVE-9', 'Critical')])),
      ],
      ['tst', 'prd']
    );

    const [repository] = comparison.repositories;
    const [tst] = repository.versions.get('tst')!;
    expect(tst.workloads).toEqual(['shop/web/app', 'shop/worker/app']);
    // what the links to their pages need, in the same order
    expect(tst.workloadReferences).toEqual([
      {
        cluster: 'tst',
        namespace: 'shop',
        kind: 'Deployment',
        name: 'web',
        container: 'app',
        manifestName: 'deployment-web-tst',
      },
      expect.objectContaining({ name: 'worker', manifestName: 'deployment-worker-tst' }),
    ]);
    expect(tst.reports).toHaveLength(1);
    expect(tst.cves.get('CVE-3')).toEqual({
      severity: 'High',
      fixable: true,
      open: true,
      relevant: true,
    });
    expect(tst.counts).toEqual({
      total: 4,
      critical: 2,
      high: 1,
      medium: 0,
      low: 1,
      fixable: 3,
      relevant: { total: 2, critical: 1, high: 1 },
    });
    // no workload of prd has a relevant report
    expect(repository.versions.get('prd')?.[0].counts.relevant).toBeUndefined();
    expect(repository.versions.has('dev')).toBe(false);
  });

  it('lists the versions of a cluster newest first, and compares them only with other clusters', () => {
    const comparison = compareClusters(
      [
        workload(report('tst', 'app:1.0.0', [cve('CVE-1')]), 'old'),
        workload(report('tst', 'app:2.0.0', []), 'new'),
        workload(report('prd', 'app:1.0.0', [cve('CVE-1')])),
        // two versions in tst only
        workload(report('tst', 'tool:1.0.0', [cve('CVE-1')])),
        workload(report('tst', 'tool:2.0.0', [])),
      ],
      ['tst', 'prd']
    );

    const [app, tool] = comparison.repositories;
    expect(app.versions.get('tst')?.map(version => version.version)).toEqual(['2.0.0', '1.0.0']);
    expect(app.versionsDiffer).toBe(true);
    // 1.0.0 runs in tst and prd with the same CVEs; 2.0.0 of tst differs from prd's
    expect(app.differences).toHaveLength(1);
    expect(app.differences[0].b.clusters).toEqual(['tst', 'prd']);
    expect(describeCandidate(comparison.upgradeCandidates[0])).toBe(
      'tst and prd run 1.0.0: moving to 2.0.0, which tst runs, removes 1 CVE (1 high)'
    );
    expect(tool.differences).toEqual([]);
    expect(repositoryStatus(tool)).toBe('Only in tst');
  });

  it('does not compare versions that the same clusters run', () => {
    const both = (cluster: string) => [
      workload(report(cluster, 'app:1.0.0', [cve('CVE-1')]), 'old'),
      workload(report(cluster, 'app:2.0.0', []), 'new'),
    ];
    const comparison = compareClusters([...both('tst'), ...both('prd')], ['tst', 'prd']);

    // tst and prd each run both versions: no cluster runs one of them and not the other
    const [app] = comparison.repositories;
    expect(repositoryStatus(app)).toBe('Same');
    expect(app.differences).toEqual([]);
    expect(app.tags.map(tag => [tag.version, tag.upgrades.length, tag.others.length])).toEqual([
      ['2.0.0', 0, 0],
      ['1.0.0', 0, 0],
    ]);
    expect(comparison.upgradeCandidates).toEqual([]);
    expect(comparison.summary).toMatchObject({ differ: 0, newerAddCves: 0 });

    // a cluster that only runs the old version has the new one to move to
    const withAcc = compareClusters(
      [...both('tst'), ...both('prd'), workload(report('acc', 'app:1.0.0', [cve('CVE-1')]))],
      ['tst', 'acc', 'prd']
    );
    expect(withAcc.repositories[0].differences).toHaveLength(1);
    expect(withAcc.upgradeCandidates.map(describeCandidate)).toEqual([
      'tst, acc and prd run 1.0.0: moving to 2.0.0, which tst and prd run, removes 1 CVE (1 high)',
    ]);
  });

  it('identifies differences and candidates uniquely, and by the reports they link to', () => {
    const scans = [
      workload(report('tst', 'app:main', [cve('CVE-1')])),
      workload(report('acc', 'app:stable', [cve('CVE-2')])),
      workload(report('prd', 'app:stable', [cve('CVE-3')])),
      workload(report('tst', 'app:1.0.0', [cve('CVE-1')]), 'old'),
      workload(report('prd', 'app:2.0.0', []), 'new'),
    ];
    const comparison = compareClusters(scans, ['tst', 'acc', 'prd']);
    const differenceIds = comparison.repositories[0].differences.map(difference => difference.id);
    expect(new Set(differenceIds).size).toBe(differenceIds.length);
    // acc's and prd's stable are one tag with other reports
    const tagIds = comparison.repositories[0].tags.map(tag => tag.id);
    expect(comparison.repositories[0].tags.map(tag => tag.version)).toEqual([
      '2.0.0',
      '1.0.0',
      'main',
      'stable',
    ]);
    expect(new Set(tagIds).size).toBe(4);
    expect(comparison.upgradeCandidates.map(candidate => candidate.id)).toEqual([
      JSON.stringify(['docker.io/library/app', tagIds[1], tagIds[0]]),
    ]);

    // a new report of the same version is another variant
    const rescanned = report('tst', 'app:main', [cve('CVE-1')]);
    rescanned.manifestName = 'app-main-rebuilt';
    const again = compareClusters([workload(rescanned), ...scans.slice(1)], ['tst', 'acc', 'prd']);
    expect(again.repositories[0].differences.map(difference => difference.id)).not.toEqual(
      differenceIds
    );
  });

  it('compares the images of big clusters quickly', () => {
    const clusters = ['tst', 'acc', 'prd'];
    const findings = Array.from({ length: 150 }, (_, i) =>
      cve(`CVE-${i}`, ['Critical', 'High', 'Medium', 'Low'][i % 4])
    );
    const scans: WorkloadScan[] = [];
    for (const [c, cluster] of clusters.entries()) {
      for (let image = 0; image < 400; image++) {
        // every tenth image is a version behind in the later clusters, with more CVEs
        const behind = image % 10 === 0 && c > 0;
        const imageScan = report(
          cluster,
          `registry.example.com/team/image-${image}:1.${behind ? 0 : 1}.0`,
          behind ? findings : findings.slice(0, 100)
        );
        for (let w = 0; w < 3; w++) scans.push(workload(imageScan, `workload-${image}-${w}`));
      }
    }

    const started = performance.now();
    const comparison = compareClusters(scans, clusters);
    const elapsed = performance.now() - started;

    expect(comparison.repositories).toHaveLength(400);
    expect(comparison.summary.versionsDiffer).toBe(40);
    expect(comparison.upgradeCandidates).toHaveLength(40);
    expect(comparison.upgradeCandidates[0].removed.cves).toHaveLength(50);
    // about 0.1 s on a laptop
    expect(elapsed).toBeLessThan(3000);
  });
});

describe('listClusters', () => {
  it('lists clusters like a sentence', () => {
    expect(listClusters([])).toBe('');
    expect(listClusters(['tst'])).toBe('tst');
    expect(listClusters(['tst', 'prd'])).toBe('tst and prd');
    expect(listClusters(['tst', 'acc', 'prd'])).toBe('tst, acc and prd');
  });
});

describe('filterRepositories', () => {
  it('shows the images that the counts of the summary count', () => {
    const comparison = compareClusters(
      [
        // newer in tst, with a CVE that prd's older version does not have
        workload(report('tst', 'app:2.0.0', [cve('CVE-1'), cve('CVE-NEW', 'Critical')])),
        workload(report('prd', 'app:1.0.0', [cve('CVE-1'), cve('CVE-OLD')])),
        // one tag, rebuilt in prd
        workload(report('tst', 'api:1.0.0', [cve('CVE-1')]), 'api'),
        workload(report('prd', 'api:1.0.0', [cve('CVE-2')]), 'api'),
        // only in tst
        workload(report('tst', 'tool:1.0.0', []), 'tool'),
        // the same everywhere
        workload(report('tst', 'redis:7.4.1', []), 'cache'),
        workload(report('prd', 'redis:7.4.1', []), 'cache'),
      ],
      ['tst', 'prd']
    );
    const names = (filter: Parameters<typeof filterRepositories>[1]) =>
      filterRepositories(comparison.repositories, filter).map(
        repository => splitRepository(repository.repository).name
      );

    expect(names('all')).toEqual(['api', 'app', 'redis', 'tool']);
    expect(names('differ')).toEqual(['api', 'app', 'tool']);
    expect(names('versions')).toEqual(['app']);
    expect(names('reports')).toEqual(['api']);
    expect(names('missing')).toEqual(['tool']);
    expect(names('newerAdds')).toEqual(['app']);
    // the summary counts images, as the tiles that show them do
    expect(comparison.summary).toEqual({
      images: 4,
      inSeveralClusters: 3,
      differ: 3,
      versionsDiffer: 1,
      reportsDiffer: 1,
      notInEveryCluster: 1,
      newerAddCves: 1,
    });
  });
});

describe('splitRepository', () => {
  it('splits the name of an image from its registry and path', () => {
    expect(splitRepository('docker.io/library/nginx')).toEqual({
      name: 'nginx',
      path: 'docker.io/library',
    });
    expect(splitRepository('europe-west4-docker.pkg.dev/project/team/service-proxy')).toEqual({
      name: 'service-proxy',
      path: 'europe-west4-docker.pkg.dev/project/team',
    });
    expect(splitRepository('local')).toEqual({ name: 'local', path: '' });
  });
});

describe('the counts of a candidate', () => {
  it('counts its CVEs per severity and names the workloads that would move', () => {
    // the workloads of one image share its report
    const old = report('prd', 'app:1.0.0', [
      cve('CVE-1', 'Critical'),
      cve('CVE-2', 'Medium'),
      cve('CVE-3', 'Medium'),
      cve('CVE-4', 'Negligible'),
    ]);
    const comparison = compareClusters(
      [workload(report('tst', 'app:2.0.0', [])), workload(old, 'web'), workload(old, 'worker')],
      ['tst', 'prd']
    );

    const [candidate] = comparison.upgradeCandidates;
    expect(
      ['Critical', 'High', 'Medium', 'Low'].map(s => severityCount(candidate.removed, s))
    ).toEqual([1, 0, 2, 0]);
    expect(severityCount(candidate.removed, 'Negligible')).toBe(0);
    expect(candidate.removed.cves).toHaveLength(4);
    expect(candidateWorkloads(candidate).map(found => `${found.cluster}/${found.name}`)).toEqual([
      'prd/web',
      'prd/worker',
    ]);
    const [prd] = comparison.repositories[0].versions.get('prd')!;
    expect(severityCount(prd.counts, 'Medium')).toBe(2);
  });
});

describe('the tags of a repository', () => {
  it('merges the reports of a tag in several clusters, and recommends the newest upgrade', () => {
    const old = report('prd', 'app:1.0.0', [cve('CVE-1', 'Critical'), cve('CVE-2')]);
    // tst scanned 1.0.0 with another database, which also finds CVE-3
    const rescanned = report('tst', 'app:1.0.0', [
      cve('CVE-1', 'Critical'),
      cve('CVE-2'),
      cve('CVE-3', 'Low'),
    ]);
    const comparison = compareClusters(
      [
        workload(old, 'web'),
        workload(old, 'worker'),
        workload(rescanned, 'web'),
        // two newer versions in two other clusters, each without the critical CVE
        workload(report('acc', 'app:2.0.0', [])),
        workload(report('acc', 'app:1.5.0', [cve('CVE-2')]), 'batch'),
        // a release line, which is not ordered with the 1.x releases of it
        workload(report('tst', 'app:1', [cve('CVE-2')]), 'legacy'),
      ],
      ['tst', 'acc', 'prd']
    );

    const tags = comparison.repositories[0].tags;
    expect(tags.map(tag => tag.version)).toEqual(['2.0.0', '1.5.0', '1', '1.0.0']);
    const tag = tags.find(found => found.version === '1.0.0')!;
    // one tag in tst and prd, with the CVEs of both reports
    expect(tag.clusters).toEqual(['tst', 'prd']);
    expect(tag.reportsDiffer).toBe(true);
    expect([...tag.cves.keys()].sort()).toEqual(['CVE-1', 'CVE-2', 'CVE-3']);
    expect(tag.counts).toMatchObject({ total: 3, critical: 1, high: 1, low: 1 });
    expect(variantWorkloads(tag).map(found => `${found.cluster}/${found.name}`)).toEqual([
      'tst/web',
      'prd/web',
      'prd/worker',
    ]);
    expect(tag.upgrades.map(option => option.to.version)).toEqual(['2.0.0', '1.5.0']);
    expect(tag.others.map(option => [option.to.version, option.order])).toEqual([
      ['1', 'unordered'],
    ]);

    // one candidate per tag: the newest version that removes CVEs, the others as alternatives
    const candidate = comparison.upgradeCandidates.find(found => found.from === tag)!;
    expect(candidate.to.version).toBe('2.0.0');
    expect(candidate.removed.cves.map(found => found.id)).toEqual(['CVE-1', 'CVE-2', 'CVE-3']);
    expect(candidate.alternatives.map(option => option.to.version)).toEqual(['1.5.0']);
    // 1.5.0 has no candidate, as 2.0.0 runs in the same cluster only; the release line 1 may
    // be any 1.x, so only 2.0.0 is newer
    expect(comparison.upgradeCandidates.map(found => found.from.version)).toEqual(['1.0.0', '1']);
    const line = tags.find(found => found.version === '1')!;
    expect(line.upgrades.map(option => option.to.version)).toEqual(['2.0.0']);
    expect(line.others.map(option => option.to.version).sort()).toEqual(['1.0.0', '1.5.0']);
  });
});
