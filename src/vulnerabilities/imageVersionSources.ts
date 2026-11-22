/*
  Where the newest version of an image is looked up. The plugin runs in the browser, which may
  only read services that allow other sites to: Docker Hub, GHCR, MCR, Amazon's public registry
  and Google's registries do not. So the tags of quay.io images come from Quay, those of gcr.io,
  *-docker.pkg.dev and registry.k8s.io images from the API of Google's Artifact Registry, those
  of the official images of Docker Hub from the library files Docker builds them from, the newest
  version of other Docker Hub images from shields.io, and the versions of GitHub projects from
  jsDelivr. The GitHub project of an image is the one its registry implies (ghcr.io, Crossplane
  packages) or the one its labels name (org.opencontainers.image.source). The release lines come
  from endoflife.date, whose products are found by the image, the project or the name. There is
  no list of known images: every image is looked up the same way. version-checker, when it runs
  in a cluster, checks every image there against its own registry.

  The name of an image only goes to its own registry, and to other services once it is known to
  be public: by its registry, which holds only public images (registry.k8s.io) or answers for it
  (Quay, Artifact Registry), or as an official image of Docker Hub on the list that jsDelivr reads
  once a day without naming an image. Docker Hub and GHCR cannot be asked from the browser whether
  an image is public, so the name of another Docker Hub image only goes to shields.io, and the
  project of a ghcr.io image to jsDelivr, when the settings allow names that may be private
  (possiblyPrivate); so do the projects of Upbound packages of other publishers than Upbound and
  the Crossplane community. Switching that setting off stops those requests that were not sent yet
  (possiblyPrivatePermit). The project an image's labels name is only asked about when the image
  is public. endoflife.date only gets the names of products on its own lists, and only when the
  settings show the end of life. Every other request of a lookup takes the permit of the newest
  versions or of the end of life as the lookup starts (imageVersionsPermit, endOfLifePermit), so
  switching one of them off also stops what its lookups have yet to ask. Answers are kept for a
  day, in localStorage where they are small.
*/
import { canonical, endOfLifeProduct, endOfLifeReleases } from './endOfLife';
import { githubProjectOfSource } from './imageSource';
import { ImageReference, imageTag, parseImageReference, registryPage } from './registry';
import { cached, clearCachedLookups } from './versionCache';
import { clearVersionCheckers } from './versionChecker';
import {
  endOfLifePermit,
  fetchBody,
  fetchJson,
  imageVersionsPermit,
  strings,
} from './versionRequests';
import { newestOfVersion, newestRelease, newestTag, parseVersion, releaseLineOf } from './versions';

// The parts of the lookups, which the views import from here
export { endOfLifeProduct, purlKey } from './endOfLife';
export type { EndOfLifeMatch } from './endOfLife';
export {
  imageVersionKey,
  parseVersionCheckerMetrics,
  versionCheckerResults,
} from './versionChecker';
export type { VersionCheckerResult } from './versionChecker';
export {
  endOfLifePermit,
  imageVersionsPermit,
  possiblyPrivatePermit,
  preferNewLookups,
  stopEndOfLifeLookups,
  stopImageVersionLookups,
  stopPossiblyPrivateLookups,
} from './versionRequests';

export interface VersionSource {
  name: string;
  url?: string;
}

export interface LatestVersion {
  latest: string;
  source: VersionSource;
}

/** A release line of a product at endoflife.date, such as MongoDB 8.0. */
export interface ReleaseLine {
  product: string;
  name: string;
  // the newest version of the line
  latest?: string;
  // whether the line reached its end of life, and the date it does or did
  eol: boolean;
  eolFrom?: string;
  url: string;
}

export interface PublicVersion {
  latest?: LatestVersion;
  line?: ReleaseLine;
}

/** Forgets the answers kept in memory; the tests start from nothing. */
export function clearVersionCache() {
  clearCachedLookups();
  clearVersionCheckers();
}

/** The active tags of a quay.io repository, the most recent first. */
function quayTags(repository: string, permit?: AbortSignal) {
  return cached<string[]>(`quay|${repository}`, async () => {
    const tags: string[] = [];
    // the newest versions are among the tags pushed last
    for (let page = 1; page <= 5; page++) {
      const body = await fetchJson(
        `https://quay.io/api/v1/repository/${repository}/tag/?onlyActiveTags=true&limit=100&page=${page}`,
        permit
      );
      if (!body) return page === 1 ? null : tags;
      tags.push(...strings((body.tags ?? []).map((tag: any) => tag?.name)));
      if (!body.has_additional) break;
    }
    return tags;
  });
}

/** The versions of a GitHub project, from the tags jsDelivr reads; GitHub's own API allows only
 * 60 requests an hour from an address. A project that may be private is asked with the permit
 * for such names, another one with the permit of the newest versions. */
function githubVersions(project: string, permit?: AbortSignal) {
  return cached<string[]>(`github|${project}`, async () => {
    const body = await fetchJson(`https://data.jsdelivr.com/v1/packages/gh/${project}`, permit);
    return body ? strings((body.versions ?? []).map((version: any) => version?.version)) : null;
  });
}

/**
 * The GitHub project an image is built from, as its registry implies it: ghcr.io images and the
 * packages of Crossplane's registries are named after their project.
 */
export function githubProject(reference: ImageReference): string | undefined {
  const { registry, repository } = reference;
  const [owner, name] = repository.split('/');
  if (registry === 'ghcr.io') return owner && name ? `${owner}/${name}` : undefined;
  if (registry === 'xpkg.upbound.io' || registry === 'xpkg.crossplane.io') {
    // Upbound publishes the providers of crossplane-contrib, one package per service
    const provider = repository.match(/^upbound\/provider-(?:family-)?(aws|azure|gcp)\b/);
    if (provider) return `crossplane-contrib/provider-upjet-${provider[1]}`;
    return owner && name ? `${owner}/${name}` : undefined;
  }
  return undefined;
}

// Registries that only hold public images, so that the project an image names may be asked about
const publicRegistries = [
  'registry.k8s.io',
  'public.ecr.aws',
  'mcr.microsoft.com',
  'docker.elastic.co',
  'xpkg.crossplane.io',
];

// The publishers of the Upbound marketplace whose packages are public: Upbound and the Crossplane
// community, whose names tell nothing about the cluster that runs them
const upboundPublishers = ['upbound/', 'crossplane-contrib/'];

/**
 * Whether an image is public by its name: it is in a registry that only holds public images, or
 * it is a package of a publisher of the Upbound marketplace whose packages are public; others may
 * have private repositories there.
 */
function isPublicByName({ registry, repository }: ImageReference) {
  return (
    publicRegistries.includes(registry) ||
    (registry === 'xpkg.upbound.io' &&
      upboundPublishers.some(publisher => repository.startsWith(publisher)))
  );
}

/**
 * The GitHub project the registry of an image implies, when its name may go to jsDelivr: the image
 * is public or the settings allow names that may be private (mayName). Whether a ghcr.io image is
 * public cannot be asked from the browser: ghcr.io does not allow other sites, GitHub's API for
 * packages needs a login, and a package can be private while the repository of its name is public.
 */
function impliedProject(reference: ImageReference, mayName: boolean) {
  return mayName ? githubProject(reference) : undefined;
}

/**
 * The names of Docker's official images: the library files that Docker builds them from, listed
 * by jsDelivr in one request a day, which names no image.
 */
function officialImageNames(permit?: AbortSignal) {
  return cached<string[]>(
    'official-names',
    async () => {
      const body = await fetchJson(
        'https://data.jsdelivr.com/v1/packages/gh/docker-library/official-images@master?structure=flat',
        permit
      );
      if (!body) return null;
      return strings((body.files ?? []).map((file: any) => file?.name)).flatMap(
        file => file.match(/^\/library\/([^/]+)$/)?.[1] ?? []
      );
    },
    { persist: true }
  );
}

/**
 * The tags of an official image of Docker Hub, from the library files that Docker builds them
 * from, read through jsDelivr: every tag that is maintained.
 */
function officialImageTags(name: string, permit?: AbortSignal) {
  return cached<string[]>(`official|${name}`, async () => {
    const text = await fetchBody(
      `https://cdn.jsdelivr.net/gh/docker-library/official-images@master/library/${name}`,
      'text',
      undefined,
      permit
    );
    if (typeof text !== 'string') return null;
    return text
      .split('\n')
      .flatMap(line => line.match(/^(?:Shared)?Tags:(.*)$/)?.[1].split(',') ?? [])
      .map(tag => tag.trim())
      .filter(Boolean);
  });
}

// what shields.io answers, with status 200, when it could not ask Docker Hub: "rate limited by
// upstream service" or "inaccessible", which say nothing about the image
const shieldsFailure = /rate limited|inaccessible/i;

/**
 * The newest version of an image of Docker Hub as shields.io, which makes the version badges of
 * projects, reads it. It sorts the most recent tags by their version and adds a v to the version.
 * When shields.io could not ask Docker Hub, the lookup fails, so that it is asked again after an
 * hour instead of being kept as the answer for a day.
 */
function dockerHubVersion(repository: string, permit: AbortSignal) {
  return cached<string>(`shields|${repository}`, async () => {
    const body = await fetchJson(
      `https://img.shields.io/docker/v/${repository}.json?sort=semver`,
      permit
    );
    const value = typeof body?.value === 'string' ? body.value : null;
    if (value && shieldsFailure.test(value)) throw new Error(`shields.io answered ${value}`);
    return value;
  });
}

/**
 * Whether the answer of shields.io shows that it knows the Docker Hub image, which it only can
 * when the image is public: a version, or "invalid response data", which it answers for some
 * public repositories. Its other messages, such as "repository or tag not found" or "no tags
 * found", show nothing about the image.
 */
export function shieldsKnowsImage(value: string | null | undefined): boolean {
  if (!value) return false;
  return /^v?\d/i.test(value.trim()) || /^invalid response data$/i.test(value.trim());
}

/** An image in Google's Artifact Registry. */
export interface ArtifactRegistryPackage {
  project: string;
  location: string;
  repository: string;
  package: string;
}

const gcrLocations: Record<string, string> = {
  '': 'us',
  'us.': 'us',
  'eu.': 'europe',
  'asia.': 'asia',
};

/**
 * Where an image of gcr.io, a *-docker.pkg.dev registry or registry.k8s.io is in Artifact
 * Registry, whose API, unlike the registries, allows other sites to read public repositories.
 */
export function artifactRegistryPackage(
  reference: ImageReference
): ArtifactRegistryPackage | undefined {
  const parts = reference.repository.split('/');
  const gcr = reference.registry.match(/^((?:us|eu|asia)\.)?gcr\.io$/);
  if (gcr) {
    // the project of a domain, such as google.com:cloudsdktool, is written google.com/cloudsdktool
    const domain = parts[0].includes('.') ? 1 : 0;
    const name = parts.slice(1 + domain).join('/');
    if (!name) return undefined;
    return {
      project: domain ? `${parts[0]}:${parts[1]}` : parts[0],
      location: gcrLocations[gcr[1] ?? ''],
      repository: reference.registry,
      package: name,
    };
  }
  const pkgDev = reference.registry.match(/^([a-z0-9-]+)-docker\.pkg\.dev$/);
  if (pkgDev && parts.length >= 3) {
    return {
      project: parts[0],
      location: pkgDev[1],
      repository: parts[1],
      package: parts.slice(2).join('/'),
    };
  }
  // registry.k8s.io sends clients to copies of this repository in many regions
  if (reference.registry === 'registry.k8s.io') {
    return {
      project: 'k8s-artifacts-prod',
      location: 'us-central1',
      repository: 'images',
      package: reference.repository,
    };
  }
  return undefined;
}

/**
 * Whether anyone may read a repository of Artifact Registry. Private repositories are asked
 * about once a day, rather than for each of their images.
 */
function isPublicRepository(url: string, permit?: AbortSignal) {
  return cached<boolean>(`ar-repository|${url}`, async () => !!(await fetchJson(url, permit)), {
    persist: true,
  });
}

/** The tags of an image of Artifact Registry, in the order of their names. */
function artifactRegistryTags(image: ArtifactRegistryPackage, permit?: AbortSignal) {
  const repositoryUrl = `https://artifactregistry.googleapis.com/v1/projects/${image.project}/locations/${image.location}/repositories/${image.repository}`;
  return cached<string[]>(`ar|${repositoryUrl}|${image.package}`, async () => {
    if (!(await isPublicRepository(repositoryUrl, permit))) return null;
    const tags: string[] = [];
    let pageToken = '';
    // versions come before names such as latest; images with many builds have thousands of tags
    for (let page = 1; page <= 5; page++) {
      const body = await fetchJson(
        `${repositoryUrl}/packages/${encodeURIComponent(image.package)}/tags?pageSize=1000${
          pageToken ? `&pageToken=${encodeURIComponent(pageToken)}` : ''
        }`,
        permit
      );
      if (!body) return page === 1 ? null : tags;
      for (const entry of body.tags ?? []) {
        const name = typeof entry?.name === 'string' ? entry.name.split('/tags/')[1] : undefined;
        if (name) tags.push(decodeURIComponent(name));
      }
      pageToken = typeof body.nextPageToken === 'string' ? body.nextPageToken : '';
      if (!pageToken) break;
    }
    return tags;
  });
}

/** The newest of the tags of a registry, or nothing when the registry no longer has the tag. */
function newestListedTag(tag: string, tags: string[] | null) {
  const newest = tags && newestTag(tag, tags);
  return newest && (newest !== tag || tags.includes(tag)) ? newest : undefined;
}

/**
 * The newest version from the registry of the image or the GitHub project it is built from: the
 * project its registry implies, or the one its labels name (sourceProject) when the image is
 * public, which its registry or shields.io knowing it shows. shields.io and the implied project
 * of an image not known to be public are only asked about when possiblyPrivate allows it; the
 * other requests take the permit of the newest versions.
 */
function registryOrProjectLatest(
  reference: ImageReference,
  tag: string,
  sourceProject: string | undefined,
  possiblyPrivate: AbortSignal | undefined,
  permit?: AbortSignal
) {
  return cached<LatestVersion>(
    `latest|${reference.registry}/${reference.repository}:${tag}|${sourceProject ?? ''}|${
      possiblyPrivate ? 'any' : 'public'
    }`,
    async () => {
      let isPublic = isPublicByName(reference);
      if (reference.registry === 'quay.io') {
        const tags = await quayTags(reference.repository, permit);
        isPublic = tags !== null;
        const newest = newestListedTag(tag, tags);
        if (newest) {
          return {
            latest: newest,
            source: { name: 'Quay', url: registryPage(`quay.io/${reference.repository}`)?.url },
          };
        }
      }
      const googleImage = artifactRegistryPackage(reference);
      if (googleImage) {
        // none for a private repository
        const tags = await artifactRegistryTags(googleImage, permit);
        isPublic = tags !== null;
        const newest = newestListedTag(tag, tags);
        if (newest) {
          return {
            latest: newest,
            source: {
              name: 'Artifact Registry',
              url: registryPage(`${reference.registry}/${reference.repository}`)?.url,
            },
          };
        }
      }
      const dockerHub = canonical(reference);
      const dockerHubPage = registryPage(`docker.io/${dockerHub.repository}`);
      const official =
        dockerHub.registry === 'docker.io' && dockerHub.repository.match(/^library\/([^/]+)$/);
      if (official) {
        // an image without a publisher may also be one built locally, so only the names of
        // Docker's official images are asked about
        const names = await officialImageNames(permit);
        const tags = names?.includes(official[1])
          ? await officialImageTags(official[1], permit)
          : null;
        // an image of that name with a tag that Docker does not build may be built locally too,
        // so only one of the official tags shows that the image, with its labels, is public
        isPublic = !!tags?.includes(tag);
        const newest = newestListedTag(tag, tags);
        if (newest)
          return { latest: newest, source: { name: 'Docker Hub', url: dockerHubPage?.url } };
      }
      let dockerHubNewest: string | undefined;
      // Docker Hub cannot be asked whether a repository is public, and shields.io learns the name
      if (dockerHub.registry === 'docker.io' && !official && possiblyPrivate) {
        const version = await dockerHubVersion(dockerHub.repository, possiblyPrivate);
        // shields.io only sees public repositories; it says so for others, and writes 2026.2.1
        // as v2026.2.1
        if (shieldsKnowsImage(version)) isPublic = true;
        dockerHubNewest =
          (version &&
            newestOfVersion(tag, /^v/i.test(tag) ? version : version.replace(/^v/, ''))) ||
          undefined;
      }
      // the releases of the project go before shields.io, which sorts the tags loosely
      const project =
        impliedProject(reference, isPublic || !!possiblyPrivate) ??
        (isPublic ? sourceProject : undefined);
      if (project) {
        // the project of an image not known to be public is only named with the permit for it
        const versions = await githubVersions(project, isPublic ? permit : possiblyPrivate);
        const newest = versions && newestRelease(tag, versions);
        if (newest) {
          return {
            latest: newest,
            source: { name: 'GitHub', url: `https://github.com/${project}/releases` },
          };
        }
      }
      if (dockerHubNewest) {
        return { latest: dockerHubNewest, source: { name: 'Docker Hub', url: dockerHubPage?.url } };
      }
      return null;
    },
    { persist: true }
  );
}

async function endOfLifeOf(
  reference: ImageReference,
  tag: string,
  project: string | undefined,
  permit: AbortSignal
): Promise<{ line?: ReleaseLine; newest?: LatestVersion }> {
  const match = await endOfLifeProduct(reference, project, permit);
  const releases = match ? await endOfLifeReleases(match.product, permit) : null;
  if (!match || !releases?.length) return {};
  const { product } = match;
  const url = `https://endoflife.date/${product}`;
  const line = releaseLineOf(tag, releases);
  // a product with the name of the image may be another one, unless the tag is one of its lines
  if (!line && match.byName) return {};
  const newest = newestRelease(
    tag,
    releases.map(release => release.latest ?? release.name)
  );
  return {
    line: line && {
      product,
      name: line.name,
      latest: line.latest,
      eol: line.isEol,
      eolFrom: line.eolFrom,
      url,
    },
    newest: newest ? { latest: newest, source: { name: 'endoflife.date', url } } : undefined,
  };
}

/**
 * The newest version of a public image and the release line of its tag. Images whose tag is not
 * a version, such as latest, are not looked up. Without the end of life, endoflife.date is not
 * asked, also not for the newest version. The lookup takes the permits of the newest versions and
 * of the end of life as it starts, so switching one of them off (changeImageVersionSetting) stops
 * the requests it has yet to make; what was stopped is not kept as an answer or a failure.
 */
export async function lookupImageVersion(
  image: string,
  options: {
    // false when version-checker already knows the newest version
    latest?: boolean;
    // false when the settings leave out the end of life, so that endoflife.date is not asked
    endOfLife?: boolean;
    // the source repository the labels of the image name (imageSourceLabel)
    source?: string;
    // the permit to send the names of images that may be private to shields.io and jsDelivr
    // (possiblyPrivatePermit), when the settings allow it
    possiblyPrivate?: AbortSignal;
  } = {}
): Promise<PublicVersion> {
  const reference = parseImageReference(image);
  const tag = imageTag(image);
  if (!reference || !tag || !parseVersion(tag)) return {};
  const sourceProject = githubProjectOfSource(options.source);
  // taken now, so that a setting that is switched off also stops the requests made later
  const versionsPermit = imageVersionsPermit();
  const endOfLifeDatesPermit = endOfLifePermit();
  // a service that fails leaves out what it would tell
  const noEndOfLife: { line?: ReleaseLine; newest?: LatestVersion } = {};
  const [latest, endOfLife] = await Promise.all([
    options.latest === false
      ? null
      : registryOrProjectLatest(
          reference,
          tag,
          sourceProject,
          options.possiblyPrivate,
          versionsPermit
        ).catch(() => null),
    options.endOfLife === false
      ? noEndOfLife
      : endOfLifeOf(
          reference,
          tag,
          githubProject(reference) ?? sourceProject,
          endOfLifeDatesPermit
        ).catch(() => noEndOfLife),
  ]);
  return { latest: latest ?? endOfLife.newest, line: endOfLife.line };
}
