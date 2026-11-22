// The products and release lines of endoflife.date, which only gets the names of products on its
// own lists, and is only asked with the permit of the end of life while that holds
// (endOfLifePermit).
import { ImageReference } from './registry';
import { cached } from './versionCache';
import { fetchJson, strings } from './versionRequests';

export interface Release {
  name: string;
  latest?: string;
  isEol: boolean;
  eolFrom?: string;
}

export function endOfLifeReleases(product: string, permit?: AbortSignal) {
  return cached<Release[]>(
    `eol|${product}`,
    async () => {
      const body = await fetchJson(
        `https://endoflife.date/api/v1/products/${encodeURIComponent(product)}/`,
        permit
      );
      if (!body) return null;
      return (body.result?.releases ?? [])
        .filter((release: any) => typeof release?.name === 'string')
        .map((release: any) => ({
          name: release.name,
          latest: typeof release.latest?.name === 'string' ? release.latest.name : undefined,
          isEol: release.isEol === true,
          eolFrom: typeof release.eolFrom === 'string' ? release.eolFrom : undefined,
        }));
    },
    { persist: true }
  );
}

const dockerHubHosts = [
  'docker.io',
  'index.docker.io',
  'registry-1.docker.io',
  'registry.hub.docker.com',
];

/**
 * The key of a package URL that names an image or a GitHub project, as endoflife.date lists them:
 * registry|path for an image, with * for a pkg:docker URL that names no registry, such as
 * *|library/redis for pkg:docker/library/redis and quay.io|argoproj/argocd for
 * pkg:oci/argocd?repository_url=quay.io/argoproj, and github|owner/name for pkg:github/owner/name.
 */
export function purlKey(purl: string): string | undefined {
  const docker = purl.match(/^pkg:docker\/([^@?#]+)(?:@[^?#]*)?(?:\?([^#]*))?/);
  if (docker) {
    let path = decodeURIComponent(docker[1]).toLowerCase();
    if (!path.includes('/')) path = `library/${path}`;
    const registry = new URLSearchParams(docker[2] ?? '').get('repository_url')?.toLowerCase();
    const host = registry && (dockerHubHosts.includes(registry) ? 'docker.io' : registry);
    return `${host || '*'}|${path}`;
  }
  const oci = purl.match(/^pkg:oci\/([^@?#/]+)(?:@[^?#]*)?\?([^#]*)/);
  if (oci) {
    const url = new URLSearchParams(oci[2]).get('repository_url')?.toLowerCase();
    const [host, ...path] = url?.replace(/^https?:\/\//, '').split('/') ?? [];
    if (!host) return undefined;
    const registry = dockerHubHosts.includes(host) ? 'docker.io' : host;
    return `${registry}|${[...path, decodeURIComponent(oci[1]).toLowerCase()].join('/')}`;
  }
  const github = purl.match(/^pkg:github\/([^/@?#]+)\/([^/@?#]+)/);
  return github ? `github|${github[1]}/${github[2]}`.toLowerCase() : undefined;
}

/** The products of endoflife.date by the package URLs of their images and projects. */
function endOfLifeIdentifiers(permit?: AbortSignal) {
  return cached<Record<string, string>>(
    'eol-identifiers',
    async () => {
      const body = await fetchJson('https://endoflife.date/api/v1/identifiers/purl/', permit);
      if (!body) return null;
      const products: Record<string, string> = {};
      for (const entry of body.result ?? []) {
        const key = typeof entry?.identifier === 'string' && purlKey(entry.identifier);
        if (key && typeof entry.product?.name === 'string') products[key] = entry.product.name;
      }
      return products;
    },
    { persist: true }
  );
}

/** The products of endoflife.date by their names and aliases, in lower case. */
function endOfLifeNames(permit?: AbortSignal) {
  return cached<Record<string, string>>(
    'eol-names',
    async () => {
      const body = await fetchJson('https://endoflife.date/api/v1/products/', permit);
      if (!body) return null;
      const products: Record<string, string> = {};
      const list: any[] = (body.result ?? []).filter((p: any) => typeof p?.name === 'string');
      // a name of a product goes before the same alias of another one
      for (const product of list) products[product.name.toLowerCase()] = product.name;
      for (const product of list) {
        for (const alias of strings(product.aliases ?? [])) {
          products[alias.toLowerCase()] ??= product.name;
        }
      }
      return products;
    },
    { persist: true }
  );
}

// Amazon's public gallery mirrors the official images of Docker Hub
export function canonical(reference: ImageReference): ImageReference {
  const mirrored = reference.repository.match(/^docker\/(library\/[^/]+)$/);
  return reference.registry === 'public.ecr.aws' && mirrored
    ? { registry: 'docker.io', repository: mirrored[1] }
    : reference;
}

/** A product of endoflife.date, and whether it was found by name only. */
export interface EndOfLifeMatch {
  product: string;
  byName: boolean;
}

/**
 * The endoflife.date product of an image: the product that lists the image or the GitHub project
 * it is built from, or else the product with the name of the image (tool for tool3), of its
 * project, or of the start of its name when its publisher carries that name too (tracer for
 * tracerproject/tracer-collector). A product found by name only counts when the tag of the image
 * is one of its versions. With a permit, its lists are only asked for while the permit holds.
 */
export async function endOfLifeProduct(
  reference: ImageReference,
  project?: string,
  permit?: AbortSignal
): Promise<EndOfLifeMatch | undefined> {
  const { registry, repository } = canonical(reference);
  const path = repository.toLowerCase();
  const identifiers = await endOfLifeIdentifiers(permit);
  const identified =
    identifiers?.[`${registry}|${path}`] ??
    identifiers?.[`*|${path}`] ??
    (project ? identifiers?.[`github|${project.toLowerCase()}`] : undefined);
  if (identified) return { product: identified, byName: false };

  const names = await endOfLifeNames(permit);
  if (!names) return undefined;
  const segments = path.split('/');
  const name = segments[segments.length - 1];
  const publisher = segments.length > 1 ? segments[segments.length - 2] : '';
  const candidates = [name, name.replace(/\d+$/, ''), project?.split('/')[1]?.toLowerCase()];
  const named = candidates.find(candidate => candidate && names[candidate]);
  if (named) return { product: names[named], byName: true };
  const start = name.split('-')[0];
  if (start !== name && names[start] && publisher.includes(start)) {
    return { product: names[start], byName: true };
  }
  return undefined;
}
