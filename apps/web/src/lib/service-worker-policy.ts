export const SERVICE_WORKER_CACHE_PREFIX = 'hermternal-prototype-assets-';

/**
 * W-01 supports the root document and the private deep-link grammar only.
 * Static hosting must rewrite these client routes to 200.html, but must never
 * rewrite reserved API, Hermes, auth, WebSocket, or PTY paths.
 */
export const NAVIGATION_ALLOWLIST = Object.freeze(['/', '/index.html']);
export const CLIENT_ROUTE_FALLBACK_PATH = '/200.html';
export const ROOT_DOCUMENT_PATH = '/index.html';

const ID_SEGMENT = '[A-Za-z0-9._~-]{16,}';
const CLIENT_ROUTE_PATTERN = new RegExp(
  `^/v1/c/${ID_SEGMENT}(?:/m/${ID_SEGMENT})?$`
);
const RESERVED_PATH_PREFIXES = Object.freeze([
  '/api',
  '/hermes',
  '/auth',
  '/ws',
  '/pty'
]);

export interface ServiceWorkerPolicyInput {
  version: string;
  build: readonly string[];
  files: readonly string[];
}

export interface ServiceWorkerPolicy {
  readonly cacheName: string;
  readonly precachePaths: readonly string[];
  isAllowedRequest(request: Pick<Request, 'method' | 'mode' | 'url'>, origin: string): boolean;
  cachePathForRequest(
    request: Pick<Request, 'method' | 'mode' | 'url'>,
    origin: string
  ): string | undefined;
  cacheNamesToDelete(cacheNames: readonly string[]): readonly string[];
}

function normalizePath(value: string): string | undefined {
  try {
    const url = new URL(value, 'https://hermternal.invalid');
    if (url.search || url.hash) {
      return undefined;
    }
    return url.pathname;
  } catch {
    return undefined;
  }
}

export function isReservedPath(pathname: string): boolean {
  return RESERVED_PATH_PREFIXES.some(
    (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`)
  );
}

export function isSupportedClientRoute(pathname: string): boolean {
  return CLIENT_ROUTE_PATTERN.test(pathname);
}

/**
 * Builds a closed policy from generated SvelteKit asset lists. Every service
 * worker read is mapped to one canonical document or an exact asset path.
 */
export function createServiceWorkerPolicy(input: ServiceWorkerPolicyInput): ServiceWorkerPolicy {
  if (!input.version) {
    throw new Error('A version is required for the service-worker cache name.');
  }

  const cacheName = `${SERVICE_WORKER_CACHE_PREFIX}${input.version}`;
  const staticAssetPaths = new Set(
    [
      ROOT_DOCUMENT_PATH,
      CLIENT_ROUTE_FALLBACK_PATH,
      ...input.build,
      ...input.files
    ]
      .map(normalizePath)
      .filter((path): path is string => Boolean(path))
  );
  const precachePaths = Object.freeze(
    [...new Set([...NAVIGATION_ALLOWLIST, ...staticAssetPaths])].sort()
  );

  function cachePathForRequest(
    request: Pick<Request, 'method' | 'mode' | 'url'>,
    origin: string
  ): string | undefined {
    if (request.method !== 'GET') {
      return undefined;
    }

    const requestUrl = new URL(request.url, origin);
    if (requestUrl.origin !== origin || requestUrl.search || requestUrl.hash) {
      return undefined;
    }

    const pathname = requestUrl.pathname;
    if (isReservedPath(pathname)) {
      return undefined;
    }

    if (request.mode === 'navigate') {
      if (NAVIGATION_ALLOWLIST.includes(pathname)) {
        return ROOT_DOCUMENT_PATH;
      }
      if (isSupportedClientRoute(pathname)) {
        return CLIENT_ROUTE_FALLBACK_PATH;
      }
      return undefined;
    }

    return staticAssetPaths.has(pathname) ? pathname : undefined;
  }

  return {
    cacheName,
    precachePaths,
    isAllowedRequest(request, origin) {
      return cachePathForRequest(request, origin) !== undefined;
    },
    cachePathForRequest,
    cacheNamesToDelete(cacheNames) {
      return cacheNames.filter(
        (name) => name.startsWith(SERVICE_WORKER_CACHE_PREFIX) && name !== cacheName
      );
    }
  };
}
