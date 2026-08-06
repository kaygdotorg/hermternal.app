import {
  isReservedPath,
  isSupportedClientRoute,
  parseSameOriginRequestTarget
} from './static-route-grammar.mjs';

export {
  CLIENT_ROUTE_FALLBACK_PATH,
  CLIENT_ROUTE_PATTERN,
  isReservedPath,
  isSupportedClientRoute,
  NAVIGATION_ALLOWLIST,
  RESERVED_PATH_PREFIXES,
  ROOT_DOCUMENT_PATH,
  SERVICE_WORKER_SCRIPT_PATH
} from './static-route-grammar.mjs';

import {
  CLIENT_ROUTE_FALLBACK_PATH,
  NAVIGATION_ALLOWLIST,
  ROOT_DOCUMENT_PATH,
  SERVICE_WORKER_SCRIPT_PATH
} from './static-route-grammar.mjs';

export const SERVICE_WORKER_CACHE_PREFIX = 'hermternal-prototype-assets-';

/**
 * W-01 supports the root document and the private deep-link grammar only.
 * Static hosting must rewrite these client routes to 200.html, but must never
 * rewrite reserved API, Hermes, auth, WebSocket, or PTY paths.
 */

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
      SERVICE_WORKER_SCRIPT_PATH,
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

    const rawTarget = parseSameOriginRequestTarget(request.url, origin);
    if (!rawTarget || rawTarget.hasQuery) {
      return undefined;
    }

    const requestUrl = new URL(request.url, origin);
    if (
      requestUrl.origin !== origin ||
      requestUrl.search ||
      requestUrl.hash ||
      requestUrl.pathname !== rawTarget.pathname
    ) {
      return undefined;
    }

    const pathname = rawTarget.pathname;
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
