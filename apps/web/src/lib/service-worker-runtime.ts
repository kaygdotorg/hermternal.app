import type { ServiceWorkerPolicy } from './service-worker-policy';

export interface ServiceWorkerCache {
  addAll(requests: readonly RequestInfo[]): Promise<void>;
  match(request: RequestInfo): Promise<Response | undefined>;
}

export interface ServiceWorkerCacheStorage {
  open(cacheName: string): Promise<ServiceWorkerCache>;
  keys(): Promise<string[]>;
  delete(cacheName: string): Promise<boolean>;
}

export interface ServiceWorkerFetchEvent {
  request: Request;
  respondWith(response: Promise<Response>): void;
}

export interface ServiceWorkerRuntimeOptions {
  cacheStorage: ServiceWorkerCacheStorage;
  fetcher: (request: RequestInfo) => Promise<Response>;
  origin: string;
}

/**
 * The runtime is dependency-injected so tests can exercise the actual install,
 * activate, and fetch decisions without a browser global or network. The
 * production worker passes CacheStorage and fetch unchanged.
 */
export function createServiceWorkerRuntime(
  policy: ServiceWorkerPolicy,
  options: ServiceWorkerRuntimeOptions
) {
  const { cacheStorage, fetcher, origin } = options;

  return {
    async install(): Promise<void> {
      const cache = await cacheStorage.open(policy.cacheName);
      const requests = policy.precachePaths.map(
        (path) => new Request(new URL(path, origin).toString())
      );
      await cache.addAll(requests);
    },

    async activate(): Promise<void> {
      const namesToDelete = policy.cacheNamesToDelete(await cacheStorage.keys());
      await Promise.all(namesToDelete.map((cacheName) => cacheStorage.delete(cacheName)));
    },

    handleFetch(event: ServiceWorkerFetchEvent): void {
      const cachePath = policy.cachePathForRequest(event.request, origin);
      if (!cachePath) {
        return;
      }

      const cacheRequest = new Request(new URL(cachePath, origin).toString());
      event.respondWith(
        (async () => {
          const cache = await cacheStorage.open(policy.cacheName);
          const cached = await cache.match(cacheRequest);
          return cached ?? fetcher(cacheRequest);
        })()
      );
    }
  };
}
