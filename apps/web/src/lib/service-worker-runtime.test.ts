import { describe, expect, it, vi } from 'vitest';
import {
  CLIENT_ROUTE_FALLBACK_PATH,
  createServiceWorkerPolicy,
  SERVICE_WORKER_CACHE_PREFIX,
  SERVICE_WORKER_SCRIPT_PATH
} from './service-worker-policy';
import {
  createServiceWorkerRuntime,
  type ServiceWorkerCache,
  type ServiceWorkerCacheStorage,
  type ServiceWorkerFetchEvent
} from './service-worker-runtime';

const origin = 'https://prototype.test';

function request(pathname: string, mode: RequestMode = 'same-origin', method = 'GET'): Request {
  if (mode === 'navigate') {
    // Browsers create navigate-mode Requests internally; the standard
    // constructor rejects that mode, so tests use the equivalent shape.
    return { url: `${origin}${pathname}`, method, mode } as Request;
  }
  return new Request(`${origin}${pathname}`, { method, mode });
}

function rawRequest(
  rawTarget: string,
  mode: RequestMode = 'same-origin',
  method = 'GET'
): Request {
  const url = rawTarget.startsWith('http') ? rawTarget : `${origin}${rawTarget}`;
  return { url, method, mode } as Request;
}

class MemoryCache implements ServiceWorkerCache {
  readonly addedRequests: string[] = [];
  readonly matchedRequests: string[] = [];
  readonly responses = new Map<string, Response>();

  async addAll(requests: readonly RequestInfo[]): Promise<void> {
    for (const item of requests) {
      this.addedRequests.push(typeof item === 'string' ? item : item.url);
    }
  }

  async match(item: RequestInfo): Promise<Response | undefined> {
    const url = typeof item === 'string' ? item : item.url;
    this.matchedRequests.push(url);
    return this.responses.get(url);
  }
}

class MemoryCacheStorage implements ServiceWorkerCacheStorage {
  readonly caches = new Map<string, MemoryCache>();
  readonly deleted: string[] = [];
  readonly opened: string[] = [];
  names: string[] = [];

  async open(cacheName: string): Promise<MemoryCache> {
    this.opened.push(cacheName);
    const cache = this.caches.get(cacheName) ?? new MemoryCache();
    this.caches.set(cacheName, cache);
    return cache;
  }

  async keys(): Promise<string[]> {
    return this.names;
  }

  async delete(cacheName: string): Promise<boolean> {
    this.deleted.push(cacheName);
    return true;
  }
}

function fetchEvent(input: Request): ServiceWorkerFetchEvent & { response?: Promise<Response> } {
  return {
    request: input,
    respondWith(response) {
      this.response = response;
    }
  };
}

describe('service worker policy and runtime', () => {
  const policy = createServiceWorkerPolicy({
    version: 'test-v2',
    build: ['/_app/immutable/app.js'],
    files: ['/manifest.webmanifest', '/icon.svg']
  });

  it('pre-caches only the versioned document and generated asset allowlist', async () => {
    const storage = new MemoryCacheStorage();
    const runtime = createServiceWorkerRuntime(policy, {
      cacheStorage: storage,
      fetcher: vi.fn(),
      origin
    });

    await runtime.install();

    const cache = storage.caches.get(policy.cacheName);
    expect(policy.cacheName).toBe(`${SERVICE_WORKER_CACHE_PREFIX}test-v2`);
    expect(cache?.addedRequests).toEqual(
      expect.arrayContaining([
        `${origin}/`,
        `${origin}/index.html`,
        `${origin}/200.html`,
        `${origin}${SERVICE_WORKER_SCRIPT_PATH}`,
        `${origin}/_app/immutable/app.js`
      ])
    );
  });

  it('deletes only old caches owned by this application prefix', async () => {
    const storage = new MemoryCacheStorage();
    storage.names = [
      policy.cacheName,
      `${SERVICE_WORKER_CACHE_PREFIX}test-v1`,
      'other-app-cache-v1',
      'hermternal-user-cache-v1'
    ];
    const runtime = createServiceWorkerRuntime(policy, {
      cacheStorage: storage,
      fetcher: vi.fn(),
      origin
    });

    await runtime.activate();

    expect(storage.deleted).toEqual([`${SERVICE_WORKER_CACHE_PREFIX}test-v1`]);
    expect(storage.deleted).not.toContain('other-app-cache-v1');
    expect(storage.deleted).not.toContain('hermternal-user-cache-v1');
  });

  it('does not read or intercept reserved, unknown, cross-origin, or non-GET requests', async () => {
    const storage = new MemoryCacheStorage();
    const fetcher = vi.fn(async () => new Response('unexpected'));
    const runtime = createServiceWorkerRuntime(policy, {
      cacheStorage: storage,
      fetcher,
      origin
    });
    const blockedPaths = [
      '/api/secret',
      '/hermes/status',
      '/auth/callback',
      '/ws/socket',
      '/pty/session',
      '/api/pty',
      '/unknown-route'
    ];

    for (const pathname of blockedPaths) {
      const event = fetchEvent(request(pathname, 'navigate'));
      runtime.handleFetch(event);
      expect(event.response).toBeUndefined();
    }

    const crossOrigin = fetchEvent(
      new Request('https://other.test/_app/immutable/app.js', { mode: 'cors' })
    );
    runtime.handleFetch(crossOrigin);
    expect(crossOrigin.response).toBeUndefined();

    const post = fetchEvent(request('/manifest.webmanifest', 'same-origin', 'POST'));
    runtime.handleFetch(post);
    expect(post.response).toBeUndefined();

    await Promise.resolve();
    expect(storage.opened).toEqual([]);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('rejects raw route mutations before cache policy normalization', () => {
    const storage = new MemoryCacheStorage();
    const runtime = createServiceWorkerRuntime(policy, {
      cacheStorage: storage,
      fetcher: vi.fn(async () => new Response('unexpected')),
      origin
    });
    const reservedPrefixes = ['/api', '/hermes', '/auth', '/ws', '/pty'];
    const rawTargets = [
      ...reservedPrefixes.flatMap((prefix) => [
        `${prefix}/../v1/c/abcdefghijklmnop`,
        `${prefix}/%2e%2e/v1/c/abcdefghijklmnop`,
        `${prefix}\\..\\v1/c/abcdefghijklmnop`,
        `${prefix}//../v1/c/abcdefghijklmnop`,
        `${prefix}/%2fv1/c/abcdefghijklmnop`,
        `${prefix}/%5cv1/c/abcdefghijklmnop`
      ]),
      '/apiary/v1/c/abcdefghijklmnop',
      '//evil.example/v1/c/abcdefghijklmnop',
      '/v1/c/abcdefghijklmnop?token=synthetic',
      '/v1/c/abcdefghijklmnop#fragment',
      `${SERVICE_WORKER_SCRIPT_PATH}?cache=synthetic`
    ];

    for (const rawTarget of rawTargets) {
      const event = fetchEvent(rawRequest(rawTarget, 'navigate'));
      runtime.handleFetch(event);
      expect(event.response).toBeUndefined();
    }
    expect(storage.opened).toEqual([]);
  });

  it('maps only supported deep links to the cached 200.html shell', async () => {
    const storage = new MemoryCacheStorage();
    const cache = await storage.open(policy.cacheName);
    cache.responses.set(`${origin}${CLIENT_ROUTE_FALLBACK_PATH}`, new Response('shell'));
    const fetcher = vi.fn(async () => new Response('network shell'));
    const runtime = createServiceWorkerRuntime(policy, {
      cacheStorage: storage,
      fetcher,
      origin
    });
    const event = fetchEvent(request('/v1/c/abcdefghijklmnop', 'navigate'));

    runtime.handleFetch(event);
    const response = await event.response;

    expect(await response?.text()).toBe('shell');
    expect(cache.matchedRequests).toEqual([`${origin}${CLIENT_ROUTE_FALLBACK_PATH}`]);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('does not use a foreign same-origin cache for an allowlisted request', async () => {
    const storage = new MemoryCacheStorage();
    const foreign = await storage.open('other-app-cache-v1');
    foreign.responses.set(`${origin}/manifest.webmanifest`, new Response('foreign'));
    const runtime = createServiceWorkerRuntime(policy, {
      cacheStorage: storage,
      fetcher: vi.fn(async () => new Response('owned network')),
      origin
    });
    const event = fetchEvent(request('/manifest.webmanifest'));

    runtime.handleFetch(event);
    const response = await event.response;

    expect(await response?.text()).toBe('owned network');
    expect(foreign.matchedRequests).toEqual([]);
    expect(storage.opened).toContain(policy.cacheName);
  });
});
