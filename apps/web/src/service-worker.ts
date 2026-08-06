/// <reference lib="webworker" />

import { build, files, version } from '$service-worker';
import { createServiceWorkerPolicy } from '$lib/service-worker-policy';
import { createServiceWorkerRuntime } from '$lib/service-worker-runtime';

const policy = createServiceWorkerPolicy({ version, build, files });
const runtime = createServiceWorkerRuntime(policy, {
  cacheStorage: caches,
  fetcher: (request) => fetch(request),
  origin: self.location.origin
});

self.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      await runtime.install();
      // Production startup owns registration; skip waiting so a newly built
      // worker can become active without making the static shell wait.
      await self.skipWaiting();
    })()
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      await runtime.activate();
      // Claim only after the owned cache is ready so offline control cannot
      // expose a partially installed shell to an existing client.
      await self.clients.claim();
    })()
  );
});

self.addEventListener('fetch', (event) => {
  // The runtime returns without respondWith for every non-allowlisted request.
  // That preserves browser handling for APIs, auth, WebSockets, PTY, and any
  // unknown same-origin path instead of turning this worker into a proxy.
  runtime.handleFetch(event);
});
