/// <reference lib="webworker" />

import { build, files, version } from '$service-worker';

const cacheName = `hermternal-prototype-${version}`;
const precache = [...build, ...files];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(cacheName).then((cache) => cache.addAll(precache)));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((key) => key !== cacheName).map((key) => caches.delete(key))))
  );
});

self.addEventListener('fetch', (event) => {
  const requestUrl = new URL(event.request.url);

  // Only same-origin GETs belong to the static asset cache. The mock boundary
  // never reaches this handler, so this cannot become a hidden API proxy.
  if (requestUrl.origin !== self.location.origin || event.request.method !== 'GET') {
    return;
  }

  event.respondWith(
    caches.match(event.request).then((cached) => cached ?? fetch(event.request))
  );
});
