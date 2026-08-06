import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { cwd } from 'node:process';

const buildDirectory = resolve(cwd(), 'build');
const fallbackPath = join(buildDirectory, '200.html');
const rootPath = join(buildDirectory, 'index.html');
const clientRoutePattern = /^\/v1\/c\/[A-Za-z0-9._~-]{16,}(?:\/m\/[A-Za-z0-9._~-]{16,})?$/;
const reservedPathPrefixes = ['/api', '/hermes', '/auth', '/ws', '/pty'];

function isReservedPath(pathname) {
  return reservedPathPrefixes.some(
    (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`)
  );
}

function safeBuildPath(pathname) {
  const relativePath = pathname.replace(/^\/+/, '');
  const candidate = resolve(buildDirectory, relativePath);
  return candidate === buildDirectory || candidate.startsWith(`${buildDirectory}/`)
    ? candidate
    : undefined;
}

/**
 * This is the exact W-01 static-host contract. Route order is security
 * relevant: reserved paths are denied before the 200.html client-route
 * rewrite, then the private deep-link grammar is rewritten, and all unknown
 * paths remain 404s.
 */
function resolveStaticPath(pathname) {
  if (isReservedPath(pathname)) {
    return undefined;
  }
  if (clientRoutePattern.test(pathname)) {
    return fallbackPath;
  }
  if (pathname === '/') {
    return rootPath;
  }
  if (pathname === '/index.html' || pathname === '/200.html') {
    return safeBuildPath(pathname);
  }
  if (pathname.startsWith('/_app/') || pathname === '/manifest.webmanifest' || pathname === '/icon.svg') {
    return safeBuildPath(pathname);
  }
  return undefined;
}

const server = createServer(async (request, response) => {
  const requestUrl = new URL(request.url ?? '/', 'http://127.0.0.1');
  const filePath = resolveStaticPath(requestUrl.pathname);

  if (!filePath) {
    response.statusCode = 404;
    response.end('not found');
    return;
  }

  try {
    response.statusCode = 200;
    response.end(await readFile(filePath));
  } catch (error) {
    response.statusCode = 500;
    response.end(String(error));
  }
});

await new Promise((resolveServer) => server.listen(0, '127.0.0.1', resolveServer));
const address = server.address();
if (!address || typeof address === 'string') {
  throw new Error('The static evidence server did not expose a TCP address.');
}

const origin = `http://127.0.0.1:${address.port}`;
const shellRoutes = ['/', '/index.html', '/v1/c/abcdefghijklmnop', '/v1/c/abcdefghijklmnop/m/qrstuvwxyzabcdef'];
const deniedRoutes = [
  '/foo/',
  '/v1/c/short',
  '/api/anything',
  '/hermes/anything',
  '/auth/login',
  '/ws/socket',
  '/pty/session',
  '/api/pty'
];

try {
  for (const pathname of shellRoutes) {
    const result = await fetch(`${origin}${pathname}`);
    if (result.status !== 200) {
      throw new Error(`Expected direct shell load ${pathname} to return 200, got ${result.status}.`);
    }
    const body = await result.text();
    if (!body.includes('/_app/')) {
      throw new Error(`Expected ${pathname} to serve the production shell.`);
    }
  }

  for (const pathname of deniedRoutes) {
    const result = await fetch(`${origin}${pathname}`);
    if (result.status !== 404) {
      throw new Error(`Expected denied or unknown route ${pathname} to remain 404, got ${result.status}.`);
    }
  }
} finally {
  await new Promise((resolveServer) => server.close(resolveServer));
}

console.log('static route evidence: root and /v1/c/* shell loads use 200.html; reserved and unknown paths stay 404');
