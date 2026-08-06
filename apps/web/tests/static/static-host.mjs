import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join, resolve } from 'node:path';
import { cwd } from 'node:process';

export const CLIENT_ROUTE_PATTERN = /^\/v1\/c\/[A-Za-z0-9._~-]{16,}(?:\/m\/[A-Za-z0-9._~-]{16,})?$/;
export const RESERVED_PATH_PREFIXES = Object.freeze(['/api', '/hermes', '/auth', '/ws', '/pty']);

const STATIC_FILE_PATHS = Object.freeze([
  '/manifest.webmanifest',
  '/icon.svg',
  '/service-worker.js'
]);

function hasInvalidRawTargetCharacter(value) {
  for (const character of value) {
    const code = character.codePointAt(0);
    if (code === undefined || code < 0x20 || (code >= 0x7f && code <= 0x9f) || code > 0x7e) {
      return true;
    }
  }
  return false;
}

/**
 * Inspect the HTTP origin-form target before any WHATWG URL parsing. The
 * production deployment must apply the same lexical boundary: decoding or
 * normalising first could turn a reserved traversal into a valid client route.
 */
export function parseRawRequestTarget(rawTarget) {
  if (
    typeof rawTarget !== 'string' ||
    rawTarget.length === 0 ||
    !rawTarget.startsWith('/') ||
    hasInvalidRawTargetCharacter(rawTarget)
  ) {
    return undefined;
  }

  const fragmentIndex = rawTarget.indexOf('#');
  if (fragmentIndex !== -1) {
    return undefined;
  }

  const queryIndex = rawTarget.indexOf('?');
  const pathname = queryIndex === -1 ? rawTarget : rawTarget.slice(0, queryIndex);
  if (
    pathname.length === 0 ||
    pathname.includes('%') ||
    pathname.includes('\\') ||
    pathname.includes('//') ||
    pathname.split('/').some((segment) => segment === '.' || segment === '..')
  ) {
    return undefined;
  }

  return Object.freeze({
    pathname,
    hasQuery: queryIndex !== -1
  });
}

export function isReservedPath(pathname) {
  return RESERVED_PATH_PREFIXES.some(
    (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`)
  );
}

function safeBuildPath(buildDirectory, pathname) {
  const relativePath = pathname.replace(/^\/+/, '');
  const candidate = resolve(buildDirectory, relativePath);
  return candidate === buildDirectory || candidate.startsWith(`${buildDirectory}/`)
    ? candidate
    : undefined;
}

/**
 * Resolve only the documented W-01 static routes. Root query parameters remain
 * available for synthetic scenario selection; canonical private client routes
 * and static assets are query/fragment-free and fail closed on any mutation.
 */
export function resolveStaticPath(rawTarget, buildDirectory = resolve(cwd(), 'build')) {
  const target = parseRawRequestTarget(rawTarget);
  if (!target || (target.hasQuery && target.pathname !== '/')) {
    return undefined;
  }

  const { pathname } = target;
  if (isReservedPath(pathname)) {
    return undefined;
  }
  if (CLIENT_ROUTE_PATTERN.test(pathname)) {
    return join(buildDirectory, '200.html');
  }
  if (pathname === '/') {
    return join(buildDirectory, 'index.html');
  }
  if (pathname === '/index.html' || pathname === '/200.html' || STATIC_FILE_PATHS.includes(pathname)) {
    return safeBuildPath(buildDirectory, pathname);
  }
  if (pathname.startsWith('/_app/')) {
    return safeBuildPath(buildDirectory, pathname);
  }
  return undefined;
}

function contentTypeFor(pathname) {
  if (pathname === '/' || CLIENT_ROUTE_PATTERN.test(pathname) || pathname.endsWith('.html')) {
    return 'text/html; charset=utf-8';
  }
  if (pathname.endsWith('.js')) return 'text/javascript; charset=utf-8';
  if (pathname.endsWith('.css')) return 'text/css; charset=utf-8';
  if (pathname.endsWith('.json') || pathname.endsWith('.webmanifest')) {
    return 'application/manifest+json; charset=utf-8';
  }
  if (pathname.endsWith('.svg')) return 'image/svg+xml';
  return 'application/octet-stream';
}

export function createStaticHost(buildDirectory = resolve(cwd(), 'build')) {
  return createServer(async (request, response) => {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      response.statusCode = 405;
      response.setHeader('allow', 'GET, HEAD');
      response.end('method not allowed');
      return;
    }

    const rawTarget = request.url ?? '';
    const parsedTarget = parseRawRequestTarget(rawTarget);
    const filePath = resolveStaticPath(rawTarget, buildDirectory);
    if (!filePath || !parsedTarget) {
      response.statusCode = 404;
      response.end('not found');
      return;
    }

    try {
      const body = await readFile(filePath);
      response.statusCode = 200;
      response.setHeader('content-type', contentTypeFor(parsedTarget.pathname));
      response.setHeader(
        'x-hermternal-static-source',
        CLIENT_ROUTE_PATTERN.test(parsedTarget.pathname)
          ? 'client-route'
          : parsedTarget.pathname === '/200.html'
            ? 'fallback-file'
            : parsedTarget.pathname === '/'
              ? 'root'
              : 'asset'
      );
      if (request.method === 'HEAD') {
        response.end();
      } else {
        response.end(body);
      }
    } catch (error) {
      response.statusCode = 500;
      response.end(String(error));
    }
  });
}

export async function startStaticHost({ buildDirectory = resolve(cwd(), 'build'), port = 4173 } = {}) {
  const server = createStaticHost(buildDirectory);
  await new Promise((resolveServer, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolveServer);
  });
  return server;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const portArgumentIndex = process.argv.indexOf('--port');
  const port = Number(
    portArgumentIndex === -1 ? process.env.PORT ?? 4173 : process.argv[portArgumentIndex + 1]
  );
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid static host port: ${port}`);
  }

  await startStaticHost({ port });
  console.log(`static evidence host listening on http://127.0.0.1:${port}`);
}
