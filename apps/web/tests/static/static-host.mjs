import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join, resolve } from 'node:path';
import { cwd } from 'node:process';
import {
  CLIENT_ROUTE_PATTERN,
  isReservedPath,
  isSupportedClientRoute,
  parseRawRequestTarget,
  RESERVED_PATH_PREFIXES,
  SERVICE_WORKER_SCRIPT_PATH
} from '../../src/lib/static-route-grammar.mjs';

export { CLIENT_ROUTE_PATTERN, parseRawRequestTarget, RESERVED_PATH_PREFIXES };

const STATIC_FILE_PATHS = Object.freeze([
  '/manifest.webmanifest',
  '/icon.svg',
  SERVICE_WORKER_SCRIPT_PATH
]);
// The W-06 browser proof is a non-product evidence route. It must serve its
// generated route document instead of the product's client-route fallback so
// Playwright executes the transport bundle in the browser realm.
const W06_BROWSER_PROOF_PATH = '/__w06/transport';

/**
 * @param {string} buildDirectory
 * @param {string} pathname
 * @returns {string | undefined}
 */
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
/**
 * @param {string} rawTarget
 * @param {string} [buildDirectory]
 * @returns {string | undefined}
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
  if (pathname === W06_BROWSER_PROOF_PATH) {
    return safeBuildPath(buildDirectory, `${W06_BROWSER_PROOF_PATH}/index.html`);
  }
  if (isSupportedClientRoute(pathname)) {
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

/** @param {string} pathname @returns {string} */
function contentTypeFor(pathname) {
  if (
    pathname === '/' ||
    pathname === W06_BROWSER_PROOF_PATH ||
    isSupportedClientRoute(pathname) ||
    pathname.endsWith('.html')
  ) {
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

/**
 * @param {string} [buildDirectory]
 * @returns {import('node:http').Server}
 */
export function createStaticHost(buildDirectory = resolve(cwd(), 'build')) {
  const server = createServer(async (request, response) => {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      response.statusCode = 405;
      response.setHeader('allow', 'GET, HEAD');
      response.setHeader('content-type', 'text/plain; charset=utf-8');
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
      const fileInfo = await stat(filePath);
      if (!fileInfo.isFile()) {
        response.statusCode = 404;
        response.end('not found');
        return;
      }

      const body = await readFile(filePath);
      response.statusCode = 200;
      response.setHeader('content-type', contentTypeFor(parsedTarget.pathname));
      response.setHeader(
        'x-hermternal-static-source',
        isSupportedClientRoute(parsedTarget.pathname)
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
    } catch {
      // Missing or non-regular files are indistinguishable from unknown paths;
      // never expose filesystem errors or absolute build paths to the client.
      response.statusCode = 404;
      response.end('not found');
    }
  });

  server.on('connect', (_request, socket) => {
    socket.end(
      'HTTP/1.1 405 Method Not Allowed\r\n' +
        'Allow: GET, HEAD\r\n' +
        'Content-Type: text/plain; charset=utf-8\r\n' +
        'Content-Length: 18\r\n' +
        'Connection: close\r\n' +
        '\r\n' +
        'method not allowed'
    );
  });

  return server;
}

/**
 * @param {{buildDirectory?: string, port?: number}} [options]
 * @returns {Promise<import('node:http').Server>}
 */
export async function startStaticHost({ buildDirectory = resolve(cwd(), 'build'), port = 4173 } = {}) {
  const server = createStaticHost(buildDirectory);
  await new Promise((resolveServer, reject) => {
    server.once('error', reject);
    server.listen({ port, host: '127.0.0.1' }, () => resolveServer(undefined));
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
