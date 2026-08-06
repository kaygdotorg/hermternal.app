import { createServer, request as createRequest } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { cwd } from 'node:process';
import { parseRawRequestTarget } from '../../src/lib/static-route-grammar.mjs';
import { resolveStaticPath } from '../static/static-host.mjs';

const PROXY_PREFIXES = Object.freeze(['/api/', '/auth/']);
const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade'
]);

function isProxyTarget(pathname) {
  return PROXY_PREFIXES.some((prefix) => pathname.startsWith(prefix));
}

function contentTypeFor(pathname) {
  if (pathname === '/' || pathname.endsWith('.html')) return 'text/html; charset=utf-8';
  if (pathname.endsWith('.js')) return 'text/javascript; charset=utf-8';
  if (pathname.endsWith('.css')) return 'text/css; charset=utf-8';
  if (pathname.endsWith('.json') || pathname.endsWith('.webmanifest')) {
    return 'application/manifest+json; charset=utf-8';
  }
  if (pathname.endsWith('.svg')) return 'image/svg+xml';
  return 'application/octet-stream';
}

function proxyHeaders(headers, target) {
  const forwarded = {};
  for (const [name, value] of Object.entries(headers)) {
    if (!HOP_BY_HOP_HEADERS.has(name.toLowerCase()) && value !== undefined) forwarded[name] = value;
  }
  forwarded.host = target.host;
  return forwarded;
}

function copyResponseHeaders(source, destination) {
  for (const [name, value] of Object.entries(source)) {
    if (!HOP_BY_HOP_HEADERS.has(name.toLowerCase()) && value !== undefined) {
      destination.setHeader(name, value);
    }
  }
}

function proxyHttp(request, response, target) {
  const upstream = createRequest(
    {
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port,
      method: request.method,
      path: request.url,
      headers: proxyHeaders(request.headers, target)
    },
    (upstreamResponse) => {
      response.statusCode = upstreamResponse.statusCode ?? 502;
      if (upstreamResponse.statusMessage) response.statusMessage = upstreamResponse.statusMessage;
      copyResponseHeaders(upstreamResponse.headers, response);
      upstreamResponse.pipe(response);
    }
  );

  upstream.setTimeout(30_000, () => upstream.destroy(new Error('upstream timeout')));
  upstream.on('error', () => {
    if (response.headersSent) {
      response.destroy();
      return;
    }
    response.statusCode = 502;
    response.setHeader('content-type', 'text/plain; charset=utf-8');
    response.end('upstream unavailable');
  });
  request.pipe(upstream);
}

function proxyUpgrade(request, socket, head, target) {
  const parsed = parseRawRequestTarget(request.url ?? '');
  if (!parsed || parsed.pathname !== '/api/ws') {
    socket.end('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
    return;
  }

  const upstream = createRequest({
    protocol: target.protocol,
    hostname: target.hostname,
    port: target.port,
    method: 'GET',
    path: request.url,
    headers: {
      ...proxyHeaders(request.headers, target),
      connection: 'Upgrade',
      upgrade: 'websocket'
    }
  });

  upstream.setTimeout(30_000, () => upstream.destroy(new Error('upstream timeout')));
  upstream.on('upgrade', (upstreamResponse, upstreamSocket, upstreamHead) => {
    const statusCode = upstreamResponse.statusCode ?? 101;
    const statusMessage = upstreamResponse.statusMessage ?? 'Switching Protocols';
    const rawHeaders = [];
    for (let index = 0; index < upstreamResponse.rawHeaders.length; index += 2) {
      const name = upstreamResponse.rawHeaders[index];
      const value = upstreamResponse.rawHeaders[index + 1];
      if (name && value && !HOP_BY_HOP_HEADERS.has(name.toLowerCase())) {
        rawHeaders.push(`${name}: ${value}`);
      }
    }
    rawHeaders.push('Connection: Upgrade', 'Upgrade: websocket');
    socket.write(`HTTP/1.1 ${statusCode} ${statusMessage}\r\n${rawHeaders.join('\r\n')}\r\n\r\n`);
    if (head.length > 0) upstreamSocket.write(head);
    if (upstreamHead.length > 0) socket.write(upstreamHead);
    upstreamSocket.pipe(socket);
    socket.pipe(upstreamSocket);
  });
  upstream.on('response', (upstreamResponse) => {
    socket.end(
      `HTTP/1.1 ${upstreamResponse.statusCode ?? 502} ${upstreamResponse.statusMessage ?? 'Upgrade Failed'}\r\nConnection: close\r\n\r\n`
    );
    upstreamResponse.resume();
  });
  upstream.on('error', () => {
    socket.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n');
  });
  upstream.end();
}

export function createLiveHost({
  buildDirectory = resolve(cwd(), 'build'),
  target = new URL(process.env.HERMES_LIVE_TARGET ?? 'http://127.0.0.1:19131')
} = {}) {
  if (target.protocol !== 'http:') throw new Error('The disposable Hermes target must use local HTTP.');

  const server = createServer(async (request, response) => {
    const rawTarget = request.url ?? '';
    const parsed = parseRawRequestTarget(rawTarget);
    if (!parsed) {
      response.statusCode = 400;
      response.end('bad request');
      return;
    }
    if (isProxyTarget(parsed.pathname)) {
      proxyHttp(request, response, target);
      return;
    }
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      response.statusCode = 405;
      response.setHeader('allow', 'GET, HEAD');
      response.end('method not allowed');
      return;
    }

    const filePath = resolveStaticPath(rawTarget, buildDirectory);
    if (!filePath) {
      response.statusCode = 404;
      response.end('not found');
      return;
    }
    try {
      const fileInfo = await stat(filePath);
      if (!fileInfo.isFile()) throw new Error('not a file');
      const body = await readFile(filePath);
      response.statusCode = 200;
      response.setHeader('content-type', contentTypeFor(parsed.pathname));
      if (request.method === 'HEAD') response.end();
      else response.end(body);
    } catch {
      response.statusCode = 404;
      response.end('not found');
    }
  });
  server.on('upgrade', (request, socket, head) => proxyUpgrade(request, socket, head, target));
  return server;
}

export async function startLiveHost({ port = 4187, ...options } = {}) {
  const server = createLiveHost(options);
  await new Promise((resolveServer, reject) => {
    server.once('error', reject);
    server.listen({ port, host: '127.0.0.1' }, () => resolveServer(undefined));
  });
  return server;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const portArgumentIndex = process.argv.indexOf('--port');
  const port = Number(
    portArgumentIndex === -1 ? process.env.PORT ?? 4187 : process.argv[portArgumentIndex + 1]
  );
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid live host port: ${port}`);
  }
  await startLiveHost({ port });
  console.log(`live proof host listening on http://127.0.0.1:${port}`);
}
