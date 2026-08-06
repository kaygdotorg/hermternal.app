import { request as httpRequest } from 'node:http';
import { connect as netConnect } from 'node:net';
import { startStaticHost, RESERVED_PATH_PREFIXES } from './static-host.mjs';

function rawHttpRequest(port, rawTarget, method = 'GET') {
  return new Promise((resolve, reject) => {
    const request = httpRequest(
      {
        host: '127.0.0.1',
        port,
        method,
        path: rawTarget,
        headers: { connection: 'close' }
      },
      (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => {
          resolve({
            status: response.statusCode ?? 0,
            headers: response.headers,
            body: Buffer.concat(chunks).toString('utf8')
          });
        });
      }
    );
    request.once('error', reject);
    request.end();
  });
}

function rawConnectRequest(port, rawTarget) {
  return new Promise((resolve, reject) => {
    const socket = netConnect({ host: '127.0.0.1', port });
    const chunks = [];
    socket.once('error', reject);
    socket.once('connect', () => {
      socket.end(
        `CONNECT ${rawTarget} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`
      );
    });
    socket.on('data', (chunk) => chunks.push(chunk));
    socket.once('end', () => {
      const rawResponse = Buffer.concat(chunks).toString('utf8');
      const [headerBlock, body = ''] = rawResponse.split('\r\n\r\n');
      const headerLines = headerBlock.split('\r\n');
      const status = Number(headerLines[0]?.split(' ')[1] ?? 0);
      const headers = Object.fromEntries(
        headerLines.slice(1).map((line) => {
          const separator = line.indexOf(':');
          return [line.slice(0, separator).toLowerCase(), line.slice(separator + 1).trim()];
        })
      );
      resolve({ status, headers, body });
    });
  });
}

const server = await startStaticHost({ port: 0 });
const address = server.address();
if (!address || typeof address === 'string') {
  throw new Error('The static evidence server did not expose a TCP address.');
}

const shellRoutes = [
  '/',
  '/?scenario=success',
  '/index.html',
  '/200.html',
  '/v1/c/abcdefghijklmnop',
  '/v1/c/abcdefghijklmnop/m/qrstuvwxyzabcdef'
];
const workerRoute = '/service-worker.js';
const canonicalMutationRoutes = [
  '/v1/c/abcdefghijklmnop?token=synthetic',
  '/v1/c/abcdefghijklmnop#fragment',
  '/v1/c/abcdefghijklmnop/',
  '/200.html?token=synthetic',
  '/service-worker.js?cache=synthetic'
];
const lexicalMutationRoutes = RESERVED_PATH_PREFIXES.flatMap((prefix) => [
  `${prefix}/../v1/c/abcdefghijklmnop`,
  `${prefix}/%2e%2e/v1/c/abcdefghijklmnop`,
  `${prefix}\\..\\v1/c/abcdefghijklmnop`,
  `${prefix}//../v1/c/abcdefghijklmnop`,
  `${prefix}/%2fv1/c/abcdefghijklmnop`,
  `${prefix}/%5cv1/c/abcdefghijklmnop`
]);
const reservedPrefixLookalikes = [
  '/apiary/v1/c/abcdefghijklmnop',
  '/hermesian/v1/c/abcdefghijklmnop',
  '/authentic/v1/c/abcdefghijklmnop',
  '/wss/v1/c/abcdefghijklmnop',
  '/ptyx/v1/c/abcdefghijklmnop'
];
const deniedRoutes = [
  '/foo/',
  '/v1/c/short',
  '/v1/c/abcdefghijklmnopx/extra',
  '//evil.example/v1/c/abcdefghijklmnop',
  'http://evil.example/v1/c/abcdefghijklmnop',
  ...reservedPrefixLookalikes,
  ...canonicalMutationRoutes,
  ...lexicalMutationRoutes
];
const missingAssetRoutes = ['/_app/missing-asset.js', '/_app/'];

try {
  for (const rawTarget of shellRoutes) {
    const result = await rawHttpRequest(address.port, rawTarget);
    if (result.status !== 200) {
      throw new Error(`Expected direct shell load ${rawTarget} to return 200, got ${result.status}.`);
    }
    if (!result.body.includes('/_app/')) {
      throw new Error(`Expected ${rawTarget} to serve the production shell.`);
    }
  }

  const worker = await rawHttpRequest(address.port, workerRoute);
  if (worker.status !== 200 || !worker.body.includes('addEventListener')) {
    throw new Error('Expected the generated /service-worker.js route to serve executable worker code.');
  }
  if (!worker.headers['content-type']?.startsWith('text/javascript')) {
    throw new Error('The generated service worker must use a JavaScript content type.');
  }

  for (const rawTarget of [...shellRoutes, workerRoute]) {
    const head = await rawHttpRequest(address.port, rawTarget, 'HEAD');
    if (head.status !== 200 || head.body !== '') {
      throw new Error(`Expected HEAD ${rawTarget} to serve headers without a response body.`);
    }
  }

  for (const method of ['POST', 'PUT', 'OPTIONS', 'PATCH', 'DELETE', 'TRACE', 'FOO']) {
    const result = await rawHttpRequest(address.port, '/v1/c/abcdefghijklmnop', method);
    const parserRejectedUnknownMethod = method === 'FOO' && result.status === 400;
    if (result.status !== 405 && !parserRejectedUnknownMethod) {
      throw new Error(
        `Expected non-GET/HEAD method ${method} to fail closed with 405 or parser-level 400, got ${result.status}.`
      );
    }
  }

  const connect = await rawConnectRequest(address.port, '/v1/c/abcdefghijklmnop');
  if (
    connect.status !== 405 ||
    connect.headers.allow !== 'GET, HEAD' ||
    connect.headers['content-length'] !== '18' ||
    connect.body !== 'method not allowed'
  ) {
    throw new Error(
      `Expected CONNECT to close with a bounded 405 response and Allow header, got ${JSON.stringify(connect)}.`
    );
  }

  for (const rawTarget of [...deniedRoutes, ...missingAssetRoutes]) {
    const result = await rawHttpRequest(address.port, rawTarget);
    if (result.status !== 404 || result.body !== 'not found') {
      throw new Error(
        `Expected raw denied or missing target ${JSON.stringify(rawTarget)} to return generic 404, got ${result.status}.`
      );
    }
  }
} finally {
  await new Promise((resolveServer) => server.close(resolveServer));
}

console.log(
  'static route evidence: shared grammar, raw lexical checks, canonical mutation denial, generic asset 404s, GET/HEAD/CONNECT methods, 200.html, and service-worker.js pass'
);
