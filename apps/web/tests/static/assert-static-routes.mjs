import { request as httpRequest } from 'node:http';
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

  for (const rawTarget of deniedRoutes) {
    const result = await rawHttpRequest(address.port, rawTarget);
    if (result.status !== 404 || result.body.includes('/_app/')) {
      throw new Error(
        `Expected raw denied or unknown target ${JSON.stringify(rawTarget)} to stay outside the shell, got ${result.status}.`
      );
    }
  }
} finally {
  await new Promise((resolveServer) => server.close(resolveServer));
}

console.log(
  'static route evidence: raw lexical checks, canonical query/fragment denial, GET/HEAD methods, 200.html, and service-worker.js pass'
);
