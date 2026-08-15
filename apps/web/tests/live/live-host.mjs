import { createHash } from 'node:crypto';
import { createServer, request as createRequest } from 'node:http';
import { connect as createConnection, isIP } from 'node:net';
import { readFile, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { cwd } from 'node:process';
import { parseRawRequestTarget } from '../../src/lib/static-route-grammar.mjs';
import { resolveStaticPath } from '../static/static-host.mjs';

const PROXY_PREFIXES = Object.freeze(['/api/', '/auth/']);
const PTY_WEBSOCKET_PATH = '/api/pty';
const CHAT_WEBSOCKET_PATH = '/api/ws';
const PTY_QUERY_KEYS = new Set(['ticket', 'resume', 'attach']);
const PTY_QUERY_LIMITS = Object.freeze({
  ticket: 512,
  resume: 128,
  attach: 512
});
const MAX_PTY_QUERY_LENGTH = 1_200;
const MAX_UPGRADE_RESPONSE_LENGTH = 64 * 1024;
const HTTP_CONTROL_CHARACTER_PATTERN = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u;
const SAFE_OPAQUE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~-]*$/u;
const WEBSOCKET_ACCEPT_MAGIC = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
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

/** @param {string} pathname @returns {boolean} */
function isProxyTarget(pathname) {
  return PROXY_PREFIXES.some((prefix) => pathname.startsWith(prefix));
}

/** @param {string} pathname @returns {boolean} */
function isPtyPath(pathname) {
  // Keep PTY routing exact. Otherwise the broader /api/ proxy prefix could
  // accidentally turn /api/pty/anything into a credentialed upstream route.
  return pathname === PTY_WEBSOCKET_PATH || pathname.startsWith(`${PTY_WEBSOCKET_PATH}/`);
}

/**
 * Validate the PTY query lexically and retain no opaque values. The browser
 * transport already constrains these values to safe opaque ASCII; repeating
 * that boundary here prevents URL decoding from changing the upstream target.
 *
 * @param {string} rawTarget
 * @returns {{queryKeyNames: readonly string[], valueLengths: Readonly<Record<string, number>>} | undefined}
 */
function parsePtyUpgradeTarget(rawTarget) {
  const parsed = parseRawRequestTarget(rawTarget);
  if (!parsed || parsed.pathname !== PTY_WEBSOCKET_PATH || !parsed.hasQuery) return undefined;

  const queryStart = rawTarget.indexOf('?');
  const rawQuery = rawTarget.slice(queryStart + 1);
  if (rawQuery.length === 0 || rawQuery.length > MAX_PTY_QUERY_LENGTH || rawQuery.includes('?')) {
    return undefined;
  }

  const queryKeyNames = [];
  /** @type {Record<string, number>} */
  const valueLengths = {};
  const seenKeys = new Set();
  for (const pair of rawQuery.split('&')) {
    const equalsIndex = pair.indexOf('=');
    if (equalsIndex <= 0 || equalsIndex !== pair.lastIndexOf('=')) return undefined;
    const key = pair.slice(0, equalsIndex);
    const value = pair.slice(equalsIndex + 1);
    const limit =
      key === 'ticket'
        ? PTY_QUERY_LIMITS.ticket
        : key === 'resume'
          ? PTY_QUERY_LIMITS.resume
          : key === 'attach'
            ? PTY_QUERY_LIMITS.attach
            : undefined;
    if (!PTY_QUERY_KEYS.has(key) || seenKeys.has(key) || limit === undefined) return undefined;
    if (value.length === 0 || value.length > limit || !SAFE_OPAQUE_PATTERN.test(value)) return undefined;
    seenKeys.add(key);
    queryKeyNames.push(key);
    valueLengths[key] = value.length;
  }

  if (!seenKeys.has('ticket') || !seenKeys.has('resume')) return undefined;
  return Object.freeze({
    queryKeyNames: Object.freeze(queryKeyNames),
    valueLengths: Object.freeze(valueLengths)
  });
}

/** @param {import('node:http').IncomingMessage} request @returns {boolean} */
function hasWebSocketUpgrade(request) {
  const upgrade = request.headers.upgrade;
  const connection = request.headers.connection;
  if (typeof upgrade !== 'string' || upgrade.trim().toLowerCase() !== 'websocket') return false;
  if (typeof connection !== 'string') return false;
  return connection.split(',').some((token) => token.trim().toLowerCase() === 'upgrade');
}

/**
 * @param {import('node:stream').Duplex} socket
 * @param {number} statusCode
 * @param {string} statusMessage
 * @param {Record<string, string>} [headers]
 */
function denyUpgrade(socket, statusCode, statusMessage, headers = {}) {
  const lines = [`HTTP/1.1 ${statusCode} ${statusMessage}`];
  for (const [name, value] of Object.entries(headers)) lines.push(`${name}: ${value}`);
  lines.push('Connection: close', '', '');
  socket.end(lines.join('\r\n'));
}

/**
 * @param {string | string[] | undefined} value
 * @param {string} token
 * @returns {boolean}
 */
function hasHeaderToken(value, token) {
  const values = Array.isArray(value) ? value : [value];
  return values.some(
    (headerValue) =>
      typeof headerValue === 'string' &&
      headerValue.split(',').some((part) => part.trim().toLowerCase() === token)
  );
}

/**
 * @param {Record<string, string | string[] | number | undefined>} headers
 * @returns {string[] | undefined}
 */
function serializeUpgradeRequestHeaders(headers) {
  const lines = [];
  for (const [name, value] of Object.entries(headers)) {
    const values = Array.isArray(value) ? value : [value];
    for (const headerValue of values) {
      if (
        !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u.test(name) ||
        (typeof headerValue !== 'string' && typeof headerValue !== 'number') ||
        HTTP_CONTROL_CHARACTER_PATTERN.test(String(headerValue)) ||
        /[\r\n]/u.test(String(headerValue))
      ) {
        return undefined;
      }
      lines.push(`${name}: ${headerValue}`);
    }
  }
  return lines;
}

/**
 * Parse one bounded HTTP response head without handing the upgraded byte
 * stream to Node's HTTP response parser. That parser can emit a valid 101 via
 * `response`, consume later WebSocket frames, and leave the browser at 1006.
 *
 * @param {Buffer} bytes
 * @returns {{statusCode: number, statusMessage: string, headers: Map<string, string>, rawHeaders: string[], headLength: number} | undefined | null}
 */
function parseUpgradeResponseHead(bytes) {
  const delimiter = bytes.indexOf(Buffer.from('\r\n\r\n'));
  if (delimiter === -1) return undefined;
  const head = bytes.subarray(0, delimiter).toString('latin1');
  const lines = head.split('\r\n');
  const statusLine = lines.shift() ?? '';
  const statusMatch = /^HTTP\/1\.[01] (\d{3})(?: ([^\r\n]*))?$/u.exec(statusLine);
  if (
    !statusMatch ||
    Number(statusMatch[1]) < 100 ||
    Number(statusMatch[1]) > 599 ||
    HTTP_CONTROL_CHARACTER_PATTERN.test(statusMatch[2] ?? '')
  ) {
    return null;
  }
  const headers = new Map();
  const rawHeaders = [];
  for (const line of lines) {
    const separator = line.indexOf(':');
    if (separator <= 0 || /[^!#$%&'*+.^_`|~0-9A-Za-z-]/u.test(line.slice(0, separator))) {
      return null;
    }
    const name = line.slice(0, separator);
    const value = line.slice(separator + 1).trim();
    if (HTTP_CONTROL_CHARACTER_PATTERN.test(value) || /[\r\n]/u.test(value)) return null;
    const key = name.toLowerCase();
    const previous = headers.get(key);
    headers.set(key, previous === undefined ? value : `${previous}, ${value}`);
    rawHeaders.push(`${name}: ${value}`);
  }
  return {
    statusCode: Number(statusMatch[1]),
    statusMessage: statusMatch[2] ?? '',
    headers,
    rawHeaders,
    headLength: delimiter + 4
  };
}

/**
 * @param {{statusCode: number, statusMessage: string, headers: Map<string, string>, rawHeaders: string[], headLength: number}} response
 * @param {import('node:http').IncomingHttpHeaders} requestHeaders
 * @returns {boolean}
 */
function isWebSocketUpgradeResponse(response, requestHeaders) {
  const key = requestHeaders['sec-websocket-key'];
  const accept = response.headers.get('sec-websocket-accept');
  if (typeof key !== 'string' || !/^[A-Za-z0-9+/]{22}==$/u.test(key)) return false;
  const expectedAccept = createHash('sha1').update(`${key}${WEBSOCKET_ACCEPT_MAGIC}`).digest('base64');
  return (
    response.statusCode === 101 &&
    hasHeaderToken(response.headers.get('connection'), 'upgrade') &&
    hasHeaderToken(response.headers.get('upgrade'), 'websocket') &&
    typeof accept === 'string' &&
    /^[A-Za-z0-9+/]{27}=$/u.test(accept) &&
    accept === expectedAccept
  );
}

/**
 * @param {{statusCode: number, statusMessage: string, rawHeaders: string[]}} response
 * @returns {string}
 */
function serializedUpgradeResponse(response) {
  const headers = response.rawHeaders.filter((line) => {
    const separator = line.indexOf(':');
    return separator > 0 && !HOP_BY_HOP_HEADERS.has(line.slice(0, separator).toLowerCase());
  });
  headers.push('Connection: Upgrade', 'Upgrade: websocket');
  return `HTTP/1.1 ${response.statusCode} ${response.statusMessage}\r\n${headers.join('\r\n')}\r\n\r\n`;
}

/** @param {string} pathname @returns {string} */
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

/**
 * @param {import('node:http').IncomingHttpHeaders} headers
 * @param {URL} target
 * @returns {import('node:http').OutgoingHttpHeaders}
 */
function proxyHeaders(headers, target) {
  /** @type {import('node:http').OutgoingHttpHeaders} */
  const forwarded = {};
  for (const [name, value] of Object.entries(headers)) {
    if (!HOP_BY_HOP_HEADERS.has(name.toLowerCase()) && value !== undefined) forwarded[name] = value;
  }
  forwarded.host = target.host;
  return forwarded;
}

/**
 * @param {import('node:http').IncomingHttpHeaders} source
 * @param {import('node:http').ServerResponse} destination
 */
function copyResponseHeaders(source, destination) {
  for (const [name, value] of Object.entries(source)) {
    if (!HOP_BY_HOP_HEADERS.has(name.toLowerCase()) && value !== undefined) {
      destination.setHeader(name, value);
    }
  }
}

/**
 * @param {import('node:http').IncomingMessage} request
 * @param {import('node:http').ServerResponse} response
 * @param {URL} target
 */
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

/**
 * @param {import('node:http').IncomingMessage} request
 * @param {import('node:stream').Duplex} socket
 * @param {Buffer} head
 * @param {URL} target
 */
function proxyUpgrade(request, socket, head, target) {
  const rawTarget = request.url ?? '';
  const parsed = parseRawRequestTarget(rawTarget);
  if (!parsed) {
    denyUpgrade(socket, 400, 'Bad Request');
    return;
  }
  if (request.method !== 'GET') {
    denyUpgrade(socket, 405, 'Method Not Allowed', { Allow: 'GET' });
    return;
  }
  if (!hasWebSocketUpgrade(request)) {
    denyUpgrade(socket, 426, 'Upgrade Required', { Upgrade: 'websocket' });
    return;
  }

  const isPtyTarget = parsed.pathname === PTY_WEBSOCKET_PATH;
  const ptyTarget = isPtyTarget ? parsePtyUpgradeTarget(rawTarget) : undefined;
  if (isPtyTarget && ptyTarget === undefined) {
    denyUpgrade(socket, 400, 'Bad Request');
    return;
  }
  if (!isPtyTarget && parsed.pathname !== CHAT_WEBSOCKET_PATH) {
    // Keep /api/ws as the reviewed Chat route, while refusing every other
    // upgrade before any credentialed upstream request is created.
    denyUpgrade(socket, 404, 'Not Found');
    return;
  }

  // `ptyTarget` contains only key names and bounded lengths. The raw target is
  // forwarded unchanged so ticket, resume, and attach remain opaque and no
  // WebSocket payload listener can decode or buffer PTY bytes.
  const requestHeaders = {
    ...proxyHeaders(request.headers, target),
    connection: 'Upgrade',
    upgrade: 'websocket'
  };
  const serializedRequestHeaders = serializeUpgradeRequestHeaders(requestHeaders);
  if (serializedRequestHeaders === undefined) {
    denyUpgrade(socket, 400, 'Bad Request');
    return;
  }
  const upstreamHost = target.hostname.startsWith('[') ? target.hostname.slice(1, -1) : target.hostname;
  const upstream = createConnection({ host: upstreamHost, port: Number(target.port) });
  let responseBytes = Buffer.alloc(0);
  let responseHandled = false;
  const fail = (statusCode = 502, statusMessage = 'Bad Gateway') => {
    if (responseHandled) return;
    responseHandled = true;
    denyUpgrade(socket, statusCode, statusMessage);
    upstream.destroy();
  };

  upstream.setTimeout(30_000, () => fail());
  upstream.on('error', () => fail());
  upstream.on('close', () => fail());
  upstream.on('connect', () => {
    upstream.write(
      `GET ${rawTarget} HTTP/1.1\r\n${serializedRequestHeaders.join('\r\n')}\r\n\r\n`
    );
  });
  upstream.on('data', (chunk) => {
    if (responseHandled) return;
    responseBytes = Buffer.concat([responseBytes, Buffer.from(chunk)]);
    const parsedResponse = parseUpgradeResponseHead(responseBytes);
    if (parsedResponse === undefined) {
      if (responseBytes.length > MAX_UPGRADE_RESPONSE_LENGTH) fail();
      return;
    }
    if (parsedResponse === null) {
      fail();
      return;
    }
    if (parsedResponse.headLength > MAX_UPGRADE_RESPONSE_LENGTH) {
      fail();
      return;
    }
    responseHandled = true;
    if (!isWebSocketUpgradeResponse(parsedResponse, request.headers)) {
      if (parsedResponse.statusCode !== 101) {
        denyUpgrade(socket, parsedResponse.statusCode, parsedResponse.statusMessage || 'Upgrade Failed');
      } else {
        denyUpgrade(socket, 502, 'Bad Gateway');
      }
      upstream.destroy();
      return;
    }

    socket.write(serializedUpgradeResponse(parsedResponse));
    if (head.length > 0) upstream.write(head);
    const upstreamBody = responseBytes.subarray(parsedResponse.headLength);
    responseBytes = Buffer.alloc(0);
    if (upstreamBody.length > 0) socket.write(upstreamBody);
    upstream.setTimeout(0);
    // These are raw duplex pipes by design. No WebSocket frame is decoded,
    // stringified, copied into an application buffer, or written to a log.
    upstream.pipe(socket);
    socket.pipe(upstream);
  });
}

/**
 * Validate only the original environment/configuration string. URL objects are
 * rejected because `new URL()` normalizes numeric, octal, short, and padded
 * authorities before this boundary can inspect their source spelling.
 *
 * @param {unknown} value
 * @returns {URL}
 */
export function validateLiveTarget(value) {
  const raw = value;
  if (typeof raw !== 'string' || raw.length === 0 || raw !== raw.trim() || /[\u0000-\u0020\\%]/u.test(raw)) {
    throw new Error('The disposable Hermes target must be a canonical HTTP loopback URL.');
  }

  const match = /^http:\/\/([^\/?#]+)\/?$/u.exec(raw);
  if (!match) throw new Error('The disposable Hermes target must be plain HTTP with no path or credentials.');

  let target;
  try {
    target = new URL(raw);
  } catch {
    throw new Error('The disposable Hermes target must be a valid HTTP loopback URL.');
  }
  if (target.protocol !== 'http:' || target.username || target.password || target.search || target.hash) {
    throw new Error('The disposable Hermes target must be plain HTTP with no path or credentials.');
  }

  const authority = match[1];
  if (authority.includes('@')) throw new Error('The disposable Hermes target must not include userinfo.');

  let host;
  let port;
  if (authority.startsWith('[')) {
    const ipv6 = /^\[([^\]]+)\](?::(\d+))?$/u.exec(authority);
    if (!ipv6) throw new Error('The disposable Hermes target must use a canonical loopback host.');
    host = ipv6[1];
    port = ipv6[2];
    if (host !== '::1' || isIP(host) !== 6) {
      throw new Error('The disposable Hermes target must use the IPv6 loopback address.');
    }
  } else {
    const hostPort = /^([^:]+)(?::(\d+))?$/u.exec(authority);
    if (!hostPort) throw new Error('The disposable Hermes target must use a canonical loopback host.');
    host = hostPort[1];
    port = hostPort[2];
    if (host.toLowerCase() !== 'localhost' && !isCanonicalLoopbackIpv4(host)) {
      throw new Error('The disposable Hermes target must use a loopback IPv4 address or localhost.');
    }
  }

  if (port === undefined) {
    throw new Error('The disposable Hermes target must include an explicit port.');
  }
  if (!/^(?:0|[1-9]\d*)$/u.test(port) || Number(port) < 1 || Number(port) > 65_535) {
    throw new Error('The disposable Hermes target port is invalid.');
  }
  if (target.pathname !== '/') throw new Error('The disposable Hermes target must not include a path.');
  return target;
}

/** @param {string} host @returns {boolean} */
function isCanonicalLoopbackIpv4(host) {
  const octets = host.split('.');
  return (
    octets.length === 4 &&
    octets.every((octet) => /^(?:0|[1-9]\d{0,2})$/u.test(octet) && Number(octet) <= 255) &&
    Number(octets[0]) === 127 &&
    isIP(host) === 4
  );
}

/**
 * @param {{buildDirectory?: string, target?: string}} [options]
 * @returns {import('node:http').Server}
 */
export function createLiveHost({
  buildDirectory = resolve(cwd(), 'build'),
  target
} = {}) {
  // Credentialed proofs must bind to explicit launcher metadata; a fallback can
  // silently send auth traffic to an unrelated local listener.
  const configuredTarget = target ?? process.env.HERMES_LIVE_TARGET;
  if (configuredTarget === undefined) {
    throw new Error('HERMES_LIVE_TARGET is required for the credentialed live lane.');
  }
  const validatedTarget = validateLiveTarget(configuredTarget);

  const server = createServer(async (request, response) => {
    const rawTarget = request.url ?? '';
    const parsed = parseRawRequestTarget(rawTarget);
    if (!parsed) {
      response.statusCode = 400;
      response.end('bad request');
      return;
    }
    if (isPtyPath(parsed.pathname)) {
      if (parsed.pathname !== PTY_WEBSOCKET_PATH) {
        response.statusCode = 404;
        response.end('not found');
        return;
      }
      if (request.method !== 'GET') {
        response.statusCode = 405;
        response.setHeader('allow', 'GET');
        response.end('method not allowed');
        return;
      }
      if (parsePtyUpgradeTarget(rawTarget) === undefined) {
        response.statusCode = 400;
        response.end('bad pty upgrade target');
        return;
      }
      // A normal HTTP request cannot open a PTY. Reject it locally rather than
      // forwarding a credential-bearing query to Hermes without an upgrade.
      response.statusCode = 426;
      response.setHeader('upgrade', 'websocket');
      response.end('upgrade required');
      return;
    }
    if (isProxyTarget(parsed.pathname)) {
      proxyHttp(request, response, validatedTarget);
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
  server.on('upgrade', (request, socket, head) => proxyUpgrade(request, socket, head, validatedTarget));
  return server;
}

/**
 * @param {{buildDirectory?: string, target?: string, port?: number}} [options]
 * @returns {Promise<import('node:http').Server>}
 */
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
