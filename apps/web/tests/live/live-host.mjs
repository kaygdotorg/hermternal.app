import { createHash } from 'node:crypto';
import { STATUS_CODES, createServer, request as createRequest } from 'node:http';
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
const SPOOFABLE_FORWARDING_HEADERS = new Set([
  'forwarded',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-origin',
  'x-forwarded-port',
  'x-forwarded-proto'
]);
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
 * @param {Record<string, string>} [headers]
 */
function denyUpgrade(socket, statusCode, headers = {}) {
  const lines = [`HTTP/1.1 ${statusCode} ${STATUS_CODES[statusCode] ?? 'Bad Gateway'}`];
  for (const [name, value] of Object.entries(headers)) lines.push(`${name}: ${value}`);
  lines.push('Connection: close', '', '');
  socket.end(lines.join('\r\n'));
}

/**
 * Validate the configured public edge authority. A missing pair means that
 * the host derives the public loopback authority from its bound socket.
 *
 * @param {string | undefined} publicHost
 * @param {string | undefined} publicOrigin
 * @returns {{host: string, origin: string} | undefined}
 */
function validatePublicEndpoint(publicHost, publicOrigin) {
  if (publicHost === undefined && publicOrigin === undefined) return undefined;
  if (typeof publicHost !== 'string' || typeof publicOrigin !== 'string') {
    throw new Error('The public Host and Origin must be configured together.');
  }
  let parsedOrigin;
  try {
    parsedOrigin = new URL(publicOrigin);
  } catch {
    throw new Error('The public Origin must be a canonical HTTP or HTTPS origin.');
  }
  if (
    (parsedOrigin.protocol !== 'http:' && parsedOrigin.protocol !== 'https:') ||
    parsedOrigin.username ||
    parsedOrigin.password ||
    parsedOrigin.pathname !== '/' ||
    parsedOrigin.search ||
    parsedOrigin.hash ||
    publicOrigin !== parsedOrigin.origin ||
    parsedOrigin.host !== publicHost
  ) {
    throw new Error('The public Host and Origin must describe one canonical public origin.');
  }
  return Object.freeze({ host: publicHost, origin: publicOrigin });
}

/**
 * Resolve the public endpoint without trusting request headers. The default
 * is the loopback address and port that accepted the request.
 *
 * @param {import('node:http').IncomingMessage} request
 * @param {{host: string, origin: string} | undefined} configured
 * @returns {{host: string, origin: string} | undefined}
 */
function publicEndpointFor(request, configured) {
  if (configured) return configured;
  const address = request.socket.localAddress;
  const port = request.socket.localPort;
  if (
    (address !== '127.0.0.1' && address !== '::1') ||
    typeof port !== 'number' ||
    !Number.isInteger(port) ||
    port < 1 ||
    port > 65_535
  ) {
    return undefined;
  }
  const host = address === '::1' ? `[${address}]` : address;
  return { host: `${host}:${port}`, origin: `http://${host}:${port}` };
}

/**
 * Validate the public edge headers before forwarding a request.
 *
 * @param {import('node:http').IncomingMessage} request
 * @param {{host: string, origin: string} | undefined} endpoint
 * @param {boolean} requireOrigin
 * @returns {number | undefined} HTTP status when the request must be denied
 */
function publicHeaderFailure(request, endpoint, requireOrigin) {
  if (!endpoint || request.headers.host !== endpoint.host) return 421;
  const origin = request.headers.origin;
  if ((requireOrigin || origin !== undefined) && origin !== endpoint.origin) return 403;
  return undefined;
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
 * @param {{statusCode: number, rawHeaders: string[]}} response
 * @returns {string}
 */
function serializedUpgradeResponse(response) {
  const headers = response.rawHeaders.filter((line) => {
    const separator = line.indexOf(':');
    return separator > 0 && !HOP_BY_HOP_HEADERS.has(line.slice(0, separator).toLowerCase());
  });
  headers.push('Connection: Upgrade', 'Upgrade: websocket');
  const reason = STATUS_CODES[response.statusCode] ?? 'Switching Protocols';
  return `HTTP/1.1 ${response.statusCode} ${reason}\r\n${headers.join('\r\n')}\r\n\r\n`;
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
    const lowerName = name.toLowerCase();
    if (
      !HOP_BY_HOP_HEADERS.has(lowerName) &&
      !SPOOFABLE_FORWARDING_HEADERS.has(lowerName) &&
      lowerName !== 'host' &&
      lowerName !== 'origin' &&
      value !== undefined
    ) {
      forwarded[name] = value;
    }
  }
  // Map the validated public authority to the private Hermes authority. The
  // target port is explicit here because URL objects omit HTTP port 80.
  forwarded.host = targetAuthority(target);
  if (headers.origin !== undefined) forwarded.origin = target.origin;
  return forwarded;
}

/** @param {URL} target @returns {string} */
function targetPort(target) {
  return target.port || (target.protocol === 'https:' ? '443' : '80');
}

/** @param {URL} target @returns {string} */
function targetHostname(target) {
  return target.hostname.startsWith('[') ? target.hostname.slice(1, -1) : target.hostname;
}

/** @param {URL} target @returns {string} */
function targetAuthority(target) {
  return `${target.hostname}:${targetPort(target)}`;
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
      hostname: targetHostname(target),
      port: targetPort(target),
      method: request.method,
      path: request.url,
      headers: proxyHeaders(request.headers, target)
    },
    (upstreamResponse) => {
      response.statusCode = upstreamResponse.statusCode ?? 502;
      // Keep reason phrases local. Upstream text is not part of the proof
      // contract and must never be reflected into an edge response.
      response.statusMessage = STATUS_CODES[response.statusCode] ?? 'Bad Gateway';
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
 * @param {{host: string, origin: string} | undefined} configuredPublicEndpoint
 */
function proxyUpgrade(request, socket, head, target, configuredPublicEndpoint) {
  const publicFailure = publicHeaderFailure(
    request,
    publicEndpointFor(request, configuredPublicEndpoint),
    true
  );
  if (publicFailure !== undefined) {
    denyUpgrade(socket, publicFailure);
    return;
  }
  const rawTarget = request.url ?? '';
  const parsed = parseRawRequestTarget(rawTarget);
  if (!parsed) {
    denyUpgrade(socket, 400);
    return;
  }
  if (request.method !== 'GET') {
    denyUpgrade(socket, 405, { Allow: 'GET' });
    return;
  }
  if (!hasWebSocketUpgrade(request)) {
    denyUpgrade(socket, 426, { Upgrade: 'websocket' });
    return;
  }

  const isPtyTarget = parsed.pathname === PTY_WEBSOCKET_PATH;
  const ptyTarget = isPtyTarget ? parsePtyUpgradeTarget(rawTarget) : undefined;
  if (isPtyTarget && ptyTarget === undefined) {
    denyUpgrade(socket, 400);
    return;
  }
  if (!isPtyTarget && parsed.pathname !== CHAT_WEBSOCKET_PATH) {
    // Keep /api/ws as the reviewed Chat route, while refusing every other
    // upgrade before any credentialed upstream request is created.
    denyUpgrade(socket, 404);
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
    denyUpgrade(socket, 400);
    return;
  }
  const upstream = createConnection({ host: targetHostname(target), port: Number(targetPort(target)) });
  let responseBytes = Buffer.alloc(0);
  let responseHandled = false;
  let clientClosed = false;
  const fail = (statusCode = 502) => {
    responseBytes = Buffer.alloc(0);
    if (responseHandled || clientClosed) {
      upstream.destroy();
      return;
    }
    responseHandled = true;
    // Never copy an upstream reason phrase into the local response. The local
    // status table provides a fixed phrase for every response code.
    denyUpgrade(socket, statusCode);
    upstream.destroy();
  };

  // An abandoned browser upgrade must not keep a private socket alive until
  // the handshake timeout. This listener remains active after 101 so either
  // side closing the raw tunnel closes the other side as well.
  const closeUpstreamForClient = () => {
    clientClosed = true;
    upstream.destroy();
  };
  socket.once('close', closeUpstreamForClient);
  socket.once('end', closeUpstreamForClient);
  socket.once('error', closeUpstreamForClient);
  upstream.setTimeout(30_000, () => fail());
  upstream.on('error', () => fail());
  upstream.on('close', () => fail());
  upstream.on('connect', () => {
    if (clientClosed) {
      upstream.destroy();
      return;
    }
    upstream.write(
      `GET ${rawTarget} HTTP/1.1\r\n${serializedRequestHeaders.join('\r\n')}\r\n\r\n`
    );
  });
  /** @param {Buffer|string} chunk */
  const handleUpgradeResponse = (chunk) => {
    if (responseHandled || clientClosed) {
      upstream.destroy();
      return;
    }
    const incoming = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    if (
      incoming.length > MAX_UPGRADE_RESPONSE_LENGTH ||
      responseBytes.length > MAX_UPGRADE_RESPONSE_LENGTH - incoming.length
    ) {
      fail();
      return;
    }
    responseBytes = Buffer.concat([responseBytes, incoming]);
    const parsedResponse = parseUpgradeResponseHead(responseBytes);
    if (parsedResponse === undefined) {
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
        denyUpgrade(socket, parsedResponse.statusCode);
      } else {
        denyUpgrade(socket, 502);
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
    // The listener above only parses the HTTP upgrade response. Leaving it
    // attached would treat every later WebSocket frame as a second handshake
    // and destroy the upstream before the duplex pipes can forward it.
    upstream.off('data', handleUpgradeResponse);
    // These are raw duplex pipes by design. No WebSocket frame is decoded,
    // stringified, copied into an application buffer, or written to a log.
    upstream.pipe(socket);
    socket.pipe(upstream);
    // Node can retain the public HTTP-upgrade socket in paused mode after the
    // handshake parser releases it. Resume it after both pipes exist so later
    // client frames reach the private Hermes socket.
    socket.resume();
  };
  upstream.on('data', handleUpgradeResponse);
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
 * @param {{buildDirectory?: string, target?: string, publicHost?: string, publicOrigin?: string}} [options]
 * @returns {import('node:http').Server}
 */
export function createLiveHost({
  buildDirectory = resolve(cwd(), 'build'),
  target,
  publicHost,
  publicOrigin
} = {}) {
  // Credentialed proofs must bind to explicit launcher metadata; a fallback can
  // silently send auth traffic to an unrelated local listener.
  const configuredTarget = target ?? process.env.HERMES_LIVE_TARGET;
  if (configuredTarget === undefined) {
    throw new Error('HERMES_LIVE_TARGET is required for the credentialed live lane.');
  }
  const validatedTarget = validateLiveTarget(configuredTarget);
  const configuredPublicEndpoint = validatePublicEndpoint(publicHost, publicOrigin);

  const server = createServer(async (request, response) => {
    const publicFailure = publicHeaderFailure(
      request,
      publicEndpointFor(request, configuredPublicEndpoint),
      false
    );
    if (publicFailure !== undefined) {
      response.statusCode = publicFailure;
      response.end(publicFailure === 421 ? 'misdirected request' : 'forbidden');
      return;
    }
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
  server.on('upgrade', (request, socket, head) =>
    proxyUpgrade(request, socket, head, validatedTarget, configuredPublicEndpoint)
  );
  return server;
}

/**
 * @param {{buildDirectory?: string, target?: string, publicHost?: string, publicOrigin?: string, port?: number}} [options]
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
