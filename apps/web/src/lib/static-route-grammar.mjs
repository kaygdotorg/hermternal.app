const ID_SEGMENT = '[A-Za-z0-9._~-]{16,}';

/**
 * W-01 keeps this grammar in one source because the browser worker and the
 * production-shaped static host must reject the same reserved and malformed
 * navigation targets before either side normalizes a URL.
 */
export const CLIENT_ROUTE_PATTERN = new RegExp(
  `^/v1/c/${ID_SEGMENT}(?:/m/${ID_SEGMENT})?$`
);

/** @type {readonly string[]} */
export const RESERVED_PATH_PREFIXES = Object.freeze([
  '/api',
  '/hermes',
  '/auth',
  '/ws',
  '/pty'
]);
export const NAVIGATION_ALLOWLIST = Object.freeze(['/', '/index.html']);
export const CLIENT_ROUTE_FALLBACK_PATH = '/200.html';
export const ROOT_DOCUMENT_PATH = '/index.html';
export const SERVICE_WORKER_SCRIPT_PATH = '/service-worker.js';

/** @param {string} pathname */
export function isReservedPath(pathname) {
  return RESERVED_PATH_PREFIXES.some(
    (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`)
  );
}

/** @param {string} pathname */
export function isSupportedClientRoute(pathname) {
  return CLIENT_ROUTE_PATTERN.test(pathname);
}

/** @param {string} value */
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
 * Validate an HTTP origin-form target before URL normalization. Query presence
 * is retained because the root fixture selector is intentionally online-only.
 * @param {string} rawTarget
 * @returns {{pathname: string, hasQuery: boolean} | undefined}
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

/**
 * Convert a same-origin absolute request URL to origin-form without parsing or
 * normalizing its pathname first, then apply the shared lexical boundary.
 * @param {string} rawUrl
 * @param {string} origin
 * @returns {{pathname: string, hasQuery: boolean} | undefined}
 */
export function parseSameOriginRequestTarget(rawUrl, origin) {
  const target = rawUrl === origin ? '/' : rawUrl.startsWith(`${origin}/`) ? rawUrl.slice(origin.length) : undefined;
  return target === undefined ? undefined : parseRawRequestTarget(target);
}
