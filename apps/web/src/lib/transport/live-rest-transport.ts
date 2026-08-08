import { parseStrictJson, StrictJsonError, type StrictJsonValue } from './strict-json';
import {
  isAuthIdentity,
  type AuthIdentity,
  type LiveMessage,
  type LiveMessageContent,
  type LiveProvider,
  type LiveToolCall,
  type LiveToolCalls,
  type LiveSession,
  type MessageListOptions,
  type ProviderDiscovery,
  type SessionList,
  type SessionListOptions,
  type SessionMessages
} from './live-rest-types';

const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_BODY_BYTES = 128 * 1024;
const MAX_BODY_BYTES = 1024 * 1024;
const MAX_PROVIDER_COUNT = 32;
const MAX_SESSION_COUNT = 100;
const MAX_MESSAGE_COUNT = 500;
const MAX_TOOL_CALL_COUNT = 64;
const MAX_ID_LENGTH = 128;
const MAX_TEXT_LENGTH = 8_192;
const MAX_SHORT_TEXT_LENGTH = 512;
// These are client representation budgets for source-defined REST values, not
// invented upstream schema claims. They keep numeric timestamps lossless for
// the reviewed dashboard horizon without accepting unbounded JSON integers.
const MAX_UNIX_SECONDS = 4_294_967_295;
const API_ROOT = '/api';
// Cancellation is best-effort at the platform stream boundary. Never let a
// hostile or synthetic reader's cancel promise hold the REST request forever.
const RESPONSE_CANCEL_TIMEOUT_MS = 100;

const SESSION_ID_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9._~-]{0,126}[A-Za-z0-9])?$/u;
const PROVIDER_NAME_MAX_LENGTH = 96;
const PROVIDER_NAME_FORBIDDEN_PATTERN = /[\s/\\\p{C}]/u;
const PROVIDER_CONTROL_PATTERN = /\p{C}/u;

export type LiveRestErrorCode =
  | 'aborted'
  | 'timeout'
  | 'network'
  | 'redirect'
  | 'http'
  | 'provider-unavailable'
  | 'unauthenticated'
  | 'not-found'
  | 'body-too-large'
  | 'malformed-json'
  | 'invalid-response'
  | 'invalid-url'
  | 'invalid-session-id'
  | 'invalid-options';

export class LiveRestError extends Error {
  readonly code: LiveRestErrorCode;
  readonly status?: number;

  constructor(code: LiveRestErrorCode, status?: number) {
    super(messageFor(code, status));
    this.name = 'LiveRestError';
    this.code = code;
    this.status = status;
  }
}

export type LiveRestFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export interface LiveRestTransportOptions {
  /** Optional only for deterministic tests; production uses the browser fetch. */
  fetch?: LiveRestFetch;
  /** Abort slow requests instead of leaving an authentication read pending. */
  timeoutMs?: number;
  /** Cap response bytes before decoding or parsing untrusted JSON. */
  maxBodyBytes?: number;
  /** Must resolve to the real browser origin and the exact `/api` root. */
  apiBaseUrl?: string;
}

export interface LiveRestTransport {
  getProviders(signal?: AbortSignal): Promise<ProviderDiscovery>;
  getAuthState(signal?: AbortSignal): Promise<AuthIdentity>;
  listSessions(options?: SessionListOptions, signal?: AbortSignal): Promise<SessionList>;
  getSessions(options?: SessionListOptions, signal?: AbortSignal): Promise<SessionList>;
  getSession(sessionId: string, signal?: AbortSignal): Promise<LiveSession>;
  getSessionMessages(
    sessionId: string,
    options?: MessageListOptions,
    signal?: AbortSignal
  ): Promise<SessionMessages>;
}

type CapturedLiveSession = Readonly<LiveSession>;

interface CanonicalAliasRecord {
  readonly requestedSessionId: string;
  readonly canonicalSessionId: string;
}

type PendingCanonicalAliasMap = WeakMap<object, CanonicalAliasRecord>;

interface LiveRestAliasAuthority {
  readonly fetchSession: (sessionId: string, signal?: AbortSignal) => Promise<LiveSession>;
  readonly pendingByWorkspace: WeakMap<object, PendingCanonicalAliasMap>;
  readonly scopeEpochByWorkspace: WeakMap<object, number>;
  readonly consumedDetails: WeakSet<object>;
}

interface CapturedCanonicalAliasScope {
  readonly epoch: number;
  readonly pending: PendingCanonicalAliasMap;
}

// Trust never travels on a returned detail object. Only the exact transport
// object created below can issue authority, and only the exact workspace that
// requested an alias can consume its exact returned detail once. Each workspace
// scope also has an epoch and map identity so a reset can revoke an in-flight
// fetch before its completion attempts to mint authority.
const liveRestAliasAuthorities = new WeakMap<object, LiveRestAliasAuthority>();

/**
 * Fetches a session for one exact workspace. Real transports use their private
 * validated request closure; structural/custom adapters can only return an
 * exact-ID detail and cannot authorize an alias response.
 *
 * The workspace scope epoch and exact pending map are captured before the
 * request awaits. A lifecycle reset replaces that map and advances its epoch,
 * so a late canonical response is still returned as data but cannot repopulate
 * the fresh scope with consumable authority.
 *
 * The returned value is one frozen, detached projection. Detail validation reads
 * only own enumerable data descriptors, so an accessor, inherited field, proxy,
 * or descriptor variant cannot change what the workspace later uses for history,
 * publication, selection, or Chat creation.
 */
export async function getLiveRestSessionForWorkspace(
  rest: LiveRestTransport,
  workspace: object,
  requestedSessionId: string,
  signal?: AbortSignal
): Promise<LiveSession> {
  if (!isWeakKey(rest) || !isWeakKey(workspace)) {
    throw new LiveRestError('invalid-response');
  }
  const requested = validateSessionId(requestedSessionId);
  const authority = liveRestAliasAuthorities.get(rest);
  const capturedScope = authority
    ? captureCanonicalAliasScope(authority, workspace)
    : undefined;
  const session = authority
    ? await authority.fetchSession(requested, signal)
    : await rest.getSession(requested, signal);
  const captured = captureLiveSessionDetail(session);
  if (!captured) {
    throw new LiveRestError('invalid-response');
  }
  if (captured.id === requested) return captured;
  if (!authority || !capturedScope) {
    throw new LiveRestError('invalid-response');
  }

  // Alias authority binds the exact detached projection, not the adapter's raw
  // object. Clones and wrappers therefore cannot consume a canonical identity,
  // while the frozen projection remains safe across every later workspace read.
  // Do not move this check after a reset: only the map and epoch captured before
  // the await may receive authority from this completion.
  if (
    authority.scopeEpochByWorkspace.get(workspace) !== capturedScope.epoch ||
    authority.pendingByWorkspace.get(workspace) !== capturedScope.pending
  ) {
    return captured;
  }
  capturedScope.pending.set(captured, {
    requestedSessionId: requested,
    canonicalSessionId: captured.id
  });
  return captured;
}

function captureCanonicalAliasScope(
  authority: LiveRestAliasAuthority,
  workspace: object
): CapturedCanonicalAliasScope {
  let pending = authority.pendingByWorkspace.get(workspace);
  if (!pending) {
    pending = new WeakMap<object, CanonicalAliasRecord>();
    authority.pendingByWorkspace.set(workspace, pending);
  }
  const epoch = authority.scopeEpochByWorkspace.get(workspace) ?? 0;
  authority.scopeEpochByWorkspace.set(workspace, epoch);
  return { epoch, pending };
}

/**
 * Consumes one alias detail issued for the exact transport/workspace pair.
 * Returning `undefined` means no authority exists for this object; a detail
 * that was issued but was altered, replayed, or presented with another alias
 * fails closed with `invalid-response`.
 */
export function consumeLiveRestCanonicalAlias(
  rest: LiveRestTransport,
  workspace: object,
  detail: unknown,
  requestedSessionId: string
): string | undefined {
  if (!isWeakKey(rest) || !isWeakKey(workspace) || !isWeakKey(detail)) return undefined;
  const authority = liveRestAliasAuthorities.get(rest);
  if (!authority || authority.consumedDetails.has(detail)) return undefined;
  const requested = validateSessionId(requestedSessionId);
  const pending = authority.pendingByWorkspace.get(workspace);
  const record = pending?.get(detail);
  if (!record) return undefined;

  pending?.delete(detail);
  authority.consumedDetails.add(detail);
  if (
    record.requestedSessionId !== requested ||
    record.canonicalSessionId === record.requestedSessionId
  ) {
    throw new LiveRestError('invalid-response');
  }
  // The pending map is keyed by the frozen projection returned by
  // getLiveRestSessionForWorkspace. Do not re-read or revalidate the detail
  // here: a second read would reopen the accessor/proxy TOCTOU boundary.
  return record.canonicalSessionId;
}

/**
 * Clear unconsumed alias authority for one workspace without reviving details.
 * Replacing the map and advancing its epoch also fences completions that were
 * already awaiting the real REST response under the previous lifecycle scope.
 */
export function resetLiveRestCanonicalAliasScope(rest: LiveRestTransport, workspace: object): void {
  if (!isWeakKey(rest) || !isWeakKey(workspace)) return;
  const authority = liveRestAliasAuthorities.get(rest);
  if (!authority) return;
  const epoch = authority.scopeEpochByWorkspace.get(workspace) ?? 0;
  authority.scopeEpochByWorkspace.set(workspace, epoch + 1);
  authority.pendingByWorkspace.set(workspace, new WeakMap<object, CanonicalAliasRecord>());
}

/**
 * Browser-cookie REST transport for the reviewed Dashboard read surface.
 * Every request is a relative or validated same-origin `/api` request, uses
 * `credentials: same-origin`, and keeps no cookie, token, ticket, or response
 * cache. WebSocket ticket acquisition belongs to a separate transport issue.
 */
export function createLiveRestTransport(options: LiveRestTransportOptions = {}): LiveRestTransport {
  const fetcher = options.fetch ?? globalThis.fetch?.bind(globalThis);
  if (!fetcher) {
    throw new LiveRestError('network');
  }

  const timeoutMs = normalizeTimeout(options.timeoutMs);
  const maxBodyBytes = normalizeBodyLimit(options.maxBodyBytes);
  const apiBaseUrl = normalizeApiBaseUrl(options.apiBaseUrl);

  async function request<T>(
    path: string,
    validator: (value: StrictJsonValue) => T,
    signal?: AbortSignal
  ): Promise<T> {
    if (signal?.aborted) {
      throw new LiveRestError('aborted');
    }

    const controller = new AbortController();
    let abortKind: 'aborted' | 'timeout' | undefined;
    let abortReject: ((error: LiveRestError) => void) | undefined;
    const abortPromise = new Promise<never>((_, reject) => {
      abortReject = reject;
    });

    const abort = (kind: 'aborted' | 'timeout'): void => {
      if (abortKind) {
        return;
      }
      abortKind = kind;
      controller.abort();
      abortReject?.(new LiveRestError(kind));
    };

    const onAbort = (): void => abort('aborted');
    if (signal?.aborted) {
      abort('aborted');
    } else {
      signal?.addEventListener('abort', onAbort, { once: true });
    }

    const timeout = setTimeout(() => abort('timeout'), timeoutMs);

    try {
      const response = await Promise.race([
        fetcher(buildRequestUrl(apiBaseUrl, path), {
          method: 'GET',
          credentials: 'same-origin',
          headers: { accept: 'application/json' },
          cache: 'no-store',
          redirect: 'error',
          signal: controller.signal
        }),
        abortPromise
      ]);

      if (
        response.redirected ||
        (response.status >= 300 && response.status < 400) ||
        response.type === 'opaqueredirect' ||
        response.type === 'opaque'
      ) {
        await cancelResponseBody(response);
        throw new LiveRestError('redirect');
      }

      if (!hasJsonContentType(response)) {
        await cancelResponseBody(response);
        throw new LiveRestError('invalid-response');
      }

      if (response.status !== 200) {
        throw await classifyHttpError(response, path, maxBodyBytes, abortPromise, () => {
          return abortKind ? new LiveRestError(abortKind) : undefined;
        });
      }

      const body = await readBoundedBody(response, maxBodyBytes, abortPromise, () => {
        return abortKind ? new LiveRestError(abortKind) : undefined;
      });
      let parsed: StrictJsonValue;

      try {
        parsed = parseStrictJson(body);
      } catch (error) {
        if (error instanceof LiveRestError) {
          throw error;
        }
        if (error instanceof StrictJsonError) {
          throw new LiveRestError('malformed-json');
        }
        throw new LiveRestError('malformed-json');
      }

      try {
        return validator(parsed);
      } catch (error) {
        if (error instanceof LiveRestError) {
          throw error;
        }
        throw new LiveRestError('invalid-response');
      }
    } catch (error) {
      if (error instanceof LiveRestError) {
        throw error;
      }
      if (abortKind) {
        throw new LiveRestError(abortKind);
      }
      throw new LiveRestError('network');
    } finally {
      clearTimeout(timeout);
      signal?.removeEventListener('abort', onAbort);
    }
  }

  const fetchSession = (sessionId: string, signal?: AbortSignal): Promise<LiveSession> => {
    const requestedSessionId = validateSessionId(sessionId);
    return request(
      `/sessions/${encodeURIComponent(requestedSessionId)}`,
      validateSession,
      signal
    );
  };

  const transport: LiveRestTransport = {
    getProviders(signal?: AbortSignal): Promise<ProviderDiscovery> {
      return request('/auth/providers', validateProviderDiscovery, signal);
    },

    getAuthState(signal?: AbortSignal): Promise<AuthIdentity> {
      return request('/auth/me', validateAuthIdentity, signal);
    },

    listSessions(options: SessionListOptions = {}, signal?: AbortSignal): Promise<SessionList> {
      const query = buildPaginationQuery(options, MAX_SESSION_COUNT);
      return request(`/sessions${query}`, validateSessionList, signal);
    },

    getSessions(options: SessionListOptions = {}, signal?: AbortSignal): Promise<SessionList> {
      const query = buildPaginationQuery(options, MAX_SESSION_COUNT);
      return request(`/sessions${query}`, validateSessionList, signal);
    },

    getSession: fetchSession,

    getSessionMessages(
      sessionId: string,
      options: MessageListOptions = {},
      signal?: AbortSignal
    ): Promise<SessionMessages> {
      const requestedSessionId = validateSessionId(sessionId);
      const query = buildPaginationQuery(options, MAX_MESSAGE_COUNT);
      return request(
        `/sessions/${encodeURIComponent(requestedSessionId)}/messages${query}`,
        validateSessionMessages,
        signal
      );
    }
  };

  liveRestAliasAuthorities.set(transport, {
    fetchSession,
    pendingByWorkspace: new WeakMap<object, PendingCanonicalAliasMap>(),
    scopeEpochByWorkspace: new WeakMap<object, number>(),
    consumedDetails: new WeakSet<object>()
  });
  return transport;
}

/** Alias retained so callers can name the reviewed boundary by its domain role. */
export const createLiveTransport = createLiveRestTransport;

export function validateSessionId(sessionId: string): string {
  if (typeof sessionId !== 'string' || !SESSION_ID_PATTERN.test(sessionId)) {
    throw new LiveRestError('invalid-session-id');
  }
  return sessionId;
}

function isWeakKey(value: unknown): value is object {
  return (typeof value === 'object' && value !== null) || typeof value === 'function';
}

function isBoundedText(value: unknown, maximum: number): value is string {
  return typeof value === 'string' && value.length <= maximum;
}

function isNullableText(value: unknown, maximum: number): value is string | null {
  return value === null || isBoundedText(value, maximum);
}

function isBoundedTimestamp(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isFinite(value) &&
    value >= 0 &&
    value <= MAX_UNIX_SECONDS
  );
}

function isBoundedCounter(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= 1_000_000_000;
}

const SESSION_DETAIL_REQUIRED_KEYS = [
  'id',
  'source',
  'model',
  'title',
  'startedAt',
  'endedAt',
  'messageCount',
  'toolCallCount',
  'inputTokens',
  'outputTokens'
] as const;

/**
 * Captures one immutable detail projection for structural adapters. Reflection
 * never reads through the source object: every accepted field comes from one
 * own data descriptor, and all own keys must be enumerable data properties on a
 * plain object. structuredClone is a fail-closed proxy check; its result is not
 * used because the descriptor values above are the single captured snapshot.
 */
function captureLiveSessionDetail(value: unknown): CapturedLiveSession | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;

  const descriptors = new Map<string, PropertyDescriptor>();
  try {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return undefined;

    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== 'string') return undefined;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !('value' in descriptor) || descriptor.enumerable !== true) {
        return undefined;
      }
      descriptors.set(key, descriptor);
    }

    const clone = globalThis.structuredClone;
    if (typeof clone !== 'function') return undefined;
    // Native structured cloning rejects Proxy objects without invoking their
    // get traps. Accessors were rejected above before this check can run.
    clone(value);
  } catch {
    return undefined;
  }

  const read = (key: string): unknown => descriptors.get(key)?.value;
  for (const key of SESSION_DETAIL_REQUIRED_KEYS) {
    if (!descriptors.has(key)) return undefined;
  }

  const id = read('id');
  const source = read('source');
  const model = read('model');
  const title = read('title');
  const startedAt = read('startedAt');
  const endedAt = read('endedAt');
  const messageCount = read('messageCount');
  const toolCallCount = read('toolCallCount');
  const inputTokens = read('inputTokens');
  const outputTokens = read('outputTokens');

  if (
    typeof id !== 'string' ||
    !SESSION_ID_PATTERN.test(id) ||
    !isNullableText(source, MAX_SHORT_TEXT_LENGTH) ||
    !isNullableText(model, MAX_SHORT_TEXT_LENGTH) ||
    !isNullableText(title, MAX_TEXT_LENGTH) ||
    !isBoundedTimestamp(startedAt) ||
    !(endedAt === null || isBoundedTimestamp(endedAt)) ||
    !isBoundedCounter(messageCount) ||
    !isBoundedCounter(toolCallCount) ||
    !isBoundedCounter(inputTokens) ||
    !isBoundedCounter(outputTokens)
  ) {
    return undefined;
  }

  const lastActive = read('lastActive');
  const isActive = read('isActive');
  const preview = read('preview');
  const parentSessionId = read('parentSessionId');
  const archived = read('archived');
  const pinned = read('pinned');
  const profile = read('profile');
  const isDefaultProfile = read('isDefaultProfile');

  if (lastActive !== undefined && !isBoundedTimestamp(lastActive)) return undefined;
  if (isActive !== undefined && typeof isActive !== 'boolean') return undefined;
  if (preview !== undefined && !isNullableText(preview, MAX_TEXT_LENGTH)) return undefined;
  if (
    parentSessionId !== undefined &&
    !(
      parentSessionId === null ||
      (typeof parentSessionId === 'string' && SESSION_ID_PATTERN.test(parentSessionId))
    )
  )
    return undefined;
  if (archived !== undefined && typeof archived !== 'boolean') return undefined;
  if (pinned !== undefined && typeof pinned !== 'boolean') return undefined;
  if (profile !== undefined && !isBoundedText(profile, MAX_SHORT_TEXT_LENGTH)) return undefined;
  if (isDefaultProfile !== undefined && typeof isDefaultProfile !== 'boolean') return undefined;

  return Object.freeze({
    id,
    source,
    model,
    title,
    startedAt,
    endedAt,
    ...(lastActive !== undefined && { lastActive }),
    ...(isActive !== undefined && { isActive }),
    messageCount,
    toolCallCount,
    inputTokens,
    outputTokens,
    ...(preview !== undefined && { preview }),
    ...(parentSessionId !== undefined && { parentSessionId }),
    ...(archived !== undefined && { archived }),
    ...(pinned !== undefined && { pinned }),
    ...(profile !== undefined && { profile }),
    ...(isDefaultProfile !== undefined && { isDefaultProfile })
  });
}

export function normalizeApiBaseUrl(value = API_ROOT): string {
  if (typeof value !== 'string' || value.length === 0 || value.includes('?') || value.includes('#')) {
    throw new LiveRestError('invalid-url');
  }

  if (value === API_ROOT || value === `${API_ROOT}/`) {
    return API_ROOT;
  }

  const browserOrigin = currentOrigin();
  if (!browserOrigin || value.startsWith('//') || !/^[a-z][a-z\d+.-]*:/iu.test(value)) {
    throw new LiveRestError('invalid-url');
  }

  let candidate: URL;
  let expectedOrigin: URL;
  try {
    candidate = new URL(value, browserOrigin);
    expectedOrigin = new URL(browserOrigin);
  } catch {
    throw new LiveRestError('invalid-url');
  }

  if (candidate.origin !== expectedOrigin.origin || !isApiPath(candidate.pathname)) {
    throw new LiveRestError('invalid-url');
  }

  return `${candidate.origin}${API_ROOT}`;
}

function currentOrigin(): string | undefined {
  const location = (globalThis as { location?: Location }).location;
  return location?.origin && location.origin !== 'null' ? location.origin : undefined;
}

function isApiPath(pathname: string): boolean {
  return pathname === API_ROOT || pathname === `${API_ROOT}/`;
}

function buildRequestUrl(baseUrl: string, path: string): string {
  if (!path.startsWith('/') || path.includes('://') || path.includes('\\')) {
    throw new LiveRestError('invalid-url');
  }
  return `${baseUrl.replace(/\/$/u, '')}${path}`;
}

function hasJsonContentType(response: Response): boolean {
  const contentType = response.headers.get('content-type');
  if (!contentType) {
    return false;
  }
  return contentType.split(';', 1)[0]?.trim().toLowerCase() === 'application/json';
}

function declaredBodyLength(response: Response): number | undefined {
  const rawContentLength = response.headers.get('content-length');
  if (rawContentLength === null) {
    return undefined;
  }

  const contentLength = rawContentLength.trim();
  if (!/^\d+$/u.test(contentLength)) {
    throw new LiveRestError('invalid-response');
  }
  const parsed = Number(contentLength);
  if (!Number.isSafeInteger(parsed)) {
    throw new LiveRestError('invalid-response');
  }
  return parsed;
}

function buildPaginationQuery(
  options: SessionListOptions | MessageListOptions,
  maxLimit: number
): string {
  const params = new URLSearchParams();

  if (options.limit !== undefined) {
    validateLimit(options.limit, maxLimit);
    params.set('limit', String(options.limit));
  }

  if (options.offset !== undefined) {
    validateOffset(options.offset);
    params.set('offset', String(options.offset));
  }

  const query = params.toString();
  return query ? `?${query}` : '';
}

function normalizeTimeout(value: number | undefined): number {
  const timeoutMs = value ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TIMEOUT_MS) {
    throw new LiveRestError('invalid-options');
  }
  return timeoutMs;
}

function normalizeBodyLimit(value: number | undefined): number {
  const maxBodyBytes = value ?? DEFAULT_MAX_BODY_BYTES;
  if (!Number.isInteger(maxBodyBytes) || maxBodyBytes < 1 || maxBodyBytes > MAX_BODY_BYTES) {
    throw new LiveRestError('invalid-options');
  }
  return maxBodyBytes;
}

function validateLimit(value: number, maxLimit: number): void {
  if (!Number.isInteger(value) || value < 1 || value > maxLimit) {
    throw new LiveRestError('invalid-options');
  }
}

function validateOffset(value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 1_000_000) {
    throw new LiveRestError('invalid-options');
  }
}

async function classifyHttpError(
  response: Response,
  path: string,
  maxBodyBytes: number,
  abortPromise: Promise<never>,
  abortError: () => LiveRestError | undefined
): Promise<LiveRestError> {
  if (response.status === 401) {
    await cancelResponseBody(response);
    return new LiveRestError('unauthenticated', response.status);
  }

  const expectedDetail =
    response.status === 404 && path.startsWith('/sessions/')
      ? 'Session not found'
      : response.status === 503 && path === '/auth/providers'
        ? 'no auth providers registered'
        : undefined;

  if (expectedDetail === undefined) {
    await cancelResponseBody(response);
    return new LiveRestError('http', response.status);
  }

  const body = await readBoundedBody(response, maxBodyBytes, abortPromise, abortError);
  let parsed: StrictJsonValue;
  try {
    parsed = parseStrictJson(body);
  } catch {
    throw new LiveRestError('malformed-json');
  }

  const object = requireObject(parsed, ['detail']);
  if (object.detail !== expectedDetail) {
    throw new LiveRestError('invalid-response');
  }

  return response.status === 404
    ? new LiveRestError('not-found', response.status)
    : new LiveRestError('provider-unavailable', response.status);
}

async function readBoundedBody(
  response: Response,
  maxBodyBytes: number,
  abortPromise: Promise<never>,
  abortError: () => LiveRestError | undefined
): Promise<string> {
  let declaredLength: number | undefined;
  try {
    declaredLength = declaredBodyLength(response);
  } catch (error) {
    await cancelResponseBody(response);
    throw error;
  }

  if (declaredLength !== undefined && declaredLength > maxBodyBytes) {
    await cancelResponseBody(response);
    throw new LiveRestError('body-too-large');
  }

  if (!response.body) {
    // A null-body Response has no cancellable stream and cannot contain a JSON
    // document. Reject it before calling arrayBuffer: that fallback has no
    // portable cancellation primitive and could otherwise outlive the request.
    throw new LiveRestError('invalid-response');
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let cancelReader = false;

  try {
    while (true) {
      const result = await Promise.race([reader.read(), abortPromise]);
      if (result.done) {
        if (declaredLength !== undefined && total !== declaredLength) {
          throw new LiveRestError('invalid-response');
        }
        break;
      }

      const value = result.value as Uint8Array | undefined;
      if (!value || !Number.isSafeInteger(value.byteLength) || value.byteLength < 0) {
        throw new LiveRestError('malformed-json');
      }

      // Check the stream's advertised chunk size before copying it. This is
      // the allocation boundary: one oversized chunk must be rejected and
      // cancelled without first materializing an attacker-sized copy.
      const remainingBodyBytes = maxBodyBytes - total;
      if (value.byteLength > remainingBodyBytes) {
        throw new LiveRestError('body-too-large');
      }
      if (declaredLength !== undefined && value.byteLength > declaredLength - total) {
        throw new LiveRestError('invalid-response');
      }

      const chunk = Uint8Array.from(value);
      if (chunk.byteLength !== value.byteLength) {
        throw new LiveRestError('malformed-json');
      }
      total += chunk.byteLength;
      chunks.push(chunk);
    }
  } catch (error) {
    cancelReader = true;
    if (error instanceof LiveRestError) {
      throw error;
    }
    const reason = abortError();
    if (reason) {
      throw reason;
    }
    throw new LiveRestError('network');
  } finally {
    if (cancelReader) {
      await cancelReaderBounded(reader);
    } else {
      releaseReader(reader);
    }
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return decodeUtf8(bytes);
}

function decodeUtf8(bytes: Uint8Array): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new LiveRestError('malformed-json');
  }
}

async function cancelResponseBody(response: Response): Promise<void> {
  if (!response.body) {
    return;
  }

  try {
    await cancelReaderBounded(response.body.getReader());
  } catch {
    // The response is already failing closed; cancellation errors are not
    // exposed as network diagnostics.
  }
}

async function cancelReaderBounded(reader: ReadableStreamDefaultReader<Uint8Array>): Promise<void> {
  let cancellation: Promise<unknown>;
  try {
    cancellation = Promise.resolve(reader.cancel());
  } catch {
    cancellation = Promise.resolve();
  }

  try {
    await Promise.race([
      cancellation,
      new Promise<void>((resolve) => setTimeout(resolve, RESPONSE_CANCEL_TIMEOUT_MS))
    ]);
  } catch {
    // The request already fails closed. A rejected cancellation must not
    // replace the bounded transport error or keep a caller waiting.
  } finally {
    releaseReader(reader);
  }
}

function releaseReader(reader: ReadableStreamDefaultReader<Uint8Array>): void {
  try {
    reader.releaseLock();
  } catch {
    // Synthetic readers may not implement the platform release contract.
  }
}

function isSafeProviderName(value: string): boolean {
  // JavaScript has no Unicode casefold primitive. Requiring lower-case identity
  // plus a stable upper/lower round trip rejects expansion folds such as ß and
  // ligatures while preserving source-backed lowercase Unicode such as é. The
  // dotless-i exception matches Python casefold, which preserves U+0131.
  const lowerCaseIdentity = value === value.toLowerCase();
  const upperLower = value.toUpperCase().toLowerCase();
  const stableCaseFold =
    value === upperLower || value.replaceAll('ı', 'i') === upperLower;
  return (
    value.length >= 1 &&
    value.length <= PROVIDER_NAME_MAX_LENGTH &&
    lowerCaseIdentity &&
    stableCaseFold &&
    !PROVIDER_NAME_FORBIDDEN_PATTERN.test(value)
  );
}

function isSafeProviderDisplayName(value: string): boolean {
  return !PROVIDER_CONTROL_PATTERN.test(value);
}

function validateProviderDiscovery(value: StrictJsonValue): ProviderDiscovery {
  const object = requireObject(value, ['providers']);
  const providers = requireArray(object.providers, MAX_PROVIDER_COUNT);
  const seen = new Set<string>();

  return {
    providers: providers.map((provider) => {
      const item = requireObject(provider, ['name', 'display_name', 'supports_password']);
      const name = requireString(item.name, 96);
      if (!isSafeProviderName(name) || seen.has(name)) {
        throw new LiveRestError('invalid-response');
      }
      const displayName = requireBoundedString(item.display_name, MAX_SHORT_TEXT_LENGTH);
      if (!isSafeProviderDisplayName(displayName)) {
        throw new LiveRestError('invalid-response');
      }
      seen.add(name);
      return {
        name,
        displayName,
        supportsPassword: requireBoolean(item.supports_password)
      } satisfies LiveProvider;
    })
  };
}

function validateAuthIdentity(value: StrictJsonValue): AuthIdentity {
  const object = requireObject(value, [
    'user_id',
    'email',
    'display_name',
    'org_id',
    'provider',
    'expires_at'
  ]);

  const identity = {
    // user_id and provider are stable authentication identity, not optional
    // profile metadata. Keep them non-empty at the REST boundary so the
    // browser-session logout guard and this parser share one invariant.
    userId: requireString(object.user_id, MAX_SHORT_TEXT_LENGTH),
    email: requireBoundedString(object.email, MAX_SHORT_TEXT_LENGTH),
    displayName: requireBoundedString(object.display_name, MAX_SHORT_TEXT_LENGTH),
    organizationId: requireBoundedString(object.org_id, MAX_SHORT_TEXT_LENGTH),
    provider: requireString(object.provider, MAX_SHORT_TEXT_LENGTH),
    expiresAt: requireBoundedInteger(object.expires_at, 0, MAX_UNIX_SECONDS)
  };

  if (!isAuthIdentity(identity)) {
    throw new LiveRestError('invalid-response');
  }
  return identity;
}

function validateSessionList(value: StrictJsonValue): SessionList {
  const object = requireObject(value, ['sessions', 'total', 'limit', 'offset']);
  const sessions = requireArray(object.sessions, MAX_SESSION_COUNT).map((session) => validateSession(session));
  const total = requireBoundedInteger(object.total, 0, 1_000_000_000);
  const limit = requireBoundedInteger(object.limit, 1, MAX_SESSION_COUNT);
  const offset = requireBoundedInteger(object.offset, 0, 1_000_000);

  return { sessions, total, limit, offset };
}

function validateSession(value: StrictJsonValue): LiveSession {
  const object = requireObject(value, [
    'id',
    'source',
    'model',
    'title',
    'started_at',
    'ended_at',
    'message_count',
    'tool_call_count',
    'input_tokens',
    'output_tokens'
  ]);
  // The route may return a canonical ID after resolving an alias or
  // continuation. The response ID must be safe, but it need not equal the
  // requested path segment.
  const id = requireSessionId(requireString(object.id, MAX_ID_LENGTH));

  return {
    id,
    source: requireNullableString(object.source, MAX_SHORT_TEXT_LENGTH),
    model: requireNullableString(object.model, MAX_SHORT_TEXT_LENGTH),
    title: requireNullableString(object.title, MAX_TEXT_LENGTH),
    startedAt: requireBoundedTimestamp(object.started_at),
    endedAt: requireNullableBoundedTimestamp(object.ended_at),
    ...(object.last_active !== undefined && {
      lastActive: requireBoundedTimestamp(object.last_active)
    }),
    ...(object.is_active !== undefined && { isActive: requireBoolean(object.is_active) }),
    messageCount: requireBoundedInteger(object.message_count, 0, 1_000_000_000),
    toolCallCount: requireBoundedInteger(object.tool_call_count, 0, 1_000_000_000),
    inputTokens: requireBoundedInteger(object.input_tokens, 0, 1_000_000_000),
    outputTokens: requireBoundedInteger(object.output_tokens, 0, 1_000_000_000),
    ...(object.preview !== undefined && {
      preview: requireNullableString(object.preview, MAX_TEXT_LENGTH)
    }),
    ...(object.parent_session_id !== undefined && {
      parentSessionId: requireNullableSessionId(object.parent_session_id)
    }),
    ...(object.archived !== undefined && { archived: requireSessionFlag(object.archived) }),
    ...(object.pinned !== undefined && { pinned: requireSessionFlag(object.pinned) }),
    ...(object.profile !== undefined && {
      profile: requireBoundedString(object.profile, MAX_SHORT_TEXT_LENGTH)
    }),
    ...(object.is_default_profile !== undefined && {
      isDefaultProfile: requireBoolean(object.is_default_profile)
    })
  };
}

function validateSessionMessages(value: StrictJsonValue): SessionMessages {
  const object = requireObject(value, ['session_id', 'messages', 'pagination']);
  const messages = requireArray(object.messages, MAX_MESSAGE_COUNT).map(validateMessage);
  const pagination = requireObject(object.pagination, ['limit', 'offset', 'returned']);
  const returned = requireBoundedInteger(pagination.returned, 0, MAX_MESSAGE_COUNT);

  if (returned !== messages.length) {
    throw new LiveRestError('invalid-response');
  }

  // Hermes may resolve aliases or continuation sessions before returning the
  // canonical ID. Validate the returned identifier independently instead of
  // requiring it to equal the literal path segment supplied by the caller.
  const sessionId = requireSessionId(requireString(object.session_id, MAX_ID_LENGTH));

  return {
    sessionId,
    messages,
    pagination: {
      limit: pagination.limit === null ? null : requireBoundedInteger(pagination.limit, 1, MAX_MESSAGE_COUNT),
      offset: requireBoundedInteger(pagination.offset, 0, 1_000_000),
      returned
    }
  };
}

function validateMessage(value: StrictJsonValue): LiveMessage {
  const object = requireObject(value, ['role', 'content']);
  const role = requireString(object.role, MAX_SHORT_TEXT_LENGTH);
  if (role !== 'user' && role !== 'assistant' && role !== 'system' && role !== 'tool') {
    throw new LiveRestError('invalid-response');
  }

  return {
    role,
    content: requireMessageContent(object.content),
    ...(object.tool_calls !== undefined && { toolCalls: requireToolCalls(object.tool_calls) }),
    ...(object.tool_name !== undefined && {
      toolName: requireNullableString(object.tool_name, MAX_SHORT_TEXT_LENGTH)
    }),
    ...(object.tool_call_id !== undefined && {
      toolCallId: requireNullableString(object.tool_call_id, MAX_ID_LENGTH)
    }),
    ...(object.timestamp !== undefined && {
      timestamp: requireBoundedTimestamp(object.timestamp)
    })
  };
}

function requireObject(
  value: StrictJsonValue,
  requiredKeys: string[]
): { [key: string]: StrictJsonValue } {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new LiveRestError('invalid-response');
  }

  // C-01 permits additive server fields. The bounded parser has already
  // accounted for their bytes, depth, nodes, and scalar limits; this projection
  // reads only reviewed semantics and never copies unknown data into models.
  const object = value as { [key: string]: StrictJsonValue };
  for (const key of requiredKeys) {
    if (!(key in object)) {
      throw new LiveRestError('invalid-response');
    }
  }
  return object;
}

function requireArray(value: StrictJsonValue, maxLength: number): StrictJsonValue[] {
  if (!Array.isArray(value) || value.length > maxLength) {
    throw new LiveRestError('invalid-response');
  }
  return value;
}

function requireString(value: StrictJsonValue, maxLength: number): string {
  // Empty strings are rejected only where the reviewed local contract assigns
  // identifier semantics. Source-defined display and metadata strings use the
  // bounded validator below because the pinned TypeScript types permit empty.
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength) {
    throw new LiveRestError('invalid-response');
  }
  return value;
}

function requireBoundedString(value: StrictJsonValue, maxLength: number): string {
  if (typeof value !== 'string' || value.length > maxLength) {
    throw new LiveRestError('invalid-response');
  }
  return value;
}

function requireNullableString(value: StrictJsonValue, maxLength: number): string | null {
  if (value === null) {
    return null;
  }
  return requireBoundedString(value, maxLength);
}

function requireNullableBoundedInteger(value: StrictJsonValue, min: number, max: number): number | null {
  if (value === null) {
    return null;
  }
  return requireBoundedInteger(value, min, max);
}

function requireNullableBoundedTimestamp(value: StrictJsonValue): number | null {
  if (value === null) return null;
  return requireBoundedTimestamp(value);
}

/**
 * Hermes stores Unix seconds with sub-second precision. Counts and pagination
 * remain integers, while timestamp fields accept only finite bounded numbers.
 */
function requireBoundedTimestamp(value: StrictJsonValue): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > MAX_UNIX_SECONDS) {
    throw new LiveRestError('invalid-response');
  }
  return value;
}

function requireMessageContent(value: StrictJsonValue): LiveMessageContent {
  if (value === null) {
    return null;
  }
  return requireBoundedString(value, MAX_TEXT_LENGTH);
}

function requireToolCalls(value: StrictJsonValue): LiveToolCalls {
  // The official history route emits null when a message has no tool calls.
  // Preserve that source representation; only non-null arrays are projected.
  if (value === null) {
    return null;
  }

  return requireArray(value, MAX_TOOL_CALL_COUNT).map((toolCall) => {
    const object = requireObject(toolCall, ['id', 'function']);
    const functionObject = requireObject(object.function, ['name', 'arguments']);
    return {
      id: requireBoundedString(object.id, MAX_ID_LENGTH),
      function: {
        name: requireBoundedString(functionObject.name, MAX_SHORT_TEXT_LENGTH),
        arguments: requireBoundedString(functionObject.arguments, MAX_TEXT_LENGTH)
      }
    };
  });
}

function requireSessionId(value: string): string {
  try {
    return validateSessionId(value);
  } catch {
    throw new LiveRestError('invalid-response');
  }
}

function requireNullableSessionId(value: StrictJsonValue): string | null {
  if (value === null) {
    return null;
  }
  return requireSessionId(requireString(value, MAX_ID_LENGTH));
}

function requireBoolean(value: StrictJsonValue): boolean {
  if (typeof value !== 'boolean') {
    throw new LiveRestError('invalid-response');
  }
  return value;
}

/**
 * Session list responses expose archive/pin flags as booleans, while raw detail
 * rows expose the SQLite INTEGER representation. Accept only those two
 * source-backed encodings and never apply JavaScript truthiness to arbitrary
 * numbers or strings.
 */
function requireSessionFlag(value: StrictJsonValue): boolean {
  if (typeof value === 'boolean') {
    return value;
  }
  if (value === 0) {
    return false;
  }
  if (value === 1) {
    return true;
  }
  throw new LiveRestError('invalid-response');
}

function requireBoundedInteger(value: StrictJsonValue, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) {
    throw new LiveRestError('invalid-response');
  }
  return value;
}

function messageFor(code: LiveRestErrorCode, status?: number): string {
  switch (code) {
    case 'aborted':
      return 'The same-origin REST request was cancelled.';
    case 'timeout':
      return 'The same-origin REST request timed out.';
    case 'network':
      return 'The same-origin REST request could not be completed.';
    case 'redirect':
      return 'The same-origin REST request received a redirect.';
    case 'http':
      return `The same-origin REST request failed with HTTP ${status ?? 0}.`;
    case 'provider-unavailable':
      return 'No reviewed authentication provider is available.';
    case 'unauthenticated':
      return 'The Dashboard session is not authenticated.';
    case 'not-found':
      return 'The requested server session was not found.';
    case 'body-too-large':
      return 'The REST response exceeded the bounded body limit.';
    case 'malformed-json':
      return 'The REST response was not valid bounded JSON.';
    case 'invalid-response':
      return 'The REST response did not match the reviewed bounded projection.';
    case 'invalid-url':
      return 'The REST transport rejected a non-same-origin API URL.';
    case 'invalid-session-id':
      return 'The session identifier is not a valid opaque path segment.';
    case 'invalid-options':
      return 'The REST transport options are outside the reviewed bounds.';
  }
}
