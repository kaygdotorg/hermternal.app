import { parseStrictJson, StrictJsonError, type StrictJsonValue } from './strict-json';
import type {
  AuthIdentity,
  LiveMessage,
  LiveProvider,
  LiveSession,
  MessageListOptions,
  ProviderDiscovery,
  SessionList,
  SessionListOptions,
  SessionMessages
} from './live-rest-types';

const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_BODY_BYTES = 128 * 1024;
const MAX_BODY_BYTES = 1024 * 1024;
const MAX_PROVIDER_COUNT = 32;
const MAX_SESSION_COUNT = 100;
const MAX_MESSAGE_COUNT = 500;
const MAX_ID_LENGTH = 128;
const MAX_TEXT_LENGTH = 8_192;
const MAX_SHORT_TEXT_LENGTH = 512;
const API_ROOT = '/api';

const SESSION_ID_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9._~-]{0,126}[A-Za-z0-9])?$/u;
const PROVIDER_NAME_MAX_LENGTH = 96;

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
  /** Must resolve to the current origin and the exact `/api` root. */
  apiBaseUrl?: string;
  /** Test-only origin context for validating an absolute same-origin base URL. */
  origin?: string;
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
  const apiBaseUrl = normalizeApiBaseUrl(options.apiBaseUrl, options.origin);

  async function request<T>(
    path: string,
    validator: (value: StrictJsonValue) => T,
    signal?: AbortSignal
  ): Promise<T> {
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

      if (response.redirected || response.type === 'opaqueredirect' || response.type === 'opaque') {
        throw new LiveRestError('redirect');
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

  return {
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

    getSession(sessionId: string, signal?: AbortSignal): Promise<LiveSession> {
      return request(`/sessions/${encodeSessionId(sessionId)}`, validateSession, signal);
    },

    getSessionMessages(
      sessionId: string,
      options: MessageListOptions = {},
      signal?: AbortSignal
    ): Promise<SessionMessages> {
      const query = buildPaginationQuery(options, MAX_MESSAGE_COUNT);
      return request(
        `/sessions/${encodeSessionId(sessionId)}/messages${query}`,
        validateSessionMessages,
        signal
      );
    }
  };
}

/** Alias retained so callers can name the reviewed boundary by its domain role. */
export const createLiveTransport = createLiveRestTransport;

export function validateSessionId(sessionId: string): string {
  if (typeof sessionId !== 'string' || !SESSION_ID_PATTERN.test(sessionId)) {
    throw new LiveRestError('invalid-session-id');
  }
  return sessionId;
}

export function normalizeApiBaseUrl(value = API_ROOT, origin = currentOrigin()): string {
  if (typeof value !== 'string' || value.length === 0 || value.includes('?') || value.includes('#')) {
    throw new LiveRestError('invalid-url');
  }

  if (value === API_ROOT || value === `${API_ROOT}/`) {
    return API_ROOT;
  }

  if (!origin || value.startsWith('//') || !/^[a-z][a-z\d+.-]*:/iu.test(value)) {
    throw new LiveRestError('invalid-url');
  }

  let candidate: URL;
  let expectedOrigin: URL;
  try {
    candidate = new URL(value, origin);
    expectedOrigin = new URL(origin);
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

function encodeSessionId(sessionId: string): string {
  return encodeURIComponent(validateSessionId(sessionId));
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
    return new LiveRestError('unauthenticated', response.status);
  }

  const expectedDetail =
    response.status === 404 && path.startsWith('/sessions/')
      ? 'Session not found'
      : response.status === 503 && path === '/auth/providers'
        ? 'no auth providers registered'
        : undefined;

  if (expectedDetail === undefined) {
    return new LiveRestError('http', response.status);
  }

  const body = await readBoundedBody(response, maxBodyBytes, abortPromise, abortError);
  let parsed: StrictJsonValue;
  try {
    parsed = parseStrictJson(body);
  } catch {
    throw new LiveRestError('malformed-json');
  }

  const object = requireObject(parsed, ['detail'], ['detail']);
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
  if (response.body) {
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;

    try {
      while (true) {
        const result = await Promise.race([reader.read(), abortPromise]);
        if (result.done) {
          break;
        }

        const value = result.value as Uint8Array | undefined;
        if (!value || typeof value.byteLength !== 'number') {
          throw new LiveRestError('malformed-json');
        }

        const chunk = Uint8Array.from(value);
        total += chunk.byteLength;
        if (total > maxBodyBytes) {
          throw new LiveRestError('body-too-large');
        }
        chunks.push(chunk);
      }
    } catch (error) {
      if (error instanceof LiveRestError) {
        throw error;
      }
      const reason = abortError();
      if (reason) {
        throw reason;
      }
      throw new LiveRestError('network');
    } finally {
      reader.releaseLock();
    }

    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }

    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
      throw new LiveRestError('malformed-json');
    }
  }

  try {
    const text = await Promise.race([response.text(), abortPromise]);
    const bytes = new TextEncoder().encode(text);
    if (bytes.byteLength > maxBodyBytes) {
      throw new LiveRestError('body-too-large');
    }
    return text;
  } catch (error) {
    if (error instanceof LiveRestError) {
      throw error;
    }
    const reason = abortError();
    if (reason) {
      throw reason;
    }
    throw new LiveRestError('network');
  }
}

function isSafeProviderName(value: string): boolean {
  if (value.length < 1 || value.length > PROVIDER_NAME_MAX_LENGTH) {
    return false;
  }
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (codePoint === undefined || codePoint <= 0x1f || codePoint === 0x7f) {
      return false;
    }
  }
  return true;
}

function validateProviderDiscovery(value: StrictJsonValue): ProviderDiscovery {
  const object = requireObject(value, ['providers'], ['providers']);
  const providers = requireArray(object.providers, MAX_PROVIDER_COUNT);
  const seen = new Set<string>();

  return {
    providers: providers.map((provider) => {
      const item = requireObject(provider, ['name', 'display_name', 'supports_password'], [
        'name',
        'display_name',
        'supports_password'
      ]);
      const name = requireString(item.name, 96);
      if (!isSafeProviderName(name) || seen.has(name)) {
        throw new LiveRestError('invalid-response');
      }
      seen.add(name);
      return {
        name,
        displayName: requireString(item.display_name, MAX_SHORT_TEXT_LENGTH),
        supportsPassword: requireBoolean(item.supports_password)
      } satisfies LiveProvider;
    })
  };
}

function validateAuthIdentity(value: StrictJsonValue): AuthIdentity {
  const object = requireObject(
    value,
    ['user_id', 'email', 'display_name', 'org_id', 'provider', 'expires_at'],
    ['user_id', 'email', 'display_name', 'org_id', 'provider', 'expires_at']
  );

  return {
    userId: requireString(object.user_id, MAX_SHORT_TEXT_LENGTH),
    email: requireNullableString(object.email, MAX_SHORT_TEXT_LENGTH),
    displayName: requireNullableString(object.display_name, MAX_SHORT_TEXT_LENGTH),
    organizationId: requireNullableString(object.org_id, MAX_SHORT_TEXT_LENGTH),
    provider: requireString(object.provider, MAX_SHORT_TEXT_LENGTH),
    expiresAt: requireNullableString(object.expires_at, MAX_SHORT_TEXT_LENGTH)
  };
}

function validateSessionList(value: StrictJsonValue): SessionList {
  const object = requireObject(value, ['sessions', 'total', 'limit', 'offset'], [
    'sessions',
    'total',
    'limit',
    'offset'
  ]);
  const sessions = requireArray(object.sessions, MAX_SESSION_COUNT).map(validateSession);
  const total = requireBoundedInteger(object.total, 0, 1_000_000_000);
  const limit = requireBoundedInteger(object.limit, 1, MAX_SESSION_COUNT);
  const offset = requireBoundedInteger(object.offset, 0, 1_000_000);

  return { sessions, total, limit, offset };
}

function validateSession(value: StrictJsonValue): LiveSession {
  const object = requireObject(value, [
    'id',
    'title',
    'preview',
    'source',
    'model',
    'started_at',
    'ended_at',
    'last_active',
    'parent_session_id',
    'message_count',
    'tool_call_count',
    'input_tokens',
    'output_tokens',
    'is_active',
    'archived',
    'pinned',
    'profile',
    'is_default_profile'
  ], ['id']);

  return {
    id: requireSessionId(requireString(object.id, MAX_ID_LENGTH)),
    ...(object.title !== undefined && { title: requireNullableString(object.title, MAX_TEXT_LENGTH) }),
    ...(object.preview !== undefined && {
      preview: requireNullableString(object.preview, MAX_TEXT_LENGTH)
    }),
    ...(object.source !== undefined && { source: requireNullableString(object.source, MAX_SHORT_TEXT_LENGTH) }),
    ...(object.model !== undefined && { model: requireNullableString(object.model, MAX_SHORT_TEXT_LENGTH) }),
    ...(object.started_at !== undefined && {
      startedAt: requireNullableString(object.started_at, MAX_SHORT_TEXT_LENGTH)
    }),
    ...(object.ended_at !== undefined && {
      endedAt: requireNullableString(object.ended_at, MAX_SHORT_TEXT_LENGTH)
    }),
    ...(object.last_active !== undefined && {
      lastActive: requireNullableString(object.last_active, MAX_SHORT_TEXT_LENGTH)
    }),
    ...(object.parent_session_id !== undefined && {
      parentSessionId: requireNullableSessionId(object.parent_session_id)
    }),
    ...(object.message_count !== undefined && {
      messageCount: requireBoundedInteger(object.message_count, 0, 1_000_000_000)
    }),
    ...(object.tool_call_count !== undefined && {
      toolCallCount: requireBoundedInteger(object.tool_call_count, 0, 1_000_000_000)
    }),
    ...(object.input_tokens !== undefined && {
      inputTokens: requireBoundedInteger(object.input_tokens, 0, 1_000_000_000)
    }),
    ...(object.output_tokens !== undefined && {
      outputTokens: requireBoundedInteger(object.output_tokens, 0, 1_000_000_000)
    }),
    ...(object.is_active !== undefined && { isActive: requireBoolean(object.is_active) }),
    ...(object.archived !== undefined && { archived: requireBoolean(object.archived) }),
    ...(object.pinned !== undefined && { pinned: requireBoolean(object.pinned) }),
    ...(object.profile !== undefined && { profile: requireString(object.profile, MAX_SHORT_TEXT_LENGTH) }),
    ...(object.is_default_profile !== undefined && {
      isDefaultProfile: requireBoolean(object.is_default_profile)
    })
  };
}

function validateSessionMessages(value: StrictJsonValue): SessionMessages {
  const object = requireObject(value, ['session_id', 'messages', 'pagination'], [
    'session_id',
    'messages',
    'pagination'
  ]);
  const messages = requireArray(object.messages, MAX_MESSAGE_COUNT).map(validateMessage);
  const pagination = requireObject(object.pagination, ['limit', 'offset', 'returned'], [
    'limit',
    'offset',
    'returned'
  ]);
  const returned = requireBoundedInteger(pagination.returned, 0, MAX_MESSAGE_COUNT);

  if (returned !== messages.length) {
    throw new LiveRestError('invalid-response');
  }

  return {
    sessionId: requireSessionId(requireString(object.session_id, MAX_ID_LENGTH)),
    messages,
    pagination: {
      limit: pagination.limit === null ? null : requireBoundedInteger(pagination.limit, 1, MAX_MESSAGE_COUNT),
      offset: requireBoundedInteger(pagination.offset, 0, 1_000_000),
      returned
    }
  };
}

function validateMessage(value: StrictJsonValue): LiveMessage {
  const object = requireObject(value, ['id', 'role', 'content'], ['id', 'role', 'content']);
  const role = requireString(object.role, MAX_SHORT_TEXT_LENGTH);
  if (role !== 'user' && role !== 'assistant' && role !== 'system' && role !== 'tool') {
    throw new LiveRestError('invalid-response');
  }

  return {
    id: requireString(object.id, MAX_ID_LENGTH),
    role,
    content: requireString(object.content, MAX_TEXT_LENGTH)
  };
}

function requireObject(
  value: StrictJsonValue,
  allowedKeys: string[],
  requiredKeys: string[]
): { [key: string]: StrictJsonValue } {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new LiveRestError('invalid-response');
  }

  const object = value as { [key: string]: StrictJsonValue };
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(object)) {
    if (!allowed.has(key)) {
      throw new LiveRestError('invalid-response');
    }
  }
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
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength) {
    throw new LiveRestError('invalid-response');
  }
  return value;
}

function requireNullableString(value: StrictJsonValue, maxLength: number): string | null {
  if (value === null) {
    return null;
  }
  return requireString(value, maxLength);
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
      return 'The REST response did not match the reviewed schema.';
    case 'invalid-url':
      return 'The REST transport rejected a non-same-origin API URL.';
    case 'invalid-session-id':
      return 'The session identifier is not a valid opaque path segment.';
    case 'invalid-options':
      return 'The REST transport options are outside the reviewed bounds.';
  }
}
