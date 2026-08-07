import { createLiveRestTransport, LiveRestError, type LiveRestFetch } from '$lib/transport/live-rest-transport';
import { parseStrictJson, type StrictJsonValue } from '$lib/transport/strict-json';
import type { AuthIdentity } from '$lib/transport/live-rest-types';

export const PASSWORD_LOGIN_PATH = '/auth/password-login';
export const LOGOUT_PATH = '/auth/logout';
export const AUTH_ME_PATH = '/api/auth/me';

const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_TIMEOUT_MS = 30_000;
const MAX_RESPONSE_BYTES = 2 * 1024;
// Stream cancellation is best effort. It must not keep a caller waiting after
// the bounded authentication operation has already been aborted.
const RESPONSE_CANCEL_TIMEOUT_MS = 100;
const MAX_PROVIDER_LENGTH = 96;
const MAX_USERNAME_LENGTH = 512;
const MAX_PASSWORD_LENGTH = 8_192;
const PROVIDER_PATTERN = /^[a-z0-9][a-z0-9._-]{0,95}$/u;

export type BrowserAuthErrorCode =
  | 'aborted'
  | 'timeout'
  | 'network'
  | 'busy'
  | 'invalid-input'
  | 'invalid-credentials'
  | 'provider-unavailable'
  | 'rate-limited'
  | 'invalid-response'
  | 'identity-unverified'
  | 'identity-failed'
  | 'logout-failed'
  | 'logout-unverified';

const ERROR_MESSAGES: Record<BrowserAuthErrorCode, string> = {
  aborted: 'Authentication was cancelled.',
  timeout: 'Authentication timed out.',
  network: 'Authentication is unavailable.',
  busy: 'An authentication action is already in progress.',
  'invalid-input': 'Authentication input is invalid.',
  'invalid-credentials': 'The username or password was not accepted.',
  'provider-unavailable': 'The selected authentication provider is unavailable.',
  'rate-limited': 'Too many sign-in attempts were made. Try again later.',
  'invalid-response': 'Authentication returned an incompatible response.',
  'identity-unverified': 'The authenticated identity could not be verified.',
  'identity-failed': 'The authentication identity check failed closed.',
  'logout-failed': 'The server session is still active.',
  'logout-unverified': 'Logout could not be verified.'
};

export function browserAuthErrorMessage(code: BrowserAuthErrorCode): string {
  return ERROR_MESSAGES[code];
}

export class BrowserAuthError extends Error {
  readonly code: BrowserAuthErrorCode;
  readonly status?: number;

  constructor(code: BrowserAuthErrorCode, status?: number) {
    super(ERROR_MESSAGES[code]);
    this.name = code === 'aborted' ? 'AbortError' : 'BrowserAuthError';
    this.code = code;
    this.status = Number.isInteger(status) && status! >= 0 && status! <= 599 ? status : undefined;
  }
}

export interface PasswordLoginInput {
  provider: string;
  username: string;
  password: string;
}

export interface PasswordLoginResult {
  identity: AuthIdentity;
  next: '/';
}

export interface BrowserAuthClient {
  verify(signal?: AbortSignal): Promise<AuthIdentity>;
  loginWithPassword(input: PasswordLoginInput, signal?: AbortSignal): Promise<PasswordLoginResult>;
  logout(signal?: AbortSignal): Promise<void>;
}

export interface BrowserAuthClientOptions {
  /** Optional only for deterministic tests; production uses browser fetch. */
  fetch?: LiveRestFetch;
  timeoutMs?: number;
}

/**
 * Browser-cookie authentication for the reviewed Hermes Dashboard routes.
 * Credentials exist only in the transient password request body. This client
 * never exposes response detail text or stores cookies, passwords, or tokens.
 */
export function createBrowserAuthClient(options: BrowserAuthClientOptions = {}): BrowserAuthClient {
  const fetcher = options.fetch ?? globalThis.fetch?.bind(globalThis);
  if (!fetcher) throw new BrowserAuthError('network');

  const timeoutMs = normalizeTimeout(options.timeoutMs);
  const rest = createLiveRestTransport({ fetch: fetcher, timeoutMs });
  let passwordActionActive = false;
  let activeLogout: Promise<void> | undefined;

  const verify = async (signal?: AbortSignal): Promise<AuthIdentity> => {
    try {
      return await rest.getAuthState(signal);
    } catch (error) {
      throw mapIdentityError(error);
    }
  };

  const loginWithPassword = async (input: PasswordLoginInput, signal?: AbortSignal): Promise<PasswordLoginResult> => {
    if (passwordActionActive || activeLogout) throw new BrowserAuthError('busy');
    const normalized = validatePasswordInput(input);
    passwordActionActive = true;

    try {
      const parsed = await requestWithDeadline(
        fetcher,
        PASSWORD_LOGIN_PATH,
        {
          method: 'POST',
          mode: 'same-origin',
          credentials: 'same-origin',
          cache: 'no-store',
          redirect: 'error',
          referrerPolicy: 'no-referrer',
          headers: {
            accept: 'application/json',
            'content-type': 'application/json'
          },
          body: JSON.stringify({ ...normalized, next: '/' })
        },
        timeoutMs,
        signal,
        async (response, responseSignal) => {
          if (isUnsafeResponse(response)) {
            await cancelBody(response);
            throw new BrowserAuthError('invalid-response', response.status);
          }
          if (response.status !== 200) {
            await cancelBody(response);
            throw mapPasswordStatus(response.status);
          }
          if (!hasJsonContentType(response)) {
            await cancelBody(response);
            throw new BrowserAuthError('invalid-response', response.status);
          }

          return parseResponse(await readBoundedResponse(response, responseSignal));
        }
      );
      const next = validatePasswordSuccess(parsed);
      let identity: AuthIdentity;
      try {
        identity = await verify(signal);
      } catch (error) {
        if (error instanceof BrowserAuthError) throw error;
        throw new BrowserAuthError('identity-failed');
      }
      return { identity, next };
    } finally {
      passwordActionActive = false;
    }
  };

  const logout = (signal?: AbortSignal): Promise<void> => {
    if (activeLogout) return activeLogout;
    if (passwordActionActive) return Promise.reject(new BrowserAuthError('busy'));

    const operation = performLogout(fetcher, rest.getAuthState, timeoutMs, signal).finally(() => {
      if (activeLogout === operation) activeLogout = undefined;
    });
    activeLogout = operation;
    return operation;
  };

  return { verify, loginWithPassword, logout };
}

async function performLogout(
  fetcher: LiveRestFetch,
  verifyIdentity: (signal?: AbortSignal) => Promise<AuthIdentity>,
  timeoutMs: number,
  signal?: AbortSignal
): Promise<void> {
  let requestError: unknown;
  try {
    await requestWithDeadline(
      fetcher,
      LOGOUT_PATH,
      {
        method: 'POST',
        mode: 'same-origin',
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'manual',
        referrerPolicy: 'no-referrer',
        headers: { accept: 'application/json' }
      },
      timeoutMs,
      signal,
      async (response) => {
        if (
          response.redirected ||
          response.type === 'opaqueredirect' ||
          response.type === 'opaque' ||
          response.status !== 302 ||
          response.headers.get('location') !== '/login'
        ) {
          await cancelBody(response);
          throw new BrowserAuthError('invalid-response', response.status);
        }
        await cancelBody(response);
      }
    );
  } catch (error) {
    requestError = error;
  }

  if (signal?.aborted) throw new BrowserAuthError('aborted');
  if (requestError instanceof BrowserAuthError && requestError.code === 'invalid-response') {
    // A response that violates the reviewed manual-redirect contract is not an
    // ambiguous transport outcome. Fail closed even if a later probe is stale.
    throw requestError;
  }

  // Logout returns a manual redirect. The identity probe is the authority for
  // success, including ambiguous network and redirect outcomes.
  try {
    await verifyIdentity(signal);
  } catch (error) {
    if (error instanceof LiveRestError && error.code === 'unauthenticated' && error.status === 401) return;
    if (error instanceof LiveRestError && error.code === 'aborted') throw new BrowserAuthError('aborted');
    throw new BrowserAuthError('logout-unverified');
  }

  if (requestError instanceof BrowserAuthError && requestError.code === 'aborted') throw requestError;
  throw new BrowserAuthError('logout-failed');
}

async function requestWithDeadline<T>(
  fetcher: LiveRestFetch,
  path: string,
  init: RequestInit,
  timeoutMs: number,
  signal: AbortSignal | undefined,
  consume: (response: Response, signal: AbortSignal) => Promise<T>
): Promise<T> {
  if (signal?.aborted) throw new BrowserAuthError('aborted');

  const controller = new AbortController();
  let abortError: BrowserAuthError | undefined;
  let rejectAbort: ((error: BrowserAuthError) => void) | undefined;
  const abortPromise = new Promise<never>((_, reject) => {
    rejectAbort = reject;
  });
  const abort = (code: 'aborted' | 'timeout'): void => {
    if (abortError) return;
    abortError = new BrowserAuthError(code);
    controller.abort(abortError);
    rejectAbort?.(abortError);
  };
  const onCallerAbort = (): void => abort('aborted');
  signal?.addEventListener('abort', onCallerAbort, { once: true });
  const timeout = setTimeout(() => abort('timeout'), timeoutMs);

  try {
    const response = await Promise.race([
      fetcher(path, { ...init, signal: controller.signal }),
      abortPromise
    ]);
    return await consume(response, controller.signal);
  } catch (error) {
    if (error instanceof BrowserAuthError) throw error;
    if (abortError) throw abortError;
    throw new BrowserAuthError('network');
  } finally {
    clearTimeout(timeout);
    signal?.removeEventListener('abort', onCallerAbort);
  }
}

function validatePasswordInput(input: PasswordLoginInput): PasswordLoginInput {
  if (
    !input ||
    typeof input.provider !== 'string' ||
    !PROVIDER_PATTERN.test(input.provider) ||
    input.provider.length > MAX_PROVIDER_LENGTH ||
    typeof input.username !== 'string' ||
    input.username.length === 0 ||
    input.username.length > MAX_USERNAME_LENGTH ||
    containsForbiddenControl(input.username) ||
    typeof input.password !== 'string' ||
    input.password.length === 0 ||
    input.password.length > MAX_PASSWORD_LENGTH ||
    containsForbiddenControl(input.password)
  ) {
    throw new BrowserAuthError('invalid-input');
  }
  return {
    provider: input.provider,
    username: input.username,
    password: input.password
  };
}

function containsForbiddenControl(value: string): boolean {
  return /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value);
}

function normalizeTimeout(value: number | undefined): number {
  const timeout = value ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isInteger(timeout) || timeout < 1 || timeout > MAX_TIMEOUT_MS) {
    throw new BrowserAuthError('invalid-input');
  }
  return timeout;
}

function mapPasswordStatus(status: number): BrowserAuthError {
  if (status === 401) return new BrowserAuthError('invalid-credentials', status);
  if (status === 404 || status === 503) return new BrowserAuthError('provider-unavailable', status);
  if (status === 429) return new BrowserAuthError('rate-limited', status);
  return new BrowserAuthError('invalid-response', status);
}

function mapIdentityError(error: unknown): BrowserAuthError {
  if (error instanceof BrowserAuthError) {
    if (error.code === 'aborted') return error;
    if (error.code === 'identity-unverified' && error.status === 401) return error;
    return new BrowserAuthError('identity-failed', error.status);
  }
  if (error instanceof LiveRestError) {
    if (error.code === 'aborted') return new BrowserAuthError('aborted');
    if (error.code === 'unauthenticated' && error.status === 401) {
      return new BrowserAuthError('identity-unverified', error.status);
    }
    return new BrowserAuthError('identity-failed', error.status);
  }
  return new BrowserAuthError('identity-failed');
}

function isUnsafeResponse(response: Response): boolean {
  return (
    response.redirected ||
    (response.status >= 300 && response.status < 400) ||
    response.type === 'opaqueredirect' ||
    response.type === 'opaque'
  );
}

function hasJsonContentType(response: Response): boolean {
  return response.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() === 'application/json';
}

async function readBoundedResponse(response: Response, signal: AbortSignal): Promise<string> {
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > MAX_RESPONSE_BYTES)) {
    await cancelBody(response);
    throw new BrowserAuthError('invalid-response', response.status);
  }
  if (!response.body) throw new BrowserAuthError('invalid-response', response.status);

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let cancelReader = false;
  let rejectAbort: ((error: BrowserAuthError) => void) | undefined;
  const abortPromise = new Promise<never>((_, reject) => {
    rejectAbort = reject;
  });
  const onAbort = (): void => {
    cancelReader = true;
    void reader.cancel().catch(() => undefined);
    rejectAbort?.(browserAuthAbortError(signal));
  };
  signal.addEventListener('abort', onAbort, { once: true });

  try {
    if (signal.aborted) onAbort();
    while (true) {
      const result = await Promise.race([reader.read(), abortPromise]);
      const abortError = abortErrorFromSignal(signal);
      if (abortError) throw abortError;
      if (result.done) break;
      const value = result.value;
      if (!value || !Number.isSafeInteger(value.byteLength) || value.byteLength < 0) {
        throw new BrowserAuthError('invalid-response', response.status);
      }
      if (total + value.byteLength > MAX_RESPONSE_BYTES) {
        throw new BrowserAuthError('invalid-response', response.status);
      }
      total += value.byteLength;
      chunks.push(Uint8Array.from(value));
    }
    const abortError = abortErrorFromSignal(signal);
    if (abortError) throw abortError;
    if (declared !== null && Number(declared) !== total) {
      throw new BrowserAuthError('invalid-response', response.status);
    }
    const body = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      body.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return new TextDecoder('utf-8', { fatal: true }).decode(body);
  } catch (error) {
    cancelReader = true;
    if (error instanceof BrowserAuthError) throw error;
    const abortError = abortErrorFromSignal(signal);
    if (abortError) throw abortError;
    throw new BrowserAuthError('invalid-response', response.status);
  } finally {
    signal.removeEventListener('abort', onAbort);
    if (cancelReader) await cancelReaderBounded(reader);
    else releaseReader(reader);
  }
}

function parseResponse(text: string): StrictJsonValue {
  try {
    return parseStrictJson(text, {
      maxDepth: 4,
      maxNodes: 16,
      maxStringLength: 512,
      maxArrayLength: 1,
      maxObjectKeys: 4
    });
  } catch {
    throw new BrowserAuthError('invalid-response');
  }
}

function validatePasswordSuccess(value: StrictJsonValue): '/' {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new BrowserAuthError('invalid-response');
  }
  const keys = Object.keys(value);
  if (keys.length !== 2 || !keys.includes('ok') || !keys.includes('next') || value.ok !== true || value.next !== '/') {
    throw new BrowserAuthError('invalid-response');
  }
  return '/';
}

async function cancelBody(response: Response): Promise<void> {
  if (!response.body) return;
  try {
    await cancelReaderBounded(response.body.getReader());
  } catch {
    // Rejection diagnostics are closed; cleanup failure must not replace them.
  }
}

function abortErrorFromSignal(signal: AbortSignal): BrowserAuthError | undefined {
  if (!signal.aborted) return undefined;
  return signal.reason instanceof BrowserAuthError ? signal.reason : new BrowserAuthError('aborted');
}

function browserAuthAbortError(signal: AbortSignal): BrowserAuthError {
  return abortErrorFromSignal(signal) ?? new BrowserAuthError('aborted');
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
    // The response is already failing closed; cleanup cannot replace its error.
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
