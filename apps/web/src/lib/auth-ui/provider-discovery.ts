import type { AuthProvider } from './types';

export const PROVIDER_DISCOVERY_PATH = '/api/auth/providers';
export const DEFAULT_PROVIDER_DISCOVERY_TIMEOUT_MS = 10_000;
export const DEFAULT_PROVIDER_DISCOVERY_MAX_BODY_BYTES = 128 * 1024;

const MAX_TIMEOUT_MS = 30_000;
const MAX_BODY_BYTES = 1024 * 1024;
const MAX_PROVIDER_COUNT = 32;
const MAX_ID_LENGTH = 96;
const MAX_DISPLAY_NAME_LENGTH = 512;
const MAX_JSON_DEPTH = 16;
const MAX_JSON_NODES = 4_096;
const MAX_JSON_STRING_LENGTH = 8_192;
const MAX_JSON_ARRAY_LENGTH = 500;
const MAX_JSON_OBJECT_KEYS = 64;
// Stream cleanup is bounded so an injected response cannot keep auth
// discovery pending after headers have already failed closed.
const RESPONSE_CANCEL_TIMEOUT_MS = 100;
const PROVIDER_NAME_FORBIDDEN_PATTERN = /[\s/\\\p{C}]/u;
const PROVIDER_CONTROL_PATTERN = /\p{C}/u;
const PROVIDER_ENVELOPE_KEYS = ['providers'] as const;
const PROVIDER_ROW_KEYS = ['display_name', 'name', 'supports_password'] as const;
const PROVIDER_UNAVAILABLE_KEYS = ['detail'] as const;

export type ProviderDiscoveryErrorCode =
  | 'aborted'
  | 'timeout'
  | 'network'
  | 'redirect'
  | 'http'
  | 'provider-unavailable'
  | 'body-too-large'
  | 'malformed-json'
  | 'invalid-response'
  | 'invalid-options';

export class ProviderDiscoveryError extends Error {
  readonly code: ProviderDiscoveryErrorCode;
  readonly status?: number;

  constructor(code: ProviderDiscoveryErrorCode, status?: number) {
    super(messageFor(code));
    this.name = 'ProviderDiscoveryError';
    this.code = code;
    this.status = status;
  }
}

export type ProviderDiscoveryFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export interface ProviderDiscoveryOptions {
  fetch?: ProviderDiscoveryFetch;
  signal?: AbortSignal;
  timeoutMs?: number;
  maxBodyBytes?: number;
}

export interface ProviderDiscoveryResult {
  providers: AuthProvider[];
}

/**
 * This adapter is intentionally local to auth-ui while the reviewed W-06
 * transport remains a separate stack. It mirrors the reviewed GET boundary:
 * relative same-origin path, cookie-only credentials, no-store cache, strict
 * bounded JSON, and a projection that never copies unknown response fields.
 */
export async function discoverProviders(options: ProviderDiscoveryOptions = {}): Promise<ProviderDiscoveryResult> {
  const fetcher = options.fetch ?? globalThis.fetch?.bind(globalThis);
  if (!fetcher) throw new ProviderDiscoveryError('network');

  const timeoutMs = normalizeTimeout(options.timeoutMs);
  const maxBodyBytes = normalizeBodyLimit(options.maxBodyBytes);
  if (options.signal?.aborted) {
    throw new ProviderDiscoveryError('aborted');
  }

  const controller = new AbortController();
  let abortCode: 'aborted' | 'timeout' | undefined;
  let rejectAbort: ((error: ProviderDiscoveryError) => void) | undefined;
  const abortPromise = new Promise<never>((_, reject) => {
    rejectAbort = reject;
  });

  const abort = (code: 'aborted' | 'timeout'): void => {
    if (abortCode) return;
    abortCode = code;
    const error = new ProviderDiscoveryError(code);
    controller.abort(error);
    rejectAbort?.(error);
  };

  const onCallerAbort = (): void => abort('aborted');
  options.signal?.addEventListener('abort', onCallerAbort, { once: true });
  const timeout = setTimeout(() => abort('timeout'), timeoutMs);

  try {
    const response = await Promise.race([
      fetcher(PROVIDER_DISCOVERY_PATH, {
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
      throw new ProviderDiscoveryError('redirect', response.status);
    }

    if (response.status !== 200) {
      throw await classifyHttpResponse(response, maxBodyBytes, abortPromise, controller.signal);
    }

    if (!hasJsonContentType(response)) {
      await cancelResponseBody(response);
      throw new ProviderDiscoveryError('invalid-response', response.status);
    }

    const body = await Promise.race([readBoundedBody(response, maxBodyBytes, controller.signal), abortPromise]);
    let parsed: unknown;
    try {
      parsed = parseStrictJson(body);
    } catch (error) {
      if (error instanceof ProviderDiscoveryError) throw error;
      throw new ProviderDiscoveryError('malformed-json');
    }

    return { providers: mapProviderEnvelope(parsed) };
  } catch (error) {
    if (error instanceof ProviderDiscoveryError) throw error;
    if (abortCode) throw new ProviderDiscoveryError(abortCode);
    throw new ProviderDiscoveryError('network');
  } finally {
    clearTimeout(timeout);
    options.signal?.removeEventListener('abort', onCallerAbort);
  }
}

async function classifyHttpResponse(
  response: Response,
  maxBodyBytes: number,
  abortPromise: Promise<never>,
  signal: AbortSignal
): Promise<ProviderDiscoveryError> {
  if (response.status === 503) {
    if (!hasJsonContentType(response)) {
      await cancelResponseBody(response);
      return new ProviderDiscoveryError('invalid-response', response.status);
    }

    const body = await Promise.race([readBoundedBody(response, maxBodyBytes, signal), abortPromise]);
    let parsed: unknown;
    try {
      parsed = parseStrictJson(body);
    } catch {
      return new ProviderDiscoveryError('malformed-json', response.status);
    }

    if (
      isRecord(parsed) &&
      hasExactKeys(parsed, PROVIDER_UNAVAILABLE_KEYS) &&
      parsed.detail === 'no auth providers registered'
    ) {
      return new ProviderDiscoveryError('provider-unavailable', response.status);
    }

    return new ProviderDiscoveryError('invalid-response', response.status);
  }

  await cancelResponseBody(response);
  return new ProviderDiscoveryError('http', response.status);
}

function mapProviderEnvelope(value: unknown): AuthProvider[] {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, PROVIDER_ENVELOPE_KEYS) ||
    !Array.isArray(value.providers) ||
    value.providers.length === 0 ||
    value.providers.length > MAX_PROVIDER_COUNT
  ) {
    throw new ProviderDiscoveryError('invalid-response');
  }

  const seen = new Set<string>();
  return value.providers.map((candidate) => {
    if (!isRecord(candidate) || !hasExactKeys(candidate, PROVIDER_ROW_KEYS)) {
      throw new ProviderDiscoveryError('invalid-response');
    }

    const name = candidate.name;
    const displayName = candidate.display_name;
    const supportsPassword = candidate.supports_password;
    if (
      typeof name !== 'string' ||
      name.length === 0 ||
      name.length > MAX_ID_LENGTH ||
      !isSafeProviderName(name) ||
      seen.has(name) ||
      typeof displayName !== 'string' ||
      displayName.length === 0 ||
      displayName.length > MAX_DISPLAY_NAME_LENGTH ||
      PROVIDER_CONTROL_PATTERN.test(displayName) ||
      typeof supportsPassword !== 'boolean'
    ) {
      throw new ProviderDiscoveryError('invalid-response');
    }

    seen.add(name);
    return {
      id: name,
      name: displayName,
      monogram: displayName.slice(0, 1).toUpperCase() || '?',
      // The pinned route exposes password capability only. A false value must
      // not be relabeled as OAuth without a separate reviewed capability.
      kind: supportsPassword ? 'password' : 'unavailable',
      description: supportsPassword
        ? 'Username and password supported'
        : 'Provider reported without a reviewed browser sign-in capability'
    } satisfies AuthProvider;
  });
}

function isSafeProviderName(value: string): boolean {
  const lowerCaseIdentity = value === value.toLowerCase();
  const upperLower = value.toUpperCase().toLowerCase();
  const stableCaseFold = value === upperLower || value.replaceAll('ı', 'i') === upperLower;
  return lowerCaseIdentity && stableCaseFold && !PROVIDER_NAME_FORBIDDEN_PATTERN.test(value);
}

function hasJsonContentType(response: Response): boolean {
  const contentType = response.headers.get('content-type');
  return contentType?.split(';', 1)[0].trim().toLowerCase() === 'application/json';
}

async function readBoundedBody(response: Response, maxBodyBytes: number, signal: AbortSignal): Promise<string> {
  const declaredLength = response.headers.get('content-length');
  if (declaredLength !== null) {
    if (!/^\d+$/u.test(declaredLength)) {
      await cancelResponseBody(response);
      throw new ProviderDiscoveryError('invalid-response');
    }
    if (Number(declaredLength) > maxBodyBytes) {
      await cancelResponseBody(response);
      throw new ProviderDiscoveryError('body-too-large');
    }
  }

  const bodyAbort = createBodyAbort(signal);
  if (!response.body) {
    try {
      // `Response.text()` has no native signal parameter. Race it with the same
      // operation signal so a synthetic no-body response cannot outlive a caller
      // cancellation or deadline.
      const text = await Promise.race([response.text(), bodyAbort.promise]);
      if (new TextEncoder().encode(text).byteLength > maxBodyBytes) {
        throw new ProviderDiscoveryError('body-too-large');
      }
      return text;
    } finally {
      bodyAbort.cleanup();
    }
  }

  const reader = response.body.getReader();
  let cancelReader = false;
  const onAbort = (): void => {
    cancelReader = true;
    // An injected fetch may return a stream that is not wired to the request
    // signal. Cancel the active reader as well so abort and timeout still stop
    // response work instead of leaving an unbounded body open in the background.
    void reader.cancel().catch(() => undefined);
  };
  signal.addEventListener('abort', onAbort, { once: true });
  if (signal.aborted) onAbort();

  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const result = await Promise.race([reader.read(), bodyAbort.promise]);
      if (signal.aborted) throw providerAbortError(signal);
      if (result.done) break;
      const value = result.value;
      if (!value || !Number.isSafeInteger(value.byteLength) || value.byteLength < 0) {
        throw new ProviderDiscoveryError('invalid-response');
      }
      if (total + value.byteLength > maxBodyBytes) {
        throw new ProviderDiscoveryError('body-too-large');
      }
      total += value.byteLength;
      chunks.push(Uint8Array.from(value));
    }
  } catch (error) {
    cancelReader = true;
    if (error instanceof ProviderDiscoveryError) throw error;
    throw new ProviderDiscoveryError('network');
  } finally {
    bodyAbort.cleanup();
    signal.removeEventListener('abort', onAbort);
    if (cancelReader) await cancelReaderBounded(reader);
    else releaseReader(reader);
  }

  if (signal.aborted) throw providerAbortError(signal);
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new ProviderDiscoveryError('malformed-json');
  }
}

async function cancelResponseBody(response: Response): Promise<void> {
  if (!response.body) return;
  try {
    await cancelReaderBounded(response.body.getReader());
  } catch {
    // The response is already being rejected; a failed cleanup must not expose
    // an implementation detail or replace the bounded diagnostic.
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
    // The request already fails closed. Cleanup cannot replace its diagnostic.
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

function createBodyAbort(signal: AbortSignal): {
  promise: Promise<never>;
  cleanup: () => void;
} {
  let onAbort: (() => void) | undefined;
  const promise = signal.aborted
    ? Promise.reject<never>(providerAbortError(signal))
    : new Promise<never>((_, reject) => {
        onAbort = () => reject(providerAbortError(signal));
        signal.addEventListener('abort', onAbort, { once: true });
      });
  return {
    promise,
    cleanup: () => {
      if (onAbort) signal.removeEventListener('abort', onAbort);
    }
  };
}

function providerAbortError(signal: AbortSignal): ProviderDiscoveryError {
  return signal.reason instanceof ProviderDiscoveryError
    ? signal.reason
    : new ProviderDiscoveryError('aborted');
}

function normalizeTimeout(value: number | undefined): number {
  const timeoutMs = value ?? DEFAULT_PROVIDER_DISCOVERY_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TIMEOUT_MS) {
    throw new ProviderDiscoveryError('invalid-options');
  }
  return timeoutMs;
}

function normalizeBodyLimit(value: number | undefined): number {
  const maxBodyBytes = value ?? DEFAULT_PROVIDER_DISCOVERY_MAX_BODY_BYTES;
  if (!Number.isInteger(maxBodyBytes) || maxBodyBytes < 1 || maxBodyBytes > MAX_BODY_BYTES) {
    throw new ProviderDiscoveryError('invalid-options');
  }
  return maxBodyBytes;
}

type StrictJsonValue = null | boolean | number | string | StrictJsonValue[] | { [key: string]: StrictJsonValue };

function parseStrictJson(text: string): StrictJsonValue {
  const parser = new BoundedJsonParser(text);
  return parser.parse();
}

class BoundedJsonParser {
  private index = 0;
  private nodes = 0;

  constructor(private readonly text: string) {}

  parse(): StrictJsonValue {
    const value = this.parseValue(0);
    this.skipWhitespace();
    if (this.index !== this.text.length) throw new Error('trailing JSON');
    return value;
  }

  private parseValue(depth: number): StrictJsonValue {
    if (depth > MAX_JSON_DEPTH) throw new Error('JSON depth exceeded');
    this.countNode();
    this.skipWhitespace();
    const character = this.text[this.index];
    if (character === '{') return this.parseObject(depth + 1);
    if (character === '[') return this.parseArray(depth + 1);
    if (character === '"') return this.parseString();
    if (character === 't') return this.parseLiteral('true', true);
    if (character === 'f') return this.parseLiteral('false', false);
    if (character === 'n') return this.parseLiteral('null', null);
    return this.parseNumber();
  }

  private parseObject(depth: number): { [key: string]: StrictJsonValue } {
    this.expect('{');
    const result: { [key: string]: StrictJsonValue } = Object.create(null) as {
      [key: string]: StrictJsonValue;
    };
    const keys = new Set<string>();
    this.skipWhitespace();
    if (this.consume('}')) return result;

    while (true) {
      this.skipWhitespace();
      if (this.text[this.index] !== '"') throw new Error('object key expected');
      const key = this.parseString();
      if (keys.has(key)) throw new Error('duplicate object key');
      keys.add(key);
      if (keys.size > MAX_JSON_OBJECT_KEYS) throw new Error('object key limit exceeded');
      this.skipWhitespace();
      this.expect(':');
      result[key] = this.parseValue(depth);
      this.skipWhitespace();
      if (this.consume('}')) return result;
      this.expect(',');
    }
  }

  private parseArray(depth: number): StrictJsonValue[] {
    this.expect('[');
    const result: StrictJsonValue[] = [];
    this.skipWhitespace();
    if (this.consume(']')) return result;

    while (true) {
      if (result.length >= MAX_JSON_ARRAY_LENGTH) throw new Error('array length exceeded');
      result.push(this.parseValue(depth));
      this.skipWhitespace();
      if (this.consume(']')) return result;
      this.expect(',');
    }
  }

  private parseString(): string {
    const start = this.index;
    this.expect('"');
    let escaped = false;
    while (this.index < this.text.length) {
      const character = this.text[this.index];
      this.index += 1;
      if (escaped) {
        escaped = false;
        continue;
      }
      if (character === '\\') {
        escaped = true;
        continue;
      }
      if (character === '"') {
        const value = JSON.parse(this.text.slice(start, this.index)) as string;
        if (value.length > MAX_JSON_STRING_LENGTH) throw new Error('string length exceeded');
        return value;
      }
      if (character < ' ') throw new Error('control character in string');
    }
    throw new Error('unterminated string');
  }

  private parseLiteral<T extends null | boolean>(literal: string, value: T): T {
    if (this.text.slice(this.index, this.index + literal.length) !== literal) {
      throw new Error('invalid literal');
    }
    this.index += literal.length;
    return value;
  }

  private parseNumber(): number {
    const match = this.text.slice(this.index).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u);
    if (!match) throw new Error('invalid number');
    const value = Number(match[0]);
    if (!Number.isFinite(value) || (Number.isInteger(value) && Math.abs(value) > Number.MAX_SAFE_INTEGER)) {
      throw new Error('unsafe number');
    }
    this.index += match[0].length;
    return value;
  }

  private skipWhitespace(): void {
    // JSON permits only space, tab, carriage return, and line feed here. Using
    // JavaScript's broader `\s` class would silently accept non-JSON separators.
    while (true) {
      const character = this.text[this.index];
      if (character !== ' ' && character !== '\t' && character !== '\r' && character !== '\n') return;
      this.index += 1;
    }
  }

  private expect(character: string): void {
    if (this.text[this.index] !== character) throw new Error(`expected ${character}`);
    this.index += 1;
  }

  private consume(character: string): boolean {
    if (this.text[this.index] !== character) return false;
    this.index += 1;
    return true;
  }

  private countNode(): void {
    this.nodes += 1;
    if (this.nodes > MAX_JSON_NODES) throw new Error('node limit exceeded');
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(record: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(record).sort();
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

function messageFor(code: ProviderDiscoveryErrorCode): string {
  switch (code) {
    case 'aborted':
      return 'Provider discovery was cancelled.';
    case 'timeout':
      return 'Provider discovery timed out.';
    case 'network':
      return 'Provider discovery is unavailable.';
    case 'redirect':
      return 'Provider discovery returned an unsafe redirect.';
    case 'http':
      return 'Provider discovery returned an unusable response.';
    case 'provider-unavailable':
      return 'No provider registry is available.';
    case 'body-too-large':
      return 'Provider discovery returned an oversized response.';
    case 'malformed-json':
      return 'Provider discovery returned malformed data.';
    case 'invalid-response':
      return 'Provider discovery returned an incompatible response.';
    case 'invalid-options':
      return 'Provider discovery configuration is invalid.';
  }
}
