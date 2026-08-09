import { webcrypto } from 'node:crypto';
import type { Page } from '@playwright/test';

const AUTH_PROOF_GLOBAL = '__hermternalNativeAuthProof';
const STORAGE_HMAC_KEY_GLOBAL = '__hermternalNativeAuthProofHmacKey';
const STORAGE_DATABASE = '__hermternal_native_auth_proof__';
const STORAGE_COOKIE = 'hermternal-native-auth-proof';
const STORAGE_LOCAL_KEY = 'hermternal-native-auth-proof';
const STORAGE_SESSION_KEY = 'hermternal-native-auth-proof';
const STORAGE_VALUE = 'seed';
const STORAGE_OVERWRITE_VALUE = 'overwrite';
const STORAGE_OBJECT_STORE = 'proof';
const STORAGE_OBJECT_KEY = 'same-key';

const STORAGE_HMAC_STATE_KIND = 'hermternal-storage-evidence-hmac-sha256-v2';
const STORAGE_HMAC_PROBE = 'hermternal-storage-evidence-hmac-probe-v2';
const STORAGE_EVIDENCE_RECORD_LIMIT = 2_048;
const STORAGE_EVIDENCE_CONTEXT_LIMIT = 1_024;
const STORAGE_EVIDENCE_DATABASE_LIMIT = 256;
const STORAGE_EVIDENCE_STORE_LIMIT = 256;

// Capture the object-inspection primordials once. Evidence is untrusted input;
// validation must not invoke attacker-controlled getters, inherited methods, or
// monkeypatched inspection functions before the shape is known to be safe.
const CAPTURED_OBJECT_CREATE = Object.create;
const CAPTURED_OBJECT_GET_PROTOTYPE_OF = Object.getPrototypeOf;
const CAPTURED_OBJECT_GET_OWN_PROPERTY_DESCRIPTOR = Object.getOwnPropertyDescriptor;
const CAPTURED_REFLECT_OWN_KEYS = Reflect.ownKeys;
const CAPTURED_OBJECT_PROTOTYPE = Object.prototype;
const CAPTURED_STRUCTURED_CLONE = typeof structuredClone === 'function'
  ? structuredClone.bind(globalThis)
  : undefined;
const STORAGE_EVIDENCE_KEYS = [
  'cryptoSupported',
  'status',
  'truncated',
  'readFailure',
  'recordCount',
  'digestCount',
  'recordLimit',
  'cookieCount',
  'localStorageEntryCount',
  'sessionStorageEntryCount',
  'indexedDbSupported',
  'indexedDbRecordCount',
  'indexedDbUnexpectedDatabaseCount',
  'indexedDbDatabaseCount',
  'indexedDbStoreCount',
  'cookieTruncated',
  'localStorageTruncated',
  'sessionStorageTruncated',
  'indexedDbTruncated',
  'truncation',
  'fingerprint'
] as const;
const STORAGE_TRUNCATION_KEYS = ['any', 'cookie', 'localStorage', 'sessionStorage', 'indexedDb'] as const;

type CapturedDataDescriptorFlags = {
  configurable: boolean;
  enumerable: boolean;
  writable: boolean;
};

type CapturedRecord = {
  values: Record<string, unknown>;
  descriptorFlags: Record<string, CapturedDataDescriptorFlags>;
};

/**
 * Storage evidence is a page-local, keyed digest. Raw values and failures never
 * cross the page boundary. A truncated or unsupported snapshot is never proof of
 * equality, even when its bounded metadata happens to match another snapshot.
 */
export type StorageEvidenceTruncation = {
  any: boolean;
  cookie: boolean;
  localStorage: boolean;
  sessionStorage: boolean;
  indexedDb: boolean;
};

type NullableStorageEvidenceTruncation = {
  any: null;
  cookie: null;
  localStorage: null;
  sessionStorage: null;
  indexedDb: null;
};

type StorageEvidenceFields = {
  truncated: boolean | null;
  readFailure: boolean | null;
  recordCount: number | null;
  digestCount: number | null;
  recordLimit: number | null;
  cookieCount: number | null;
  localStorageEntryCount: number | null;
  sessionStorageEntryCount: number | null;
  indexedDbSupported: boolean | null;
  indexedDbRecordCount: number | null;
  indexedDbUnexpectedDatabaseCount: number | null;
  indexedDbDatabaseCount: number | null;
  indexedDbStoreCount: number | null;
  cookieTruncated: boolean | null;
  localStorageTruncated: boolean | null;
  sessionStorageTruncated: boolean | null;
  indexedDbTruncated: boolean | null;
  truncation: StorageEvidenceTruncation | NullableStorageEvidenceTruncation;
  fingerprint: string | null;
};

type SupportedStorageEvidence = StorageEvidenceFields & {
  cryptoSupported: true;
  status: 'supported';
  truncated: false;
  readFailure: false;
  recordCount: number;
  digestCount: number;
  recordLimit: number;
  cookieCount: number;
  localStorageEntryCount: number;
  sessionStorageEntryCount: number;
  indexedDbSupported: true;
  indexedDbRecordCount: number;
  indexedDbUnexpectedDatabaseCount: 0;
  indexedDbDatabaseCount: number;
  indexedDbStoreCount: number;
  cookieTruncated: false;
  localStorageTruncated: false;
  sessionStorageTruncated: false;
  indexedDbTruncated: false;
  truncation: StorageEvidenceTruncation;
  fingerprint: string;
};

type TruncatedStorageEvidence = StorageEvidenceFields & {
  cryptoSupported: true;
  status: 'truncated';
  truncated: true;
  readFailure: false;
  recordCount: number | null;
  digestCount: null;
  recordLimit: number;
  cookieCount: number | null;
  localStorageEntryCount: number | null;
  sessionStorageEntryCount: number | null;
  indexedDbSupported: true | null;
  indexedDbRecordCount: number | null;
  indexedDbUnexpectedDatabaseCount: 0 | null;
  indexedDbDatabaseCount: number | null;
  indexedDbStoreCount: number | null;
  cookieTruncated: boolean | null;
  localStorageTruncated: boolean | null;
  sessionStorageTruncated: boolean | null;
  indexedDbTruncated: boolean | null;
  truncation: StorageEvidenceTruncation;
  fingerprint: null;
};

type UnsupportedStorageEvidence = StorageEvidenceFields & {
  cryptoSupported: false;
  status: 'unsupported';
  truncated: null;
  readFailure: true;
  recordCount: null;
  digestCount: null;
  recordLimit: null;
  cookieCount: null;
  localStorageEntryCount: null;
  sessionStorageEntryCount: null;
  indexedDbSupported: null;
  indexedDbRecordCount: null;
  indexedDbUnexpectedDatabaseCount: null;
  indexedDbDatabaseCount: null;
  indexedDbStoreCount: null;
  cookieTruncated: null;
  localStorageTruncated: null;
  sessionStorageTruncated: null;
  indexedDbTruncated: null;
  truncation: NullableStorageEvidenceTruncation;
  fingerprint: null;
};

type PageStorageEvidence = SupportedStorageEvidence | TruncatedStorageEvidence | UnsupportedStorageEvidence;
export type StorageEvidence = PageStorageEvidence;

export type StorageEvidenceFailureInjection =
  | 'crypto-unavailable'
  | 'random'
  | 'import-key'
  | 'probe-sign'
  | 'sign'
  | 'cookie-read'
  | 'cookie-sign'
  | 'local-storage-read'
  | 'session-storage-read'
  | 'idb-metadata'
  | 'idb-enumeration-unavailable'
  | 'idb-open'
  | 'idb-read'
  | 'canonicalization'
  | 'truncation';

export type StorageEvidenceReadOptions = {
  injectFailure?: StorageEvidenceFailureInjection;
};

export type NativeCredentialEvidence = {
  liveValueMatchCount: number;
  liveNonEmptyCount: number;
  defaultValueMatchCount: number;
  serializedCredentialCount: number;
  formDataEventCount: number;
  formDataConstructionCount: number;
  formDataCredentialEntryCount: number;
};

function emptyStorageEvidence(): UnsupportedStorageEvidence {
  return {
    cryptoSupported: false,
    status: 'unsupported',
    truncated: null,
    readFailure: true,
    recordCount: null,
    digestCount: null,
    recordLimit: null,
    cookieCount: null,
    localStorageEntryCount: null,
    sessionStorageEntryCount: null,
    indexedDbSupported: null,
    indexedDbRecordCount: null,
    indexedDbUnexpectedDatabaseCount: null,
    indexedDbDatabaseCount: null,
    indexedDbStoreCount: null,
    cookieTruncated: null,
    localStorageTruncated: null,
    sessionStorageTruncated: null,
    indexedDbTruncated: null,
    truncation: { any: null, cookie: null, localStorage: null, sessionStorage: null, indexedDb: null },
    fingerprint: null
  };
}

type CookieDigestRecord = {
  context: 'cookie';
  origin: string;
  store: 'cookie';
  key: string;
  valueDigest: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
  expires: number | null;
};

type CookieDigestResult = {
  records: CookieDigestRecord[];
  count: number;
  truncated: boolean;
};

type CookieHmacKey = Awaited<ReturnType<typeof webcrypto.subtle.importKey>>;
const cookieHmacKeys = new WeakMap<Page, Promise<CookieHmacKey>>();
const hmacOwnershipPages = new WeakSet<Page>();
const COOKIE_HMAC_CONTEXT = 'hermternal-storage-evidence:cookie:v2';
const MAX_COOKIE_FIELD_LENGTH = 4_096;

function compareCookieStrings(left: string, right: string): number {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function cookieDomainApplies(hostname: string, domain: string): boolean {
  const normalized = domain.startsWith('.') ? domain.slice(1) : domain;
  return normalized !== '' && (hostname === normalized || hostname.endsWith(`.${normalized}`));
}

function cookiePathApplies(pathname: string, cookiePath: string): boolean {
  if (!cookiePath.startsWith('/')) return false;
  if (pathname === cookiePath) return true;
  if (!pathname.startsWith(cookiePath)) return false;
  if (cookiePath.endsWith('/')) return true;
  return pathname[cookiePath.length] === '/';
}

function assertCookieText(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_COOKIE_FIELD_LENGTH) {
    throw new Error('cookie-field');
  }
  return value;
}

function assertCookieValue(value: unknown): string {
  if (typeof value !== 'string' || value.length > MAX_COOKIE_FIELD_LENGTH) throw new Error('cookie-value');
  return value;
}

async function getCookieHmacKey(page: Page, injectFailure?: StorageEvidenceFailureInjection): Promise<CookieHmacKey> {
  const existing = cookieHmacKeys.get(page);
  if (existing) return await existing;
  const promise = (async (): Promise<CookieHmacKey> => {
    if (injectFailure === 'random' || injectFailure === 'import-key') throw new Error('cookie-crypto');
    const material = new Uint8Array(32);
    try {
      webcrypto.getRandomValues(material);
      const key = await webcrypto.subtle.importKey(
        'raw',
        material,
        { name: 'HMAC', hash: 'SHA-256', length: 256 },
        false,
        ['sign']
      );
      if (
        key.type !== 'secret' ||
        key.extractable !== false ||
        key.algorithm.name !== 'HMAC' ||
        (key.algorithm as HmacKeyAlgorithm).length !== 256 ||
        (key.algorithm as HmacKeyAlgorithm).hash.name !== 'SHA-256' ||
        key.usages.length !== 1 ||
        key.usages[0] !== 'sign'
      ) {
        throw new Error('cookie-key');
      }
      return key;
    } finally {
      material.fill(0);
    }
  })();
  cookieHmacKeys.set(page, promise);
  try {
    return await promise;
  } catch (error) {
    cookieHmacKeys.delete(page);
    throw error;
  }
}

// Context cookies are the only Node-side raw storage boundary. Consume each
// value immediately into an HMAC descriptor, clear the transient API object, and
// pass only non-reversible digests into the page-side canonical record set.
async function readScopedCookieDigests(
  page: Page,
  scopedUrl: URL,
  options: StorageEvidenceReadOptions
): Promise<CookieDigestResult> {
  if (options.injectFailure === 'cookie-read' || options.injectFailure === 'cookie-sign') throw new Error('cookie-read');
  const cookies = await page.context().cookies([scopedUrl.toString()]);
  const count = cookies.length;
  if (!Number.isSafeInteger(count) || count < 0) throw new Error('cookie-count');
  if (count > STORAGE_EVIDENCE_CONTEXT_LIMIT) {
    for (const cookie of cookies) {
      try {
        cookie.value = '';
      } catch {
        // The API object is transient; never retain or report a value.
      }
    }
    return { records: [], count, truncated: true };
  }

  const key = await getCookieHmacKey(page, options.injectFailure);
  const records: CookieDigestRecord[] = [];
  for (const cookie of cookies) {
    let value = '';
    let canonical = '';
    try {
      const name = assertCookieText(cookie.name);
      const domain = assertCookieText(cookie.domain).toLowerCase();
      const cookiePath = assertCookieText(cookie.path);
      value = assertCookieValue(cookie.value);
      if (!cookieDomainApplies(scopedUrl.hostname.toLowerCase(), domain)) throw new Error('cookie-domain');
      if (!cookiePathApplies(scopedUrl.pathname || '/', cookiePath)) throw new Error('cookie-path');
      if (cookie.secure !== true && cookie.secure !== false) throw new Error('cookie-secure');
      if (cookie.secure && scopedUrl.protocol !== 'https:') throw new Error('cookie-secure-scope');
      if (cookie.httpOnly !== true && cookie.httpOnly !== false) throw new Error('cookie-http-only');
      const sameSite = cookie.sameSite ?? null;
      if (sameSite !== null && !['Strict', 'Lax', 'None'].includes(sameSite)) throw new Error('cookie-same-site');
      const expires = cookie.expires === -1 ? null : cookie.expires;
      if (expires !== null && (!Number.isFinite(expires) || expires < 0)) throw new Error('cookie-expires');
      canonical = JSON.stringify({
        context: 'cookie',
        origin: scopedUrl.origin,
        store: 'cookie',
        key: name,
        value,
        domain,
        path: cookiePath,
        secure: cookie.secure,
        httpOnly: cookie.httpOnly,
        sameSite,
        expires
      });
      const signature = await webcrypto.subtle.sign(
        { name: 'HMAC' },
        key,
        new TextEncoder().encode(`${COOKIE_HMAC_CONTEXT}\n${canonical}`)
      );
      const digest = Array.from(new Uint8Array(signature), (byte) => byte.toString(16).padStart(2, '0')).join('');
      if (!/^[0-9a-f]{64}$/.test(digest)) throw new Error('cookie-digest');
      records.push({
        context: 'cookie',
        origin: scopedUrl.origin,
        store: 'cookie',
        key: name,
        valueDigest: digest,
        domain,
        path: cookiePath,
        secure: cookie.secure,
        httpOnly: cookie.httpOnly,
        sameSite,
        expires
      });
    } finally {
      try {
        cookie.value = '';
      } catch {
        // No raw cookie value is retained in helper state or diagnostics.
      }
      value = '';
      canonical = '';
    }
  }
  records.sort((left, right) =>
    compareCookieStrings(left.key, right.key) ||
    compareCookieStrings(left.domain, right.domain) ||
    compareCookieStrings(left.path, right.path) ||
    Number(left.secure) - Number(right.secure) ||
    Number(left.httpOnly) - Number(right.httpOnly) ||
    compareCookieStrings(left.sameSite ?? '', right.sameSite ?? '') ||
    (left.expires ?? -1) - (right.expires ?? -1) ||
    compareCookieStrings(left.valueDigest, right.valueDigest)
  );
  return { records, count, truncated: false };
}

async function primeStorageHmac(page: Page, options: StorageEvidenceReadOptions): Promise<void> {
  // Mark ownership before evaluation so a failure after publication remains
  // eligible for identity-guarded cleanup on the next teardown attempt.
  hmacOwnershipPages.add(page);
  await page.evaluate(
    async ({ hmacKeyGlobal, hmacStateKind, hmacProbe, injectFailure }) => {
      if (injectFailure === 'crypto-unavailable' || injectFailure === 'random' || injectFailure === 'import-key') {
        throw new Error('crypto');
      }
      const cryptoApi = globalThis.crypto;
      const subtle = cryptoApi?.subtle;
      if (
        !cryptoApi ||
        !subtle ||
        typeof cryptoApi.getRandomValues !== 'function' ||
        typeof subtle.importKey !== 'function' ||
        typeof subtle.sign !== 'function'
      ) {
        throw new Error('crypto');
      }
      const globals = globalThis as typeof globalThis & Record<string, unknown>;
      const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
      const defineProperty = Object.defineProperty;
      const freeze = Object.freeze;
      const previousDescriptor = getOwnPropertyDescriptor(globals, hmacKeyGlobal);
      const previousValueDescriptor = previousDescriptor
        ? getOwnPropertyDescriptor(previousDescriptor, 'value')
        : undefined;
      const isDataDescriptor = previousValueDescriptor !== undefined;
      const existingState = isDataDescriptor ? previousDescriptor?.value : undefined;
      let key: CryptoKey;
      if (
        isDataDescriptor &&
        existingState !== undefined &&
        typeof existingState === 'object' &&
        existingState !== null
      ) {
        const state = existingState as Record<string, unknown>;
        if (
          state.kind !== hmacStateKind ||
          state.ownerToken !== existingState ||
          typeof state.key !== 'object' ||
          state.key === null
        ) {
          throw new Error('crypto-state');
        }
        key = state.key as CryptoKey;
      } else {
        if (
          previousDescriptor &&
          previousDescriptor.configurable !== true &&
          (!isDataDescriptor || previousDescriptor.writable !== true)
        ) {
          throw new Error('crypto-global');
        }
        const material = new Uint8Array(32);
        try {
          cryptoApi.getRandomValues(material);
          key = (await subtle.importKey(
            'raw',
            material,
            { name: 'HMAC', hash: 'SHA-256', length: 256 },
            false,
            ['sign']
          )) as CryptoKey;
        } finally {
          material.fill(0);
        }
        const priorDescriptor = previousDescriptor
          ? freeze({ ...previousDescriptor }) as PropertyDescriptor
          : undefined;
        const state = {} as {
          kind: string;
          key: CryptoKey;
          priorDescriptor: PropertyDescriptor | undefined;
          ownerToken: object;
        };
        defineProperty(state, 'kind', {
          configurable: false,
          enumerable: false,
          writable: false,
          value: hmacStateKind
        });
        defineProperty(state, 'key', {
          configurable: false,
          enumerable: false,
          writable: false,
          value: key
        });
        defineProperty(state, 'priorDescriptor', {
          configurable: false,
          enumerable: false,
          writable: false,
          value: priorDescriptor
        });
        defineProperty(state, 'ownerToken', {
          configurable: false,
          enumerable: false,
          writable: false,
          value: state
        });
        try {
          if (!previousDescriptor) {
            defineProperty(globals, hmacKeyGlobal, {
              configurable: true,
              enumerable: false,
              writable: false,
              value: state
            });
          } else if (previousDescriptor.configurable === true) {
            defineProperty(globals, hmacKeyGlobal, {
              configurable: true,
              enumerable: false,
              writable: false,
              value: state
            });
          } else {
            defineProperty(globals, hmacKeyGlobal, { ...previousDescriptor, value: state });
          }
        } catch (error) {
          try {
            if (previousDescriptor) defineProperty(globals, hmacKeyGlobal, previousDescriptor);
            else delete globals[hmacKeyGlobal];
          } catch {
            // Do not replace a failed publication error with rollback noise.
          }
          throw error;
        }
      }
      const algorithm = key.algorithm as unknown as Record<string, unknown>;
      const hash = algorithm.hash as { name?: unknown } | undefined;
      if (
        key.type !== 'secret' ||
        key.extractable !== false ||
        algorithm.name !== 'HMAC' ||
        algorithm.length !== 256 ||
        hash?.name !== 'SHA-256' ||
        key.usages.length !== 1 ||
        key.usages[0] !== 'sign'
      ) {
        throw new Error('crypto-key');
      }
      if (injectFailure === 'probe-sign') throw new Error('crypto-probe');
      const signature = await subtle.sign({ name: 'HMAC' }, key, new TextEncoder().encode(hmacProbe));
      if (new Uint8Array(signature).byteLength !== 32) throw new Error('crypto-sign');
    },
    {
      hmacKeyGlobal: STORAGE_HMAC_KEY_GLOBAL,
      hmacStateKind: STORAGE_HMAC_STATE_KIND,
      hmacProbe: STORAGE_HMAC_PROBE,
      injectFailure: options.injectFailure
    }
  );
}

export async function readStorageEvidence(
  page: Page,
  options: StorageEvidenceReadOptions = {}
): Promise<StorageEvidence> {
  let scopedUrl: URL;
  let cookieEvidence: CookieDigestResult;
  try {
    await primeStorageHmac(page, options);
    scopedUrl = new URL(page.url());
    if (scopedUrl.protocol !== 'http:' && scopedUrl.protocol !== 'https:') throw new Error('scope');
    cookieEvidence = await readScopedCookieDigests(page, scopedUrl, options);
  } catch {
    cookieHmacKeys.delete(page);
    return emptyStorageEvidence();
  }
  return await page
    .evaluate(
      async ({
        databaseName,
        objectStoreName,
        objectKey,
        cookieRecords,
        cookieCount,
        cookieTruncated,
        injectFailure,
        hmacKeyGlobal,
        hmacStateKind: STORAGE_HMAC_STATE_KIND,
        hmacProbe: STORAGE_HMAC_PROBE,
        evidenceRecordLimit: STORAGE_EVIDENCE_RECORD_LIMIT,
        evidenceContextLimit: STORAGE_EVIDENCE_CONTEXT_LIMIT,
        evidenceDatabaseLimit: STORAGE_EVIDENCE_DATABASE_LIMIT,
        evidenceStoreLimit: STORAGE_EVIDENCE_STORE_LIMIT
      }): Promise<PageStorageEvidence> => {
        type RecordContext = 'cookie' | 'localStorage' | 'sessionStorage' | 'indexedDB';
        type RawStorageRecord = {
          context: RecordContext;
          origin: string;
          store: string;
          key: unknown;
          value: unknown;
          database?: string;
          domain?: string;
          path?: string;
          secure?: boolean;
          httpOnly?: boolean;
          sameSite?: string | null;
          expires?: number | null;
        };
        type StringStorageResult = {
          records: RawStorageRecord[];
          count: number;
          truncated: boolean;
        };
        type IndexedDbResult = {
          supported: boolean;
          records: RawStorageRecord[];
          recordCount: number;
          unexpectedDatabaseCount: number;
          databaseCount: number;
          storeCount: number;
          truncated: boolean;
          databases: Array<{ name: string; version: number; stores: string[] }>;
        };

        const unsupportedEvidence = (): UnsupportedStorageEvidence => ({
          cryptoSupported: false,
          status: 'unsupported',
          truncated: null,
          readFailure: true,
          recordCount: null,
          digestCount: null,
          recordLimit: null,
          cookieCount: null,
          localStorageEntryCount: null,
          sessionStorageEntryCount: null,
          indexedDbSupported: null,
          indexedDbRecordCount: null,
          indexedDbUnexpectedDatabaseCount: null,
          indexedDbDatabaseCount: null,
          indexedDbStoreCount: null,
          cookieTruncated: null,
          localStorageTruncated: null,
          sessionStorageTruncated: null,
          indexedDbTruncated: null,
          truncation: { any: null, cookie: null, localStorage: null, sessionStorage: null, indexedDb: null },
          fingerprint: null
        });
        const truncatedEvidence = (truncation: StorageEvidenceTruncation): TruncatedStorageEvidence => ({
          cryptoSupported: true,
          status: 'truncated',
          truncated: true,
          readFailure: false,
          recordCount: null,
          digestCount: null,
          recordLimit: STORAGE_EVIDENCE_RECORD_LIMIT,
          cookieCount: null,
          localStorageEntryCount: null,
          sessionStorageEntryCount: null,
          indexedDbSupported: null,
          indexedDbRecordCount: null,
          indexedDbUnexpectedDatabaseCount: null,
          indexedDbDatabaseCount: null,
          indexedDbStoreCount: null,
          cookieTruncated: truncation.cookie,
          localStorageTruncated: truncation.localStorage,
          sessionStorageTruncated: truncation.sessionStorage,
          indexedDbTruncated: truncation.indexedDb,
          truncation,
          fingerprint: null
        });
        const compareStrings = (left: string, right: string): number => {
          if (left < right) return -1;
          if (left > right) return 1;
          return 0;
        };
        const assertSafeCount = (value: number): number => {
          if (!Number.isSafeInteger(value) || value < 0) throw new Error('count');
          return value;
        };
        // Capture inspection primordials before canonicalization. Storage values
        // are untrusted and must not be read through monkeypatched accessors or
        // Proxy traps while their shape is being checked.
        const capturedObjectGetPrototypeOf = Object.getPrototypeOf;
        const capturedObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
        const capturedReflectOwnKeys = Reflect.ownKeys;
        const capturedArrayIsArray = Array.isArray;
        const capturedArrayPrototype = Array.prototype;
        const capturedObjectPrototype = Object.prototype;
        const capturedStructuredClone = typeof structuredClone === 'function'
          ? structuredClone.bind(globalThis)
          : undefined;
        const isDataDescriptor = (descriptor: PropertyDescriptor | undefined): descriptor is PropertyDescriptor =>
          descriptor !== undefined &&
          capturedObjectGetOwnPropertyDescriptor(descriptor, 'value') !== undefined &&
          capturedObjectGetOwnPropertyDescriptor(descriptor, 'get') === undefined &&
          capturedObjectGetOwnPropertyDescriptor(descriptor, 'set') === undefined;
        const isCanonicalArrayIndex = (key: string): boolean => {
          if (key === '') return false;
          const index = Number(key);
          return Number.isSafeInteger(index) && index >= 0 && index < 4_294_967_295 && String(index) === key;
        };
        const canonicalBudget = {
          bytes: 0,
          nodes: 0,
          depth: 0,
          keys: 0,
          arrays: 0,
          strings: 0
        };
        const charge = (text: string): string => {
          canonicalBudget.bytes += text.length;
          if (!Number.isSafeInteger(canonicalBudget.bytes) || canonicalBudget.bytes > 1_048_576) {
            throw new Error('canonical-budget');
          }
          return text;
        };
        const canonicalize = (value: unknown, seen = new Set<object>(), depth = 0): string => {
          canonicalBudget.nodes += 1;
          if (canonicalBudget.nodes > 65_536 || depth > 32) throw new Error('canonical-budget');
          if (value === null) return charge('null');
          if (value === undefined) return charge('undefined');
          switch (typeof value) {
            case 'string':
              canonicalBudget.strings += 1;
              if (canonicalBudget.strings > 32_768 || value.length > 65_536) throw new Error('canonical-string');
              return charge(`string:${JSON.stringify(value)}`);
            case 'boolean':
              return charge(`boolean:${value ? 'true' : 'false'}`);
            case 'number':
              if (Number.isNaN(value)) return charge('number:NaN');
              if (value === Infinity) return charge('number:+Infinity');
              if (value === -Infinity) return charge('number:-Infinity');
              if (Object.is(value, -0)) return charge('number:-0');
              return charge(`number:${value}`);
            case 'bigint':
              return charge(`bigint:${value.toString()}`);
            case 'symbol':
            case 'function':
              throw new Error('uncanonicalizable');
          }

          const objectValue = value as object;
          if (seen.has(objectValue)) throw new Error('cycle');
          seen.add(objectValue);
          try {
            if (value instanceof Date) {
              const timestamp = value.getTime();
              if (!Number.isFinite(timestamp)) throw new Error('invalid-date');
              return charge(`date:${value.toISOString()}`);
            }
            if (value instanceof ArrayBuffer) {
              const bytes = new Uint8Array(value);
              if (bytes.byteLength > 65_536) throw new Error('canonical-bytes');
              return charge(`array-buffer:${Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')}`);
            }
            if (ArrayBuffer.isView(value)) {
              const view = value as ArrayBufferView & { constructor: { name?: string } };
              const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
              if (bytes.byteLength > 65_536) throw new Error('canonical-bytes');
              return charge(`view:${JSON.stringify(view.constructor.name ?? 'unknown')}:${Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')}`);
            }
            if (capturedArrayIsArray(value)) {
              canonicalBudget.arrays += 1;
              if (canonicalBudget.arrays > 4_096) throw new Error('canonical-array');
              const prototype = capturedObjectGetPrototypeOf(value);
              if (prototype !== capturedArrayPrototype) throw new Error('array-prototype');

              // Read the intrinsic length descriptor before any element. All
              // own keys and descriptors are then validated before descriptor
              // values are consumed, preserving sparse holes without `value[index]`.
              const ownKeys = capturedReflectOwnKeys(value);
              const lengthDescriptor = capturedObjectGetOwnPropertyDescriptor(value, 'length');
              if (
                !isDataDescriptor(lengthDescriptor) ||
                lengthDescriptor.enumerable !== false ||
                lengthDescriptor.configurable !== false ||
                lengthDescriptor.writable !== true ||
                !Number.isSafeInteger(lengthDescriptor.value) ||
                lengthDescriptor.value < 0 ||
                lengthDescriptor.value > 2_048
              ) {
                throw new Error('canonical-array-length');
              }
              const length = lengthDescriptor.value;
              const elementDescriptors = new Map<number, PropertyDescriptor>();
              for (const key of ownKeys) {
                if (typeof key !== 'string') throw new Error('array-symbol-key');
                if (key === 'length') continue;
                if (!isCanonicalArrayIndex(key)) throw new Error('array-extra-key');
                const index = Number(key);
                if (index >= length) throw new Error('array-index');
                const descriptor = capturedObjectGetOwnPropertyDescriptor(value, key);
                if (!isDataDescriptor(descriptor) || descriptor.enumerable !== true) throw new Error('array-accessor');
                elementDescriptors.set(index, descriptor);
              }
              if (ownKeys.length !== elementDescriptors.size + 1) throw new Error('array-keys');

              const entries: string[] = [];
              for (let index = 0; index < length; index += 1) {
                const descriptor = elementDescriptors.get(index);
                entries.push(descriptor ? canonicalize(descriptor.value, seen, depth + 1) : 'hole');
              }
              // A Proxy can mimic the validated shape until structuredClone;
              // reject it after all descriptor values are safely canonicalized.
              if (!capturedStructuredClone) throw new Error('array-clone');
              capturedStructuredClone(value);
              return charge(`array:[${entries.join(',')}]`);
            }
            if (value instanceof Map) {
              canonicalBudget.keys += value.size;
              if (canonicalBudget.keys > 32_768) throw new Error('canonical-map');
              const entries = Array.from(value.entries(), ([key, entry]) => [
                canonicalize(key, seen, depth + 1),
                canonicalize(entry, seen, depth + 1)
              ] as const).sort(([leftKey, leftValue], [rightKey, rightValue]) =>
                compareStrings(leftKey, rightKey) || compareStrings(leftValue, rightValue)
              );
              return charge(`map:[${entries.map(([key, entry]) => `[${key},${entry}]`).join(',')}]`);
            }
            if (value instanceof Set) {
              canonicalBudget.keys += value.size;
              if (canonicalBudget.keys > 32_768) throw new Error('canonical-set');
              const entries = Array.from(value, (entry) => canonicalize(entry, seen, depth + 1)).sort(compareStrings);
              return charge(`set:[${entries.join(',')}]`);
            }

            const prototype = capturedObjectGetPrototypeOf(value);
            if (prototype !== capturedObjectPrototype && prototype !== null) throw new Error('prototype');
            const ownKeys = capturedReflectOwnKeys(value);
            if (ownKeys.some((key): key is symbol => typeof key === 'symbol')) throw new Error('symbol-key');
            const keys = (ownKeys as string[]).sort(compareStrings);
            canonicalBudget.keys += keys.length;
            if (canonicalBudget.keys > 32_768) throw new Error('canonical-keys');
            const parts: string[] = [];
            for (const key of keys) {
              if (key.length > 4_096) throw new Error('canonical-key');
              const descriptor = capturedObjectGetOwnPropertyDescriptor(value, key);
              if (!isDataDescriptor(descriptor)) throw new Error('accessor');
              parts.push(`${JSON.stringify(key)}:${canonicalize(descriptor.value, seen, depth + 1)}`);
            }
            if (!capturedStructuredClone) throw new Error('object-clone');
            capturedStructuredClone(value);
            return charge(`object:{${parts.join(',')}}`);
          } finally {
            seen.delete(objectValue);
          }
        };
        const canonicalRecord = (record: RawStorageRecord): string => canonicalize(
          record.database === undefined
            ? {
                context: record.context,
                origin: record.origin,
                store: record.store,
                key: record.key,
                value: record.value,
                ...(record.context === 'cookie'
                  ? {
                      domain: record.domain,
                      path: record.path,
                      secure: record.secure,
                      httpOnly: record.httpOnly,
                      sameSite: record.sameSite,
                      expires: record.expires
                    }
                  : {})
              }
            : {
                context: record.context,
                origin: record.origin,
                database: record.database,
                store: record.store,
                key: record.key,
                value: record.value
              }
        );
        const openApprovedDatabase = (version: number): Promise<IDBDatabase> =>
          new Promise<IDBDatabase>((resolve, reject) => {
            let settled = false;
            const fail = (): void => {
              if (settled) return;
              settled = true;
              reject(new Error('idb-open'));
            };
            let request: IDBOpenDBRequest;
            try {
              request = version > 0 ? indexedDB.open(databaseName, version) : indexedDB.open(databaseName);
            } catch {
              fail();
              return;
            }
            request.onupgradeneeded = () => {
              try {
                request.transaction?.abort();
              } catch {
                fail();
              }
            };
            request.onerror = fail;
            request.onblocked = fail;
            request.onsuccess = () => {
              if (settled) {
                request.result.close();
                return;
              }
              settled = true;
              resolve(request.result);
            };
          });
        const readStringStorage = (storage: Storage, context: 'localStorage' | 'sessionStorage', origin: string): StringStorageResult => {
          if (context === 'localStorage' && injectFailure === 'local-storage-read') throw new Error('storage-read');
          if (context === 'sessionStorage' && injectFailure === 'session-storage-read') throw new Error('storage-read');
          const count = assertSafeCount(storage.length);
          if (count > STORAGE_EVIDENCE_CONTEXT_LIMIT) {
            return { records: [], count, truncated: true };
          }
          const records: RawStorageRecord[] = [];
          for (let index = 0; index < count; index += 1) {
            const key = storage.key(index);
            if (key === null) throw new Error('storage-key');
            const value = storage.getItem(key);
            if (value === null) throw new Error('storage-value');
            records.push({ context, origin, store: context, key, value });
          }
          if (storage.length !== count) throw new Error('storage-race');
          return { records, count, truncated: false };
        };
        // Enumerate bounded database metadata only. Any name outside the exact
        // test-owned allowlist fails closed before an IndexedDB connection opens.
        const readIndexedDb = async (origin: string): Promise<IndexedDbResult> => {
          if (injectFailure === 'idb-enumeration-unavailable' || typeof indexedDB === 'undefined' || typeof indexedDB.databases !== 'function') {
            throw new Error('idb-metadata');
          }
          if (injectFailure === 'idb-metadata') throw new Error('idb-metadata');
          const listed = await indexedDB.databases();
          if (!Array.isArray(listed) || listed.length > STORAGE_EVIDENCE_DATABASE_LIMIT) throw new Error('idb-metadata');
          const databases = listed.map((entry) => {
            if (
              !entry ||
              typeof entry.name !== 'string' ||
              entry.name.length === 0 ||
              entry.name.length > 512 ||
              typeof entry.version !== 'number' ||
              !Number.isSafeInteger(entry.version) ||
              entry.version < 0
            ) {
              throw new Error('idb-metadata');
            }
            return { name: entry.name, version: entry.version };
          });
          databases.sort((left, right) => compareStrings(left.name, right.name) || left.version - right.version);
          for (let index = 1; index < databases.length; index += 1) {
            if (databases[index - 1].name === databases[index].name) throw new Error('idb-duplicate');
          }
          if (databases.some((entry) => entry.name !== databaseName)) throw new Error('idb-unexpected');
          const ownDatabase = databases.find((entry) => entry.name === databaseName);
          if (!ownDatabase) {
            return {
              supported: true,
              records: [],
              recordCount: 0,
              unexpectedDatabaseCount: 0,
              databaseCount: 0,
              storeCount: 0,
              truncated: false,
              databases: []
            };
          }
          if (injectFailure === 'idb-open') throw new Error('idb-open');
          let database: IDBDatabase | undefined;
          try {
            database = await openApprovedDatabase(ownDatabase.version);
            const stores = Array.from(database.objectStoreNames).sort(compareStrings);
            if (stores.length > STORAGE_EVIDENCE_STORE_LIMIT) throw new Error('idb-store-limit');
            if (stores.some((storeName) => storeName !== objectStoreName)) throw new Error('idb-unexpected-store');
            if (!stores.includes(objectStoreName)) {
              return {
                supported: true,
                records: [],
                recordCount: 0,
                unexpectedDatabaseCount: 0,
                databaseCount: 1,
                storeCount: 0,
                truncated: false,
                databases: [{ name: ownDatabase.name, version: ownDatabase.version, stores: [] }]
              };
            }
            if (injectFailure === 'idb-read') throw new Error('idb-read');
            const result = await new Promise<{ count: number; value: unknown; present: boolean }>((resolve, reject) => {
              let settled = false;
              const fail = (): void => {
                if (settled) return;
                settled = true;
                reject(new Error('idb-read'));
              };
              try {
                const transaction = database!.transaction(objectStoreName, 'readonly');
                const store = transaction.objectStore(objectStoreName);
                const countRequest = store.count(IDBKeyRange.only(objectKey));
                const valueRequest = store.get(objectKey);
                let count: number | undefined;
                let value: unknown;
                countRequest.onsuccess = () => {
                  try {
                    count = assertSafeCount(countRequest.result);
                  } catch {
                    fail();
                  }
                };
                valueRequest.onsuccess = () => {
                  value = valueRequest.result;
                };
                countRequest.onerror = fail;
                valueRequest.onerror = fail;
                transaction.onerror = fail;
                transaction.onabort = fail;
                transaction.oncomplete = () => {
                  if (settled || count === undefined) {
                    if (!settled) fail();
                    return;
                  }
                  settled = true;
                  resolve({ count, value, present: count > 0 });
                };
              } catch {
                fail();
              }
            });
            return {
              supported: true,
              records: result.present
                ? [{ context: 'indexedDB', origin, database: databaseName, store: objectStoreName, key: objectKey, value: result.value }]
                : [],
              recordCount: result.count,
              unexpectedDatabaseCount: 0,
              databaseCount: 1,
              storeCount: 1,
              truncated: false,
              databases: [{ name: ownDatabase.name, version: ownDatabase.version, stores: [objectStoreName] }]
            };
          } finally {
            database?.close();
          }
        };

        try {
          if (injectFailure === 'crypto-unavailable' || injectFailure === 'random' || injectFailure === 'import-key') {
            throw new Error('crypto');
          }
          const cryptoApi = globalThis.crypto;
          const subtle = cryptoApi?.subtle;
          if (
            !cryptoApi ||
            !subtle ||
            typeof cryptoApi.getRandomValues !== 'function' ||
            typeof subtle.importKey !== 'function' ||
            typeof subtle.sign !== 'function'
          ) {
            throw new Error('crypto');
          }
          const globals = globalThis as typeof globalThis & Record<string, unknown>;
          const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
          const defineProperty = Object.defineProperty;
          const freeze = Object.freeze;
          const previousDescriptor = getOwnPropertyDescriptor(globals, hmacKeyGlobal);
          const previousValueDescriptor = previousDescriptor
            ? getOwnPropertyDescriptor(previousDescriptor, 'value')
            : undefined;
          const isDataDescriptor = previousValueDescriptor !== undefined;
          const existingState = isDataDescriptor ? previousDescriptor?.value : undefined;
          let key: CryptoKey;
          if (
            isDataDescriptor &&
            existingState !== undefined &&
            typeof existingState === 'object' &&
            existingState !== null
          ) {
            const state = existingState as Record<string, unknown>;
            if (
              state.kind !== STORAGE_HMAC_STATE_KIND ||
              state.ownerToken !== existingState ||
              typeof state.key !== 'object' ||
              state.key === null
            ) {
              throw new Error('crypto-state');
            }
            key = state.key as CryptoKey;
          } else {
            if (
              previousDescriptor &&
              previousDescriptor.configurable !== true &&
              (!isDataDescriptor || previousDescriptor.writable !== true)
            ) {
              throw new Error('crypto-global');
            }
            const material = new Uint8Array(32);
            try {
              cryptoApi.getRandomValues(material);
              key = (await subtle.importKey(
                'raw',
                material,
                { name: 'HMAC', hash: 'SHA-256', length: 256 },
                false,
                ['sign']
              )) as CryptoKey;
            } finally {
              material.fill(0);
            }
            const priorDescriptor = previousDescriptor
              ? freeze({ ...previousDescriptor }) as PropertyDescriptor
              : undefined;
            const state = {} as {
              kind: string;
              key: CryptoKey;
              priorDescriptor: PropertyDescriptor | undefined;
              ownerToken: object;
            };
            defineProperty(state, 'kind', {
              configurable: false,
              enumerable: false,
              writable: false,
              value: STORAGE_HMAC_STATE_KIND
            });
            defineProperty(state, 'key', {
              configurable: false,
              enumerable: false,
              writable: false,
              value: key
            });
            defineProperty(state, 'priorDescriptor', {
              configurable: false,
              enumerable: false,
              writable: false,
              value: priorDescriptor
            });
            defineProperty(state, 'ownerToken', {
              configurable: false,
              enumerable: false,
              writable: false,
              value: state
            });
            try {
              if (!previousDescriptor) {
                defineProperty(globals, hmacKeyGlobal, {
                  configurable: true,
                  enumerable: false,
                  writable: false,
                  value: state
                });
              } else if (previousDescriptor.configurable === true) {
                defineProperty(globals, hmacKeyGlobal, {
                  configurable: true,
                  enumerable: false,
                  writable: false,
                  value: state
                });
              } else {
                defineProperty(globals, hmacKeyGlobal, { ...previousDescriptor, value: state });
              }
            } catch (error) {
              try {
                if (previousDescriptor) defineProperty(globals, hmacKeyGlobal, previousDescriptor);
                else delete globals[hmacKeyGlobal];
              } catch {
                // Preserve the publication failure without exposing rollback detail.
              }
              throw error;
            }
          }
          const algorithm = key.algorithm as unknown as Record<string, unknown>;
          const hash = algorithm.hash as { name?: unknown } | undefined;
          if (
            key.type !== 'secret' ||
            key.extractable !== false ||
            algorithm.name !== 'HMAC' ||
            algorithm.length !== 256 ||
            hash?.name !== 'SHA-256' ||
            !Array.isArray(key.usages) ||
            key.usages.length !== 1 ||
            key.usages[0] !== 'sign'
          ) {
            throw new Error('crypto-key');
          }
          const encoder = new TextEncoder();
          let signCount = 0;
          const signText = async (value: string): Promise<string> => {
            if (injectFailure === 'sign' && signCount > 0) throw new Error('crypto-sign');
            signCount += 1;
            const signature = await subtle.sign({ name: 'HMAC' }, key, encoder.encode(value));
            const bytes = new Uint8Array(signature);
            if (bytes.byteLength !== 32) throw new Error('crypto-sign');
            return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
          };

          // Prove import and HMAC-SHA-256 signing before touching any storage.
          if (injectFailure === 'probe-sign') throw new Error('crypto-probe');
          await signText(STORAGE_HMAC_PROBE);
          if (injectFailure === 'truncation') {
            return truncatedEvidence({ any: true, cookie: true, localStorage: false, sessionStorage: false, indexedDb: false });
          }

          const origin = globalThis.location?.origin;
          if (typeof origin !== 'string') throw new Error('origin');
          if (!Array.isArray(cookieRecords) || cookieRecords.some((record) =>
            record.context !== 'cookie' ||
            record.store !== 'cookie' ||
            record.origin !== origin ||
            typeof record.key !== 'string' ||
            typeof record.valueDigest !== 'string' ||
            !/^[0-9a-f]{64}$/.test(record.valueDigest)
          )) {
            throw new Error('cookie-scope');
          }
          const cookies: StringStorageResult = {
            records: cookieRecords.map((record) => ({
              context: 'cookie',
              origin: record.origin,
              store: 'cookie',
              key: record.key,
              value: record.valueDigest,
              domain: record.domain,
              path: record.path,
              secure: record.secure,
              httpOnly: record.httpOnly,
              sameSite: record.sameSite,
              expires: record.expires
            })),
            count: cookieCount,
            truncated: cookieTruncated
          };
          const local = readStringStorage(localStorage, 'localStorage', origin);
          const session = readStringStorage(sessionStorage, 'sessionStorage', origin);
          const indexedDb = await readIndexedDb(origin);
          const recordCount = assertSafeCount(cookies.count + local.count + session.count + indexedDb.recordCount);
          const truncation: StorageEvidenceTruncation = {
            cookie: cookies.truncated,
            localStorage: local.truncated,
            sessionStorage: session.truncated,
            indexedDb: indexedDb.truncated,
            any: cookies.truncated || local.truncated || session.truncated || indexedDb.truncated
          };
          if (truncation.any) return truncatedEvidence(truncation);
          if (injectFailure === 'canonicalization') throw new Error('canonicalization');
          const rawRecords = [...cookies.records, ...local.records, ...session.records, ...indexedDb.records];
          const canonicalRecords = rawRecords.map(canonicalRecord).sort(compareStrings);
          if (canonicalRecords.length > STORAGE_EVIDENCE_RECORD_LIMIT) {
            return truncatedEvidence({ any: true, cookie: false, localStorage: false, sessionStorage: false, indexedDb: false });
          }
          const digests: string[] = [];
          for (const record of canonicalRecords) digests.push(await signText(record));
          digests.sort(compareStrings);

          const truncationAllFalse: StorageEvidenceTruncation = {
            any: false,
            cookie: false,
            localStorage: false,
            sessionStorage: false,
            indexedDb: false
          };
          const metadata = canonicalize({
            version: 2,
            origin,
            counts: {
              recordCount,
              digestCount: digests.length,
              cookieCount: cookies.count,
              localStorageEntryCount: local.count,
              sessionStorageEntryCount: session.count,
              indexedDbSupported: indexedDb.supported,
              indexedDbRecordCount: indexedDb.recordCount,
              indexedDbUnexpectedDatabaseCount: indexedDb.unexpectedDatabaseCount,
              indexedDbDatabaseCount: indexedDb.databaseCount,
              indexedDbStoreCount: indexedDb.storeCount
            },
            recordLimit: STORAGE_EVIDENCE_RECORD_LIMIT,
            truncation: truncationAllFalse,
            indexedDb: indexedDb.databases
          });
          const fingerprint = await signText(
            `hermternal-storage-evidence:v2\nmetadata:${metadata}\ndigests:${digests.join('\\n')}`
          );
          return {
            cryptoSupported: true,
            status: 'supported',
            truncated: false,
            readFailure: false,
            recordCount,
            digestCount: digests.length,
            recordLimit: STORAGE_EVIDENCE_RECORD_LIMIT,
            cookieCount: cookies.count,
            localStorageEntryCount: local.count,
            sessionStorageEntryCount: session.count,
            indexedDbSupported: true,
            indexedDbRecordCount: indexedDb.recordCount,
            indexedDbUnexpectedDatabaseCount: 0,
            indexedDbDatabaseCount: indexedDb.databaseCount,
            indexedDbStoreCount: indexedDb.storeCount,
            cookieTruncated: false,
            localStorageTruncated: false,
            sessionStorageTruncated: false,
            indexedDbTruncated: false,
            truncation: truncationAllFalse,
            fingerprint
          };
        } catch {
          // No exception, raw value, or partially collected digest crosses the page boundary.
          return unsupportedEvidence();
        }
      },
      {
        databaseName: STORAGE_DATABASE,
        objectStoreName: STORAGE_OBJECT_STORE,
        objectKey: STORAGE_OBJECT_KEY,
        cookieRecords: cookieEvidence.records,
        cookieCount: cookieEvidence.count,
        cookieTruncated: cookieEvidence.truncated,
        injectFailure: options.injectFailure,
        hmacKeyGlobal: STORAGE_HMAC_KEY_GLOBAL,
        hmacStateKind: STORAGE_HMAC_STATE_KIND,
        hmacProbe: STORAGE_HMAC_PROBE,
        evidenceRecordLimit: STORAGE_EVIDENCE_RECORD_LIMIT,
        evidenceContextLimit: STORAGE_EVIDENCE_CONTEXT_LIMIT,
        evidenceDatabaseLimit: STORAGE_EVIDENCE_DATABASE_LIMIT,
        evidenceStoreLimit: STORAGE_EVIDENCE_STORE_LIMIT
      }
    )
    .catch(() => emptyStorageEvidence());
}

type CapturedStorageEvidence = {
  kind: 'supported' | 'truncated' | 'unsupported';
  values: Record<string, unknown>;
  truncation: Record<string, unknown>;
  descriptorFlags: Record<string, CapturedDataDescriptorFlags>;
  truncationDescriptorFlags: Record<string, CapturedDataDescriptorFlags>;
};

function captureExactRecord(
  value: unknown,
  expectedKeys: readonly string[],
  rejectProxy: boolean
): CapturedRecord | undefined {
  try {
    if (typeof value !== 'object' || value === null) return undefined;
    const prototype = CAPTURED_OBJECT_GET_PROTOTYPE_OF(value);
    if (prototype !== CAPTURED_OBJECT_PROTOTYPE && prototype !== null) return undefined;

    const ownKeys = CAPTURED_REFLECT_OWN_KEYS(value);
    if (ownKeys.length !== expectedKeys.length) return undefined;
    const seenKeys = CAPTURED_OBJECT_CREATE(null) as Record<string, boolean>;
    for (const key of ownKeys) {
      if (typeof key !== 'string' || seenKeys[key] === true) return undefined;
      seenKeys[key] = true;
    }
    for (const key of expectedKeys) {
      if (seenKeys[key] !== true) return undefined;
    }

    const values = CAPTURED_OBJECT_CREATE(null) as Record<string, unknown>;
    const descriptorFlags = CAPTURED_OBJECT_CREATE(null) as Record<string, CapturedDataDescriptorFlags>;
    for (const key of expectedKeys) {
      const descriptor = CAPTURED_OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(value, key);
      if (
        !descriptor ||
        typeof descriptor.enumerable !== 'boolean' ||
        typeof descriptor.configurable !== 'boolean' ||
        typeof descriptor.writable !== 'boolean' ||
        descriptor.enumerable !== true
      ) {
        return undefined;
      }
      const valueMarker = CAPTURED_OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(descriptor, 'value');
      const getterMarker = CAPTURED_OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(descriptor, 'get');
      const setterMarker = CAPTURED_OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(descriptor, 'set');
      if (!valueMarker || getterMarker || setterMarker) return undefined;
      values[key] = descriptor.value;
      descriptorFlags[key] = {
        configurable: descriptor.configurable,
        enumerable: descriptor.enumerable,
        writable: descriptor.writable
      };
    }

    // Preserve descriptor flags without retaining descriptor objects. Exact
    // equality must reject value-identical evidence whose writable or
    // configurable shape changes, including nested truncation records.

    // structuredClone rejects Proxy objects in browser and Node runtimes. Run
    // it only after descriptor checks and value snapshotting so untrusted
    // accessors, symbols, inherited fields, and extra own fields fail closed.
    if (rejectProxy) {
      if (!CAPTURED_STRUCTURED_CLONE) return undefined;
      CAPTURED_STRUCTURED_CLONE(value);
    }
    return { values, descriptorFlags };
  } catch {
    return undefined;
  }
}

function isSafeEvidenceCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function captureStorageEvidence(value: unknown): CapturedStorageEvidence | undefined {
  const top = captureExactRecord(value, STORAGE_EVIDENCE_KEYS, true);
  if (!top) return undefined;
  const truncation = captureExactRecord(top.values.truncation, STORAGE_TRUNCATION_KEYS, true);
  if (!truncation) return undefined;

  try {
    const fields = top.values;
    const flags = truncation.values;
    const allNull = (keys: readonly string[]): boolean => keys.every((key) => fields[key] === null);
    const allFalse = (): boolean =>
      flags.any === false &&
      flags.cookie === false &&
      flags.localStorage === false &&
      flags.sessionStorage === false &&
      flags.indexedDb === false;
    const supported =
      fields.cryptoSupported === true &&
      fields.status === 'supported' &&
      fields.truncated === false &&
      fields.readFailure === false &&
      isSafeEvidenceCount(fields.recordCount) &&
      isSafeEvidenceCount(fields.digestCount) &&
      fields.recordLimit === STORAGE_EVIDENCE_RECORD_LIMIT &&
      isSafeEvidenceCount(fields.cookieCount) &&
      isSafeEvidenceCount(fields.localStorageEntryCount) &&
      isSafeEvidenceCount(fields.sessionStorageEntryCount) &&
      fields.indexedDbSupported === true &&
      isSafeEvidenceCount(fields.indexedDbRecordCount) &&
      fields.indexedDbUnexpectedDatabaseCount === 0 &&
      isSafeEvidenceCount(fields.indexedDbDatabaseCount) &&
      isSafeEvidenceCount(fields.indexedDbStoreCount) &&
      fields.cookieTruncated === false &&
      fields.localStorageTruncated === false &&
      fields.sessionStorageTruncated === false &&
      fields.indexedDbTruncated === false &&
      allFalse() &&
      typeof fields.fingerprint === 'string' &&
      /^[0-9a-f]{64}$/.test(fields.fingerprint);
    if (supported) {
      return {
        kind: 'supported',
        values: fields,
        truncation: flags,
        descriptorFlags: top.descriptorFlags,
        truncationDescriptorFlags: truncation.descriptorFlags
      };
    }

    const truncated =
      fields.cryptoSupported === true &&
      fields.status === 'truncated' &&
      fields.truncated === true &&
      fields.readFailure === false &&
      fields.recordCount === null &&
      fields.digestCount === null &&
      fields.recordLimit === STORAGE_EVIDENCE_RECORD_LIMIT &&
      fields.cookieCount === null &&
      fields.localStorageEntryCount === null &&
      fields.sessionStorageEntryCount === null &&
      fields.indexedDbSupported === null &&
      fields.indexedDbRecordCount === null &&
      fields.indexedDbUnexpectedDatabaseCount === null &&
      fields.indexedDbDatabaseCount === null &&
      fields.indexedDbStoreCount === null &&
      typeof fields.cookieTruncated === 'boolean' &&
      typeof fields.localStorageTruncated === 'boolean' &&
      typeof fields.sessionStorageTruncated === 'boolean' &&
      typeof fields.indexedDbTruncated === 'boolean' &&
      typeof flags.any === 'boolean' &&
      typeof flags.cookie === 'boolean' &&
      typeof flags.localStorage === 'boolean' &&
      typeof flags.sessionStorage === 'boolean' &&
      typeof flags.indexedDb === 'boolean' &&
      flags.any === (flags.cookie || flags.localStorage || flags.sessionStorage || flags.indexedDb) &&
      fields.cookieTruncated === flags.cookie &&
      fields.localStorageTruncated === flags.localStorage &&
      fields.sessionStorageTruncated === flags.sessionStorage &&
      fields.indexedDbTruncated === flags.indexedDb &&
      fields.fingerprint === null;
    if (truncated) {
      return {
        kind: 'truncated',
        values: fields,
        truncation: flags,
        descriptorFlags: top.descriptorFlags,
        truncationDescriptorFlags: truncation.descriptorFlags
      };
    }

    const unsupported =
      fields.cryptoSupported === false &&
      fields.status === 'unsupported' &&
      fields.truncated === null &&
      fields.readFailure === true &&
      allNull([
        'recordCount',
        'digestCount',
        'recordLimit',
        'cookieCount',
        'localStorageEntryCount',
        'sessionStorageEntryCount',
        'indexedDbSupported',
        'indexedDbRecordCount',
        'indexedDbUnexpectedDatabaseCount',
        'indexedDbDatabaseCount',
        'indexedDbStoreCount',
        'cookieTruncated',
        'localStorageTruncated',
        'sessionStorageTruncated',
        'indexedDbTruncated',
        'fingerprint'
      ]) &&
      flags.any === null &&
      flags.cookie === null &&
      flags.localStorage === null &&
      flags.sessionStorage === null &&
      flags.indexedDb === null;
    return unsupported
      ? {
          kind: 'unsupported',
          values: fields,
          truncation: flags,
          descriptorFlags: top.descriptorFlags,
          truncationDescriptorFlags: truncation.descriptorFlags
        }
      : undefined;
  } catch {
    return undefined;
  }
}

function descriptorFlagsEqual(
  keys: readonly string[],
  left: Record<string, CapturedDataDescriptorFlags>,
  right: Record<string, CapturedDataDescriptorFlags>
): boolean {
  return keys.every((key) => {
    const leftFlags = left[key];
    const rightFlags = right[key];
    return (
      leftFlags !== undefined &&
      rightFlags !== undefined &&
      leftFlags.configurable === rightFlags.configurable &&
      leftFlags.enumerable === rightFlags.enumerable &&
      leftFlags.writable === rightFlags.writable
    );
  });
}

export function storageEvidenceEqual(left: StorageEvidence, right: StorageEvidence): boolean {
  try {
    const leftEvidence = captureStorageEvidence(left);
    const rightEvidence = captureStorageEvidence(right);
    if (!leftEvidence || !rightEvidence || leftEvidence.kind !== 'supported' || rightEvidence.kind !== 'supported') {
      return false;
    }
    const leftRecord = leftEvidence.values;
    const rightRecord = rightEvidence.values;
    const leftTruncation = leftEvidence.truncation;
    const rightTruncation = rightEvidence.truncation;
    const leftDescriptorFlags = leftEvidence.descriptorFlags;
    const rightDescriptorFlags = rightEvidence.descriptorFlags;
    const leftTruncationDescriptorFlags = leftEvidence.truncationDescriptorFlags;
    const rightTruncationDescriptorFlags = rightEvidence.truncationDescriptorFlags;
    return (
      descriptorFlagsEqual(STORAGE_EVIDENCE_KEYS, leftDescriptorFlags, rightDescriptorFlags) &&
      descriptorFlagsEqual(
        STORAGE_TRUNCATION_KEYS,
        leftTruncationDescriptorFlags,
        rightTruncationDescriptorFlags
      ) &&
      leftRecord.recordCount === rightRecord.recordCount &&
      leftRecord.digestCount === rightRecord.digestCount &&
      leftRecord.recordLimit === rightRecord.recordLimit &&
      leftRecord.cookieCount === rightRecord.cookieCount &&
      leftRecord.localStorageEntryCount === rightRecord.localStorageEntryCount &&
      leftRecord.sessionStorageEntryCount === rightRecord.sessionStorageEntryCount &&
      leftRecord.indexedDbSupported === rightRecord.indexedDbSupported &&
      leftRecord.indexedDbRecordCount === rightRecord.indexedDbRecordCount &&
      leftRecord.indexedDbUnexpectedDatabaseCount === rightRecord.indexedDbUnexpectedDatabaseCount &&
      leftRecord.indexedDbDatabaseCount === rightRecord.indexedDbDatabaseCount &&
      leftRecord.indexedDbStoreCount === rightRecord.indexedDbStoreCount &&
      leftRecord.cookieTruncated === rightRecord.cookieTruncated &&
      leftRecord.localStorageTruncated === rightRecord.localStorageTruncated &&
      leftRecord.sessionStorageTruncated === rightRecord.sessionStorageTruncated &&
      leftRecord.indexedDbTruncated === rightRecord.indexedDbTruncated &&
      leftTruncation.any === rightTruncation.any &&
      leftTruncation.cookie === rightTruncation.cookie &&
      leftTruncation.localStorage === rightTruncation.localStorage &&
      leftTruncation.sessionStorage === rightTruncation.sessionStorage &&
      leftTruncation.indexedDb === rightTruncation.indexedDb &&
      leftRecord.fingerprint === rightRecord.fingerprint
    );
  } catch {
    return false;
  }
}

async function writeIndexedDbValue(page: Page, value: string): Promise<void> {
  await page.evaluate(
    async ({ databaseName, objectKey, objectStoreName, nextValue }) => {
      if (typeof indexedDB === 'undefined') return;
      await new Promise<void>((resolve, reject) => {
        let settled = false;
        const finish = (error?: Error): void => {
          if (settled) return;
          settled = true;
          if (error) reject(error);
          else resolve();
        };
        const request = indexedDB.open(databaseName, 1);
        request.onupgradeneeded = () => {
          try {
            if (!request.result.objectStoreNames.contains(objectStoreName)) {
              request.result.createObjectStore(objectStoreName);
            }
          } catch {
            finish(new Error('idb-upgrade'));
          }
        };
        request.onerror = () => finish(new Error('idb-open'));
        request.onblocked = () => finish(new Error('idb-blocked'));
        request.onsuccess = () => {
          const database = request.result;
          try {
            const transaction = database.transaction(objectStoreName, 'readwrite');
            transaction.objectStore(objectStoreName).put(nextValue, objectKey);
            transaction.oncomplete = () => {
              database.close();
              finish();
            };
            transaction.onerror = () => {
              database.close();
              finish(new Error('idb-write'));
            };
            transaction.onabort = () => {
              database.close();
              finish(new Error('idb-abort'));
            };
          } catch {
            database.close();
            finish(new Error('idb-write'));
          }
        };
      });
    },
    {
      databaseName: STORAGE_DATABASE,
      objectKey: STORAGE_OBJECT_KEY,
      objectStoreName: STORAGE_OBJECT_STORE,
      nextValue: value
    }
  );
}

export async function seedNativeStorage(page: Page): Promise<void> {
  await page.evaluate(
    ({ cookieName, localKey, sessionKey, value }) => {
      document.cookie = `${cookieName}=${value}; Path=/; SameSite=Lax`;
      localStorage.setItem(localKey, value);
      sessionStorage.setItem(sessionKey, value);
    },
    { cookieName: STORAGE_COOKIE, localKey: STORAGE_LOCAL_KEY, sessionKey: STORAGE_SESSION_KEY, value: STORAGE_VALUE }
  );
  await writeIndexedDbValue(page, STORAGE_VALUE);
}

export async function overwriteNativeStorage(page: Page): Promise<void> {
  await page.evaluate(
    ({ cookieName, localKey, sessionKey, value }) => {
      document.cookie = `${cookieName}=${value}; Path=/; SameSite=Lax`;
      localStorage.setItem(localKey, value);
      sessionStorage.setItem(sessionKey, value);
    },
    {
      cookieName: STORAGE_COOKIE,
      localKey: STORAGE_LOCAL_KEY,
      sessionKey: STORAGE_SESSION_KEY,
      value: STORAGE_OVERWRITE_VALUE
    }
  );
  await writeIndexedDbValue(page, STORAGE_OVERWRITE_VALUE);
}

export async function clearNativeStorage(page: Page): Promise<void> {
  let result: { failures: string[] };
  try {
    result = await page.evaluate(
      async ({ cookieName, databaseName, localKey, hmacKeyGlobal, hmacStateKind, restoreHmac, sessionKey }) => {
        const failures: string[] = [];
        const markFailure = (name: string): void => {
          if (!failures.includes(name)) failures.push(name);
        };
        const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
        const defineProperty = Object.defineProperty;
        const isDataDescriptor = (descriptor: PropertyDescriptor | undefined): descriptor is PropertyDescriptor =>
          descriptor !== undefined &&
          getOwnPropertyDescriptor(descriptor, 'value') !== undefined &&
          getOwnPropertyDescriptor(descriptor, 'get') === undefined &&
          getOwnPropertyDescriptor(descriptor, 'set') === undefined;
        const sameDescriptor = (
          actual: PropertyDescriptor | undefined,
          expected: PropertyDescriptor | undefined
        ): boolean => {
          if (actual === undefined || expected === undefined) return actual === expected;
          if (
            actual.enumerable !== expected.enumerable ||
            actual.configurable !== expected.configurable ||
            isDataDescriptor(actual) !== isDataDescriptor(expected)
          ) {
            return false;
          }
          if (isDataDescriptor(actual) && isDataDescriptor(expected)) {
            return actual.writable === expected.writable && actual.value === expected.value;
          }
          return actual.get === expected.get && actual.set === expected.set;
        };

        try {
          document.cookie = `${cookieName}=; Max-Age=0; Path=/; SameSite=Lax`;
          if (document.cookie.split(';').some((entry) => entry.trim().startsWith(`${cookieName}=`))) {
            markFailure('cookie-remaining');
          }
        } catch {
          markFailure('cookie-clear');
        }
        try {
          localStorage.removeItem(localKey);
          if (localStorage.getItem(localKey) !== null) markFailure('local-storage-remaining');
        } catch {
          markFailure('local-storage-clear');
        }
        try {
          sessionStorage.removeItem(sessionKey);
          if (sessionStorage.getItem(sessionKey) !== null) markFailure('session-storage-remaining');
        } catch {
          markFailure('session-storage-clear');
        }

        if (typeof indexedDB !== 'undefined') {
          try {
            const deleted = await new Promise<boolean>((resolve) => {
              let settled = false;
              const finish = (success: boolean): void => {
                if (settled) return;
                settled = true;
                resolve(success);
              };
              let request: IDBOpenDBRequest;
              try {
                request = indexedDB.deleteDatabase(databaseName);
              } catch {
                finish(false);
                return;
              }
              request.onsuccess = () => finish(true);
              request.onerror = () => finish(false);
              request.onblocked = () => finish(false);
            });
            if (!deleted) markFailure('indexed-db-clear');
          } catch {
            markFailure('indexed-db-clear');
          }
        }

        // Restore only the exact state object installed by this helper. A
        // replacement global, even with the same kind string, is never touched.
        if (restoreHmac) {
          try {
            const globals = globalThis as typeof globalThis & Record<string, unknown>;
            const descriptor = getOwnPropertyDescriptor(globals, hmacKeyGlobal);
            if (descriptor) {
              if (!isDataDescriptor(descriptor)) {
                markFailure('hmac-global');
              } else {
                const state = descriptor.value;
                if (typeof state !== 'object' || state === null) {
                  markFailure('hmac-global');
                } else {
                  const kindDescriptor = getOwnPropertyDescriptor(state, 'kind');
                  const ownerDescriptor = getOwnPropertyDescriptor(state, 'ownerToken');
                  const priorDescriptorDescriptor = getOwnPropertyDescriptor(state, 'priorDescriptor');
                  if (
                    !isDataDescriptor(kindDescriptor) ||
                    !isDataDescriptor(ownerDescriptor) ||
                    !isDataDescriptor(priorDescriptorDescriptor) ||
                    kindDescriptor.value !== hmacStateKind ||
                    ownerDescriptor.value !== state
                  ) {
                    markFailure('hmac-global');
                  } else {
                    const priorDescriptor = priorDescriptorDescriptor.value as PropertyDescriptor | undefined;
                    if (priorDescriptor !== undefined && typeof priorDescriptor !== 'object') {
                      markFailure('hmac-global');
                    } else {
                      try {
                        if (priorDescriptor) {
                          defineProperty(globals, hmacKeyGlobal, priorDescriptor);
                        } else if (descriptor.configurable === true) {
                          if (!delete globals[hmacKeyGlobal]) markFailure('hmac-global');
                        } else {
                          markFailure('hmac-global');
                        }
                      } catch {
                        markFailure('hmac-global');
                      }
                      if (!sameDescriptor(getOwnPropertyDescriptor(globals, hmacKeyGlobal), priorDescriptor)) {
                        markFailure('hmac-global');
                      }
                    }
                  }
                }
              }
            }
          } catch {
            markFailure('hmac-global');
          }
        }

        return { failures };
      },
      {
        cookieName: STORAGE_COOKIE,
        databaseName: STORAGE_DATABASE,
        localKey: STORAGE_LOCAL_KEY,
        hmacKeyGlobal: STORAGE_HMAC_KEY_GLOBAL,
        hmacStateKind: STORAGE_HMAC_STATE_KIND,
        restoreHmac: hmacOwnershipPages.has(page),
        sessionKey: STORAGE_SESSION_KEY
      }
    );
  } catch {
    throw new Error('Native storage cleanup failed: page-evaluate');
  }
  if (result.failures.length > 0) {
    throw new Error(`Native storage cleanup failed: ${result.failures.join(',')}`);
  }
  cookieHmacKeys.delete(page);
  hmacOwnershipPages.delete(page);
}

export type NativeCredentialProofInstallOptions = {
  injectFailure?: 'after-formdata-install';
};

export async function installNativeCredentialProof(
  page: Page,
  options: NativeCredentialProofInstallOptions = {}
): Promise<void> {
  await page.evaluate(
    ({ globalName, injectFailure }) => {
      const windowRecord = window as unknown as Record<string, unknown>;
      const form = document.querySelector('form[aria-label="Hermes password sign in"]') as HTMLFormElement | null;
      if (!form) throw new Error('Native auth proof form is unavailable.');
      const liveUsernameMatches = Array.from(form.querySelectorAll('input#auth-username')) as HTMLInputElement[];
      const livePasswordMatches = Array.from(form.querySelectorAll('input#auth-password')) as HTMLInputElement[];
      const fixtureUsernameMatches = Array.from(
        form.querySelectorAll('input[data-fixture-field="username"]')
      ) as HTMLInputElement[];
      const fixturePasswordMatches = Array.from(
        form.querySelectorAll('input[data-fixture-field="password"]')
      ) as HTMLInputElement[];
      const liveShape = liveUsernameMatches.length === 1 && livePasswordMatches.length === 1;
      const fixtureShape = fixtureUsernameMatches.length === 1 && fixturePasswordMatches.length === 1;
      const fixtureForm = form.getAttribute('data-form-type') === 'other';
      const mode = !fixtureForm && liveShape && fixtureUsernameMatches.length === 0 && fixturePasswordMatches.length === 0
        ? 'live'
        : fixtureForm && fixtureShape && liveShape
          ? 'fixture'
          : undefined;
      if (!mode) throw new Error('Native auth proof controls are ambiguous.');
      const username = mode === 'live' ? liveUsernameMatches[0] : fixtureUsernameMatches[0];
      const password = mode === 'live' ? livePasswordMatches[0] : fixturePasswordMatches[0];
      const unexpectedInput = form.querySelector('input:not(#auth-username):not(#auth-password)');
      const usernameBeforePassword = Boolean(
        username.compareDocumentPosition(password) & Node.DOCUMENT_POSITION_FOLLOWING
      );
      const visible = (input: HTMLInputElement): boolean => {
        const style = getComputedStyle(input);
        const box = input.getBoundingClientRect();
        return !input.hidden && style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0' &&
          box.width > 0 && box.height > 0;
      };
      if (
        unexpectedInput ||
        !usernameBeforePassword ||
        !visible(username) ||
        !visible(password)
      ) {
        throw new Error('Native auth proof controls are not the reviewed pair.');
      }
      const controls = { username, password };

      const originalFormDataDescriptor = Object.getOwnPropertyDescriptor(window, 'FormData');
      const previousGlobalDescriptor = Object.getOwnPropertyDescriptor(window, globalName);
      const originalFormData = window.FormData;
      const state = {
        mode,
        username: `native-proof-${crypto.randomUUID()}`,
        password: `native-proof-${crypto.randomUUID()}`,
        formDataEventCount: 0,
        formDataConstructionCount: 0,
        formDataCredentialEntryCount: 0,
        originalFormData,
        originalFormDataDescriptor,
        previousGlobalDescriptor,
        formDataProxy: undefined as typeof FormData | undefined,
        formDataListener: undefined as ((event: Event) => void) | undefined
      };
      let proof: {
        kind: 'native-auth-proof';
        mode: 'live' | 'fixture';
        form: HTMLFormElement;
        username: HTMLInputElement;
        password: HTMLInputElement;
        state: typeof state;
        cleanup: () => string[];
      };
      const cleanup = (): string[] => {
        const failures: string[] = [];
        const markFailure = (name: string): void => {
          if (!failures.includes(name)) failures.push(name);
        };
        const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
        const isDataDescriptor = (descriptor: PropertyDescriptor | undefined): descriptor is PropertyDescriptor =>
          descriptor !== undefined &&
          getOwnPropertyDescriptor(descriptor, 'value') !== undefined &&
          getOwnPropertyDescriptor(descriptor, 'get') === undefined &&
          getOwnPropertyDescriptor(descriptor, 'set') === undefined;
        const sameDescriptor = (
          actual: PropertyDescriptor | undefined,
          expected: PropertyDescriptor | undefined
        ): boolean => {
          if (actual === undefined || expected === undefined) return actual === expected;
          if (
            actual.enumerable !== expected.enumerable ||
            actual.configurable !== expected.configurable ||
            isDataDescriptor(actual) !== isDataDescriptor(expected)
          ) {
            return false;
          }
          if (isDataDescriptor(actual) && isDataDescriptor(expected)) {
            return actual.writable === expected.writable && actual.value === expected.value;
          }
          return actual.get === expected.get && actual.set === expected.set;
        };
        const clearControl = (name: string, control: HTMLInputElement): void => {
          try {
            control.value = '';
            if (control.value !== '') markFailure(`${name}-live`);
          } catch {
            markFailure(`${name}-live`);
          }
          try {
            control.defaultValue = '';
            if (control.defaultValue !== '') markFailure(`${name}-default`);
          } catch {
            markFailure(`${name}-default`);
          }
          try {
            control.removeAttribute('value');
            if (control.hasAttribute('value')) markFailure(`${name}-serialized`);
          } catch {
            markFailure(`${name}-serialized`);
          }
        };

        clearControl('username', controls.username);
        clearControl('password', controls.password);

        const listener = state.formDataListener;
        if (listener) {
          try {
            form.removeEventListener('formdata', listener);
            state.formDataListener = undefined;
          } catch {
            // Keep the listener reference so a later scrub can retry removal.
            markFailure('formdata-listener');
          }
        }

        try {
          state.username = '';
          if (state.username !== '') markFailure('username-state');
        } catch {
          markFailure('username-state');
        }
        try {
          state.password = '';
          if (state.password !== '') markFailure('password-state');
        } catch {
          markFailure('password-state');
        }

        if (state.formDataProxy) {
          try {
            const currentFormData = window.FormData;
            if (currentFormData === state.formDataProxy) {
              if (originalFormDataDescriptor) {
                Object.defineProperty(window, 'FormData', originalFormDataDescriptor);
              } else if (!delete windowRecord.FormData) {
                markFailure('formdata-global');
              }
              if (!sameDescriptor(getOwnPropertyDescriptor(window, 'FormData'), originalFormDataDescriptor)) {
                markFailure('formdata-global');
              } else {
                state.formDataProxy = undefined;
              }
            } else if (currentFormData === originalFormData &&
              sameDescriptor(getOwnPropertyDescriptor(window, 'FormData'), originalFormDataDescriptor)) {
              state.formDataProxy = undefined;
            } else {
              // Never clobber a replacement constructor; retain ownership for retry.
              markFailure('formdata-replaced');
            }
          } catch {
            markFailure('formdata-global');
          }
        }

        // Keep the published proof handle until every earlier cleanup step has
        // succeeded. This preserves listener and descriptor ownership for retry.
        if (failures.length === 0) {
          try {
            const currentDescriptor = getOwnPropertyDescriptor(window, globalName);
            const currentValue = currentDescriptor && isDataDescriptor(currentDescriptor)
              ? currentDescriptor.value
              : undefined;
            if (currentValue === proof) {
              if (previousGlobalDescriptor) {
                Object.defineProperty(window, globalName, previousGlobalDescriptor);
              } else if (!delete windowRecord[globalName]) {
                markFailure('proof-global');
              }
              if (!sameDescriptor(getOwnPropertyDescriptor(window, globalName), previousGlobalDescriptor)) {
                markFailure('proof-global');
              }
            } else if (!sameDescriptor(currentDescriptor, previousGlobalDescriptor)) {
              // Do not remove or overwrite a replacement global.
              markFailure('proof-global-replaced');
            }
          } catch {
            markFailure('proof-global');
          }
        }
        return failures;
      };

      // Publish the cleanup handle before any listener or constructor mutation.
      // This makes an interrupted install recoverable by the outer finally block.
      proof = {
        kind: 'native-auth-proof',
        mode,
        form,
        username: controls.username,
        password: controls.password,
        state,
        cleanup
      };
      try {
        if (previousGlobalDescriptor && 'writable' in previousGlobalDescriptor) {
          Object.defineProperty(window, globalName, {
            ...previousGlobalDescriptor,
            enumerable: false,
            value: proof
          });
        } else {
          Object.defineProperty(window, globalName, {
            configurable: previousGlobalDescriptor?.configurable ?? true,
            enumerable: false,
            writable: true,
            value: proof
          });
        }

        state.formDataListener = (event: Event) => {
          state.formDataEventCount += 1;
          const formData = (event as FormDataEvent).formData;
          for (const [, value] of formData.entries()) {
            if (value === state.username || value === state.password) state.formDataCredentialEntryCount += 1;
          }
        };
        form.addEventListener('formdata', state.formDataListener);

        const formDataProxy = new Proxy(state.originalFormData, {
          construct(target, argumentsList, newTarget) {
            state.formDataConstructionCount += 1;
            const formData = Reflect.construct(target, argumentsList, newTarget) as FormData;
            for (const [, value] of formData.entries()) {
              if (value === state.username || value === state.password) state.formDataCredentialEntryCount += 1;
            }
            return formData;
          }
        });
        state.formDataProxy = formDataProxy;
        const descriptor = state.originalFormDataDescriptor;
        if (descriptor && 'writable' in descriptor) {
          Object.defineProperty(window, 'FormData', { ...descriptor, value: formDataProxy });
        } else {
          Object.defineProperty(window, 'FormData', {
            configurable: descriptor?.configurable ?? true,
            enumerable: descriptor?.enumerable ?? true,
            writable: true,
            value: formDataProxy
          });
        }

        if (injectFailure === 'after-formdata-install') {
          throw new Error('Injected native auth proof install failure.');
        }

        const valueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
        if (!valueSetter) throw new Error('Input value setter is unavailable.');
        valueSetter.call(controls.username, state.username);
        valueSetter.call(controls.password, state.password);
        controls.username.dispatchEvent(new Event('input', { bubbles: true }));
        controls.password.dispatchEvent(new Event('input', { bubbles: true }));
      } catch (error) {
        const cleanupFailures = cleanup();
        if (cleanupFailures.length > 0) throw new Error('Native auth proof install cleanup failed.');
        throw error;
      }
    },
    { globalName: AUTH_PROOF_GLOBAL, injectFailure: options.injectFailure }
  );
}

export async function readNativeCredentialEvidence(page: Page): Promise<NativeCredentialEvidence> {
  return await page.evaluate((globalName): NativeCredentialEvidence => {
    const emptyEvidence = (): NativeCredentialEvidence => ({
      liveValueMatchCount: 0,
      liveNonEmptyCount: 0,
      defaultValueMatchCount: 0,
      serializedCredentialCount: 0,
      formDataEventCount: 0,
      formDataConstructionCount: 0,
      formDataCredentialEntryCount: 0
    });
    const proof = (window as unknown as Record<string, unknown>)[globalName] as
      | {
          kind: 'native-auth-proof';
          mode: 'live' | 'fixture';
          form: HTMLFormElement;
          username: HTMLInputElement;
          password: HTMLInputElement;
          state: {
            username: string;
            password: string;
            formDataEventCount: number;
            formDataConstructionCount: number;
            formDataCredentialEntryCount: number;
          };
        }
      | undefined;
    if (!proof || proof.kind !== 'native-auth-proof') return emptyEvidence();

    const selectors = proof.mode === 'live'
      ? { username: 'input#auth-username', password: 'input#auth-password' }
      : { username: 'input[data-fixture-field="username"]', password: 'input[data-fixture-field="password"]' };
    const usernameMatches = Array.from(proof.form.querySelectorAll(selectors.username));
    const passwordMatches = Array.from(proof.form.querySelectorAll(selectors.password));
    const unexpectedInput = proof.form.querySelector('input:not(#auth-username):not(#auth-password)');
    const usernameBeforePassword = Boolean(
      proof.username.compareDocumentPosition(proof.password) & Node.DOCUMENT_POSITION_FOLLOWING
    );
    const visible = (input: HTMLInputElement): boolean => {
      const style = getComputedStyle(input);
      const box = input.getBoundingClientRect();
      return !input.hidden && style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0' &&
        box.width > 0 && box.height > 0;
    };
    if (
      !proof.form.isConnected ||
      usernameMatches.length !== 1 ||
      passwordMatches.length !== 1 ||
      usernameMatches[0] !== proof.username ||
      passwordMatches[0] !== proof.password ||
      unexpectedInput ||
      !usernameBeforePassword ||
      proof.username.form !== proof.form ||
      proof.password.form !== proof.form ||
      !visible(proof.username) ||
      !visible(proof.password)
    ) {
      throw new Error('Native auth proof controls changed.');
    }

    const expected = [proof.state.username, proof.state.password];
    const markup = document.documentElement.outerHTML;
    return {
      liveValueMatchCount: Number(proof.username.value === expected[0]) + Number(proof.password.value === expected[1]),
      liveNonEmptyCount: Number(proof.username.value !== '') + Number(proof.password.value !== ''),
      defaultValueMatchCount: Number(proof.username.defaultValue === expected[0]) + Number(proof.password.defaultValue === expected[1]),
      serializedCredentialCount: expected.reduce((count, value) => count + Number(markup.includes(value)), 0),
      formDataEventCount: proof.state.formDataEventCount,
      formDataConstructionCount: proof.state.formDataConstructionCount,
      formDataCredentialEntryCount: proof.state.formDataCredentialEntryCount
    };
  }, AUTH_PROOF_GLOBAL);
}

export async function scrubNativeCredentialProof(page: Page): Promise<void> {
  let result: { failures: string[] };
  try {
    result = await page.evaluate((globalName) => {
      const failures: string[] = [];
      const markFailure = (name: string): void => {
        if (!failures.includes(name)) failures.push(name);
      };
      const windowRecord = window as unknown as Record<string, unknown>;
      const proof = windowRecord[globalName] as
        | {
            kind?: string;
            form?: HTMLFormElement;
            username?: HTMLInputElement;
            password?: HTMLInputElement;
            cleanup?: () => string[];
          }
        | undefined;
      const activeProof = proof?.kind === 'native-auth-proof' ? proof : undefined;

      // Prefer the page-published transaction handle. Its cleanup retains any
      // unresolved listener or descriptor ownership for a later retry.
      if (activeProof?.cleanup) {
        try {
          for (const failure of activeProof.cleanup()) markFailure(failure);
        } catch {
          markFailure('proof-cleanup');
        }
      }

      if (!activeProof) {
        const form = document.querySelector('form[aria-label="Hermes password sign in"]');
        const fallbackUsername = form?.querySelector(
          'input[autocomplete="username"], input[data-fixture-field="username"]'
        ) as HTMLInputElement | null;
        const fallbackPassword = form?.querySelector(
          'input[autocomplete="current-password"], input[data-fixture-field="password"]'
        ) as HTMLInputElement | null;
        const controls = [fallbackUsername, fallbackPassword].filter(
          (control): control is HTMLInputElement => control !== null
        );
        for (const [index, control] of controls.entries()) {
          const name = index === 0 ? 'username' : 'password';
          try {
            control.value = '';
            if (control.value !== '') markFailure(`${name}-live`);
          } catch {
            markFailure(`${name}-live`);
          }
          try {
            control.defaultValue = '';
            if (control.defaultValue !== '') markFailure(`${name}-default`);
          } catch {
            markFailure(`${name}-default`);
          }
          try {
            control.removeAttribute('value');
            if (control.hasAttribute('value')) markFailure(`${name}-serialized`);
          } catch {
            markFailure(`${name}-serialized`);
          }
        }
      }
      return { failures };
    }, AUTH_PROOF_GLOBAL);
  } catch {
    throw new Error('Native auth proof cleanup failed: page-evaluate');
  }
  if (result.failures.length > 0) {
    throw new Error(`Native auth proof cleanup failed: ${result.failures.join(',')}`);
  }
}
