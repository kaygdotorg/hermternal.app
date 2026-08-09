export const LIVE_PROOF_PROMPT = 'Reply with exactly: Hermternal live proof complete.';
export const LIVE_PROOF_ASSISTANT_MARKER = 'Hermternal live proof complete.';

const DEFAULT_MAX_EVENTS = 256;
const MAX_ID_LENGTH = 256;
const MAX_ROUTE_LENGTH = 256;
const MAX_METHOD_LENGTH = 64;
const MAX_EVENT_NAME_LENGTH = 96;
const MAX_STATUS_LENGTH = 32;
const MAX_MESSAGE_COUNT = 10_000;
export const LIVE_PROOF_HISTORY_LIMIT = 500;
const HMAC_TAG_PATTERN = /^h1:[0-9a-f]{64}$/u;
const RAW_ID_KEYS = Object.freeze(['requestId', 'sessionId', 'storedSessionId']);

/** @typedef {{ kind: 'page', sign?: never } | { kind: 'test', sign: (domain: string, value: string) => string }} LiveProofSigner */

const LIVE_PROOF_CAPTURE_KEYS = Object.freeze([
  'ordered',
  'websocketOpen',
  'gatewayReady',
  'serverFirstReady',
  'sessionAction',
  'prompt',
  'promptAcknowledgement',
  'delta',
  'completion',
  'history',
  'historyStatusOk',
  'messageCount',
  'promptCount',
  'completionCount'
]);

/**
 * Canonicalize dynamic REST session routes before they enter the retained
 * ledger. The route template is intentionally fixed: a route event can prove
 * which operation ran without retaining an opaque session identity or query.
 * Unknown descendants remain classified, never copied into the event.
 *
 * @param {string} value
 */
export function normalizeLiveProofRoute(value) {
  const pathname = value.split(/[?#]/u, 1)[0];
  if (pathname === '/api/sessions' || pathname === '/api/sessions/search') return pathname;
  const segments = pathname.split('/');
  if (segments[1] !== 'api' || segments[2] !== 'sessions' || segments.length < 4) {
    return pathname;
  }
  if (segments.length === 5 && segments[3].length > 0 && segments[4] === 'messages') {
    return '/api/sessions/:sessionId/messages';
  }
  if (segments.length === 4 && segments[3].length > 0) {
    return '/api/sessions/:sessionId';
  }
  return '/api/sessions/:sessionId/unknown';
}

/** @param {unknown} value */
function boundedRawId(value) {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_ID_LENGTH) {
    throw new Error('live proof ledger received an unsafe identity');
  }
  return value;
}

/** @param {unknown} value */
function boundedTag(value) {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || !HMAC_TAG_PATTERN.test(value)) {
    throw new Error('live proof ledger received an unsafe identity tag');
  }
  return value;
}

/** @param {unknown} value */
function requiredTag(value) {
  const tag = boundedTag(value);
  if (!tag) throw new Error('live proof history identity tag was not produced');
  return tag;
}

/**
 * This signer exists only so synchronous unit tests can exercise the ledger
 * without a browser. It is deliberately not cryptographic and is never used
 * by the production page lane. Production callers must pass the page signer
 * mode and supply tags created by the page-local nonextractable CryptoKey.
 *
 * @param {string} domain
 * @param {string} value
 */
function deterministicTestTag(domain, value) {
  const input = `${domain}\0${value}`;
  let state = 0x811c9dc5;
  for (let index = 0; index < input.length; index += 1) {
    state ^= input.charCodeAt(index);
    state = Math.imul(state, 0x01000193) >>> 0;
  }
  let hex = '';
  for (let lane = 0; lane < 8; lane += 1) {
    state = (state ^ (state >>> 13)) >>> 0;
    state = Math.imul(state, 0x5bd1e995) >>> 0;
    state = (state ^ (state >>> 15)) >>> 0;
    hex += state.toString(16).padStart(8, '0');
  }
  return `h1:${hex}`;
}

/**
 * Explicit deterministic signer for unit tests only. Keeping it in the test
 * ledger module makes the production factory fail closed when no page signer
 * is supplied without importing Node crypto or retaining a production key.
 */
export function createLiveProofTestSigner() {
  /** @type {{ kind: 'test', sign: (domain: string, value: string) => string }} */
  const signer = {
    kind: 'test',
    sign(domain, value) {
      if (typeof domain !== 'string' || typeof value !== 'string') {
        throw new Error('live proof test signer input is invalid');
      }
      return deterministicTestTag(domain, value);
    }
  };
  return Object.freeze(signer);
}

/** @param {unknown} value */
function boundedMessageId(value) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error('live proof history message identity is invalid');
  }
  return value;
}

/** @param {unknown} value */
function boundedRoute(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_ROUTE_LENGTH) {
    throw new Error('live proof ledger received an unsafe route');
  }
  return normalizeLiveProofRoute(value);
}

/** @param {unknown} value */
function boundedMethod(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_METHOD_LENGTH) {
    throw new Error('live proof ledger received an unsafe method');
  }
  return value;
}

/** @param {unknown} value */
function boundedEventName(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_EVENT_NAME_LENGTH) {
    throw new Error('live proof ledger received an unsafe event');
  }
  return value;
}

/** @param {unknown} value */
function boundedStatus(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_STATUS_LENGTH) {
    throw new Error('live proof ledger received an unsafe status');
  }
  return value;
}

/** @param {unknown} value */
function boundedCount(value) {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > MAX_MESSAGE_COUNT) {
    throw new Error('live proof ledger received an unsafe count');
  }
  return value;
}

/** @param {unknown} value */
function boundedHistoryPhase(value) {
  if (value !== 'pre-send' && value !== 'post-completion') {
    throw new Error('live proof ledger received an unsafe history phase');
  }
  return value;
}

/**
 * Keep only typed, assertion-local projections. Production tags must be made
 * in the page realm by a nonextractable Web Crypto HMAC key. The Node ledger
 * accepts those tags but never owns a key or receives the source identity.
 *
 * The deterministic signer is available only through the explicit unit-test
 * escape hatch. Omitting a signer or passing any other signer mode fails closed.
 *
 * @param {number} maxEvents
 * @param {{ signer?: LiveProofSigner, allowTestSigner?: boolean }} options
 */
export function createLiveProofLedger(maxEvents = DEFAULT_MAX_EVENTS, options = {}) {
  if (!Number.isInteger(maxEvents) || maxEvents < 16 || maxEvents > 1024) {
    throw new Error('live proof ledger capacity is not bounded');
  }
  const signer = options?.signer;
  if (!signer || (signer.kind !== 'page' && signer.kind !== 'test')) {
    throw new Error('live proof ledger requires a page-local signer');
  }
  if (signer.kind === 'test' && options.allowTestSigner !== true) {
    throw new Error('live proof test signer requires explicit test opt-in');
  }
  if (signer.kind === 'test' && typeof signer.sign !== 'function') {
    throw new Error('live proof test signer is incomplete');
  }
  const trustedSigner = /** @type {LiveProofSigner} */ (signer);
  /** @type {Array<Record<string, unknown>>} */
  const events = [];
  let nextSequence = 0;

  /** @param {unknown} value */
  const identityTag = (value) => {
    if (trustedSigner.kind !== 'test') {
      throw new Error('production identity tags must come from the page realm');
    }
    const raw = boundedRawId(value);
    return raw === undefined ? undefined : requiredTag(trustedSigner.sign('identity', raw));
  };

  /** @param {unknown} values */
  const messageProjectionTag = (values) => {
    if (trustedSigner.kind !== 'test') {
      throw new Error('production history tags must come from the page realm');
    }
    if (!Array.isArray(values) || !Number.isSafeInteger(values.length) || values.length > LIVE_PROOF_HISTORY_LIMIT) {
      throw new Error('live proof history message projection sequence is not bounded');
    }
    const trustedValues = readStrictArray(values, 'live proof history message projection sequence');
    const projections = trustedValues.map(canonicalHistoryMessage);
    return requiredTag(trustedSigner.sign('message-projection-sequence', JSON.stringify(projections)));
  };

  /** @param {Record<string, unknown>} event @param {string} tagKey @param {string} rawKey */
  function eventTag(event, tagKey, rawKey) {
    if (Object.prototype.hasOwnProperty.call(event, tagKey)) {
      return boundedTag(event[tagKey]);
    }
    if (Object.prototype.hasOwnProperty.call(event, rawKey)) {
      if (trustedSigner.kind !== 'test') {
        throw new Error('production ledger received a raw dynamic identity');
      }
      return identityTag(event[rawKey]);
    }
    return undefined;
  }

  /** @param {Record<string, unknown>} event */
  function rejectRawIdentityFields(event) {
    if (trustedSigner.kind === 'page' && RAW_ID_KEYS.some((key) => Object.prototype.hasOwnProperty.call(event, key))) {
      throw new Error('production ledger received a raw dynamic identity');
    }
  }

  /** @param {Record<string, unknown>} event */
  function append(event) {
    if (events.length >= maxEvents) {
      throw new Error('live proof ledger capacity was exceeded');
    }
    nextSequence += 1;
    const projected = Object.freeze({ sequence: nextSequence, ...event });
    events.push(projected);
    return projected;
  }

  return Object.freeze({
    /** Tag one transient raw identity without retaining it. */
    identityTag,
    /** Tag one transient canonical history-message sequence without retaining rows. */
    messageProjectionTag,
    /** @param {{ method: string, route: string }} event */
    recordHttpRequest(event) {
      return append({
        kind: 'http.request',
        method: boundedMethod(event.method),
        route: boundedRoute(event.route)
      });
    },
    /** @param {{ method: string, route: string, status: number }} event */
    recordHttpResponse(event) {
      if (!Number.isInteger(event.status) || event.status < 100 || event.status > 599) {
        throw new Error('live proof ledger received an unsafe HTTP status');
      }
      return append({
        kind: 'http.response',
        method: boundedMethod(event.method),
        route: boundedRoute(event.route),
        status: event.status
      });
    },
    /** @param {{ route: string, ticketOnly: boolean, originBound: boolean }} event */
    recordWebSocketOpen(event) {
      if (event.originBound !== true) {
        throw new Error('live proof WebSocket origin was not page-bound');
      }
      return append({
        kind: 'ws.open',
        route: boundedRoute(event.route),
        ticketOnly: event.ticketOnly === true,
        originBound: true
      });
    },
    /**
     * Production callers provide only page-produced tags. Raw identity aliases
     * remain accepted solely for explicit deterministic unit-test signers.
     * @param {{ method: string, requestTag?: string, sessionTag?: string, requestId?: string, sessionId?: string }} event
     */
    recordWebSocketSent(event) {
      rejectRawIdentityFields(event);
      return append({
        kind: 'ws.sent',
        method: boundedMethod(event.method),
        requestTag: eventTag(event, 'requestTag', 'requestId'),
        sessionTag: eventTag(event, 'sessionTag', 'sessionId')
      });
    },
    /**
     * A response projection carries a page-validated successful-result bit. A
     * request tag alone is not an acknowledgement: error, resultless, or
     * malformed JSON-RPC responses remain explicitly unsuccessful.
     * @param {{ event: string, acknowledgement?: boolean, requestTag?: string, sessionTag?: string, requestId?: string, sessionId?: string }} event
     */
    recordWebSocketReceived(event) {
      const properties = readStrictObject(
        event,
        'live proof WebSocket received event',
        ['event', 'acknowledgement', 'requestTag', 'sessionTag', 'requestId', 'sessionId']
      );
      const eventName = boundedEventName(properties.get('event'));
      const acknowledgement = properties.get('acknowledgement');
      if (eventName === 'response') {
        if (typeof acknowledgement !== 'boolean') {
          throw new Error('live proof response acknowledgement is invalid');
        }
      } else if (acknowledgement !== undefined) {
        throw new Error('live proof response acknowledgement is misplaced');
      }
      rejectRawIdentityFields(event);
      /** @param {string} tagKey @param {string} rawKey */
      const safeTag = (tagKey, rawKey) => {
        if (properties.has(tagKey)) return boundedTag(properties.get(tagKey));
        if (properties.has(rawKey)) {
          if (trustedSigner.kind !== 'test') {
            throw new Error('production ledger received a raw dynamic identity');
          }
          return identityTag(properties.get(rawKey));
        }
        return undefined;
      };
      return append({
        kind: 'ws.received',
        event: eventName,
        requestTag: safeTag('requestTag', 'requestId'),
        sessionTag: safeTag('sessionTag', 'sessionId'),
        acknowledgement: eventName === 'response' ? acknowledgement : undefined
      });
    },
    /** @param {{ sessionTag?: string, sessionId?: string }} [event] */
    recordGatewayReady(event = {}) {
      rejectRawIdentityFields(event);
      return append({
        kind: 'gateway.ready',
        sessionTag: eventTag(event, 'sessionTag', 'sessionId')
      });
    },
    /** @param {{ method: 'session.create' | 'session.resume', requestTag?: string, sessionTag?: string, storedSessionTag?: string, requestId?: string, sessionId?: string, storedSessionId?: string }} event */
    recordSessionAction(event) {
      rejectRawIdentityFields(event);
      if (event.method !== 'session.create' && event.method !== 'session.resume') {
        throw new Error('live proof ledger received an unsafe session action');
      }
      return append({
        kind: 'session.action',
        method: event.method,
        requestTag: eventTag(event, 'requestTag', 'requestId'),
        sessionTag: eventTag(event, 'sessionTag', 'sessionId'),
        storedSessionTag: eventTag(event, 'storedSessionTag', 'storedSessionId')
      });
    },
    /** @param {{ requestTag?: string, sessionTag?: string, requestId?: string, sessionId?: string, promptMatches: boolean }} event */
    recordPrompt(event) {
      rejectRawIdentityFields(event);
      return append({
        kind: 'prompt.submit',
        requestTag: eventTag(event, 'requestTag', 'requestId'),
        sessionTag: eventTag(event, 'sessionTag', 'sessionId'),
        promptMatches: event.promptMatches === true
      });
    },
    /** @param {{ requestTag?: string, sessionTag?: string, requestId?: string, sessionId?: string }} event */
    recordDelta(event) {
      rejectRawIdentityFields(event);
      return append({
        kind: 'message.delta',
        requestTag: eventTag(event, 'requestTag', 'requestId'),
        sessionTag: eventTag(event, 'sessionTag', 'sessionId')
      });
    },
    /** @param {{ requestTag?: string, sessionTag?: string, requestId?: string, sessionId?: string, status: string, markerMatches: boolean }} event */
    recordCompletion(event) {
      rejectRawIdentityFields(event);
      return append({
        kind: 'message.complete',
        requestTag: eventTag(event, 'requestTag', 'requestId'),
        sessionTag: eventTag(event, 'sessionTag', 'sessionId'),
        status: boundedStatus(event.status),
        markerMatches: event.markerMatches === true
      });
    },
    /**
     * Store only the bounded canonical-history projection. The watermark and
     * raw message rows stay transient in the one-shot read; canonical projection
     * tags are the only retained history-identity evidence.
     *
     * @param {{
     *   phase: 'pre-send'|'post-completion',
     *   status: number,
     *   sessionTag?: string,
     *   sessionId?: string,
     *   historyComplete: boolean,
     *   watermarkEstablished: boolean,
     *   prefixStable: boolean,
     *   postFenceMatched: boolean,
     *   promptMatches: boolean,
     *   assistantMarkerMatches: boolean,
     *   candidateUserCount: number,
     *   candidateAssistantCount: number,
     *   messageCount: number,
     *   historyProjectionTag?: string,
     *   prefixProjectionTag?: string
     * }} event
     */
    recordHistoryResponse(event) {
      rejectRawIdentityFields(event);
      if (!Number.isInteger(event.status) || event.status < 100 || event.status > 599) {
        throw new Error('live proof ledger received an unsafe history status');
      }
      return append({
        kind: 'history.response',
        phase: boundedHistoryPhase(event.phase),
        status: event.status,
        sessionTag: eventTag(event, 'sessionTag', 'sessionId'),
        historyComplete: event.historyComplete === true,
        watermarkEstablished: event.watermarkEstablished === true,
        prefixStable: event.prefixStable === true,
        postFenceMatched: event.postFenceMatched === true,
        promptMatches: event.promptMatches === true,
        assistantMarkerMatches: event.assistantMarkerMatches === true,
        candidateUserCount: boundedCount(event.candidateUserCount),
        candidateAssistantCount: boundedCount(event.candidateAssistantCount),
        messageCount: boundedCount(event.messageCount),
        historyProjectionTag: boundedTag(event.historyProjectionTag),
        prefixProjectionTag: boundedTag(event.prefixProjectionTag)
      });
    },
    /** @param {{ status: number, cookieJarCleared: boolean, storageCleared: boolean }} event */
    recordLogout(event) {
      if (!Number.isInteger(event.status) || event.status < 100 || event.status > 599) {
        throw new Error('live proof ledger received an unsafe logout status');
      }
      return append({
        kind: 'logout',
        status: event.status,
        cookieJarCleared: event.cookieJarCleared === true,
        storageCleared: event.storageCleared === true
      });
    },
    snapshot() {
      return events.slice();
    }
  });
}

/** @param {Array<Record<string, unknown>>} events @param {string} kind */
export function firstLiveProofEvent(events, kind) {
  return events.find((event) => event.kind === kind);
}

/** @param {Array<Record<string, unknown>>} events @param {string} kind */
function firstSequence(events, kind) {
  return firstLiveProofEvent(events, kind)?.sequence;
}

/** @param {Array<Record<string, unknown>>} events @param {string} kind */
function eventCount(events, kind) {
  return events.reduce((count, event) => count + (event.kind === kind ? 1 : 0), 0);
}

/** @param {Record<string, unknown> | undefined} event */
function sequenceOf(event) {
  return typeof event?.sequence === 'number' ? event.sequence : undefined;
}

/** @param {unknown} value */
function isEventList(value) {
  return Array.isArray(value) && value.length <= 1024 && value.every((event) => {
    return event !== null && typeof event === 'object' && !Array.isArray(event);
  });
}

/** @param {Record<string, unknown>} event */
function hasRawIdentityField(event) {
  return RAW_ID_KEYS.some((key) => Object.prototype.hasOwnProperty.call(event, key));
}

/** @param {unknown} value @returns {value is Record<string, any>} */
function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

const DESCRIPTOR_KEYS = Object.freeze(['value', 'writable', 'enumerable', 'configurable']);
const RAW_MESSAGE_KEYS = Object.freeze([
  'id', 'role', 'content', 'tool_calls', 'tool_name', 'tool_call_id', 'timestamp'
]);
const CANONICAL_MESSAGE_KEYS = Object.freeze([
  'id', 'role', 'content', 'toolCalls', 'toolName', 'toolCallId', 'timestamp'
]);
const MESSAGE_KEYS = Object.freeze([...new Set([...RAW_MESSAGE_KEYS, ...CANONICAL_MESSAGE_KEYS])]);

/**
 * @param {unknown} descriptor
 * @param {string} label
 * @returns {PropertyDescriptor}
 */
function readNativeDataDescriptor(descriptor, label) {
  if (descriptor === undefined || descriptor === null || typeof descriptor !== 'object' || Array.isArray(descriptor)) {
    throw new Error(`${label} descriptor is malformed`);
  }
  let descriptorKeys;
  try {
    descriptorKeys = Reflect.ownKeys(descriptor);
  } catch {
    throw new Error(`${label} descriptor is malformed`);
  }
  if (
    descriptorKeys.length !== DESCRIPTOR_KEYS.length ||
    descriptorKeys.some((key) => typeof key !== 'string' || !DESCRIPTOR_KEYS.includes(key))
  ) {
    throw new Error(`${label} descriptor is malformed`);
  }
  for (const key of DESCRIPTOR_KEYS) {
    const field = Object.getOwnPropertyDescriptor(descriptor, key);
    if (
      !field ||
      !Object.prototype.hasOwnProperty.call(field, 'value') ||
      Object.prototype.hasOwnProperty.call(field, 'get') ||
      Object.prototype.hasOwnProperty.call(field, 'set') ||
      field.enumerable !== true ||
      field.writable !== true ||
      field.configurable !== true
    ) {
      throw new Error(`${label} descriptor is malformed`);
    }
  }
  const typedDescriptor = /** @type {PropertyDescriptor} */ (descriptor);
  if (
    typeof typedDescriptor.writable !== 'boolean' ||
    typeof typedDescriptor.enumerable !== 'boolean' ||
    typeof typedDescriptor.configurable !== 'boolean'
  ) {
    throw new Error(`${label} descriptor is malformed`);
  }
  return typedDescriptor;
}

/** @param {unknown} value @param {string} label @param {readonly string[]|undefined} allowedKeys @param {boolean} exact */
function readStrictObject(value, label, allowedKeys = undefined, exact = false) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} is not a plain object`);
  }
  try {
    const firstPrototype = Object.getPrototypeOf(value);
    if (firstPrototype !== Object.prototype) throw new Error(`${label} is not a plain object`);
    const firstKeys = /** @type {string[]} */ (Reflect.ownKeys(value));
    const secondPrototype = Object.getPrototypeOf(value);
    const secondKeys = /** @type {string[]} */ (Reflect.ownKeys(value));
    if (
      secondPrototype !== firstPrototype ||
      firstKeys.length !== secondKeys.length ||
      firstKeys.some((key, index) => key !== secondKeys[index]) ||
      firstKeys.some((key) => typeof key !== 'string')
    ) {
      throw new Error(`${label} has unstable or symbol keys`);
    }
    const allowed = allowedKeys ? new Set(allowedKeys) : undefined;
    if (allowed && firstKeys.some((key) => !allowed.has(key))) {
      throw new Error(`${label} has unexpected keys`);
    }
    if (exact && allowed && (firstKeys.length !== allowed.size || [...allowed].some((key) => !firstKeys.includes(key)))) {
      throw new Error(`${label} has unexpected keys`);
    }
    const values = new Map();
    for (const key of firstKeys) {
      const descriptor = readNativeDataDescriptor(
        Object.getOwnPropertyDescriptor(value, key),
        `${label}.${key}`
      );
      if (descriptor.writable !== true || descriptor.enumerable !== true || descriptor.configurable !== true) {
        throw new Error(`${label}.${key} descriptor is malformed`);
      }
      const readBack = Reflect.get(value, key, value);
      if (!Object.is(readBack, descriptor.value)) {
        throw new Error(`${label}.${key} descriptor read-back changed`);
      }
      const secondDescriptor = readNativeDataDescriptor(
        Object.getOwnPropertyDescriptor(value, key),
        `${label}.${key}`
      );
      if (
        !Object.is(secondDescriptor.value, descriptor.value) ||
        secondDescriptor.writable !== descriptor.writable ||
        secondDescriptor.enumerable !== descriptor.enumerable ||
        secondDescriptor.configurable !== descriptor.configurable
      ) {
        throw new Error(`${label}.${key} descriptor changed`);
      }
      values.set(key, descriptor.value);
    }
    const finalKeys = /** @type {string[]} */ (Reflect.ownKeys(value));
    if (
      Object.getPrototypeOf(value) !== Object.prototype ||
      finalKeys.length !== firstKeys.length ||
      finalKeys.some((key, index) => key !== firstKeys[index])
    ) {
      throw new Error(`${label} has unstable or symbol keys`);
    }
    for (const key of firstKeys) {
      const finalDescriptor = readNativeDataDescriptor(
        Object.getOwnPropertyDescriptor(value, key),
        `${label}.${key}`
      );
      if (
        !Object.is(finalDescriptor.value, values.get(key)) ||
        !Object.is(Reflect.get(value, key, value), finalDescriptor.value)
      ) {
        throw new Error(`${label}.${key} descriptor changed`);
      }
    }
    return values;
  } catch (error) {
    if (
      error instanceof Error &&
      (
        error.message.startsWith(`${label} `) ||
        error.message.startsWith(`${label}.`) ||
        error.message.startsWith(`${label}[`)
      )
    ) {
      throw error;
    }
    throw new Error(`${label} is not a trusted plain object`);
  }
}

/** @param {unknown} value @param {string} label */
function readStrictArray(value, label) {
  if (!Array.isArray(value)) {
    throw new Error(`${label} is not a trusted array`);
  }
  const firstPrototype = Object.getPrototypeOf(value);
  if (firstPrototype !== Array.prototype) {
    throw new Error(`${label} is not a trusted array`);
  }
  const length = value.length;
  if (!Number.isSafeInteger(length) || length < 0) throw new Error(`${label} length is invalid`);
  let firstKeys;
  let secondKeys;
  let secondPrototype;
  try {
    firstKeys = /** @type {string[]} */ (Reflect.ownKeys(value));
    secondPrototype = Object.getPrototypeOf(value);
    secondKeys = /** @type {string[]} */ (Reflect.ownKeys(value));
  } catch {
    throw new Error(`${label} keys are invalid`);
  }
  if (
    value.length !== length ||
    secondPrototype !== firstPrototype ||
    firstKeys.length !== secondKeys.length ||
    firstKeys.some((key, index) => key !== secondKeys[index])
  ) {
    throw new Error(`${label} has unstable shape`);
  }
  if (
    firstKeys.length !== length + 1 ||
    firstKeys.some((key) => typeof key !== 'string') ||
    !firstKeys.includes('length') ||
    firstKeys.some((key) => key !== 'length' && (!/^[0-9]+$/u.test(key) || Number(key) >= length))
  ) {
    throw new Error(`${label} has unexpected keys`);
  }
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
  const normalizedLength = readNativeDataDescriptor(lengthDescriptor, `${label}.length`);
  if (
    normalizedLength.value !== length ||
    normalizedLength.writable !== true ||
    normalizedLength.enumerable !== false ||
    normalizedLength.configurable !== false
  ) {
    throw new Error(`${label}.length descriptor is malformed`);
  }
  const result = [];
  for (let index = 0; index < length; index += 1) {
    const key = String(index);
    const descriptor = readNativeDataDescriptor(
      Object.getOwnPropertyDescriptor(value, key),
      `${label}[${index}]`
    );
    if (descriptor.writable !== true || descriptor.enumerable !== true || descriptor.configurable !== true) {
      throw new Error(`${label}[${index}] descriptor is malformed`);
    }
    const readBack = Reflect.get(value, key, value);
    if (!Object.is(readBack, descriptor.value)) {
      throw new Error(`${label}[${index}] descriptor read-back changed`);
    }
    const secondDescriptor = readNativeDataDescriptor(
      Object.getOwnPropertyDescriptor(value, key),
      `${label}[${index}]`
    );
    if (
      !Object.is(secondDescriptor.value, descriptor.value) ||
      secondDescriptor.writable !== descriptor.writable ||
      secondDescriptor.enumerable !== descriptor.enumerable ||
      secondDescriptor.configurable !== descriptor.configurable ||
      !Object.is(Reflect.get(value, key, value), secondDescriptor.value)
    ) {
      throw new Error(`${label}[${index}] descriptor changed`);
    }
    result.push(descriptor.value);
  }
  const finalKeys = /** @type {string[]} */ (Reflect.ownKeys(value));
  if (
    value.length !== length ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    finalKeys.length !== firstKeys.length ||
    finalKeys.some((key, index) => key !== firstKeys[index])
  ) {
    throw new Error(`${label} has unstable shape`);
  }
  const finalLengthDescriptor = readNativeDataDescriptor(
    Object.getOwnPropertyDescriptor(value, 'length'),
    `${label}.length`
  );
  if (
    finalLengthDescriptor.value !== length ||
    finalLengthDescriptor.writable !== true ||
    finalLengthDescriptor.enumerable !== false ||
    finalLengthDescriptor.configurable !== false
  ) {
    throw new Error(`${label}.length descriptor changed`);
  }
  for (let index = 0; index < length; index += 1) {
    const key = String(index);
    const finalDescriptor = readNativeDataDescriptor(
      Object.getOwnPropertyDescriptor(value, key),
      `${label}[${index}]`
    );
    if (
      !Object.is(finalDescriptor.value, result[index]) ||
      !Object.is(Reflect.get(value, key, value), finalDescriptor.value)
    ) {
      throw new Error(`${label}[${index}] descriptor changed`);
    }
  }
  return result;
}

/**
 * Keep source-defined history text lossless: optional tool metadata and message
 * content may be empty, but never exceed the reviewed size bound.
 * @param {unknown} value
 * @param {number} maxLength
 * @param {string} message
 */
function boundedHistoryString(value, maxLength, message) {
  if (typeof value !== 'string' || value.length > maxLength) throw new Error(message);
  return value;
}

/** @param {unknown} value */
function boundedHistorySessionId(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_ID_LENGTH) {
    throw new Error('live proof history session identity is invalid');
  }
  return value;
}

/** @param {unknown} value */
function parseHistoryToolCalls(value) {
  if (value === null) return null;
  if (!Array.isArray(value) || !Number.isSafeInteger(value.length) || value.length > 64) {
    throw new Error('live proof history tool calls are invalid');
  }
  const toolCalls = readStrictArray(value, 'live proof history tool calls');
  return toolCalls.map((toolCall, index) => {
    const call = readStrictObject(toolCall, `live proof history tool call ${index}`, ['id', 'function'], true);
    const functionValue = readStrictObject(call.get('function'), `live proof history tool call ${index}.function`, ['name', 'arguments'], true);
    return {
      id: boundedHistoryString(call.get('id'), MAX_ID_LENGTH, 'live proof history tool call id is invalid'),
      function: {
        name: boundedHistoryString(functionValue.get('name'), 512, 'live proof history tool name is invalid'),
        arguments: boundedHistoryString(
          functionValue.get('arguments'),
          8_192,
          'live proof history tool arguments are invalid'
        )
      }
    };
  });
}

/** @param {unknown} value */
function parseHistoryTimestamp(value) {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    Object.is(value, -0) ||
    value < 0 ||
    value > 4_294_967_295
  ) {
    throw new Error('live proof history timestamp is invalid');
  }
  return value;
}

/** @param {unknown} projection @param {string} label @param {(value: unknown) => unknown} parser */
function parseOptionalProjection(projection, label, parser) {
  const properties = readStrictObject(projection, label, ['present', 'value'], false);
  const present = properties.get('present');
  if (present === false && properties.size === 1) return { present: false };
  if (present === true && properties.size === 2) {
    return { present: true, value: parser(properties.get('value')) };
  }
  throw new Error(`${label} projection is malformed`);
}

/**
 * Read one reviewed optional field without collapsing omitted and explicit null.
 * A malformed canonical projection is terminal; it never falls back to raw data.
 * Parsed rows use camelCase marker objects; raw Hermes rows use snake_case keys.
 *
 * @param {Map<string, unknown>} properties
 * @param {string} rawKey
 * @param {string} canonicalKey
 * @param {(value: unknown) => unknown} parser
 */
function parseReviewedOptional(properties, rawKey, canonicalKey, parser) {
  const hasCanonical = properties.has(canonicalKey);
  const hasRaw = rawKey !== canonicalKey && properties.has(rawKey);
  if (hasCanonical && hasRaw) throw new Error(`live proof history ${canonicalKey} projection is ambiguous`);
  if (hasCanonical) {
    const value = properties.get(canonicalKey);
    if (canonicalKey === 'timestamp' && (value === null || typeof value !== 'object')) {
      return { present: true, value: parser(value) };
    }
    return parseOptionalProjection(value, `live proof history ${canonicalKey}`, parser);
  }
  if (!hasRaw) return { present: false };
  return { present: true, value: parser(properties.get(rawKey)) };
}

/**
 * @param {unknown} value
 * @returns {{
 *   id: number,
 *   role: 'user'|'assistant'|'system'|'tool',
 *   content: string|null,
 *   toolCalls: { present: boolean, value?: unknown },
 *   toolName: { present: boolean, value?: unknown },
 *   toolCallId: { present: boolean, value?: unknown },
 *   timestamp: { present: boolean, value?: unknown }
 * }}
 */
function parseHistoryMessage(value) {
  const properties = readStrictObject(value, 'live proof history message', MESSAGE_KEYS, false);
  if (!properties.has('id') || !properties.has('role') || !properties.has('content')) {
    throw new Error('live proof history message is incomplete');
  }
  const role = properties.get('role');
  if (role !== 'user' && role !== 'assistant' && role !== 'system' && role !== 'tool') {
    throw new Error('live proof history message role is invalid');
  }
  const content = properties.get('content');
  if (content !== null && (typeof content !== 'string' || content.length > 8_192)) {
    throw new Error('live proof history message content is invalid');
  }
  return {
    id: boundedMessageId(properties.get('id')),
    role,
    content,
    toolCalls: parseReviewedOptional(properties, 'tool_calls', 'toolCalls', parseHistoryToolCalls),
    toolName: parseReviewedOptional(
      properties,
      'tool_name',
      'toolName',
      (item) => item === null ? null : boundedHistoryString(item, 512, 'live proof history tool name is invalid')
    ),
    toolCallId: parseReviewedOptional(
      properties,
      'tool_call_id',
      'toolCallId',
      (item) => item === null ? null : boundedHistoryString(item, MAX_ID_LENGTH, 'live proof history tool call id is invalid')
    ),
    timestamp: parseReviewedOptional(properties, 'timestamp', 'timestamp', parseHistoryTimestamp)
  };
}

/** @param {unknown} value */
function canonicalHistoryMessage(value) {
  return parseHistoryMessage(value);
}

/** @param {unknown} value */
function requireHistoryResponse(value) {
  const properties = readStrictObject(
    value,
    'live proof history response',
    ['session_id', 'messages', 'pagination'],
    true
  );
  if (!properties.has('session_id') || !properties.has('messages') || !properties.has('pagination')) {
    throw new Error('live proof history response is incomplete');
  }
  const rawMessages = properties.get('messages');
  if (
    !Array.isArray(rawMessages) ||
    !Number.isSafeInteger(rawMessages.length) ||
    rawMessages.length > LIVE_PROOF_HISTORY_LIMIT
  ) {
    throw new Error('live proof history exceeded its bound');
  }
  const messages = readStrictArray(rawMessages, 'live proof history messages');
  const pagination = readStrictObject(
    properties.get('pagination'),
    'live proof history pagination',
    ['limit', 'offset', 'returned'],
    true
  );
  return {
    sessionId: boundedHistorySessionId(properties.get('session_id')),
    messages,
    pagination
  };
}

/**
 * Parse one bounded canonical history response. Raw rows and IDs exist only for
 * this call. The returned projection contains HMAC message-projection tags,
 * booleans, and
 * counts; `watermark` is the transient pre-send high-water mark and must not be
 * written to the ledger.
 *
 * @param {unknown} response
 * @param {{
 *   phase: 'pre-send'|'post-completion',
 *   sessionId: string,
 *   prompt: string,
 *   assistantMarker: string,
 *   messageProjectionTagger: (messages: unknown[]) => string,
 *   fence?: number,
 *   preHistoryProjectionTag?: string
 * }} expected
 */
export function matchLiveProofHistory(response, expected) {
  if (
    !isRecord(expected) ||
    (expected.phase !== 'pre-send' && expected.phase !== 'post-completion') ||
    typeof expected.sessionId !== 'string' ||
    expected.sessionId.length === 0 ||
    expected.sessionId.length > MAX_ID_LENGTH ||
    expected.prompt !== LIVE_PROOF_PROMPT ||
    expected.assistantMarker !== LIVE_PROOF_ASSISTANT_MARKER ||
    typeof expected.messageProjectionTagger !== 'function'
  ) {
    throw new Error('live proof history matcher input is not approved');
  }
  const candidate = requireHistoryResponse(response);
  const rawMessages = /** @type {unknown[]} */ (candidate.messages);
  const messages = rawMessages.map(parseHistoryMessage);
  const ids = messages.map((message) => message.id);
  for (let index = 1; index < ids.length; index += 1) {
    if (ids[index] <= ids[index - 1]) {
      throw new Error('live proof history message ordering is invalid');
    }
  }
  const pagination = candidate.pagination;
  const historyComplete =
    pagination.get('limit') === LIVE_PROOF_HISTORY_LIMIT &&
    pagination.get('offset') === 0 &&
    pagination.get('returned') === messages.length &&
    messages.length < LIVE_PROOF_HISTORY_LIMIT;
  const sessionMatches = candidate.sessionId === expected.sessionId;
  const historyProjectionTag = requiredTag(expected.messageProjectionTagger(messages));
  const watermark = ids.length === 0 ? 0 : Math.max(...ids);
  const watermarkEstablished = expected.phase === 'pre-send' && historyComplete && sessionMatches;

  if (expected.phase === 'pre-send') {
    return Object.freeze({
      sessionMatches,
      historyComplete,
      watermarkEstablished,
      prefixStable: false,
      postFenceMatched: false,
      promptMatches: false,
      assistantMarkerMatches: false,
      candidateUserCount: 0,
      candidateAssistantCount: 0,
      messageCount: messages.length,
      historyProjectionTag,
      prefixProjectionTag: historyProjectionTag,
      watermark,
      matched: watermarkEstablished
    });
  }

  const fence = expected.fence;
  const fenceValid = typeof fence === 'number' && Number.isSafeInteger(fence) && fence >= 0;
  const fenceValue = fenceValid ? /** @type {number} */ (fence) : 0;
  const prefixMessages = fenceValid ? messages.filter((message) => message.id <= fenceValue) : [];
  const prefixProjectionTag = requiredTag(expected.messageProjectionTagger(prefixMessages));
  const prefixStable =
    fenceValid &&
    typeof expected.preHistoryProjectionTag === 'string' &&
    HMAC_TAG_PATTERN.test(expected.preHistoryProjectionTag) &&
    prefixProjectionTag === expected.preHistoryProjectionTag;
  const postFenceMessages = fenceValid ? messages.filter((message) => message.id > fenceValue) : [];
  const candidateUsers = postFenceMessages.filter((message) => message.role === 'user');
  const candidateAssistants = postFenceMessages.filter((message) => message.role === 'assistant');
  const promptMatches =
    candidateUsers.length === 1 && candidateUsers[0].content === expected.prompt;
  const assistantMarkerMatches =
    candidateAssistants.length === 1 && candidateAssistants[0].content === expected.assistantMarker;
  const promptIndex = promptMatches ? postFenceMessages.indexOf(candidateUsers[0]) : -1;
  const assistantIndex = assistantMarkerMatches
    ? postFenceMessages.indexOf(candidateAssistants[0])
    : -1;
  const postFenceMatched =
    promptIndex >= 0 &&
    assistantIndex > promptIndex &&
    candidateUsers.length === 1 &&
    candidateAssistants.length === 1;

  return Object.freeze({
    sessionMatches,
    historyComplete,
    watermarkEstablished: false,
    prefixStable,
    postFenceMatched,
    promptMatches,
    assistantMarkerMatches,
    candidateUserCount: candidateUsers.length,
    candidateAssistantCount: candidateAssistants.length,
    messageCount: messages.length,
    historyProjectionTag,
    prefixProjectionTag,
    watermark: undefined,
    matched:
      historyComplete &&
      sessionMatches &&
      prefixStable &&
      postFenceMatched &&
      promptMatches &&
      assistantMarkerMatches
  });
}

/**
 * Assert the causal proof chain. The result is fixed-shape and safe to use in
 * Playwright expectations; it never includes diagnostic payloads or identities.
 * Expected identity values are attempt-local HMAC tags, never raw IDs.
 *
 * @param {Array<Record<string, unknown>>} events
 * @param {{ sessionTag?: string, promptRequestTag?: string, promptSessionTag?: string, completionStatus?: string }} expected
 */
export function matchLiveProofLedger(events, expected) {
  if (!isEventList(events)) {
    throw new Error('live proof ledger sequence is not bounded');
  }
  if (events.some(hasRawIdentityField)) {
    throw new Error('live proof ledger retained a raw identity');
  }
  const expectedSessionTag = boundedTag(expected?.sessionTag);
  const expectedPromptRequestTag = boundedTag(expected?.promptRequestTag);
  const expectedPromptSessionTag = boundedTag(expected?.promptSessionTag);
  const websocketOpens = events.filter((event) => event.kind === 'ws.open');
  const websocket = websocketOpens.length === 1 &&
    websocketOpens[0].route === '/api/ws' &&
    websocketOpens[0].ticketOnly === true &&
    websocketOpens[0].originBound === true
    ? websocketOpens[0]
    : undefined;
  const readyEvents = events.filter((event) => event.kind === 'gateway.ready');
  const receivedApplicationEvents = events.filter(
    (event) => event.kind === 'ws.received' && event.event !== 'response'
  );
  const serverFirstReady = receivedApplicationEvents[0]?.event === 'gateway.ready';
  const ready = readyEvents.length === 1 && serverFirstReady ? readyEvents[0] : undefined;
  const session = events.find((event) =>
    event.kind === 'session.action' &&
    (event.method === 'session.create' || event.method === 'session.resume') &&
    !!expectedSessionTag &&
    (event.sessionTag === expectedSessionTag || event.storedSessionTag === expectedSessionTag)
  );
  const prompts = events.filter((event) => event.kind === 'prompt.submit');
  const prompt = prompts.find((event) =>
    typeof event.requestTag === 'string' &&
    typeof event.sessionTag === 'string' &&
    event.promptMatches === true &&
    (!expectedPromptRequestTag || event.requestTag === expectedPromptRequestTag) &&
    (!expectedPromptSessionTag || event.sessionTag === expectedPromptSessionTag)
  );
  const promptAcknowledgements = events.filter((event) =>
    !!prompt &&
    event.kind === 'ws.received' &&
    event.event === 'response' &&
    event.acknowledgement === true &&
    event.requestTag === prompt.requestTag
  );
  const acknowledgement = promptAcknowledgements.length === 1 ? promptAcknowledgements[0] : undefined;
  const deltas = events.filter((event) => event.kind === 'message.delta');
  const delta = deltas.find((event) =>
    !!prompt &&
    event.requestTag === undefined &&
    typeof event.sessionTag === 'string' &&
    event.sessionTag === prompt.sessionTag
  );
  const completions = events.filter((event) => event.kind === 'message.complete');
  const complete = completions.find((event) =>
    event.markerMatches === true &&
    event.status === (expected?.completionStatus ?? 'complete') &&
    !!prompt &&
    event.requestTag === undefined &&
    typeof event.sessionTag === 'string' &&
    event.sessionTag === prompt.sessionTag
  );
  const histories = events.filter((event) => event.kind === 'history.response');
  const preHistories = histories.filter((event) =>
    event.phase === 'pre-send' &&
    event.status === 200 &&
    !!expectedSessionTag &&
    event.sessionTag === expectedSessionTag &&
    event.historyComplete === true &&
    event.watermarkEstablished === true &&
    typeof event.historyProjectionTag === 'string'
  );
  const postHistories = histories.filter((event) =>
    event.phase === 'post-completion' &&
    event.status === 200 &&
    !!expectedSessionTag &&
    event.sessionTag === expectedSessionTag &&
    event.historyComplete === true &&
    event.prefixStable === true &&
    event.postFenceMatched === true &&
    event.promptMatches === true &&
    event.assistantMarkerMatches === true &&
    event.candidateUserCount === 1 &&
    event.candidateAssistantCount === 1
  );
  const preHistory = preHistories.length === 1 ? preHistories[0] : undefined;
  const history = preHistories.length === 1 && postHistories.length === 1
    ? postHistories[0]
    : undefined;
  const websocketSequence = sequenceOf(websocket);
  const readySequence = sequenceOf(ready);
  const sessionSequence = sequenceOf(session);
  const preHistorySequence = sequenceOf(preHistory);
  const promptSequence = sequenceOf(prompt);
  const acknowledgementSequence = sequenceOf(acknowledgement);
  const deltaSequence = sequenceOf(delta);
  const completeSequence = sequenceOf(complete);
  const historySequence = sequenceOf(history);
  const ordered =
    typeof websocketSequence === 'number' &&
    typeof readySequence === 'number' &&
    typeof sessionSequence === 'number' &&
    typeof preHistorySequence === 'number' &&
    typeof promptSequence === 'number' &&
    typeof acknowledgementSequence === 'number' &&
    typeof deltaSequence === 'number' &&
    typeof completeSequence === 'number' &&
    typeof historySequence === 'number' &&
    websocketSequence < readySequence &&
    readySequence < sessionSequence &&
    sessionSequence < preHistorySequence &&
    preHistorySequence < promptSequence &&
    promptSequence < acknowledgementSequence &&
    acknowledgementSequence < deltaSequence &&
    deltaSequence < completeSequence &&
    completeSequence < historySequence;
  return Object.freeze({
    ordered,
    websocketOpen: !!websocket,
    gatewayReady: readyEvents.length === 1,
    serverFirstReady,
    sessionAction: !!session,
    prompt: !!prompt && prompts.length === 1,
    promptAcknowledgement: !!acknowledgement,
    delta: !!delta && deltas.length === 1,
    completion: !!complete && completions.length === 1,
    history: !!history,
    historyStatusOk: history?.status === 200,
    messageCount: typeof history?.messageCount === 'number' ? history.messageCount : 0,
    promptCount: prompts.length,
    completionCount: eventCount(events, 'message.complete')
  });
}

/**
 * Require the exact fixed-shape result before the screenshot lane can start.
 * Keeping this assertion beside the ledger prevents a caller from replacing the
 * causal proof with independent booleans or a stable-looking UI attribute.
 *
 * @param {unknown} proof
 */
export function assertLiveProofLedgerCaptureReady(proof) {
  if (proof === null || typeof proof !== 'object' || Array.isArray(proof)) {
    throw new Error('live screenshot capture requires a complete causal Hermes proof');
  }
  const candidate = /** @type {Record<string, unknown>} */ (proof);
  const actualKeys = Object.keys(candidate);
  if (
    actualKeys.length !== LIVE_PROOF_CAPTURE_KEYS.length ||
    LIVE_PROOF_CAPTURE_KEYS.some((key, index) => actualKeys[index] !== key)
  ) {
    throw new Error('live screenshot capture proof shape is not approved');
  }
  for (const key of LIVE_PROOF_CAPTURE_KEYS.slice(0, -3)) {
    if (candidate[key] !== true) {
      throw new Error('live screenshot capture requires a complete causal Hermes proof');
    }
  }
  if (
    typeof candidate.messageCount !== 'number' ||
    !Number.isInteger(candidate.messageCount) ||
    candidate.messageCount < 1 ||
    candidate.messageCount > MAX_MESSAGE_COUNT ||
    candidate.promptCount !== 1 ||
    candidate.completionCount !== 1
  ) {
    throw new Error('live screenshot capture proof counts are not approved');
  }
  return true;
}

/** @param {Array<Record<string, unknown>>} events @param {string} before @param {string} after */
export function assertLiveProofHappensBefore(events, before, after) {
  const beforeSequence = firstSequence(events, before);
  const afterSequence = firstSequence(events, after);
  if (typeof beforeSequence !== 'number' || typeof afterSequence !== 'number' || beforeSequence >= afterSequence) {
    throw new Error('live proof ledger ordering assertion failed');
  }
  return true;
}
