import { createHmac, randomBytes } from 'node:crypto';

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

/** @param {unknown} value */
function boundedRawId(value) {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_ID_LENGTH) {
    throw new Error('live proof ledger received an unsafe identity');
  }
  return value;
}

/** @param {unknown} value */
function boundedTag(value) {
  if (value === undefined || value === null) return undefined;
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

/** @param {Uint8Array} key @param {string} domain @param {string} value */
function hmacTag(key, domain, value) {
  return `h1:${createHmac('sha256', key).update(domain).update('\0').update(value).digest('hex')}`;
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
  return value;
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
 * Keep only typed, assertion-local projections. Raw session/request identities
 * are HMAC-tagged with a fresh attempt key before they enter this ledger. The
 * key never appears in a snapshot, reporter annotation, artifact, or error.
 */
export function createLiveProofLedger(maxEvents = DEFAULT_MAX_EVENTS) {
  if (!Number.isInteger(maxEvents) || maxEvents < 16 || maxEvents > 1024) {
    throw new Error('live proof ledger capacity is not bounded');
  }
  const attemptKey = randomBytes(32);
  /** @type {Array<Record<string, unknown>>} */
  const events = [];
  let nextSequence = 0;

  /** @param {unknown} value */
  const identityTag = (value) => {
    const raw = boundedRawId(value);
    return raw === undefined ? undefined : hmacTag(attemptKey, 'identity', raw);
  };

  /** @param {unknown} values */
  const messageIdTag = (values) => {
    if (!Array.isArray(values) || values.length > LIVE_PROOF_HISTORY_LIMIT) {
      throw new Error('live proof history message identity sequence is not bounded');
    }
    const ids = values.map(boundedMessageId);
    return hmacTag(attemptKey, 'message-id-sequence', ids.join(','));
  };

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
    /** Tag one transient ordered message-id sequence without retaining ids. */
    messageIdTag,
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
    /** @param {{ route: string, ticketOnly: boolean }} event */
    recordWebSocketOpen(event) {
      return append({
        kind: 'ws.open',
        route: boundedRoute(event.route),
        ticketOnly: event.ticketOnly === true
      });
    },
    /** @param {{ method: string, requestId?: string, sessionId?: string }} event */
    recordWebSocketSent(event) {
      return append({
        kind: 'ws.sent',
        method: boundedMethod(event.method),
        requestTag: identityTag(event.requestId),
        sessionTag: identityTag(event.sessionId)
      });
    },
    /** @param {{ event: string, requestId?: string, sessionId?: string }} event */
    recordWebSocketReceived(event) {
      return append({
        kind: 'ws.received',
        event: boundedEventName(event.event),
        requestTag: identityTag(event.requestId),
        sessionTag: identityTag(event.sessionId)
      });
    },
    /** @param {{ sessionId?: string }} [event] */
    recordGatewayReady(event = {}) {
      return append({ kind: 'gateway.ready', sessionTag: identityTag(event.sessionId) });
    },
    /** @param {{ method: 'session.create' | 'session.resume', requestId?: string, sessionId?: string, storedSessionId?: string }} event */
    recordSessionAction(event) {
      if (event.method !== 'session.create' && event.method !== 'session.resume') {
        throw new Error('live proof ledger received an unsafe session action');
      }
      return append({
        kind: 'session.action',
        method: event.method,
        requestTag: identityTag(event.requestId),
        sessionTag: identityTag(event.sessionId),
        storedSessionTag: identityTag(event.storedSessionId)
      });
    },
    /** @param {{ requestId?: string, sessionId?: string, promptMatches: boolean }} event */
    recordPrompt(event) {
      return append({
        kind: 'prompt.submit',
        requestTag: identityTag(event.requestId),
        sessionTag: identityTag(event.sessionId),
        promptMatches: event.promptMatches === true
      });
    },
    /** @param {{ requestId?: string, sessionId?: string }} event */
    recordDelta(event) {
      return append({
        kind: 'message.delta',
        requestTag: identityTag(event.requestId),
        sessionTag: identityTag(event.sessionId)
      });
    },
    /** @param {{ requestId?: string, sessionId?: string, status: string, markerMatches: boolean }} event */
    recordCompletion(event) {
      return append({
        kind: 'message.complete',
        requestTag: identityTag(event.requestId),
        sessionTag: identityTag(event.sessionId),
        status: boundedStatus(event.status),
        markerMatches: event.markerMatches === true
      });
    },
    /**
     * Store only the bounded canonical-history projection. The watermark and
     * raw message rows stay transient in the one-shot read; sequence tags are
     * the only retained message-identity evidence.
     *
     * @param {{
     *   phase: 'pre-send'|'post-completion',
     *   status: number,
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
     *   historyIdTag?: string,
     *   prefixIdTag?: string
     * }} event
     */
    recordHistoryResponse(event) {
      if (!Number.isInteger(event.status) || event.status < 100 || event.status > 599) {
        throw new Error('live proof ledger received an unsafe history status');
      }
      return append({
        kind: 'history.response',
        phase: boundedHistoryPhase(event.phase),
        status: event.status,
        sessionTag: identityTag(event.sessionId),
        historyComplete: event.historyComplete === true,
        watermarkEstablished: event.watermarkEstablished === true,
        prefixStable: event.prefixStable === true,
        postFenceMatched: event.postFenceMatched === true,
        promptMatches: event.promptMatches === true,
        assistantMarkerMatches: event.assistantMarkerMatches === true,
        candidateUserCount: boundedCount(event.candidateUserCount),
        candidateAssistantCount: boundedCount(event.candidateAssistantCount),
        messageCount: boundedCount(event.messageCount),
        historyIdTag: boundedTag(event.historyIdTag),
        prefixIdTag: boundedTag(event.prefixIdTag)
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

/**
 * @param {unknown} value
 * @returns {{ id: number, role: 'user'|'assistant'|'system'|'tool', content: string|null }}
 */
function parseHistoryMessage(value) {
  if (!isRecord(value)) throw new Error('live proof history message is invalid');
  const role = value.role;
  if (role !== 'user' && role !== 'assistant' && role !== 'system' && role !== 'tool') {
    throw new Error('live proof history message role is invalid');
  }
  const content = value.content;
  if (content !== null && (typeof content !== 'string' || content.length > 8_192)) {
    throw new Error('live proof history message content is invalid');
  }
  return { id: boundedMessageId(value.id), role, content };
}

/** @param {unknown} value */
function requireHistoryResponse(value) {
  if (!isRecord(value)) throw new Error('live proof history response is invalid');
  if (!('session_id' in value) || !('messages' in value) || !('pagination' in value)) {
    throw new Error('live proof history response is incomplete');
  }
  if (!Array.isArray(value.messages) || value.messages.length > LIVE_PROOF_HISTORY_LIMIT) {
    throw new Error('live proof history exceeded its bound');
  }
  if (!isRecord(value.pagination)) throw new Error('live proof history pagination is incomplete');
  if (!('limit' in value.pagination) || !('offset' in value.pagination) || !('returned' in value.pagination)) {
    throw new Error('live proof history pagination is incomplete');
  }
  return /** @type {Record<string, any>} */ (value);
}

/**
 * Parse one bounded canonical history response. Raw rows and IDs exist only for
 * this call. The returned projection contains HMAC sequence tags, booleans, and
 * counts; `watermark` is the transient pre-send high-water mark and must not be
 * written to the ledger.
 *
 * @param {unknown} response
 * @param {{
 *   phase: 'pre-send'|'post-completion',
 *   sessionId: string,
 *   prompt: string,
 *   assistantMarker: string,
 *   messageIdTagger: (ids: number[]) => string,
 *   fence?: number,
 *   preHistoryIdTag?: string
 * }} expected
 */
export function matchLiveProofHistory(response, expected) {
  if (
    !isRecord(expected) ||
    (expected.phase !== 'pre-send' && expected.phase !== 'post-completion') ||
    typeof expected.sessionId !== 'string' ||
    expected.sessionId.length === 0 ||
    expected.prompt !== LIVE_PROOF_PROMPT ||
    expected.assistantMarker !== LIVE_PROOF_ASSISTANT_MARKER ||
    typeof expected.messageIdTagger !== 'function'
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
    pagination.limit === LIVE_PROOF_HISTORY_LIMIT &&
    pagination.offset === 0 &&
    pagination.returned === messages.length &&
    messages.length < LIVE_PROOF_HISTORY_LIMIT;
  const sessionMatches = candidate.session_id === expected.sessionId;
  const historyIdTag = requiredTag(expected.messageIdTagger(ids));
  const watermark = ids.length === 0 ? 0 : ids[ids.length - 1];
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
      historyIdTag,
      prefixIdTag: historyIdTag,
      watermark,
      matched: watermarkEstablished
    });
  }

  const fence = expected.fence;
  const fenceValid = typeof fence === 'number' && Number.isSafeInteger(fence) && fence >= 0;
  const fenceValue = fenceValid ? /** @type {number} */ (fence) : 0;
  const prefixMessages = fenceValid ? messages.filter((message) => message.id <= fenceValue) : [];
  const prefixIds = prefixMessages.map((message) => message.id);
  const prefixIdTag = requiredTag(expected.messageIdTagger(prefixIds));
  const prefixStable =
    fenceValid &&
    typeof expected.preHistoryIdTag === 'string' &&
    HMAC_TAG_PATTERN.test(expected.preHistoryIdTag) &&
    prefixIdTag === expected.preHistoryIdTag;
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
    historyIdTag,
    prefixIdTag,
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
    websocketOpens[0].ticketOnly === true
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
  const acknowledgement = events.find((event) =>
    !!prompt &&
    event.kind === 'ws.received' &&
    event.event === 'response' &&
    event.requestTag === prompt.requestTag
  );
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
    typeof event.historyIdTag === 'string'
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
