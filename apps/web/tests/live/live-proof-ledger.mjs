export const LIVE_PROOF_PROMPT = 'Reply with exactly: Hermternal live proof complete.';
export const LIVE_PROOF_ASSISTANT_MARKER = 'Hermternal live proof complete.';

const DEFAULT_MAX_EVENTS = 256;
const MAX_ID_LENGTH = 256;
const MAX_ROUTE_LENGTH = 256;
const MAX_METHOD_LENGTH = 64;
const MAX_EVENT_NAME_LENGTH = 96;
const MAX_STATUS_LENGTH = 32;
const MAX_MESSAGE_COUNT = 10_000;

/** @param {unknown} value */
function boundedId(value) {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_ID_LENGTH) {
    throw new Error('live proof ledger received an unsafe identity');
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

/**
 * Keep only typed, assertion-local projections. No Page, Request, Response,
 * WebSocket, raw frame, prompt, transcript, cookie, URL, or response body is
 * retained by this ledger.
 */
export function createLiveProofLedger(maxEvents = DEFAULT_MAX_EVENTS) {
  if (!Number.isInteger(maxEvents) || maxEvents < 16 || maxEvents > 1024) {
    throw new Error('live proof ledger capacity is not bounded');
  }
  /** @type {Array<Record<string, unknown>>} */
  const events = [];
  let nextSequence = 0;

  /** @param {Record<string, unknown>} event */
  function append(event) {
    if (events.length >= maxEvents) {
      throw new Error('live proof ledger capacity was exceeded');
    }
    nextSequence += 1;
    const projected = Object.freeze({ sequence: nextSequence, ...event });
    // Do not dispatch through Array.prototype.push here. The live proof lane
    // runs beside untrusted test code, so a poisoned mutable prototype must not
    // be able to suppress or replace a proof event.
    events[events.length] = projected;
    return projected;
  }

  return Object.freeze({
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
        requestId: boundedId(event.requestId),
        sessionId: boundedId(event.sessionId)
      });
    },
    /** @param {{ event: string, requestId?: string, sessionId?: string }} event */
    recordWebSocketReceived(event) {
      return append({
        kind: 'ws.received',
        event: boundedEventName(event.event),
        requestId: boundedId(event.requestId),
        sessionId: boundedId(event.sessionId)
      });
    },
    /** @param {{ sessionId?: string }} [event] */
    recordGatewayReady(event = {}) {
      return append({ kind: 'gateway.ready', sessionId: boundedId(event.sessionId) });
    },
    /** @param {{ method: 'session.create' | 'session.resume', requestId?: string, sessionId?: string, storedSessionId?: string }} event */
    recordSessionAction(event) {
      if (event.method !== 'session.create' && event.method !== 'session.resume') {
        throw new Error('live proof ledger received an unsafe session action');
      }
      return append({
        kind: 'session.action',
        method: event.method,
        requestId: boundedId(event.requestId),
        sessionId: boundedId(event.sessionId),
        storedSessionId: boundedId(event.storedSessionId)
      });
    },
    /** @param {{ requestId?: string, sessionId?: string, promptMatches: boolean }} event */
    recordPrompt(event) {
      return append({
        kind: 'prompt.submit',
        requestId: boundedId(event.requestId),
        sessionId: boundedId(event.sessionId),
        promptMatches: event.promptMatches === true
      });
    },
    /** @param {{ requestId?: string, sessionId?: string }} event */
    recordDelta(event) {
      return append({
        kind: 'message.delta',
        requestId: boundedId(event.requestId),
        sessionId: boundedId(event.sessionId)
      });
    },
    /** @param {{ requestId?: string, sessionId?: string, status: string, markerMatches: boolean }} event */
    recordCompletion(event) {
      return append({
        kind: 'message.complete',
        requestId: boundedId(event.requestId),
        sessionId: boundedId(event.sessionId),
        status: boundedStatus(event.status),
        markerMatches: event.markerMatches === true
      });
    },
    /** @param {{ status: number, sessionId?: string, promptMatches: boolean, assistantMarkerMatches: boolean, messageCount: number }} event */
    recordHistoryResponse(event) {
      if (!Number.isInteger(event.status) || event.status < 100 || event.status > 599) {
        throw new Error('live proof ledger received an unsafe history status');
      }
      return append({
        kind: 'history.response',
        status: event.status,
        sessionId: boundedId(event.sessionId),
        promptMatches: event.promptMatches === true,
        assistantMarkerMatches: event.assistantMarkerMatches === true,
        messageCount: boundedCount(event.messageCount)
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

/**
 * Match the exact history contract without returning message content. The
 * caller may pass the raw response only inside the assertion process; this
 * function returns fixed booleans and a bounded message count.
 *
 * @param {unknown} response
 * @param {{ sessionId: string, prompt: string, assistantMarker: string }} expected
 */
export function matchLiveProofHistory(response, expected) {
  const candidate = response !== null && typeof response === 'object' && !Array.isArray(response)
    ? /** @type {Record<string, unknown>} */ (response)
    : undefined;
  const sessionId = candidate?.session_id ?? candidate?.sessionId;
  const messages = Array.isArray(candidate?.messages) ? candidate.messages : [];
  if (messages.length > MAX_MESSAGE_COUNT) {
    throw new Error('live proof history exceeded its bound');
  }
  let promptMatches = false;
  let assistantMarkerMatches = false;
  for (const message of messages) {
    if (message === null || typeof message !== 'object' || Array.isArray(message)) continue;
    const record = /** @type {Record<string, unknown>} */ (message);
    const role = record.role;
    const content = record.content;
    if (role === 'user' && content === expected.prompt) promptMatches = true;
    if (role === 'assistant' && typeof content === 'string' && content.includes(expected.assistantMarker)) {
      assistantMarkerMatches = true;
    }
  }
  return Object.freeze({
    sessionMatches: sessionId === expected.sessionId,
    promptMatches,
    assistantMarkerMatches,
    messageCount: messages.length,
    matched: sessionId === expected.sessionId && promptMatches && assistantMarkerMatches
  });
}

/**
 * Assert the causal proof chain. The result is fixed-shape and safe to use in
 * Playwright expectations; it never includes diagnostic payloads or IDs.
 *
 * @param {Array<Record<string, unknown>>} events
 * @param {{ sessionId: string, promptRequestId?: string, promptSessionId?: string, completionStatus?: string }} expected
 */
export function matchLiveProofLedger(events, expected) {
  if (!isEventList(events)) {
    throw new Error('live proof ledger sequence is not bounded');
  }
  const expectedSessionId =
    typeof expected.sessionId === 'string' && expected.sessionId.length > 0
      ? expected.sessionId
      : undefined;
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
    !!expectedSessionId &&
    (event.sessionId === expectedSessionId || event.storedSessionId === expectedSessionId)
  );
  const prompts = events.filter((event) => event.kind === 'prompt.submit');
  const prompt = prompts.find((event) =>
    typeof event.requestId === 'string' &&
    event.requestId.length > 0 &&
    typeof event.sessionId === 'string' &&
    event.sessionId.length > 0 &&
    event.promptMatches === true &&
    (!expected.promptRequestId || event.requestId === expected.promptRequestId) &&
    (!expected.promptSessionId || event.sessionId === expected.promptSessionId)
  );
  const acknowledgement = events.find((event) =>
    !!prompt &&
    event.kind === 'ws.received' &&
    event.event === 'response' &&
    event.requestId === prompt.requestId
  );
  const deltas = events.filter((event) => event.kind === 'message.delta');
  const delta = deltas.find((event) =>
    !!prompt &&
    typeof event.requestId === 'string' &&
    typeof event.sessionId === 'string' &&
    event.requestId === prompt.requestId &&
    event.sessionId === prompt.sessionId
  );
  const completions = events.filter((event) => event.kind === 'message.complete');
  const complete = completions.find((event) =>
    event.markerMatches === true &&
    event.status === (expected.completionStatus ?? 'ok') &&
    !!prompt &&
    typeof event.requestId === 'string' &&
    typeof event.sessionId === 'string' &&
    event.requestId === prompt.requestId &&
    event.sessionId === prompt.sessionId
  );
  const history = events.find((event) =>
    event.kind === 'history.response' &&
    event.status === 200 &&
    !!expectedSessionId &&
    event.sessionId === expectedSessionId &&
    event.promptMatches === true &&
    event.assistantMarkerMatches === true
  );
  const websocketSequence = sequenceOf(websocket);
  const readySequence = sequenceOf(ready);
  const sessionSequence = sequenceOf(session);
  const promptSequence = sequenceOf(prompt);
  const acknowledgementSequence = sequenceOf(acknowledgement);
  const deltaSequence = sequenceOf(delta);
  const completeSequence = sequenceOf(complete);
  const historySequence = sequenceOf(history);
  const ordered =
    typeof websocketSequence === 'number' &&
    typeof readySequence === 'number' &&
    typeof sessionSequence === 'number' &&
    typeof promptSequence === 'number' &&
    typeof acknowledgementSequence === 'number' &&
    typeof deltaSequence === 'number' &&
    typeof completeSequence === 'number' &&
    typeof historySequence === 'number' &&
    websocketSequence < readySequence &&
    readySequence < sessionSequence &&
    sessionSequence < promptSequence &&
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

/** @param {Array<Record<string, unknown>>} events @param {string} before @param {string} after */
export function assertLiveProofHappensBefore(events, before, after) {
  const beforeSequence = firstSequence(events, before);
  const afterSequence = firstSequence(events, after);
  if (typeof beforeSequence !== 'number' || typeof afterSequence !== 'number' || beforeSequence >= afterSequence) {
    throw new Error('live proof ledger ordering assertion failed');
  }
  return true;
}
