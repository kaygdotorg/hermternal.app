export const SHARED_SESSION_FIRST_PROMPT =
  'Reply with exactly: Hermternal shared session marker A.';
export const SHARED_SESSION_FIRST_ASSISTANT_MARKER = 'Hermternal shared session marker A.';
export const SHARED_SESSION_SECOND_PROMPT =
  'Reply with exactly: Hermternal shared session marker B.';
export const SHARED_SESSION_SECOND_ASSISTANT_MARKER = 'Hermternal shared session marker B.';

const DEFAULT_MAX_EVENTS = 512;
const MAX_ROUTE_LENGTH = 256;
const MAX_METHOD_LENGTH = 64;
const MAX_EVENT_NAME_LENGTH = 96;
const MAX_STATUS_LENGTH = 32;
const MAX_MESSAGE_COUNT = 10_000;
const MAX_QUERY_KEYS = 8;
const MAX_QUERY_VALUE_LENGTH = 512;

/** @typedef {'first' | 'second'} SharedProofPhase */
/** @typedef {'session.create' | 'session.resume'} SessionActionMethod */
/** @typedef {'chat-to-terminal' | 'terminal-to-chat'} ModeTransition */
/** @typedef {{ [key: string]: any, sequence: number, kind: string }} SharedProofEvent */
/** @typedef {{ firstCompletionStatus?: string, secondCompletionStatus?: string }} SharedProofExpected */

/** @param {unknown} value @param {number} maxLength @param {string} message */
function boundedText(value, maxLength, message) {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength) {
    throw new Error(message);
  }
  return value;
}

/** @param {unknown} value */
function boundedRoute(value) {
  return boundedText(value, MAX_ROUTE_LENGTH, 'shared proof route is not bounded');
}

/** @param {unknown} value */
function boundedMethod(value) {
  return boundedText(value, MAX_METHOD_LENGTH, 'shared proof method is not bounded');
}

/** @param {unknown} value */
function boundedEventName(value) {
  return boundedText(value, MAX_EVENT_NAME_LENGTH, 'shared proof event is not bounded');
}

/** @param {unknown} value */
function boundedStatus(value) {
  return boundedText(value, MAX_STATUS_LENGTH, 'shared proof status is not bounded');
}

/** @param {unknown} value @returns {SharedProofPhase} */
function boundedPhase(value) {
  if (value !== 'first' && value !== 'second') {
    throw new Error('shared proof phase is not bounded');
  }
  return value;
}

/** @param {unknown} value @returns {SessionActionMethod} */
function boundedMethodName(value) {
  if (value !== 'session.create' && value !== 'session.resume') {
    throw new Error('shared proof session method is not bounded');
  }
  return value;
}

/** @param {unknown} value @returns {ModeTransition} */
function boundedModeEvent(value) {
  if (value !== 'chat-to-terminal' && value !== 'terminal-to-chat') {
    throw new Error('shared proof mode event is not bounded');
  }
  return value;
}

/** @param {number} value */
function boundedLength(value) {
  if (!Number.isInteger(value) || value < 0 || value > MAX_QUERY_VALUE_LENGTH) {
    throw new Error('shared proof query length is not bounded');
  }
  return value;
}

/** @param {number} value */
function boundedCount(value) {
  if (!Number.isInteger(value) || value < 0 || value > MAX_MESSAGE_COUNT) {
    throw new Error('shared proof count is not bounded');
  }
  return value;
}

/** @param {number} value */
function boundedQueryKeyCount(value) {
  if (!Number.isInteger(value) || value < 0 || value > MAX_QUERY_KEYS) {
    throw new Error('shared proof query key count is not bounded');
  }
  return value;
}

/** @param {number} value */
function boundedStatusCode(value) {
  if (!Number.isInteger(value) || value < 100 || value > 599) {
    throw new Error('shared proof status code is not bounded');
  }
  return value;
}

/** @param {number} value */
function boundedCloseCode(value) {
  if (!Number.isInteger(value) || value < 0 || value > 65_535) {
    throw new Error('shared proof close code is not bounded');
  }
  return value;
}

/**
 * Keep only route/method/event names, statuses, bounded counts/lengths, close
 * codes, and boolean identity/content projections. Raw IDs, credentials,
 * tickets, query strings, prompts, assistant text, bodies, frames, and browser
 * objects never enter this ledger.
 */
/**
 * @param {number} [maxEvents=DEFAULT_MAX_EVENTS]
 */
export function createSharedSessionProofLedger(maxEvents = DEFAULT_MAX_EVENTS) {
  if (!Number.isInteger(maxEvents) || maxEvents < 32 || maxEvents > 2048) {
    throw new Error('shared proof ledger capacity is not bounded');
  }
  /** @type {Array<SharedProofEvent>} */
  const events = [];
  let nextSequence = 0;

  /** @param {{ [key: string]: any, kind: string }} event @returns {SharedProofEvent} */
  function append(event) {
    if (events.length >= maxEvents) throw new Error('shared proof ledger capacity exceeded');
    nextSequence += 1;
    const projected = Object.freeze({ sequence: nextSequence, ...event });
    events[events.length] = projected;
    return projected;
  }

  return Object.freeze({
    /** @param {{ method: string, route: string }} event */
    recordHttpRequest({ method, route }) {
      return append({
        kind: 'http.request',
        method: boundedMethod(method),
        route: boundedRoute(route)
      });
    },
    /** @param {{ method: string, route: string, status: number }} event */
    recordHttpResponse({ method, route, status }) {
      return append({
        kind: 'http.response',
        method: boundedMethod(method),
        route: boundedRoute(route),
        status: boundedStatusCode(status)
      });
    },
    /** @param {{ route: string, ticketOnly: boolean }} event */
    recordChatWebSocket({ route, ticketOnly }) {
      return append({
        kind: 'chat.socket',
        route: boundedRoute(route),
        ticketOnly: ticketOnly === true
      });
    },
    /** @param {{ code?: number }} [event] */
    recordChatWebSocketClose({ code } = {}) {
      return append({
        kind: 'chat.close',
        ...(code === undefined ? {} : { code: boundedCloseCode(code) })
      });
    },
    /** @param {{ route: string, queryKeyCount: number, ticketPresent: boolean, resumePresent: boolean, attachPresent: boolean, ticketLength: number, resumeLength: number, attachLength: number, resumeMatches: boolean, legacyMode: boolean }} event */
    recordPtyUpgrade({
      route,
      queryKeyCount,
      ticketPresent,
      resumePresent,
      attachPresent,
      ticketLength,
      resumeLength,
      attachLength,
      resumeMatches,
      legacyMode
    }) {
      return append({
        kind: 'pty.upgrade',
        route: boundedRoute(route),
        queryKeyCount: boundedQueryKeyCount(queryKeyCount),
        ticketPresent: ticketPresent === true,
        resumePresent: resumePresent === true,
        attachPresent: attachPresent === true,
        ticketLength: boundedLength(ticketLength),
        resumeLength: boundedLength(resumeLength),
        attachLength: boundedLength(attachLength),
        resumeMatches: resumeMatches === true,
        legacyMode: legacyMode === true
      });
    },
    /** @param {{ serverFirst: boolean }} event */
    recordGatewayReady({ serverFirst }) {
      return append({
        kind: 'gateway.ready',
        serverFirst: serverFirst === true
      });
    },
    /** @param {{ matches: boolean }} event */
    recordAuthenticatedIdentity({ matches }) {
      return append({ kind: 'auth.identity', matches: matches === true });
    },
    /** @param {{ method: SessionActionMethod }} event */
    recordSessionAction({ method }) {
      return append({ kind: 'session.action', method: boundedMethodName(method) });
    },
    /** @param {{ method: SessionActionMethod, matches: boolean, promoted?: boolean }} event */
    recordSessionIdentity({ method, matches, promoted }) {
      return append({
        kind: 'session.identity',
        method: boundedMethodName(method),
        matches: matches === true,
        promoted: promoted === true
      });
    },
    /** @param {{ phase: SharedProofPhase, markerMatches: boolean, sessionMatches: boolean }} event */
    recordPrompt({ phase, markerMatches, sessionMatches }) {
      return append({
        kind: 'prompt.submit',
        phase: boundedPhase(phase),
        markerMatches: markerMatches === true,
        sessionMatches: sessionMatches === true
      });
    },
    /** @param {{ phase: SharedProofPhase, requestMatches: boolean }} event */
    recordPromptAcknowledgement({ phase, requestMatches }) {
      return append({
        kind: 'prompt.ack',
        phase: boundedPhase(phase),
        requestMatches: requestMatches === true
      });
    },
    /** @param {{ phase: SharedProofPhase, requestMatches: boolean, sessionMatches: boolean, requestIdPresent?: boolean, sessionIdPresent?: boolean }} event */
    recordDelta({ phase, requestMatches, sessionMatches, requestIdPresent, sessionIdPresent }) {
      return append({
        kind: 'message.delta',
        phase: boundedPhase(phase),
        requestMatches: requestMatches === true,
        sessionMatches: sessionMatches === true,
        requestIdPresent: requestIdPresent !== false,
        sessionIdPresent: sessionIdPresent !== false
      });
    },
    /** @param {{ phase: SharedProofPhase, status: string, requestMatches: boolean, sessionMatches: boolean, markerMatches: boolean, requestIdPresent?: boolean, sessionIdPresent?: boolean }} event */
    recordCompletion({ phase, status, requestMatches, sessionMatches, markerMatches, requestIdPresent, sessionIdPresent }) {
      return append({
        kind: 'message.complete',
        phase: boundedPhase(phase),
        status: boundedStatus(status),
        requestMatches: requestMatches === true,
        sessionMatches: sessionMatches === true,
        markerMatches: markerMatches === true,
        requestIdPresent: requestIdPresent !== false,
        sessionIdPresent: sessionIdPresent !== false
      });
    },
    /** @param {{ phase: SharedProofPhase, status: number, sessionMatches: boolean, firstPromptMatches: boolean, firstAssistantMarkerMatches: boolean, secondPromptMatches: boolean, secondAssistantMarkerMatches: boolean, messageCount: number }} event */
    recordHistory({
      phase,
      status,
      sessionMatches,
      firstPromptMatches,
      firstAssistantMarkerMatches,
      secondPromptMatches,
      secondAssistantMarkerMatches,
      messageCount
    }) {
      return append({
        kind: 'history.response',
        phase: boundedPhase(phase),
        status: boundedStatusCode(status),
        sessionMatches: sessionMatches === true,
        firstPromptMatches: firstPromptMatches === true,
        firstAssistantMarkerMatches: firstAssistantMarkerMatches === true,
        secondPromptMatches: secondPromptMatches === true,
        secondAssistantMarkerMatches: secondAssistantMarkerMatches === true,
        messageCount: boundedCount(messageCount)
      });
    },
    /** @param {{ event: ModeTransition }} value */
    recordModeTransition({ event }) {
      return append({ kind: 'mode.transition', event: boundedModeEvent(event) });
    },
    /** @param {{ status: number, cookieJarCleared?: boolean, storageCleared?: boolean }} event */
    recordLogout({ status, cookieJarCleared, storageCleared }) {
      return append({
        kind: 'logout',
        status: boundedStatusCode(status),
        cookieJarCleared: cookieJarCleared === true,
        storageCleared: storageCleared === true
      });
    },
    snapshot() {
      return events.slice();
    }
  });
}

/** @param {unknown} value @returns {value is Array<SharedProofEvent>} */
function isEventList(value) {
  return Array.isArray(value) && value.length <= 2048 && value.every((event) => {
    return event !== null && typeof event === 'object' && !Array.isArray(event);
  });
}

/** @param {SharedProofEvent | undefined} event */
function sequenceOf(event) {
  return typeof event?.sequence === 'number' ? event.sequence : undefined;
}

/** @param {SharedProofEvent | undefined} event */
function sequenceOrSentinel(event) {
  return sequenceOf(event) ?? -1;
}

/** @param {Array<SharedProofEvent>} events @param {(event: SharedProofEvent) => boolean} predicate */
function firstEvent(events, predicate) {
  return events.find(predicate);
}

/** @param {Array<SharedProofEvent>} events @param {(event: SharedProofEvent) => boolean} predicate */
function countEvents(events, predicate) {
  return events.reduce((count, event) => count + (predicate(event) ? 1 : 0), 0);
}

/** @param {Array<SharedProofEvent>} events @param {string} kind @param {SharedProofPhase} phase */
function onePhaseEvent(events, kind, phase) {
  const matches = events.filter((event) => event.kind === kind && event.phase === phase);
  return matches.length === 1 ? matches[0] : undefined;
}

/** @param {Array<SharedProofEvent>} events @param {string} kind @param {SharedProofPhase} phase */
function phaseEventCount(events, kind, phase) {
  return countEvents(events, (event) => event.kind === kind && event.phase === phase);
}

/** @param {Array<SharedProofEvent>} events @param {string} kind @param {SharedProofPhase} phase @param {(event: SharedProofEvent) => boolean} predicate */
function phaseEvent(events, kind, phase, predicate) {
  return firstEvent(events, (event) =>
    event.kind === kind && event.phase === phase && predicate(event)
  );
}

/**
 * Match the complete shared-session chain with a fixed-shape result. Every
 * diagnostic field is a boolean or bounded count; no raw identity/content is
 * returned to Playwright's assertion reporter.
 */
/**
 * @param {unknown} events
 * @param {SharedProofExpected} [expected={}]
 */
export function matchSharedSessionProofLedger(events, expected = {}) {
  if (!isEventList(events)) throw new Error('shared proof ledger sequence is not bounded');
  const chatSockets = events.filter((event) => event.kind === 'chat.socket');
  const ptyUpgrades = events.filter((event) => event.kind === 'pty.upgrade');
  const actions = events.filter((event) => event.kind === 'session.action');
  const identities = events.filter((event) => event.kind === 'session.identity');
  const prompts = events.filter((event) => event.kind === 'prompt.submit');
  const acknowledgements = events.filter((event) => event.kind === 'prompt.ack');
  const deltas = events.filter((event) => event.kind === 'message.delta');
  const completions = events.filter((event) => event.kind === 'message.complete');
  const histories = events.filter((event) => event.kind === 'history.response');
  const transitions = events.filter((event) => event.kind === 'mode.transition');
  const ready = events.filter((event) => event.kind === 'gateway.ready');
  const closeEvents = events.filter((event) => event.kind === 'chat.close');
  const authenticatedIdentity = events.find(
    (event) => event.kind === 'auth.identity' && event.matches === true
  );

  const loginRequest = firstEvent(events, (event) =>
    event.kind === 'http.request' && event.method === 'POST' && event.route === '/auth/password-login'
  );
  const loginResponse = firstEvent(events, (event) =>
    event.kind === 'http.response' && event.method === 'POST' && event.route === '/auth/password-login' &&
    typeof loginRequest?.sequence === 'number' && event.sequence > loginRequest.sequence
  );
  const identityRequest = firstEvent(events, (event) =>
    event.kind === 'http.request' && event.method === 'GET' && event.route === '/api/auth/me'
  );
  const identityResponse = firstEvent(events, (event) =>
    event.kind === 'http.response' && event.method === 'GET' && event.route === '/api/auth/me' &&
    typeof identityRequest?.sequence === 'number' && event.sequence > identityRequest.sequence && event.status === 200
  );
  const ticketRequest = firstEvent(events, (event) =>
    event.kind === 'http.request' && event.method === 'POST' && event.route === '/api/auth/ws-ticket'
  );
  const ticketResponse = firstEvent(events, (event) =>
    event.kind === 'http.response' && event.method === 'POST' && event.route === '/api/auth/ws-ticket' &&
    typeof ticketRequest?.sequence === 'number' && event.sequence > ticketRequest.sequence && event.status === 200
  );
  const socket = chatSockets.length === 1 && chatSockets[0].route === '/api/ws' && chatSockets[0].ticketOnly === true
    ? chatSockets[0]
    : undefined;
  const gatewayReady = ready.length === 1 && ready[0].serverFirst === true ? ready[0] : undefined;
  const action = actions.length === 1 &&
    (actions[0].method === 'session.create' || actions[0].method === 'session.resume')
    ? actions[0]
    : undefined;
  const identityMatch = identities.some((event) => event.matches === true && event.method === action?.method);
  const freshSessionPromotion = action?.method !== 'session.create' ||
    identities.some((event) => event.method === 'session.create' && event.matches === true && event.promoted === true);
  const resumeAuthoritativeIdentity = action?.method !== 'session.resume' ||
    identities.some((event) => event.method === 'session.resume' && event.matches === true && event.promoted === false);
  const firstPrompt = onePhaseEvent(events, 'prompt.submit', 'first');
  const secondPrompt = onePhaseEvent(events, 'prompt.submit', 'second');
  const firstAck = phaseEvent(events, 'prompt.ack', 'first', (event) => event.requestMatches === true);
  const secondAck = phaseEvent(events, 'prompt.ack', 'second', (event) => event.requestMatches === true);
  const firstDelta = phaseEvent(events, 'message.delta', 'first', (event) =>
    event.requestMatches === true && event.sessionMatches === true
  );
  const secondDelta = phaseEvent(events, 'message.delta', 'second', (event) =>
    event.requestMatches === true && event.sessionMatches === true
  );
  const firstCompletion = phaseEvent(events, 'message.complete', 'first', (event) =>
    event.status === (expected.firstCompletionStatus ?? 'ok') &&
    event.requestMatches === true && event.sessionMatches === true && event.markerMatches === true
  );
  const secondCompletion = phaseEvent(events, 'message.complete', 'second', (event) =>
    event.status === (expected.secondCompletionStatus ?? 'ok') &&
    event.requestMatches === true && event.sessionMatches === true && event.markerMatches === true
  );
  const firstHistory = onePhaseEvent(events, 'history.response', 'first');
  const finalHistory = onePhaseEvent(events, 'history.response', 'second');
  const pty = ptyUpgrades.length === 1 && ptyUpgrades[0].route === '/api/pty' ? ptyUpgrades[0] : undefined;
  const chatToTerminal = firstEvent(events, (event) =>
    event.kind === 'mode.transition' && event.event === 'chat-to-terminal'
  );
  const terminalToChat = firstEvent(events, (event) =>
    event.kind === 'mode.transition' && event.event === 'terminal-to-chat'
  );
  const firstHistorySequence = sequenceOf(firstHistory);
  const noSecondSessionCreate = actions.every((event) =>
    event.method !== 'session.create' ||
    (typeof firstHistorySequence === 'number' && typeof event.sequence === 'number' && event.sequence <= firstHistorySequence)
  );
  const ordered =
    typeof sequenceOf(loginRequest) === 'number' &&
    typeof sequenceOf(loginResponse) === 'number' &&
    typeof sequenceOf(identityRequest) === 'number' &&
    typeof sequenceOf(identityResponse) === 'number' &&
    typeof sequenceOf(ticketRequest) === 'number' &&
    typeof sequenceOf(ticketResponse) === 'number' &&
    typeof sequenceOf(socket) === 'number' &&
    typeof sequenceOf(gatewayReady) === 'number' &&
    typeof sequenceOf(action) === 'number' &&
    typeof sequenceOf(firstPrompt) === 'number' &&
    typeof sequenceOf(firstAck) === 'number' &&
    typeof sequenceOf(firstDelta) === 'number' &&
    typeof sequenceOf(firstCompletion) === 'number' &&
    typeof sequenceOf(firstHistory) === 'number' &&
    typeof sequenceOf(chatToTerminal) === 'number' &&
    typeof sequenceOf(pty) === 'number' &&
    typeof sequenceOf(terminalToChat) === 'number' &&
    typeof sequenceOf(secondPrompt) === 'number' &&
    typeof sequenceOf(secondAck) === 'number' &&
    typeof sequenceOf(secondDelta) === 'number' &&
    typeof sequenceOf(secondCompletion) === 'number' &&
    typeof sequenceOf(finalHistory) === 'number' &&
    sequenceOrSentinel(loginRequest) < sequenceOrSentinel(loginResponse) &&
    sequenceOrSentinel(loginResponse) < sequenceOrSentinel(identityRequest) &&
    sequenceOrSentinel(identityRequest) < sequenceOrSentinel(identityResponse) &&
    sequenceOrSentinel(identityResponse) < sequenceOrSentinel(ticketRequest) &&
    sequenceOrSentinel(ticketRequest) < sequenceOrSentinel(ticketResponse) &&
    sequenceOrSentinel(ticketResponse) < sequenceOrSentinel(socket) &&
    sequenceOrSentinel(socket) < sequenceOrSentinel(gatewayReady) &&
    sequenceOrSentinel(gatewayReady) < sequenceOrSentinel(action) &&
    sequenceOrSentinel(action) < sequenceOrSentinel(firstPrompt) &&
    sequenceOrSentinel(firstPrompt) < sequenceOrSentinel(firstAck) &&
    sequenceOrSentinel(firstAck) < sequenceOrSentinel(firstDelta) &&
    sequenceOrSentinel(firstDelta) < sequenceOrSentinel(firstCompletion) &&
    sequenceOrSentinel(firstCompletion) < sequenceOrSentinel(firstHistory) &&
    sequenceOrSentinel(firstHistory) < sequenceOrSentinel(chatToTerminal) &&
    sequenceOrSentinel(chatToTerminal) < sequenceOrSentinel(pty) &&
    sequenceOrSentinel(pty) < sequenceOrSentinel(terminalToChat) &&
    sequenceOrSentinel(terminalToChat) < sequenceOrSentinel(secondPrompt) &&
    sequenceOrSentinel(secondPrompt) < sequenceOrSentinel(secondAck) &&
    sequenceOrSentinel(secondAck) < sequenceOrSentinel(secondDelta) &&
    sequenceOrSentinel(secondDelta) < sequenceOrSentinel(secondCompletion) &&
    sequenceOrSentinel(secondCompletion) < sequenceOrSentinel(finalHistory);

  return Object.freeze({
    ordered,
    login: loginResponse?.status >= 200 && loginResponse?.status < 400,
    authenticated: identityResponse?.status === 200 && authenticatedIdentity?.matches === true,
    ticket: ticketResponse?.status === 200,
    chatWebSocketOpen: !!socket,
    chatWebSocketCount: chatSockets.length,
    chatWebSocketCloseCount: closeEvents.length,
    chatWebSocketClosed: closeEvents.length === 1,
    gatewayReady: !!gatewayReady,
    sessionAction: !!action && identityMatch && freshSessionPromotion && resumeAuthoritativeIdentity,
    freshSessionPromotion,
    resumeAuthoritativeIdentity,
    sessionCreateCount: countEvents(actions, (event) => event.method === 'session.create'),
    sessionResumeCount: countEvents(actions, (event) => event.method === 'session.resume'),
    noSecondSessionCreate,
    firstPrompt: !!firstPrompt && firstPrompt.markerMatches === true && firstPrompt.sessionMatches === true,
    secondPrompt: !!secondPrompt && secondPrompt.markerMatches === true && secondPrompt.sessionMatches === true,
    secondPromptSameOwner: !!secondPrompt && secondPrompt.sessionMatches === true,
    promptCount: prompts.length,
    firstPromptAcknowledgement: !!firstAck,
    secondPromptAcknowledgement: !!secondAck,
    firstDelta: !!firstDelta,
    secondDelta: !!secondDelta,
    firstCompletion: !!firstCompletion,
    secondCompletion: !!secondCompletion,
    completionCount: completions.length,
    firstHistory: !!firstHistory && firstHistory.status === 200 &&
      firstHistory.sessionMatches === true && firstHistory.firstPromptMatches === true &&
      firstHistory.firstAssistantMarkerMatches === true,
    finalHistory: !!finalHistory && finalHistory.status === 200 &&
      finalHistory.sessionMatches === true && finalHistory.firstPromptMatches === true &&
      finalHistory.firstAssistantMarkerMatches === true && finalHistory.secondPromptMatches === true &&
      finalHistory.secondAssistantMarkerMatches === true,
    historyPairCount: histories.length,
    modeChatToTerminal: !!chatToTerminal,
    modeTerminalToChat: !!terminalToChat,
    ptyUpgrade: !!pty,
    ptyUpgradeCount: ptyUpgrades.length,
    ptyQueryExact: !!pty && pty.queryKeyCount === 2,
    ptyTicketPresent: !!pty && pty.ticketPresent === true && pty.ticketLength > 0,
    ptyResumePresent: !!pty && pty.resumePresent === true && pty.resumeLength > 0,
    ptyResumeMatches: !!pty && pty.resumeMatches === true,
    ptyAttachAbsent: !!pty && pty.attachPresent === false && pty.attachLength === 0,
    legacyMode: !!pty && pty.legacyMode === true,
    noSecondChatTransport: chatSockets.length === 1,
    noSecondPtyUpgrade: ptyUpgrades.length === 1,
    finalHistoryMessageCount: typeof finalHistory?.messageCount === 'number' ? finalHistory.messageCount : 0,
    logout: events.some((event) =>
      event.kind === 'logout' && event.status === 302 &&
      event.cookieJarCleared === true && event.storageCleared === true
    )
  });
}

/**
 * Inspect one raw REST response only during the assertion. The return shape is
 * deliberately fixed and never includes the canonical ID or message content.
 */
/**
 * @param {unknown} response
 * @param {{ sessionId: string, firstPrompt: string, firstAssistantMarker: string, secondPrompt: string, secondAssistantMarker: string }} expected
 */
export function matchSharedSessionHistory(response, expected) {
  const candidate = response !== null && typeof response === 'object' && !Array.isArray(response)
    ? /** @type {Record<string, unknown>} */ (response)
    : undefined;
  const sessionId = candidate?.session_id ?? candidate?.sessionId;
  const messages = Array.isArray(candidate?.messages) ? candidate.messages : [];
  if (messages.length > MAX_MESSAGE_COUNT) throw new Error('shared proof history exceeded its bound');
  let firstPromptMatches = false;
  let firstAssistantMarkerMatches = false;
  let secondPromptMatches = false;
  let secondAssistantMarkerMatches = false;
  for (const message of messages) {
    if (message === null || typeof message !== 'object' || Array.isArray(message)) continue;
    const record = /** @type {Record<string, unknown>} */ (message);
    const role = record.role;
    const content = record.content;
    if (role === 'user' && content === expected.firstPrompt) firstPromptMatches = true;
    if (role === 'assistant' && typeof content === 'string' && content.includes(expected.firstAssistantMarker)) {
      firstAssistantMarkerMatches = true;
    }
    if (role === 'user' && content === expected.secondPrompt) secondPromptMatches = true;
    if (role === 'assistant' && typeof content === 'string' && content.includes(expected.secondAssistantMarker)) {
      secondAssistantMarkerMatches = true;
    }
  }
  return Object.freeze({
    sessionMatches: sessionId === expected.sessionId,
    firstPromptMatches,
    firstAssistantMarkerMatches,
    secondPromptMatches,
    secondAssistantMarkerMatches,
    messageCount: messages.length,
    matched: sessionId === expected.sessionId && firstPromptMatches && firstAssistantMarkerMatches &&
      secondPromptMatches && secondAssistantMarkerMatches
  });
}

/** @param {unknown} value */
export function isSharedSessionProofRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
