import { LIVE_PROOF_ASSISTANT_MARKER, LIVE_PROOF_PROMPT } from './live-proof-ledger.mjs';

export const LIVE_RECONCILIATION_ENV = 'HERMTERNAL_LIVE_RECONCILIATION';
export const LIVE_RECONCILIATION_MAX_SESSIONS = 100;
export const LIVE_RECONCILIATION_MAX_MESSAGES = 500;
export const LIVE_RECONCILIATION_STATUSES = Object.freeze([
  'no-match-uncertain',
  'delivery-observed',
  'completion-observed',
  'ambiguous'
]);
export const LIVE_RECONCILIATION_COUNT_VALUES = Object.freeze(['zero', 'one', 'multiple']);

const SESSION_ID_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9._~-]{0,126}[A-Za-z0-9])?$/u;
const MAX_TEXT_LENGTH = 8_192;

/**
 * Parse only the bounded session-list projection needed for reconciliation.
 * Pagination must prove that the complete authoritative list fit in one
 * response; the mode never guesses a page, sorts by recency, or follows a
 * continuation it cannot prove complete.
 *
 * @param {unknown} value
 * @returns {Array<{ id: string, messageCount: number }>}
 */
export function parseReconciliationSessionList(value) {
  const object = requireRecord(value);
  requireKeys(object, ['sessions', 'total', 'limit', 'offset']);
  const sessions = object.sessions;
  const total = boundedInteger(object.total, 0, LIVE_RECONCILIATION_MAX_SESSIONS);
  const limit = boundedInteger(object.limit, 1, LIVE_RECONCILIATION_MAX_SESSIONS);
  const offset = boundedInteger(object.offset, 0, LIVE_RECONCILIATION_MAX_SESSIONS);
  if (
    !Array.isArray(sessions) ||
    sessions.length > LIVE_RECONCILIATION_MAX_SESSIONS ||
    offset !== 0 ||
    limit !== LIVE_RECONCILIATION_MAX_SESSIONS ||
    sessions.length !== total
  ) {
    throw new Error('live reconciliation pagination is not complete');
  }

  const seen = new Set();
  return sessions.map((value) => {
    const session = requireRecord(value);
    const id = requireSessionId(session.id);
    if (seen.has(id)) throw new Error('live reconciliation session identity is duplicated');
    seen.add(id);
    return {
      id,
      messageCount: boundedInteger(session.message_count, 0, LIVE_RECONCILIATION_MAX_MESSAGES)
    };
  });
}

/**
 * Parse one complete bounded message history. A returned alias or an omitted
 * page boundary is not safe evidence for this read-only reconciliation.
 *
 * @param {unknown} value
 * @param {string} expectedSessionId
 * @param {number} expectedMessageCount
 * @returns {Array<{ role: 'user'|'assistant'|'system'|'tool', content: string|null }>}
 */
export function parseReconciliationSessionMessages(value, expectedSessionId, expectedMessageCount) {
  const object = requireRecord(value);
  requireKeys(object, ['session_id', 'messages', 'pagination']);
  const sessionId = requireSessionId(object.session_id);
  const messages = object.messages;
  const pagination = requireRecord(object.pagination);
  requireKeys(pagination, ['limit', 'offset', 'returned']);
  const limit = pagination.limit;
  const offset = boundedInteger(pagination.offset, 0, LIVE_RECONCILIATION_MAX_MESSAGES);
  const returned = boundedInteger(pagination.returned, 0, LIVE_RECONCILIATION_MAX_MESSAGES);
  if (
    sessionId !== expectedSessionId ||
    !Array.isArray(messages) ||
    messages.length > LIVE_RECONCILIATION_MAX_MESSAGES ||
    expectedMessageCount < 0 ||
    expectedMessageCount > LIVE_RECONCILIATION_MAX_MESSAGES ||
    messages.length !== expectedMessageCount ||
    returned !== messages.length ||
    offset !== 0 ||
    (limit !== null && limit !== LIVE_RECONCILIATION_MAX_MESSAGES)
  ) {
    throw new Error('live reconciliation message pagination is not complete');
  }
  return messages.map(parseMessage);
}

/**
 * Scan all supplied authoritative histories in memory and return only fixed
 * counts and a safe status. The caller owns the transient IDs required to
 * request each history; this result never returns them.
 *
 * @param {{
 *   sessions: Array<{ id: string, messageCount: number }>,
 *   getMessages: (sessionId: string, messageCount: number) => Promise<Array<{ role: 'user'|'assistant'|'system'|'tool', content: string|null }>>,
 *   prompt?: string,
 *   assistantMarker?: string
 * }} input
 */
export async function reconcileLiveHistory({
  sessions,
  getMessages,
  prompt = LIVE_PROOF_PROMPT,
  assistantMarker = LIVE_PROOF_ASSISTANT_MARKER
}) {
  if (
    !Array.isArray(sessions) ||
    sessions.length > LIVE_RECONCILIATION_MAX_SESSIONS ||
    typeof getMessages !== 'function' ||
    typeof prompt !== 'string' ||
    prompt !== LIVE_PROOF_PROMPT ||
    typeof assistantMarker !== 'string' ||
    assistantMarker !== LIVE_PROOF_ASSISTANT_MARKER
  ) {
    throw new Error('live reconciliation input is not approved');
  }

  let promptCount = 0;
  let completedPairCount = 0;
  const promptSessions = new Set();
  const completedPairSessions = new Set();
  const seen = new Set();

  for (const session of sessions) {
    if (!session || typeof session !== 'object' || Array.isArray(session)) {
      throw new Error('live reconciliation session projection is invalid');
    }
    const sessionId = requireSessionId(session.id);
    if (seen.has(sessionId)) throw new Error('live reconciliation session identity is duplicated');
    seen.add(sessionId);
    const messageCount = boundedInteger(session.messageCount, 0, LIVE_RECONCILIATION_MAX_MESSAGES);
    const messages = await getMessages(sessionId, messageCount);
    if (!Array.isArray(messages) || messages.length !== messageCount) {
      throw new Error('live reconciliation message projection is incomplete');
    }
    for (const message of messages) parseMessage(message);

    for (let index = 0; index < messages.length; index += 1) {
      const message = messages[index];
      if (message.role !== 'user' || message.content !== prompt) continue;
      promptCount = Math.min(promptCount + 1, 2);
      promptSessions.add(sessionId);
      let pair = false;
      for (let next = index + 1; next < messages.length; next += 1) {
        const candidate = messages[next];
        if (candidate.role === 'user' && candidate.content === prompt) break;
        if (
          candidate.role === 'assistant' &&
          typeof candidate.content === 'string' &&
          candidate.content.includes(assistantMarker)
        ) {
          pair = true;
          break;
        }
      }
      if (pair) {
        completedPairCount = Math.min(completedPairCount + 1, 2);
        completedPairSessions.add(sessionId);
      }
    }
  }

  const promptMatches = countValue(promptCount);
  const completedPairs = countValue(completedPairCount);
  const ambiguous =
    promptCount > 1 ||
    completedPairCount > 1 ||
    promptSessions.size > 1 ||
    completedPairSessions.size > 1 ||
    (completedPairCount === 1 &&
      (promptCount !== 1 || !sameOnlySession(promptSessions, completedPairSessions)));
  const status = ambiguous
    ? 'ambiguous'
    : completedPairCount === 1
      ? 'completion-observed'
      : promptCount === 1
        ? 'delivery-observed'
        : 'no-match-uncertain';

  return Object.freeze({ promptMatches, completedPairs, status });
}

/** @param {{ promptMatches: string, completedPairs: string, status: string }} result */
export function formatLiveReconciliationResult(result) {
  const safe = assertLiveReconciliationResult(result);
  return `live reconciliation\tpromptMatches=${safe.promptMatches}\tcompletedPairs=${safe.completedPairs}\tstatus=${safe.status}`;
}

/** @param {{ promptMatches: string, completedPairs: string, status: string }} result */
export function assertLiveReconciliationResult(result) {
  if (
    result === null ||
    typeof result !== 'object' ||
    Array.isArray(result) ||
    Object.keys(result).length !== 3 ||
    !LIVE_RECONCILIATION_COUNT_VALUES.includes(result.promptMatches) ||
    !LIVE_RECONCILIATION_COUNT_VALUES.includes(result.completedPairs) ||
    !LIVE_RECONCILIATION_STATUSES.includes(result.status)
  ) {
    throw new Error('live reconciliation result is not approved');
  }
  return Object.freeze({
    promptMatches: result.promptMatches,
    completedPairs: result.completedPairs,
    status: result.status
  });
}

/**
 * @param {unknown} value
 * @returns {{ role: 'user'|'assistant'|'system'|'tool', content: string|null }}
 */
function parseMessage(value) {
  const message = requireRecord(value);
  if (
    message.role !== 'user' &&
    message.role !== 'assistant' &&
    message.role !== 'system' &&
    message.role !== 'tool'
  ) {
    throw new Error('live reconciliation message role is invalid');
  }
  if (message.content !== null && (typeof message.content !== 'string' || message.content.length > MAX_TEXT_LENGTH)) {
    throw new Error('live reconciliation message content is invalid');
  }
  return { role: message.role, content: message.content };
}

/** @param {unknown} value */
function requireRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('live reconciliation response is invalid');
  }
  return /** @type {Record<string, any>} */ (value);
}

/** @param {Record<string, unknown>} object @param {string[]} keys */
function requireKeys(object, keys) {
  for (const key of keys) if (!(key in object)) throw new Error('live reconciliation response is incomplete');
}

/** @param {unknown} value @param {number} min @param {number} max @returns {number} */
function boundedInteger(value, min, max) {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) {
    throw new Error('live reconciliation value is out of bounds');
  }
  return value;
}

/** @param {unknown} value */
function requireSessionId(value) {
  if (typeof value !== 'string' || !SESSION_ID_PATTERN.test(value)) {
    throw new Error('live reconciliation session identity is invalid');
  }
  return value;
}

/** @param {number} value */
function countValue(value) {
  return value === 0 ? 'zero' : value === 1 ? 'one' : 'multiple';
}

/** @param {Set<string>} first @param {Set<string>} second */
function sameOnlySession(first, second) {
  if (first.size !== 1 || second.size !== 1) return false;
  return first.values().next().value === second.values().next().value;
}
