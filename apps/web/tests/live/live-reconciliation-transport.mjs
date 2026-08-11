import { LIVE_PROOF_ASSISTANT_MARKER, LIVE_PROOF_PROMPT } from './live-proof-ledger.mjs';

export const LIVE_RECONCILIATION_MAX_RESPONSE_BYTES = 256 * 1024;
export const LIVE_RECONCILIATION_MAX_RESPONSE_CHUNKS = 4096;
export const LIVE_RECONCILIATION_RESPONSE_TIMEOUT_MS = 30_000;
const MAX_PROVIDER_COUNT = 32;
const SAFE_PROVIDER_NAME = /^[a-z0-9][a-z0-9._-]{0,95}$/u;
const SESSION_ID_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9._~-]{0,126}[A-Za-z0-9])?$/u;
const MAX_TEXT_LENGTH = 8_192;

/**
 * Fetch and validate one bounded reconciliation projection in the authenticated
 * page realm. Cookies stay browser-owned, and only the fixed provider/login/
 * identity/history projection crosses back to the test process.
 *
 * @param {any} page
 * @param {{
 *   baseURL: string,
 *   kind: 'providers'|'login'|'auth-me'|'history',
 *   provider?: string,
 *   username?: string,
 *   password?: string
 * }} request
 */
export async function requestLiveReconciliationProjection(page, request) {
  if (
    page === null ||
    typeof page !== 'object' ||
    typeof page.evaluate !== 'function' ||
    request === null ||
    typeof request !== 'object' ||
    typeof request.baseURL !== 'string' ||
    !/^http:\/\/127\.0\.0\.1:\d+\/$/u.test(request.baseURL) ||
    (request.kind !== 'providers' &&
      request.kind !== 'login' &&
      request.kind !== 'auth-me' &&
      request.kind !== 'history')
  ) {
    throw new Error('live reconciliation transport input is not approved');
  }
  if (
    request.kind === 'login' &&
    (typeof request.provider !== 'string' ||
      typeof request.username !== 'string' ||
      typeof request.password !== 'string')
  ) {
    throw new Error('live reconciliation login input is not approved');
  }
  return page.evaluate(
    /**
     * @param {{
     *   baseURL: string,
     *   kind: 'providers'|'login'|'auth-me'|'history',
     *   provider?: string,
     *   username?: string,
     *   password?: string
     * }} args
     */
    async ({ baseURL, kind, provider, username, password }) => {
      const MAX_BYTES = 256 * 1024;
      const MAX_CHUNKS = 4096;
      const TIMEOUT_MS = 30_000;
      const MAX_SESSIONS = 100;
      const MAX_MESSAGES = 500;
      const MAX_PROVIDER_COUNT_IN_PAGE = 32;
      const SAFE_PROVIDER_NAME_IN_PAGE = /^[a-z0-9][a-z0-9._-]{0,95}$/u;
      const SESSION_ID_PATTERN_IN_PAGE = /^[A-Za-z0-9](?:[A-Za-z0-9._~-]{0,126}[A-Za-z0-9])?$/u;
      const MAX_TEXT_LENGTH_IN_PAGE = 8_192;
      const PROMPT = 'Reply with exactly: Hermternal live proof complete.';
      const ASSISTANT_MARKER = 'Hermternal live proof complete.';

      /** @param {unknown} value @returns {Record<string, any>|undefined} */
      function record(value) {
        return value !== null && typeof value === 'object' && !Array.isArray(value) ? value : undefined;
      }

      /** @param {unknown} value @param {number} min @param {number} max */
      function boundedInteger(value, min, max) {
        if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) {
          throw new Error('live reconciliation response value is out of bounds');
        }
        return value;
      }

      /** @param {unknown} value */
      function sessionId(value) {
        if (typeof value !== 'string' || !SESSION_ID_PATTERN_IN_PAGE.test(value)) {
          throw new Error('live reconciliation session identity is invalid');
        }
        return value;
      }

      /** @param {unknown} value */
      function parseMessage(value) {
        const message = record(value);
        if (
          message === undefined ||
          (message.role !== 'user' &&
            message.role !== 'assistant' &&
            message.role !== 'system' &&
            message.role !== 'tool')
        ) {
          throw new Error('live reconciliation message role is invalid');
        }
        if (
          message.content !== null &&
          (typeof message.content !== 'string' || message.content.length > MAX_TEXT_LENGTH_IN_PAGE)
        ) {
          throw new Error('live reconciliation message content is invalid');
        }
        return { role: message.role, content: message.content };
      }

      /** @param {any} response @param {AbortController} controller @param {number} deadline */
      async function readBoundedJson(response, controller, deadline) {
        if (!response || response.body === null || typeof response.body?.getReader !== 'function') {
          controller.abort();
          throw new Error('live reconciliation response body is not streamable');
        }
        const contentLength = response.headers.get('content-length');
        if (contentLength !== null) {
          if (!/^(?:0|[1-9][0-9]*)$/u.test(contentLength)) {
            controller.abort();
            throw new Error('live reconciliation response length is invalid');
          }
          const declaredLength = Number(contentLength);
          if (!Number.isSafeInteger(declaredLength) || declaredLength > MAX_BYTES) {
            controller.abort();
            throw new Error('live reconciliation response exceeded its bound');
          }
        }
        const reader = response.body.getReader();
        const chunks = [];
        let bytes = 0;
        let chunkCount = 0;
        let cancelRequested = false;
        const cancelReader = () => {
          if (cancelRequested) return;
          cancelRequested = true;
          // Do not wait for a hostile or stalled cancel promise. The fixed
          // timeout result must still reach cleanup, while this best-effort
          // cancellation releases the browser stream when it cooperates.
          void Promise.resolve(reader.cancel()).catch(() => undefined);
        };
        const readNextChunk = async () => {
          const remaining = deadline - Date.now();
          if (remaining <= 0) {
            cancelReader();
            controller.abort();
            throw new Error('live reconciliation transport timed out');
          }
          let timer;
          const deadlinePromise = new Promise((_, reject) => {
            timer = setTimeout(() => {
              cancelReader();
              controller.abort();
              reject(new Error('live reconciliation transport timed out'));
            }, remaining);
          });
          try {
            return await Promise.race([reader.read(), deadlinePromise]);
          } finally {
            clearTimeout(timer);
          }
        };
        try {
          while (true) {
            const next = await readNextChunk();
            if (!next || next.done === true) break;
            const chunk = next.value;
            if (!(chunk instanceof Uint8Array)) {
              await reader.cancel();
              controller.abort();
              throw new Error('live reconciliation response chunk is invalid');
            }
            chunkCount += 1;
            if (
              chunkCount > MAX_CHUNKS ||
              chunk.byteLength > MAX_BYTES - bytes
            ) {
              await reader.cancel();
              controller.abort();
              throw new Error('live reconciliation response exceeded its bound');
            }
            chunks.push(chunk);
            bytes += chunk.byteLength;
          }
        } catch (error) {
          cancelReader();
          controller.abort();
          if (error instanceof Error && error.message.startsWith('live reconciliation')) throw error;
          throw new Error('live reconciliation response body read failed');
        }
        const body = new Uint8Array(bytes);
        let offset = 0;
        for (const chunk of chunks) {
          body.set(chunk, offset);
          offset += chunk.byteLength;
        }
        try {
          return JSON.parse(new TextDecoder().decode(body));
        } catch {
          throw new Error('live reconciliation response was malformed');
        }
      }

      const projectionDeadline = Date.now() + TIMEOUT_MS;

      /**
       * @param {string} path
       * @param {{ method?: 'GET'|'POST', body?: string }} [options]
       */
      async function fetchJson(path, options = {}) {
        const remaining = projectionDeadline - Date.now();
        if (remaining <= 0) throw new Error('live reconciliation transport timed out');
        const controller = new AbortController();
        let timer;
        const fetchDeadline = new Promise((_, reject) => {
          timer = setTimeout(() => {
            controller.abort();
            reject(new Error('live reconciliation transport timed out'));
          }, remaining);
        });
        try {
          const fetchResult = fetch(new URL(path, baseURL).href, {
            method: options.method ?? 'GET',
            headers: {
              accept: 'application/json',
              ...(options.method === 'POST' ? { 'content-type': 'application/json' } : {})
            },
            body: options.body,
            credentials: 'include',
            cache: 'no-store',
            redirect: 'error',
            signal: controller.signal
          });
          const response = /** @type {Response} */ (await Promise.race([fetchResult, fetchDeadline]));
          if (
            response.status !== 200 ||
            response.headers.get('content-type')?.toLowerCase().includes('application/json') !== true
          ) {
            controller.abort();
            throw new Error('live reconciliation response was not approved');
          }
          return await readBoundedJson(response, controller, projectionDeadline);
        } catch (error) {
          if (error instanceof Error && error.message.startsWith('live reconciliation')) throw error;
          throw new Error('live reconciliation transport failed');
        } finally {
          clearTimeout(timer);
        }
      }

      /** @param {unknown} value */
      function parseProviderResponse(value) {
        const object = record(value);
        const providers = object?.providers;
        if (
          !Array.isArray(providers) ||
          providers.length === 0 ||
          providers.length > MAX_PROVIDER_COUNT_IN_PAGE
        ) {
          throw new Error('live reconciliation provider response was invalid');
        }
        const passwordProviders = providers.filter((candidate) => {
          const item = record(candidate);
          return (
            item !== undefined &&
            typeof item.name === 'string' &&
            SAFE_PROVIDER_NAME_IN_PAGE.test(item.name) &&
            typeof item.display_name === 'string' &&
            item.display_name.length <= 512 &&
            item.supports_password === true
          );
        });
        if (passwordProviders.length !== 1) {
          throw new Error('live reconciliation password provider is ambiguous');
        }
        return passwordProviders[0].name;
      }

      /** @param {unknown} value */
      function assertLoginResponse(value) {
        const object = record(value);
        if (
          object === undefined ||
          object.ok !== true ||
          object.next !== '/' ||
          Object.keys(object).some((key) => key !== 'ok' && key !== 'next')
        ) {
          throw new Error('live reconciliation login was not verified');
        }
        return true;
      }

      /** @param {unknown} value */
      function assertIdentity(value) {
        const object = record(value);
        const expiresAt = object?.expires_at;
        if (
          object === undefined ||
          typeof object.user_id !== 'string' ||
          object.user_id.length === 0 ||
          object.user_id.length > 512 ||
          typeof object.provider !== 'string' ||
          object.provider.length === 0 ||
          object.provider.length > 512 ||
          typeof expiresAt !== 'number' ||
          !Number.isInteger(expiresAt) ||
          expiresAt < 0 ||
          expiresAt > 4_294_967_295
        ) {
          throw new Error('live reconciliation authentication was not verified');
        }
        return true;
      }

      /** @param {unknown} value */
      function parseSessions(value) {
        const object = record(value);
        const sessions = object?.sessions;
        const total = boundedInteger(object?.total, 0, MAX_SESSIONS);
        const limit = boundedInteger(object?.limit, 1, MAX_SESSIONS);
        const offset = boundedInteger(object?.offset, 0, MAX_SESSIONS);
        if (
          !Array.isArray(sessions) ||
          sessions.length > MAX_SESSIONS ||
          offset !== 0 ||
          limit !== MAX_SESSIONS ||
          sessions.length !== total
        ) {
          throw new Error('live reconciliation pagination is not complete');
        }
        const seen = new Set();
        return sessions.map((candidate) => {
          const item = record(candidate);
          const id = sessionId(item?.id);
          if (seen.has(id)) throw new Error('live reconciliation session identity is duplicated');
          seen.add(id);
          return {
            id,
            messageCount: boundedInteger(item?.message_count, 0, MAX_MESSAGES)
          };
        });
      }

      /**
       * @param {unknown} value
       * @param {string} expectedSessionId
       * @param {number} expectedMessageCount
       */
      function parseMessages(value, expectedSessionId, expectedMessageCount) {
        const object = record(value);
        const returnedSessionId = sessionId(object?.session_id);
        const messages = object?.messages;
        const pagination = record(object?.pagination);
        const returned = boundedInteger(pagination?.returned, 0, MAX_MESSAGES);
        const offset = boundedInteger(pagination?.offset, 0, MAX_MESSAGES);
        const limit = pagination?.limit;
        if (
          returnedSessionId !== expectedSessionId ||
          !Array.isArray(messages) ||
          messages.length > MAX_MESSAGES ||
          messages.length !== expectedMessageCount ||
          returned !== messages.length ||
          offset !== 0 ||
          (limit !== null && limit !== MAX_MESSAGES)
        ) {
          throw new Error('live reconciliation message pagination is not complete');
        }
        return messages.map(parseMessage);
      }

      /** @param {number} value */
      function countValue(value) {
        return value === 0 ? 'zero' : value === 1 ? 'one' : 'multiple';
      }

      /**
       * @param {Array<{ id: string, messageCount: number }>} sessionList
       * @param {Map<string, Array<{ role: string, content: string|null }>>} historyBySession
       */
      function historyResult(sessionList, historyBySession) {
        let promptCount = 0;
        let completedPairCount = 0;
        const promptSessions = new Set();
        const completedPairSessions = new Set();
        for (const session of sessionList) {
          const messages = historyBySession.get(session.id);
          if (!messages) throw new Error('live reconciliation history projection is incomplete');
          for (let index = 0; index < messages.length; index += 1) {
            const message = messages[index];
            if (message.role !== 'user' || message.content !== PROMPT) continue;
            promptCount = Math.min(promptCount + 1, 2);
            promptSessions.add(session.id);
            let pair = false;
            for (let next = index + 1; next < messages.length; next += 1) {
              const candidate = messages[next];
              if (candidate.role === 'user') break;
              if (candidate.role === 'assistant' && candidate.content === ASSISTANT_MARKER) {
                pair = true;
                break;
              }
            }
            if (pair) {
              completedPairCount = Math.min(completedPairCount + 1, 2);
              completedPairSessions.add(session.id);
            }
          }
        }
        const multipleMatches =
          promptCount > 1 ||
          completedPairCount > 1 ||
          promptSessions.size > 1 ||
          completedPairSessions.size > 1 ||
          (completedPairCount === 1 &&
            (promptCount !== 1 ||
              promptSessions.size !== 1 ||
              completedPairSessions.size !== 1 ||
              [...promptSessions][0] !== [...completedPairSessions][0]));
        return {
          promptMatches: countValue(promptCount),
          completedPairs: countValue(completedPairCount),
          status:
            promptCount === 0
              ? 'no-match-uncertain'
              : multipleMatches
                ? 'multiple-matches-ambiguous'
                : 'match-unattributed'
        };
      }

      if (kind === 'providers') {
        return { provider: parseProviderResponse(await fetchJson('/api/auth/providers')) };
      }
      if (kind === 'login') {
        assertLoginResponse(
          await fetchJson('/auth/password-login', {
            method: 'POST',
            body: JSON.stringify({ provider, username, password, next: '/' })
          })
        );
        return { authenticated: true };
      }
      if (kind === 'auth-me') {
        assertIdentity(await fetchJson('/api/auth/me'));
        return { authenticated: true };
      }
      const sessions = parseSessions(await fetchJson('/api/sessions?limit=100&offset=0'));
      const historyBySession = new Map();
      for (const session of sessions) {
        historyBySession.set(
          session.id,
          parseMessages(
            await fetchJson(
              `/api/sessions/${encodeURIComponent(session.id)}/messages?limit=500&offset=0`
            ),
            session.id,
            session.messageCount
          )
        );
      }
      return historyResult(sessions, historyBySession);
    },
    {
      baseURL: request.baseURL,
      kind: request.kind,
      provider: request.provider,
      username: request.username,
      password: request.password
    }
  );
}

/**
 * The same bounded stream reader is exported for synthetic transport tests.
 * It accepts only a response-like object and returns parsed JSON inside the
 * caller's realm; production callers use the page-realm copy above.
 *
 * @param {any} response
 * @param {AbortController} controller
 */
export async function readBoundedLiveReconciliationJson(response, controller) {
  if (
    response === null ||
    typeof response !== 'object' ||
    controller === null ||
    typeof controller !== 'object' ||
    typeof controller.abort !== 'function'
  ) {
    throw new Error('live reconciliation response reader input is not approved');
  }
  if (response.body === null || typeof response.body?.getReader !== 'function') {
    controller.abort();
    throw new Error('live reconciliation response body is not streamable');
  }
  const contentLength = response.headers?.get?.('content-length');
  if (contentLength !== null && contentLength !== undefined) {
    if (!/^(?:0|[1-9][0-9]*)$/u.test(contentLength)) {
      controller.abort();
      throw new Error('live reconciliation response length is invalid');
    }
    const declaredLength = Number(contentLength);
    if (!Number.isSafeInteger(declaredLength) || declaredLength > LIVE_RECONCILIATION_MAX_RESPONSE_BYTES) {
      controller.abort();
      throw new Error('live reconciliation response exceeded its bound');
    }
  }
  const reader = response.body.getReader();
  const chunks = [];
  let bytes = 0;
  let chunkCount = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (!next || next.done === true) break;
      const chunk = next.value;
      if (!(chunk instanceof Uint8Array)) {
        await reader.cancel();
        controller.abort();
        throw new Error('live reconciliation response chunk is invalid');
      }
      chunkCount += 1;
      if (
        chunkCount > LIVE_RECONCILIATION_MAX_RESPONSE_CHUNKS ||
        chunk.byteLength > LIVE_RECONCILIATION_MAX_RESPONSE_BYTES - bytes
      ) {
        await reader.cancel();
        controller.abort();
        throw new Error('live reconciliation response exceeded its bound');
      }
      chunks.push(chunk);
      bytes += chunk.byteLength;
    }
  } catch (error) {
    try {
      await reader.cancel();
    } catch {
      // The transport is already failing closed; do not expose cancel errors.
    }
    controller.abort();
    if (error instanceof Error && error.message.startsWith('live reconciliation')) throw error;
    throw new Error('live reconciliation response body read failed');
  }
  const body = new Uint8Array(bytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder().decode(body));
  } catch {
    throw new Error('live reconciliation response was malformed');
  }
}
