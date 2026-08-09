import { describe, expect, it } from 'vitest';
import { requestLiveReconciliationProjection } from '../../tests/live/live-reconciliation-transport.mjs';
import { LIVE_PROOF_ASSISTANT_MARKER, LIVE_PROOF_PROMPT } from '../../tests/live/live-proof-ledger.mjs';
import { reconcileLiveHistory } from '../../tests/live/live-reconciliation.mjs';

const BASE_URL = 'http://127.0.0.1:4187/';
const SESSION_ID = 'intervening-user-session';
const SHARED_INTERVENING_USER_CORPUS = [
  { role: 'user' as const, content: LIVE_PROOF_PROMPT },
  // Any new user turn fences the earlier prompt from a later assistant marker.
  { role: 'user' as const, content: 'A later user turn starts a new completion pair.' },
  { role: 'assistant' as const, content: LIVE_PROOF_ASSISTANT_MARKER }
];
const EXPECTED = {
  promptMatches: 'one',
  completedPairs: 'zero',
  status: 'match-unattributed'
};

function jsonResponse(value: unknown): Response {
  const body = Uint8Array.from([...JSON.stringify(value)].map((character) => character.charCodeAt(0)));
  let consumed = false;
  return {
    status: 200,
    headers: {
      get(name: string) {
        return name === 'content-type' ? 'application/json' : null;
      }
    },
    body: {
      getReader() {
        return {
          async read() {
            if (consumed) return { done: true, value: undefined };
            consumed = true;
            return { done: false, value: body };
          },
          async cancel() {}
        };
      }
    }
  } as unknown as Response;
}

function pageWithSharedCorpus() {
  return {
    evaluate: async (callback: (args: unknown) => Promise<unknown>, args: unknown) => {
      const previousFetch = globalThis.fetch;
      globalThis.fetch = (async (input) => {
        const path = new URL(String(input)).pathname;
        if (path === '/api/sessions') {
          return jsonResponse({
            sessions: [{ id: SESSION_ID, message_count: SHARED_INTERVENING_USER_CORPUS.length }],
            total: 1,
            limit: 100,
            offset: 0
          });
        }
        if (path === `/api/sessions/${SESSION_ID}/messages`) {
          return jsonResponse({
            session_id: SESSION_ID,
            messages: SHARED_INTERVENING_USER_CORPUS,
            pagination: {
              limit: 500,
              offset: 0,
              returned: SHARED_INTERVENING_USER_CORPUS.length
            }
          });
        }
        throw new Error(`unexpected reconciliation path: ${path}`);
      }) as typeof fetch;
      try {
        return await callback(args);
      } finally {
        globalThis.fetch = previousFetch;
      }
    }
  };
}

describe('reconciliation history projection parity', () => {
  it('fences an exact assistant marker after an intervening user message in both projections', async () => {
    const pureProjection = await reconcileLiveHistory({
      sessions: [{ id: SESSION_ID, messageCount: SHARED_INTERVENING_USER_CORPUS.length }],
      getMessages: async () => SHARED_INTERVENING_USER_CORPUS
    });
    const pageProjection = await requestLiveReconciliationProjection(pageWithSharedCorpus(), {
      baseURL: BASE_URL,
      kind: 'history'
    });

    // Keep this corpus shared: the page realm must not silently use looser pairing rules.
    expect({ pureProjection, pageProjection }).toEqual({
      pureProjection: EXPECTED,
      pageProjection: EXPECTED
    });
  });
});
