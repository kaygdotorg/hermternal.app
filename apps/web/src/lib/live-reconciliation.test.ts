import { describe, expect, it } from 'vitest';
import {
  LIVE_RECONCILIATION_MAX_MESSAGES,
  assertLiveReconciliationResult,
  formatLiveReconciliationResult,
  parseReconciliationSessionList,
  parseReconciliationSessionMessages,
  reconcileLiveHistory
} from '../../tests/live/live-reconciliation.mjs';
import { LIVE_PROOF_ASSISTANT_MARKER, LIVE_PROOF_PROMPT } from '../../tests/live/live-proof-ledger.mjs';

const SESSION = { id: 'session-1', messageCount: 2 };

function messages() {
  return [
    { role: 'user' as const, content: LIVE_PROOF_PROMPT },
    { role: 'assistant' as const, content: LIVE_PROOF_ASSISTANT_MARKER }
  ];
}

describe('live reconciliation-only proof', () => {
  it('preserves zero prompt matches as no-match-uncertain', async () => {
    const result = await reconcileLiveHistory({
      sessions: [{ id: 'session-empty', messageCount: 0 }],
      getMessages: async () => []
    });
    expect(result).toEqual({
      promptMatches: 'zero',
      completedPairs: 'zero',
      status: 'no-match-uncertain'
    });
  });

  it('reports exact delivery and ordered completion observations without submitting', async () => {
    const requests: string[] = [];
    const result = await reconcileLiveHistory({
      sessions: [SESSION],
      getMessages: async (sessionId) => {
        requests.push(sessionId);
        return messages();
      }
    });
    expect(requests).toEqual(['session-1']);
    expect(result).toEqual({
      promptMatches: 'one',
      completedPairs: 'one',
      status: 'match-unattributed'
    });

    const incomplete = await reconcileLiveHistory({
      sessions: [{ id: 'session-incomplete', messageCount: 1 }],
      getMessages: async () => [{ role: 'user', content: LIVE_PROOF_PROMPT }]
    });
    expect(incomplete).toEqual({
      promptMatches: 'one',
      completedPairs: 'zero',
      status: 'match-unattributed'
    });
  });

  it('keeps one stale historical pair unattributed to the current run', async () => {
    const result = await reconcileLiveHistory({
      sessions: [{ id: 'stale-session', messageCount: 2 }],
      getMessages: async () => messages()
    });
    expect(result).toEqual({
      promptMatches: 'one',
      completedPairs: 'one',
      status: 'match-unattributed'
    });
  });

  it('keeps one manually seeded pair unattributed without a pre-send boundary', async () => {
    const result = await reconcileLiveHistory({
      sessions: [{ id: 'manually-seeded-session', messageCount: 2 }],
      getMessages: async () => messages()
    });
    expect(result).toEqual({
      promptMatches: 'one',
      completedPairs: 'one',
      status: 'match-unattributed'
    });
  });

  it('requires exact assistant marker equality', async () => {
    const result = await reconcileLiveHistory({
      sessions: [{ id: 'substring-session', messageCount: 2 }],
      getMessages: async () => [
        { role: 'user', content: LIVE_PROOF_PROMPT },
        { role: 'assistant', content: `${LIVE_PROOF_ASSISTANT_MARKER} with extra text` }
      ]
    });
    expect(result).toEqual({
      promptMatches: 'one',
      completedPairs: 'zero',
      status: 'match-unattributed'
    });
  });

  it('marks multiple exact historical pairs as ambiguous', async () => {
    const result = await reconcileLiveHistory({
      sessions: [{ id: 'multiple-pair-session', messageCount: 4 }],
      getMessages: async () => [...messages(), ...messages()]
    });
    expect(result).toEqual({
      promptMatches: 'multiple',
      completedPairs: 'multiple',
      status: 'multiple-matches-ambiguous'
    });
  });

  it('marks multiple prompts or sessions ambiguous and rejects pagination uncertainty', async () => {
    const duplicate = await reconcileLiveHistory({
      sessions: [{ id: 'session-duplicate', messageCount: 3 }],
      getMessages: async () => [
        ...messages(),
        { role: 'user', content: LIVE_PROOF_PROMPT }
      ]
    });
    expect(duplicate.status).toBe('multiple-matches-ambiguous');
    expect(duplicate.promptMatches).toBe('multiple');

    expect(() =>
      parseReconciliationSessionList({
        sessions: [{ id: 'session-1', message_count: 1 }],
        total: 2,
        limit: 100,
        offset: 0
      })
    ).toThrow('pagination');
    expect(() =>
      parseReconciliationSessionMessages(
        {
          session_id: 'session-1',
          messages: [],
          pagination: { limit: 500, offset: 0, returned: 0 }
        },
        'session-1',
        1
      )
    ).toThrow('pagination');
    expect(() =>
      parseReconciliationSessionList({
        sessions: Array.from({ length: 101 }, (_, index) => ({
          id: `session-${index}`,
          message_count: 0
        })),
        total: 101,
        limit: 100,
        offset: 0
      })
    ).toThrow('out of bounds');
  });

  it('fails closed on malformed rows and preserves the fixed result shape', () => {
    expect(() =>
      parseReconciliationSessionMessages(
        {
          session_id: 'session-1',
          messages: [{ role: 'user', content: 'x'.repeat(8_193) }],
          pagination: { limit: 500, offset: 0, returned: 1 }
        },
        'session-1',
        1
      )
    ).toThrow('content');
    expect(() =>
      assertLiveReconciliationResult({
        promptMatches: 'zero',
        completedPairs: 'zero',
        status: 'free-form'
      })
    ).toThrow('not approved');
    expect(formatLiveReconciliationResult({
      promptMatches: 'zero',
      completedPairs: 'zero',
      status: 'no-match-uncertain'
    })).toBe(
      'live reconciliation\tpromptMatches=zero\tcompletedPairs=zero\tstatus=no-match-uncertain'
    );
    expect(LIVE_RECONCILIATION_MAX_MESSAGES).toBe(500);
  });
});
