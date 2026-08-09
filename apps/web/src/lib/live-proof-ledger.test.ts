import { describe, expect, it } from 'vitest';
import {
  LIVE_PROOF_ASSISTANT_MARKER,
  LIVE_PROOF_HISTORY_LIMIT,
  LIVE_PROOF_PROMPT,
  assertLiveProofHappensBefore,
  assertLiveProofLedgerCaptureReady,
  createLiveProofLedger,
  matchLiveProofHistory,
  matchLiveProofLedger
} from '../../tests/live/live-proof-ledger.mjs';

function expectedTags(ledger: ReturnType<typeof createLiveProofLedger>) {
  return {
    sessionTag: ledger.identityTag('stored-1'),
    promptRequestTag: ledger.identityTag('prompt-1'),
    promptSessionTag: ledger.identityTag('ephemeral-1')
  };
}

function historyEvent(
  ledger: ReturnType<typeof createLiveProofLedger>,
  phase: 'pre-send' | 'post-completion',
  ids: number[],
  overrides: Record<string, unknown> = {}
) {
  return {
    phase,
    status: 200,
    sessionId: 'stored-1',
    historyComplete: true,
    watermarkEstablished: phase === 'pre-send',
    prefixStable: phase === 'post-completion',
    postFenceMatched: phase === 'post-completion',
    promptMatches: phase === 'post-completion',
    assistantMarkerMatches: phase === 'post-completion',
    candidateUserCount: phase === 'post-completion' ? 1 : 0,
    candidateAssistantCount: phase === 'post-completion' ? 1 : 0,
    messageCount: ids.length,
    historyIdTag: ledger.messageIdTag(ids),
    prefixIdTag: ledger.messageIdTag(phase === 'pre-send' ? ids : ids.slice(0, 2)),
    ...overrides
  };
}

function validProofEvents(options: { route?: string; ticketOnly?: boolean } = {}) {
  const ledger = createLiveProofLedger();
  const preIds = [10, 11];
  const postIds = [10, 11, 12, 13];
  ledger.recordWebSocketOpen({
    route: options.route ?? '/api/ws',
    ticketOnly: options.ticketOnly ?? true
  });
  ledger.recordWebSocketReceived({ event: 'gateway.ready' });
  ledger.recordGatewayReady();
  ledger.recordSessionAction({
    method: 'session.resume',
    requestId: 'create-1',
    sessionId: 'ephemeral-1',
    storedSessionId: 'stored-1'
  });
  ledger.recordHistoryResponse(historyEvent(ledger, 'pre-send', preIds));
  ledger.recordPrompt({ requestId: 'prompt-1', sessionId: 'ephemeral-1', promptMatches: true });
  ledger.recordWebSocketReceived({ event: 'response', requestId: 'prompt-1' });
  ledger.recordDelta({ sessionId: 'ephemeral-1' });
  ledger.recordCompletion({
    sessionId: 'ephemeral-1',
    status: 'complete',
    markerMatches: true
  });
  ledger.recordHistoryResponse(historyEvent(ledger, 'post-completion', postIds));
  return { ledger, events: ledger.snapshot(), expected: expectedTags(ledger) };
}

function historyResponse(
  sessionId: string,
  messages: Array<Record<string, unknown>>,
  limit = LIVE_PROOF_HISTORY_LIMIT
) {
  return {
    session_id: sessionId,
    messages,
    pagination: { limit, offset: 0, returned: messages.length }
  };
}

function proofMessages(ids: number[] = [10, 11, 12, 13]) {
  return ids.map((id) => {
    if (id === 10) return { id, role: 'system', content: null };
    if (id === 11) return { id, role: 'assistant', content: 'prior answer' };
    if (id === 12) return { id, role: 'user', content: LIVE_PROOF_PROMPT };
    return { id, role: 'assistant', content: LIVE_PROOF_ASSISTANT_MARKER };
  });
}

describe('bounded live proof ledger', () => {
  it('keeps a bounded typed sequence and refuses overflow', () => {
    const ledger = createLiveProofLedger(16);
    for (let index = 0; index < 16; index += 1) {
      ledger.recordHttpRequest({ method: 'GET', route: 'auth.me' });
    }
    expect(ledger.snapshot()).toHaveLength(16);
    expect(() => ledger.recordHttpRequest({ method: 'GET', route: 'auth.me' })).toThrow(
      'capacity was exceeded'
    );
  });

  it('matches the exact ordered session, fence, prompt, completion, and history chain', () => {
    const valid = validProofEvents();
    const proof = matchLiveProofLedger(valid.events, valid.expected);
    expect(proof).toEqual({
      ordered: true,
      websocketOpen: true,
      gatewayReady: true,
      serverFirstReady: true,
      sessionAction: true,
      prompt: true,
      promptAcknowledgement: true,
      delta: true,
      completion: true,
      history: true,
      historyStatusOk: true,
      messageCount: 4,
      promptCount: 1,
      completionCount: 1
    });
    expect(assertLiveProofLedgerCaptureReady(proof)).toBe(true);
    expect(() => assertLiveProofLedgerCaptureReady({ ...proof, ordered: false })).toThrow(
      'complete causal Hermes proof'
    );
  });

  it('retains HMAC identity tags but never raw session or request IDs', () => {
    const valid = validProofEvents();
    const serialized = JSON.stringify(valid.events);
    expect(serialized).not.toContain('stored-1');
    expect(serialized).not.toContain('ephemeral-1');
    expect(serialized).not.toContain('prompt-1');
    expect(valid.events.every((event) => !('sessionId' in event) && !('requestId' in event))).toBe(true);
    expect(serialized).toContain('h1:');
  });

  it('rejects mismatched identity or re-ordered completion evidence', () => {
    const valid = validProofEvents();
    const completion = valid.events.find((event) => event.kind === 'message.complete');
    expect(completion).toBeTruthy();
    const mismatched = valid.events.map((event) =>
      event === completion
        ? { ...event, sessionTag: valid.ledger.identityTag('wrong-session') }
        : event
    );
    expect(matchLiveProofLedger(mismatched, valid.expected).completion).toBe(false);

    const reordered = valid.events.map((event) =>
      event === completion ? { ...event, sequence: 1 } : event
    );
    expect(matchLiveProofLedger(reordered, valid.expected).ordered).toBe(false);
    expect(() => assertLiveProofHappensBefore(reordered, 'prompt.submit', 'message.complete')).toThrow(
      'ordering assertion failed'
    );
  });

  it('rejects completion before delta or prompt acknowledgement', () => {
    const valid = validProofEvents();
    const acknowledgement = valid.events.find(
      (event) => event.kind === 'ws.received' && event.event === 'response'
    );
    const delta = valid.events.find((event) => event.kind === 'message.delta');
    const completion = valid.events.find((event) => event.kind === 'message.complete');
    expect(acknowledgement && delta && completion).toBeTruthy();

    const completionBeforeDelta = valid.events.map((event) => {
      if (event === completion) return { ...event, sequence: Number(delta?.sequence) - 1 };
      return event;
    });
    expect(matchLiveProofLedger(completionBeforeDelta, valid.expected).ordered).toBe(false);

    const completionBeforeAcknowledgement = valid.events.map((event) => {
      if (event === completion) return { ...event, sequence: Number(acknowledgement?.sequence) - 1 };
      return event;
    });
    expect(matchLiveProofLedger(completionBeforeAcknowledgement, valid.expected).ordered).toBe(false);
  });

  it('uses source session correlation and complete status, never a fabricated event request ID', () => {
    const valid = validProofEvents();
    expect(matchLiveProofLedger(valid.events, valid.expected).completion).toBe(true);

    const wrongStatus = valid.events.map((event) =>
      event.kind === 'message.complete' ? { ...event, status: 'error' } : event
    );
    expect(matchLiveProofLedger(wrongStatus, valid.expected).completion).toBe(false);

    const wrongSession = valid.events.map((event) =>
      event.kind === 'message.complete'
        ? { ...event, sessionTag: valid.ledger.identityTag('wrong-session') }
        : event
    );
    expect(matchLiveProofLedger(wrongSession, valid.expected).completion).toBe(false);

    const fabricatedRequest = valid.events.map((event) =>
      event.kind === 'message.complete'
        ? { ...event, requestTag: valid.ledger.identityTag('prompt-1') }
        : event
    );
    expect(matchLiveProofLedger(fabricatedRequest, valid.expected).completion).toBe(false);
  });

  it('rejects duplicate prompts, gateway readiness, sockets, and completions', () => {
    const valid = validProofEvents();
    const prompt = valid.events.find((event) => event.kind === 'prompt.submit');
    const ready = valid.events.find((event) => event.kind === 'gateway.ready');
    const socket = valid.events.find((event) => event.kind === 'ws.open');
    const completion = valid.events.find((event) => event.kind === 'message.complete');
    expect(prompt && ready && socket && completion).toBeTruthy();

    expect(matchLiveProofLedger([...valid.events, { ...prompt, sequence: 100 }], valid.expected).prompt).toBe(false);
    expect(matchLiveProofLedger([...valid.events, { ...ready, sequence: 101 }], valid.expected).gatewayReady).toBe(false);
    expect(matchLiveProofLedger([...valid.events, { ...socket, sequence: 102 }], valid.expected).websocketOpen).toBe(false);
    expect(matchLiveProofLedger([...valid.events, { ...completion, sequence: 103 }], valid.expected).completion).toBe(false);
  });

  it('rejects wrong WebSocket route, missing ticket-only flag, and non-server-first readiness', () => {
    expect(matchLiveProofLedger(validProofEvents({ route: '/wrong' }).events, validProofEvents().expected).ordered).toBe(false);
    expect(matchLiveProofLedger(validProofEvents({ ticketOnly: false }).events, validProofEvents().expected).ordered).toBe(false);

    const nonServerFirst = [
      { sequence: 0, kind: 'ws.received', event: 'notice' },
      ...validProofEvents().events
    ];
    const valid = validProofEvents();
    expect(matchLiveProofLedger(nonServerFirst, valid.expected).serverFirstReady).toBe(false);
    expect(matchLiveProofLedger(nonServerFirst, valid.expected).ordered).toBe(false);
  });

  it('rejects a missing prompt acknowledgement', () => {
    const valid = validProofEvents();
    const withoutAcknowledgement = valid.events.filter(
      (event) => !(event.kind === 'ws.received' && event.event === 'response')
    );
    const proof = matchLiveProofLedger(withoutAcknowledgement, valid.expected);
    expect(proof.promptAcknowledgement).toBe(false);
    expect(proof.ordered).toBe(false);
  });

  it('requires an exact post-watermark pair and rejects stale-only history', () => {
    const ledger = createLiveProofLedger();
    const pre = matchLiveProofHistory(
      historyResponse('stored-1', [
        { id: 10, role: 'system', content: null },
        { id: 11, role: 'assistant', content: 'prior answer' }
      ]),
      {
        phase: 'pre-send',
        sessionId: 'stored-1',
        prompt: LIVE_PROOF_PROMPT,
        assistantMarker: LIVE_PROOF_ASSISTANT_MARKER,
        messageIdTagger: ledger.messageIdTag
      }
    );
    expect(pre.matched).toBe(true);
    expect(pre.watermark).toBe(11);

    const stale = matchLiveProofHistory(
      historyResponse('stored-1', [
        { id: 10, role: 'user', content: LIVE_PROOF_PROMPT },
        { id: 11, role: 'assistant', content: LIVE_PROOF_ASSISTANT_MARKER }
      ]),
      {
        phase: 'post-completion',
        sessionId: 'stored-1',
        prompt: LIVE_PROOF_PROMPT,
        assistantMarker: LIVE_PROOF_ASSISTANT_MARKER,
        messageIdTagger: ledger.messageIdTag,
        fence: pre.watermark,
        preHistoryIdTag: pre.historyIdTag
      }
    );
    expect(stale.prefixStable).toBe(true);
    expect(stale.postFenceMatched).toBe(false);
    expect(stale.matched).toBe(false);

    const post = matchLiveProofHistory(
      historyResponse('stored-1', proofMessages()),
      {
        phase: 'post-completion',
        sessionId: 'stored-1',
        prompt: LIVE_PROOF_PROMPT,
        assistantMarker: LIVE_PROOF_ASSISTANT_MARKER,
        messageIdTagger: ledger.messageIdTag,
        fence: pre.watermark,
        preHistoryIdTag: pre.historyIdTag
      }
    );
    expect(post).toMatchObject({
      historyComplete: true,
      prefixStable: true,
      postFenceMatched: true,
      promptMatches: true,
      assistantMarkerMatches: true,
      candidateUserCount: 1,
      candidateAssistantCount: 1,
      matched: true
    });
  });

  it('rejects prefix or suffix marker text, extra candidates, and session mismatch', () => {
    const ledger = createLiveProofLedger();
    const pre = matchLiveProofHistory(
      historyResponse('stored-1', [
        { id: 10, role: 'system', content: null },
        { id: 11, role: 'assistant', content: 'prior answer' }
      ]),
      {
        phase: 'pre-send',
        sessionId: 'stored-1',
        prompt: LIVE_PROOF_PROMPT,
        assistantMarker: LIVE_PROOF_ASSISTANT_MARKER,
        messageIdTagger: ledger.messageIdTag
      }
    );
    const baseExpected = {
      phase: 'post-completion' as const,
      sessionId: 'stored-1',
      prompt: LIVE_PROOF_PROMPT,
      assistantMarker: LIVE_PROOF_ASSISTANT_MARKER,
      messageIdTagger: ledger.messageIdTag,
      fence: pre.watermark,
      preHistoryIdTag: pre.historyIdTag
    };

    const suffix = matchLiveProofHistory(
      historyResponse('stored-1', [
        { id: 10, role: 'system', content: null },
        { id: 11, role: 'assistant', content: 'prior answer' },
        { id: 12, role: 'user', content: LIVE_PROOF_PROMPT },
        { id: 13, role: 'assistant', content: `${LIVE_PROOF_ASSISTANT_MARKER} extra` }
      ]),
      baseExpected
    );
    expect(suffix.matched).toBe(false);
    expect(suffix.assistantMarkerMatches).toBe(false);

    const extra = matchLiveProofHistory(
      historyResponse('stored-1', [
        ...proofMessages(),
        { id: 14, role: 'assistant', content: 'another answer' }
      ]),
      baseExpected
    );
    expect(extra.candidateAssistantCount).toBe(2);
    expect(extra.matched).toBe(false);

    const wrongSession = matchLiveProofHistory(
      historyResponse('wrong-session', proofMessages()),
      baseExpected
    );
    expect(wrongSession.sessionMatches).toBe(false);
    expect(wrongSession.matched).toBe(false);

    const prefixChanged = matchLiveProofHistory(
      historyResponse('stored-1', [
        { id: 10, role: 'system', content: null },
        { id: 12, role: 'assistant', content: 'replacement' },
        { id: 13, role: 'user', content: LIVE_PROOF_PROMPT },
        { id: 14, role: 'assistant', content: LIVE_PROOF_ASSISTANT_MARKER }
      ]),
      baseExpected
    );
    expect(prefixChanged.prefixStable).toBe(false);
    expect(prefixChanged.matched).toBe(false);
  });

  it('fails closed on duplicate IDs, incomplete pagination, and an unbounded page', () => {
    const ledger = createLiveProofLedger();
    const expected = {
      phase: 'pre-send' as const,
      sessionId: 'stored-1',
      prompt: LIVE_PROOF_PROMPT,
      assistantMarker: LIVE_PROOF_ASSISTANT_MARKER,
      messageIdTagger: ledger.messageIdTag
    };
    expect(() => matchLiveProofHistory(
      historyResponse('stored-1', [
        { id: 10, role: 'system', content: null },
        { id: 10, role: 'assistant', content: 'duplicate' }
      ]),
      expected
    )).toThrow('ordering');

    expect(matchLiveProofHistory(
      historyResponse('stored-1', [{ id: 10, role: 'system', content: null }], 499),
      expected
    ).historyComplete).toBe(false);

    const fullPage = Array.from({ length: LIVE_PROOF_HISTORY_LIMIT }, (_, index) => ({
      id: index + 1,
      role: 'system',
      content: null
    }));
    expect(matchLiveProofHistory(historyResponse('stored-1', fullPage), expected).matched).toBe(false);
  });
});
