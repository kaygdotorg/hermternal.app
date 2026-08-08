import { describe, expect, it } from 'vitest';
import {
  LIVE_PROOF_ASSISTANT_MARKER,
  LIVE_PROOF_PROMPT,
  assertLiveProofHappensBefore,
  createLiveProofLedger,
  matchLiveProofHistory,
  matchLiveProofLedger
} from '../../tests/live/live-proof-ledger.mjs';

function validProofEvents(options: { route?: string; ticketOnly?: boolean } = {}) {
  const ledger = createLiveProofLedger();
  ledger.recordWebSocketOpen({
    route: options.route ?? '/api/ws',
    ticketOnly: options.ticketOnly ?? true
  });
  ledger.recordWebSocketReceived({ event: 'gateway.ready', sessionId: 'ephemeral-1' });
  ledger.recordGatewayReady({ sessionId: 'ephemeral-1' });
  ledger.recordSessionAction({
    method: 'session.create',
    requestId: 'create-1',
    sessionId: 'ephemeral-1',
    storedSessionId: 'stored-1'
  });
  ledger.recordPrompt({ requestId: 'prompt-1', sessionId: 'ephemeral-1', promptMatches: true });
  ledger.recordWebSocketReceived({ event: 'response', requestId: 'prompt-1' });
  ledger.recordDelta({ requestId: 'prompt-1', sessionId: 'ephemeral-1' });
  ledger.recordCompletion({
    requestId: 'prompt-1',
    sessionId: 'ephemeral-1',
    status: 'ok',
    markerMatches: true
  });
  ledger.recordHistoryResponse({
    status: 200,
    sessionId: 'stored-1',
    promptMatches: true,
    assistantMarkerMatches: true,
    messageCount: 2
  });
  return ledger.snapshot();
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

  it('matches the exact ordered session, prompt, completion, and history chain', () => {
    const ledger = createLiveProofLedger();
    ledger.recordHttpRequest({ method: 'GET', route: 'auth.me' });
    ledger.recordHttpResponse({ method: 'GET', route: 'auth.me', status: 200 });
    ledger.recordWebSocketOpen({ route: '/api/ws', ticketOnly: true });
    ledger.recordWebSocketReceived({ event: 'gateway.ready', sessionId: 'ephemeral-1' });
    ledger.recordGatewayReady({ sessionId: 'ephemeral-1' });
    ledger.recordSessionAction({
      method: 'session.create',
      requestId: 'create-1',
      sessionId: 'ephemeral-1',
      storedSessionId: 'stored-1'
    });
    ledger.recordPrompt({ requestId: 'prompt-1', sessionId: 'ephemeral-1', promptMatches: true });
    ledger.recordWebSocketReceived({ event: 'response', requestId: 'prompt-1' });
    ledger.recordDelta({ requestId: 'prompt-1', sessionId: 'ephemeral-1' });
    ledger.recordCompletion({
      requestId: 'prompt-1',
      sessionId: 'ephemeral-1',
      status: 'ok',
      markerMatches: true
    });
    ledger.recordHistoryResponse({
      status: 200,
      sessionId: 'stored-1',
      promptMatches: true,
      assistantMarkerMatches: true,
      messageCount: 2
    });

    const events = ledger.snapshot();
    expect(matchLiveProofLedger(events, {
      sessionId: 'stored-1',
      promptRequestId: 'prompt-1',
      promptSessionId: 'ephemeral-1'
    })).toEqual({
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
      messageCount: 2,
      promptCount: 1,
      completionCount: 1
    });
    expect(assertLiveProofHappensBefore(events, 'gateway.ready', 'prompt.submit')).toBe(true);
  });

  it('rejects mismatched identity or re-ordered completion evidence', () => {
    const ledger = createLiveProofLedger();
    ledger.recordGatewayReady();
    ledger.recordCompletion({
      requestId: 'prompt-1',
      sessionId: 'wrong-session',
      status: 'ok',
      markerMatches: true
    });
    ledger.recordPrompt({ requestId: 'prompt-1', sessionId: 'ephemeral-1', promptMatches: true });
    ledger.recordHistoryResponse({
      status: 200,
      sessionId: 'stored-1',
      promptMatches: true,
      assistantMarkerMatches: true,
      messageCount: 2
    });
    expect(matchLiveProofLedger(ledger.snapshot(), {
      sessionId: 'stored-1',
      promptRequestId: 'prompt-1',
      promptSessionId: 'ephemeral-1'
    }).ordered).toBe(false);
    expect(() => assertLiveProofHappensBefore(ledger.snapshot(), 'prompt.submit', 'message.complete')).toThrow(
      'ordering assertion failed'
    );
  });

  it('rejects completion before delta or prompt acknowledgement', () => {
    const valid = validProofEvents();
    const acknowledgement = valid.find(
      (event) => event.kind === 'ws.received' && event.event === 'response'
    );
    const delta = valid.find((event) => event.kind === 'message.delta');
    const completion = valid.find((event) => event.kind === 'message.complete');
    expect(acknowledgement && delta && completion).toBeTruthy();

    const completionBeforeDelta = valid.map((event) => {
      if (event === completion) return { ...event, sequence: Number(delta?.sequence) - 1 };
      return event;
    });
    expect(matchLiveProofLedger(completionBeforeDelta, { sessionId: 'stored-1' }).ordered).toBe(false);

    const completionBeforeAcknowledgement = valid.map((event) => {
      if (event === completion) return { ...event, sequence: Number(acknowledgement?.sequence) - 1 };
      return event;
    });
    expect(matchLiveProofLedger(completionBeforeAcknowledgement, { sessionId: 'stored-1' }).ordered).toBe(false);
  });

  it('rejects request-ID-free completion, wrong status, and missing canonical history identity', () => {
    const requestlessCompletion = validProofEvents().map((event) =>
      event.kind === 'message.complete' ? { ...event, requestId: undefined } : event
    );
    expect(matchLiveProofLedger(requestlessCompletion, { sessionId: 'stored-1' }).completion).toBe(false);

    const wrongStatus = validProofEvents().map((event) =>
      event.kind === 'message.complete' ? { ...event, status: 'error' } : event
    );
    expect(matchLiveProofLedger(wrongStatus, { sessionId: 'stored-1' }).completion).toBe(false);

    const missingCanonicalHistory = validProofEvents().map((event) =>
      event.kind === 'history.response' ? { ...event, sessionId: undefined } : event
    );
    expect(matchLiveProofLedger(missingCanonicalHistory, { sessionId: 'stored-1' }).history).toBe(false);
  });

  it('rejects duplicate prompts, gateway readiness, sockets, and completions', () => {
    const valid = validProofEvents();
    const prompt = valid.find((event) => event.kind === 'prompt.submit');
    const ready = valid.find((event) => event.kind === 'gateway.ready');
    const socket = valid.find((event) => event.kind === 'ws.open');
    const completion = valid.find((event) => event.kind === 'message.complete');
    expect(prompt && ready && socket && completion).toBeTruthy();

    expect(matchLiveProofLedger([...valid, { ...prompt, sequence: 100 }], { sessionId: 'stored-1' }).prompt).toBe(false);
    expect(matchLiveProofLedger([...valid, { ...ready, sequence: 101 }], { sessionId: 'stored-1' }).gatewayReady).toBe(false);
    expect(matchLiveProofLedger([...valid, { ...socket, sequence: 102 }], { sessionId: 'stored-1' }).websocketOpen).toBe(false);
    expect(matchLiveProofLedger([...valid, { ...completion, sequence: 103 }], { sessionId: 'stored-1' }).completion).toBe(false);
  });

  it('rejects wrong WebSocket route, missing ticket-only flag, and non-server-first readiness', () => {
    expect(matchLiveProofLedger(validProofEvents({ route: '/wrong' }), { sessionId: 'stored-1' }).ordered).toBe(false);
    expect(matchLiveProofLedger(validProofEvents({ ticketOnly: false }), { sessionId: 'stored-1' }).ordered).toBe(false);

    const nonServerFirst = [
      { sequence: 0, kind: 'ws.received', event: 'notice' },
      ...validProofEvents()
    ];
    expect(matchLiveProofLedger(nonServerFirst, { sessionId: 'stored-1' }).serverFirstReady).toBe(false);
    expect(matchLiveProofLedger(nonServerFirst, { sessionId: 'stored-1' }).ordered).toBe(false);
  });

  it('rejects a missing prompt acknowledgement', () => {
    const withoutAcknowledgement = validProofEvents().filter(
      (event) => !(event.kind === 'ws.received' && event.event === 'response')
    );
    const proof = matchLiveProofLedger(withoutAcknowledgement, { sessionId: 'stored-1' });
    expect(proof.promptAcknowledgement).toBe(false);
    expect(proof.ordered).toBe(false);
  });

  it('matches only the exact canonical session and user/assistant pair', () => {
    expect(matchLiveProofHistory({
      session_id: 'stored-1',
      messages: [
        { role: 'user', content: LIVE_PROOF_PROMPT },
        { role: 'assistant', content: `prefix ${LIVE_PROOF_ASSISTANT_MARKER}` }
      ]
    }, {
      sessionId: 'stored-1',
      prompt: LIVE_PROOF_PROMPT,
      assistantMarker: LIVE_PROOF_ASSISTANT_MARKER
    })).toEqual({
      sessionMatches: true,
      promptMatches: true,
      assistantMarkerMatches: true,
      messageCount: 2,
      matched: true
    });

    expect(matchLiveProofHistory({
      session_id: 'wrong-session',
      messages: [
        { role: 'user', content: LIVE_PROOF_PROMPT },
        { role: 'assistant', content: LIVE_PROOF_ASSISTANT_MARKER }
      ]
    }, {
      sessionId: 'stored-1',
      prompt: LIVE_PROOF_PROMPT,
      assistantMarker: LIVE_PROOF_ASSISTANT_MARKER
    }).matched).toBe(false);
  });
});
