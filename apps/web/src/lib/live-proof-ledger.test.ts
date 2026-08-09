import { describe, expect, it } from 'vitest';
import {
  LIVE_PROOF_ASSISTANT_MARKER,
  LIVE_PROOF_HISTORY_LIMIT,
  LIVE_PROOF_PROMPT,
  assertLiveProofHappensBefore,
  assertLiveProofLedgerCaptureReady,
  createLiveProofLedger,
  createLiveProofTestSigner,
  matchLiveProofHistory,
  matchLiveProofLedger
} from '../../tests/live/live-proof-ledger.mjs';

function createTestLedger(maxEvents?: number) {
  return createLiveProofLedger(maxEvents, {
    signer: createLiveProofTestSigner(),
    allowTestSigner: true
  });
}

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
  messages: Array<Record<string, unknown>>,
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
    messageCount: messages.length,
    historyProjectionTag: ledger.messageProjectionTag(messages),
    prefixProjectionTag: ledger.messageProjectionTag(
      phase === 'pre-send' ? messages : messages.slice(0, 2)
    ),
    ...overrides
  };
}

function validProofEvents(options: { route?: string; ticketOnly?: boolean } = {}) {
  const ledger = createTestLedger();
  const preMessages = proofMessages([10, 11]);
  const postMessages = proofMessages();
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
  ledger.recordHistoryResponse(historyEvent(ledger, 'pre-send', preMessages));
  ledger.recordPrompt({ requestId: 'prompt-1', sessionId: 'ephemeral-1', promptMatches: true });
  ledger.recordWebSocketReceived({ event: 'response', requestId: 'prompt-1' });
  ledger.recordDelta({ sessionId: 'ephemeral-1' });
  ledger.recordCompletion({
    sessionId: 'ephemeral-1',
    status: 'complete',
    markerMatches: true
  });
  ledger.recordHistoryResponse(historyEvent(ledger, 'post-completion', postMessages));
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
  it('requires an explicit page signer and keeps test signing opt-in', () => {
    expect(() => createLiveProofLedger()).toThrow('page-local signer');
    expect(() => createLiveProofLedger(256, { signer: createLiveProofTestSigner() })).toThrow(
      'explicit test opt-in'
    );
    expect(() => createTestLedger().recordPrompt({
      requestId: 'raw-request',
      sessionId: 'raw-session',
      promptMatches: true
    })).not.toThrow();
    const production = createLiveProofLedger(256, { signer: { kind: 'page' } });
    expect(() => production.recordPrompt({
      requestId: 'raw-request',
      sessionId: 'raw-session',
      promptMatches: true
    })).toThrow('raw dynamic identity');
    const pageTag = createTestLedger().identityTag('page-session');
    expect(() => production.recordPrompt({
      requestTag: pageTag,
      sessionTag: pageTag,
      promptMatches: true
    })).not.toThrow();
    expect(() => production.identityTag('page-session')).toThrow('page realm');
    expect(() => production.messageProjectionTag([])).toThrow('page realm');
    expect(() => createLiveProofLedger(256, {
      signer: { kind: 'test', sign: () => undefined as unknown as string },
      allowTestSigner: true
    }).identityTag('raw-request')).toThrow('identity tag');
  });

  it('rejects hostile optional descriptors, wrappers, proxies, and fractional timestamps', () => {
    const ledger = createTestLedger();
    const accessor = {
      id: 1,
      role: 'assistant',
      content: 'answer',
      toolCalls: { present: true, value: null }
    };
    Object.defineProperty(accessor.toolCalls, 'present', {
      configurable: true,
      enumerable: true,
      get: () => true
    });
    expect(() => ledger.messageProjectionTag([accessor])).toThrow('descriptor');

    const extra = {
      id: 1,
      role: 'assistant',
      content: 'answer',
      toolCalls: { present: false, value: null }
    };
    expect(() => ledger.messageProjectionTag([extra])).toThrow('projection is malformed');

    const fallback = {
      id: 1,
      role: 'assistant',
      content: 'answer',
      toolCalls: { present: 'yes' },
      tool_calls: null
    };
    expect(() => ledger.messageProjectionTag([fallback])).toThrow();

    const hostileProxy = new Proxy(
      { id: 1, role: 'assistant', content: 'answer' },
      {
        getOwnPropertyDescriptor(target, key) {
          if (key === 'content') {
            return {
              configurable: true,
              enumerable: true,
              get: () => 'answer'
            };
          }
          return Object.getOwnPropertyDescriptor(target, key);
        }
      }
    );
    expect(() => ledger.messageProjectionTag([hostileProxy])).toThrow('descriptor');

    let ownKeysCalls = 0;
    const unstableArray = new Proxy(
      [{ id: 1, role: 'assistant', content: 'answer' }],
      {
        ownKeys(target) {
          ownKeysCalls += 1;
          const keys = Reflect.ownKeys(target);
          return ownKeysCalls === 1 ? keys : [...keys, 'extra'];
        }
      }
    );
    expect(() => ledger.messageProjectionTag(unstableArray)).toThrow('unstable shape');

    let addedExtra = false;
    const lateExtraProxy = new Proxy(
      { id: 1, role: 'assistant', content: 'answer' },
      {
        getOwnPropertyDescriptor(target, key) {
          if (!addedExtra && key === 'content') {
            addedExtra = true;
            Object.defineProperty(target, 'extra', {
              configurable: true,
              enumerable: true,
              writable: true,
              value: true
            });
          }
          return Object.getOwnPropertyDescriptor(target, key);
        }
      }
    );
    expect(() => ledger.messageProjectionTag([lateExtraProxy])).toThrow('unstable or symbol keys');

    expect(() => ledger.messageProjectionTag([
      { id: 1, role: 'assistant', content: 'answer', timestamp: 1.5 }
    ])).toThrow('timestamp');
    expect(() => ledger.messageProjectionTag([
      { id: 1, role: 'assistant', content: 'answer', timestamp: Number.NaN }
    ])).toThrow('timestamp');
    expect(() => ledger.messageProjectionTag([
      { id: 1, role: 'assistant', content: 'answer', timestamp: 4_294_967_296 }
    ])).toThrow('timestamp');
  });

  it('keeps a bounded typed sequence and refuses overflow', () => {
    const ledger = createTestLedger(16);
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

  it('binds every reviewed row field and optional presence state in the tag', () => {
    const ledger = createTestLedger();
    const base = {
      id: 1,
      role: 'tool',
      content: 'tool output',
      tool_calls: [{ id: 'call-1', function: { name: 'lookup', arguments: '{}' } }],
      tool_name: 'lookup',
      tool_call_id: 'call-1',
      timestamp: 1_700_000_000
    };
    const tag = (row: Record<string, unknown>) => ledger.messageProjectionTag([row]);
    expect(() => tag({ id: 1, role: 'assistant', content: '' })).not.toThrow();
    expect(() => tag({
      id: 1,
      role: 'tool',
      content: '',
      tool_calls: [{ id: '', function: { name: '', arguments: '' } }],
      tool_name: '',
      tool_call_id: ''
    })).not.toThrow();
    expect(tag(base)).not.toBe(tag({ ...base, id: 2 }));
    expect(tag(base)).not.toBe(tag({ ...base, role: 'assistant' }));
    expect(tag(base)).not.toBe(tag({ ...base, content: 'changed' }));
    expect(tag(base)).not.toBe(tag({ ...base, tool_calls: null }));
    expect(tag(base)).not.toBe(tag({
      ...base,
      tool_calls: [{ id: 'call-1', function: { name: 'lookup', arguments: 'changed' } }]
    }));
    expect(tag(base)).not.toBe(tag({ ...base, tool_name: 'other' }));
    expect(tag(base)).not.toBe(tag({ ...base, tool_call_id: 'other' }));
    expect(tag(base)).not.toBe(tag({ ...base, timestamp: 1_700_000_001 }));
    expect(() => tag({ ...base, content: 'x'.repeat(8_193) })).toThrow('content');
    expect(() => tag({ ...base, tool_name: 'x'.repeat(513) })).toThrow('tool name');
    expect(() => tag({ ...base, tool_name: undefined })).toThrow('tool name');
    const explicitNull = {
      id: 1,
      role: 'tool',
      content: 'tool output',
      tool_calls: null,
      tool_name: null,
      tool_call_id: null,
      timestamp: 1_700_000_000
    };
    expect(tag(explicitNull)).not.toBe(tag({
      id: 1,
      role: 'tool',
      content: 'tool output',
      timestamp: 1_700_000_000
    }));
    expect(tag(explicitNull)).toBe(tag({
      id: 1,
      role: 'tool',
      content: 'tool output',
      toolCalls: { present: true, value: null },
      toolName: { present: true, value: null },
      toolCallId: { present: true, value: null },
      timestamp: 1_700_000_000
    }));
  });

  it('canonicalizes dynamic session routes before retaining HTTP events', () => {
    const ledger = createTestLedger();
    const rawSessionId = 'raw-session-id-must-not-survive';
    ledger.recordHttpRequest({
      method: 'GET',
      route: `/api/sessions/${rawSessionId}/messages?limit=500&offset=0`
    });
    ledger.recordHttpResponse({
      method: 'GET',
      route: `/api/sessions/${rawSessionId}/messages?limit=500&offset=0`,
      status: 200
    });
    const serialized = JSON.stringify(ledger.snapshot());
    expect(serialized).not.toContain(rawSessionId);
    expect(ledger.snapshot()).toMatchObject([
      { kind: 'http.request', route: '/api/sessions/:sessionId/messages' },
      { kind: 'http.response', route: '/api/sessions/:sessionId/messages' }
    ]);
  });

  it('binds prefix stability to the full reviewed message projection', () => {
    const ledger = createTestLedger();
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
        messageProjectionTagger: ledger.messageProjectionTag
      }
    );

    const sameIdRoleAndContentChanged = matchLiveProofHistory(
      historyResponse('stored-1', [
        { id: 10, role: 'assistant', content: 'replacement' },
        { id: 11, role: 'assistant', content: 'prior answer' },
        { id: 12, role: 'user', content: LIVE_PROOF_PROMPT },
        { id: 13, role: 'assistant', content: LIVE_PROOF_ASSISTANT_MARKER }
      ]),
      {
        phase: 'post-completion',
        sessionId: 'stored-1',
        prompt: LIVE_PROOF_PROMPT,
        assistantMarker: LIVE_PROOF_ASSISTANT_MARKER,
        messageProjectionTagger: ledger.messageProjectionTag,
        fence: pre.watermark,
        preHistoryProjectionTag: pre.historyProjectionTag
      }
    );
    expect(sameIdRoleAndContentChanged.prefixStable).toBe(false);
    expect(sameIdRoleAndContentChanged.matched).toBe(false);

    const reviewedOptionalFieldChanged = matchLiveProofHistory(
      historyResponse('stored-1', [
        { id: 10, role: 'system', content: null },
        { id: 11, role: 'assistant', content: 'prior answer', tool_name: 'changed-tool' },
        { id: 12, role: 'user', content: LIVE_PROOF_PROMPT },
        { id: 13, role: 'assistant', content: LIVE_PROOF_ASSISTANT_MARKER }
      ]),
      {
        phase: 'post-completion',
        sessionId: 'stored-1',
        prompt: LIVE_PROOF_PROMPT,
        assistantMarker: LIVE_PROOF_ASSISTANT_MARKER,
        messageProjectionTagger: ledger.messageProjectionTag,
        fence: pre.watermark,
        preHistoryProjectionTag: pre.historyProjectionTag
      }
    );
    expect(reviewedOptionalFieldChanged.prefixStable).toBe(false);
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
    const ledger = createTestLedger();
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
        messageProjectionTagger: ledger.messageProjectionTag
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
        messageProjectionTagger: ledger.messageProjectionTag,
        fence: pre.watermark,
        preHistoryProjectionTag: pre.historyProjectionTag
      }
    );
    expect(stale.prefixStable).toBe(false);
    expect(stale.postFenceMatched).toBe(false);
    expect(stale.matched).toBe(false);

    const post = matchLiveProofHistory(
      historyResponse('stored-1', proofMessages()),
      {
        phase: 'post-completion',
        sessionId: 'stored-1',
        prompt: LIVE_PROOF_PROMPT,
        assistantMarker: LIVE_PROOF_ASSISTANT_MARKER,
        messageProjectionTagger: ledger.messageProjectionTag,
        fence: pre.watermark,
        preHistoryProjectionTag: pre.historyProjectionTag
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
    const ledger = createTestLedger();
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
        messageProjectionTagger: ledger.messageProjectionTag
      }
    );
    const baseExpected = {
      phase: 'post-completion' as const,
      sessionId: 'stored-1',
      prompt: LIVE_PROOF_PROMPT,
      assistantMarker: LIVE_PROOF_ASSISTANT_MARKER,
      messageProjectionTagger: ledger.messageProjectionTag,
      fence: pre.watermark,
      preHistoryProjectionTag: pre.historyProjectionTag
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
    const ledger = createTestLedger();
    const expected = {
      phase: 'pre-send' as const,
      sessionId: 'stored-1',
      prompt: LIVE_PROOF_PROMPT,
      assistantMarker: LIVE_PROOF_ASSISTANT_MARKER,
      messageProjectionTagger: ledger.messageProjectionTag
    };
    expect(() => matchLiveProofHistory(
      historyResponse('x'.repeat(257), []),
      expected
    )).toThrow('session identity');
    expect(() => matchLiveProofHistory(
      historyResponse('stored-1', []),
      { ...expected, sessionId: 'x'.repeat(257) }
    )).toThrow('matcher input');
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
