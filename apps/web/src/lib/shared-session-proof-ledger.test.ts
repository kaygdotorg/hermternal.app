import { describe, expect, it } from 'vitest';
import {
  SHARED_SESSION_FIRST_ASSISTANT_MARKER,
  SHARED_SESSION_FIRST_PROMPT,
  SHARED_SESSION_SECOND_ASSISTANT_MARKER,
  SHARED_SESSION_SECOND_PROMPT,
  createSharedSessionProofLedger,
  matchSharedSessionHistory,
  matchSharedSessionProofLedger
} from '../../tests/live/shared-session-proof-ledger.mjs';

function validSharedProofEvents() {
  const ledger = createSharedSessionProofLedger();
  ledger.recordHttpRequest({ method: 'POST', route: '/auth/password-login' });
  ledger.recordHttpResponse({ method: 'POST', route: '/auth/password-login', status: 302 });
  ledger.recordHttpRequest({ method: 'GET', route: '/api/auth/me' });
  ledger.recordHttpResponse({ method: 'GET', route: '/api/auth/me', status: 200 });
  ledger.recordAuthenticatedIdentity({ matches: true });
  ledger.recordHttpRequest({ method: 'POST', route: '/api/auth/ws-ticket' });
  ledger.recordHttpResponse({ method: 'POST', route: '/api/auth/ws-ticket', status: 200 });
  ledger.recordChatWebSocket({ route: '/api/ws', ticketOnly: true });
  ledger.recordGatewayReady({ serverFirst: true });
  ledger.recordSessionAction({ method: 'session.create' });
  ledger.recordSessionIdentity({ method: 'session.create', matches: true, promoted: true });
  ledger.recordPrompt({ phase: 'first', markerMatches: true, sessionMatches: true });
  ledger.recordPromptAcknowledgement({ phase: 'first', requestMatches: true });
  ledger.recordDelta({ phase: 'first', requestMatches: true, sessionMatches: true });
  ledger.recordCompletion({
    phase: 'first',
    status: 'ok',
    requestMatches: true,
    sessionMatches: true,
    markerMatches: true
  });
  ledger.recordHistory({
    phase: 'first',
    status: 200,
    sessionMatches: true,
    firstPromptMatches: true,
    firstAssistantMarkerMatches: true,
    secondPromptMatches: false,
    secondAssistantMarkerMatches: false,
    messageCount: 2
  });
  ledger.recordModeTransition({ event: 'chat-to-terminal' });
  ledger.recordPtyUpgrade({
    route: '/api/pty',
    queryKeyCount: 2,
    ticketPresent: true,
    resumePresent: true,
    attachPresent: false,
    ticketLength: 48,
    resumeLength: 32,
    attachLength: 0,
    resumeMatches: true,
    legacyMode: true
  });
  ledger.recordModeTransition({ event: 'terminal-to-chat' });
  ledger.recordPrompt({ phase: 'second', markerMatches: true, sessionMatches: true });
  ledger.recordPromptAcknowledgement({ phase: 'second', requestMatches: true });
  ledger.recordDelta({ phase: 'second', requestMatches: true, sessionMatches: true });
  ledger.recordCompletion({
    phase: 'second',
    status: 'ok',
    requestMatches: true,
    sessionMatches: true,
    markerMatches: true
  });
  ledger.recordHistory({
    phase: 'second',
    status: 200,
    sessionMatches: true,
    firstPromptMatches: true,
    firstAssistantMarkerMatches: true,
    secondPromptMatches: true,
    secondAssistantMarkerMatches: true,
    messageCount: 4
  });
  return ledger;
}

describe('bounded shared-session proof ledger', () => {
  it('matches the fixed Chat–Terminal–Chat chain without retaining identities or content', () => {
    const ledger = validSharedProofEvents();
    const proof = matchSharedSessionProofLedger(ledger.snapshot());

    expect(proof).toMatchObject({
      ordered: true,
      login: true,
      authenticated: true,
      ticket: true,
      chatWebSocketOpen: true,
      chatWebSocketCount: 1,
      chatWebSocketCloseCount: 0,
      chatWebSocketClosed: false,
      gatewayReady: true,
      sessionAction: true,
      freshSessionPromotion: true,
      resumeAuthoritativeIdentity: true,
      sessionCreateCount: 1,
      sessionResumeCount: 0,
      noSecondSessionCreate: true,
      firstPrompt: true,
      secondPrompt: true,
      secondPromptSameOwner: true,
      promptCount: 2,
      firstPromptAcknowledgement: true,
      secondPromptAcknowledgement: true,
      firstDelta: true,
      secondDelta: true,
      firstCompletion: true,
      secondCompletion: true,
      completionCount: 2,
      firstHistory: true,
      finalHistory: true,
      historyPairCount: 2,
      modeChatToTerminal: true,
      modeTerminalToChat: true,
      ptyUpgrade: true,
      ptyUpgradeCount: 1,
      ptyQueryExact: true,
      ptyTicketPresent: true,
      ptyResumePresent: true,
      ptyResumeMatches: true,
      ptyAttachAbsent: true,
      legacyMode: true,
      noSecondChatTransport: true,
      noSecondPtyUpgrade: true,
      finalHistoryMessageCount: 4,
      logout: false
    });
    const serialized = JSON.stringify(proof);
    expect(serialized).not.toContain('session-');
    expect(serialized).not.toContain(SHARED_SESSION_FIRST_PROMPT);
    expect(serialized).not.toContain(SHARED_SESSION_FIRST_ASSISTANT_MARKER);
    expect(serialized).not.toContain(SHARED_SESSION_SECOND_PROMPT);
    expect(serialized).not.toContain(SHARED_SESSION_SECOND_ASSISTANT_MARKER);
  });

  it('rejects duplicate transports and a PTY attach projection', () => {
    const ledger = validSharedProofEvents();
    ledger.recordChatWebSocket({ route: '/api/ws', ticketOnly: true });
    expect(matchSharedSessionProofLedger(ledger.snapshot()).noSecondChatTransport).toBe(false);
    expect(matchSharedSessionProofLedger(ledger.snapshot()).ordered).toBe(false);

    const ptyAttachLedger = validSharedProofEvents();
    const pty = ptyAttachLedger.snapshot().find((event) => event.kind === 'pty.upgrade');
    expect(pty).toBeDefined();
    const projection = pty ? { ...pty, attachPresent: true, attachLength: 12 } : undefined;
    const withoutPty = ptyAttachLedger.snapshot().filter((event) => event !== pty);
    expect(matchSharedSessionProofLedger([...withoutPty, projection!]).ptyAttachAbsent).toBe(false);
  });

  it('rejects duplicate qualifying history captures for one phase', () => {
    const ledger = validSharedProofEvents();
    const firstHistory = ledger.snapshot().find((event) => event.kind === 'history.response' && event.phase === 'first');
    expect(firstHistory).toBeDefined();
    const duplicate = firstHistory ? { ...firstHistory, sequence: firstHistory.sequence + 100 } : undefined;
    const proof = matchSharedSessionProofLedger([...ledger.snapshot(), duplicate!]);
    expect(proof.historyPairCount).toBe(3);
    expect(proof.firstHistory).toBe(false);
    expect(proof.ordered).toBe(false);
  });

  it('accepts omitted wire IDs when active-prompt correlation is retained as booleans', () => {
    const events = validSharedProofEvents().snapshot().map((event) =>
      event.kind === 'message.delta' || event.kind === 'message.complete'
        ? { ...event, requestIdPresent: false, sessionIdPresent: false }
        : event
    );
    const proof = matchSharedSessionProofLedger(events);
    expect(proof.firstDelta).toBe(true);
    expect(proof.secondDelta).toBe(true);
    expect(proof.firstCompletion).toBe(true);
    expect(proof.secondCompletion).toBe(true);
    expect(JSON.stringify(proof)).not.toContain('requestIdPresent');
    expect(JSON.stringify(proof)).not.toContain('sessionIdPresent');
  });

  it('requires authoritative resume identity and fresh-session promotion evidence', () => {
    const resumed = validSharedProofEvents().snapshot().map((event) => {
      if (event.kind === 'session.action') return { ...event, method: 'session.resume' };
      if (event.kind === 'session.identity') return { ...event, method: 'session.resume', promoted: false };
      return event;
    });
    expect(matchSharedSessionProofLedger(resumed).resumeAuthoritativeIdentity).toBe(true);
    const mismatched = resumed.map((event) =>
      event.kind === 'session.identity' ? { ...event, matches: false } : event
    );
    expect(matchSharedSessionProofLedger(mismatched).resumeAuthoritativeIdentity).toBe(false);
    expect(matchSharedSessionProofLedger(mismatched).sessionAction).toBe(false);
  });

  it('matches first history as a pair and final history as both pairs without returning bodies', () => {
    const first = matchSharedSessionHistory({
      session_id: 'stored-session',
      messages: [
        { role: 'user', content: SHARED_SESSION_FIRST_PROMPT },
        { role: 'assistant', content: `prefix ${SHARED_SESSION_FIRST_ASSISTANT_MARKER}` }
      ]
    }, {
      sessionId: 'stored-session',
      firstPrompt: SHARED_SESSION_FIRST_PROMPT,
      firstAssistantMarker: SHARED_SESSION_FIRST_ASSISTANT_MARKER,
      secondPrompt: SHARED_SESSION_SECOND_PROMPT,
      secondAssistantMarker: SHARED_SESSION_SECOND_ASSISTANT_MARKER
    });
    expect(first).toEqual({
      sessionMatches: true,
      firstPromptMatches: true,
      firstAssistantMarkerMatches: true,
      secondPromptMatches: false,
      secondAssistantMarkerMatches: false,
      messageCount: 2,
      matched: false
    });
    expect(JSON.stringify(first)).not.toContain('stored-session');
    expect(JSON.stringify(first)).not.toContain(SHARED_SESSION_FIRST_PROMPT);

    const final = matchSharedSessionHistory({
      session_id: 'stored-session',
      messages: [
        { role: 'user', content: SHARED_SESSION_FIRST_PROMPT },
        { role: 'assistant', content: SHARED_SESSION_FIRST_ASSISTANT_MARKER },
        { role: 'user', content: SHARED_SESSION_SECOND_PROMPT },
        { role: 'assistant', content: SHARED_SESSION_SECOND_ASSISTANT_MARKER }
      ]
    }, {
      sessionId: 'stored-session',
      firstPrompt: SHARED_SESSION_FIRST_PROMPT,
      firstAssistantMarker: SHARED_SESSION_FIRST_ASSISTANT_MARKER,
      secondPrompt: SHARED_SESSION_SECOND_PROMPT,
      secondAssistantMarker: SHARED_SESSION_SECOND_ASSISTANT_MARKER
    });
    expect(final.matched).toBe(true);
    expect(final.messageCount).toBe(4);
  });

  it('bounds capacity and lengths before adding any projection', () => {
    expect(() => createSharedSessionProofLedger(31)).toThrow('capacity');
    const ledger = createSharedSessionProofLedger(32);
    for (let index = 0; index < 32; index += 1) {
      ledger.recordHttpRequest({ method: 'GET', route: '/api/auth/me' });
    }
    expect(ledger.snapshot()).toHaveLength(32);
    expect(() => ledger.recordHttpRequest({ method: 'GET', route: '/api/auth/me' })).toThrow('capacity');
    expect(() => ledger.recordPtyUpgrade({
      route: '/api/pty',
      queryKeyCount: 2,
      ticketPresent: true,
      resumePresent: true,
      attachPresent: false,
      ticketLength: 513,
      resumeLength: 32,
      attachLength: 0,
      resumeMatches: true,
      legacyMode: true
    })).toThrow('bounded');
  });
});
