import { describe, expect, it } from 'vitest';
import {
  createLiveRestTransport,
  LiveRestError,
  normalizeApiBaseUrl,
  validateSessionId
} from './live-rest-transport';
import {
  LIVE_AUTH_IDENTITY_FIXTURE,
  LIVE_PROVIDER_DISCOVERY_FIXTURE,
  LIVE_REST_FIXTURE_IDS,
  LIVE_SESSION_FIXTURE,
  LIVE_SESSION_LIST_FIXTURE,
  LIVE_SESSION_MESSAGES_FIXTURE
} from './live-rest-fixtures';
import { parseStrictJson, StrictJsonError } from './strict-json';

type FetchCall = {
  input: RequestInfo | URL;
  init: RequestInit | undefined;
};

function response(
  body: string | Uint8Array | null,
  status = 200,
  headers: Record<string, string> = { 'content-type': 'application/json' }
): Response {
  return new Response(body as unknown as BodyInit | null, { status, headers });
}

function nullBodyResponse(
  bytes: Uint8Array,
  headers: Record<string, string> = { 'content-type': 'application/json' }
): { response: Response; arrayBufferCalls: number } {
  const result = new Response(null, { status: 200, headers });
  let arrayBufferCalls = 0;
  Object.defineProperty(result, 'arrayBuffer', {
    configurable: true,
    value: async () => {
      arrayBufferCalls += 1;
      return Uint8Array.from(bytes).buffer;
    }
  });
  return {
    response: result,
    get arrayBufferCalls() {
      return arrayBufferCalls;
    }
  };
}

function fetchSequence(...responses: Response[]): { fetch: typeof fetch; calls: FetchCall[] } {
  const calls: FetchCall[] = [];
  let index = 0;
  return {
    calls,
    fetch: async (input, init) => {
      calls.push({ input, init });
      const next = responses[Math.min(index, responses.length - 1)];
      index += 1;
      if (!next) {
        throw new Error('missing synthetic response');
      }
      return next;
    }
  };
}

function rawProviderDiscovery(): string {
  return JSON.stringify({
    providers: [
      {
        name: LIVE_PROVIDER_DISCOVERY_FIXTURE.providers[0]?.name,
        display_name: LIVE_PROVIDER_DISCOVERY_FIXTURE.providers[0]?.displayName,
        supports_password: false
      }
    ]
  });
}

function rawAuthIdentity(): string {
  return JSON.stringify({
    user_id: LIVE_AUTH_IDENTITY_FIXTURE.userId,
    email: LIVE_AUTH_IDENTITY_FIXTURE.email,
    display_name: LIVE_AUTH_IDENTITY_FIXTURE.displayName,
    org_id: LIVE_AUTH_IDENTITY_FIXTURE.organizationId,
    provider: LIVE_AUTH_IDENTITY_FIXTURE.provider,
    expires_at: LIVE_AUTH_IDENTITY_FIXTURE.expiresAt
  });
}

function rawSession(session = LIVE_SESSION_FIXTURE): string {
  return JSON.stringify({
    id: session.id,
    title: session.title,
    preview: session.preview,
    source: session.source,
    model: session.model,
    started_at: session.startedAt,
    ended_at: session.endedAt,
    last_active: session.lastActive,
    parent_session_id: session.parentSessionId,
    message_count: session.messageCount,
    tool_call_count: session.toolCallCount,
    input_tokens: session.inputTokens,
    output_tokens: session.outputTokens,
    is_active: session.isActive,
    archived: session.archived,
    pinned: session.pinned,
    profile: session.profile,
    is_default_profile: session.isDefaultProfile
  });
}

function rawSessionList(): string {
  const value = JSON.parse(rawSessionListWithCount(1)) as Record<string, unknown>;
  value.limit = LIVE_SESSION_LIST_FIXTURE.limit;
  return JSON.stringify(value);
}

function rawSessionListWithCount(count: number): string {
  return JSON.stringify({
    sessions: Array.from({ length: count }, (_, index) =>
      JSON.parse(rawSession({
        ...LIVE_SESSION_FIXTURE,
        id: `synthetic-session-${String(index + 1).padStart(4, '0')}`
      }))
    ),
    total: count,
    limit: count,
    offset: 0
  });
}

function rawSessionMessages(sessionId = LIVE_SESSION_MESSAGES_FIXTURE.sessionId): string {
  return JSON.stringify({
    session_id: sessionId,
    messages: LIVE_SESSION_MESSAGES_FIXTURE.messages.map((message) => ({
      id: message.id,
      role: message.role,
      content: message.content
    })),
    pagination: {
      limit: LIVE_SESSION_MESSAGES_FIXTURE.pagination.limit,
      offset: LIVE_SESSION_MESSAGES_FIXTURE.pagination.offset,
      returned: LIVE_SESSION_MESSAGES_FIXTURE.pagination.returned
    }
  });
}

function rawSessionMessagesWithCount(sessionId: string, count: number, content = 'Synthetic message'): string {
  return JSON.stringify({
    session_id: sessionId,
    messages: Array.from({ length: count }, (_, index) => ({
      id: `synthetic-message-${String(index + 1).padStart(4, '0')}`,
      role: 'assistant',
      content
    })),
    pagination: {
      limit: count,
      offset: 0,
      returned: count
    }
  });
}

describe('strict JSON parser', () => {
  it('accepts bounded JSON whitespace and rejects duplicate keys', () => {
    expect(parseStrictJson(' \t{ "ok": true }\n')).toEqual({ ok: true });
    expect(() => parseStrictJson('{"ok":true,"ok":false}')).toThrow(StrictJsonError);
  });

  it('preserves escaped transcript newline, tab, and carriage return data', () => {
    expect(parseStrictJson('{"content":"line 1\\nline 2\\tindented\\rreset"}')).toEqual({
      content: 'line 1\nline 2\tindented\rreset'
    });
    expect(() => parseStrictJson('{"content":"line 1\nline 2"}')).toThrow(StrictJsonError);
  });

  it('rejects unsafe numbers, controls, excessive depth, and excessive nodes', () => {
    expect(() => parseStrictJson('{"value":9007199254740992}')).toThrow(StrictJsonError);
    expect(() => parseStrictJson('{"value":1e400}')).toThrow(StrictJsonError);
    expect(() => parseStrictJson('{"value":"\\u0000"}')).toThrow(StrictJsonError);
    expect(() => parseStrictJson('[[[[0]]]]', { maxDepth: 2 })).toThrow(StrictJsonError);
    expect(() => parseStrictJson('[0,1,2]', { maxNodes: 2 })).toThrow(StrictJsonError);
  });
});

describe('createLiveRestTransport', () => {
  it('reads provider discovery with same-origin cookie credentials only', async () => {
    const fixture = fetchSequence(response(rawProviderDiscovery()));
    const transport = createLiveRestTransport({ fetch: fixture.fetch });

    await expect(transport.getProviders()).resolves.toEqual(LIVE_PROVIDER_DISCOVERY_FIXTURE);

    const call = fixture.calls[0];
    expect(call.input).toBe('/api/auth/providers');
    expect(call.init).toMatchObject({
      method: 'GET',
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error'
    });
    expect(call.init?.headers).toEqual({ accept: 'application/json' });
    expect(call.init).not.toHaveProperty('body');
    expect(call.init).not.toHaveProperty('authorization');
  });

  it('reads auth state, session list, detail, and messages without a ticket route', async () => {
    const fixture = fetchSequence(
      response(rawAuthIdentity()),
      response(rawSessionList()),
      response(rawSession()),
      response(rawSessionMessages())
    );
    const transport = createLiveRestTransport({ fetch: fixture.fetch });

    await expect(transport.getAuthState()).resolves.toEqual(LIVE_AUTH_IDENTITY_FIXTURE);
    await expect(transport.listSessions({ limit: 50, offset: 0 })).resolves.toEqual(
      LIVE_SESSION_LIST_FIXTURE
    );
    await expect(transport.getSession(LIVE_SESSION_FIXTURE.id)).resolves.toEqual(LIVE_SESSION_FIXTURE);
    await expect(transport.getSessionMessages(LIVE_SESSION_FIXTURE.id)).resolves.toEqual(
      LIVE_SESSION_MESSAGES_FIXTURE
    );

    expect(fixture.calls.map((call) => String(call.input))).toEqual([
      '/api/auth/me',
      '/api/sessions?limit=50&offset=0',
      '/api/sessions/synthetic-session-0001',
      '/api/sessions/synthetic-session-0001/messages'
    ]);
    expect(fixture.calls.map((call) => String(call.input)).join('\n')).not.toContain('ws-ticket');
    expect(fixture.calls.map((call) => String(call.input)).join('\n')).not.toContain('search');
  });

  it('exposes the session list alias without adding a search route', async () => {
    const fixture = fetchSequence(response(rawSessionList()));
    const transport = createLiveRestTransport({ fetch: fixture.fetch });

    await expect(transport.getSessions()).resolves.toEqual(LIVE_SESSION_LIST_FIXTURE);
    expect(fixture.calls[0]?.input).toBe('/api/sessions');
  });

  it('accepts the advertised 100-session and 500-message route caps', async () => {
    const sessionFixture = fetchSequence(response(rawSessionListWithCount(100)));
    const sessionTransport = createLiveRestTransport({ fetch: sessionFixture.fetch });
    const sessions = await sessionTransport.listSessions({ limit: 100 });
    expect(sessions.sessions).toHaveLength(100);
    expect(sessions.sessions.at(-1)?.id).toBe('synthetic-session-0100');

    const messageFixture = fetchSequence(
      response(rawSessionMessagesWithCount(LIVE_SESSION_MESSAGES_FIXTURE.sessionId, 500))
    );
    const messageTransport = createLiveRestTransport({ fetch: messageFixture.fetch });
    const messages = await messageTransport.getSessionMessages(LIVE_SESSION_MESSAGES_FIXTURE.sessionId, {
      limit: 500
    });
    expect(messages.messages).toHaveLength(500);
    expect(messages.messages.at(-1)?.id).toBe('synthetic-message-0500');
    expect(messages.pagination.returned).toBe(500);
  });

  it('preserves escaped transcript whitespace through the typed message projection', async () => {
    const fixture = fetchSequence(
      response(
        rawSessionMessagesWithCount(
          LIVE_SESSION_MESSAGES_FIXTURE.sessionId,
          1,
          'line 1\nline 2\tindented\rreset'
        )
      )
    );
    const messages = await createLiveRestTransport({ fetch: fixture.fetch }).getSessionMessages(
      LIVE_SESSION_MESSAGES_FIXTURE.sessionId
    );
    expect(messages.messages[0]?.content).toBe('line 1\nline 2\tindented\rreset');
  });

  it('ignores bounded additive fields across providers, auth, sessions, and messages', async () => {
    const provider = JSON.parse(rawProviderDiscovery()) as {
      providers: Array<Record<string, unknown>>;
      [key: string]: unknown;
    };
    provider.future_provider_field = { enabled: true };
    provider.providers[0].future_provider_field = ['ignored'];

    const auth = JSON.parse(rawAuthIdentity()) as Record<string, unknown>;
    auth.future_identity_field = { source: 'ignored' };

    const sessionList = JSON.parse(rawSessionList()) as {
      sessions: Array<Record<string, unknown>>;
      [key: string]: unknown;
    };
    sessionList.future_list_field = 'ignored';
    sessionList.sessions[0].future_session_field = { version: 2 };

    const session = JSON.parse(rawSession()) as Record<string, unknown>;
    session.future_detail_field = true;

    const messages = JSON.parse(rawSessionMessages()) as {
      messages: Array<Record<string, unknown>>;
      pagination: Record<string, unknown>;
      [key: string]: unknown;
    };
    messages.future_messages_field = ['ignored'];
    messages.messages[0].future_message_field = { interactive: false };
    messages.pagination.future_pagination_field = 7;

    const fixture = fetchSequence(
      response(JSON.stringify(provider)),
      response(JSON.stringify(auth)),
      response(JSON.stringify(sessionList)),
      response(JSON.stringify(session)),
      response(JSON.stringify(messages))
    );
    const transport = createLiveRestTransport({ fetch: fixture.fetch });

    await expect(transport.getProviders()).resolves.toEqual(LIVE_PROVIDER_DISCOVERY_FIXTURE);
    await expect(transport.getAuthState()).resolves.toEqual(LIVE_AUTH_IDENTITY_FIXTURE);
    await expect(transport.listSessions()).resolves.toEqual(LIVE_SESSION_LIST_FIXTURE);
    await expect(transport.getSession(LIVE_SESSION_FIXTURE.id)).resolves.toEqual(LIVE_SESSION_FIXTURE);
    await expect(transport.getSessionMessages(LIVE_SESSION_FIXTURE.id)).resolves.toEqual(
      LIVE_SESSION_MESSAGES_FIXTURE
    );
  });

  it('enforces source-backed provider identifiers and safe display labels', async () => {
    const providerResponse = (name: string, displayName = 'Synthetic Provider'): Response =>
      response(
        JSON.stringify({
          providers: [{ name, display_name: displayName, supports_password: false }]
        })
      );

    await expect(
      createLiveRestTransport({ fetch: fetchSequence(providerResponse('é', 'Identité Synthétique')).fetch }).getProviders()
    ).resolves.toEqual({
      providers: [{ name: 'é', displayName: 'Identité Synthétique', supportsPassword: false }]
    });

    for (const name of ['Synthetic', 'synthetic provider', 'synthetic/provider', 'synthetic\\provider', 'synthetic​provider', 'ß']) {
      await expect(
        createLiveRestTransport({ fetch: fetchSequence(providerResponse(name)).fetch }).getProviders()
      ).rejects.toMatchObject({ code: 'invalid-response' });
    }

    await expect(
      createLiveRestTransport({ fetch: fetchSequence(providerResponse('synthetic-provider', 'Synthetic​Provider')).fetch }).getProviders()
    ).rejects.toMatchObject({ code: 'invalid-response' });
  });

  it('fails closed when required response semantics are missing or the wrong type', async () => {
    const wrongProvider = JSON.parse(rawProviderDiscovery()) as {
      providers: Array<Record<string, unknown>>;
    };
    wrongProvider.providers[0].supports_password = 'false';
    await expect(
      createLiveRestTransport({ fetch: fetchSequence(response(JSON.stringify(wrongProvider))).fetch }).getProviders()
    ).rejects.toMatchObject({ code: 'invalid-response' });

    const missingAuth = JSON.parse(rawAuthIdentity()) as Record<string, unknown>;
    delete missingAuth.provider;
    await expect(
      createLiveRestTransport({ fetch: fetchSequence(response(JSON.stringify(missingAuth))).fetch }).getAuthState()
    ).rejects.toMatchObject({ code: 'invalid-response' });

    const missingListField = JSON.parse(rawSessionList()) as Record<string, unknown>;
    delete missingListField.total;
    await expect(
      createLiveRestTransport({ fetch: fetchSequence(response(JSON.stringify(missingListField))).fetch }).listSessions()
    ).rejects.toMatchObject({ code: 'invalid-response' });

    const wrongDetail = JSON.parse(rawSession()) as Record<string, unknown>;
    wrongDetail.id = 42;
    await expect(
      createLiveRestTransport({ fetch: fetchSequence(response(JSON.stringify(wrongDetail))).fetch }).getSession(
        LIVE_SESSION_FIXTURE.id
      )
    ).rejects.toMatchObject({ code: 'invalid-response' });

    const missingMessages = JSON.parse(rawSessionMessages()) as Record<string, unknown>;
    delete missingMessages.pagination;
    await expect(
      createLiveRestTransport({ fetch: fetchSequence(response(JSON.stringify(missingMessages))).fetch }).getSessionMessages(
        LIVE_SESSION_FIXTURE.id
      )
    ).rejects.toMatchObject({ code: 'invalid-response' });

    const wrongMessages = JSON.parse(rawSessionMessages()) as {
      pagination: Record<string, unknown>;
    };
    wrongMessages.pagination.returned = '1';
    await expect(
      createLiveRestTransport({ fetch: fetchSequence(response(JSON.stringify(wrongMessages))).fetch }).getSessionMessages(
        LIVE_SESSION_FIXTURE.id
      )
    ).rejects.toMatchObject({ code: 'invalid-response' });
  });

  it('fails closed on duplicate JSON keys, mismatched pagination, and returned ID mismatches', async () => {
    const duplicate = fetchSequence(response('{"providers":[],"providers":[]}'));
    await expect(createLiveRestTransport({ fetch: duplicate.fetch }).getProviders()).rejects.toMatchObject({
      code: 'malformed-json'
    });

    const mismatched = fetchSequence(
      response(
        JSON.stringify({
          session_id: LIVE_SESSION_MESSAGES_FIXTURE.sessionId,
          messages: [],
          pagination: { limit: null, offset: 0, returned: 1 }
        })
      )
    );
    await expect(
      createLiveRestTransport({ fetch: mismatched.fetch }).getSessionMessages(LIVE_SESSION_FIXTURE.id)
    ).rejects.toMatchObject({ code: 'invalid-response' });

    const invalidReturnedId = fetchSequence(response('{"id":"../auth/me"}'));
    await expect(
      createLiveRestTransport({ fetch: invalidReturnedId.fetch }).getSession(LIVE_SESSION_FIXTURE.id)
    ).rejects.toMatchObject({ code: 'invalid-response' });

    const wrongDetailId = fetchSequence(response(rawSession({ ...LIVE_SESSION_FIXTURE, id: 'synthetic-session-0002' })));
    await expect(
      createLiveRestTransport({ fetch: wrongDetailId.fetch }).getSession(LIVE_SESSION_FIXTURE.id)
    ).rejects.toMatchObject({ code: 'invalid-response' });

    const wrongMessagesId = fetchSequence(response(rawSessionMessages('synthetic-session-0002')));
    await expect(
      createLiveRestTransport({ fetch: wrongMessagesId.fetch }).getSessionMessages(LIVE_SESSION_FIXTURE.id)
    ).rejects.toMatchObject({ code: 'invalid-response' });
  });

  it('rejects oversized, wrong-media, malformed-UTF8, redirected, and non-success responses', async () => {
    const oversized = fetchSequence(response('{"providers":[]}'));
    await expect(
      createLiveRestTransport({ fetch: oversized.fetch, maxBodyBytes: 4 }).getProviders()
    ).rejects.toMatchObject({ code: 'body-too-large' });

    const missingContentType = fetchSequence(
      response(new TextEncoder().encode(rawProviderDiscovery()), 200, {})
    );
    await expect(
      createLiveRestTransport({ fetch: missingContentType.fetch }).getProviders()
    ).rejects.toMatchObject({ code: 'invalid-response' });

    const wrongContentType = fetchSequence(
      response(rawProviderDiscovery(), 200, { 'content-type': 'text/plain' })
    );
    await expect(
      createLiveRestTransport({ fetch: wrongContentType.fetch }).getProviders()
    ).rejects.toMatchObject({ code: 'invalid-response' });

    const nullBodyOversized = nullBodyResponse(Uint8Array.of(1, 2, 3, 4, 5), {
      'content-type': 'application/json',
      'content-length': '5'
    });
    await expect(
      createLiveRestTransport({
        fetch: fetchSequence(nullBodyOversized.response).fetch,
        maxBodyBytes: 4
      }).getProviders()
    ).rejects.toMatchObject({ code: 'body-too-large' });
    expect(nullBodyOversized.arrayBufferCalls).toBe(0);

    const malformedUtf8 = nullBodyResponse(Uint8Array.of(0xff, 0xfe), {
      'content-type': 'application/json',
      'content-length': '2'
    });
    await expect(
      createLiveRestTransport({ fetch: fetchSequence(malformedUtf8.response).fetch }).getProviders()
    ).rejects.toMatchObject({ code: 'malformed-json' });

    const nullBodyWithoutLength = nullBodyResponse(new TextEncoder().encode(rawProviderDiscovery()));
    await expect(
      createLiveRestTransport({ fetch: fetchSequence(nullBodyWithoutLength.response).fetch }).getProviders()
    ).rejects.toMatchObject({ code: 'invalid-response' });
    expect(nullBodyWithoutLength.arrayBufferCalls).toBe(0);

    const redirectedResponse = response(rawProviderDiscovery());
    Object.defineProperty(redirectedResponse, 'redirected', { value: true });
    const redirected = fetchSequence(redirectedResponse);
    await expect(createLiveRestTransport({ fetch: redirected.fetch }).getProviders()).rejects.toMatchObject({
      code: 'redirect'
    });

    const unavailable = fetchSequence(
      response('{"detail":"no auth providers registered","future_detail":true}', 503)
    );
    await expect(createLiveRestTransport({ fetch: unavailable.fetch }).getProviders()).rejects.toMatchObject({
      code: 'provider-unavailable',
      status: 503
    });

    const unexpectedUnavailable = fetchSequence(response('{"detail":"unexpected"}', 503));
    await expect(
      createLiveRestTransport({ fetch: unexpectedUnavailable.fetch }).getProviders()
    ).rejects.toMatchObject({ code: 'invalid-response' });

    const notFound = fetchSequence(response('{"detail":"Session not found","future_detail":true}', 404));
    await expect(
      createLiveRestTransport({ fetch: notFound.fetch }).getSession(LIVE_SESSION_FIXTURE.id)
    ).rejects.toMatchObject({ code: 'not-found', status: 404 });

    const unexpectedNotFound = fetchSequence(response('{"detail":"unexpected"}', 404));
    await expect(
      createLiveRestTransport({ fetch: unexpectedNotFound.fetch }).getSession(LIVE_SESSION_FIXTURE.id)
    ).rejects.toMatchObject({ code: 'invalid-response' });

    const unauthenticated = fetchSequence(response('{"detail":"Unauthorized"}', 401));
    await expect(createLiveRestTransport({ fetch: unauthenticated.fetch }).getAuthState()).rejects.toMatchObject({
      code: 'unauthenticated',
      status: 401
    });
  });

  it('fails closed on timeout, abort, network errors, and invalid route input', async () => {
    const pending = {
      fetch: async () => await new Promise<Response>(() => undefined)
    };
    const timeoutTransport = createLiveRestTransport({ fetch: pending.fetch, timeoutMs: 5 });
    await expect(timeoutTransport.getProviders()).rejects.toMatchObject({ code: 'timeout' });

    const controller = new AbortController();
    const abortTransport = createLiveRestTransport({
      fetch: async () => await new Promise<Response>(() => undefined)
    });
    const aborted = abortTransport.getProviders(controller.signal);
    controller.abort();
    await expect(aborted).rejects.toMatchObject({ code: 'aborted' });

    const earlyController = new AbortController();
    earlyController.abort();
    let earlyFetchCalls = 0;
    const earlyAbortTransport = createLiveRestTransport({
      fetch: async () => {
        earlyFetchCalls += 1;
        return response(rawProviderDiscovery());
      }
    });
    await expect(earlyAbortTransport.getProviders(earlyController.signal)).rejects.toMatchObject({
      code: 'aborted'
    });
    expect(earlyFetchCalls).toBe(0);

    const networkTransport = createLiveRestTransport({
      fetch: async () => {
        throw new Error('untrusted network detail');
      }
    });
    await expect(networkTransport.getProviders()).rejects.toMatchObject({
      code: 'network',
      message: 'The same-origin REST request could not be completed.'
    });

    expect(() => validateSessionId('../auth/me')).toThrowError(LiveRestError);
    expect(() => validateSessionId('a/b')).toThrowError(LiveRestError);
    expect(() => createLiveRestTransport({ apiBaseUrl: 'https://attacker.invalid/api' })).toThrowError(
      LiveRestError
    );

    const browserOrigin = window.location.origin;
    expect(normalizeApiBaseUrl(`${browserOrigin}/api`)).toBe(`${browserOrigin}/api`);
    expect(() =>
      createLiveRestTransport({
        apiBaseUrl: 'https://attacker.invalid/api',
        origin: 'https://attacker.invalid'
      } as never)
    ).toThrowError(LiveRestError);
  });

  it('caps options and preserves exact bounded error messages', () => {
    expect(() => createLiveRestTransport({ timeoutMs: 0 })).toThrowError(LiveRestError);
    expect(() => createLiveRestTransport({ maxBodyBytes: 0 })).toThrowError(LiveRestError);
    expect(() => createLiveRestTransport({ fetch: fetchSequence(response(rawSessionList())).fetch }).listSessions({
      limit: 101
    })).toThrowError(LiveRestError);
    expect(() => createLiveRestTransport({ fetch: fetchSequence(response(rawSessionList())).fetch }).listSessions({
      offset: -1
    })).toThrowError(LiveRestError);
    expect(new LiveRestError('invalid-response').message.length).toBeLessThanOrEqual(240);
    expect(LIVE_REST_FIXTURE_IDS.providerDiscovery).toBe('w06-provider-discovery-v1');
  });
});
