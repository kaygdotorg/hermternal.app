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

function response(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { 'content-type': 'application/json' }
  });
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
  return JSON.stringify({
    sessions: [JSON.parse(rawSession())],
    total: LIVE_SESSION_LIST_FIXTURE.total,
    limit: LIVE_SESSION_LIST_FIXTURE.limit,
    offset: LIVE_SESSION_LIST_FIXTURE.offset
  });
}

function rawSessionMessages(): string {
  return JSON.stringify({
    session_id: LIVE_SESSION_MESSAGES_FIXTURE.sessionId,
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

describe('strict JSON parser', () => {
  it('accepts bounded JSON whitespace and rejects duplicate keys', () => {
    expect(parseStrictJson(' \t{ "ok": true }\n')).toEqual({ ok: true });
    expect(() => parseStrictJson('{"ok":true,"ok":false}')).toThrow(StrictJsonError);
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

  it('fails closed on unknown keys, duplicate JSON keys, and mismatched pagination', async () => {
    const unknown = fetchSequence(response('{"providers":[],"unexpected":true}'));
    await expect(createLiveRestTransport({ fetch: unknown.fetch }).getProviders()).rejects.toMatchObject({
      code: 'invalid-response'
    });

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
  });

  it('rejects oversized, redirected, and non-success responses without echoing body data', async () => {
    const oversized = fetchSequence(response('{"providers":[]}'));
    await expect(
      createLiveRestTransport({ fetch: oversized.fetch, maxBodyBytes: 4 }).getProviders()
    ).rejects.toMatchObject({ code: 'body-too-large' });

    const redirectedResponse = response(rawProviderDiscovery());
    Object.defineProperty(redirectedResponse, 'redirected', { value: true });
    const redirected = fetchSequence(redirectedResponse);
    await expect(createLiveRestTransport({ fetch: redirected.fetch }).getProviders()).rejects.toMatchObject({
      code: 'redirect'
    });

    const unavailable = fetchSequence(response('{"detail":"no auth providers registered"}', 503));
    await expect(createLiveRestTransport({ fetch: unavailable.fetch }).getProviders()).rejects.toMatchObject({
      code: 'provider-unavailable',
      status: 503
    });

    const unexpectedUnavailable = fetchSequence(response('{"detail":"unexpected"}', 503));
    await expect(
      createLiveRestTransport({ fetch: unexpectedUnavailable.fetch }).getProviders()
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
    expect(normalizeApiBaseUrl('https://app.example/api', 'https://app.example')).toBe(
      'https://app.example/api'
    );
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
