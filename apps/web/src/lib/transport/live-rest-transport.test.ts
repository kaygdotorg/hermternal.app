import { describe, expect, it, vi } from 'vitest';
import {
  captureLiveSessionProjection,
  consumeLiveRestCanonicalAlias,
  createLiveRestTransport,
  getLiveRestSessionForWorkspace,
  LiveRestError,
  normalizeApiBaseUrl,
  resetLiveRestCanonicalAliasScope,
  validateSessionId,
  type LiveRestTransport
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
import type { LiveSession } from './live-rest-types';

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

function pendingBodyResponse(
  headers: Record<string, string> = { 'content-type': 'application/json' },
  status = 200,
  cancellation: 'resolve' | 'pending' = 'resolve'
): { response: Response; get cancelCalls(): number } {
  let cancelCalls = 0;
  const body = {
    getReader() {
      return {
        read: () => new Promise<ReadableStreamReadResult<Uint8Array>>(() => undefined),
        cancel: () => {
          cancelCalls += 1;
          return cancellation === 'pending' ? new Promise<void>(() => undefined) : Promise.resolve();
        },
        releaseLock: () => undefined
      };
    }
  } as unknown as ReadableStream<Uint8Array>;
  const result = new Response(null, { status, headers });
  Object.defineProperty(result, 'body', { configurable: true, value: body });
  return {
    response: result,
    get cancelCalls() {
      return cancelCalls;
    }
  };
}

function scriptedBodyResponse(
  reads: Array<ReadableStreamReadResult<Uint8Array>>,
  headers: Record<string, string> = { 'content-type': 'application/json' }
): { response: Response; get cancelCalls(): number } {
  let index = 0;
  let cancelCalls = 0;
  const body = {
    getReader() {
      return {
        read: async () => reads[index++] ?? { done: true, value: undefined },
        cancel: async () => {
          cancelCalls += 1;
        },
        releaseLock: () => undefined
      };
    }
  } as unknown as ReadableStream<Uint8Array>;
  const result = new Response(null, { status: 200, headers });
  Object.defineProperty(result, 'body', { configurable: true, value: body });
  return {
    response: result,
    get cancelCalls() {
      return cancelCalls;
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

function createDeferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((nextResolve, nextReject) => {
    resolve = nextResolve;
    reject = nextReject;
  });
  return { promise, resolve, reject };
}

async function withObjectPrototypeValuePollution<T>(
  descriptor: PropertyDescriptor,
  callback: () => Promise<T>
): Promise<T> {
  const previous = Reflect.getOwnPropertyDescriptor(Object.prototype, 'value');
  try {
    Object.defineProperty(Object.prototype, 'value', { configurable: true, ...descriptor });
    return await callback();
  } finally {
    if (previous) {
      Object.defineProperty(Object.prototype, 'value', previous);
    } else {
      delete (Object.prototype as Record<string, unknown>).value;
    }
  }
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

function populateSessionObject(
  target: object,
  session: LiveSession = LIVE_SESSION_FIXTURE
): object {
  for (const [key, value] of Object.entries(session)) {
    Object.defineProperty(target, key, {
      configurable: true,
      enumerable: true,
      value,
      writable: true
    });
  }
  return target;
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
    messages: Array.from({ length: count }, () => ({
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
    expect(() => parseStrictJson(JSON.stringify({ content: Array.from({ length: 501 }, () => null) }))).toThrow(
      StrictJsonError
    );
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
    expect(messages.messages.at(-1)?.content).toBe('Synthetic message');
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

  it('projects source-defined numeric expiry, text content, and tool metadata', async () => {
    const auth = JSON.parse(rawAuthIdentity()) as Record<string, unknown>;
    auth.expires_at = 1_767_225_600;
    const messages = {
      session_id: LIVE_SESSION_MESSAGES_FIXTURE.sessionId,
      messages: [
        { role: 'assistant', content: null },
        {
          role: 'tool',
          content: 'Synthetic tool result',
          tool_name: 'synthetic_tool',
          tool_call_id: 'call-1',
          timestamp: 1_767_225_601,
          tool_calls: [
            {
              id: 'call-1',
              function: { name: 'synthetic_tool', arguments: '{"query":"redacted"}' }
            }
          ]
        },
        { role: 'assistant', content: 'Synthetic multimodal summary' }
      ],
      pagination: { limit: null, offset: 0, returned: 3 }
    };
    const fixture = fetchSequence(response(JSON.stringify(auth)), response(JSON.stringify(messages)));
    const transport = createLiveRestTransport({ fetch: fixture.fetch });

    await expect(transport.getAuthState()).resolves.toMatchObject({ expiresAt: 1_767_225_600 });
    await expect(transport.getSessionMessages(LIVE_SESSION_MESSAGES_FIXTURE.sessionId)).resolves.toEqual({
      sessionId: LIVE_SESSION_MESSAGES_FIXTURE.sessionId,
      messages: [
        { role: 'assistant', content: null },
        {
          role: 'tool',
          content: 'Synthetic tool result',
          toolName: 'synthetic_tool',
          toolCallId: 'call-1',
          timestamp: 1_767_225_601,
          toolCalls: [
            {
              id: 'call-1',
              function: { name: 'synthetic_tool', arguments: '{"query":"redacted"}' }
            }
          ]
        },
        { role: 'assistant', content: 'Synthetic multimodal summary' }
      ],
      pagination: messages.pagination
    });
  });

  it('accepts official null tool_calls and preserves its distinction from omission', async () => {
    const withNullToolCalls = {
      session_id: LIVE_SESSION_MESSAGES_FIXTURE.sessionId,
      messages: [
        { role: 'user', content: 'Synthetic user message', tool_calls: null },
        { role: 'assistant', content: 'Synthetic assistant message', tool_calls: null },
        { role: 'system', content: null, tool_calls: null },
        { role: 'tool', content: 'Synthetic tool result', tool_calls: null }
      ],
      pagination: { limit: null, offset: 0, returned: 4 }
    };
    const withoutToolCalls = {
      session_id: LIVE_SESSION_MESSAGES_FIXTURE.sessionId,
      messages: [{ role: 'assistant', content: 'No tool-call field' }],
      pagination: { limit: null, offset: 0, returned: 1 }
    };
    const fixture = fetchSequence(
      response(JSON.stringify(withNullToolCalls)),
      response(JSON.stringify(withoutToolCalls))
    );
    const transport = createLiveRestTransport({ fetch: fixture.fetch });

    await expect(transport.getSessionMessages(LIVE_SESSION_MESSAGES_FIXTURE.sessionId)).resolves.toMatchObject({
      messages: [
        { role: 'user', content: 'Synthetic user message', toolCalls: null },
        { role: 'assistant', content: 'Synthetic assistant message', toolCalls: null },
        { role: 'system', content: null, toolCalls: null },
        { role: 'tool', content: 'Synthetic tool result', toolCalls: null }
      ]
    });

    const omitted = await transport.getSessionMessages(LIVE_SESSION_MESSAGES_FIXTURE.sessionId);
    expect(omitted.messages[0]).not.toHaveProperty('toolCalls');
  });

  it('preserves omitted, null, and valid tool metadata across roles while rejecting malformed types', async () => {
    const roles = ['user', 'assistant', 'system', 'tool'] as const;
    const messages = roles.flatMap((role) => [
      { role, content: `Synthetic ${role} omitted` },
      { role, content: `Synthetic ${role} null`, tool_name: null, tool_call_id: null },
      {
        role,
        content: `Synthetic ${role} strings`,
        tool_name: `${role}-tool`,
        tool_call_id: `${role}-call`
      }
    ]);
    const payload = {
      session_id: LIVE_SESSION_MESSAGES_FIXTURE.sessionId,
      messages,
      pagination: { limit: null, offset: 0, returned: messages.length }
    };

    const parsed = await createLiveRestTransport({
      fetch: fetchSequence(response(JSON.stringify(payload))).fetch
    }).getSessionMessages(LIVE_SESSION_MESSAGES_FIXTURE.sessionId);

    expect(parsed.messages).toHaveLength(roles.length * 3);
    roles.forEach((role, roleIndex) => {
      const omitted = parsed.messages[roleIndex * 3];
      const nulled = parsed.messages[roleIndex * 3 + 1];
      const valued = parsed.messages[roleIndex * 3 + 2];

      expect(omitted).not.toHaveProperty('toolName');
      expect(omitted).not.toHaveProperty('toolCallId');
      expect(nulled).toMatchObject({ toolName: null, toolCallId: null });
      expect(valued).toMatchObject({
        toolName: `${role}-tool`,
        toolCallId: `${role}-call`
      });
    });

    const malformedValues = [true, 42, [], {}] as const;
    for (const role of roles) {
      for (const field of ['tool_name', 'tool_call_id'] as const) {
        for (const malformedValue of malformedValues) {
          const invalidPayload = {
            session_id: LIVE_SESSION_MESSAGES_FIXTURE.sessionId,
            messages: [{ role, content: 'Synthetic malformed metadata', [field]: malformedValue }],
            pagination: { limit: null, offset: 0, returned: 1 }
          };
          await expect(
            createLiveRestTransport({
              fetch: fetchSequence(response(JSON.stringify(invalidPayload))).fetch
            }).getSessionMessages(LIVE_SESSION_MESSAGES_FIXTURE.sessionId)
          ).rejects.toMatchObject({ code: 'invalid-response' });
        }
      }
    }
  });

  it('accepts bounded fractional Unix timestamps emitted by the official Hermes session store', async () => {
    const session = JSON.parse(rawSession()) as Record<string, unknown>;
    session.started_at = 1_767_225_600.125;
    session.ended_at = 1_767_225_601.5;
    session.last_active = 1_767_225_602.875;
    const messages = JSON.parse(rawSessionMessages()) as {
      messages: Array<Record<string, unknown>>;
    };
    messages.messages[0].timestamp = 1_767_225_603.25;
    const fixture = fetchSequence(response(JSON.stringify(session)), response(JSON.stringify(messages)));
    const transport = createLiveRestTransport({ fetch: fixture.fetch });

    await expect(transport.getSession(LIVE_SESSION_FIXTURE.id)).resolves.toMatchObject({
      startedAt: 1_767_225_600.125,
      endedAt: 1_767_225_601.5,
      lastActive: 1_767_225_602.875
    });
    await expect(transport.getSessionMessages(LIVE_SESSION_FIXTURE.id)).resolves.toMatchObject({
      messages: [{ timestamp: 1_767_225_603.25 }]
    });
  });

  it('accepts raw session-detail omissions and normalizes SQLite archive flags', async () => {
    const detail = JSON.parse(rawSession()) as Record<string, unknown>;
    delete detail.last_active;
    delete detail.is_active;
    delete detail.preview;
    detail.archived = 1;
    detail.pinned = 0;

    const parsed = await createLiveRestTransport({
      fetch: fetchSequence(response(JSON.stringify(detail))).fetch
    }).getSession(LIVE_SESSION_FIXTURE.id);

    expect(parsed).toMatchObject({
      id: LIVE_SESSION_FIXTURE.id,
      messageCount: LIVE_SESSION_FIXTURE.messageCount,
      archived: true,
      pinned: false
    });
    expect(parsed).not.toHaveProperty('lastActive');
    expect(parsed).not.toHaveProperty('isActive');
    expect(parsed).not.toHaveProperty('preview');
  });

  it('preserves optional session-detail omission and null distinctions', async () => {
    const present = JSON.parse(rawSession()) as Record<string, unknown>;
    present.last_active = 1_767_225_602.125;
    present.is_active = true;
    present.preview = null;
    present.archived = false;
    present.pinned = true;

    const omitted = JSON.parse(rawSession()) as Record<string, unknown>;
    delete omitted.last_active;
    delete omitted.is_active;
    delete omitted.preview;
    delete omitted.archived;
    delete omitted.pinned;

    const fixture = fetchSequence(
      response(JSON.stringify(present)),
      response(JSON.stringify(omitted))
    );
    const transport = createLiveRestTransport({ fetch: fixture.fetch });

    await expect(transport.getSession(LIVE_SESSION_FIXTURE.id)).resolves.toMatchObject({
      lastActive: 1_767_225_602.125,
      isActive: true,
      preview: null,
      archived: false,
      pinned: true
    });

    const omittedResult = await transport.getSession(LIVE_SESSION_FIXTURE.id);
    expect(omittedResult).not.toHaveProperty('lastActive');
    expect(omittedResult).not.toHaveProperty('isActive');
    expect(omittedResult).not.toHaveProperty('preview');
    expect(omittedResult).not.toHaveProperty('archived');
    expect(omittedResult).not.toHaveProperty('pinned');
  });

  it('rejects malformed optional session fields and unsupported archive flag encodings', async () => {
    const invalidOptionalFields: Array<{
      field: 'last_active' | 'is_active' | 'preview';
      values: unknown[];
    }> = [
      { field: 'last_active', values: [null, -1, 4_294_967_296, '1767225600', true, [], {}] },
      { field: 'is_active', values: [null, 0, 1, 'false', [], {}] },
      { field: 'preview', values: [true, 42, [], {}, 'x'.repeat(8_193)] }
    ];

    for (const { field, values } of invalidOptionalFields) {
      for (const value of values) {
        const invalid = JSON.parse(rawSession()) as Record<string, unknown>;
        invalid[field] = value;
        await expect(
          createLiveRestTransport({
            fetch: fetchSequence(response(JSON.stringify(invalid))).fetch
          }).getSession(LIVE_SESSION_FIXTURE.id)
        ).rejects.toMatchObject({ code: value === 'x'.repeat(8_193) ? 'malformed-json' : 'invalid-response' });
      }
    }

    for (const field of ['archived', 'pinned'] as const) {
      for (const value of [null, -1, 2, 1.5, '0', [], {}] as const) {
        const invalid = JSON.parse(rawSession()) as Record<string, unknown>;
        invalid[field] = value;
        await expect(
          createLiveRestTransport({
            fetch: fetchSequence(response(JSON.stringify(invalid))).fetch
          }).getSession(LIVE_SESSION_FIXTURE.id)
        ).rejects.toMatchObject({ code: 'invalid-response' });
      }
    }
  });

  it('accepts empty profile metadata while stable identity fields remain non-empty', async () => {
    const providers = JSON.parse(rawProviderDiscovery()) as {
      providers: Array<Record<string, unknown>>;
    };
    providers.providers[0].display_name = '';

    const auth = JSON.parse(rawAuthIdentity()) as Record<string, unknown>;
    auth.email = '';
    auth.display_name = '';
    auth.org_id = '';

    const session = JSON.parse(rawSession()) as Record<string, unknown>;
    session.source = '';
    session.model = '';
    session.title = '';
    session.preview = '';
    session.profile = '';

    const messages = {
      session_id: LIVE_SESSION_MESSAGES_FIXTURE.sessionId,
      messages: [
        {
          role: 'tool',
          content: '',
          tool_name: '',
          tool_call_id: '',
          tool_calls: [{ id: '', function: { name: '', arguments: '' } }]
        }
      ],
      pagination: { limit: null, offset: 0, returned: 1 }
    };

    const fixture = fetchSequence(
      response(JSON.stringify(providers)),
      response(JSON.stringify(auth)),
      response(JSON.stringify(session)),
      response(JSON.stringify(messages))
    );
    const transport = createLiveRestTransport({ fetch: fixture.fetch });

    await expect(transport.getProviders()).resolves.toMatchObject({
      providers: [{ displayName: '' }]
    });
    await expect(transport.getAuthState()).resolves.toMatchObject({
      userId: 'synthetic-user',
      email: '',
      displayName: '',
      organizationId: '',
      provider: 'synthetic-provider'
    });
    await expect(transport.getSession(LIVE_SESSION_FIXTURE.id)).resolves.toMatchObject({
      source: '',
      model: '',
      title: '',
      preview: '',
      profile: ''
    });
    await expect(
      transport.getSessionMessages(LIVE_SESSION_MESSAGES_FIXTURE.sessionId)
    ).resolves.toMatchObject({
      messages: [
        {
          role: 'tool',
          content: '',
          toolName: '',
          toolCallId: '',
          toolCalls: [{ id: '', function: { name: '', arguments: '' } }]
        }
      ]
    });

    const emptyProvider = JSON.parse(rawProviderDiscovery()) as {
      providers: Array<Record<string, unknown>>;
    };
    emptyProvider.providers[0].name = '';
    await expect(
      createLiveRestTransport({
        fetch: fetchSequence(response(JSON.stringify(emptyProvider))).fetch
      }).getProviders()
    ).rejects.toMatchObject({ code: 'invalid-response' });

    const emptySessionId = JSON.parse(rawSession()) as Record<string, unknown>;
    emptySessionId.id = '';
    await expect(
      createLiveRestTransport({
        fetch: fetchSequence(response(JSON.stringify(emptySessionId))).fetch
      }).getSession(LIVE_SESSION_FIXTURE.id)
    ).rejects.toMatchObject({ code: 'invalid-response' });
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

    for (const field of ['user_id', 'provider']) {
      const missingAuth = JSON.parse(rawAuthIdentity()) as Record<string, unknown>;
      delete missingAuth[field];
      await expect(
        createLiveRestTransport({ fetch: fetchSequence(response(JSON.stringify(missingAuth))).fetch }).getAuthState()
      ).rejects.toMatchObject({ code: 'invalid-response' });
    }

    for (const field of ['user_id', 'provider']) {
      const emptyAuth = JSON.parse(rawAuthIdentity()) as Record<string, unknown>;
      emptyAuth[field] = '';
      await expect(
        createLiveRestTransport({ fetch: fetchSequence(response(JSON.stringify(emptyAuth))).fetch }).getAuthState()
      ).rejects.toMatchObject({ code: 'invalid-response' });
    }

    for (const field of ['email', 'display_name', 'org_id', 'expires_at']) {
      const nullableAuth = JSON.parse(rawAuthIdentity()) as Record<string, unknown>;
      nullableAuth[field] = null;
      await expect(
        createLiveRestTransport({ fetch: fetchSequence(response(JSON.stringify(nullableAuth))).fetch }).getAuthState()
      ).rejects.toMatchObject({ code: 'invalid-response' });
    }

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

    for (const field of [
      'source',
      'model',
      'title',
      'started_at',
      'ended_at',
      'message_count',
      'tool_call_count',
      'input_tokens',
      'output_tokens'
    ]) {
      const missingSessionField = JSON.parse(rawSession()) as Record<string, unknown>;
      delete missingSessionField[field];
      await expect(
        createLiveRestTransport({ fetch: fetchSequence(response(JSON.stringify(missingSessionField))).fetch }).getSession(
          LIVE_SESSION_FIXTURE.id
        )
      ).rejects.toMatchObject({ code: 'invalid-response' });
    }

    for (const field of ['started_at', 'last_active']) {
      const wrongSessionTimestamp = JSON.parse(rawSession()) as Record<string, unknown>;
      wrongSessionTimestamp[field] = '2026-01-01T00:00:00Z';
      await expect(
        createLiveRestTransport({ fetch: fetchSequence(response(JSON.stringify(wrongSessionTimestamp))).fetch }).getSession(
          LIVE_SESSION_FIXTURE.id
        )
      ).rejects.toMatchObject({ code: 'invalid-response' });
    }

    const wrongEndedAt = JSON.parse(rawSession()) as Record<string, unknown>;
    wrongEndedAt.ended_at = '2026-01-01T00:00:00Z';
    await expect(
      createLiveRestTransport({ fetch: fetchSequence(response(JSON.stringify(wrongEndedAt))).fetch }).getSession(
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

    for (const expiresAt of ['1767225600', -1, 4_294_967_296, 1.5]) {
      const invalidAuth = JSON.parse(rawAuthIdentity()) as Record<string, unknown>;
      invalidAuth.expires_at = expiresAt;
      await expect(
        createLiveRestTransport({ fetch: fetchSequence(response(JSON.stringify(invalidAuth))).fetch }).getAuthState()
      ).rejects.toMatchObject({ code: 'invalid-response' });
    }

    for (const content of [true, 1, [], {}] as const) {
      const invalidMessages = {
        session_id: LIVE_SESSION_MESSAGES_FIXTURE.sessionId,
        messages: [{ role: 'assistant', content }],
        pagination: { limit: null, offset: 0, returned: 1 }
      };
      await expect(
        createLiveRestTransport({ fetch: fetchSequence(response(JSON.stringify(invalidMessages))).fetch }).getSessionMessages(
          LIVE_SESSION_FIXTURE.id
        )
      ).rejects.toMatchObject({ code: 'invalid-response' });
    }

    const invalidToolCalls = {
      session_id: LIVE_SESSION_MESSAGES_FIXTURE.sessionId,
      messages: [
        {
          role: 'tool',
          content: 'Synthetic tool result',
          tool_calls: [{ id: 'call-1', function: { name: 'synthetic_tool', arguments: 42 } }]
        }
      ],
      pagination: { limit: null, offset: 0, returned: 1 }
    };
    await expect(
      createLiveRestTransport({ fetch: fetchSequence(response(JSON.stringify(invalidToolCalls))).fetch }).getSessionMessages(
        LIVE_SESSION_FIXTURE.id
      )
    ).rejects.toMatchObject({ code: 'invalid-response' });
  });

  it('fails closed on duplicate keys and pagination errors while accepting resolved session IDs', async () => {
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

    const resolvedDetailId = fetchSequence(
      response(rawSession({ ...LIVE_SESSION_FIXTURE, id: 'synthetic-session-0002' }))
    );
    const resolvedDetail = await createLiveRestTransport({ fetch: resolvedDetailId.fetch }).getSession(
      LIVE_SESSION_FIXTURE.id
    );
    expect(resolvedDetail).toMatchObject({ id: 'synthetic-session-0002' });
    expect(Object.getOwnPropertySymbols(resolvedDetail)).toEqual([]);
    expect(Reflect.ownKeys(resolvedDetail)).toEqual(Object.keys(resolvedDetail));

    const resolvedMessagesId = fetchSequence(response(rawSessionMessages('synthetic-session-0002')));
    await expect(
      createLiveRestTransport({ fetch: resolvedMessagesId.fetch }).getSessionMessages(LIVE_SESSION_FIXTURE.id)
    ).resolves.toMatchObject({ sessionId: 'synthetic-session-0002' });
  });

  it('binds canonical alias authority to the exact transport, workspace, and detail once', async () => {
    const alias = LIVE_SESSION_FIXTURE.id;
    const canonical = 'synthetic-session-0002';
    const fixture = fetchSequence(
      response(rawSession({ ...LIVE_SESSION_FIXTURE, id: canonical })),
      response(rawSession({ ...LIVE_SESSION_FIXTURE, id: canonical })),
      response(rawSession({ ...LIVE_SESSION_FIXTURE, id: canonical }))
    );
    const transport = createLiveRestTransport({ fetch: fixture.fetch });
    const otherTransport = createLiveRestTransport({
      fetch: fetchSequence(response(rawSession({ ...LIVE_SESSION_FIXTURE, id: canonical }))).fetch
    });
    const workspace = {};
    const otherWorkspace = {};

    const detail = await getLiveRestSessionForWorkspace(transport, workspace, alias);
    expect(detail.id).toBe(canonical);
    expect(Object.getOwnPropertySymbols(detail)).toEqual([]);
    expect(Object.getOwnPropertyDescriptors(detail)).toEqual(
      expect.objectContaining({ id: expect.any(Object) })
    );

    const spreadClone = { ...detail };
    const descriptorClone = Object.create(
      Object.getPrototypeOf(detail),
      Object.getOwnPropertyDescriptors(detail)
    ) as LiveSession;
    expect(consumeLiveRestCanonicalAlias(transport, workspace, spreadClone, alias)).toBeUndefined();
    expect(consumeLiveRestCanonicalAlias(transport, workspace, descriptorClone, alias)).toBeUndefined();
    expect(consumeLiveRestCanonicalAlias(transport, otherWorkspace, detail, alias)).toBeUndefined();
    expect(consumeLiveRestCanonicalAlias(otherTransport, workspace, detail, alias)).toBeUndefined();
    expect(() =>
      consumeLiveRestCanonicalAlias(transport, workspace, detail, 'synthetic-session-0003')
    ).toThrowError(new LiveRestError('invalid-response'));
    expect(consumeLiveRestCanonicalAlias(transport, workspace, detail, alias)).toBeUndefined();

    const secondDetail = await getLiveRestSessionForWorkspace(transport, workspace, alias);
    expect(consumeLiveRestCanonicalAlias(transport, workspace, secondDetail, alias)).toBe(canonical);
    expect(consumeLiveRestCanonicalAlias(transport, workspace, secondDetail, alias)).toBeUndefined();
    expect(consumeLiveRestCanonicalAlias(transport, workspace, { id: canonical }, alias)).toBeUndefined();

    const malformedAdapter: LiveRestTransport = {
      ...transport,
      getSession: vi.fn().mockResolvedValue({ ...detail, id: 42 })
    };
    await expect(
      getLiveRestSessionForWorkspace(malformedAdapter, {}, alias)
    ).rejects.toMatchObject({ code: 'invalid-response' });
  });

  it('clears pending alias authority when a workspace scope resets', async () => {
    const transport = createLiveRestTransport({
      fetch: fetchSequence(
        response(rawSession({ ...LIVE_SESSION_FIXTURE, id: 'synthetic-session-0002' }))
      ).fetch
    });
    const workspace = {};
    const detail = await getLiveRestSessionForWorkspace(transport, workspace, LIVE_SESSION_FIXTURE.id);

    resetLiveRestCanonicalAliasScope(transport, workspace);

    expect(
      consumeLiveRestCanonicalAlias(transport, workspace, detail, LIVE_SESSION_FIXTURE.id)
    ).toBeUndefined();
  });

  it('does not let a deferred real REST alias repopulate a reset workspace scope', async () => {
    const alias = LIVE_SESSION_FIXTURE.id;
    const canonical = 'synthetic-session-0002';
    const deferredResponse = createDeferred<Response>();
    let fetchCalls = 0;
    const transport = createLiveRestTransport({
      fetch: async () => {
        fetchCalls += 1;
        return fetchCalls === 1
          ? deferredResponse.promise
          : response(rawSession({ ...LIVE_SESSION_FIXTURE, id: canonical }));
      }
    });
    const workspace = {};

    const staleFetch = getLiveRestSessionForWorkspace(transport, workspace, alias);
    resetLiveRestCanonicalAliasScope(transport, workspace);
    deferredResponse.resolve(response(rawSession({ ...LIVE_SESSION_FIXTURE, id: canonical })));

    const staleDetail = await staleFetch;
    expect(staleDetail.id).toBe(canonical);
    expect(consumeLiveRestCanonicalAlias(transport, workspace, staleDetail, alias)).toBeUndefined();

    const freshDetail = await getLiveRestSessionForWorkspace(transport, workspace, alias);
    expect(consumeLiveRestCanonicalAlias(transport, workspace, freshDetail, alias)).toBe(canonical);
    expect(fetchCalls).toBe(2);
  });

  it('rejects a wrapper that relays a real transport alias detail', async () => {
    const canonical = 'synthetic-session-0002';
    const realTransport = createLiveRestTransport({
      fetch: fetchSequence(response(rawSession({ ...LIVE_SESSION_FIXTURE, id: canonical }))).fetch
    });
    const wrapper: LiveRestTransport = {
      ...realTransport,
      getSession: vi.fn((sessionId, signal) => realTransport.getSession(sessionId, signal))
    };

    await expect(
      getLiveRestSessionForWorkspace(wrapper, {}, LIVE_SESSION_FIXTURE.id)
    ).rejects.toMatchObject({ code: 'invalid-response' });
  });

  it('rejects malformed direct detail values before alias authority is issued', async () => {
    const malformed: LiveSession = {
      ...LIVE_SESSION_FIXTURE,
      id: 'not-a-valid-session-id'
    };
    const adapter: LiveRestTransport = {
      getProviders: vi.fn(),
      getAuthState: vi.fn(),
      listSessions: vi.fn(),
      getSessions: vi.fn(),
      getSession: vi.fn().mockResolvedValue(malformed),
      getSessionMessages: vi.fn()
    };

    await expect(
      getLiveRestSessionForWorkspace(adapter, {}, LIVE_SESSION_FIXTURE.id)
    ).rejects.toMatchObject({ code: 'invalid-response' });
  });

  it('captures an exact-ID custom detail as one immutable projection', async () => {
    const source = { ...LIVE_SESSION_FIXTURE };
    const adapter: LiveRestTransport = {
      getProviders: vi.fn(),
      getAuthState: vi.fn(),
      listSessions: vi.fn(),
      getSessions: vi.fn(),
      getSession: vi.fn().mockResolvedValue(source),
      getSessionMessages: vi.fn()
    };

    const captured = await getLiveRestSessionForWorkspace(adapter, {}, source.id);

    expect(captured).not.toBe(source);
    expect(Object.isFrozen(captured)).toBe(true);
    expect(captured).toEqual(source);
    source.id = 'foreign-session';
    source.title = 'mutated source';
    expect(captured.id).toBe(LIVE_SESSION_FIXTURE.id);
    expect(captured.title).toBe(LIVE_SESSION_FIXTURE.title);
  });

  it('exposes one normalized frozen projection for later list consumers', () => {
    const source = { ...LIVE_SESSION_FIXTURE, additive: 'ignored by the projection' };
    const captured = captureLiveSessionProjection(source);
    if (!captured) throw new Error('Expected a valid session projection.');

    expect(captured).not.toBe(source);
    expect(Object.isFrozen(captured)).toBe(true);
    expect(captured).toEqual(LIVE_SESSION_FIXTURE);
    source.id = 'foreign-session';
    source.title = 'mutated source';
    expect(captured.id).toBe(LIVE_SESSION_FIXTURE.id);
    expect(captured.title).toBe(LIVE_SESSION_FIXTURE.title);
  });

  it('rejects wrappers and exotic objects before structuredClone traversal', async () => {
    const customPrototype = Object.create(Object.prototype);
    const wrappers: Array<[string, object]> = [
      ['custom prototype', populateSessionObject(Object.create(customPrototype))],
      ['Number', Object.setPrototypeOf(populateSessionObject(new Number(1)), Object.prototype)],
      ['Boolean', Object.setPrototypeOf(populateSessionObject(new Boolean(true)), Object.prototype)],
      ['boxed string', Object.setPrototypeOf(new String('boxed'), Object.prototype)],
      ['Date', Object.setPrototypeOf(populateSessionObject(new Date()), Object.prototype)],
      ['Map', Object.setPrototypeOf(populateSessionObject(new Map()), Object.prototype)],
      ['Set', Object.setPrototypeOf(populateSessionObject(new Set()), Object.prototype)],
      ['RegExp', Object.setPrototypeOf(populateSessionObject(/synthetic/u), Object.prototype)],
      ['WeakMap', Object.setPrototypeOf(populateSessionObject(new WeakMap()), Object.prototype)],
      ['WeakSet', Object.setPrototypeOf(populateSessionObject(new WeakSet()), Object.prototype)],
      ['Promise', Object.setPrototypeOf(populateSessionObject(Promise.resolve()), Object.prototype)],
      ['ArrayBuffer', Object.setPrototypeOf(populateSessionObject(new ArrayBuffer(1)), Object.prototype)],
      ['DataView', Object.setPrototypeOf(populateSessionObject(new DataView(new ArrayBuffer(1))), Object.prototype)],
      ['typed array', Object.setPrototypeOf(populateSessionObject(new Uint8Array([1])), Object.prototype)]
    ];
    const clone = vi.spyOn(globalThis, 'structuredClone');

    try {
      for (const [label, wrapper] of wrappers) {
        const adapter: LiveRestTransport = {
          getProviders: vi.fn(),
          getAuthState: vi.fn(),
          listSessions: vi.fn(),
          getSessions: vi.fn(),
          getSession: vi.fn().mockResolvedValue(wrapper),
          getSessionMessages: vi.fn()
        };
        await expect(
          getLiveRestSessionForWorkspace(adapter, {}, LIVE_SESSION_FIXTURE.id)
        ).rejects.toMatchObject({ code: 'invalid-response' });
        expect(adapter.getSessionMessages, label).not.toHaveBeenCalled();
      }
      expect(clone).not.toHaveBeenCalled();
    } finally {
      clone.mockRestore();
    }
  });

  it('does not clone invalid details with expensive additive data', () => {
    const invalid = {
      ...LIVE_SESSION_FIXTURE,
      id: '../invalid-session',
      hostilePayload: 'x'.repeat(512 * 1024)
    } as unknown;
    const clone = vi.spyOn(globalThis, 'structuredClone');

    try {
      expect(captureLiveSessionProjection(invalid)).toBeUndefined();
      expect(clone).not.toHaveBeenCalled();
    } finally {
      clone.mockRestore();
    }
  });

  it('accepts a null-prototype projection while Object.prototype is safely polluted', async () => {
    const source = populateSessionObject(Object.create(null));
    let captured: ReturnType<typeof captureLiveSessionProjection>;
    await withObjectPrototypeValuePollution(
      {
        get: () => {
          throw new Error('inherited descriptor value must not be read');
        }
      },
      async () => {
        captured = captureLiveSessionProjection(source);
      }
    );
    expect(captured?.id).toBe(LIVE_SESSION_FIXTURE.id);
  });

  it('rejects inherited, accessor, Proxy, and descriptor-variant details before use', async () => {
    let inheritedReads = 0;
    const inheritedDetail = Object.create({
      get id(): string {
        inheritedReads += 1;
        return inheritedReads === 1 ? LIVE_SESSION_FIXTURE.id : 'foreign-session';
      }
    }) as Record<string, unknown>;
    for (const [key, value] of Object.entries(LIVE_SESSION_FIXTURE)) {
      if (key !== 'id') Object.defineProperty(inheritedDetail, key, { value, enumerable: true });
    }

    let accessorReads = 0;
    const accessorDetail = { ...LIVE_SESSION_FIXTURE };
    Object.defineProperty(accessorDetail, 'id', {
      configurable: true,
      enumerable: true,
      get: () => {
        accessorReads += 1;
        return accessorReads === 1 ? LIVE_SESSION_FIXTURE.id : 'foreign-session';
      }
    });

    let proxyReads = 0;
    const proxyDetail = new Proxy({ ...LIVE_SESSION_FIXTURE }, {
      get: (target, key, receiver) => {
        if (key === 'id') {
          proxyReads += 1;
          return proxyReads === 1 ? LIVE_SESSION_FIXTURE.id : 'foreign-session';
        }
        return Reflect.get(target, key, receiver);
      }
    });

    const descriptorDetail = { ...LIVE_SESSION_FIXTURE };
    Object.defineProperty(descriptorDetail, 'id', {
      configurable: true,
      enumerable: false,
      value: LIVE_SESSION_FIXTURE.id,
      writable: true
    });

    const variants = [inheritedDetail, accessorDetail, proxyDetail, descriptorDetail];
    for (const detail of variants) {
      const adapter: LiveRestTransport = {
        getProviders: vi.fn(),
        getAuthState: vi.fn(),
        listSessions: vi.fn(),
        getSessions: vi.fn(),
        getSession: vi.fn().mockResolvedValue(detail),
        getSessionMessages: vi.fn()
      };
      await expect(
        getLiveRestSessionForWorkspace(adapter, {}, LIVE_SESSION_FIXTURE.id)
      ).rejects.toMatchObject({ code: 'invalid-response' });
      expect(adapter.getSessionMessages).not.toHaveBeenCalled();
    }
    expect(inheritedReads).toBe(0);
    expect(accessorReads).toBe(0);
    expect(proxyReads).toBe(0);
  });

  it.each(['getter', 'data'] as const)(
    'rejects own accessor and Proxy details under Object.prototype.value %s pollution',
    async (pollution) => {
      let pollutedValueReads = 0;
      let accessorReads = 0;
      let proxyReads = 0;
      const accessorDetail = { ...LIVE_SESSION_FIXTURE };
      Object.defineProperty(accessorDetail, 'id', {
        configurable: true,
        enumerable: true,
        get: () => {
          accessorReads += 1;
          return LIVE_SESSION_FIXTURE.id;
        }
      });
      const proxyDetail = new Proxy({ ...LIVE_SESSION_FIXTURE }, {
        get: (target, key, receiver) => {
          if (key === 'id') {
            proxyReads += 1;
            return LIVE_SESSION_FIXTURE.id;
          }
          return Reflect.get(target, key, receiver);
        }
      });
      const details = [accessorDetail, proxyDetail];
      const previous = Reflect.getOwnPropertyDescriptor(Object.prototype, 'value');
      const descriptor: PropertyDescriptor =
        pollution === 'getter'
          ? {
              get: () => {
                pollutedValueReads += 1;
                return LIVE_SESSION_FIXTURE.id;
              }
            }
          : { value: LIVE_SESSION_FIXTURE.id, writable: true };

      const results: Array<{ status: 'resolved' | 'rejected'; error?: unknown }> = [];
      await withObjectPrototypeValuePollution(descriptor, async () => {
        for (const detail of details) {
          const adapter: LiveRestTransport = {
            getProviders: vi.fn(),
            getAuthState: vi.fn(),
            listSessions: vi.fn(),
            getSessions: vi.fn(),
            getSession: vi.fn().mockResolvedValue(detail),
            getSessionMessages: vi.fn()
          };
          try {
            await getLiveRestSessionForWorkspace(adapter, {}, LIVE_SESSION_FIXTURE.id);
            results.push({ status: 'resolved' });
          } catch (error) {
            results.push({ status: 'rejected', error });
          }
        }
      });

      expect(results).toHaveLength(details.length);
      for (const result of results) {
        expect(result).toMatchObject({ status: 'rejected', error: { code: 'invalid-response' } });
      }
      expect(Reflect.getOwnPropertyDescriptor(Object.prototype, 'value')).toEqual(previous);
      expect(pollutedValueReads).toBe(0);
      expect(accessorReads).toBe(0);
      expect(proxyReads).toBe(0);
    }
  );

  it('rejects oversized, wrong-media, malformed-UTF8, redirected, and non-success responses', async () => {
    const oversized = fetchSequence(response('{"providers":[]}'));
    await expect(
      createLiveRestTransport({ fetch: oversized.fetch, maxBodyBytes: 4 }).getProviders()
    ).rejects.toMatchObject({ code: 'body-too-large' });

    const oversizedChunk = scriptedBodyResponse([{ done: false, value: new Uint8Array(5) }]);
    const fromSpy = vi.spyOn(Uint8Array, 'from');
    await expect(
      createLiveRestTransport({
        fetch: fetchSequence(oversizedChunk.response).fetch,
        maxBodyBytes: 4
      }).getProviders()
    ).rejects.toMatchObject({ code: 'body-too-large' });
    expect(fromSpy).not.toHaveBeenCalled();
    expect(oversizedChunk.cancelCalls).toBe(1);
    fromSpy.mockRestore();

    const declaredOversized = scriptedBodyResponse([{ done: false, value: new Uint8Array(1) }], {
      'content-type': 'application/json',
      'content-length': '5'
    });
    await expect(
      createLiveRestTransport({
        fetch: fetchSequence(declaredOversized.response).fetch,
        maxBodyBytes: 4
      }).getProviders()
    ).rejects.toMatchObject({ code: 'body-too-large' });
    expect(declaredOversized.cancelCalls).toBe(1);

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

    const pendingWrongContentType = pendingBodyResponse({ 'content-type': 'text/plain' }, 200, 'pending');
    await expect(
      createLiveRestTransport({ fetch: fetchSequence(pendingWrongContentType.response).fetch }).getProviders()
    ).rejects.toMatchObject({ code: 'invalid-response' });
    expect(pendingWrongContentType.cancelCalls).toBe(1);

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

    const malformedUtf8 = scriptedBodyResponse(
      [
        { done: false, value: Uint8Array.of(0xff, 0xfe) },
        { done: true, value: undefined }
      ],
      {
        'content-type': 'application/json',
        'content-length': '2'
      }
    );
    await expect(
      createLiveRestTransport({ fetch: fetchSequence(malformedUtf8.response).fetch }).getProviders()
    ).rejects.toMatchObject({ code: 'malformed-json' });
    expect(malformedUtf8.cancelCalls).toBe(0);

    const nullBodyWithoutLength = nullBodyResponse(new TextEncoder().encode(rawProviderDiscovery()));
    await expect(
      createLiveRestTransport({ fetch: fetchSequence(nullBodyWithoutLength.response).fetch }).getProviders()
    ).rejects.toMatchObject({ code: 'invalid-response' });
    expect(nullBodyWithoutLength.arrayBufferCalls).toBe(0);

    const providerBytes = new TextEncoder().encode(rawProviderDiscovery());
    const shortStream = scriptedBodyResponse(
      [
        { done: false, value: providerBytes },
        { done: true, value: undefined }
      ],
      {
        'content-type': 'application/json',
        'content-length': String(providerBytes.byteLength + 1)
      }
    );
    await expect(
      createLiveRestTransport({ fetch: fetchSequence(shortStream.response).fetch }).getProviders()
    ).rejects.toMatchObject({ code: 'invalid-response' });

    const longStream = scriptedBodyResponse([{ done: false, value: providerBytes }], {
      'content-type': 'application/json',
      'content-length': String(providerBytes.byteLength - 1)
    });
    await expect(
      createLiveRestTransport({ fetch: fetchSequence(longStream.response).fetch }).getProviders()
    ).rejects.toMatchObject({ code: 'invalid-response' });
    expect(longStream.cancelCalls).toBe(1);

    const shortNullBody = nullBodyResponse(providerBytes, {
      'content-type': 'application/json',
      'content-length': String(providerBytes.byteLength + 1)
    });
    await expect(
      createLiveRestTransport({ fetch: fetchSequence(shortNullBody.response).fetch }).getProviders()
    ).rejects.toMatchObject({ code: 'invalid-response' });
    expect(shortNullBody.arrayBufferCalls).toBe(0);

    const longNullBody = nullBodyResponse(providerBytes, {
      'content-type': 'application/json',
      'content-length': String(providerBytes.byteLength - 1)
    });
    await expect(
      createLiveRestTransport({ fetch: fetchSequence(longNullBody.response).fetch }).getProviders()
    ).rejects.toMatchObject({ code: 'invalid-response' });
    expect(longNullBody.arrayBufferCalls).toBe(0);

    const redirectedResponse = response(rawProviderDiscovery());
    Object.defineProperty(redirectedResponse, 'redirected', { value: true });
    const redirected = fetchSequence(redirectedResponse);
    await expect(createLiveRestTransport({ fetch: redirected.fetch }).getProviders()).rejects.toMatchObject({
      code: 'redirect'
    });

    const semanticRedirect = fetchSequence(response(rawProviderDiscovery(), 302));
    await expect(
      createLiveRestTransport({ fetch: semanticRedirect.fetch }).getProviders()
    ).rejects.toMatchObject({ code: 'redirect' });

    const pendingRedirect = pendingBodyResponse({ 'content-type': 'application/json' }, 302, 'pending');
    await expect(
      createLiveRestTransport({ fetch: fetchSequence(pendingRedirect.response).fetch }).getProviders()
    ).rejects.toMatchObject({ code: 'redirect' });
    expect(pendingRedirect.cancelCalls).toBe(1);

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

    const pendingUnauthenticated = pendingBodyResponse(
      { 'content-type': 'application/json' },
      401,
      'pending'
    );
    await expect(
      createLiveRestTransport({ fetch: fetchSequence(pendingUnauthenticated.response).fetch }).getAuthState()
    ).rejects.toMatchObject({ code: 'unauthenticated', status: 401 });
    expect(pendingUnauthenticated.cancelCalls).toBe(1);

    const pendingServerError = pendingBodyResponse(
      { 'content-type': 'application/json' },
      500,
      'pending'
    );
    await expect(
      createLiveRestTransport({ fetch: fetchSequence(pendingServerError.response).fetch }).getProviders()
    ).rejects.toMatchObject({ code: 'http', status: 500 });
    expect(pendingServerError.cancelCalls).toBe(1);

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

    const pendingBody = pendingBodyResponse();
    const bodyController = new AbortController();
    const bodyAbortTransport = createLiveRestTransport({
      fetch: fetchSequence(pendingBody.response).fetch
    });
    const bodyAbort = bodyAbortTransport.getProviders(bodyController.signal);
    await Promise.resolve();
    bodyController.abort();
    await expect(bodyAbort).rejects.toMatchObject({ code: 'aborted' });
    expect(pendingBody.cancelCalls).toBe(1);

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
