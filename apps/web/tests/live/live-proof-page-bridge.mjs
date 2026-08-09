/** @typedef {Record<string, any>} BridgeEvent */
/** @typedef {Map<string, any>} BridgeProperties */
/** @typedef {{ allowEmpty?: boolean, pattern?: RegExp }} BoundedStringOptions */

/**
 * Install the live-proof observation boundary in the browser page. Dynamic
 * session/request/message values are parsed, compared, and signed here. Only
 * fixed operation projections, booleans, bounded counts, and page-produced
 * HMAC tags cross back to Playwright.
 *
 * The signing key is imported from page-local random bytes and is never
 * returned, serialized, or handed to a Node-side signer.
 *
 * @param {{ prompt: string, marker: string }} config
 */
export function installLiveProofPageBridge(config) {
  const MAX_QUEUE_EVENTS = 512;
  const MAX_PENDING_OBSERVATIONS = 512;
  const MAX_PENDING_CONTROL_REQUESTS = 128;
  const MAX_SOCKETS = 16;
  const MAX_FRAME_BYTES = 256 * 1024;
  const MAX_HISTORY_BYTES = 256 * 1024;
  const MAX_HISTORY_CHUNKS = 4096;
  const MAX_HISTORY_MESSAGES = 500;
  const MAX_HISTORY_DEPTH = 16;
  const MAX_HISTORY_CHILDREN = 128;
  const MAX_HISTORY_NODES = 4096;
  const MAX_ID_LENGTH = 256;
  const MAX_SESSION_ID_LENGTH = 128;
  const MAX_ROUTE_LENGTH = 256;
  const MAX_URL_LENGTH = 2048;
  const MAX_WS_TICKET_LENGTH = 512;
  const MAX_METHOD_LENGTH = 64;
  const MAX_EVENT_NAME_LENGTH = 96;
  const MAX_STATUS_LENGTH = 32;
  const MAX_TOOL_CALLS = 64;
  const MAX_TOOL_STRING_LENGTH = 8192;
  const MAX_PROMPT_LENGTH = 16 * 1024;
  const MAX_TIMESTAMP = 4_294_967_295;
  const HISTORY_TIMEOUT_MS = 30_000;
  const OBSERVATION_DRAIN_TIMEOUT_MS = 5_000;
  const HMAC_KEY_BYTES = 32;
  const HMAC_TAG_PATTERN = /^h1:[0-9a-f]{64}$/u;
  const SAFE_ID_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9._~:-]{0,254}[A-Za-z0-9])?$/u;
  const SAFE_SESSION_ID_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9._~-]{0,126}[A-Za-z0-9])?$/u;
  const SAFE_WS_TICKET_PATTERN = /^[A-Za-z0-9_-]+$/u;
  const FIXED_HTTP_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
  const FIXED_WS_OPERATIONS = new Set([
    'session.create',
    'session.resume',
    'prompt.submit',
    'session.interrupt',
    'approval.respond',
    'clarify.respond'
  ]);
  const FIXED_EVENT_NAMES = new Set([
    'gateway.ready',
    'session.info',
    'message.delta',
    'reasoning.delta',
    'thinking.delta',
    'message.complete',
    'tool.start',
    'tool.complete',
    'approval.request',
    'clarify.request',
    'error'
  ]);
  const FIXED_COMPLETION_STATUSES = new Set([
    'complete',
    'ok',
    'success',
    'error',
    'failed',
    'cancelled',
    'interrupted',
    'unknown'
  ]);
  const FIXED_ROUTE_NAMES = new Map([
    ['/auth/password-login', '/auth/password-login'],
    ['/auth/logout', '/auth/logout'],
    ['/api/auth/me', '/api/auth/me'],
    ['/api/auth/providers', '/api/auth/providers'],
    ['/api/auth/ws-ticket', '/api/auth/ws-ticket'],
    ['/api/sessions', '/api/sessions'],
    ['/api/sessions/search', '/api/sessions/search']
  ]);
  const PLAIN_OBJECT_PROTO = Object.prototype;
  const ARRAY_PROTO = Array.prototype;
  const NativeURL = globalThis.URL;

  /** @param {string} label @returns {never} */
  function fail(label) {
    throw new Error(`live proof page bridge ${label}`);
  }

  /** @param {string[]} first @param {string[]} second @returns {boolean} */
  function sameKeys(first, second) {
    if (first.length !== second.length) return false;
    for (let index = 0; index < first.length; index += 1) {
      if (first[index] !== second[index]) return false;
    }
    return true;
  }

  /**
   * @param {PropertyDescriptor | undefined} descriptor
   * @param {boolean} writable
   * @param {boolean} enumerable
   * @param {boolean} configurable
   * @returns {boolean}
   */
  function descriptorFlagsMatch(descriptor, writable, enumerable, configurable) {
    return (
      descriptor !== undefined &&
      Object.prototype.hasOwnProperty.call(descriptor, 'value') &&
      !Object.prototype.hasOwnProperty.call(descriptor, 'get') &&
      !Object.prototype.hasOwnProperty.call(descriptor, 'set') &&
      descriptor.writable === writable &&
      descriptor.enumerable === enumerable &&
      descriptor.configurable === configurable
    );
  }

  /**
   * @param {any} value
   * @param {string} key
   * @param {PropertyDescriptor} descriptor
   * @param {string} label
   */
  function descriptorValueIsStable(value, key, descriptor, label) {
    let first;
    let second;
    try {
      first = Reflect.get(value, key, value);
      second = Reflect.get(value, key, value);
    } catch {
      fail(`${label}.${String(key)} is unreadable`);
    }
    if (!Object.is(first, descriptor.value) || !Object.is(second, descriptor.value) || !Object.is(first, second)) {
      fail(`${label}.${String(key)} is unstable`);
    }
  }

  /**
   * Snapshot own data descriptors before reading any semantic fields. Repeating
   * the prototype, key, descriptor, and value reads rejects accessors, symbols,
   * mutable descriptor lies, and the hostile proxy patterns that can be detected
   * without mutating an object supplied by the page transport.
   */
  /**
   * @param {any} value
   * @param {string} label
   * @param {object} expectedPrototype
   * @param {number} maxKeys
   * @param {(key: string) => [boolean, boolean, boolean]} flagsForKey
   * @returns {BridgeProperties}
   */
  function descriptorSnapshot(
    value,
    label,
    expectedPrototype,
    maxKeys = MAX_HISTORY_CHILDREN,
    flagsForKey = (_key) => [true, true, true]
  ) {
    let firstPrototype;
    let secondPrototype;
    /** @type {string[]} */
    let firstKeys = [];
    /** @type {string[]} */
    let secondKeys = [];
    /** @type {Array<PropertyDescriptor | undefined>} */
    let firstDescriptors = [];
    /** @type {Array<PropertyDescriptor | undefined>} */
    let secondDescriptors = [];
    try {
      firstPrototype = Object.getPrototypeOf(value);
      firstKeys = /** @type {string[]} */ (Reflect.ownKeys(value));
      firstDescriptors = firstKeys.map((key) => Object.getOwnPropertyDescriptor(value, key));
      secondKeys = /** @type {string[]} */ (Reflect.ownKeys(value));
      secondDescriptors = secondKeys.map((key) => Object.getOwnPropertyDescriptor(value, key));
      secondPrototype = Object.getPrototypeOf(value);
    } catch {
      fail(`${label} is a proxy or cannot be inspected`);
    }
    if (
      firstPrototype !== expectedPrototype ||
      secondPrototype !== expectedPrototype ||
      firstPrototype !== secondPrototype ||
      firstKeys.length > maxKeys ||
      !sameKeys(firstKeys, secondKeys)
    ) {
      fail(`${label} has unstable or excessive own keys`);
    }
    const entries = new Map();
    for (let index = 0; index < firstKeys.length; index += 1) {
      const key = firstKeys[index];
      if (typeof key !== 'string') fail(`${label} has a symbol key`);
      const descriptor = firstDescriptors[index];
      const secondDescriptor = secondDescriptors[index];
      if (!descriptor || !secondDescriptor) fail(`${label}.${key} has an unsafe descriptor`);
      const [writable, enumerable, configurable] = flagsForKey(key);
      if (
        !descriptorFlagsMatch(descriptor, writable, enumerable, configurable) ||
        !descriptorFlagsMatch(secondDescriptor, writable, enumerable, configurable) ||
        !Object.is(descriptor.value, secondDescriptor.value)
      ) {
        fail(`${label}.${key} has an unsafe descriptor`);
      }
      descriptorValueIsStable(value, key, descriptor, label);
      entries.set(key, descriptor.value);
    }
    return entries;
  }

  /**
   * @param {any} value
   * @param {string} label
   * @param {string[]} allowedKeys
   * @param {string[]} requiredKeys
   * @param {number} maxKeys
   * @returns {BridgeProperties}
   */
  function strictObject(value, label, allowedKeys, requiredKeys = [], maxKeys = MAX_HISTORY_CHILDREN) {
    const properties = descriptorSnapshot(value, label, PLAIN_OBJECT_PROTO, maxKeys);
    const allowed = new Set(allowedKeys);
    for (const key of properties.keys()) {
      if (!allowed.has(key)) fail(`${label} has an unexpected key`);
    }
    for (const key of requiredKeys) {
      if (!properties.has(key)) fail(`${label} is missing ${key}`);
    }
    return properties;
  }

  /**
   * @param {any} value
   * @param {string} label
   * @param {number} maxLength
   * @returns {any[]}
   */
  function strictArray(value, label, maxLength = MAX_HISTORY_CHILDREN) {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== ARRAY_PROTO) {
      fail(`${label} is not a native array`);
    }
    const properties = descriptorSnapshot(
      value,
      label,
      ARRAY_PROTO,
      maxLength + 1,
      (key) => (key === 'length' ? [true, false, false] : [true, true, true])
    );
    if (!properties.has('length')) fail(`${label} is missing length`);
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
    if (
      !lengthDescriptor ||
      !Object.prototype.hasOwnProperty.call(lengthDescriptor, 'value') ||
      lengthDescriptor.value !== properties.get('length') ||
      lengthDescriptor.writable !== true ||
      lengthDescriptor.enumerable !== false ||
      lengthDescriptor.configurable !== false
    ) {
      fail(`${label} has an unsafe length descriptor`);
    }
    const length = properties.get('length');
    if (!Number.isSafeInteger(length) || length < 0 || length > maxLength) {
      fail(`${label} has an unsafe length`);
    }
    if (properties.size !== length + 1) fail(`${label} has holes or extra keys`);
    const values = [];
    for (let index = 0; index < length; index += 1) {
      const key = String(index);
      if (!properties.has(key)) fail(`${label} has a hole`);
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !descriptorFlagsMatch(descriptor, true, true, true) || !Object.is(descriptor.value, properties.get(key))) {
        fail(`${label}[${index}] has an unsafe descriptor`);
      }
      values.push(properties.get(key));
    }
    return values;
  }

  /**
   * @param {unknown} value
   * @param {number} maxLength
   * @param {string} label
   * @param {BoundedStringOptions} options
   * @returns {string}
   */
  function boundedString(value, maxLength, label, { allowEmpty = false, pattern } = {}) {
    if (typeof value !== 'string' || (!allowEmpty && value.length === 0) || value.length > maxLength) {
      fail(`${label} is not bounded`);
    }
    if (pattern && !pattern.test(value)) fail(`${label} is not canonical`);
    return value;
  }

  /** @param {unknown} value @param {string} label @returns {string} */
  function boundedTag(value, label = 'identity tag') {
    if (typeof value !== 'string' || !HMAC_TAG_PATTERN.test(value)) fail(`${label} is unsafe`);
    return value;
  }

  /** @param {unknown} value @returns {string | undefined} */
  function optionalTag(value) {
    return value === undefined ? undefined : boundedTag(value);
  }

  /** @param {unknown} value @param {string} label @returns {string} */
  function boundedSessionId(value, label = 'session identity') {
    return boundedString(value, MAX_SESSION_ID_LENGTH, label, { pattern: SAFE_SESSION_ID_PATTERN });
  }

  /** @param {unknown} value @param {string} label @returns {string} */
  function boundedRequestId(value, label = 'request identity') {
    return boundedString(value, MAX_ID_LENGTH, label, { pattern: SAFE_ID_PATTERN });
  }

  /** @param {unknown} value @returns {number} */
  function boundedTimestamp(value) {
    if (
      typeof value !== 'number' ||
      !Number.isSafeInteger(value) ||
      Object.is(value, -0) ||
      value < 0 ||
      value > MAX_TIMESTAMP
    ) {
      fail('history timestamp is invalid');
    }
    return value;
  }

  /** @param {unknown} value @returns {number} */
  function boundedMessageId(value) {
    if (
      typeof value !== 'number' ||
      !Number.isSafeInteger(value) ||
      Object.is(value, -0) ||
      value <= 0
    ) {
      fail('history message identity is invalid');
    }
    return value;
  }

  /** @param {unknown} value @param {string} label @param {number} max @returns {number} */
  function boundedCount(value, label, max = MAX_HISTORY_MESSAGES) {
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || value > max) {
      fail(`${label} is invalid`);
    }
    return value;
  }

  /**
   * @param {BridgeProperties} properties
   * @param {string} rawKey
   * @param {string} canonicalKey
   * @param {(value: any) => any} parser
   * @returns {{ present: boolean, value?: any }}
   */
  function readOptionalAlias(properties, rawKey, canonicalKey, parser) {
    const hasRaw = properties.has(rawKey);
    const hasCanonical = rawKey !== canonicalKey && properties.has(canonicalKey);
    if (hasRaw && hasCanonical) fail(`${canonicalKey} is ambiguous`);
    if (!hasRaw && !hasCanonical) return { present: false };

    const candidate = properties.get(hasRaw ? rawKey : canonicalKey);
    if (hasRaw && rawKey !== canonicalKey) return { present: true, value: parser(candidate) };
    // Timestamp uses one wire key in both forms. A number is the raw field; an
    // object is the reviewed {present,value} marker. Explicit null remains a
    // present raw value and is rejected by the timestamp parser.
    if (rawKey === canonicalKey && (candidate === null || typeof candidate !== 'object' || Array.isArray(candidate))) {
      return { present: true, value: parser(candidate) };
    }

    const wrapper = strictObject(
      candidate,
      canonicalKey,
      ['present', 'value'],
      ['present'],
      2
    );
    const present = wrapper.get('present');
    if (present === false && wrapper.size === 1) return { present: false };
    if (present === true && wrapper.size === 2) {
      return { present: true, value: parser(wrapper.get('value')) };
    }
    fail(`${canonicalKey} optional marker is malformed`);
  }

  /** @param {any} value @returns {any} */
  function parseToolCalls(value) {
    if (value === null) return null;
    const calls = strictArray(value, 'history tool calls', MAX_TOOL_CALLS);
    return calls.map((call, index) => {
      const object = strictObject(call, `history tool call ${index}`, ['id', 'function'], ['id', 'function'], 2);
      const functionObject = strictObject(
        object.get('function'),
        `history tool call ${index}.function`,
        ['name', 'arguments'],
        ['name', 'arguments'],
        2
      );
      return {
        id: boundedRequestId(object.get('id'), 'tool call identity'),
        function: {
          name: boundedString(functionObject.get('name'), 512, 'tool name'),
          arguments: boundedString(functionObject.get('arguments'), MAX_TOOL_STRING_LENGTH, 'tool arguments', {
            allowEmpty: true
          })
        }
      };
    });
  }

  /** @param {any} value @returns {any} */
  function canonicalMessage(value) {
    const properties = strictObject(
      value,
      'history message',
      [
        'id',
        'role',
        'content',
        'tool_calls',
        'tool_name',
        'tool_call_id',
        'timestamp',
        'toolCalls',
        'toolName',
        'toolCallId'
      ],
      ['id', 'role', 'content']
    );
    const id = boundedMessageId(properties.get('id'));
    const role = properties.get('role');
    if (role !== 'user' && role !== 'assistant' && role !== 'system' && role !== 'tool') {
      fail('history message role is invalid');
    }
    const content = properties.get('content');
    if (content !== null && (typeof content !== 'string' || content.length > MAX_TOOL_STRING_LENGTH)) {
      fail('history message content is invalid');
    }
    return {
      id,
      role,
      content,
      toolCalls: readOptionalAlias(properties, 'tool_calls', 'toolCalls', parseToolCalls),
      toolName: readOptionalAlias(properties, 'tool_name', 'toolName', (item) =>
        item === null ? null : boundedString(item, 512, 'tool name')
      ),
      toolCallId: readOptionalAlias(properties, 'tool_call_id', 'toolCallId', (item) =>
        item === null ? null : boundedRequestId(item, 'tool call identity')
      ),
      timestamp: readOptionalAlias(properties, 'timestamp', 'timestamp', boundedTimestamp)
    };
  }

  /** @param {any} value @returns {any} */
  function parseHistoryResponse(value) {
    const response = strictObject(
      value,
      'history response',
      ['session_id', 'messages', 'pagination'],
      ['session_id', 'messages', 'pagination'],
      3
    );
    const sessionId = boundedSessionId(response.get('session_id'));
    const rawMessages = strictArray(response.get('messages'), 'history messages', MAX_HISTORY_MESSAGES);
    if (rawMessages.length > MAX_HISTORY_MESSAGES) fail('history message count exceeded its bound');
    const pagination = strictObject(
      response.get('pagination'),
      'history pagination',
      ['limit', 'offset', 'returned'],
      ['limit', 'offset', 'returned'],
      3
    );
    const limit = boundedCount(pagination.get('limit'), 'history pagination limit');
    const offset = boundedCount(pagination.get('offset'), 'history pagination offset');
    const returned = boundedCount(pagination.get('returned'), 'history pagination returned');
    const messages = rawMessages.map(canonicalMessage);
    for (let index = 1; index < messages.length; index += 1) {
      if (messages[index].id <= messages[index - 1].id) fail('history message ordering is invalid');
    }
    const historyComplete =
      limit === MAX_HISTORY_MESSAGES &&
      offset === 0 &&
      returned === messages.length &&
      messages.length < MAX_HISTORY_MESSAGES;
    return { sessionId, messages, historyComplete };
  }

  /** @param {any} value @param {string} label @returns {BridgeProperties | undefined} */
  function parsePayloadProperties(value, label) {
    if (value === null || typeof value !== 'object') return undefined;
    if (Array.isArray(value)) return undefined;
    return descriptorSnapshot(value, label, PLAIN_OBJECT_PROTO, MAX_HISTORY_CHILDREN);
  }

  /** @param {any} payload @returns {string} */
  function fixedStatusFromPayload(payload) {
    const properties = parsePayloadProperties(payload, 'message completion payload');
    if (!properties) return 'unknown';
    let candidate;
    if (properties.has('status') && properties.get('status') !== null && properties.get('status') !== undefined) {
      candidate = properties.get('status');
    } else if (properties.has('outcome') && properties.get('outcome') !== null && properties.get('outcome') !== undefined) {
      candidate = properties.get('outcome');
    }
    if (candidate === undefined) return 'unknown';
    boundedString(candidate, MAX_STATUS_LENGTH, 'completion status');
    if (!FIXED_COMPLETION_STATUSES.has(candidate)) fail('completion status is not approved');
    return candidate;
  }

  /** @param {any} value @param {string} expected @returns {boolean} */
  function hasExactText(value, expected) {
    const pending = [{ value, depth: 0 }];
    let inspected = 0;
    while (pending.length > 0) {
      const current = pending.pop();
      if (!current) continue;
      const candidate = current.value;
      const depth = current.depth;
      inspected += 1;
      if (inspected > MAX_HISTORY_NODES) fail('event payload exceeded its inspection bound');
      if (typeof candidate === 'string') {
        if (candidate === expected) return true;
        continue;
      }
      if (candidate === null || typeof candidate !== 'object' || depth >= MAX_HISTORY_DEPTH) continue;
      if (Array.isArray(candidate)) {
        const values = strictArray(candidate, 'event payload array', MAX_HISTORY_CHILDREN);
        for (let index = values.length - 1; index >= 0; index -= 1) {
          pending.push({ value: values[index], depth: depth + 1 });
        }
        continue;
      }
      const properties = descriptorSnapshot(candidate, 'event payload object', PLAIN_OBJECT_PROTO, MAX_HISTORY_CHILDREN);
      const values = [...properties.values()];
      for (let index = values.length - 1; index >= 0; index -= 1) {
        pending.push({ value: values[index], depth: depth + 1 });
      }
    }
    return false;
  }

  /** @param {unknown} text @returns {Record<string, any> | undefined} */
  function parseFrameText(text) {
    if (typeof text !== 'string' || text.length === 0 || text.length > MAX_FRAME_BYTES) return undefined;
    if (new TextEncoder().encode(text).byteLength > MAX_FRAME_BYTES) return undefined;
    try {
      const parsed = JSON.parse(text);
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined;
      return parsed;
    } catch {
      return undefined;
    }
  }

  /** @param {any} payload @returns {Promise<Record<string, any> | undefined>} */
  async function parseFrame(payload) {
    let text;
    if (typeof payload === 'string') {
      text = payload;
    } else if (typeof Blob === 'function' && payload instanceof Blob) {
      if (!Number.isSafeInteger(payload.size) || payload.size > MAX_FRAME_BYTES) return undefined;
      text = await payload.text();
    } else if (payload instanceof ArrayBuffer) {
      if (payload.byteLength > MAX_FRAME_BYTES) return undefined;
      text = new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(payload));
    } else if (ArrayBuffer.isView(payload)) {
      if (payload.byteLength > MAX_FRAME_BYTES) return undefined;
      text = new TextDecoder('utf-8', { fatal: true }).decode(
        new Uint8Array(payload.buffer, payload.byteOffset, payload.byteLength)
      );
    } else {
      return undefined;
    }
    if (typeof text !== 'string' || text.length > MAX_FRAME_BYTES) return undefined;
    return parseFrameText(text);
  }

  /** @param {unknown} pathname @returns {string | undefined} */
  function normalizeRoute(pathname) {
    if (typeof pathname !== 'string' || pathname.length === 0 || pathname.length > MAX_ROUTE_LENGTH) return undefined;
    const fixed = FIXED_ROUTE_NAMES.get(pathname);
    if (fixed) return fixed;
    const segments = pathname.split('/');
    if (
      segments.length === 5 &&
      segments[1] === 'api' &&
      segments[2] === 'sessions' &&
      segments[3].length > 0 &&
      segments[3].length <= MAX_ID_LENGTH &&
      segments[4] === 'messages'
    ) {
      return '/api/sessions/:sessionId/messages';
    }
    if (
      segments.length === 4 &&
      segments[1] === 'api' &&
      segments[2] === 'sessions' &&
      segments[3].length > 0 &&
      segments[3].length <= MAX_ID_LENGTH
    ) {
      return '/api/sessions/:sessionId';
    }
    return undefined;
  }

  /** @param {unknown} url @returns {string | undefined} */
  function trackedRoute(url) {
    if (typeof url !== 'string' || url.length === 0 || url.length > MAX_URL_LENGTH) return undefined;
    try {
      const parsed = new NativeURL(url, location.href);
      if (parsed.origin !== location.origin) return undefined;
      return normalizeRoute(parsed.pathname);
    } catch {
      return undefined;
    }
  }

  /** @param {unknown} value @param {string} label @returns {string} */
  function fixedMethod(value, label = 'HTTP method') {
    if (value === undefined) return 'GET';
    const method = boundedString(value, MAX_METHOD_LENGTH, label).toUpperCase();
    if (!FIXED_HTTP_METHODS.has(method)) fail(`${label} is not approved`);
    return method;
  }

  /** @param {any} input @param {any} init @returns {string | undefined} */
  function readNativeMethod(input, init) {
    if (init !== undefined && init !== null) {
      if (typeof init !== 'object' && typeof init !== 'function') return undefined;
      const properties = descriptorSnapshot(init, 'fetch init', PLAIN_OBJECT_PROTO, 32);
      if (properties.has('method')) return fixedMethod(properties.get('method'));
    }
    if (typeof Request === 'function' && input instanceof Request) {
      return fixedMethod(input.method);
    }
    return 'GET';
  }

  /** @param {any} input @param {any} init @returns {{ route: string, method: string } | undefined} */
  function requestInfo(input, init) {
    let url;
    try {
      if (typeof input === 'string') {
        url = input;
      } else if (typeof NativeURL === 'function' && input instanceof NativeURL) {
        url = input.href;
      } else if (typeof Request === 'function' && input instanceof Request) {
        url = input.url;
      } else {
        return undefined;
      }
      const route = trackedRoute(url);
      if (!route) return undefined;
      const method = readNativeMethod(input, init);
      if (!method) return undefined;
      return { route, method };
    } catch {
      return undefined;
    }
  }

  /**
   * @param {BridgeProperties} properties
   * @param {string} rawKey
   * @param {string} camelKey
   * @param {string} label
   * @param {RegExp} pattern
   * @returns {string | undefined}
   */
  function readOptionalString(properties, rawKey, camelKey, label, pattern = SAFE_ID_PATTERN) {
    const hasRaw = properties.has(rawKey);
    const hasCamel = properties.has(camelKey);
    if (hasRaw && hasCamel) fail(`${label} is ambiguous`);
    const value = hasRaw ? properties.get(rawKey) : hasCamel ? properties.get(camelKey) : undefined;
    if (value === undefined || value === null || value === '') return undefined;
    return boundedString(value, MAX_ID_LENGTH, label, { pattern });
  }

  /** @param {any} frame @returns {any} */
  function parseSentFrame(frame) {
    const properties = strictObject(
      frame,
      'sent WebSocket frame',
      ['jsonrpc', 'id', 'method', 'params'],
      ['jsonrpc', 'method'],
      4
    );
    if (properties.get('jsonrpc') !== '2.0') fail('sent WebSocket frame version is invalid');
    const method = boundedString(properties.get('method'), MAX_METHOD_LENGTH, 'WebSocket operation');
    if (!FIXED_WS_OPERATIONS.has(method)) return undefined;
    let requestId;
    if (properties.has('id')) {
      const candidate = properties.get('id');
      if (candidate !== null) requestId = boundedRequestId(candidate);
    }
    const params = properties.has('params') ? properties.get('params') : undefined;
    return { method, requestId, params };
  }

  /** @param {unknown} candidate @returns {string} */
  function candidateWebSocketHref(candidate) {
    try {
      if (typeof candidate === 'string') return candidate;
      if (typeof NativeURL === 'function' && candidate instanceof NativeURL) return candidate.href;
    } catch {
      // The raw candidate stays page-local; callers receive only a fixed failure.
    }
    fail('WebSocket URL is not approved');
  }

  /** @param {unknown} candidate @returns {string} */
  function validateWebSocketUrl(candidate) {
    const href = candidateWebSocketHref(candidate);
    if (
      href.length === 0 ||
      href.length > MAX_URL_LENGTH ||
      href.includes('%') ||
      href.includes('\\') ||
      href.includes('#') ||
      href.includes('@')
    ) {
      fail('WebSocket URL is not approved');
    }

    let page;
    let parsed;
    try {
      page = new NativeURL(location.href);
      parsed = new NativeURL(href, page.href);
    } catch {
      fail('WebSocket URL is not approved');
    }

    const pageSecurity = page.protocol === 'http:' ? 'http' : page.protocol === 'https:' ? 'https' : undefined;
    const socketSecurity = parsed.protocol === 'ws:' ? 'http' : parsed.protocol === 'wss:' ? 'https' : undefined;
    if (!pageSecurity || !socketSecurity || pageSecurity !== socketSecurity) {
      fail('WebSocket URL is not approved');
    }
    if (parsed.username !== '' || parsed.password !== '' || parsed.hash !== '') {
      fail('WebSocket URL is not approved');
    }
    if (parsed.hostname !== page.hostname) {
      fail('WebSocket URL is not approved');
    }
    const pagePort = page.port || (page.protocol === 'http:' ? '80' : '443');
    const socketPort = parsed.port || (parsed.protocol === 'ws:' ? '80' : '443');
    if (pagePort !== socketPort || parsed.pathname !== '/api/ws') {
      fail('WebSocket URL is not approved');
    }

    const rawQuery = parsed.search.startsWith('?') ? parsed.search.slice(1) : '';
    const queryParts = rawQuery.split('&');
    if (queryParts.length !== 1) fail('WebSocket URL is not approved');
    const separator = queryParts[0].indexOf('=');
    if (separator <= 0) fail('WebSocket URL is not approved');
    const key = queryParts[0].slice(0, separator);
    const ticket = queryParts[0].slice(separator + 1);
    if (
      key !== 'ticket' ||
      ticket.length === 0 ||
      ticket.length > MAX_WS_TICKET_LENGTH ||
      !SAFE_WS_TICKET_PATTERN.test(ticket)
    ) {
      fail('WebSocket URL is not approved');
    }

    // Return only the page-local normalized URL. The ticket and original URL
    // never enter a projection or an error message.
    return parsed.href;
  }

  /** @param {any} value @param {string} label @param {{ nodes: number }} state @param {number} depth */
  function validateBoundedResponseValue(value, label, state, depth = 0) {
    state.nodes += 1;
    if (state.nodes > MAX_HISTORY_NODES || depth > MAX_HISTORY_DEPTH) {
      fail(`${label} exceeded its bound`);
    }
    if (value === null || typeof value === 'boolean') return;
    if (typeof value === 'string') {
      boundedString(value, MAX_FRAME_BYTES, label, { allowEmpty: true });
      return;
    }
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) fail(`${label} is invalid`);
      return;
    }
    if (Array.isArray(value)) {
      for (const child of strictArray(value, `${label} array`, MAX_HISTORY_CHILDREN)) {
        validateBoundedResponseValue(child, label, state, depth + 1);
      }
      return;
    }
    if (typeof value !== 'object') fail(`${label} is invalid`);
    const properties = descriptorSnapshot(value, `${label} object`, PLAIN_OBJECT_PROTO, MAX_HISTORY_CHILDREN);
    for (const [key, child] of properties) {
      boundedString(key, MAX_ROUTE_LENGTH, `${label} key`, { allowEmpty: false });
      validateBoundedResponseValue(child, label, state, depth + 1);
    }
  }

  /** @param {any} value @param {string} label @returns {boolean} */
  function validResponseResult(value, label) {
    if (value === undefined) return false;
    validateBoundedResponseValue(value, label, { nodes: 0 });
    return true;
  }

  /** @param {any} frame @returns {any} */
  function parseEventFrame(frame) {
    const root = descriptorSnapshot(frame, 'received WebSocket frame', PLAIN_OBJECT_PROTO, MAX_HISTORY_CHILDREN);
    if (root.get('jsonrpc') !== '2.0') fail('received WebSocket frame version is invalid');
    if (root.has('method')) {
      const event = strictObject(
        frame,
        'received event envelope',
        ['jsonrpc', 'method', 'params'],
        ['jsonrpc', 'method', 'params'],
        3
      );
      if (event.get('method') !== 'event') return undefined;
      const params = strictObject(
        event.get('params'),
        'event envelope',
        [
          'type',
          'session_id',
          'sessionId',
          'request_id',
          'requestId',
          'sequence',
          'payload',
          'approval_id',
          'approvalId',
          'clarification_id',
          'clarificationId'
        ],
        ['type'],
        MAX_HISTORY_CHILDREN
      );
      const type = boundedString(params.get('type'), MAX_EVENT_NAME_LENGTH, 'event name');
      if (!FIXED_EVENT_NAMES.has(type)) fail('event name is not approved');
      const sessionId = readOptionalString(params, 'session_id', 'sessionId', 'event session identity', SAFE_SESSION_ID_PATTERN);
      const requestId =
        type === 'message.delta' || type === 'message.complete' || type === 'error'
          ? undefined
          : readOptionalString(params, 'request_id', 'requestId', 'event request identity', SAFE_ID_PATTERN);
      const payload = params.has('payload') ? params.get('payload') : null;
      return { kind: 'event', type, sessionId, requestId, payload };
    }
    if (!root.has('id')) return undefined;
    const responseId = root.get('id');
    if (responseId === null) return undefined;
    const boundedResponseId = boundedRequestId(responseId, 'response identity');
    if (root.has('error')) {
      const errorResponse = strictObject(
        frame,
        'received error response',
        ['jsonrpc', 'id', 'error'],
        ['jsonrpc', 'id', 'error'],
        3
      );
      validateBoundedResponseValue(errorResponse.get('error'), 'response error', { nodes: 0 });
      return { kind: 'response', responseId: boundedResponseId, acknowledgement: false };
    }
    if (!root.has('result')) fail('received response has no result');
    const successResponse = strictObject(
      frame,
      'received success response',
      ['jsonrpc', 'id', 'result'],
      ['jsonrpc', 'id', 'result'],
      3
    );
    return {
      kind: 'response',
      responseId: boundedResponseId,
      result: successResponse.get('result'),
      acknowledgement: validResponseResult(successResponse.get('result'), 'response result')
    };
  }

  /** @returns {Promise<CryptoKey>} */
  async function importPageLocalHmacKey() {
    const keyBytes = new Uint8Array(HMAC_KEY_BYTES);
    globalThis.crypto.getRandomValues(keyBytes);
    try {
      return await globalThis.crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
      );
    } finally {
      keyBytes.fill(0);
    }
  }

  /** @param {any} key @returns {boolean} */
  function approvedHmacKey(key) {
    if (key === null || typeof key !== 'object') return false;
    if (key.type !== 'secret' || key.extractable !== false) return false;
    if (key.algorithm?.name !== 'HMAC' || key.algorithm.hash?.name !== 'SHA-256' || key.algorithm.length !== 256) {
      return false;
    }
    const usages = key.usages;
    return Array.isArray(usages) && usages.length === 1 && usages[0] === 'sign';
  }


    const configProperties = strictObject(config, 'bridge configuration', ['prompt', 'marker'], ['prompt', 'marker'], 2);
    const prompt = boundedString(configProperties.get('prompt'), MAX_PROMPT_LENGTH, 'prompt', { allowEmpty: false });
    const marker = boundedString(configProperties.get('marker'), MAX_TOOL_STRING_LENGTH, 'marker', { allowEmpty: false });
    const keyPromise = importPageLocalHmacKey();
    /** @type {BridgeEvent[]} */
    const queue = [];
    /** @type {Set<any>} */
    const sockets = new Set();
    /** @type {Map<string, string>} */
    const controlRequests = new Map();
    /** @type {Promise<void>} */
    let operationTail = Promise.resolve();
    let pendingOperations = 0;
    let bridgeFailure = false;
    let observationStopped = false;
    /** @type {string | undefined} */
    let canonicalSessionId;
    /** @type {string | undefined} */
    let canonicalSessionTag;
    /** @type {string | undefined} */
    let promptRequestTag;
    /** @type {string | undefined} */
    let promptSessionTag;
    /** @type {number | undefined} */
    let preFence;
    /** @type {string | undefined} */
    let preHistoryProjectionTag;
    let websocketOpenCount = 0;
    let websocketCloseCount = 0;

    /** @param {BridgeEvent} event */
    const push = (event) => {
      if (observationStopped) fail('observation is stopped');
      if (queue.length >= MAX_QUEUE_EVENTS) fail('projection queue exceeded its bound');
      queue.push(Object.freeze(event));
    };

    /** @param {() => Promise<void> | void} operation */
    const enqueue = (operation) => {
      if (observationStopped) return;
      if (pendingOperations >= MAX_PENDING_OBSERVATIONS) {
        bridgeFailure = true;
        return;
      }
      pendingOperations += 1;
      operationTail = operationTail
        .then(operation)
        .catch(() => {
          bridgeFailure = true;
        })
        .finally(() => {
          pendingOperations -= 1;
        });
    };

    /** @param {unknown} value @returns {Promise<string>} */
    const identityTag = async (value) => {
      const raw = boundedRequestId(value, 'identity');
      const key = await keyPromise;
      if (!approvedHmacKey(key)) fail('HMAC key is not an approved nonextractable SHA-256 key');
      const input = new TextEncoder().encode(`identity\0${raw}`);
      const bytes = await globalThis.crypto.subtle.sign('HMAC', key, input);
      const hex = Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, '0')).join('');
      return boundedTag(`h1:${hex}`);
    };

    /** @param {any[]} canonicalMessages @returns {Promise<string>} */
    const messageProjectionTag = async (canonicalMessages) => {
      const serialized = JSON.stringify(canonicalMessages);
      const encoded = new TextEncoder().encode(serialized);
      if (encoded.byteLength > MAX_HISTORY_BYTES) fail('history projection exceeded its bound');
      const key = await keyPromise;
      if (!approvedHmacKey(key)) fail('HMAC key is not an approved nonextractable SHA-256 key');
      const bytes = await globalThis.crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`message-projection-sequence\0${serialized}`));
      const hex = Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, '0')).join('');
      return boundedTag(`h1:${hex}`, 'history projection tag');
    };

    /** @param {any} payload @returns {Promise<void>} */
    const inspectSentFrame = async (payload) => {
      const frame = await parseFrame(payload);
      if (!frame) return;
      const parsed = parseSentFrame(frame);
      if (!parsed) return;
      const requestTag = parsed.requestId === undefined ? undefined : await identityTag(parsed.requestId);
      let sessionTag;
      if (parsed.method === 'session.create' || parsed.method === 'session.resume' || parsed.method === 'prompt.submit') {
        const params = strictObject(
          parsed.params,
          `${parsed.method} parameters`,
          parsed.method === 'prompt.submit' ? ['session_id', 'text'] : ['session_id'],
          parsed.method === 'prompt.submit' ? ['session_id', 'text'] : parsed.method === 'session.resume' ? ['session_id'] : [],
          4
        );
        if (params.has('session_id')) {
          const sessionId = boundedSessionId(params.get('session_id'));
          sessionTag = await identityTag(sessionId);
          if (parsed.method === 'session.resume') {
            canonicalSessionId = sessionId;
            canonicalSessionTag = sessionTag;
            push({ kind: 'session.action', method: parsed.method, requestTag, sessionTag });
          }
        }
        if (parsed.method === 'prompt.submit') {
          const text = boundedString(params.get('text'), MAX_PROMPT_LENGTH, 'prompt frame text', { allowEmpty: false });
          promptRequestTag = requestTag;
          promptSessionTag = sessionTag;
          push({
            kind: 'prompt.submit',
            requestTag,
            sessionTag,
            promptMatches: text === prompt
          });
        }
      }
      push({ kind: 'ws.sent', method: parsed.method, requestTag, sessionTag });
      if (parsed.method === 'session.create' || parsed.method === 'session.resume') {
        if (parsed.requestId === undefined) return;
        if (controlRequests.has(parsed.requestId) || controlRequests.size >= MAX_PENDING_CONTROL_REQUESTS) {
          fail('control request table exceeded its bound');
        }
        controlRequests.set(parsed.requestId, parsed.method);
      }
    };

    /** @param {any} payload @returns {Promise<void>} */
    const inspectReceivedFrame = async (payload) => {
      const frame = await parseFrame(payload);
      if (!frame) return;
      const parsed = parseEventFrame(frame);
      if (!parsed) return;
      if (parsed.kind === 'event') {
        const sessionTag = parsed.sessionId === undefined ? undefined : await identityTag(parsed.sessionId);
        const requestTag = parsed.requestId === undefined ? undefined : await identityTag(parsed.requestId);
        push({ kind: 'ws.received', event: parsed.type, requestTag, sessionTag });
        if (parsed.type === 'gateway.ready') {
          push({ kind: 'gateway.ready', sessionTag });
        } else if (parsed.type === 'message.delta') {
          push({ kind: 'message.delta', sessionTag });
        } else if (parsed.type === 'message.complete') {
          push({
            kind: 'message.complete',
            sessionTag,
            status: fixedStatusFromPayload(parsed.payload),
            markerMatches: hasExactText(parsed.payload, marker)
          });
        }
        return;
      }

      if (parsed.responseId === undefined) return;
      const requestTag = await identityTag(parsed.responseId);
      push({
        kind: 'ws.received',
        event: 'response',
        requestTag,
        acknowledgement: parsed.acknowledgement === true
      });
      const controlMethod = controlRequests.get(parsed.responseId);
      try {
        if (controlMethod === 'session.create') {
          if (parsed.acknowledgement !== true) return;
          const result = strictObject(
            parsed.result,
            'session.create response',
            ['session_id', 'stored_session_id', 'info'],
            ['session_id', 'stored_session_id'],
            3
          );
          const sessionId = boundedSessionId(result.get('session_id'));
          const storedSessionId = boundedSessionId(result.get('stored_session_id'));
          canonicalSessionId = storedSessionId;
          canonicalSessionTag = await identityTag(storedSessionId);
          push({
            kind: 'session.action',
            method: controlMethod,
            requestTag,
            sessionTag: await identityTag(sessionId),
            storedSessionTag: canonicalSessionTag
          });
        }
      } finally {
        controlRequests.delete(parsed.responseId);
      }
    };

    const nativeFetch = globalThis.fetch.bind(globalThis);
    globalThis.fetch = async (input, init) => {
      const info = requestInfo(input, init);
      if (info) push({ kind: 'http.request', method: info.method, route: info.route });
      try {
        const response = await nativeFetch(input, init);
        if (info) {
          const status = response.status;
          if (!Number.isInteger(status) || status < 100 || status > 599) fail('HTTP response status is invalid');
          push({ kind: 'http.response', method: info.method, route: info.route, status });
        }
        return response;
      } catch (error) {
        if (info) push({ kind: 'http.failure', method: info.method, route: info.route });
        throw error;
      }
    };

    const NativeWebSocket = globalThis.WebSocket;
    if (typeof NativeWebSocket !== 'function') fail('WebSocket is unavailable');

    /** @param {any} socket */
    const closeConstructedSocket = (socket) => {
      try {
        if (socket !== null && socket !== undefined && typeof socket.close === 'function') {
          socket.close(1000, 'live proof observation setup failed');
        } else if (socket !== null && socket !== undefined && typeof socket.cancel === 'function') {
          void Promise.resolve(socket.cancel()).catch(() => undefined);
        }
      } catch {
        // Native close/cancel diagnostics stay page-local and are never retained.
      }
    };

    const TrackedWebSocket = new Proxy(NativeWebSocket, {
      construct(target, argumentsList, newTarget) {
        // Prove the page origin, security mode, route, and opaque ticket before
        // creating or observing a socket. Invalid sockets never enter the set,
        // queue, or close lifecycle, and the validator emits no raw URL text.
        const approvedHref = validateWebSocketUrl(argumentsList[0]);
        if (sockets.size >= MAX_SOCKETS) fail('WebSocket count exceeded its bound');
        // This is a lifetime bound, not an active-socket bound. Check it before
        // native construction so the 513th approved ticket is never sent to a
        // real server when the observation budget is exhausted.
        if (websocketOpenCount >= MAX_QUEUE_EVENTS) fail('WebSocket open count exceeded its bound');
        const constructorArguments = [approvedHref, ...argumentsList.slice(1)];
        let socket;
        try {
          socket = Reflect.construct(target, constructorArguments, newTarget);
        } catch {
          // Do not let a native constructor diagnostic echo the validated URL or
          // opaque ticket beyond the page realm.
          fail('WebSocket construction failed');
        }

        let registered = false;
        try {
          sockets.add(socket);
          registered = true;
          const nativeSend = socket.send.bind(socket);
          Object.defineProperty(socket, 'send', {
            configurable: false,
            enumerable: false,
            writable: false,
            /** @type {(payload: any) => any} */
            value(payload) {
              enqueue(() => inspectSentFrame(payload));
              return nativeSend(payload);
            }
          });
          socket.addEventListener('message', (/** @type {any} */ event) => {
            enqueue(() => inspectReceivedFrame(event.data));
          });
          socket.addEventListener(
            'close',
            () => {
              if (websocketCloseCount >= MAX_QUEUE_EVENTS) {
                bridgeFailure = true;
                return;
              }
              websocketCloseCount += 1;
              sockets.delete(socket);
            },
            { once: true }
          );
          push({
            kind: 'ws.open',
            route: '/api/ws',
            ticketOnly: true,
            originBound: true
          });
          websocketOpenCount += 1;
          return socket;
        } catch {
          if (registered) {
            try {
              sockets.delete(socket);
            } catch {
              // Cleanup remains best effort and never exposes source diagnostics.
            }
          }
          closeConstructedSocket(socket);
          fail('WebSocket observation setup failed');
        }
      }
    });
    Object.defineProperty(globalThis, 'WebSocket', {
      configurable: true,
      enumerable: false,
      writable: true,
      value: TrackedWebSocket
    });

    /** @param {any} response @param {AbortController} controller @param {number} deadline @returns {Promise<any>} */
    async function readBoundedJson(response, controller, deadline) {
      if (response === null || typeof response !== 'object' || response.body === null || typeof response.body?.getReader !== 'function') {
        controller.abort();
        fail('history response body is not streamable');
      }
      const contentLength = response.headers?.get?.('content-length');
      if (contentLength !== null && contentLength !== undefined) {
        if (!/^(?:0|[1-9][0-9]*)$/u.test(contentLength)) {
          controller.abort();
          fail('history response length is invalid');
        }
        const declaredLength = Number(contentLength);
        if (!Number.isSafeInteger(declaredLength) || declaredLength > MAX_HISTORY_BYTES) {
          controller.abort();
          fail('history response exceeded its bound');
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
        void Promise.resolve(reader.cancel()).catch(() => undefined);
      };
      const readNextChunk = async () => {
        const remaining = deadline - Date.now();
        if (remaining <= 0) {
          cancelReader();
          controller.abort();
          fail('history transport timed out');
        }
        let timer;
        const deadlinePromise = new Promise((_, reject) => {
          timer = setTimeout(() => {
            cancelReader();
            controller.abort();
            reject(new Error('live proof history transport timed out'));
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
          if (!(chunk instanceof Uint8Array)) fail('history response chunk is invalid');
          chunkCount += 1;
          if (chunkCount > MAX_HISTORY_CHUNKS || chunk.byteLength > MAX_HISTORY_BYTES - bytes) {
            fail('history response exceeded its bound');
          }
          chunks.push(chunk);
          bytes += chunk.byteLength;
        }
      } catch (error) {
        cancelReader();
        controller.abort();
        if (error instanceof Error && error.message.startsWith('live proof')) throw error;
        fail('history response body read failed');
      }

      const raw = new Uint8Array(bytes);
      let offset = 0;
      for (const chunk of chunks) {
        raw.set(chunk, offset);
        offset += chunk.byteLength;
      }
      try {
        return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
      } catch {
        fail('history response was malformed');
      }
    }

    /** @param {string} path @param {number} deadline @returns {Promise<any>} */
    async function fetchHistoryJson(path, deadline) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) fail('history transport timed out');
      const controller = new AbortController();
      let timer;
      const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(new Error('live proof history transport timed out'));
        }, remaining);
      });
      try {
        const response = await Promise.race([
          globalThis.fetch(path, {
            method: 'GET',
            headers: { accept: 'application/json' },
            credentials: 'include',
            cache: 'no-store',
            redirect: 'error',
            signal: controller.signal
          }),
          timeout
        ]);
        if (
          response.status !== 200 ||
          response.headers.get('content-type')?.toLowerCase().includes('application/json') !== true
        ) {
          controller.abort();
          fail('history response was not approved');
        }
        return await readBoundedJson(response, controller, deadline);
      } catch (error) {
        controller.abort();
        if (error instanceof Error && error.message.startsWith('live proof')) throw error;
        fail('history transport failed');
      } finally {
        clearTimeout(timer);
      }
    }

    /** @param {'pre-send' | 'post-completion'} phase @returns {Promise<BridgeEvent>} */
    const readHistory = async (phase) => {
      if (phase !== 'pre-send' && phase !== 'post-completion') fail('history phase is invalid');
      await keyPromise;
      if (canonicalSessionId === undefined || canonicalSessionTag === undefined) fail('canonical session is unavailable');
      if (phase === 'pre-send' && preFence !== undefined) fail('pre-send history was duplicated');
      if (phase === 'post-completion' && (preFence === undefined || preHistoryProjectionTag === undefined)) {
        fail('history fence is unavailable');
      }

      const deadline = Date.now() + HISTORY_TIMEOUT_MS;
      /** @type {any} */
      let rawResponse;
      /** @type {any} */
      let parsedHistory;
      /** @type {string | undefined} */
      let historyProjectionTag;
      /** @type {string | undefined} */
      let prefixProjectionTag;
      /** @type {BridgeEvent | undefined} */
      let projection;
      try {
        const encodedSessionId = encodeURIComponent(canonicalSessionId);
        rawResponse = await fetchHistoryJson(
          `/api/sessions/${encodedSessionId}/messages?limit=${MAX_HISTORY_MESSAGES}&offset=0`,
          deadline
        );
        parsedHistory = parseHistoryResponse(rawResponse);
        historyProjectionTag = await messageProjectionTag(parsedHistory.messages);
        const sessionMatches = parsedHistory.sessionId === canonicalSessionId;
        if (phase === 'pre-send') {
          preFence = parsedHistory.messages.length === 0 ? 0 : parsedHistory.messages[parsedHistory.messages.length - 1].id;
          preHistoryProjectionTag = historyProjectionTag;
          prefixProjectionTag = historyProjectionTag;
          projection = {
            status: 200,
            sessionTag: canonicalSessionTag,
            sessionMatches,
            historyComplete: parsedHistory.historyComplete,
            watermarkEstablished: parsedHistory.historyComplete && sessionMatches,
            prefixStable: false,
            postFenceMatched: false,
            promptMatches: false,
            assistantMarkerMatches: false,
            candidateUserCount: 0,
            candidateAssistantCount: 0,
            messageCount: parsedHistory.messages.length,
            historyProjectionTag,
            prefixProjectionTag,
            matched: parsedHistory.historyComplete && sessionMatches
          };
        } else {
          if (preFence === undefined) fail('history fence is unavailable');
          const fence = preFence;
          const prefixMessages = parsedHistory.messages.filter(/** @param {any} message */ (message) => message.id <= fence);
          const postFenceMessages = parsedHistory.messages.filter(/** @param {any} message */ (message) => message.id > fence);
          prefixProjectionTag = await messageProjectionTag(prefixMessages);
          const prefixStable = prefixProjectionTag === preHistoryProjectionTag;
          const candidateUsers = postFenceMessages.filter(/** @param {any} message */ (message) => message.role === 'user');
          const candidateAssistants = postFenceMessages.filter(/** @param {any} message */ (message) => message.role === 'assistant');
          const candidateUserCount = candidateUsers.length;
          const candidateAssistantCount = candidateAssistants.length;
          const promptMatches = candidateUserCount === 1 && candidateUsers[0].content === prompt;
          const assistantMarkerMatches = candidateAssistantCount === 1 && candidateAssistants[0].content === marker;
          const promptIndex = promptMatches ? postFenceMessages.indexOf(candidateUsers[0]) : -1;
          const assistantIndex = assistantMarkerMatches ? postFenceMessages.indexOf(candidateAssistants[0]) : -1;
          const postFenceMatched =
            promptIndex >= 0 &&
            assistantIndex > promptIndex &&
            candidateUserCount === 1 &&
            candidateAssistantCount === 1;
          projection = {
            status: 200,
            sessionTag: canonicalSessionTag,
            sessionMatches,
            historyComplete: parsedHistory.historyComplete,
            watermarkEstablished: false,
            prefixStable,
            postFenceMatched,
            promptMatches,
            assistantMarkerMatches,
            candidateUserCount,
            candidateAssistantCount,
            messageCount: parsedHistory.messages.length,
            historyProjectionTag,
            prefixProjectionTag,
            matched:
              parsedHistory.historyComplete &&
              sessionMatches &&
              prefixStable &&
              postFenceMatched &&
              promptMatches &&
              assistantMarkerMatches
          };
        }
        return projection;
      } finally {
        // The response body, canonical rows, IDs, prompt/marker comparisons, and
        // fence are attempt-local page values. Only the fixed projection survives.
        rawResponse = undefined;
        parsedHistory = undefined;
        historyProjectionTag = undefined;
        prefixProjectionTag = undefined;
        if (phase === 'post-completion') {
          preFence = undefined;
          preHistoryProjectionTag = undefined;
          canonicalSessionId = undefined;
          controlRequests.clear();
        }
      }
    };

    /** @returns {Promise<BridgeEvent[]>} */
    const drain = async () => {
      let timer;
      const timeout = new Promise((resolve) => {
        timer = setTimeout(() => resolve(false), OBSERVATION_DRAIN_TIMEOUT_MS);
      });
      const settled = await Promise.race([operationTail.then(() => true), timeout]);
      clearTimeout(timer);
      if (settled !== true) {
        bridgeFailure = true;
        observationStopped = true;
      }
      const result = queue.splice(0, queue.length).map((event) => Object.freeze({ ...event }));
      if (bridgeFailure) fail('observation failed');
      return result;
    };

    const ready = async () => {
      try {
        const key = await keyPromise;
        return approvedHmacKey(key);
      } catch {
        return false;
      }
    };

    const closeSockets = () => {
      for (const socket of sockets) {
        try {
          socket.close(1000, 'live proof complete');
        } catch {
          // Closing a page-owned socket is best effort; no socket error crosses.
        }
      }
      sockets.clear();
    };

    const state = () => ({
      websocketOpenCount: boundedCount(websocketOpenCount, 'WebSocket open count', MAX_QUEUE_EVENTS),
      websocketCloseCount: boundedCount(websocketCloseCount, 'WebSocket close count', MAX_QUEUE_EVENTS),
      canonicalSessionTag: optionalTag(canonicalSessionTag),
      promptRequestTag: optionalTag(promptRequestTag),
      promptSessionTag: optionalTag(promptSessionTag)
    });

    const bridge = Object.freeze({
      drain,
      readHistory,
      ready,
      closeSockets,
      state
    });
    Object.defineProperty(globalThis, '__hermternalLiveProofBridge', {
      configurable: false,
      enumerable: false,
      writable: false,
      value: bridge
    });
}

/** @returns {any} */
function installedBridge() {
  return /** @type {any} */ (globalThis).__hermternalLiveProofBridge;
}

/** @returns {Promise<boolean>} */
export function assertLiveProofPageBridgeReady() {
  return installedBridge().ready();
}

/** @returns {Promise<Array<Record<string, unknown>>>} */
export function drainLiveProofPageEvents() {
  return installedBridge().drain();
}

/** @param {{ phase: 'pre-send'|'post-completion' }} options */
export function readLiveProofPageHistory(options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    throw new Error('live proof page bridge history options are invalid');
  }
  let firstPrototype;
  let secondPrototype;
  let firstKeys;
  let secondKeys;
  let firstDescriptor;
  let secondDescriptor;
  try {
    firstPrototype = Object.getPrototypeOf(options);
    firstKeys = Reflect.ownKeys(options);
    firstDescriptor = Object.getOwnPropertyDescriptor(options, 'phase');
    secondPrototype = Object.getPrototypeOf(options);
    secondKeys = Reflect.ownKeys(options);
    secondDescriptor = Object.getOwnPropertyDescriptor(options, 'phase');
  } catch {
    throw new Error('live proof page bridge history options are malformed');
  }
  if (
    firstPrototype !== Object.prototype ||
    secondPrototype !== Object.prototype ||
    firstPrototype !== secondPrototype ||
    firstKeys.length !== 1 ||
    secondKeys.length !== 1 ||
    firstKeys[0] !== 'phase' ||
    secondKeys[0] !== 'phase' ||
    !firstDescriptor ||
    !secondDescriptor ||
    !Object.prototype.hasOwnProperty.call(firstDescriptor, 'value') ||
    !Object.prototype.hasOwnProperty.call(secondDescriptor, 'value') ||
    Object.prototype.hasOwnProperty.call(firstDescriptor, 'get') ||
    Object.prototype.hasOwnProperty.call(firstDescriptor, 'set') ||
    Object.prototype.hasOwnProperty.call(secondDescriptor, 'get') ||
    Object.prototype.hasOwnProperty.call(secondDescriptor, 'set') ||
    firstDescriptor.writable !== true ||
    firstDescriptor.enumerable !== true ||
    firstDescriptor.configurable !== true ||
    secondDescriptor.writable !== true ||
    secondDescriptor.enumerable !== true ||
    secondDescriptor.configurable !== true ||
    !Object.is(firstDescriptor.value, secondDescriptor.value) ||
    !Object.is(Reflect.get(options, 'phase', options), firstDescriptor.value) ||
    !Object.is(Reflect.get(options, 'phase', options), secondDescriptor.value)
  ) {
    throw new Error('live proof page bridge history options are malformed');
  }
  return installedBridge().readHistory(firstDescriptor.value);
}

/** @returns {{ websocketOpenCount: number, websocketCloseCount: number, canonicalSessionTag?: string, promptRequestTag?: string, promptSessionTag?: string }} */
export function readLiveProofPageState() {
  return installedBridge().state();
}

export function closeLiveProofPageSockets() {
  installedBridge().closeSockets();
}
