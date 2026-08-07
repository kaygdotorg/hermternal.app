import { describe, expect, it, vi } from "vitest";
import {
  DASHBOARD_CONTRACT,
  HERMES_SOURCE_SHA,
  JSON_RPC_APPROVAL_METHOD,
  JSON_RPC_CLARIFICATION_METHOD,
  JSON_RPC_EVENT_METHOD,
  JSON_RPC_GATEWAY_READY_EVENT,
  JSON_RPC_INTERRUPT_METHOD,
  JSON_RPC_PROMPT_METHOD,
  JSON_RPC_SESSION_CREATE_METHOD,
  JSON_RPC_SESSION_RESUME_METHOD,
  JSON_RPC_WS_PATH,
  JsonRpcChatError,
  createJsonRpcChatTransport,
  parseBoundedJsonFrame,
  type JsonRpcChatEvent,
  type JsonRpcChatOptions,
  type JsonRpcChatRequest,
  type JsonRpcWebSocket,
  type JsonRpcWebSocketUpgradeRequest,
} from "./json-rpc-chat";

// These synthetic evidence values are referenced by the deterministic W-07
// fixture IDs documented in json-rpc-chat.md; they never represent a live deployment.
const COMPATIBILITY_EVIDENCE: JsonRpcChatOptions["compatibilityEvidence"] = {
  deployment: {
    identity: "synthetic-deployment-001",
    trustChannel: "release-channel",
    scope: "fixture_only",
  },
  routeManifest: {
    path: "contracts/hermes-dashboard/manifest.md",
    revision: DASHBOARD_CONTRACT,
    sha256: "3c6b44dc8dd90836f4fc5c5158d459959c569fb811db4b198e87d78ea5010197",
    sizeBytes: 17859,
  },
  sourceReview: {
    path: "contracts/fixtures/source-audit/planning-reconciliation/planning_review.json",
    sha256: "0a84cba82e6e966ab35de187f560fd38d6e10c43dd2204062d6ebf2bc5c32077",
    sizeBytes: 20045,
  },
  proxyProof: {
    path: "docs/deployment/proof-matrix.md",
    sha256: "52fb8d0fb9f21ee7a80c5796343c3893a7f715c93fd47e832f5be098bc865212",
    sizeBytes: 16167,
  },
};

class FakeWebSocket implements JsonRpcWebSocket {
  onopen: ((event?: unknown) => void) | null = null;
  onmessage: ((event: { readonly data: unknown }) => void) | null = null;
  onerror: ((event?: unknown) => void) | null = null;
  onclose:
    | ((event?: { readonly code?: number; readonly reason?: string }) => void)
    | null = null;
  readonly sent: string[] = [];
  closed: { readonly code?: number; readonly reason?: string } | undefined;
  throwOnSend = false;

  send(data: string): void {
    if (this.throwOnSend || this.closed) {
      throw new Error("socket-closed");
    }
    this.sent.push(data);
  }

  close(code?: number, reason?: string): void {
    if (this.closed) {
      return;
    }
    this.closed = { code, reason };
    this.onclose?.(this.closed);
  }

  emitOpen(): void {
    this.onopen?.();
  }

  emitMessage(data: unknown): void {
    this.onmessage?.({
      data: typeof data === "string" ? data : JSON.stringify(data),
    });
  }

  emitClose(code = 1006, reason = ""): void {
    this.onclose?.({ code, reason });
  }
}

interface TestHarness {
  readonly transport: ReturnType<typeof createJsonRpcChatTransport>;
  readonly sockets: FakeWebSocket[];
  readonly upgrades: JsonRpcWebSocketUpgradeRequest[];
  readonly tickets: string[];
}

function makeHarness(overrides: Partial<JsonRpcChatOptions> = {}): TestHarness {
  const sockets: FakeWebSocket[] = [];
  const upgrades: JsonRpcWebSocketUpgradeRequest[] = [];
  const tickets: string[] = [];
  let ticketCount = 0;
  const options: JsonRpcChatOptions = {
    selectedSessionId: "session-marker-001",
    ticketProvider: async (signal) => {
      if (signal.aborted) {
        throw new JsonRpcChatError("aborted");
      }
      ticketCount += 1;
      return `ticket-${ticketCount}`;
    },
    createWebSocket: (upgrade) => {
      upgrades.push(upgrade);
      tickets.push(upgrade.query.ticket);
      const socket = new FakeWebSocket();
      sockets.push(socket);
      return socket;
    },
    compatibilityEvidence: COMPATIBILITY_EVIDENCE,
    verifyAttestation: async (evidence) =>
      evidence.contract === DASHBOARD_CONTRACT &&
      evidence.hermesSourceSha === HERMES_SOURCE_SHA &&
      evidence.websocketPath === JSON_RPC_WS_PATH &&
      evidence.deployment.identity === "synthetic-deployment-001" &&
      evidence.routeManifest.revision === DASHBOARD_CONTRACT &&
      evidence.routeManifest.sha256 ===
        COMPATIBILITY_EVIDENCE.routeManifest.sha256 &&
      evidence.sourceReview.sha256 ===
        COMPATIBILITY_EVIDENCE.sourceReview.sha256 &&
      evidence.proxyProof.sha256 === COMPATIBILITY_EVIDENCE.proxyProof.sha256,
    runBehavioralProbe: async () => true,
    ...overrides,
  };
  return {
    transport: createJsonRpcChatTransport(options),
    sockets,
    upgrades,
    tickets,
  };
}

async function flush(): Promise<void> {
  for (let index = 0; index < 32; index += 1) {
    await Promise.resolve();
  }
}

function frame(socket: FakeWebSocket, index: number): Record<string, unknown> {
  const raw = socket.sent[index];
  if (!raw) {
    throw new Error(`missing frame ${index}`);
  }
  return JSON.parse(raw) as Record<string, unknown>;
}

function emitResponse(
  socket: FakeWebSocket,
  id: string,
  result: unknown = { status: "ok" },
): void {
  socket.emitMessage({ jsonrpc: "2.0", id, result });
}

function emitEvent(
  socket: FakeWebSocket,
  type: string,
  payload: Record<string, unknown> = {},
  fields: Record<string, unknown> = {},
): void {
  socket.emitMessage({
    jsonrpc: "2.0",
    method: JSON_RPC_EVENT_METHOD,
    params: { type, payload, ...fields },
  });
}

async function connectHarness(harness: TestHarness): Promise<FakeWebSocket> {
  const connection = harness.transport.connect();
  await flush();
  const socket = harness.sockets.at(-1);
  if (!socket) {
    throw new Error("fake socket was not created");
  }
  socket.emitOpen();
  expect(socket.sent).toHaveLength(0);
  expect(harness.transport.state.status).toBe("handshaking");
  emitEvent(socket, JSON_RPC_GATEWAY_READY_EVENT, {
    skin: "synthetic-skin",
    change_events: true,
  });
  await flush();
  const resume = frame(socket, 0);
  expect(resume.method).toBe(JSON_RPC_SESSION_RESUME_METHOD);
  expect(resume.params).toEqual({ session_id: "session-marker-001" });
  emitResponse(socket, resume.id as string, {
    session_id: "session-marker-001",
    restored: true,
  });
  await connection;
  expect(harness.transport.state.status).toBe("ready");
  return socket;
}

function promptFrame(socket: FakeWebSocket): Record<string, unknown> {
  return frame(socket, 1);
}

function emitPromptAccepted(socket: FakeWebSocket): string {
  const prompt = promptFrame(socket);
  emitResponse(socket, prompt.id as string, { status: "streaming" });
  return prompt.id as string;
}

async function reconnectHarness(harness: TestHarness): Promise<FakeWebSocket> {
  const reconnect = harness.transport.reconnect();
  await flush();
  const replacement = harness.sockets.at(-1);
  if (!replacement) {
    throw new Error("replacement socket was not created");
  }
  replacement.emitOpen();
  emitEvent(replacement, JSON_RPC_GATEWAY_READY_EVENT, { skin: "replacement" });
  await flush();
  const resume = frame(replacement, 0);
  expect(resume.method).toBe(JSON_RPC_SESSION_RESUME_METHOD);
  emitResponse(replacement, resume.id as string, { restored: true });
  await reconnect;
  return replacement;
}

describe("createJsonRpcChatTransport", () => {
  it("waits for server-first gateway.ready, runs both gates, and restores with session.resume", async () => {
    const onOpen = vi.fn();
    const harness = makeHarness({ onOpen });
    const connection = harness.transport.connect();
    await flush();
    const socket = harness.sockets[0];
    if (!socket) {
      throw new Error("fake socket was not created");
    }
    socket.emitOpen();
    expect(harness.transport.state.status).toBe("handshaking");
    expect(socket.sent).toHaveLength(0);
    expect(() =>
      harness.transport.sendPrompt("blocked before ready"),
    ).toThrowError(expect.objectContaining({ code: "not-connected" }));

    emitEvent(
      socket,
      JSON_RPC_GATEWAY_READY_EVENT,
      { skin: "synthetic", change_events: true },
      { additive: "ignored" },
    );
    await flush();
    expect(harness.transport.state.status).toBe("restoring");
    expect(() =>
      harness.transport.sendPrompt("blocked during restore"),
    ).toThrowError(expect.objectContaining({ code: "not-connected" }));
    expect(socket.sent).toHaveLength(1);
    const resume = frame(socket, 0);
    expect(resume).toMatchObject({
      jsonrpc: "2.0",
      method: JSON_RPC_SESSION_RESUME_METHOD,
      params: { session_id: "session-marker-001" },
    });
    emitResponse(socket, resume.id as string, {
      restored: true,
      additive: { safe: true },
    });
    await connection;

    expect(harness.transport.state.status).toBe("ready");
    expect(onOpen).toHaveBeenCalledTimes(1);
    expect(harness.upgrades).toEqual([
      {
        path: JSON_RPC_WS_PATH,
        origin: "same-origin",
        query: { ticket: "ticket-1" },
      },
    ]);
  });

  it("creates one empty source-owned session and uses its ephemeral ID for the first prompt", async () => {
    const harness = makeHarness({ selectedSessionId: undefined });
    const connection = harness.transport.connect();
    await flush();
    const socket = harness.sockets[0];
    if (!socket) throw new Error("fake socket was not created");
    socket.emitOpen();
    emitEvent(socket, JSON_RPC_GATEWAY_READY_EVENT, {
      skin: "synthetic",
      change_events: true,
    });
    await connection;

    const creation = harness.transport.createSession();
    const create = frame(socket, 0);
    expect(create).toMatchObject({
      jsonrpc: "2.0",
      method: JSON_RPC_SESSION_CREATE_METHOD,
      params: {},
    });
    emitResponse(socket, create.id as string, {
      session_id: "live-draft-1",
      stored_session_id: "stored-draft-1",
      message_count: 0,
      messages: [],
      info: { model: "synthetic/model", additive: true },
    });
    await expect(creation).resolves.toEqual({
      sessionId: "live-draft-1",
      storedSessionId: "stored-draft-1",
      model: "synthetic/model",
    });

    harness.transport.sendPrompt("first persisted prompt");
    expect(frame(socket, 1)).toMatchObject({
      method: JSON_RPC_PROMPT_METHOD,
      params: { session_id: "live-draft-1", text: "first persisted prompt" },
    });
  });

  it("uses exact prompt, interrupt, approval, and clarification methods with opaque source payloads", async () => {
    const events: JsonRpcChatEvent[] = [];
    const harness = makeHarness();
    harness.transport.subscribe((event) => events.push(event));
    const socket = await connectHarness(harness);
    const request = harness.transport.sendPrompt(
      "synthetic prompt that is not retained",
    );
    const prompt = promptFrame(socket);
    expect(prompt).toMatchObject({
      jsonrpc: "2.0",
      method: JSON_RPC_PROMPT_METHOD,
      params: {
        session_id: "session-marker-001",
        text: "synthetic prompt that is not retained",
      },
    });
    const requestId = prompt.id as string;
    emitResponse(socket, requestId, { status: "streaming" });

    emitEvent(
      socket,
      "message.delta",
      { text: "hello " },
      { request_id: requestId, sequence: 1 },
    );
    emitEvent(
      socket,
      "reasoning.delta",
      { text: "thinking" },
      { request_id: requestId, sequence: 2 },
    );
    emitEvent(
      socket,
      "thinking.delta",
      { text: "private thought" },
      { request_id: requestId, sequence: 3 },
    );
    emitEvent(
      socket,
      "tool.start",
      { name: "lookup" },
      { request_id: requestId, sequence: 4 },
    );
    emitEvent(
      socket,
      "tool.complete",
      { name: "lookup", status: "ok" },
      { request_id: requestId, sequence: 5 },
    );
    emitEvent(
      socket,
      "approval.request",
      { approval_id: "approval-1", title: "Synthetic approval" },
      {
        request_id: requestId,
        sequence: 6,
      },
    );

    const approval = harness.transport.respondToApproval(
      requestId,
      "approval-1",
      true,
    );
    const approvalFrame = frame(socket, 2);
    expect(approvalFrame).toMatchObject({
      jsonrpc: "2.0",
      method: JSON_RPC_APPROVAL_METHOD,
      params: { session_id: "session-marker-001", choice: "once", all: false },
    });
    expect(JSON.stringify(approvalFrame)).not.toContain("synthetic prompt");
    emitResponse(socket, approvalFrame.id as string);
    await approval;

    emitEvent(
      socket,
      "clarify.request",
      { clarification_id: "clarification-1", question: "Continue?" },
      {
        request_id: requestId,
        sequence: 7,
      },
    );
    const clarification = harness.transport.answerClarification(
      requestId,
      "clarification-1",
      "yes",
    );
    const clarificationFrame = frame(socket, 3);
    expect(clarificationFrame).toMatchObject({
      jsonrpc: "2.0",
      method: JSON_RPC_CLARIFICATION_METHOD,
      params: { request_id: requestId, answer: "yes" },
    });
    emitResponse(socket, clarificationFrame.id as string);
    await clarification;

    emitEvent(
      socket,
      "message.complete",
      { text: "done", status: "ok" },
      { request_id: requestId, sequence: 8 },
    );
    await expect(request.completion).resolves.toMatchObject({
      type: "message.complete",
      requestId,
    });
    expect(request.state).toEqual({ id: requestId, status: "completed" });
    expect(events.map((event) => event.type)).toEqual(
      [
        JSON_RPC_GATEWAY_READY_EVENT,
        "session.info",
        // No session.info was sent in this fixture; the remaining types are exact source event names.
        "message.delta",
        "reasoning.delta",
        "thinking.delta",
        "tool.start",
        "tool.complete",
        "approval.request",
        "clarify.request",
        "message.complete",
      ].filter((type) => type !== "session.info"),
    );
  });

  it("preserves event-derived streaming state when acknowledgement arrives later", async () => {
    const harness = makeHarness();
    const socket = await connectHarness(harness);
    const request = harness.transport.sendPrompt(
      "event before acknowledgement",
    );
    const prompt = promptFrame(socket);

    emitEvent(
      socket,
      "message.delta",
      { text: "streaming first" },
      { request_id: prompt.id, sequence: 1 },
    );
    expect(request.state).toEqual({ id: prompt.id, status: "streaming" });
    emitResponse(socket, prompt.id as string, { status: "streaming" });
    expect(request.state).toEqual({ id: prompt.id, status: "streaming" });

    emitEvent(
      socket,
      "message.complete",
      { status: "ok" },
      { request_id: prompt.id, sequence: 2 },
    );
    await expect(request.completion).resolves.toMatchObject({
      type: "message.complete",
    });
  });

  it("tombstones a completed prompt until its late acknowledgement is consumed", async () => {
    const harness = makeHarness();
    const socket = await connectHarness(harness);
    const request = harness.transport.sendPrompt(
      "completion before acknowledgement",
    );
    const prompt = promptFrame(socket);

    emitEvent(
      socket,
      "message.complete",
      { status: "ok" },
      { request_id: prompt.id },
    );
    await expect(request.completion).resolves.toMatchObject({
      type: "message.complete",
    });
    expect(request.state).toEqual({ id: prompt.id, status: "completed" });

    emitResponse(socket, prompt.id as string, { status: "streaming" });
    expect(harness.transport.state.status).toBe("ready");
  });

  it("fails closed on contradictory approval state invariants", async () => {
    const invalidStates = [
      { state: "requested", approved: true },
      { state: "resolved", approved: null },
    ] as const;

    for (const [index, approvalState] of invalidStates.entries()) {
      const harness = makeHarness();
      const socket = await connectHarness(harness);
      const request = harness.transport.sendPrompt(
        `approval-state-fixture-${index}`,
      );
      const requestId = emitPromptAccepted(socket);

      emitEvent(
        socket,
        "approval.request",
        { approval_id: `approval-state-${index}`, ...approvalState },
        { request_id: requestId },
      );

      await expect(request.completion).rejects.toMatchObject({
        code: "uncertain-delivery",
      });
      expect(socket.closed?.code).toBe(1002);
      expect(harness.transport.state.status).toBe("failed");
    }
  });

  it("fails closed when an approval owner is malformed", async () => {
    const harness = makeHarness();
    const socket = await connectHarness(harness);
    const request = harness.transport.sendPrompt(
      "invalid approval owner fixture",
    );
    const requestId = emitPromptAccepted(socket);

    emitEvent(
      socket,
      "approval.request",
      { approval_id: "invalid/owner", state: "requested", approved: null },
      { request_id: requestId },
    );

    await expect(request.completion).rejects.toMatchObject({
      code: "uncertain-delivery",
    });
    expect(socket.closed?.code).toBe(1002);
    expect(harness.transport.state.status).toBe("failed");
  });

  it("derives blocking owners from source request_id when payloads omit local owner fields", async () => {
    const events: JsonRpcChatEvent[] = [];
    const harness = makeHarness();
    harness.transport.subscribe((event) => events.push(event));
    const socket = await connectHarness(harness);
    const request = harness.transport.sendPrompt("owner fallback prompt");
    const requestId = emitPromptAccepted(socket);

    emitEvent(
      socket,
      "approval.request",
      { title: "Approve this action" },
      { request_id: requestId },
    );
    expect(events.at(-1)).toMatchObject({
      type: "approval.request",
      requestId,
      approvalId: requestId,
    });
    const approval = harness.transport.respondToApproval(
      requestId,
      requestId,
      false,
    );
    const approvalFrame = frame(socket, 2);
    expect(approvalFrame.params).toEqual({
      session_id: "session-marker-001",
      choice: "deny",
      all: false,
    });
    emitResponse(socket, approvalFrame.id as string);
    await approval;

    emitEvent(
      socket,
      "clarify.request",
      { question: "Continue?" },
      { request_id: requestId },
    );
    expect(events.at(-1)).toMatchObject({
      type: "clarify.request",
      requestId,
      clarificationId: requestId,
    });
    const clarification = harness.transport.answerClarification(
      requestId,
      requestId,
      "yes",
    );
    const clarificationFrame = frame(socket, 3);
    expect(clarificationFrame.params).toEqual({
      request_id: requestId,
      answer: "yes",
    });
    emitResponse(socket, clarificationFrame.id as string);
    await clarification;

    emitEvent(
      socket,
      "message.complete",
      { status: "ok" },
      { request_id: requestId },
    );
    await expect(request.completion).resolves.toMatchObject({
      type: "message.complete",
      requestId,
    });
  });

  it("ignores additive noninteractive events and fails closed on unsupported interactive events", async () => {
    const harness = makeHarness();
    const socket = await connectHarness(harness);
    emitEvent(socket, "tool.progress", { percent: 50, additive: true });
    // Official global change broadcasts are session-less and encode that with
    // an empty session_id rather than omitting the field.
    emitEvent(socket, "sessions.changed", {}, { session_id: "" });
    expect(socket.closed).toBeUndefined();
    expect(harness.transport.state.status).toBe("ready");

    emitEvent(socket, "secret.request", { prompt: "never expose this" });
    expect(socket.closed?.code).toBe(1000);
    expect(harness.transport.state.status).toBe("incompatible");
  });

  it("accepts additive fields in responses and rejects malformed or oversized frames without raw retention", async () => {
    const harness = makeHarness({ maxFrameBytes: 256 });
    const socket = await connectHarness(harness);
    const request = harness.transport.sendPrompt("redaction marker prompt");
    const prompt = promptFrame(socket);
    emitResponse(socket, prompt.id as string, {
      status: "streaming",
      additive: { safe: true },
    });
    expect(harness.transport.state.status).toBe("ready");

    socket.emitMessage('{"jsonrpc":');
    await expect(request.completion).rejects.toMatchObject({
      code: "uncertain-delivery",
    });
    expect(socket.closed?.code).toBe(1002);
    expect(harness.transport.state.status).toBe("failed");
    expect(JSON.stringify(harness.transport.state)).not.toContain(
      "redaction marker prompt",
    );

    const second = makeHarness({ maxFrameBytes: 256 });
    const secondSocket = await connectHarness(second);
    secondSocket.emitMessage("x".repeat(257));
    expect(secondSocket.closed?.code).toBe(1002);
    expect(second.transport.state.status).toBe("failed");
  });

  it("enforces optional ordered fixture sequences and marks the operation uncertain", async () => {
    const harness = makeHarness();
    const socket = await connectHarness(harness);
    const request = harness.transport.sendPrompt("out-of-order prompt");
    const requestId = emitPromptAccepted(socket);
    emitEvent(
      socket,
      "message.delta",
      { text: "late" },
      { request_id: requestId, sequence: 2 },
    );

    await expect(request.completion).rejects.toMatchObject({
      code: "uncertain-delivery",
    });
    expect(request.state.status).toBe("uncertain-delivery");
    expect(socket.closed?.code).toBe(1002);
    expect(harness.transport.state.status).toBe("failed");
  });

  it("marks disconnect uncertainty before and after acknowledgement and never replays prompt text", async () => {
    const before = makeHarness();
    const beforeSocket = await connectHarness(before);
    const beforeRequest = before.transport.sendPrompt(
      "before acknowledgement prompt",
    );
    beforeSocket.emitClose();
    await expect(beforeRequest.completion).rejects.toMatchObject({
      code: "uncertain-delivery",
    });
    const replacementBefore = await reconnectHarness(before);
    expect(before.tickets).toEqual(["ticket-1", "ticket-2"]);
    expect(JSON.stringify(replacementBefore.sent)).not.toContain(
      "before acknowledgement prompt",
    );

    const after = makeHarness();
    const afterSocket = await connectHarness(after);
    const afterRequest = after.transport.sendPrompt(
      "after acknowledgement prompt",
    );
    emitPromptAccepted(afterSocket);
    afterSocket.emitClose();
    await expect(afterRequest.completion).rejects.toMatchObject({
      code: "uncertain-delivery",
    });
    const replacementAfter = await reconnectHarness(after);
    expect(JSON.stringify(replacementAfter.sent)).not.toContain(
      "after acknowledgement prompt",
    );
  });

  it("invalidates the old generation before reconnect callbacks and suppresses stale frames", async () => {
    const onReconnect = vi.fn();
    const harness = makeHarness({ onReconnect });
    const firstConnect = harness.transport.connect();
    await flush();
    const first = harness.sockets[0];
    if (!first) {
      throw new Error("first socket was not created");
    }
    const secondConnect = harness.transport.reconnect();
    await flush();
    const second = harness.sockets[1];
    if (!second) {
      throw new Error("second socket was not created");
    }

    first.emitOpen();
    emitEvent(first, JSON_RPC_GATEWAY_READY_EVENT, { stale: true });
    expect(onReconnect).toHaveBeenCalledTimes(1);
    expect(second.sent).toHaveLength(0);
    second.emitOpen();
    emitEvent(second, JSON_RPC_GATEWAY_READY_EVENT, { current: true });
    await flush();
    const resume = frame(second, 0);
    emitResponse(second, resume.id as string, { restored: true });

    await expect(firstConnect).rejects.toMatchObject({ code: "aborted" });
    await secondConnect;
    expect(harness.transport.state.status).toBe("ready");
    expect(harness.transport.state.generation).toBeGreaterThan(1);
    expect(harness.tickets).toEqual(["ticket-1", "ticket-2"]);
  });

  it("settles explicit close at offline and suppresses reconnect until connect is requested", async () => {
    const harness = makeHarness();
    await connectHarness(harness);
    harness.transport.close();

    expect(harness.transport.state.status).toBe("offline");
    await expect(harness.transport.reconnect()).rejects.toMatchObject({
      code: "closed",
    });
    expect(harness.sockets).toHaveLength(1);

    const connection = harness.transport.connect();
    await flush();
    const replacement = harness.sockets.at(-1);
    if (!replacement) {
      throw new Error("replacement socket was not created");
    }
    replacement.emitOpen();
    emitEvent(replacement, JSON_RPC_GATEWAY_READY_EVENT, { reopened: true });
    await flush();
    const resume = frame(replacement, 0);
    emitResponse(replacement, resume.id as string, { restored: true });
    await connection;
    expect(harness.transport.state.status).toBe("ready");
  });

  it("closes the socket and settles an attached connection abort while waiting for gateway.ready", async () => {
    const harness = makeHarness();
    const controller = new AbortController();
    const connection = harness.transport.connect(controller.signal);
    await flush();
    const socket = harness.sockets[0];
    if (!socket) {
      throw new Error("fake socket was not created");
    }
    socket.emitOpen();
    controller.abort("secret-shaped abort reason");
    await expect(connection).rejects.toMatchObject({ code: "aborted" });
    expect(socket.closed).toBeDefined();
    expect(harness.transport.state.status).toBe("offline");
    expect(JSON.stringify(harness.transport.state)).not.toContain(
      "secret-shaped",
    );
  });

  it("cleans up every pending operation when the socket send fails", async () => {
    const harness = makeHarness();
    const socket = await connectHarness(harness);
    socket.throwOnSend = true;
    expect(() =>
      harness.transport.sendPrompt("send failure prompt"),
    ).toThrowError(expect.objectContaining({ code: "connection-failed" }));
    expect(socket.closed).toBeDefined();
    expect(harness.transport.state.status).toBe("delivery_uncertain");
  });

  it("ignores a late control acknowledgement after local abort and rejects duplicate owners", async () => {
    const harness = makeHarness();
    const socket = await connectHarness(harness);
    const request = harness.transport.sendPrompt("control owner prompt");
    const requestId = emitPromptAccepted(socket);
    emitEvent(
      socket,
      "approval.request",
      { approval_id: "approval-owner" },
      { request_id: requestId },
    );
    const controller = new AbortController();
    const response = harness.transport.respondToApproval(
      requestId,
      "approval-owner",
      false,
      controller.signal,
    );
    const control = frame(socket, 2);
    controller.abort("do not forward");
    await expect(response).rejects.toMatchObject({ code: "aborted" });
    expect(() =>
      harness.transport.respondToApproval(requestId, "approval-owner", true),
    ).toThrowError(expect.objectContaining({ code: "invalid-input" }));
    emitResponse(socket, control.id as string);
    expect(harness.transport.state.status).toBe("ready");
    harness.transport.abort(requestId);
    await expect(request.completion).rejects.toMatchObject({
      code: "cancelled",
    });
  });

  it("sends session.interrupt as the explicit stop operation", async () => {
    const harness = makeHarness();
    const socket = await connectHarness(harness);
    const request = harness.transport.sendPrompt("interrupt me");
    const requestId = emitPromptAccepted(socket);
    const interruption = harness.transport.interrupt(requestId);
    const interruptFrame = frame(socket, 2);
    expect(interruptFrame).toMatchObject({
      jsonrpc: "2.0",
      method: JSON_RPC_INTERRUPT_METHOD,
      params: { session_id: "session-marker-001" },
    });
    emitResponse(socket, interruptFrame.id as string, { interrupted: true });
    await interruption;
    expect(request.state.status).toBe("interrupting");
    harness.transport.abort(requestId);
    await expect(request.completion).rejects.toMatchObject({
      code: "cancelled",
    });
  });

  it("fails closed when compatibility evidence is missing or a gate exceeds its deadline", async () => {
    const missing = makeHarness({ compatibilityEvidence: undefined as never });
    const missingConnection = missing.transport.connect();
    await flush();
    const missingSocket = missing.sockets[0];
    if (!missingSocket) {
      throw new Error("fake socket was not created");
    }
    missingSocket.emitOpen();
    emitEvent(missingSocket, JSON_RPC_GATEWAY_READY_EVENT, { missing: true });
    await expect(missingConnection).rejects.toMatchObject({
      code: "incompatible",
    });
    expect(missing.transport.state.status).toBe("incompatible");

    vi.useFakeTimers();
    try {
      const hanging = makeHarness({
        compatibilityGateTimeoutMs: 5,
        verifyAttestation: () => new Promise<boolean>(() => undefined),
      });
      const connection = hanging.transport.connect();
      void connection.catch(() => undefined);
      await flush();
      const socket = hanging.sockets[0];
      if (!socket) {
        throw new Error("fake socket was not created");
      }
      socket.emitOpen();
      emitEvent(socket, JSON_RPC_GATEWAY_READY_EVENT, { hanging: true });
      await flush();
      await vi.advanceTimersByTimeAsync(5);
      await expect(connection).rejects.toMatchObject({ code: "incompatible" });
      expect(hanging.transport.state.status).toBe("incompatible");
    } finally {
      vi.useRealTimers();
    }
  });

  it("enforces the route-manifest session ID grammar at construction and resume boundaries", () => {
    expect(() => makeHarness({ selectedSessionId: "a-" })).toThrowError(
      expect.objectContaining({ code: "invalid-input" }),
    );
    expect(() => makeHarness({ selectedSessionId: "ab_" })).toThrowError(
      expect.objectContaining({ code: "invalid-input" }),
    );
    expect(() => makeHarness({ selectedSessionId: "a" })).not.toThrow();
    expect(() => makeHarness({ selectedSessionId: "a-b" })).not.toThrow();
  });

  it("times out gateway.ready and control acknowledgements with semantic cleanup", async () => {
    vi.useFakeTimers();
    try {
      const handshake = makeHarness({ gatewayReadyTimeoutMs: 5 });
      const connection = handshake.transport.connect();
      void connection.catch(() => undefined);
      await flush();
      const socket = handshake.sockets[0];
      if (!socket) {
        throw new Error("fake socket was not created");
      }
      socket.emitOpen();
      await vi.advanceTimersByTimeAsync(5);
      await expect(connection).rejects.toMatchObject({
        code: "gateway-ready-timeout",
      });
      expect(socket.closed?.code).toBe(1002);
      expect(handshake.transport.state.status).toBe("failed");

      const controlHarness = makeHarness({ acknowledgementTimeoutMs: 5 });
      const controlSocket = await connectHarness(controlHarness);
      const request = controlHarness.transport.sendPrompt("ack timeout");
      const requestId = emitPromptAccepted(controlSocket);
      emitEvent(
        controlSocket,
        "approval.request",
        { approval_id: "approval-timeout" },
        { request_id: requestId },
      );
      const response = controlHarness.transport.respondToApproval(
        requestId,
        "approval-timeout",
        true,
      );
      void response.catch(() => undefined);
      void request.completion.catch(() => undefined);
      await vi.advanceTimersByTimeAsync(5);
      await expect(response).rejects.toMatchObject({ code: "ack-timeout" });
      expect(controlHarness.transport.state.status).toBe("delivery_uncertain");
      await expect(request.completion).rejects.toMatchObject({
        code: "uncertain-delivery",
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("closes a socket resolved before the outer abort continuation exactly once", async () => {
    const caller = new AbortController();
    const socket = new FakeWebSocket();
    const close = vi.spyOn(socket, "close");
    const harness = makeHarness({
      ticketProvider: async () => "ticket-1",
      createWebSocket: () => {
        // The first microtask lets awaitWithAbort adopt the resolved value;
        // the second aborts before the outer async continuation runs.
        queueMicrotask(() => queueMicrotask(() => caller.abort()));
        return socket;
      },
    });

    const connection = harness.transport.connect(caller.signal);
    await expect(connection).rejects.toMatchObject({ code: "aborted" });
    expect(close).toHaveBeenCalledTimes(1);
    expect(close).toHaveBeenCalledWith(1000, "cancelled");
    expect(harness.transport.state.status).toBe("offline");
  });

  it("publishes authentication-required ticket failures as auth_required", async () => {
    const harness = makeHarness({
      ticketProvider: async () => {
        throw new JsonRpcChatError("authentication-required");
      },
    });

    await expect(harness.transport.connect()).rejects.toMatchObject({
      code: "authentication-required",
    });
    expect(harness.transport.state.status).toBe("auth_required");
    expect(harness.sockets).toHaveLength(0);
  });

  it("classifies every pinned close code and rejects unknown codes as incompatible", async () => {
    const cases: Array<[number, string]> = [
      [4401, "auth_required"],
      [4403, "incompatible"],
      [4404, "incompatible"],
      [4408, "failed"],
      [4409, "failed"],
      [4410, "failed"],
      [1011, "failed"],
      [4999, "incompatible"],
    ];
    for (const [code, expected] of cases) {
      const harness = makeHarness();
      const socket = await connectHarness(harness);
      socket.emitClose(code, "redacted");
      expect(harness.transport.state.status).toBe(expected);
      expect(harness.transport.state.closeCode).toBe(code);
      expect(harness.transport.state.closeClassification).toBeDefined();
    }
  });

  it("enforces the exact bounded JSON container depth, including empty containers", () => {
    const atLimit = `${"[".repeat(16)}${"]".repeat(16)}`;
    const overLimit = `${"[".repeat(17)}${"]".repeat(17)}`;
    expect(parseBoundedJsonFrame(atLimit)).toEqual(expect.any(Array));
    expect(() => parseBoundedJsonFrame(overLimit)).toThrowError(
      expect.objectContaining({ code: "malformed-frame" }),
    );
  });

  it("imports in a no-network browser-like boundary without touching fetch or WebSocket globals", async () => {
    const fetchSpy = vi.fn();
    const existingFetch = globalThis.fetch;
    const existingWebSocket = globalThis.WebSocket;
    vi.stubGlobal("fetch", fetchSpy);
    vi.stubGlobal("WebSocket", undefined);
    try {
      const imported = await import("./json-rpc-chat");
      expect(typeof imported.createJsonRpcChatTransport).toBe("function");
      expect(fetchSpy).not.toHaveBeenCalled();
      expect(globalThis.WebSocket).toBeUndefined();
    } finally {
      vi.unstubAllGlobals();
      if (existingFetch) {
        vi.stubGlobal("fetch", existingFetch);
      }
      if (existingWebSocket) {
        vi.stubGlobal("WebSocket", existingWebSocket);
      }
    }
  });

  it("suppresses stale gateway gates when a ready listener reconnects synchronously", async () => {
    const verifyAttestation = vi.fn(async () => true);
    const runBehavioralProbe = vi.fn(async () => true);
    let transport!: ReturnType<typeof createJsonRpcChatTransport>;
    let reconnectPromise: Promise<void> | undefined;
    let triggered = false;
    const harness = makeHarness({
      verifyAttestation,
      runBehavioralProbe,
      onEvent: (event) => {
        if (event.type === JSON_RPC_GATEWAY_READY_EVENT && !triggered) {
          triggered = true;
          reconnectPromise = transport.reconnect();
          void reconnectPromise.catch(() => undefined);
        }
      }
    });
    transport = harness.transport;
    const first = transport.connect();
    await flush();
    const firstSocket = harness.sockets[0];
    if (!firstSocket) throw new Error('first socket was not created');
    firstSocket.emitOpen();
    emitEvent(firstSocket, JSON_RPC_GATEWAY_READY_EVENT, { skin: 'first', change_events: true });
    await flush();

    const replacement = harness.sockets[1];
    if (!replacement) throw new Error('replacement socket was not created');
    replacement.emitOpen();
    emitEvent(replacement, JSON_RPC_GATEWAY_READY_EVENT, { skin: 'replacement', change_events: true });
    await flush();
    const resume = frame(replacement, 0);
    emitResponse(replacement, resume.id as string, { restored: true });
    await expect(first).rejects.toBeInstanceOf(JsonRpcChatError);
    await reconnectPromise;

    expect(verifyAttestation).toHaveBeenCalledTimes(1);
    expect(runBehavioralProbe).toHaveBeenCalledTimes(1);
    expect(transport.state.status).toBe('ready');
  });

  it("fails closed without running gates when gateway.ready reentrantly repeats", async () => {
    const verifyAttestation = vi.fn(async () => true);
    let socket!: FakeWebSocket;
    let repeated = false;
    const harness = makeHarness({
      verifyAttestation,
      onEvent: (event) => {
        if (event.type === JSON_RPC_GATEWAY_READY_EVENT && !repeated) {
          repeated = true;
          emitEvent(socket, JSON_RPC_GATEWAY_READY_EVENT, { skin: 'duplicate', change_events: true });
        }
      }
    });
    const connection = harness.transport.connect();
    await flush();
    socket = harness.sockets[0] as FakeWebSocket;
    socket.emitOpen();
    emitEvent(socket, JSON_RPC_GATEWAY_READY_EVENT, { skin: 'first', change_events: true });

    await expect(connection).rejects.toMatchObject({ code: 'protocol-violation' });
    expect(verifyAttestation).not.toHaveBeenCalled();
  });

  it("preserves cancellation when an error listener aborts the operation", async () => {
    let transport!: ReturnType<typeof createJsonRpcChatTransport>;
    let requestId: string | undefined;
    const harness = makeHarness({
      onEvent: (event) => {
        if (event.type === 'error' && requestId) transport.abort(requestId);
      }
    });
    transport = harness.transport;
    const socket = await connectHarness(harness);
    const request = transport.sendPrompt('abort from error listener');
    requestId = request.id;
    emitEvent(socket, 'error', { message: 'server failed' }, { request_id: request.id });

    await expect(request.completion).rejects.toMatchObject({ code: 'cancelled' });
    expect(transport.state.status).not.toBe('failed');
  });

  it("does not overwrite cancellation when a completion listener aborts", async () => {
    let transport!: ReturnType<typeof createJsonRpcChatTransport>;
    let request: JsonRpcChatRequest | undefined;
    const harness = makeHarness({
      onEvent: (event) => {
        if (event.type === 'message.complete') request?.abort();
      }
    });
    transport = harness.transport;
    const socket = await connectHarness(harness);
    request = transport.sendPrompt('abort from completion listener');
    emitEvent(socket, 'message.complete', { text: 'done' }, { request_id: request.id });

    await expect(request.completion).rejects.toMatchObject({ code: 'cancelled' });
    expect(request.state.status).toBe('cancelled');
    expect(transport.state.status).not.toBe('failed');
  });

  it("adopts the active attempt before a connecting subscriber reconnects", async () => {
    let transport!: ReturnType<typeof createJsonRpcChatTransport>;
    let nested: Promise<void> | undefined;
    let reentered = false;
    const harness = makeHarness({
      onStateChange: (state) => {
        if (state.status === 'connecting' && !reentered) {
          reentered = true;
          nested = transport.reconnect();
          void nested.catch(() => undefined);
        }
      }
    });
    transport = harness.transport;
    const first = transport.connect();
    await flush();

    const replacement = harness.sockets.at(-1);
    if (!replacement) throw new Error('replacement socket was not created');
    replacement.emitOpen();
    emitEvent(replacement, JSON_RPC_GATEWAY_READY_EVENT, { replacement: true });
    await flush();
    const resume = frame(replacement, 0);
    emitResponse(replacement, resume.id as string, { restored: true });

    await expect(first).rejects.toMatchObject({ code: 'aborted' });
    await nested;
    expect(harness.tickets).toEqual(['ticket-1']);
    expect(transport.state.status).toBe('ready');
  });

  it("suppresses recursive onReconnect callbacks while allowing the replacement to finish", async () => {
    let transport!: ReturnType<typeof createJsonRpcChatTransport>;
    let nested: Promise<void> | undefined;
    let callbackCount = 0;
    const harness = makeHarness({
      onReconnect: () => {
        callbackCount += 1;
        if (callbackCount === 1) {
          nested = transport.reconnect();
          void nested.catch(() => undefined);
        }
      }
    });
    transport = harness.transport;
    await connectHarness(harness);

    const outer = transport.reconnect();
    void outer.catch(() => undefined);
    await flush();
    const replacement = harness.sockets.at(-1);
    if (!replacement) throw new Error('replacement socket was not created');
    replacement.emitOpen();
    emitEvent(replacement, JSON_RPC_GATEWAY_READY_EVENT, { replacement: true });
    await flush();
    const resume = frame(replacement, 0);
    emitResponse(replacement, resume.id as string, { restored: true });

    await expect(outer).rejects.toMatchObject({ code: 'aborted' });
    await nested;
    expect(callbackCount).toBe(1);
    expect(transport.state.status).toBe('ready');
  });
});
