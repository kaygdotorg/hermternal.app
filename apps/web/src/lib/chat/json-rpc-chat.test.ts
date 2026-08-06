import { describe, expect, it, vi } from 'vitest';
import {
  JSON_RPC_HANDSHAKE_METHOD,
  JSON_RPC_PROMPT_METHOD,
  JsonRpcChatError,
  createJsonRpcChatTransport,
  type JsonRpcChatEvent,
  type JsonRpcChatOptions,
  type JsonRpcWebSocket
} from './json-rpc-chat';

class FakeWebSocket implements JsonRpcWebSocket {
  onopen: ((event?: unknown) => void) | null = null;
  onmessage: ((event: { readonly data: unknown }) => void) | null = null;
  onerror: ((event?: unknown) => void) | null = null;
  onclose: ((event?: { readonly code?: number; readonly reason?: string }) => void) | null = null;
  readonly sent: string[] = [];
  closed: { readonly code?: number; readonly reason?: string } | undefined;

  send(data: string): void {
    if (this.closed) {
      throw new Error('socket-closed');
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
    this.onmessage?.({ data: typeof data === 'string' ? data : JSON.stringify(data) });
  }

  emitClose(code = 1006, reason = ''): void {
    const handler = this.onclose;
    handler?.({ code, reason });
  }
}

interface TestHarness {
  readonly transport: ReturnType<typeof createJsonRpcChatTransport>;
  readonly sockets: FakeWebSocket[];
  readonly tickets: string[];
  readonly options: JsonRpcChatOptions;
}

function makeHarness(overrides: Partial<JsonRpcChatOptions> = {}): TestHarness {
  const sockets: FakeWebSocket[] = [];
  const tickets: string[] = [];
  let ticketCount = 0;
  const options: JsonRpcChatOptions = {
    ticketProvider: async (signal) => {
      if (signal.aborted) {
        throw new JsonRpcChatError('aborted');
      }
      ticketCount += 1;
      return `ticket-${ticketCount}`;
    },
    createWebSocket: (ticket) => {
      tickets.push(ticket);
      const socket = new FakeWebSocket();
      sockets.push(socket);
      return socket;
    },
    ...overrides
  };
  return {
    transport: createJsonRpcChatTransport(options),
    sockets,
    tickets,
    options
  };
}

async function flush(): Promise<void> {
  for (let index = 0; index < 6; index += 1) {
    await Promise.resolve();
  }
}

async function connectHarness(harness: TestHarness): Promise<FakeWebSocket> {
  const connection = harness.transport.connect();
  await flush();
  const socket = harness.sockets.at(-1);
  if (!socket) {
    throw new Error('fake socket was not created');
  }
  socket.emitOpen();
  const handshake = frame(socket, 0);
  expect(handshake.method).toBe(JSON_RPC_HANDSHAKE_METHOD);
  socket.emitMessage({
    jsonrpc: '2.0',
    id: handshake.id,
    result: { accepted: true }
  });
  await connection;
  return socket;
}

function frame(socket: FakeWebSocket, index: number): Record<string, unknown> {
  const raw = socket.sent[index];
  if (!raw) {
    throw new Error(`missing frame ${index}`);
  }
  return JSON.parse(raw) as Record<string, unknown>;
}

function emitResponse(socket: FakeWebSocket, id: string): void {
  socket.emitMessage({ jsonrpc: '2.0', id, result: { accepted: true } });
}

function emitEvent(socket: FakeWebSocket, method: string, params: Record<string, unknown>): void {
  socket.emitMessage({ jsonrpc: '2.0', method, params });
}

describe('createJsonRpcChatTransport', () => {
  it('performs the handshake and emits ordered stream, tool, approval, clarification, and completion events', async () => {
    const events: JsonRpcChatEvent[] = [];
    const harness = makeHarness();
    harness.transport.subscribe((event) => events.push(event));
    const socket = await connectHarness(harness);

    const request = harness.transport.sendPrompt('synthetic prompt');
    const prompt = frame(socket, 1);
    expect(prompt).toMatchObject({
      jsonrpc: '2.0',
      method: JSON_RPC_PROMPT_METHOD,
      params: { prompt: 'synthetic prompt' }
    });
    expect(typeof prompt.id).toBe('string');
    emitResponse(socket, prompt.id as string);

    emitEvent(socket, 'chat.stream', {
      request_id: prompt.id,
      sequence: 1,
      delta: 'synthetic '
    });
    emitEvent(socket, 'chat.tool', {
      request_id: prompt.id,
      sequence: 2,
      tool_call_id: 'tool-1',
      name: 'lookup',
      phase: 'started'
    });
    emitEvent(socket, 'chat.approval', {
      request_id: prompt.id,
      sequence: 3,
      approval_id: 'approval-1',
      title: 'Synthetic approval',
      state: 'requested',
      approved: null
    });
    emitEvent(socket, 'chat.clarification', {
      request_id: prompt.id,
      sequence: 4,
      clarification_id: 'clarification-1',
      question: 'Synthetic clarification?'
    });
    emitEvent(socket, 'chat.complete', {
      request_id: prompt.id,
      sequence: 5,
      outcome: 'success'
    });

    await expect(request.completion).resolves.toMatchObject({
      type: 'completion',
      requestId: prompt.id,
      sequence: 5,
      outcome: 'success'
    });
    expect(request.state).toEqual({ id: prompt.id, status: 'completed' });
    expect(events.map((event) => event.type)).toEqual([
      'stream',
      'tool',
      'approval',
      'clarification',
      'completion'
    ]);
    expect(events.map((event) => event.sequence)).toEqual([1, 2, 3, 4, 5]);
  });

  it('sends approval and clarification responses with request IDs but no prompt replay material', async () => {
    const harness = makeHarness();
    const socket = await connectHarness(harness);
    const request = harness.transport.sendPrompt('do not copy this prompt');
    const prompt = frame(socket, 1);
    emitResponse(socket, prompt.id as string);

    const approval = harness.transport.respondToApproval(prompt.id as string, 'approval-1', true);
    const approvalFrame = frame(socket, 2);
    expect(approvalFrame).toMatchObject({
      jsonrpc: '2.0',
      method: 'chat.approval.respond',
      params: { request_id: prompt.id, approval_id: 'approval-1', approved: true }
    });
    expect(JSON.stringify(approvalFrame)).not.toContain('do not copy this prompt');
    emitResponse(socket, approvalFrame.id as string);
    await approval;

    const clarification = harness.transport.answerClarification(
      prompt.id as string,
      'clarification-1',
      'synthetic answer'
    );
    const clarificationFrame = frame(socket, 3);
    expect(clarificationFrame).toMatchObject({
      jsonrpc: '2.0',
      method: 'chat.clarification.respond',
      params: {
        request_id: prompt.id,
        clarification_id: 'clarification-1',
        answer: 'synthetic answer'
      }
    });
    emitResponse(socket, clarificationFrame.id as string);
    await clarification;
  });

  it('fails closed on malformed frames without retaining frame material', async () => {
    const onClose = vi.fn();
    const harness = makeHarness({ onClose });
    const socket = await connectHarness(harness);

    socket.emitMessage('{"jsonrpc":');

    expect(socket.closed?.code).toBe(1002);
    expect(harness.transport.state.status).toBe('failed');
    expect(onClose).toHaveBeenCalledWith('protocol-error');
    expect(JSON.stringify(onClose.mock.calls)).not.toContain('jsonrpc');
  });

  it('rejects oversized frames before parsing them', async () => {
    const harness = makeHarness({ maxFrameBytes: 256 });
    const socket = await connectHarness(harness);

    socket.emitMessage('x'.repeat(257));

    expect(socket.closed?.code).toBe(1002);
    expect(harness.transport.state.status).toBe('failed');
  });

  it('rejects out-of-order events and marks an accepted prompt as uncertain', async () => {
    const harness = makeHarness();
    const socket = await connectHarness(harness);
    const request = harness.transport.sendPrompt('out-of-order prompt');
    const prompt = frame(socket, 1);
    emitResponse(socket, prompt.id as string);

    emitEvent(socket, 'chat.stream', {
      request_id: prompt.id,
      sequence: 2,
      delta: 'late'
    });

    await expect(request.completion).rejects.toMatchObject({ code: 'uncertain-delivery' });
    expect(request.state.status).toBe('uncertain-delivery');
    expect(socket.closed?.code).toBe(1002);
    expect(harness.transport.state.status).toBe('failed');
  });

  it('marks a disconnect before prompt acknowledgement uncertain and never replays it after reconnect', async () => {
    const onUncertainDelivery = vi.fn();
    const onReconnect = vi.fn();
    const harness = makeHarness({ onUncertainDelivery, onReconnect });
    const socket = await connectHarness(harness);
    const request = harness.transport.sendPrompt('one-shot prompt');
    const prompt = frame(socket, 1);

    socket.emitClose();
    await expect(request.completion).rejects.toMatchObject({ code: 'uncertain-delivery' });
    expect(request.state.status).toBe('uncertain-delivery');
    expect(onUncertainDelivery).toHaveBeenCalledWith(prompt.id);

    const reconnect = harness.transport.reconnect();
    await flush();
    const replacement = harness.sockets.at(-1);
    if (!replacement) {
      throw new Error('replacement socket was not created');
    }
    replacement.emitOpen();
    const handshake = frame(replacement, 0);
    replacement.emitMessage({ jsonrpc: '2.0', id: handshake.id, result: { accepted: true } });
    await reconnect;

    expect(harness.tickets).toEqual(['ticket-1', 'ticket-2']);
    expect(replacement.sent).toHaveLength(1);
    expect(onReconnect).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(replacement.sent)).not.toContain('one-shot prompt');
  });

  it('marks a disconnect after prompt acknowledgement uncertain and still does not replay it', async () => {
    const harness = makeHarness();
    const socket = await connectHarness(harness);
    const request = harness.transport.sendPrompt('acknowledged but incomplete');
    const prompt = frame(socket, 1);
    emitResponse(socket, prompt.id as string);

    socket.emitClose();
    await expect(request.completion).rejects.toMatchObject({ code: 'uncertain-delivery' });
    expect(request.state.status).toBe('uncertain-delivery');

    const reconnect = harness.transport.reconnect();
    await flush();
    const replacement = harness.sockets.at(-1);
    if (!replacement) {
      throw new Error('replacement socket was not created');
    }
    replacement.emitOpen();
    const handshake = frame(replacement, 0);
    replacement.emitMessage({ jsonrpc: '2.0', id: handshake.id, result: { accepted: true } });
    await reconnect;

    expect(replacement.sent).toHaveLength(1);
    expect(JSON.stringify(replacement.sent)).not.toContain('acknowledged but incomplete');
  });

  it('suppresses stale frames during rapid reconnect and uses a fresh ticket', async () => {
    const onOpen = vi.fn();
    const harness = makeHarness({ onOpen });
    const firstConnect = harness.transport.connect();
    await flush();
    const first = harness.sockets[0];
    if (!first) {
      throw new Error('first socket was not created');
    }

    const secondConnect = harness.transport.reconnect();
    await flush();
    const second = harness.sockets[1];
    if (!second) {
      throw new Error('second socket was not created');
    }

    first.emitOpen();
    first.emitMessage({ jsonrpc: '2.0', id: 'rpc-1', result: { accepted: true } });
    second.emitOpen();
    const secondHandshake = frame(second, 0);
    second.emitMessage({
      jsonrpc: '2.0',
      id: secondHandshake.id,
      result: { accepted: true }
    });

    await expect(firstConnect).rejects.toMatchObject({ code: 'aborted' });
    await secondConnect;
    expect(harness.transport.state).toMatchObject({ status: 'connected', generation: 2 });
    expect(harness.tickets).toEqual(['ticket-1', 'ticket-2']);
    expect(onOpen).toHaveBeenCalledTimes(1);
  });

  it('cancels without replaying prompt text or forwarding an abort reason', async () => {
    const onAbort = vi.fn();
    const harness = makeHarness({ onAbort });
    const socket = await connectHarness(harness);
    const controller = new AbortController();
    const marker = 'Bearer synthetic-secret-prompt';
    const request = harness.transport.sendPrompt(marker, { signal: controller.signal });
    const prompt = frame(socket, 1);

    controller.abort(marker);
    await expect(request.completion).rejects.toMatchObject({ code: 'cancelled', name: 'AbortError' });
    expect(request.state.status).toBe('cancelled');
    expect(onAbort).toHaveBeenCalledWith(prompt.id);

    const cancel = frame(socket, 2);
    expect(cancel).toMatchObject({
      jsonrpc: '2.0',
      method: 'chat.cancel',
      params: { request_id: prompt.id }
    });
    expect(JSON.stringify(cancel)).not.toContain(marker);
    expect(JSON.stringify(request.state)).not.toContain(marker);

    // A prompt acknowledgement racing with local cancellation is ignored, not
    // treated as a reason to replay or expose the original input.
    emitResponse(socket, prompt.id as string);
    expect(harness.transport.state.status).toBe('connected');
  });
});
