import type { BrowserChatOptions } from '$lib/chat/browser-chat';
import {
  JsonRpcChatError,
  type BoundedJsonValue,
  type JsonRpcChatEvent,
  type JsonRpcChatRequest,
  type JsonRpcChatTransport,
  type JsonRpcConnectionState
} from '$lib/chat/json-rpc-chat';
import type { LiveRestTransport, LiveSession } from '$lib/transport';
import { mapLiveMessages, mapLiveSessions } from './live-workspace';
import type { SessionSummary, TimelineItem, WorkspaceRuntimeState } from './types';

export interface LiveWorkspaceSnapshot {
  readonly state: WorkspaceRuntimeState;
  readonly sessions: SessionSummary[];
  readonly activeSessionId?: string;
  readonly title: string;
  readonly model: string;
  readonly timeline: TimelineItem[];
}

export interface LiveWorkspaceSessionOptions {
  readonly rest: LiveRestTransport;
  readonly createChat: (options: BrowserChatOptions) => JsonRpcChatTransport;
}

type LiveWorkspaceSubscriber = (snapshot: Readonly<LiveWorkspaceSnapshot>) => void;

interface PendingApproval {
  readonly requestId: string;
  readonly approvalId: string;
}

interface PendingClarification {
  readonly requestId: string;
  readonly clarificationId: string;
}

/**
 * Coordinates REST restoration and one user-led browser chat connection.
 * Server reads replace local presentation arrays. Disconnects never reconnect or
 * replay a prompt automatically, and disposal drops every session reference.
 */
export class LiveWorkspaceSession {
  private readonly rest: LiveRestTransport;
  private readonly createChat: LiveWorkspaceSessionOptions['createChat'];
  private readonly subscribers = new Set<LiveWorkspaceSubscriber>();
  private readonly approvals = new Map<string, PendingApproval>();
  private readonly clarifications = new Map<string, PendingClarification>();
  private snapshot: LiveWorkspaceSnapshot = initialSnapshot();
  private controller: AbortController | undefined;
  private chat: JsonRpcChatTransport | undefined;
  private activeRequest: JsonRpcChatRequest | undefined;
  private generation = 0;
  private disposed = false;

  constructor(options: LiveWorkspaceSessionOptions) {
    this.rest = options.rest;
    this.createChat = options.createChat;
  }

  get current(): Readonly<LiveWorkspaceSnapshot> {
    return this.snapshot;
  }

  subscribe(subscriber: LiveWorkspaceSubscriber): () => void {
    this.assertActive();
    this.subscribers.add(subscriber);
    subscriber(this.snapshot);
    return () => this.subscribers.delete(subscriber);
  }

  async initialize(): Promise<void> {
    const operation = this.begin();
    this.publish({ ...initialSnapshot(), state: 'loading' });

    try {
      const response = await this.rest.listSessions({ limit: 100, offset: 0 }, operation.signal);
      if (!this.isCurrent(operation.generation)) return;
      const liveSessions = response.sessions.filter((session) => session.archived !== true);
      const sessions = mapLiveSessions(liveSessions);
      if (liveSessions.length === 0) {
        this.publish({ ...initialSnapshot(), sessions, state: 'empty' });
        return;
      }
      const selected = liveSessions.find((session) => session.isActive) ?? liveSessions[0];
      await this.openSession(selected, sessions, operation);
    } catch (error) {
      this.publishLoadFailure(error, operation.generation);
    }
  }

  async selectSession(sessionId: string): Promise<void> {
    this.assertActive();
    const operation = this.begin();
    this.publish({ ...this.snapshot, activeSessionId: sessionId, state: 'loading', timeline: [] });

    try {
      const session = await this.rest.getSession(sessionId, operation.signal);
      if (!this.isCurrent(operation.generation)) return;
      await this.openSession(session, this.snapshot.sessions, operation);
    } catch (error) {
      this.publishLoadFailure(error, operation.generation);
    }
  }

  async createSession(): Promise<void> {
    this.assertActive();
    const operation = this.begin();
    this.publish({ ...initialSnapshot(), sessions: this.snapshot.sessions, state: 'loading' });

    const chat = this.createChat({
      onEvent: (event) => this.handleEvent(operation.generation, event),
      onStateChange: (state) => this.handleConnectionState(operation.generation, state),
      onUncertainDelivery: () => this.publishUncertainDelivery(operation.generation)
    });
    this.chat = chat;
    try {
      await chat.connect(operation.signal);
      if (!this.isCurrent(operation.generation) || this.chat !== chat) return;
      const created = await chat.createSession(operation.signal);
      if (!this.isCurrent(operation.generation) || this.chat !== chat) return;
      const model = created.model?.trim() || 'Hermes';
      const draft: SessionSummary = {
        id: created.storedSessionId,
        title: 'Untitled chat',
        detail: 'New chat',
        group: 'recent',
        selected: true
      };
      this.publish({
        state: 'empty',
        sessions: [draft, ...this.snapshot.sessions.filter((session) => session.id !== draft.id)],
        activeSessionId: created.storedSessionId,
        title: draft.title,
        model,
        timeline: []
      });
    } catch (error) {
      this.publishLoadFailure(error, operation.generation);
    }
  }

  sendPrompt(text: string): void {
    this.assertActive();
    const chat = this.chat;
    if (
      !chat ||
      (this.snapshot.state !== 'ready' && this.snapshot.state !== 'empty' && this.snapshot.state !== 'stopped')
    )
      return;

    let request: JsonRpcChatRequest;
    try {
      request = chat.sendPrompt(text);
    } catch {
      this.publish({ ...this.snapshot, state: 'retryable-error' });
      return;
    }

    this.activeRequest = request;
    const userItem: TimelineItem = {
      kind: 'user-message',
      id: `${request.id}:user`,
      text
    };
    const streamItem: TimelineItem = {
      kind: 'streaming',
      id: `${request.id}:stream`,
      text: '',
      model: this.snapshot.model
    };
    this.publish({
      ...this.snapshot,
      state: 'streaming',
      timeline: [...this.snapshot.timeline, userItem, streamItem]
    });

    void request.completion
      .then(() => this.refreshMessagesAfterCompletion(request))
      .catch((error) => this.handlePromptFailure(request, error));
  }

  async stop(): Promise<void> {
    this.assertActive();
    const request = this.activeRequest;
    if (!request || !this.chat) return;
    try {
      await this.chat.interrupt(request.id);
    } catch {
      // The visible stopped state remains local and never fabricates completion.
    }
    if (this.activeRequest !== request) return;
    this.activeRequest = undefined;
    this.publish({
      ...this.snapshot,
      state: 'stopped',
      timeline: [
        ...withoutStreamingItem(this.snapshot.timeline, request.id),
        { kind: 'stopped', id: `${request.id}:stopped`, text: 'The response was interrupted. No prompt was replayed.' }
      ]
    });
  }

  async retryConnection(): Promise<void> {
    this.assertActive();
    if (!this.chat || !this.snapshot.activeSessionId) return;
    this.publish({ ...this.snapshot, state: 'reconnecting' });
    try {
      await this.chat.reconnect();
      await this.refreshMessages(this.snapshot.activeSessionId, this.generation);
    } catch {
      if (!this.disposed) this.publish({ ...this.snapshot, state: 'retryable-error' });
    }
  }

  async approve(itemId: string, approved: boolean): Promise<void> {
    const owner = this.approvals.get(itemId);
    if (!owner || !this.chat) return;
    try {
      await this.chat.respondToApproval(owner.requestId, owner.approvalId, approved);
      this.approvals.delete(itemId);
      this.updateApprovalStatus(itemId, approved ? 'approved' : 'rejected');
    } catch {
      this.publish({ ...this.snapshot, state: 'retryable-error' });
    }
  }

  async answerClarification(itemId: string, answer: string): Promise<void> {
    const owner = this.clarifications.get(itemId);
    if (!owner || !this.chat) return;
    try {
      await this.chat.answerClarification(owner.requestId, owner.clarificationId, answer);
      this.clarifications.delete(itemId);
      this.publish({
        ...this.snapshot,
        timeline: this.snapshot.timeline.map((item) =>
          item.id === itemId && item.kind === 'clarification' ? { ...item, selectedOption: answer } : item
        )
      });
    } catch {
      this.publish({ ...this.snapshot, state: 'retryable-error' });
    }
  }

  invalidate(): void {
    if (this.disposed) return;
    this.generation += 1;
    this.controller?.abort();
    this.controller = undefined;
    this.chat?.close();
    this.chat = undefined;
    this.activeRequest = undefined;
    this.approvals.clear();
    this.clarifications.clear();
    this.publish(initialSnapshot());
  }

  dispose(): void {
    if (this.disposed) return;
    this.invalidate();
    this.disposed = true;
    this.subscribers.clear();
  }

  private async openSession(
    session: LiveSession,
    sessions: SessionSummary[],
    operation: { readonly generation: number; readonly signal: AbortSignal }
  ): Promise<void> {
    const response = await this.rest.getSessionMessages(session.id, { limit: 500, offset: 0 }, operation.signal);
    if (!this.isCurrent(operation.generation)) return;

    const model = session.model?.trim() || 'Hermes';
    const timeline = mapLiveMessages(session.id, response.messages, model);
    const chat = this.createChat({
      selectedSessionId: session.id,
      onEvent: (event) => this.handleEvent(operation.generation, event),
      onStateChange: (state) => this.handleConnectionState(operation.generation, state),
      onUncertainDelivery: () => this.publishUncertainDelivery(operation.generation)
    });
    this.chat = chat;
    this.publish({
      state: 'loading',
      sessions,
      activeSessionId: session.id,
      title: session.title?.trim() || 'Untitled chat',
      model,
      timeline
    });
    await chat.connect(operation.signal);
    if (!this.isCurrent(operation.generation) || this.chat !== chat) return;
    this.publish({ ...this.snapshot, state: timeline.length === 0 ? 'empty' : 'ready' });
  }

  private handleEvent(generation: number, event: JsonRpcChatEvent): void {
    if (!this.isCurrent(generation)) return;
    const request = this.activeRequest;

    if (event.type === 'message.delta' && request && event.requestId === request.id) {
      const delta = payloadText(event.payload);
      if (delta) this.updateStreamingText(request.id, delta, false);
      return;
    }

    if (event.type === 'message.complete' && request && event.requestId === request.id) {
      const text = payloadText(event.payload);
      if (text) this.updateStreamingText(request.id, text, true);
      return;
    }

    if ((event.type === 'tool.start' || event.type === 'tool.complete') && request) {
      const label = payloadNamedText(event.payload, 'name') ?? 'Hermes tool';
      const status = event.type === 'tool.start' ? 'running' : 'completed';
      this.publish({
        ...this.snapshot,
        timeline: [
          ...this.snapshot.timeline,
          {
            kind: 'tool',
            id: `${request.id}:${event.type}:${event.sequence ?? this.snapshot.timeline.length}`,
            label,
            detail: status === 'running' ? 'Tool execution started.' : 'Tool execution completed.',
            status
          }
        ]
      });
      return;
    }

    if (event.type === 'approval.request' && event.requestId) {
      const itemId = `approval:${event.approvalId}`;
      this.approvals.set(itemId, { requestId: event.requestId, approvalId: event.approvalId });
      this.publish({
        ...this.snapshot,
        state: 'ready',
        timeline: [
          ...this.snapshot.timeline,
          {
            kind: 'approval',
            id: itemId,
            title: payloadNamedText(event.payload, 'title') ?? 'Permission required',
            description:
              payloadNamedText(event.payload, 'description') ?? 'Hermes requires approval before continuing.',
            confirmLabel: 'Allow once',
            rejectLabel: 'Deny',
            status: 'pending'
          }
        ]
      });
      return;
    }

    if (event.type === 'clarify.request' && event.requestId) {
      const itemId = `clarification:${event.clarificationId}`;
      this.clarifications.set(itemId, { requestId: event.requestId, clarificationId: event.clarificationId });
      this.publish({
        ...this.snapshot,
        state: 'ready',
        timeline: [
          ...this.snapshot.timeline,
          {
            kind: 'clarification',
            id: itemId,
            question: payloadNamedText(event.payload, 'question') ?? 'Hermes needs more information.',
            options: payloadStringArray(event.payload, 'options')
          }
        ]
      });
    }
  }

  private updateApprovalStatus(itemId: string, status: 'approved' | 'rejected'): void {
    this.publish({
      ...this.snapshot,
      timeline: this.snapshot.timeline.map((item) =>
        item.id === itemId && item.kind === 'approval' ? { ...item, status } : item
      )
    });
  }

  private handleConnectionState(generation: number, state: JsonRpcConnectionState): void {
    if (!this.isCurrent(generation)) return;
    if (state.status === 'reconnecting') this.publish({ ...this.snapshot, state: 'reconnecting' });
    if (state.status === 'incompatible' || state.status === 'auth_required') {
      this.publish({ ...this.snapshot, state: 'permanent-error' });
    }
    if (state.status === 'failed' || state.status === 'delivery_uncertain') {
      this.publish({ ...this.snapshot, state: 'retryable-error' });
    }
  }

  private updateStreamingText(requestId: string, text: string, complete: boolean): void {
    const id = `${requestId}:stream`;
    let found = false;
    const timeline = this.snapshot.timeline.map((item): TimelineItem => {
      if (item.id !== id || item.kind !== 'streaming') return item;
      found = true;
      const nextText = complete ? text : `${item.text}${text}`;
      return complete
        ? { kind: 'assistant-message', id, text: nextText, model: item.model, status: 'complete' }
        : { ...item, text: nextText };
    });
    if (found) this.publish({ ...this.snapshot, timeline, state: complete ? 'ready' : 'streaming' });
  }

  private async refreshMessagesAfterCompletion(request: JsonRpcChatRequest): Promise<void> {
    if (this.activeRequest !== request || !this.snapshot.activeSessionId) return;
    this.activeRequest = undefined;
    await this.refreshMessages(this.snapshot.activeSessionId, this.generation);
  }

  private async refreshMessages(sessionId: string, generation: number): Promise<void> {
    try {
      const response = await this.rest.getSessionMessages(sessionId, { limit: 500, offset: 0 });
      if (!this.isCurrent(generation) || this.snapshot.activeSessionId !== sessionId) return;
      const timeline = mapLiveMessages(sessionId, response.messages, this.snapshot.model);
      this.publish({ ...this.snapshot, timeline, state: timeline.length === 0 ? 'empty' : 'ready' });
    } catch {
      if (this.isCurrent(generation)) this.publish({ ...this.snapshot, state: 'retryable-error' });
    }
  }

  private handlePromptFailure(request: JsonRpcChatRequest, error: unknown): void {
    if (this.activeRequest !== request) return;
    this.activeRequest = undefined;
    const uncertain = error instanceof JsonRpcChatError && error.code === 'uncertain-delivery';
    this.publish({
      ...this.snapshot,
      state: 'retryable-error',
      timeline: [
        ...withoutStreamingItem(this.snapshot.timeline, request.id),
        {
          kind: 'error',
          id: `${request.id}:error`,
          title: uncertain ? 'Delivery is uncertain' : 'Response interrupted',
          detail: uncertain
            ? 'Hermes may have received this prompt. Reconnect and inspect server history before sending again.'
            : 'Reconnect before sending another prompt. No prompt was replayed.'
        }
      ]
    });
  }

  private publishUncertainDelivery(generation: number): void {
    if (this.isCurrent(generation)) this.publish({ ...this.snapshot, state: 'retryable-error' });
  }

  private publishLoadFailure(error: unknown, generation: number): void {
    if (!this.isCurrent(generation) || isAbort(error)) return;
    this.publish({ ...this.snapshot, state: 'retryable-error' });
  }

  private begin(): { readonly generation: number; readonly signal: AbortSignal } {
    this.assertActive();
    this.generation += 1;
    this.controller?.abort();
    this.chat?.close();
    this.chat = undefined;
    this.activeRequest = undefined;
    this.approvals.clear();
    this.clarifications.clear();
    this.controller = new AbortController();
    return { generation: this.generation, signal: this.controller.signal };
  }

  private isCurrent(generation: number): boolean {
    return !this.disposed && generation === this.generation;
  }

  private publish(snapshot: LiveWorkspaceSnapshot): void {
    if (this.disposed) return;
    this.snapshot = snapshot;
    this.subscribers.forEach((subscriber) => subscriber(snapshot));
  }

  private assertActive(): void {
    if (this.disposed) throw new Error('Live workspace session is disposed.');
  }
}

function initialSnapshot(): LiveWorkspaceSnapshot {
  return {
    state: 'loading',
    sessions: [],
    title: 'Hermes',
    model: 'Hermes',
    timeline: []
  };
}

function withoutStreamingItem(timeline: readonly TimelineItem[], requestId: string): TimelineItem[] {
  return timeline.filter((item) => item.id !== `${requestId}:stream`);
}

function payloadText(payload: BoundedJsonValue): string | undefined {
  return (
    payloadNamedText(payload, 'delta') ?? payloadNamedText(payload, 'text') ?? payloadNamedText(payload, 'content')
  );
}

function payloadNamedText(payload: BoundedJsonValue, key: string): string | undefined {
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) return undefined;
  const value = payload[key];
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function payloadStringArray(payload: BoundedJsonValue, key: string): string[] {
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) return [];
  const value = payload[key];
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === 'string' && item.length > 0);
}

function isAbort(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError';
}
