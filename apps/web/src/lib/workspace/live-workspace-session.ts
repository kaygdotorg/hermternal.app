import type { BrowserChatOptions } from '$lib/chat/browser-chat';
import {
  JsonRpcChatError,
  type BoundedJsonValue,
  type JsonRpcChatEvent,
  type JsonRpcChatRequest,
  type JsonRpcChatTransport,
  type JsonRpcCloseClassification,
  type JsonRpcConnectionState
} from '$lib/chat/json-rpc-chat';
import { LiveRestError, type LiveRestTransport, type LiveSession } from '$lib/transport';
import { mapLiveMessages, mapLiveSessions } from './live-workspace';
import type { SessionSummary, TimelineItem, WorkspaceRuntimeState } from './types';

export interface LiveWorkspaceSnapshot {
  readonly state: WorkspaceRuntimeState;
  readonly sessions: SessionSummary[];
  readonly activeSessionId?: string;
  readonly title: string;
  readonly model: string;
  readonly timeline: TimelineItem[];
  /** Semantic terminal cause retained separately from the broad UI state. */
  readonly permanentFailure?: LiveWorkspacePermanentFailure;
}

export interface LiveWorkspaceSessionOptions {
  readonly rest: LiveRestTransport;
  readonly createChat: (options: BrowserChatOptions) => JsonRpcChatTransport;
}

type LiveWorkspaceSubscriber = (snapshot: Readonly<LiveWorkspaceSnapshot>) => void;

export type LiveWorkspacePermanentReason = 'authentication-required' | 'incompatible';

export interface LiveWorkspacePermanentFailure {
  readonly reason: LiveWorkspacePermanentReason;
  readonly closeCode?: number;
  readonly closeClassification?: JsonRpcCloseClassification;
}

interface PendingApproval {
  readonly requestId: string;
  readonly approvalId: string;
}

interface PendingClarification {
  readonly requestId: string;
  readonly clarificationId: string;
}

interface ActivePromptOwnership {
  readonly request: JsonRpcChatRequest;
  readonly generation: number;
  readonly sessionId: string;
  readonly chat: JsonRpcChatTransport;
  /** Epoch allocated after the synchronous transport send has returned. */
  readonly promptEpoch: number;
  readonly signal?: AbortSignal;
}

interface RetryOwnership {
  readonly token: number;
  readonly controller: AbortController;
  readonly removeOperationAbort: () => void;
}

interface CommittedHistoryOwnership {
  readonly generation: number;
  readonly sessionId: string;
  readonly chat: JsonRpcChatTransport;
  readonly refreshEpoch: number;
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
  private activePromptOwnership: ActivePromptOwnership | undefined;
  private retryController: AbortController | undefined;
  private retryToken = 0;
  private generation = 0;
  // History reads are presentation-owned operations. A generation protects
  // session replacement, while this monotonic epoch also protects same-session
  // overlap: a newer prompt, reconnect, terminal connection state, or
  // lifecycle reset revokes every older refresh's publication authority.
  private refreshEpoch = 0;
  // A successful REST replacement is a narrow commit barrier. A late generic
  // transport callback may not regress that committed server view, but the
  // barrier is cleared by every newer operation and never covers auth/origin
  // failures or a history read that is still pending.
  private committedHistory: CommittedHistoryOwnership | undefined;
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
    if (!this.ownsOperation(operation)) return;

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
    this.publish({
      ...this.snapshot,
      activeSessionId: sessionId,
      state: 'loading',
      timeline: [],
      permanentFailure: undefined
    });
    if (!this.ownsOperation(operation)) return;

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
    if (!this.ownsOperation(operation)) return;

    let chat: JsonRpcChatTransport;
    try {
      chat = this.createChat({
        onEvent: (event) => this.handleEvent(operation.generation, event),
        onStateChange: (state) => this.handleConnectionState(operation.generation, state),
        onUncertainDelivery: () => this.publishUncertainDelivery(operation.generation)
      });
    } catch (error) {
      this.publishLoadFailure(error, operation.generation);
      return;
    }

    // Factory acquisition is an ownership boundary. A synchronous factory may
    // reenter invalidate/dispose or start another session before returning.
    if (!this.ownsOperation(operation)) {
      closeChat(chat);
      return;
    }
    this.chat = chat;
    try {
      await chat.connect(operation.signal);
      if (!this.ownsChatOperation(operation, chat)) {
        this.closeChatIfOwned(chat);
        return;
      }
      const created = await chat.createSession(operation.signal);
      if (!this.ownsChatOperation(operation, chat)) {
        this.closeChatIfOwned(chat);
        return;
      }
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
    const generation = this.generation;
    const sessionId = this.snapshot.activeSessionId;
    const operationSignal = this.controller?.signal;
    if (
      !chat ||
      !sessionId ||
      (this.snapshot.state !== 'ready' && this.snapshot.state !== 'empty' && this.snapshot.state !== 'stopped')
    )
      return;

    let request: JsonRpcChatRequest;
    try {
      request = chat.sendPrompt(text);
    } catch {
      if (!this.ownsPromptStart(generation, chat, operationSignal) || this.activeRequest !== undefined) return;
      this.advanceRefreshEpoch();
      this.publish({ ...this.snapshot, state: 'retryable-error' });
      return;
    }

    // sendPrompt can synchronously deliver callbacks. Do not adopt a returned
    // request after invalidation, disposal, replacement, or a reentrant prompt.
    if (
      !this.ownsPromptStart(generation, chat, operationSignal) ||
      this.activeRequest !== undefined
    ) {
      try {
        request.abort();
      } catch {
        // A stale transport owns cleanup of its own request.
      }
      return;
    }

    // Allocate the prompt epoch only after the synchronous transport call has
    // returned. Completion and failure continuations consume this exact token;
    // they must never mint ownership from the promise-reaction turn.
    const promptEpoch = this.advanceRefreshEpoch();
    const ownership: ActivePromptOwnership = {
      request,
      generation,
      sessionId,
      chat,
      promptEpoch,
      signal: operationSignal
    };
    this.activeRequest = request;
    this.activePromptOwnership = ownership;
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
      .then(() => this.refreshMessagesAfterCompletion(ownership))
      .catch((error) => this.handlePromptFailure(ownership, error));
  }

  async stop(): Promise<void> {
    this.assertActive();
    const request = this.activeRequest;
    const chat = this.chat;
    const generation = this.generation;
    if (!request || !chat) return;
    try {
      await chat.interrupt(request.id);
    } catch {
      // The visible stopped state remains local and never fabricates completion.
    }
    if (
      this.activeRequest !== request ||
      !this.isCurrent(generation) ||
      this.chat !== chat
    )
      return;
    this.activeRequest = undefined;
    this.activePromptOwnership = undefined;
    this.advanceRefreshEpoch();
    this.publish({
      ...this.snapshot,
      state: 'stopped',
      timeline: [
        ...withoutStreamingItem(this.snapshot.timeline, request.id),
        { kind: 'stopped', id: `${request.id}:stopped`, text: 'The response was interrupted. No prompt was replayed.' }
      ]
    });
  }

  cancelReconnect(): void {
    this.assertActive();
    if (this.snapshot.state !== 'reconnecting') return;
    this.supersedeRetry();
    this.advanceRefreshEpoch();
    this.publish({ ...this.snapshot, state: 'offline' });
  }

  async retryConnection(): Promise<void> {
    this.assertActive();
    const chat = this.chat;
    const generation = this.generation;
    const sessionId = this.snapshot.activeSessionId;
    if (!chat || !sessionId) return;

    // Reconnect supersedes prompt completion/failure ownership before the
    // transport can synchronously publish its reconnect transition.
    this.revokeActivePrompt(true);
    if (!this.ownsChat(generation, chat, sessionId)) return;

    const operationSignal = this.controller?.signal;
    const retry = this.beginRetry(operationSignal);
    const refreshEpoch = this.advanceRefreshEpoch();
    this.publish({ ...this.snapshot, state: 'reconnecting', permanentFailure: undefined });
    // Subscribers can synchronously invalidate, replace, or start retry 2 from
    // this publication. Only the exact retry token may continue.
    if (!this.ownsRetry(generation, chat, sessionId, refreshEpoch, retry)) {
      retry.removeOperationAbort();
      return;
    }

    try {
      await chat.reconnect(retry.controller.signal);
      if (!this.ownsRetry(generation, chat, sessionId, refreshEpoch, retry)) return;
      await this.refreshMessages(sessionId, generation, chat, retry.controller.signal, refreshEpoch);
      if (!this.ownsRetry(generation, chat, sessionId, refreshEpoch, retry)) return;
    } catch (error) {
      if (!this.ownsRetry(generation, chat, sessionId, refreshEpoch, retry)) return;
      this.publishLoadFailure(error, generation);
    } finally {
      retry.removeOperationAbort();
      if (this.retryController === retry.controller) this.retryController = undefined;
    }
  }

  async approve(itemId: string, approved: boolean): Promise<void> {
    const owner = this.approvals.get(itemId);
    const chat = this.chat;
    const generation = this.generation;
    if (!owner || !chat) return;
    try {
      await chat.respondToApproval(owner.requestId, owner.approvalId, approved);
      if (!this.isCurrent(generation) || this.chat !== chat || this.approvals.get(itemId) !== owner) return;
      this.approvals.delete(itemId);
      this.updateApprovalStatus(itemId, approved ? 'approved' : 'rejected');
    } catch {
      if (!this.isCurrent(generation) || this.chat !== chat || this.approvals.get(itemId) !== owner) return;
      this.publish({ ...this.snapshot, state: 'retryable-error' });
    }
  }

  async answerClarification(itemId: string, answer: string): Promise<void> {
    const owner = this.clarifications.get(itemId);
    const chat = this.chat;
    const generation = this.generation;
    if (!owner || !chat) return;
    try {
      await chat.answerClarification(owner.requestId, owner.clarificationId, answer);
      if (!this.isCurrent(generation) || this.chat !== chat || this.clarifications.get(itemId) !== owner) return;
      this.clarifications.delete(itemId);
      this.publish({
        ...this.snapshot,
        timeline: this.snapshot.timeline.map((item) =>
          item.id === itemId && item.kind === 'clarification' ? { ...item, selectedOption: answer } : item
        )
      });
    } catch {
      if (!this.isCurrent(generation) || this.chat !== chat || this.clarifications.get(itemId) !== owner) return;
      this.publish({ ...this.snapshot, state: 'retryable-error' });
    }
  }

  invalidate(): void {
    if (this.disposed) return;
    this.resetForInvalidation(true);
  }

  dispose(): void {
    if (this.disposed) return;
    // Mark disposed and detach subscribers before closing the transport. Hermes
    // close callbacks can synchronously re-enter; no callback may publish or
    // observe a still-active workspace during disposal.
    this.disposed = true;
    this.subscribers.clear();
    this.resetForInvalidation(false);
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
    // Publish the successful REST projection before ticket or WebSocket setup.
    // A synchronous factory failure can happen before a ticket request exists;
    // retaining this bounded server view avoids replacing a valid reload with
    // an empty error screen. The restore is not committed until connect/resume
    // succeeds below, so transport failure remains retryable.
    this.publish({
      state: 'loading',
      sessions,
      activeSessionId: session.id,
      title: session.title?.trim() || 'Untitled chat',
      model,
      timeline
    });
    if (!this.ownsOperation(operation)) return;

    let chat: JsonRpcChatTransport;
    try {
      chat = this.createChat({
        selectedSessionId: session.id,
        onEvent: (event) => this.handleEvent(operation.generation, event),
        onStateChange: (state) => this.handleConnectionState(operation.generation, state),
        onUncertainDelivery: () => this.publishUncertainDelivery(operation.generation)
      });
    } catch (error) {
      this.publishLoadFailure(error, operation.generation);
      return;
    }
    // A synchronous factory can reenter the workspace. Do not adopt a resource
    // that belongs to an invalidated or replaced operation.
    if (!this.ownsOperation(operation)) {
      closeChat(chat);
      return;
    }
    this.chat = chat;
    if (!this.ownsChatOperation(operation, chat)) {
      this.closeChatIfOwned(chat);
      return;
    }
    await chat.connect(operation.signal);
    if (!this.ownsChatOperation(operation, chat)) {
      this.closeChatIfOwned(chat);
      return;
    }
    // REST history is only a committed restore after the gateway connection
    // and session resume have succeeded. A pre-ticket/connect failure must
    // remain retryable; a late generic callback after this commit must not
    // erase the server-owned timeline that is already on screen.
    this.commitHistory(operation.generation, session.id, chat);
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

    // A completed REST replacement is a narrow server-history commit. Hermes
    // can report a generic failed/uncertain callback after that commit because
    // prompt events, acknowledgements, and socket close notifications are not
    // ordered as one client transaction. Preserve the committed view only for
    // the exact generation/session/chat; pending history must still lose to a
    // failure, and auth/origin classifications always remain authoritative.
    const preserveCommittedHistory =
      (state.status === 'failed' || state.status === 'delivery_uncertain') &&
      this.ownsCommittedHistory();

    if (isTerminalConnectionStatus(state.status) && !preserveCommittedHistory) {
      this.advanceRefreshEpoch();
      this.supersedeRetry();
    }

    if (state.status === 'reconnecting') this.publish({ ...this.snapshot, state: 'reconnecting' });
    if (state.status === 'incompatible' || state.status === 'auth_required') {
      this.publishPermanentFailure(generation, {
        reason: state.status === 'auth_required' ? 'authentication-required' : 'incompatible',
        ...(state.closeCode !== undefined ? { closeCode: state.closeCode } : {}),
        ...(state.closeClassification !== undefined
          ? { closeClassification: state.closeClassification }
          : {})
      });
    }
    if (
      (state.status === 'failed' || state.status === 'delivery_uncertain') &&
      !preserveCommittedHistory
    ) {
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

  private async refreshMessagesAfterCompletion(ownership: ActivePromptOwnership): Promise<void> {
    // The transport emits message.complete before resolving the request. A
    // close/reconnect can therefore supersede this token in the same turn.
    // Never mint a new refresh epoch from a stale promise continuation.
    if (
      this.activeRequest !== ownership.request ||
      this.activePromptOwnership !== ownership ||
      !this.ownsPromptCompletion(ownership)
    )
      return;
    this.activeRequest = undefined;
    this.activePromptOwnership = undefined;
    await this.refreshMessages(
      ownership.sessionId,
      ownership.generation,
      ownership.chat,
      ownership.signal,
      ownership.promptEpoch
    );
  }

  private async refreshMessages(
    sessionId: string,
    generation: number,
    expectedChat: JsonRpcChatTransport | undefined,
    signal: AbortSignal | undefined,
    refreshEpoch: number
  ): Promise<void> {
    try {
      const response = await this.rest.getSessionMessages(
        sessionId,
        { limit: 500, offset: 0 },
        signal
      );
      if (!this.ownsRefresh(generation, sessionId, expectedChat, signal, refreshEpoch)) return;
      const timeline = mapLiveMessages(sessionId, response.messages, this.snapshot.model);
      if (!this.ownsRefresh(generation, sessionId, expectedChat, signal, refreshEpoch)) return;
      if (expectedChat) this.commitHistory(generation, sessionId, expectedChat);
      this.publish({ ...this.snapshot, timeline, state: timeline.length === 0 ? 'empty' : 'ready' });
    } catch (error) {
      // Abort and stale non-abort failures are both deliberately silent. A
      // replacement operation owns the visible state and must not be
      // downgraded to retryable-error by an old REST continuation.
      if (!this.ownsRefresh(generation, sessionId, expectedChat, signal, refreshEpoch)) return;
      if (error instanceof LiveRestError && error.code === 'unauthenticated' && error.status === 401) {
        this.publishPermanentFailure(generation, { reason: 'authentication-required' });
        return;
      }
      this.publish({ ...this.snapshot, state: 'retryable-error' });
    }
  }

  private handlePromptFailure(ownership: ActivePromptOwnership, error: unknown): void {
    if (
      this.activeRequest !== ownership.request ||
      this.activePromptOwnership !== ownership ||
      !this.ownsPromptCompletion(ownership)
    )
      return;
    this.activeRequest = undefined;
    this.activePromptOwnership = undefined;
    this.advanceRefreshEpoch();
    const uncertain = error instanceof JsonRpcChatError && error.code === 'uncertain-delivery';
    const permanentFailure = this.snapshot.permanentFailure;
    const authenticationRequired = permanentFailure?.reason === 'authentication-required';
    const incompatibleOrigin =
      permanentFailure?.reason === 'incompatible' &&
      permanentFailure.closeClassification === 'host-or-origin-rejected';
    const permanent = this.snapshot.state === 'permanent-error';
    this.publish({
      ...this.snapshot,
      // Preserve the terminal classification published by the transport before
      // the rejected completion reaches this handler. A broad permanent state
      // is not enough to choose safe sign-in versus origin guidance.
      state: permanent ? 'permanent-error' : 'retryable-error',
      timeline: [
        ...withoutStreamingItem(this.snapshot.timeline, ownership.request.id),
        {
          kind: 'error',
          id: `${ownership.request.id}:error`,
          title: authenticationRequired
            ? 'Authentication required'
            : incompatibleOrigin
              ? 'Incompatible origin'
              : permanent
                ? 'Incompatible deployment'
                : uncertain
                  ? 'Delivery is uncertain'
                  : 'Response interrupted',
          detail: authenticationRequired
            ? 'Sign in again before sending another prompt.'
            : incompatibleOrigin
              ? 'Hermes rejected this origin for chat. Use a reviewed origin before sending another prompt.'
              : permanent
                ? 'This Hermes deployment is outside the reviewed chat contract. No prompt was replayed.'
                : uncertain
                  ? 'Hermes may have received this prompt. Reconnect and inspect server history before sending again.'
                  : 'Reconnect before sending another prompt. No prompt was replayed.'
        }
      ]
    });
  }

  private publishPermanentFailure(
    generation: number,
    permanentFailure: LiveWorkspacePermanentFailure
  ): void {
    if (!this.isCurrent(generation)) return;
    this.advanceRefreshEpoch();
    const request = this.activeRequest;
    this.activeRequest = undefined;
    this.activePromptOwnership = undefined;
    this.supersedeRetry();
    const timeline = request
      ? [
          ...withoutStreamingItem(this.snapshot.timeline, request.id),
          {
            kind: 'error' as const,
            id: `${request.id}:error`,
            title: permanentFailure.reason === 'authentication-required'
              ? 'Authentication required'
              : 'Incompatible origin',
            detail: permanentFailure.reason === 'authentication-required'
              ? 'Sign in again before sending another prompt.'
              : 'Hermes rejected this origin for chat. Use a reviewed origin before sending another prompt.'
          }
        ]
      : this.snapshot.timeline;
    this.publish({ ...this.snapshot, state: 'permanent-error', permanentFailure, timeline });
  }

  private publishUncertainDelivery(generation: number): void {
    if (!this.isCurrent(generation)) return;
    // Keep the prompt owner until its completion rejection is observed. A
    // transport may publish delivery_uncertain before a terminal close state;
    // the latter must still be able to render the exact prompt error without
    // letting the stale promise mint a new refresh owner. If no prompt is
    // active, revoke any pending history read immediately. A completed REST
    // commit is the one exception: a late generic uncertainty callback cannot
    // erase that exact server-owned view.
    const preserveCommittedHistory =
      !this.activePromptOwnership && this.ownsCommittedHistory();
    if (!this.activePromptOwnership && !preserveCommittedHistory) this.advanceRefreshEpoch();
    if (preserveCommittedHistory) return;
    this.supersedeRetry();
    if (this.snapshot.state !== 'permanent-error') {
      this.publish({ ...this.snapshot, state: 'retryable-error' });
    }
  }

  private publishLoadFailure(error: unknown, generation: number): void {
    if (!this.isCurrent(generation) || isAbort(error)) return;
    // `connect()` reports a terminal auth/incompatibility state through its
    // callback before rejecting. The surrounding load catch must not downgrade
    // that state to a generic retryable error; generic load failures still
    // revoke same-generation history ownership below.
    if (this.snapshot.state === 'permanent-error') return;
    if (
      (error instanceof LiveRestError &&
        error.code === 'unauthenticated' &&
        error.status === 401) ||
      (error instanceof JsonRpcChatError && error.code === 'authentication-required')
    ) {
      this.publishPermanentFailure(generation, { reason: 'authentication-required' });
      return;
    }
    if (error instanceof JsonRpcChatError && error.code === 'incompatible') {
      this.publishPermanentFailure(generation, { reason: 'incompatible' });
      return;
    }
    // A generic terminal load failure also supersedes any same-generation
    // history owner, including one started before an explicit reconnect.
    this.advanceRefreshEpoch();
    this.activeRequest = undefined;
    this.activePromptOwnership = undefined;
    this.supersedeRetry();
    this.publish({ ...this.snapshot, state: 'retryable-error', permanentFailure: undefined });
  }

  private begin(): { readonly generation: number; readonly signal: AbortSignal } {
    this.assertActive();
    this.generation += 1;
    this.advanceRefreshEpoch();
    this.supersedeRetry();
    this.controller?.abort();
    const chat = this.chat;
    this.chat = undefined;
    this.activeRequest = undefined;
    this.activePromptOwnership = undefined;
    this.approvals.clear();
    this.clarifications.clear();
    chat?.close();
    this.controller = new AbortController();
    return { generation: this.generation, signal: this.controller.signal };
  }

  private resetForInvalidation(publishSnapshot: boolean): void {
    this.generation += 1;
    this.advanceRefreshEpoch();
    this.supersedeRetry();
    this.controller?.abort();
    this.controller = undefined;
    const chat = this.chat;
    // Detach the identity before close so close callbacks cannot act on the
    // transport that is being invalidated or trigger a second close.
    this.chat = undefined;
    this.activeRequest = undefined;
    this.activePromptOwnership = undefined;
    this.approvals.clear();
    this.clarifications.clear();
    chat?.close();
    const cleared = initialSnapshot();
    if (publishSnapshot) this.publish(cleared);
    else this.snapshot = cleared;
  }

  private advanceRefreshEpoch(): number {
    this.refreshEpoch += 1;
    this.committedHistory = undefined;
    return this.refreshEpoch;
  }

  private revokeActivePrompt(abortRequest = false): void {
    const request = this.activeRequest;
    this.activeRequest = undefined;
    this.activePromptOwnership = undefined;
    if (!request) return;
    this.advanceRefreshEpoch();
    if (abortRequest) {
      try {
        request.abort();
      } catch {
        // The transport owns cleanup of an already-stale request.
      }
    }
  }

  private beginRetry(operationSignal?: AbortSignal): RetryOwnership {
    this.retryController?.abort();
    this.retryToken += 1;
    const controller = new AbortController();
    const onOperationAbort = (): void => controller.abort();
    if (operationSignal) {
      operationSignal.addEventListener('abort', onOperationAbort, { once: true });
      if (operationSignal.aborted) controller.abort();
    }
    this.retryController = controller;
    return {
      token: this.retryToken,
      controller,
      removeOperationAbort: () =>
        operationSignal?.removeEventListener('abort', onOperationAbort)
    };
  }

  private supersedeRetry(): void {
    this.retryToken += 1;
    this.retryController?.abort();
    this.retryController = undefined;
  }

  private ownsOperation(operation: { readonly generation: number; readonly signal: AbortSignal }): boolean {
    return (
      this.isCurrent(operation.generation) &&
      this.controller?.signal === operation.signal &&
      !operation.signal.aborted
    );
  }

  private ownsChatOperation(
    operation: { readonly generation: number; readonly signal: AbortSignal },
    chat: JsonRpcChatTransport
  ): boolean {
    return this.ownsOperation(operation) && this.chat === chat;
  }

  private ownsPromptStart(
    generation: number,
    chat: JsonRpcChatTransport,
    signal: AbortSignal | undefined
  ): boolean {
    return (
      this.isCurrent(generation) &&
      this.chat === chat &&
      this.controller?.signal === signal &&
      !signal?.aborted
    );
  }

  private ownsPromptCompletion(ownership: ActivePromptOwnership): boolean {
    return (
      this.isCurrent(ownership.generation) &&
      this.chat === ownership.chat &&
      this.snapshot.activeSessionId === ownership.sessionId &&
      this.controller?.signal === ownership.signal &&
      this.refreshEpoch === ownership.promptEpoch &&
      !ownership.signal?.aborted
    );
  }

  private ownsRetry(
    generation: number,
    chat: JsonRpcChatTransport,
    sessionId: string,
    refreshEpoch: number,
    retry: RetryOwnership
  ): boolean {
    return (
      this.isCurrent(generation) &&
      this.chat === chat &&
      this.snapshot.activeSessionId === sessionId &&
      this.refreshEpoch === refreshEpoch &&
      this.retryToken === retry.token &&
      this.retryController === retry.controller &&
      !retry.controller.signal.aborted
    );
  }

  private closeChatIfOwned(chat: JsonRpcChatTransport): void {
    if (this.chat !== chat) return;
    this.chat = undefined;
    closeChat(chat);
  }

  private commitHistory(
    generation: number,
    sessionId: string,
    chat: JsonRpcChatTransport
  ): void {
    if (!this.ownsChat(generation, chat, sessionId)) return;
    this.committedHistory = {
      generation,
      sessionId,
      chat,
      refreshEpoch: this.refreshEpoch
    };
  }

  private ownsCommittedHistory(): boolean {
    const committed = this.committedHistory;
    return (
      committed !== undefined &&
      committed.generation === this.generation &&
      committed.sessionId === this.snapshot.activeSessionId &&
      committed.chat === this.chat &&
      committed.refreshEpoch === this.refreshEpoch
    );
  }

  private ownsRefresh(
    generation: number,
    sessionId: string,
    expectedChat: JsonRpcChatTransport | undefined,
    signal: AbortSignal | undefined,
    refreshEpoch: number
  ): boolean {
    return (
      !signal?.aborted &&
      refreshEpoch === this.refreshEpoch &&
      this.isCurrent(generation) &&
      this.snapshot.activeSessionId === sessionId &&
      (expectedChat === undefined || this.chat === expectedChat)
    );
  }

  private isCurrent(generation: number): boolean {
    return !this.disposed && generation === this.generation;
  }

  private ownsChat(generation: number, chat: JsonRpcChatTransport, sessionId: string): boolean {
    return this.isCurrent(generation) && this.chat === chat && this.snapshot.activeSessionId === sessionId;
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

function isTerminalConnectionStatus(status: JsonRpcConnectionState['status']): boolean {
  return (
    status === 'offline' ||
    status === 'auth_required' ||
    status === 'incompatible' ||
    status === 'failed' ||
    status === 'delivery_uncertain' ||
    status === 'closing'
  );
}

function isAbort(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError';
}

function closeChat(chat: JsonRpcChatTransport): void {
  try {
    chat.close();
  } catch {
    // Resource cleanup must not replace the bounded workspace failure.
  }
}
