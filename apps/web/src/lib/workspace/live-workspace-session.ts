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
import {
  consumeLiveRestCanonicalAlias,
  getLiveRestSessionForWorkspace,
  resetLiveRestCanonicalAliasScope
} from '$lib/transport/live-rest-transport';
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
  /** Set only after this exact prompt receives a successful message.complete event. */
  completionObserved: boolean;
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

interface CommittedCompletionOwnership {
  readonly generation: number;
  readonly sessionId: string;
  readonly chat: JsonRpcChatTransport;
  readonly request: JsonRpcChatRequest;
  readonly refreshEpoch: number;
}

interface PendingCompletionOwnership extends CommittedCompletionOwnership {
  deferredGenericFailure: boolean;
}

/**
 * Keeps only the opaque persisted session identity needed to route Retry back
 * through restore after history loading fails before the session is published.
 * No transcript, prompt, ticket, or transport payload belongs here.
 */
interface FailedRestoreOwnership {
  readonly generation: number;
  readonly sessionId: string;
}

/**
 * A created chat is displayed under its future REST ID before its first turn
 * exists. Its live socket ID is deliberately not resumable until a successful
 * post-completion REST read confirms that Hermes persisted the row.
 */
interface CreatedDraftOwnership {
  readonly generation: number;
  readonly sessionId: string;
  readonly chat: JsonRpcChatTransport;
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
  // A retry after factory failure owns the workspace controller because there
  // is no transport-specific reconnect operation to abort.
  private factoryRetryGeneration: number | undefined;
  private generation = 0;
  // History reads are presentation-owned operations. A generation protects
  // session replacement, while this monotonic epoch also protects same-session
  // overlap: a newer prompt, reconnect, terminal connection state, or
  // lifecycle reset revokes every older refresh's publication authority.
  private refreshEpoch = 0;
  // A successful REST replacement is a general history barrier for retaining
  // the server-owned timeline. Generic failure suppression is narrower and
  // requires committedCompletion below; this barrier is cleared by every newer
  // operation and never covers auth/origin failures or pending reads.
  private committedHistory: CommittedHistoryOwnership | undefined;
  // Generic late failures may be ignored only after the exact prompt observed a
  // successful message.complete and its REST reconciliation committed. Initial
  // restore and reconnect history use committedHistory but never this marker.
  private committedCompletion: CommittedCompletionOwnership | undefined;
  // A completion event establishes a short-lived owner before the REST response
  // arrives. A matching generic failure is deferred against this owner rather
  // than advancing the refresh epoch; auth/origin/uncertain failures still
  // revoke it immediately.
  private pendingCompletion: PendingCompletionOwnership | undefined;
  private failedRestore: FailedRestoreOwnership | undefined;
  private createdDraft: CreatedDraftOwnership | undefined;
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
      await this.openSession(selected, sessions, operation, selected.id);
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
      const session = await getLiveRestSessionForWorkspace(
        this.rest,
        this,
        sessionId,
        operation.signal
      );
      if (!this.isCurrent(operation.generation)) return;
      await this.openSession(session, this.snapshot.sessions, operation, sessionId);
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
      this.createdDraft = {
        generation: operation.generation,
        sessionId: created.storedSessionId,
        chat
      };
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
      this.activeRequest !== undefined ||
      (this.snapshot.state !== 'ready' && this.snapshot.state !== 'empty' && this.snapshot.state !== 'stopped')
    )
      return;

    // Completion publication can synchronously reenter through a subscriber
    // while the completed request still owns its REST reconciliation. Reject
    // that send before transport delivery; the post-call guard remains below
    // for callbacks that originate inside the transport call itself.
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
      signal: operationSignal,
      completionObserved: false
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
    if (this.factoryRetryGeneration === this.generation) {
      // Factory retries have no chat identity yet; abort the workspace
      // operation itself so a late REST result cannot start a new transport.
      resetLiveRestCanonicalAliasScope(this.rest, this);
      this.controller?.abort();
      this.factoryRetryGeneration = undefined;
    }
    this.supersedeRetry();
    this.advanceRefreshEpoch();
    this.publish({ ...this.snapshot, state: 'offline' });
  }

  async retryConnection(): Promise<void> {
    this.assertActive();
    const chat = this.chat;
    const sessionId = this.snapshot.activeSessionId;

    if (!chat) {
      const failedRestoreSessionId =
        this.failedRestore?.generation === this.generation ? this.failedRestore.sessionId : undefined;
      if (sessionId ?? failedRestoreSessionId) {
        // A history failure can happen before openSession publishes the active
        // identity. Retry that same opaque persisted session instead of routing
        // the action to createSession and silently creating a second session.
        await this.retryActiveSession(sessionId ?? failedRestoreSessionId!);
      } else {
        // A new-session factory can fail before a stored session ID exists.
        // Retry the guarded create path instead of leaving the visible Retry
        // action inert; createSession's generation ownership coalesces stale
        // or reentrant attempts before a transport is adopted.
        await this.createSession();
      }
      return;
    }

    if (!sessionId) return;

    const generation = this.generation;
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
      if (this.ownsCreatedDraft(generation, sessionId, chat)) {
        // The server has not confirmed this draft exists yet. The transport
        // intentionally reconnects without session.resume or a REST read; keep
        // the composer disabled until the user explicitly starts a replacement
        // draft rather than presenting an empty-looking stale live identity.
        this.publish({ ...this.snapshot, state: 'retryable-error' });
        return;
      }
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

  private async retryActiveSession(sessionId: string): Promise<void> {
    // A factory failure leaves no chat identity to reconnect. Start a new
    // generation so Retry repeats the complete active-session path: REST
    // session lookup, bounded history read, ticket acquisition, WebSocket
    // connection, and session resume. A reentrant or newer retry aborts this
    // operation and stale callbacks cannot create or publish a replacement.
    const operation = this.begin();
    const sessions = this.snapshot.sessions;
    // Preserve the opaque restore target across the new retry generation. If
    // the session lookup or history read fails again before identity is shown,
    // the next Retry must still address this persisted session.
    this.failedRestore = { generation: operation.generation, sessionId };
    this.factoryRetryGeneration = operation.generation;
    this.publish({ ...this.snapshot, state: 'reconnecting', permanentFailure: undefined });
    if (!this.ownsFactoryRetry(operation)) return;

    try {
      const session = await getLiveRestSessionForWorkspace(
        this.rest,
        this,
        sessionId,
        operation.signal
      );
      if (!this.ownsFactoryRetry(operation)) return;
      await this.openSession(session, sessions, operation, sessionId);
    } catch (error) {
      if (this.ownsFactoryRetry(operation)) this.publishLoadFailure(error, operation.generation);
    } finally {
      if (this.factoryRetryGeneration === operation.generation) {
        this.factoryRetryGeneration = undefined;
      }
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
    operation: { readonly generation: number; readonly signal: AbortSignal },
    requestedSessionId: string
  ): Promise<void> {
    // Keep only the opaque persisted identity until the first bounded history
    // read succeeds. This private retry target covers failures that occur
    // before the active session can be published to the presentation state.
    if (!this.ownsOperation(operation)) return;
    // getLiveRestSessionForWorkspace returns one frozen detached projection.
    // Capture the values once so every later history, mapping, publication, and
    // Chat decision uses the same identity snapshot rather than re-reading a
    // mutable adapter object.
    const capturedSessionId = session.id;
    const capturedModel = session.model;
    const capturedTitle = session.title;
    const canonicalSessionId = consumeLiveRestCanonicalAlias(
      this.rest,
      this,
      session,
      requestedSessionId
    );
    if (capturedSessionId !== requestedSessionId && canonicalSessionId !== capturedSessionId) {
      throw new LiveRestError('invalid-response');
    }
    const canonicalizedAlias = canonicalSessionId !== undefined;
    const expectedActiveSessionId = this.snapshot.activeSessionId;
    this.failedRestore = { generation: operation.generation, sessionId: capturedSessionId };
    const response = await this.rest.getSessionMessages(
      capturedSessionId,
      { limit: 500, offset: 0 },
      operation.signal
    );
    // Cancellation may leave the generation unchanged while aborting the
    // controller. Do not publish a late provisional timeline over the user's
    // explicit offline state when a REST adapter resolves after abort.
    if (!this.ownsOperation(operation)) return;
    // History remains strict even when the detail route resolved an alias. The
    // only permitted mismatch with the provisional snapshot is the canonical ID
    // authorized by the private one-shot detail record; foreign history never reaches
    // presentation state or creates a transport that could resume it.
    if (
      response.sessionId !== capturedSessionId ||
      (expectedActiveSessionId !== undefined &&
        response.sessionId !== expectedActiveSessionId &&
        !(canonicalizedAlias && expectedActiveSessionId === requestedSessionId))
    ) {
      throw new LiveRestError('invalid-response');
    }
    const model = capturedModel?.trim() || 'Hermes';
    const timeline = mapLiveMessages(capturedSessionId, response.messages, model);
    // Once history is available, the normal snapshot now carries the selected
    // identity and subsequent retry routing can use that public session ID.
    this.failedRestore = undefined;
    // Publish the successful REST projection before ticket or WebSocket setup.
    // A synchronous factory failure can happen before a ticket request exists;
    // retaining this bounded server view avoids replacing a valid reload with
    // an empty error screen. The restore is not committed until connect/resume
    // succeeds below, so transport failure remains retryable.
    this.publish({
      state: 'loading',
      sessions,
      activeSessionId: capturedSessionId,
      title: capturedTitle?.trim() || 'Untitled chat',
      model,
      timeline
    });
    if (!this.ownsOperation(operation)) return;

    let chat: JsonRpcChatTransport;
    try {
      chat = this.createChat({
        selectedSessionId: capturedSessionId,
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
    this.commitHistory(operation.generation, capturedSessionId, chat);
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
      const ownership = this.activePromptOwnership;
      if (
        !ownership ||
        ownership.request !== request ||
        !this.ownsPromptCompletion(ownership) ||
        // JsonRpcChatTransport already fails closed when a wire event names a
        // different session. Keep the optional projected ID in this ownership
        // check too, so an adapter cannot promote a cross-session completion.
        (event.sessionId !== undefined && event.sessionId !== ownership.sessionId)
      ) {
        return;
      }
      if (isSuccessfulMessageComplete(event.payload)) {
        ownership.completionObserved = true;
        this.pendingCompletion = {
          generation: ownership.generation,
          sessionId: ownership.sessionId,
          chat: ownership.chat,
          request: ownership.request,
          refreshEpoch: ownership.promptEpoch,
          deferredGenericFailure: false
        };
      }
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

    // Hermes can report a generic failed/uncertain callback after REST because
    // prompt events, acknowledgements, and socket close notifications are not
    // ordered as one client transaction. An exact completed-prompt marker can
    // suppress generic failure only after REST commits; while that exact read is
    // pending, only a matching generic failure may be deferred. Auth/origin and
    // uncertain classifications remain authoritative immediately.
    const committedHistory = this.ownsCommittedHistory();
    const preserveLateGenericFailure = state.status === 'failed' && this.ownsCommittedCompletion();
    const deferLateGenericFailure =
      state.status === 'failed' && this.deferPendingGenericFailure();
    const preserveLateUncertainty = state.status === 'delivery_uncertain' && committedHistory;

    if (
      isTerminalConnectionStatus(state.status) &&
      !preserveLateGenericFailure &&
      !deferLateGenericFailure &&
      !preserveLateUncertainty
    ) {
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
    if (preserveLateGenericFailure) {
      // A generic terminal callback after successful completion and REST
      // reconciliation is stale lifecycle information. Keep the confirmed
      // server history and ready state; a real uncertain or classified close
      // still takes the recovery/permanent path below.
      return;
    }
    if (deferLateGenericFailure) {
      // The exact prompt completed, but REST has not committed its server-owned
      // replacement yet. Keep the transient completion view until that read
      // settles; a failure, cancellation, or ownership loss will revoke it.
      return;
    }
    if (preserveLateUncertainty) {
      // Uncertain delivery remains actionable recovery even when the last
      // completed history read succeeded. Never treat uncertainty as success.
      this.supersedeRetry();
      this.publish({ ...this.snapshot, state: 'retryable-error' });
      return;
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
    const completionOwnership = ownership.completionObserved ? ownership : undefined;
    if (completionOwnership && !this.ownsPendingCompletion(completionOwnership)) {
      this.pendingCompletion = {
        generation: completionOwnership.generation,
        sessionId: completionOwnership.sessionId,
        chat: completionOwnership.chat,
        request: completionOwnership.request,
        refreshEpoch: completionOwnership.promptEpoch,
        deferredGenericFailure: false
      };
    }
    this.activeRequest = undefined;
    this.activePromptOwnership = undefined;
    await this.refreshMessages(
      ownership.sessionId,
      ownership.generation,
      ownership.chat,
      ownership.signal,
      ownership.promptEpoch,
      completionOwnership
    );
  }

  private async refreshMessages(
    sessionId: string,
    generation: number,
    expectedChat: JsonRpcChatTransport | undefined,
    signal: AbortSignal | undefined,
    refreshEpoch: number,
    completionOwnership?: ActivePromptOwnership
  ): Promise<void> {
    try {
      const response = await this.rest.getSessionMessages(
        sessionId,
        { limit: 500, offset: 0 },
        signal
      );
      if (!this.ownsRefresh(generation, sessionId, expectedChat, signal, refreshEpoch)) {
        if (completionOwnership) this.clearPendingCompletion(completionOwnership.request);
        return;
      }
      // REST may resolve aliases to canonical IDs at the transport boundary,
      // but every workspace history refresh is owned by the requested durable
      // session. A different response must not replace the timeline, promote a
      // draft, or commit either history ownership record for a foreign session.
      if (response.sessionId !== sessionId || response.sessionId !== this.snapshot.activeSessionId) {
        throw new LiveRestError('invalid-response');
      }
      const timeline = mapLiveMessages(sessionId, response.messages, this.snapshot.model);
      if (!this.ownsRefresh(generation, sessionId, expectedChat, signal, refreshEpoch)) {
        if (completionOwnership) this.clearPendingCompletion(completionOwnership.request);
        return;
      }
      if (expectedChat) {
        if (this.ownsCreatedDraft(generation, sessionId, expectedChat)) {
          // A completed first turn plus this successful server read establishes
          // persistence. Promote only this exact chat, generation, and stored
          // ID so stale completions cannot change a replacement's reconnect key.
          expectedChat.promoteSession(sessionId);
          this.createdDraft = undefined;
        }
        this.commitHistory(generation, sessionId, expectedChat);
        if (completionOwnership) {
          this.commitCompletionHistory(completionOwnership);
          this.clearPendingCompletion(completionOwnership.request);
        }
      }
      this.publish({ ...this.snapshot, timeline, state: timeline.length === 0 ? 'empty' : 'ready' });
    } catch (error) {
      // Abort and stale non-abort failures are both deliberately silent. A
      // replacement operation owns the visible state and must not be
      // downgraded to retryable-error by an old REST continuation.
      if (!this.ownsRefresh(generation, sessionId, expectedChat, signal, refreshEpoch)) {
        if (completionOwnership) this.clearPendingCompletion(completionOwnership.request);
        return;
      }
      if (completionOwnership) this.clearPendingCompletion(completionOwnership.request);
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
    if (preserveCommittedHistory) {
      // The committed timeline remains readable, but the uncertain transport
      // is not sendable. Expose recovery so the composer keeps any draft and
      // cannot clear it by attempting a prompt on a dead socket.
      this.supersedeRetry();
      this.publish({ ...this.snapshot, state: 'retryable-error' });
      return;
    }
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
    resetLiveRestCanonicalAliasScope(this.rest, this);
    this.failedRestore = undefined;
    this.createdDraft = undefined;
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
    resetLiveRestCanonicalAliasScope(this.rest, this);
    this.failedRestore = undefined;
    this.createdDraft = undefined;
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
    this.committedCompletion = undefined;
    this.pendingCompletion = undefined;
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

  private ownsFactoryRetry(operation: {
    readonly generation: number;
    readonly signal: AbortSignal;
  }): boolean {
    return (
      this.factoryRetryGeneration === operation.generation && this.ownsOperation(operation)
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

  private commitCompletionHistory(ownership: ActivePromptOwnership): void {
    if (
      !ownership.completionObserved ||
      ownership.promptEpoch !== this.refreshEpoch ||
      !this.ownsChat(ownership.generation, ownership.chat, ownership.sessionId)
    )
      return;
    this.committedCompletion = {
      generation: ownership.generation,
      sessionId: ownership.sessionId,
      chat: ownership.chat,
      request: ownership.request,
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

  private ownsCommittedCompletion(): boolean {
    const committed = this.committedCompletion;
    return (
      committed !== undefined &&
      committed.generation === this.generation &&
      committed.sessionId === this.snapshot.activeSessionId &&
      committed.chat === this.chat &&
      committed.refreshEpoch === this.refreshEpoch
    );
  }

  private ownsPendingCompletion(
    ownership?: Pick<CommittedCompletionOwnership, 'request'>
  ): PendingCompletionOwnership | undefined {
    const pending = this.pendingCompletion;
    if (
      pending === undefined ||
      (ownership !== undefined && pending.request !== ownership.request) ||
      pending.generation !== this.generation ||
      pending.sessionId !== this.snapshot.activeSessionId ||
      pending.chat !== this.chat ||
      pending.refreshEpoch !== this.refreshEpoch
    )
      return undefined;
    return pending;
  }

  private deferPendingGenericFailure(): boolean {
    const pending = this.ownsPendingCompletion();
    if (!pending) return false;
    pending.deferredGenericFailure = true;
    return true;
  }

  private clearPendingCompletion(request: JsonRpcChatRequest): void {
    if (this.pendingCompletion?.request === request) this.pendingCompletion = undefined;
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

  private ownsCreatedDraft(
    generation: number,
    sessionId: string,
    chat: JsonRpcChatTransport
  ): boolean {
    const draft = this.createdDraft;
    return (
      draft !== undefined &&
      draft.generation === generation &&
      draft.sessionId === sessionId &&
      draft.chat === chat &&
      this.ownsChat(generation, chat, sessionId)
    );
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

function isSuccessfulMessageComplete(payload: BoundedJsonValue): boolean {
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) return true;
  const status = payload.status ?? payload.outcome;
  return status !== 'error' && status !== 'failed' && status !== 'cancelled';
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
