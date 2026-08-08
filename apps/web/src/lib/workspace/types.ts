export type Appearance = 'light' | 'dark';

/** Presentation copy must name synthetic playback unless a future runtime explicitly opts into live status semantics. */
export type WorkspaceDataSource = 'synthetic-preview' | 'live-runtime';

export type WorkspaceRuntimeState =
  | 'ready'
  | 'streaming'
  | 'stopped'
  | 'loading'
  | 'empty'
  | 'offline'
  | 'reconnecting'
  | 'retryable-error'
  | 'permanent-error'
  | 'compatibility-check-failed'
  | 'unsupported-version';

export type ToolStatus = 'completed' | 'running' | 'pending' | 'failed';

export interface SessionSummary {
  id: string;
  title: string;
  detail?: string;
  group: 'pinned' | 'recent';
  unread?: boolean;
  selected?: boolean;
}

export interface ImageAttachment {
  id: string;
  alt: string;
  caption: string;
  src?: string;
}

export interface UserMessageItem {
  kind: 'user-message';
  id: string;
  text: string;
  attachments?: ImageAttachment[];
}

export interface AssistantMessageItem {
  kind: 'assistant-message';
  id: string;
  text: string;
  model: string;
  status?: 'complete' | 'draft';
}

export interface ToolItem {
  kind: 'tool';
  id: string;
  label: string;
  detail: string;
  status: ToolStatus;
}

export interface ApprovalItem {
  kind: 'approval';
  id: string;
  title: string;
  description: string;
  confirmLabel: string;
  rejectLabel: string;
  status: 'pending' | 'approved' | 'rejected';
}

export interface ClarificationItem {
  kind: 'clarification';
  id: string;
  question: string;
  options: string[];
  selectedOption?: string;
}

export interface ImageItem {
  kind: 'image';
  id: string;
  attachment: ImageAttachment;
}

export interface StreamingItem {
  kind: 'streaming';
  id: string;
  text: string;
  model: string;
}

export interface StoppedItem {
  kind: 'stopped';
  id: string;
  text: string;
}

export interface LoadingItem {
  kind: 'loading';
  id: string;
  label: string;
}

export interface ErrorItem {
  kind: 'error';
  id: string;
  title: string;
  detail: string;
}

export type TimelineItem =
  | UserMessageItem
  | AssistantMessageItem
  | ToolItem
  | ApprovalItem
  | ClarificationItem
  | ImageItem
  | StreamingItem
  | StoppedItem
  | LoadingItem
  | ErrorItem;

/**
 * Synthetic approval scopes are presentation metadata for the preview. The
 * live session adapter still maps every allow scope to its reviewed boolean
 * approval boundary until the transport exposes scope-aware permissions.
 */
export type ApprovalScope = 'once' | 'session' | 'always';

export type WorkspaceAction =
  | { type: 'new-session' }
  | { type: 'select-session'; sessionId: string }
  | { type: 'edit-title'; title: string }
  | { type: 'toggle-inspector' }
  | { type: 'set-model'; model: string }
  | { type: 'set-policy' }
  | { type: 'attach' }
  | { type: 'send'; text: string }
  | { type: 'stop' }
  | { type: 'retry' }
  | { type: 'cancel-reconnect' }
  | { type: 'check-connection' }
  | { type: 'back-to-sessions' }
  | { type: 'retry-compatibility-check' }
  | { type: 'return-to-sign-in' }
  | { type: 'open-workspace' }
  | { type: 'dismiss' }
  | { type: 'approve-tool'; itemId: string; scope: ApprovalScope }
  | { type: 'reject-tool'; itemId: string; scope: 'deny' }
  | { type: 'answer-clarification'; itemId: string; answer: string };

export type WorkspaceActionHandler = (action: WorkspaceAction) => void;
