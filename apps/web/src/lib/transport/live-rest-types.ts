export type NullableString = string | null;

/**
 * The pinned Hermes web type defines message content as text or null. The
 * transport keeps that source authority instead of widening the REST boundary
 * to arbitrary JSON values returned by an unreviewed future route.
 */
export type LiveMessageContent = string | null;

export interface LiveToolCall {
  id: string;
  function: {
    name: string;
    arguments: string;
  };
}

export interface LiveProvider {
  name: string;
  displayName: string;
  supportsPassword: boolean;
}

export interface ProviderDiscovery {
  providers: LiveProvider[];
}

export interface AuthIdentity {
  userId: string;
  email: string;
  displayName: string;
  organizationId: string;
  provider: string;
  expiresAt: number;
}

export interface LiveSession {
  id: string;
  source: NullableString;
  model: NullableString;
  title: NullableString;
  startedAt: number;
  endedAt: number | null;
  lastActive: number;
  isActive: boolean;
  messageCount: number;
  toolCallCount: number;
  inputTokens: number;
  outputTokens: number;
  preview: NullableString;
  parentSessionId?: NullableString;
  // These fields are additive session-list metadata observed in the pinned
  // route. They remain optional because SessionInfo does not require them.
  archived?: boolean;
  pinned?: boolean;
  profile?: string;
  isDefaultProfile?: boolean;
}

export interface SessionList {
  sessions: LiveSession[];
  total: number;
  limit: number;
  offset: number;
}

export type LiveMessageRole = 'user' | 'assistant' | 'system' | 'tool';

export interface LiveMessage {
  role: LiveMessageRole;
  content: LiveMessageContent;
  toolCalls?: LiveToolCall[];
  toolName?: string;
  toolCallId?: string;
  timestamp?: number;
}

export interface SessionMessages {
  sessionId: string;
  messages: LiveMessage[];
  pagination: {
    limit: number | null;
    offset: number;
    returned: number;
  };
}

export interface SessionListOptions {
  limit?: number;
  offset?: number;
}

export interface MessageListOptions {
  limit?: number;
  offset?: number;
}
