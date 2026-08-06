export type NullableString = string | null;

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
  email: NullableString;
  displayName: NullableString;
  organizationId: NullableString;
  provider: string;
  expiresAt: NullableString;
}

export interface LiveSession {
  id: string;
  title?: NullableString;
  preview?: NullableString;
  source?: NullableString;
  model?: NullableString;
  startedAt?: NullableString;
  endedAt?: NullableString;
  lastActive?: NullableString;
  parentSessionId?: NullableString;
  messageCount?: number;
  toolCallCount?: number;
  inputTokens?: number;
  outputTokens?: number;
  isActive?: boolean;
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
  id: string;
  role: LiveMessageRole;
  content: string;
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
