import type { StrictJsonValue } from './strict-json';

export type NullableString = string | null;

/**
 * Lossless bounded JSON content from the pinned message projection. The root
 * may be null, text, a list, or a dictionary; nested values remain the
 * parser's bounded JSON values so multimodal and tool payloads are not
 * flattened or string-coerced.
 */
export type LiveMessageContent =
  | null
  | string
  | StrictJsonValue[]
  | { [key: string]: StrictJsonValue };

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
  expiresAt: number | null;
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
  id: number;
  role: LiveMessageRole;
  content: LiveMessageContent;
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
