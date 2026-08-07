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

/**
 * Official Hermes history may serialize an empty tool-call field as null even
 * though the pinned source type declares it as optional. Keep that distinction
 * lossless while retaining a bounded array shape for non-null values.
 */
export type LiveToolCalls = LiveToolCall[] | null;

export interface LiveProvider {
  name: string;
  displayName: string;
  supportsPassword: boolean;
}

export interface ProviderDiscovery {
  providers: LiveProvider[];
}

export interface AuthIdentity {
  /** Stable identity returned only for an authenticated Dashboard session. */
  userId: string;
  /** Optional profile metadata; the Basic provider may return an empty value. */
  email: string;
  /** Optional profile metadata; the Basic provider may return an empty value. */
  displayName: string;
  /** Optional profile metadata; the Basic provider may return an empty value. */
  organizationId: string;
  /** Stable provider identity returned with an authenticated session. */
  provider: string;
  /** Stable, bounded session-expiry value returned with an authenticated session. */
  expiresAt: number;
}

/**
 * Shared authentication proof for REST and browser-session boundaries.
 * Profile metadata is present in the source projection but is not proof that a
 * protected session exists; only the stable user/provider fields and bounded
 * expiry participate in the authenticated identity invariant.
 */
export function isAuthIdentity(value: unknown): value is AuthIdentity {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const candidate = value as Record<string, unknown>;
  if (Object.keys(candidate).sort().join('|') !== 'displayName|email|expiresAt|organizationId|provider|userId') {
    return false;
  }

  const boundedText = (item: unknown): item is string =>
    typeof item === 'string' && item.length <= 512;
  const stableText = (item: unknown): item is string =>
    boundedText(item) && item.length > 0;

  return (
    stableText(candidate.userId) &&
    boundedText(candidate.email) &&
    boundedText(candidate.displayName) &&
    boundedText(candidate.organizationId) &&
    stableText(candidate.provider) &&
    typeof candidate.expiresAt === 'number' &&
    Number.isInteger(candidate.expiresAt) &&
    candidate.expiresAt >= 0 &&
    candidate.expiresAt <= 4_294_967_295
  );
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
  toolCalls?: LiveToolCalls;
  /** Official history may emit null for either optional tool metadata field. */
  toolName?: NullableString;
  toolCallId?: NullableString;
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
