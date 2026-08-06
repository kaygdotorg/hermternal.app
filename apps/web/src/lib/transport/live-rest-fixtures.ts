import type {
  AuthIdentity,
  LiveProvider,
  LiveSession,
  LiveMessage,
  ProviderDiscovery,
  SessionList,
  SessionMessages
} from './live-rest-types';

/**
 * These fixtures are redacted synthetic transport evidence. They describe the
 * accepted client shapes without pretending that a provider, cookie, session,
 * message, hostname, or Hermes deployment is live.
 */
export const LIVE_REST_FIXTURE_IDS = Object.freeze({
  providerDiscovery: 'w06-provider-discovery-v1',
  authState: 'w06-auth-state-v1',
  sessionList: 'w06-session-list-v1',
  sessionDetail: 'w06-session-detail-v1',
  sessionMessages: 'w06-session-messages-v1'
});

export const LIVE_PROVIDER_FIXTURE: LiveProvider = Object.freeze({
  name: 'synthetic-provider',
  displayName: 'Synthetic Provider',
  supportsPassword: false
});

export const LIVE_PROVIDER_DISCOVERY_FIXTURE: ProviderDiscovery = Object.freeze({
  providers: [LIVE_PROVIDER_FIXTURE]
});

export const LIVE_AUTH_IDENTITY_FIXTURE: AuthIdentity = Object.freeze({
  userId: 'synthetic-user',
  email: 'synthetic@example.invalid',
  displayName: 'Synthetic User',
  organizationId: 'synthetic-org',
  provider: 'synthetic-provider',
  // Synthetic Unix seconds prove the source-backed numeric representation.
  expiresAt: 1_767_225_600
});

export const LIVE_SESSION_FIXTURE: LiveSession = Object.freeze({
  id: 'synthetic-session-0001',
  title: 'Synthetic session',
  preview: 'Synthetic redacted preview',
  source: 'synthetic',
  model: 'synthetic-model',
  startedAt: 1_767_225_600,
  endedAt: null,
  lastActive: 1_767_225_601,
  parentSessionId: null,
  messageCount: 1,
  toolCallCount: 0,
  inputTokens: 0,
  outputTokens: 0,
  isActive: false,
  archived: false,
  pinned: false,
  profile: 'synthetic-profile',
  isDefaultProfile: true
});

export const LIVE_SESSION_LIST_FIXTURE: SessionList = Object.freeze({
  sessions: [LIVE_SESSION_FIXTURE],
  total: 1,
  limit: 50,
  offset: 0
});

export const LIVE_MESSAGE_FIXTURE: LiveMessage = Object.freeze({
  role: 'user',
  content: 'Synthetic redacted message'
});

export const LIVE_SESSION_MESSAGES_FIXTURE: SessionMessages = Object.freeze({
  sessionId: LIVE_SESSION_FIXTURE.id,
  messages: [LIVE_MESSAGE_FIXTURE],
  pagination: {
    limit: null,
    offset: 0,
    returned: 1
  }
});
