import type { Appearance } from '$lib/workspace/types';

export type AuthViewState =
  | 'provider-selection'
  | 'password'
  | 'callback'
  | 'failure'
  | 'session-expired'
  | 'discovery-pending'
  | 'discovery-retry'
  | 'discovery-empty'
  | 'discovery-malformed'
  | 'discovery-aborted'
  | 'provider-unavailable'
  | 'password-submitting';

export type AuthProviderKind = 'oauth' | 'password';
export type AuthDiscoveryMode = 'fixture' | 'live';

/** Unknown deployment kinds must stop at the unavailable state, never inherit a known provider path. */
export function authStateForProviderKind(value: unknown): AuthViewState {
  if (value === 'password') return 'password';
  if (value === 'oauth') return 'callback';
  return 'provider-unavailable';
}

export interface AuthProvider {
  id: string;
  name: string;
  monogram: string;
  kind: AuthProviderKind;
  description: string;
}

export type AuthAction =
  | { type: 'choose-provider'; providerId: string; providerKind: AuthProviderKind }
  | { type: 'back-to-providers' }
  | { type: 'submit-password-fixture' }
  | { type: 'toggle-password-visibility' }
  | { type: 'cancel-callback' }
  | { type: 'retry-authentication' }
  | { type: 'choose-provider-again' }
  | { type: 'retry-discovery' }
  | { type: 'cancel-discovery' }
  | { type: 'back-to-sign-in' }
  | { type: 'sign-in-again' }
  | { type: 'discard-draft' };

export type AuthActionHandler = (action: AuthAction) => void;

export interface AuthPreviewProps {
  appearance?: Appearance;
  state?: AuthViewState;
  providers?: AuthProvider[];
  discoveryMode?: AuthDiscoveryMode;
  onAction?: AuthActionHandler;
}
