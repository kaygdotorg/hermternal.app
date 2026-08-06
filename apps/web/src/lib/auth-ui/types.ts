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

export interface AuthProvider {
  id: string;
  name: string;
  monogram: string;
  kind: AuthProviderKind;
  description: string;
}

export type AuthAction =
  | { type: 'choose-provider'; providerId: string }
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

export interface PasswordSubmission {
  username: string;
  password: string;
}

export type PasswordSubmissionHandler = (submission: PasswordSubmission) => void;

export interface AuthPreviewProps {
  appearance?: Appearance;
  state?: AuthViewState;
  providers?: AuthProvider[];
  discoveryMode?: AuthDiscoveryMode;
  onAction?: AuthActionHandler;
  onPasswordSubmit?: PasswordSubmissionHandler;
  failureMessage?: string;
  failureCode?: string;
}
