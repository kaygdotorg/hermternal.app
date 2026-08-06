import type { Appearance } from '$lib/workspace/types';

export type AuthViewState =
  | 'provider-selection'
  | 'password'
  | 'callback'
  | 'failure'
  | 'session-expired'
  | 'discovery-pending'
  | 'discovery-retry'
  | 'provider-unavailable'
  | 'password-submitting';

export type AuthProviderKind = 'oauth' | 'password';

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
  | { type: 'submit-password'; username: string; password: string }
  | { type: 'toggle-password-visibility' }
  | { type: 'cancel-callback' }
  | { type: 'retry-authentication' }
  | { type: 'choose-provider-again' }
  | { type: 'retry-discovery' }
  | { type: 'back-to-sign-in' }
  | { type: 'sign-in-again' }
  | { type: 'discard-draft' };

export type AuthActionHandler = (action: AuthAction) => void;

export interface AuthPreviewProps {
  appearance?: Appearance;
  state?: AuthViewState;
  providers?: AuthProvider[];
  onAction?: AuthActionHandler;
}
