import type { Appearance } from '$lib/workspace/types';

/**
 * The leaf values below are the approved Paper-backed presentation records,
 * grouped into seven semantic families. Interaction, localization, and zoom
 * evidence stays in styles/tests; logout lifecycle values stay internal to the
 * BrowserAuthSession and are deliberately absent from this public union.
 */
export type AuthViewState =
  | 'provider-selection'
  | 'password'
  | 'password-submitting'
  | 'callback'
  | 'failure'
  | 'session-expired'
  | 'discovery-pending'
  | 'discovery-retry'
  | 'discovery-empty'
  | 'discovery-malformed'
  | 'discovery-aborted'
  | 'provider-unavailable';

export type AuthPresentationFamily =
  | 'provider-selection'
  | 'password-sign-in'
  | 'oauth-callback'
  | 'authentication-failure'
  | 'session-expired'
  | 'provider-discovery'
  | 'interaction-accessibility';

export type AuthDiscoveryFailureVariant = 'retry' | 'empty' | 'malformed' | 'aborted' | 'unavailable';
export type AuthProviderKind = 'oauth' | 'password' | 'unavailable';
export type AuthDiscoveryMode = 'fixture' | 'live';

/** Unknown deployment kinds must stop at the reviewed fail-closed family. */
export function authStateForProviderKind(value: unknown): AuthViewState {
  if (value === 'password') return 'password';
  if (value === 'oauth') return 'callback';
  return 'provider-unavailable';
}

export function authPresentationFamilyForState(value: AuthViewState): AuthPresentationFamily {
  if (value === 'provider-selection') return 'provider-selection';
  if (value === 'password' || value === 'password-submitting') return 'password-sign-in';
  if (value === 'callback') return 'oauth-callback';
  if (value === 'failure') return 'authentication-failure';
  if (value === 'session-expired') return 'session-expired';
  return 'provider-discovery';
}

export interface AuthProvider {
  id: string;
  name: string;
  monogram: string;
  kind: AuthProviderKind;
  /** Desktop Paper description. */
  description: string;
  /** Optional narrow-layout copy from the mobile Paper board. */
  mobileDescription?: string;
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
  passwordSubmitting?: boolean;
  onAction?: AuthActionHandler;
  onPasswordSubmit?: PasswordSubmissionHandler;
  failureMessage?: string;
  failureCode?: string;
}
