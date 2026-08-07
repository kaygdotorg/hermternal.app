import type { AuthIdentity } from '$lib/transport/live-rest-types';
import type { AuthProvider } from './types';
import {
  BrowserAuthError,
  type BrowserAuthClient,
  type BrowserAuthErrorCode,
  type PasswordLoginInput
} from './browser-auth';
import type { ProviderDiscoveryResult } from './provider-discovery';

export type BrowserAuthStatus =
  | 'signed_out'
  | 'discovering'
  | 'provider_unavailable'
  | 'redirecting'
  | 'password_submitting'
  | 'native_exchanging'
  | 'authenticated'
  | 'refreshing'
  | 'expired'
  | 'logging_out'
  | 'logout_failed'
  | 'failed';

export interface BrowserAuthSnapshot {
  status: BrowserAuthStatus;
  identity?: AuthIdentity;
  providers: AuthProvider[];
  selectedProviderId?: string;
  errorCode?: BrowserAuthErrorCode;
}

export interface BrowserAuthSessionOptions {
  client: BrowserAuthClient;
  discoverProviders: (signal?: AbortSignal) => Promise<ProviderDiscoveryResult>;
  /** Closes chat and clears client-side session references without retaining data. */
  invalidateLocalSession: () => void;
}

export type BrowserAuthSubscriber = (snapshot: Readonly<BrowserAuthSnapshot>) => void;

/**
 * Coordinates the browser-auth lifecycle without storing reusable credentials.
 * Every operation owns one abort controller and generation number, so cancelled
 * or superseded work cannot publish stale authenticated state.
 */
export class BrowserAuthSession {
  private readonly client: BrowserAuthClient;
  private readonly discoverProviderRegistry: (signal?: AbortSignal) => Promise<ProviderDiscoveryResult>;
  private readonly invalidateLocalSession: () => void;
  private readonly subscribers = new Set<BrowserAuthSubscriber>();
  private snapshot: BrowserAuthSnapshot = {
    status: 'signed_out',
    providers: []
  };
  private controller: AbortController | undefined;
  private generation = 0;
  private disposed = false;

  constructor(options: BrowserAuthSessionOptions) {
    this.client = options.client;
    this.discoverProviderRegistry = options.discoverProviders;
    this.invalidateLocalSession = options.invalidateLocalSession;
  }

  get current(): Readonly<BrowserAuthSnapshot> {
    return this.snapshot;
  }

  subscribe(subscriber: BrowserAuthSubscriber): () => void {
    this.assertActive();
    this.subscribers.add(subscriber);
    subscriber(this.snapshot);
    return () => this.subscribers.delete(subscriber);
  }

  async initialize(): Promise<void> {
    if (this.isLogoutState()) return;
    const operation = this.begin('refreshing');
    try {
      const identity = await this.client.verify(operation.signal);
      if (!this.isCurrent(operation.generation)) return;
      this.publish({ status: 'authenticated', identity, providers: [] });
    } catch (error) {
      if (!this.isCurrent(operation.generation) || isAbort(error)) return;
      if (isIdentityUnavailable(error)) {
        await this.discover(operation);
        return;
      }
      this.publishFailure(error);
    }
  }

  async retryDiscovery(): Promise<void> {
    // Logout owns the generation until its identity probe completes. Discovery
    // is read-only, but starting it here would abort the logout request and
    // expose a retry action over a pending sign-out state.
    if (this.isLogoutState()) return;
    // A failed identity barrier has not established signed-out authority. A
    // direct caller must retry verification rather than bypassing it with a
    // provider-registry request.
    if (
      this.snapshot.status === 'failed' &&
      (this.snapshot.errorCode === 'identity-failed' || !this.snapshot.selectedProviderId)
    ) {
      await this.initialize();
      return;
    }
    const operation = this.begin('discovering', { providers: [] });
    await this.discover(operation);
  }

  chooseProvider(providerId: string): AuthProvider | undefined {
    this.assertActive();
    const provider = this.snapshot.providers.find((candidate) => candidate.id === providerId);
    if (!provider || this.isBusy()) return undefined;
    this.publish({
      ...this.snapshot,
      status: 'signed_out',
      selectedProviderId: provider.id,
      errorCode: undefined
    });
    return provider;
  }

  clearSelection(): void {
    this.assertActive();
    if (this.isBusy()) return;
    this.publish({ status: 'signed_out', providers: this.snapshot.providers });
  }

  async loginWithPassword(input: Omit<PasswordLoginInput, 'provider'>): Promise<void> {
    this.assertActive();
    if (this.isBusy()) return;

    const provider = this.selectedPasswordProvider();
    if (!provider) {
      this.publishFailure(new BrowserAuthError('invalid-input'));
      return;
    }

    const operation = this.begin('password_submitting', {
      providers: this.snapshot.providers,
      selectedProviderId: provider.id
    });
    try {
      const result = await this.client.loginWithPassword({ provider: provider.id, ...input }, operation.signal);
      if (!this.isCurrent(operation.generation)) return;
      this.publish({
        status: 'authenticated',
        identity: result.identity,
        providers: []
      });
    } catch (error) {
      if (!this.isCurrent(operation.generation) || isAbort(error)) return;
      this.publishFailure(error, provider.id);
    }
  }

  async logout(): Promise<void> {
    this.assertActive();
    if (this.snapshot.status === 'logging_out') return;

    this.invalidateAndCancel('logging_out');
    const operation = this.activeOperation();
    try {
      await this.client.logout(operation.signal);
      if (!this.isCurrent(operation.generation)) return;
      this.publish({ status: 'signed_out', providers: [] });
    } catch (error) {
      if (!this.isCurrent(operation.generation) || isAbort(error)) return;
      const reconciliation = await this.reconcileLogout(operation);
      if (!this.isCurrent(operation.generation)) return;
      if (reconciliation === 'signed_out') {
        this.publish({ status: 'signed_out', providers: [] });
        return;
      }
      this.publishLogoutFailure(reconciliation === 'authenticated' ? 'logout-failed' : 'logout-unverified');
    }
  }

  expire(): void {
    this.assertActive();
    if (this.isLogoutState()) return;
    this.invalidateAndCancel('expired');
  }

  cancel(): void {
    this.assertActive();
    // A logout is a protected boundary: the caller may not abort it or replace
    // its pending or recovery state with discovery or signed-out UI before verification.
    if (this.isLogoutState()) return;
    this.generation += 1;
    this.controller?.abort();
    this.controller = undefined;
    if (this.snapshot.status !== 'authenticated') {
      this.publish({ status: 'signed_out', providers: [] });
    }
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.generation += 1;
    this.controller?.abort();
    this.controller = undefined;
    this.subscribers.clear();
  }

  private async discover(operation: { generation: number; signal: AbortSignal }): Promise<void> {
    if (this.isCurrent(operation.generation)) this.publish({ status: 'discovering', providers: [] });
    try {
      const result = await this.discoverProviderRegistry(operation.signal);
      if (!this.isCurrent(operation.generation)) return;
      this.publish({
        status: result.providers.length === 0 ? 'provider_unavailable' : 'signed_out',
        providers: result.providers
      });
    } catch (error) {
      if (!this.isCurrent(operation.generation) || isAbort(error)) return;
      this.publish({ status: 'provider_unavailable', providers: [] });
    }
  }

  private begin(
    status: BrowserAuthStatus,
    retained: Partial<BrowserAuthSnapshot> = {}
  ): {
    generation: number;
    signal: AbortSignal;
  } {
    this.assertActive();
    this.generation += 1;
    this.controller?.abort();
    this.controller = new AbortController();
    this.publish({ status, providers: [], ...retained, errorCode: undefined });
    return this.activeOperation();
  }

  private activeOperation(): { generation: number; signal: AbortSignal } {
    if (!this.controller) this.controller = new AbortController();
    return { generation: this.generation, signal: this.controller.signal };
  }

  private invalidateAndCancel(status: 'expired' | 'logging_out'): void {
    this.generation += 1;
    this.controller?.abort();
    this.controller = new AbortController();
    this.invalidateLocalSession();
    this.publish({ status, providers: [] });
  }

  /**
   * Logout failures stay in logout-only recovery. A fresh identity probe is the
   * authority for ambiguous transport outcomes; provider discovery must never
   * turn an uncertain sign-out into a generic sign-in retry.
   */
  private async reconcileLogout(
    operation: { generation: number; signal: AbortSignal }
  ): Promise<'signed_out' | 'authenticated' | 'unknown'> {
    try {
      await this.client.verify(operation.signal);
      return 'authenticated';
    } catch (error) {
      if (isUnauthenticated(error)) return 'signed_out';
      return 'unknown';
    }
  }

  private publishLogoutFailure(errorCode: 'logout-failed' | 'logout-unverified'): void {
    this.publish({
      status: 'logout_failed',
      providers: [],
      errorCode
    });
  }

  private selectedPasswordProvider(): AuthProvider | undefined {
    const selected = this.snapshot.selectedProviderId;
    if (!selected) return undefined;
    return this.snapshot.providers.find((provider) => provider.id === selected && provider.kind === 'password');
  }

  private publishFailure(error: unknown, selectedProviderId?: string): void {
    const authError = error instanceof BrowserAuthError ? error : new BrowserAuthError('network');
    this.publish({
      status: authError.code === 'provider-unavailable' ? 'provider_unavailable' : 'failed',
      providers: this.snapshot.providers,
      selectedProviderId,
      errorCode: authError.code
    });
  }

  private publish(snapshot: BrowserAuthSnapshot): void {
    this.snapshot = snapshot;
    for (const subscriber of this.subscribers) subscriber(snapshot);
  }

  private isBusy(): boolean {
    return (
      this.snapshot.status === 'refreshing' ||
      this.snapshot.status === 'discovering' ||
      this.snapshot.status === 'password_submitting' ||
      this.isLogoutState()
    );
  }

  private isLogoutState(): boolean {
    return this.snapshot.status === 'logging_out' || this.snapshot.status === 'logout_failed';
  }

  private isCurrent(generation: number): boolean {
    return !this.disposed && generation === this.generation;
  }

  private assertActive(): void {
    if (this.disposed) throw new BrowserAuthError('aborted');
  }
}

function isAbort(error: unknown): boolean {
  return error instanceof BrowserAuthError && error.code === 'aborted';
}

function isIdentityUnavailable(error: unknown): boolean {
  return error instanceof BrowserAuthError && error.code === 'identity-unverified' && error.status === 401;
}

function isUnauthenticated(error: unknown): boolean {
  return error instanceof BrowserAuthError && error.code === 'identity-unverified' && error.status === 401;
}
