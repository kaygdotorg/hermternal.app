import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import type { AuthIdentity } from '$lib/transport/live-rest-types';
import { BrowserAuthError, type BrowserAuthClient } from './browser-auth';
import { BrowserAuthSession } from './browser-auth-session';
import BrowserAuthView from './BrowserAuthView.svelte';

const identity: AuthIdentity = {
  userId: 'user-1',
  email: 'person@example.invalid',
  displayName: 'Synthetic Person',
  organizationId: 'org-1',
  provider: 'basic',
  expiresAt: 2_000_000_000
};

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

describe('BrowserAuthView', () => {
  it('wires verified discovery, provider selection, and transient password submission', async () => {
    const pendingLogin = deferred<{ identity: AuthIdentity; next: '/' }>();
    const loginWithPassword = vi.fn(() => pendingLogin.promise);
    const client: BrowserAuthClient = {
      verify: vi.fn(async () => {
        throw new BrowserAuthError('identity-unverified', 401);
      }),
      loginWithPassword,
      logout: vi.fn(async () => undefined)
    };
    const session = new BrowserAuthSession({
      client,
      discoverProviders: vi.fn(async () => ({
        providers: [
          {
            id: 'basic',
            name: 'Hermes password',
            monogram: 'H',
            kind: 'password' as const,
            description: 'Username and password supported'
          }
        ]
      })),
      invalidateLocalSession: vi.fn()
    });
    const onAuthenticated = vi.fn();
    render(BrowserAuthView, { session, onAuthenticated });

    await fireEvent.click(await screen.findByRole('button', { name: 'Hermes password' }));
    await waitFor(() => expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'password'));

    fireEvent.input(screen.getByLabelText('Username'), {
      target: { value: 'synthetic-user' }
    });
    fireEvent.input(screen.getByLabelText('Password'), {
      target: { value: 'transient-password' }
    });
    fireEvent.submit(screen.getByRole('form', { name: 'Hermes password sign in' }));

    expect(loginWithPassword).toHaveBeenCalledTimes(1);
    expect(loginWithPassword).toHaveBeenCalledWith(
      {
        provider: 'basic',
        username: 'synthetic-user',
        password: 'transient-password'
      },
      expect.any(AbortSignal)
    );
    expect(JSON.stringify(session.current)).not.toContain('transient-password');
    await waitFor(() =>
      expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'password-submitting')
    );

    pendingLogin.resolve({ identity, next: '/' });
    await waitFor(() => expect(screen.queryByTestId('auth-preview')).not.toBeInTheDocument());
    expect(onAuthenticated).toHaveBeenCalledWith(identity);
  });

  it('renders fixed login errors without copying submitted credentials', async () => {
    const client: BrowserAuthClient = {
      verify: vi.fn(async () => {
        throw new BrowserAuthError('identity-unverified', 401);
      }),
      loginWithPassword: vi.fn(async () => {
        throw new BrowserAuthError('invalid-credentials', 401);
      }),
      logout: vi.fn(async () => undefined)
    };
    const session = new BrowserAuthSession({
      client,
      discoverProviders: async () => ({
        providers: [
          {
            id: 'basic',
            name: 'Hermes password',
            monogram: 'H',
            kind: 'password' as const,
            description: 'Username and password supported'
          }
        ]
      }),
      invalidateLocalSession: vi.fn()
    });
    render(BrowserAuthView, { session });

    await fireEvent.click(await screen.findByRole('button', { name: 'Hermes password' }));
    fireEvent.input(screen.getByLabelText('Username'), {
      target: { value: 'synthetic-user' }
    });
    fireEvent.input(screen.getByLabelText('Password'), {
      target: { value: 'must-not-render' }
    });
    fireEvent.submit(screen.getByRole('form', { name: 'Hermes password sign in' }));

    expect(await screen.findByText('The username or password was not accepted.')).toBeInTheDocument();
    expect(screen.getByText('invalid-credentials')).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('must-not-render');
  });
});
