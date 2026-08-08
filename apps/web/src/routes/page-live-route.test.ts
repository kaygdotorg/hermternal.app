import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import type { AuthIdentity } from '$lib/transport/live-rest-types';
import { type BrowserAuthClient } from '$lib/auth-ui/browser-auth';
import { BrowserAuthSession } from '$lib/auth-ui/browser-auth-session';
import type { LiveRootContext } from '$lib/root-route';
import type { LiveWorkspaceSession, LiveWorkspaceSnapshot } from '$lib/workspace/live-workspace-session';
import Page from './+page.svelte';

const mockRoot = vi.hoisted(() => ({ context: undefined as unknown }));

vi.mock('$lib/root-route', () => ({
  createLiveRootContext: () => mockRoot.context,
  resolveRootRoute: () => ({ mode: 'live' })
}));

const identity: AuthIdentity = {
  userId: 'user-1',
  email: 'person@example.test',
  displayName: 'Test person',
  organizationId: 'org-1',
  provider: 'basic',
  expiresAt: 2_000_000_000
};

function createWorkspace(
  permanentFailure: LiveWorkspaceSnapshot['permanentFailure'],
  state: LiveWorkspaceSnapshot['state'] = 'permanent-error'
) {
  let snapshot: LiveWorkspaceSnapshot = {
    state,
    sessions: [{ id: 'session-1', title: 'Live session', group: 'recent' }],
    activeSessionId: 'session-1',
    title: 'Live session',
    model: 'Hermes 4',
    timeline: [],
    permanentFailure
  };
  const subscribers = new Set<(next: Readonly<LiveWorkspaceSnapshot>) => void>();
  const workspace = {
    get current(): Readonly<LiveWorkspaceSnapshot> {
      return snapshot;
    },
    subscribe: vi.fn((subscriber: (next: Readonly<LiveWorkspaceSnapshot>) => void) => {
      subscribers.add(subscriber);
      subscriber(snapshot);
      return () => subscribers.delete(subscriber);
    }),
    initialize: vi.fn().mockResolvedValue(undefined),
    selectSession: vi.fn().mockResolvedValue(undefined),
    createSession: vi.fn().mockResolvedValue(undefined),
    sendPrompt: vi.fn(),
    stop: vi.fn().mockResolvedValue(undefined),
    retryConnection: vi.fn().mockResolvedValue(undefined),
    approve: vi.fn().mockResolvedValue(undefined),
    answerClarification: vi.fn().mockResolvedValue(undefined),
    invalidate: vi.fn(() => {
      snapshot = {
        state: 'loading',
        sessions: [],
        title: 'Hermes',
        model: 'Hermes',
        timeline: []
      };
      subscribers.forEach((subscriber) => subscriber(snapshot));
    }),
    dispose: vi.fn()
  };
  return workspace as unknown as LiveWorkspaceSession & typeof workspace;
}

function createContext(
  permanentFailure: LiveWorkspaceSnapshot['permanentFailure'],
  state: LiveWorkspaceSnapshot['state'] = 'permanent-error',
  logout: BrowserAuthClient['logout'] = vi.fn(async () => undefined)
) {
  const workspace = createWorkspace(permanentFailure, state);
  const client: BrowserAuthClient = {
    verify: vi.fn(async () => identity),
    loginWithPassword: vi.fn(async () => ({ identity, next: '/' as const })),
    logout
  };
  const auth = new BrowserAuthSession({
    client,
    discoverProviders: vi.fn(async () => ({ providers: [] })),
    invalidateLocalSession: () => workspace.invalidate()
  });
  const context = { auth, workspace } as unknown as LiveRootContext;
  mockRoot.context = context;
  return { auth, workspace };
}

describe('live root route composition', () => {
  it('routes visible Sign out through BrowserAuthSession.logout exactly once', async () => {
    let resolveLogout!: () => void;
    const logoutRequest = new Promise<void>((resolve) => {
      resolveLogout = resolve;
    });
    const clientLogout = vi.fn(async () => logoutRequest);
    const { auth, workspace } = createContext(undefined, 'ready', clientLogout);
    const logout = vi.spyOn(auth, 'logout');

    render(Page);

    const trigger = await screen.findByRole('button', { name: 'Open account menu' });
    fireEvent.pointerDown(trigger, { button: 0, pointerType: 'mouse' });
    fireEvent.click(trigger, { detail: 1 });
    const signOut = await screen.findByRole('menuitem', { name: 'Sign out' });

    fireEvent.pointerDown(signOut, { button: 0, pointerType: 'mouse' });
    fireEvent.click(signOut, { detail: 1 });

    expect(logout).toHaveBeenCalledTimes(1);
    expect(workspace.invalidate).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'logout-pending'));
    expect(screen.getByRole('heading', { name: 'Signing out' })).toBeInTheDocument();
    resolveLogout();
    await waitFor(() => expect(clientLogout).toHaveBeenCalledTimes(1));
  });

  it('routes a rendered 4401 workspace action through BrowserAuthSession.expire', async () => {
    const { auth, workspace } = createContext({
      reason: 'authentication-required',
      closeCode: 4401,
      closeClassification: 'authentication-rejected'
    });
    const expire = vi.spyOn(auth, 'expire');

    render(Page);

    await screen.findByRole('button', { name: 'Back to sessions' });
    await fireEvent.click(screen.getByRole('button', { name: 'Back to sessions' }));

    expect(expire).toHaveBeenCalledTimes(1);
    expect(workspace.invalidate).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'session-expired'));
    expect(screen.getByRole('heading', { name: 'Session expired' })).toBeInTheDocument();
  });

  it('routes semantic ticket 401 authentication-required state through the same sign-in bridge', async () => {
    const { auth, workspace } = createContext({ reason: 'authentication-required' });
    const expire = vi.spyOn(auth, 'expire');

    render(Page);

    await screen.findByRole('button', { name: 'Back to sessions' });
    await fireEvent.click(screen.getByRole('button', { name: 'Back to sessions' }));

    expect(expire).toHaveBeenCalledTimes(1);
    expect(workspace.invalidate).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'session-expired'));
  });

  it('keeps a rendered ticket 403 failure retryable without a sign-in transition', async () => {
    const { auth, workspace } = createContext(undefined, 'retryable-error');
    const expire = vi.spyOn(auth, 'expire');

    render(Page);

    expect(await screen.findByTestId('retryable-error-state')).toBeInTheDocument();
    expect(expire).not.toHaveBeenCalled();
    expect(workspace.invalidate).not.toHaveBeenCalled();
    expect(auth.current.status).toBe('authenticated');
    expect(screen.getByText('Connection lost')).toBeInTheDocument();
  });

  it('keeps a rendered 4403 workspace failure on the authenticated incompatible boundary', async () => {
    const { auth, workspace } = createContext({
      reason: 'incompatible',
      closeCode: 4403,
      closeClassification: 'host-or-origin-rejected'
    });
    const expire = vi.spyOn(auth, 'expire');

    render(Page);

    await screen.findByRole('button', { name: 'Back to sessions' });
    await fireEvent.click(screen.getByRole('button', { name: 'Back to sessions' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));

    expect(expire).not.toHaveBeenCalled();
    expect(workspace.invalidate).not.toHaveBeenCalled();
    expect(auth.current.status).toBe('authenticated');
    expect(screen.getByTestId('permanent-error-state')).toBeInTheDocument();
    expect(screen.getByText('Incompatible origin')).toBeInTheDocument();
  });
});
