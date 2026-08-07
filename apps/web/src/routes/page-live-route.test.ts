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

function createWorkspace(permanentFailure: NonNullable<LiveWorkspaceSnapshot['permanentFailure']>) {
  let snapshot: LiveWorkspaceSnapshot = {
    state: 'permanent-error',
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

function createContext(permanentFailure: NonNullable<LiveWorkspaceSnapshot['permanentFailure']>) {
  const workspace = createWorkspace(permanentFailure);
  const client: BrowserAuthClient = {
    verify: vi.fn(async () => identity),
    loginWithPassword: vi.fn(async () => ({ identity, next: '/' as const })),
    logout: vi.fn(async () => undefined)
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
