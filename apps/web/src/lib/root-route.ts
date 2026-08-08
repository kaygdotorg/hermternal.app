import { createBrowserChatTransport } from '$lib/chat/browser-chat';
import type { BrowserWebSocketFactory } from '$lib/chat/browser-chat';
import {
  createBrowserPtyTransport,
  type BrowserPtyWebSocketFactory
} from '$lib/terminal/current-session-terminal';
import { createBrowserAuthClient } from '$lib/auth-ui/browser-auth';
import { BrowserAuthSession } from '$lib/auth-ui/browser-auth-session';
import { discoverProviders } from '$lib/auth-ui/provider-discovery';
import { createLiveRestTransport, type LiveRestFetch } from '$lib/transport';
import { LiveWorkspaceSession } from '$lib/workspace/live-workspace-session';
import type { MockScenario } from '$lib/transport';

export type RootRouteSelection =
  { readonly mode: 'fixture'; readonly scenario: MockScenario; readonly delayMs: number } | { readonly mode: 'live' };

export interface LiveRootContext {
  readonly auth: BrowserAuthSession;
  readonly workspace: LiveWorkspaceSession;
}

export interface LiveRootDependencies {
  readonly fetch?: LiveRestFetch;
  /** Shared browser socket seam used by the Chat adapter and, when no PTY-specific seam is supplied, PTY tests. */
  readonly createSocket?: BrowserWebSocketFactory;
  /** PTY's binary socket surface; production uses the default browser adapter. */
  readonly createPtySocket?: BrowserPtyWebSocketFactory;
}

/**
 * Only the explicit closed fixture scenarios bypass live authentication.
 * Other query strings remain on the normal product path.
 */
export function resolveRootRoute(search: string): RootRouteSelection {
  const params = new URLSearchParams(search);
  const scenario = params.get('scenario');
  if (scenario === 'empty' || scenario === 'failure' || scenario === 'success') {
    return {
      mode: 'fixture',
      scenario,
      delayMs: params.get('delayMs') === 'short' ? 250 : 0
    };
  }
  return { mode: 'live' };
}

/**
 * Compose the reviewed same-origin browser boundaries without adding a shared
 * credential, ticket, response, or transcript store.
 */
export function createLiveRootContext(dependencies: LiveRootDependencies = {}): LiveRootContext {
  const rest = createLiveRestTransport({ fetch: dependencies.fetch });
  const createPtySocket: BrowserPtyWebSocketFactory | undefined =
    dependencies.createPtySocket ??
    (dependencies.createSocket
      ? (url, signal) => dependencies.createSocket?.(url, signal) as unknown as ReturnType<BrowserPtyWebSocketFactory>
      : undefined);
  const workspace = new LiveWorkspaceSession({
    rest,
    createChat: (options) =>
      createBrowserChatTransport({
        ...options,
        fetch: dependencies.fetch,
        createSocket: dependencies.createSocket
      }),
    createTerminal: () => createBrowserPtyTransport({ fetch: dependencies.fetch, createSocket: createPtySocket })
  });
  const auth = new BrowserAuthSession({
    client: createBrowserAuthClient({ fetch: dependencies.fetch }),
    discoverProviders: (signal) => discoverProviders({ fetch: dependencies.fetch, signal }),
    // Authentication invalidation closes chat and drops session presentation
    // references before logout or expiry publishes its next observable state.
    invalidateLocalSession: () => workspace.invalidate()
  });

  let expiredTerminalGeneration: number | undefined;
  workspace.subscribe((snapshot) => {
    // PTY 4401 is an authentication boundary even when TerminalSurface is
    // hidden behind Chat. Keep it separate from 4403, which remains a
    // fail-closed origin/deployment error and never expires the root session.
    const terminal = snapshot.terminal;
    if (
      auth.current.status !== 'authenticated' ||
      terminal?.failure !== 'authentication-required' ||
      terminal.generation === expiredTerminalGeneration
    ) {
      return;
    }
    expiredTerminalGeneration = terminal.generation;
    try {
      auth.expire();
    } catch {
      // Auth may already be transitioning through logout or expiry. The
      // existing BrowserAuthSession lifecycle remains the authority.
    }
  });

  return { auth, workspace };
}
