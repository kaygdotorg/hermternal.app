import { createBrowserChatTransport } from '$lib/chat/browser-chat';
import type { BrowserWebSocketFactory } from '$lib/chat/browser-chat';
import { createBrowserPtyTransport } from '$lib/terminal/current-session-terminal';
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
  /**
   * The authenticated view receives this shared session, but cannot destroy it:
   * authentication expiry unmounts that view and a later sign-in remounts it.
   */
  readonly workspace: LiveWorkspaceSession;
  /** Permanently releases root-owned auth and workspace resources exactly once. */
  dispose(): void;
}

export interface LiveRootDependencies {
  readonly fetch?: LiveRestFetch;
  readonly createSocket?: BrowserWebSocketFactory;
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
  const workspace = new LiveWorkspaceSession({
    rest,
    createChat: (options) =>
      createBrowserChatTransport({
        ...options,
        fetch: dependencies.fetch,
        createSocket: dependencies.createSocket
      }),
    createTerminal: () => createBrowserPtyTransport({ fetch: dependencies.fetch })
  });
  const auth = new BrowserAuthSession({
    client: createBrowserAuthClient({ fetch: dependencies.fetch }),
    discoverProviders: (signal) => discoverProviders({ fetch: dependencies.fetch, signal }),
    // Authentication invalidation closes chat and drops session presentation
    // references before logout or expiry publishes its next observable state.
    invalidateLocalSession: () => workspace.invalidate()
  });

  let disposed = false;

  function dispose(): void {
    if (disposed) return;
    disposed = true;
    // The route is the sole permanent owner; its authenticated child is only a
    // subscriber and may disappear during expiry without closing this session.
    workspace.dispose();
    auth.dispose();
  }

  return { auth, workspace, dispose };
}
