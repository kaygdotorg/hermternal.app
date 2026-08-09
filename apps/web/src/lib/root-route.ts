import { createBrowserChatTransport } from '$lib/chat/browser-chat';
import type { BrowserWebSocketFactory } from '$lib/chat/browser-chat';
import { createBrowserAuthClient } from '$lib/auth-ui/browser-auth';
import {
  createBrowserPtyTransport,
  getCurrentSessionTerminalLifecycleIdentity,
  type BrowserPtyWebSocketFactory,
  type CurrentSessionTerminalBridge,
  type CurrentSessionTerminalLifecycleIdentity,
  type CurrentSessionTerminalLifecycleStamp
} from '$lib/terminal/current-session-terminal';
import { BrowserAuthSession } from '$lib/auth-ui/browser-auth-session';
import { discoverProviders } from '$lib/auth-ui/provider-discovery';
import { createLiveRestTransport, type LiveRestFetch } from '$lib/transport';
import { LiveWorkspaceSession } from '$lib/workspace/live-workspace-session';
import type { MockScenario } from '$lib/transport';

export type RootRouteSelection =
  { readonly mode: 'fixture'; readonly scenario: MockScenario; readonly delayMs: number } | { readonly mode: 'live' };

/**
 * Opaque root ownership capability. Its object identity is the lifecycle proof;
 * it intentionally exposes neither session, ticket, nor transport identifiers.
 */
export type RootTerminalLifecycleLease = object;

export interface LiveRootContext {
  readonly auth: BrowserAuthSession;
  /**
   * The authenticated view receives this shared session, but cannot destroy it:
   * authentication expiry unmounts that view and a later sign-in remounts it.
   */
  readonly workspace: LiveWorkspaceSession;
  /**
   * Register only a bridge-issued callback stamp. The root resolves its private
   * producer record and never mints a lease from caller-controlled structure.
   */
  registerTerminalLifecycle(
    terminal: CurrentSessionTerminalBridge,
    stamp: CurrentSessionTerminalLifecycleStamp
  ): RootTerminalLifecycleLease | undefined;
  /**
   * The rendered 4401 route may expire auth once for the currently registered
   * capability. Retired or replaced lifecycle callbacks are ignored.
   */
  expireTerminalAuthentication(lease: RootTerminalLifecycleLease | undefined): void;
  /** Permanently releases root-owned auth and workspace resources exactly once. */
  dispose(): void;
}

export interface LiveRootDependencies {
  readonly fetch?: LiveRestFetch;
  readonly createSocket?: BrowserWebSocketFactory;
  /** Binary PTY socket seam; production otherwise uses the same-origin browser adapter. */
  readonly createPtySocket?: BrowserPtyWebSocketFactory;
}

interface ActiveTerminalLifecycle {
  readonly lease: RootTerminalLifecycleLease;
  readonly terminal: CurrentSessionTerminalBridge;
  readonly identity: CurrentSessionTerminalLifecycleIdentity;
}

function hasLiveBinding(identity: CurrentSessionTerminalLifecycleIdentity): boolean {
  return identity.binding !== undefined;
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
    // Construction validates the current browser origin before a ticket can be
    // minted. Missing or malformed browser authority therefore fails closed.
    createTerminal: () =>
      createBrowserPtyTransport({
        fetch: dependencies.fetch,
        createSocket: dependencies.createPtySocket
      })
  });
  const auth = new BrowserAuthSession({
    client: createBrowserAuthClient({ fetch: dependencies.fetch }),
    discoverProviders: (signal) => discoverProviders({ fetch: dependencies.fetch, signal }),
    // Authentication invalidation closes chat and drops session presentation
    // references before logout or expiry publishes its next observable state.
    // The active root lease is retired first, so an old 4401 control cannot
    // affect the bridge created by a later authenticated lifecycle.
    invalidateLocalSession: () => {
      activeTerminalLifecycle = undefined;
      workspace.invalidate();
    }
  });

  let disposed = false;
  let activeTerminalLifecycle: ActiveTerminalLifecycle | undefined;

  function retireTerminalLifecycle(): void {
    // Dropping the only capability reference makes an old rendered callback
    // inert. The capability has no serializable data, so tickets and session
    // identifiers cannot cross this root/presentation boundary.
    activeTerminalLifecycle = undefined;
  }

  function registerTerminalLifecycle(
    terminal: CurrentSessionTerminalBridge,
    stamp: CurrentSessionTerminalLifecycleStamp
  ): RootTerminalLifecycleLease | undefined {
    const identity = getCurrentSessionTerminalLifecycleIdentity(stamp);
    if (disposed || workspace.terminal !== terminal || !identity || !hasLiveBinding(identity)) return undefined;
    const active = activeTerminalLifecycle;
    if (
      active?.terminal === terminal &&
      active.identity.binding === identity.binding &&
      active.identity.nativeTransportGeneration === identity.nativeTransportGeneration
    ) {
      // A terminal close callback can arrive after its bridge binding retires.
      // Its previously accepted producer stamp remains the same lifecycle only.
      return active.lease;
    }
    const liveIdentity = terminal.lifecycleIdentity;
    if (
      liveIdentity.binding !== identity.binding ||
      liveIdentity.nativeTransportGeneration !== identity.nativeTransportGeneration
    ) return undefined;
    // Fresh registration must prove the bridge still owns this exact binding and
    // native generation. A caller-created object has no WeakMap producer record.
    retireTerminalLifecycle();
    const lease: RootTerminalLifecycleLease = {};
    activeTerminalLifecycle = { lease, terminal, identity };
    return lease;
  }

  function expireTerminalAuthentication(lease: RootTerminalLifecycleLease | undefined): void {
    const active = activeTerminalLifecycle;
    if (disposed || lease === undefined || active?.lease !== lease) return;
    retireTerminalLifecycle();
    // Retire before publishing expiry. Duplicate 4401 controls and any old
    // callback cannot expire a new authenticated lifecycle.
    auth.expire();
  }

  function dispose(): void {
    if (disposed) return;
    disposed = true;
    retireTerminalLifecycle();
    // The route is the sole permanent owner; its authenticated child is only a
    // subscriber and may disappear during expiry without closing this session.
    workspace.dispose();
    auth.dispose();
  }

  return { auth, workspace, registerTerminalLifecycle, expireTerminalAuthentication, dispose };
}
