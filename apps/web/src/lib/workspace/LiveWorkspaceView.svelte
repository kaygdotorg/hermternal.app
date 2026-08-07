<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import WorkspacePreview from './WorkspacePreview.svelte';
  import type { LiveWorkspaceSession, LiveWorkspaceSnapshot } from './live-workspace-session';
  import type { Appearance, WorkspaceAction } from './types';

  export let session: LiveWorkspaceSession;
  export let appearance: Appearance = 'light';
  export let onReturnToSignIn: () => void = () => {};

  let snapshot: Readonly<LiveWorkspaceSnapshot> = session.current;
  let unsubscribe: (() => void) | undefined;
  let coordinator = session.coordinator;
  let terminal = session.terminal;

  onMount(() => {
    coordinator = session.coordinator;
    terminal = session.terminal;
    unsubscribe = session.subscribe((next) => {
      snapshot = next;
      coordinator = session.coordinator;
      terminal = session.terminal;
    });
    void session.initialize();
  });

  onDestroy(() => {
    // The route root owns final disposal. This authenticated projection only
    // releases its subscription so expiry can remount the same workspace.
    unsubscribe?.();
  });

  function handleAction(action: WorkspaceAction): void {
    if (action.type === 'return-to-sign-in') {
      if (snapshot.permanentFailure?.reason === 'authentication-required' || snapshot.terminal?.failure === 'authentication-required') {
        onReturnToSignIn();
      }
      return;
    }
    if (action.type === 'back-to-sessions' || action.type === 'dismiss') {
      // Both visible permanent-error exits lead back to sign-in only when the
      // transport proved that authentication is required. Incompatible-origin
      // failures remain on the reviewed fail-closed workspace boundary.
      if (snapshot.permanentFailure?.reason === 'authentication-required') {
        onReturnToSignIn();
      }
      return;
    }
    if (action.type === 'set-mode') void session.activateMode(action.mode);
    if (action.type === 'terminal-reconnect') void session.reconnectTerminal();
    if (action.type === 'terminal-detach') session.detachTerminal();
    if (action.type === 'terminal-close') session.closeTerminal();
    if (action.type === 'new-session') void session.createSession();
    if (action.type === 'select-session') void session.selectSession(action.sessionId);
    if (action.type === 'send') session.sendPrompt(action.text);
    if (action.type === 'stop') void session.stop();
    if (action.type === 'retry' || action.type === 'check-connection') void session.retryConnection();
    if (action.type === 'cancel-reconnect') session.cancelReconnect();
    if (action.type === 'approve-tool') {
      // The preview carries once/session/always metadata; this live adapter is
      // intentionally limited to the existing boolean approval transport.
      void session.approve(action.itemId, true);
    }
    if (action.type === 'reject-tool') void session.approve(action.itemId, false);
    if (action.type === 'answer-clarification') {
      void session.answerClarification(action.itemId, action.answer);
    }
  }
</script>

<WorkspacePreview
  activeSessionId={snapshot.activeSessionId ?? ''}
  artifactInspectorEnabled={false}
  coordinator={snapshot.coordinator ?? coordinator?.state}
  focusIntent={snapshot.coordinator?.focusIntent}
  mode={snapshot.mode ?? coordinator?.mode ?? 'chat'}
  modeActionsEnabled={true}
  terminal={terminal}
  {appearance}
  dataMode="live"
  interactionEnabled={snapshot.activeSessionId !== undefined}
  model={snapshot.model}
  permanentFailure={snapshot.permanentFailure}
  sessions={snapshot.sessions}
  state={snapshot.state}
  timelineEmptyLabel="No messages in this chat yet."
  timelineItems={snapshot.timeline}
  title={snapshot.title}
  onAction={handleAction}
/>
