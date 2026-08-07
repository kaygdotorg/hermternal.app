<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import WorkspacePreview from './WorkspacePreview.svelte';
  import type { LiveWorkspaceSession, LiveWorkspaceSnapshot } from './live-workspace-session';
  import type { Appearance, WorkspaceAction } from './types';

  export let session: LiveWorkspaceSession;
  export let appearance: Appearance = 'light';

  let snapshot: Readonly<LiveWorkspaceSnapshot> = session.current;
  let unsubscribe: (() => void) | undefined;

  onMount(() => {
    unsubscribe = session.subscribe((next) => {
      snapshot = next;
    });
    void session.initialize();
  });

  onDestroy(() => {
    unsubscribe?.();
    session.dispose();
  });

  function handleAction(action: WorkspaceAction): void {
    if (action.type === 'new-session') void session.createSession();
    if (action.type === 'select-session') void session.selectSession(action.sessionId);
    if (action.type === 'send') session.sendPrompt(action.text);
    if (action.type === 'stop') void session.stop();
    if (action.type === 'retry') void session.retryConnection();
    if (action.type === 'approve-tool') void session.approve(action.itemId, true);
    if (action.type === 'reject-tool') void session.approve(action.itemId, false);
    if (action.type === 'answer-clarification') {
      void session.answerClarification(action.itemId, action.answer);
    }
  }
</script>

<WorkspacePreview
  activeSessionId={snapshot.activeSessionId ?? ''}
  artifactInspectorEnabled={false}
  {appearance}
  dataMode="live"
  interactionEnabled={snapshot.activeSessionId !== undefined}
  model={snapshot.model}
  sessions={snapshot.sessions}
  state={snapshot.state}
  timelineEmptyLabel="No messages in this chat yet."
  timelineItems={snapshot.timeline}
  title={snapshot.title}
  onAction={handleAction}
/>
