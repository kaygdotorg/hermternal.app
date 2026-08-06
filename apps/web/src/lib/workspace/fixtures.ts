import type { ImageAttachment, SessionSummary, TimelineItem, WorkspaceRuntimeState } from './types';

/**
 * These fixtures make the UI reviewable without a transport, credential, or
 * transcript mirror. They intentionally describe a believable long session
 * while remaining synthetic and local to the presentation layer.
 */
export const DEFAULT_SESSIONS: SessionSummary[] = [
  { id: 'product-roadmap', title: 'Product roadmap', group: 'pinned', unread: true },
  { id: 'interaction-study', title: 'Interaction study', group: 'pinned' },
  { id: 'offline-drafts', title: 'Offline drafts', group: 'pinned' },
  {
    id: 'quarterly-logistics',
    title: 'Quarterly logistics',
    detail: 'Tool approval required',
    group: 'recent',
    selected: true
  },
  { id: 'emea-supply-chain', title: 'EMEA supply chain', group: 'recent' },
  { id: 'app-architecture', title: 'App architecture', group: 'recent' }
];

export const DEFAULT_IMAGE: ImageAttachment = {
  id: 'synthetic-logistics-chart',
  alt: 'Synthetic container load by hub chart',
  caption: 'Container load by hub · synthetic fixture'
};

export const DEFAULT_TIMELINE: TimelineItem[] = [
  {
    kind: 'user-message',
    id: 'user-1',
    text: 'Analyze the shipping surge in EMEA hubs for Q3. Focus specifically on Rotterdam and Hamburg.'
  },
  {
    kind: 'assistant-message',
    id: 'assistant-1',
    model: 'Atlas · balanced',
    status: 'draft',
    text: 'I’ll trace the strongest signal through the synthetic logistics fixture before summarizing the bottleneck.'
  },
  {
    kind: 'tool',
    id: 'tool-1',
    label: 'Read logistics fixture',
    detail: 'Synthetic source · 12 rows · read-only',
    status: 'completed'
  },
  {
    kind: 'approval',
    id: 'approval-1',
    title: 'Allow a mock route check?',
    description: 'This presentation-only tool would compare two synthetic hub snapshots. No network request is made.',
    confirmLabel: 'Allow once',
    rejectLabel: 'Not now',
    status: 'pending'
  },
  {
    kind: 'tool',
    id: 'tool-2',
    label: 'Compare Rotterdam and Hamburg',
    detail: 'Waiting for approval',
    status: 'pending'
  },
  {
    kind: 'clarification',
    id: 'clarification-1',
    question: 'Should the comparison include inland transfers?',
    options: ['Include transfers', 'Ocean legs only']
  },
  {
    kind: 'image',
    id: 'image-1',
    attachment: DEFAULT_IMAGE
  },
  {
    kind: 'assistant-message',
    id: 'assistant-2',
    model: 'Atlas · balanced',
    text: 'The strongest signal is a processing bottleneck at Rotterdam. Hamburg remains steadier when inland transfers are excluded.'
  }
];

export function timelineForState(state: WorkspaceRuntimeState): TimelineItem[] {
  if (state === 'loading') {
    return [{ kind: 'loading', id: 'loading-1', label: 'Restoring session' }];
  }

  if (state === 'empty') {
    return [];
  }

  if (state === 'streaming') {
    return [
      ...DEFAULT_TIMELINE.slice(0, 4),
      {
        kind: 'streaming',
        id: 'streaming-1',
        model: 'Atlas · balanced',
        text: 'The strongest signal is a processing bottleneck at Rotterdam'
      }
    ];
  }

  if (state === 'stopped') {
    return [
      ...DEFAULT_TIMELINE.slice(0, 4),
      {
        kind: 'stopped',
        id: 'stopped-1',
        text: 'The partial response remains in the transcript. No automatic retry will be attempted.'
      }
    ];
  }

  if (state === 'retryable-error') {
    return [
      ...DEFAULT_TIMELINE.slice(0, 2),
      {
        kind: 'error',
        id: 'error-1',
        title: 'Connection lost',
        detail: 'Your draft is safe. Reconnect before sending it.'
      }
    ];
  }

  if (state === 'permanent-error') {
    return [
      ...DEFAULT_TIMELINE.slice(0, 2),
      {
        kind: 'error',
        id: 'error-2',
        title: 'Session state rejected',
        detail: 'No prompt was resent. Return to sessions to continue safely.'
      }
    ];
  }

  if (state === 'compatibility-check-failed' || state === 'unsupported-version') {
    // The approved gate keeps synthetic session context visible behind its
    // blocking layer. Actions are disabled by the runtime state, not removed.
    return DEFAULT_TIMELINE;
  }

  return DEFAULT_TIMELINE;
}
