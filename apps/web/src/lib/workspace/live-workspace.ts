import type { LiveMessage, LiveSession } from '$lib/transport';
import type { SessionSummary, TimelineItem } from './types';

/**
 * Convert bounded REST reads into the existing workspace presentation contract.
 * The caller replaces these arrays on each server read; this module does not
 * persist a transcript or copy tool arguments and tool output into compact UI.
 */
export function mapLiveSessions(sessions: readonly LiveSession[]): SessionSummary[] {
  return sessions
    .filter((session) => session.archived !== true)
    .map((session) => ({
      id: session.id,
      title: visibleSessionTitle(session),
      detail: sessionDetail(session),
      group: session.pinned === true ? 'pinned' : 'recent'
    }));
}

export function mapLiveMessages(sessionId: string, messages: readonly LiveMessage[], model = 'Hermes'): TimelineItem[] {
  const items: TimelineItem[] = [];

  messages.forEach((message, messageIndex) => {
    const baseId = `${sessionId}:message:${messageIndex}`;
    const text = visibleText(message.content);

    if (message.role === 'user' && text) {
      items.push({ kind: 'user-message', id: baseId, text });
      return;
    }

    if (message.role === 'assistant') {
      if (text) {
        items.push({ kind: 'assistant-message', id: baseId, text, model, status: 'complete' });
      }
      message.toolCalls?.forEach((toolCall, toolIndex) => {
        items.push({
          kind: 'tool',
          id: `${baseId}:tool:${toolIndex}`,
          label: toolCall.function.name,
          detail: 'Tool request recorded by Hermes.',
          status: 'completed'
        });
      });
      return;
    }

    if (message.role === 'tool') {
      items.push({
        kind: 'tool',
        id: baseId,
        label: message.toolName || 'Tool',
        detail: 'Tool response received.',
        status: 'completed'
      });
    }
    // System messages are source-owned control context, not conversation copy.
  });

  return items;
}

function visibleSessionTitle(session: LiveSession): string {
  return visibleText(session.title) ?? 'Untitled chat';
}

function sessionDetail(session: LiveSession): string {
  const count = `${session.messageCount} ${session.messageCount === 1 ? 'message' : 'messages'}`;
  const model = visibleText(session.model);
  return model ? `${count} · ${model}` : count;
}

function visibleText(value: string | null): string | undefined {
  const text = value?.trim();
  return text ? text : undefined;
}
