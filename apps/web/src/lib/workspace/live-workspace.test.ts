import { describe, expect, it } from 'vitest';
import type { LiveMessage, LiveSession } from '$lib/transport';
import { mapLiveMessages, mapLiveSessions } from './live-workspace';

const SESSION: LiveSession = {
  id: 'session-1',
  source: 'web',
  model: 'Hermes 4',
  title: 'Live session',
  startedAt: 1,
  endedAt: null,
  lastActive: 2,
  isActive: true,
  messageCount: 2,
  toolCallCount: 1,
  inputTokens: 10,
  outputTokens: 20,
  preview: 'retained server preview'
};

describe('live workspace mapping', () => {
  it('maps active REST sessions without copying transcript previews', () => {
    const sessions = mapLiveSessions([
      { ...SESSION, pinned: true },
      { ...SESSION, id: 'archived', archived: true, preview: 'hidden transcript' },
      { ...SESSION, id: 'untitled', title: '   ', model: null, messageCount: 1 }
    ]);

    expect(sessions).toEqual([
      {
        id: 'session-1',
        title: 'Live session',
        detail: '2 messages · Hermes 4',
        group: 'pinned'
      },
      {
        id: 'untitled',
        title: 'Untitled chat',
        detail: '1 message',
        group: 'recent'
      }
    ]);
    expect(JSON.stringify(sessions)).not.toContain('server preview');
    expect(JSON.stringify(sessions)).not.toContain('hidden transcript');
  });

  it('maps conversation text while redacting tool arguments, outputs, and system context', () => {
    const messages: LiveMessage[] = [
      { role: 'system', content: 'private system context' },
      { role: 'user', content: 'Run the report' },
      {
        role: 'assistant',
        content: 'I will check it.',
        toolCalls: [
          {
            id: 'tool-call-1',
            function: { name: 'report_lookup', arguments: '{"secret":"never-copy"}' }
          }
        ]
      },
      {
        role: 'tool',
        content: 'sensitive tool output',
        toolName: 'report_lookup',
        toolCallId: 'tool-call-1'
      }
    ];

    const timeline = mapLiveMessages('session-1', messages, 'Hermes 4');

    expect(timeline).toEqual([
      { kind: 'user-message', id: 'session-1:message:1', text: 'Run the report' },
      {
        kind: 'assistant-message',
        id: 'session-1:message:2',
        text: 'I will check it.',
        model: 'Hermes 4',
        status: 'complete'
      },
      {
        kind: 'tool',
        id: 'session-1:message:2:tool:0',
        label: 'report_lookup',
        detail: 'Tool request recorded by Hermes.',
        status: 'completed'
      },
      {
        kind: 'tool',
        id: 'session-1:message:3',
        label: 'report_lookup',
        detail: 'Tool response received.',
        status: 'completed'
      }
    ]);
    expect(JSON.stringify(timeline)).not.toContain('private system context');
    expect(JSON.stringify(timeline)).not.toContain('never-copy');
    expect(JSON.stringify(timeline)).not.toContain('sensitive tool output');
  });
});
