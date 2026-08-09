import { render, waitFor } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { CurrentSessionTerminalEvent, CurrentSessionTerminalState } from '$lib/terminal/current-session-terminal';
import TerminalSurface from './TerminalSurface.svelte';

const harness = vi.hoisted(() => {
  const instances: any[] = [];
  let deferredMount: Promise<void> | undefined;
  const createTerminalRenderer = vi.fn((options: any) => {
    const instance: any = {
      state: 'idle', error: null, write: vi.fn(), resize: vi.fn(), focus: vi.fn(), whenIdle: vi.fn(), dispose: vi.fn(),
      mount: vi.fn(async () => { await deferredMount; instance.state = 'ready'; options.onStateChange?.('ready'); })
    };
    instances.push(instance);
    return instance;
  });
  return { instances, createTerminalRenderer, setDeferred: (value?: Promise<void>) => { deferredMount = value; } };
});
vi.mock('$lib/terminal/renderer', () => ({ createTerminalRenderer: harness.createTerminalRenderer }));

const attached = (sessionId: string, generation: number): CurrentSessionTerminalState => ({
  status: 'attached', generation, sessionId, outputMayBeTruncated: false, explicitlyClosed: false
});

function replacementBridge() {
  const listeners = new Set<(event: CurrentSessionTerminalEvent) => void>();
  const readinessWaiters = new Set<() => void>();
  let current = attached('session-one', 1);
  let rendererReady = false;

  const publish = (event: CurrentSessionTerminalEvent): void => {
    if (event.type === 'state') current = event.state;
    for (const listener of listeners) listener(event);
  };

  return {
    get state() { return current; },
    get lifecycleIdentity() { return { binding: undefined, nativeTransportGeneration: current.generation }; },
    subscribe(listener: (event: CurrentSessionTerminalEvent) => void) {
      listeners.add(listener);
      listener({ type: 'state', state: current });
      return () => listeners.delete(listener);
    },
    sendInput: vi.fn(), resize: vi.fn(), detach: vi.fn(),
    setRendererReady: vi.fn((ready: boolean) => {
      rendererReady = ready;
      if (!ready) return;
      for (const resolve of [...readinessWaiters]) {
        readinessWaiters.delete(resolve);
        resolve();
      }
    }),
    async replaceSession(sessionId: string, chunks: readonly Uint8Array[]): Promise<void> {
      // Production replacement first removes the old current-session owner. The
      // attach path must observe TerminalSurface closing readiness synchronously.
      publish({ type: 'state', state: { status: 'closed', generation: current.generation, outputMayBeTruncated: false, explicitlyClosed: false } });
      if (!rendererReady) await new Promise<void>((resolve) => readinessWaiters.add(resolve));
      const generation = current.generation + 1;
      publish({ type: 'state', state: attached(sessionId, generation) });
      for (const bytes of chunks) publish({ type: 'bytes', generation, bytes, outputMayBeTruncated: false });
    }
  };
}

beforeEach(() => {
  harness.instances.length = 0;
  harness.createTerminalRenderer.mockClear();
  harness.setDeferred();
});

describe('live workspace terminal replacement', () => {
  it('holds initial replacement bytes until the replacement renderer owns readiness', async () => {
    const bridge = replacementBridge();
    const view = render(TerminalSurface, { bridge, active: true });
    await waitFor(() => expect(harness.instances).toHaveLength(1));
    const sessionOneRenderer = harness.instances[0];

    let releaseReplacementRenderer!: () => void;
    harness.setDeferred(new Promise<void>((resolve) => { releaseReplacementRenderer = resolve; }));
    const chunks = [new Uint8Array([0xff, 0x00]), new Uint8Array([0x80, 0x01])];
    let replacementSettled = false;
    const replacement = bridge.replaceSession('session-two', chunks).then(() => { replacementSettled = true; });

    await waitFor(() => expect(harness.instances).toHaveLength(2));
    expect(bridge.setRendererReady).toHaveBeenLastCalledWith(false);
    expect(sessionOneRenderer.dispose).toHaveBeenCalledTimes(1);
    expect(replacementSettled).toBe(false);

    const sessionTwoRenderer = harness.instances[1];
    releaseReplacementRenderer();
    await replacement;

    expect(sessionOneRenderer.write).not.toHaveBeenCalled();
    expect(sessionTwoRenderer.write.mock.calls.map(([bytes]: [Uint8Array]) => bytes)).toEqual(chunks);
    expect(sessionTwoRenderer.write).toHaveBeenCalledTimes(2);
    expect(sessionTwoRenderer.dispose).not.toHaveBeenCalled();
    expect(harness.instances).toHaveLength(2);
    view.unmount();
  });
});
