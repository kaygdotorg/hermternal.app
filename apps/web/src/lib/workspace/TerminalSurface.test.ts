import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { FocusIntent } from '$lib/session/coordinator';
import type {
  CurrentSessionTerminalBridge,
  CurrentSessionTerminalEvent,
  CurrentSessionTerminalState
} from '$lib/terminal/current-session-terminal';
import TerminalSurface from './TerminalSurface.svelte';

const rendererHarness = vi.hoisted(() => {
  const instances: Array<{
    state: 'idle' | 'loading' | 'ready' | 'error' | 'disposed';
    error: null;
    mount: ReturnType<typeof vi.fn>;
    write: ReturnType<typeof vi.fn>;
    resize: ReturnType<typeof vi.fn>;
    focus: ReturnType<typeof vi.fn>;
    whenIdle: ReturnType<typeof vi.fn>;
    dispose: ReturnType<typeof vi.fn>;
    onInput?: (data: string) => void;
  }> = [];
  const createTerminalRenderer = vi.fn((options: { onInput?: (data: string) => void; onStateChange?: (state: string) => void }) => {
    const instance = {
      state: 'idle' as 'idle' | 'loading' | 'ready' | 'error' | 'disposed',
      error: null,
      mount: vi.fn(async () => {
        instance.state = 'ready';
        options.onStateChange?.('ready');
      }),
      write: vi.fn(),
      resize: vi.fn(),
      focus: vi.fn(),
      whenIdle: vi.fn().mockResolvedValue(undefined),
      dispose: vi.fn(),
      onInput: options.onInput
    };
    instances.push(instance);
    return instance;
  });
  return { instances, createTerminalRenderer };
});

vi.mock('$lib/terminal/renderer', () => ({
  createTerminalRenderer: rendererHarness.createTerminalRenderer
}));

const INITIAL_STATE: CurrentSessionTerminalState = {
  status: 'closed',
  generation: 0,
  outputMayBeTruncated: false,
  explicitlyClosed: false
};

function createBridge() {
  const listeners = new Set<(event: CurrentSessionTerminalEvent) => void>();
  let state = INITIAL_STATE;
  const bridge = {
    get state() {
      return state;
    },
    subscribe(listener: (event: CurrentSessionTerminalEvent) => void) {
      listeners.add(listener);
      listener({ type: 'state', state });
      return () => listeners.delete(listener);
    },
    sendInput: vi.fn(),
    resize: vi.fn(),
    setRendererReady: vi.fn(),
    reconnect: vi.fn().mockResolvedValue(undefined),
    detach: vi.fn(),
    close: vi.fn(),
    emit(event: CurrentSessionTerminalEvent) {
      if (event.type === 'state') state = event.state;
      for (const listener of [...listeners]) listener(event);
    }
  };
  return bridge as typeof bridge & { readonly asBridge: CurrentSessionTerminalBridge };
}

function setRect(node: HTMLElement, width = 800, height = 400): void {
  Object.defineProperty(node, 'getBoundingClientRect', {
    configurable: true,
    value: () => ({ width, height, top: 0, right: width, bottom: height, left: 0, x: 0, y: 0 })
  });
}

describe('TerminalSurface', () => {
  beforeEach(() => {
    rendererHarness.createTerminalRenderer.mockClear();
    rendererHarness.instances.length = 0;
  });

  it('lazy-loads only after activation, forwards raw output/input/resize, and disposes the renderer', async () => {
    const bridge = createBridge();
    const resizeCallbacks: Array<() => void> = [];
    vi.stubGlobal(
      'ResizeObserver',
      class {
        constructor(callback: () => void) {
          resizeCallbacks.push(callback);
        }
        observe() {}
        disconnect() {}
      }
    );
    const view = render(TerminalSurface, { bridge, active: false });

    await Promise.resolve();
    expect(rendererHarness.createTerminalRenderer).not.toHaveBeenCalled();

    await view.rerender({
      bridge,
      active: true,
      coordinator: {
        status: 'active',
        mode: 'terminal',
        sessionGeneration: 1,
        compatibility: 'compatible',
        chatStatus: 'ready',
        terminalStatus: 'attached',
        activeSessionId: 'session-1',
        terminalSessionId: 'session-1'
      }
    });
    await waitFor(() => expect(rendererHarness.createTerminalRenderer).toHaveBeenCalledTimes(1));
    const renderer = rendererHarness.instances[0]!;
    const host = screen.getByRole('region', { name: 'Terminal input and output' });
    setRect(host);

    bridge.emit({
      type: 'state',
      state: {
        status: 'attached',
        generation: 0,
        sessionId: 'session-1',
        outputMayBeTruncated: false,
        explicitlyClosed: false,
        reconnectSupported: false
      }
    });
    const bytes = new Uint8Array([0xff, 0x00, 0x80]);
    bridge.emit({ type: 'bytes', generation: 0, bytes, outputMayBeTruncated: false });
    renderer.onInput?.('printf ready');
    resizeCallbacks[0]?.();

    expect(renderer.write).toHaveBeenCalledWith(bytes);
    expect(bridge.sendInput).toHaveBeenCalledWith('printf ready');
    expect(renderer.resize).toHaveBeenCalledWith(100, 20);
    expect(bridge.resize).toHaveBeenCalledWith(100, 20);

    view.unmount();
    expect(bridge.setRendererReady).toHaveBeenLastCalledWith(false);
    expect(renderer.dispose).toHaveBeenCalledTimes(1);
    vi.unstubAllGlobals();
  });

  it('keeps readiness closed when the renderer sink is torn down', async () => {
    const bridge = createBridge();
    const view = render(TerminalSurface, { bridge, active: true });
    await waitFor(() => expect(rendererHarness.instances).toHaveLength(1));

    bridge.setRendererReady.mockClear();
    view.unmount();

    expect(bridge.setRendererReady).toHaveBeenCalledTimes(1);
    expect(bridge.setRendererReady).toHaveBeenCalledWith(false);
    expect(bridge.setRendererReady).not.toHaveBeenCalledWith(true);
  });

  it('applies coordinator focus intent and exposes lifecycle recovery actions', async () => {
    const bridge = createBridge();
    const focusIntent: FocusIntent = {
      mode: 'terminal',
      target: 'w-term-input',
      sessionId: 'session-1',
      sessionGeneration: 1,
      sequence: 1
    };
    const onAction = vi.fn();
    render(TerminalSurface, { bridge, active: true, focusIntent, onAction });
    await waitFor(() => expect(rendererHarness.instances.at(-1)?.focus).toHaveBeenCalled());

    bridge.emit({
      type: 'state',
      state: {
        status: 'failed',
        generation: 2,
        sessionId: 'session-1',
        closeCode: 4401,
        closeClassification: 'authentication-rejected',
        outputMayBeTruncated: false,
        explicitlyClosed: false,
        failure: 'authentication-required'
      }
    });

    await waitFor(() => expect(screen.getByText(/Authentication required/)).toBeInTheDocument());
    await fireEvent.click(screen.getByRole('button', { name: 'Return to sign in' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Return to Chat mode' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Detach terminal' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Close terminal' }));

    expect(onAction).toHaveBeenCalledWith({ type: 'return-to-sign-in' });
    expect(onAction).toHaveBeenCalledWith({ type: 'set-mode', mode: 'chat' });
    expect(onAction).toHaveBeenCalledWith({ type: 'terminal-detach' });
    expect(onAction).toHaveBeenCalledWith({ type: 'terminal-close' });
  });

  it('keeps the renderer ready across PTY generations and rewires when the bridge is replaced', async () => {
    const firstBridge = createBridge();
    const secondBridge = createBridge();
    const view = render(TerminalSurface, { bridge: firstBridge, active: true });
    await waitFor(() => expect(rendererHarness.instances).toHaveLength(1));
    const firstRenderer = rendererHarness.instances[0]!;

    firstBridge.emit({
      type: 'state',
      state: {
        status: 'attached',
        generation: 1,
        sessionId: 'session-1',
        outputMayBeTruncated: false,
        explicitlyClosed: false
      }
    });
    await waitFor(() => expect(rendererHarness.instances).toHaveLength(1));
    expect(firstRenderer.dispose).not.toHaveBeenCalled();

    const currentBytes = new Uint8Array([0x41]);
    firstBridge.emit({ type: 'bytes', generation: 1, bytes: currentBytes, outputMayBeTruncated: false });
    expect(firstRenderer.write).toHaveBeenCalledWith(currentBytes);

    await view.rerender({ bridge: secondBridge, active: true });
    await waitFor(() => expect(rendererHarness.instances).toHaveLength(2));
    const secondRenderer = rendererHarness.instances[1]!;
    expect(firstRenderer.dispose).toHaveBeenCalledTimes(1);

    const staleBytes = new Uint8Array([0x42]);
    firstBridge.emit({ type: 'bytes', generation: 1, bytes: staleBytes, outputMayBeTruncated: false });
    expect(secondRenderer.write).not.toHaveBeenCalled();
    const replacementBytes = new Uint8Array([0x43]);
    secondBridge.emit({ type: 'bytes', generation: 0, bytes: replacementBytes, outputMayBeTruncated: false });
    expect(secondRenderer.write).toHaveBeenCalledWith(replacementBytes);

    view.unmount();
  });
});
