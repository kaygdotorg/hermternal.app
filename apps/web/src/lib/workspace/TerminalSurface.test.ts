import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { FocusIntent, SessionCoordinatorState, TerminalBinding } from '$lib/session/coordinator';
import type { CurrentSessionTerminalEvent, CurrentSessionTerminalState } from '$lib/terminal/current-session-terminal';
import TerminalSurface from './TerminalSurface.svelte';

const harness = vi.hoisted(() => {
  const instances: any[] = [];
  let deferredMount: Promise<void> | undefined;
  const createTerminalRenderer = vi.fn((options: any) => {
    const instance: any = {
      state: 'idle', error: null, write: vi.fn(), resize: vi.fn(), focus: vi.fn(), whenIdle: vi.fn(), dispose: vi.fn(),
      mount: vi.fn(async () => { await deferredMount; instance.state = 'ready'; options.onStateChange?.('ready'); }), onInput: options.onInput
    };
    instances.push(instance);
    return instance;
  });
  return { instances, createTerminalRenderer, setDeferred: (value?: Promise<void>) => { deferredMount = value; } };
});
vi.mock('$lib/terminal/renderer', () => ({ createTerminalRenderer: harness.createTerminalRenderer }));

const attached = (sessionId = 'one', generation = 1): CurrentSessionTerminalState => ({ status: 'attached', generation, sessionId, outputMayBeTruncated: false, explicitlyClosed: false });
const coordinator = (sessionId = 'one', generation = 1, mode: 'chat' | 'terminal' = 'terminal'): SessionCoordinatorState => ({ status: 'active', mode, activeSessionId: sessionId, sessionGeneration: generation, compatibility: 'compatible', chatStatus: 'ready', terminalStatus: 'attached', terminalSessionId: sessionId });
const intent = (sequence = 1, sessionId = 'one', generation = 1): FocusIntent => ({ mode: 'terminal', target: 'w-term-input', sessionId, sessionGeneration: generation, sequence });

function bridge(state = attached()) {
  const listeners = new Set<(event: CurrentSessionTerminalEvent) => void>();
  let current = state;
  let nativeGeneration = state.generation;
  const createBinding = (): TerminalBinding => ({ sessionId: state.sessionId ?? 'one', invalidate: vi.fn() });
  let binding: TerminalBinding | undefined = createBinding();
  return {
    get state() { return current; },
    get lifecycleIdentity() { return { binding, nativeTransportGeneration: nativeGeneration }; },
    subscribe(listener: (event: CurrentSessionTerminalEvent) => void) { listeners.add(listener); listener({ type: 'state', state: current }); return () => listeners.delete(listener); },
    sendInput: vi.fn(), resize: vi.fn(), detach: vi.fn(), setRendererReady: vi.fn(),
    emit(event: CurrentSessionTerminalEvent) { if (event.type === 'state') current = event.state; for (const listener of listeners) listener(event); },
    replaceLease() { binding = createBinding(); }, setNativeGeneration(value: number) { nativeGeneration = value; }
  };
}
function rect(node: HTMLElement, width = 800, height = 400) { Object.defineProperty(node, 'getBoundingClientRect', { configurable: true, value: () => ({ width, height }) }); }

beforeEach(() => { harness.instances.length = 0; harness.createTerminalRenderer.mockClear(); harness.setDeferred(); });

describe('TerminalSurface', () => {
  it('lazily mounts W-Term, gates replay, and forwards opaque bytes, input, and resize', async () => {
    const b = bridge();
    const callbacks: (() => void)[] = [];
    vi.stubGlobal('ResizeObserver', class { constructor(callback: () => void) { callbacks.push(callback); } observe() {} disconnect() {} });
    const view = render(TerminalSurface, { bridge: b, active: false, coordinator: coordinator() });
    expect(harness.createTerminalRenderer).not.toHaveBeenCalled();
    await view.rerender({ bridge: b, active: true, coordinator: coordinator() });
    await waitFor(() => expect(harness.instances).toHaveLength(1));
    const renderer = harness.instances[0];
    const host = screen.getByRole('region', { name: 'Terminal input and output' }); rect(host); callbacks[0]?.();
    const bytes = new Uint8Array([255, 0, 128]); b.emit({ type: 'bytes', generation: 1, bytes, outputMayBeTruncated: false }); renderer.onInput('pwd');
    expect(renderer.write).toHaveBeenCalledWith(bytes); expect(b.sendInput).toHaveBeenCalledWith('pwd'); expect(renderer.resize).toHaveBeenCalledWith(100, 20); expect(b.resize).toHaveBeenCalledWith(100, 20); expect(b.setRendererReady).toHaveBeenCalledWith(true);
    view.unmount(); expect(b.setRendererReady).toHaveBeenLastCalledWith(false); expect(renderer.dispose).toHaveBeenCalled(); vi.unstubAllGlobals();
  });

  it('fails closed when delayed renderer mount rejects', async () => {
    const b = bridge(); harness.createTerminalRenderer.mockImplementationOnce((options: any) => ({ state: 'idle', error: null, mount: vi.fn().mockRejectedValue(new Error('raw')), write: vi.fn(), resize: vi.fn(), focus: vi.fn(), dispose: vi.fn(), whenIdle: vi.fn(), onInput: options.onInput }));
    render(TerminalSurface, { bridge: b, active: true, coordinator: coordinator() });
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Terminal unavailable.'));
    expect(b.setRendererReady).toHaveBeenLastCalledWith(false); expect(b.detach).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['mode', (b: ReturnType<typeof bridge>, view: any) => view.rerender({ bridge: b, active: true, coordinator: coordinator('one', 1, 'chat'), focusIntent: intent() })],
    ['target', (b: ReturnType<typeof bridge>, view: any) => view.rerender({ bridge: b, active: true, coordinator: coordinator(), focusIntent: { ...intent(), target: 'composer' } })],
    ['session', (b: ReturnType<typeof bridge>, view: any) => view.rerender({ bridge: b, active: true, coordinator: coordinator('two'), focusIntent: intent() })],
    ['coordinator generation', (b: ReturnType<typeof bridge>, view: any) => view.rerender({ bridge: b, active: true, coordinator: coordinator('one', 2), focusIntent: intent() })],
    ['focus sequence', (b: ReturnType<typeof bridge>, view: any) => view.rerender({ bridge: b, active: true, coordinator: coordinator(), focusIntent: intent(2) })],
    ['native generation', (b: ReturnType<typeof bridge>) => { b.setNativeGeneration(2); return Promise.resolve(); }],
    ['binding lease', (b: ReturnType<typeof bridge>) => { b.replaceLease(); return Promise.resolve(); }]
  ])('does not focus after a delayed mount when %s changes', async (_label, invalidate) => {
    let release!: () => void; harness.setDeferred(new Promise<void>((resolve) => { release = resolve; }));
    const b = bridge(); const view = render(TerminalSurface, { bridge: b, active: true, coordinator: coordinator(), focusIntent: intent() });
    await waitFor(() => expect(harness.instances).toHaveLength(1));
    await invalidate(b, view); release(); await Promise.resolve(); await Promise.resolve();
    expect(harness.instances[0].focus).not.toHaveBeenCalled(); view.unmount();
  });

  it('rejects replacement bridge and unmount focus continuations', async () => {
    let release!: () => void; harness.setDeferred(new Promise<void>((resolve) => { release = resolve; }));
    const first = bridge(); const second = bridge(); const view = render(TerminalSurface, { bridge: first, active: true, coordinator: coordinator(), focusIntent: intent() });
    await waitFor(() => expect(harness.instances).toHaveLength(1));
    await view.rerender({ bridge: second, active: true, coordinator: coordinator(), focusIntent: intent() }); view.unmount(); release(); await Promise.resolve();
    expect(harness.instances.every((item) => item.focus.mock.calls.length === 0)).toBe(true);
  });

  it('preserves accessible keyboard controls and reduced-motion-safe terminal semantics through rapid terminal-chat-terminal changes', async () => {
    const b = bridge(); const onAction = vi.fn(); const view = render(TerminalSurface, { bridge: b, active: true, coordinator: coordinator(), focusIntent: intent(), onAction });
    await waitFor(() => expect(harness.instances).toHaveLength(1));
    await view.rerender({ bridge: b, active: false, coordinator: coordinator('one', 1, 'chat') });
    await view.rerender({ bridge: b, active: true, coordinator: coordinator(), focusIntent: intent(2) });
    await fireEvent.keyDown(screen.getByRole('button', { name: 'Return to Chat mode' }), { key: 'Enter' });
    expect(screen.getByRole('region', { name: 'Terminal input and output' })).toHaveAttribute('aria-describedby', 'terminal-help');
    expect(screen.getByRole('button', { name: 'Detach terminal' })).toBeVisible(); expect(screen.getByRole('button', { name: 'Close terminal' })).toBeVisible();
    await fireEvent.click(screen.getByRole('button', { name: 'Return to Chat mode' })); expect(onAction).toHaveBeenCalledWith({ type: 'set-mode', mode: 'chat' }); view.unmount();
  });
});
