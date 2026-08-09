import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { tick } from 'svelte';
import { describe, expect, it, vi } from 'vitest';
import AuthPreview from './AuthPreview.svelte';
import { DEFAULT_PROVIDERS } from './fixtures';

type PasswordDomState = [string, string, string, string, string | null, string | null];

function readPasswordDomState(username: HTMLInputElement, password: HTMLInputElement): PasswordDomState {
  return [
    username.value,
    password.value,
    username.defaultValue,
    password.defaultValue,
    username.getAttribute('value'),
    password.getAttribute('value')
  ];
}

const EMPTY_PASSWORD_DOM_STATE: PasswordDomState = ['', '', '', '', null, null];

describe('AuthPreview', () => {
  it('renders provider selection without exposing search or deep-link controls', () => {
    render(AuthPreview, { state: 'provider-selection' });

    expect(screen.getByRole('heading', { name: 'Connect to Hermes' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Nous' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Hermes password' })).toBeInTheDocument();
    expect(screen.queryByRole('searchbox')).not.toBeInTheDocument();
    expect(screen.queryByText(/deep link/i)).not.toBeInTheDocument();
    expect(screen.getByText(/no discovery request is made/i)).toBeInTheDocument();
  });

  it.each([
    ['empty', []],
    ['duplicate IDs', [DEFAULT_PROVIDERS[0], { ...DEFAULT_PROVIDERS[1], id: DEFAULT_PROVIDERS[0].id }]],
    ['missing kind', [{ ...DEFAULT_PROVIDERS[0], kind: undefined }]],
    ['future kind', [{ ...DEFAULT_PROVIDERS[0], kind: 'device-code' }]],
    ['malformed entry', [null]]
  ])('fails closed when provider fixtures contain %s', async (_label, providers) => {
    render(AuthPreview, { state: 'provider-selection', providers: providers as never });

    expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'provider-unavailable');
    expect(screen.getByRole('alert')).toHaveTextContent('No sign-in method is available');
    expect(screen.queryByRole('button', { name: 'Nous' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Hermes password' })).not.toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Provider discovery stopped' })).toHaveFocus());
  });

  it('renders a provider without reviewed browser capability as visible but unavailable', () => {
    render(AuthPreview, {
      state: 'provider-selection',
      providers: [
        {
          id: 'provider-neutral',
          name: 'Provider Neutral',
          monogram: 'P',
          kind: 'unavailable',
          description: 'Provider reported without a reviewed browser sign-in capability'
        }
      ]
    });

    expect(screen.getByRole('button', { name: 'Provider Neutral, unavailable' })).toBeDisabled();
    expect(screen.getByText(/without a reviewed browser sign-in capability/i)).toBeInTheDocument();
  });

  it('marks the synthetic password form so password managers do not treat it as reusable credentials', () => {
    render(AuthPreview, { state: 'password' });

    const form = screen.getByRole('form', { name: 'Hermes password sign in' });
    const username = screen.getByLabelText('Username');
    const password = screen.getByLabelText('Password');
    expect(form).toHaveAttribute('autocomplete', 'off');
    expect(form).toHaveAttribute('data-form-type', 'other');
    expect(form).toHaveAttribute('method', 'dialog');
    for (const field of [username, password]) {
      expect(field).toHaveAttribute('autocomplete', 'off');
      expect(field).toHaveAttribute('data-1p-ignore');
      expect(field).toHaveAttribute('data-lpignore', 'true');
      expect(field).not.toHaveAttribute('name');
      expect(field).toHaveAttribute('data-fixture-field');
    }
    expect(username).toHaveValue('');
    expect(username).toHaveAttribute('placeholder', 'Enter username');
    expect(password).toHaveAttribute('placeholder', 'Enter password');
    expect(screen.getByRole('button', { name: 'Sign in' })).toHaveAttribute('type', 'reset');
  });

  it('fences live fields until hydration owns focus and preserves password-manager semantics', async () => {
    render(AuthPreview, { discoveryMode: 'live', state: 'password' });

    const form = screen.getByRole('form', { name: 'Hermes password sign in' });
    const username = screen.getByLabelText('Username');
    const password = screen.getByLabelText('Password');
    expect(form).toHaveAttribute('method', 'dialog');
    expect(screen.getByRole('button', { name: 'Sign in' })).toHaveAttribute('type', 'reset');
    expect(form).toHaveAttribute('data-field-ownership', 'pending');
    expect(form).not.toHaveAttribute('autocomplete');
    expect(form).not.toHaveAttribute('data-form-type');
    expect(username).toHaveAttribute('readonly');
    expect(password).toHaveAttribute('readonly');
    expect(username).toHaveAttribute('autocomplete', 'username');
    expect(password).toHaveAttribute('autocomplete', 'current-password');
    expect(username).toHaveAttribute('name', 'username');
    expect(password).toHaveAttribute('name', 'password');
    for (const field of [username, password]) {
      expect(field).not.toHaveAttribute('data-1p-ignore');
      expect(field).not.toHaveAttribute('data-lpignore');
      expect(field).not.toHaveAttribute('data-fixture-field');
    }

    await waitFor(() => expect(form).toHaveAttribute('data-field-ownership', 'ready'));
    expect(username).not.toHaveAttribute('readonly');
    expect(password).not.toHaveAttribute('readonly');
    expect(username).toHaveFocus();
  });

  it('keeps pointer ownership while submitting one credential-free action and clearing synchronously', async () => {
    const onAction = vi.fn();
    render(AuthPreview, { state: 'password', onAction });
    await waitFor(() => expect(screen.getByRole('form', { name: 'Hermes password sign in' })).toHaveAttribute('data-field-ownership', 'ready'));

    const username = screen.getByLabelText('Username');
    const password = screen.getByLabelText('Password');
    const signIn = screen.getByRole('button', { name: 'Sign in' });
    fireEvent.input(username, { target: { value: 'fixture-user' } });
    fireEvent.input(password, { target: { value: 'fixture-password' } });

    fireEvent.pointerDown(signIn, { button: 0, pointerType: 'mouse' });

    expect(username).toHaveValue('');
    expect(password).toHaveValue('');
    expect(onAction).toHaveBeenCalledTimes(1);
    expect(onAction).toHaveBeenCalledWith({ type: 'submit-password-fixture' });
    expect(onAction).toHaveBeenCalledTimes(1);
    expect(onAction.mock.calls[0]?.[0]).toEqual({ type: 'submit-password-fixture' });
    await waitFor(() => expect(signIn).toBeInTheDocument());

    fireEvent.pointerUp(signIn, { button: 0, pointerType: 'mouse' });
    fireEvent.click(signIn, { detail: 1 });
    expect(onAction).toHaveBeenCalledTimes(1);
  });

  it('emits cancel-sign-in separately and restores password focus and ownership on a synchronous return', async () => {
    let view!: ReturnType<typeof render>;
    const onAction = vi.fn((action: { type: string }) => {
      if (action.type === 'cancel-sign-in') void view.rerender({ state: 'password' });
    });
    view = render(AuthPreview, { state: 'password', onAction });

    await waitFor(() => expect(screen.getByRole('form', { name: 'Hermes password sign in' })).toHaveAttribute('data-field-ownership', 'ready'));
    await view.rerender({ state: 'password-submitting' });
    const cancel = await screen.findByRole('button', { name: 'Cancel sign-in' });

    await fireEvent.click(cancel);

    expect(onAction).toHaveBeenCalledWith({ type: 'cancel-sign-in' });
    expect(onAction).not.toHaveBeenCalledWith({ type: 'back-to-providers' });
    await waitFor(() => {
      expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'password');
      expect(screen.getByRole('form', { name: 'Hermes password sign in' })).toHaveAttribute('data-field-ownership', 'ready');
      expect(screen.getByLabelText('Username')).toHaveFocus();
    });
  });

  it.each(['pointerup', 'pointercancel'] as const)('suppresses the compatibility click after cancel-sign-in %s without clearing the returned provider selection', async (completion) => {
    let view!: ReturnType<typeof render>;
    const onAction = vi.fn((action: { type: string }) => {
      if (action.type === 'cancel-sign-in') void view.rerender({ state: 'password' });
    });
    view = render(AuthPreview, { state: 'password', onAction });
    await waitFor(() => expect(screen.getByRole('form', { name: 'Hermes password sign in' })).toHaveAttribute('data-field-ownership', 'ready'));
    await view.rerender({ state: 'password-submitting' });

    const cancel = screen.getByRole('button', { name: 'Cancel sign-in' });
    fireEvent.pointerDown(cancel, { button: 0, pointerType: 'mouse' });
    await waitFor(() => expect(screen.getByRole('button', { name: 'Back to providers' })).toBeInTheDocument());

    if (completion === 'pointerup') fireEvent.pointerUp(cancel, { button: 0, pointerType: 'mouse' });
    else fireEvent.pointerCancel(cancel, { pointerType: 'mouse' });
    fireEvent.click(screen.getByRole('button', { name: 'Back to providers' }), { detail: 1 });

    expect(onAction).toHaveBeenCalledTimes(1);
    expect(onAction).toHaveBeenCalledWith({ type: 'cancel-sign-in' });
    await waitFor(() => expect(screen.getByRole('form', { name: 'Hermes password sign in' })).toHaveAttribute('data-field-ownership', 'ready'));
    expect(screen.getByLabelText('Username')).toHaveFocus();
  });

  it('scrubs all input representations after bounded observer deliveries and tasks', async () => {
    let callbackDom: PasswordDomState | undefined;
    let transientSubmissionMatches = false;
    const onPasswordSubmit = vi.fn(({ username, password }: { username: string; password: string }) => {
      transientSubmissionMatches = username === 'hostile-user' && password === 'hostile-password';
      const callbackUsername = screen.getByLabelText('Username') as HTMLInputElement;
      const callbackPassword = screen.getByLabelText('Password') as HTMLInputElement;
      callbackDom = readPasswordDomState(callbackUsername, callbackPassword);
    });
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    // Force the documented fallback so the focus timer is part of the fake
    // schedule being stepped, rather than an uncontrolled animation frame.
    vi.stubGlobal('requestAnimationFrame', undefined);
    const view = render(AuthPreview, { discoveryMode: 'live', state: 'password', onPasswordSubmit });

    // Svelte's focus routine awaits tick() before scheduling its fallback
    // timeout. Flush that continuation explicitly so the one observed timer is
    // known focus work, not an inference from an empty queue.
    await tick();
    await Promise.resolve();
    expect(vi.getTimerCount()).toBe(1);
    // Release the known focus timer before installing scrub/observer timers so
    // each later callback can be stepped and attributed to its own phase.
    await vi.advanceTimersToNextTimerAsync();
    await Promise.resolve();
    await Promise.resolve();
    expect(vi.getTimerCount()).toBe(0);
    const form = screen.getByRole('form', { name: 'Hermes password sign in' });
    expect(form).toHaveAttribute('data-field-ownership', 'ready');
    const username = screen.getByLabelText('Username') as HTMLInputElement;
    const password = screen.getByLabelText('Password') as HTMLInputElement;
    fireEvent.input(username, { target: { value: 'hostile-user' } });
    fireEvent.input(password, { target: { value: 'hostile-password' } });
    username.defaultValue = 'retained-default-user';
    password.defaultValue = 'retained-default-password';

    const resetObservation: PasswordDomState[] = [];
    form.addEventListener('reset', (event) => {
      resetObservation.push(readPasswordDomState(username, password));
      event.preventDefault();
      username.value = 'reset-listener-user';
      password.value = 'reset-listener-password';
    });
    const observerSnapshots: PasswordDomState[] = [];
    const restorationSnapshots: PasswordDomState[] = [];
    const hostileTaskSnapshots: PasswordDomState[] = [];
    let observerCount = 0;
    let lateTaskQueued = false;
    let lateTaskRan = false;
    const observerInstances = new Set<FakeMutationObserver>();
    class FakeMutationObserver {
      private pending = false;
      private connected = false;
      private epoch = 0;
      private observedTarget: Node | undefined;
      private observeSubtree = false;
      private attributeFilter: Set<string> | undefined;

      constructor(private readonly callback: () => void) {}

      observe(target: Node, options?: MutationObserverInit): void {
        this.connected = true;
        this.epoch += 1;
        this.observedTarget = target;
        this.observeSubtree = options?.subtree === true;
        this.attributeFilter = options?.attributeFilter ? new Set(options.attributeFilter) : undefined;
        observerInstances.add(this);
      }
      disconnect(): void {
        this.connected = false;
        this.epoch += 1;
        this.observedTarget = undefined;
        this.attributeFilter = undefined;
        observerInstances.delete(this);
      }
      notify(target: Node, attributeName: string): void {
        if (!this.connected || this.pending || !this.observedTarget) return;
        const targetIsObserved =
          target === this.observedTarget || (this.observeSubtree && this.observedTarget.contains(target));
        if (!targetIsObserved || (this.attributeFilter && !this.attributeFilter.has(attributeName))) return;
        this.pending = true;
        const queuedEpoch = this.epoch;
        queueMicrotask(() => {
          this.pending = false;
          if (!this.connected || queuedEpoch !== this.epoch) return;
          this.callback();
        });
      }
      takeRecords(): MutationRecord[] {
        return [];
      }
    }
    vi.stubGlobal('MutationObserver', FakeMutationObserver);
    const notifyMutation = (target: Node = form, attributeName = 'value'): void => {
      for (const observer of observerInstances) observer.notify(target, attributeName);
    };
    const removeAttributeSpies = [username, password].map((input) =>
      vi.spyOn(input, 'removeAttribute').mockImplementation((name: string) => {
        HTMLInputElement.prototype.removeAttribute.call(input, name);
        if (name === 'value') notifyMutation(input, name);
      })
    );
    const setAttributeSpies = [username, password].map((input) =>
      vi.spyOn(input, 'setAttribute').mockImplementation((name: string, value: string) => {
        HTMLInputElement.prototype.setAttribute.call(input, name, value);
        if (name === 'value') notifyMutation(input, name);
      })
    );
    const defaultValueDescriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'defaultValue');
    if (!defaultValueDescriptor?.get || !defaultValueDescriptor.set) throw new Error('defaultValue descriptor unavailable');
    for (const input of [username, password]) {
      Object.defineProperty(input, 'defaultValue', {
        configurable: true,
        enumerable: defaultValueDescriptor.enumerable,
        get: () => defaultValueDescriptor.get!.call(input),
        set: (value: string) => {
          defaultValueDescriptor.set!.call(input, value);
          notifyMutation(input, 'value');
        }
      });
    }
    const observer = new MutationObserver(() => {
      observerCount += 1;
      observerSnapshots.push(readPasswordDomState(username, password));
      if (observerCount === 1) {
        username.value = 'observer-sync-user';
        password.value = 'observer-sync-password';
        username.defaultValue = 'observer-sync-default';
        password.defaultValue = 'observer-sync-default';
        // The defaultValue setter above queues the self-generated delivery;
        // serialized value-attribute writes coalesce into that same delivery.
        username.setAttribute('value', 'observer-sync-attr');
        password.setAttribute('value', 'observer-sync-attr');
        restorationSnapshots.push(readPasswordDomState(username, password));
        return;
      }
      if (observerCount !== 2) return;
      lateTaskQueued = true;
      // This task is queued by the observer delivery caused by the second
      // bounded clear, after the component's staging timer already exists.
      setTimeout(() => {
        lateTaskRan = true;
        username.value = 'late';
        password.value = 'late';
        username.defaultValue = 'late-default';
        password.defaultValue = 'late-default';
        username.setAttribute('value', 'late-attr');
        password.setAttribute('value', 'late-attr');
        hostileTaskSnapshots.push(readPasswordDomState(username, password));
      }, 0);
    });
    observer.observe(form, { attributes: true, subtree: true, attributeFilter: ['value'] });
    const unrelatedTarget = document.createElement('input');
    notifyMutation(unrelatedTarget, 'value');
    notifyMutation(username, 'class');
    expect(observerCount).toBe(0);

    const queuedTimers: Array<() => void> = [];
    const setTimeoutSpy = vi.spyOn(globalThis, 'setTimeout').mockImplementation(((handler: TimerHandler) => {
      if (typeof handler === 'function') queuedTimers.push(handler as () => void);
      return 1 as unknown as ReturnType<typeof setTimeout>;
    }) as unknown as typeof setTimeout);
    try {
      // Hydration readiness above has already released focusEnteredState's
      // fallback timer. The captured queue therefore starts empty and contains
      // only the bounded scrub/hostile callbacks created by this submission.
      expect(queuedTimers).toHaveLength(0);
      fireEvent.submit(form);

      expect(onPasswordSubmit).toHaveBeenCalledTimes(1);
      expect(transientSubmissionMatches).toBe(true);
      onPasswordSubmit.mockClear();
      expect(callbackDom).toEqual(EMPTY_PASSWORD_DOM_STATE);
      expect(resetObservation).toEqual([EMPTY_PASSWORD_DOM_STATE]);

      // The first bounded observer delivery restores the representations so
      // the first and second clears produce separate later deliveries.
      await Promise.resolve();
      expect(observerSnapshots[0]).toEqual(EMPTY_PASSWORD_DOM_STATE);
      await Promise.resolve();
      await Promise.resolve();
      expect(restorationSnapshots).toEqual([['observer-sync-user', 'observer-sync-password', 'observer-sync-attr', 'observer-sync-attr', 'observer-sync-attr', 'observer-sync-attr']]);
      expect(observerSnapshots[1]).toEqual(EMPTY_PASSWORD_DOM_STATE);
      expect(lateTaskQueued).toBe(true);

      const hostileState: PasswordDomState = ['late', 'late', 'late-attr', 'late-attr', 'late-attr', 'late-attr'];
      expect(queuedTimers).toHaveLength(2);

      // The first captured callback is the hostile observer task. It runs
      // before the component's staging fence because the observer delivery
      // queued it during the second bounded clear.
      const hostileTask = queuedTimers.shift()!;
      hostileTask();
      expect(lateTaskRan).toBe(true);
      expect(hostileTaskSnapshots).toEqual([hostileState]);
      expect(readPasswordDomState(username, password)).toEqual(hostileState);
      expect(queuedTimers).toHaveLength(1);

      // The hostile writes queue one finite self-generated observer delivery;
      // flush that delivery before stepping the component's staging fence.
      await Promise.resolve();
      await Promise.resolve();
      expect(observerSnapshots.at(-1)).toEqual(hostileState);

      // The staging fence only queues the final bounded task and does not
      // clear or restore the fields itself.
      const stagingTask = queuedTimers.shift()!;
      stagingTask();
      expect(readPasswordDomState(username, password)).toEqual(hostileState);
      expect(queuedTimers).toHaveLength(1);

      // The final bounded task is the only phase that restores live, default,
      // and serialized value representations.
      const finalTask = queuedTimers.shift()!;
      finalTask();
      expect(readPasswordDomState(username, password)).toEqual(EMPTY_PASSWORD_DOM_STATE);
      expect(queuedTimers).toHaveLength(0);
      expect(observerCount).toBeGreaterThanOrEqual(3);
      expect(observerCount).toBeLessThanOrEqual(5);
      expect(JSON.stringify(callbackDom)).not.toContain('hostile-password');

      // A queued observer delivery from the old observer epoch must not run
      // after disconnect. Capture the notifier before disconnecting so this
      // explicitly exercises the fake's epoch guard.
      const observerCountBeforeDisconnect = observerCount;
      notifyMutation();
      observer.disconnect();
      await Promise.resolve();
      expect(observerCount).toBe(observerCountBeforeDisconnect);
    } finally {
      observer.disconnect();
      for (const input of [username, password]) Reflect.deleteProperty(input, 'defaultValue');
      removeAttributeSpies.forEach((spy) => spy.mockRestore());
      setAttributeSpies.forEach((spy) => spy.mockRestore());
      setTimeoutSpy.mockRestore();
      vi.unstubAllGlobals();
      vi.useRealTimers();
    }
  });

  it('scrubs retained input references synchronously during unmount', async () => {
    const view = render(AuthPreview, { discoveryMode: 'live', state: 'password' });
    await waitFor(() => expect(screen.getByRole('form', { name: 'Hermes password sign in' })).toHaveAttribute('data-field-ownership', 'ready'));
    const username = screen.getByLabelText('Username') as HTMLInputElement;
    const password = screen.getByLabelText('Password') as HTMLInputElement;
    username.value = 'unmount-user';
    password.value = 'unmount-password';
    username.defaultValue = 'unmount-default-user';
    password.defaultValue = 'unmount-default-password';

    view.unmount();

    expect(username.value).toBe('');
    expect(password.value).toBe('');
    expect(username.defaultValue).toBe('');
    expect(password.defaultValue).toBe('');
    expect(username.getAttribute('value')).toBeNull();
    expect(password.getAttribute('value')).toBeNull();
  });

  it('does not let a delayed scrub from a replaced attempt clear a new password entry', async () => {
    const onPasswordSubmit = vi.fn();
    const view = render(AuthPreview, { discoveryMode: 'live', state: 'password', onPasswordSubmit });
    await waitFor(() => expect(screen.getByRole('form', { name: 'Hermes password sign in' })).toHaveAttribute('data-field-ownership', 'ready'));

    const delayedTimers: Array<() => void> = [];
    const setTimeoutSpy = vi.spyOn(globalThis, 'setTimeout').mockImplementation(((handler: TimerHandler) => {
      if (typeof handler === 'function') delayedTimers.push(handler as () => void);
      return 1 as unknown as ReturnType<typeof setTimeout>;
    }) as unknown as typeof setTimeout);
    let staleFinalTimer!: () => void;
    try {
      const form = screen.getByRole('form', { name: 'Hermes password sign in' });
      fireEvent.input(screen.getByLabelText('Username'), { target: { value: 'old-user' } });
      fireEvent.input(screen.getByLabelText('Password'), { target: { value: 'old-password' } });
      fireEvent.submit(form);
      await Promise.resolve();
      await Promise.resolve();
      expect(delayedTimers).toHaveLength(1);

      // Run the known staging callback so the final callback is captured before
      // the old owner is invalidated. Do not invoke a generic timer collection.
      const staleStagingTimer = delayedTimers.shift()!;
      staleStagingTimer();
      expect(delayedTimers).toHaveLength(1);
      staleFinalTimer = delayedTimers.shift()!;
    } finally {
      setTimeoutSpy.mockRestore();
    }

    await view.rerender({ state: 'provider-selection' });
    await view.rerender({ state: 'password' });
    await waitFor(() => expect(screen.getByRole('form', { name: 'Hermes password sign in' })).toHaveAttribute('data-field-ownership', 'ready'));
    const username = screen.getByLabelText('Username') as HTMLInputElement;
    const password = screen.getByLabelText('Password') as HTMLInputElement;
    username.value = 'new-user';
    password.value = 'new-password';
    username.defaultValue = 'new-default-user';
    password.defaultValue = 'new-default-password';
    username.setAttribute('value', 'new-attr-user');
    password.setAttribute('value', 'new-attr-password');

    // The old epoch's final task is invoked after the new owner is ready.
    staleFinalTimer();
    expect(readPasswordDomState(username, password)).toEqual([
      'new-user',
      'new-password',
      'new-attr-user',
      'new-attr-password',
      'new-attr-user',
      'new-attr-password'
    ]);
  });

  it('invalidates queued scrub microtasks before a new password entry', async () => {
    const onAction = vi.fn();
    let transientSubmissionMatches = false;
    const onPasswordSubmit = vi.fn((credentials: { username: string; password: string }) => {
      transientSubmissionMatches = credentials.username === 'queued-old-user' && credentials.password === 'queued-old-password';
    });
    const queuedMicrotasks: Array<() => void> = [];
    const nativeQueueMicrotask = globalThis.queueMicrotask;
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    vi.stubGlobal('requestAnimationFrame', undefined);
    vi.stubGlobal('queueMicrotask', (callback: VoidFunction) => {
      queuedMicrotasks.push(callback);
    });

    try {
      const view = render(AuthPreview, { discoveryMode: 'live', state: 'password', onAction, onPasswordSubmit });
      // Preserve the initial focus fallback sequence explicitly. The first timer
      // belongs to focus ownership, not the scrub scheduler under test.
      await tick();
      await Promise.resolve();
      expect(vi.getTimerCount()).toBe(1);
      await vi.advanceTimersToNextTimerAsync();
      await Promise.resolve();
      await Promise.resolve();
      expect(vi.getTimerCount()).toBe(0);
      // Svelte may leave scheduler jobs in the shared queue during hydration;
      // the focus fallback above is the only pre-submit work this regression
      // needs to preserve, so isolate the scrub queue from those jobs.
      queuedMicrotasks.length = 0;

      const form = screen.getByRole('form', { name: 'Hermes password sign in' });
      const username = screen.getByLabelText('Username') as HTMLInputElement;
      const password = screen.getByLabelText('Password') as HTMLInputElement;
      fireEvent.input(username, { target: { value: 'queued-old-user' } });
      fireEvent.input(password, { target: { value: 'queued-old-password' } });
      fireEvent.submit(form);

      expect(onPasswordSubmit).toHaveBeenCalledTimes(1);
      expect(transientSubmissionMatches).toBe(true);
      onPasswordSubmit.mockClear();
      // A real live callback queues owned scrub work. Hold every callback
      // produced by this submit, then invalidate its generation before any of
      // that stale work is released.
      expect(queuedMicrotasks.length).toBeGreaterThan(0);
      const staleQueuedMicrotasks = queuedMicrotasks.splice(0);
      // Keep only the submit callbacks under manual control. Svelte's own
      // rerender scheduler must use the native queue while the new owner is
      // established; the stale callbacks remain deferred in our array.
      vi.stubGlobal('queueMicrotask', nativeQueueMicrotask);
      fireEvent.click(screen.getByRole('button', { name: 'Back to providers' }));
      expect(onAction).toHaveBeenCalledWith({ type: 'back-to-providers' });

      await view.rerender({ state: 'provider-selection' });
      await view.rerender({ state: 'password' });
      await tick();
      await Promise.resolve();
      // The provider handoff and the new password entry each retain their
      // fallback focus timer. Flush both state-transition timers before the
      // retry owner is populated.
      expect(vi.getTimerCount()).toBeGreaterThan(0);
      for (let timerPass = 0; timerPass < 4 && vi.getTimerCount() > 0; timerPass += 1) {
        await vi.advanceTimersToNextTimerAsync();
      }
      await Promise.resolve();
      await Promise.resolve();
      expect(vi.getTimerCount()).toBe(0);

      const retryUsername = screen.getByLabelText('Username') as HTMLInputElement;
      const retryPassword = screen.getByLabelText('Password') as HTMLInputElement;
      expect(screen.getByRole('form', { name: 'Hermes password sign in' })).toHaveAttribute('data-field-ownership', 'ready');
      retryUsername.value = 'queued-new-user';
      retryPassword.value = 'queued-new-password';
      retryUsername.defaultValue = 'queued-new-default-user';
      retryPassword.defaultValue = 'queued-new-default-password';
      // Setting defaultValue also serializes the value attribute. Assert that
      // coupled phase before deliberately overwriting the serialized form.
      expect(readPasswordDomState(retryUsername, retryPassword)).toEqual([
        'queued-new-user',
        'queued-new-password',
        'queued-new-default-user',
        'queued-new-default-password',
        'queued-new-default-user',
        'queued-new-default-password'
      ]);
      retryUsername.setAttribute('value', 'queued-new-attr-user');
      retryPassword.setAttribute('value', 'queued-new-attr-password');

      for (const staleMicrotask of staleQueuedMicrotasks) staleMicrotask();
      // The stale owner must not clear the new live values or its final
      // serialized/default representation. DOM semantics couple defaultValue
      // to the value attribute, so the final phase is asserted as that pair.
      expect(readPasswordDomState(retryUsername, retryPassword)).toEqual([
        'queued-new-user',
        'queued-new-password',
        'queued-new-attr-user',
        'queued-new-attr-password',
        'queued-new-attr-user',
        'queued-new-attr-password'
      ]);
      view.unmount();
    } finally {
      vi.unstubAllGlobals();
      vi.useRealTimers();
    }
  });

  it('ignores a stale focus callback after the focus epoch changes', async () => {
    const pendingFrames: Array<(timestamp: number) => void> = [];
    vi.stubGlobal('requestAnimationFrame', (callback: (timestamp: number) => void) => {
      pendingFrames.push(callback);
      return pendingFrames.length;
    });
    try {
      const view = render(AuthPreview, { discoveryMode: 'live', state: 'password' });
      await waitFor(() => expect(pendingFrames).toHaveLength(1));

      await view.rerender({ state: 'provider-selection' });
      await waitFor(() => expect(pendingFrames).toHaveLength(2));

      const stalePasswordFrame = pendingFrames.shift()!;
      const providerFrame = pendingFrames.shift()!;
      providerFrame(0);
      await Promise.resolve();
      await view.rerender({ state: 'password' });
      await waitFor(() => expect(pendingFrames).toHaveLength(1));
      stalePasswordFrame(0);
      await Promise.resolve();
      expect(screen.getByRole('form', { name: 'Hermes password sign in' })).toHaveAttribute('data-field-ownership', 'pending');
      pendingFrames.shift()!(0);
      await waitFor(() => expect(screen.getByRole('form', { name: 'Hermes password sign in' })).toHaveAttribute('data-field-ownership', 'ready'));
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('does not let a delayed cancel scrub clear a new password owner', async () => {
    const onAction = vi.fn();
    const view = render(AuthPreview, { state: 'password-submitting', onAction });
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Signing in to Hermes' })).toHaveFocus());

    const delayedTimers: Array<() => void> = [];
    const setTimeoutSpy = vi.spyOn(globalThis, 'setTimeout').mockImplementation(((handler: TimerHandler) => {
      if (typeof handler === 'function') delayedTimers.push(handler as () => void);
      return 1 as unknown as ReturnType<typeof setTimeout>;
    }) as unknown as typeof setTimeout);
    let staleFinalTimer!: () => void;
    try {
      fireEvent.click(screen.getByRole('button', { name: 'Cancel sign-in' }));
      await Promise.resolve();
      await Promise.resolve();
      expect(delayedTimers).toHaveLength(1);
      const staleStagingTimer = delayedTimers.shift()!;
      staleStagingTimer();
      expect(delayedTimers).toHaveLength(1);
      staleFinalTimer = delayedTimers.shift()!;
    } finally {
      setTimeoutSpy.mockRestore();
    }

    await view.rerender({ state: 'password' });
    await waitFor(() => expect(screen.getByRole('form', { name: 'Hermes password sign in' })).toHaveAttribute('data-field-ownership', 'ready'));
    const username = screen.getByLabelText('Username') as HTMLInputElement;
    const password = screen.getByLabelText('Password') as HTMLInputElement;
    username.value = 'new-owner';
    password.value = 'new-owner-password';
    username.defaultValue = 'new-owner-default';
    password.defaultValue = 'new-owner-password-default';
    username.setAttribute('value', 'new-owner-attr');
    password.setAttribute('value', 'new-owner-password-attr');

    staleFinalTimer();
    expect(readPasswordDomState(username, password)).toEqual([
      'new-owner',
      'new-owner-password',
      'new-owner-attr',
      'new-owner-password-attr',
      'new-owner-attr',
      'new-owner-password-attr'
    ]);
  });

  it('uses fail-closed native semantics while hydrated Enter submits through the local handler', async () => {
    const onAction = vi.fn();
    render(AuthPreview, { state: 'password', onAction });

    const form = screen.getByRole('form', { name: 'Hermes password sign in' });
    const username = screen.getByLabelText('Username');
    const password = screen.getByLabelText('Password');
    const signIn = screen.getByRole('button', { name: 'Sign in' });
    expect(form).toHaveAttribute('method', 'dialog');
    expect(signIn).toHaveAttribute('type', 'reset');

    await waitFor(() => expect(form).toHaveAttribute('data-field-ownership', 'ready'));
    fireEvent.input(username, { target: { value: 'keyboard-user' } });
    fireEvent.input(password, { target: { value: 'keyboard-password' } });
    fireEvent.keyDown(password, { key: 'Enter' });

    expect(onAction).toHaveBeenCalledWith({ type: 'submit-password-fixture' });
    expect(username).toHaveValue('');
    expect(password).toHaveValue('');
  });

  it('intercepts Enter on a live named field and clears both values after the transient callback', async () => {
    const onPasswordSubmit = vi.fn();
    render(AuthPreview, {
      discoveryMode: 'live',
      state: 'password',
      onPasswordSubmit
    });

    const form = screen.getByRole('form', { name: 'Hermes password sign in' });
    const username = screen.getByLabelText('Username');
    const password = screen.getByLabelText('Password');
    await waitFor(() => expect(form).toHaveAttribute('data-field-ownership', 'ready'));
    expect(username).toHaveAttribute('name', 'username');
    expect(password).toHaveAttribute('name', 'password');

    fireEvent.input(username, { target: { value: 'live-user' } });
    fireEvent.input(password, { target: { value: 'live-password' } });
    fireEvent.keyDown(password, { key: 'Enter' });

    expect(onPasswordSubmit).toHaveBeenCalledTimes(1);
    const transientSubmissionMatches = onPasswordSubmit.mock.calls.some(([credentials]) => {
      const value = credentials as { username?: string; password?: string } | undefined;
      return value?.username === 'live-user' && value.password === 'live-password';
    });
    expect(transientSubmissionMatches).toBe(true);
    onPasswordSubmit.mockClear();
    expect(username).toHaveValue('');
    expect(password).toHaveValue('');
  });

  it('passes live credentials only to the transient password callback and clears the form', async () => {
    const onAction = vi.fn();
    const onPasswordSubmit = vi.fn();
    render(AuthPreview, {
      discoveryMode: 'live',
      state: 'password',
      onAction,
      onPasswordSubmit
    });
    await waitFor(() => expect(screen.getByRole('form', { name: 'Hermes password sign in' })).toHaveAttribute('data-field-ownership', 'ready'));

    fireEvent.input(screen.getByLabelText('Username'), {
      target: { value: 'synthetic-user' }
    });
    fireEvent.input(screen.getByLabelText('Password'), {
      target: { value: 'transient-password' }
    });
    fireEvent.submit(screen.getByRole('form', { name: 'Hermes password sign in' }));

    expect(onPasswordSubmit).toHaveBeenCalledTimes(1);
    const transientSubmissionMatches = onPasswordSubmit.mock.calls.some(([credentials]) => {
      const value = credentials as { username?: string; password?: string } | undefined;
      return value?.username === 'synthetic-user' && value.password === 'transient-password';
    });
    expect(transientSubmissionMatches).toBe(true);
    onPasswordSubmit.mockClear();
    expect(onAction).not.toHaveBeenCalledWith({
      type: 'submit-password-fixture'
    });
    expect(onAction).toHaveBeenCalledTimes(0);
    await waitFor(() => {
      expect(screen.getByLabelText('Username')).toHaveValue('');
      expect(screen.getByLabelText('Password')).toHaveValue('');
    });
  });

  it('rejects blank credentials and clears the uncontrolled form on cancel and state changes', async () => {
    const onAction = vi.fn();
    const view = render(AuthPreview, { state: 'password', onAction });
    const form = screen.getByRole('form', { name: 'Hermes password sign in' });

    fireEvent.submit(form);
    expect(onAction).not.toHaveBeenCalled();

    fireEvent.input(screen.getByLabelText('Password'), {
      target: { value: 'temporary-fixture' }
    });
    fireEvent.click(screen.getByRole('button', { name: 'Back to providers' }));
    await waitFor(() => expect(screen.getByLabelText('Password')).toHaveValue(''));

    await view.rerender({ state: 'password' });
    fireEvent.input(screen.getByLabelText('Password'), {
      target: { value: 'state-change-fixture' }
    });
    await view.rerender({ state: 'provider-selection' });
    await view.rerender({ state: 'password' });

    await waitFor(() => expect(screen.getByLabelText('Password')).toHaveValue(''));
    expect(onAction).toHaveBeenCalledWith({ type: 'back-to-providers' });
    expect(onAction.mock.calls.every(([action]) => typeof action?.type === 'string')).toBe(true);
  });

  it('moves focus to each entered task and exposes state-specific live semantics', async () => {
    const view = render(AuthPreview, { state: 'provider-selection' });

    await view.rerender({ state: 'password' });
    await waitFor(() => expect(screen.getByLabelText('Username')).toHaveFocus());

    await view.rerender({ state: 'password-submitting' });
    const submitting = screen.getByRole('status');
    expect(submitting).toHaveAttribute('aria-live', 'polite');
    expect(submitting).toHaveAttribute('aria-atomic', 'true');
    expect(submitting).toHaveTextContent('Signing in');
    expect(screen.getByRole('form', { name: 'Hermes password sign in' })).toHaveAttribute('aria-busy', 'true');
    expect(screen.getByLabelText('Username')).toHaveAttribute('placeholder', 'Cleared');
    expect(screen.getByLabelText('Password')).toHaveAttribute('placeholder', 'Cleared');
    expect(screen.getByText('Hidden')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Signing in to Hermes' })).toHaveFocus());

    await view.rerender({ state: 'failure' });
    const failure = screen.getByRole('alert');
    expect(failure).toHaveAttribute('aria-live', 'assertive');
    expect(failure).toHaveTextContent('Sign-in did not complete');
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Sign-in did not complete' })).toHaveFocus());

    await view.rerender({ state: 'session-expired' });
    expect(screen.getByRole('alert')).toHaveTextContent('Session expired');
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Session expired' })).toHaveFocus());

    await view.rerender({ state: 'discovery-pending' });
    expect(screen.getByRole('status')).toHaveTextContent('Discovering sign-in methods');
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Discovering sign-in methods' })).toHaveFocus());

    for (const [state, heading, announcement] of [
      ['discovery-empty', 'No sign-in methods available', 'invalid empty registry'],
      ['discovery-malformed', 'Provider discovery returned incompatible data', 'incompatible data'],
      ['discovery-aborted', 'Provider discovery was cancelled', 'was cancelled'],
      ['provider-unavailable', 'Provider discovery stopped', 'No sign-in method is available']
    ] as const) {
      await view.rerender({ state });
      expect(screen.getByRole('alert')).toHaveTextContent(announcement);
      await waitFor(() => expect(screen.getByRole('heading', { name: heading })).toHaveFocus());
    }

    await view.rerender({ state: 'discovery-retry' });
    expect(screen.getByRole('status')).toHaveTextContent('Provider discovery can be retried');
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Retry provider discovery' })).toHaveFocus());
  });

  it('disables provider controls during discovery and exposes retryable failure actions', () => {
    const pending = render(AuthPreview, { state: 'discovery-pending' });
    expect(screen.getByRole('button', { name: 'Nous, loading' })).toBeDisabled();
    pending.unmount();

    const onAction = vi.fn();
    render(AuthPreview, { state: 'failure', onAction });
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));

    expect(onAction).toHaveBeenCalledWith({ type: 'retry-authentication' });
  });

  it('renders logout pending without exposing retry or cancellation actions', async () => {
    const onAction = vi.fn();
    render(AuthPreview, { state: 'logout-pending', discoveryMode: 'live', onAction });

    expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'logout-pending');
    expect(screen.getByRole('heading', { name: 'Signing out' })).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent('Signing out');
    expect(screen.queryByRole('button', { name: /retry discovery/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /cancel/i })).not.toBeInTheDocument();
    expect(onAction).not.toHaveBeenCalled();
  });

  it('renders logout recovery with only retry sign out', () => {
    const onAction = vi.fn();
    render(AuthPreview, {
      state: 'logout-failed',
      discoveryMode: 'live',
      failureCode: 'logout-unverified',
      failureMessage: 'Logout could not be verified.',
      onAction
    });

    expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'logout-failed');
    expect(screen.getByRole('heading', { name: 'Sign-out could not be verified' })).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('Only Retry sign out is available');
    expect(screen.getByRole('button', { name: 'Retry sign out' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Try again' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Choose provider' })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Retry sign out' }));
    expect(onAction).toHaveBeenCalledWith({ type: 'retry-logout' });
  });

  it('renders live success, pending, empty, malformed, unavailable, aborted, and retry states truthfully', () => {
    const liveProviders = [
      {
        id: 'codex',
        name: 'Codex',
        monogram: 'C',
        kind: 'oauth' as const,
        description: 'OAuth provider · same-origin browser boundary'
      }
    ];
    const live = render(AuthPreview, {
      discoveryMode: 'live',
      providers: liveProviders,
      state: 'provider-selection'
    });
    expect(screen.getByText(/live same-origin discovery/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Codex' })).toBeInTheDocument();
    live.unmount();

    const pendingAction = vi.fn();
    const pending = render(AuthPreview, {
      discoveryMode: 'live',
      state: 'discovery-pending',
      onAction: pendingAction
    });
    expect(screen.getByText(/same-origin GET \/api\/auth\/providers request is pending/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Nous, loading' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel discovery' }));
    expect(pendingAction).toHaveBeenCalledWith({ type: 'cancel-discovery' });
    pending.unmount();

    const states = [
      ['discovery-empty', 'No sign-in methods available'],
      ['discovery-malformed', 'Provider discovery returned incompatible data'],
      ['provider-unavailable', 'Provider discovery stopped'],
      ['discovery-aborted', 'Provider discovery was cancelled'],
      ['discovery-retry', 'Retry provider discovery']
    ] as const;

    for (const [state, heading] of states) {
      const view = render(AuthPreview, { discoveryMode: 'live', state });
      expect(screen.getByRole('heading', { name: heading })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Retry discovery' })).toBeInTheDocument();
      view.unmount();
    }
  });
});
