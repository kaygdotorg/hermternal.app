'use strict';

// Playwright forks workers with an IPC channel. Preload this guard with
// NODE_OPTIONS so process.send is protected before Playwright loads fixtures or
// executes a test body. The guard never changes Object.prototype,
// Array.prototype, or TestInfo.errors; it only forwards detached policy output.
if (typeof process.send === 'function') {
  const originalSend = process.send.bind(process);
  const policy = require('./live-artifact-policy.mjs');
  // Capture every credential variant before Playwright loads the worker or a
  // test can delete/replace its environment. The frozen array is passed on
  // every send; worker code cannot clear the guard's closed-over values.
  const capturedLiveSecrets = Object.freeze([...policy.liveCredentialValues()]);
  const safeSend = (message, ...rest) => {
    try {
      const safeMessage = policy.redactLiveTransportMessage(message, capturedLiveSecrets);
      return originalSend(safeMessage, ...rest);
    } catch {
      // Playwright falls back to JSON.stringify(message) when process.send
      // throws. Returning without forwarding is the fail-closed outcome.
      return undefined;
    }
  };

  const descriptor = Object.getOwnPropertyDescriptor(process, 'send');
  try {
    Object.defineProperty(process, 'send', {
      configurable: false,
      enumerable: descriptor?.enumerable ?? false,
      value: safeSend,
      writable: false
    });
  } catch {
    throw new Error('live IPC guard could not pin process.send');
  }
  if (process.send !== safeSend) throw new Error('live IPC guard was not installed');
}
