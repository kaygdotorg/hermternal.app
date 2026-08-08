'use strict';

// Playwright forks workers with an IPC channel. Preload this guard with
// NODE_OPTIONS so process.send is protected before Playwright loads fixtures or
// executes a test body. The guard never changes Object.prototype,
// Array.prototype, or TestInfo.errors; it only forwards detached policy output.
if (typeof process.send === 'function') {
  const originalSend = process.send.bind(process);
  const policy = require('./live-artifact-policy.mjs');
  const safeSend = (message, ...rest) => {
    try {
      const safeMessage = policy.redactLiveTransportMessage(message);
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
