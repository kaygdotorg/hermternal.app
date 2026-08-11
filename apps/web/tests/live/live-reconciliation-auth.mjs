/**
 * Run one reconciliation operation with ownership-safe cleanup. The operation
 * must call markLoginRequest immediately before a request that could set the
 * session cookie. Cleanup is deliberately split into independent attempts so a
 * failed logout cannot prevent scoped cookie and browser-state cleanup.
 *
 * The result is a fixed control projection only; callback errors and response
 * bodies never leave this boundary.
 *
 * @param {{
 *   operation: (markLoginRequest: () => void) => Promise<void>,
 *   logout: () => Promise<void>,
 *   clearCookies: () => Promise<void>,
 *   clearBrowserState: () => Promise<void>
 * }} input
 */
export async function runLiveReconciliationAttempt({
  operation,
  logout,
  clearCookies,
  clearBrowserState
}) {
  if (
    typeof operation !== 'function' ||
    typeof logout !== 'function' ||
    typeof clearCookies !== 'function' ||
    typeof clearBrowserState !== 'function'
  ) {
    throw new Error('live reconciliation cleanup callbacks are not approved');
  }

  let loginRequestMayHaveIssuedSession = false;
  let operationFailed = false;
  const markLoginRequest = () => {
    loginRequestMayHaveIssuedSession = true;
  };

  try {
    await operation(markLoginRequest);
  } catch {
    operationFailed = true;
  }

  let cleanupFailed = false;
  let logoutAttempted = false;
  if (loginRequestMayHaveIssuedSession) {
    logoutAttempted = true;
    try {
      await logout();
    } catch {
      cleanupFailed = true;
    }
  }

  try {
    await clearCookies();
  } catch {
    cleanupFailed = true;
  }

  try {
    await clearBrowserState();
  } catch {
    cleanupFailed = true;
  }

  return Object.freeze({
    operationFailed,
    cleanupFailed,
    loginRequestMayHaveIssuedSession,
    logoutAttempted,
    cookiesCleanupAttempted: true,
    browserStateCleanupAttempted: true
  });
}
