import { SERVICE_WORKER_SCRIPT_PATH } from './service-worker-policy';

type ServiceWorkerContainerLike = Pick<ServiceWorkerContainer, 'register'> &
  Partial<Pick<ServiceWorkerContainer, 'addEventListener' | 'removeEventListener'>> & {
    readonly controller?: ServiceWorker | null;
  };

function browserServiceWorkerContainer(): ServiceWorkerContainerLike | undefined {
  try {
    if (typeof navigator === 'undefined' || !('serviceWorker' in navigator)) {
      return undefined;
    }
    return navigator.serviceWorker;
  } catch {
    return undefined;
  }
}

/**
 * Register the worker from the normal client lifecycle without making it part
 * of rendering or transport state. Unsupported browsers and rejected
 * registrations are intentionally silent: the shell remains usable without a
 * worker, and no URL or browser error is copied into UI or logs.
 */
export function registerServiceWorker(
  container: ServiceWorkerContainerLike | undefined = browserServiceWorkerContainer()
): () => void {
  let disposed = false;
  let tornDown = false;
  let reloaded = false;
  const hadController = Boolean(container?.controller);

  if (!container) {
    return () => {
      disposed = true;
    };
  }

  const onControllerChange = () => {
    // A first controller assignment belongs to the initial page lifecycle. Only
    // an already-controlled page may reload, and a controller removal must not
    // turn an update hint into a blank or looping navigation.
    if (!hadController || !container.controller || disposed || reloaded) {
      return;
    }

    reloaded = true;
    try {
      globalThis.location?.reload();
    } catch {
      // A reload is an optional update hint, never a reason to fail the shell.
    }
  };

  try {
    container.addEventListener?.('controllerchange', onControllerChange);
  } catch {
    // Event support is optional; registration remains the useful boundary.
  }

  try {
    const registration = container.register(SERVICE_WORKER_SCRIPT_PATH, { scope: '/' });
    void registration.then(
      () => {
        if (disposed) return;
      },
      () => {
        if (disposed) return;
        // Fail closed. Do not log the rejection or expose its URL/error text.
      }
    );
  } catch {
    // Unsupported, insecure, or unavailable workers do not block app startup.
  }

  return () => {
    if (tornDown) {
      return;
    }
    tornDown = true;
    disposed = true;
    try {
      container.removeEventListener?.('controllerchange', onControllerChange);
    } catch {
      // Teardown is best-effort and must remain safe during unmount.
    }
  };
}
