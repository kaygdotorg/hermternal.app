import type { AuthProvider, AuthProviderKind } from './types';

function isProviderKind(value: unknown): value is AuthProviderKind {
  return value === 'oauth' || value === 'password';
}

/**
 * Treat deployment-shaped provider data as untrusted even in this local
 * preview. A partial, duplicated, empty, or future schema must not expose a
 * sign-in action until the presentation contract understands it.
 */
export function validateAuthProviders(value: unknown): AuthProvider[] | null {
  if (!Array.isArray(value) || value.length === 0) return null;

  const seenIds = new Set<string>();
  const providers: AuthProvider[] = [];
  for (const candidate of value) {
    if (!candidate || typeof candidate !== 'object') return null;
    const provider = candidate as Record<string, unknown>;
    const normalizedId = typeof provider.id === 'string' ? provider.id.trim() : '';
    if (
      normalizedId === '' ||
      seenIds.has(normalizedId) ||
      typeof provider.name !== 'string' ||
      provider.name.trim() === '' ||
      typeof provider.monogram !== 'string' ||
      provider.monogram.trim() === '' ||
      typeof provider.description !== 'string' ||
      provider.description.trim() === '' ||
      !isProviderKind(provider.kind)
    ) {
      return null;
    }
    seenIds.add(normalizedId);
    providers.push(provider as unknown as AuthProvider);
  }

  return providers;
}

/**
 * Provider cards are synthetic presentation fixtures. They document the
 * deployment-reported shape without discovering providers or storing input.
 */
export const DEFAULT_PROVIDERS: AuthProvider[] = [
  {
    id: 'nous',
    name: 'Nous',
    monogram: 'N',
    kind: 'oauth',
    description: 'OAuth · local fixture only'
  },
  {
    id: 'hermes-password',
    name: 'Hermes password',
    monogram: 'H',
    kind: 'password',
    description: 'Username and password supported'
  }
];
