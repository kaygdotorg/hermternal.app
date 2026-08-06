import type { AuthProvider } from './types';

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
    description: 'OAuth · opens the provider'
  },
  {
    id: 'hermes-password',
    name: 'Hermes password',
    monogram: 'H',
    kind: 'password',
    description: 'Username and password supported'
  }
];
