export type MockScenario = 'empty' | 'failure' | 'success';

export type MockWorkspaceState =
  | {
      status: 'empty';
      fixtureId: string;
    }
  | {
      status: 'success';
      fixtureId: string;
      workspaceLabel: string;
      detail: string;
    };

export type MockCancellationReason = 'user' | 'retry' | 'unmount';

export interface MockPendingState {
  status: 'pending';
  fixtureId: string;
}

export interface MockCancelledState {
  status: 'cancelled';
  fixtureId: string;
  reason: MockCancellationReason;
}

export interface MockFailureState {
  status: 'failure';
  fixtureId: string;
  message: string;
}

export type MockShellState =
  | MockWorkspaceState
  | MockPendingState
  | MockCancelledState
  | MockFailureState;

export interface MockTransportOptions {
  delayMs?: number;
  scenario?: MockScenario;
}

/**
 * This is the only transport contract exposed to the prototype shell. A live
 * implementation is deliberately absent until the security, compatibility,
 * contract, and Paper gates are approved.
 */
export interface MockTransport {
  getWorkspace(signal?: AbortSignal): Promise<MockWorkspaceState>;
}
