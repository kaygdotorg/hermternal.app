export const MOCK_FIXTURE_IDS = Object.freeze({
  empty: 'w01-empty-v1',
  failure: 'w01-failure-v1',
  success: 'w01-success-v1'
});

export const SUCCESS_FIXTURE = Object.freeze({
  fixtureId: MOCK_FIXTURE_IDS.success,
  workspaceLabel: 'Synthetic workspace',
  detail: 'No provider, account, credential, or live session state is loaded.'
});
