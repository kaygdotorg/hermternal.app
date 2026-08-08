import { liveArtifactOutputDirectory, removeLiveArtifacts } from './live-artifact-policy.mjs';

export default async function teardown() {
  await removeLiveArtifacts(process.env.PLAYWRIGHT_LIVE_OUTPUT_DIR ?? liveArtifactOutputDirectory());
}
