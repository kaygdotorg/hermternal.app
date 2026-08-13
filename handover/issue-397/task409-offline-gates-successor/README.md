# Offline post-replay gate successor

This speculative runner accepts only the closed final #403 provenance and a
complete #404/#405 Phase B result. It binds the isolated repository, replay
head and tree, unchanged protected main commit, and the required dev target.

The command set is closed and offline. It includes Git integrity, web checks,
unit tests, static build, privacy redaction, accessibility, no-network browser,
and authentication click plus Enter checks. A source hook also requires DOM
clearing, accessibility evidence, and screenshot redaction evidence.

Each command runs with a fixed environment that contains no credentials. The
report records exact argv, exit code, and SHA-256 values for stdout and stderr.
Any failure, unavailable command, skipped gate, incomplete hook, excessive
output, network indicator, main change, or dev-target difference rejects the
whole result. No partial summary can claim PASS.

The tests replace only the process boundary. They do not replace the strict
provenance, interlock, repository, or authentication-source validators.

This checkpoint does not run replay, live Hermes, network calls, or deployment.
