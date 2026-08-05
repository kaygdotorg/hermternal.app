# State models

This directory will define language-neutral, observable state transitions for the future `v0.0.1` milestone. Each platform will implement the behavior with native state and lifecycle tools.

## Required states

Models must cover browser and native authentication, connection, revision compatibility, session restoration, prompt submission, streaming, interruption, approvals, clarification, model selection, error recovery, private deep links under `/v1/c/...`, and the web-only `/api/pty` Terminal.

The active model rule is explicit: an idle change applies now; a normal streaming choice may defer without altering the current stream; a deferred expensive choice may be dropped and require confirmation plus resubmission after the turn. Approval and clarification remain separate states. Images are the only attachment type. There is one profile and no transcript mirror.

Missing or mismatched deployment attestation, or a failed behavioral probe, enters a blocked state and cannot start live operation. The pinned revision is `f5be9236e00ddf2f2a412697f267078fc4ee068e`.

Reconnect must restore the session before any prompt retry. A client must not blindly retry a prompt when delivery is uncertain. No state model adds terminal-read, sudo, or secret operations. Sharing is deferred to `v0.0.2`.

These specifications describe behavior only. No runtime state-management code exists here yet. See the [Dashboard contract](../hermes-dashboard/README.md) and [fixture coverage](../fixtures/README.md).
