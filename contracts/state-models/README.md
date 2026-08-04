# State models

This directory will define language-neutral state transitions for authentication, connection, session restoration, prompt submission, streaming, interruption, approvals, clarification, errors, and recovery.

The specifications describe observable behavior. Each platform will implement the behavior with native state and lifecycle tools. Reconnect rules must restore the session before any prompt retry. A client must not blindly retry a prompt when delivery is uncertain.

No runtime state-management code exists here yet.
