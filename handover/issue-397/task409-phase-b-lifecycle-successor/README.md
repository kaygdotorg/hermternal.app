# Phase B lifecycle successor checkpoint

This checkpoint replaces the rejected lifecycle harness at a new path. It does
not change or approve the frozen candidate-three or candidate-four evidence.

The successor uses a closed triad descriptor with exactly three ordered roles.
It reads the descriptor and each artifact through bounded, repeated descriptor
reads. It verifies exact paths and SHA-256 values. It computes normalized JSON
identity from the JSON bytes without JSON reserialization. Phase A runs once
before the external anchor and once at Phase B entry. Final stable reads bind
the descriptor and all three artifacts without a hidden validator call.

The test fixture is local mock data. Only the final Git observation callback is
synthetic. The checkpoint does not execute Git, replay, the candidate shell, a
network operation, credentials, sockets, or Hermes. The final candidate-five
triad and its production authority are not part of this checkpoint.

Run `python3 -B test_phase_b_lifecycle_successor.py` and repeat with `-O -B`.
