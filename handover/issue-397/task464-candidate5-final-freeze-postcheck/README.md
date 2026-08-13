# Candidate-five post-freeze verification

This verifier is for the durable candidate-five final set at guarded commit
`94b9c2465c1c59b5ca5d62fea050a830e3d50d0b`. It is separate from the
pre-publication final-freeze suite. That suite correctly requires an absent
output root before it creates a set; this verifier instead requires the exact
five-file set to exist already.

The tests stable-read each fixed output through no-follow descriptors, require
regular owner-private mode `0600` files with one hard link, verify the exact
hashes and inodes, and use the approved #403 and #401 modules to inspect the
complete set and check JSON, Markdown, and shell parity. They then attempt a
second publication through the approved final-freeze coordinator. It must
reject before a writer loads, and every original byte, inode, mode, and hash
must remain unchanged.

The verifier never runs the generated shell, Phase A, replay, Hermes, network
access, or credentials. It has no mock data and does not publish any file.

Run from this directory:

```sh
python3 -B test_final_freeze_postcheck.py
python3 -O -B test_final_freeze_postcheck.py
shasum -a 256 -c SHA256SUMS
```
