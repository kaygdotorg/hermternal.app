# Issue #397 v4 replay operator

This directory adds the one missing operator entry point. It does not contain
replay logic. It stable-reads the fixed reviewed failure-v2 adapter, Phase A v4
adapter, profile module, profile JSON, and preflight wrapper. It compiles the
verified buffers without a source rewrite, then delegates one call to the
approved v4 wrapper.

There are no caller-selected authority paths, SHA-256 values, profile values,
or output roots. The fixed v4 anchor is:

```text
/home/kayg/Developer/hermternal-issue397-phase-a-anchor-v4/evidence/anchor.json
c92ecfed3b0578537d38fc79172bf5d0100096976bfd1a8beb1a5d54968cd193
```

The fixed early-failure root is:

```text
/home/kayg/Developer/hermternal-issue397-replay-failure-v2
```

Use preflight before the operator replay:

```sh
/usr/bin/python3 -B replay_operator_v4.py --preflight
```

After independent authorization, use exactly one replay command:

```sh
/usr/bin/python3 -B replay_operator_v4.py --run
```

`--preflight` delegates only to the approved no-process preflight. `--run`
delegates once to the approved failure-v2 wrapper. This operator does not run
Hermes, use credentials, make a network call, transform shell bytes, or add a
second replay path.
