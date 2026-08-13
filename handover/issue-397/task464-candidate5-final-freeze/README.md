# Candidate-five final-freeze activation

This narrow checkpoint activates only the reviewed candidate-five final-set
composition. It verified-loads the exact #403 orchestration source and the
approved #402 publisher, creates the triad once, then creates a distinct
authority descriptor and provenance record with `O_EXCL|O_NOFOLLOW`.

`--prepare` uses a private temporary mode-0700 root and removes it when the
command returns. `--publish` is the only durable mode. It writes only below
`handover/issue-397/task464-candidate5-final/`, rejects any existing complete
or partial output set, and never executes the generated shell.

The five durable files are `candidate-five.md`, `candidate-five.json`,
`candidate-five.sh`, `authority-descriptor.json`, and
`provenance-manifest.json`. Each is regular mode `0600` while published. The
coordinator does not treat a partial set as valid and reports a failure instead
of adopting, overwriting, or repairing a pre-existing path.

Run focused checks with:

```sh
python3 -B test_final_freeze.py
python3 -O -B test_final_freeze.py
python3 -B final_freeze.py --prepare
```

Do not use `--publish` before an independent review approves this exact source.
