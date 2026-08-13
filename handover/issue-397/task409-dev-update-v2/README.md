# #407 dev update v2

This is the final small consumer of one exact #406 v3 PASS report. It does
not accept the old v1 report, a report from another path, a changed report, or
a partial gate result. `final-offline-report-pin.json` is deliberately
`deferred` until the reviewed #406 run exists. There is no fallback.

After independent review, finalize that one pin with the canonical private
paths and SHA-256 values for the #406 report and its #405 result and completion
records. It must also pin the final candidate commit, tree, and completion
source commit.

The plan command validates the complete v3 report schema, result/completion
chain, current clean candidate checkout, ancestry from the fixed `origin/dev`
base, tracked `origin/dev` commit and tree, tracked `origin/main`, and an
initial remote readback. It writes a private create-only plan. It does not
push.

```sh
/usr/bin/python3 -B dev_update_v2.py plan --pin /absolute/final-pin.json \
  --repository /absolute/retained-repository --plan /private/plan.json
```

Only a successful plan contains this fixed argv:

```text
/usr/bin/git push --porcelain origin <candidate>:refs/heads/dev
```

An external operator can run that exact argv once. Then use the separate
post-readback command to create evidence that `origin/dev` now names the
candidate and `origin/main` stayed at its fixed commit:

```sh
/usr/bin/python3 -B dev_update_v2.py post-readback \
  --repository /absolute/retained-repository --plan /private/plan.json \
  --report /private/report.json
```

The verifier never calls `git push`, force, lease, wildcard, delete, tag, or
main refspec. Plan and report files are create-only, owner-private `0600`
records. Tests mock only the Git subprocess boundary; JSON parsing, hash
checks, chained evidence reads, and create-only writes are real.
