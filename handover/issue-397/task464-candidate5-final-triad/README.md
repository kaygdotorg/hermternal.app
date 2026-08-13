# Candidate-five final-triad orchestration successor

This speculative checkpoint generates the candidate-five JSON, Markdown, and
shell bytes in memory from exact durable inputs. It loads each successor only
after an exact SHA-256 check. It does not execute the shell and it does not
publish or freeze final evidence.

The strict #401 authority descriptor and the closed provenance manifest are
different documents. A consumer accepts only the complete triad, descriptor,
and provenance set. It rejects every partial set.

Final publication stays disabled until the approved #402 commit
`bad52e81aac1e29639847339e789915eb0e9039c` is integrated. Its exact approved
source SHA-256 is pinned in the orchestrator. Compatibility is tested by running a test-provided publication module in
a private temporary root and using genuine #401 as its callback. The callback
must see single-link artifacts and exact JSON, Markdown, shell, argv, and stdin
authority. Source formatting and source-text searches do not decide approval.

Provenance generation and final inspection both use approved #401 parsing and
extraction against the exact JSON, Markdown, and standalone shell bytes. They
derive and compare all three shell hashes, normalized JSON identity, and argv
digest. No equality field or hash is a constant claim.

The durable Markdown has later prose closing fences, which #401 treats as an
ambiguous second shell-fence close. The successor makes one explicit final-only
adaptation: it keeps the authority closing fence and replaces each later exact
closing-fence record with a fixed HTML comment. It does not change the shell
body, JSON shell, or any opening-fence record.

Run `python3 -B test_generator_orchestrator.py` and repeat with `python3 -O -B`.
