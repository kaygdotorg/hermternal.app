# Candidate-five final-triad orchestration successor

This speculative checkpoint generates the candidate-five JSON, Markdown, and
shell bytes in memory from exact durable inputs. It loads each successor only
after an exact SHA-256 check. It does not execute the shell and it does not
publish or freeze final evidence.

The strict #401 authority descriptor and the closed provenance manifest are
different documents. A consumer accepts only the complete triad, descriptor,
and provenance set. It rejects every partial set.

Final publication is disabled because the current #401 and #402 contracts do
not compose. #401 requires each artifact to have one hard link. #402 calls its
validator before it removes the private stage link, when each artifact has two
hard links. A reviewed dependency correction is required before final output
generation and publication.

Run `python3 -B test_generator_orchestrator.py` and repeat with `python3 -O -B`.
