# Normal non-force dev-update successor

This speculative verifier consumes only a complete approved #406 PASS report.
It requires the candidate commit and tree, clean repository state, ancestry from
the pinned dev base, unchanged origin/dev and protected origin/main, and exact
pre- and post-update remote identities.

The only planned write is `/usr/bin/git push --porcelain origin
<candidate>:refs/heads/dev`. Force, force-with-lease, wildcards, deletions,
tags, main, and every other ref are rejected. The verifier does not execute the
push. It returns the argv only after all read-only gates pass.

Post-push evidence has a closed schema with dev before/after, main before/after,
candidate tree, exact refspec, normal non-force mode, and #406 evidence hash.
This checkpoint does not update dev or main.
