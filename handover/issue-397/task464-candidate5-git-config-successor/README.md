# Candidate-five Git-config successor

This checkpoint wraps the frozen `task409-execution-preflight/review_task464_git_v3.py` reviewer. It does not change that reviewer or other frozen evidence. The wrapper reads the reviewer through one no-follow descriptor, checks SHA-256 `dc4e95cc055947673702048222fe963cbce1ac9673e35d072ecd2214e252ab7c`, and executes only the verified bytes.

The local `.git/config` authority is an exact byte contract. It permits the four canonical Git-init records plus `core.hooksPath=/dev/null` and `protocol.allow=never`. It rejects all other serialization and semantic records. This includes extra keys, duplicate keys, alternate case, quotes, continuations, comments, CRLF, NUL, and a missing final LF.

After the frozen metadata inspection creates its guard, the successor makes exactly one semantic config call. The call must return the same six records from `file:.git/config`. The successor binds `/usr/bin/git` by identity and SHA-256 before use. It uses one fixed environment and command prefix. A closed command grammar permits only the frozen reviewer's known read-only subcommands and exact operand forms. It rejects later `-c`, `--config-env`, repository selectors, option abbreviations, credentials, and all other command expansion before a subprocess starts. It rechecks the executable and repository metadata before and after the semantic call and each later Git call.

Run the focused checks from the repository root:

```sh
python3 -B handover/issue-397/task464-candidate5-git-config-successor/test_candidate5_git_config_successor.py
python3 -O -B handover/issue-397/task464-candidate5-git-config-successor/test_candidate5_git_config_successor.py
python3 -m py_compile handover/issue-397/task464-candidate5-git-config-successor/candidate5_git_config_successor.py handover/issue-397/task464-candidate5-git-config-successor/test_candidate5_git_config_successor.py
cd handover/issue-397/task464-candidate5-git-config-successor && shasum -a 256 -c SHA256SUMS
```

The tests use temporary local Git repositories. They do not contact a remote, run replay, start Hermes, read credentials, or publish files.
