# Candidate-five framing and range successor

This directory is a new checkpoint for issue #397. The files in
`../task464-candidate5/` stay frozen. Candidate-three and candidate-four stay
rejected historical evidence.

The successor reads the frozen `cc73c174...` generator through one no-follow
descriptor and checks its exact SHA-256. It compiles and executes only those
verified bytes. The source path is filename metadata for diagnostics. No import
loader can reopen the path for execution. The successor changes the range
validation in memory. It does not edit the frozen file.

An inclusive range has this exact form:

```text
<40 lowercase hexadecimal characters>^..<40 lowercase hexadecimal characters>
```

The validator checks `left`, `right`, and `notation` separately. It then
requires `notation == left + ".." + right`. Git `rev-list` receives the checked
notation. The cumulative patch calculation receives the checked endpoints.
The rejected-authentication commit range also has separate endpoint checks.

Run the focused checks from the repository root:

```sh
python3 -B handover/issue-397/task464-candidate5-successor/test_candidate5_framing_range_successor.py
python3 -O -B handover/issue-397/task464-candidate5-successor/test_candidate5_framing_range_successor.py
python3 -m py_compile handover/issue-397/task464-candidate5-successor/candidate5_framing_range_successor.py handover/issue-397/task464-candidate5-successor/test_candidate5_framing_range_successor.py
cd handover/issue-397/task464-candidate5-successor && shasum -a 256 -c SHA256SUMS
```

`SHA256SUMS` binds the checkpoint source, regression test, and documentation.
It does not include itself because a file cannot contain its own stable digest.
The swap-after-read test replaces a private temporary path after verification.
It proves that the replacement bytes do not execute and that the verified bytes
do execute.

This checkpoint uses mock handover data. It does not run Git, Hermes, a replay,
network access, publication, or production integration.
