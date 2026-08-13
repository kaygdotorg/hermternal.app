# Candidate-five framing and range successor

This directory is a new checkpoint for issue #397. The files in
`../task464-candidate5/` stay frozen. Candidate-three and candidate-four stay
rejected historical evidence.

The successor loads the frozen `cc73c174...` generator only after an exact
SHA-256 check. It changes the range validation in memory. It does not edit the
frozen file.

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
```

This checkpoint uses mock handover data. It does not run Git, Hermes, a replay,
network access, publication, or production integration.
