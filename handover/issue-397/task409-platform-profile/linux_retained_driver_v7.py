#!/usr/bin/env python3
"""Add the reviewed local object-preservation step to retained driver v6."""
from __future__ import annotations

import hashlib
from pathlib import Path

import linux_retained_driver_v6 as predecessor
import object_preservation

HERE = Path(__file__).resolve().parent
V6_PATH = HERE / "linux_retained_driver_v6.py"
V6_SHA256 = "4363f123a52863304f56eb6847c7e228fc43eae765eb1658d3c0cf521af88cde"
POLICY_PATH = HERE / "object_preservation.py"
POLICY_SHA256 = "1894901105a07fc925b7271bdb32b0cae92ffb80bd2cbbcd77c828a09819b57e"
PROOF_PATH = HERE / "forbidden_proof.py"
PROOF_SHA256 = "95009c152eb9dbd04cdef58a5c1dddcce8f79365b22a8aca60ab272266a100b6"
PRESERVATION_RECORD_SHA256 = "8aea6f4fcc34388362fff8840518d61f39ca8565548dc1b63e78de31101631c3"
RELATIVE_OBJECT_PATH = b"objects = os.path.realpath(out('rev-parse', '--git-path', 'objects'))"
CANONICAL_OBJECT_PATH = b"""objects_value = out('rev-parse', '--git-path', 'objects')
objects = os.path.realpath(
    objects_value if os.path.isabs(objects_value) else os.path.join(repo, objects_value)
)"""
RANGE_LOCALS = b'''  local lane="$1" record source expected parent tree path_blob cherry_path abort_rc
  local paths=()'''
ORDERED_RANGE_LOCALS = b'''  local lane="$1" record source expected parent tree path_blob cherry_path abort_rc
  local expected_cherry prior_source
  local paths=() applied_sources=()'''
REJECT_ANY_NEGATIVE_CHERRY = b'''    cherry_path="$(git_replay cherry "$CURRENT_HEAD" "$source")"
    test -n "$cherry_path" || fail "git cherry returned an empty duplicate-check result for $source"
    while IFS= read -r record; do
      case "$record" in -*) fail "duplicate source patch rejected by git cherry: $record" ;; esac
    done <<< "$cherry_path"'''
REQUIRE_ORDERED_CHERRY = b'''    cherry_path="$(git_replay cherry "$CURRENT_HEAD" "$source")"
    test -n "$cherry_path" || fail "git cherry returned an empty duplicate-check result for $source"
    expected_cherry=''
    for prior_source in "${applied_sources[@]}"; do
      expected_cherry+="- $prior_source"$'\\n'
    done
    expected_cherry+="+ $source"
    test "$cherry_path" = "$expected_cherry" || fail "ordered git cherry signs differ for $source"'''
RANGE_COMMIT = b'''    commit_staged "replay(task409): $lane:$source" "$expected" "${paths[@]}"'''
ORDERED_RANGE_COMMIT = RANGE_COMMIT + b'''\n    applied_sources+=("$source")'''
SEMANTIC_LS_TREE_READ = b'''      read -r new_mode target_type new_blob _ <<< "$target_line"'''
SEMANTIC_LS_TREE_FIELD_READ = b'''      IFS=$' \\t' read -r new_mode target_type new_blob target_path <<< "$target_line"'''
CHECKOUT_INDEX = b'''    git_replay checkout-index --force -- "$path"'''
CHECKOUT_AND_REFRESH_INDEX = CHECKOUT_INDEX + b'''\n    before_mutation
    git_replay update-index --refresh -- "$path"'''
STRICT_RECORD_LINES = b"""def strict_record_lines(raw, label='records'):
    \"\"\"Parse a non-empty LF-framed stream without CR or blank rows.\"\"\"
    if not isinstance(raw, (bytes, bytearray)):
        raise SystemExit(f'{label} is not byte data')
    raw = bytes(raw)
    if (not raw or b'\\r' in raw or not raw.endswith(b'\\n')
            or raw.endswith(b'\\n\\n')):
        raise SystemExit(f'{label} must be LF-framed with no blank records')
    rows = raw[:-1].split(b'\\n')
    if any(not row for row in rows):
        raise SystemExit(f'{label} contains an empty record')
    return rows"""
MATRIX_RECORD_IMPORTS = b"""import json
import sys
from pathlib import Path
matrix, stage, output = sys.argv[1:]"""
MATRIX_RECORD_IMPORTS_FIXED = b"""import json
import sys
from pathlib import Path

""" + STRICT_RECORD_LINES + b"""

matrix, stage, output = sys.argv[1:]"""
FORBIDDEN_RECORD_IMPORTS = b"""import json
import sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_bytes())
expected = [value.encode() for value in data['forbidden_ancestry']['commits'] + data['forbidden_ancestry']['raw_semantic_source_commits']]"""
FORBIDDEN_RECORD_IMPORTS_FIXED = b"""import json
import sys
from pathlib import Path

""" + STRICT_RECORD_LINES + b"""

data = json.loads(Path(sys.argv[1]).read_bytes())
expected = [value.encode() for value in data['forbidden_ancestry']['commits'] + data['forbidden_ancestry']['raw_semantic_source_commits']]"""
PARENT_IDENTITY_CHECK = b"""def verify_parent(path, wanted, label):
    verify(path, path, wanted, label, allow_nlink_growth=True)"""
STABLE_PARENT_IDENTITY_CHECK = b"""def verify_parent(path, wanted, label):
    st = os.lstat(path)
    if (stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode)
            or os.path.realpath(path) != path):
        raise SystemExit(label + ' path changed')
    actual = [
        str(st.st_dev), str(st.st_ino), str(st.st_uid),
        format(stat.S_IMODE(st.st_mode), '04o'),
    ]
    if actual != wanted[:4]:
        raise SystemExit(label + ' identity changed')"""
COMMIT_TARGET_DISCOVERY = b'''  local EXPECTED_COMMIT_TARGET_ROWS=() target_path target_state
  for target_path in "${paths[@]}"; do
    target_state="$(target_state_record "$target_path")"
    EXPECTED_COMMIT_TARGET_ROWS+=("$target_state")
  done'''
OPERATION_TARGET_BINDING = b'''  local EXPECTED_COMMIT_TARGET_ROWS=() target_path target_blob target_mode target_kind target_index
  test "${#EXPECTED_OPERATION_TARGET_ROWS[@]}" -eq "${#paths[@]}" || fail "active operation target row count mismatch"
  for target_index in "${!paths[@]}"; do
    IFS=$'\t' read -r target_path target_blob target_mode target_kind <<< "${EXPECTED_OPERATION_TARGET_ROWS[$target_index]}"
    test "$target_path" = "${paths[$target_index]}" || fail "active operation target path order mismatch"
    case "$target_kind:$target_blob:$target_mode" in
      absent:-:-|file:[0-9a-f][0-9a-f]*:[0-9][0-9][0-9][0-9][0-9][0-9]) ;;
      *) fail "active operation target row is malformed for $target_path" ;;
    esac
    EXPECTED_COMMIT_TARGET_ROWS+=("${EXPECTED_OPERATION_TARGET_ROWS[$target_index]}")
  done'''
RANGE_OPERATION_ARRAY = b'''  local paths=() applied_sources=()'''
RANGE_OPERATION_ARRAY_FIXED = b'''  local paths=() applied_sources=()
  local EXPECTED_OPERATION_TARGET_ROWS=()'''
RANGE_TARGET_LOOP = b'''    while IFS=$'\t' read -r path target_blob target_mode target_kind; do
      assert_path_state "$path" "$target_blob" "$target_mode" "$target_kind"
    done < "$target_records_file"'''
RANGE_TARGET_LOOP_FIXED = b'''    EXPECTED_OPERATION_TARGET_ROWS=()
    while IFS=$'\t' read -r path target_blob target_mode target_kind; do
      assert_path_state "$path" "$target_blob" "$target_mode" "$target_kind"
      EXPECTED_OPERATION_TARGET_ROWS+=("$path"$'\t'"$target_blob"$'\t'"$target_mode"$'\t'"$target_kind")
    done < "$target_records_file"'''
SEMANTIC_OPERATION_LOCALS = b'''  local path old_blob old_mode old_kind new_blob new_mode new_kind target_line target_type'''
SEMANTIC_OPERATION_LOCALS_FIXED = SEMANTIC_OPERATION_LOCALS + b'''
  local EXPECTED_OPERATION_TARGET_ROWS=()'''
SEMANTIC_CAS = b'''    cas_path "$path" "$old_blob" "$old_mode" "$old_kind" "$new_blob" "$new_mode" "$new_kind"'''
SEMANTIC_CAS_FIXED = SEMANTIC_CAS + b'''
    EXPECTED_OPERATION_TARGET_ROWS+=("$path"$'\t'"$new_blob"$'\t'"$new_mode"$'\t'"$new_kind")'''
MATRIX_OPERATION_LOCALS = b'''  local paths=() snapshots=() row path old_blob old_mode new_blob new_mode old_kind'''
MATRIX_OPERATION_LOCALS_FIXED = MATRIX_OPERATION_LOCALS + b'''
  local EXPECTED_OPERATION_TARGET_ROWS=()'''
MATRIX_CAS = b'''    cas_path "$path" "$old_blob" "$old_mode" "$old_kind" "$new_blob" "$new_mode" file'''
MATRIX_CAS_FIXED = MATRIX_CAS + b'''
    EXPECTED_OPERATION_TARGET_ROWS+=("$path"$'\t'"$new_blob"$'\t'"$new_mode"$'\t'file)'''
README_COMMIT = b'''  commit_staged 'replay(task409): reviewed scripts README merge' - scripts/README.md'''
README_COMMIT_FIXED = b'''  local EXPECTED_OPERATION_TARGET_ROWS=("scripts/README.md"$'\t'"$merged_blob"$'\t'100644$'\t'file)
  commit_staged 'replay(task409): reviewed scripts README merge' - scripts/README.md'''
PACK_OBJECTS = b"packed = run(['pack-objects', pack_prefix], input_bytes=pack_input)"
PACK_OBJECTS_WITHOUT_REVERSE_INDEX = b"packed = run(['-c', 'pack.writeReverseIndex=false', 'pack-objects', pack_prefix], input_bytes=pack_input)"


def _authenticate() -> None:
    if hashlib.sha256(V6_PATH.read_bytes()).hexdigest() != V6_SHA256:
        raise RuntimeError("Linux retained-driver v6 SHA-256 differs")
    if hashlib.sha256(POLICY_PATH.read_bytes()).hexdigest() != POLICY_SHA256:
        raise RuntimeError("object preservation policy SHA-256 differs")
    if hashlib.sha256(PROOF_PATH.read_bytes()).hexdigest() != PROOF_SHA256:
        raise RuntimeError("forbidden proof policy SHA-256 differs")


def load_driver():
    """Reuse the exact authenticated v6 driver mechanics."""
    _authenticate()
    return predecessor.load_driver()


def preservation_record() -> dict[str, object]:
    """Return the canonical authority closure and forbidden-object binding."""
    _authenticate()
    authority = load_driver().load_frozen_authority().document
    record = object_preservation.build_record(authority, predecessor.forbidden_proof_record())
    if object_preservation.record_sha256(record) != PRESERVATION_RECORD_SHA256:
        raise RuntimeError("object preservation record SHA-256 differs")
    return record


def derive_contract():
    """Apply authenticated preservation, validation, commit, and pack fixes to v6."""
    _authenticate()
    base = predecessor.derive_contract()
    record = preservation_record()
    stdin = object_preservation.repair_generated_validator(
        base.stdin, record, PRESERVATION_RECORD_SHA256, POLICY_PATH, POLICY_SHA256,
        PROOF_PATH, PROOF_SHA256
    )
    # Git can return .git/objects here. Resolve that value from the replay
    # repository, not from the process working directory (/).
    if stdin.count(RELATIVE_OBJECT_PATH) != 1:
        raise RuntimeError("replay object-path validator anchor differs")
    stdin = stdin.replace(RELATIVE_OBJECT_PATH, CANONICAL_OBJECT_PATH)
    # Earlier commits in one range must become negative while only the current
    # declared member stays positive. Do not accept any other sign sequence.
    if (stdin.count(RANGE_LOCALS) != 1
            or stdin.count(REJECT_ANY_NEGATIVE_CHERRY) != 1
            or stdin.count(RANGE_COMMIT) != 1):
        raise RuntimeError("ordered range cherry validator anchor differs")
    stdin = stdin.replace(RANGE_LOCALS, ORDERED_RANGE_LOCALS)
    stdin = stdin.replace(REJECT_ANY_NEGATIVE_CHERRY, REQUIRE_ORDERED_CHERRY)
    stdin = stdin.replace(RANGE_COMMIT, ORDERED_RANGE_COMMIT)
    # ls-tree separates metadata with spaces and the path with a tab. The
    # driver-wide newline/tab IFS cannot parse its metadata fields.
    if stdin.count(SEMANTIC_LS_TREE_READ) != 1:
        raise RuntimeError("semantic ls-tree parser anchor differs")
    stdin = stdin.replace(SEMANTIC_LS_TREE_READ, SEMANTIC_LS_TREE_FIELD_READ)
    # cacheinfo has no current stat data. Refresh it after checkout writes the
    # exact blob so the immediate diff-files proof is deterministic.
    if stdin.count(CHECKOUT_INDEX) != 1:
        raise RuntimeError("checkout-index refresh anchor differs")
    stdin = stdin.replace(CHECKOUT_INDEX, CHECKOUT_AND_REFRESH_INDEX)
    # These two short validators call the approved LF record parser but omit
    # its local definition. Each heredoc is a separate Python scope.
    if (stdin.count(MATRIX_RECORD_IMPORTS) != 1
            or stdin.count(FORBIDDEN_RECORD_IMPORTS) != 1):
        raise RuntimeError("record validator helper anchor differs")
    stdin = stdin.replace(MATRIX_RECORD_IMPORTS, MATRIX_RECORD_IMPORTS_FIXED)
    stdin = stdin.replace(FORBIDDEN_RECORD_IMPORTS, FORBIDDEN_RECORD_IMPORTS_FIXED)
    # /tmp is shared. Its link count can change when an unrelated process adds
    # or removes a child. Across replay stages, bind only its stable identity.
    if stdin.count(PARENT_IDENTITY_CHECK) != 1:
        raise RuntimeError("cross-stage parent identity anchor differs")
    stdin = stdin.replace(PARENT_IDENTITY_CHECK, STABLE_PARENT_IDENTITY_CHECK)
    # Every commit caller already has the authenticated active operation row.
    # Carry that row to the post-commit gate instead of inferring by path.
    replacements = (
        (COMMIT_TARGET_DISCOVERY, OPERATION_TARGET_BINDING),
        (RANGE_OPERATION_ARRAY, RANGE_OPERATION_ARRAY_FIXED),
        (RANGE_TARGET_LOOP, RANGE_TARGET_LOOP_FIXED),
        (SEMANTIC_OPERATION_LOCALS, SEMANTIC_OPERATION_LOCALS_FIXED),
        (SEMANTIC_CAS, SEMANTIC_CAS_FIXED),
        (MATRIX_OPERATION_LOCALS, MATRIX_OPERATION_LOCALS_FIXED),
        (MATRIX_CAS, MATRIX_CAS_FIXED),
        (README_COMMIT, README_COMMIT_FIXED),
    )
    for old, new in replacements:
        if stdin.count(old) != 1:
            raise RuntimeError("active operation target-row anchor differs")
        stdin = stdin.replace(old, new)
    # New Git versions can add a .rev sidecar by default. Disable that optional
    # accelerator so the retained closure stays the exact pack/index pair.
    if stdin.count(PACK_OBJECTS) != 1:
        raise RuntimeError("retained pack output anchor differs")
    stdin = stdin.replace(PACK_OBJECTS, PACK_OBJECTS_WITHOUT_REVERSE_INDEX)
    load_driver().compile_derived(stdin)
    return load_driver().DerivedDriver(
        base.argv, stdin, base.source_sha256, hashlib.sha256(stdin).hexdigest()
    )


def __getattr__(name: str):
    return getattr(predecessor, name)
