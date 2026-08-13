# Candidate4 generated Python escape invariant: one source backslash; no global escape replacement.
#!/bin/bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

# Task #409 / artifact #464. This is an offline future replay only. It reads local
# objects through a read-only alternate object database and never fetches, pushes,
# contacts a service, starts Hermes, opens a socket, or reads credentials.
readonly GIT=/usr/bin/git
readonly PYTHON=/opt/homebrew/bin/python3
readonly BASH=/bin/bash
readonly ENV=/usr/bin/env
readonly MKDIR=/bin/mkdir
readonly RM=/bin/rm
readonly RMDIR=/bin/rmdir
readonly CUT=/usr/bin/cut
readonly SHASUM=/usr/bin/shasum
readonly SOURCE=/Users/agents/Developer/hermternal
readonly MARKDOWN=/private/tmp/task464-test32-md.md
readonly MATRIX_SOURCE=/private/tmp/task464-test32-json.json
MATRIX="$MATRIX_SOURCE"
readonly MATRIX_EXPECTED_BINDING_SHA256='f5b77b8764c303e1aceb96f82b12623c575a4f0d20eb6cc67586e67454399b99'
MATRIX_BOUND=0
MATRIX_SOURCE_VALIDATED=0
MATRIX_SNAPSHOT_DEVICE=''
MATRIX_SNAPSHOT_INODE=''
MATRIX_SNAPSHOT_SIZE=''
MATRIX_SNAPSHOT_REALPATH=''
readonly BASE=729f2613af2b78d58b07918478e9102d5716f367
readonly BASE_TREE=43f86b645fc9f89d5d4aa1e6978b1f61f0b5c69f
readonly MAIN=3ebf8b3fe4767442490ab3053c0c1ccf84e8019f
readonly PROXY=e3a2d2e662f2e606f318d35f4fccc63ba9738f7c
readonly LAUNCHER=d3c40687659ee645a5f03bc80cbf61ec8c49979a
readonly LIVE=80fe3b68fb676a3b6589fce9aed79140bf37b667
readonly SWIFT=221620c04bb051f2597c52bdeb16ccc55c5b2e9c
readonly REJECTED_AUTH_LEFT=d88cd9adfcef94980ae674f40d99c65e1cf9b666
readonly REJECTED_AUTH_RIGHT=f87ce048b5afc4fad7ac361baa589d47745b580b
readonly CLEAN_PRIMARY_ROOT="/private/tmp/hermternal-task409-final-clean-primary.$$"
readonly CLEAN_PRIMARY="$CLEAN_PRIMARY_ROOT/repository"
readonly REPLAY_ROOT="/private/tmp/hermternal-task409-final-replay.$$"
readonly REPLAY="$REPLAY_ROOT/replay"
readonly README_TMP="$REPLAY_ROOT/scripts-README.merge"
readonly MATRIX_SNAPSHOT="$REPLAY_ROOT/matrix.snapshot.json"
SOURCE_BOUND=0
SOURCE_REALPATH=''
SOURCE_DEVICE=''
SOURCE_INODE=''
SOURCE_UID=''
SOURCE_MODE=''
SOURCE_GIT_DIR=''
SOURCE_GIT_COMMON_DIR=''
SOURCE_OBJECTS=''
SOURCE_GIT_DEVICE=''
SOURCE_GIT_INODE=''
SOURCE_GIT_UID=''
SOURCE_GIT_MODE=''
SOURCE_COMMON_DEVICE=''
SOURCE_COMMON_INODE=''
SOURCE_COMMON_UID=''
SOURCE_COMMON_MODE=''
SOURCE_OBJECTS_DEVICE=''
SOURCE_OBJECTS_INODE=''
SOURCE_OBJECTS_UID=''
SOURCE_OBJECTS_MODE=''
SOURCE_CAPTURE_DEV=''
SOURCE_CAPTURE_MAIN=''
SOURCE_CAPTURE_TREE=''
CLEAN_PRIMARY_ROOT_BOUND=0
CLEAN_PRIMARY_ROOT_DEVICE=''
CLEAN_PRIMARY_ROOT_INODE=''
CLEAN_PRIMARY_ROOT_UID=''
CLEAN_PRIMARY_ROOT_MODE=''
CLEAN_PRIMARY_ROOT_REALPATH=''
CLEAN_PRIMARY_ROOT_NLINK=''
CLEAN_PRIMARY_PARENT_DEVICE=''
CLEAN_PRIMARY_PARENT_INODE=''
CLEAN_PRIMARY_PARENT_UID=''
CLEAN_PRIMARY_PARENT_MODE=''
CLEAN_PRIMARY_PARENT_NLINK=''
CLEAN_PRIMARY_REPOSITORY_BOUND=0
CLEAN_PRIMARY_REPOSITORY_DEVICE=''
CLEAN_PRIMARY_REPOSITORY_INODE=''
CLEAN_PRIMARY_REPOSITORY_UID=''
CLEAN_PRIMARY_REPOSITORY_MODE=''
CLEAN_PRIMARY_REPOSITORY_NLINK=''
CLEAN_PRIMARY_BOUND=0
CLEAN_PRIMARY_REALPATH=''
CLEAN_PRIMARY_DEVICE=''
CLEAN_PRIMARY_INODE=''
CLEAN_PRIMARY_UID=''
CLEAN_PRIMARY_MODE=''
CLEAN_PRIMARY_GIT_DIR=''
CLEAN_PRIMARY_COMMON_DIR=''
CLEAN_PRIMARY_OBJECTS=''
CLEAN_PRIMARY_GIT_DEVICE=''
CLEAN_PRIMARY_GIT_INODE=''
CLEAN_PRIMARY_GIT_UID=''
CLEAN_PRIMARY_GIT_MODE=''
CLEAN_PRIMARY_COMMON_DEVICE=''
CLEAN_PRIMARY_COMMON_INODE=''
CLEAN_PRIMARY_COMMON_UID=''
CLEAN_PRIMARY_COMMON_MODE=''
CLEAN_PRIMARY_OBJECTS_DEVICE=''
CLEAN_PRIMARY_OBJECTS_INODE=''
CLEAN_PRIMARY_OBJECTS_UID=''
CLEAN_PRIMARY_OBJECTS_MODE=''
REPLAY_ROOT_BOUND=0
REPLAY_ROOT_DEVICE=''
REPLAY_ROOT_INODE=''
REPLAY_ROOT_UID=''
REPLAY_ROOT_MODE=''
REPLAY_ROOT_REALPATH=''
REPLAY_GIT_BOUND=0
REPLAY_ROOT_NLINK=''
REPLAY_PARENT_DEVICE=''
REPLAY_PARENT_INODE=''
REPLAY_PARENT_UID=''
REPLAY_PARENT_MODE=''
REPLAY_PARENT_NLINK=''
REPLAY_CHECKOUT_BOUND=0
REPLAY_CHECKOUT_PRESENT=0
REPLAY_CHECKOUT_DEVICE=''
REPLAY_CHECKOUT_INODE=''
REPLAY_CHECKOUT_UID=''
REPLAY_CHECKOUT_MODE=''
REPLAY_CHECKOUT_NLINK=''
readonly COMMITTER_NAME='Task409 guarded replay'
readonly COMMITTER_EMAIL='task409-replay@localhost'

# The exact /usr/bin/env -i invocation is mandatory. The allowlist fails closed before
# any Git or Python operation, so numbered Git config variables, GIT_CONFIG_PARAMETERS,
# PYTHONPATH, Python runtime overrides, and other inherited launch overrides cannot pass.
fail() {
  printf 'task409-final-driver: %s\n' "$*" >&2
  exit 1
}
secure_temp_file() {
  local directory="$1" prefix="$2" path
  path="$($PYTHON - "$directory" "$prefix" <<'PY'
import os
import sys
import tempfile
directory, prefix = sys.argv[1:]
fd, path = tempfile.mkstemp(prefix='.task464-' + prefix + '.', dir=directory)
os.fchmod(fd, 0o600)
os.close(fd)
print(path)
PY
)" || fail "secure temporary-file creation failed: $prefix"
  case "$path" in "$directory"/.task464-*) ;; *) fail "temporary file escaped its directory: $path" ;; esac
  test -f "$path" || fail "temporary file was not created: $path"
  printf '%s\n' "$path"
}
cleanup_temp_file() {
  local path="$1"
  case "$path" in "$REPLAY_ROOT"/.task464-*|/private/tmp/.task464-*) ;; *) fail "temporary cleanup path escaped its allowlist: $path" ;; esac
  "$RM" -f -- "$path"
  test ! -e "$path" || fail "temporary file cleanup failed: $path"
}
producer_to_file() {
  local label="$1" directory="$2" output status
  shift 2
  output="$(secure_temp_file "$directory" "$label")"
  set +e
  "$@" > "$output"
  status=$?
  set -e
  if [ "$status" -ne 0 ]; then
    cleanup_temp_file "$output"
    fail "record producer failed ($label), rc=$status"
  fi
  test -s "$output" || { cleanup_temp_file "$output"; fail "record producer emitted no rows: $label"; }
  printf '%s\n' "$output"
}
assert_environment() {
  local env_file env_status name ignored
  env_file="$(secure_temp_file /private/tmp environment)"
  set +e
  "$ENV" > "$env_file"
  env_status=$?
  set -e
  test "$env_status" -eq 0 || { cleanup_temp_file "$env_file"; fail "environment enumeration failed: $env_status"; }
  test -s "$env_file" || { cleanup_temp_file "$env_file"; fail "environment enumeration was empty"; }
  while IFS='=' read -r name ignored; do
    case "$name" in
      GIT_CONFIG_PARAMETERS|GIT_CONFIG_COUNT|GIT_CONFIG_KEY_*|GIT_CONFIG_VALUE_*|PYTHONPATH|PYTHONHOME|PYTHONSTARTUP|PYTHONUSERBASE|PYTHONINSPECT|PYTHONWARNINGS|BASH_ENV|ENV|CDPATH|NODE_OPTIONS|RUBYOPT|PERL5OPT|DYLD_*|LD_*)
        cleanup_temp_file "$env_file"; fail "forbidden inherited environment variable: $name" ;;
      PATH|HOME|LANG|LC_ALL|GIT_CONFIG_NOSYSTEM|GIT_CONFIG_GLOBAL|GIT_CONFIG_SYSTEM|GIT_TERMINAL_PROMPT|GIT_OPTIONAL_LOCKS|GIT_NO_REPLACE_OBJECTS|GIT_NO_LAZY_FETCH|PWD|SHLVL|_) ;;
      *) cleanup_temp_file "$env_file"; fail "environment variable is not allowlisted: $name" ;;
    esac
  done < "$env_file"
  cleanup_temp_file "$env_file"
}
assert_environment
export PATH=/usr/bin:/bin
export HOME=/dev/null
export LANG=C
export LC_ALL=C
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null
export GIT_TERMINAL_PROMPT=0
export GIT_OPTIONAL_LOCKS=0
export GIT_NO_REPLACE_OBJECTS=1
export GIT_NO_LAZY_FETCH=1

CURRENT_HEAD=''
CURRENT_TREE=''
BOOTSTRAP_HEAD=''
BOOTSTRAP_TREE=''
REPLAY_READY=0
DIRTY_PATHS=()
APPLIED_PATCH_IDS=''
CLEANUP_ALLOWLIST=()
CLEAN_PRIMARY_CLEANUP_ALLOWLIST=()
BASH_ARRAY_SMOKE_DONE=0
CLEAN_PRIMARY_SMOKE_DONE=0

git_hermetic() {
  "$ENV" -i \
    PATH=/usr/bin:/bin \
    HOME=/dev/null \
    LANG=C \
    LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_SYSTEM=/dev/null \
    GIT_TERMINAL_PROMPT=0 \
    GIT_OPTIONAL_LOCKS=0 \
    GIT_NO_REPLACE_OBJECTS=1 \
    GIT_NO_LAZY_FETCH=1 \
    "$GIT" \
    --no-replace-objects \
    --no-lazy-fetch \
    --no-optional-locks \
    -c core.hooksPath=/dev/null \
    -c protocol.allow=never \
    "$@"
}
git_source() {
  git_hermetic -C "$SOURCE" "$@"
}
git_primary() {
  git_hermetic -C "$CLEAN_PRIMARY" "$@"
}
git_replay() {
  git_hermetic -C "$REPLAY" "$@"
}
patch_id_stable() {
  git_hermetic patch-id --stable
}

bind_source_identity() {
  test "$SOURCE_BOUND" -eq 0 || fail "source identity already bound"
  local git_dir common_dir objects fields
  git_dir="$(git_source rev-parse --absolute-git-dir)"
  common_dir="$(git_source rev-parse --git-common-dir)"
  objects="$(git_source rev-parse --git-path objects)"
  SOURCE_CAPTURE_DEV="$(git_source rev-parse origin/dev)"
  SOURCE_CAPTURE_MAIN="$(git_source rev-parse origin/main)"
  SOURCE_CAPTURE_TREE="$(git_source rev-parse "${SOURCE_CAPTURE_DEV}^{tree}")"
  test "$SOURCE_CAPTURE_DEV" = "$BASE" || fail "source origin/dev is not BASE"
  test "$SOURCE_CAPTURE_MAIN" = "$MAIN" || fail "source origin/main is not MAIN"
  test "$SOURCE_CAPTURE_TREE" = "$BASE_TREE" || fail "source base tree is not BASE_TREE"
  fields="$($PYTHON - "$SOURCE" "$git_dir" "$common_dir" "$objects" <<'PY'
import os
import stat
import sys
source, git_dir, common_dir, objects = sys.argv[1:]
def canonical(base, value):
    return os.path.realpath(value if os.path.isabs(value) else os.path.join(base, value))
def checked(path, label):
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or os.path.realpath(path) != path:
        raise SystemExit(label + ' is not a canonical non-symlink directory')
    return path, st
def values(st):
    return [str(st.st_dev), str(st.st_ino), str(st.st_uid), format(stat.S_IMODE(st.st_mode), '04o')]
source_path, source_st = checked(source, 'source')
git_path, git_st = checked(canonical(source, git_dir), 'source Git directory')
common_path, common_st = checked(canonical(source, common_dir), 'source common directory')
objects_path, objects_st = checked(canonical(source, objects), 'source object store')
if os.path.lexists(os.path.join(objects_path, 'info', 'alternates')):
    raise SystemExit('source object store has alternates')
print('\t'.join([source_path, git_path, common_path, objects_path] + values(source_st) + values(git_st) + values(common_st) + values(objects_st)))
PY
)"
  IFS=$'\t' read -r SOURCE_REALPATH SOURCE_GIT_DIR SOURCE_GIT_COMMON_DIR SOURCE_OBJECTS \
    SOURCE_DEVICE SOURCE_INODE SOURCE_UID SOURCE_MODE SOURCE_GIT_DEVICE SOURCE_GIT_INODE SOURCE_GIT_UID SOURCE_GIT_MODE \
    SOURCE_COMMON_DEVICE SOURCE_COMMON_INODE SOURCE_COMMON_UID SOURCE_COMMON_MODE SOURCE_OBJECTS_DEVICE SOURCE_OBJECTS_INODE SOURCE_OBJECTS_UID SOURCE_OBJECTS_MODE <<< "$fields"
  test "$SOURCE_REALPATH" = "$SOURCE" || fail "source canonical path was not bound"
  SOURCE_BOUND=1
  assert_source_binding
}

assert_source_binding() {
  test "$SOURCE_BOUND" -eq 1 || fail "source identity is not bound"
  local git_dir common_dir objects
  git_dir="$(git_source rev-parse --absolute-git-dir)"
  common_dir="$(git_source rev-parse --git-common-dir)"
  objects="$(git_source rev-parse --git-path objects)"
  test "$(git_source rev-parse origin/dev)" = "$SOURCE_CAPTURE_DEV" || fail "source origin/dev drifted"
  test "$(git_source rev-parse origin/main)" = "$SOURCE_CAPTURE_MAIN" || fail "source origin/main drifted"
  test "$(git_source rev-parse "${SOURCE_CAPTURE_DEV}^{tree}")" = "$SOURCE_CAPTURE_TREE" || fail "source tree drifted"
  test "$SOURCE_CAPTURE_DEV" = "$BASE" || fail "source BASE drifted"
  test "$SOURCE_CAPTURE_MAIN" = "$MAIN" || fail "source MAIN drifted"
  test "$SOURCE_CAPTURE_TREE" = "$BASE_TREE" || fail "source BASE_TREE drifted"
  "$PYTHON" - "$SOURCE" "$git_dir" "$common_dir" "$objects" "$SOURCE_REALPATH" "$SOURCE_GIT_DIR" "$SOURCE_GIT_COMMON_DIR" "$SOURCE_OBJECTS" \
    "$SOURCE_DEVICE" "$SOURCE_INODE" "$SOURCE_UID" "$SOURCE_MODE" "$SOURCE_GIT_DEVICE" "$SOURCE_GIT_INODE" "$SOURCE_GIT_UID" "$SOURCE_GIT_MODE" \
    "$SOURCE_COMMON_DEVICE" "$SOURCE_COMMON_INODE" "$SOURCE_COMMON_UID" "$SOURCE_COMMON_MODE" "$SOURCE_OBJECTS_DEVICE" "$SOURCE_OBJECTS_INODE" "$SOURCE_OBJECTS_UID" "$SOURCE_OBJECTS_MODE" <<'PY'
import os
import stat
import sys
(source, git_dir, common_dir, objects, expected_source, expected_git, expected_common, expected_objects, *values) = sys.argv[1:]
def canonical(base, value):
    return os.path.realpath(value if os.path.isabs(value) else os.path.join(base, value))
def check(path, expected, wanted, label):
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or os.path.realpath(path) != expected or expected != path:
        raise SystemExit(label + ' path changed')
    actual = [str(st.st_dev), str(st.st_ino), str(st.st_uid), format(stat.S_IMODE(st.st_mode), '04o')]
    if actual != wanted:
        raise SystemExit(label + ' lstat identity changed')
check(source, expected_source, values[0:4], 'source')
check(canonical(source, git_dir), expected_git, values[4:8], 'source Git directory')
check(canonical(source, common_dir), expected_common, values[8:12], 'source common directory')
check(canonical(source, objects), expected_objects, values[12:16], 'source object store')
if os.path.lexists(os.path.join(expected_objects, 'info', 'alternates')):
    raise SystemExit('source object store alternates appeared')
PY
}

create_clean_primary_root() {
  test "${CLEAN_PRIMARY_ROOT_BOUND}" -eq 0 || fail "create clean primary root already bound"
  assert_root_shape
  assert_worktree_separation
  local identity
  identity="$($PYTHON - "create clean primary root" "${CLEAN_PRIMARY_ROOT}" "${CLEAN_PRIMARY}" "$SOURCE" "$CLEAN_PRIMARY" "$CLEAN_PRIMARY_BOUND" <<'PY'

import os
import stat
import subprocess
import sys

label, root, child, source, clean, clean_bound = sys.argv[1:]
root = os.path.abspath(root)
child = os.path.abspath(child)
source = os.path.abspath(source)
clean = os.path.abspath(clean)
if os.path.realpath(root) != root or os.path.realpath(child) != child:
    raise SystemExit(f'{label} root/child path is not canonical')
if os.path.dirname(child) != root or os.path.basename(child) not in ('repository', 'replay'):
    raise SystemExit(f'{label} child is not an exact root child')
parent = os.path.dirname(root)
if os.path.realpath(parent) != parent:
    raise SystemExit(f'{label} parent is not canonical')

ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0', 'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}

def identity(st):
    return (str(st.st_dev), str(st.st_ino), str(st.st_uid),
            format(stat.S_IMODE(st.st_mode), '04o'), str(st.st_nlink))

def occupied(raw, repo, owner):
    if not isinstance(raw, str) or not raw or '\x00' in raw:
        raise SystemExit(f'{owner} registry has a malformed empty worktree path')
    absolute = raw if os.path.isabs(raw) else os.path.abspath(os.path.join(repo, raw))
    forms = tuple(dict.fromkeys((raw, absolute, os.path.normpath(absolute), os.path.realpath(absolute))))
    try:
        st = os.lstat(absolute)
    except FileNotFoundError:
        # Stale/prunable paths remain lexical occupancy evidence. They do not
        # need an lstat identity until they exist again.
        return forms, ('missing',)
    except OSError as exc:
        raise SystemExit(f'{owner} registered worktree lstat failed: {raw}: {exc}')
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or os.path.realpath(absolute) != absolute:
        raise SystemExit(f'{owner} registered worktree is not a canonical real directory: {raw}')
    return forms, ('present', *identity(st))

def parse_registry(output, owner, repo):
    # Each porcelain block must contain exactly one non-empty worktree path.
    # Locked, prunable, duplicate, and stale records are retained; malformed
    # blocks fail closed rather than becoming an unoccupied empty record.
    records = []
    block = []
    def finish(lines):
        if not lines:
            return
        paths = [line[9:] for line in lines if line.startswith('worktree ')]
        if any(line == 'worktree' for line in lines) or len(paths) != 1 or not paths[0]:
            raise SystemExit(f'{owner} registry block is malformed or ambiguous')
        raw = paths[0]
        forms, state = occupied(raw, repo, owner)
        records.append((raw, forms, state, tuple(lines)))
    for line in output.splitlines():
        if line == '':
            finish(block)
            block = []
        else:
            block.append(line)
    finish(block)
    return tuple(records)

def registry_snapshot():
    repos = [('source', source)]
    if clean_bound == '1':
        repos.append(('clean-primary', clean))
    rows = []
    for owner, repo in repos:
        output = subprocess.check_output([
            '/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks',
            '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', '-c', 'protocol.allow=never',
            'worktree', 'list', '--porcelain',
        ], env=ENV, text=True)
        rows.append((owner, output, parse_registry(output, owner, repo)))
    return tuple(rows)

def overlap(a, b):
    if a == b:
        return True
    if not os.path.isabs(a) or not os.path.isabs(b):
        return False
    try:
        return os.path.commonpath([a, b]) in (a, b)
    except ValueError:
        return False

def validate_registry(rows, candidate):
    candidate_forms = (candidate, os.path.realpath(candidate))
    for owner, _output, records in rows:
        repo = source if owner == 'source' else clean
        own_forms, _own_state = occupied(repo, repo, owner)
        own_forms = set(own_forms)
        for raw, entry_forms, _state, _lines in records:
            if set(entry_forms) & own_forms:
                continue
            if any(overlap(item, target) for item in entry_forms for target in candidate_forms):
                raise SystemExit(f'registered/nested worktree overlaps {candidate}: {raw}')

before_registry = registry_snapshot()
validate_registry(before_registry, root)
parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    parent_before = os.fstat(parent_fd)
    if not stat.S_ISDIR(parent_before.st_mode) or os.path.realpath(parent) != parent:
        raise SystemExit(f'{label} parent descriptor is unsafe')
    name = os.path.basename(root)
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise SystemExit(f'{label} root already exists')
    os.mkdir(name, 0o700, dir_fd=parent_fd)
    root_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        root_first = os.fstat(root_fd)
        if not stat.S_ISDIR(root_first.st_mode) or stat.S_IMODE(root_first.st_mode) != 0o700:
            raise SystemExit(f'{label} root descriptor is unsafe')
        os.mkdir(os.path.basename(child), 0o700, dir_fd=root_fd)
        child_fd = os.open(os.path.basename(child), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            child_stat = os.fstat(child_fd)
            if not stat.S_ISDIR(child_stat.st_mode) or stat.S_IMODE(child_stat.st_mode) != 0o700:
                raise SystemExit(f'{label} child descriptor is unsafe')
            root_after = os.fstat(root_fd)
            parent_after = os.fstat(parent_fd)
            root_final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            child_final = os.stat(os.path.basename(child), dir_fd=root_fd, follow_symlinks=False)
            os.fsync(root_fd)
            os.fsync(parent_fd)
        finally:
            os.close(child_fd)
    finally:
        os.close(root_fd)
finally:
    os.close(parent_fd)

def ident(st):
    return (str(st.st_dev), str(st.st_ino), str(st.st_uid), format(stat.S_IMODE(st.st_mode), '04o'), str(st.st_nlink))
if ident(parent_before) != ident(parent_after):
    raise SystemExit(f'{label} parent changed during root/child creation')
if ident(root_after) != ident(root_final) or ident(child_stat) != ident(child_final):
    raise SystemExit(f'{label} root/child final identity changed during creation')
after_registry = registry_snapshot()
if after_registry != before_registry:
    raise SystemExit(f'{label} registered worktree registry changed during root/child creation')
if os.path.realpath(root) != root or os.path.realpath(child) != child:
    raise SystemExit(f'{label} root/child became noncanonical')
print('\t'.join([root, *ident(parent_after), *ident(root_after), child, *ident(child_final)]))

PY
)"
  IFS=$'\t' read -r \
    CLEAN_PRIMARY_ROOT_REALPATH \
    CLEAN_PRIMARY_PARENT_DEVICE CLEAN_PRIMARY_PARENT_INODE CLEAN_PRIMARY_PARENT_UID CLEAN_PRIMARY_PARENT_MODE CLEAN_PRIMARY_PARENT_NLINK \
    CLEAN_PRIMARY_ROOT_DEVICE CLEAN_PRIMARY_ROOT_INODE CLEAN_PRIMARY_ROOT_UID CLEAN_PRIMARY_ROOT_MODE CLEAN_PRIMARY_ROOT_NLINK \
    CLEAN_PRIMARY_REPOSITORY_REALPATH CLEAN_PRIMARY_REPOSITORY_DEVICE CLEAN_PRIMARY_REPOSITORY_INODE CLEAN_PRIMARY_REPOSITORY_UID CLEAN_PRIMARY_REPOSITORY_MODE CLEAN_PRIMARY_REPOSITORY_NLINK <<< "$identity"
  test "${CLEAN_PRIMARY_ROOT_REALPATH}" = "${CLEAN_PRIMARY_ROOT}" || fail "create clean primary root canonical binding failed"
  test "${CLEAN_PRIMARY_REPOSITORY_REALPATH}" = "${CLEAN_PRIMARY}" || fail "create clean primary root child canonical binding failed"
  CLEAN_PRIMARY_ROOT_BOUND=1
  CLEAN_PRIMARY_REPOSITORY_BOUND=1
  CLEAN_PRIMARY_REPOSITORY_PRESENT=1
  assert_root_shape
  assert_worktree_separation
}



bind_clean_primary_identity() {
  test "$CLEAN_PRIMARY_ROOT_BOUND" -eq 1 || fail "clean-primary root is not bound"
  test "$CLEAN_PRIMARY_BOUND" -eq 0 || fail "clean-primary identity already bound"
  local git_dir common_dir objects fields
  assert_root_shape
  assert_worktree_separation
  git_dir="$(git_primary rev-parse --absolute-git-dir)"
  assert_root_shape
  assert_worktree_separation
  common_dir="$(git_primary rev-parse --git-common-dir)"
  assert_root_shape
  assert_worktree_separation
  objects="$(git_primary rev-parse --git-path objects)"
  assert_root_shape
  assert_worktree_separation
  fields="$($PYTHON - "$CLEAN_PRIMARY_ROOT" "$CLEAN_PRIMARY" "$SOURCE_OBJECTS" "$SOURCE_GIT_COMMON_DIR" "$git_dir" "$common_dir" "$objects" <<'PY'
import os
import stat
import sys
root, repo, source_objects, source_common, git_dir, common_dir, objects = sys.argv[1:]
def canonical(base, value):
    return os.path.realpath(value if os.path.isabs(value) else os.path.join(base, value))
def checked(path, label):
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or os.path.realpath(path) != path:
        raise SystemExit(label + ' is not a canonical non-symlink directory')
    return path, st
def values(st):
    return [str(st.st_dev), str(st.st_ino), str(st.st_uid), format(stat.S_IMODE(st.st_mode), '04o')]
root_path, root_st = checked(root, 'clean-primary root')
if stat.S_IMODE(root_st.st_mode) != 0o700:
    raise SystemExit('clean-primary root mode is not 0700')
repo_path, repo_st = checked(repo, 'clean-primary repository')
if repo_path == root_path or os.path.commonpath([repo_path, root_path]) != root_path:
    raise SystemExit('clean-primary repository escaped its root')
git_path, git_st = checked(canonical(repo, git_dir), 'clean-primary Git directory')
common_path, common_st = checked(canonical(repo, common_dir), 'clean-primary common directory')
objects_path, objects_st = checked(canonical(repo, objects), 'clean-primary object store')
if os.path.lexists(os.path.join(objects_path, 'info', 'alternates')):
    raise SystemExit('clean-primary has a mutable alternate')
if os.path.samefile(objects_path, source_objects) or os.path.samefile(common_path, source_common):
    raise SystemExit('clean-primary shares SOURCE storage')
print('\t'.join([repo_path, git_path, common_path, objects_path] + values(root_st) + values(repo_st) + values(git_st) + values(common_st) + values(objects_st)))
PY
)"
  IFS=$'\t' read -r CLEAN_PRIMARY_REALPATH CLEAN_PRIMARY_GIT_DIR CLEAN_PRIMARY_COMMON_DIR CLEAN_PRIMARY_OBJECTS \
    CLEAN_PRIMARY_ROOT_DEVICE CLEAN_PRIMARY_ROOT_INODE CLEAN_PRIMARY_ROOT_UID CLEAN_PRIMARY_ROOT_MODE \
    CLEAN_PRIMARY_DEVICE CLEAN_PRIMARY_INODE CLEAN_PRIMARY_UID CLEAN_PRIMARY_MODE CLEAN_PRIMARY_GIT_DEVICE CLEAN_PRIMARY_GIT_INODE CLEAN_PRIMARY_GIT_UID CLEAN_PRIMARY_GIT_MODE \
    CLEAN_PRIMARY_COMMON_DEVICE CLEAN_PRIMARY_COMMON_INODE CLEAN_PRIMARY_COMMON_UID CLEAN_PRIMARY_COMMON_MODE CLEAN_PRIMARY_OBJECTS_DEVICE CLEAN_PRIMARY_OBJECTS_INODE CLEAN_PRIMARY_OBJECTS_UID CLEAN_PRIMARY_OBJECTS_MODE <<< "$fields"
  CLEAN_PRIMARY_ROOT_REALPATH="$CLEAN_PRIMARY_ROOT"
  test "$CLEAN_PRIMARY_REALPATH" = "$CLEAN_PRIMARY" || fail "clean-primary canonical path was not bound"
  test "$CLEAN_PRIMARY_ROOT_REALPATH" = "$CLEAN_PRIMARY_ROOT" || fail "clean-primary root canonical path was not bound"
  CLEAN_PRIMARY_BOUND=1
  assert_clean_primary_identity
}

assert_clean_primary_storage_unshared() {
  "$PYTHON" - "$CLEAN_PRIMARY_OBJECTS" "$SOURCE_OBJECTS" <<'PY'
import os
import stat
import sys
objects, source_objects = sys.argv[1:]
objects = os.path.realpath(objects)
source_objects = os.path.realpath(source_objects)
if objects == source_objects or os.path.samefile(objects, source_objects):
    raise SystemExit('clean-primary object store shares SOURCE')
alternate = os.path.join(objects, 'info', 'alternates')
if os.path.lexists(alternate):
    raise SystemExit('clean-primary object store has objects/info/alternates')
regular_files = 0
for dirpath, dirnames, filenames in os.walk(objects, topdown=True, followlinks=False):
    dirnames[:] = sorted(dirnames)
    filenames.sort()
    for name in dirnames:
        path = os.path.join(dirpath, name)
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or os.path.realpath(path) != path:
            raise SystemExit('clean-primary object-store directory is not canonical')
    for name in filenames:
        path = os.path.join(dirpath, name)
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or os.path.realpath(path) != path:
            raise SystemExit('clean-primary object-store file is not a canonical regular file')
        if st.st_nlink != 1:
            raise SystemExit('clean-primary object-store file has a shared hardlink')
        regular_files += 1
if regular_files == 0:
    raise SystemExit('clean-primary object store contains no regular object files')
PY
}

assert_clean_primary_identity() {
  test "$CLEAN_PRIMARY_ROOT_BOUND" -eq 1 && test "$CLEAN_PRIMARY_BOUND" -eq 1 || fail "clean-primary identity is incomplete"
  local git_dir common_dir objects
  git_dir="$(git_primary rev-parse --absolute-git-dir)"
  common_dir="$(git_primary rev-parse --git-common-dir)"
  objects="$(git_primary rev-parse --git-path objects)"
  "$PYTHON" - "$CLEAN_PRIMARY_ROOT" "$CLEAN_PRIMARY" "$git_dir" "$common_dir" "$objects" "$SOURCE_OBJECTS" "$SOURCE_GIT_COMMON_DIR" \
    "$CLEAN_PRIMARY_ROOT_DEVICE" "$CLEAN_PRIMARY_ROOT_INODE" "$CLEAN_PRIMARY_ROOT_UID" "$CLEAN_PRIMARY_ROOT_MODE" "$CLEAN_PRIMARY_ROOT_REALPATH" \
    "$CLEAN_PRIMARY_REALPATH" "$CLEAN_PRIMARY_DEVICE" "$CLEAN_PRIMARY_INODE" "$CLEAN_PRIMARY_UID" "$CLEAN_PRIMARY_MODE" \
    "$CLEAN_PRIMARY_GIT_DIR" "$CLEAN_PRIMARY_GIT_DEVICE" "$CLEAN_PRIMARY_GIT_INODE" "$CLEAN_PRIMARY_GIT_UID" "$CLEAN_PRIMARY_GIT_MODE" \
    "$CLEAN_PRIMARY_COMMON_DIR" "$CLEAN_PRIMARY_COMMON_DEVICE" "$CLEAN_PRIMARY_COMMON_INODE" "$CLEAN_PRIMARY_COMMON_UID" "$CLEAN_PRIMARY_COMMON_MODE" \
    "$CLEAN_PRIMARY_OBJECTS" "$CLEAN_PRIMARY_OBJECTS_DEVICE" "$CLEAN_PRIMARY_OBJECTS_INODE" "$CLEAN_PRIMARY_OBJECTS_UID" "$CLEAN_PRIMARY_OBJECTS_MODE" <<'PY'
import os
import stat
import sys
(root, repo, git_dir, common_dir, objects, source_objects, source_common, root_dev, root_ino, root_uid, root_mode, root_real, repo_real, repo_dev, repo_ino, repo_uid, repo_mode, git_real, git_dev, git_ino, git_uid, git_mode, common_real, common_dev, common_ino, common_uid, common_mode, objects_real, objects_dev, objects_ino, objects_uid, objects_mode) = sys.argv[1:]
def canonical(base, value):
    return os.path.realpath(value if os.path.isabs(value) else os.path.join(base, value))
def check(path, expected, wanted, label, required_mode=None):
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or os.path.realpath(path) != expected or expected != path:
        raise SystemExit(label + ' path changed')
    actual = [str(st.st_dev), str(st.st_ino), str(st.st_uid), format(stat.S_IMODE(st.st_mode), '04o')]
    if actual != wanted:
        raise SystemExit(label + ' lstat identity changed')
    if required_mode is not None and stat.S_IMODE(st.st_mode) != required_mode:
        raise SystemExit(label + ' mode changed')
check(root, root_real, [root_dev, root_ino, root_uid, root_mode], 'clean-primary root', 0o700)
check(repo, repo_real, [repo_dev, repo_ino, repo_uid, repo_mode], 'clean-primary repository')
if repo == root or os.path.commonpath([repo, root]) != root:
    raise SystemExit('clean-primary repository escaped its root')
check(canonical(repo, git_dir), git_real, [git_dev, git_ino, git_uid, git_mode], 'clean-primary Git directory')
check(canonical(repo, common_dir), common_real, [common_dev, common_ino, common_uid, common_mode], 'clean-primary common directory')
check(canonical(repo, objects), objects_real, [objects_dev, objects_ino, objects_uid, objects_mode], 'clean-primary object store')
if os.path.lexists(os.path.join(objects_real, 'info', 'alternates')):
    raise SystemExit('clean-primary alternates appeared')
if os.path.samefile(objects_real, source_objects) or os.path.samefile(common_real, source_common):
    raise SystemExit('clean-primary storage became shared with SOURCE')
PY
  assert_clean_primary_storage_unshared
}

assert_clean_primary_state() {
  assert_source_binding
  assert_clean_primary_identity
  test "$(git_primary rev-parse --show-toplevel)" = "$CLEAN_PRIMARY" || fail "clean-primary top-level changed"
  test "$(git_primary rev-parse origin/dev)" = "$BASE" || fail "clean-primary origin/dev drifted"
  test "$(git_primary rev-parse origin/main)" = "$MAIN" || fail "clean-primary origin/main drifted"
  if git_primary symbolic-ref -q HEAD >/dev/null 2>&1; then fail "clean-primary HEAD is attached"; fi
  test "$(git_primary rev-parse HEAD)" = "$BASE" || fail "clean-primary HEAD drifted"
  test "$(git_primary rev-parse HEAD^{tree})" = "$BASE_TREE" || fail "clean-primary tree drifted"
  local whole_worktree_status
  whole_worktree_status="$(git_primary status --porcelain=v1 --untracked-files=all --ignored=traditional --ignore-submodules=none)"
  test -z "$whole_worktree_status" || fail "clean-primary whole worktree is not clean, including ignored/untracked files"
  test -z "$(git_primary ls-files --others --ignored --exclude-standard -z)" || fail "clean-primary has ignored descendants"
  git_primary diff --no-ext-diff --quiet
  git_primary diff --cached --no-ext-diff --quiet
}

before_clean_primary_mutation() {
  assert_root_shape
  assert_source_binding
  assert_worktree_separation
  if [ "$CLEAN_PRIMARY_BOUND" -eq 1 ]; then
    assert_clean_primary_identity
    assert_clean_primary_storage_unshared
  fi
}

assert_clean_primary_adversarial_smoke() {
  [ "$CLEAN_PRIMARY_SMOKE_DONE" -eq 0 ] || return 0
  "$PYTHON" <<'PY'
import os
import shutil
import stat
import tempfile
root = tempfile.mkdtemp(prefix='task409-clean-primary-smoke.', dir='/private/tmp')
def identity(path):
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or os.path.realpath(path) != path:
        raise RuntimeError('identity rejected')
    return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), path)
def require_reject(label, fn):
    try:
        result = fn()
    except Exception:
        return
    if result is False:
        return
    raise RuntimeError('smoke accepted '+label)
def storage_check(source, clean, repository):
    if os.path.lexists(os.path.join(clean, 'info', 'alternates')):
        raise RuntimeError('alternate accepted')
    if os.path.samefile(source, clean):
        raise RuntimeError('shared store accepted')
    if os.path.realpath(repository) == os.path.realpath(clean):
        raise RuntimeError('repository identity accepted')
def no_shared_hardlinks(objects):
    count = 0
    for dirpath, dirnames, filenames in os.walk(objects, topdown=True, followlinks=False):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode) or st.st_nlink != 1:
                return False
            if stat.S_ISREG(st.st_mode):
                count += 1
    return count > 0
try:
    preexisting = os.path.join(root, 'preexisting')
    os.mkdir(preexisting, 0o700)
    require_reject('preexisting path', lambda: os.mkdir(preexisting, 0o700))
    bound = os.path.join(root, 'bound')
    os.mkdir(bound, 0o700)
    expected = identity(bound)
    os.rename(bound, bound+'.real')
    os.symlink(bound+'.real', bound)
    require_reject('symlink substitution', lambda: identity(bound) == expected)
    os.unlink(bound)
    os.rename(bound+'.real', bound)
    source = os.path.join(root, 'source-objects')
    clean = os.path.join(root, 'clean-objects')
    repository = os.path.join(root, 'repository')
    os.mkdir(source, 0o700); os.mkdir(clean, 0o700); os.mkdir(repository, 0o700); os.mkdir(os.path.join(clean, 'info'), 0o700)
    alternate = os.path.join(clean, 'info', 'alternates')
    with open(alternate, 'w'):
        pass
    require_reject('alternates', lambda: storage_check(source, clean, repository))
    os.unlink(alternate)
    hardlink_store = os.path.join(root, 'hardlink-objects')
    os.mkdir(hardlink_store, 0o700)
    pack_dir = os.path.join(hardlink_store, 'pack')
    os.mkdir(pack_dir, 0o700)
    loose = os.path.join(hardlink_store, 'aa-loose-object')
    pack = os.path.join(pack_dir, 'sample.pack')
    index = os.path.join(pack_dir, 'sample.idx')
    for path in (loose, pack, index):
        with open(path, 'wb') as handle:
            handle.write(b'x')
        os.link(path, path + '.shared')
    require_reject('shared hardlinked object/pack/index file', lambda: no_shared_hardlinks(hardlink_store))
    shutil.rmtree(hardlink_store)
    shutil.rmtree(clean)
    os.symlink(source, clean)
    require_reject('shared object store', lambda: storage_check(source, clean, repository))
    os.unlink(clean); os.mkdir(clean, 0o700); os.mkdir(os.path.join(clean, 'info'), 0o700)
    bound_refs = {'dev': 'exact-dev', 'main': 'exact-main', 'tree': 'exact-tree'}
    source_refs = dict(bound_refs); source_refs['dev'] = 'drifted-dev'
    require_reject('source/ref drift', lambda: source_refs == bound_refs)
    clean_status = ['?? unknown']
    require_reject('dirty clean-primary', lambda: not clean_status)
    ignored_status = ['!! ignored']
    require_reject('ignored clean-primary artifact', lambda: not ignored_status)
    swapped = os.path.join(root, 'inode-swap')
    os.mkdir(swapped, 0o700); old = identity(swapped); os.rename(swapped, swapped+'.old'); os.mkdir(swapped, 0o700)
    require_reject('inode swap', lambda: identity(swapped) == old)
    os.chmod(swapped, 0o755); mode_bound = identity(swapped); os.chmod(swapped, 0o700)
    require_reject('mode swap', lambda: identity(swapped) == mode_bound)
    cleanup = os.path.join(root, 'cleanup'); os.mkdir(cleanup, 0o700); os.mkdir(os.path.join(cleanup, 'repository'), 0o700)
    with open(os.path.join(cleanup, 'unknown'), 'w'):
        pass
    require_reject('unknown cleanup artifact', lambda: set(os.listdir(cleanup)) == {'repository'})
finally:
    shutil.rmtree(root)
PY
  CLEAN_PRIMARY_SMOKE_DONE=1
}

bootstrap_clean_primary() {
  create_clean_primary_root
  before_clean_primary_mutation
  assert_source_binding
  assert_root_shape
  # The repository child was created through the held root descriptor. Git CLI
  # still accepts a pathname, so assert parent/root/child immediately before and after it.
  # --no-hardlinks copies objects into a distinct local object store; no network or mutable alternate is used.
  git_hermetic -c protocol.file.allow=always clone --no-local --no-hardlinks --no-checkout --no-tags "$SOURCE" "$CLEAN_PRIMARY" >/dev/null
  bind_clean_primary_identity
  assert_root_shape
  assert_worktree_separation
  before_clean_primary_mutation
  git_primary config --local core.hooksPath /dev/null
  before_clean_primary_mutation
  git_primary config --local protocol.allow never
  before_clean_primary_mutation
  git_primary config --local remote.origin.url "$SOURCE"
  before_clean_primary_mutation
  git_primary config --local remote.origin.fetch '+refs/heads/*:refs/remotes/origin/*'
  before_clean_primary_mutation
  git_primary update-ref --no-deref refs/remotes/origin/dev "$BASE"
  before_clean_primary_mutation
  git_primary update-ref --no-deref refs/remotes/origin/main "$MAIN"
  before_clean_primary_mutation
  git_primary update-ref --no-deref HEAD "$BASE"
  before_clean_primary_mutation
  assert_root_shape
  assert_worktree_separation
  git_primary checkout --detach --force "$BASE" >/dev/null
  assert_root_shape
  assert_worktree_separation
  assert_clean_primary_state
}

create_replay_root() {
  test "${REPLAY_ROOT_BOUND}" -eq 0 || fail "create replay root already bound"
  assert_root_shape
  assert_worktree_separation
  local identity
  identity="$($PYTHON - "create replay root" "${REPLAY_ROOT}" "${REPLAY}" "$SOURCE" "$CLEAN_PRIMARY" "$CLEAN_PRIMARY_BOUND" <<'PY'

import os
import stat
import subprocess
import sys

label, root, child, source, clean, clean_bound = sys.argv[1:]
root = os.path.abspath(root)
child = os.path.abspath(child)
source = os.path.abspath(source)
clean = os.path.abspath(clean)
if os.path.realpath(root) != root or os.path.realpath(child) != child:
    raise SystemExit(f'{label} root/child path is not canonical')
if os.path.dirname(child) != root or os.path.basename(child) not in ('repository', 'replay'):
    raise SystemExit(f'{label} child is not an exact root child')
parent = os.path.dirname(root)
if os.path.realpath(parent) != parent:
    raise SystemExit(f'{label} parent is not canonical')

ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0', 'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}

def identity(st):
    return (str(st.st_dev), str(st.st_ino), str(st.st_uid),
            format(stat.S_IMODE(st.st_mode), '04o'), str(st.st_nlink))

def occupied(raw, repo, owner):
    if not isinstance(raw, str) or not raw or '\x00' in raw:
        raise SystemExit(f'{owner} registry has a malformed empty worktree path')
    absolute = raw if os.path.isabs(raw) else os.path.abspath(os.path.join(repo, raw))
    forms = tuple(dict.fromkeys((raw, absolute, os.path.normpath(absolute), os.path.realpath(absolute))))
    try:
        st = os.lstat(absolute)
    except FileNotFoundError:
        # Stale/prunable paths remain lexical occupancy evidence. They do not
        # need an lstat identity until they exist again.
        return forms, ('missing',)
    except OSError as exc:
        raise SystemExit(f'{owner} registered worktree lstat failed: {raw}: {exc}')
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or os.path.realpath(absolute) != absolute:
        raise SystemExit(f'{owner} registered worktree is not a canonical real directory: {raw}')
    return forms, ('present', *identity(st))

def parse_registry(output, owner, repo):
    # Each porcelain block must contain exactly one non-empty worktree path.
    # Locked, prunable, duplicate, and stale records are retained; malformed
    # blocks fail closed rather than becoming an unoccupied empty record.
    records = []
    block = []
    def finish(lines):
        if not lines:
            return
        paths = [line[9:] for line in lines if line.startswith('worktree ')]
        if any(line == 'worktree' for line in lines) or len(paths) != 1 or not paths[0]:
            raise SystemExit(f'{owner} registry block is malformed or ambiguous')
        raw = paths[0]
        forms, state = occupied(raw, repo, owner)
        records.append((raw, forms, state, tuple(lines)))
    for line in output.splitlines():
        if line == '':
            finish(block)
            block = []
        else:
            block.append(line)
    finish(block)
    return tuple(records)

def registry_snapshot():
    repos = [('source', source)]
    if clean_bound == '1':
        repos.append(('clean-primary', clean))
    rows = []
    for owner, repo in repos:
        output = subprocess.check_output([
            '/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks',
            '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', '-c', 'protocol.allow=never',
            'worktree', 'list', '--porcelain',
        ], env=ENV, text=True)
        rows.append((owner, output, parse_registry(output, owner, repo)))
    return tuple(rows)

def overlap(a, b):
    if a == b:
        return True
    if not os.path.isabs(a) or not os.path.isabs(b):
        return False
    try:
        return os.path.commonpath([a, b]) in (a, b)
    except ValueError:
        return False

def validate_registry(rows, candidate):
    candidate_forms = (candidate, os.path.realpath(candidate))
    for owner, _output, records in rows:
        repo = source if owner == 'source' else clean
        own_forms, _own_state = occupied(repo, repo, owner)
        own_forms = set(own_forms)
        for raw, entry_forms, _state, _lines in records:
            if set(entry_forms) & own_forms:
                continue
            if any(overlap(item, target) for item in entry_forms for target in candidate_forms):
                raise SystemExit(f'registered/nested worktree overlaps {candidate}: {raw}')

before_registry = registry_snapshot()
validate_registry(before_registry, root)
parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    parent_before = os.fstat(parent_fd)
    if not stat.S_ISDIR(parent_before.st_mode) or os.path.realpath(parent) != parent:
        raise SystemExit(f'{label} parent descriptor is unsafe')
    name = os.path.basename(root)
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise SystemExit(f'{label} root already exists')
    os.mkdir(name, 0o700, dir_fd=parent_fd)
    root_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        root_first = os.fstat(root_fd)
        if not stat.S_ISDIR(root_first.st_mode) or stat.S_IMODE(root_first.st_mode) != 0o700:
            raise SystemExit(f'{label} root descriptor is unsafe')
        os.mkdir(os.path.basename(child), 0o700, dir_fd=root_fd)
        child_fd = os.open(os.path.basename(child), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            child_stat = os.fstat(child_fd)
            if not stat.S_ISDIR(child_stat.st_mode) or stat.S_IMODE(child_stat.st_mode) != 0o700:
                raise SystemExit(f'{label} child descriptor is unsafe')
            root_after = os.fstat(root_fd)
            parent_after = os.fstat(parent_fd)
            root_final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            child_final = os.stat(os.path.basename(child), dir_fd=root_fd, follow_symlinks=False)
            os.fsync(root_fd)
            os.fsync(parent_fd)
        finally:
            os.close(child_fd)
    finally:
        os.close(root_fd)
finally:
    os.close(parent_fd)

def ident(st):
    return (str(st.st_dev), str(st.st_ino), str(st.st_uid), format(stat.S_IMODE(st.st_mode), '04o'), str(st.st_nlink))
if ident(parent_before) != ident(parent_after):
    raise SystemExit(f'{label} parent changed during root/child creation')
if ident(root_after) != ident(root_final) or ident(child_stat) != ident(child_final):
    raise SystemExit(f'{label} root/child final identity changed during creation')
after_registry = registry_snapshot()
if after_registry != before_registry:
    raise SystemExit(f'{label} registered worktree registry changed during root/child creation')
if os.path.realpath(root) != root or os.path.realpath(child) != child:
    raise SystemExit(f'{label} root/child became noncanonical')
print('\t'.join([root, *ident(parent_after), *ident(root_after), child, *ident(child_final)]))

PY
)"
  IFS=$'\t' read -r \
    REPLAY_ROOT_REALPATH \
    REPLAY_PARENT_DEVICE REPLAY_PARENT_INODE REPLAY_PARENT_UID REPLAY_PARENT_MODE REPLAY_PARENT_NLINK \
    REPLAY_ROOT_DEVICE REPLAY_ROOT_INODE REPLAY_ROOT_UID REPLAY_ROOT_MODE REPLAY_ROOT_NLINK \
    REPLAY_CHECKOUT_REALPATH REPLAY_CHECKOUT_DEVICE REPLAY_CHECKOUT_INODE REPLAY_CHECKOUT_UID REPLAY_CHECKOUT_MODE REPLAY_CHECKOUT_NLINK <<< "$identity"
  test "${REPLAY_ROOT_REALPATH}" = "${REPLAY_ROOT}" || fail "create replay root canonical binding failed"
  test "${REPLAY_CHECKOUT_REALPATH}" = "${REPLAY}" || fail "create replay root child canonical binding failed"
  REPLAY_ROOT_BOUND=1
  REPLAY_CHECKOUT_BOUND=1
  REPLAY_CHECKOUT_PRESENT=1
  assert_root_shape
  assert_worktree_separation
}




bind_matrix_snapshot() {
  test "$REPLAY_ROOT_BOUND" -eq 1 || fail "matrix snapshot requires a bound replay root"
  test "$MATRIX_BOUND" -eq 0 || fail "matrix snapshot was already bound"
  local identity
  identity="$("$PYTHON" - "$MATRIX_SOURCE" "$MATRIX_SNAPSHOT" "$MATRIX_EXPECTED_BINDING_SHA256" <<'PY'
import os
import stat

def read_stable_file(path, label='file'):
    path = os.fspath(path)
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_size, st.st_nlink)

    def parent_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_nlink)

    # Bind the expected parent before opening it by pathname. A canonical
    # directory can still be swapped for another canonical directory between
    # realpath/lstat and open; comparing the pre-open lstat with the held
    # descriptor prevents that substitution from redirecting the child read.
    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            second = os.fstat(fd)
            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent identity changed while reading')
    if file_identity(first) != file_identity(second) or file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return b''.join(chunks), first

import hashlib
import json
import os
import re
import stat
import sys
source, snapshot, expected = sys.argv[1:]
if not hasattr(os, 'O_NOFOLLOW'):
    raise SystemExit('secure no-follow support is unavailable')
if not re.fullmatch(r'[0-9a-f]{64}', expected):
    raise SystemExit('matrix identity token is not a SHA-256 value')
def normalized_sha(raw):
    normalized = raw.replace(expected.encode('ascii'), b'0' * 64)
    for key in (b'"shell_sha256": "', b'"driver_shell_sha256": "', b'"expected_body_sha256": "'):
        normalized = re.sub(re.escape(key) + rb'[0-9a-f]{64}(?=")', lambda match: match.group(0)[:len(key)] + b'0' * 64, normalized)
    return hashlib.sha256(normalized).hexdigest()
raw, source_stat = read_stable_file(source, 'matrix source')
if normalized_sha(raw) != expected:
    raise SystemExit('matrix source normalized SHA-256 mismatch')
try:
    json.loads(raw.decode('utf-8'))
except Exception as exc:
    raise SystemExit(f'matrix source JSON parse failed: {exc}')
try:
    snapshot_fd = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
except FileExistsError:
    raise SystemExit(f'matrix snapshot already exists: {snapshot}')
try:
    view = memoryview(raw)
    written = 0
    while written < len(raw):
        written += os.write(snapshot_fd, view[written:])
    os.fsync(snapshot_fd)
finally:
    os.close(snapshot_fd)
snapshot_stat = os.lstat(snapshot)
if stat.S_ISLNK(snapshot_stat.st_mode) or not stat.S_ISREG(snapshot_stat.st_mode):
    raise SystemExit('matrix snapshot is not a regular file')
if stat.S_IMODE(snapshot_stat.st_mode) != 0o600:
    raise SystemExit('matrix snapshot mode is not 0600')
if snapshot_stat.st_size != len(raw):
    raise SystemExit('matrix snapshot size mismatch after write')
if os.path.realpath(snapshot) != snapshot:
    raise SystemExit('matrix snapshot canonical path changed')
reread, reread_stat = read_stable_file(snapshot, 'matrix snapshot')
if reread != raw:
    raise SystemExit('matrix snapshot bytes differ from the single source read')
if (reread_stat.st_dev, reread_stat.st_ino, reread_stat.st_size) != (snapshot_stat.st_dev, snapshot_stat.st_ino, snapshot_stat.st_size):
    raise SystemExit('matrix snapshot descriptor identity changed')
if normalized_sha(reread) != expected:
    raise SystemExit('matrix snapshot normalized SHA-256 mismatch after reopen')
print(f'{snapshot_stat.st_dev}\t{snapshot_stat.st_ino}\t{snapshot_stat.st_size}\t{os.path.realpath(snapshot)}')
PY
)"
  IFS=$'\t' read -r MATRIX_SNAPSHOT_DEVICE MATRIX_SNAPSHOT_INODE MATRIX_SNAPSHOT_SIZE MATRIX_SNAPSHOT_REALPATH <<< "$identity"
  test -n "$MATRIX_SNAPSHOT_DEVICE" && test -n "$MATRIX_SNAPSHOT_INODE" && test -n "$MATRIX_SNAPSHOT_SIZE" || fail "matrix snapshot identity was not captured"
  test "$MATRIX_SNAPSHOT_REALPATH" = "$MATRIX_SNAPSHOT" || fail "matrix snapshot canonical identity was not captured"
  MATRIX="$MATRIX_SNAPSHOT"
  MATRIX_BOUND=1
  assert_matrix_identity
}

assert_bash32_array_smoke() {
  [ "$BASH_ARRAY_SMOKE_DONE" -eq 0 ] || return 0
  # Save and restore only when the declared array has elements. Bash 3.2 nounset
  # rejects an empty/unset indexed-array expansion even when it is quoted.
  local saved_dirty=() item count saved_count
  saved_count=${#DIRTY_PATHS[@]}
  if [ "$saved_count" -gt 0 ]; then
    saved_dirty=("${DIRTY_PATHS[@]}")
  fi
  DIRTY_PATHS=()
  count=0
  if [ "${#DIRTY_PATHS[@]}" -gt 0 ]; then
    for item in "${DIRTY_PATHS[@]}"; do
      count=$((count + 1))
    done
  fi
  test "$count" -eq 0 || fail "empty DIRTY_PATHS smoke case yielded an element"
  test "${#DIRTY_PATHS[@]}" -eq 0 || fail "empty DIRTY_PATHS smoke length changed"
  add_dirty_path 'task409-smoke/one path'
  test "${#DIRTY_PATHS[@]}" -eq 1 || fail "single DIRTY_PATHS smoke path was not added"
  add_dirty_path 'task409-smoke/one path'
  test "${#DIRTY_PATHS[@]}" -eq 1 || fail "duplicate DIRTY_PATHS smoke path was added twice"
  DIRTY_PATHS=('task409-smoke/one path' 'task409-smoke/two')
  count=0
  if [ "${#DIRTY_PATHS[@]}" -gt 0 ]; then
    for item in "${DIRTY_PATHS[@]}"; do
      case "$item" in
        'task409-smoke/one path'|'task409-smoke/two') count=$((count + 1)) ;;
        *) fail "non-empty DIRTY_PATHS smoke path was altered: $item" ;;
      esac
    done
  fi
  test "$count" -eq 2 || fail "non-empty DIRTY_PATHS smoke case lost a path"
  DIRTY_PATHS=()
  if [ "${#saved_dirty[@]}" -gt 0 ]; then
    DIRTY_PATHS=("${saved_dirty[@]}")
  fi
  test "${#DIRTY_PATHS[@]}" -eq "$saved_count" || fail "DIRTY_PATHS smoke save/restore cardinality changed"
  BASH_ARRAY_SMOKE_DONE=1
}

assert_replay_closure() {
  # Closure is checked after replay bootstrap and again immediately before
  # cleanup. The replay alternate is intentional, but only its exact bound
  # clean-primary object store is allowed; HTTP, replacement, promisor, partial,
  # helper, shallow, and graft metadata remain forbidden.
  "$PYTHON" - "$REPLAY" "$CLEAN_PRIMARY_OBJECTS" "$MATRIX" "$CURRENT_HEAD" <<'PY'
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

repo, clean_objects, matrix, expected_head = sys.argv[1:]
ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
    'GIT_CONFIG_SYSTEM': '/dev/null', 'GIT_TERMINAL_PROMPT': '0',
    'GIT_OPTIONAL_LOCKS': '0', 'GIT_NO_REPLACE_OBJECTS': '1',
    'GIT_NO_LAZY_FETCH': '1',
}

def run(*args, check=True):
    command = [
        '/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch',
        '--no-optional-locks', '-C', repo,
        '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never',
        *args,
    ]
    process = subprocess.run(
        command, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False,
    )
    if check and process.returncode:
        raise SystemExit(f'Git replay closure command failed: {args!r}')
    return process

def out(*args):
    process = run(*args)
    return process.stdout.decode('utf-8', errors='strict').strip()

def identity(st):
    return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_size, st.st_nlink)

def require_regular(path, label):
    st = os.lstat(path)
    if (stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode)
            or st.st_nlink != 1 or os.path.realpath(path) != path):
        raise SystemExit(f'{label} is not a canonical regular single-link file')
    return st

if out('rev-parse', '--show-object-format') != 'sha1':
    raise SystemExit('replay repository object format is not SHA-1')
if out('rev-parse', '--is-shallow-repository') != 'false':
    raise SystemExit('replay repository is shallow')
if expected_head and out('rev-parse', 'HEAD') != expected_head:
    raise SystemExit('replay HEAD changed during closure check')
repo = os.path.realpath(repo)
git_dir = os.path.realpath(out('rev-parse', '--absolute-git-dir'))
if git_dir != os.path.join(repo, '.git'):
    raise SystemExit('replay Git directory is external or noncanonical')
common_dir = out('rev-parse', '--git-common-dir')
common_dir = os.path.realpath(common_dir if os.path.isabs(common_dir) else os.path.join(repo, common_dir))
if common_dir != git_dir or os.path.lexists(os.path.join(git_dir, 'commondir')):
    raise SystemExit('replay common directory is external or indirect')
objects = os.path.realpath(out('rev-parse', '--git-path', 'objects'))
if objects != os.path.join(git_dir, 'objects'):
    raise SystemExit('replay object store is external or noncanonical')
for path in (
    os.path.join(git_dir, 'shallow'),
    os.path.join(git_dir, 'info', 'grafts'),
    os.path.join(git_dir, 'refs', 'replace'),
    os.path.join(objects, 'info', 'http-alternates'),
):
    if os.path.lexists(path):
        raise SystemExit(f'forbidden replay metadata exists: {path}')
packed_refs = os.path.join(git_dir, 'packed-refs')
if os.path.lexists(packed_refs):
    packed_st = require_regular(packed_refs, 'replay packed-refs')
    if b'refs/replace/' in Path(packed_refs).read_bytes():
        raise SystemExit('packed replacement refs are forbidden')
pack_dir = os.path.join(objects, 'pack')
if os.path.lexists(pack_dir) and (os.path.islink(pack_dir)
        or not os.path.isdir(pack_dir) or os.path.realpath(pack_dir) != pack_dir):
    raise SystemExit('replay pack directory is not canonical')
if os.path.isdir(pack_dir):
    for directory, names, files in os.walk(pack_dir, topdown=True, followlinks=False):
        names[:] = sorted(names)
        files.sort()
        if any(os.path.islink(os.path.join(directory, name)) for name in names):
            raise SystemExit('replay pack directory contains a symlink')
        if any(name.endswith('.promisor') for name in files):
            raise SystemExit('replay promisor pack metadata is forbidden')

alternate = os.path.join(objects, 'info', 'alternates')
alt_st = require_regular(alternate, 'replay alternates')
fd = os.open(alternate, os.O_RDONLY | os.O_NOFOLLOW)
try:
    first = os.fstat(fd)
    chunks = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    second = os.fstat(fd)
finally:
    os.close(fd)
final = os.stat(alternate, follow_symlinks=False)
if identity(first) != identity(second) or identity(first) != identity(final):
    raise SystemExit('replay alternates changed during closure check')
expected_alternate = (os.path.realpath(clean_objects) + '\\n').encode('utf-8')
if b''.join(chunks) != expected_alternate:
    raise SystemExit('replay alternates are not the exact clean-primary object store')

config = run(
    'config', '--local', '--get-regexp',
    r'^(extensions\.partialClone|remote\..*|protocol\..*\.allow)$',
    check=False,
)
for line in config.stdout.decode('utf-8', errors='strict').splitlines():
    key, _, value = line.partition(' ')
    lowered = key.lower()
    if lowered == 'extensions.partialclone' or lowered.startswith('remote.'):
        raise SystemExit('partial-clone, promisor, remote-helper, or remote transport configuration is forbidden')
    if lowered.startswith('protocol.') and value.strip().lower() not in ('never', ''):
        raise SystemExit('unsafe protocol transport policy is forbidden')

fsck = run('fsck', '--full', '--strict', '--no-reflogs', '--no-progress', check=False)
if fsck.returncode != 0:
    raise SystemExit('strict replay fsck failed')
missing = run('rev-list', '--objects', '--all', '--missing=error', check=False)
if missing.returncode != 0:
    raise SystemExit('replay object closure is incomplete')

expected_by_key = {
    'commit': 'commit', 'parent': 'commit', 'parents': 'commit',
    'child': 'commit', 'tree': 'tree', 'blob': 'blob',
}
object_ids = {}
def collect(node, key=None):
    if isinstance(node, dict):
        for child_key, child in node.items():
            collect(child, child_key)
    elif isinstance(node, list):
        for child in node:
            collect(child, key)
    elif isinstance(node, str) and re.fullmatch(r'[0-9a-f]{40}', node) and key in expected_by_key:
        object_ids[node] = expected_by_key[key]

data = json.loads(Path(matrix).read_bytes())
collect(data)
for object_id, expected_type in sorted(object_ids.items()):
    actual = out('cat-file', '-t', object_id)
    if actual != expected_type:
        raise SystemExit(f'explicit replay object type mismatch: {object_id}: {actual} != {expected_type}')
PY
}

assert_tools() {
  for tool in "$GIT" "$PYTHON" "$BASH" "$ENV" "$MKDIR" "$RM" "$RMDIR" "$CUT" "$SHASUM"; do
    test -x "$tool" || fail "trusted executable unavailable: $tool"
  done
  test "$(git_hermetic --version | "$CUT" -d' ' -f1)" = git || fail "unexpected Git executable"
  local bash_version
  bash_version="$("$BASH" -c 'printf "%s" "$BASH_VERSION"')"
  case "$bash_version" in 3.2.*|4.*|5.*) ;; *) fail "unsupported trusted Bash version: $bash_version" ;; esac
  assert_bash32_array_smoke
  assert_clean_primary_adversarial_smoke
}


assert_root_shape() {
  case "$CLEAN_PRIMARY_ROOT" in /private/tmp/hermternal-task409-final-clean-primary.[0-9]*) ;; *) fail "invalid clean-primary root: $CLEAN_PRIMARY_ROOT" ;; esac
  case "$REPLAY_ROOT" in /private/tmp/hermternal-task409-final-replay.[0-9]*) ;; *) fail "invalid replay root: $REPLAY_ROOT" ;; esac
  test "$CLEAN_PRIMARY" = "$CLEAN_PRIMARY_ROOT/repository" || fail "clean-primary repository escaped its root"
  test "$REPLAY" = "$REPLAY_ROOT/replay" || fail "replay checkout escaped its root"
  "$PYTHON" - "$SOURCE" "$CLEAN_PRIMARY_ROOT" "$CLEAN_PRIMARY" "$REPLAY_ROOT" "$REPLAY" "$CLEAN_PRIMARY_ROOT_BOUND" "$CLEAN_PRIMARY_REPOSITORY_BOUND" "$CLEAN_PRIMARY_BOUND" "$REPLAY_ROOT_BOUND" "$REPLAY_CHECKOUT_BOUND" "$REPLAY_CHECKOUT_PRESENT" "$REPLAY_GIT_BOUND" "$CLEAN_PRIMARY_PARENT_DEVICE" "$CLEAN_PRIMARY_PARENT_INODE" "$CLEAN_PRIMARY_PARENT_UID" "$CLEAN_PRIMARY_PARENT_MODE" "$CLEAN_PRIMARY_PARENT_NLINK" "$CLEAN_PRIMARY_ROOT_DEVICE" "$CLEAN_PRIMARY_ROOT_INODE" "$CLEAN_PRIMARY_ROOT_UID" "$CLEAN_PRIMARY_ROOT_MODE" "$CLEAN_PRIMARY_ROOT_NLINK" "$CLEAN_PRIMARY_ROOT_REALPATH" "$CLEAN_PRIMARY_REPOSITORY_DEVICE" "$CLEAN_PRIMARY_REPOSITORY_INODE" "$CLEAN_PRIMARY_REPOSITORY_UID" "$CLEAN_PRIMARY_REPOSITORY_MODE" "$CLEAN_PRIMARY_REPOSITORY_NLINK" "$REPLAY_PARENT_DEVICE" "$REPLAY_PARENT_INODE" "$REPLAY_PARENT_UID" "$REPLAY_PARENT_MODE" "$REPLAY_PARENT_NLINK" "$REPLAY_ROOT_DEVICE" "$REPLAY_ROOT_INODE" "$REPLAY_ROOT_UID" "$REPLAY_ROOT_MODE" "$REPLAY_ROOT_NLINK" "$REPLAY_ROOT_REALPATH" "$REPLAY_CHECKOUT_DEVICE" "$REPLAY_CHECKOUT_INODE" "$REPLAY_CHECKOUT_UID" "$REPLAY_CHECKOUT_MODE" "$REPLAY_CHECKOUT_NLINK" <<'PY'
import os
import stat
import sys
(values) = sys.argv[1:]
(source, clean_root, clean_repo, replay_root, replay_repo, clean_root_bound, clean_child_bound, clean_bound, replay_root_bound, replay_child_bound, replay_child_present, replay_git_bound, *rest) = values
idx = 0
def take(n):
    global idx
    value = rest[idx:idx+n]; idx += n
    return value
clean_parent = take(5); clean_root_id = take(5); clean_child = take(5)
replay_parent = take(5); replay_root_id = take(5); replay_child = take(5)
def overlaps(a, b):
    try:
        return a == b or os.path.commonpath([a, b]) in (a, b)
    except ValueError:
        return False
def verify(path, expected, wanted, label, required_mode=None, allow_nlink_growth=True):
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or os.path.realpath(path) != expected or expected != path:
        raise SystemExit(label + ' path changed')
    actual = [str(st.st_dev), str(st.st_ino), str(st.st_uid), format(stat.S_IMODE(st.st_mode), '04o'), str(st.st_nlink)]
    if actual[:4] != wanted[:4] or (not allow_nlink_growth and actual[4] != wanted[4]) or (allow_nlink_growth and int(actual[4]) < int(wanted[4])):
        raise SystemExit(label + ' identity changed')
    if required_mode is not None and stat.S_IMODE(st.st_mode) != required_mode:
        raise SystemExit(label + ' mode changed')
def verify_parent(path, wanted, label):
    verify(path, path, wanted, label, allow_nlink_growth=True)
source_real = os.path.realpath(source)
if source_real != source:
    raise SystemExit('SOURCE path is not canonical')
for candidate, label in ((clean_root, 'clean-primary'), (replay_root, 'replay')):
    parent = os.path.dirname(candidate)
    parent_st = os.lstat(parent)
    if stat.S_ISLNK(parent_st.st_mode) or not stat.S_ISDIR(parent_st.st_mode) or os.path.realpath(parent) != parent:
        raise SystemExit(label + ' parent is not canonical')
if clean_root_bound == '0':
    if os.path.lexists(clean_root) or os.path.lexists(clean_repo):
        raise SystemExit('unbound clean-primary path exists')
else:
    verify_parent(os.path.dirname(clean_root), clean_parent, 'clean-primary parent')
    verify(clean_root, clean_root, clean_root_id, 'clean-primary root', 0o700)
    if clean_child_bound != '1':
        raise SystemExit('clean-primary root is bound without its child descriptor')
    verify(clean_repo, clean_repo, clean_child, 'clean-primary repository')
if replay_root_bound == '0':
    if os.path.lexists(replay_root) or os.path.lexists(replay_repo):
        raise SystemExit('unbound replay root exists')
else:
    verify_parent(os.path.dirname(replay_root), replay_parent, 'replay parent')
    verify(replay_root, replay_root, replay_root_id, 'replay root', 0o700)
    if replay_child_present == '0':
        if os.path.lexists(replay_repo):
            raise SystemExit('removed replay checkout still exists')
    else:
        if replay_child_bound != '1':
            raise SystemExit('replay root is present without its child descriptor')
        verify(replay_repo, replay_repo, replay_child, 'replay checkout')
clean_real = os.path.realpath(clean_root)
replay_real = os.path.realpath(replay_root)
if overlaps(source_real, clean_real) or overlaps(source_real, replay_real) or overlaps(clean_real, replay_real):
    raise SystemExit('repository/root paths overlap')
PY
}


assert_matrix_identity() {
  if [ "$MATRIX_BOUND" -eq 0 ]; then
    test "$MATRIX" = "$MATRIX_SOURCE" || fail "unbound matrix path changed"
    test "$MATRIX_SOURCE_VALIDATED" -eq 1 || fail "matrix source was not validated before root creation"
    return 0
  fi
  test "$MATRIX_BOUND" -eq 1 || fail "invalid matrix binding state"
  test "$MATRIX" = "$MATRIX_SNAPSHOT" || fail "matrix path escaped immutable snapshot"
  "$PYTHON" - "$MATRIX" "$MATRIX_EXPECTED_BINDING_SHA256" "$MATRIX_SNAPSHOT_DEVICE" "$MATRIX_SNAPSHOT_INODE" "$MATRIX_SNAPSHOT_SIZE" "$MATRIX_SNAPSHOT_REALPATH" <<'PY'
import os
import stat

def read_stable_file(path, label='file'):
    path = os.fspath(path)
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_size, st.st_nlink)

    def parent_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_nlink)

    # Bind the expected parent before opening it by pathname. A canonical
    # directory can still be swapped for another canonical directory between
    # realpath/lstat and open; comparing the pre-open lstat with the held
    # descriptor prevents that substitution from redirecting the child read.
    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            second = os.fstat(fd)
            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent identity changed while reading')
    if file_identity(first) != file_identity(second) or file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return b''.join(chunks), first

import hashlib
import json
import os
import re
import stat
import sys
path, expected, expected_device, expected_inode, expected_size, expected_realpath = sys.argv[1:]
if not hasattr(os, 'O_NOFOLLOW'):
    raise SystemExit('secure no-follow open is unavailable')
if not re.fullmatch(r'[0-9a-f]{64}', expected):
    raise SystemExit('matrix identity token is not a SHA-256 value')
raw, first = read_stable_file(path, 'matrix snapshot')
path_stat = os.lstat(path)
if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISREG(path_stat.st_mode):
    raise SystemExit('matrix snapshot path is not a regular non-symlink file')
if (path_stat.st_dev, path_stat.st_ino, path_stat.st_size) != (first.st_dev, first.st_ino, first.st_size):
    raise SystemExit('matrix snapshot path identity changed')
if (str(first.st_dev), str(first.st_ino), str(first.st_size)) != (expected_device, expected_inode, expected_size):
    raise SystemExit('matrix snapshot device/inode/size binding changed')
if os.path.realpath(path) != expected_realpath or expected_realpath != path:
    raise SystemExit('matrix snapshot canonical path changed')
token = expected.encode('ascii')
normalized = raw.replace(token, b'0' * 64)
for key in (b'"shell_sha256": "', b'"driver_shell_sha256": "', b'"expected_body_sha256": "'):
    normalized = re.sub(re.escape(key) + rb'[0-9a-f]{64}(?=")', lambda match: match.group(0)[:len(key)] + b'0' * 64, normalized)
if hashlib.sha256(normalized).hexdigest() != expected:
    raise SystemExit('matrix snapshot normalized SHA-256 mismatch')
try:
    json.loads(raw.decode('utf-8'))
except Exception as exc:
    raise SystemExit(f'matrix snapshot JSON parse failed: {exc}')
PY
}


assert_worktree_separation() {
  # Git has no compatible advisory lock for its common-dir worktree registry.
  # Therefore each scan is operation-adjacent and fails closed on registry/root
  # changes; stale unrelated records are retained as occupancy evidence and are
  # ignored only after raw and canonical forms prove no candidate overlap.
  "$PYTHON" - "$SOURCE" "$CLEAN_PRIMARY" "$REPLAY" "$CLEAN_PRIMARY_ROOT" "$REPLAY_ROOT" "$CLEAN_PRIMARY_BOUND" "$REPLAY_ROOT_BOUND" "$CLEAN_PRIMARY_REPOSITORY_BOUND" "$REPLAY_CHECKOUT_BOUND" "$REPLAY_CHECKOUT_PRESENT" "$REPLAY_GIT_BOUND" <<'PY'
import os
import stat
import subprocess
import sys

ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0', 'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}
source, clean, replay, clean_root, replay_root, clean_bound, replay_root_bound, clean_child_bound, replay_child_bound, replay_child_present, replay_git_bound = sys.argv[1:]
repos = [('source', source)]
if clean_bound == '1':
    repos.append(('clean-primary', clean))
if replay_root_bound == '1' and replay_child_present == '1' and replay_git_bound == '1' and os.path.isdir(replay) and not os.path.islink(replay):
    repos.append(('replay', replay))
candidate_roots = [('clean-primary-root', clean_root), ('replay-root', replay_root)]
repo_by_owner = {'source': source, 'clean-primary': clean, 'replay': replay}

def root_state(path, label):
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} candidate is not canonical: {path}')
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return (path, 'absent')
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise SystemExit(f'{label} candidate is not a real directory: {path}')
    return (path, 'present', str(st.st_dev), str(st.st_ino), str(st.st_uid), format(stat.S_IMODE(st.st_mode), '04o'))

def root_snapshot():
    return tuple((label, root_state(path, label)) for label, path in candidate_roots)

def overlap(a, b):
    if a == b:
        return True
    if not os.path.isabs(a) or not os.path.isabs(b):
        return False
    try:
        return os.path.commonpath([a, b]) in (a, b)
    except ValueError:
        return False

def identity(st):
    return (str(st.st_dev), str(st.st_ino), str(st.st_uid),
            format(stat.S_IMODE(st.st_mode), '04o'), str(st.st_nlink))

def occupied_forms(raw, repo, owner):
    if not isinstance(raw, str) or not raw or '\x00' in raw:
        raise SystemExit(f'{owner} registry block has a malformed empty worktree path')
    absolute = raw if os.path.isabs(raw) else os.path.abspath(os.path.join(repo, raw))
    forms = tuple(dict.fromkeys((raw, absolute, os.path.normpath(absolute), os.path.realpath(absolute))))
    try:
        st = os.lstat(absolute)
    except FileNotFoundError:
        return forms, ('missing',)
    except OSError as exc:
        raise SystemExit(f'{owner} registered worktree lstat failed: {raw}: {exc}')
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or os.path.realpath(absolute) != absolute:
        raise SystemExit(f'{owner} registered worktree is not a canonical real directory: {raw}')
    return forms, ('present', *identity(st))

def parse_records(output, owner, repo):
    rows, block = [], []
    def finish(lines):
        if not lines:
            return
        paths = [line[9:] for line in lines if line.startswith('worktree ')]
        if any(line == 'worktree' for line in lines) or len(paths) != 1 or not paths[0]:
            raise SystemExit(f'{owner} registry block is malformed or ambiguous')
        raw = paths[0]
        forms, state = occupied_forms(raw, repo, owner)
        rows.append((raw, forms, state, tuple(lines)))
    for line in output.splitlines():
        if line == '':
            finish(block); block = []
        else:
            block.append(line)
    finish(block)
    return tuple(rows)

def registry_snapshot():
    rows = []
    for owner, repo in repos:
        output = subprocess.check_output([
            '/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks',
            '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', '-c', 'protocol.allow=never',
            'worktree', 'list', '--porcelain'], env=ENV, text=True)
        rows.append((owner, output, parse_records(output, owner, repo)))
    return tuple(rows)

def validate(rows, roots):
    targets = tuple(root[0] for _label, root in roots) + tuple(os.path.realpath(root[0]) for _label, root in roots)
    for owner, _output, records in rows:
        repo = repo_by_owner[owner]
        own, _own_state = occupied_forms(repo, repo, owner)
        own = set(own)
        for raw, forms, _state, _lines in records:
            if set(forms) & own:
                continue
            if any(overlap(item, target) for item in forms for target in targets):
                raise SystemExit(f'registered/nested worktree overlap: {raw}')

roots_before = root_snapshot()
registry_before = registry_snapshot()
validate(registry_before, roots_before)
if root_snapshot() != roots_before:
    raise SystemExit('root identity changed during worktree scan')
registry_after = registry_snapshot()
if registry_after != registry_before:
    raise SystemExit('registered worktree registry changed during scan')
if root_snapshot() != roots_before:
    raise SystemExit('root identity changed after worktree scan')
validate(registry_after, roots_before)
PY
}


assert_primary_pins() {
  assert_clean_primary_state
}


assert_status_paths() {
  "$PYTHON" - "$REPLAY" "$@" <<'PY'
ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}  # hermetic Git environment
import subprocess
import sys
repo = sys.argv[1]
expected = set(sys.argv[2:])
raw = subprocess.check_output([
    '/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never',
    'status', '--porcelain=v1', '--untracked-files=all', '-z'
], env=ENV)
actual = set()
for record in raw.split(b'\0'):
    if not record:
        continue
    if len(record) < 4:
        raise SystemExit('malformed porcelain record')
    status = record[:2].decode(errors='strict')
    path = record[3:].decode(errors='strict')
    if status[0] in 'RC' or status[1] in 'RC':
        raise SystemExit(f'rename/copy status is not allowed: {path}')
    actual.add(path)
if actual != expected:
    raise SystemExit(f'status path mismatch: actual={sorted(actual)!r} expected={sorted(expected)!r}')
PY
}

assert_replay_object_binding() {
  "$PYTHON" - "$REPLAY" "$CLEAN_PRIMARY_OBJECTS" "$SOURCE_OBJECTS" <<'PY'
ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}  # hermetic Git environment
import os
import stat

def read_stable_file(path, label='file'):
    path = os.fspath(path)
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_size, st.st_nlink)

    def parent_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_nlink)

    # Bind the expected parent before opening it by pathname. A canonical
    # directory can still be swapped for another canonical directory between
    # realpath/lstat and open; comparing the pre-open lstat with the held
    # descriptor prevents that substitution from redirecting the child read.
    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            second = os.fstat(fd)
            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent identity changed while reading')
    if file_identity(first) != file_identity(second) or file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return b''.join(chunks), first

import os
import stat
import subprocess
import sys
repo, clean_objects, source_objects = sys.argv[1:]
git_dir = subprocess.check_output(['/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', 'rev-parse', '--absolute-git-dir'], text=True, env=ENV).strip()
objects = os.path.join(git_dir, 'objects')
repo_real = os.path.realpath(repo)
if repo_real != repo:
    raise SystemExit('replay repository path is not canonical')
required_files = (os.path.join(git_dir, 'HEAD'), os.path.join(git_dir, 'config'))
for required in required_files:
    required_st = os.lstat(required)
    if (stat.S_ISLNK(required_st.st_mode) or not stat.S_ISREG(required_st.st_mode)
            or required_st.st_nlink != 1 or os.path.realpath(required) != required):
        raise SystemExit('replay HEAD/config identity is not a regular canonical single-link file')
    read_stable_file(required, 'replay required metadata')
objects_st = os.lstat(objects)
if (stat.S_ISLNK(objects_st.st_mode) or not stat.S_ISDIR(objects_st.st_mode)
        or os.path.realpath(objects) != objects):
    raise SystemExit('replay object store is not a canonical directory')
info_dir = os.path.join(objects, 'info')
info_st = os.lstat(info_dir)
if (stat.S_ISLNK(info_st.st_mode) or not stat.S_ISDIR(info_st.st_mode)
        or os.path.realpath(info_dir) != info_dir):
    raise SystemExit('replay object info directory is not canonical')
dotgit = os.path.join(repo, '.git')
dotgit_st = os.lstat(dotgit)
if (stat.S_ISLNK(dotgit_st.st_mode) or not stat.S_ISDIR(dotgit_st.st_mode)
        or os.path.realpath(dotgit) != dotgit):
    raise SystemExit('replay Git directory is not a canonical directory')
if os.path.realpath(git_dir) != dotgit:
    raise SystemExit('replay Git directory is not the repository-local .git directory')
common_dir = subprocess.check_output([
    '/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks',
    '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never',
    'rev-parse', '--git-common-dir',
], text=True, env=ENV).strip()
common_dir = os.path.realpath(common_dir if os.path.isabs(common_dir) else os.path.join(repo, common_dir))
if common_dir != git_dir:
    raise SystemExit('replay common directory is external or substituted')
if os.path.lexists(os.path.join(git_dir, 'commondir')):
    raise SystemExit('replay commondir indirection is forbidden')
for forbidden in (
    os.path.join(git_dir, 'shallow'),
    os.path.join(git_dir, 'info', 'grafts'),
    os.path.join(git_dir, 'refs', 'replace'),
    os.path.join(objects, 'info', 'http-alternates'),
):
    if os.path.lexists(forbidden):
        raise SystemExit('replay contains forbidden shallow, graft, replacement, or HTTP alternate metadata')
pack_dir = os.path.join(objects, 'pack')
if os.path.lexists(pack_dir) and (os.path.islink(pack_dir) or not os.path.isdir(pack_dir)
        or os.path.realpath(pack_dir) != pack_dir):
    raise SystemExit('replay pack directory is not canonical')
if os.path.isdir(pack_dir):
    for dirpath, dirnames, filenames in os.walk(pack_dir, topdown=True, followlinks=False):
        dirnames[:] = sorted(dirnames)
        filenames.sort()
        if any(os.path.islink(os.path.join(dirpath, name)) for name in dirnames):
            raise SystemExit('replay pack metadata contains a symlinked directory')
        if any(name.endswith('.promisor') for name in filenames):
            raise SystemExit('replay promisor metadata is forbidden')
alternate = os.path.join(objects, 'info', 'alternates')
st = os.lstat(alternate)
if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or os.path.realpath(alternate) != alternate:
    raise SystemExit('replay alternate is not a regular canonical file')
raw_alternate, _alternate_stat = read_stable_file(alternate, 'replay alternates')
if raw_alternate != (os.path.realpath(clean_objects) + '\n').encode():
    raise SystemExit('replay alternate is not clean-primary object store')
if os.path.samefile(objects, source_objects) or os.path.samefile(objects, clean_objects):
    raise SystemExit('replay object store is shared')
PY
}

assert_replay_state() {
  local expected_head="$1"
  local expected_tree="$2"
  shift 2
  test "$(git_replay rev-parse --show-toplevel)" = "$REPLAY" || fail "replay root changed"
  if git_replay symbolic-ref -q HEAD >/dev/null 2>&1; then fail "replay HEAD is attached"; fi
  test "$(git_replay rev-parse HEAD)" = "$expected_head" || fail "replay HEAD drifted"
  test "$(git_replay rev-parse HEAD^{tree})" = "$expected_tree" || fail "replay tree drifted"
  test "$(git_replay rev-parse refs/remotes/origin/dev)" = "$BASE" || fail "replay origin/dev drifted"
  test "$(git_replay rev-parse refs/remotes/origin/main)" = "$MAIN" || fail "replay origin/main drifted"
  assert_replay_object_binding
  assert_status_paths "$@"
}


assert_bootstrap_state() {
  test "$REPLAY_READY" -eq 0 || fail "bootstrap boundary used after replay became ready"
  test -z "$CURRENT_HEAD" || fail "bootstrap current HEAD is unexpectedly populated"
  test -z "$CURRENT_TREE" || fail "bootstrap current tree is unexpectedly populated"
  test "${#DIRTY_PATHS[@]}" -eq 0 || fail "bootstrap boundary has dirty transaction paths"
  # The descriptor-created replay child is intentionally not a Git repository
  # until init completes. Do not invoke Git or worktree-list before that point.
  if [ "$REPLAY_GIT_BOUND" -eq 0 ]; then
    return 0
  fi
  if git_replay rev-parse --verify refs/remotes/origin/dev >/dev/null 2>&1; then
    test "$(git_replay rev-parse refs/remotes/origin/dev)" = "$BASE" || fail "bootstrap replay origin/dev drifted"
  fi
  if git_replay rev-parse --verify refs/remotes/origin/main >/dev/null 2>&1; then
    test "$(git_replay rev-parse refs/remotes/origin/main)" = "$MAIN" || fail "bootstrap replay origin/main drifted"
  fi
  if [ -e "$REPLAY" ]; then
    if git_replay rev-parse --verify HEAD >/dev/null 2>&1; then
      test -n "$BOOTSTRAP_HEAD" || fail "bootstrap HEAD state is not declared"
      test -n "$BOOTSTRAP_TREE" || fail "bootstrap tree state is not declared"
      if git_replay symbolic-ref -q HEAD >/dev/null 2>&1; then
        fail "bootstrap replay HEAD is attached"
      fi
      test "$(git_replay rev-parse HEAD)" = "$BOOTSTRAP_HEAD" || fail "bootstrap HEAD drifted"
      test "$(git_replay rev-parse HEAD^{tree})" = "$BOOTSTRAP_TREE" || fail "bootstrap tree drifted"
      assert_status_paths
    else
      test -z "$BOOTSTRAP_HEAD" || fail "bootstrap HEAD declaration precedes HEAD creation"
      test -z "$BOOTSTRAP_TREE" || fail "bootstrap tree declaration precedes HEAD creation"
    fi
  else
    test -z "$BOOTSTRAP_HEAD" || fail "bootstrap HEAD declaration without replay checkout"
    test -z "$BOOTSTRAP_TREE" || fail "bootstrap tree declaration without replay checkout"
  fi
}

before_mutation() {
  assert_tools
  assert_root_shape
  assert_matrix_identity
  assert_source_binding
  assert_clean_primary_state
  assert_worktree_separation
  if [ "$REPLAY_READY" -eq 1 ]; then
    # Forward no optional arguments for an empty array. This is required for
    # Bash 3.2 nounset safety and keeps assert_replay_state's zero-arg contract.
    if [ "${#DIRTY_PATHS[@]}" -gt 0 ]; then
      assert_replay_state "$CURRENT_HEAD" "$CURRENT_TREE" "${DIRTY_PATHS[@]}"
    else
      assert_replay_state "$CURRENT_HEAD" "$CURRENT_TREE"
    fi
  else
    assert_bootstrap_state
  fi
}


add_dirty_path() {
  local candidate="$1"
  local existing
  # Do not expand an empty indexed array under Bash 3.2 nounset.
  if [ "${#DIRTY_PATHS[@]}" -gt 0 ]; then
    for existing in "${DIRTY_PATHS[@]}"; do
      [ "$existing" = "$candidate" ] && return 0
    done
  fi
  DIRTY_PATHS+=("$candidate")
}

assert_path_state() {
  "$PYTHON" - "$REPLAY" "$@" <<'PY'
ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}  # hermetic Git environment
import os
import stat
import subprocess
import sys
repo, path, expected_blob, expected_mode, expected_kind = sys.argv[1:]
def run(*args, check=True):
    p = subprocess.run(['/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV)
    if check and p.returncode:
        raise SystemExit(f'Git failed: {args!r}: {p.stderr.decode(errors="replace")}')
    return p
index = run('ls-files', '--stage', '--', path).stdout.decode()
full = os.path.join(repo, path)
if expected_kind == 'absent':
    if index or os.path.lexists(full):
        raise SystemExit(f'expected exact absence for {path}')
    raise SystemExit(0)
if expected_kind != 'file':
    raise SystemExit(f'unsupported expected kind {expected_kind!r}')
lines = index.rstrip('\n').splitlines()
if len(lines) != 1:
    raise SystemExit(f'index stage/absence mismatch for {path}')
mode, blob, rest = lines[0].split(' ', 2)
stage, recorded = rest.split('\t', 1)
if stage != '0' or recorded != path:
    raise SystemExit(f'index stage/path mismatch for {path}')
if mode != expected_mode or blob != expected_blob:
    raise SystemExit(f'index CAS mismatch for {path}: {(mode, blob)} != {(expected_mode, expected_blob)}')
if not os.path.isfile(full) or os.path.islink(full):
    raise SystemExit(f'worktree type mismatch for {path}')
actual_blob = run('hash-object', '--', path).stdout.decode().strip()
if actual_blob != expected_blob:
    raise SystemExit(f'worktree blob mismatch for {path}')
actual_mode = '100755' if stat.S_IXUSR & os.stat(full).st_mode else '100644'
if actual_mode != expected_mode:
    raise SystemExit(f'worktree mode mismatch for {path}')
if run('diff-files', '--quiet', '--', path, check=False).returncode != 0:
    raise SystemExit(f'worktree/index differ for {path}')
PY
}

assert_source_blob() {
  local source="$1"
  local path="$2"
  local expected="$3"
  local actual
  actual="$(git_replay rev-parse "$source:$path")"
  test "$actual" = "$expected" || fail "source target blob mismatch for $path"
  test "$(git_replay cat-file -t "$actual")" = blob || fail "source target is not a blob for $path"
}

assert_declared_projection() {
  local lane="$1"
  local selected="${2-}"
  local args=("$MATRIX" "$REPLAY" "$lane")
  [ -z "$selected" ] || args+=("$selected")
  "$PYTHON" - "${args[@]}" <<'PY'
ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}  # hermetic Git environment
import os
import stat

def read_stable_file(path, label='file'):
    path = os.fspath(path)
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_size, st.st_nlink)

    def parent_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_nlink)

    # Bind the expected parent before opening it by pathname. A canonical
    # directory can still be swapped for another canonical directory between
    # realpath/lstat and open; comparing the pre-open lstat with the held
    # descriptor prevents that substitution from redirecting the child read.
    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            second = os.fstat(fd)
            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent identity changed while reading')
    if file_identity(first) != file_identity(second) or file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return b''.join(chunks), first

import os
import stat
import subprocess
import sys
import json
matrix, repo, lane_id = sys.argv[1:4]
selected = sys.argv[4] if len(sys.argv) == 5 else None
data = json.loads(read_stable_file(matrix, 'matrix')[0].decode('utf-8'))
lane = next(item for item in data['ordered_lanes'] if item['id'] == lane_id)

def run(*args, check=True):
    p = subprocess.run(['/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV)
    if check and p.returncode:
        raise SystemExit(f'Git failed: {args!r}: {p.stderr.decode(errors="replace")}')
    return p

def tree_state(ref, path):
    raw = run('ls-tree', ref, '--', path).stdout.decode().splitlines()
    if not raw:
        return {'blob': None, 'mode': None, 'type': 'absent'}
    if len(raw) != 1:
        raise SystemExit(f'ambiguous declared tree state for {ref}:{path}')
    meta, recorded = raw[0].split('\t', 1)
    if recorded != path:
        raise SystemExit(f'declared tree path mismatch for {ref}:{path}')
    mode, kind, blob = meta.split()
    return {'blob': blob if kind == 'blob' else None, 'mode': mode, 'type': 'file' if kind == 'blob' else kind}

def content_state(path):
    full = os.path.join(repo, path)
    raw = run('ls-files', '--stage', '--', path).stdout.decode()
    if not raw:
        if os.path.lexists(full):
            return {'blob': None, 'mode': None, 'type': 'worktree-only'}
        return {'blob': None, 'mode': None, 'type': 'absent'}
    lines = raw.rstrip('\n').splitlines()
    if len(lines) != 1:
        raise SystemExit(f'index stage overlap for {path}')
    mode, blob, rest = lines[0].split(' ', 2)
    stage, recorded = rest.split('\t', 1)
    if stage != '0' or recorded != path:
        raise SystemExit(f'index stage/path mismatch for {path}')
    if not os.path.isfile(full) or os.path.islink(full):
        return {'blob': blob, 'mode': mode, 'type': 'worktree-nonfile'}
    actual_blob = run('hash-object', '--', path).stdout.decode().strip()
    actual_mode = '100755' if stat.S_IXUSR & os.stat(full).st_mode else '100644'
    if run('diff-files', '--quiet', '--', path, check=False).returncode != 0:
        return {'blob': actual_blob, 'mode': actual_mode, 'type': 'worktree-different'}
    return {'blob': actual_blob, 'mode': actual_mode, 'type': 'file'}

def compare(expected, actual, label):
    for key in ('blob', 'mode', 'type'):
        if actual.get(key) != expected.get(key):
            raise SystemExit(f'{label}: {key} mismatch: actual={actual.get(key)!r} expected={expected.get(key)!r}')

def validate_tree_record(record, path, label):
    tree_commit = record.get('tree_commit')
    if not isinstance(tree_commit, str) or len(tree_commit) != 40:
        raise SystemExit(f'{label}.{path}: missing full tree commit')
    expected_tree = record.get('tree')
    actual_tree = run('rev-parse', f'{tree_commit}^{{tree}}').stdout.decode().strip()
    if actual_tree != expected_tree:
        raise SystemExit(f'{label}.{path}: tree mismatch')
    compare(record, tree_state(tree_commit, path), f'{label}.{path}.tree')

source = lane.get('source_parent_state')
stage = lane.get('stage_precondition')
if not source or not stage:
    raise SystemExit(f'{lane_id}: declared source-parent/stage state maps are required')
source_commit = source.get('commit')
source_tree = source.get('tree')
if run('rev-parse', f'{source_commit}^{{tree}}').stdout.decode().strip() != source_tree:
    raise SystemExit(f'{lane_id}: source-parent tree binding mismatch')
for path, record in source['paths'].items():
    record = dict(record)
    record['tree_commit'] = source_commit
    validate_tree_record(record, path, f'{lane_id}.source-parent')

stage_paths = stage['paths']
selected_paths = [selected] if selected is not None else list(stage_paths)
for path in selected_paths:
    if path not in stage_paths:
        raise SystemExit(f'{lane_id}: undeclared stage path {path}')
    record = stage_paths[path]
    validate_tree_record(record, path, f'{lane_id}.stage')
    compare(record, content_state(path), f'{lane_id}.stage.current')
PY
}

cas_path() {
  # This is a compare-and-swap transaction: old index blob/mode/stage, old worktree
  # blob/mode/type or absence are checked before update-index; target is checked after
  # both index and worktree updates. No path-wide source apply is used.
  local path="$1" old_blob="$2" old_mode="$3" old_kind="$4"
  local new_blob="$5" new_mode="$6" new_kind="$7"
  assert_path_state "$path" "$old_blob" "$old_mode" "$old_kind"
  # Callers add no optimistic dirty entry for this path. The entry is added only
  # after update-index succeeds, so the pre-CAS boundary cannot accept a clean path
  # that has merely been listed as dirty in advance.
  if [ "$new_kind" = absent ]; then
    before_mutation
    git_replay update-index --force-remove -- "$path" 2>/dev/null || true
    add_dirty_path "$path"
    before_mutation
    if [ -e "$REPLAY/$path" ] || [ -L "$REPLAY/$path" ]; then
      "$RM" -f -- "$REPLAY/$path"
    fi
  else
    test "$new_kind" = file || fail "unsupported target type for $path"
    test "$new_mode" = 100644 || test "$new_mode" = 100755 || fail "unsupported target mode for $path"
    test "$(git_replay cat-file -t "$new_blob")" = blob || fail "target blob is not local for $path"
    before_mutation
    git_replay update-index --add --cacheinfo "$new_mode,$new_blob,$path"
    add_dirty_path "$path"
    before_mutation
    git_replay checkout-index --force -- "$path"
  fi
  assert_path_state "$path" "$new_blob" "$new_mode" "$new_kind"
}

assert_exact_staged() {
  "$PYTHON" - "$REPLAY" "$@" <<'PY'
ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}  # hermetic Git environment
import subprocess
import sys
repo = sys.argv[1]
expected = set(sys.argv[2:])
raw = subprocess.check_output([
    '/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never',
    'diff', '--cached', '--name-only', '-z', '--'
], env=ENV)
actual = set(x.decode() for x in raw.split(b'\0') if x)
if not actual:
    raise SystemExit('staged result is empty')
if actual != expected:
    raise SystemExit(f'staged path mismatch: actual={sorted(actual)!r} expected={sorted(expected)!r}')
PY
}

binary_patch_id() {
  local left="$1" right="$2"
  shift 2
  git_replay diff --binary --full-index --no-ext-diff --no-textconv "$left" "$right" -- "$@" \
    | patch_id_stable | "$CUT" -d' ' -f1
}
raw_patch_sha256() {
  local left="$1" right="$2"
  shift 2
  git_replay diff --binary --full-index --no-ext-diff --no-textconv "$left" "$right" -- "$@" \
    | "$SHASUM" -a 256 | "$CUT" -d' ' -f1
}

assert_cached_patch() {
  local expected="$1"
  shift
  local raw patch
  raw="$(git_replay diff --cached --binary --full-index --no-ext-diff --no-textconv -- "$@")"
  test -n "$raw" || fail "empty staged binary patch"
  patch="$(printf '%s' "$raw" | patch_id_stable | "$CUT" -d' ' -f1)"
  if [ "$expected" != - ]; then
    test "$patch" = "$expected" || fail "staged patch-id mismatch: $patch != $expected"
  fi
}

assert_commit_target_states() {
  local head="$1"
  shift
  "$PYTHON" - "$REPLAY" "$head" "$@" <<'PY'
import os
import subprocess
import sys

repo, head = sys.argv[1:3]
arguments = sys.argv[3:]
try:
    separator = arguments.index('--')
except ValueError:
    raise SystemExit('commit target verifier is missing its path/row separator')
paths = arguments[:separator]
rows = arguments[separator + 1:]
if len(paths) != len(rows) or len(set(paths)) != len(paths):
    raise SystemExit('commit target verifier path/row cardinality mismatch')
ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}
def run(*args):
    command = [
        '/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks',
        '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never',
        *args,
    ]
    process = subprocess.run(command, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if process.returncode:
        raise SystemExit(f'Git target-state check failed: {args!r}: {process.stderr.decode(errors="replace")}')
    return process.stdout
for row in rows:
    fields = row.split('\t')
    if len(fields) != 4:
        raise SystemExit(f'malformed expected target row: {row!r}')
    path, expected_blob, expected_mode, expected_kind = fields
    raw = run('ls-tree', head, '--', path).decode()
    if expected_kind == 'absent':
        if raw:
            raise SystemExit(f'expected absent path is present in HEAD: {path}')
        continue
    if expected_kind != 'file' or expected_blob == '-' or expected_mode == '-':
        raise SystemExit(f'invalid expected target state: {row!r}')
    lines = raw.splitlines()
    if len(lines) != 1:
        raise SystemExit(f'HEAD target path is missing or ambiguous: {path}')
    meta, recorded = lines[0].split('\t', 1)
    mode, kind, oid = meta.split()
    if recorded != path:
        raise SystemExit(f'HEAD target path mismatch: {path}')
    if kind != 'blob' or oid != expected_blob or mode != expected_mode:
        raise SystemExit(f'HEAD target state mismatch for {path}: {(oid, mode, kind)} != {(expected_blob, expected_mode, "blob")}')
    actual_type = run('cat-file', '-t', oid).decode().strip()
    if actual_type != 'blob':
        raise SystemExit(f'HEAD target object type mismatch for {path}: {actual_type} != blob')
PY
}

assert_commit_gate() {
  local parent="$1" head="$2" expected_patch="$3"
  shift 3
  local paths=("$@") raw patch
  test "${#EXPECTED_COMMIT_TARGET_ROWS[@]}" -eq "${#paths[@]}" || fail "declared commit target row count mismatch"
  assert_commit_target_states "$head" "${paths[@]}" -- "${EXPECTED_COMMIT_TARGET_ROWS[@]}"
  test "$(git_replay rev-parse "$head^")" = "$parent" || fail "post-commit parent mismatch"
  assert_exact_commit_paths "$head" "${paths[@]}"
  raw="$(git_replay diff --binary --full-index --no-ext-diff --no-textconv "$parent" "$head" -- "${paths[@]}")"
  test -n "$raw" || fail "post-commit binary patch is empty"
  git_replay diff --check "$parent" "$head" -- "${paths[@]}"
  if [ "$expected_patch" != - ]; then
    patch="$(printf '%s' "$raw" | patch_id_stable | "$CUT" -d' ' -f1)"
    test "$patch" = "$expected_patch" || fail "post-commit patch-id mismatch: $patch != $expected_patch"
  fi
}

assert_exact_commit_paths() {
  local head="$1"
  shift
  "$PYTHON" - "$REPLAY" "$head" "$@" <<'PY'
ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}  # hermetic Git environment
import subprocess
import sys
repo, head = sys.argv[1:3]
expected = set(sys.argv[3:])
raw = subprocess.check_output([
    '/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never',
    'diff-tree', '--root', '--no-commit-id', '--name-only', '-r', '-z', head
], env=ENV)
actual = set(x.decode() for x in raw.split(b'\0') if x)
if actual != expected:
    raise SystemExit(f'commit path mismatch: actual={sorted(actual)!r} expected={sorted(expected)!r}')
PY
}

assert_unique_patch_id() {
  local value="$1"
  [ "$value" = - ] && return 0
  case "|$APPLIED_PATCH_IDS|" in
    *"|$value|"*) fail "stable patch-id would be applied twice: $value" ;;
  esac
  APPLIED_PATCH_IDS="${APPLIED_PATCH_IDS}${value}|"
}

target_state_record() {
  local path="$1"
  "$PYTHON" - "$MATRIX" "$path" <<'PY'
import json
import os
import stat
import sys


def read_stable_file(path, label='file'):
    path = os.fspath(path)
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)
    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not canonical')
    def file_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_size, st.st_nlink)
    def parent_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_nlink)
    expected_parent = parent_identity(parent_pre)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent changed before child open')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            second = os.fstat(fd)
            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
    if parent_identity(parent_second) != expected_parent:
        raise SystemExit(f'{label} parent changed while reading')
    if file_identity(first) != file_identity(second) or file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1 or os.path.realpath(path) != path:
        raise SystemExit(f'{label} final identity changed')
    return b''.join(chunks), first

matrix, path = sys.argv[1:]
data = json.loads(read_stable_file(matrix, 'matrix source')[0].decode('utf-8'))
found = []
for lane in data['ordered_lanes']:
    for sequence in (lane.get('range', {}).get('source_commits', []), [lane.get('source_commit')] if lane.get('source_commit') else []):
        for commit in sequence:
            if commit and path in commit.get('target_states', {}):
                state = commit['target_states'][path]
                found.append((lane['id'], 'commit', commit['commit'], state))
    for map_name, state_map in (('stage', lane.get('stage_precondition', {}).get('paths', {})), ('parent', lane.get('source_parent_state', {}).get('paths', {}))):
        if path in state_map:
            found.append((lane['id'], map_name, lane.get('order'), state_map[path]))
if not found:
    raise SystemExit(f'no declared target state for committed path: {path}')
# A path may be repeated by later lanes, but a commit must match one exact declared
# state. Reject ambiguity instead of silently selecting the first lane's state.
unique = {(item[3].get('blob'), item[3].get('mode'), item[3].get('type')) for item in found}
if len(unique) != 1:
    raise SystemExit(f'ambiguous declared target state for committed path: {path}')
state = found[-1][3]
print('\t'.join([path, state.get('blob') or '-', state.get('mode') or '-', state.get('type') or 'absent']))
PY
}

commit_staged() {
  local message="$1" expected_patch="$2"
  shift 2
  local paths=("$@") parent staged_raw staged_patch expected_tree
  local EXPECTED_COMMIT_TARGET_ROWS=() target_path target_state
  for target_path in "${paths[@]}"; do
    target_state="$(target_state_record "$target_path")"
    EXPECTED_COMMIT_TARGET_ROWS+=("$target_state")
  done
  assert_exact_staged "${paths[@]}"
  git_replay diff --cached --check -- "${paths[@]}"
  expected_tree="$(git_replay write-tree)" || fail "staged index tree could not be pinned"
  test -n "$expected_tree" || fail "staged index tree is empty"
  staged_raw="$(git_replay diff --cached --binary --full-index --no-ext-diff --no-textconv -- "${paths[@]}")"
  test -n "$staged_raw" || fail "empty staged binary patch"
  staged_patch="$(printf '%s' "$staged_raw" | patch_id_stable | "$CUT" -d' ' -f1)"
  test -n "$staged_patch" || fail "empty staged patch-id"
  if [ "$expected_patch" = - ]; then
    assert_unique_patch_id "$staged_patch"
  else
    assert_unique_patch_id "$expected_patch"
  fi
  parent="$CURRENT_HEAD"
  before_mutation
  git_replay -c user.name="$COMMITTER_NAME" -c user.email="$COMMITTER_EMAIL" commit --no-verify -m "$message"
  CURRENT_HEAD="$(git_replay rev-parse HEAD)"
  CURRENT_TREE="$(git_replay rev-parse HEAD^{tree})"
  test "$CURRENT_TREE" = "$expected_tree" || fail "post-commit tree differs from pinned staged tree"
  DIRTY_PATHS=()
  assert_replay_state "$CURRENT_HEAD" "$CURRENT_TREE"
  assert_commit_gate "$parent" "$CURRENT_HEAD" "$expected_patch" "${paths[@]}"
}

range_records() {
  local lane="$1"
  "$PYTHON" - "$MATRIX" "$lane" <<'PY'
import os
import stat

def read_stable_file(path, label='file'):
    path = os.fspath(path)
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_size, st.st_nlink)

    def parent_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_nlink)

    # Bind the expected parent before opening it by pathname. A canonical
    # directory can still be swapped for another canonical directory between
    # realpath/lstat and open; comparing the pre-open lstat with the held
    # descriptor prevents that substitution from redirecting the child read.
    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            second = os.fstat(fd)
            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent identity changed while reading')
    if file_identity(first) != file_identity(second) or file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return b''.join(chunks), first

import json
import sys
m = json.loads(read_stable_file(sys.argv[1], 'matrix')[0].decode('utf-8'))
lane = next(x for x in m['ordered_lanes'] if x['id'] == sys.argv[2])
for c in lane['range']['source_commits']:
    print('\t'.join([
        c['commit'], c['stable_patch_id'], c['parents'][0], c['tree'],
        '\x1f'.join(c['changed_paths'])
    ]))
PY
}

range_target_records() {
  local lane="$1"
  local source="$2"
  "$PYTHON" - "$MATRIX" "$lane" "$source" <<'PY'
import os
import stat

def read_stable_file(path, label='file'):
    path = os.fspath(path)
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_size, st.st_nlink)

    def parent_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_nlink)

    # Bind the expected parent before opening it by pathname. A canonical
    # directory can still be swapped for another canonical directory between
    # realpath/lstat and open; comparing the pre-open lstat with the held
    # descriptor prevents that substitution from redirecting the child read.
    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            second = os.fstat(fd)
            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent identity changed while reading')
    if file_identity(first) != file_identity(second) or file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return b''.join(chunks), first

import json
import sys
m = json.loads(read_stable_file(sys.argv[1], 'matrix')[0].decode('utf-8'))
lane = next(x for x in m['ordered_lanes'] if x['id'] == sys.argv[2])
source = sys.argv[3]
commit = next(c for c in lane['range']['source_commits'] if c['commit'] == source)
for path in commit['changed_paths']:
    state = commit['target_states'][path]
    print('\t'.join([path, state['blob'] or '-', state['mode'] or '-', state['type']]))
PY
}

assert_range_records_file() {
  local lane="$1" file="$2"
  "$PYTHON" - "$MATRIX" "$lane" "$file" <<'PY'
import json
import sys
from pathlib import Path
matrix, lane_id, output = sys.argv[1:]
data = json.loads(Path(matrix).read_bytes())
lane = next(row for row in data['ordered_lanes'] if row['id'] == lane_id)
sequence = lane['range']
expected = []
for commit in sequence['source_commits']:
    expected.append('\\t'.join([commit['commit'], commit['stable_patch_id'], commit['parents'][0], commit['tree'], '\\x1f'.join(commit['changed_paths'])]).encode())
actual = Path(output).read_bytes().splitlines()
if len(actual) != sequence['count'] or actual != expected:
    raise SystemExit(f'{lane_id}: range records are empty, truncated, reordered, or have tail loss')
PY
}
assert_range_target_records_file() {
  local lane="$1" source="$2" file="$3"
  "$PYTHON" - "$MATRIX" "$lane" "$source" "$file" <<'PY'
import json
import sys
from pathlib import Path
matrix, lane_id, source, output = sys.argv[1:]
data = json.loads(Path(matrix).read_bytes())
lane = next(row for row in data['ordered_lanes'] if row['id'] == lane_id)
commit = next(row for row in lane['range']['source_commits'] if row['commit'] == source)
expected = []
for path in commit['changed_paths']:
    state = commit['target_states'][path]
    expected.append('\\t'.join([path, state['blob'] or '-', state['mode'] or '-', state['type']]).encode())
actual = Path(output).read_bytes().splitlines()
if not expected or actual != expected:
    raise SystemExit(f'{lane_id}:{source}: target records are empty, truncated, reordered, or have tail loss')
PY
}
assert_semantic_records_file() {
  local lane="$1" file="$2"
  "$PYTHON" - "$MATRIX" "$lane" "$file" <<'PY'
import json
import sys
from pathlib import Path
matrix, lane_id, output = sys.argv[1:]
data = json.loads(Path(matrix).read_bytes())
lane = next(row for row in data['ordered_lanes'] if row['id'] == lane_id)
if lane_id == 'dependency-audit-correction':
    target = lane['source_commit']['commit']; parent = lane['source_commit']['parents'][0]; paths = lane['owned_paths']
else:
    target = lane['semantic_delta']['child']; parent = lane['semantic_delta']['parent']; paths = lane['semantic_delta']['owned_paths']
expected = [target.encode(), parent.encode(), '\\x1f'.join(paths).encode()]
actual = Path(output).read_bytes().splitlines()
if actual != expected:
    raise SystemExit(f'{lane_id}: semantic records are empty, truncated, reordered, or have tail loss')
PY
}
assert_projection_stage_records_file() {
  local lane="$1" file="$2"
  "$PYTHON" - "$MATRIX" "$lane" "$file" <<'PY'
import json
import sys
from pathlib import Path
matrix, lane_id, output = sys.argv[1:]
data = json.loads(Path(matrix).read_bytes())
lane = next(row for row in data['ordered_lanes'] if row['id'] == lane_id)
paths = lane.get('semantic_delta', {}).get('owned_paths') or lane['owned_paths']
expected = []
for path in paths:
    state = lane['stage_precondition']['paths'][path]
    expected.append('\\t'.join([path, state['blob'] or '-', state['mode'] or '-', state['type']]).encode())
actual = Path(output).read_bytes().splitlines()
if not expected or actual != expected:
    raise SystemExit(f'{lane_id}: projection records are empty, truncated, reordered, or have tail loss')
PY
}
assert_matrix_records_file() {
  local stage="$1" file="$2"
  "$PYTHON" - "$MATRIX" "$stage" "$file" <<'PY'
import json
import sys
from pathlib import Path
matrix, stage, output = sys.argv[1:]
data = json.loads(Path(matrix).read_bytes())
expected = []
for row in data['live_overlap']['blob_matrix']:
    if stage == 'launcher' and row['launcher_mechanical']:
        expected.append('\\t'.join([row['path'], row['proxy_blob'] or '-', row['proxy_mode'] or '-', row['d3_launcher_blob'] or '-', row['d3_launcher_mode'] or '-']).encode())
    if stage == 'live' and row['live_mechanical']:
        old_blob = row['d3_launcher_blob'] if row['launcher_mechanical'] else row['proxy_blob']
        old_mode = row['d3_launcher_mode'] if row['launcher_mechanical'] else row['proxy_mode']
        expected.append('\\t'.join([row['path'], old_blob or '-', old_mode or '-', row['80fe_live_blob'] or '-', row['80fe_live_mode'] or '-']).encode())
actual = Path(output).read_bytes().splitlines()
if not expected or actual != expected:
    raise SystemExit(f'{stage}: matrix records are empty, truncated, reordered, or have tail loss')
PY
}
forbidden_ancestry_records() {
  "$PYTHON" - "$MATRIX" <<'PY'
import json
import sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_bytes())
for value in data['forbidden_ancestry']['commits'] + data['forbidden_ancestry']['raw_semantic_source_commits']:
    print(value)
PY
}
assert_forbidden_ancestry_records_file() {
  local file="$1"
  "$PYTHON" - "$MATRIX" "$file" <<'PY'
import json
import sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_bytes())
expected = [value.encode() for value in data['forbidden_ancestry']['commits'] + data['forbidden_ancestry']['raw_semantic_source_commits']]
actual = Path(sys.argv[2]).read_bytes().splitlines()
if not expected or actual != expected:
    raise SystemExit('forbidden ancestry records are empty, truncated, reordered, or have tail loss')
PY
}

apply_range_lane() {
  local lane="$1" record source expected parent tree path_blob cherry_path abort_rc
  local paths=()
  local records_file target_records_file
  records_file="$(producer_to_file range-records "$REPLAY_ROOT" range_records "$lane")"
  assert_range_records_file "$lane" "$records_file"
  while IFS=$'	' read -r source expected parent tree path_blob; do
    [ -n "$source" ] || continue
    test "$(git_replay rev-parse "$source^")" = "$parent" || fail "source parent mismatch for $source"
    test "$(git_replay rev-parse "$source^{tree}")" = "$tree" || fail "source tree mismatch for $source"
    IFS=$'' read -r -a paths <<< "$path_blob"
    test "${#paths[@]}" -gt 0 || fail "empty source path set for $source"
    cherry_path="$(git_replay cherry "$CURRENT_HEAD" "$source")"
    test -n "$cherry_path" || fail "git cherry returned an empty duplicate-check result for $source"
    while IFS= read -r record; do
      case "$record" in -*) fail "duplicate source patch rejected by git cherry: $record" ;; esac
    done <<< "$cherry_path"
    DIRTY_PATHS=()
    before_mutation
    if git_replay cherry-pick --no-commit "$source"; then
      :
    else
      DIRTY_PATHS=("${paths[@]}")
      before_mutation
      if git_replay cherry-pick --abort; then
        :
      else
        abort_rc=$?
        fail "cherry-pick abort failed in $lane at $source with rc=$abort_rc"
      fi
      DIRTY_PATHS=()
      before_mutation
      fail "cherry-pick conflict in $lane at $source"
    fi
    DIRTY_PATHS=("${paths[@]}")
    assert_replay_state "$CURRENT_HEAD" "$CURRENT_TREE" "${DIRTY_PATHS[@]}"
    target_records_file="$(producer_to_file range-target-records "$REPLAY_ROOT" range_target_records "$lane" "$source")"
    assert_range_target_records_file "$lane" "$source" "$target_records_file"
    while IFS=$'	' read -r path target_blob target_mode target_kind; do
      assert_path_state "$path" "$target_blob" "$target_mode" "$target_kind"
    done < "$target_records_file"
    cleanup_temp_file "$target_records_file"
    assert_exact_staged "${paths[@]}"
    git_replay diff --cached --check -- "${paths[@]}"
    test "$(binary_patch_id "$parent" "$source" "${paths[@]}")" = "$expected" || fail "source patch-id mismatch for $source"
    assert_cached_patch "$expected" "${paths[@]}"
    commit_staged "replay(task409): $lane:$source" "$expected" "${paths[@]}"
  done < "$records_file"
  cleanup_temp_file "$records_file"
}


semantic_records() {
  local lane="$1"
  "$PYTHON" - "$MATRIX" "$lane" <<'PY'
import os
import stat

def read_stable_file(path, label='file'):
    path = os.fspath(path)
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_size, st.st_nlink)

    def parent_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_nlink)

    # Bind the expected parent before opening it by pathname. A canonical
    # directory can still be swapped for another canonical directory between
    # realpath/lstat and open; comparing the pre-open lstat with the held
    # descriptor prevents that substitution from redirecting the child read.
    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            second = os.fstat(fd)
            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent identity changed while reading')
    if file_identity(first) != file_identity(second) or file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return b''.join(chunks), first

import json
import sys
m = json.loads(read_stable_file(sys.argv[1], 'matrix')[0].decode('utf-8'))
lane = next(x for x in m['ordered_lanes'] if x['id'] == sys.argv[2])
if lane['id'] == 'dependency-audit-correction':
    target = lane['source_commit']['commit']
    parent = lane['source_commit']['parents'][0]
    paths = lane['owned_paths']
else:
    target = lane['semantic_delta']['child']
    parent = lane['semantic_delta']['parent']
    paths = lane['semantic_delta']['owned_paths']
print(target)
print(parent)
print('\x1f'.join(paths))
PY
}


snapshot_paths() {
  "$PYTHON" - "$REPLAY" "$@" <<'PY'
ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}  # hermetic Git environment
import os
import stat
import subprocess
import sys
repo = sys.argv[1]
for path in sys.argv[2:]:
    p = subprocess.run(['/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', 'ls-files', '--stage', '--', path], stdout=subprocess.PIPE, check=True, env=ENV)
    raw = p.stdout.decode()
    if not raw:
        if os.path.lexists(os.path.join(repo, path)):
            raise SystemExit(f'non-indexed worktree path is not exact absence: {path}')
        print(f'{path}\t-\t-\tabsent')
        continue
    lines = raw.rstrip('\n').splitlines()
    if len(lines) != 1:
        raise SystemExit(f'index stage overlap for {path}')
    mode, blob, rest = lines[0].split(' ', 2)
    stage, recorded = rest.split('\t', 1)
    if stage != '0' or recorded != path:
        raise SystemExit(f'index stage/path mismatch for {path}')
    full = os.path.join(repo, path)
    if not os.path.isfile(full) or os.path.islink(full):
        raise SystemExit(f'worktree type mismatch for {path}')
    actual = subprocess.check_output(['/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', 'hash-object', '--', path], text=True, env=ENV).strip()
    if actual != blob:
        raise SystemExit(f'worktree blob mismatch for {path}')
    actual_mode = '100755' if stat.S_IXUSR & os.stat(full).st_mode else '100644'
    if actual_mode != mode:
        raise SystemExit(f'worktree mode mismatch for {path}')
    subprocess.run(['/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', 'diff-files', '--quiet', '--', path], check=True, env=ENV)
    print(f'{path}\t{blob}\t{mode}\tfile')
PY
}

projection_stage_records() {
  local lane="$1"
  "$PYTHON" - "$MATRIX" "$lane" <<'PY'
import os
import stat

def read_stable_file(path, label='file'):
    path = os.fspath(path)
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_size, st.st_nlink)

    def parent_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_nlink)

    # Bind the expected parent before opening it by pathname. A canonical
    # directory can still be swapped for another canonical directory between
    # realpath/lstat and open; comparing the pre-open lstat with the held
    # descriptor prevents that substitution from redirecting the child read.
    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            second = os.fstat(fd)
            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent identity changed while reading')
    if file_identity(first) != file_identity(second) or file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return b''.join(chunks), first

import json
import sys
m = json.loads(read_stable_file(sys.argv[1], 'matrix')[0].decode('utf-8'))
lane = next(x for x in m['ordered_lanes'] if x['id'] == sys.argv[2])
paths = lane.get('semantic_delta', {}).get('owned_paths') or lane['owned_paths']
for path in paths:
    state = lane['stage_precondition']['paths'][path]
    print('\t'.join([path, state['blob'] or '-', state['mode'] or '-', state['type']]))
PY
}

apply_semantic_lane() {
  local lane="$1" record semantic_file projection_file
  local info=()
  semantic_file="$(producer_to_file semantic-records "$REPLAY_ROOT" semantic_records "$lane")"
  assert_semantic_records_file "$lane" "$semantic_file"
  while IFS= read -r record; do
    info[${#info[@]}]="$record"
  done < "$semantic_file"
  cleanup_temp_file "$semantic_file"
  test "${#info[@]}" -eq 3 || fail "semantic producer row count mismatch for $lane"
  local target="${info[0]-}" source_parent="${info[1]-}" path_blob="${info[2]-}"
  local paths=()
  IFS=$'\x1f' read -r -a paths <<< "$path_blob"
  test -n "$target" && test -n "$source_parent" || fail "semantic parent/child missing for $lane"
  test "${#paths[@]}" -gt 0 || fail "empty semantic path set for $lane"
  test "$(git_replay rev-parse "$target^1")" = "$source_parent" || fail "semantic source parent mismatch for $lane"
  DIRTY_PATHS=()
  before_mutation
  assert_declared_projection "$lane"
  local path old_blob old_mode old_kind new_blob new_mode new_kind target_line target_type
  projection_file="$(producer_to_file projection-records "$REPLAY_ROOT" projection_stage_records "$lane")"
  assert_projection_stage_records_file "$lane" "$projection_file"
  while IFS=$'\t' read -r path old_blob old_mode old_kind; do
    assert_declared_projection "$lane" "$path"
    target_line="$(git_replay ls-tree "$target" -- "$path")"
    if [ -z "$target_line" ]; then
      new_blob='-'
      new_mode='-'
      new_kind=absent
    else
      read -r new_mode target_type new_blob _ <<< "$target_line"
      test "$target_type" = blob || fail "semantic target type mismatch for $path"
      new_kind=file
      assert_source_blob "$target" "$path" "$new_blob"
    fi
    cas_path "$path" "$old_blob" "$old_mode" "$old_kind" "$new_blob" "$new_mode" "$new_kind"
  done < "$projection_file"
  cleanup_temp_file "$projection_file"
  assert_exact_staged "${paths[@]}"
  git_replay diff --cached --check -- "${paths[@]}"
  commit_staged "replay(task409): $lane semantic projection" - "${paths[@]}"
}

matrix_records() {
  local stage="$1"
  "$PYTHON" - "$MATRIX" "$stage" <<'PY'
import os
import stat

def read_stable_file(path, label='file'):
    path = os.fspath(path)
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_size, st.st_nlink)

    def parent_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_nlink)

    # Bind the expected parent before opening it by pathname. A canonical
    # directory can still be swapped for another canonical directory between
    # realpath/lstat and open; comparing the pre-open lstat with the held
    # descriptor prevents that substitution from redirecting the child read.
    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            second = os.fstat(fd)
            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent identity changed while reading')
    if file_identity(first) != file_identity(second) or file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return b''.join(chunks), first

import json
import sys
m = json.loads(read_stable_file(sys.argv[1], 'matrix')[0].decode('utf-8'))
for row in m['live_overlap']['blob_matrix']:
    if sys.argv[2] == 'launcher' and row['launcher_mechanical']:
        print('\t'.join([row['path'], row['proxy_blob'] or '-', row['proxy_mode'] or '-', row['d3_launcher_blob'] or '-', row['d3_launcher_mode'] or '-']))
    if sys.argv[2] == 'live' and row['live_mechanical']:
        old_blob = row['d3_launcher_blob'] if row['launcher_mechanical'] else row['proxy_blob']
        old_mode = row['d3_launcher_mode'] if row['launcher_mechanical'] else row['proxy_mode']
        print('\t'.join([row['path'], old_blob or '-', old_mode or '-', row['80fe_live_blob'] or '-', row['80fe_live_mode'] or '-']))
PY
}

apply_matrix_stage() {
  local stage="$1" expected_patch expected_raw source_left target projection_lane
  if [ "$stage" = launcher ]; then
    source_left="$BASE"
    target="$LAUNCHER"
    projection_lane=launcher-semantic-projection
    expected_patch=cd1e6446174eca48b7bca2b263c332e0f71303b1
    expected_raw=5c9f76cd27ba4c4136f324926aab1f01f00e1033b21ee0dfb81da9ac3d016942
  else
    source_left="$LAUNCHER"
    target="$LIVE"
    projection_lane=live-proof-semantic-projection
    expected_patch=304ee69ee3b7753aa516ee86f3b3053d3f9ec97b
    expected_raw=12892436be96696fa5f0261e5c238b5aa82d46267b829b5e081896ab642dd1c3
  fi
  local rows=() record matrix_file
  matrix_file="$(producer_to_file matrix-records "$REPLAY_ROOT" matrix_records "$stage")"
  assert_matrix_records_file "$stage" "$matrix_file"
  while IFS= read -r record; do
    rows[${#rows[@]}]="$record"
  done < "$matrix_file"
  cleanup_temp_file "$matrix_file"
  test "${#rows[@]}" -gt 0 || fail "empty $stage matrix stage"
  local paths=() snapshots=() row path old_blob old_mode new_blob new_mode old_kind
  for row in "${rows[@]}"; do
    IFS=$'	' read -r path old_blob old_mode new_blob new_mode <<< "$row"
    paths+=("$path")
    snapshots+=("$row")
  done
  DIRTY_PATHS=()
  before_mutation
  assert_declared_projection "$projection_lane"
  for row in "${snapshots[@]}"; do
    IFS=$'	' read -r path old_blob old_mode new_blob new_mode <<< "$row"
    assert_declared_projection "$projection_lane" "$path"
    old_kind=file
    [ "$old_blob" = - ] && old_kind=absent
    [ "$old_mode" = - ] && old_mode=-
    [ "$new_blob" = - ] && fail "matrix target unexpectedly absent for $path"
    assert_source_blob "$target" "$path" "$new_blob"
    cas_path "$path" "$old_blob" "$old_mode" "$old_kind" "$new_blob" "$new_mode" file
  done
  assert_exact_staged "${paths[@]}"
  git_replay diff --cached --check -- "${paths[@]}"
  test "$(binary_patch_id "$source_left" "$target" "${paths[@]}")" = "$expected_patch" || fail "approved mechanical source patch-id mismatch for $stage"
  test "$(raw_patch_sha256 "$source_left" "$target" "${paths[@]}")" = "$expected_raw" || fail "approved mechanical source raw SHA mismatch for $stage"
  assert_cached_patch - "${paths[@]}"
  commit_staged "replay(task409): $stage semantic projection" - "${paths[@]}"
}


assert_stage_two_overlap() {
  "$PYTHON" - "$MATRIX" "$REPLAY" "$CURRENT_HEAD" <<'PY'
ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}  # hermetic Git environment
import os
import stat

def read_stable_file(path, label='file'):
    path = os.fspath(path)
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_size, st.st_nlink)

    def parent_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_nlink)

    # Bind the expected parent before opening it by pathname. A canonical
    # directory can still be swapped for another canonical directory between
    # realpath/lstat and open; comparing the pre-open lstat with the held
    # descriptor prevents that substitution from redirecting the child read.
    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            second = os.fstat(fd)
            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent identity changed while reading')
    if file_identity(first) != file_identity(second) or file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return b''.join(chunks), first

import json
import subprocess
import sys
m, repo, head = json.loads(read_stable_file(sys.argv[1], 'matrix')[0].decode('utf-8')), sys.argv[2], sys.argv[3]
def run(*args):
    return subprocess.check_output(['/usr/bin/git','--no-replace-objects','--no-lazy-fetch','--no-optional-locks','-C',repo,'-c','core.hooksPath=/dev/null','-c','protocol.allow=never',*args], text=True, env=ENV).strip()
rows = {r['path']: r for r in m['live_overlap']['blob_matrix']}
for path in m['live_overlap']['stage_two_required_d3_overlap_paths']:
    if run('rev-parse', f'{head}:{path}') != rows[path]['d3_launcher_blob']:
        raise SystemExit(f'd3 overlap mismatch for {path}')
if run('rev-parse', f'{head}:scripts/README.md') != m['live_overlap']['scripts_readme']['proxy_post_lane_blob']:
    raise SystemExit('README changed before separate merge')
PY
}

merge_scripts_readme() {
  local merged_blob parent
  before_mutation
  "$PYTHON" - "$REPLAY" "$README_TMP" "$MATRIX" <<'PY'
ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}  # hermetic Git environment
import os
import stat

def read_stable_file(path, label='file'):
    path = os.fspath(path)
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_size, st.st_nlink)

    def parent_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_nlink)

    # Bind the expected parent before opening it by pathname. A canonical
    # directory can still be swapped for another canonical directory between
    # realpath/lstat and open; comparing the pre-open lstat with the held
    # descriptor prevents that substitution from redirecting the child read.
    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            second = os.fstat(fd)
            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent identity changed while reading')
    if file_identity(first) != file_identity(second) or file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return b''.join(chunks), first

from pathlib import Path
import hashlib
import json
import subprocess
import sys
repo, out, matrix = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
git = '/usr/bin/git'
def show(spec):
    return subprocess.check_output([git, '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-C', str(repo), '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', 'show', spec], env=ENV)
metadata = json.loads(read_stable_file(matrix, 'matrix source')[0].decode('utf-8'))
anchor_text = metadata['live_overlap']['scripts_readme']['section_anchor']
if not isinstance(anchor_text, str):
    raise SystemExit('README anchor metadata is not a string')
anchor = anchor_text.encode('utf-8')
if anchor != b'## Disposable Caddy proof renderer\n':
    raise SystemExit('README anchor metadata does not decode to the canonical LF anchor')
prefix = show('80fe3b68fb676a3b6589fce9aed79140bf37b667:scripts/README.md')
section = show('e3a2d2e662f2e606f318d35f4fccc63ba9738f7c:scripts/README.md')
if prefix.count(anchor) != 1 or section.count(anchor) != 1:
    raise SystemExit('README anchor count mismatch')
merged = prefix.split(anchor, 1)[0] + section[section.index(anchor):]
if len(merged) != 44854 or merged.count(b'\n') != 739:
    raise SystemExit('README shape mismatch')
if hashlib.sha256(merged).hexdigest() != '2a15d48344d3d00c9e6a0f95f1805ec41c251b8886487bb3b1935fdff70c2030':
    raise SystemExit('README SHA-256 mismatch')
out.write_bytes(merged)
PY
  test -f "$README_TMP"
  before_mutation
  merged_blob="$(git_replay hash-object -w -- "$README_TMP")"
  test "$merged_blob" = d74f0c1431901f83e736389395a122c48e521a32 || fail "README Git blob mismatch"
  cas_path scripts/README.md c2a31b8b58237551b698c64671a027da28ed84ff 100644 file "$merged_blob" 100644 file
  assert_exact_staged scripts/README.md
  git_replay diff --cached --check -- scripts/README.md
  parent="$CURRENT_HEAD"
  commit_staged 'replay(task409): reviewed scripts README merge' - scripts/README.md
}

assert_final_matrix() {
  "$PYTHON" - "$MATRIX" "$REPLAY" "$CURRENT_HEAD" <<'PY'
ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}  # hermetic Git environment
import os
import stat

def read_stable_file(path, label='file'):
    path = os.fspath(path)
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_size, st.st_nlink)

    def parent_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_nlink)

    # Bind the expected parent before opening it by pathname. A canonical
    # directory can still be swapped for another canonical directory between
    # realpath/lstat and open; comparing the pre-open lstat with the held
    # descriptor prevents that substitution from redirecting the child read.
    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            second = os.fstat(fd)
            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent identity changed while reading')
    if file_identity(first) != file_identity(second) or file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return b''.join(chunks), first

import hashlib
import json
import subprocess
import sys
m, repo, head = json.loads(read_stable_file(sys.argv[1], 'matrix')[0].decode('utf-8')), sys.argv[2], sys.argv[3]
def run(*args):
    return subprocess.check_output(['/usr/bin/git','--no-replace-objects','--no-lazy-fetch','--no-optional-locks','-C',repo,'-c','core.hooksPath=/dev/null','-c','protocol.allow=never',*args], text=True, env=ENV).strip()
for row in m['live_overlap']['blob_matrix']:
    path = row['path']
    actual = run('rev-parse', f'{head}:{path}')
    if actual != row['expected_final_blob']:
        raise SystemExit(f'final blob mismatch for {path}')
    tree_line = run('ls-tree', head, '--', path)
    if not tree_line.startswith(row['expected_final_mode'] + ' blob '):
        raise SystemExit(f'final mode/type mismatch for {path}')
readme = subprocess.check_output(['/usr/bin/git','--no-replace-objects','--no-lazy-fetch','--no-optional-locks','-C',repo,'-c','core.hooksPath=/dev/null','-c','protocol.allow=never','show',f'{head}:scripts/README.md'], env=ENV)
info = m['live_overlap']['scripts_readme']
if len(readme) != info['expected_bytes'] or readme.count(b'\n') != info['expected_lines']:
    raise SystemExit('final README shape mismatch')
if hashlib.sha256(readme).hexdigest() != info['expected_sha256']:
    raise SystemExit('final README SHA mismatch')
if run('rev-parse', f'{head}:scripts/README.md') != info['expected_git_blob']:
    raise SystemExit('final README blob mismatch')
PY
}

assert_forbidden_ancestry() {
  local bad_object ancestry_file
  local bad_objects=()
  ancestry_file="$(producer_to_file forbidden-ancestry "$REPLAY_ROOT" forbidden_ancestry_records)"
  assert_forbidden_ancestry_records_file "$ancestry_file"
  while IFS= read -r bad_object; do
    bad_objects[${#bad_objects[@]}]="$bad_object"
  done < "$ancestry_file"
  cleanup_temp_file "$ancestry_file"
  test "${#bad_objects[@]}" -gt 0 || fail "forbidden ancestry producer emitted no rows"
  bad_objects[${#bad_objects[@]}]="$REJECTED_AUTH_LEFT"
  bad_objects[${#bad_objects[@]}]="$REJECTED_AUTH_RIGHT"
  local bad rc
  for bad in "${bad_objects[@]}"; do
    set +e
    git_replay merge-base --is-ancestor "$bad" "$CURRENT_HEAD"
    rc=$?
    set -e
    test "$rc" -eq 1 || fail "forbidden ancestry $bad returned $rc, expected exact rc=1"
  done
}

assert_root_empty() {
  "$PYTHON" - "$REPLAY_ROOT" "$REPLAY_ROOT_DEVICE" "$REPLAY_ROOT_INODE" "$REPLAY_ROOT_UID" "$REPLAY_ROOT_MODE" "$REPLAY_ROOT_REALPATH" <<'PY'
import os
import stat
import sys
root, expected_device, expected_inode, expected_uid, expected_mode, expected_realpath = sys.argv[1:]
st = os.lstat(root)
if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
    raise SystemExit('replay root is not a non-symlink directory before rmdir')
if (str(st.st_dev), str(st.st_ino), str(st.st_uid), format(stat.S_IMODE(st.st_mode), '04o')) != (expected_device, expected_inode, expected_uid, expected_mode):
    raise SystemExit('replay root lstat identity changed before rmdir')
if os.path.realpath(root) != expected_realpath or expected_realpath != root:
    raise SystemExit('replay root canonical identity changed before rmdir')
if os.listdir(root):
    raise SystemExit('replay root is not empty before rmdir')
PY
}


assert_final_root_cleanup_boundary() {
  assert_root_shape
  assert_worktree_separation
  assert_primary_pins
  test "$REPLAY_READY" -eq 0 || fail "replay checkout still marked ready before root removal"
  test -z "$CURRENT_HEAD" && test -z "$CURRENT_TREE" || fail "replay state remains bound before root removal"
  test "${#DIRTY_PATHS[@]}" -eq 0 || fail "dirty paths remain before root removal"
  assert_root_empty
}

assert_replay_preinit_state() {
  # Targeted regression smoke for the descriptor-created, pre-init child: it
  # must be present and bound, while no Git registry call is permitted yet.
  test "$REPLAY_ROOT_BOUND" -eq 1 || fail "pre-init smoke lost replay root binding"
  test "$REPLAY_CHECKOUT_PRESENT" -eq 1 || fail "pre-init smoke lost checkout presence"
  test "$REPLAY_CHECKOUT_BOUND" -eq 1 || fail "pre-init smoke lost checkout identity"
  test "$REPLAY_GIT_BOUND" -eq 0 || fail "pre-init smoke ran Git identity too early"
  test -d "$REPLAY" && test ! -e "$REPLAY/.git" || fail "pre-init smoke found Git metadata"
  assert_root_shape
  assert_worktree_separation
}

assert_replay_checkout_removed_state() {
  # Regression guard: checkout removal leaves the root bound for final rmdir,
  # but no child or Git identity may be consumed by later cleanup assertions.
  test "$REPLAY_ROOT_BOUND" -eq 1 || fail "removed-checkout smoke lost replay root binding"
  test "$REPLAY_CHECKOUT_PRESENT" -eq 0 || fail "removed-checkout smoke still marks child present"
  test "$REPLAY_CHECKOUT_BOUND" -eq 0 || fail "removed-checkout smoke still binds child identity"
  test "$REPLAY_GIT_BOUND" -eq 0 || fail "removed-checkout smoke still binds Git identity"
  test ! -e "$REPLAY" && test ! -L "$REPLAY" || fail "removed-checkout smoke found replay child"
  assert_root_shape
  assert_worktree_separation
  test "$REPLAY_CHECKOUT_PRESENT" -eq 0 || fail "removed-checkout smoke state drifted"
}

cleanup_success_only() {
  local path allowed item
  for path in "$@"; do
    allowed=0
    for item in "${CLEANUP_ALLOWLIST[@]}"; do
      [ "$path" = "$item" ] && allowed=1
    done
    test "$allowed" -eq 1 || fail "cleanup path is not allowlisted: $path"
    case "$path" in "$REPLAY_ROOT"/*) ;; *) fail "cleanup path escaped replay root: $path" ;; esac
    [ -e "$path" ] || [ -L "$path" ] || continue
    case "$path" in
      "$REPLAY")
        before_mutation
        "$RM" -rf -- "$path"
        REPLAY_READY=0
        CURRENT_HEAD=''
        CURRENT_TREE=''
        BOOTSTRAP_HEAD=''
        BOOTSTRAP_TREE=''
        DIRTY_PATHS=()
        REPLAY_CHECKOUT_PRESENT=0
        REPLAY_CHECKOUT_BOUND=0
        REPLAY_GIT_BOUND=0
        REPLAY_OBJECTS_BOUND=0
        REPLAY_INFO_BOUND=0
        REPLAY_ALTERNATES_BOUND=0
        assert_replay_checkout_removed_state
        ;;
      "$README_TMP") before_mutation; "$RM" -f -- "$path" ;;
      "$MATRIX_SNAPSHOT") before_mutation; "$RM" -f -- "$path"; MATRIX_BOUND=2 ;;
      *) fail "unexpected cleanup path: $path" ;;
    esac
  done
  test ! -e "$REPLAY" || fail 'replay checkout cleanup incomplete'
  test ! -e "$README_TMP" || fail 'README temp cleanup incomplete'
  test ! -e "$MATRIX_SNAPSHOT" || fail 'matrix snapshot cleanup incomplete'
  allowed=0
  for item in "${CLEANUP_ALLOWLIST[@]}"; do
    [ "$REPLAY_ROOT" = "$item" ] && allowed=1
  done
  test "$allowed" -eq 1 || fail 'replay root is not an explicit cleanup allowlist entry'
  assert_final_root_cleanup_boundary
  "$RMDIR" -- "$REPLAY_ROOT"
  REPLAY_ROOT_BOUND=0
  REPLAY_CHECKOUT_BOUND=0
  REPLAY_CHECKOUT_PRESENT=0
  REPLAY_GIT_BOUND=0
}

cleanup_clean_primary_success_only() {
  local allowed item
  test "$CLEAN_PRIMARY_ROOT_BOUND" -eq 1 || fail 'clean-primary root is not bound for cleanup'
  allowed=0
  for item in "${CLEAN_PRIMARY_CLEANUP_ALLOWLIST[@]}"; do
    [ "$CLEAN_PRIMARY_ROOT" = "$item" ] && allowed=1
  done
  test "$allowed" -eq 1 || fail 'clean-primary cleanup path is not allowlisted'
  assert_source_binding
  assert_clean_primary_state
  assert_worktree_separation
  "$PYTHON" - "$CLEAN_PRIMARY_ROOT" "$CLEAN_PRIMARY_ROOT_DEVICE" "$CLEAN_PRIMARY_ROOT_INODE" "$CLEAN_PRIMARY_ROOT_UID" "$CLEAN_PRIMARY_ROOT_MODE" "$CLEAN_PRIMARY_ROOT_REALPATH" "$CLEAN_PRIMARY" <<'PY'
import os
import stat
import sys
root, expected_device, expected_inode, expected_uid, expected_mode, expected_realpath, repository = sys.argv[1:]
st = os.lstat(root)
if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or os.path.realpath(root) != expected_realpath or expected_realpath != root:
    raise SystemExit('clean-primary root identity changed before cleanup')
if (str(st.st_dev), str(st.st_ino), str(st.st_uid), format(stat.S_IMODE(st.st_mode), '04o')) != (expected_device, expected_inode, expected_uid, expected_mode):
    raise SystemExit('clean-primary root lstat changed before cleanup')
if set(os.listdir(root)) != {os.path.basename(repository)}:
    raise SystemExit('unknown clean-primary cleanup artifact present')
if os.path.islink(repository) or not os.path.isdir(repository) or os.path.realpath(repository) != repository:
    raise SystemExit('clean-primary repository changed before cleanup')
PY
  "$RM" -rf -- "$CLEAN_PRIMARY_ROOT"
  test ! -e "$CLEAN_PRIMARY_ROOT" || fail 'clean-primary cleanup incomplete'
  CLEAN_PRIMARY_ROOT_BOUND=0
  CLEAN_PRIMARY_REPOSITORY_BOUND=0
  CLEAN_PRIMARY_BOUND=0
}


# Static manifest validation is read-only. SOURCE may be noisy; the clean-primary copy is validated separately.
static_validate_matrix() {
  local repository="$1"
  "$PYTHON" - "$MATRIX" "$repository" "$MARKDOWN" "$MATRIX_EXPECTED_BINDING_SHA256" <<'PY'
from __future__ import annotations
ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}  # hermetic Git environment
import os
import stat

def read_stable_file(path, label='file'):
    path = os.fspath(path)
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SystemExit(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)

    def file_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_size, st.st_nlink)

    def parent_identity(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_nlink)

    # Bind the expected parent before opening it by pathname. A canonical
    # directory can still be swapped for another canonical directory between
    # realpath/lstat and open; comparing the pre-open lstat with the held
    # descriptor prevents that substitution from redirecting the child read.
    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise SystemExit(f'{label} parent is not a canonical directory')
    expected_parent = parent_identity(parent_pre)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent_first = os.fstat(parent_fd)
        if parent_identity(parent_first) != expected_parent:
            raise SystemExit(f'{label} parent identity changed before child open')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise SystemExit(f'{label} is not a regular single-link file')
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            second = os.fstat(fd)
            final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            parent_second = os.fstat(parent_fd)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
    if parent_identity(parent_first) != parent_identity(parent_second):
        raise SystemExit(f'{label} parent identity changed while reading')
    if file_identity(first) != file_identity(second) or file_identity(first) != file_identity(final):
        raise SystemExit(f'{label} descriptor/final-path identity changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
        raise SystemExit(f'{label} final path is not a regular single-link file')
    if os.path.realpath(path) != path:
        raise SystemExit(f'{label} path became non-canonical while reading')
    return b''.join(chunks), first

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

matrix, repo, markdown, expected_binding = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]), sys.argv[4]
raw_matrix, _matrix_stat = read_stable_file(matrix, 'matrix source')

def normalized_matrix_bytes(raw, token):
    normalized = raw.replace(token.encode('ascii'), b'0' * 64)
    for key in (b'"shell_sha256": "', b'"driver_shell_sha256": "', b'"expected_body_sha256": "'):
        normalized = re.sub(re.escape(key) + rb'[0-9a-f]{64}(?=")', lambda match: match.group(0)[:len(key)] + b'0' * 64, normalized)
    return normalized

data = json.loads(raw_matrix)
execution_driver = data['execution_driver']
validation_contract = data['validation_contract']
for identity_key in ('matrix_identity', 'replay_root_identity', 'clean_primary_storage_identity'):
    if execution_driver.get(identity_key) != validation_contract.get(identity_key):
        raise SystemExit(f'duplicated identity contract mismatch: {identity_key}')
if execution_driver.get('source_of_truth') != '/execution_driver/shell':
    raise SystemExit('execution driver source-of-truth mismatch')
stale_scripts = execution_driver.get('non_authoritative_standalone_scripts')
if not isinstance(stale_scripts, list) or not any(item.get('path') == '/private/tmp/' + 'hermternal-task409-approved-driver.sh' and 'non-authoritative' in item.get('status', '') for item in stale_scripts):
    raise SystemExit('stale standalone driver policy is missing')
fresh_requirement = execution_driver.get('fresh_shell_requirement')
if not isinstance(fresh_requirement, dict) or fresh_requirement.get('required_before_execution') is not True:
    raise SystemExit('fresh shell extraction requirement is missing')
identity = execution_driver['matrix_identity']
if identity['source_path'] != str(matrix):
    raise SystemExit('matrix source-path metadata mismatch')
if identity['expected_normalized_sha256'] != expected_binding:
    raise SystemExit('matrix identity token mismatch')
if hashlib.sha256(normalized_matrix_bytes(raw_matrix, expected_binding)).hexdigest() != expected_binding:
    raise SystemExit('matrix source normalized SHA-256 mismatch')
shell_bytes = execution_driver['shell'].encode('utf-8')
shell_sha = hashlib.sha256(shell_bytes).hexdigest()
if execution_driver['shell_sha256'] != shell_sha or validation_contract['driver_shell_sha256'] != shell_sha:
    raise SystemExit('driver shell hash metadata mismatch')
expected_shell_metadata = {'body_bytes': len(shell_bytes), 'body_lines': len(shell_bytes.splitlines()), 'terminal_byte_hex': shell_bytes[-1:].hex()}
if execution_driver.get('shell_size_metadata') != expected_shell_metadata or validation_contract.get('shell_size_metadata') != expected_shell_metadata:
    raise SystemExit('numeric shell metadata mismatch')
if validation_contract.get('driver_shell_body_bytes') != len(shell_bytes) or validation_contract.get('driver_shell_body_lines') != len(shell_bytes.splitlines()):
    raise SystemExit('duplicated numeric shell size metadata mismatch')
extraction = data['execution_driver']['markdown_fence_extraction']
markdown_bytes, _markdown_stat = read_stable_file(markdown, 'Markdown source')
full_ids = set(re.findall(r'(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])', (raw_matrix + markdown_bytes).decode('utf-8').lower()))
short_ref = re.compile(r'(?<![0-9a-f])[0-9a-f]{7,39}(?![0-9a-f])')
for label, payload in (('JSON', raw_matrix.decode('utf-8')), ('Markdown', markdown_bytes.decode('utf-8'))):
    for match in short_ref.finditer(payload.lower()):
        token = match.group(0)
        if any(value.startswith(token) for value in full_ids):
            raise SystemExit(f'abbreviated exact reference in {label}: {token}')
section_heading = extraction['section_heading'].encode('utf-8')
section_start = markdown_bytes.index(section_heading)
opening = extraction['opening_fence'].encode('ascii')
closing = extraction['closing_fence'].encode('ascii')
opening_start = markdown_bytes.index(opening, section_start + len(section_heading))
body_start = opening_start + len(opening)
closing_start = markdown_bytes.index(closing, body_start)
body = markdown_bytes[body_start:closing_start]
if body != shell_bytes:
    raise SystemExit('Markdown direct-fence body differs from JSON shell')
if len(body) != extraction['expected_body_bytes'] or hashlib.sha256(body).hexdigest() != extraction['expected_body_sha256']:
    raise SystemExit('Markdown direct-fence body metadata mismatch')
if extraction['expected_body_bytes'] != len(shell_bytes) or extraction.get('expected_body_lines') != len(shell_bytes.splitlines()):
    raise SystemExit('Markdown and JSON shell size metadata mismatch')
if body[-1:].hex() != extraction['expected_terminal_byte_hex'] or shell_bytes[-1:].hex() != extraction['expected_terminal_byte_hex']:
    raise SystemExit('driver terminal-byte metadata mismatch')
ordered_steps_header = b'| Order | Step | Boundary | Gate |'
ordered_steps_start = markdown_bytes.index(ordered_steps_header)
ordered_steps_lines = markdown_bytes[ordered_steps_start:].splitlines()
parsed_md_steps = []
for line in ordered_steps_lines[2:]:
    if not line.startswith(b'| '):
        break
    fields = line.split(b'|')
    if len(fields) != 6 or not fields[1].strip().isdigit():
        break
    parsed_md_steps.append({
        'order': int(fields[1].strip()),
        'gate': fields[4].strip().decode('utf-8'),
    })
json_steps = data['execution_driver']['ordered_steps']
if len(parsed_md_steps) != 21 or [row['order'] for row in parsed_md_steps] != list(range(1, 22)):
    raise SystemExit('Markdown ordered-step table must contain exactly 21 ordered rows')
if len(json_steps) != 21 or [row['order'] for row in json_steps] != list(range(1, 22)):
    raise SystemExit('JSON ordered-step metadata must contain exactly 21 ordered rows')
if [row['gate'] for row in parsed_md_steps] != [row['gate'] for row in json_steps]:
    raise SystemExit('Markdown and JSON ordered-step gate strings differ')
appendix_metadata = validation_contract['markdown_parity_appendix']
appendix_heading = appendix_metadata['section_heading'].encode('utf-8')
appendix_opening = appendix_metadata['opening_fence'].encode('ascii')
appendix_closing = appendix_metadata['closing_fence'].encode('ascii')
appendix_heading_start = markdown_bytes.index(appendix_heading)
appendix_opening_start = markdown_bytes.index(appendix_opening, appendix_heading_start + len(appendix_heading))
appendix_body_start = appendix_opening_start + len(appendix_opening)
appendix_closing_start = markdown_bytes.index(appendix_closing, appendix_body_start)
appendix = json.loads(markdown_bytes[appendix_body_start:appendix_closing_start].decode('utf-8'))
target_mirrors = []
changed_mirrors = []
def collect_mirrors(node, pointer=''):
    if isinstance(node, dict):
        if 'target_states' in node:
            target_mirrors.append({'json_pointer': pointer or '/', 'changed_paths': node.get('changed_paths', []), 'target_states': node['target_states']})
        if 'changed_paths' in node:
            changed_mirrors.append({'json_pointer': pointer or '/', 'changed_paths': node['changed_paths']})
        for key, value in node.items():
            child = f'{pointer}/{key}' if pointer else f'/{key}'
            collect_mirrors(value, child)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            child = f'{pointer}/{index}' if pointer else f'/{index}'
            collect_mirrors(value, child)
collect_mirrors(data)
expected_appendix = {'target_states': target_mirrors, 'historical_changed_paths': changed_mirrors}
if appendix != expected_appendix:
    raise SystemExit('Markdown target-state/changed-path mirror content mismatch')
if appendix_metadata['target_state_entry_count'] != len(target_mirrors) or appendix_metadata['target_state_path_count'] != sum(len(row['target_states']) for row in target_mirrors):
    raise SystemExit('Markdown target-state mirror counts mismatch')
if appendix_metadata['historical_changed_path_entry_count'] != len(changed_mirrors) or appendix_metadata['historical_changed_path_count'] != sum(len(row['changed_paths']) for row in changed_mirrors):
    raise SystemExit('Markdown historical changed-path mirror counts mismatch')

git = '/usr/bin/git'
HEX = re.compile(r'^[0-9a-f]{40}$')

def run(*args, check=True, input_bytes=None):
    p = subprocess.run([git, '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', *args], input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV)
    if check and p.returncode:
        raise SystemExit(f'Git command failed ({p.returncode}): {args!r}: {p.stderr.decode(errors="replace")}')
    return p

def out(*args):
    return run(*args).stdout.decode().strip()
def assert_object_closure():
    if out('rev-parse', '--show-object-format') != 'sha1':
        raise SystemExit('repository object format is not SHA-1')
    if out('rev-parse', '--is-shallow-repository') != 'false':
        raise SystemExit('repository is shallow')
    git_dir = Path(out('rev-parse', '--absolute-git-dir'))
    if os.path.realpath(git_dir) != str(git_dir):
        raise SystemExit('repository Git directory is not canonical')
    forbidden = (
        git_dir / 'shallow', git_dir / 'info' / 'grafts',
        git_dir / 'refs' / 'replace', git_dir / 'objects' / 'info' / 'alternates',
        git_dir / 'objects' / 'info' / 'http-alternates',
    )
    if any(path.exists() or path.is_symlink() for path in forbidden):
        raise SystemExit('repository contains forbidden shallow, graft, replacement, or alternate metadata')
    packed_refs = git_dir / 'packed-refs'
    if packed_refs.exists() and b'refs/replace/' in packed_refs.read_bytes():
        raise SystemExit('repository contains packed replacement refs')
    pack_dir = git_dir / 'objects' / 'pack'
    if pack_dir.exists() and (pack_dir.is_symlink() or os.path.realpath(pack_dir) != str(pack_dir)):
        raise SystemExit('repository pack directory is not canonical')
    if pack_dir.is_dir():
        for directory, names, files in os.walk(pack_dir, topdown=True, followlinks=False):
            names[:] = sorted(names)
            files.sort()
            if any(os.path.islink(os.path.join(directory, name)) for name in names):
                raise SystemExit('repository pack metadata contains a symlinked directory')
            if any(name.endswith('.promisor') for name in files):
                raise SystemExit('repository contains promisor pack metadata')
    config = run('config', '--local', '--get-regexp', r'^(extensions\.partialClone|remote\..*|protocol\..*\.allow)$', check=False)
    for line in config.stdout.decode().splitlines():
        key, _, value = line.partition(' ')
        if key.lower() == 'extensions.partialclone' or key.lower().endswith('.promisor') or key.lower().endswith('.vcs'):
            raise SystemExit('repository contains partial-clone, promisor, or custom-helper configuration')
        if value.strip().lower() not in ('never', ''):
            raise SystemExit('repository contains an unsafe protocol transport policy')
    fsck = run('fsck', '--full', '--strict', '--no-reflogs', '--no-progress')
    if fsck.returncode != 0:
        raise SystemExit('strict repository fsck failed')
    missing = run('rev-list', '--objects', '--all', '--missing=error')
    if missing.returncode != 0:
        raise SystemExit('repository object closure is incomplete')
    expected_by_key = {
        'commit': 'commit', 'parent': 'commit', 'parents': 'commit',
        'child': 'commit', 'tree': 'tree', 'blob': 'blob',
    }
    object_ids = {}
    def collect(node, key=None):
        if isinstance(node, dict):
            for child_key, child in node.items():
                collect(child, child_key)
        elif isinstance(node, list):
            for child in node:
                collect(child, key)
        elif isinstance(node, str) and re.fullmatch(r'[0-9a-f]{40}', node) and key in expected_by_key:
            object_ids[node] = expected_by_key[key]
    collect(data)
    for object_id, expected_type in sorted(object_ids.items()):
        actual = out('cat-file', '-t', object_id)
        if actual != expected_type:
            raise SystemExit(f'explicit object type mismatch: {object_id}: {actual} != {expected_type}')

assert_object_closure()

def oid(value, kind, label, missing=False):
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise SystemExit(f'{label}: expected full lowercase ID, got {value!r}')
    p = run('cat-file', '-t', value, check=False)
    actual = p.stdout.decode().strip() if p.returncode == 0 else 'missing'
    if missing and actual == 'missing':
        return
    if actual != kind:
        raise SystemExit(f'{label}: expected {kind}, got {actual} for {value}')

def changed(commit):
    return set(out('diff-tree', '--root', '--no-commit-id', '--name-only', '-r', commit).splitlines())

def tree_state(ref, path):
    raw = out('ls-tree', ref, '--', path)
    if not raw:
        return {'blob': None, 'mode': None, 'type': 'absent'}
    lines = raw.splitlines()
    if len(lines) != 1:
        raise SystemExit(f'ambiguous tree state for {ref}:{path}')
    meta, recorded = lines[0].split('\t', 1)
    if recorded != path:
        raise SystemExit(f'tree path mismatch for {ref}:{path}')
    mode, kind, blob = meta.split()
    return {'blob': blob if kind == 'blob' else None, 'mode': mode, 'type': 'file' if kind == 'blob' else kind}

def patch_id(left, right, paths):
    raw = run('diff', '--binary', '--full-index', '--no-ext-diff', '--no-textconv', left, right, '--', *paths).stdout
    if not raw:
        raise SystemExit(f'empty binary patch: {left}..{right} {paths!r}')
    p = subprocess.run([git, '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', '-c', 'protocol.allow=never', 'patch-id', '--stable'], input=raw, stdout=subprocess.PIPE, check=True, env=ENV)
    return p.stdout.decode().split()[0], raw

def validate_commit(c, label, require_target_states=False):
    commit = c['commit']
    oid(commit, 'commit', label + '.commit')
    parents = out('rev-list', '--parents', '-n', '1', commit).split()[1:]
    if parents != c['parents']:
        raise SystemExit(f'{label}: parent mismatch')
    if out('rev-parse', f'{commit}^{{tree}}') != c['tree']:
        raise SystemExit(f'{label}: tree mismatch')
    changed_paths = set(c.get('changed_paths', []))
    if changed(commit) != changed_paths:
        raise SystemExit(f'{label}: exact changed-path scope mismatch')
    if require_target_states:
        states = c.get('target_states')
        if not isinstance(states, dict) or set(states) != changed_paths:
            raise SystemExit(f'{label}: exact target-state scope mismatch')
        for path in c['changed_paths']:
            expected = states[path]
            if expected.get('tree') != c['tree']:
                raise SystemExit(f'{label}.{path}: target tree binding mismatch')
            actual = tree_state(commit, path)
            for key in ('blob', 'mode', 'type'):
                if actual.get(key) != expected.get(key):
                    raise SystemExit(f'{label}.{path}: target {key} mismatch')
            if expected['type'] == 'file':
                oid(expected['blob'], 'blob', f'{label}.{path}.target_blob')
    if len(parents) == 1 and c.get('stable_patch_id'):
        actual, _ = patch_id(parents[0], commit, c['changed_paths'])
        if actual != c['stable_patch_id']:
            raise SystemExit(f'{label}: stable patch-id mismatch')

if out('rev-parse', 'origin/dev') != data['base']['commit'] or data['base']['commit'] != '729f2613af2b78d58b07918478e9102d5716f367':
    raise SystemExit('base/origin/dev mismatch')
if out('rev-parse', 'origin/main') != data['base']['protected_main_commit']:
    raise SystemExit('origin/main mismatch')
oid(data['base']['commit'], 'commit', 'base.commit')
oid(data['base']['tree'], 'tree', 'base.tree')
oid(data['base']['protected_main_commit'], 'commit', 'protected_main.commit')
if out('rev-parse', f'{data["base"]["commit"]}^{{tree}}') != data['base']['tree']:
    raise SystemExit('base tree mismatch')

stable_ids = []
for lane in data['ordered_lanes']:
    name = lane['id']
    r = lane.get('range')
    if r:
        commits = out('rev-list', '--reverse', r['notation']).split()
        listed = [c['commit'] for c in r['source_commits']]
        if commits != listed or len(commits) != r['count']:
            raise SystemExit(f'{name}: inclusive range mismatch')
        if int(out('rev-list', '--merges', '--count', r['notation'])) != r['merge_commit_count']:
            raise SystemExit(f'{name}: merge count mismatch')
        union = set()
        for c in r['source_commits']:
            validate_commit(c, f'{name}.{c["commit"]}', require_target_states=True)
            union.update(c['changed_paths'])
            stable_ids.append(c['stable_patch_id'])
        if union != set(r['path_allowlist']) or len(union) != len(r['path_allowlist']):
            raise SystemExit(f'{name}: range path scope mismatch')
        actual, _ = patch_id(r['left'], r['right'], r['path_allowlist'])
        if actual != r['cumulative_stable_patch_id']:
            raise SystemExit(f'{name}: cumulative patch-id mismatch')
        stable_ids.append(r['cumulative_stable_patch_id'])
    for key in ('source_commit', 'intermediate_checkpoint'):
        c = lane.get(key)
        if c:
            validate_commit(c, f'{name}.{key}')
            stable_ids.append(c['stable_patch_id'])
    sd = lane.get('semantic_delta')
    if sd:
        oid(sd['parent'], 'commit', f'{name}.semantic.parent')
        oid(sd['child'], 'commit', f'{name}.semantic.child')
        oid(sd['parent_tree'], 'tree', f'{name}.semantic.parent_tree')
        oid(sd['child_tree'], 'tree', f'{name}.semantic.child_tree')
        if out('rev-parse', f"{sd['parent']}^{{tree}}") != sd['parent_tree']:
            raise SystemExit(f'{name}: semantic parent tree binding mismatch')
        if out('rev-parse', f"{sd['child']}^{{tree}}") != sd['child_tree']:
            raise SystemExit(f'{name}: semantic child tree binding mismatch')
        parents = out('rev-list', '--parents', '-n', '1', sd['child']).split()[1:]
        if parents != sd['child_parents']:
            raise SystemExit(f'{name}: semantic child parent mismatch')
        if changed(sd['child']) != set(sd['delta_paths']):
            raise SystemExit(f'{name}: semantic delta scope mismatch')
        actual, _ = patch_id(sd['parent'], sd['child'], sd['delta_paths'])
        if actual != sd['stable_patch_id']:
            raise SystemExit(f'{name}: semantic patch-id mismatch')
        stable_ids.append(sd['stable_patch_id'])

    if name in {
        'renderer-lifecycle', 'authentication-semantic-delta', 'fixture-registry-authority',
        'dependency-audit-correction', 'swift-parity-correction',
        'launcher-semantic-projection', 'live-proof-semantic-projection',
    }:
        source_state = lane.get('source_parent_state')
        stage_state = lane.get('stage_precondition')
        if not source_state or not stage_state:
            raise SystemExit(f'{name}: missing declared source-parent/stage state maps')
        source_paths = set(source_state['paths'])
        expected_path_list = lane.get('semantic_delta', {}).get('owned_paths') or lane.get('owned_paths') or lane.get('projection_paths')
        expected_paths = set(expected_path_list)
        if source_paths != expected_paths or set(stage_state['paths']) != expected_paths:
            raise SystemExit(f'{name}: declared projection state path scope mismatch')
        source_tree = out('rev-parse', f"{source_state['commit']}^{{tree}}")
        if source_tree != source_state['tree']:
            raise SystemExit(f'{name}: declared source-parent tree mismatch')
        for path, record in source_state['paths'].items():
            if record.get('tree') != source_state['tree']:
                raise SystemExit(f'{name}.{path}: source-parent path tree mismatch')
            actual = tree_state(source_state['commit'], path)
            if any(actual.get(key) != record.get(key) for key in ('blob', 'mode', 'type')):
                raise SystemExit(f'{name}.{path}: source-parent blob/mode/type mismatch')
            if record['type'] == 'file':
                oid(record['blob'], 'blob', f'{name}.{path}.source_parent_blob')
        for path, record in stage_state['paths'].items():
            tree_commit = record.get('tree_commit')
            if not isinstance(tree_commit, str) or len(tree_commit) != 40:
                raise SystemExit(f'{name}.{path}: stage tree commit missing')
            stage_tree = out('rev-parse', f"{tree_commit}^{{tree}}")
            if stage_tree != record.get('tree'):
                raise SystemExit(f'{name}.{path}: stage tree mismatch')
            actual = tree_state(tree_commit, path)
            if any(actual.get(key) != record.get(key) for key in ('blob', 'mode', 'type')):
                raise SystemExit(f'{name}.{path}: stage blob/mode/type mismatch')
            if record['type'] == 'file':
                oid(record['blob'], 'blob', f'{name}.{path}.stage_blob')
    oracle = lane.get('rehearsal_oracle')
    if oracle:
        validate_commit(oracle, f'{name}.rehearsal_oracle')
        stable_ids.append(oracle['stable_patch_id'])
    audit = lane.get('source_ancestry_audit')
    if audit:
        commits = out('rev-list', '--reverse', audit['notation']).split()
        listed = [c['commit'] for c in audit['source_commits']]
        if commits != listed or len(commits) != audit['count']:
            raise SystemExit(f'{name}: ancestry audit range mismatch')
        if int(out('rev-list', '--merges', '--count', audit['notation'])) != audit['merge_commit_count']:
            raise SystemExit(f'{name}: ancestry audit merge count mismatch')
        union = set()
        for c in audit['source_commits']:
            validate_commit(c, f'{name}.audit.{c["commit"]}')
            union.update(c['changed_paths'])
            stable_ids.append(c['stable_patch_id'])
        if union != set(audit['path_allowlist']):
            raise SystemExit(f'{name}: ancestry audit path scope mismatch')
        actual, _ = patch_id(audit['left'], audit['right'], audit['path_allowlist'])
        if actual != audit['cumulative_stable_patch_id']:
            raise SystemExit(f'{name}: ancestry audit cumulative patch-id mismatch')
        stable_ids.append(audit['cumulative_stable_patch_id'])

# A source ancestry audit can repeat a patch ID already recorded by its source_commit.
# Duplicate application is rejected by assert_unique_patch_id in the replay transaction;
# here require uniqueness inside every independently executable source sequence.
for lane in data['ordered_lanes']:
    for key in ('range', 'source_ancestry_audit'):
        sequence = lane.get(key)
        if sequence:
            sequence_ids = [c['stable_patch_id'] for c in sequence['source_commits']]
            if len(sequence_ids) != len(set(sequence_ids)):
                raise SystemExit(f"{lane['id']}: duplicate stable patch ID inside executable sequence")

for lane_id in ('launcher-semantic-projection', 'live-proof-semantic-projection'):
    lane = next(x for x in data['ordered_lanes'] if x['id'] == lane_id)
    left, right = lane['projection_parent'], lane['source_commit']['commit']
    actual, raw = patch_id(left, right, lane['projection_paths'])
    if actual != lane['source_commit']['approved_scoped_stable_patch_id']:
        raise SystemExit(f'{lane_id}: approved scoped patch-id mismatch')
    if hashlib.sha256(raw).hexdigest() != lane['source_commit']['approved_scoped_raw_sha256']:
        raise SystemExit(f'{lane_id}: approved scoped raw SHA mismatch')
    actual, raw = patch_id(left, right, lane['mechanical_paths'])
    if actual != lane['source_commit']['approved_mechanical_scoped_stable_patch_id']:
        raise SystemExit(f'{lane_id}: mechanical patch-id mismatch')
    if hashlib.sha256(raw).hexdigest() != lane['source_commit']['approved_mechanical_scoped_raw_sha256']:
        raise SystemExit(f'{lane_id}: mechanical raw SHA mismatch')

for obj in data['historical_compatibility_objects']:
    oid(obj['commit'], 'commit', 'historical.commit')
    oid(obj['tree'], 'tree', 'historical.tree')
for value in data['forbidden_ancestry']['commits'] + data['forbidden_ancestry']['raw_semantic_source_commits']:
    oid(value, 'commit', 'forbidden.commit')
for endpoint in data['forbidden_ancestry']['authentication_range'].split('..'):
    oid(endpoint, 'commit', 'rejected-auth.endpoint')
for row in data['live_overlap']['blob_matrix']:
    for key in ('base_blob', 'proxy_blob', 'd3_launcher_blob', 'f54_blob', '80fe_live_blob'):
        if row[key]:
            oid(row[key], 'blob', f'{row["path"]}.{key}')
    for key in ('base_mode', 'proxy_mode', 'd3_launcher_mode', 'f54_mode', '80fe_live_mode', 'expected_final_mode'):
        if row[key] is not None and row[key] not in ('100644', '100755'):
            raise SystemExit(f'{row["path"]}: invalid mode')
    oid(row['expected_final_blob'], 'blob', f'{row["path"]}.expected_final', missing=row['path'] == 'scripts/README.md')

lo = data['live_overlap']
if len(lo['launcher_paths']) != 11 or len(lo['live_paths']) != 22 or len(lo['union_paths']) != 29 or len(lo['intersection_paths']) != 4:
    raise SystemExit('11/22/29/4 cardinality mismatch')
if set(lo['union_paths']) != set(lo['launcher_paths']) | set(lo['live_paths']):
    raise SystemExit('union path mismatch')
if set(lo['intersection_paths']) != set(lo['launcher_paths']) & set(lo['live_paths']):
    raise SystemExit('intersection path mismatch')
if len(set(row['path'] for row in lo['blob_matrix'])) != 29:
    raise SystemExit('duplicate blob-matrix path')
if set(lo['launcher_mechanical_paths']) != set(lo['launcher_paths']) - {'scripts/README.md'}:
    raise SystemExit('launcher mechanical mismatch')
if set(lo['live_mechanical_paths']) != set(lo['live_paths']) - {'scripts/README.md'}:
    raise SystemExit('live mechanical mismatch')
if set(lo['stage_two_required_d3_overlap_paths']) != set(lo['intersection_paths']) - {'scripts/README.md'}:
    raise SystemExit('stage-two d3 overlap mismatch')

anchor_text = data['live_overlap']['scripts_readme']['section_anchor']
if not isinstance(anchor_text, str):
    raise SystemExit('README anchor metadata is not a string')
anchor = anchor_text.encode('utf-8')
if anchor != b'## Disposable Caddy proof renderer\n':
    raise SystemExit('README anchor metadata does not decode to the canonical LF anchor')
prefix = run('show', '80fe3b68fb676a3b6589fce9aed79140bf37b667:scripts/README.md').stdout
section = run('show', 'e3a2d2e662f2e606f318d35f4fccc63ba9738f7c:scripts/README.md').stdout
if prefix.count(anchor) != 1 or section.count(anchor) != 1:
    raise SystemExit('README anchor mismatch')
merged = prefix.split(anchor, 1)[0] + section[section.index(anchor):]
info = lo['scripts_readme']
if info.get('computed_git_blob') != info['expected_git_blob']:
    raise SystemExit('README computed/expected Git blob metadata mismatch')
if len(merged) != info['expected_bytes'] or merged.count(b'\n') != info['expected_lines']:
    raise SystemExit('README shape mismatch')
if hashlib.sha256(merged).hexdigest() != info['expected_sha256']:
    raise SystemExit('README raw SHA mismatch')
computed = run('hash-object', '--stdin', input_bytes=merged).stdout.decode().strip()
if computed != info['expected_git_blob']:
    raise SystemExit('README blob mismatch')
if run('cat-file', '-t', info['expected_git_blob'], check=False).returncode == 0:
    raise SystemExit('future README blob unexpectedly exists before replay')

if 'assert_clean_primary_storage_unshared' not in execution_driver['shell'] or 'st_nlink' not in execution_driver['shell']:
    raise SystemExit('clean-primary st_nlink hardlink proof is missing from the driver')
if 'status --porcelain=v1 --untracked-files=all --ignored=traditional --ignore-submodules=none' not in execution_driver['shell']:
    raise SystemExit('complete whole-worktree ignored/untracked cleanliness proof is missing')
# SOURCE is intentionally not required to be clean while this static
# validation runs; clean-primary is separately required to be completely clean before replay mutation.
if out('rev-parse', '--is-inside-work-tree') != 'true' or out('rev-parse', '--is-bare-repository') != 'false':
    raise SystemExit('repository shape mismatch')
PY
}

# Verify SOURCE read-only, build a dedicated clean-primary, then create replay.
assert_tools
bind_source_identity
assert_root_shape
assert_worktree_separation
static_validate_matrix "$SOURCE"
MATRIX_SOURCE_VALIDATED=1
bootstrap_clean_primary
static_validate_matrix "$CLEAN_PRIMARY"
assert_clean_primary_state
assert_worktree_separation

# Bootstrap a standalone detached replay repository without git worktree add or fetch.
# Replay reads/mutations use clean-primary and replay only; SOURCE is never a workspace.
create_replay_root
assert_replay_preinit_state
CLEANUP_ALLOWLIST=("$REPLAY" "$README_TMP" "$MATRIX_SNAPSHOT" "$REPLAY_ROOT")
CLEAN_PRIMARY_CLEANUP_ALLOWLIST=("$CLEAN_PRIMARY_ROOT")
before_mutation
bind_matrix_snapshot
before_mutation
assert_root_shape
before_mutation
git_hermetic init "$REPLAY" >/dev/null
assert_root_shape
assert_worktree_separation
REPLAY_GIT_DIR="$REPLAY/.git"
test -d "$REPLAY_GIT_DIR" || fail "replay Git directory was not created"
test "$(git_replay rev-parse --absolute-git-dir)" = "$REPLAY_GIT_DIR" || fail "replay Git directory escaped replay root"
assert_root_shape
assert_worktree_separation
before_mutation
$MKDIR -p "$REPLAY/.git/objects/info"
before_mutation
printf '%s\n' "$CLEAN_PRIMARY_OBJECTS" > "$REPLAY/.git/objects/info/alternates"
before_mutation
git_replay config --local core.hooksPath /dev/null
before_mutation
git_replay config --local protocol.allow never
before_mutation
git_replay update-ref refs/remotes/origin/dev "$BASE"
before_mutation
git_replay update-ref refs/remotes/origin/main "$MAIN"
before_mutation
git_replay update-ref --no-deref HEAD "$BASE"
BOOTSTRAP_HEAD="$BASE"
BOOTSTRAP_TREE="$BASE_TREE"
before_mutation
git_replay read-tree --reset -u "$BASE"
CURRENT_HEAD="$(git_replay rev-parse HEAD)"
CURRENT_TREE="$(git_replay rev-parse HEAD^{tree})"
test "$CURRENT_HEAD" = "$BASE" || fail 'initial detached HEAD is not BASE'
test "$CURRENT_TREE" = "$BASE_TREE" || fail 'initial base tree mismatch'
REPLAY_READY=1
BOOTSTRAP_HEAD=''
BOOTSTRAP_TREE=''
assert_replay_state "$CURRENT_HEAD" "$CURRENT_TREE"
assert_replay_closure
REPLAY_GIT_BOUND=1
assert_root_shape
assert_worktree_separation
before_mutation

# Ordered execution. Ranges use exact inclusive source order. Semantic lanes and matrix
# stages project only approved paths; no candidate-to-source whole-tree diff/apply occurs.
apply_range_lane renderer-lifecycle
apply_semantic_lane renderer-lifecycle
apply_range_lane static-manifest-chain
apply_range_lane authentication-design-token-manifest
apply_semantic_lane authentication-semantic-delta
apply_range_lane fixture-registry-authority
apply_semantic_lane fixture-registry-authority
apply_range_lane apple-benchmark-range
apply_range_lane proxy-deployment-proof
apply_matrix_stage launcher
assert_stage_two_overlap
apply_semantic_lane dependency-audit-correction
apply_semantic_lane swift-parity-correction
apply_matrix_stage live
merge_scripts_readme

before_mutation
assert_final_matrix
assert_forbidden_ancestry
assert_primary_pins
printf 'FINAL_HEAD=%s\nREMOTE_DEV=%s\nINDEPENDENT_APPROVAL_REQUIRED=1\nNO_PUSH_PERFORMED=1\n' "$CURRENT_HEAD" "$(git_primary rev-parse origin/dev)"
assert_replay_closure
cleanup_success_only "$REPLAY" "$README_TMP" "$MATRIX_SNAPSHOT"
# Keep the post-call lifecycle ledger explicit: cleanup_success_only resets this only after the replay child was removed.
REPLAY_GIT_BOUND=0
cleanup_clean_primary_success_only
printf 'TASK409_FINAL_REPLAY_OK=1\nCLEAN_PRIMARY_REMOVED=1\n'
