import argparse
import ast
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

JSON_PATH = Path('/private/tmp/hermternal-task409-final-execution-matrix.json')
MARKDOWN_PATH = Path('/private/tmp/hermternal-task409-final-execution-matrix.md')
HARD_LANE_IDS = [
    'renderer-lifecycle',
    'static-manifest-chain',
    'authentication-design-token-manifest',
    'authentication-semantic-delta',
    'fixture-registry-authority',
    'apple-benchmark-range',
    'proxy-deployment-proof',
    'launcher-semantic-projection',
    'dependency-audit-correction',
    'swift-parity-correction',
    'live-proof-semantic-projection',
]
RAW_SHA_PREDECLARED_LANES = [
    'launcher-semantic-projection',
    'live-proof-semantic-projection',
]

STABLE_READER = r'''
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
'''

ROOT_CREATION = r'''\
  test "$1" = clean-primary -o "$1" = replay || fail "unknown root creation label"
'''

ROOT_PY = r'''
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
            '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never',
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
'''

WORKTREE = r'''
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
            '-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never',
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
'''

ASSERT_ROOT_SHAPE = r'''
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
'''


def transform_heredocs(shell, predicate, transform):
    out=[]; pos=0; marker="<<'PY'\n"
    while True:
        start=shell.find(marker,pos)
        if start<0:
            out.append(shell[pos:]); return ''.join(out)
        body=start+len(marker); end=shell.find('\nPY',body)
        if end<0: raise RuntimeError('unterminated heredoc')
        code=shell[body:end]
        if predicate(code): code=transform(code)
        out.extend((shell[pos:body],code)); pos=end


def inject_reader(code, anchor):
    if 'def read_stable_file(' in code:
        return code
    if anchor not in code:
        raise RuntimeError(f'missing reader anchor {anchor!r}')
    # Insert only at a statement boundary. Preserve a leading future import;
    # Python requires ``from __future__`` to precede every ordinary import.
    # Inserting immediately before an expression such as ``json.load(open(...))``
    # can also split ``data =`` and leave invalid Python after replacement.
    prefix = 'import os\nimport stat\n' + STABLE_READER + '\n'
    future = re.match(r'((?:from __future__ import [^\n]+\n)+)', code)
    if future:
        return future.group(1) + prefix + code[future.end():]
    return prefix + code


def replace_once(code, old, new, label):
    n=code.count(old)
    if n!=1: raise RuntimeError(f'{label}: expected one, got {n}')
    return code.replace(old,new,1)


def json_reader(code):
    code=inject_reader(code,'json.load(open')
    code=code.replace('data = json.load(open(matrix))',"data = json.loads(read_stable_file(matrix, 'matrix')[0].decode('utf-8'))")
    code=code.replace('m, repo, head = json.load(open(sys.argv[1])), sys.argv[2], sys.argv[3]',"m, repo, head = json.loads(read_stable_file(sys.argv[1], 'matrix')[0].decode('utf-8')), sys.argv[2], sys.argv[3]")
    code=code.replace('m = json.load(open(sys.argv[1]))',"m = json.loads(read_stable_file(sys.argv[1], 'matrix')[0].decode('utf-8'))")
    code=re.sub(r'json\.load\(open\(([^()]+)\)\)',r"json.loads(read_stable_file(\1, 'matrix')[0].decode('utf-8'))",code)
    if 'json.load(open' in code: raise RuntimeError('json.load(open) remained')
    return code


def bind_reader(code):
    code=inject_reader(code,'config_path, config_st = checked')
    old='''config_fd = os.open(config_path, os.O_RDONLY | os.O_NOFOLLOW)
try:
    config = os.read(config_fd, 1024 * 1024)
finally:
    os.close(config_fd)'''
    return replace_once(code,old,"config, _config_stat = read_stable_file(config_path, 'replay config')",'bind config')


def assert_reader(code):
    code=inject_reader(code,'def check(path, expected, values, kind, label, allow_dir_nlink_growth=False):')
    if "with open(config, 'rb') as fh:\n    config_bytes = fh.read()" in code:
        code=code.replace("with open(config, 'rb') as fh:\n    config_bytes = fh.read()","config_bytes, _config_stat = read_stable_file(config, 'replay config')",1)
    old='''fd = os.open(alternates, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        raw = b''
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            raw += chunk
        end = os.fstat(fd)
    finally:
        os.close(fd)
    if (st.st_dev, st.st_ino, st.st_size, st.st_nlink) != (end.st_dev, end.st_ino, end.st_size, end.st_nlink):
        raise SystemExit('replay alternates descriptor changed while reading')
    if str(st.st_size) != alt_size or hashlib.sha256(raw).hexdigest() != alt_sha:
        raise SystemExit('replay alternates content identity changed')'''
    new="""raw, alt_read_stat = read_stable_file(alternates, 'replay alternates')
    if str(alt_read_stat.st_size) != alt_size or hashlib.sha256(raw).hexdigest() != alt_sha:
        raise SystemExit('replay alternates content identity changed')"""
    if old in code:
        code=code.replace(old,new,1)
    direct="if open(alternate, 'rb').read() != (os.path.realpath(clean_objects) + '\\n').encode():\n        raise SystemExit('replay alternate is not clean-primary object store')"
    replacement="raw, _alternate_stat = read_stable_file(alternate, 'replay alternates')\n    if raw != (os.path.realpath(clean_objects) + '\\n').encode():\n        raise SystemExit('replay alternate is not clean-primary object store')"
    if direct in code:
        code=code.replace(direct,replacement,1)
    return code


def smoke_reader(code):
    code=inject_reader(code,'def descriptor_create(parent, name, data):')
    code=replace_once(code,"raw = open(os.path.join(dotgit, 'config'), 'rb').read()","raw = read_stable_file(os.path.join(dotgit, 'config'), 'smoke replay config')[0]",'smoke config')
    code=replace_once(code,"before = open(count, 'rb').read()","before = read_stable_file(count, 'helper count')[0]",'smoke before')
    code=replace_once(code,"open(count, 'rb').read() != before","read_stable_file(count, 'helper count')[0] != before",'smoke after')
    code=replace_once(code,"open(sentinel, 'rb').read() != b'unchanged\\n'","read_stable_file(sentinel, 'external sentinel')[0] != b'unchanged\\n'",'smoke sentinel')
    return code


def matrix_reader(code):
    code=inject_reader(code,'source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)')
    old='''source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
try:
    source_stat = os.fstat(source_fd)
    if not stat.S_ISREG(source_stat.st_mode):
        raise SystemExit('matrix source is not a regular file')
    chunks = []
    while True:
        chunk = os.read(source_fd, 1024 * 1024)
        if not chunk:
            break
        chunks.append(chunk)
    raw = b''.join(chunks)
    end_stat = os.fstat(source_fd)
finally:
    os.close(source_fd)
if (source_stat.st_dev, source_stat.st_ino, source_stat.st_size) != (end_stat.st_dev, end_stat.st_ino, end_stat.st_size):
    raise SystemExit('matrix source descriptor changed while reading')'''
    code=replace_once(code,old,"raw, source_stat = read_stable_file(source, 'matrix source')",'matrix source')
    old2='''read_fd = os.open(snapshot, os.O_RDONLY | os.O_NOFOLLOW)
try:
    read_chunks = []
    while True:
        chunk = os.read(read_fd, 1024 * 1024)
        if not chunk:
            break
        read_chunks.append(chunk)
    reread = b''.join(read_chunks)
    reread_stat = os.fstat(read_fd)
finally:
    os.close(read_fd)'''
    if old2 in code: code=code.replace(old2,"reread, reread_stat = read_stable_file(snapshot, 'matrix snapshot')",1)
    return code


def readme_reader(code):
    code=inject_reader(code,'source_fd = os.open(str(matrix), os.O_RDONLY | os.O_NOFOLLOW)')
    old='''source_fd = os.open(str(matrix), os.O_RDONLY | os.O_NOFOLLOW)
try:
    matrix_stat = os.fstat(source_fd)
    raw_matrix = b''
    while True:
        chunk = os.read(source_fd, 1024 * 1024)
        if not chunk: break
        raw_matrix += chunk
    if matrix_stat != os.fstat(source_fd):
        raise SystemExit('matrix source changed while reading')
finally:
    os.close(source_fd)'''
    return replace_once(code,old,"raw_matrix, _matrix_stat = read_stable_file(matrix, 'matrix source')",'README matrix')


def validator_reader(code):
    start=code.find('def read_stable(path):\n')
    end=code.find('\nraw_matrix = read_stable(matrix)',start)
    if start<0 or end<0: raise RuntimeError('validator reader anchors missing')
    return code[:start]+STABLE_READER+"\ndef read_stable(path):\n    return read_stable_file(path, 'validator input')[0]\n"+code[end:]


def replace_function(shell, start, end, new):
    a=shell.index(start); b=shell.index(end,a)
    return shell[:a]+new+shell[b:]


def root_create_function(label, root_var, child_path_var, child_state_var):
    prefix = root_var[:-len('_ROOT')] if root_var.endswith('_ROOT') else root_var
    words = label.replace('_', ' ')
    kind = label.replace('create_', '').replace('_root', '')
    return f'''{label}() {{
  test "${{{root_var}_BOUND}}" -eq 0 || fail "{words} already bound"
  assert_root_shape
  assert_worktree_separation
  local identity
  identity="$($PYTHON - "{words}" "${{{root_var}}}" "${{{child_path_var}}}" "$SOURCE" "$CLEAN_PRIMARY" "$CLEAN_PRIMARY_BOUND" <<'PY'
{ROOT_PY}
PY
)"
  IFS=$'\\t' read -r \\
    {root_var}_REALPATH \\
    {prefix}_PARENT_DEVICE {prefix}_PARENT_INODE {prefix}_PARENT_UID {prefix}_PARENT_MODE {prefix}_PARENT_NLINK \\
    {root_var}_DEVICE {root_var}_INODE {root_var}_UID {root_var}_MODE {root_var}_NLINK \\
    {child_state_var}_REALPATH {child_state_var}_DEVICE {child_state_var}_INODE {child_state_var}_UID {child_state_var}_MODE {child_state_var}_NLINK <<< "$identity"
  test "${{{root_var}_REALPATH}}" = "${{{root_var}}}" || fail "{words} canonical binding failed"
  test "${{{child_state_var}_REALPATH}}" = "${{{child_path_var}}}" || fail "{words} child canonical binding failed"
  {root_var}_BOUND=1
  {child_state_var}_BOUND=1
  {child_state_var}_PRESENT=1
  assert_root_shape
  assert_worktree_separation
}}

'''


def replay_binding_hardening(code):
    """Harden the standalone replay alternate/object metadata validator."""
    code = ensure_standalone_readers(code)
    marker = "objects = os.path.join(git_dir, 'objects')\n"
    if 'replay Git directory is not the repository-local .git directory' in code:
        return code
    addition = r'''repo_real = os.path.realpath(repo)
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
], text=True).strip()
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
'''
    return replace_once(code, marker, marker + addition, 'replay binding metadata')


def static_validator_reader(code):
    """Bind static matrix and Markdown reads to stable no-follow descriptors."""
    if 'raw_matrix, _matrix_stat = read_stable_file(matrix' in code:
        return code
    if 'raw_matrix = matrix.read_bytes()' not in code:
        return code
    code = inject_reader(code, 'matrix, repo, markdown, expected_binding = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]), sys.argv[4]')
    code = code.replace(
        'raw_matrix = matrix.read_bytes()',
        "raw_matrix, _matrix_stat = read_stable_file(matrix, 'matrix source')",
        1,
    )
    code = code.replace(
        'markdown_bytes = markdown.read_bytes()',
        "markdown_bytes, _markdown_stat = read_stable_file(markdown, 'Markdown source')",
        1,
    )
    return code


def metadata_path_reader(code):
    """Replace the README merge helper's pathname JSON reopen."""
    if 'metadata = json.loads(read_stable_file(matrix' in code:
        return code
    if 'metadata = json.loads(matrix.read_bytes())' not in code:
        return code
    code = inject_reader(code, 'repo, out, matrix = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])')
    return code.replace(
        'metadata = json.loads(matrix.read_bytes())',
        "metadata = json.loads(read_stable_file(matrix, 'matrix source')[0].decode('utf-8'))",
        1,
    )


def ensure_standalone_readers(code):
    """Make each transformed runtime validator carry its own stable reader.

    Heredocs run as separate Python processes. The matrix-identity and replay
    object-binding validators must therefore each define the parent-bound
    no-follow reader in the same heredoc, even when a later transform inserted
    the call after the original reader pass.
    """
    if 'read_stable_file(' not in code or 'def read_stable_file(' in code:
        return code
    # Insert at the top-level import boundary. ``inject_reader`` preserves a
    # future-import prefix and avoids splitting an assignment statement.
    return inject_reader(code, 'import ')


def ensure_any_standalone_reader(code):
    """Add a parent-bound reader to any transformed heredoc that needs one."""
    return ensure_standalone_readers(code)


def embedded_git_policy(code):
    """Give every embedded Git subprocess an explicit, auditable environment.

    Each heredoc is a separate Python process. Keep calls module-qualified so
    the static reviewer can enumerate every Git subprocess independently, then
    add exactly one explicit ``env=ENV`` keyword to every subprocess call. The
    argv policy is applied by the surrounding harden_shell replacements and is
    still visible at each call site; no private alias may hide a bypass from the
    reviewer.
    """
    if 'subprocess.run(' not in code and 'subprocess.check_output(' not in code:
        return code
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        raise RuntimeError(f'embedded Git heredoc cannot be parsed for env binding: {exc}') from exc
    calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if not isinstance(node.func.value, ast.Name) or node.func.value.id != 'subprocess':
            continue
        if node.func.attr not in ('run', 'check_output', 'Popen', 'check_call'):
            continue
        if any(keyword.arg == 'env' for keyword in node.keywords):
            continue
        calls.append(node)
    if calls:
        lines = code.splitlines(keepends=True)
        offsets = []
        total = 0
        for line in lines:
            offsets.append(total)
            total += len(line.encode('utf-8'))
        raw = code.encode('utf-8')
        inserts = []
        for node in calls:
            end = offsets[node.end_lineno - 1] + node.end_col_offset
            close = end - 1
            if raw[close:close + 1] != b')':
                raise RuntimeError('embedded Git subprocess call has no closing parenthesis')
            prefix = b', ' if node.args or node.keywords else b''
            inserts.append((close, prefix + b'env=ENV'))
        for position, value in sorted(inserts, reverse=True):
            raw = raw[:position] + value + raw[position:]
        code = raw.decode('utf-8')
    if 'ENV = {' not in code:
        env = """ENV = {
    'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
    'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
}  # hermetic Git environment
"""
        future = re.match(r'((?:from __future__ import [^\n]+\n)*)', code)
        code = code[:future.end()] + env + code[future.end():]
    # Existing source heredocs may have a static Git argv that omitted one or
    # more required switches. Normalize every literal Git argv after env
    # insertion, including compact one-line calls and multi-line lists.
    if "'/usr/bin/git'" in code or 'git,' in code:
        replacements = {
            "'/usr/bin/git','-C'": "'/usr/bin/git','--no-replace-objects','--no-lazy-fetch','--no-optional-locks','-C'",
            "'/usr/bin/git', '-C'": "'/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-C'",
            "'/usr/bin/git', *args": "'/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', *args",
            "'/usr/bin/git','-C'": "'/usr/bin/git','--no-replace-objects','--no-lazy-fetch','--no-optional-locks','-C'",
            "[git, '-C'": "[git, '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-C'",
        }
        for old, new in replacements.items():
            code = code.replace(old, new)
        code = code.replace(
            "'-c','core.hooksPath=/dev/null',*args",
            "'-c','core.hooksPath=/dev/null','-c','protocol.allow=never',*args",
        )
        code = code.replace(
            "'-c', 'core.hooksPath=/dev/null', *args",
            "'-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', *args",
        )
        code = code.replace(
            "'-c', 'core.hooksPath=/dev/null','show'",
            "'-c', 'core.hooksPath=/dev/null','-c','protocol.allow=never','show'",
        )
        code = code.replace(
            "'-c','core.hooksPath=/dev/null','show'",
            "'-c','core.hooksPath=/dev/null','-c','protocol.allow=never','show'",
        )
    return code


def add_producer_validators(shell):
    """Replace fail-open process substitutions with checked temp-file producers."""
    # Use producer-first files because Bash 3.2 has no process substitution
    # failure channel. Every producer is status-checked, nonempty-checked, and
    # validated against the exact matrix rows before the consumer opens it.
    secure = r'''secure_temp_file() {
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
  printf '%s\\n' "$path"
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
  printf '%s\\n' "$output"
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
'''
    shell, replaced = re.subn(
        r'(?ms)^assert_environment\(\) \{.*?^\}\nassert_environment\n',
        secure + 'assert_environment\n',
        shell,
        count=1,
    )
    if replaced != 1:
        raise RuntimeError('environment producer anchor mismatch')

    validators = r'''assert_range_records_file() {
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
'''
    shell = shell.replace('apply_range_lane() {', validators + '\napply_range_lane() {', 1)

    shell = re.sub(
        r'(?m)^(  local lane="\$1" record source expected parent tree path_blob cherry_path abort_rc\n  local paths=\(\))$',
        r'\1\n  local records_file target_records_file\n  records_file="$(producer_to_file range-records "$REPLAY_ROOT" range_records "$lane")"\n  assert_range_records_file "$lane" "$records_file"',
        shell,
        count=1,
    )
    shell = shell.replace(
        '    while IFS=$\'\\t\' read -r path target_blob target_mode target_kind; do\n      assert_path_state "$path" "$target_blob" "$target_mode" "$target_kind"\n    done < <(range_target_records "$lane" "$source")',
        '    target_records_file="$(producer_to_file range-target-records "$REPLAY_ROOT" range_target_records "$lane" "$source")"\n    assert_range_target_records_file "$lane" "$source" "$target_records_file"\n    while IFS=$\'\\t\' read -r path target_blob target_mode target_kind; do\n      assert_path_state "$path" "$target_blob" "$target_mode" "$target_kind"\n    done < "$target_records_file"\n    cleanup_temp_file "$target_records_file"',
        1,
    )
    shell = shell.replace('  done < <(range_records "$lane")\n}', '  done < "$records_file"\n  cleanup_temp_file "$records_file"\n}', 1)
    shell = re.sub(
        r'(?ms)^apply_semantic_lane\(\) \{.*?^\}\n\n\nmatrix_records\(\)',
        lambda m: m.group(0).replace(
            '  local lane="$1" record\n  local info=()',
            '  local lane="$1" record semantic_file projection_file\n  local info=()\n  semantic_file="$(producer_to_file semantic-records "$REPLAY_ROOT" semantic_records "$lane")"\n  assert_semantic_records_file "$lane" "$semantic_file"',
            1,
        ).replace(
            '  done < <(semantic_records "$lane")',
            '  done < "$semantic_file"\n  cleanup_temp_file "$semantic_file"\n  test "${#info[@]}" -eq 3 || fail "semantic producer row count mismatch for $lane"',
            1,
        ).replace(
            '  local path old_blob old_mode old_kind new_blob new_mode new_kind target_line target_type\n',
            '  local path old_blob old_mode old_kind new_blob new_mode new_kind target_line target_type\n  projection_file="$(producer_to_file projection-records "$REPLAY_ROOT" projection_stage_records "$lane")"\n  assert_projection_stage_records_file "$lane" "$projection_file"\n',
            1,
        ).replace(
            '  done < <(projection_stage_records "$lane")',
            '  done < "$projection_file"\n  cleanup_temp_file "$projection_file"',
            1,
        ),
        shell,
        count=1,
    )
    shell = shell.replace(
        '  local rows=() record\n  while IFS= read -r record; do\n    rows[${#rows[@]}]="$record"\n  done < <(matrix_records "$stage")',
        '  local rows=() record matrix_file\n  matrix_file="$(producer_to_file matrix-records "$REPLAY_ROOT" matrix_records "$stage")"\n  assert_matrix_records_file "$stage" "$matrix_file"\n  while IFS= read -r record; do\n    rows[${#rows[@]}]="$record"\n  done < "$matrix_file"\n  cleanup_temp_file "$matrix_file"',
        1,
    )
    shell = re.sub(
        r'(?ms)^assert_forbidden_ancestry\(\) \{.*?^\}\n\n\nassert_root_empty\(\)',
        '''assert_forbidden_ancestry() {
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


assert_root_empty()''',
        shell,
        count=1,
    )
    # The source Markdown uses a literal tab inside the Bash $'...' IFS
    # expression. Match either that byte or the escaped spelling so this pass
    # remains stable if the source renderer changes its escape style.
    shell = re.sub(
        r'''(?ms)    while IFS=\$'[^']*' read -r path target_blob target_mode target_kind; do
      assert_path_state "\$path" "\$target_blob" "\$target_mode" "\$target_kind"
    done < <\(range_target_records "\$lane" "\$source"\)''',
        '''    target_records_file="$(producer_to_file range-target-records "$REPLAY_ROOT" range_target_records "$lane" "$source")"
    assert_range_target_records_file "$lane" "$source" "$target_records_file"
    while IFS=$'\\t' read -r path target_blob target_mode target_kind; do
      assert_path_state "$path" "$target_blob" "$target_mode" "$target_kind"
    done < "$target_records_file"
    cleanup_temp_file "$target_records_file"''',
        shell,
        count=1,
    )

    # Replace the complete semantic lane after the source-shape transforms.
    # This avoids leaving a producer failure hidden behind a consumer loop when
    # the source contains literal rather than escaped tab bytes.
    semantic_start = shell.index('apply_semantic_lane() {')
    semantic_end = shell.index('matrix_records() {', semantic_start)
    semantic = '''apply_semantic_lane() {
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
  IFS=$'\\x1f' read -r -a paths <<< "$path_blob"
  test -n "$target" && test -n "$source_parent" || fail "semantic parent/child missing for $lane"
  test "${#paths[@]}" -gt 0 || fail "empty semantic path set for $lane"
  test "$(git_replay rev-parse "$target^1")" = "$source_parent" || fail "semantic source parent mismatch for $lane"
  DIRTY_PATHS=()
  before_mutation
  assert_declared_projection "$lane"
  local path old_blob old_mode old_kind new_blob new_mode new_kind target_line target_type
  projection_file="$(producer_to_file projection-records "$REPLAY_ROOT" projection_stage_records "$lane")"
  assert_projection_stage_records_file "$lane" "$projection_file"
  while IFS=$'\\t' read -r path old_blob old_mode old_kind; do
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

'''
    shell = shell[:semantic_start] + semantic + shell[semantic_end:]

    # Replace the ancestry reader by index so heredoc spacing cannot weaken the
    # producer-first status check.
    ancestry_start = shell.index('assert_forbidden_ancestry() {')
    ancestry_end = shell.index('assert_root_empty() {', ancestry_start)
    ancestry = '''assert_forbidden_ancestry() {
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

'''
    shell = shell[:ancestry_start] + ancestry + shell[ancestry_end:]
    if '< <(' in shell or '> <(' in shell:
        raise RuntimeError('process substitution remained after producer hardening')
    return shell


REPLAY_CLOSURE_FUNCTION = r'''assert_replay_closure() {
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

'''


def guard_optional_dirty_arrays(shell):
    """Make every optional DIRTY_PATHS expansion nounset-safe in Bash 3.2.

    Bash 3.2 can reject an empty indexed-array expansion under ``set -u``.
    Count-gated blocks are intentionally explicit here: unlike ``${array[@]-}``,
    they preserve zero arguments and unlike a conditional expansion they make
    the before_mutation forwarding contract visible to static review.
    """
    smoke = '''assert_bash32_array_smoke() {
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

'''
    before = '''before_mutation() {
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


'''
    dirty = '''add_dirty_path() {
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

'''
    shell, smoke_count = re.subn(
        r'(?ms)^assert_bash32_array_smoke\(\) \{.*?^\}\n\n(?=assert_replay_closure\(\) \{)',
        smoke,
        shell,
        count=1,
    )
    if smoke_count != 1:
        raise RuntimeError('candidate4 Bash smoke function anchor mismatch')
    shell, before_count = re.subn(
        r'(?ms)^before_mutation\(\) \{.*?^\}\n\n\n(?=add_dirty_path\(\) \{)',
        before,
        shell,
        count=1,
    )
    if before_count != 1:
        raise RuntimeError('candidate4 before_mutation anchor mismatch')
    shell, dirty_count = re.subn(
        r'(?ms)^add_dirty_path\(\) \{.*?^\}\n\n(?=assert_path_state\(\) \{)',
        dirty,
        shell,
        count=1,
    )
    if dirty_count != 1:
        raise RuntimeError('candidate4 add_dirty_path anchor mismatch')
    return shell


def harden_shell(shell):
    """Apply the final hermetic Git, closure, and clean-primary contract."""
    # Preserve Bash 3.2 array semantics without relying on unquoted expansion.
    # The source used the older empty-array guard spelling; every resulting
    # expansion is deliberately quoted so paths containing spaces stay atomic.
    shell = re.sub(
        r'\$\{([A-Za-z_][A-Za-z0-9_]*)\[@\]\+"\$\{\1\[@\]\}"\}',
        r'"${\1[@]}"',
        shell,
    )
    shell = shell.replace('--ignored=all', '--ignored=traditional --ignore-submodules=none')
    shell = shell.replace('--local --no-hardlinks', '--no-local --no-hardlinks')
    shell = shell.replace(
        "if '--ignored=traditional --ignore-submodules=none' not in execution_driver['shell']:",
        "if 'status --porcelain=v1 --untracked-files=all --ignored=traditional --ignore-submodules=none' not in execution_driver['shell']:",
    )
    shell = shell.replace(
        "if open(alternate, 'rb').read() != (os.path.realpath(clean_objects) + '\\n').encode():\n    raise SystemExit('replay alternate is not clean-primary object store')",
        "raw_alternate, _alternate_stat = read_stable_file(alternate, 'replay alternates')\nif raw_alternate != (os.path.realpath(clean_objects) + '\\n').encode():\n    raise SystemExit('replay alternate is not clean-primary object store')",
    )
    shell = shell.replace(
        "    metadata = json.loads(matrix.read_bytes())",
        "    metadata = json.loads(read_stable_file(matrix, 'matrix source')[0].decode('utf-8'))",
    )
    shell = shell.replace(
        "  whole_worktree_status=\"$(git_primary status --porcelain=v1 --untracked-files=all --ignored=traditional --ignore-submodules=none)\"\n  test -z \"$whole_worktree_status\"",
        "  whole_worktree_status=\"$(git_primary status --porcelain=v1 --untracked-files=all --ignored=traditional --ignore-submodules=none)\"\n  test -z \"$whole_worktree_status\"",
    )
    shell = shell.replace(
        '  test -z "$whole_worktree_status" || fail "clean-primary whole worktree is not clean, including ignored/untracked files"\n',
        '  test -z "$whole_worktree_status" || fail "clean-primary whole worktree is not clean, including ignored/untracked files"\n  test -z "$(git_primary ls-files --others --ignored --exclude-standard -z)" || fail "clean-primary has ignored descendants"\n',
        1,
    )
    environment_case = 'PATH|HOME|LANG|LC_ALL|GIT_CONFIG_NOSYSTEM|GIT_CONFIG_GLOBAL|GIT_CONFIG_SYSTEM|GIT_TERMINAL_PROMPT|GIT_OPTIONAL_LOCKS|GIT_NO_REPLACE_OBJECTS|PWD|SHLVL|_)'
    shell = shell.replace(
        environment_case,
        'PATH|HOME|LANG|LC_ALL|GIT_CONFIG_NOSYSTEM|GIT_CONFIG_GLOBAL|GIT_CONFIG_SYSTEM|GIT_TERMINAL_PROMPT|GIT_OPTIONAL_LOCKS|GIT_NO_REPLACE_OBJECTS|GIT_NO_LAZY_FETCH|PWD|SHLVL|_)',
        1,
    )
    shell = shell.replace('export GIT_NO_REPLACE_OBJECTS=1\n', 'export GIT_NO_REPLACE_OBJECTS=1\nexport GIT_NO_LAZY_FETCH=1\n', 1)
    old_git_functions = '''git_source() {
  "$GIT" -C "$SOURCE" -c core.hooksPath=/dev/null -c protocol.allow=never "$@"
}
git_primary() {
  "$GIT" -C "$CLEAN_PRIMARY" -c core.hooksPath=/dev/null -c protocol.allow=never "$@"
}
git_replay() {
  "$GIT" -C "$REPLAY" -c core.hooksPath=/dev/null -c protocol.allow=never "$@"
}
'''
    new_git_functions = '''git_hermetic() {
  "$ENV" -i \\
    PATH=/usr/bin:/bin \\
    HOME=/dev/null \\
    LANG=C \\
    LC_ALL=C \\
    GIT_CONFIG_NOSYSTEM=1 \\
    GIT_CONFIG_GLOBAL=/dev/null \\
    GIT_CONFIG_SYSTEM=/dev/null \\
    GIT_TERMINAL_PROMPT=0 \\
    GIT_OPTIONAL_LOCKS=0 \\
    GIT_NO_REPLACE_OBJECTS=1 \\
    GIT_NO_LAZY_FETCH=1 \\
    "$GIT" \\
    --no-replace-objects \\
    --no-lazy-fetch \\
    --no-optional-locks \\
    -c core.hooksPath=/dev/null \\
    -c protocol.allow=never \\
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
'''
    if old_git_functions in shell:
        shell = shell.replace(old_git_functions, new_git_functions, 1)
    # Even the executable version probe must use the centralized hermetic
    # wrapper; a direct $GIT invocation would bypass the sanitized environment.
    shell = shell.replace(
        "  test \"$($GIT --version | $CUT -d' ' -f1)\" = git || fail \"unexpected Git executable\"\n",
        "  test \"$(git_hermetic --version | \"$CUT\" -d' ' -f1)\" = git || fail \"unexpected Git executable\"\n",
        1,
    )
    # Keep patch-id itself inside the same hermetic Git policy; it is a Git
    # subprocess even when its input arrives through a validated pipe.
    shell = shell.replace('git_replay() {\n  git_hermetic -C "$REPLAY" "$@"\n}\n', 'git_replay() {\n  git_hermetic -C "$REPLAY" "$@"\n}\npatch_id_stable() {\n  git_hermetic patch-id --stable\n}\n', 1)
    shell = shell.replace('"$GIT" patch-id --stable', 'patch_id_stable')
    shell = shell.replace("[git, 'patch-id', '--stable']", "[git, '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', 'patch-id', '--stable']")
    shell = shell.replace(
        '  "$GIT" -c core.hooksPath=/dev/null -c protocol.allow=never clone ',
        '  git_hermetic -c protocol.file.allow=always clone ',
    )
    shell = shell.replace(
        '  git_hermetic clone --no-local --no-hardlinks --no-checkout --no-tags',
        '  git_hermetic -c protocol.file.allow=always clone --no-local --no-hardlinks --no-checkout --no-tags',
    )
    shell = shell.replace(
        '  "$GIT" -c core.hooksPath=/dev/null -c protocol.allow=never init ',
        '  git_hermetic init ',
    )
    # Every embedded repository subprocess receives the same no-replace,
    # no-lazy-fetch, no-optional-locks, hooks, and protocol gates.
    shell = shell.replace(
        "'/usr/bin/git', '-C',",
        "'/usr/bin/git', '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-C',",
    )
    shell = shell.replace(
        "git, '-C',",
        "git, '--no-replace-objects', '--no-lazy-fetch', '--no-optional-locks', '-C',",
    )
    shell = shell.replace(
        "'-c', 'core.hooksPath=/dev/null',",
        "'-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never',",
    )
    shell = shell.replace(
        "git = '/usr/bin/git'\n",
        "git = '/usr/bin/git'\n",
        1,
    )
    # Add a shared logical command builder to each embedded Python validator.
    # The shell wrapper cannot cross a heredoc boundary, so the policy is
    # repeated explicitly for subprocess.run/check_output callers.
    shell = shell.replace(
        "git = '/usr/bin/git'\n",
        "git = '/usr/bin/git'\n",
        1,
    )
    # The replay object-binding validator is transformed after the original
    # reader pass. Run a final heredoc-wide pass here so it cannot depend on a
    # reader defined in another Python process.
    shell = transform_heredocs(
        shell,
        lambda code: "read_stable_file(" in code and "def read_stable_file(" not in code,
        ensure_standalone_readers,
    )
    # Re-run the same pass after replay metadata hardening, which may add a
    # second stable read to an otherwise standalone validator.
    shell = transform_heredocs(
        shell,
        lambda code: "read_stable_file(" in code and "def read_stable_file(" not in code,
        ensure_standalone_readers,
    )
    shell = transform_heredocs(
        shell,
        lambda code: "raw_alternate, _alternate_stat = read_stable_file(alternate, 'replay alternates')" in code,
        replay_binding_hardening,
    )
    shell = transform_heredocs(
        shell,
        lambda code: "read_stable_file(" in code and "def read_stable_file(" not in code,
        ensure_standalone_readers,
    )
    target_gate = r'''assert_commit_target_states() {
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

'''
    if 'assert_commit_target_states() {' not in shell:
        shell = shell.replace('assert_commit_gate() {', target_gate + 'assert_commit_gate() {', 1)
    shell = shell.replace(
        '  if [ "$expected_patch" != - ]; then\n    patch="$(printf \'%s\' "$raw" | "$GIT" patch-id --stable | "$CUT" -d\' \' -f1)"\n',
        '  test "${#EXPECTED_COMMIT_TARGET_ROWS[@]}" -eq "${#paths[@]}" || fail "declared commit target row count mismatch"\n  assert_commit_target_states "$head" "${paths[@]}" -- "${EXPECTED_COMMIT_TARGET_ROWS[@]}"\n  if [ "$expected_patch" != - ]; then\n    patch="$(printf \'%s\' "$raw" | "$GIT" patch-id --stable | "$CUT" -d\' \' -f1)"\n',
        1,
    )
    shell = shell.replace(
        '  local paths=("$@") raw patch\n  test "$(git_replay rev-parse "$head^")" = "$parent" || fail "post-commit parent mismatch"\n',
        '  local paths=("$@") raw patch\n  test "${#EXPECTED_COMMIT_TARGET_ROWS[@]}" -eq "${#paths[@]}" || fail "declared commit target row count mismatch"\n  assert_commit_target_states "$head" "${paths[@]}" -- "${EXPECTED_COMMIT_TARGET_ROWS[@]}"\n  test "$(git_replay rev-parse "$head^")" = "$parent" || fail "post-commit parent mismatch"\n',
        1,
    )
    shell = transform_heredocs(
        shell,
        lambda code: 'subprocess.run(' in code or 'subprocess.check_output(' in code,
        embedded_git_policy,
    )
    # The replay-closure helper is a shell-level executable check, not merely
    # the static validator's Python function. Define it before bootstrap invokes
    # it so closure failures cannot become an undefined-command bypass.
    if 'assert_replay_closure() {' not in shell:
        shell = shell.replace('assert_tools() {', REPLAY_CLOSURE_FUNCTION + 'assert_tools() {', 1)
    target_record = r'''target_state_record() {
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

'''
    if 'target_state_record() {' not in shell:
        shell = shell.replace('commit_staged() {', target_record + 'commit_staged() {', 1)
    shell = shell.replace(
        '  local message="$1" expected_patch="$2"\n  shift 2\n  local paths=("$@") parent staged_raw staged_patch\n',
        '  local message="$1" expected_patch="$2"\n  shift 2\n  local paths=("$@") parent staged_raw staged_patch expected_tree\n  local EXPECTED_COMMIT_TARGET_ROWS=() target_path target_state\n  for target_path in "${paths[@]}"; do\n    target_state="$(target_state_record "$target_path")"\n    EXPECTED_COMMIT_TARGET_ROWS+=("$target_state")\n  done\n',
        1,
    )
    # Pin the staged index tree before each commit and compare it with the
    # resulting commit tree. This is independent of Git's commit output and
    # closes a staged-tree substitution between validation and commit.
    tree_pin = '  expected_tree="$(git_replay write-tree)" || fail "staged index tree could not be pinned"\n  test -n "$expected_tree" || fail "staged index tree is empty"\n'
    commit_start = shell.index('commit_staged() {')
    commit_end = shell.index('\n}\n\nrange_records()', commit_start)
    commit_body = shell[commit_start:commit_end]
    if 'git_replay write-tree' not in commit_body:
        check_line = next(
            line for line in ('  git_replay diff --cached --check -- "${paths[@]}"\n',)
            if line in commit_body
        )
        commit_body = commit_body.replace(check_line, check_line + tree_pin, 1)
        shell = shell[:commit_start] + commit_body + shell[commit_end:]
    shell = shell.replace(
        '  CURRENT_TREE="$(git_replay rev-parse HEAD^{tree})"\n  DIRTY_PATHS=()\n',
        '  CURRENT_TREE="$(git_replay rev-parse HEAD^{tree})"\n  test "$CURRENT_TREE" = "$expected_tree" || fail "post-commit tree differs from pinned staged tree"\n  DIRTY_PATHS=()\n',
        1,
    )
    static_anchor = "def out(*args):\n    return run(*args).stdout.decode().strip()\n"
    static_checks = '''def assert_object_closure():
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
    config = run('config', '--local', '--get-regexp', r'^(extensions\\.partialClone|remote\\..*|protocol\\..*\\.allow)$', check=False)
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
'''
    if static_anchor in shell and 'def assert_object_closure()' not in shell:
        shell = shell.replace(static_anchor, static_anchor + static_checks, 1)
    return shell


def patch_shell(shell):
    shell=transform_heredocs(shell,lambda c:'json.load(open' in c,json_reader)
    shell=transform_heredocs(shell,lambda c:'config_fd = os.open(config_path' in c,bind_reader)
    shell=transform_heredocs(shell,lambda c:"with open(config, 'rb')" in c,assert_reader)
    shell=transform_heredocs(shell,lambda c:"raw = open(os.path.join(dotgit, 'config'), 'rb').read()" in c,smoke_reader)
    shell=transform_heredocs(shell,lambda c:'source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)' in c,matrix_reader)
    shell=transform_heredocs(shell,lambda c:'fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)' in c and 'expected_device' in c,lambda c: c[:c.index('fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)')] + "raw, first = read_stable_file(path, 'matrix snapshot')\n" + c[c.index('path_stat = os.lstat(path)'):])
    shell=transform_heredocs(shell,lambda c:'source_fd = os.open(str(matrix), os.O_RDONLY | os.O_NOFOLLOW)' in c,readme_reader)
    shell=transform_heredocs(shell,lambda c:'raw_matrix = matrix.read_bytes()' in c,static_validator_reader)
    shell=transform_heredocs(shell,lambda c:'metadata = json.loads(matrix.read_bytes())' in c,metadata_path_reader)
    shell=transform_heredocs(shell,lambda c:'def read_stable(path):' in c and 'raw_matrix = read_stable(matrix)' in c,validator_reader)
    shell=transform_heredocs(shell,lambda c:"raw, first = read_stable_file(path, 'matrix snapshot')" in c,ensure_standalone_readers)
    # replay_binding_hardening may introduce its reader call in the same pass;
    # run the standalone pass again so each Python heredoc is self-contained.
    shell=transform_heredocs(shell,lambda c:"raw_alternate, _alternate_stat = read_stable_file(alternate, 'replay alternates')" in c,replay_binding_hardening)
    shell=transform_heredocs(shell,lambda c:"raw_alternate, _alternate_stat = read_stable_file(alternate, 'replay alternates')" in c,ensure_standalone_readers)
    shell=replace_function(shell,'assert_worktree_separation() {\n','\n\nassert_primary_pins() {',WORKTREE)
    shell=replace_function(shell,'assert_root_shape() {\n','\n\nassert_matrix_identity() {',ASSERT_ROOT_SHAPE)
    shell=replace_function(shell,'create_clean_primary_root() {\n','\n\nbind_clean_primary_identity() {',root_create_function('create_clean_primary_root','CLEAN_PRIMARY_ROOT','CLEAN_PRIMARY','CLEAN_PRIMARY_REPOSITORY'))
    shell=replace_function(shell,'create_replay_root() {\n','\n\n\nbind_matrix_snapshot() {',root_create_function('create_replay_root','REPLAY_ROOT','REPLAY','REPLAY_CHECKOUT'))
    # Add descriptor-bound child state before any Git clone/init, with immediate
    # checks on both sides of the Git CLI residual path window.
    shell=shell.replace('  assert_source_binding\n  # --no-hardlinks copies objects', '  assert_source_binding\n  assert_root_shape\n  # The repository child was created through the held root descriptor. Git CLI\n  # still accepts a pathname, so assert parent/root/child immediately before and after it.\n  # --no-hardlinks copies objects',1)
    shell=shell.replace('  git_hermetic clone --no-local --no-hardlinks --no-checkout --no-tags "$SOURCE" "$CLEAN_PRIMARY" >/dev/null\n  bind_clean_primary_identity', '  git_hermetic clone --no-local --no-hardlinks --no-checkout --no-tags "$SOURCE" "$CLEAN_PRIMARY" >/dev/null\n  assert_root_shape\n  assert_worktree_separation\n  bind_clean_primary_identity',1)
    shell=shell.replace('  bind_clean_primary_identity\n  before_clean_primary_mutation', '  bind_clean_primary_identity\n  assert_root_shape\n  assert_worktree_separation\n  before_clean_primary_mutation',1)
    shell=shell.replace('  git_primary checkout --detach --force "$BASE" >/dev/null\n  assert_clean_primary_state', '  assert_root_shape\n  assert_worktree_separation\n  git_primary checkout --detach --force "$BASE" >/dev/null\n  assert_root_shape\n  assert_worktree_separation\n  assert_clean_primary_state',1)
    # Identity binding itself performs repository-aware rev-parse calls. Keep
    # the root and registry checks adjacent to that sequence while the child is
    # descriptor-bound but not yet Git-identity-bound.
    bind_old = '''  local git_dir common_dir objects fields
  git_dir="$(git_primary rev-parse --absolute-git-dir)"
  common_dir="$(git_primary rev-parse --git-common-dir)"
  objects="$(git_primary rev-parse --git-path objects)"
'''
    bind_new = '''  local git_dir common_dir objects fields
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
'''
    bind_count=shell.count(bind_old)
    if bind_count == 1:
        shell=shell.replace(bind_old, bind_new, 1)
    elif bind_count != 0 or shell.count(bind_new) != 1:
        raise RuntimeError('clean-primary identity call-site anchor mismatch')
    bootstrap_old = '''  test -z "$CURRENT_TREE" || fail "bootstrap current tree is unexpectedly populated"
  test "${#DIRTY_PATHS[@]}" -eq 0 || fail "bootstrap boundary has dirty transaction paths"
  if git_replay rev-parse --verify refs/remotes/origin/dev >/dev/null 2>&1; then
'''
    bootstrap_new = '''  test -z "$CURRENT_TREE" || fail "bootstrap current tree is unexpectedly populated"
  test "${#DIRTY_PATHS[@]}" -eq 0 || fail "bootstrap boundary has dirty transaction paths"
  # The descriptor-created replay child is intentionally not a Git repository
  # until init completes. Do not invoke Git or worktree-list before that point.
  if [ "$REPLAY_GIT_BOUND" -eq 0 ]; then
    return 0
  fi
  if git_replay rev-parse --verify refs/remotes/origin/dev >/dev/null 2>&1; then
'''
    bootstrap_count=shell.count(bootstrap_old)
    if bootstrap_count == 1:
        shell=shell.replace(bootstrap_old, bootstrap_new, 1)
    elif bootstrap_count != 0 and shell.count(bootstrap_new) != 1:
        raise RuntimeError('bootstrap guard anchor mismatch')
    preinit = '''assert_replay_preinit_state() {
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

'''
    # Remove prior generated copies before inserting the canonical smoke helper.
    # The generator may be resumed after a partial write, so definitions must not
    # accumulate across fixed-point regeneration runs.
    shell=re.sub(r'(?ms)^(?:assert_replay_preinit_state|assert_replay_checkout_removed_state)\(\) \{.*?^\}\n\n', '', shell)
    shell=shell.replace('create_replay_root\nCLEANUP_ALLOWLIST=', 'create_replay_root\nassert_replay_preinit_state\nCLEANUP_ALLOWLIST=', 1)
    replay_init_old = '''"$MKDIR" -p "$REPLAY"
before_mutation
"$GIT" -c core.hooksPath=/dev/null -c protocol.allow=never init "$REPLAY" >/dev/null
REPLAY_GIT_DIR="$(git_replay rev-parse --absolute-git-dir)"
case "$REPLAY_GIT_DIR" in "$REPLAY"/.git|"$REPLAY"/*) ;; *) fail "replay Git directory escaped replay root" ;; esac
before_mutation
"$MKDIR" -p "$REPLAY/.git/objects/info"
before_mutation
printf '%s\\n' "$CLEAN_PRIMARY_OBJECTS" > "$REPLAY/.git/objects/info/alternates"
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
'''
    replay_init_new = '''assert_root_shape
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
printf '%s\\n' "$CLEAN_PRIMARY_OBJECTS" > "$REPLAY/.git/objects/info/alternates"
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
'''

    if replay_init_old not in shell:
        raise RuntimeError('replay init anchor mismatch')
    shell=shell.replace(replay_init_old, replay_init_new, 1)
    # Earlier Git-policy rewrites can leave the tail of the original bootstrap
    # after the replacement prefix. Remove that second bootstrap transaction so
    # alternate creation, ref setup, and closure run exactly once.
    replay_alt = re.compile(r'(?m)^(?:"?\$MKDIR"?|-?\$MKDIR) -p "\$REPLAY/\.git/objects/info"\n')
    replay_alt_matches = list(replay_alt.finditer(shell))
    if len(replay_alt_matches) > 1:
        duplicate_start = replay_alt_matches[1].start()
        duplicate_end_match = re.search(r'(?m)^assert_replay_state "\$CURRENT_HEAD" "\$CURRENT_TREE"\n', shell[duplicate_start:])
        if duplicate_end_match is None:
            raise RuntimeError('duplicate replay bootstrap cleanup anchor missing')
        duplicate_end = duplicate_start + duplicate_end_match.end()
        shell = shell[:duplicate_start] + shell[duplicate_end:]
    # Add descriptor-bound state variables near existing root variables.
    anchor="CLEAN_PRIMARY_ROOT_REALPATH=''\n"
    insert="""CLEAN_PRIMARY_ROOT_REALPATH=''\nCLEAN_PRIMARY_ROOT_NLINK=''\nCLEAN_PRIMARY_PARENT_DEVICE=''\nCLEAN_PRIMARY_PARENT_INODE=''\nCLEAN_PRIMARY_PARENT_UID=''\nCLEAN_PRIMARY_PARENT_MODE=''\nCLEAN_PRIMARY_PARENT_NLINK=''\nCLEAN_PRIMARY_REPOSITORY_BOUND=0\nCLEAN_PRIMARY_REPOSITORY_DEVICE=''\nCLEAN_PRIMARY_REPOSITORY_INODE=''\nCLEAN_PRIMARY_REPOSITORY_UID=''\nCLEAN_PRIMARY_REPOSITORY_MODE=''\nCLEAN_PRIMARY_REPOSITORY_NLINK=''\n"""
    shell=replace_once(shell,anchor,insert,'clean root globals')
    anchor="REPLAY_ROOT_REALPATH=''\n"
    insert="""REPLAY_ROOT_REALPATH=''\nREPLAY_GIT_BOUND=0\nREPLAY_ROOT_NLINK=''\nREPLAY_PARENT_DEVICE=''\nREPLAY_PARENT_INODE=''\nREPLAY_PARENT_UID=''\nREPLAY_PARENT_MODE=''\nREPLAY_PARENT_NLINK=''\nREPLAY_CHECKOUT_BOUND=0\nREPLAY_CHECKOUT_DEVICE=''\nREPLAY_CHECKOUT_INODE=''\nREPLAY_CHECKOUT_UID=''\nREPLAY_CHECKOUT_MODE=''\nREPLAY_CHECKOUT_NLINK=''\n"""
    shell=replace_once(shell,anchor,insert,'replay root globals')
    shell=shell.replace("REPLAY_CHECKOUT_BOUND=0\n", "REPLAY_CHECKOUT_BOUND=0\nREPLAY_CHECKOUT_PRESENT=0\n", 1)
    # Ensure cleanup resets child-bound flags only after successful cleanup.
    shell=shell.replace('  CLEAN_PRIMARY_ROOT_BOUND=0\n  CLEAN_PRIMARY_BOUND=0\n}', '  CLEAN_PRIMARY_ROOT_BOUND=0\n  CLEAN_PRIMARY_REPOSITORY_BOUND=0\n  CLEAN_PRIMARY_BOUND=0\n}',1)
    shell=shell.replace('  REPLAY_ROOT_BOUND=0\n}', '  REPLAY_ROOT_BOUND=0\n  REPLAY_CHECKOUT_BOUND=0\n  REPLAY_CHECKOUT_PRESENT=0\n  REPLAY_GIT_BOUND=0\n}',1)
    # Once the replay checkout is removed, retain the root identity for the
    # final rmdir audit but clear every child/repository state consumed by Git.
    cleanup_old = '''        DIRTY_PATHS=()
        ;;'''
    cleanup_new = '''        DIRTY_PATHS=()
        REPLAY_CHECKOUT_PRESENT=0
        REPLAY_CHECKOUT_BOUND=0
        REPLAY_GIT_BOUND=0
        REPLAY_OBJECTS_BOUND=0
        REPLAY_INFO_BOUND=0
        REPLAY_ALTERNATES_BOUND=0
        assert_replay_checkout_removed_state
        ;;'''
    shell=shell.replace(cleanup_old, cleanup_new, 1)
    removed_state = '''assert_replay_checkout_removed_state() {
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

'''
    cleanup_anchor='cleanup_success_only() {\n'
    if cleanup_anchor in shell:
        shell=shell.replace(cleanup_anchor, preinit + removed_state + cleanup_anchor, 1)
    # Recheck replay closure while the replay Git identity and checkout are still
    # bound, immediately before the allowlisted replay cleanup call. The first
    # post-bootstrap check proves the initial object graph; this second check
    # catches any closure drift introduced by the complete replay transaction.
    cleanup_call='cleanup_success_only "$REPLAY" "$README_TMP" "$MATRIX_SNAPSHOT"'
    if cleanup_call not in shell:
        raise RuntimeError('replay cleanup call anchor missing')
    shell=shell.replace(
        cleanup_call,
        'assert_replay_closure\n' + cleanup_call + '\n# Keep the post-call lifecycle ledger explicit: cleanup_success_only resets this only after the replay child was removed.\nREPLAY_GIT_BOUND=0',
        1,
    )
    shell = harden_shell(shell)
    shell = add_producer_validators(shell)
    shell = guard_optional_dirty_arrays(shell)
    shell = shell.replace(
        'for bad in "${bad_objects[@]}"; do',
        'for bad in "${bad_objects[@]}"; do',
    )
    shell = shell.replace(
        "item.get('path') == '/private/tmp/hermternal-task409-approved-driver.sh'",
        "item.get('path') == '/private/tmp/' + 'hermternal-task409-approved-driver.sh'",
    )
    # Generated child Python must retain one source backslash for delimiter,
    # alternate-LF, and regex semantics. These comments are emitted so a review
    # can distinguish source escapes from Python runtime values.
    shell = '# Candidate4 generated Python escape invariant: one source backslash; no global escape replacement.\n' + shell
    return shell


def normalized_sha(raw, token):
    n = raw.replace(token.encode(), b'0' * 64)
    for key in (
        b'"shell_sha256": "',
        b'"driver_shell_sha256": "',
        b'"expected_body_sha256": "',
    ):
        n = re.sub(
            re.escape(key) + rb'[0-9a-f]{64}(?=")',
            lambda m: m.group(0)[:len(key)] + b'0' * 64,
            n,
        )
    return hashlib.sha256(n).hexdigest()


def read_generator_file(path, label):
    """Read a generator input through a held no-follow descriptor pair."""
    path = os.fspath(path)
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise RuntimeError(f'{label} path is not canonical: {path}')
    parent = os.path.dirname(path)
    name = os.path.basename(path)
    parent_pre = os.lstat(parent)
    if (not stat.S_ISDIR(parent_pre.st_mode) or stat.S_ISLNK(parent_pre.st_mode)
            or os.path.realpath(parent) != parent):
        raise RuntimeError(f'{label} parent is not canonical')
    parent_id = (parent_pre.st_dev, parent_pre.st_ino, parent_pre.st_uid, parent_pre.st_nlink)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent_first = os.fstat(parent_fd)
        if (parent_first.st_dev, parent_first.st_ino, parent_first.st_uid, parent_first.st_nlink) != parent_id:
            raise RuntimeError(f'{label} parent changed before open')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise RuntimeError(f'{label} is not a regular single-link file')
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
    file_id = lambda st: (st.st_dev, st.st_ino, st.st_uid, st.st_size, st.st_nlink)
    if file_id(first) != file_id(second) or file_id(first) != file_id(final):
        raise RuntimeError(f'{label} changed while reading')
    if (parent_second.st_dev, parent_second.st_ino, parent_second.st_uid, parent_second.st_nlink) != parent_id:
        raise RuntimeError(f'{label} parent changed while reading')
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1 or os.path.realpath(path) != path:
        raise RuntimeError(f'{label} final identity changed')
    raw = b''.join(chunks)
    if len(raw) != first.st_size:
        raise RuntimeError(f'{label} byte count disagrees with fstat')
    return raw


def extract_fenced(raw, heading, opening, label):
    heading = heading.encode()
    opening = opening.encode()
    start = raw.find(heading)
    if start < 0:
        raise RuntimeError(f'{label} heading is missing')
    opening_at = raw.find(opening, start + len(heading))
    if opening_at < 0:
        raise RuntimeError(f'{label} opening fence is missing')
    body_start = opening_at + len(opening)
    closing_at = raw.find(b'```', body_start)
    if closing_at < 0:
        raise RuntimeError(f'{label} closing fence is missing')
    return raw[body_start:closing_at]


def parse_ordered_steps(raw):
    text = raw.decode('utf-8')
    header = '| Order | Step | Boundary | Gate |'
    start = text.index(header)
    rows = []
    for line in text[start:].splitlines()[2:]:
        if not line.startswith('| '):
            break
        fields = line.split('|')
        if len(fields) != 6 or not fields[1].strip().isdigit():
            break
        rows.append({
            'order': int(fields[1].strip()),
            'id': fields[2].strip().strip('`'),
            'boundary': fields[3].strip().strip('`'),
            'gate': fields[4].strip(),
        })
    if len(rows) != 21 or [row['order'] for row in rows] != list(range(1, 22)):
        raise RuntimeError('Markdown ordered-step table must contain exactly 21 ordered rows')
    return rows


def collect_mirrors(value, pointer='', historical=None, targets=None):
    if historical is None:
        historical = []
    if targets is None:
        targets = []
    if isinstance(value, dict):
        if 'target_states' in value:
            targets.append({
                'json_pointer': pointer or '/',
                'changed_paths': value.get('changed_paths', []),
                'target_states': value['target_states'],
            })
        if 'changed_paths' in value:
            historical.append({
                'json_pointer': pointer or '/',
                'changed_paths': value['changed_paths'],
            })
        for key, child in value.items():
            child_pointer = f'{pointer}/{key}' if pointer else f'/{key}'
            collect_mirrors(child, child_pointer, historical, targets)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_pointer = f'{pointer}/{index}' if pointer else f'/{index}'
            collect_mirrors(child, child_pointer, historical, targets)
    return historical, targets


def canonicalize_paths(value, output_json, output_markdown):
    """Rewrite only exact legacy artifact paths, never an embedded suffix.

    Matching the full absolute legacy names avoids turning an already canonical
    ``/private/tmp/...`` path into ``/private/private/tmp/...``.
    """
    legacy_json = '/tmp/hermternal-task409-final-execution-matrix.json'
    legacy_markdown = '/tmp/hermternal-task409-final-execution-matrix.md'
    if isinstance(value, str):
        if value == legacy_json:
            return str(output_json)
        if value == legacy_markdown:
            return str(output_markdown)
        return value
    if isinstance(value, list):
        return [canonicalize_paths(item, output_json, output_markdown) for item in value]
    if isinstance(value, dict):
        return {key: canonicalize_paths(item, output_json, output_markdown) for key, item in value.items()}
    return value


EXACT_GIT_REFERENCE_EXPANSIONS = {
    '013ea2ef': '013ea2ef992bc309290efe6f8d899a4c85381f80',
    '5559e9ad': '5559e9ad4cf78debc98e8935c47cdc956535f96c',
    '822b9668': '822b9668577f8f0f983abde6f00423c586042823',
    'e664505c': 'e664505c7ad9779855a394c62f72823fad7eba76',
    '5e36276a': '5e36276a27bf0f241d6a860a2cf2c865dc97be83',
    'a88dd123': 'a88dd1233c01f780544d563b2a030fdd1cfd0c0f',
    '1f5c2f52': '1f5c2f5282b1be0fdbac508749e99b5e790d3a9b',
    '8be4f513': '8be4f513286813a7a1cbe7bbc997f53b7d557209',
    '1ffc3418': '1ffc341888ea6f22bbaad42b5f989038213d72d4',
    'e3a2d2e6': 'e3a2d2e662f2e606f318d35f4fccc63ba9738f7c',
    '80fe': '80fe3b68fb676a3b6589fce9aed79140bf37b667',
}


def expand_exact_git_references(value):
    """Expand reviewed ledger prefixes and remove only a range suffix.

    The validator rejects an abbreviated token when it prefixes a known object
    ID. Expand only the reviewed, unique ledger prefixes. The source also has a
    mechanical ``<full>..<full>..`` range spelling; remove that final suffix
    with a callable replacement so the replacement is semantic rather than an
    opaque backreference string.
    """
    if isinstance(value, str):
        for short, full in EXACT_GIT_REFERENCE_EXPANSIONS.items():
            value = re.sub(rf'(?<![0-9a-f]){re.escape(short)}(?![0-9a-f])', full, value)

        def keep_range(match):
            return match.group(1)

        value = re.sub(
            r'(?<![0-9a-f])([0-9a-f]{40}\\.\\.[0-9a-f]{40})\\.\\.(?![0-9a-f])',
            keep_range,
            value,
        )
        return value
    if isinstance(value, list):
        return [expand_exact_git_references(item) for item in value]
    if isinstance(value, dict):
        return {key: expand_exact_git_references(item) for key, item in value.items()}
    return value


# Candidate 1 is immutable input. Candidate4 has no implicit outputs: all three
# destinations are explicit CLI arguments and are validated before any publish.
FROZEN_PATHS = {
    '/private/tmp/task464-candidate1-json.json', '/private/tmp/task464-candidate1-md.md',
    '/private/tmp/task464-candidate1-shell.sh',
    '/private/tmp/task464-candidate2-json.json', '/private/tmp/task464-candidate2-md.md',
    '/private/tmp/task464-candidate2-shell.sh',
    '/private/tmp/task464-candidate3-execution-matrix.json', '/private/tmp/task464-candidate3-execution-matrix.md',
    '/private/tmp/task464-candidate3-shell.sh', '/private/tmp/task464-candidate3-shell.inspect.sh',
    '/private/tmp/task464-candidate3-shell-mutated-3dbc0a4e.sh',
    '/private/tmp/task464-candidate3-shell-oldhash-independent.sh',
    '/private/tmp/task464-test32-json.json', '/private/tmp/task464-test32-md.md',
    '/private/tmp/task464-test32-shell.sh',
    '/private/tmp/task464-sole-writer-generator.py',
    '/private/tmp/task464-candidate4-generator-safe.py',
    '/private/tmp/task464-working-input.json', '/private/tmp/task464-working-input.md',
}
REHEARSAL_OUTPUTS = {
    '/private/tmp/task464-test32-json.json', '/private/tmp/task464-test32-md.md',
    '/private/tmp/task464-test32-shell.sh',
}
OWNER_MARKER = b'TASK464-CANDIDATE4-REHEARSAL-OWNER:v1\n'

def canonical_target(value, label):
    path = Path(value)
    if not path.is_absolute() or os.path.realpath(path) != os.fspath(path):
        raise RuntimeError(f'{label} must be an absolute canonical path: {path}')
    if path.parent != Path('/private/tmp'):
        raise RuntimeError(f'{label} must be a direct /private/tmp target: {path}')
    if os.path.normpath(os.fspath(path)) != os.fspath(path):
        raise RuntimeError(f'{label} is not normalized: {path}')
    return path

def reject_target_set(targets):
    values = tuple(os.fspath(path) for path in targets)
    expected = (
        '/private/tmp/task464-test32-json.json',
        '/private/tmp/task464-test32-md.md',
        '/private/tmp/task464-test32-shell.sh',
    )
    if values != expected:
        raise RuntimeError('output role/path mismatch; JSON, Markdown, and shell roles are fixed')
    if len(set(values)) != 3:
        raise RuntimeError('output targets must be distinct')
    for path in targets:
        value = os.fspath(path)
        if value in FROZEN_PATHS and value not in REHEARSAL_OUTPUTS:
            raise RuntimeError(f'output target is frozen or immutable: {path}')
        if value not in REHEARSAL_OUTPUTS:
            raise RuntimeError(f'output target is not an allowlisted rehearsal path: {path}')
        if os.path.lexists(path):
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode) or st.st_nlink != 1:
                raise RuntimeError(f'output target is a symlink or hardlink: {path}')
            raise RuntimeError(f'output target already exists; refusing overwrite: {path}')

def _file_identity(st):
    """Capture descriptor metadata used for staging and ownership checks."""
    return (
        st.st_dev,
        st.st_ino,
        st.st_uid,
        stat.S_IMODE(st.st_mode),
        st.st_nlink,
        st.st_size,
    )


def _inode_identity(st):
    """Return the stable inode key used to avoid stale-name deletion."""
    return (st.st_dev, st.st_ino)


def _lstat_inode(path):
    try:
        return _inode_identity(os.lstat(path))
    except FileNotFoundError:
        return None


def _add_cleanup_errors(primary, errors):
    if not errors:
        return
    details = '; '.join(f'{label}: {exc!r}' for label, exc in errors)
    try:
        primary.add_note(f'publication cleanup errors (retried): {details}')
    except Exception:
        pass
    try:
        setattr(primary, 'cleanup_errors', tuple(errors))
    except Exception:
        pass


def _raw_close(fd):
    """Close through libc after an injected/ambiguous os.close failure."""
    libc = ctypes.CDLL(None, use_errno=True)
    close = libc.close
    close.argtypes = [ctypes.c_int]
    close.restype = ctypes.c_int
    result = close(fd)
    if result != 0:
        error = ctypes.get_errno()
        if error != errno.EBADF:
            raise OSError(error, os.strerror(error))


def _close_fd(entry, errors):
    fd = entry.get('fd')
    if fd is None:
        return
    try:
        os.close(fd)
    except BaseException as primary:
        # A wrapper may raise after the real close, or before it. The libc
        # fallback closes the descriptor in the latter case; EBADF means the
        # first close already consumed it. Preserve close errors as secondary.
        try:
            _raw_close(fd)
        except BaseException as fallback:
            if not (isinstance(fallback, OSError) and fallback.errno == errno.EBADF):
                errors.append((f'{entry["label"]} descriptor fallback close', fallback))
        errors.append((f'{entry["label"]} descriptor close', primary))
    finally:
        entry['fd'] = None


def _stat_entry(entry, path_key):
    """Read an entry name relative to its held directory descriptor."""
    if path_key == 'target':
        return os.stat(entry['target'].name, dir_fd=entry['public_fd'], follow_symlinks=False)
    if path_key == 'stage':
        return os.stat(entry['stage_name'], dir_fd=entry['stage_fd'], follow_symlinks=False)
    raise RuntimeError(f'unknown publication path role: {path_key}')


def _unlink_entry(entry, path_key, label):
    """Unlink an owned name after identity validation.

    macOS/POSIX has no general unlink-by-file-descriptor primitive. The held
    descriptor and recorded inode prevent stale-name cleanup after a rename or
    a detected substitution. An actively hostile same-UID process can still
    swap a pathname after this check and before unlink; that cooperative
    concurrency boundary is stated rather than overclaimed.
    """
    try:
        path_stat = _stat_entry(entry, path_key)
    except FileNotFoundError:
        return True
    if entry.get('inode') is None or _inode_identity(path_stat) != entry['inode']:
        return False
    fd = entry.get('fd')
    if fd is not None:
        descriptor = os.fstat(fd)
        if _inode_identity(descriptor) != entry['inode'] or descriptor.st_nlink == 0:
            return False
    if path_key == 'target':
        os.unlink(entry['target'].name, dir_fd=entry['public_fd'])
    else:
        os.unlink(entry['stage_name'], dir_fd=entry['stage_fd'])
    return True


def _cleanup_one(entry, path_key, label, errors):
    """Attempt one owned cleanup twice and keep cleanup errors secondary."""
    for attempt in range(2):
        try:
            owned = _unlink_entry(entry, path_key, label)
            if not owned:
                errors.append((f'{label} ownership mismatch', RuntimeError('current name is not the recorded inode')))
            return
        except BaseException as exc:
            errors.append((f'{label} attempt {attempt + 1}', exc))


def _cleanup_entries(entries, stage):
    """Attempt every output/stage cleanup and descriptor close independently."""
    errors = []
    for entry in reversed(entries):
        if entry.get('published'):
            _cleanup_one(entry, 'target', f'{entry["label"]} published output', errors)
        _cleanup_one(entry, 'stage', f'{entry["label"]} staged pathname', errors)
    for entry in entries:
        _close_fd(entry, errors)
    _close_fd(stage, errors)
    return errors


def _fsync_directory(directory):
    fd = os.open(os.fspath(directory), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _digest_fd(fd, size):
    digest = hashlib.sha256()
    chunks = []
    offset = 0
    while offset < size:
        chunk = os.pread(fd, min(1024 * 1024, size - offset), offset)
        if not chunk:
            break
        digest.update(chunk)
        chunks.append(chunk)
        offset += len(chunk)
    if offset != size:
        raise RuntimeError('staged descriptor size changed while validating')
    return digest.hexdigest(), b''.join(chunks)


def _validate_staged(entry):
    """Validate held descriptor and exact stage leaf immediately before link."""
    descriptor = os.fstat(entry['fd'])
    if _file_identity(descriptor) != entry['identity']:
        raise RuntimeError(f'{entry["label"]} staged descriptor identity changed')
    path_stat = _stat_entry(entry, 'stage')
    if _file_identity(path_stat) != entry['identity']:
        raise RuntimeError(f'{entry["label"]} staged pathname identity changed')
    digest, raw = _digest_fd(entry['fd'], entry['size'])
    if digest != entry['digest'] or raw != entry['data']:
        raise RuntimeError(f'{entry["label"]} staged bytes changed')
    # Rebind immediately before the hard link. This second fstat/digest pass
    # closes same-inode content mutation between the first validation and link;
    # cooperative writers must not mutate a held stage fd during publication.
    descriptor = os.fstat(entry['fd'])
    digest, raw = _digest_fd(entry['fd'], entry['size'])
    if _file_identity(descriptor) != entry['identity'] or digest != entry['digest'] or raw != entry['data']:
        raise RuntimeError(f'{entry["label"]} staged bytes changed before publication')


def _reconcile_publication(entry):
    """Reconcile target and stage identities after every link attempt."""
    try:
        target_inode = _inode_identity(_stat_entry(entry, 'target'))
    except FileNotFoundError:
        target_inode = None
    try:
        stage_inode = _inode_identity(_stat_entry(entry, 'stage'))
    except FileNotFoundError:
        stage_inode = None
    entry['published'] = target_inode == entry['inode']
    entry['source_present'] = stage_inode == entry['inode']
    return target_inode, stage_inode


def _link_entry_no_replace(entry):
    """Create the public name as a no-replace hard link to the held stage leaf."""
    os.link(
        entry['stage_name'],
        entry['target'].name,
        src_dir_fd=entry['stage_fd'],
        dst_dir_fd=entry['public_fd'],
        follow_symlinks=False,
    )


def _injected_link_paths(entry):
    """Expose absolute paths for focused test wrappers without changing default safety."""
    return entry['stage_dir'] / entry['stage_name'], entry['target']


def _open_stage(parent):
    """Create a private 0700 stage directory and retain its directory fd."""
    raw = tempfile.mkdtemp(prefix='.task464-candidate4-stage.', dir=os.fspath(parent))
    path = Path(raw)
    fd = None
    try:
        os.chmod(path, 0o700, follow_symlinks=False)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o700:
            raise RuntimeError('staging directory identity or mode is unsafe')
        return {
            'label': 'staging directory',
            'path': path,
            'fd': fd,
            'inode': _inode_identity(st),
            'identity': _file_identity(st),
        }
    except BaseException:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass
        try:
            os.rmdir(path)
        except Exception:
            pass
        raise


def _remove_stage_dir(stage, errors):
    """Remove only the exact empty stage directory after its fd is closed."""
    path = stage['path']
    try:
        st = os.lstat(path)
        if _inode_identity(st) != stage['inode']:
            errors.append(('staging directory identity changed', RuntimeError(str(path))))
            return
        os.rmdir(path)
    except FileNotFoundError:
        return
    except BaseException as exc:
        errors.append(('staging directory cleanup', exc))


def write_temp(stage, name, data):
    """Create an exact private stage leaf with O_EXCL and retain its fd."""
    fd = os.open(
        name,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=stage['fd'],
    )
    entry = {
        'label': name,
        'stage': stage,
        'stage_dir': stage['path'],
        'stage_fd': stage['fd'],
        'stage_name': name,
        'fd': fd,
        'inode': None,
        'identity': None,
        'size': len(data),
        'digest': hashlib.sha256(data).hexdigest(),
        'data': bytes(data),
        'published': False,
        'source_present': True,
    }
    try:
        # Bind identity immediately after O_EXCL creation, before content write.
        descriptor = os.fstat(fd)
        entry['inode'] = _inode_identity(descriptor)
        entry['identity'] = _file_identity(descriptor)
        if descriptor.st_nlink != 1:
            raise RuntimeError(f'{name} staged file is not single-link')
        os.fchmod(fd, 0o600)
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            view = view[count:]
        os.fsync(fd)
        final = os.fstat(fd)
        expected = (
            final.st_dev, final.st_ino, final.st_uid, stat.S_IMODE(final.st_mode),
            final.st_nlink, len(data),
        )
        if _file_identity(final) != expected:
            raise RuntimeError(f'{name} staged file identity or size is unsafe')
        # Keep the immediate post-mkstemp inode binding, but validate later
        # against the final size-bearing identity after the exact write.
        entry['identity'] = _file_identity(final)
    except BaseException as primary:
        cleanup_errors = []
        # Do not close the shared stage fd here: earlier staged leaves still
        # need it for identity-bound rollback. Remove this leaf only when its
        # inode was recorded by the immediate post-O_EXCL fstat; never adopt a
        # fresh pathname lstat as ownership after an fstat failure.
        if entry['inode'] is not None:
            _cleanup_one(entry, 'stage', f'{name} staging cleanup', cleanup_errors)
        _close_fd(entry, cleanup_errors)
        _add_cleanup_errors(primary, cleanup_errors)
        raise
    return entry


def publish_once(targets, payloads, final_validate=None, rename_impl=None):
    """Publish rehearsal leaves with an advisory-lock/private-stage protocol.

    The /private/tmp directory inode is locked exclusively for the whole
    stage/publish/validate/rollback transaction. This coordinates cooperative
    writers without creating another artifact. Exact leaves live in a random
    0700 stage directory, stay fd-bound, and are linked into the public
    directory with no-replace hard-link semantics. POSIX/macOS cannot make
    three names visible atomically across a crash; a hostile same-UID pathname
    swap or process death can still leave partial visibility or residue.
    """
    if len(targets) != len(payloads) or len(targets) != 3:
        raise RuntimeError('publication requires exactly three targets and payloads')
    expected_targets = (
        Path('/private/tmp/task464-test32-json.json'),
        Path('/private/tmp/task464-test32-md.md'),
        Path('/private/tmp/task464-test32-shell.sh'),
    )
    canonical_targets = tuple(Path(item) for item in targets)
    if canonical_targets != expected_targets:
        raise RuntimeError('publication helper received noncanonical or role-mismatched targets')
    if any(
        os.path.realpath(item) != os.fspath(item)
        or item.parent != Path('/private/tmp')
        for item in canonical_targets
    ):
        raise RuntimeError('publication helper received noncanonical target')

    entries = []
    stage = None
    public_fd = None
    lock_fd = None
    lock_held = False
    primary = None
    try:
        # Open the exact parent once, and a stable pre-existing regular lock
        # file separately. The lock is generator infrastructure, not output.
        public_fd = os.open('/private/tmp', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        public_stat = os.fstat(public_fd)
        if not stat.S_ISDIR(public_stat.st_mode) or os.path.realpath('/private/tmp') != '/private/tmp':
            raise RuntimeError('public directory identity is unsafe')
        lock_path = Path('/private/tmp/task464-candidate4-rehearsal.lock')
        lock_pre = os.lstat(lock_path)
        if (
            not stat.S_ISREG(lock_pre.st_mode)
            or stat.S_ISLNK(lock_pre.st_mode)
            or lock_pre.st_nlink != 1
            or stat.S_IMODE(lock_pre.st_mode) != 0o600
            or lock_pre.st_uid != os.getuid()
            or os.path.realpath(lock_path) != os.fspath(lock_path)
        ):
            raise RuntimeError('rehearsal lock file identity or mode is unsafe')
        lock_fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
        lock_post = os.fstat(lock_fd)
        if (
            _file_identity(lock_post)[:5] != _file_identity(lock_pre)[:5]
            or stat.S_IMODE(lock_post.st_mode) != 0o600
            or lock_post.st_nlink != 1
        ):
            raise RuntimeError('rehearsal lock file changed before locking')
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        lock_held = True
        stage = _open_stage('/private/tmp')
        for label, target, data in zip(('json', 'md', 'shell'), canonical_targets, payloads):
            if os.path.lexists(target):
                raise RuntimeError(f'publication target already exists: {target}')
            entry = write_temp(stage, label, data)
            entry['target'] = target
            entry['public_fd'] = public_fd
            entries.append(entry)

        for entry in entries:
            _validate_staged(entry)
            try:
                os.stat(entry['target'].name, dir_fd=public_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise RuntimeError(f'publication target appeared during staging: {entry["target"]}')
            link_error = None
            try:
                if rename_impl is None:
                    _link_entry_no_replace(entry)
                else:
                    # Test hooks receive absolute names. The production path
                    # above uses held stage/public dirfds and never follows a
                    # mutable source pathname.
                    source, target = _injected_link_paths(entry)
                    rename_impl(source, target)
            except BaseException as exc:
                link_error = exc
            # Reconcile after every attempt, including a wrapper that raises
            # after creating the hard link. Non-ENOENT errors are not hidden.
            try:
                target_inode, stage_inode = _reconcile_publication(entry)
            except BaseException as reconcile_error:
                if link_error is not None:
                    _add_cleanup_errors(link_error, [('link reconciliation', reconcile_error)])
                    raise link_error
                raise
            if link_error is not None:
                raise link_error
            if target_inode != entry['inode']:
                raise RuntimeError(f'{entry["label"]} publication inode mismatch')
            if stage_inode != entry['inode']:
                raise RuntimeError(f'{entry["label"]} stage inode disappeared unexpectedly')

        _fsync_directory('/private/tmp')
        result = None if final_validate is None else final_validate(
            canonical_targets, tuple(payloads)
        )

        # Keep public hard links until all final validation succeeds; remove
        # stage names and close descriptors while still holding the lock.
        success_errors = []
        for entry in entries:
            _cleanup_one(entry, 'stage', f'{entry["label"]} success stage cleanup', success_errors)
        for entry in entries:
            _close_fd(entry, success_errors)
        _close_fd(stage, success_errors)
        _remove_stage_dir(stage, success_errors)
        if success_errors:
            error = RuntimeError('publication cleanup failed after validation')
            _add_cleanup_errors(error, success_errors)
            raise error
        _fsync_directory('/private/tmp')
        return result
    except BaseException as exc:
        primary = exc
        # Reconcile every entry after every failure so post-effect link errors
        # and identity checks cannot leak an owned target merely because a flag
        # was stale. Cleanup attempts remain under the advisory lock.
        reconciliation_errors = []
        for entry in entries:
            try:
                _reconcile_publication(entry)
            except BaseException as residual:
                reconciliation_errors.append((f'{entry["label"]} rollback reconciliation', residual))
        cleanup_errors = _cleanup_entries(entries, stage) if stage is not None else []
        if stage is not None:
            _remove_stage_dir(stage, cleanup_errors)
        _add_cleanup_errors(primary, reconciliation_errors + cleanup_errors)
        raise
    finally:
        release_errors = []
        if lock_held:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except BaseException as exc:
                release_errors.append(('public directory unlock', exc))
        if lock_fd is not None:
            try:
                os.close(lock_fd)
            except BaseException as exc:
                release_errors.append(('rehearsal lock close', exc))
        if public_fd is not None:
            try:
                os.close(public_fd)
            except BaseException as exc:
                release_errors.append(('public directory close', exc))
        if release_errors and primary is not None:
            _add_cleanup_errors(primary, release_errors)
        elif release_errors:
            raise RuntimeError(f'publication lock release failed: {release_errors!r}')

def parse_cli(argv=None):
    parser = argparse.ArgumentParser(description='Generate mutable Task464 candidate4 rehearsal artifacts')
    parser.add_argument('--input-json', required=True)
    parser.add_argument('--input-markdown', required=True)
    parser.add_argument('--output-json', required=True)
    parser.add_argument('--output-markdown', required=True)
    parser.add_argument('--output-shell', required=True)
    return parser.parse_args(argv)

def main(argv=None):
    args = parse_cli(argv)
    source_json = canonical_target(args.input_json, 'input JSON')
    source_markdown = canonical_target(args.input_markdown, 'input Markdown')
    output_json = canonical_target(args.output_json, 'output JSON')
    output_markdown = canonical_target(args.output_markdown, 'output Markdown')
    output_shell = canonical_target(args.output_shell, 'output shell')
    if source_json in (output_json, output_markdown, output_shell) or source_markdown in (output_json, output_markdown, output_shell):
        raise RuntimeError('input and output paths must be distinct')
    reject_target_set((output_json, output_markdown, output_shell))
    doc = json.loads(read_generator_file(source_json, 'JSON metadata source').decode('utf-8'))
    raw_markdown = read_generator_file(source_markdown, 'Markdown migration source')
    source_shell = extract_fenced(raw_markdown, '## Canonical machine-readable ordered execution driver\n', '```bash\n', 'Markdown driver')
    doc = canonicalize_paths(doc, output_json, output_markdown)
    doc = expand_exact_git_references(doc)
    # The source Markdown still carries a legacy Authority row. Candidate 4 keeps
    # authority metadata only in JSON and rejects that row during parity checks.
    # The obsolete old-runbook path was never an execution input. Remove only the
    # nested authority field; keep the repository and no-mutation declarations.
    authority = doc.get('authority')
    if isinstance(authority, dict):
        authority.pop('old_runbook', None)
    execution = doc.setdefault('execution_driver', {})
    validation = doc.setdefault('validation_contract', {})
    execution['shell'] = patch_shell(source_shell.decode('utf-8'))
    execution['shell'] = execution['shell'].replace(str(JSON_PATH), str(output_json)).replace(str(MARKDOWN_PATH), str(output_markdown))
    execution.setdefault('markdown_fence_extraction', {
        'section_heading': '## Canonical machine-readable ordered execution driver\n',
        'opening_fence': '```bash\n',
        'closing_fence': '```',
        'body_rule': 'exact bytes strictly between the first exact opening and first exact closing delimiter',
        'expected_body_bytes': 0,
        'expected_body_lines': 0,
        'expected_terminal_byte_hex': '',
        'expected_body_sha256': '0' * 64,
    })
    contract={
     'raw_and_canonical_registry_occupancy':'Every raw registered worktree path and every canonicalizable target remain occupied for collision checks; locked, prunable, duplicate, and stale records are never modified.',
     'stale_record_policy':'A stale/noncanonical record is ignored only after its raw and canonicalizable forms prove no overlap with a candidate root; malformed records without exactly one worktree path fail closed as ambiguous.',
     'root_creation':'Open the canonical parent with O_RDONLY|O_DIRECTORY|O_NOFOLLOW, bind parent identity, mkdir each 0700 root and exact child through dir_fd, hold root/child descriptors through fstat/final-stat/fsync, and compare operation-adjacent registry snapshots.',
     'child_before_git':'Clean-primary repository and replay checkout children are descriptor-created and identity-bound before Git clone/init; parent, root, and child are asserted immediately before and after each Git CLI call.',
     'git_cli_residual_window':'Git clone/init require a pathname and cannot consume the held descriptor. The residual check-to-use window is bounded by the immediately adjacent parent/root/child identity assertions; any detected substitution fails closed before further writes.',
     'residual_toctou_limitations':'Two pathname windows remain intentionally unclaimed as atomic guarantees: descriptor-close to pathname Git CLI behavior, and check-to-pathname cleanup behavior. They are bounded by adjacent identity checks and fail closed when detected; neither is solved atomicity.',
     'registry_serialization':'The candidate4 rehearsal uses the pre-existing /private/tmp/task464-candidate4-rehearsal.lock regular file with an exclusive advisory flock held across stage, publish, validation, and rollback; noncooperating same-UID actors can ignore this lock.'
    }
    execution['root_creation_contract']=contract
    validation['root_creation_contract']=json.loads(json.dumps(contract))
    execution['worktree_separation_contract']=contract
    validation['worktree_separation_contract']=json.loads(json.dumps(contract))
    validation['invocation_argv']=list(execution['argv'])
    validation['strict_environment_allowlist']=list(execution['strict_git_environment']['allowlist'])
    validation['forbidden_inherited_environment_patterns'] = list(execution['strict_git_environment']['reject_inherited_patterns'])
    validation['clean_primary_whole_worktree_status'] = {
        'required_status': 'empty',
        'status_command': 'git status --porcelain=v1 --untracked-files=all --ignored=traditional --ignore-submodules=none',
        'ignored_descendant_command': 'git ls-files --others --ignored --exclude-standard -z',
        'unstaged_diff_command': 'git diff --no-ext-diff --quiet',
        'staged_diff_command': 'git diff --cached --no-ext-diff --quiet',
    }
    execution['clean_primary_whole_worktree_status'] = json.loads(json.dumps(validation['clean_primary_whole_worktree_status']))
    validation['source_identity_fields'] = [
        'canonical path', 'owner', 'mode', 'st_dev', 'st_ino',
        'Git common directory', 'object-store directory',
    ]
    validation['clean_primary_identity_fields'] = [
        'canonical path', 'owner', 'mode', 'st_dev', 'st_ino',
        'Git common directory', 'object-store directory',
        'no objects/info/alternates', 'object store distinct from SOURCE',
        'common directory distinct from SOURCE',
        'regular object/pack/index/info files st_nlink == 1',
        'no shared hardlinked copied object files',
    ]
    execution['source_identity_fields'] = list(validation['source_identity_fields'])
    execution['clean_primary_identity_fields'] = list(validation['clean_primary_identity_fields'])
    validation['source_identity_fields'] = list(validation['source_identity_fields'])
    storage_identity = {
        'required_st_nlink': 1,
        'no_objects_info_alternates': True,
        'distinct_from_source': True,
        'regular_storage_files': ['loose objects', 'pack files', 'index files', 'info files'],
        'hardlink_policy': 'every copied regular storage file has st_nlink == 1',
    }
    replay_root_identity = {
        'root_template': '/private/tmp/hermternal-task409-final-replay.$$ and /private/tmp/hermternal-task409-final-clean-primary.$$',
        'identity_fields': ['st_dev', 'st_ino', 'st_uid', 'mode', 'st_size', 'st_nlink', 'canonical path'],
        'root_mode': '0700',
        'child_mode': '0700',
        'fresh_root_policy': 'reject every pre-existing, symlinked, gitfile, external, or noncanonical root',
    }
    fresh_shell_requirement = {
        'required_before_execution': True,
        'source': 'fresh exact Markdown fenced shell extraction',
        'never_execute_standalone': True,
        'stale_driver': '/private/tmp/hermternal-task409-approved-driver.sh',
    }
    root_template = '/private/tmp/hermternal-task409-final-clean-primary.$$'
    repository_template = '/private/tmp/hermternal-task409-final-clean-primary.$$/repository'
    historical_mirrors, target_mirrors = collect_mirrors(doc)
    parity_appendix = {
        'section_heading': '## Machine-readable parity appendix\n',
        'opening_fence': '```json\n',
        'closing_fence': '```',
        'target_state_entry_count': len(target_mirrors),
        'target_state_path_count': sum(len(row['target_states']) for row in target_mirrors),
        'historical_changed_path_entry_count': len(historical_mirrors),
        'historical_changed_path_count': sum(len(row['changed_paths']) for row in historical_mirrors),
    }
    ordered_steps = parse_ordered_steps(raw_markdown)
    # Candidate 3 owns one immutable lane sequence. Validate both the source ledger
    # and generated metadata before emitting any artifact.
    actual_lane_ids = [row.get('id') for row in doc.get('ordered_lanes', [])]
    if actual_lane_ids != HARD_LANE_IDS:
        raise RuntimeError(f'ordered lane sequence mismatch: {actual_lane_ids!r}')
    for lane in doc['ordered_lanes']:
        if not isinstance(lane.get('id'), str) or not lane['id']:
            raise RuntimeError('lane id is missing or empty')
    # Raw SHA claims are intentionally restricted to the two predeclared mechanical
    # projection lanes; all other lanes must not imply raw SHA coverage.
    for lane in doc['ordered_lanes']:
        lane_id = lane['id']
        if lane_id not in RAW_SHA_PREDECLARED_LANES:
            for key in ('raw_sha256', 'expected_raw_sha256', 'raw_patch_sha256'):
                if key in lane:
                    raise RuntimeError(f'unapproved raw SHA metadata in {lane_id}: {key}')
    object_closure = {
        'commands': [
            'git fsck --full --strict --no-reflogs --no-progress',
            'git rev-list --objects --all --missing=error',
            'git rev-parse --show-object-format == sha1',
            'git cat-file --batch-check for every explicit object ID and expected type',
        ],
        'reject': ['promisor', 'missing object', 'replacement refs', 'shallow state', 'grafts', 'remote-helper access', 'alternates substitution'],
        'scope': 'SOURCE and CLEAN_PRIMARY before replay; REPLAY after bootstrap and before cleanup',
    }
    clean_primary_clone_transport = {
        'clone_command': 'git_hermetic -c protocol.file.allow=always clone --no-local --no-hardlinks --no-checkout --no-tags SOURCE CLEAN_PRIMARY',
        'source_constraint': 'absolute local SOURCE pathname only',
        'default_policy': 'protocol.allow=never',
        'exception_scope': 'protocol.file.allow=always is scoped to this one local clone invocation so --no-local can copy without network access',
        'network': 'forbidden',
        'remote_helpers': 'forbidden',
    }
    for target in (execution, validation):
        target['ordered_steps'] = json.loads(json.dumps(ordered_steps))
        target['matrix_identity'] = {
            'source_path': str(output_json),
            'algorithm': 'SHA-256 of exact JSON bytes after replacing the expected_normalized_sha256 token and shell_sha256, driver_shell_sha256, and expected_body_sha256 fields with zeroes; no whitespace normalization and no JSON reserialization for comparison.',
            'source_open_flags': ['O_RDONLY', 'O_NOFOLLOW'],
            'snapshot_open_flags': ['O_WRONLY', 'O_CREAT', 'O_EXCL', 'O_NOFOLLOW'],
            'snapshot_identity_fields': ['st_dev', 'st_ino', 'st_size', 'realpath'],
            'snapshot_mode': '0600',
            'snapshot_path_template': '$REPLAY_ROOT/matrix.snapshot.json',
            'boundary_rule': 'At every mutation boundary, compare O_NOFOLLOW descriptor and final-path device, inode, size, canonical path, and exact bytes before proceeding; bind normalized SHA-256 from raw JSON bytes.',
            'expected_normalized_sha256': validation.get('matrix_identity', {}).get('expected_normalized_sha256', '0' * 64),
        }
        target['clean_primary_storage_identity'] = json.loads(json.dumps(storage_identity))
        target['replay_root_identity'] = json.loads(json.dumps(replay_root_identity))
        target['fresh_shell_requirement'] = json.loads(json.dumps(fresh_shell_requirement))
        target['clean_primary_root_template'] = root_template
        target['clean_primary_root_template_normalized'] = root_template
        target['clean_primary_repository_template'] = repository_template
        target['markdown_parity_appendix'] = json.loads(json.dumps(parity_appendix))
        target['non_authoritative_standalone_scripts'] = [{
            'path': '/private/tmp/hermternal-task409-approved-driver.sh',
            'status': 'stale and non-authoritative; do not execute',
            'required_action': 'fresh extraction only',
        }]
        target['object_closure_contract'] = json.loads(json.dumps(object_closure))
        target['clean_primary_clone_transport'] = json.loads(json.dumps(clean_primary_clone_transport))
    validation['driver_ordered_steps'] = json.loads(json.dumps(ordered_steps))
    execution['argv'] = [
        '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'HOME=/dev/null', 'LANG=C', 'LC_ALL=C',
        'GIT_CONFIG_NOSYSTEM=1', 'GIT_CONFIG_GLOBAL=/dev/null', 'GIT_CONFIG_SYSTEM=/dev/null',
        'GIT_TERMINAL_PROMPT=0', 'GIT_OPTIONAL_LOCKS=0', 'GIT_NO_REPLACE_OBJECTS=1',
        '/bin/bash', '-euo', 'pipefail', '-s',
    ]
    validation['invocation_argv'] = list(execution['argv'])
    validation['strict_environment_allowlist'] = [
        'PATH', 'HOME', 'LANG', 'LC_ALL', 'GIT_CONFIG_NOSYSTEM', 'GIT_CONFIG_GLOBAL',
        'GIT_CONFIG_SYSTEM', 'GIT_TERMINAL_PROMPT', 'GIT_OPTIONAL_LOCKS', 'GIT_NO_REPLACE_OBJECTS',
        'PWD', 'GIT_NO_LAZY_FETCH', 'SHLVL', '_',
    ]
    execution['strict_git_environment']['set']['GIT_NO_LAZY_FETCH'] = '1'
    execution['strict_git_environment']['allowlist'] = list(validation['strict_environment_allowlist'])
    validation['forbidden_inherited_environment_patterns'] = [
        'GIT_CONFIG_PARAMETERS', 'GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_*', 'GIT_CONFIG_VALUE_*',
        'PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP', 'PYTHONUSERBASE', 'PYTHONINSPECT', 'PYTHONWARNINGS',
        'BASH_ENV', 'ENV', 'CDPATH', 'NODE_OPTIONS', 'RUBYOPT', 'PERL5OPT', 'DYLD_*', 'LD_*',
    ]
    execution['strict_git_environment']['reject_inherited_patterns'] = list(validation['forbidden_inherited_environment_patterns'])
    validation['matrix_identity']['source_path'] = str(output_json)
    execution['matrix_identity']['source_path'] = str(output_json)
    validation['clean_primary_whole_worktree_status']['status_command'] = 'git status --porcelain=v1 --untracked-files=all --ignored=traditional --ignore-submodules=none'
    candidate=validation['matrix_identity']['expected_normalized_sha256']
    for _ in range(80):
        execution['shell']=re.sub(r"(MATRIX_EXPECTED_BINDING_SHA256=')[0-9a-f]{64}(')",r'\g<1>'+candidate+r'\2',execution['shell'],count=1)
        b=execution['shell'].encode(); sha=hashlib.sha256(b).hexdigest()
        execution['shell_sha256']=sha; validation['driver_shell_sha256']=sha
        fence=execution['markdown_fence_extraction']; fence.update(expected_body_bytes=len(b),expected_body_lines=len(b.splitlines()),expected_terminal_byte_hex=b[-1:].hex(),expected_body_sha256=sha)
        execution['markdown_fence_extraction']=fence; validation['markdown_fence_extraction']=json.loads(json.dumps(fence))
        meta={'body_bytes':len(b),'body_lines':len(b.splitlines()),'terminal_byte_hex':b[-1:].hex()}
        execution['shell_size_metadata']=meta; validation['shell_size_metadata']=json.loads(json.dumps(meta))
        validation['driver_shell_body_bytes']=len(b); validation['driver_shell_body_lines']=len(b.splitlines())
        execution['matrix_identity']['expected_normalized_sha256']=candidate; validation['matrix_identity']['expected_normalized_sha256']=candidate
        validation['invocation_argv']=list(execution['argv']); validation['strict_environment_allowlist']=list(execution['strict_git_environment']['allowlist'])
        raw=(json.dumps(doc,indent=2,ensure_ascii=False)+'\n').encode(); nxt=normalized_sha(raw,candidate)
        if nxt==candidate: break
        candidate=nxt
    else: raise RuntimeError('fixed-point hash did not converge')
    json_bytes=(json.dumps(doc,indent=2,ensure_ascii=False)+'\n').encode()
    md=raw_markdown
    for old_path, new_path in (
        (str(JSON_PATH).encode(), str(output_json).encode()),
        (str(MARKDOWN_PATH).encode(), str(output_markdown).encode()),
        (b'/tmp/hermternal-task409-final-execution-matrix.json', str(output_json).encode()),
        (b'/tmp/hermternal-task409-final-execution-matrix.md', str(output_markdown).encode()),
    ):
        md=md.replace(old_path, new_path)
    # Candidate 3 removes only this obsolete Markdown authority row. The JSON
    # authority object is independently stripped above; no path rewriting is used.
    md=re.sub(rb'(?m)^\| Authority \| `[^`]*` \|\n', b'', md, count=1)
    if b'| Authority |' in md or b'old_runbook' in json_bytes:
        raise RuntimeError('obsolete Authority metadata remained before artifact write')
    heading=b'## Canonical machine-readable ordered execution driver\n'; opening=b'```bash\n'; closing=b'```'; sec=md.index(heading); bs=md.index(opening,sec+len(heading))+len(opening); be=md.index(closing,bs); md=md[:bs]+execution['shell'].encode()+md[be:]
    md=re.sub(rb'(Driver shell SHA-256: `)[0-9a-f]{64}(`)',rb'\g<1>'+execution['shell_sha256'].encode()+rb'\2',md,count=1)
    md=re.sub(rb'(Shell body bytes \| `)\d+(`)',rb'\g<1>'+str(len(execution['shell'].encode())).encode()+rb'\2',md,count=1)
    md=re.sub(rb'(Shell body lines \| `)\d+(`)',rb'\g<1>'+str(len(execution['shell'].splitlines())).encode()+rb'\2',md,count=1)
    md=re.sub(rb'(body and JSON shell are `)\d+(` bytes)',rb'\g<1>'+str(len(execution['shell'].encode())).encode()+rb'\2',md,count=1)
    md=re.sub(rb'(body and JSON shell are `)\d+(` LF lines)',rb'\g<1>'+str(len(execution['shell'].splitlines())).encode()+rb'\2',md,count=1)
    md=re.sub(rb'(Fresh extraction boundary:.*?shell SHA-256 `)[0-9a-f]{64}(`)',rb'\g<1>'+execution['shell_sha256'].encode()+rb'\2',md,count=1)
    md=re.sub(rb'(Fresh extraction boundary:.*?normalized JSON identity `)[0-9a-f]{64}(`)',rb'\g<1>'+candidate.encode()+rb'\2',md,count=1)
    md=re.sub(rb'(Byte-exact Markdown extraction:.*?body and JSON shell are `)\d+(` bytes, SHA-256 `)[0-9a-f]{64}(`, terminal)',lambda m:m.group(1)+str(len(execution['shell'].encode())).encode()+m.group(2)+execution['shell_sha256'].encode()+m.group(3),md,count=1)
    md=re.sub(rb'(Byte-exact Markdown extraction:.*?terminal byte `[^`]+`)',lambda m:m.group(0),md,count=1)
    md=re.sub(rb'(?m)^(\| Driver shell SHA-256 \| `)[0-9a-f]{64}(` \|)$',rb'\g<1>'+execution['shell_sha256'].encode()+rb'\2',md,count=1)
    md=re.sub(rb'(?m)^(\| Shell body bytes \| `)\d+(` \|)$',rb'\g<1>'+str(len(execution['shell'].encode())).encode()+rb'\2',md,count=1)
    md=re.sub(rb'(?m)^(\| Shell body lines \| `)\d+(` \|)$',rb'\g<1>'+str(len(execution['shell'].splitlines())).encode()+rb'\2',md,count=1)
    md=re.sub(rb'(?m)^- Invocation argv: `[^`]*`$',b'- Invocation argv: '+json.dumps(execution['argv'],separators=(',', ':')).encode(),md,count=1)
    md=re.sub(rb'(?m)^- Future-only invocation: `[^`]*`$',b'- Future-only invocation: '+b' '.join(item.encode() for item in execution['argv']),md,count=1)
    md=re.sub(rb'(?im)(normalized JSON identity|Matrix identity:.*?normalized SHA-256) `([0-9a-f]{64})`',lambda m:m.group(1)+b' `'+candidate.encode()+b'`',md)
    # Post-build assertions run before the one-time candidate-3 writes. They inspect
    # the executable shell body, not prose that names forbidden Bash constructs.
    json_shell=execution['shell'].encode('utf-8')
    if json_shell != execution['shell'].encode('utf-8') or not json_shell.endswith(b'\n'):
        raise RuntimeError('JSON shell body is not stable UTF-8 with terminal LF')
    for forbidden in (b'< <(', b'> <(', b'declare -A', b'mapfile', b'readarray', b'read -d \'\''):
        if forbidden in json_shell:
            raise RuntimeError(f'forbidden Bash construct remained: {forbidden!r}')
    if re.search(rb'\bdeclare\s+-n\b|\bnameref\b|\$\{![^}]*\}|\$\{[^}]*\^\^|\$\{[^}]*,,', json_shell):
        raise RuntimeError('forbidden Bash 4/nounset construct remained')
    if len(execution.get('ordered_steps', execution['ordered_steps'])) != 21:
        raise RuntimeError('execution metadata must contain exactly 21 ordered steps')
    if [row.get('order') for row in execution['ordered_steps']] != list(range(1,22)):
        raise RuntimeError('execution metadata step order mismatch')
    if [row.get('id') for row in doc['ordered_lanes']] != HARD_LANE_IDS:
        raise RuntimeError('final lane sequence mismatch')
    if b'| Authority |' in md or b'old_runbook' in json_bytes:
        raise RuntimeError('obsolete Authority metadata remained in final artifacts')
    sec=md.index(heading); fresh_start=md.index(opening,sec+len(heading))+len(opening); fresh_end=md.index(closing,fresh_start); fresh=md[fresh_start:fresh_end]
    if fresh != json_shell:
        raise RuntimeError('Markdown and JSON shell bodies differ before write')

    # All in-memory validations passed. Stage private same-directory files, then publish
    # each target exactly once. The shell remains mutable rehearsal output and is never
    # executed as a whole by this generator.
    json_shell = execution['shell'].encode('utf-8')
    if fresh != json_shell:
        raise RuntimeError('Markdown and JSON shell bodies differ before publish')
    if not (json_bytes.endswith(b'\n') and md.endswith(b'\n') and fresh.endswith(b'\n')):
        raise RuntimeError('all rehearsal artifacts must have terminal LF')
    # Comments are emitted into the shell so reviewers can see why guards and Python
    # escapes are present; these comments are part of the fixed-point bytes.
    if b'Bash 3.2 nounset' not in fresh or b'generated Python escape invariant' not in fresh:
        raise RuntimeError('required candidate4 generated-shell comments are missing')
    def read_published_exact(path, expected, label):
        # During final validation each public name still hard-links its private
        # stage leaf, so st_nlink is intentionally 2. Read through an O_NOFOLLOW
        # descriptor and bind exact bytes; stage cleanup reduces the final name
        # back to one link before the transaction returns.
        fd = os.open(os.fspath(path), os.O_RDONLY | os.O_NOFOLLOW)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink < 2:
                raise RuntimeError(f'{label} published inode is not stage-bound')
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            second = os.fstat(fd)
        finally:
            os.close(fd)
        raw = b''.join(chunks)
        if _file_identity(first) != _file_identity(second) or raw != expected:
            raise RuntimeError(f'{label} published bytes or identity changed')
        return raw

    def validate_published(paths, expected_payloads):
        final_json = read_published_exact(paths[0], expected_payloads[0], 'candidate4 JSON')
        final_md = read_published_exact(paths[1], expected_payloads[1], 'candidate4 Markdown')
        final_shell = read_published_exact(paths[2], expected_payloads[2], 'candidate4 shell')
        if (final_json, final_md, final_shell) != expected_payloads:
            raise RuntimeError('candidate4 outputs changed after atomic publish')
        final_doc = json.loads(final_json.decode('utf-8'))
        if final_doc['execution_driver']['shell'].encode('utf-8') != final_shell:
            raise RuntimeError('fresh candidate4 shell differs from JSON shell')
        extracted = extract_fenced(final_md, '## Canonical machine-readable ordered execution driver\n', '```bash\n', 'published Markdown driver')
        if extracted != final_shell:
            raise RuntimeError('published Markdown and shell parity failed')
        return final_json, final_md, final_shell

    final_json, final_md, final_shell = publish_once(
        (output_json, output_markdown, output_shell),
        (json_bytes, md, fresh),
        final_validate=validate_published,
    )
    print('normalized', candidate)
    print('shell', len(final_shell), len(final_shell.splitlines()), final_shell[-1:].hex(), hashlib.sha256(final_shell).hexdigest())
    print('json', len(final_json), len(final_json.splitlines()), final_json[-1:].hex(), hashlib.sha256(final_json).hexdigest())
    print('markdown', len(final_md), len(final_md.splitlines()), final_md[-1:].hex(), hashlib.sha256(final_md).hexdigest())
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
