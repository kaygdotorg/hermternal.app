#!/bin/bash
# Bash 3.2-compatible Phase A wrapper.
#
# This wrapper only parses raw argv and forwards immutable artifact facts. It
# never creates a manifest, parent directory, owner marker, or run root. The
# Python gate validates the complete closed manifest in memory first, then
# allocates exactly one validated private preflight root and writes the
# validated manifest there (or to --manifest after that allocation).
set -eu
set -o pipefail
umask 077

PREFLIGHT_PY=/private/tmp/task409-execution-preflight/task409_execution_preflight_v3.py

usage() {
    printf '%s\n' \
        'Usage: run_task409_execution_preflight_v3.sh --markdown PATH --json PATH --shell PATH \' \
        '  --markdown-sha256 SHA --json-sha256 SHA --shell-sha256 SHA \' \
        '  --normalized-json-sha256 SHA --markdown-identity ID --json-identity ID --shell-identity ID \' \
        '  --shell-body-bytes N --shell-body-lines N --shell-terminal-byte-hex HEX \' \
        '  --lane candidate-4 --object-format sha1 --base-ref REF --base-commit OID --base-tree OID \' \
        '  --main-ref REF --main-commit OID [--manifest NEW_FILE] [--preflight-root NEW_LEAF] [--dry-run]' \
        '' \
        'The wrapper rejects --execute and --ref before any allocation.' >&2
}

fail() {
    printf '%s\n' "REJECT: $1" >&2
    exit 2
}

block_execute() {
    printf '%s\n' 'BLOCKER: Phase A --execute is forbidden before allocation' >&2
    exit 3
}

# Scan raw argv before consuming values. A forbidden token cannot hide as an
# option value, and --ref= is rejected even though argparse would not use it.
for raw in "$@"; do
    case "$raw" in
        --execute) block_execute ;;
        --ref|--ref=*) fail 'Phase A does not support --ref' ;;
    esac
done

markdown=''
json_path=''
shell_path=''
markdown_sha256=''
json_sha256=''
shell_sha256=''
normalized_json_sha256=''
markdown_identity=''
json_identity=''
shell_identity=''
shell_body_bytes=''
shell_body_lines=''
shell_terminal_byte_hex=''
lane=''
object_format=''
base_ref=''
base_commit=''
base_tree=''
main_ref=''
main_commit=''
manifest_path=''
preflight_root=''
dry_run=0
seen=' '

mark_seen() {
    case "$seen" in
        *" $1 "*) fail "duplicate option: $1" ;;
    esac
    seen="$seen$1 "
}

need_value() {
    [ "$#" -ge 2 ] || fail "missing value for $1"
    [ -n "$2" ] || fail "missing value for $1"
    case "$2" in
        --*) fail "option-looking value for $1" ;;
    esac
}

while [ "$#" -gt 0 ]; do
    option=$1
    case "$option" in
        --execute) block_execute ;;
        --ref|--ref=*) fail 'Phase A does not support --ref' ;;
        --markdown|--json|--shell|--markdown-sha256|--json-sha256|--shell-sha256|--normalized-json-sha256|--markdown-identity|--json-identity|--shell-identity|--shell-body-bytes|--shell-body-lines|--shell-terminal-byte-hex|--lane|--object-format|--base-ref|--base-commit|--base-tree|--main-ref|--main-commit|--manifest|--preflight-root)
            mark_seen "$option"
            need_value "$@"
            value=$2
            case "$option" in
                --markdown) markdown=$value ;;
                --json) json_path=$value ;;
                --shell) shell_path=$value ;;
                --markdown-sha256) markdown_sha256=$value ;;
                --json-sha256) json_sha256=$value ;;
                --shell-sha256) shell_sha256=$value ;;
                --normalized-json-sha256) normalized_json_sha256=$value ;;
                --markdown-identity) markdown_identity=$value ;;
                --json-identity) json_identity=$value ;;
                --shell-identity) shell_identity=$value ;;
                --shell-body-bytes) shell_body_bytes=$value ;;
                --shell-body-lines) shell_body_lines=$value ;;
                --shell-terminal-byte-hex) shell_terminal_byte_hex=$value ;;
                --lane) lane=$value ;;
                --object-format) object_format=$value ;;
                --base-ref) base_ref=$value ;;
                --base-commit) base_commit=$value ;;
                --base-tree) base_tree=$value ;;
                --main-ref) main_ref=$value ;;
                --main-commit) main_commit=$value ;;
                --manifest) manifest_path=$value ;;
                --preflight-root) preflight_root=$value ;;
            esac
            shift 2
            ;;
        --dry-run)
            mark_seen "$option"
            dry_run=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage
            fail "unknown option: $option"
            ;;
    esac
done

require_value() {
    [ -n "$2" ] || fail "missing required option: $1"
}

require_value markdown "$markdown"
require_value json "$json_path"
require_value shell "$shell_path"
require_value markdown_sha256 "$markdown_sha256"
require_value json_sha256 "$json_sha256"
require_value shell_sha256 "$shell_sha256"
require_value normalized_json_sha256 "$normalized_json_sha256"
require_value markdown_identity "$markdown_identity"
require_value json_identity "$json_identity"
require_value shell_identity "$shell_identity"
require_value shell_body_bytes "$shell_body_bytes"
require_value shell_body_lines "$shell_body_lines"
require_value shell_terminal_byte_hex "$shell_terminal_byte_hex"
require_value lane "$lane"
require_value object_format "$object_format"
require_value base_ref "$base_ref"
require_value base_commit "$base_commit"
require_value base_tree "$base_tree"
require_value main_ref "$main_ref"
require_value main_commit "$main_commit"
unset -f require_value

case "$markdown" in /*) ;; *) fail '--markdown must be absolute' ;; esac
case "$json_path" in /*) ;; *) fail '--json must be absolute' ;; esac
case "$shell_path" in /*) ;; *) fail '--shell must be absolute' ;; esac
if [ -n "$manifest_path" ]; then
    case "$manifest_path" in /*) ;; *) fail '--manifest must be absolute' ;; esac
fi
if [ -n "$preflight_root" ]; then
    case "$preflight_root" in /*) ;; *) fail '--preflight-root must be absolute' ;; esac
fi

invoke_phase_a() {
    set -- "$PREFLIGHT_PY" \
        --wrapper-facts "$markdown" "$json_path" "$shell_path" \
        "$markdown_sha256" "$json_sha256" "$shell_sha256" "$normalized_json_sha256" \
        "$markdown_identity" "$json_identity" "$shell_identity" \
        "$shell_body_bytes" "$shell_body_lines" "$shell_terminal_byte_hex" \
        "$lane" "$object_format" "$base_ref" "$base_commit" "$base_tree" "$main_ref" "$main_commit"
    if [ -n "$manifest_path" ]; then
        set -- "$@" --manifest-output "$manifest_path"
    fi
    if [ -n "$preflight_root" ]; then
        set -- "$@" --preflight-root "$preflight_root"
    fi
    if [ "$dry_run" -eq 1 ]; then
        set -- "$@" --dry-run
    fi
    /usr/bin/python3 "$@"
}

# No filesystem mutation occurs in this shell process. Python performs the
# semantic validation before its one and only root allocation.
invoke_phase_a
