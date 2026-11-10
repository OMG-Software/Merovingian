#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Fails when a unit test file names a function that builds a homeserver runtime
# or drives the client-server stack. Those scenarios belong in tests/integration/
# (tests/unit/AGENTS.md, ADR-0593). One grep over every file: the gate runs in
# every platform's suite, including the slow BSD VMs.

set -eu

repo_root=${1:-.}
cd "$repo_root"

forbidden='start_runtime|start_client_server|wire_federation_callbacks|handle_client_server_request|handle_client_server_http_request|run_client_server_flow'

files=$(find tests/unit -type f \( -name '*.cpp' -o -name '*.hpp' \) | sort)
if [ -z "$files" ]; then
    printf '%s\n' 'No unit test sources found under tests/unit; refusing to pass an empty check.' >&2
    exit 2
fi

# -w matches whole identifiers only, so start_runtime_options does not match.
# Mentions in comments count too: the rule is about what a unit file may name.
# grep exits 0 on a match, 1 on none and 2 on an error; only 1 passes.
status=0
# shellcheck disable=SC2086 # the file list is split on whitespace on purpose; test file names hold none
found=$(grep -HnwE "$forbidden" $files) || status=$?
case "$status" in
    0)
        printf '%s\n' 'Unit tests must not build a runtime or drive the client-server stack; move these scenarios to tests/integration/ (ADR-0593):' >&2
        printf '%s\n' "$found" >&2
        exit 1
        ;;
    1) ;;
    *)
        printf '%s\n' "grep failed with status $status; the unit test isolation check did not run." >&2
        exit 2
        ;;
esac
