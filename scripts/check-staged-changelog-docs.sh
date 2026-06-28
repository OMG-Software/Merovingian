#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

repo_root=${1:-.}
cd "$repo_root"

if [ "${MEROVINGIAN_SKIP_CHANGE_DOC_CHECK:-}" = "1" ]; then
    exit 0
fi

if [ -n "${GIT_STAGED_FILES:-}" ]; then
    staged_files=$GIT_STAGED_FILES
else
    staged_files=$(git diff --cached --name-only --diff-filter=ACMR)
fi

if [ -z "$staged_files" ]; then
    exit 0
fi

requires_change_record=0
has_changelog=0
has_docs=0

while IFS= read -r file; do
    [ -n "$file" ] || continue

    case "$file" in
        CHANGELOG.md)
            has_changelog=1
            ;;
        docs/*.md|docs/todos/*.md|docs/dependencies/*.md)
            has_docs=1
            ;;
    esac

    case "$file" in
        src/*|include/merovingian/*|tests/*|migrations/*|config/*|packaging/*|security/*|scripts/*|meson.build|meson.options|build.py|Dockerfile|README.md)
            requires_change_record=1
            ;;
    esac
done <<EOF
$staged_files
EOF

if [ "$requires_change_record" -eq 0 ]; then
    exit 0
fi

status=0

if [ "$has_changelog" -eq 0 ]; then
    printf '%s\n' 'staged project changes require a CHANGELOG.md update' >&2
    status=1
fi

if [ "$has_docs" -eq 0 ]; then
    printf '%s\n' 'staged project changes require a relevant docs/*.md update' >&2
    status=1
fi

if [ "$status" -ne 0 ]; then
    printf '%s\n' 'Set MEROVINGIAN_SKIP_CHANGE_DOC_CHECK=1 only for reviewed non-behavioural maintenance commits.' >&2
fi

exit "$status"
