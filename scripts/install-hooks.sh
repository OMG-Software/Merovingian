#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

repo_root=$(git rev-parse --show-toplevel)
hooks_dir="$repo_root/.git/hooks"

install -m 0755 "$repo_root/scripts/hooks/pre-commit" "$hooks_dir/pre-commit"

printf '%s\n' 'Installed Merovingian pre-commit hook.'
