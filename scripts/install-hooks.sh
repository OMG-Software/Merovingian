#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

repo_root=$(git rev-parse --show-toplevel)
hooks_dir=$(git rev-parse --git-path hooks)
mkdir -p "$hooks_dir"

install -m 0755 "$repo_root/scripts/hooks/pre-commit" "$hooks_dir/pre-commit"

printf '%s\n' 'Installed Merovingian pre-commit hook.'
