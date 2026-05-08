#!/usr/bin/env bash
set -euo pipefail

ROOTS=(include src tests)

reject_pattern() {
  local pattern="$1"
  local description="$2"

  if grep -R --line-number --perl-regexp "$pattern" "${ROOTS[@]}"; then
    echo "Rejected pattern detected: ${description}"
    exit 1
  fi
}

reject_pattern '\\bnew\\s+' 'naked new'
reject_pattern '\\bdelete\\s+' 'naked delete'
reject_pattern '\\bmalloc\\s*\\(' 'malloc'
reject_pattern '\\bcalloc\\s*\\(' 'calloc'
reject_pattern '\\brealloc\\s*\\(' 'realloc'
reject_pattern '\\bfree\\s*\\(' 'free'
reject_pattern 'std::shared_ptr' 'shared_ptr requires explicit review'
