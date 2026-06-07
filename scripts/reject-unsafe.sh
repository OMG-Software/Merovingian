#!/usr/bin/env bash
set -euo pipefail

ROOTS=(include src tests)

# Only scan C and C++ source files. Other files in the tree (Python test
# scripts, embedded JavaScript, SQL migrations, shell scripts) legitimately
# use keywords like "new", "delete", "free", and "malloc" in non-C++ contexts
# and must not be flagged by this gate.
CPP_INCLUDES=(
  --include='*.cpp'
  --include='*.hpp'
  --include='*.h'
  --include='*.cc'
  --include='*.c'
)

reject_pattern() {
  local pattern="$1"
  local description="$2"

  if grep -R --line-number --perl-regexp "${CPP_INCLUDES[@]}" "$pattern" "${ROOTS[@]}"; then
    echo "Rejected pattern detected: ${description}"
    exit 1
  fi
}

reject_pattern '(^|[=(:,{]\s*|return\s+)new\s+[A-Za-z_:]' 'naked new'
reject_pattern '(^|[;{]\s*)delete\s+[A-Za-z_]' 'naked delete'
reject_pattern '\bmalloc\s*\(' 'malloc'
reject_pattern '\bcalloc\s*\(' 'calloc'
reject_pattern '\brealloc\s*\(' 'realloc'
reject_pattern '\bfree\s*\(' 'free'
reject_pattern 'std::shared_ptr' 'shared_ptr requires explicit review'
