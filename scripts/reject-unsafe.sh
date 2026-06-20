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
# std::shared_ptr is allowed only with an explicit per-line annotation.
# Add "// SHARED_PTR: reviewed — <reason>" on the same line to exempt.
SHARED_PTR_HITS=$(grep -Rn --perl-regexp "${CPP_INCLUDES[@]}" 'std::shared_ptr' "${ROOTS[@]}" \
  | grep -v 'SHARED_PTR: reviewed' || true)
if [ -n "$SHARED_PTR_HITS" ]; then
  printf '%s\n' "$SHARED_PTR_HITS"
  echo "Rejected pattern detected: shared_ptr requires explicit review (add '// SHARED_PTR: reviewed — <reason>')"
  exit 1
fi
