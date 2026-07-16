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

# Crypto-boundary rule (src/crypto/AGENTS.md): only src/crypto/, src/events/,
# src/auth/, and src/core/secret_buffer.cpp (memory locking/zeroing) may call
# libsodium functions directly.  Anything else must route through crypto/ or
# auth/ wrappers.
SODIUM_HITS=$(grep -R --line-number --extended-regexp \
  --include='*.cpp' --include='*.hpp' --include='*.h' --include='*.cc' --include='*.c' \
  '\b(sodium_|randombytes_|crypto_(generichash|pwhash|sign|secretbox|aead|kx|scalarmult|box|hash|core|verify|onetimeauth|shorthash|auth|kdf|secretstream|stream))([A-Za-z0-9_]*)[[:space:]]*\(' \
  include src \
  | grep -vE '^(src/crypto/|src/events/|src/auth/|src/core/secret_buffer\.cpp|include/merovingian/crypto/|include/merovingian/events/|include/merovingian/auth/)' \
  | grep -vE '^[[:space:]]*//' \
  || true)
if [ -n "$SODIUM_HITS" ]; then
  printf '%s\n' "$SODIUM_HITS"
  echo "Rejected pattern detected: direct libsodium call outside src/crypto/, src/events/, src/auth/, or src/core/secret_buffer.cpp"
  exit 1
fi

SODIUM_INCLUDES=$(grep -R --line-number --extended-regexp \
  --include='*.cpp' --include='*.hpp' --include='*.h' --include='*.cc' --include='*.c' \
  '#include[[:space:]]+(<sodium\.h>|"sodium\.h")' \
  include src \
  | grep -vE '^(src/crypto/|src/events/|src/auth/|src/core/secret_buffer\.cpp|include/merovingian/crypto/|include/merovingian/events/|include/merovingian/auth/)' \
  || true)
if [ -n "$SODIUM_INCLUDES" ]; then
  printf '%s\n' "$SODIUM_INCLUDES"
  echo "Rejected pattern detected: <sodium.h> included outside src/crypto/, src/events/, src/auth/, or src/core/secret_buffer.cpp"
  exit 1
fi
