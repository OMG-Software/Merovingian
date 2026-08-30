#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build-time hardening gate: statically inspect an ELF binary's headers and
# fail closed if any of the link-time hardening defences documented in
# docs/hardening.md ("Build-time toolchain hardening") are missing.
#
# This is the CI-time counterpart to the runtime probe in
# src/platform/elf_probe.cpp / hardening_self_check.cpp. The runtime
# self-check can only run *inside a live merovingian-server process*, which
# in CI is gated behind conditions that are frequently unmet (root
# containers can never satisfy the privilege-drop check; non-root runners
# without CAP_SETPCAP can never satisfy the capability-bounding check — see
# docs/hardening.md and tests/integration/test_server_startup_hardening_flow.cpp).
# That leaves the *build* itself unverified in most CI jobs today. This
# script closes that gap: it needs only `readelf` against the built binary,
# so it runs identically whether the CI job is root, non-root, or containerized.
#
# Checks (all required, matching meson.build's hardening_compile_flags /
# hardening_link_flags when -Dhardening=true):
#   - ET_DYN (PIE)
#   - PT_GNU_RELRO program header present
#   - DT_BIND_NOW (or DF_BIND_NOW in DT_FLAGS_1) in the dynamic section
#   - PT_GNU_STACK present without the executable flag (non-exec stack)
#
# A fully static binary (scripts/build-static-linux.sh's -static-pie output)
# has no PT_DYNAMIC section, so BIND_NOW cannot apply; pass --static to skip
# that one check while still requiring PIE, RELRO, and the non-exec stack.

set -eu

static_binary=0

usage() {
    cat <<'EOF'
Usage:
  sh scripts/check-elf-hardening.sh [--static] <binary>

Options:
  --static   Skip the BIND_NOW check (statically linked binaries have no
             PT_DYNAMIC section for it to apply to).
  --help     Show this help text.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --static)
            static_binary=1
            ;;
        --help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        -*)
            printf 'check-elf-hardening: unknown option: %s\n' "$1" >&2
            exit 2
            ;;
        *)
            break
            ;;
    esac
    shift
done

if [ "$#" -ne 1 ]; then
    usage >&2
    exit 2
fi

binary=$1

command -v readelf >/dev/null 2>&1 || {
    printf 'check-elf-hardening: readelf not found (install binutils)\n' >&2
    exit 2
}

if [ ! -f "$binary" ]; then
    printf 'check-elf-hardening: binary not found: %s\n' "$binary" >&2
    exit 1
fi

fail_count=0

fail() {
    printf 'check-elf-hardening: FAIL: %s\n' "$1" >&2
    fail_count=$((fail_count + 1))
}

pass() {
    printf 'check-elf-hardening: OK: %s\n' "$1"
}

# --- PIE (ET_DYN) -----------------------------------------------------------
elf_type=$(readelf -h "$binary" 2>/dev/null | awk -F': *' '/^ *Type:/ {print $2}')
case "$elf_type" in
    DYN*)
        pass "PIE: ELF type is ET_DYN ($elf_type)"
        ;;
    *)
        fail "PIE: ELF type is not ET_DYN (got: ${elf_type:-unreadable}); rebuild with -fPIE -pie"
        ;;
esac

# --- RELRO (PT_GNU_RELRO) ---------------------------------------------------
if readelf -lW "$binary" 2>/dev/null | grep -q 'GNU_RELRO'; then
    pass "RELRO: PT_GNU_RELRO segment present"
else
    fail "RELRO: no PT_GNU_RELRO segment; rebuild with -Wl,-z,relro"
fi

# --- BIND_NOW (DT_BIND_NOW / DF_BIND_NOW in DT_FLAGS_1) ---------------------
if [ "$static_binary" -eq 1 ]; then
    pass "BIND_NOW: skipped (--static binary has no PT_DYNAMIC section)"
else
    dynamic_flags=$(readelf -d "$binary" 2>/dev/null || true)
    if printf '%s\n' "$dynamic_flags" | grep -qE '\(BIND_NOW\)|Flags:.*\bNOW\b'; then
        pass "BIND_NOW: dynamic section advertises immediate binding"
    else
        fail "BIND_NOW: no BIND_NOW flag in the dynamic section; rebuild with -Wl,-z,now"
    fi
fi

# --- Non-executable stack (PT_GNU_STACK without the E flag) ----------------
stack_line=$(readelf -lW "$binary" 2>/dev/null | grep 'GNU_STACK' || true)
if [ -z "$stack_line" ]; then
    fail "NX stack: no PT_GNU_STACK segment; rebuild with a linker that emits GNU_STACK"
else
    # The Flg column is R, RW, or RWE — reject only if E (executable) is set.
    flags=$(printf '%s\n' "$stack_line" | awk '{for (i=1;i<=NF;i++) if ($i ~ /^R?W?E?$/ && $i != "") last=$i} END {print last}')
    case "$flags" in
        *E*)
            fail "NX stack: PT_GNU_STACK is executable (flags=$flags); rebuild with -Wl,-z,noexecstack"
            ;;
        *)
            pass "NX stack: PT_GNU_STACK is non-executable (flags=$flags)"
            ;;
    esac
fi

if [ "$fail_count" -gt 0 ]; then
    printf 'check-elf-hardening: %s check(s) failed for %s\n' "$fail_count" "$binary" >&2
    exit 1
fi

printf 'check-elf-hardening: all link-time hardening checks passed for %s\n' "$binary"
