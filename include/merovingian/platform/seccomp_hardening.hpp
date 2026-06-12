// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::platform
{

struct SeccompProbeResult final
{
    bool probed{false};         // true when /proc/self/status was read successfully
    bool seccomp_active{false}; // true when Seccomp: 2 (SECCOMP_MODE_FILTER)
};

// Applies a seccomp-bpf syscall allowlist to the calling process via
// prctl(PR_SET_NO_NEW_PRIVS) + seccomp(SECCOMP_SET_MODE_FILTER).
// Must be called before listeners bind and before run_startup_hardening_self_check().
// The default action is SECCOMP_RET_LOG: unrecognised syscalls are written to the
// kernel audit log but allowed — safe for beta until the allowlist is validated.
// On non-Linux or kernels without CONFIG_SECCOMP_FILTER, returns false;
// the hardening self-check probe then reports `unknown`.
[[nodiscard]] auto apply_seccomp_filter() noexcept -> bool;

// Reads /proc/self/status to detect whether a seccomp-bpf filter is active.
// Returns probed=true and seccomp_active=true when "Seccomp: 2" is found
// (SECCOMP_MODE_FILTER). On non-Linux, returns probed=false.
[[nodiscard]] auto probe_seccomp_status() -> SeccompProbeResult;

} // namespace merovingian::platform
