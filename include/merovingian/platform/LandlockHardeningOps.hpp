// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/platform/LandlockAddRuleOutcome.hpp"

#include <cstdint>
#include <functional>
#include <string>

namespace merovingian::platform
{

// The three Landlock syscalls, plus the ABI-version probe, as an injectable
// function table — mirrors media::DecoderHardeningOps. Default-constructs to
// the real syscalls, issued via a raw ::syscall() rather than a libc wrapper
// (glibc did not gain landlock_create_ruleset()/landlock_add_rule()/
// landlock_restrict_self() wrappers until 2.38; the kernel/glibc pair this
// project builds and ships against must not be assumed to have them). Tests
// substitute individual members to exercise each fail-closed path without
// actually restricting the test process.
struct LandlockHardeningOps final
{
    // landlock_create_ruleset(nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION).
    // Returns the ABI version (>= 1) when Landlock is available, or a value
    // < 1 when it is not (ENOSYS on kernels < 5.13, EOPNOTSUPP when Landlock
    // is disabled at boot, e.g. via the lsm= boot parameter).
    std::function<int()> query_abi_version;

    // landlock_create_ruleset(&attr, sizeof(attr), 0) with
    // attr.handled_access_fs = handled_access_fs. Returns the ruleset fd, or
    // a negative value on failure. Only called after query_abi_version() has
    // returned >= 1, so a negative return here is always a genuine error,
    // never "Landlock is unavailable".
    std::function<int(std::uint64_t handled_access_fs, int abi)> create_ruleset;

    // Opens `path` (O_PATH | O_CLOEXEC) and, on success, calls
    // landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
    // &{allowed_access, parent_fd}, 0), closing the opened path fd
    // afterwards regardless of outcome.
    std::function<LandlockAddRuleOutcome(int ruleset_fd, std::string const& path, std::uint64_t allowed_access)>
        add_rule;

    // prctl(PR_SET_NO_NEW_PRIVS, 1). landlock_restrict_self() fails with
    // EPERM unless no_new_privs is set (or the caller has CAP_SYS_ADMIN), so
    // this runs immediately before restrict_self; a failure is fatal.
    std::function<bool()> set_no_new_privs;

    // landlock_restrict_self(ruleset_fd, 0).
    std::function<bool(int ruleset_fd)> restrict_self;

    LandlockHardeningOps();
};

} // namespace merovingian::platform
