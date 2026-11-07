// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <functional>

namespace merovingian::media
{

// The syscalls apply_decoder_hardening() drives, exposed as an injectable
// function table so its fail-closed sequencing is unit-testable without
// actually installing (or failing to install) a real seccomp filter, pledge
// promise set, or Capsicum capability mode in the calling process — doing
// that for real inside the unit-test binary would sandbox the test process
// itself. Default-constructs to the real platform calls (only the members
// applicable on the current platform are wired; the rest are left empty and
// are never invoked). Tests substitute individual members with safe stand-ins
// to simulate one control failing while the rest succeed.
struct DecoderHardeningOps final
{
    // setrlimit(resource, {value, value}); used for RLIMIT_AS, RLIMIT_CPU,
    // RLIMIT_FSIZE, RLIMIT_CORE, RLIMIT_NOFILE. Present on every platform.
    std::function<bool(int resource, std::uint64_t value)> set_resource_limit;
    // Linux only: prctl(PR_SET_DUMPABLE, 0, 0, 0, 0).
    std::function<bool()> disable_core_dumps;
    // Linux only: prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0).
    std::function<bool()> set_no_new_privs;
    // Linux only: merovingian::platform::apply_decoder_seccomp_filter().
    std::function<bool()> apply_seccomp_filter;
    // OpenBSD only: pledge("stdio", nullptr).
    std::function<bool()> apply_pledge;
    // FreeBSD only: cap_enter().
    std::function<bool()> apply_capsicum;
    // Whether this platform has an in-process decoder sandbox at all: true on
    // Linux, OpenBSD and FreeBSD, false everywhere else (NetBSD). Defaults to
    // decoder_platform_sandbox_available(); tests clear it to exercise the
    // refusal on a platform that does have a sandbox.
    bool platform_sandbox_available{false};

    DecoderHardeningOps();
};

} // namespace merovingian::media
