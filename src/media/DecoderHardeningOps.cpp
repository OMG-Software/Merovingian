// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/media/DecoderHardeningOps.hpp"

#include "merovingian/media/decoder_hardening.hpp"
#include "merovingian/platform/seccomp_hardening.hpp"

#include <sys/resource.h>

#if defined(__linux__)
#include <sys/prctl.h>
#elif defined(__OpenBSD__)
#include <unistd.h>
#elif defined(__FreeBSD__)
#include <sys/capsicum.h>
#endif

#include <cstdint>

namespace merovingian::media
{
namespace
{

    [[nodiscard]] auto real_set_resource_limit(int resource, std::uint64_t value) noexcept -> bool
    {
        auto limit = rlimit{static_cast<rlim_t>(value), static_cast<rlim_t>(value)};
        return ::setrlimit(resource, &limit) == 0;
    }

#if defined(__linux__)
    [[nodiscard]] auto real_disable_core_dumps() noexcept -> bool
    {
        return ::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0;
    }

    [[nodiscard]] auto real_set_no_new_privs() noexcept -> bool
    {
        return ::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0;
    }

    [[nodiscard]] auto real_apply_seccomp_filter() noexcept -> bool
    {
        return merovingian::platform::apply_decoder_seccomp_filter();
    }
#elif defined(__OpenBSD__)
    [[nodiscard]] auto real_apply_pledge() noexcept -> bool
    {
        return ::pledge("stdio", nullptr) == 0;
    }
#elif defined(__FreeBSD__)
    [[nodiscard]] auto real_apply_capsicum() noexcept -> bool
    {
        return ::cap_enter() == 0;
    }
#endif

} // namespace

DecoderHardeningOps::DecoderHardeningOps()
    : set_resource_limit(real_set_resource_limit)
#if defined(__linux__)
    , disable_core_dumps(real_disable_core_dumps)
    , set_no_new_privs(real_set_no_new_privs)
    , apply_seccomp_filter(real_apply_seccomp_filter)
#elif defined(__OpenBSD__)
    , apply_pledge(real_apply_pledge)
#elif defined(__FreeBSD__)
    , apply_capsicum(real_apply_capsicum)
#endif
    , platform_sandbox_available(decoder_platform_sandbox_available())
{
}

} // namespace merovingian::media
