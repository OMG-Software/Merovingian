// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/platform/hardening_self_check.hpp"

#include <utility>

namespace merovingian::platform
{
namespace
{

[[nodiscard]] auto compile_time_stack_protector_status() noexcept -> HardeningStatus
{
#if defined(__SSP__) || defined(__SSP_STRONG__) || defined(__SSP_ALL__)
    return HardeningStatus::enabled;
#else
    return HardeningStatus::unknown;
#endif
}

[[nodiscard]] auto compile_time_fortify_status() noexcept -> HardeningStatus
{
#if defined(_FORTIFY_SOURCE) && _FORTIFY_SOURCE > 0
    return HardeningStatus::enabled;
#else
    return HardeningStatus::unknown;
#endif
}

[[nodiscard]] auto compile_time_pie_status() noexcept -> HardeningStatus
{
#if defined(__PIE__) || defined(__pie__)
    return HardeningStatus::enabled;
#else
    return HardeningStatus::unknown;
#endif
}

} // namespace

HardeningSelfCheck::HardeningSelfCheck(std::vector<HardeningCheck> checks)
    : m_checks{std::move(checks)}
{
}

auto HardeningSelfCheck::checks() const noexcept -> std::vector<HardeningCheck> const&
{
    return m_checks;
}

auto HardeningSelfCheck::count() const noexcept -> std::size_t
{
    return m_checks.size();
}

auto run_startup_hardening_self_check() -> HardeningSelfCheck
{
    auto checks = std::vector<HardeningCheck>{};
    checks.reserve(13U);
    checks.push_back({"compiler hardening", HardeningStatus::unknown});
    checks.push_back({"linker hardening", HardeningStatus::unknown});
    checks.push_back({"PIE", compile_time_pie_status()});
    checks.push_back({"RELRO", HardeningStatus::unknown});
    checks.push_back({"stack protector", compile_time_stack_protector_status()});
    checks.push_back({"FORTIFY_SOURCE", compile_time_fortify_status()});
    checks.push_back({"seccomp", HardeningStatus::unknown});
    checks.push_back({"pledge/unveil", HardeningStatus::unknown});
    checks.push_back({"capsicum", HardeningStatus::unknown});
    checks.push_back({"privilege drop", HardeningStatus::unknown});
    checks.push_back({"filesystem restrictions", HardeningStatus::unknown});
    checks.push_back({"core dump policy", HardeningStatus::unknown});
    checks.push_back({"secret redaction policy", HardeningStatus::enabled});

    return HardeningSelfCheck{std::move(checks)};
}

auto hardening_status_name(HardeningStatus status) noexcept -> char const*
{
    switch (status)
    {
    case HardeningStatus::enabled:
        return "enabled";
    case HardeningStatus::disabled:
        return "disabled";
    case HardeningStatus::unknown:
        return "unknown";
    }

    return "unknown";
}

} // namespace merovingian::platform
