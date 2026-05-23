// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/platform/hardening_self_check.hpp"

#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <string>
#include <utility>
#include <vector>

namespace merovingian::platform
{
namespace
{

    [[nodiscard]] auto compile_time_stack_protector_enabled() noexcept -> bool
    {
#if defined(__SSP__) || defined(__SSP_STRONG__) || defined(__SSP_ALL__)
        return true;
#else
        return false;
#endif
    }

    [[nodiscard]] auto compile_time_fortify_enabled() noexcept -> bool
    {
#if defined(_FORTIFY_SOURCE) && _FORTIFY_SOURCE > 0
        return true;
#else
        return false;
#endif
    }

    [[nodiscard]] auto compile_time_pie_enabled() noexcept -> bool
    {
#if defined(__PIE__) || defined(__pie__)
        return true;
#else
        return false;
#endif
    }

    // Compiler hardening rolls up the toolchain-driven defences that the build
    // system enforces (stack protector, FORTIFY_SOURCE, PIE). When the
    // compiler emits all three, the binary inherits the project's hardening
    // contract regardless of which translation unit asks.
    [[nodiscard]] auto compile_time_compiler_hardening_enabled() noexcept -> bool
    {
        return compile_time_stack_protector_enabled() && compile_time_fortify_enabled() && compile_time_pie_enabled();
    }

    constexpr auto alpha_exception_doc_reference =
        "Documented alpha-only exception; see docs/hardening-alpha-exceptions.md.";

    [[nodiscard]] auto enabled_or_alpha_exception(bool enabled, std::string reason) -> HardeningCheck
    {
        if (enabled)
        {
            return HardeningCheck{{}, HardeningStatus::enabled, {}};
        }
        return HardeningCheck{
            {}, HardeningStatus::alpha_exception, std::move(reason) + " " + alpha_exception_doc_reference};
    }

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("hardening_self_check", event, std::move(fields)));
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

auto HardeningSelfCheck::production_blockers() const -> std::vector<HardeningCheck>
{
    auto blockers = std::vector<HardeningCheck>{};
    for (auto const& check : m_checks)
    {
        if (check.status == HardeningStatus::alpha_exception || check.status == HardeningStatus::disabled ||
            check.status == HardeningStatus::unknown)
        {
            blockers.push_back(check);
        }
    }
    return blockers;
}

auto HardeningSelfCheck::production_blocker_count() const noexcept -> std::size_t
{
    auto count = std::size_t{0U};
    for (auto const& check : m_checks)
    {
        if (check.status == HardeningStatus::alpha_exception || check.status == HardeningStatus::disabled ||
            check.status == HardeningStatus::unknown)
        {
            ++count;
        }
    }
    return count;
}

auto HardeningSelfCheck::is_production_ready() const noexcept -> bool
{
    return production_blocker_count() == 0U;
}

auto HardeningSelfCheck::is_alpha_ready() const noexcept -> bool
{
    // Alpha tolerates documented `alpha_exception` placeholders and the
    // compile-time `unknown` baselines that survive when the toolchain did
    // not advertise a hardening macro. A `disabled` status, however, is a
    // hard failure: an operator deliberately turned a defence off.
    for (auto const& check : m_checks)
    {
        if (check.status == HardeningStatus::disabled)
        {
            return false;
        }
    }
    return true;
}

auto run_startup_hardening_self_check() -> HardeningSelfCheck
{
    auto checks = std::vector<HardeningCheck>{};
    checks.reserve(13U);

    auto add = [&checks](std::string name, HardeningCheck check) {
        check.name = std::move(name);
        checks.push_back(std::move(check));
    };

    add("compiler hardening",
        enabled_or_alpha_exception(compile_time_compiler_hardening_enabled(),
                                   "Toolchain did not advertise stack protector + FORTIFY + PIE at compile time."));
    // The linker flag set (`-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack`) is
    // applied in meson.build but cannot be re-introspected from inside the
    // binary without parsing PT_GNU_RELRO/PT_GNU_STACK at runtime, which is
    // out of scope for alpha.
    add("linker hardening", enabled_or_alpha_exception(false, "Runtime ELF program-header probe is deferred."));
    add("PIE", enabled_or_alpha_exception(compile_time_pie_enabled(),
                                          "Compile did not advertise __PIE__; PIE may still be linked via -pie."));
    add("RELRO", enabled_or_alpha_exception(false, "Runtime PT_GNU_RELRO probe is deferred."));
    add("stack protector", enabled_or_alpha_exception(compile_time_stack_protector_enabled(),
                                                      "Compile did not advertise __SSP__/__SSP_STRONG__/__SSP_ALL__."));
    add("FORTIFY_SOURCE",
        enabled_or_alpha_exception(compile_time_fortify_enabled(), "Compile did not advertise _FORTIFY_SOURCE > 0."));
    add("seccomp", enabled_or_alpha_exception(false, "Linux seccomp-bpf profile is not yet enforced at startup."));
    add("pledge/unveil",
        enabled_or_alpha_exception(false, "OpenBSD pledge/unveil invocations are not yet wired into startup."));
    add("capsicum",
        enabled_or_alpha_exception(false, "FreeBSD Capsicum capability mode entry is not yet wired into startup."));
    add("privilege drop",
        enabled_or_alpha_exception(
            false,
            "setuid/setgid privilege drop is delegated to the service manager (systemd/OpenRC/rc.d) for alpha."));
    add("filesystem restrictions",
        enabled_or_alpha_exception(false,
                                   "Filesystem confinement is delegated to systemd sandboxing directives for alpha."));
    add("core dump policy",
        enabled_or_alpha_exception(false, "RLIMIT_CORE clamp is not yet applied inside the process."));
    add("secret redaction policy", HardeningCheck{{}, HardeningStatus::enabled, {}});

    auto result = HardeningSelfCheck{std::move(checks)};

    // Log each check that is not fully enabled so operators can see the exact
    // hardening gaps at startup without inspecting the health endpoint.
    for (auto const& check : result.checks())
    {
        if (check.status != HardeningStatus::enabled)
        {
            log_diagnostic("check.not_enabled",
                           {{"name", check.name, false},
                            {"status", std::string{hardening_status_name(check.status)}, false},
                            {"note", check.note, false}});
        }
    }
    log_diagnostic("self_check.complete",
                   {{"total_checks",        std::to_string(result.count()),                  false},
                    {"production_blockers",  std::to_string(result.production_blocker_count()), false},
                    {"alpha_ready",          result.is_alpha_ready() ? std::string{"true"} : std::string{"false"}, false}});

    return result;
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
    case HardeningStatus::alpha_exception:
        return "alpha_exception";
    }

    return "unknown";
}

} // namespace merovingian::platform
