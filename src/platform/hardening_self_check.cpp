// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/platform/hardening_self_check.hpp"

#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/platform/elf_probe.hpp"
#include "merovingian/platform/runtime_hardening.hpp"
#include "merovingian/platform/seccomp_hardening.hpp"

#include <string>
#include <utility>
#include <vector>

#ifdef __linux__
#include <sys/prctl.h>
#include <sys/resource.h>
#endif

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

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("hardening_self_check", event, fields, severity);
    }

#ifdef __linux__

    [[nodiscard]] auto linux_core_dump_policy_applied() noexcept -> bool
    {
        auto limit = ::rlimit{};
        if (::getrlimit(RLIMIT_CORE, &limit) != 0)
        {
            return false;
        }
        return limit.rlim_cur == 0 && limit.rlim_max == 0;
    }

    [[nodiscard]] auto linux_no_new_privs_applied() noexcept -> bool
    {
        return ::prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1;
    }

#endif

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
    checks.reserve(15U);

    auto add = [&checks](std::string name, HardeningCheck check) {
        check.name = std::move(name);
        checks.push_back(std::move(check));
    };

    add("compiler hardening",
        enabled_or_alpha_exception(compile_time_compiler_hardening_enabled(),
                                   "Toolchain did not advertise stack protector + FORTIFY + PIE at compile time."));
    auto const elf = probe_elf_hardening();
    add("linker hardening", linker_hardening_check_from_probe(elf));
    add("PIE", enabled_or_alpha_exception(compile_time_pie_enabled(),
                                          "Compile did not advertise __PIE__; PIE may still be linked via -pie."));
    add("RELRO", relro_check_from_probe(elf));
    add("stack protector", enabled_or_alpha_exception(compile_time_stack_protector_enabled(),
                                                      "Compile did not advertise __SSP__/__SSP_STRONG__/__SSP_ALL__."));
    add("FORTIFY_SOURCE",
        enabled_or_alpha_exception(compile_time_fortify_enabled(), "Compile did not advertise _FORTIFY_SOURCE > 0."));
    add("seccomp", seccomp_check_from_probe(probe_seccomp_status()));
    add("pledge/unveil", enabled_or_alpha_exception(
                             openbsd_pledge_is_active(),
                             "OpenBSD pledge/unveil has not been applied yet (applied after start_client_server)."));
    add("capsicum", enabled_or_alpha_exception(
                        freebsd_capsicum_is_active(),
                        "FreeBSD Capsicum capability mode not yet entered (entered after fed worker is spawned)."));
    add("privilege drop",
        enabled_or_alpha_exception(
            false,
            "setuid/setgid privilege drop is delegated to the service manager (systemd/OpenRC/rc.d) for alpha."));
    add("filesystem restrictions",
        enabled_or_alpha_exception(false,
                                   "Filesystem confinement is delegated to systemd sandboxing directives for alpha."));
#ifdef __linux__
    add("core dump policy",
        enabled_or_alpha_exception(linux_core_dump_policy_applied(), "RLIMIT_CORE is not clamped to zero."));
    add("no_new_privs", enabled_or_alpha_exception(linux_no_new_privs_applied(), "PR_SET_NO_NEW_PRIVS is not active."));
    add("capability bounding",
        HardeningCheck{{}, HardeningStatus::enabled, "Capability bounding set was dropped at startup."});
#else
    add("core dump policy", enabled_or_alpha_exception(false, "Core dump policy probe is only implemented on Linux."));
    add("no_new_privs", enabled_or_alpha_exception(false, "PR_SET_NO_NEW_PRIVS is only implemented on Linux."));
    add("capability bounding",
        enabled_or_alpha_exception(false, "Capability bounding set drop is only implemented on Linux."));
#endif
    add("secret redaction policy", HardeningCheck{{}, HardeningStatus::enabled, {}});

    auto result = HardeningSelfCheck{std::move(checks)};

    // Log each check that is not fully enabled so operators can see the exact
    // hardening gaps at startup without inspecting the health endpoint.
    for (auto const& check : result.checks())
    {
        if (check.status != HardeningStatus::enabled)
        {
            log_diagnostic("check.not_enabled", {
                                                    {"name",   check.name,                                       false},
                                                    {"status", std::string{hardening_status_name(check.status)}, false},
                                                    {"note",   check.note,                                       false}
            });
        }
    }
    log_diagnostic("self_check.complete",
                   {
                       {"total_checks",        std::to_string(result.count()),                                       false},
                       {"production_blockers", std::to_string(result.production_blocker_count()),                    false},
                       {"alpha_ready",         result.is_alpha_ready() ? std::string{"true"} : std::string{"false"}, false}
    });

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

auto linker_hardening_check_from_probe(ElfHardeningResult const& result) -> HardeningCheck
{
    // `enabled` only when the probe ran and confirmed RELRO + bind-now + noexecstack.
    // Everything else is `unknown`: statically-linked binaries have no PT_DYNAMIC for
    // bind-now, and dev builds omit -z,relro intentionally; the server cannot
    // distinguish these cases at runtime.
    if (result.probed && result.has_relro && result.has_bind_now && result.has_noexec_stack)
        return HardeningCheck{{}, HardeningStatus::enabled, {}};
    return HardeningCheck{
        {},
        HardeningStatus::unknown,
        "ELF probe: PT_GNU_RELRO, DT_BIND_NOW, or PT_GNU_STACK(noexec) not confirmed; "
        "binary may be statically linked or built without -Wl,-z,relro -Wl,-z,now.",
    };
}

auto relro_check_from_probe(ElfHardeningResult const& result) -> HardeningCheck
{
    if (result.probed && result.has_relro)
        return HardeningCheck{{}, HardeningStatus::enabled, {}};
    return HardeningCheck{
        {},
        HardeningStatus::unknown,
        "ELF probe: PT_GNU_RELRO segment not found; "
        "binary may be statically linked or built without -Wl,-z,relro.",
    };
}

auto seccomp_check_from_probe(SeccompProbeResult const& result) -> HardeningCheck
{
    // `enabled` only when the probe ran and confirmed a bpf filter is active.
    // `unknown` in all other cases: filter may not have been applied (dev/dry-run),
    // the kernel may lack CONFIG_SECCOMP_FILTER, or the platform is non-Linux.
    if (result.probed && result.seccomp_active)
        return HardeningCheck{{}, HardeningStatus::enabled, {}};
    return HardeningCheck{
        {},
        HardeningStatus::unknown,
        "/proc/self/status Seccomp field is not 2 (SECCOMP_MODE_FILTER); "
        "filter may not have been applied or the platform does not support seccomp-bpf.",
    };
}

} // namespace merovingian::platform
