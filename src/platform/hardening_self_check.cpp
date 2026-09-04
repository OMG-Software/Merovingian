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

#include <sys/resource.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/capability.h>
#include <sys/prctl.h>
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

    // Compiler hardening rolls up the compile-time toolchain defences (stack
    // protector + FORTIFY_SOURCE). PIE is verified separately via the ELF probe
    // because Meson compiles static library objects with -fPIC (overriding -fPIE),
    // so __PIE__ is never defined in library translation units.
    [[nodiscard]] auto compile_time_compiler_hardening_enabled(bool elf_pie_active) noexcept -> bool
    {
        return compile_time_stack_protector_enabled() && compile_time_fortify_enabled() && elf_pie_active;
    }

    // Use `unknown` when a control cannot be confirmed but is not a deliberate
    // operator-driven failure. Examples: a compile-time macro was absent, a probe
    // could not run, or a control is applied later in the startup sequence.
    [[nodiscard]] auto enabled_or_unknown(bool enabled, std::string reason) -> HardeningCheck
    {
        if (enabled)
        {
            return HardeningCheck{{}, HardeningStatus::enabled, {}};
        }
        return HardeningCheck{{}, HardeningStatus::unknown, std::move(reason)};
    }

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("hardening_self_check", event, fields, severity);
    }

    // getrlimit(RLIMIT_CORE) and geteuid() are POSIX, so both probes run on
    // every supported platform. They sat behind an __linux__ guard only because
    // the checks that used them did (0.12.5 audit, finding 10): the effect was
    // that a FreeBSD or OpenBSD server reported "unknown" for controls it had
    // actually applied, and is_ready() then refused to start it.
    [[nodiscard]] auto core_dump_policy_applied() noexcept -> bool
    {
        auto limit = ::rlimit{};
        if (::getrlimit(RLIMIT_CORE, &limit) != 0)
        {
            return false;
        }
        if (limit.rlim_cur != 0 || limit.rlim_max != 0)
        {
            return false;
        }
#ifdef __linux__
        // 0.12.5 audit, finding 21: RLIMIT_CORE=0 alone is not the whole
        // policy. A core_pattern that pipes to a handler (systemd-coredump,
        // apport) is not bound by the process rlimit, so the dumpable flag has
        // to be checked too or the probe reports success over a process whose
        // memory can still be captured.
        return ::prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0;
#else
        return true;
#endif
    }

    // Returns true when the process is running as a non-root user. This is the
    // runtime signal that the service manager (systemd/OpenRC/rc.d) has applied
    // privilege drop and UID-based filesystem restrictions.
    [[nodiscard]] auto running_as_nonroot() noexcept -> bool
    {
        return ::geteuid() != 0;
    }

#ifdef __linux__

    [[nodiscard]] auto linux_no_new_privs_applied() noexcept -> bool
    {
        return ::prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1;
    }

    // Returns true when the capability bounding set has been dropped (all caps
    // removed). Checks CAP_CHOWN (0) as a sentinel — if it is absent from the
    // bounding set, apply_linux_capability_bounding_set() has run.
    [[nodiscard]] auto linux_capability_bounding_dropped() noexcept -> bool
    {
        // prctl(PR_CAPBSET_READ, cap) returns 1 if cap is in the bounding set,
        // 0 if it was dropped, -1 on error. CAP_CHOWN == 0.
        return ::prctl(PR_CAPBSET_READ, CAP_CHOWN, 0, 0, 0) == 0;
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
        if (check.status != HardeningStatus::enabled)
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
        if (check.status != HardeningStatus::enabled)
        {
            ++count;
        }
    }
    return count;
}

auto HardeningSelfCheck::is_ready() const noexcept -> bool
{
    // The server refuses to start unless every hardening check is confirmed
    // enabled. There is no "alpha" readiness level; unknown and disabled both
    // block startup.
    return production_blocker_count() == 0U;
}

auto run_startup_hardening_self_check() -> HardeningSelfCheck
{
    auto checks = std::vector<HardeningCheck>{};
    checks.reserve(15U);

    auto add = [&checks](std::string name, HardeningCheck check) {
        check.name = std::move(name);
        checks.push_back(std::move(check));
    };

    // Probe ELF program headers first — the result feeds both PIE and the
    // compiler hardening composite so it must precede both checks.
    auto const elf = probe_elf_hardening();
    // ET_DYN (PIE) is confirmed by the ELF probe rather than a compile-time
    // macro: Meson compiles static-library objects with -fPIC which overrides
    // -fPIE and prevents __PIE__ from being defined in those translation units.
    auto const elf_pie_active = elf.probed && elf.is_pie;

    add("compiler hardening",
        enabled_or_unknown(compile_time_compiler_hardening_enabled(elf_pie_active),
                           "Stack protector, FORTIFY_SOURCE, or PIE (ELF ET_DYN) not confirmed."));
    add("linker hardening", linker_hardening_check_from_probe(elf));
    add("PIE", elf_pie_active
                   ? HardeningCheck{{}, HardeningStatus::enabled, {}}
                   : HardeningCheck{{},
                                    HardeningStatus::unknown,
                                    "ELF probe: binary is ET_EXEC (not PIE-linked); rebuild with -pie linker flag."});
    add("RELRO", relro_check_from_probe(elf));
    add("stack protector", enabled_or_unknown(compile_time_stack_protector_enabled(),
                                              "Compile did not advertise __SSP__/__SSP_STRONG__/__SSP_ALL__."));
    add("FORTIFY_SOURCE",
        enabled_or_unknown(compile_time_fortify_enabled(), "Compile did not advertise _FORTIFY_SOURCE > 0."));
    add("seccomp", seccomp_check_from_probe(probe_seccomp_status()));

    // pledge/unveil: OpenBSD-only control. On all other platforms it is not
    // applicable — returning `enabled` is correct: there is no security gap.
#ifdef __OpenBSD__
    add("pledge/unveil",
        enabled_or_unknown(openbsd_pledge_is_active(),
                           "OpenBSD pledge/unveil has not been applied yet (applied in start_client_server)."));
#else
    add("pledge/unveil", HardeningCheck{{}, HardeningStatus::enabled, "Not applicable on this platform."});
#endif

    // capsicum: FreeBSD-only control. Same reasoning as pledge/unveil above.
#ifdef __FreeBSD__
    add("capsicum",
        enabled_or_unknown(freebsd_capsicum_is_active(),
                           "FreeBSD Capsicum capability mode not yet entered (entered after fed worker is spawned)."));
#else
    add("capsicum", HardeningCheck{{}, HardeningStatus::enabled, "Not applicable on this platform."});
#endif

    // privilege drop / filesystem restrictions: the process running as a
    // non-root UID is the runtime signal that the service manager has applied
    // privilege drop and UID-based filesystem access controls. Running as root
    // is a hard failure — the server must never run as root in production.
    auto const nonroot = running_as_nonroot();
    add("privilege drop",
        nonroot ? HardeningCheck{{}, HardeningStatus::enabled, {}}
                : HardeningCheck{{},
                                 HardeningStatus::disabled,
                                 "Server is running as root. Configure the service manager to use a dedicated non-root "
                                 "user (systemd: User=merovingian)."});
    add("filesystem restrictions",
        nonroot ? HardeningCheck{{}, HardeningStatus::enabled, {}}
                : HardeningCheck{{},
                                 HardeningStatus::disabled,
                                 "Server is running as root. Apply UID-based or landlock filesystem restrictions."});
    add("core dump policy",
        enabled_or_unknown(core_dump_policy_applied(),
                           "RLIMIT_CORE is not clamped to zero, or the process is still dumpable."));

    // no_new_privs and capability bounding are Linux mechanisms with no BSD
    // equivalent to probe. 0.12.5 audit, finding 10: they used to report
    // `unknown` off Linux, and since is_ready() treats anything but `enabled`
    // as a blocker, a FreeBSD or OpenBSD server could not start at all despite
    // documented Tier 1 support. They now use the same "not applicable on this
    // platform" idiom already used for pledge/unveil and Capsicum on Linux --
    // the equivalent BSD controls are probed by those two checks.
#ifdef __linux__
    add("no_new_privs", enabled_or_unknown(linux_no_new_privs_applied(), "PR_SET_NO_NEW_PRIVS is not active."));
    add("capability bounding",
        enabled_or_unknown(linux_capability_bounding_dropped(),
                           "Capability bounding set has not been dropped (apply_runtime_hardening_controls not "
                           "yet called, or called after this check)."));
#else
    add("no_new_privs", HardeningCheck{{}, HardeningStatus::enabled, "Not applicable on this platform."});
    add("capability bounding", HardeningCheck{{}, HardeningStatus::enabled, "Not applicable on this platform."});
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
                       {"total_checks",        std::to_string(result.count()),                                 false},
                       {"production_blockers", std::to_string(result.production_blocker_count()),              false},
                       {"ready",               result.is_ready() ? std::string{"true"} : std::string{"false"}, false}
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
