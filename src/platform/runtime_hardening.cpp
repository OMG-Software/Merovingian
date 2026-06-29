// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/platform/runtime_hardening.hpp"

#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#ifdef __linux__
#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#endif

#ifdef __OpenBSD__
#include <atomic>

#include <unistd.h>
#endif

#ifdef __FreeBSD__
#include <cerrno>
#include <cstring>

#include <sys/capsicum.h>
#endif

namespace merovingian::platform
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("runtime_hardening", event, fields, severity);
    }

    [[nodiscard]] auto reject(std::string reason) -> HardeningPlanDecision
    {
        return {false, true, std::move(reason)};
    }

    [[nodiscard]] auto accept() -> HardeningPlanDecision
    {
        return {true, false, {}};
    }

    [[nodiscard]] auto accept_optional(std::string reason) -> HardeningPlanDecision
    {
        return {true, false, "optional hardening unavailable: " + std::move(reason)};
    }

    [[nodiscard]] auto reject_if_required(HardeningMode mode, std::string reason) -> HardeningPlanDecision
    {
        if (mode == HardeningMode::required)
        {
            return reject(std::move(reason));
        }

        return accept_optional(std::move(reason));
    }

    [[nodiscard]] auto path_is_absolute_normalized(std::string_view path) noexcept -> bool
    {
        if (path.empty() || path.front() != '/')
        {
            return false;
        }
        if (path.size() > 1U && path.back() == '/')
        {
            return false;
        }
        if (path == "/")
        {
            return true;
        }

        auto segment_start = std::size_t{1U};
        while (segment_start < path.size())
        {
            auto segment_end = path.find('/', segment_start);
            if (segment_end == std::string_view::npos)
            {
                segment_end = path.size();
            }
            if (segment_end == segment_start)
            {
                return false;
            }

            auto const segment = path.substr(segment_start, segment_end - segment_start);
            if (segment == "." || segment == "..")
            {
                return false;
            }

            segment_start = segment_end + 1U;
        }

        return true;
    }

    [[nodiscard]] auto is_path_or_child_of(std::string_view path, std::string_view protected_path) noexcept -> bool
    {
        return path == protected_path ||
               (path.size() > protected_path.size() && path.substr(0U, protected_path.size()) == protected_path &&
                path[protected_path.size()] == '/');
    }

    [[nodiscard]] auto writable_path_is_safe(std::string_view path) noexcept -> bool
    {
        return path_is_absolute_normalized(path) && path != "/" && !is_path_or_child_of(path, "/etc") &&
               !is_path_or_child_of(path, "/usr");
    }

} // namespace

auto hardening_platform_name(HardeningPlatform platform) noexcept -> char const*
{
    switch (platform)
    {
    case HardeningPlatform::linux:
        return "linux";
    case HardeningPlatform::bsd:
        return "bsd";
    case HardeningPlatform::portable:
        return "portable";
    }

    return "unknown";
}

auto hardening_action_name(HardeningAction action) noexcept -> char const*
{
    switch (action)
    {
    case HardeningAction::privilege_drop:
        return "privilege_drop";
    case HardeningAction::filesystem_restriction:
        return "filesystem_restriction";
    case HardeningAction::resource_limit:
        return "resource_limit";
    case HardeningAction::memory_locking:
        return "memory_locking";
    case HardeningAction::random_source:
        return "random_source";
    case HardeningAction::signal_handling:
        return "signal_handling";
    case HardeningAction::syscall_filter:
        return "syscall_filter";
    case HardeningAction::capability_bounding:
        return "capability_bounding";
    case HardeningAction::sandbox_profile:
        return "sandbox_profile";
    }

    return "unknown";
}

auto hardening_mode_name(HardeningMode mode) noexcept -> char const*
{
    switch (mode)
    {
    case HardeningMode::optional:
        return "optional";
    case HardeningMode::required:
        return "required";
    }

    return "unknown";
}

auto default_linux_hardening_profile() -> RuntimeHardeningProfile
{
    auto profile = RuntimeHardeningProfile{};
    profile.platform = HardeningPlatform::linux;
    profile.mode = HardeningMode::required;
    profile.privilege_drop.user = "merovingian";
    profile.privilege_drop.group = "merovingian";
    profile.filesystem.read_only_paths = {"/usr", "/etc/merovingian"};
    profile.filesystem.writable_paths = {"/var/lib/merovingian", "/run/merovingian"};
    profile.resources.max_address_space_bytes = 1073741824U;
    return profile;
}

auto default_bsd_hardening_profile() -> RuntimeHardeningProfile
{
    auto profile = default_linux_hardening_profile();
    profile.platform = HardeningPlatform::bsd;
    // The test harness and several runtime utilities (e.g. media thumbnail
    // scratch files) rely on the system temporary directory. OpenBSD's
    // unveil(2) requires every reachable path to be listed, so /tmp is
    // included alongside the persistent and runtime state directories.
    profile.filesystem.writable_paths = {"/var/lib/merovingian", "/var/run/merovingian", "/tmp"};
    return profile;
}

auto default_portable_hardening_profile() -> RuntimeHardeningProfile
{
    auto profile = default_linux_hardening_profile();
    profile.platform = HardeningPlatform::portable;
    profile.mode = HardeningMode::optional;
    return profile;
}

auto privilege_drop_plan_is_safe(PrivilegeDropPlan const& plan) noexcept -> bool
{
    return !plan.user.empty() && !plan.group.empty() && plan.drop_supplementary_groups && plan.clear_environment;
}

auto filesystem_plan_is_safe(FilesystemRestrictionPlan const& plan) noexcept -> bool
{
    return plan.deny_home && plan.deny_proc_write && plan.private_tmp && !plan.writable_paths.empty() &&
           std::ranges::all_of(plan.writable_paths, [](std::string const& path) {
               return writable_path_is_safe(path);
           });
}

auto resource_limit_plan_is_safe(ResourceLimitPlan const& plan) noexcept -> bool
{
    return plan.max_open_files > 0U && plan.max_processes > 0U && plan.max_address_space_bytes > 0U &&
           plan.max_core_bytes == 0U;
}

auto memory_locking_plan_is_safe(MemoryLockingPlan const& plan) noexcept -> bool
{
    return plan.lock_secret_pages && plan.disable_core_dumps && plan.wipe_on_release;
}

auto random_source_plan_is_safe(RandomSourcePlan const& plan) noexcept -> bool
{
    return !plan.source_path.empty() && plan.require_nonblocking && plan.fail_if_unavailable;
}

auto signal_handling_plan_is_safe(SignalHandlingPlan const& plan) noexcept -> bool
{
    return plan.install_shutdown_handlers && plan.ignore_sigpipe && plan.block_unexpected_signals;
}

auto linux_hardening_plan_is_documented(LinuxHardeningPlan const& plan) noexcept -> bool
{
    return plan.seccomp_filter_required && plan.no_new_privs_required && plan.capability_bounding_required &&
           plan.core_dump_policy_required && plan.landlock_documented && plan.apparmor_documented &&
           plan.selinux_documented && plan.systemd_sandboxing_documented;
}

auto bsd_hardening_plan_is_documented(BsdHardeningPlan const& plan) noexcept -> bool
{
    return plan.pledge_documented && plan.unveil_documented && plan.capsicum_documented && plan.jail_documented &&
           plan.chroot_documented && plan.setrlimit_documented;
}

auto evaluate_runtime_hardening_profile(RuntimeHardeningProfile const& profile) -> HardeningPlanDecision
{
    auto result = [&]() -> HardeningPlanDecision {
        if (!filesystem_plan_is_safe(profile.filesystem))
        {
            return reject("filesystem restriction plan is unsafe");
        }
        if (!privilege_drop_plan_is_safe(profile.privilege_drop))
        {
            return reject_if_required(profile.mode, "privilege drop plan is incomplete");
        }
        if (!resource_limit_plan_is_safe(profile.resources))
        {
            return reject_if_required(profile.mode, "resource limit plan is unsafe");
        }
        if (!memory_locking_plan_is_safe(profile.memory))
        {
            return reject_if_required(profile.mode, "memory locking plan is unsafe");
        }
        if (!random_source_plan_is_safe(profile.random))
        {
            return reject_if_required(profile.mode, "random source plan is unsafe");
        }
        if (!signal_handling_plan_is_safe(profile.signals))
        {
            return reject_if_required(profile.mode, "signal handling plan is unsafe");
        }
        if (profile.platform == HardeningPlatform::linux && !linux_hardening_plan_is_documented(profile.linux))
        {
            return reject_if_required(profile.mode, "linux hardening plan is incomplete");
        }
        if (profile.platform == HardeningPlatform::bsd && !bsd_hardening_plan_is_documented(profile.bsd))
        {
            return reject_if_required(profile.mode, "bsd hardening plan is incomplete");
        }
        return accept();
    }();
    log_diagnostic(result.accepted ? "profile.accepted" : "profile.rejected",
                   {
                       {"platform", std::string{hardening_platform_name(profile.platform)}, false},
                       {"mode",     std::string{hardening_mode_name(profile.mode)},         false},
                       {"reason",   result.reason,                                          false}
    });
    return result;
}

auto evaluate_hardening_gates(std::vector<HardeningGate> const& gates) -> HardeningPlanDecision
{
    for (auto const& gate : gates)
    {
        if (gate.name.empty())
        {
            log_diagnostic("gates.rejected", {
                                                 {"reason", "hardening gate name is required", false}
            });
            return reject("hardening gate name is required");
        }
        if (gate.mode == HardeningMode::required && !gate.available)
        {
            auto const reason = "required hardening gate unavailable: " + gate.name;
            log_diagnostic("gates.rejected", {
                                                 {"gate",   gate.name, false},
                                                 {"reason", reason,    false}
            });
            return reject(reason);
        }
    }

    log_diagnostic("gates.accepted", {
                                         {"gate_count", std::to_string(gates.size()), false}
    });
    return accept();
}

auto linux_deployment_profile_notes() -> std::vector<std::string>
{
    return {
        "Linux profile: enable seccomp filters, no_new_privs, capability bounding, and resource limits before serving "
        "traffic.",
        "Linux profile: document Landlock, AppArmor, and SELinux policy expectations for deployments that support "
        "them.",
        "Linux profile: systemd units should use sandboxing directives such as PrivateTmp, ProtectSystem, ProtectHome, "
        "NoNewPrivileges, RestrictAddressFamilies, and CapabilityBoundingSet.",
    };
}

auto bsd_deployment_profile_notes() -> std::vector<std::string>
{
    return {
        "BSD profile: document pledge and unveil restrictions where available.",
        "BSD profile: document Capsicum, jails, and chroot deployment boundaries where available.",
        "BSD profile: setrlimit gates should bound file descriptors, processes, address space, and core dump "
        "generation.",
    };
}

auto runtime_hardening_ci_gate_notes() -> std::vector<std::string>
{
    return {
        "CI gate: unit tests validate hardening profile fail-closed behavior across Linux, BSD, and portable plans.",
        "CI gate: BSD build verifies that platform hardening scaffolds remain portable where OS APIs are documented "
        "but not linked.",
        "CI gate: static analysis and unsafe source gates protect hardening code paths from accidental unsafe API use.",
    };
}

namespace
{

#ifdef __linux__

    [[nodiscard]] auto apply_linux_core_dump_policy() noexcept -> bool
    {
        auto const limit = ::rlimit{
            .rlim_cur = 0,
            .rlim_max = 0,
        };
        if (::setrlimit(RLIMIT_CORE, &limit) != 0)
        {
            return false;
        }
        std::ignore = ::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        return true;
    }

    [[nodiscard]] auto apply_linux_no_new_privs() noexcept -> bool
    {
        return ::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0;
    }

    [[nodiscard]] auto apply_linux_capability_bounding_set() noexcept -> bool
    {
        // Drop every capability from the ambient bounding set. Failures are
        // ignored for individual caps because the kernel may not expose all
        // caps to userspace; the goal is to drop as many as possible.
        for (auto cap = std::int32_t{0}; cap <= CAP_LAST_CAP; ++cap)
        {
            std::ignore = ::prctl(PR_CAPBSET_DROP, cap, 0, 0, 0);
        }
        return true;
    }

#endif // __linux__

#ifdef __OpenBSD__

    // Atomic flag set once pledge(2) is called. Allows the probe function to
    // answer without re-entering the kernel on every health-check query.
    static std::atomic<bool> g_pledge_applied{false};

    // Apply filesystem access restrictions via unveil(2), then restrict
    // available syscalls via pledge(2). Returns false on any failure.
    [[nodiscard]] auto apply_openbsd_pledge_unveil(RuntimeHardeningProfile const& profile) noexcept -> bool
    {
        // Paths in read_only_paths need read + execute permission so that shared
        // libraries under /usr and worker binaries can be accessed and executed.
        for (auto const& path : profile.filesystem.read_only_paths)
        {
            if (::unveil(path.c_str(), "rx") != 0)
            {
                return false;
            }
        }
        // Paths in writable_paths need read + write + create (WAL files, sockets).
        for (auto const& path : profile.filesystem.writable_paths)
        {
            if (::unveil(path.c_str(), "rwc") != 0)
            {
                return false;
            }
        }
        // LibreSSL CA bundle — OpenBSD ships LibreSSL; /etc/ssl is the trust store
        // for outbound TLS connections and federation server verification.
        if (::unveil("/etc/ssl", "r") != 0)
        {
            return false;
        }
        // Lock the vnode allowlist — no further paths may be added after this point.
        if (::unveil(nullptr, nullptr) != 0)
        {
            return false;
        }
        if (::pledge(bsd_pledge_promises(), nullptr) != 0)
        {
            return false;
        }
        g_pledge_applied.store(true, std::memory_order_release);
        return true;
    }

#endif // __OpenBSD__

} // namespace

#ifdef __OpenBSD__

auto bsd_pledge_promises() noexcept -> char const*
{
    // proc + exec: required to fork and exec the thumbnail and federation worker
    //              child processes via posix_spawn() and fork()/execv().
    // flock:       SQLite WAL-mode file locking (flock(2) on WAL files).
    // unix:        AF_UNIX IPC channel to the out-of-process federation worker.
    // dns:         server-discovery DNS resolution for outbound federation.
    return "stdio rpath wpath cpath flock inet unix dns proc exec";
}

auto openbsd_pledge_is_active() noexcept -> bool
{
    return g_pledge_applied.load(std::memory_order_acquire);
}

#endif // __OpenBSD__

#ifdef __FreeBSD__

auto freebsd_capsicum_is_active() noexcept -> bool
{
    auto mode = unsigned int{0U};
    return ::cap_getmode(&mode) == 0 && mode != 0U;
}

auto apply_freebsd_capsicum_capability_mode() -> HardeningPlanDecision
{
    if (::cap_enter() != 0)
    {
        return reject("FreeBSD cap_enter() failed: " + std::string{::strerror(errno)});
    }
    return accept();
}

#endif // __FreeBSD__

auto apply_runtime_hardening_controls(RuntimeHardeningProfile const& profile) -> HardeningPlanDecision
{
    auto profile_decision = evaluate_runtime_hardening_profile(profile);
    if (!profile_decision.accepted)
    {
        return profile_decision;
    }

    if (profile.platform == HardeningPlatform::linux)
    {
#ifdef __linux__
        if (profile.linux.core_dump_policy_required && !apply_linux_core_dump_policy())
        {
            return reject_if_required(profile.mode, "failed to apply Linux core dump policy");
        }
        if (profile.linux.no_new_privs_required && !apply_linux_no_new_privs())
        {
            return reject_if_required(profile.mode, "failed to apply PR_SET_NO_NEW_PRIVS");
        }
        if (profile.linux.capability_bounding_required && !apply_linux_capability_bounding_set())
        {
            return reject_if_required(profile.mode, "failed to drop Linux capability bounding set");
        }
        return accept();
#else
        return reject_if_required(profile.mode, "Linux hardening requested on non-Linux platform");
#endif
    }

    if (profile.platform == HardeningPlatform::bsd)
    {
#ifdef __OpenBSD__
        if (!apply_openbsd_pledge_unveil(profile))
        {
            return reject_if_required(profile.mode, "OpenBSD pledge/unveil application failed");
        }
        return accept();
#elif defined(__FreeBSD__)
        // Capsicum capability mode is entered separately after all resources are opened;
        // call apply_freebsd_capsicum_capability_mode() from main.cpp after spawning
        // the federation worker. This call only validates the profile.
        return accept();
#else
        // NetBSD and other BSD variants: no in-process sandbox primitives implemented.
        return reject_if_required(profile.mode, "BSD sandbox helpers are not yet implemented on this BSD variant");
#endif
    }

    // Portable profile: service-manager units apply privilege drop and filesystem
    // restrictions; the process only validates that the plan documents them.
    return accept();
}

} // namespace merovingian::platform
