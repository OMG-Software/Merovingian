// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/platform/runtime_hardening.hpp>

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

namespace merovingian::platform
{
namespace
{

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
    return path == protected_path
        || (path.size() > protected_path.size() && path.substr(0U, protected_path.size()) == protected_path
            && path[protected_path.size()] == '/');
}

[[nodiscard]] auto writable_path_is_safe(std::string_view path) noexcept -> bool
{
    return path_is_absolute_normalized(path) && path != "/" && !is_path_or_child_of(path, "/etc")
        && !is_path_or_child_of(path, "/usr");
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
    profile.filesystem.writable_paths = {"/var/lib/merovingian", "/var/run/merovingian"};
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
    return plan.deny_home && plan.deny_proc_write && plan.private_tmp && !plan.writable_paths.empty()
        && std::ranges::all_of(plan.writable_paths, [](std::string const& path) {
               return writable_path_is_safe(path);
           });
}

auto resource_limit_plan_is_safe(ResourceLimitPlan const& plan) noexcept -> bool
{
    return plan.max_open_files > 0U && plan.max_processes > 0U && plan.max_address_space_bytes > 0U
        && plan.max_core_bytes == 0U;
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
    return plan.seccomp_filter_required && plan.no_new_privs_required && plan.capability_bounding_required
        && plan.landlock_documented && plan.apparmor_documented && plan.selinux_documented
        && plan.systemd_sandboxing_documented;
}

auto bsd_hardening_plan_is_documented(BsdHardeningPlan const& plan) noexcept -> bool
{
    return plan.pledge_documented && plan.unveil_documented && plan.capsicum_documented && plan.jail_documented
        && plan.chroot_documented && plan.setrlimit_documented;
}

auto evaluate_runtime_hardening_profile(RuntimeHardeningProfile const& profile) -> HardeningPlanDecision
{
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
}

auto evaluate_hardening_gates(std::vector<HardeningGate> const& gates) -> HardeningPlanDecision
{
    for (auto const& gate : gates)
    {
        if (gate.name.empty())
        {
            return reject("hardening gate name is required");
        }
        if (gate.mode == HardeningMode::required && !gate.available)
        {
            return reject("required hardening gate unavailable: " + gate.name);
        }
    }

    return accept();
}

auto linux_deployment_profile_notes() -> std::vector<std::string>
{
    return {
        "Linux profile: enable seccomp filters, no_new_privs, capability bounding, and resource limits before serving traffic.",
        "Linux profile: document Landlock, AppArmor, and SELinux policy expectations for deployments that support them.",
        "Linux profile: systemd units should use sandboxing directives such as PrivateTmp, ProtectSystem, ProtectHome, NoNewPrivileges, RestrictAddressFamilies, and CapabilityBoundingSet.",
    };
}

auto bsd_deployment_profile_notes() -> std::vector<std::string>
{
    return {
        "BSD profile: document pledge and unveil restrictions where available.",
        "BSD profile: document Capsicum, jails, and chroot deployment boundaries where available.",
        "BSD profile: setrlimit gates should bound file descriptors, processes, address space, and core dump generation.",
    };
}

auto runtime_hardening_ci_gate_notes() -> std::vector<std::string>
{
    return {
        "CI gate: unit tests validate hardening profile fail-closed behavior across Linux, BSD, and portable plans.",
        "CI gate: BSD build verifies that platform hardening scaffolds remain portable where OS APIs are documented but not linked.",
        "CI gate: static analysis and unsafe source gates protect hardening code paths from accidental unsafe API use.",
    };
}

} // namespace merovingian::platform
