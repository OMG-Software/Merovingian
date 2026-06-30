// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::platform
{

enum class HardeningPlatform
{
    linux,
    bsd,
    portable,
};

enum class HardeningAction
{
    privilege_drop,
    filesystem_restriction,
    resource_limit,
    memory_locking,
    random_source,
    signal_handling,
    syscall_filter,
    capability_bounding,
    sandbox_profile,
};

enum class HardeningMode
{
    optional,
    required,
};

struct PrivilegeDropPlan final
{
    std::string user{};
    std::string group{};
    bool drop_supplementary_groups{true};
    bool clear_environment{true};
};

struct FilesystemRestrictionPlan final
{
    std::vector<std::string> read_only_paths{};
    std::vector<std::string> writable_paths{};
    bool deny_home{true};
    bool deny_proc_write{true};
    bool private_tmp{true};
};

struct ResourceLimitPlan final
{
    std::uint64_t max_open_files{1024U};
    std::uint64_t max_processes{64U};
    std::uint64_t max_address_space_bytes{0U};
    std::uint64_t max_core_bytes{0U};
};

struct MemoryLockingPlan final
{
    bool lock_secret_pages{true};
    bool disable_core_dumps{true};
    bool wipe_on_release{true};
};

struct RandomSourcePlan final
{
    std::string source_path{"/dev/urandom"};
    bool require_nonblocking{true};
    bool fail_if_unavailable{true};
};

struct SignalHandlingPlan final
{
    bool install_shutdown_handlers{true};
    bool ignore_sigpipe{true};
    bool block_unexpected_signals{true};
};

struct LinuxHardeningPlan final
{
    bool seccomp_filter_required{true};
    bool no_new_privs_required{true};
    bool capability_bounding_required{true};
    bool core_dump_policy_required{true};
    bool landlock_documented{true};
    bool apparmor_documented{true};
    bool selinux_documented{true};
    bool systemd_sandboxing_documented{true};
};

struct BsdHardeningPlan final
{
    bool pledge_documented{true};
    bool unveil_documented{true};
    bool capsicum_documented{true};
    bool jail_documented{true};
    bool chroot_documented{true};
    bool setrlimit_documented{true};
};

struct RuntimeHardeningProfile final
{
    HardeningPlatform platform{HardeningPlatform::portable};
    HardeningMode mode{HardeningMode::required};
    PrivilegeDropPlan privilege_drop{};
    FilesystemRestrictionPlan filesystem{};
    ResourceLimitPlan resources{};
    MemoryLockingPlan memory{};
    RandomSourcePlan random{};
    SignalHandlingPlan signals{};
    LinuxHardeningPlan linux{};
    BsdHardeningPlan bsd{};
};

struct HardeningPlanDecision final
{
    bool accepted{false};
    bool fail_closed{true};
    std::string reason{};
};

struct HardeningGate final
{
    std::string name{};
    HardeningAction action{HardeningAction::sandbox_profile};
    HardeningMode mode{HardeningMode::required};
    bool available{false};
};

[[nodiscard]] auto hardening_platform_name(HardeningPlatform platform) noexcept -> char const*;
[[nodiscard]] auto hardening_action_name(HardeningAction action) noexcept -> char const*;
[[nodiscard]] auto hardening_mode_name(HardeningMode mode) noexcept -> char const*;
[[nodiscard]] auto default_linux_hardening_profile() -> RuntimeHardeningProfile;
[[nodiscard]] auto default_bsd_hardening_profile() -> RuntimeHardeningProfile;
[[nodiscard]] auto default_portable_hardening_profile() -> RuntimeHardeningProfile;
[[nodiscard]] auto privilege_drop_plan_is_safe(PrivilegeDropPlan const& plan) noexcept -> bool;
[[nodiscard]] auto filesystem_plan_is_safe(FilesystemRestrictionPlan const& plan) noexcept -> bool;
[[nodiscard]] auto resource_limit_plan_is_safe(ResourceLimitPlan const& plan) noexcept -> bool;
[[nodiscard]] auto memory_locking_plan_is_safe(MemoryLockingPlan const& plan) noexcept -> bool;
[[nodiscard]] auto random_source_plan_is_safe(RandomSourcePlan const& plan) noexcept -> bool;
[[nodiscard]] auto signal_handling_plan_is_safe(SignalHandlingPlan const& plan) noexcept -> bool;
[[nodiscard]] auto linux_hardening_plan_is_documented(LinuxHardeningPlan const& plan) noexcept -> bool;
[[nodiscard]] auto bsd_hardening_plan_is_documented(BsdHardeningPlan const& plan) noexcept -> bool;
[[nodiscard]] auto evaluate_runtime_hardening_profile(RuntimeHardeningProfile const& profile) -> HardeningPlanDecision;
[[nodiscard]] auto evaluate_hardening_gates(std::vector<HardeningGate> const& gates) -> HardeningPlanDecision;

// Apply the platform-specific controls that are safe to invoke from inside the
// server process at the point start_client_server() runs. Linux: core-dump
// policy, no_new_privs, capability bounding. OpenBSD: unveil(2) + pledge(2).
// FreeBSD: profile is validated here; cap_enter(2) is deferred — call
// apply_freebsd_capsicum_capability_mode() from main.cpp after all resources
// are open and the federation worker is spawned. Portable: no-op.
[[nodiscard]] auto apply_runtime_hardening_controls(RuntimeHardeningProfile const& profile) -> HardeningPlanDecision;

// Apply the STRICTER hardening sequence for the federation worker child
// (issue #319). Called from the worker's main() after config + master-key file
// are read and the IPC fd is validated, but BEFORE the event loop opens the DB
// and starts threads. Linux sequence: RLIMIT_CORE=0 + PR_SET_DUMPABLE=0,
// PR_SET_NO_NEW_PRIVS, drop all capabilities from the bounding set, then
// install the worker seccomp-bpf allowlist (which denies execve/execveat — the
// worker never spawns). Fail-closed: returns rejected if any required control
// fails. Non-Linux: accepted no-op (seccomp is Linux-only).
[[nodiscard]] auto apply_worker_hardening() -> HardeningPlanDecision;

// Probe: true when OpenBSD pledge(2) has been applied in this process.
// On all non-OpenBSD platforms the inline stub returns false at compile time.
#ifdef __OpenBSD__
[[nodiscard]] auto openbsd_pledge_is_active() noexcept -> bool;
// The space-separated pledge promise set passed to pledge(2) at startup.
[[nodiscard]] auto bsd_pledge_promises() noexcept -> char const*;
#else
[[nodiscard]] inline auto openbsd_pledge_is_active() noexcept -> bool
{
    return false;
}
#endif

// Probe: true when the process is in FreeBSD Capsicum capability mode.
// On all non-FreeBSD platforms the inline stub returns false at compile time.
#ifdef __FreeBSD__
[[nodiscard]] auto freebsd_capsicum_is_active() noexcept -> bool;
// Enter FreeBSD Capsicum capability mode. Must be called AFTER all file
// descriptors needed for the server's lifetime are open and the federation
// worker has been spawned via posix_spawn() (which requires path access).
[[nodiscard]] auto apply_freebsd_capsicum_capability_mode() -> HardeningPlanDecision;
#else
[[nodiscard]] inline auto freebsd_capsicum_is_active() noexcept -> bool
{
    return false;
}
#endif

[[nodiscard]] auto linux_deployment_profile_notes() -> std::vector<std::string>;
[[nodiscard]] auto bsd_deployment_profile_notes() -> std::vector<std::string>;
[[nodiscard]] auto runtime_hardening_ci_gate_notes() -> std::vector<std::string>;

} // namespace merovingian::platform
