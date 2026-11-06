// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// PHASE-B: forwarding includes, removed when consumers include the new headers directly.
#include "merovingian/platform/BsdHardeningPlan.hpp"
#include "merovingian/platform/FilesystemRestrictionPlan.hpp"
#include "merovingian/platform/HardeningAction.hpp"
#include "merovingian/platform/HardeningGate.hpp"
#include "merovingian/platform/HardeningMode.hpp"
#include "merovingian/platform/HardeningPlanDecision.hpp"
#include "merovingian/platform/HardeningPlatform.hpp"
#include "merovingian/platform/LinuxHardeningPlan.hpp"
#include "merovingian/platform/MemoryLockingPlan.hpp"
#include "merovingian/platform/PrivilegeDropPlan.hpp"
#include "merovingian/platform/RandomSourcePlan.hpp"
#include "merovingian/platform/ResourceLimitPlan.hpp"
#include "merovingian/platform/RuntimeHardeningProfile.hpp"
#include "merovingian/platform/SignalHandlingPlan.hpp"
#include "merovingian/platform/UnveilRule.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::platform
{

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

// The unveil(2) calls the OpenBSD runtime profile makes, in order, or nullopt
// when one would fail because neither the path nor the directory it would be
// created in exists (unveil's ENOENT). The first call hides the rest of the
// filesystem and none can be undone, so every call must be known to succeed
// before the first is made (ADR-0162). `directory_exists` is the only probe;
// the function is otherwise pure, so it is tested on every platform.
[[nodiscard]] auto openbsd_unveil_rules(RuntimeHardeningProfile const& profile,
                                        std::function<bool(std::string const&)> const& directory_exists)
    -> std::optional<std::vector<UnveilRule>>;
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
// fails. Non-Linux: also fail-closed — see worker_hardening_unavailable_decision()
// below. There is no in-process worker sandbox on non-Linux platforms, so a
// caller that requested hardening cannot silently be told it succeeded.
[[nodiscard]] auto apply_worker_hardening() -> HardeningPlanDecision;

// Builds the fail-closed decision apply_worker_hardening() returns on
// platforms without an in-process worker sandbox (seccomp-bpf, capability
// bounding, core dump policy, and PR_SET_NO_NEW_PRIVS are Linux-only). Pure —
// performs no syscalls and touches no process state — so it is safe to call
// directly from tests on any platform to verify the fail-closed reason and
// shape without installing a real sandbox on the calling process. Exposed for
// testing.
[[nodiscard]] auto worker_hardening_unavailable_decision() -> HardeningPlanDecision;

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
