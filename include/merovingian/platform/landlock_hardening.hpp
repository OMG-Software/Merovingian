// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/platform/LandlockAccess.hpp"         // split-shim
#include "merovingian/platform/LandlockAddRuleOutcome.hpp" // split-shim
#include "merovingian/platform/LandlockHardeningOps.hpp"
#include "merovingian/platform/LandlockHardeningResult.hpp"
#include "merovingian/platform/LandlockPathRule.hpp"
#include "merovingian/platform/LandlockSecretExposure.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace merovingian::config
{
class Config;
} // namespace merovingian::config

namespace merovingian::platform
{

// ADR-0062 part 3: the federation worker restricts its own filesystem access
// with Linux Landlock before handling any untrusted input, so that a
// compromise reached through a memory-safety bug (not merely one abusing an
// intentionally-opened file) cannot open the operator master key, TLS
// private keys, main's database URI file, or the worker's own database URI
// file directly off disk. See docs/adr/0062-...md and docs/hardening.md.

// Highest Landlock ABI version this build knows how to request rights for.
// A running kernel that reports a higher ABI is used at this capped level —
// forward compatible, never fails just because the kernel is newer than this
// build. A kernel that reports a lower ABI has its request masked down to
// exactly the rights that ABI version supports (see landlock_handled_access_fs).
inline constexpr int k_landlock_max_known_abi = 6;

// Rights masks, downgraded to whatever `abi` supports. `abi` must be >= 1.
// Dropping unsupported bits for an older-but-still-supported kernel is
// correct Landlock practice (see landlock(7), "Best-effort approach");
// refusing to run there is not — that is what the ABI < 1 "unavailable" path
// in apply_worker_landlock() is reserved for.
[[nodiscard]] auto landlock_handled_access_fs(int abi) noexcept -> std::uint64_t;
[[nodiscard]] auto landlock_read_only_access(int abi) noexcept -> std::uint64_t;
[[nodiscard]] auto landlock_read_execute_access(int abi) noexcept -> std::uint64_t;
[[nodiscard]] auto landlock_read_write_access(int abi) noexcept -> std::uint64_t;

// Returns `requested` restricted to what a path-beneath rule may grant on this
// inode. The kernel rejects (EINVAL) a rule on a non-directory whose access
// includes any directory-only right (READ_DIR, REMOVE_*, MAKE_*, REFER), so
// for a regular file only the file-level rights (EXECUTE, WRITE_FILE,
// READ_FILE, TRUNCATE) are kept. Directories keep `requested` unchanged.
[[nodiscard]] auto landlock_access_for_inode(std::uint64_t requested, bool is_directory) noexcept -> std::uint64_t;

// Builds the federation worker's path allowlist from its own config copy.
// Paths the config carries (the SQLite database directory) are read from
// `config`, never hard-coded; fixed OS-integration paths (CA trust store,
// resolver configuration, NSS/dynamic-linker library directories) are
// best-effort (LandlockPathRule::required = false). See
// docs/adr/0062-federation-worker-holds-no-secret-files-secrets-arrive-over-inherited-fds.md,
// part 3, "Allowlist derivation" for the strace evidence this list was
// derived from.
[[nodiscard]] auto build_worker_landlock_rules(config::Config const& config) -> std::vector<LandlockPathRule>;

// Every non-empty secret file path in `config` the worker must never be able
// to open: the master key, both TLS private keys, main's database URI file,
// the worker's own database URI file (delivered over an fd, never opened),
// the registration token file, and the SMTP password file (ADR-0220).
[[nodiscard]] auto worker_landlock_secret_paths(config::Config const& config) -> std::vector<std::string>;

// Returns the first rule whose path is, or is an ancestor directory of, one
// of `secret_paths`, or std::nullopt when none is. A rule on a directory
// grants everything beneath it, so an exact-path comparison is not enough.
// Paths are compared by component after std::filesystem::weakly_canonical,
// so a symlink cannot hide an overlap and /etc/merov never covers
// /etc/merovingian.
[[nodiscard]] auto find_landlock_rule_covering_secret(std::vector<LandlockPathRule> const& rules,
                                                      std::vector<std::string> const& secret_paths)
    -> std::optional<LandlockSecretExposure>;

// Applies the Landlock filesystem restriction described by `rules`, or
// determines Landlock is unavailable and defers to `allow_without_landlock`:
//
//   * Landlock unavailable (ABI query < 1) + allow_without_landlock=false
//     -> rejected.
//   * Landlock unavailable + allow_without_landlock=true -> accepted,
//     applied=false, critical_warning=true. The caller MUST log CRITICAL on
//     every such start, not just the first.
//   * Any other Landlock failure (ruleset create, a required rule's
//     add_rule, or restrict_self) -> ALWAYS rejected, regardless of
//     allow_without_landlock — an operator opt-out covers "this kernel has
//     no Landlock", never "Landlock is present but broken".
//   * Success -> accepted=true, applied=true, critical_warning=false.
[[nodiscard]] auto apply_worker_landlock(std::vector<LandlockPathRule> const& rules, bool allow_without_landlock,
                                         LandlockHardeningOps const& ops = LandlockHardeningOps{})
    -> LandlockHardeningResult;

} // namespace merovingian::platform
