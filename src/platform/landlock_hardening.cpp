// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/platform/landlock_hardening.hpp"

#include "merovingian/config/config.hpp"
#include "merovingian/core/file_descriptor.hpp"

#include <algorithm>
#include <filesystem>
#include <tuple>
#include <utility>

#ifdef __linux__
#include <cerrno>

#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

#if __has_include(<linux/landlock.h>)
#include <linux/landlock.h>
#define MEROVINGIAN_HAVE_LINUX_LANDLOCK_H 1
#endif
#endif // __linux__

namespace merovingian::platform
{

namespace
{

    // ---- Landlock ABI constants (stable, purely additive; see landlock(7)) --
    // Named locally (k_access_fs_* rather than the LANDLOCK_ACCESS_FS_* macro
    // names) so this compiles identically whether or not <linux/landlock.h> is
    // available, without redefinition hazards if it is.
    constexpr std::uint64_t k_access_fs_execute = 1ULL << 0U;
    constexpr std::uint64_t k_access_fs_write_file = 1ULL << 1U;
    constexpr std::uint64_t k_access_fs_read_file = 1ULL << 2U;
    constexpr std::uint64_t k_access_fs_read_dir = 1ULL << 3U;
    constexpr std::uint64_t k_access_fs_remove_dir = 1ULL << 4U;
    constexpr std::uint64_t k_access_fs_remove_file = 1ULL << 5U;
    constexpr std::uint64_t k_access_fs_make_char = 1ULL << 6U;
    constexpr std::uint64_t k_access_fs_make_dir = 1ULL << 7U;
    constexpr std::uint64_t k_access_fs_make_reg = 1ULL << 8U;
    constexpr std::uint64_t k_access_fs_make_sock = 1ULL << 9U;
    constexpr std::uint64_t k_access_fs_make_fifo = 1ULL << 10U;
    constexpr std::uint64_t k_access_fs_make_block = 1ULL << 11U;
    constexpr std::uint64_t k_access_fs_make_sym = 1ULL << 12U;
    constexpr std::uint64_t k_access_fs_refer = 1ULL << 13U;    // ABI 2 (Linux 5.19)
    constexpr std::uint64_t k_access_fs_truncate = 1ULL << 14U; // ABI 3 (Linux 6.2)

    [[nodiscard]] auto access_rights_for(LandlockAccess access, int abi) noexcept -> std::uint64_t;

} // namespace

auto landlock_handled_access_fs(int abi) noexcept -> std::uint64_t
{
    // The full set this build ever restricts. Every bit here that no rule
    // ever grants (MAKE_CHAR/MAKE_SOCK/MAKE_FIFO/MAKE_BLOCK, EXECUTE outside
    // library directories) becomes globally denied once handled — that is
    // the point: "handled" means "now governed by Landlock rules", not
    // "granted somewhere".
    auto mask = k_access_fs_execute | k_access_fs_write_file | k_access_fs_read_file | k_access_fs_read_dir |
                k_access_fs_remove_dir | k_access_fs_remove_file | k_access_fs_make_char | k_access_fs_make_dir |
                k_access_fs_make_reg | k_access_fs_make_sock | k_access_fs_make_fifo | k_access_fs_make_block |
                k_access_fs_make_sym;
    if (abi >= 2)
    {
        mask |= k_access_fs_refer;
    }
    if (abi >= 3)
    {
        mask |= k_access_fs_truncate;
    }
    return mask;
}

auto landlock_read_only_access(int abi) noexcept -> std::uint64_t
{
    std::ignore = abi;
    return k_access_fs_read_file | k_access_fs_read_dir;
}

auto landlock_read_execute_access(int abi) noexcept -> std::uint64_t
{
    return landlock_read_only_access(abi) | k_access_fs_execute;
}

auto landlock_read_write_access(int abi) noexcept -> std::uint64_t
{
    // Deliberately excludes EXECUTE and MAKE_CHAR/MAKE_SOCK/MAKE_FIFO/
    // MAKE_BLOCK: the SQLite database directory never needs to serve
    // executable pages or hold device/socket/fifo nodes.
    auto mask = k_access_fs_read_file | k_access_fs_read_dir | k_access_fs_write_file | k_access_fs_remove_dir |
                k_access_fs_remove_file | k_access_fs_make_dir | k_access_fs_make_reg | k_access_fs_make_sym;
    if (abi >= 3)
    {
        mask |= k_access_fs_truncate;
    }
    return mask;
}

namespace
{

    auto access_rights_for(LandlockAccess access, int abi) noexcept -> std::uint64_t
    {
        switch (access)
        {
        case LandlockAccess::read_only:
            return landlock_read_only_access(abi);
        case LandlockAccess::read_execute:
            return landlock_read_execute_access(abi);
        case LandlockAccess::read_write:
            return landlock_read_write_access(abi);
        }
        return landlock_read_only_access(abi);
    }

} // namespace

#ifdef __linux__
namespace
{

#ifndef MEROVINGIAN_HAVE_LINUX_LANDLOCK_H
    // Minimal Landlock ABI struct layouts for build environments whose kernel
    // headers predate <linux/landlock.h> (added to the kernel uapi headers in
    // Linux 5.13). These layouts are part of the stable kernel ABI and never
    // change once shipped.
    struct landlock_ruleset_attr // NOLINT(readability-identifier-naming)
    {
        std::uint64_t handled_access_fs;
        std::uint64_t handled_access_net;
    };

    struct landlock_path_beneath_attr // NOLINT(readability-identifier-naming)
    {
        std::uint64_t allowed_access;
        std::int32_t parent_fd;
    } __attribute__((packed));
#endif // !MEROVINGIAN_HAVE_LINUX_LANDLOCK_H

    // Unqualified lookup: resolves to the global ::landlock_ruleset_attr /
    // ::landlock_path_beneath_attr from <linux/landlock.h> when it is
    // available, or to the fallback definitions immediately above (in this
    // same anonymous namespace) otherwise. Exactly one definition exists in
    // either case, so there is no ambiguity.
    using RulesetAttr = landlock_ruleset_attr;
    using PathBeneathAttr = landlock_path_beneath_attr;

    constexpr auto k_create_ruleset_version_flag = std::uint32_t{1U << 0U};
    constexpr auto k_rule_path_beneath = std::uint16_t{1U};

} // namespace

// Landlock syscall numbers. Added in Linux 5.13 on x86_64 and aarch64 via the
// generic syscall table, so both architectures share the same numbers.
// Numeric fallback mirrors the existing __NR_clone3/__NR_close_range/
// __NR_faccessat2 pattern in seccomp_hardening.cpp for builds against older
// kernel headers than the runtime kernel.
#ifndef __NR_landlock_create_ruleset
#if defined(__x86_64__) || defined(__aarch64__)
#define __NR_landlock_create_ruleset 444
#endif
#endif
#ifndef __NR_landlock_add_rule
#if defined(__x86_64__) || defined(__aarch64__)
#define __NR_landlock_add_rule 445
#endif
#endif
#ifndef __NR_landlock_restrict_self
#if defined(__x86_64__) || defined(__aarch64__)
#define __NR_landlock_restrict_self 446
#endif
#endif

namespace
{

#ifdef __NR_landlock_create_ruleset

    [[nodiscard]] auto real_query_abi_version() -> int
    {
        return static_cast<int>(::syscall(__NR_landlock_create_ruleset, nullptr, 0U, k_create_ruleset_version_flag));
    }

    [[nodiscard]] auto real_create_ruleset(std::uint64_t handled_access_fs) -> int
    {
        auto const attr = RulesetAttr{.handled_access_fs = handled_access_fs, .handled_access_net = 0U};
        return static_cast<int>(::syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0U));
    }

#else

    [[nodiscard]] auto real_query_abi_version() -> int
    {
        errno = ENOSYS;
        return -1;
    }

    [[nodiscard]] auto real_create_ruleset(std::uint64_t /*handled_access_fs*/) -> int
    {
        errno = ENOSYS;
        return -1;
    }

#endif // __NR_landlock_create_ruleset

#ifdef __NR_landlock_add_rule

    [[nodiscard]] auto real_add_rule(int ruleset_fd, std::string const& path, std::uint64_t allowed_access)
        -> LandlockAddRuleOutcome
    {
        // O_PATH: resolve the path without requiring read/write/execute
        // permission on it directly — landlock_add_rule() only needs a
        // reference to the inode, not an open channel to its contents.
        auto path_fd = core::FileDescriptor{::open(path.c_str(), O_PATH | O_CLOEXEC)}; // NOLINT(*-vararg)
        if (!path_fd.valid())
        {
            return LandlockAddRuleOutcome::path_unavailable;
        }

        auto const attr = PathBeneathAttr{.allowed_access = allowed_access, .parent_fd = path_fd.get()};
        auto const rc = ::syscall(__NR_landlock_add_rule, ruleset_fd, static_cast<int>(k_rule_path_beneath), &attr, 0U);
        return rc == 0 ? LandlockAddRuleOutcome::success : LandlockAddRuleOutcome::failed;
    }

#else

    [[nodiscard]] auto real_add_rule(int /*ruleset_fd*/, std::string const& /*path*/, std::uint64_t /*allowed_access*/)
        -> LandlockAddRuleOutcome
    {
        return LandlockAddRuleOutcome::failed;
    }

#endif // __NR_landlock_add_rule

#ifdef __NR_landlock_restrict_self

    [[nodiscard]] auto real_restrict_self(int ruleset_fd) -> bool
    {
        return ::syscall(__NR_landlock_restrict_self, ruleset_fd, 0U) == 0;
    }

#else

    [[nodiscard]] auto real_restrict_self(int /*ruleset_fd*/) -> bool
    {
        return false;
    }

#endif // __NR_landlock_restrict_self

} // namespace
#endif // __linux__

LandlockHardeningOps::LandlockHardeningOps()
#ifdef __linux__
    : query_abi_version{real_query_abi_version}
    , create_ruleset{real_create_ruleset}
    , add_rule{real_add_rule}
    , restrict_self{real_restrict_self}
#endif
{
}

auto build_worker_landlock_rules(config::Config const& config) -> std::vector<LandlockPathRule>
{
    auto rules = std::vector<LandlockPathRule>{};

    // ---- Database (config-derived; never hard-coded) -----------------------
    // Only the SQLite backend needs a filesystem grant: PostgreSQL is
    // reached over a network socket (already unrestricted by Landlock, which
    // only governs filesystem actions), authenticated with the URI ADR-0062
    // part 2 delivers over an inherited fd, never a path the worker opens.
    if (config.database().backend == config::DatabaseBackend::sqlite && !config.database().sqlite_path.empty())
    {
        auto const dir = std::filesystem::path{config.database().sqlite_path}.parent_path();
        auto const dir_str = dir.empty() ? std::string{"."} : dir.string();
        // Read-write on the *directory*, not just the database file: WAL mode
        // creates -wal/-shm files and a rollback journal is created and
        // removed around each write transaction, none of which exist yet on
        // a first boot. A rule scoped to the file alone would not permit
        // creating those siblings.
        rules.push_back({.path = dir_str, .access = LandlockAccess::read_write, .required = true});
    }

    // ---- TLS / CA trust store (best-effort: distro-dependent) --------------
    // Mirrors http::detect_system_ca_trust()'s candidate file/directory list
    // (src/http/outbound_client.cpp), which the worker's relay pool reaches
    // via OutboundClient for outbound federation requests, plus the
    // directories Debian/Ubuntu's per-certificate symlinks under
    // /etc/ssl/certs commonly resolve into. See ADR-0062 part 3, "Allowlist
    // derivation" for the strace evidence.
    for (auto const* dir : {"/etc/ssl", "/etc/pki", "/usr/share/ca-certificates", "/usr/local/share/certs",
                            "/etc/openssl", "/usr/pkg/etc/openssl"})
    {
        rules.push_back({.path = dir, .access = LandlockAccess::read_only, .required = false});
    }

    // ---- Name resolution (glibc NSS: getaddrinfo for outbound federation) --
    for (auto const* file : {"/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/gai.conf", "/etc/host.conf"})
    {
        rules.push_back({.path = file, .access = LandlockAccess::read_only, .required = false});
    }

    // ---- NSS / TLS shared libraries, lazily dlopen'd ------------------------
    // getaddrinfo() dlopen()s libnss_dns.so/libnss_files.so on first use; the
    // TLS stack may load engine/provider modules from the same library
    // directories. Read+execute so mmap(PROT_EXEC) of the library file
    // succeeds.
    for (auto const* dir :
         {"/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu"})
    {
        rules.push_back({.path = dir, .access = LandlockAccess::read_execute, .required = false});
    }

    // ---- Timezone data -------------------------------------------------------
    rules.push_back({.path = "/usr/share/zoneinfo", .access = LandlockAccess::read_only, .required = false});
    rules.push_back({.path = "/etc/localtime", .access = LandlockAccess::read_only, .required = false});

    return rules;
}

auto apply_worker_landlock(std::vector<LandlockPathRule> const& rules, bool allow_without_landlock,
                           LandlockHardeningOps const& ops) -> LandlockHardeningResult
{
#ifdef __linux__
    auto const abi = ops.query_abi_version();
    if (abi < 1)
    {
        if (allow_without_landlock)
        {
            return {.accepted = true,
                    .applied = false,
                    .critical_warning = true,
                    .reason = "Landlock filesystem restriction is unavailable on this kernel (ABI query returned " +
                              std::to_string(abi) +
                              "); continuing WITHOUT a filesystem sandbox because "
                              "federation.worker.allow_without_landlock=true. A worker compromised through a "
                              "memory-safety bug can open any file this process's Unix permissions allow, "
                              "including the operator master key and TLS private keys."};
        }
        return {.accepted = false,
                .applied = false,
                .critical_warning = false,
                .reason = "Landlock filesystem restriction is unavailable on this kernel (ABI query returned " +
                          std::to_string(abi) +
                          "; requires Linux 5.13+ with Landlock enabled). Set "
                          "federation.worker.allow_without_landlock=true to run without it (logs CRITICAL on "
                          "every start), or upgrade the kernel / enable Landlock "
                          "(CONFIG_SECURITY_LANDLOCK=y and, if the lsm= boot parameter is set, include "
                          "\"landlock\" in it)."};
    }

    auto const bounded_abi = std::min(abi, k_landlock_max_known_abi);
    auto ruleset_fd = core::FileDescriptor{ops.create_ruleset(landlock_handled_access_fs(bounded_abi))};
    if (!ruleset_fd.valid())
    {
        return {.accepted = false,
                .applied = false,
                .critical_warning = false,
                .reason = "landlock_create_ruleset() failed despite Landlock ABI " + std::to_string(abi) +
                          " being available on this kernel -- this is always fatal, independent of "
                          "federation.worker.allow_without_landlock"};
    }

    for (auto const& rule : rules)
    {
        auto const outcome = ops.add_rule(ruleset_fd.get(), rule.path, access_rights_for(rule.access, bounded_abi));
        if (outcome == LandlockAddRuleOutcome::success)
        {
            continue;
        }
        if (outcome == LandlockAddRuleOutcome::path_unavailable && !rule.required)
        {
            continue;
        }
        return {.accepted = false,
                .applied = false,
                .critical_warning = false,
                .reason = "failed to add Landlock rule for path '" + rule.path +
                          "' -- this is always fatal, independent of federation.worker.allow_without_landlock"};
    }

    if (!ops.restrict_self(ruleset_fd.get()))
    {
        return {.accepted = false,
                .applied = false,
                .critical_warning = false,
                .reason = "landlock_restrict_self() failed -- this is always fatal, independent of "
                          "federation.worker.allow_without_landlock"};
    }

    return {.accepted = true, .applied = true, .critical_warning = false, .reason = {}};
#else
    std::ignore = rules;
    if (allow_without_landlock)
    {
        return {.accepted = true,
                .applied = false,
                .critical_warning = true,
                .reason = "Landlock is a Linux-only control; this platform has no in-process filesystem sandbox "
                          "for the federation worker, and federation.worker.allow_without_landlock=true accepts "
                          "that."};
    }
    return {.accepted = false,
            .applied = false,
            .critical_warning = false,
            .reason = "Landlock is a Linux-only control; this platform cannot satisfy the federation worker's "
                      "filesystem restriction. Set federation.worker.allow_without_landlock=true to run without "
                      "it."};
#endif
}

} // namespace merovingian::platform
