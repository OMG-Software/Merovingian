// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/platform/landlock_hardening.hpp"

#include "merovingian/config/config.hpp"
#include "merovingian/core/file_descriptor.hpp"

#include <algorithm>
#include <filesystem>
#include <system_error>
#include <tuple>
#include <utility>

#ifdef __linux__
#include <cerrno>
#include <cstddef>

#include <fcntl.h>
#include <sys/stat.h>
#if defined(__linux__)
#include <sys/prctl.h>
#endif
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
    // Landlock ABI 6 (Linux 6.10) scopes. The kernel headers may not define
    // these yet, so use local names and let <linux/landlock.h> override when present.
    constexpr std::uint64_t k_scope_signal = 1ULL << 1U;

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

auto landlock_access_for_inode(std::uint64_t requested, bool is_directory) noexcept -> std::uint64_t
{
    if (is_directory)
    {
        return requested;
    }
    constexpr auto file_level_access =
        k_access_fs_execute | k_access_fs_write_file | k_access_fs_read_file | k_access_fs_truncate;
    return requested & file_level_access;
}

#ifdef __linux__
// Used only when a ruleset is built, which is Linux-only; defining it
// elsewhere trips -Wunused-function under -Werror (FreeBSD, NetBSD).
namespace
{

    [[nodiscard]] auto access_rights_for(LandlockAccess access, int abi) noexcept -> std::uint64_t
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
#endif // __linux__

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

    // Independent ruleset attribute with the ABI-6 scoped member. The runtime
    // kernel is asked for the ABI version first, so we can pass the correct size
    // for that ABI; the layout always matches the kernel's current definition.
    struct RulesetAttr
    {
        std::uint64_t handled_access_fs;
        std::uint64_t handled_access_net;
        std::uint64_t scoped;
    };
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

    [[nodiscard]] auto real_create_ruleset(std::uint64_t handled_access_fs, int abi) -> int
    {
        // Value-initialise, then set the fields this code knows. Newer kernel
        // headers add members (quiet_access_*), which a designated initializer
        // would have to name to satisfy -Wmissing-field-initializers, and the
        // kernel requires every byte it does not understand to be zero.
        auto attr = RulesetAttr{};
        attr.handled_access_fs = handled_access_fs;
        attr.handled_access_net = 0U;
        // ISO-2: when Landlock ABI 6+ is available, scope signal delivery so a
        // compromised worker cannot target processes outside its own sandbox.
        if (abi >= 6)
        {
            attr.scoped = k_scope_signal;
        }
        // Pass the size the target ABI understands. Older kernels reject a
        // larger attribute, so do not include the scoped member unless ABI 6+.
        auto const attr_size = (abi >= 6) ? sizeof(RulesetAttr) : offsetof(RulesetAttr, scoped);
        return static_cast<int>(::syscall(__NR_landlock_create_ruleset, &attr, attr_size, 0U));
    }

#else

    [[nodiscard]] auto real_query_abi_version() -> int
    {
        errno = ENOSYS;
        return -1;
    }

    [[nodiscard]] auto real_create_ruleset(std::uint64_t /*handled_access_fs*/, int /*abi*/) -> int
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

        // fstat works on an O_PATH fd. A rule on a non-directory may only
        // carry file-level rights; asking for READ_DIR on /etc/resolv.conf is
        // EINVAL, which failed every allowlisted regular file.
        struct stat path_stat{};
        if (::fstat(path_fd.get(), &path_stat) != 0)
        {
            return LandlockAddRuleOutcome::path_unavailable;
        }
        auto const access = landlock_access_for_inode(allowed_access, S_ISDIR(path_stat.st_mode));
        auto const attr = PathBeneathAttr{.allowed_access = access, .parent_fd = path_fd.get()};
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

    [[nodiscard]] auto real_set_no_new_privs() -> bool
    {
#if defined(__linux__)
        return ::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0; // NOLINT(*-vararg)
#else
        return false;
#endif
    }

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
    , set_no_new_privs{real_set_no_new_privs}
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
    //
    // Deliberately NOT the whole of /etc/ssl or /etc/pki: those trees hold the
    // conventional TLS private-key directories (/etc/ssl/private,
    // /etc/pki/tls/private). Only the certificate stores themselves, the
    // OpenSSL config files, and the directories Debian's /etc/ssl/certs
    // symlinks resolve into are granted.
    for (auto const* path :
         {"/etc/ssl/certs", "/etc/ssl/cert.pem", "/etc/ssl/ca-bundle.pem", "/etc/ssl/openssl.cnf", "/etc/pki/tls/certs",
          "/etc/pki/ca-trust", "/etc/pki/tls/openssl.cnf", "/usr/share/ca-certificates",
          "/usr/local/share/ca-certificates", "/usr/local/share/certs", "/etc/openssl/certs", "/etc/openssl/cert.pem",
          "/usr/pkg/etc/openssl/certs", "/usr/pkg/etc/openssl/cert.pem"})
    {
        rules.push_back({.path = path, .access = LandlockAccess::read_only, .required = false});
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

auto worker_landlock_secret_paths(config::Config const& config) -> std::vector<std::string>
{
    auto paths = std::vector<std::string>{};
    for (auto const* path :
         {&config.security().secrets.master_key_file, &config.listeners().client.tls_private_key_file,
          &config.listeners().federation.tls_private_key_file, &config.database().uri_file,
          &config.federation_worker().database_uri_file, &config.security().registration.token_file})
    {
        if (!path->empty())
        {
            paths.push_back(*path);
        }
    }
    return paths;
}

namespace
{
    // Resolves symlinks for the portion of `path` that exists, so that a
    // symlinked rule or secret cannot hide an overlap; falls back to a
    // lexical normalisation if resolution fails.
    [[nodiscard]] auto canonical_for_coverage(std::string const& path) -> std::filesystem::path
    {
        auto error = std::error_code{};
        auto resolved = std::filesystem::weakly_canonical(std::filesystem::path{path}, error);
        if (error)
        {
            resolved = std::filesystem::path{path}.lexically_normal();
        }
        return resolved;
    }

    // True when `ancestor` equals `path` or is a directory above it, compared
    // component by component (so /etc/merov does not cover /etc/merovingian).
    [[nodiscard]] auto path_covers(std::filesystem::path const& ancestor, std::filesystem::path const& path) -> bool
    {
        auto ancestor_it = ancestor.begin();
        auto path_it = path.begin();
        for (; ancestor_it != ancestor.end(); ++ancestor_it, ++path_it)
        {
            // A trailing empty component comes from a trailing separator.
            if (ancestor_it->empty())
            {
                continue;
            }
            if (path_it == path.end() || *ancestor_it != *path_it)
            {
                return false;
            }
        }
        return true;
    }
} // namespace

auto find_landlock_rule_covering_secret(std::vector<LandlockPathRule> const& rules,
                                        std::vector<std::string> const& secret_paths)
    -> std::optional<LandlockSecretExposure>
{
    for (auto const& secret : secret_paths)
    {
        auto const secret_path = canonical_for_coverage(secret);
        for (auto const& rule : rules)
        {
            if (path_covers(canonical_for_coverage(rule.path), secret_path))
            {
                return LandlockSecretExposure{.rule_path = rule.path, .secret_path = secret};
            }
        }
    }
    return std::nullopt;
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
    auto ruleset_fd = core::FileDescriptor{ops.create_ruleset(landlock_handled_access_fs(bounded_abi), abi)};
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

    // The kernel refuses landlock_restrict_self() with EPERM unless
    // no_new_privs is set or the caller has CAP_SYS_ADMIN. The worker's own
    // seccomp step sets it too, but later and only when apply_hardening is
    // on, so set it here, immediately before it is needed. The worker never
    // execs (seccomp denies execve), so this costs it nothing.
    if (!ops.set_no_new_privs())
    {
        return {.accepted = false,
                .applied = false,
                .critical_warning = false,
                .reason = "prctl(PR_SET_NO_NEW_PRIVS) failed before landlock_restrict_self() -- this is always "
                          "fatal, independent of federation.worker.allow_without_landlock"};
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
    std::ignore = ops;
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
