// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/platform/LandlockHardeningOps.hpp"

#include "merovingian/core/FileDescriptor.hpp"
#include "merovingian/platform/LandlockAddRuleOutcome.hpp"
#include "merovingian/platform/LandlockHardening.hpp"

#include <cstdint>
#include <string>

#ifdef __linux__
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>

#if __has_include(<linux/landlock.h>)
#include <linux/landlock.h>
#define MEROVINGIAN_HAVE_LINUX_LANDLOCK_H 1
#endif
#endif // __linux__

namespace merovingian::platform
{

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
// __NR_faccessat2 pattern in SeccompHardening.cpp for builds against older
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

    // Landlock ABI 6 (Linux 6.10) scope: signals only within the domain. The
    // kernel headers may not define it yet, so it is named here. Declared only
    // where the real ruleset is built, which is the only place it is used; on
    // other platforms an unused constant is an error under -Werror.
    constexpr std::uint64_t k_scope_signal = 1ULL << 1U;

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

} // namespace merovingian::platform
