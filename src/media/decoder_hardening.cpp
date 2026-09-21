// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/media/decoder_hardening.hpp"

#include "merovingian/platform/seccomp_hardening.hpp"

#include <sys/resource.h>

#if defined(__linux__)
#include <sys/prctl.h>
#elif defined(__OpenBSD__)
#include <unistd.h>
#elif defined(__FreeBSD__)
#include <sys/capsicum.h>
#endif

namespace merovingian::media
{
namespace
{

    // Resource ceilings the worker imposes on itself regardless of the
    // request, so a malformed frame or hostile image cannot exhaust the
    // host. Values match the historical constants that used to live in
    // thumbnail_worker_main.cpp.
    constexpr std::uint64_t max_address_space = 768ULL * 1024ULL * 1024ULL; // 768 MiB RSS+heap
    constexpr std::uint64_t max_file_size = 64ULL * 1024ULL * 1024ULL;      // 64 MiB
    constexpr std::uint64_t max_open_files = 16ULL;

    [[nodiscard]] auto max_cpu_seconds(bool sanitizer_build) noexcept -> std::uint64_t
    {
        if (sanitizer_build)
        {
            // ASan/TSan/MSan are much slower under CI QEMU emulation.
            return 120ULL;
        }
#if defined(NDEBUG)
        return 15ULL;
#else
        return 60ULL;
#endif
    }

    [[nodiscard]] auto real_set_resource_limit(int resource, std::uint64_t value) noexcept -> bool
    {
        auto limit = rlimit{static_cast<rlim_t>(value), static_cast<rlim_t>(value)};
        return ::setrlimit(resource, &limit) == 0;
    }

#if defined(__linux__)
    [[nodiscard]] auto real_disable_core_dumps() noexcept -> bool
    {
        return ::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0;
    }

    [[nodiscard]] auto real_set_no_new_privs() noexcept -> bool
    {
        return ::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0;
    }

    [[nodiscard]] auto real_apply_seccomp_filter() noexcept -> bool
    {
        return merovingian::platform::apply_decoder_seccomp_filter();
    }
#elif defined(__OpenBSD__)
    [[nodiscard]] auto real_apply_pledge() noexcept -> bool
    {
        return ::pledge("stdio", nullptr) == 0;
    }
#elif defined(__FreeBSD__)
    [[nodiscard]] auto real_apply_capsicum() noexcept -> bool
    {
        return ::cap_enter() == 0;
    }
#endif

} // namespace

DecoderHardeningOps::DecoderHardeningOps()
    : set_resource_limit(real_set_resource_limit)
#if defined(__linux__)
    , disable_core_dumps(real_disable_core_dumps)
    , set_no_new_privs(real_set_no_new_privs)
    , apply_seccomp_filter(real_apply_seccomp_filter)
#elif defined(__OpenBSD__)
    , apply_pledge(real_apply_pledge)
#elif defined(__FreeBSD__)
    , apply_capsicum(real_apply_capsicum)
#endif
{
}

auto decoder_hardening_is_sanitizer_build() noexcept -> bool
{
#if defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer) || __has_feature(memory_sanitizer)
    return true;
#else
    return false;
#endif
#elif defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
    return true;
#else
    return false;
#endif
}

auto apply_decoder_hardening(DecoderHardeningOps const& ops) -> DecoderHardeningResult
{
    auto const sanitizer_build = decoder_hardening_is_sanitizer_build();

    if (!sanitizer_build)
    {
        // Sanitizer builds reserve a large virtual address space for shadow
        // memory that a tight RLIMIT_AS would make un-mmap-able; the
        // instrumented worker would die before decoding. Skipped here (CI
        // only) — production builds always keep the cap.
        if (!ops.set_resource_limit(RLIMIT_AS, max_address_space))
        {
            return {.accepted = false, .failed_control = "setrlimit(RLIMIT_AS)"};
        }
    }
    if (!ops.set_resource_limit(RLIMIT_CPU, max_cpu_seconds(sanitizer_build)))
    {
        return {.accepted = false, .failed_control = "setrlimit(RLIMIT_CPU)"};
    }
    if (!ops.set_resource_limit(RLIMIT_FSIZE, max_file_size))
    {
        return {.accepted = false, .failed_control = "setrlimit(RLIMIT_FSIZE)"};
    }
    if (!ops.set_resource_limit(RLIMIT_CORE, 0ULL))
    {
        return {.accepted = false, .failed_control = "setrlimit(RLIMIT_CORE)"};
    }
    if (!ops.set_resource_limit(RLIMIT_NOFILE, max_open_files))
    {
        return {.accepted = false, .failed_control = "setrlimit(RLIMIT_NOFILE)"};
    }

#if defined(__linux__)
    if (!ops.disable_core_dumps())
    {
        return {.accepted = false, .failed_control = "prctl(PR_SET_DUMPABLE)"};
    }
    if (!ops.set_no_new_privs())
    {
        return {.accepted = false, .failed_control = "prctl(PR_SET_NO_NEW_PRIVS)"};
    }
    if (!sanitizer_build)
    {
        // M-08: this installs the DECODER profile, not the general server
        // filter and not the federation-worker filter — see
        // docs/hardening.md, "Thumbnail worker sandbox", and
        // seccomp_hardening.hpp. The seccomp-bpf allowlist is incompatible
        // with sanitizer runtimes, which need syscalls the decoder profile
        // denies (shadow memory, error reporting, /proc access), so it is
        // skipped in sanitizer builds so the worker can run under
        // ASan/UBSan/TSan.
        if (!ops.apply_seccomp_filter())
        {
            return {.accepted = false, .failed_control = "apply_decoder_seccomp_filter"};
        }
    }
#elif defined(__OpenBSD__)
    // "stdio" covers read/write on already-open descriptors, memory
    // allocation and clock reads — everything libpng and libjpeg-turbo need
    // once the request is being decoded. It grants no filesystem, socket,
    // exec or process-creation access, so a decoder exploit has nothing to
    // reach for.
    if (!ops.apply_pledge())
    {
        return {.accepted = false, .failed_control = "pledge"};
    }
#elif defined(__FreeBSD__)
    // Capability mode: the process keeps the descriptors it already holds
    // and loses the global namespaces entirely — no open(2) by path, no
    // socket(2), no exec. Same shape as the pledge above.
    if (!ops.apply_capsicum())
    {
        return {.accepted = false, .failed_control = "cap_enter"};
    }
#endif

    return {.accepted = true, .failed_control = {}};
}

} // namespace merovingian::media
