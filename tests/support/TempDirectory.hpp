// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <format>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>

namespace merovingian::tests
{

// Return a writable directory suitable for test scratch files.
//
// This helper wraps std::filesystem::temp_directory_path() with a fallback
// chain so that tests keep working on restricted CI runners where the
// platform default temp directory is missing or not a directory (e.g. some
// OpenBSD VM images report "/tmp" as not-a-directory).  The primary behavior
// is still the standard temp directory; the fallbacks are only used when that
// directory is unusable.
[[nodiscard]] inline auto temporary_directory() -> std::filesystem::path
{
    auto const is_usable = [](std::filesystem::path const& candidate) {
        try
        {
            return std::filesystem::is_directory(candidate);
        }
        catch (...)
        {
            return false;
        }
    };

    try
    {
        auto const primary = std::filesystem::temp_directory_path();
        if (is_usable(primary))
        {
            return primary;
        }
    }
    catch (...)
    {
        // Fall through to the fallback chain.
    }

    // Prefer a system-wide volatile directory, then the build directory.
    for (auto const* raw : {"/var/tmp", "/tmp", "/var/run"})
    {
        std::filesystem::path const candidate{raw};
        if (is_usable(candidate))
        {
            return candidate;
        }
    }

    try
    {
        auto const cwd = std::filesystem::current_path();
        if (is_usable(cwd))
        {
            return cwd;
        }
    }
    catch (...)
    {
        // Deliberately ignored; current_path() failing is caught below.
    }

    throw std::runtime_error{"merovingian::tests::temporary_directory: no usable temporary directory found"};
}

// Return a path under temporary_directory() that no other test, process or
// account uses: <stem>-<pid>-<counter>-<random><extension>. The file is not
// created. A fixed name in the shared temporary directory is not safe: a file
// another account left there cannot be overwritten (sticky /tmp), so the write
// fails and the test reads that run's stale file, and two suites running at
// once overwrite each other's files (ADR-0753).
[[nodiscard]] inline auto unique_temporary_path(std::string_view stem, std::string_view extension)
    -> std::filesystem::path
{
    static auto counter = std::atomic<std::uint64_t>{0U};
    auto device = std::random_device{};
    auto const random_bits = (static_cast<std::uint64_t>(device()) << 32U) | static_cast<std::uint64_t>(device());
    auto const sequence = counter.fetch_add(1U, std::memory_order_relaxed);
    return temporary_directory() /
           std::format("{}-{}-{}-{:016x}{}", stem, ::getpid(), sequence, random_bits, extension);
}

} // namespace merovingian::tests
