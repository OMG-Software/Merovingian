// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <filesystem>
#include <stdexcept>
#include <string>

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

} // namespace merovingian::tests
