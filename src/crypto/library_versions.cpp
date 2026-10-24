// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/library_versions.hpp"

#include "merovingian/core/library_version.hpp"

#include <vector>

#include <sodium.h>

namespace merovingian::crypto
{

auto library_versions() -> std::vector<core::LibraryVersion>
{
    // sodium_version_string() returns libsodium's own copy of the string, so its address says
    // which object libsodium lives in.
    auto const* const running = ::sodium_version_string();
    return {core::describe_library("libsodium", running, SODIUM_VERSION_STRING, running)};
}

} // namespace merovingian::crypto
