// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/library_version.hpp"

#include <vector>

namespace merovingian::crypto
{

// libsodium, as linked into this executable. Reported here because only crypto (and the modules
// ADR-0014 names) may call libsodium.
[[nodiscard]] auto library_versions() -> std::vector<core::LibraryVersion>;

} // namespace merovingian::crypto
