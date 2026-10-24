// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/library_version.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::canonicaljson
{

// yyjson, as linked into this executable.
[[nodiscard]] auto library_versions() -> std::vector<core::LibraryVersion>;

// yyjson_version()'s packed 0xMMmmpp as "major.minor.patch".
[[nodiscard]] auto format_yyjson_version(std::uint32_t version) -> std::string;

} // namespace merovingian::canonicaljson
