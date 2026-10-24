// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/library_version.hpp"

#include <vector>

namespace merovingian::http
{

// libcurl, as linked into this executable.
[[nodiscard]] auto library_versions() -> std::vector<core::LibraryVersion>;

} // namespace merovingian::http
