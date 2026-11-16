// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// Module-internal helper shared by the oauth sources; not intended as public API.

#include <string>
#include <string_view>

namespace merovingian::oauth
{

// `text` with `A-Z` mapped to `a-z` and every other byte unchanged. No locale is consulted.
[[nodiscard]] auto ascii_lower(std::string_view text) -> std::string;

} // namespace merovingian::oauth
