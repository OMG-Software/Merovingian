// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/events/EventParseResult.hpp"
#include "merovingian/events/limits.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::events
{

[[nodiscard]] auto matrix_id_is_valid(std::string_view id, char sigil) noexcept -> bool;
[[nodiscard]] auto event_type_is_valid(std::string_view type) noexcept -> bool;
// Shared admission rule for incoming and locally composed state keys. Empty
// keys and ordinary Unicode remain valid; escaped NUL in content is unrelated.
[[nodiscard]] auto state_key_contains_nul(std::string_view state_key) noexcept -> bool;
[[nodiscard]] auto parse_event_envelope(canonicaljson::Value const& json) -> EventParseResult;

} // namespace merovingian::events
