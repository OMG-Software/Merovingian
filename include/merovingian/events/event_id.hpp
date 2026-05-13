// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace merovingian::events
{

struct EventIdResult final
{
    std::string event_id{};
    std::string error{};
};

[[nodiscard]] auto event_id_is_valid(std::string_view event_id) noexcept -> bool;
[[nodiscard]] auto make_content_hash_id(canonicaljson::Value const& event) -> EventIdResult;

} // namespace merovingian::events
