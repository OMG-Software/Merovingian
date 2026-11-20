// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace merovingian::sync
{

// One element of an MSC4186 `RequiredStateRequest`'s `include` or `exclude`. MSC4186: `type` "If omitted then matches
// all types", `state_key` "If omitted then matches all state keys". A field that is present matches only its own value:
// the object form has no wildcard string, so `{"state_key":"*"}` names the state key "*" and nothing else. Only the
// legacy [type, state_key] pair form reads "*" as "any" (ADR-0865).
struct RequiredStateElement final
{
    std::optional<std::string> type{};
    std::optional<std::string> state_key{};

    [[nodiscard]] auto operator==(RequiredStateElement const&) const -> bool = default;

    // Whether the element matches a state entry.
    [[nodiscard]] auto matches(std::string_view event_type, std::string_view key) const noexcept -> bool
    {
        return (!type.has_value() || *type == event_type) && (!state_key.has_value() || *state_key == key);
    }

    // Whether the element can match an `m.room.member` event: it names that type or no type.
    [[nodiscard]] auto may_name_members() const noexcept -> bool
    {
        return !type.has_value() || *type == "m.room.member";
    }
};

} // namespace merovingian::sync
