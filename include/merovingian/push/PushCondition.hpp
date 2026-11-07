// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/push/PushConditionKind.hpp"

#include <optional>
#include <string>

namespace merovingian::push
{

// One condition of an `override`/`underride` push rule. Field usage depends
// on `kind`:
//   event_match                     -> key, pattern
//   contains_display_name           -> (none)
//   room_member_count               -> is
//   sender_notification_permission  -> key
//   event_property_is               -> key, value
//   event_property_contains         -> key, value
struct PushCondition final
{
    PushConditionKind kind{PushConditionKind::unknown};
    std::string key{};
    std::string pattern{};
    std::string is{};
    // Only set when the parsed rule provided a `value` member. Per spec,
    // "A non-compound canonical JSON value" — i.e. string, integer, boolean,
    // or null; an absent `value` (missing from a malformed rule) leaves this
    // empty and the condition fails closed (never matches).
    std::optional<canonicaljson::Value> value{};
};

} // namespace merovingian::push
