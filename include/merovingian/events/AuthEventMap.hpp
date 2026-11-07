// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"

#include <string>

namespace merovingian::events
{

struct AuthEventMap final
{
    canonicaljson::Value create{};
    // The event ID is stored separately from the signed PDU JSON. Callers that
    // build this map from persistent state must preserve the authoritative ID
    // for the create event so first-join authorization can verify prev_events.
    std::string create_event_id{};
    canonicaljson::Value power_levels{};
    canonicaljson::Value join_rules{};
    canonicaljson::Value sender_member{};
    canonicaljson::Value target_member{};
    canonicaljson::Value authorising_user_member{};
    canonicaljson::Value third_party_invite{};
};

} // namespace merovingian::events
