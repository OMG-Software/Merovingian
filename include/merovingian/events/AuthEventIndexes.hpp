// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/events/IndexedAuthEvent.hpp"

#include <string_view>

namespace merovingian::events
{

// The auth events one event is judged against, each already read into an index (ADR-0693). The slots are those of
// AuthEventMap; a null slot is an absent auth event. Nothing is copied: the indexes and the events they borrow must
// outlive the authorisation that reads them.
struct AuthEventIndexes final
{
    IndexedAuthEvent const* create{nullptr};
    // The create event's ID, kept apart from its JSON as in AuthEventMap.
    std::string_view create_event_id{};
    IndexedAuthEvent const* power_levels{nullptr};
    IndexedAuthEvent const* join_rules{nullptr};
    IndexedAuthEvent const* sender_member{nullptr};
    IndexedAuthEvent const* target_member{nullptr};
    IndexedAuthEvent const* authorising_user_member{nullptr};
    IndexedAuthEvent const* third_party_invite{nullptr};
};

} // namespace merovingian::events
