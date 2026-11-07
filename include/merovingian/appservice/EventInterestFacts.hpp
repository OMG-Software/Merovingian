// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <span>
#include <string>
#include <string_view>

namespace merovingian::appservice
{

// What the interest test knows about one event in one room. Every view must
// outlive the call.
struct EventInterestFacts final
{
    std::string_view room_id{};
    // Every alias the room has on this server (a room may have several); empty when it has none.
    std::span<std::string const> room_aliases{};
    std::string_view sender{};
    // The state_key of an `m.room.member` event, i.e. the user the membership change is about
    // (the invitee of an invite, the user kicked or banned). Empty for any other event.
    std::string_view member_event_target{};
    // Every user CURRENTLY joined to the room (the sender, if already a member, should be
    // included by the caller — the test does not special-case it against `sender`).
    std::span<std::string const> room_members{};
};

} // namespace merovingian::appservice
