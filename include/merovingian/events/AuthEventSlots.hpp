// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string_view>

namespace merovingian::events
{

// What decides which slots of an AuthEventMap a state event fills, for the event being judged.
struct AuthEventSlots final
{
    std::string_view sender{};
    std::string_view target_state_key{};
    std::string_view event_type{};
    std::string_view third_party_invite_token{};
    // A join's content.join_authorised_via_users_server (join_authorising_user). The authorising
    // server's signature is verified before any of this, on every ingestion path (ADR-0171); the
    // map only lets the membership and power checks run.
    std::string_view authorising_user{};
};

} // namespace merovingian::events
