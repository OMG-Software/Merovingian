// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentInvite.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace merovingian::database
{

// DB-4: the `membership` row, and the change to the user's invite metadata, that
// an m.room.member event implies. Passed with the event to store_event_with_state
// (or prepare_store_event_with_state) so the event, its current_state row, the
// membership row and the invite change commit in ONE transaction: a ban can never
// be durable while the row still says join. The invite change follows the
// membership: "invite" writes `invite` (when given), and so does "knock", whose
// `invite` is the knock on a room on another server and the knock_room_state it
// was answered with (ADR-0243); "join", "leave" and "ban" delete the user's invite
// metadata; anything else leaves it alone. Readers of the record must check the
// user's membership before treating it as an invite.
struct MembershipProjection final
{
    std::string user_id{};
    std::string membership{};
    std::uint64_t stream_ordering{0U};
    std::optional<PersistentInvite> invite{};
};

} // namespace merovingian::database
