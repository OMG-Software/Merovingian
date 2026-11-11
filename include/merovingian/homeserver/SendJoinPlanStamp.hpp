// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>

namespace merovingian::homeserver
{

// What a cached SendJoinPlanBase was built from (ADR-0624). A base is reused only while every field is equal.
struct SendJoinPlanStamp final
{
    // database::room_state_revision: moves on every write to the room's current state and every event rewrite.
    std::uint64_t state_revision{0U};
    // The room's current state rows, so that a writer which removes a row is noticed even if it moves no revision.
    std::size_t state_rows{0U};
    std::size_t roster_size{0U};
    // The caps a `sizes_only` verdict was judged against.
    std::uint64_t max_body_bytes{0U};
    std::uint64_t max_frame_bytes{0U};

    [[nodiscard]] auto operator==(SendJoinPlanStamp const&) const noexcept -> bool = default;
};

} // namespace merovingian::homeserver
