// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentStateGroupStateEntry.hpp"
#include "merovingian/database/StateGroupKeyHash.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace merovingian::database
{

// The last state a room's forward extremities resolved to, so a PDU that leaves the set of distinct state groups
// unchanged (a message, say) does not resolve it again (ADR-0600). State groups are immutable and resolution is a pure
// function of them and of the events they name, so a hit returns exactly what resolving would.
//
// In memory only, never persisted. One entry per room, at most `max_rooms` rooms and `max_rows` rows in all, the least
// recently used room evicted first. No lock and no `mutable` (ADR-0525): `find` is non-const because a hit refreshes
// the room's recency, and every caller holds `runtime.mutex`.
class ResolvedStateMemo final
{
public:
    using Entries = std::vector<PersistentStateGroupStateEntry>;
    using size_type = std::size_t;

    static constexpr size_type max_rooms = 256U;
    // A row is one state entry or one group ID of a key. As many as one resolution may submit.
    static constexpr size_type max_rows = 131'072U;

    // The entries remembered for exactly this room, context and sorted group IDs, or nullptr. Valid until the memo is
    // next changed. `context` names everything else the result depends on (the room version and the limits).
    [[nodiscard]] auto find(std::string_view room_id, std::string_view context,
                            std::vector<std::string> const& sorted_group_ids) -> Entries const*;
    // Replaces the room's entry. A result too large for the memo is not kept, and the room's old entry goes with it.
    auto remember(std::string_view room_id, std::string_view context, std::vector<std::string> sorted_group_ids,
                  Entries entries) -> void;
    // Drops the room's entry: an event in its groups has changed (a redaction, a status change) or been reloaded.
    auto forget_room(std::string_view room_id) -> void;
    auto clear() noexcept -> void;

    [[nodiscard]] auto rooms() const noexcept -> size_type
    {
        return by_room_.size();
    }
    [[nodiscard]] auto rows() const noexcept -> size_type
    {
        return rows_;
    }

private:
    struct Entry final
    {
        std::string context{};
        std::vector<std::string> sorted_group_ids{};
        Entries entries{};
        std::uint64_t last_used{0U};
    };

    [[nodiscard]] static auto rows_of(Entry const& entry) noexcept -> size_type;
    auto evict_least_recently_used() -> void;

    std::unordered_map<std::string, Entry, detail::StateGroupKeyHash, std::equal_to<>> by_room_{};
    size_type rows_{0U};
    std::uint64_t clock_{0U};
};

} // namespace merovingian::database
