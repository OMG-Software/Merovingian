// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace merovingian::database
{

// The state group that holds the state before an event whose prev_events name exactly these distinct state groups, so
// a later event naming the same groups reads that group instead of resolving them again and storing the result again
// (ADR-0694). State groups are immutable and resolution is a pure function of them, of the events they name and of the
// room version and limits (`context`), so a hit names exactly the state resolving would give.
//
// In memory only, never persisted: a restart resolves each set of groups once more. At most `max_entries` entries, the
// oldest dropped first. No lock and no `mutable` (ADR-0525): `find` is const and changes nothing, and every caller
// holds `runtime.mutex`.
class StateBeforeMemo final
{
public:
    using size_type = std::size_t;

    static constexpr size_type max_entries = 1024U;

    // The group remembered for exactly this room, context and sorted distinct group IDs, or nullptr. Valid until the
    // memo is next changed.
    [[nodiscard]] auto find(std::string_view room_id, std::string_view context,
                            std::vector<std::string> const& sorted_group_ids) const -> std::string const*;
    // Remembers `state_group_id` for the key, replacing what was there.
    auto remember(std::string_view room_id, std::string_view context, std::vector<std::string> const& sorted_group_ids,
                  std::string state_group_id) -> void;
    // Drops the room's entries: an event in their groups has changed (a redaction, a status change) or been reloaded.
    auto forget_room(std::string_view room_id) -> void;
    auto clear() noexcept -> void;

    [[nodiscard]] auto size() const noexcept -> size_type
    {
        return entries_.size();
    }

private:
    struct Entry final
    {
        std::string room_id{};
        std::string state_group_id{};
        std::uint64_t sequence{0U};
    };

    [[nodiscard]] static auto key_of(std::string_view room_id, std::string_view context,
                                     std::vector<std::string> const& sorted_group_ids) -> std::string;

    std::unordered_map<std::string, Entry> entries_{};
    // Insertion order, oldest first: sequence -> key.
    std::map<std::uint64_t, std::string> order_{};
    std::uint64_t next_sequence_{0U};
};

} // namespace merovingian::database
