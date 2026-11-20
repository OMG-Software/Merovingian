// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/RequiredStateConfig.hpp"
#include "merovingian/sync/SlidingSyncFilters.hpp"
#include "merovingian/sync/SlidingSyncRange.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace merovingian::sync
{

// MSC4186 §lists[*] — one named room list with windowing and sort criteria.
struct SlidingSyncList final
{
    std::vector<SlidingSyncRange> ranges{};
    // The request gave neither `range` nor `ranges`: MSC4186 "SyncListConfig", "If this field is missing, the room list
    // is not limited by range (i.e. includes all rooms that match the filter)".
    bool whole_list{false};
    // Sort order: "by_recency", "by_notification_count", "by_name" (applied left-to-right).
    std::vector<std::string> sort{};
    // Each pair is [event_type, state_key]; "*" is a wildcard for either component.
    // The MSC3575 form, kept for clients that send it ("$LAZY" and "$ME" are sentinels there).
    std::vector<std::pair<std::string, std::string>> required_state{};
    // The MSC4186 form (`{include, exclude, lazy_members}`), at most one entry for a parsed request (ADR-0865).
    std::vector<RequiredStateConfig> required_state_configs{};
    std::uint64_t timeline_limit{20U};
    std::optional<SlidingSyncFilters> filters{};
    bool include_heroes{false};
    // Only events whose type appears here advance a room's recency position.
    // Empty means all event types count.
    std::vector<std::string> bump_event_types{};

    // Compared with the config a list was last computed under: a list that is new or changed may
    // window rooms its previous window lacks (see SlidingSyncConnectionState::list_configs).
    [[nodiscard]] auto operator==(SlidingSyncList const&) const -> bool = default;
};

} // namespace merovingian::sync
