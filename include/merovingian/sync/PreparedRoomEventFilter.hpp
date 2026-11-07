// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/RoomFilter.hpp"

#include <cstddef>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace merovingian::sync
{

// A RoomFilter's room, type and sender lists, prepared once so that judging an event does not depend on
// how long the lists are. `room_passes_filter` and `event_passes_filter` scan their lists for every event;
// that suits a /sync filter judged against a handful of events, not a /search that judges every event of
// every room the user has been in with lists a client sized (security audit run 2, F-30; ADR-0332).
// Rooms and senders become hash sets; `types` and `not_types` become a hash set of exact types and a
// sorted list of the `prefix*` patterns with any pattern covered by a shorter one dropped (so at most one
// can match an event type, found by binary search); a pattern with a `*` before its last character is kept
// whole and judged by `type_pattern_matches`. Answers are those of `room_passes_filter` and
// `event_passes_filter` for the same RoomFilter (its `timeline` lists), entry for entry.
class PreparedRoomEventFilter final
{
public:
    explicit PreparedRoomEventFilter(RoomFilter const& filter);

    [[nodiscard]] auto room_passes(std::string_view room_id) const noexcept -> bool;
    [[nodiscard]] auto event_passes(std::string_view event_type, std::string_view sender) const noexcept -> bool;

private:
    struct StringHash final
    {
        using is_transparent = void;
        [[nodiscard]] auto operator()(std::string_view text) const noexcept -> std::size_t
        {
            return std::hash<std::string_view>{}(text);
        }
    };
    using StringSet = std::unordered_set<std::string, StringHash, std::equal_to<>>;

    // The patterns of one `types` or `not_types` list.
    struct TypePatterns final
    {
        // False for an empty list, which restricts nothing.
        bool any{false};
        StringSet exact{};
        // Sorted; none is a prefix of another.
        std::vector<std::string> prefixes{};
        // Patterns with a '*' before their last character; scanned one by one.
        std::vector<std::string> globs{};

        explicit TypePatterns(std::vector<std::string> const& patterns);
        [[nodiscard]] auto matches(std::string_view event_type) const noexcept -> bool;
    };

    StringSet rooms_;
    StringSet not_rooms_;
    StringSet senders_;
    StringSet not_senders_;
    TypePatterns types_;
    TypePatterns not_types_;
};

} // namespace merovingian::sync
