// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/sliding_sync_room_list.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace merovingian::sync
{
namespace
{

    // ── JSON helpers (local, minimal set) ──────────────────────────────────

    [[nodiscard]] auto find_member(canonicaljson::Object const& obj, std::string_view key) noexcept
        -> canonicaljson::Value const*
    {
        for (auto const& m : obj)
        {
            if (m.key == key)
            {
                return m.value.get();
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto as_object(canonicaljson::Value const& v) noexcept
        -> canonicaljson::Object const*
    {
        return std::get_if<canonicaljson::Object>(&v.storage());
    }

    [[nodiscard]] auto as_string(canonicaljson::Value const& v) noexcept -> std::string const*
    {
        return std::get_if<std::string>(&v.storage());
    }

    [[nodiscard]] auto as_array(canonicaljson::Value const& v) noexcept
        -> canonicaljson::Array const*
    {
        return std::get_if<canonicaljson::Array>(&v.storage());
    }

    // ── Filter helpers ─────────────────────────────────────────────────────

    // True when the room has an m.room.encryption state event.
    [[nodiscard]] auto room_is_encrypted(database::PersistentStore const& store,
                                         std::string_view room_id) noexcept -> bool
    {
        return std::ranges::any_of(store.state, [&](database::PersistentStateEvent const& s) {
            return s.room_id == room_id && s.event_type == "m.room.encryption";
        });
    }

    // True when user has an invite membership in the room.
    [[nodiscard]] auto user_is_invited(database::PersistentStore const& store,
                                       std::string_view room_id,
                                       std::string_view user) noexcept -> bool
    {
        return std::ranges::any_of(store.memberships, [&](database::PersistentMembership const& m) {
            return m.room_id == room_id && m.user_id == user && m.membership == "invite";
        });
    }

    // True when room_id appears in the user's m.direct global account-data.
    [[nodiscard]] auto room_is_dm(database::PersistentStore const& store,
                                  std::string_view room_id,
                                  std::string_view user) noexcept -> bool
    {
        for (auto const& ad : store.account_data)
        {
            if (ad.user_id != user || !ad.room_id.empty() || ad.event_type != "m.direct")
            {
                continue;
            }
            // m.direct content: { "@user:server": ["!room:server", ...], ... }
            auto const parsed = canonicaljson::parse_lossless(ad.content_json);
            if (parsed.error != canonicaljson::ParseError::none)
            {
                continue;
            }
            auto const* root = as_object(parsed.value);
            if (root == nullptr)
            {
                continue;
            }
            for (auto const& member : *root)
            {
                auto const* arr = as_array(*member.value);
                if (arr == nullptr)
                {
                    continue;
                }
                for (auto const& item : *arr)
                {
                    if (auto const* s = as_string(item); s != nullptr && *s == room_id)
                    {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    // True when room_id is tagged m.favourite in the user's room account-data.
    [[nodiscard]] auto room_is_favourite(database::PersistentStore const& store,
                                         std::string_view room_id,
                                         std::string_view user) noexcept -> bool
    {
        for (auto const& ad : store.account_data)
        {
            if (ad.user_id != user || ad.room_id != room_id || ad.event_type != "m.tag")
            {
                continue;
            }
            auto const parsed = canonicaljson::parse_lossless(ad.content_json);
            if (parsed.error != canonicaljson::ParseError::none)
            {
                continue;
            }
            auto const* root = as_object(parsed.value);
            if (root == nullptr)
            {
                continue;
            }
            auto const* tags_val = find_member(*root, "tags");
            if (tags_val == nullptr)
            {
                continue;
            }
            auto const* tags = as_object(*tags_val);
            if (tags == nullptr)
            {
                continue;
            }
            if (find_member(*tags, "m.favourite") != nullptr)
            {
                return true;
            }
        }
        return false;
    }

    // Returns the value of m.room.create content.type, or "" if absent.
    [[nodiscard]] auto room_type(database::PersistentStore const& store,
                                 std::string_view room_id) -> std::string
    {
        for (auto const& se : store.state)
        {
            if (se.room_id != room_id || se.event_type != "m.room.create")
            {
                continue;
            }
            // Find the event JSON for this state entry.
            for (auto const& ev : store.events)
            {
                if (ev.event_id != se.event_id)
                {
                    continue;
                }
                auto const parsed = canonicaljson::parse_lossless(ev.json);
                if (parsed.error != canonicaljson::ParseError::none)
                {
                    return {};
                }
                auto const* root = as_object(parsed.value);
                if (root == nullptr)
                {
                    return {};
                }
                auto const* content_val = find_member(*root, "content");
                if (content_val == nullptr)
                {
                    return {};
                }
                auto const* content = as_object(*content_val);
                if (content == nullptr)
                {
                    return {};
                }
                auto const* type_val = find_member(*content, "type");
                if (type_val == nullptr)
                {
                    return {};
                }
                auto const* s = as_string(*type_val);
                return s != nullptr ? *s : std::string{};
            }
        }
        return {};
    }

    [[nodiscard]] auto passes_filters(database::PersistentStore const& store,
                                      std::string_view room_id,
                                      std::string_view user,
                                      SlidingSyncFilters const& f) -> bool
    {
        if (f.is_encrypted.has_value())
        {
            if (room_is_encrypted(store, room_id) != *f.is_encrypted)
            {
                return false;
            }
        }
        if (f.is_invite.has_value())
        {
            if (user_is_invited(store, room_id, user) != *f.is_invite)
            {
                return false;
            }
        }
        if (f.is_dm.has_value())
        {
            if (room_is_dm(store, room_id, user) != *f.is_dm)
            {
                return false;
            }
        }
        if (f.is_favourite.has_value())
        {
            if (room_is_favourite(store, room_id, user) != *f.is_favourite)
            {
                return false;
            }
        }
        if (!f.room_types.empty() || !f.not_room_types.empty())
        {
            auto const type = room_type(store, room_id);
            if (!f.room_types.empty())
            {
                auto const match = std::ranges::any_of(f.room_types,
                                                       [&](std::string const& t) { return t == type; });
                if (!match)
                {
                    return false;
                }
            }
            if (!f.not_room_types.empty())
            {
                auto const match = std::ranges::any_of(f.not_room_types,
                                                       [&](std::string const& t) { return t == type; });
                if (match)
                {
                    return false;
                }
            }
        }
        return true;
    }

    // ── Sort key helpers ───────────────────────────────────────────────────

    // Maximum stream_ordering among events in the room whose type is in
    // bump_types (or all events when bump_types is empty).
    [[nodiscard]] auto recency_key(database::PersistentStore const& store,
                                   std::string_view room_id,
                                   std::vector<std::string> const& bump_types) noexcept -> std::uint64_t
    {
        auto max = std::uint64_t{0U};
        for (auto const& ev : store.events)
        {
            if (ev.room_id != room_id)
            {
                continue;
            }
            if (!bump_types.empty())
            {
                // Only bump on types the client asked for — requires parsing the event type.
                auto const parsed = canonicaljson::parse_lossless(ev.json);
                if (parsed.error != canonicaljson::ParseError::none)
                {
                    continue;
                }
                auto const* root = as_object(parsed.value);
                if (root == nullptr)
                {
                    continue;
                }
                auto const* type_val = find_member(*root, "type");
                if (type_val == nullptr)
                {
                    continue;
                }
                auto const* type_s = as_string(*type_val);
                if (type_s == nullptr)
                {
                    continue;
                }
                auto const bumps = std::ranges::any_of(bump_types,
                                                       [&](std::string const& t) { return t == *type_s; });
                if (!bumps)
                {
                    continue;
                }
            }
            if (ev.stream_ordering > max)
            {
                max = ev.stream_ordering;
            }
        }
        return max;
    }

    // Total number of unread m.room.message / m.room.encrypted events in the
    // room since the user's last m.read receipt.
    [[nodiscard]] auto notification_key(database::PersistentStore const& store,
                                        std::string_view room_id,
                                        std::string_view user) noexcept -> std::uint64_t
    {
        // Find the stream_ordering of the user's last read receipt in the room.
        // TODO: scan store.receipts filtered by user to find the true read_ordering.
        auto read_ordering = std::uint64_t{0U};
        std::ignore = user;
        for (auto const& ev : store.events)
        {
            if (ev.room_id != room_id)
            {
                continue;
            }
            std::ignore = ev;
        }

        auto count = std::uint64_t{0U};
        for (auto const& ev : store.events)
        {
            if (ev.room_id != room_id || ev.stream_ordering <= read_ordering)
            {
                continue;
            }
            auto const parsed = canonicaljson::parse_lossless(ev.json);
            if (parsed.error != canonicaljson::ParseError::none)
            {
                continue;
            }
            auto const* root = as_object(parsed.value);
            if (root == nullptr)
            {
                continue;
            }
            auto const* type_val = find_member(*root, "type");
            auto const* type_s   = type_val != nullptr ? as_string(*type_val) : nullptr;
            if (type_s == nullptr)
            {
                continue;
            }
            if (*type_s == "m.room.message" || *type_s == "m.room.encrypted")
            {
                ++count;
            }
        }
        return count;
    }

    [[nodiscard]] auto room_display_name(database::PersistentStore const& store,
                                         std::string_view room_id) -> std::string
    {
        for (auto const& se : store.state)
        {
            if (se.room_id != room_id || se.event_type != "m.room.name")
            {
                continue;
            }
            for (auto const& ev : store.events)
            {
                if (ev.event_id != se.event_id)
                {
                    continue;
                }
                auto const parsed = canonicaljson::parse_lossless(ev.json);
                if (parsed.error != canonicaljson::ParseError::none)
                {
                    return {};
                }
                auto const* root = as_object(parsed.value);
                if (root == nullptr)
                {
                    return {};
                }
                auto const* content_val = find_member(*root, "content");
                if (content_val == nullptr)
                {
                    return {};
                }
                auto const* content = as_object(*content_val);
                if (content == nullptr)
                {
                    return {};
                }
                auto const* name_val = find_member(*content, "name");
                if (name_val == nullptr)
                {
                    return {};
                }
                auto const* s = as_string(*name_val);
                return s != nullptr ? *s : std::string{};
            }
        }
        return {};
    }

    // ── Ops generation ─────────────────────────────────────────────────────

    // Build the windowed room IDs for the given ranges from the full sorted list.
    [[nodiscard]] auto window_rooms(std::vector<std::string> const& sorted,
                                    std::vector<SlidingSyncRange> const& ranges)
        -> std::vector<std::string>
    {
        auto out = std::vector<std::string>{};
        for (auto const& range : ranges)
        {
            auto const start = static_cast<std::size_t>(range.start);
            auto const end   = static_cast<std::size_t>(range.end);
            for (auto i = start; i <= end && i < sorted.size(); ++i)
            {
                out.push_back(sorted[i]);
            }
        }
        return out;
    }

    // Emit SYNC ops covering all requested ranges.
    [[nodiscard]] auto make_sync_ops(std::vector<std::string> const& sorted,
                                     std::vector<SlidingSyncRange> const& ranges)
        -> std::vector<SlidingSyncOp>
    {
        auto ops = std::vector<SlidingSyncOp>{};
        for (auto const& range : ranges)
        {
            auto op      = SlidingSyncOp{};
            op.op        = "SYNC";
            op.range     = range;
            auto const start = static_cast<std::size_t>(range.start);
            auto const end   = static_cast<std::size_t>(range.end);
            for (auto i = start; i <= end && i < sorted.size(); ++i)
            {
                op.room_ids.push_back(sorted[i]);
            }
            ops.push_back(std::move(op));
        }
        return ops;
    }

} // namespace

auto compute_room_list(homeserver::HomeserverRuntime const& rt,
                       std::string_view                     user,
                       SlidingSyncList const&               list,
                       std::vector<std::string> const&      prev_window,
                       database::PersistentStore const&     store) -> RoomListResult
{
    // Step 1 — enumerate rooms where the user is joined.
    auto joined_room_ids = std::vector<std::string>{};
    for (auto const& room : rt.database.rooms)
    {
        auto const joined = std::ranges::any_of(store.memberships,
                                                [&](database::PersistentMembership const& m) {
                                                    return m.room_id == room.room_id &&
                                                           m.user_id == user &&
                                                           m.membership == "join";
                                                });
        if (joined)
        {
            joined_room_ids.push_back(room.room_id);
        }
    }

    // Step 2 — apply filters.
    if (list.filters.has_value())
    {
        auto const& f = *list.filters;
        std::erase_if(joined_room_ids, [&](std::string const& room_id) {
            return !passes_filters(store, room_id, user, f);
        });
    }

    auto const total_count = static_cast<std::uint64_t>(joined_room_ids.size());

    // Step 3 — sort.
    // Sort keys are applied left-to-right; ties fall through to the next key.
    std::stable_sort(joined_room_ids.begin(), joined_room_ids.end(),
                     [&](std::string const& a, std::string const& b) {
                         for (auto const& key : list.sort)
                         {
                             if (key == "by_notification_count")
                             {
                                 auto const na = notification_key(store, a, user);
                                 auto const nb = notification_key(store, b, user);
                                 if (na != nb)
                                 {
                                     return na > nb;  // descending
                                 }
                             }
                             else if (key == "by_recency")
                             {
                                 auto const ra = recency_key(store, a, list.bump_event_types);
                                 auto const rb = recency_key(store, b, list.bump_event_types);
                                 if (ra != rb)
                                 {
                                     return ra > rb;  // most-recent first
                                 }
                             }
                             else if (key == "by_name")
                             {
                                 auto const na = room_display_name(store, a);
                                 auto const nb = room_display_name(store, b);
                                 // Unnamed rooms sort last.
                                 if (na.empty() != nb.empty())
                                 {
                                     return !na.empty();
                                 }
                                 if (na != nb)
                                 {
                                     return na < nb;
                                 }
                             }
                         }
                         // Final tie-break: room_id lexicographic (stable).
                         return a < b;
                     });

    // Step 4 — window and generate ops.
    auto const current_window = window_rooms(joined_room_ids, list.ranges);
    auto ops                  = std::vector<SlidingSyncOp>{};

    if (prev_window.empty())
    {
        // Initial request for this list: emit SYNC for all ranges.
        ops = make_sync_ops(joined_room_ids, list.ranges);
    }
    else
    {
        // Incremental: emit SYNC only for ranges whose contents changed.
        auto prev_offset = std::size_t{0U};
        for (auto const& range : list.ranges)
        {
            auto const start = static_cast<std::size_t>(range.start);
            auto const end   = static_cast<std::size_t>(range.end);
            auto const len   = end >= start ? (end - start + 1U) : 0U;

            // Slice of current window for this range.
            auto current_slice = std::vector<std::string>{};
            for (auto i = start; i <= end && i < joined_room_ids.size(); ++i)
            {
                current_slice.push_back(joined_room_ids[i]);
            }

            // Corresponding slice of the previous window.
            auto prev_slice = std::vector<std::string>{};
            for (auto i = prev_offset; i < prev_offset + len && i < prev_window.size(); ++i)
            {
                prev_slice.push_back(prev_window[i]);
            }
            prev_offset += len;

            if (current_slice != prev_slice)
            {
                auto op      = SlidingSyncOp{};
                op.op        = "SYNC";
                op.range     = range;
                op.room_ids  = current_slice;
                ops.push_back(std::move(op));
            }
        }
    }

    return RoomListResult{total_count, current_window, std::move(ops)};
}

} // namespace merovingian::sync
