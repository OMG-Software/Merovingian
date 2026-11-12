// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/SlidingSyncRequestLookups.hpp"

#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Value.hpp"

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <string>
#include <utility>
#include <variant>

namespace merovingian::sync
{
namespace
{

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

    [[nodiscard]] auto as_object(canonicaljson::Value const& v) noexcept -> canonicaljson::Object const*
    {
        return std::get_if<canonicaljson::Object>(&v.storage());
    }

    [[nodiscard]] auto as_string(canonicaljson::Value const& v) noexcept -> std::string const*
    {
        return std::get_if<std::string>(&v.storage());
    }

    [[nodiscard]] auto as_array(canonicaljson::Value const& v) noexcept -> canonicaljson::Array const*
    {
        return std::get_if<canonicaljson::Array>(&v.storage());
    }

    // content.type of the event with `event_id`, or empty when it is absent or malformed.
    [[nodiscard]] auto create_event_type(database::PersistentStore const& store, std::string const& event_id)
        -> std::string
    {
        for (auto const& ev : store.events.with_id(event_id))
        {
            auto const parsed = canonicaljson::parse_lossless(ev.json);
            if (parsed.error != canonicaljson::ParseError::none)
            {
                return {};
            }
            auto const* root = as_object(parsed.value);
            auto const* content_val = root == nullptr ? nullptr : find_member(*root, "content");
            auto const* content = content_val == nullptr ? nullptr : as_object(*content_val);
            auto const* type_val = content == nullptr ? nullptr : find_member(*content, "type");
            auto const* type = type_val == nullptr ? nullptr : as_string(*type_val);
            return type != nullptr ? *type : std::string{};
        }
        return {};
    }

    // True when the event's "type" is one of `types`.
    [[nodiscard]] auto event_type_is_one_of(std::string_view event_json, std::vector<std::string> const& types) -> bool
    {
        auto const parsed = canonicaljson::parse_lossless(event_json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return false;
        }
        auto const* root = as_object(parsed.value);
        auto const* type_val = root == nullptr ? nullptr : find_member(*root, "type");
        auto const* type = type_val == nullptr ? nullptr : as_string(*type_val);
        return type != nullptr && std::ranges::find(types, *type) != types.end();
    }

    // content.name of an m.room.name event, or empty when it has none.
    [[nodiscard]] auto room_name_from_event(std::string_view event_json) -> std::string
    {
        auto const parsed = canonicaljson::parse_lossless(event_json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return {};
        }
        auto const* root = as_object(parsed.value);
        auto const* content_val = root == nullptr ? nullptr : find_member(*root, "content");
        auto const* content = content_val == nullptr ? nullptr : as_object(*content_val);
        auto const* name_val = content == nullptr ? nullptr : find_member(*content, "name");
        auto const* name = name_val == nullptr ? nullptr : as_string(*name_val);
        return name != nullptr ? *name : std::string{};
    }

    // The bump types as one string that no other list of types shares.
    [[nodiscard]] auto bump_key(std::vector<std::string> const& types) -> std::string
    {
        auto key = std::string{};
        for (auto const& type : types)
        {
            key += std::to_string(type.size()) + ':' + type;
        }
        return key;
    }

} // namespace

SlidingSyncRequestLookups::SlidingSyncRequestLookups(database::PersistentStore const& store, std::string_view user)
    : m_store{&store}
    , m_user{user}
{
}

auto SlidingSyncRequestLookups::load_memberships() -> void
{
    if (m_memberships_loaded)
    {
        return;
    }
    m_memberships_loaded = true;
    // The rooms the store holds a record for, once: a membership row of a room the store lacks is not a joined room.
    auto known_rooms = std::unordered_set<std::string>{};
    known_rooms.reserve(m_store->rooms.size());
    for (auto const& room : m_store->rooms)
    {
        known_rooms.insert(room.room_id);
    }
    // The user's own rows through the per-user index (ADR-0609), never the table.
    database::for_each_user_membership_row(*m_store, m_user, [&](database::PersistentMembership const& row) {
        ++m_membership_rows_visited;
        if (row.membership == "join" && known_rooms.contains(row.room_id))
        {
            m_joined.push_back(row.room_id);
        }
        else if (row.membership == "invite")
        {
            m_invited.insert(row.room_id);
        }
    });
}

auto SlidingSyncRequestLookups::joined_rooms() -> std::vector<std::string> const&
{
    load_memberships();
    return m_joined;
}

auto SlidingSyncRequestLookups::is_invited(std::string_view room_id) -> bool
{
    load_memberships();
    return m_invited.contains(std::string{room_id});
}

auto SlidingSyncRequestLookups::is_encrypted(std::string_view room_id) const -> bool
{
    // The room's current state by its index (ADR-0344): no scan of the state table.
    return database::find_current_state_event_id(*m_store, room_id, "m.room.encryption", "").has_value();
}

auto SlidingSyncRequestLookups::load_direct() -> void
{
    if (m_direct_loaded)
    {
        return;
    }
    m_direct_loaded = true;
    auto const content = database::find_account_data_content(*m_store, m_user, std::string_view{}, "m.direct");
    if (!content.has_value())
    {
        return;
    }
    // m.direct content: { "@user:server": ["!room:server", ...], ... }
    // Account data is never signed and may hold fractional numbers: general parser.
    auto const parsed = canonicaljson::parse_json(*content);
    auto const* root = parsed.error == canonicaljson::ParseError::none ? as_object(parsed.value) : nullptr;
    if (root == nullptr)
    {
        return;
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
            if (auto const* s = as_string(item); s != nullptr)
            {
                m_direct.insert(*s);
            }
        }
    }
}

auto SlidingSyncRequestLookups::is_dm(std::string_view room_id) -> bool
{
    load_direct();
    return m_direct.contains(std::string{room_id});
}

auto SlidingSyncRequestLookups::is_favourite(std::string_view room_id) -> bool
{
    auto const key = std::string{room_id};
    if (auto const found = m_favourites.find(key); found != m_favourites.end())
    {
        return found->second;
    }
    auto favourite = false;
    if (auto const content = database::find_account_data_content(*m_store, m_user, room_id, "m.tag");
        content.has_value())
    {
        // m.tag content may contain non-canonical doubles such as order:0.5.
        auto const parsed = canonicaljson::parse_json(*content);
        auto const* root = parsed.error == canonicaljson::ParseError::none ? as_object(parsed.value) : nullptr;
        auto const* tags_val = root == nullptr ? nullptr : find_member(*root, "tags");
        auto const* tags = tags_val == nullptr ? nullptr : as_object(*tags_val);
        favourite = tags != nullptr && find_member(*tags, "m.favourite") != nullptr;
    }
    m_favourites.emplace(key, favourite);
    return favourite;
}

auto SlidingSyncRequestLookups::room_type(std::string_view room_id) -> std::string const&
{
    auto const key = std::string{room_id};
    if (auto const found = m_room_types.find(key); found != m_room_types.end())
    {
        return found->second;
    }
    auto type = std::string{};
    if (auto const create = database::find_current_state_event_id(*m_store, room_id, "m.room.create", "");
        create.has_value())
    {
        type = create_event_type(*m_store, *create);
    }
    return m_room_types.emplace(key, std::move(type)).first->second;
}

auto SlidingSyncRequestLookups::read_markers(std::string_view room_id) -> ReadMarkers const&
{
    auto const key = std::string{room_id};
    if (auto const found = m_markers.find(key); found != m_markers.end())
    {
        return found->second;
    }
    // Only the user's own rows in this room, through the receipt index (ADR-0651): never a pass over the table.
    auto markers = read_markers_for(*m_store, room_id, m_user);
    return m_markers.emplace(key, std::move(markers)).first->second;
}

auto SlidingSyncRequestLookups::recency(std::string_view room_id, std::vector<std::string> const& bump_types)
    -> std::uint64_t
{
    auto& per_room = m_recency[bump_key(bump_types)];
    auto const key = std::string{room_id};
    if (auto const found = per_room.find(key); found != per_room.end())
    {
        return found->second;
    }
    // The room's own rows (ADR-0435), newest first; the first whose type is wanted is the room's newest such event.
    auto const rows = m_store->events.room_in_stream_order(room_id);
    auto result = std::uint64_t{0U};
    if (rows.begin() != rows.end())
    {
        auto const newest = (*std::ranges::prev(rows.end())).stream_ordering;
        if (bump_types.empty())
        {
            result = newest;
        }
        else
        {
            auto examined = std::size_t{0U};
            for (auto row = rows.end(); row != rows.begin();)
            {
                --row;
                if (examined == max_recency_rows_examined)
                {
                    // Budget spent: the room's newest event stands in, as the unfiltered key would (ADR-0666).
                    result = newest;
                    break;
                }
                ++examined;
                ++m_recency_rows_visited;
                if (event_type_is_one_of((*row).json, bump_types))
                {
                    result = (*row).stream_ordering;
                    break;
                }
            }
        }
    }
    per_room.emplace(key, result);
    return result;
}

auto SlidingSyncRequestLookups::room_name(std::string_view room_id) -> std::string const&
{
    auto const key = std::string{room_id};
    if (auto const found = m_names.find(key); found != m_names.end())
    {
        return found->second;
    }
    auto name = std::string{};
    if (auto const event_id = database::find_current_state_event_id(*m_store, room_id, "m.room.name", "");
        event_id.has_value())
    {
        for (auto const& event : m_store->events.with_id(*event_id))
        {
            name = room_name_from_event(event.json);
            break;
        }
    }
    return m_names.emplace(key, std::move(name)).first->second;
}

auto SlidingSyncRequestLookups::recency_rows_visited() const noexcept -> std::uint64_t
{
    return m_recency_rows_visited;
}

auto SlidingSyncRequestLookups::membership_rows_visited() const noexcept -> std::uint64_t
{
    return m_membership_rows_visited;
}

} // namespace merovingian::sync
