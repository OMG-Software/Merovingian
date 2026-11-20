// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/SlidingSyncRequestLookups.hpp"

#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/database/PersistentInvite.hpp"
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/sync/RoomReadAccess.hpp"
#include "merovingian/sync/RoomReadKind.hpp"

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <string>
#include <string_view>
#include <unordered_set>
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

    // content.<member> of an event, when it is a string; empty otherwise.
    [[nodiscard]] auto content_string(std::string_view event_json, std::string_view member) -> std::string
    {
        auto const parsed = canonicaljson::parse_lossless(event_json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return {};
        }
        auto const* root = as_object(parsed.value);
        auto const* content_val = root == nullptr ? nullptr : find_member(*root, "content");
        auto const* content = content_val == nullptr ? nullptr : as_object(*content_val);
        auto const* value_val = content == nullptr ? nullptr : find_member(*content, member);
        auto const* value = value_val == nullptr ? nullptr : as_string(*value_val);
        return value != nullptr ? *value : std::string{};
    }

    // content.name of an m.room.name event, or empty when it has none.
    [[nodiscard]] auto room_name_from_event(std::string_view event_json) -> std::string
    {
        return content_string(event_json, "name");
    }

    // The JSON of the state event of `type` with an empty state_key in the user's invite record of `room_id`, or
    // nullptr: what the invite's stripped state says about the room, which is all a user only invited may be told
    // (ADR-0864). The record is bounded in bytes per user (ADR-0619, ADR-0708) and read by reference.
    [[nodiscard]] auto invite_state_event(database::PersistentStore const& store, std::string_view room_id,
                                          std::string_view user, std::string_view type) -> std::string const*
    {
        auto const* invite = database::find_invite_row(store, room_id, user);
        if (invite == nullptr)
        {
            return nullptr;
        }
        for (auto const& event_json : invite->invite_state_events_json)
        {
            auto const parsed = canonicaljson::parse_lossless(event_json);
            auto const* root = parsed.error == canonicaljson::ParseError::none ? as_object(parsed.value) : nullptr;
            auto const* type_val = root == nullptr ? nullptr : find_member(*root, "type");
            auto const* key_val = root == nullptr ? nullptr : find_member(*root, "state_key");
            auto const* event_type = type_val == nullptr ? nullptr : as_string(*type_val);
            auto const* state_key = key_val == nullptr ? nullptr : as_string(*key_val);
            if (event_type != nullptr && *event_type == type && state_key != nullptr && state_key->empty())
            {
                return &event_json;
            }
        }
        return nullptr;
    }

    // The JSON of the summary state event of `type` (empty state key) a user invited to or knocking on `room_id` is
    // told about, from the source its `stripped_state` is built from (`build_knock_state_events_array`): the user's
    // invite record when it has one (an invite, or a knock on a room on another server, ADR-0243), else, for a knock on
    // a room this server holds, the room's current state. A local knock has no invite record, and reading the record
    // alone left its `is_encrypted`, `room_types` and name empty (PR #608 review).
    [[nodiscard]] auto stripped_summary_event(database::PersistentStore const& store, std::string_view room_id,
                                              std::string_view user, std::string_view type, bool knocked)
        -> std::string const*
    {
        if (database::find_invite_row(store, room_id, user) != nullptr || !knocked)
        {
            return invite_state_event(store, room_id, user, type);
        }
        auto const event_id = database::find_current_state_event_id(store, room_id, type, "");
        if (!event_id.has_value())
        {
            return nullptr;
        }
        auto const found = store.events.find(*event_id);
        return found != store.events.end() ? &found->json : nullptr;
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
    // The user's own rows through the per-user index (ADR-0609), never the table. Which joined rooms the store holds
    // is settled by `joined_rooms` alone, so an invite lookup (the long-poll's wake check) never reads the room table.
    database::for_each_user_membership_row(*m_store, m_user, [&](database::PersistentMembership const& row) {
        ++m_membership_rows_visited;
        if (row.membership == "join")
        {
            m_join_rows.push_back(row.room_id);
        }
        else if (row.membership == "invite")
        {
            m_invited.insert_or_assign(row.room_id, row.stream_ordering);
        }
        else if (row.membership == "knock")
        {
            m_knocked.insert_or_assign(row.room_id, row.stream_ordering);
        }
        else if (row.membership == "leave" || row.membership == "ban")
        {
            m_departure_rows.insert_or_assign(row.room_id, std::pair{row.stream_ordering, row.membership});
        }
    });
}

auto SlidingSyncRequestLookups::knocked_rooms() -> std::vector<std::string>
{
    load_memberships();
    auto rooms = std::vector<std::string>{};
    rooms.reserve(m_knocked.size());
    for (auto const& entry : m_knocked)
    {
        rooms.push_back(entry.first);
    }
    return rooms;
}

auto SlidingSyncRequestLookups::is_knocked(std::string_view room_id) -> bool
{
    load_memberships();
    return m_knocked.contains(std::string{room_id});
}

auto SlidingSyncRequestLookups::include_departed_rooms(std::unordered_set<std::string> const& previously_sent,
                                                       std::unordered_set<std::string> const& ignored_senders) -> void
{
    load_memberships();
    m_departed.clear();
    for (auto const& [room_id, row] : m_departure_rows)
    {
        // The member event that ended the stay, by the state index. A rejected remote invite's leave is an outlier with
        // no state row, and counts as leaving of the user's own accord.
        auto sender = std::string{};
        if (auto const member = database::find_current_state_event_id(*m_store, room_id, "m.room.member", m_user);
            member.has_value())
        {
            if (auto const event = m_store->events.find(*member); event != m_store->events.end())
            {
                sender = event->sender_user_id;
            }
        }
        auto const by_another = !sender.empty() && sender != m_user;
        auto const banned = row.second == "ban";
        auto const sent_before = previously_sent.contains(room_id);
        if (!banned && !by_another && !sent_before)
        {
            continue;
        }
        // "Rooms the user has been banned from, but never joined, should not be part of the list", nor a kick of a
        // room never joined or sent that an ignored user sent. Only these few ask the room's membership rows.
        auto const ignored_kick = by_another && !sent_before && ignored_senders.contains(sender);
        if ((banned || ignored_kick) && room_read_access_for(*m_store, room_id, m_user).kind == RoomReadKind::none)
        {
            continue;
        }
        m_departed.emplace(room_id, row);
    }
}

auto SlidingSyncRequestLookups::departed_rooms() -> std::vector<std::string>
{
    auto rooms = std::vector<std::string>{};
    rooms.reserve(m_departed.size());
    for (auto const& entry : m_departed)
    {
        rooms.push_back(entry.first);
    }
    return rooms;
}

auto SlidingSyncRequestLookups::departed_membership(std::string_view room_id) -> std::string_view
{
    auto const found = m_departed.find(std::string{room_id});
    return found == m_departed.end() ? std::string_view{} : std::string_view{found->second.second};
}

auto SlidingSyncRequestLookups::is_unjoined(std::string_view room_id) -> bool
{
    return is_invited(room_id) || is_knocked(room_id) || m_departed.contains(std::string{room_id});
}

auto SlidingSyncRequestLookups::joined_rooms() -> std::vector<std::string> const&
{
    load_memberships();
    if (m_joined_resolved)
    {
        return m_joined;
    }
    m_joined_resolved = true;
    // A join row of a room the store lacks is not a joined room. One pass over the room table, matched against the
    // user's own join rows: nothing is copied per room the user is not in.
    auto const wanted = std::unordered_set<std::string_view>{m_join_rows.begin(), m_join_rows.end()};
    auto held = std::unordered_set<std::string_view>{};
    for (auto const& room : m_store->rooms)
    {
        ++m_room_rows_visited;
        if (wanted.contains(room.room_id))
        {
            held.insert(room.room_id);
        }
    }
    for (auto& room_id : m_join_rows)
    {
        if (held.contains(room_id))
        {
            m_joined.push_back(std::move(room_id));
        }
    }
    m_join_rows.clear();
    return m_joined;
}

auto SlidingSyncRequestLookups::invited_rooms() -> std::vector<std::string>
{
    load_memberships();
    auto rooms = std::vector<std::string>{};
    rooms.reserve(m_invited.size());
    for (auto const& entry : m_invited)
    {
        rooms.push_back(entry.first);
    }
    return rooms;
}

auto SlidingSyncRequestLookups::is_invited(std::string_view room_id) -> bool
{
    load_memberships();
    return m_invited.contains(std::string{room_id});
}

auto SlidingSyncRequestLookups::withhold_invite(std::string_view room_id) -> void
{
    load_memberships();
    m_invited.erase(std::string{room_id});
}

auto SlidingSyncRequestLookups::is_encrypted(std::string_view room_id) -> bool
{
    if (is_invited(room_id) || is_knocked(room_id))
    {
        return stripped_summary_event(*m_store, room_id, m_user, "m.room.encryption", is_knocked(room_id)) != nullptr;
    }
    // The room's current state by its index (ADR-0344): no scan of the state table.
    auto const encryption = database::find_current_state_event_id(*m_store, room_id, "m.room.encryption", "");
    if (auto const departed = m_departed.find(std::string{room_id}); departed != m_departed.end())
    {
        // Nothing after the departure is the user's to learn (ADR-0867).
        if (!encryption.has_value())
        {
            return false;
        }
        auto const event = m_store->events.find(*encryption);
        return event != m_store->events.end() && event->stream_ordering <= departed->second.first;
    }
    return encryption.has_value();
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
    return room_tags(room_id).contains("m.favourite");
}

auto SlidingSyncRequestLookups::room_tags(std::string_view room_id) -> std::unordered_set<std::string> const&
{
    auto const key = std::string{room_id};
    if (auto const found = m_tags.find(key); found != m_tags.end())
    {
        return found->second;
    }
    auto tags = std::unordered_set<std::string>{};
    if (auto const content = database::find_account_data_content(*m_store, m_user, room_id, "m.tag");
        content.has_value())
    {
        // m.tag content may contain non-canonical doubles such as order:0.5.
        auto const parsed = canonicaljson::parse_json(*content);
        auto const* root = parsed.error == canonicaljson::ParseError::none ? as_object(parsed.value) : nullptr;
        auto const* tags_val = root == nullptr ? nullptr : find_member(*root, "tags");
        if (auto const* tag_map = tags_val == nullptr ? nullptr : as_object(*tags_val); tag_map != nullptr)
        {
            for (auto const& member : *tag_map)
            {
                tags.insert(member.key);
            }
        }
    }
    return m_tags.emplace(key, std::move(tags)).first->second;
}

auto SlidingSyncRequestLookups::space_children(std::string_view space_id) -> std::unordered_set<std::string> const&
{
    auto const key = std::string{space_id};
    if (auto const found = m_space_children.find(key); found != m_space_children.end())
    {
        return found->second;
    }
    auto children = std::unordered_set<std::string>{};
    load_memberships();
    // MSC4186 `spaces`: "The server will inspect the `m.space.child` state events for the JOINED space room IDs given";
    // an unknown space, or one the user is not joined to, names no room. Only direct children count, and a child
    // event without a non-empty `via` is not a child (CS API "m.space.child"). Joined is read from the user's own join
    // rows until `joined_rooms` has settled them, so a lookup that never lists the joined rooms (the long poll's invite
    // check) still finds the space, and reads no room table: a join row of a room the store lacks has no state rows,
    // so it names no child either way (PR #608 review).
    auto const& joined = m_joined_resolved ? m_joined : m_join_rows;
    if (std::ranges::find(joined, key) != joined.end())
    {
        database::for_each_room_state_row(*m_store, space_id, [&](database::PersistentStateEvent const& row) {
            if (row.event_type != "m.space.child" || row.state_key.empty())
            {
                return;
            }
            auto const event = m_store->events.find(row.event_id);
            if (event == m_store->events.end())
            {
                return;
            }
            auto const parsed = canonicaljson::parse_json(event->json);
            auto const* root = parsed.error == canonicaljson::ParseError::none ? as_object(parsed.value) : nullptr;
            auto const* content_val = root == nullptr ? nullptr : find_member(*root, "content");
            auto const* content = content_val == nullptr ? nullptr : as_object(*content_val);
            auto const* via_val = content == nullptr ? nullptr : find_member(*content, "via");
            auto const* via = via_val == nullptr ? nullptr : std::get_if<canonicaljson::Array>(&via_val->storage());
            if (via != nullptr && !via->empty())
            {
                children.insert(row.state_key);
            }
        });
    }
    return m_space_children.emplace(key, std::move(children)).first->second;
}

auto SlidingSyncRequestLookups::room_type(std::string_view room_id) -> std::string const&
{
    auto const key = std::string{room_id};
    if (auto const found = m_room_types.find(key); found != m_room_types.end())
    {
        return found->second;
    }
    auto type = std::string{};
    if (is_invited(room_id) || is_knocked(room_id))
    {
        if (auto const* create =
                stripped_summary_event(*m_store, room_id, m_user, "m.room.create", is_knocked(room_id));
            create != nullptr)
        {
            type = content_string(*create, "type");
        }
    }
    else if (auto const create = database::find_current_state_event_id(*m_store, room_id, "m.room.create", "");
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
    // Only the user's own rows in this room, through the receipt index (ADR-0737): never a pass over the table.
    auto markers = read_markers_for(*m_store, room_id, m_user);
    return m_markers.emplace(key, std::move(markers)).first->second;
}

auto SlidingSyncRequestLookups::recency(std::string_view room_id, std::vector<std::string> const& bump_types)
    -> std::uint64_t
{
    load_memberships();
    // An invited room's bump stamp is the invite's position (ADR-0864): its events are not the user's to rank by. So
    // is a knocked or departed room's (MSC4186 `bump_stamp`: "when the relevant membership happened", ADR-0867).
    if (auto const invited = m_invited.find(std::string{room_id}); invited != m_invited.end())
    {
        return invited->second;
    }
    if (auto const knocked = m_knocked.find(std::string{room_id}); knocked != m_knocked.end())
    {
        return knocked->second;
    }
    if (auto const departed = m_departed.find(std::string{room_id}); departed != m_departed.end())
    {
        return departed->second.first;
    }
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
    if (is_invited(room_id) || is_knocked(room_id))
    {
        if (auto const* event = stripped_summary_event(*m_store, room_id, m_user, "m.room.name", is_knocked(room_id));
            event != nullptr)
        {
            name = room_name_from_event(*event);
        }
    }
    // A departed room's `by_name` key is empty: its name now may postdate the departure (ADR-0867).
    else if (m_departed.contains(key))
    {
        name.clear();
    }
    else if (auto const event_id = database::find_current_state_event_id(*m_store, room_id, "m.room.name", "");
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

auto SlidingSyncRequestLookups::room_rows_visited() const noexcept -> std::uint64_t
{
    return m_room_rows_visited;
}

} // namespace merovingian::sync
