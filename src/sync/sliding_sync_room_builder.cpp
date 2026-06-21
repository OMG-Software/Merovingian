// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/sliding_sync_room_builder.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/sync/stream_token.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace merovingian::sync
{
namespace
{

    // ── JSON helpers ────────────────────────────────────────────────────────

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

    [[nodiscard]] auto as_int(canonicaljson::Value const& v) noexcept -> std::int64_t const*
    {
        return std::get_if<std::int64_t>(&v.storage());
    }

    // ── required_state wildcard matching ───────────────────────────────────

    [[nodiscard]] auto matches_required_state_pair(std::string_view req_type,
                                                    std::string_view req_key,
                                                    std::string_view event_type,
                                                    std::string_view state_key) noexcept -> bool
    {
        auto const type_match = (req_type == "*") || (req_type == event_type);
        auto const key_match  = (req_key  == "*") || (req_key  == state_key);
        return type_match && key_match;
    }

    [[nodiscard]] auto state_event_matches_any(
        std::vector<std::pair<std::string, std::string>> const& pairs,
        std::string_view event_type,
        std::string_view state_key) noexcept -> bool
    {
        return std::ranges::any_of(pairs, [&](auto const& p) {
            return matches_required_state_pair(p.first, p.second, event_type, state_key);
        });
    }

    // ── Name / avatar from state ────────────────────────────────────────────

    [[nodiscard]] auto state_content_string(database::PersistentStore const& store,
                                             std::string_view room_id,
                                             std::string_view event_type,
                                             std::string_view content_field) -> std::optional<std::string>
    {
        for (auto const& se : store.state)
        {
            if (se.room_id != room_id || se.event_type != event_type)
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
                    return std::nullopt;
                }
                auto const* root = as_object(parsed.value);
                if (root == nullptr)
                {
                    return std::nullopt;
                }
                auto const* content_val = find_member(*root, "content");
                if (content_val == nullptr)
                {
                    return std::nullopt;
                }
                auto const* content = as_object(*content_val);
                if (content == nullptr)
                {
                    return std::nullopt;
                }
                auto const* field_val = find_member(*content, content_field);
                if (field_val == nullptr)
                {
                    return std::nullopt;
                }
                auto const* s = as_string(*field_val);
                if (s == nullptr || s->empty())
                {
                    return std::nullopt;
                }
                return *s;
            }
        }
        return std::nullopt;
    }

    // ── Member counts ───────────────────────────────────────────────────────

    [[nodiscard]] auto count_memberships(database::PersistentStore const& store,
                                          std::string_view room_id,
                                          std::string_view membership_value) noexcept -> std::uint64_t
    {
        auto count = std::uint64_t{0U};
        for (auto const& m : store.memberships)
        {
            if (m.room_id == room_id && m.membership == membership_value)
            {
                ++count;
            }
        }
        return count;
    }

    // ── Heroes ──────────────────────────────────────────────────────────────

    [[nodiscard]] auto build_heroes(database::PersistentStore const& store,
                                     std::string_view room_id,
                                     std::string_view self_user_id) -> std::vector<SlidingSyncHero>
    {
        constexpr std::size_t max_heroes = 5U;
        auto heroes = std::vector<SlidingSyncHero>{};

        for (auto const& m : store.memberships)
        {
            if (heroes.size() >= max_heroes)
            {
                break;
            }
            if (m.room_id != room_id || m.user_id == self_user_id || m.membership != "join")
            {
                continue;
            }
            auto hero = SlidingSyncHero{};
            hero.user_id = m.user_id;

            // Look up display_name and avatar_url from the member state event.
            for (auto const& se : store.state)
            {
                if (se.room_id != room_id || se.event_type != "m.room.member" ||
                    se.state_key != m.user_id)
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
                        break;
                    }
                    auto const* root = as_object(parsed.value);
                    if (root == nullptr)
                    {
                        break;
                    }
                    auto const* content_val = find_member(*root, "content");
                    auto const* content     = content_val != nullptr ? as_object(*content_val) : nullptr;
                    if (content == nullptr)
                    {
                        break;
                    }
                    if (auto const* dn = find_member(*content, "displayname"); dn != nullptr)
                    {
                        if (auto const* s = as_string(*dn); s != nullptr && !s->empty())
                        {
                            hero.display_name = *s;
                        }
                    }
                    if (auto const* av = find_member(*content, "avatar_url"); av != nullptr)
                    {
                        if (auto const* s = as_string(*av); s != nullptr && !s->empty())
                        {
                            hero.avatar_url = *s;
                        }
                    }
                    break;
                }
                break;
            }
            heroes.push_back(std::move(hero));
        }
        return heroes;
    }

    // ── Notification / highlight counts ─────────────────────────────────────

    [[nodiscard]] auto count_notifications(database::PersistentStore const& store,
                                            std::string_view room_id,
                                            std::string_view user,
                                            std::uint64_t since_ordering) noexcept -> std::uint64_t
    {
        auto count = std::uint64_t{0U};
        for (auto const& ev : store.events)
        {
            if (ev.room_id != room_id || ev.stream_ordering <= since_ordering)
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
            std::ignore = user;  // future: filter by push rules
        }
        return count;
    }

    [[nodiscard]] auto count_highlights(database::PersistentStore const& store,
                                         std::string_view room_id,
                                         std::string_view user,
                                         std::uint64_t since_ordering) noexcept -> std::uint64_t
    {
        // Simple mention scan: check m.mentions.user_ids or body for @user_id.
        auto count = std::uint64_t{0U};
        for (auto const& ev : store.events)
        {
            if (ev.room_id != room_id || ev.stream_ordering <= since_ordering)
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
            auto const* content_val = find_member(*root, "content");
            auto const* content     = content_val != nullptr ? as_object(*content_val) : nullptr;
            if (content == nullptr)
            {
                continue;
            }
            // Check m.mentions.user_ids (MSC3952 / Matrix v1.7+).
            if (auto const* mentions_val = find_member(*content, "m.mentions"); mentions_val != nullptr)
            {
                if (auto const* mentions = as_object(*mentions_val); mentions != nullptr)
                {
                    if (auto const* uids_val = find_member(*mentions, "user_ids"); uids_val != nullptr)
                    {
                        if (auto const* arr = std::get_if<canonicaljson::Array>(&uids_val->storage());
                            arr != nullptr)
                        {
                            for (auto const& uid_val : *arr)
                            {
                                auto const* uid = as_string(uid_val);
                                if (uid != nullptr && *uid == user)
                                {
                                    ++count;
                                }
                            }
                        }
                    }
                }
            }
        }
        return count;
    }

    // Latest origin_server_ts in the room's timeline.
    [[nodiscard]] auto latest_timestamp(database::PersistentStore const& store,
                                         std::string_view room_id) noexcept -> std::uint64_t
    {
        auto ts = std::uint64_t{0U};
        for (auto const& ev : store.events)
        {
            if (ev.room_id != room_id)
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
            auto const* ots_val = find_member(*root, "origin_server_ts");
            if (ots_val == nullptr)
            {
                continue;
            }
            if (auto const* n = as_int(*ots_val); n != nullptr && *n > 0)
            {
                auto const uts = static_cast<std::uint64_t>(*n);
                if (uts > ts)
                {
                    ts = uts;
                }
            }
        }
        return ts;
    }

} // namespace

// ── Public API ───────────────────────────────────────────────────────────────

auto build_room_response(homeserver::HomeserverRuntime const& rt,
                         std::string_view                     room_id,
                         std::string_view                     user,
                         SlidingSyncRoomSubscription const&   sub,
                         std::uint64_t                        since_event_ordering,
                         bool                                 is_initial,
                         database::PersistentStore const&     store) -> SlidingSyncRoomResponse
{
    auto resp = SlidingSyncRoomResponse{};

    resp.initial = is_initial;

    // ── Name and avatar ─────────────────────────────────────────────────────
    resp.name   = state_content_string(store, room_id, "m.room.name",   "name");
    resp.avatar = state_content_string(store, room_id, "m.room.avatar", "url");

    // ── is_dm ───────────────────────────────────────────────────────────────
    // Check m.direct global account-data.
    for (auto const& ad : store.account_data)
    {
        if (ad.user_id != user || !ad.room_id.empty() || ad.event_type != "m.direct")
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
        for (auto const& member : *root)
        {
            auto const* arr = std::get_if<canonicaljson::Array>(&member.value->storage());
            if (arr == nullptr)
            {
                continue;
            }
            for (auto const& item : *arr)
            {
                if (auto const* s = as_string(item); s != nullptr && *s == room_id)
                {
                    resp.is_dm = true;
                }
            }
        }
        break;
    }

    // ── Counts ──────────────────────────────────────────────────────────────
    resp.joined_count  = count_memberships(store, room_id, "join");
    resp.invited_count = count_memberships(store, room_id, "invite");
    resp.notification_count = count_notifications(store, room_id, user, since_event_ordering);
    resp.highlight_count    = count_highlights(store, room_id, user, since_event_ordering);

    // ── Timestamp ───────────────────────────────────────────────────────────
    resp.timestamp = latest_timestamp(store, room_id);

    // ── Heroes ──────────────────────────────────────────────────────────────
    if (sub.include_heroes)
    {
        resp.heroes = build_heroes(store, room_id, user);
    }

    // ── required_state ──────────────────────────────────────────────────────
    if (!sub.required_state.empty())
    {
        for (auto const& se : store.state)
        {
            if (se.room_id != room_id)
            {
                continue;
            }
            if (!state_event_matches_any(sub.required_state, se.event_type, se.state_key))
            {
                continue;
            }
            // On incremental responses include only state that changed since pos.
            for (auto const& ev : store.events)
            {
                if (ev.event_id != se.event_id)
                {
                    continue;
                }
                if (!is_initial && ev.stream_ordering <= since_event_ordering)
                {
                    break; // unchanged since last pos — skip
                }
                resp.required_state_json.push_back(ev.json);
                break;
            }
        }
    }

    // ── Timeline ─────────────────────────────────────────────────────────────
    // Collect events in chronological order, respecting the since floor.
    auto timeline_events = std::vector<std::pair<std::uint64_t, std::string>>{};
    for (auto const& ev : store.events)
    {
        if (ev.room_id != room_id)
        {
            continue;
        }
        if (!is_initial && ev.stream_ordering <= since_event_ordering)
        {
            continue;
        }
        timeline_events.emplace_back(ev.stream_ordering, ev.json);
    }
    std::sort(timeline_events.begin(), timeline_events.end(),
              [](auto const& a, auto const& b) { return a.first < b.first; });

    auto const limit = static_cast<std::size_t>(sub.timeline_limit);
    if (timeline_events.size() > limit)
    {
        resp.limited = true;
        // Keep the last `limit` events and record a prev_batch token for the first dropped.
        auto const drop_count = timeline_events.size() - limit;
        // prev_batch points to just before the first kept event.
        auto const first_kept_ordering = timeline_events[drop_count].first;
        resp.prev_batch = encode_stream_token(
            StreamToken{first_kept_ordering > 0U ? first_kept_ordering - 1U : 0U, 0U, 0U});
        timeline_events.erase(timeline_events.begin(),
                              timeline_events.begin() + static_cast<std::ptrdiff_t>(drop_count));
    }
    for (auto& [ordering, json] : timeline_events)
    {
        resp.timeline_json.push_back(std::move(json));
        std::ignore = ordering;
    }

    std::ignore = rt;  // rt available for future extensions (e.g. runtime state)
    return resp;
}

} // namespace merovingian::sync
