// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/sliding_sync_room_builder.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_set>
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

    [[nodiscard]] auto as_object(canonicaljson::Value const& v) noexcept -> canonicaljson::Object const*
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

    // Convert a stored persistent event's signed wire JSON into the
    // client-facing event shape by injecting the "event_id" field. Room
    // event formats do not carry event_id on the wire (it is derived from a
    // reference hash), but every client-facing event — timeline and
    // required_state alike — must include it per the Matrix spec's Room
    // Event Format. Mirrors client_server.cpp's client_event_value().
    [[nodiscard]] auto client_event_json(std::string_view event_id, std::string_view stored_json) -> std::string
    {
        auto const parsed = canonicaljson::parse_lossless(stored_json);
        if (parsed.error == canonicaljson::ParseError::none)
        {
            if (auto const* obj = as_object(parsed.value); obj != nullptr)
            {
                auto client_obj = *obj;
                // Stored JSON from v1-v3 rooms (and PDUs relayed by other
                // implementations) may already carry event_id — replace it
                // rather than appending a duplicate key (#457).
                std::erase_if(client_obj, [](canonicaljson::ObjectMember const& member) {
                    return member.key == "event_id";
                });
                client_obj.push_back(
                    canonicaljson::make_member("event_id", canonicaljson::Value{std::string{event_id}}));
                auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(client_obj)});
                if (serialized.error == canonicaljson::CanonicalJsonError::none)
                {
                    return serialized.output;
                }
            }
        }
        return std::string{stored_json};
    }

    // ── required_state wildcard matching ───────────────────────────────────

    [[nodiscard]] auto matches_required_state_pair(std::string_view req_type, std::string_view req_key,
                                                   std::string_view event_type, std::string_view state_key) noexcept
        -> bool
    {
        auto const type_match = (req_type == "*") || (req_type == event_type);
        auto const key_match = (req_key == "*") || (req_key == state_key);
        return type_match && key_match;
    }

    [[nodiscard]] auto state_event_matches_any(std::vector<std::pair<std::string, std::string>> const& pairs,
                                               std::string_view event_type, std::string_view state_key) noexcept -> bool
    {
        return std::ranges::any_of(pairs, [&](auto const& p) {
            return matches_required_state_pair(p.first, p.second, event_type, state_key);
        });
    }

    // ── required_state sentinel resolution ("$ME" / "$LAZY") ───────────────

    // Extract the set of user_ids relevant to lazy-loaded ("$LAZY") member
    // resolution from a timeline: whoever sent an event, plus — for
    // m.room.member events specifically — the membership's subject, so an
    // invite/kick/ban target is covered even if they never sent anything.
    [[nodiscard]] auto extract_timeline_membership(
        std::vector<std::pair<std::uint64_t, std::string>> const& timeline_events) -> std::unordered_set<std::string>
    {
        auto members = std::unordered_set<std::string>{};
        for (auto const& [ordering, json] : timeline_events)
        {
            std::ignore = ordering;
            auto const parsed = canonicaljson::parse_lossless(json);
            if (parsed.error != canonicaljson::ParseError::none)
            {
                continue;
            }
            auto const* root = as_object(parsed.value);
            if (root == nullptr)
            {
                continue;
            }
            if (auto const* sender_val = find_member(*root, "sender"); sender_val != nullptr)
            {
                if (auto const* s = as_string(*sender_val); s != nullptr)
                {
                    members.insert(*s);
                }
            }
            auto const* type_val = find_member(*root, "type");
            auto const* type_s = type_val != nullptr ? as_string(*type_val) : nullptr;
            if (type_s != nullptr && *type_s == "m.room.member")
            {
                if (auto const* sk_val = find_member(*root, "state_key"); sk_val != nullptr)
                {
                    if (auto const* s = as_string(*sk_val); s != nullptr)
                    {
                        members.insert(*s);
                    }
                }
            }
        }
        return members;
    }

    // Resolve MSC3575/MSC4186 required_state sentinel state keys ("$ME",
    // "$LAZY") into concrete pairs the plain matcher understands.
    //
    // "$ME" always becomes the requesting user's own ID — matrix-rust-sdk and
    // Synapse both do a straight substitution, so this reuses all of the
    // existing since-floor delta logic for free.
    //
    // "$LAZY" (only meaningful for m.room.member) becomes:
    //   - one explicit pair per user relevant to *this response's* timeline
    //     (`timeline_membership`), when the timeline is limited (truncated —
    //     there's a gap the client can't otherwise bridge) or this is the
    //     room's first appearance on the connection. Matches matrix-rust-sdk/
    //     Synapse's "only the people in the timeline we're returning"
    //     restriction; or
    //   - the wildcard "*", when the timeline is a continuous, non-initial
    //     slice, so the client's existing membership cache stays valid and
    //     only genuine membership changes need to flow.
    // Callers separately bypass the since-floor for members newly relevant to
    // this connection (see build_room_response's lazy_members_already_sent)
    // regardless of which branch produced the matching pair.
    [[nodiscard]] auto resolve_required_state(std::vector<std::pair<std::string, std::string>> const& required_state,
                                              std::string_view user,
                                              std::unordered_set<std::string> const& timeline_membership,
                                              bool scope_lazy_to_timeline)
        -> std::vector<std::pair<std::string, std::string>>
    {
        auto resolved = std::vector<std::pair<std::string, std::string>>{};
        resolved.reserve(required_state.size());
        for (auto const& [event_type, state_key] : required_state)
        {
            if (event_type == "m.room.member" && state_key == "$LAZY")
            {
                if (scope_lazy_to_timeline)
                {
                    for (auto const& member_id : timeline_membership)
                    {
                        resolved.emplace_back(event_type, member_id);
                    }
                }
                else
                {
                    resolved.emplace_back(event_type, "*");
                }
                continue;
            }
            if (event_type == "m.room.member" && state_key == "$ME")
            {
                resolved.emplace_back(event_type, std::string{user});
                continue;
            }
            resolved.emplace_back(event_type, state_key);
        }
        return resolved;
    }

    // ── Name / avatar from state ────────────────────────────────────────────

    [[nodiscard]] auto state_content_string(database::PersistentStore const& store, std::string_view room_id,
                                            std::string_view event_type, std::string_view content_field)
        -> std::optional<std::string>
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

    [[nodiscard]] auto count_memberships(database::PersistentStore const& store, std::string_view room_id,
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

    [[nodiscard]] auto build_heroes(database::PersistentStore const& store, std::string_view room_id,
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
                if (se.room_id != room_id || se.event_type != "m.room.member" || se.state_key != m.user_id)
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
                    auto const* content = content_val != nullptr ? as_object(*content_val) : nullptr;
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

    // Counts events strictly after `read_ordering` — the user's last read
    // receipt position, NOT the sync position (#417). The user's own events
    // never count as unread.
    [[nodiscard]] auto count_notifications(database::PersistentStore const& store, std::string_view room_id,
                                           std::string_view user, std::uint64_t read_ordering) noexcept -> std::uint64_t
    {
        auto count = std::uint64_t{0U};
        for (auto const& ev : store.events)
        {
            if (ev.room_id != room_id || ev.stream_ordering <= read_ordering || ev.sender_user_id == user)
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
            auto const* type_s = type_val != nullptr ? as_string(*type_val) : nullptr;
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

    [[nodiscard]] auto count_highlights(database::PersistentStore const& store, std::string_view room_id,
                                        std::string_view user, std::uint64_t read_ordering) noexcept -> std::uint64_t
    {
        // Simple mention scan: check m.mentions.user_ids or body for @user_id.
        auto count = std::uint64_t{0U};
        for (auto const& ev : store.events)
        {
            if (ev.room_id != room_id || ev.stream_ordering <= read_ordering || ev.sender_user_id == user)
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
            auto const* content = content_val != nullptr ? as_object(*content_val) : nullptr;
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
                        if (auto const* arr = std::get_if<canonicaljson::Array>(&uids_val->storage()); arr != nullptr)
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
    [[nodiscard]] auto latest_timestamp(database::PersistentStore const& store, std::string_view room_id) noexcept
        -> std::uint64_t
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

auto build_room_response(homeserver::HomeserverRuntime const& rt, std::string_view room_id, std::string_view user,
                         SlidingSyncRoomSubscription const& sub, std::uint64_t room_since_event_ordering,
                         bool is_initial, database::PersistentStore const& store,
                         std::unordered_set<std::string> const& lazy_members_already_sent) -> SlidingSyncRoomResponse
{
    auto resp = SlidingSyncRoomResponse{};

    resp.initial = is_initial;

    // ── Name and avatar ─────────────────────────────────────────────────────
    resp.name = state_content_string(store, room_id, "m.room.name", "name");
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
    resp.joined_count = count_memberships(store, room_id, "join");
    resp.invited_count = count_memberships(store, room_id, "invite");
    // #417: counts are relative to the user's last READ RECEIPT, not the sync
    // position — "events the user hasn't read", not "events the client hasn't
    // synced".
    auto const read_ordering = read_receipt_ordering(rt, store, room_id, user);
    resp.notification_count = count_notifications(store, room_id, user, read_ordering);
    resp.highlight_count = count_highlights(store, room_id, user, read_ordering);

    // ── Timestamp ───────────────────────────────────────────────────────────
    resp.timestamp = latest_timestamp(store, room_id);

    // ── Heroes ──────────────────────────────────────────────────────────────
    if (sub.include_heroes)
    {
        resp.heroes = build_heroes(store, room_id, user);
    }

    // ── Timeline ─────────────────────────────────────────────────────────────
    // Collect events in chronological order, respecting the since floor.
    // Computed before required_state: resolving required_state's "$LAZY"
    // member sentinel needs to know which senders/subjects appear in the
    // timeline this response is about to return.
    auto timeline_events = std::vector<std::pair<std::uint64_t, std::string>>{};
    for (auto const& ev : store.events)
    {
        if (ev.room_id != room_id)
        {
            continue;
        }
        if (!is_initial && ev.stream_ordering <= room_since_event_ordering)
        {
            continue;
        }
        timeline_events.emplace_back(ev.stream_ordering, client_event_json(ev.event_id, ev.json));
    }
    std::sort(timeline_events.begin(), timeline_events.end(), [](auto const& a, auto const& b) {
        return a.first < b.first;
    });

    auto const limit = static_cast<std::size_t>(sub.timeline_limit);
    bool const timeline_limited = timeline_events.size() > limit;
    if (timeline_limited)
    {
        // Keep the last `limit` events; MSC4186 returns timeline as a plain
        // [Event] array without a per-room prev_batch or limited flag.
        auto const drop_count = timeline_events.size() - limit;
        timeline_events.erase(timeline_events.begin(),
                              timeline_events.begin() + static_cast<std::ptrdiff_t>(drop_count));
    }

    // ── required_state ──────────────────────────────────────────────────────
    if (!sub.required_state.empty())
    {
        auto const lazy_load_room_members = std::ranges::any_of(sub.required_state, [](auto const& p) {
            return p.first == "m.room.member" && p.second == "$LAZY";
        });

        // Members relevant to this response's timeline, and — among those —
        // the ones this connection has never been sent before. A brand-new
        // relevant member must be delivered even if their own m.room.member
        // event predates the since-floor (they only just became relevant;
        // their membership event itself may be old and otherwise unchanged).
        auto const timeline_membership =
            lazy_load_room_members ? extract_timeline_membership(timeline_events) : std::unordered_set<std::string>{};
        auto new_lazy_members = std::unordered_set<std::string>{};
        if (lazy_load_room_members)
        {
            for (auto const& member_id : timeline_membership)
            {
                if (!lazy_members_already_sent.contains(member_id))
                {
                    new_lazy_members.insert(member_id);
                }
            }
        }

        auto const scope_lazy_to_timeline = timeline_limited || is_initial;
        auto const resolved_required_state =
            resolve_required_state(sub.required_state, user, timeline_membership, scope_lazy_to_timeline);

        for (auto const& se : store.state)
        {
            if (se.room_id != room_id)
            {
                continue;
            }
            if (!state_event_matches_any(resolved_required_state, se.event_type, se.state_key))
            {
                continue;
            }
            bool const bypass_floor = is_initial || (lazy_load_room_members && se.event_type == "m.room.member" &&
                                                     new_lazy_members.contains(se.state_key));
            // On incremental responses include only state that changed since
            // pos, unless this is a newly-relevant lazy-loaded member seeing
            // their first delivery on this connection (bypass_floor).
            for (auto const& ev : store.events)
            {
                if (ev.event_id != se.event_id)
                {
                    continue;
                }
                if (!bypass_floor && ev.stream_ordering <= room_since_event_ordering)
                {
                    break; // unchanged since last pos — skip
                }
                resp.required_state_json.push_back(client_event_json(ev.event_id, ev.json));
                if (lazy_load_room_members && se.event_type == "m.room.member" &&
                    timeline_membership.contains(se.state_key))
                {
                    resp.lazy_members_included.insert(se.state_key);
                }
                break;
            }
        }
    }

    for (auto& [ordering, json] : timeline_events)
    {
        resp.timeline_json.push_back(std::move(json));
        std::ignore = ordering;
    }

    return resp;
}

auto read_receipt_ordering(homeserver::HomeserverRuntime const& rt, database::PersistentStore const& store,
                           std::string_view room_id, std::string_view user) -> std::uint64_t
{
    // Collect the events named by the user's read receipts in this room.
    // m.read and m.read.private both advance the read position; the baseline
    // is the highest stream ordering among the receipted events.
    auto receipted_event_ids = std::unordered_set<std::string>{};
    for (auto const& receipt : rt.receipts)
    {
        if (receipt.room_id != room_id || receipt.user_id != user)
        {
            continue;
        }
        if (receipt.receipt_type != "m.read" && receipt.receipt_type != "m.read.private")
        {
            continue;
        }
        receipted_event_ids.insert(receipt.event_id);
    }
    if (receipted_event_ids.empty())
    {
        return 0U;
    }

    auto read_ordering = std::uint64_t{0U};
    for (auto const& ev : store.events)
    {
        if (ev.room_id != room_id || !receipted_event_ids.contains(ev.event_id))
        {
            continue;
        }
        read_ordering = std::max(read_ordering, ev.stream_ordering);
    }
    return read_ordering;
}

} // namespace merovingian::sync
