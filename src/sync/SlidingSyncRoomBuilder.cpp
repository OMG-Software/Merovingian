// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/SlidingSyncRoomBuilder.hpp"

#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/ObjectMember.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/database/RedactionView.hpp"
#include "merovingian/database/StickyEventView.hpp"
#include "merovingian/homeserver/PushRuleUnreadClassifier.hpp"
#include "merovingian/sync/BundledAggregations.hpp"
#include "merovingian/sync/RequiredStateElement.hpp"
#include "merovingian/sync/RoomReadKind.hpp"
#include "merovingian/sync/ThreadNotificationCounts.hpp"
#include "merovingian/sync/TimelineExpansion.hpp"
#include "merovingian/sync/TimelineWindow.hpp"
#include "merovingian/sync/ViewerEventUnsigned.hpp"
#include "merovingian/trust_safety/IgnoreList.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
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

    // Convert a stored persistent event's signed wire JSON into the
    // client-facing event shape by injecting the "event_id" field. Room
    // event formats do not carry event_id on the wire (it is derived from a
    // reference hash), but every client-facing event — timeline and
    // required_state alike — must include it per the Matrix spec's Room
    // Event Format. Mirrors ClientServerRuntime.cpp's client_event_value().
    //
    // `unsigned` is never taken from the stored copy: it is outside the event's signatures, so a remote
    // sender can put anything there. It is built from `redacted_because` (attach_redacted_because) and the
    // viewer's own `transaction_id`, `membership` and `prev_content` (ViewerEventUnsigned), and the sticky remaining
    // time (attach_sticky_remaining), the same rule as client_event_with_id (ADR-0402). A stored row that cannot be
    // read is withheld (empty string).
    [[nodiscard]] auto client_event_value(database::PersistentStore const& store,
                                          database::PersistentEvent const& event)
        -> std::optional<canonicaljson::Object>
    {
        auto const parsed = canonicaljson::parse_lossless(event.json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto const* obj = as_object(parsed.value);
        if (obj == nullptr)
        {
            return std::nullopt;
        }
        auto client_obj = *obj;
        // Stored JSON from v1-v3 rooms (and PDUs relayed by other
        // implementations) may already carry event_id — replace it
        // rather than appending a duplicate key (#457).
        std::erase_if(client_obj, [](canonicaljson::ObjectMember const& member) {
            return member.key == "event_id" || member.key == "unsigned";
        });
        client_obj.push_back(canonicaljson::make_member("event_id", canonicaljson::Value{event.event_id}));
        // CSAZ-11: a redacted event carries unsigned.redacted_because; a redaction event
        // carries `redacts` where older and newer clients look for it.
        database::add_redaction_compat(client_obj);
        database::attach_redacted_because(store, event.event_id, client_obj);
        // MSC4354: an unexpired sticky event carries its remaining time, as client_event_with_id adds it (ADR-0853).
        database::attach_sticky_remaining(store, event.event_id, client_obj);
        return client_obj;
    }

    [[nodiscard]] auto serialized_client_event(canonicaljson::Value const& value) -> std::string
    {
        auto const serialized = canonicaljson::serialize_canonical(value);
        return serialized.error == canonicaljson::CanonicalJsonError::none ? serialized.output : std::string{};
    }

    [[nodiscard]] auto client_event_json(database::PersistentStore const& store, database::PersistentEvent const& event,
                                         ViewerEventUnsigned& viewer) -> std::string
    {
        auto client_obj = client_event_value(store, event);
        if (!client_obj.has_value())
        {
            return {};
        }
        return serialized_client_event(viewer.apply(event, canonicaljson::Value{std::move(*client_obj)}));
    }

    // As above, with the event's bundled aggregations (`unsigned.m.relations`) added to the viewer's
    // `unsigned`: built by the server, never taken from the stored copy.
    [[nodiscard]] auto client_event_json(database::PersistentStore const& store, database::PersistentEvent const& event,
                                         ViewerEventUnsigned& viewer, BundledAggregations& aggregations) -> std::string
    {
        auto client_obj = client_event_value(store, event);
        if (!client_obj.has_value())
        {
            return {};
        }
        return serialized_client_event(
            aggregations.apply(event, viewer.apply(event, canonicaljson::Value{std::move(*client_obj)})));
    }

    // Ignoring Users (spec: docs/matrix-v1.19-spec/client-server-api.md
    // #ignoring-users, Server behaviour). Parses `event_json` once to answer
    // both questions trust_safety::is_delivery_suppressed needs: is this a
    // state event (has a "state_key" member), and — the one case where a
    // state event is withheld anyway — is it `user`'s own room invite (an
    // m.room.member event with state_key == user and content.membership ==
    // "invite")? MSC4186 has no separate invite-state surface like legacy
    // /sync's rooms.invite.<room_id>.invite_state, so this classification
    // stands in for build_invite_state_events_array's suppression there, for
    // both the timeline and required_state below.
    struct EventIgnoreClassification final
    {
        bool is_state_event{false};
        bool is_new_room_invite_for_user{false};
    };

    [[nodiscard]] auto classify_event_for_ignore_filter(std::string_view event_json, std::string_view user)
        -> EventIgnoreClassification
    {
        auto result = EventIgnoreClassification{};
        auto const parsed = canonicaljson::parse_lossless(event_json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return result;
        }
        auto const* root = as_object(parsed.value);
        if (root == nullptr)
        {
            return result;
        }
        result.is_state_event = find_member(*root, "state_key") != nullptr;
        auto const* type_val = find_member(*root, "type");
        auto const* type_s = type_val != nullptr ? as_string(*type_val) : nullptr;
        if (type_s == nullptr || *type_s != "m.room.member")
        {
            return result;
        }
        auto const* state_key_val = find_member(*root, "state_key");
        auto const* state_key_s = state_key_val != nullptr ? as_string(*state_key_val) : nullptr;
        if (state_key_s == nullptr || *state_key_s != user)
        {
            return result;
        }
        auto const* content_val = find_member(*root, "content");
        auto const* content = content_val != nullptr ? as_object(*content_val) : nullptr;
        auto const* membership_val = content != nullptr ? find_member(*content, "membership") : nullptr;
        auto const* membership_s = membership_val != nullptr ? as_string(*membership_val) : nullptr;
        result.is_new_room_invite_for_user = membership_s != nullptr && *membership_s == "invite";
        return result;
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

    // ── MSC4186 required_state configs (ADR-0865) ──────────────────────────

    // Whether a config returns a state entry: an include element matches it and no exclude element does. Under
    // `lazy_members` an include element reaches `m.room.member` only when it names that type, so `{}` is "everything
    // but the members" (MSC4186 "Lazy loaded memberships"); the lazily loaded members are added apart from this.
    [[nodiscard]] auto config_returns_state(RequiredStateConfig const& config, std::string_view event_type,
                                            std::string_view state_key) noexcept -> bool
    {
        auto const is_member = event_type == "m.room.member";
        auto const included = std::ranges::any_of(config.include, [&](RequiredStateElement const& e) {
            if (is_member && config.lazy_members && (!e.type.has_value() || *e.type != "m.room.member"))
            {
                return false;
            }
            return e.matches(event_type, state_key);
        });
        return included && std::ranges::none_of(config.exclude, [&](RequiredStateElement const& e) {
                   return e.matches(event_type, state_key);
               });
    }

    // Whether a legacy pair names every member event: type `m.room.member` or "*", and state key "*".
    [[nodiscard]] auto pair_names_every_member(std::pair<std::string, std::string> const& p) noexcept -> bool
    {
        return (p.first == "*" || p.first == "m.room.member") && p.second == "*";
    }

    // Whether a config element names every member event: type `m.room.member` or omitted, and no state key.
    [[nodiscard]] auto element_names_every_member(RequiredStateElement const& e) noexcept -> bool
    {
        return e.may_name_members() && !e.state_key.has_value();
    }

    // MSC4186 "Combining room configs": members are lazily loaded only if no config "return[s] all membership events
    // (and [doesn't] have `lazy_members` set)". A config that excludes any member event does not return all of them.
    [[nodiscard]] auto config_returns_every_member(RequiredStateConfig const& config) noexcept -> bool
    {
        if (config.lazy_members)
        {
            return false;
        }
        auto const excludes_a_member = std::ranges::any_of(config.exclude, [](RequiredStateElement const& e) {
            return e.may_name_members();
        });
        return !excludes_a_member && std::ranges::any_of(config.include, element_names_every_member);
    }

    // Whether the combined room config lazily loads members through an MSC4186 config.
    [[nodiscard]] auto configs_load_members_lazily(SlidingSyncRoomSubscription const& sub) noexcept -> bool
    {
        auto const any_lazy = std::ranges::any_of(sub.required_state_configs, [](RequiredStateConfig const& c) {
            return c.lazy_members;
        });
        if (!any_lazy)
        {
            return false;
        }
        auto const legacy_returns_every_member = std::ranges::any_of(sub.required_state, pair_names_every_member);
        return !legacy_returns_every_member &&
               std::ranges::none_of(sub.required_state_configs, config_returns_every_member);
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
        for (auto const& entry : timeline_events)
        {
            auto const& json = entry.second;
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

    // The stream ordering of the room's current state event of `event_type` with an empty state key, none without one.
    [[nodiscard]] auto current_state_ordering(database::PersistentStore const& store, std::string_view room_id,
                                              std::string_view event_type) -> std::optional<std::uint64_t>
    {
        auto const event_id = database::find_current_state_event_id(store, room_id, event_type, "");
        if (!event_id.has_value())
        {
            return std::nullopt;
        }
        auto const found = store.events.find(*event_id);
        return found != store.events.end() ? std::optional<std::uint64_t>{found->stream_ordering} : std::nullopt;
    }

    [[nodiscard]] auto state_content_string(database::PersistentStore const& store, std::string_view room_id,
                                            std::string_view event_type, std::string_view content_field)
        -> std::optional<std::string>
    {
        // The room's first state row of the type, whatever its state key, from the room's own rows (ADR-0344).
        auto first_event_id = std::optional<std::string>{};
        database::for_each_room_state_row(store, room_id, [&](database::PersistentStateEvent const& se) {
            if (!first_event_id.has_value() && se.event_type == event_type)
            {
                first_event_id = se.event_id;
            }
        });
        if (first_event_id.has_value())
        {
            for (auto const& ev : store.events.with_id(*first_event_id))
            {
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
        // The room's own membership rows (ADR-0437), not every room's.
        database::for_each_room_membership_row(store, room_id, [&](database::PersistentMembership const& m) {
            if (m.membership == membership_value)
            {
                ++count;
            }
        });
        return count;
    }

    // ── Heroes ──────────────────────────────────────────────────────────────

    // A hero's name and avatar from the content of their member event. One that is absent, empty or not a string stays
    // unset, as does either when the event cannot be read.
    auto fill_hero_profile(SlidingSyncHero& hero, std::string_view member_event_json) -> void
    {
        auto const parsed = canonicaljson::parse_lossless(member_event_json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return;
        }
        auto const* root = as_object(parsed.value);
        auto const* content_val = root != nullptr ? find_member(*root, "content") : nullptr;
        auto const* content = content_val != nullptr ? as_object(*content_val) : nullptr;
        if (content == nullptr)
        {
            return;
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
    }

    [[nodiscard]] auto build_heroes(database::PersistentStore const& store, std::string_view room_id,
                                    std::string_view self_user_id) -> std::vector<SlidingSyncHero>
    {
        constexpr std::size_t max_heroes = 5U;
        auto heroes = std::vector<SlidingSyncHero>{};

        // MSC4186 "heroes": "the same users as the `m.heroes` section" of /v3/sync, from the room's own membership rows
        // (ADR-0437): the first `max_heroes` other users who are joined, then invited; the left and banned ones only
        // "when no joined or invited members are available".
        auto joined = std::vector<std::string>{};
        auto invited = std::vector<std::string>{};
        auto departed = std::vector<std::string>{};
        database::for_each_room_membership_row(store, room_id, [&](database::PersistentMembership const& m) {
            if (m.user_id == self_user_id)
            {
                return;
            }
            if (m.membership == "join" && joined.size() < max_heroes)
            {
                joined.push_back(m.user_id);
            }
            else if (m.membership == "invite" && invited.size() < max_heroes)
            {
                invited.push_back(m.user_id);
            }
            else if ((m.membership == "leave" || m.membership == "ban") && departed.size() < max_heroes)
            {
                departed.push_back(m.user_id);
            }
        });
        auto hero_user_ids = std::move(joined);
        auto* const departed_or_none = hero_user_ids.empty() && invited.empty() ? &departed : nullptr;
        for (auto* const more : {&invited, departed_or_none})
        {
            if (more == nullptr)
            {
                continue;
            }
            for (auto& user_id : *more)
            {
                if (hero_user_ids.size() < max_heroes)
                {
                    hero_user_ids.push_back(std::move(user_id));
                }
            }
        }

        for (auto const& hero_user_id : hero_user_ids)
        {
            auto hero = SlidingSyncHero{};
            hero.user_id = hero_user_id;

            // Look up display_name and avatar_url from the member state event.
            if (auto const member_event_id =
                    database::find_current_state_event_id(store, room_id, "m.room.member", hero_user_id);
                member_event_id.has_value())
            {
                if (auto const member_event = store.events.find(*member_event_id); member_event != store.events.end())
                {
                    fill_hero_profile(hero, member_event->json);
                }
            }
            heroes.push_back(std::move(hero));
        }
        return heroes;
    }

    // Latest origin_server_ts of any event of the room (every status), kept by the event table as rows come and go,
    // so this costs one lookup, not a parse of the room's history (ADR-0497).
    [[nodiscard]] auto latest_timestamp(database::PersistentStore const& store, std::string_view room_id) noexcept
        -> std::uint64_t
    {
        return static_cast<std::uint64_t>(store.events.room_latest_origin_server_ts(room_id));
    }

} // namespace

// ── Public API ───────────────────────────────────────────────────────────────

// Counts the events `markers` do not cover — relative to the user's read
// receipts, NOT the sync position (#417) — per thread, as the spec asks: "the
// server is to partition the notification count to each thread (with the main
// timeline being its own thread)". The user's own events never count as
// unread. Whether an event is a notification or a highlight is the user's push
// rules' decision (`unread`, R15, ADR-0205), and only events after the start of
// the user's current join count.
// Only accepted events count: a rejected or soft-failed event is never served to clients, so it
// is never unread. The push badge counts the same way in one bounded pass of its own
// (homeserver::count_push_badge, ADR-0207); a change to what counts here changes it there too.
auto count_unread_by_thread(database::PersistentStore const& store, std::string_view room_id, std::string_view user,
                            ReadMarkers const& markers, UnreadEventClassifier& unread) -> ThreadNotificationCounts
{
    auto counts = ThreadNotificationCounts{};
    auto const counted_after = unread.counted_after(room_id);
    if (!counted_after.has_value())
    {
        return counts;
    }
    // Newest first, down to the marker or the start of the join, for at most the budget of rows (ADR-0617): nothing
    // at or below that floor can be unread, and the room's history is never read.
    auto const rows = store.events.room_in_stream_order(room_id);
    auto const floor = std::ranges::upper_bound(rows, std::max(markers.unthreaded, *counted_after), {},
                                                &database::PersistentEvent::stream_ordering);
    auto examined = std::size_t{0U};
    // The JSON bytes this count may still parse (ADR-0655): sender-sized events are parsed in full and followed through
    // up to three parents each, so the rows alone do not bound the work.
    auto bytes_left = max_unread_bytes_parsed;
    for (auto row = rows.end(); row > floor && examined < max_unread_rows_examined;)
    {
        --row;
        ++examined;
        auto const& ev = *row;
        store.sync_unread_rows_examined.add(1U);
        if (ev.status != "accepted" || ev.sender_user_id == user)
        {
            continue;
        }
        // Counted only if the timeline would show it: a backfilled event stored after the join is
        // judged by the state at the event, as /sync's timeline judges it.
        if (!unread.visible(ev))
        {
            continue;
        }
        if (ev.json.size() > bytes_left)
        {
            break;
        }
        bytes_left -= ev.json.size();
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
        auto const outcome = unread.classify(room_id, parsed.value);
        if (!outcome.notify)
        {
            continue;
        }
        auto thread_id = event_thread_id(store, *root, &bytes_left);
        if (markers.covers(ev.stream_ordering, thread_id))
        {
            continue;
        }
        auto& thread = counts.threads[std::move(thread_id)];
        ++thread.notification_count;
        thread.highlight_count += outcome.highlight ? 1U : 0U;
    }
    return counts;
}

auto count_notifications(database::PersistentStore const& store, std::string_view room_id, std::string_view user,
                         ReadMarkers const& markers, UnreadEventClassifier& unread) -> std::uint64_t
{
    return count_unread_by_thread(store, room_id, user, markers, unread).total().notification_count;
}

auto count_highlights(database::PersistentStore const& store, std::string_view room_id, std::string_view user,
                      ReadMarkers const& markers, UnreadEventClassifier& unread) -> std::uint64_t
{
    return count_unread_by_thread(store, room_id, user, markers, unread).total().highlight_count;
}

// Combine a list's room-config fields with a room_subscription's, per MSC4186
// room-config combination. When a room matches both a list and a
// room_subscription, required_state is the superset (union with exact-duplicate
// dedup and wildcard-aware pruning of subsumed pairs), timeline_limit is the
// maximum of the two, and include_heroes is OR'd. Wildcard-aware pruning means
// a pair such as ("m.room.member", "$ME") is dropped when
// ("m.room.member", "*") is also present, since the wildcard already matches
// every state_key; the subsumption rules reuse the anonymous-namespace matcher
// so they stay identical to the runtime matching rules.
auto build_room_response(homeserver::HomeserverRuntime const& rt, std::string_view room_id, std::string_view user,
                         SlidingSyncRoomSubscription const& sub, std::uint64_t room_since_event_ordering,
                         bool is_initial, database::PersistentStore const& store,
                         std::unordered_set<std::string> const& lazy_members_already_sent,
                         std::unordered_set<std::string> const& ignored_senders, TimelineExpansion expansion,
                         std::optional<std::uint64_t> room_last_sent_ordering,
                         std::optional<std::uint64_t> timeline_upper_bound, std::string_view device_id)
    -> SlidingSyncRoomResponse
{
    // One filter for the request: the classifier borrows it, so both share its lazy indexes.
    auto visibility = HistoryVisibility{store, user};
    auto unread = homeserver::PushRuleUnreadClassifier{
        store, user, static_cast<std::size_t>(rt.config.server().client_api.max_push_rules_per_user), visibility};
    return build_room_response(rt, room_id, user, sub, room_since_event_ordering, is_initial, store,
                               lazy_members_already_sent, ignored_senders, visibility, unread, expansion,
                               room_last_sent_ordering, timeline_upper_bound, device_id);
}

auto timeline_limit_expands(SlidingSyncConnectionState const& conn, std::string_view room_id,
                            std::uint64_t timeline_limit) -> bool
{
    auto const key = std::string{room_id};
    if (!conn.rooms_seen.contains(key))
    {
        return false;
    }
    auto const recorded = conn.room_timeline_limits.find(key);
    return recorded == conn.room_timeline_limits.end() || timeline_limit > recorded->second;
}

auto combine_room_configs(SlidingSyncList const& list, SlidingSyncRoomSubscription const& sub)
    -> SlidingSyncRoomSubscription
{
    auto combined = sub;
    combined.timeline_limit = std::max(list.timeline_limit, sub.timeline_limit);
    combined.include_heroes = list.include_heroes || sub.include_heroes;

    // Union the two required_state vectors, dropping exact duplicates.
    auto merged = std::vector<std::pair<std::string, std::string>>{};
    merged.reserve(sub.required_state.size() + list.required_state.size());
    auto const push_unique = [&](std::string const& t, std::string const& k) {
        for (auto const& existing : merged)
        {
            if (existing.first == t && existing.second == k)
            {
                return;
            }
        }
        merged.emplace_back(t, k);
    };
    for (auto const& [t, k] : sub.required_state)
    {
        push_unique(t, k);
    }
    for (auto const& [t, k] : list.required_state)
    {
        push_unique(t, k);
    }

    // Prune pairs subsumed by another pair's wildcard pattern: pair p is
    // subsumed when some other pair o matches p via the sliding-sync wildcard
    // rules (o's type "*" or equal to p's, o's key "*" or equal to p's).
    auto pruned = std::vector<std::pair<std::string, std::string>>{};
    pruned.reserve(merged.size());
    for (auto const& p : merged)
    {
        auto subsumed = false;
        for (auto const& o : merged)
        {
            if (&o == &p)
            {
                continue;
            }
            if (matches_required_state_pair(o.first, o.second, p.first, p.second))
            {
                subsumed = true;
                break;
            }
        }
        if (!subsumed)
        {
            pruned.push_back(p);
        }
    }
    combined.required_state = std::move(pruned);

    // MSC4186 configs are kept apart, so each one's `exclude` filters only what it includes (ADR-0865).
    for (auto const& config : list.required_state_configs)
    {
        if (std::ranges::find(combined.required_state_configs, config) == combined.required_state_configs.end())
        {
            combined.required_state_configs.push_back(config);
        }
    }
    return combined;
}

auto build_room_response(homeserver::HomeserverRuntime const& /*rt*/, std::string_view room_id, std::string_view user,
                         SlidingSyncRoomSubscription const& sub, std::uint64_t room_since_event_ordering,
                         bool is_initial, database::PersistentStore const& store,
                         std::unordered_set<std::string> const& lazy_members_already_sent,
                         std::unordered_set<std::string> const& ignored_senders, HistoryVisibility& visibility,
                         UnreadEventClassifier& unread, TimelineExpansion expansion,
                         std::optional<std::uint64_t> room_last_sent_ordering,
                         std::optional<std::uint64_t> timeline_upper_bound, std::string_view device_id,
                         SlidingSyncRequestLookups* lookups) -> SlidingSyncRoomResponse
{
    // The request's lookups; a caller that serves one room builds nothing to share, so the room gets its own.
    auto own_lookups = std::optional<SlidingSyncRequestLookups>{};
    if (lookups == nullptr)
    {
        lookups = &own_lookups.emplace(store, user);
    }

    auto resp = SlidingSyncRoomResponse{};

    resp.initial = is_initial;

    // The requesting user's own `unsigned.membership` and, for the sending device, `unsigned.transaction_id`
    // on every event of the response, through the request's one HistoryVisibility (ADR-0402).
    auto viewer_unsigned = ViewerEventUnsigned{store, visibility, user, device_id};

    // ── Name and avatar ─────────────────────────────────────────────────────
    resp.name = state_content_string(store, room_id, "m.room.name", "name");
    resp.avatar = state_content_string(store, room_id, "m.room.avatar", "url");
    // MSC4186 `name` / `avatar` `null`: removed. An event with no usable value is the spec's removal (an absent or
    // empty `name` is treated as no `m.room.name`); an initial response sends nothing for it.
    resp.name_removed = !is_initial && !resp.name.has_value() &&
                        database::find_current_state_event_id(store, room_id, "m.room.name", "").has_value();
    resp.avatar_removed = !is_initial && !resp.avatar.has_value() &&
                          database::find_current_state_event_id(store, room_id, "m.room.avatar", "").has_value();
    resp.name_event_ordering = current_state_ordering(store, room_id, "m.room.name");
    resp.avatar_event_ordering = current_state_ordering(store, room_id, "m.room.avatar");

    // ── is_dm ───────────────────────────────────────────────────────────────
    // The room is in the user's m.direct global account data, parsed once per request.
    resp.is_dm = lookups->is_dm(room_id);

    // ── Counts ──────────────────────────────────────────────────────────────
    resp.joined_count = count_memberships(store, room_id, "join");
    resp.invited_count = count_memberships(store, room_id, "invite");
    // #417: counts are relative to the user's last READ RECEIPT, not the sync
    // position — "events the user hasn't read", not "events the client hasn't
    // synced".
    auto const unread_counts =
        count_unread_by_thread(store, room_id, user, lookups->read_markers(room_id), unread).total();
    resp.notification_count = unread_counts.notification_count;
    resp.highlight_count = unread_counts.highlight_count;

    // ── Timestamp ───────────────────────────────────────────────────────────
    resp.timestamp = latest_timestamp(store, room_id);

    // ── Heroes ──────────────────────────────────────────────────────────────
    // MSC4186: "Heroes are only included if the room name is not set", whether or not the request asked for them with
    // MSC3575's `include_heroes` (ADR-0865).
    if (!resp.name.has_value())
    {
        resp.heroes = build_heroes(store, room_id, user);
    }

    // ── Timeline ─────────────────────────────────────────────────────────────
    // Collect events in chronological order, respecting the since floor.
    // Computed before required_state: resolving required_state's "$LAZY"
    // member sentinel needs to know which senders/subjects appear in the
    // timeline this response is about to return.
    // An initial room has no floor; an expanded one (MSC4186 "Changes to
    // `timeline_limit`") ignores it for the timeline and resends the latest
    // events, while required_state below keeps it.
    bool const timeline_has_floor = !is_initial && expansion == TimelineExpansion::none;
    auto timeline_events = std::vector<std::pair<std::uint64_t, std::string>>{};
    // The row behind each timeline entry, in the same order, for the bundled aggregations below.
    auto timeline_rows = std::vector<std::reference_wrapper<database::PersistentEvent const>>{};
    // Newest first, and only until the window and one more event that proves it is limited are held: the events
    // older than that are never built (ADR-0494). The kept window is the newest `limit` events that pass, as when
    // every event of the room was built and the oldest dropped.
    auto const limit = static_cast<std::size_t>(sub.timeline_limit);
    // Read through sync::newest_timeline_window, which also stops after max_timeline_rows_skipped rows not taken
    // (ADR-0616, ADR-0664): a room whose newest history the caller cannot see, or an ignored sender filled, is not
    // walked to its first event under runtime.mutex. Rejected and soft-failed rows are never offered to `wanted`
    // (ADR-0064 phase B2: they are never relayed; room state is built separately from current_state).
    // An incremental window stops at the delta floor, and an initial or expanded one has none.
    auto client_json_of = std::unordered_map<database::PersistentEvent const*, std::string>{};
    auto const window = newest_timeline_window(
        store, room_id, timeline_has_floor ? std::optional<std::uint64_t>{room_since_event_ordering} : std::nullopt,
        timeline_upper_bound.value_or(std::numeric_limits<std::uint64_t>::max()), limit,
        [&](database::PersistentEvent const& ev) {
            // m.room.history_visibility (CSAZ-3): an event the user may not see is not part of
            // their timeline, however recently the room was synced.
            if (!visibility.can_see(ev))
            {
                return false;
            }
            // Ignoring Users: non-state events from an ignored sender are
            // withheld from the timeline; state events are still delivered so
            // the room's visible state stays accurate — except the recipient's
            // own room invite, which the spec says must never be sent from an
            // ignored inviter even though it is itself a state event.
            // The event is parsed only when its sender is ignored (ADR-0436).
            if (ignored_senders.contains(ev.sender_user_id))
            {
                auto const ignore_classification = classify_event_for_ignore_filter(ev.json, user);
                if (trust_safety::is_delivery_suppressed(ignored_senders, ev.sender_user_id,
                                                         ignore_classification.is_state_event,
                                                         ignore_classification.is_new_room_invite_for_user))
                {
                    return false;
                }
            }
            auto client_json = client_event_json(store, ev, viewer_unsigned);
            if (client_json.empty())
            {
                return false;
            }
            client_json_of.emplace(&ev, std::move(client_json));
            return true;
        });
    for (auto const* ev : window.matched)
    {
        timeline_events.emplace_back(ev->stream_ordering, std::move(client_json_of.at(ev)));
        timeline_rows.push_back(std::cref(*ev));
    }

    bool const timeline_over_limit = timeline_events.size() > limit;
    // A walk that ran out of budget may have left older events out, so the timeline is limited (ADR-0616).
    bool const timeline_limited = timeline_over_limit || window.budget_ran_out;
    // MSC4186 §rooms[roomId] `prev_batch`: a /messages `from` that pages back to the
    // events before this timeline. /messages?dir=b returns events strictly older than
    // `from`, so it is the oldest returned event's ordering (as /v3/sync's prev_batch),
    // or, when nothing is returned, one past the newest event withheld.
    if (!timeline_events.empty())
    {
        auto const oldest_kept = timeline_over_limit ? timeline_events.size() - limit : std::size_t{0U};
        resp.prev_batch = limit == 0U ? std::to_string(timeline_events.back().first + 1U)
                                      : std::to_string(timeline_events[oldest_kept].first);
    }
    else if (window.budget_ran_out && window.oldest_examined.has_value())
    {
        // Nothing taken before the budget ran out: page back from where the walk stopped.
        resp.prev_batch = std::to_string(*window.oldest_examined);
    }
    if (timeline_limited)
    {
        // Keep the newest `limit` events. MSC4186 `limited`: "True if there are more
        // events since the previous sync than were included in the `timeline` field,
        // or that the client should paginate to fetch more events." Without it a
        // client takes the truncated timeline for the room's whole history.
        resp.limited = true;
    }
    if (timeline_over_limit)
    {
        auto const drop_count = timeline_events.size() - limit;
        timeline_events.erase(timeline_events.begin(),
                              timeline_events.begin() + static_cast<std::ptrdiff_t>(drop_count));
        timeline_rows.erase(timeline_rows.begin(), timeline_rows.begin() + static_cast<std::ptrdiff_t>(drop_count));
    }
    // MSC4186 says nothing of bundled aggregations, so the classic /sync rule is followed: a section
    // that is `limited` carries them (client-server-api.md, "Aggregations of child events"), one
    // that is not does not. Only the kept events are serialized again, with their aggregations.
    if (timeline_limited)
    {
        auto aggregations = BundledAggregations{
            store, visibility, user, ignored_senders, [&store](database::PersistentEvent const& child) {
                return canonicaljson::Value{client_event_value(store, child).value_or(canonicaljson::Object{})};
            }};
        for (auto index = std::size_t{0U}; index < timeline_events.size(); ++index)
        {
            if (auto bundled = client_event_json(store, timeline_rows[index].get(), viewer_unsigned, aggregations);
                !bundled.empty())
            {
                timeline_events[index].second = std::move(bundled);
            }
        }
    }
    // A room's first send on the connection has no previous send and no "previous
    // sync", so it is neither expanded nor live.
    auto const last_sent = room_last_sent_ordering.value_or(room_since_event_ordering);
    for (auto const& entry : timeline_events)
    {
        auto const ordering = entry.first;
        if (is_initial)
        {
            break;
        }
        if (ordering <= last_sent)
        {
            // MSC4186: "If the server does return events that predate the last time
            // the room was sent to the client, it MUST set the `expanded_timeline`".
            resp.expanded_timeline = true;
        }
        if (ordering > room_since_event_ordering)
        {
            // `num_live`: events "that have happened since the previous sync request".
            ++resp.num_live;
        }
    }

    // ── required_state ──────────────────────────────────────────────────────
    if (!sub.required_state.empty() || !sub.required_state_configs.empty())
    {
        // MSC3575's "$LAZY" pair, or an MSC4186 config's `lazy_members` that no other config overrides.
        auto const legacy_lazy = std::ranges::any_of(sub.required_state, [](auto const& p) {
            return p.first == "m.room.member" && p.second == "$LAZY";
        });
        auto const configs_lazy = configs_load_members_lazily(sub);
        auto const lazy_load_room_members = legacy_lazy || configs_lazy;
        resp.lazy_load_members = lazy_load_room_members;

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

        // The room's own state rows, in storage order (ADR-0344), not every room's.
        // A lazily loaded member is never filtered by `exclude` (MSC4186): it is matched apart from the configs. As
        // for "$LAZY", that is the timeline's members when the timeline is limited or the room initial, and otherwise
        // every member change since the floor (MSC4186's "all membership updates ... when `limited` is false").
        auto const lazily_loaded = [&](std::string_view event_type, std::string_view state_key) {
            return configs_lazy && event_type == "m.room.member" &&
                   (!scope_lazy_to_timeline || timeline_membership.contains(std::string{state_key}));
        };
        database::for_each_room_state_row(store, room_id, [&](database::PersistentStateEvent const& se) {
            auto const requested = state_event_matches_any(resolved_required_state, se.event_type, se.state_key) ||
                                   std::ranges::any_of(sub.required_state_configs,
                                                       [&](RequiredStateConfig const& c) {
                                                           return config_returns_state(c, se.event_type, se.state_key);
                                                       }) ||
                                   lazily_loaded(se.event_type, se.state_key);
            if (!requested)
            {
                return;
            }
            bool const bypass_floor = is_initial || (lazy_load_room_members && se.event_type == "m.room.member" &&
                                                     new_lazy_members.contains(se.state_key));
            // On incremental responses include only state that changed since
            // pos, unless this is a newly-relevant lazy-loaded member seeing
            // their first delivery on this connection (bypass_floor).
            for (auto const& ev : store.events.with_id(se.event_id))
            {
                if (!bypass_floor && ev.stream_ordering <= room_since_event_ordering)
                {
                    break; // unchanged since last pos — skip
                }
                // Every entry reaching here is already a known state event
                // (from store.state); only the invite override can still
                // withhold it — see classify_event_for_ignore_filter above.
                // The event is parsed only when its sender is ignored (ADR-0436).
                if (ignored_senders.contains(ev.sender_user_id) &&
                    trust_safety::is_delivery_suppressed(
                        ignored_senders, ev.sender_user_id, /*is_state_event=*/true,
                        classify_event_for_ignore_filter(ev.json, user).is_new_room_invite_for_user))
                {
                    break; // spec: invites from ignored users are not sent
                }
                if (auto client_json = client_event_json(store, ev, viewer_unsigned); !client_json.empty())
                {
                    resp.required_state_json.push_back(std::move(client_json));
                    if (se.event_type == "m.room.member")
                    {
                        resp.required_state_members.insert(se.state_key);
                    }
                }
                if (lazy_load_room_members && se.event_type == "m.room.member" &&
                    timeline_membership.contains(se.state_key))
                {
                    resp.lazy_members_included.insert(se.state_key);
                }
                break;
            }
        });
    }

    for (auto& entry : timeline_events)
    {
        resp.timeline_json.push_back(std::move(entry.second));
    }

    return resp;
}

auto add_sticky_sender_members(database::PersistentStore const& store, std::string_view room_id, std::string_view user,
                               std::unordered_set<std::string> const& senders,
                               std::unordered_set<std::string> const& lazy_members_already_sent,
                               std::unordered_set<std::string> const& ignored_senders, ViewerEventUnsigned& viewer,
                               SlidingSyncRoomResponse& room) -> std::size_t
{
    if (!room.lazy_load_members)
    {
        return 0U;
    }
    auto ordered = std::vector<std::string>{senders.begin(), senders.end()};
    std::ranges::sort(ordered);
    auto added = std::size_t{0U};
    for (auto const& sender : ordered)
    {
        if (lazy_members_already_sent.contains(sender) || room.required_state_members.contains(sender))
        {
            continue;
        }
        auto const member_event_id = database::find_current_state_event_id(store, room_id, "m.room.member", sender);
        if (!member_event_id.has_value())
        {
            continue;
        }
        auto const found = store.events.find(*member_event_id);
        if (found == store.events.end())
        {
            continue;
        }
        auto const& ev = *found;
        if (ignored_senders.contains(ev.sender_user_id) &&
            trust_safety::is_delivery_suppressed(
                ignored_senders, ev.sender_user_id, /*is_state_event=*/true,
                classify_event_for_ignore_filter(ev.json, user).is_new_room_invite_for_user))
        {
            continue;
        }
        if (auto client_json = client_event_json(store, ev, viewer); !client_json.empty())
        {
            room.required_state_json.push_back(std::move(client_json));
            room.required_state_members.insert(sender);
            room.lazy_members_included.insert(sender);
            ++added;
        }
    }
    return added;
}

namespace
{
    // MSC4186 "StrippedState": the `type`, `state_key`, `content` and `sender` of an event, or nullopt.
    [[nodiscard]] auto stripped_state_value(std::string const& event_json) -> std::optional<canonicaljson::Value>
    {
        auto const parsed = canonicaljson::parse_lossless(event_json);
        auto const* root = parsed.error == canonicaljson::ParseError::none ? as_object(parsed.value) : nullptr;
        if (root == nullptr)
        {
            return std::nullopt;
        }
        auto stripped = canonicaljson::Object{};
        for (auto const* const key : {"content", "sender", "state_key", "type"})
        {
            if (auto const* value = find_member(*root, key); value != nullptr)
            {
                stripped.emplace_back(key, std::make_unique<canonicaljson::Value>(*value));
            }
        }
        return canonicaljson::Value{std::move(stripped)};
    }

    // The user's own current m.room.member event in the room, by the state index, or nullptr.
    [[nodiscard]] auto own_member_event(database::PersistentStore const& store, std::string_view room_id,
                                        std::string_view user) -> database::PersistentEvent const*
    {
        auto const event_id = database::find_current_state_event_id(store, room_id, "m.room.member", user);
        if (!event_id.has_value())
        {
            return nullptr;
        }
        auto const found = store.events.find(*event_id);
        return found == store.events.end() ? nullptr : &*found;
    }

    // Whether the combined room config asks for a state entry of a departed room: a pair, a config, or a lazily loaded
    // member. MSC4186 "Lazy loaded memberships": the senders of the timeline's events and the targets of its membership
    // events, so `lazy_members` holds the user (every event in it is their own membership) and whoever sent each kept
    // event: the kicker or banner, whose member event is read from the departure's state like the rest.
    [[nodiscard]] auto departed_state_requested(SlidingSyncRoomSubscription const& sub, std::string_view user,
                                                std::unordered_set<std::string> const& lazy_members,
                                                std::string_view event_type, std::string_view state_key) -> bool
    {
        auto const pairs = resolve_required_state(sub.required_state, user, lazy_members,
                                                  /*scope_lazy_to_timeline=*/true);
        if (state_event_matches_any(pairs, event_type, state_key))
        {
            return true;
        }
        if (std::ranges::any_of(sub.required_state_configs, [&](RequiredStateConfig const& c) {
                return config_returns_state(c, event_type, state_key);
            }))
        {
            return true;
        }
        return configs_load_members_lazily(sub) && event_type == "m.room.member" &&
               lazy_members.contains(std::string{state_key});
    }

    // What a departed room's state event says of itself: its type, state key and, for the room's name or avatar,
    // the value, read from one parse of its JSON.
    struct DepartedStateEntry
    {
        std::string type{};
        std::string state_key{};
        std::optional<std::string> name_or_avatar{};
    };

    [[nodiscard]] auto departed_state_entry(std::string const& event_json) -> std::optional<DepartedStateEntry>
    {
        auto const parsed = canonicaljson::parse_lossless(event_json);
        auto const* root = parsed.error == canonicaljson::ParseError::none ? as_object(parsed.value) : nullptr;
        auto const* type_val = root == nullptr ? nullptr : find_member(*root, "type");
        auto const* key_val = root == nullptr ? nullptr : find_member(*root, "state_key");
        auto const* type = type_val == nullptr ? nullptr : as_string(*type_val);
        auto const* key = key_val == nullptr ? nullptr : as_string(*key_val);
        if (type == nullptr || key == nullptr)
        {
            return std::nullopt;
        }
        auto entry = DepartedStateEntry{*type, *key, std::nullopt};
        auto const is_name = *type == "m.room.name";
        if ((!is_name && *type != "m.room.avatar") || !key->empty())
        {
            return entry;
        }
        auto const* content_val = find_member(*root, "content");
        auto const* content = content_val == nullptr ? nullptr : as_object(*content_val);
        auto const* value = content == nullptr ? nullptr : find_member(*content, is_name ? "name" : "url");
        auto const* text = value == nullptr ? nullptr : as_string(*value);
        if (text != nullptr && !text->empty())
        {
            entry.name_or_avatar = *text;
        }
        return entry;
    }

    // An event's `origin_server_ts`, or 0.
    [[nodiscard]] auto origin_server_ts_of(std::string const& event_json) -> std::uint64_t
    {
        auto const parsed = canonicaljson::parse_lossless(event_json);
        auto const* root = parsed.error == canonicaljson::ParseError::none ? as_object(parsed.value) : nullptr;
        auto const* ts = root == nullptr ? nullptr : find_member(*root, "origin_server_ts");
        auto const* value = ts == nullptr ? nullptr : std::get_if<std::int64_t>(&ts->storage());
        return value == nullptr || *value < 0 ? 0U : static_cast<std::uint64_t>(*value);
    }
} // namespace

auto build_departed_room_response(database::PersistentStore const& store, std::string_view room_id,
                                  std::string_view user, SlidingSyncRoomSubscription const& sub,
                                  RoomReadAccess const& access, HistoryVisibility& visibility,
                                  std::string_view device_id) -> SlidingSyncRoomResponse
{
    auto resp = SlidingSyncRoomResponse{};
    resp.initial = true;
    auto const* const own = own_member_event(store, room_id, user);
    if (access.kind != RoomReadKind::as_of)
    {
        auto stripped = canonicaljson::Array{};
        if (own != nullptr)
        {
            if (auto value = stripped_state_value(own->json); value.has_value())
            {
                stripped.push_back(std::move(*value));
            }
        }
        resp.invite_state_json = serialized_client_event(canonicaljson::Value{std::move(stripped)});
        return resp;
    }
    auto viewer = ViewerEventUnsigned{store, visibility, user, device_id};
    // The timeline: the event that ended the stay and, when a later one (a ban after leaving) is current, that one.
    auto timeline = std::vector<database::PersistentEvent const*>{};
    if (auto const boundary = store.events.find(access.boundary_event_id); boundary != store.events.end())
    {
        timeline.push_back(&*boundary);
    }
    if (own != nullptr && own->event_id != access.boundary_event_id)
    {
        timeline.push_back(own);
    }
    // MSC4186 `timeline_limit`: the newest that many of them, oldest first, and `prev_batch` from the oldest kept.
    std::erase_if(timeline, [&visibility](database::PersistentEvent const* ev) {
        return !visibility.can_see(*ev);
    });
    auto const limit = static_cast<std::size_t>(sub.timeline_limit);
    auto const kept_from = timeline.size() > limit ? timeline.size() - limit : std::size_t{0U};
    auto const kept = std::span{timeline}.subspan(kept_from);
    // MSC4186 "Lazy loaded memberships": the kept events' senders and the targets of their membership events (the
    // user, whose own membership each of them is).
    auto lazy_members = std::unordered_set<std::string>{std::string{user}};
    for (auto const* const ev : kept)
    {
        lazy_members.insert(ev->sender_user_id);
    }
    // The state as of the departure, never later (RoomReadAccess, ADR-0084): a lazily loaded kicker's member event too.
    for (auto const& event_id :
         room_state_event_ids(store, room_id, access, std::nullopt).value_or(std::vector<std::string>{}))
    {
        auto const found = store.events.find(event_id);
        auto const entry = found == store.events.end() ? std::nullopt : departed_state_entry(found->json);
        if (!entry.has_value())
        {
            continue;
        }
        if (entry->name_or_avatar.has_value())
        {
            (entry->type == "m.room.name" ? resp.name : resp.avatar) = entry->name_or_avatar;
        }
        if (!departed_state_requested(sub, user, lazy_members, entry->type, entry->state_key))
        {
            continue;
        }
        if (auto json = client_event_json(store, *found, viewer); !json.empty())
        {
            resp.required_state_json.push_back(std::move(json));
        }
    }
    for (auto const* const ev : kept)
    {
        if (auto json = client_event_json(store, *ev, viewer); !json.empty())
        {
            resp.timeline_json.push_back(std::move(json));
            if (!resp.prev_batch.has_value())
            {
                resp.prev_batch = std::to_string(ev->stream_ordering);
            }
        }
    }
    if (!resp.prev_batch.has_value() && !timeline.empty())
    {
        // Nothing kept (`timeline_limit` 0): page back from one past the newest event withheld, as a joined room's
        // empty timeline does, so `/messages?dir=b` returns it and everything before. Never `limited` without it.
        resp.prev_batch = std::to_string(timeline.back()->stream_ordering + 1U);
    }
    // Earlier events the user could see are not in it; `/messages` from `prev_batch` reaches them.
    resp.limited = true;
    resp.timestamp = timeline.empty() ? 0U : origin_server_ts_of(timeline.back()->json);
    return resp;
}

auto read_receipt_markers(homeserver::HomeserverRuntime const& /*rt*/, database::PersistentStore const& store,
                          std::string_view room_id, std::string_view user) -> ReadMarkers
{
    return read_markers_for(store, room_id, user);
}

} // namespace merovingian::sync
