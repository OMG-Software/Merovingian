// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/homeserver/presence_service.hpp"

#include "merovingian/auth/identity.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/homeserver/appservice_ephemeral.hpp"
#include "merovingian/observability/logger.hpp"

#include <algorithm>
#include <chrono>
#include <limits>
#include <mutex>
#include <tuple>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::homeserver
{
namespace
{

    [[nodiscard]] auto string_member(std::string_view key, std::string_view value) -> canonicaljson::ObjectMember
    {
        return canonicaljson::make_member(std::string{key}, canonicaljson::Value{std::string{value}});
    }

    [[nodiscard]] auto find_member(canonicaljson::Object const& object, std::string_view key)
        -> canonicaljson::Value const*
    {
        for (auto const& member : object)
        {
            if (member.key == key)
            {
                return member.value.get();
            }
        }
        return nullptr;
    }

    // The members every presence body carries: `presence`, `status_msg` when set,
    // `last_active_ago` and `currently_active`.
    [[nodiscard]] auto base_content(database::PersistentPresence const& row, std::int64_t now_ms)
        -> canonicaljson::Object
    {
        auto content = canonicaljson::Object{};
        content.push_back(string_member("presence", row.presence));
        if (!row.status_msg.empty())
        {
            content.push_back(string_member("status_msg", row.status_msg));
        }
        content.push_back(
            canonicaljson::make_member("last_active_ago", canonicaljson::Value{presence_last_active_ago(row, now_ms)}));
        content.push_back(canonicaljson::make_member("currently_active", canonicaljson::Value{row.currently_active}));
        return content;
    }

    [[nodiscard]] auto find_row(database::PersistentStore const& store, std::string_view user_id)
    {
        return std::ranges::find_if(store.presence_states, [user_id](database::PersistentPresence const& row) {
            return row.user_id == user_id;
        });
    }

    [[nodiscard]] auto joined_rooms_of(database::PersistentStore const& store, std::string_view user)
        -> std::unordered_set<std::string_view>
    {
        auto rooms = std::unordered_set<std::string_view>{};
        for (auto const& membership : store.memberships)
        {
            if (membership.membership == "join" && membership.user_id == user)
            {
                rooms.insert(membership.room_id);
            }
        }
        return rooms;
    }

    [[nodiscard]] auto users_share_a_joined_room(database::PersistentStore const& store, std::string_view first,
                                                 std::string_view second) -> bool
    {
        auto const first_rooms = joined_rooms_of(store, first);
        if (first_rooms.empty())
        {
            return false;
        }
        return std::ranges::any_of(store.memberships, [&](database::PersistentMembership const& membership) {
            return membership.membership == "join" && membership.user_id == second &&
                   first_rooms.contains(membership.room_id);
        });
    }

    [[nodiscard]] auto is_local_user(HomeserverRuntime const& runtime, std::string_view user_id) -> bool
    {
        return auth::user_id_server_name(user_id) == runtime.config.server().server_name;
    }

    auto log_presence(std::string_view event, std::vector<observability::StructuredLogField> const& fields,
                      observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("presence", event, fields, severity);
    }

} // namespace

auto presence_state_is_valid(std::string_view state) noexcept -> bool
{
    return state == "online" || state == "offline" || state == "unavailable";
}

auto presence_enabled(HomeserverRuntime const& runtime) noexcept -> bool
{
    return runtime.config.presence().enabled;
}

auto presence_now_ms() -> std::int64_t
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

auto presence_last_active_ago(database::PersistentPresence const& row, std::int64_t now_ms) noexcept -> std::int64_t
{
    auto ago = std::max(row.last_active_ago, std::int64_t{0});
    if (row.observed_at_ms > 0 && now_ms > row.observed_at_ms)
    {
        auto const elapsed = now_ms - row.observed_at_ms;
        ago = ago > std::numeric_limits<std::int64_t>::max() - elapsed ? std::numeric_limits<std::int64_t>::max()
                                                                       : ago + elapsed;
    }
    return ago;
}

auto presence_event_content(database::PersistentStore const& store, database::PersistentPresence const& row,
                            std::int64_t now_ms) -> canonicaljson::Object
{
    auto content = base_content(row, now_ms);
    // Spec (m.presence): `displayname` and `avatar_url` are the user's current ones, "if any".
    if (auto const profile = database::find_profile(store, row.user_id); profile.has_value())
    {
        if (!profile->displayname.empty())
        {
            content.push_back(string_member("displayname", profile->displayname));
        }
        if (!profile->avatar_url.empty())
        {
            content.push_back(string_member("avatar_url", profile->avatar_url));
        }
    }
    return content;
}

auto presence_edu_content(database::PersistentPresence const& row, std::int64_t now_ms) -> std::string
{
    auto entry = canonicaljson::Object{};
    entry.push_back(string_member("user_id", row.user_id));
    for (auto& member : base_content(row, now_ms))
    {
        entry.push_back(std::move(member));
    }
    auto push = canonicaljson::Array{};
    push.push_back(canonicaljson::Value{std::move(entry)});
    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member("push", canonicaljson::Value{std::move(push)}));
    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(content)});
    return serialized.error == canonicaljson::CanonicalJsonError::none ? serialized.output : std::string{};
}

auto record_presence(HomeserverRuntime& runtime, database::PersistentPresence row) -> bool
{
    row.observed_at_ms = presence_now_ms();
    if (!database::upsert_presence(runtime.database.persistent_store, row))
    {
        return false;
    }
    // Appservices that receive ephemeral data are told (R08).
    queue_appservice_presence(runtime, row);
    return true;
}

auto read_presence(HomeserverRuntime const& runtime, std::string_view requester, std::string_view target)
    -> PresenceRead
{
    if (!presence_enabled(runtime))
    {
        return {PresenceReadStatus::not_found, {}};
    }
    auto const& store = runtime.database.persistent_store;
    if (target != requester && !users_share_a_joined_room(store, requester, target))
    {
        return {PresenceReadStatus::forbidden, {}};
    }
    auto const now_ms = presence_now_ms();
    auto const row = find_row(store, target);
    if (row != store.presence_states.end())
    {
        return {PresenceReadStatus::ok, base_content(*row, now_ms)};
    }
    if (!is_local_user(runtime, target))
    {
        return {PresenceReadStatus::not_found, {}};
    }
    // A local user who has not connected or set a presence is offline: "The user is not connected
    // to an event stream".
    auto fallback = database::PersistentPresence{};
    fallback.user_id = std::string{target};
    return {PresenceReadStatus::ok, base_content(fallback, now_ms)};
}

auto parse_sync_presence_mode(std::optional<std::string_view> value) noexcept -> std::optional<SyncPresenceMode>
{
    if (!value.has_value() || *value == "online")
    {
        return SyncPresenceMode::online;
    }
    if (*value == "unavailable")
    {
        return SyncPresenceMode::unavailable;
    }
    if (*value == "offline")
    {
        return SyncPresenceMode::offline;
    }
    return std::nullopt;
}

auto apply_sync_presence(HomeserverRuntime& runtime, std::string_view user, SyncPresenceMode mode)
    -> std::optional<database::PersistentPresence>
{
    if (mode == SyncPresenceMode::offline || !presence_enabled(runtime))
    {
        return std::nullopt;
    }
    auto& store = runtime.database.persistent_store;
    auto const now_ms = presence_now_ms();
    auto const desired =
        mode == SyncPresenceMode::online ? std::string_view{"online"} : std::string_view{"unavailable"};
    auto const existing = std::ranges::find_if(store.presence_states, [user](database::PersistentPresence const& row) {
        return row.user_id == user;
    });
    if (existing != store.presence_states.end() && existing->presence == desired)
    {
        if (mode == SyncPresenceMode::online)
        {
            // Still online: nothing to tell anyone, but the user did just do something.
            existing->last_active_ago = 0;
            existing->observed_at_ms = now_ms;
            existing->currently_active = true;
        }
        return std::nullopt;
    }
    auto row = existing != store.presence_states.end() ? *existing : database::PersistentPresence{};
    row.user_id = std::string{user};
    row.presence = std::string{desired};
    row.last_active_ago = mode == SyncPresenceMode::online || existing == store.presence_states.end()
                              ? std::int64_t{0}
                              : presence_last_active_ago(*existing, now_ms);
    row.currently_active = mode == SyncPresenceMode::online;
    if (!record_presence(runtime, row))
    {
        return std::nullopt;
    }
    row.observed_at_ms = now_ms;
    return row;
}

auto build_sync_presence_events(database::PersistentStore const& store, sync::EventTypeFilter const& filter,
                                std::string_view user, bool has_since, std::uint64_t since_sync_stream_id,
                                std::uint64_t since_ordering, std::uint64_t sync_position, std::int64_t now_ms,
                                std::uint64_t& max_observed_stream_id) -> canonicaljson::Array
{
    auto events = canonicaljson::Array{};
    // Presence is shared only with users in a room the caller is joined to (Matrix v1.19
    // Presence security considerations). Two passes over the memberships, whatever the number
    // of rooms or presence rows.
    auto joined_rooms = std::unordered_set<std::string_view>{};
    auto newly_joined_rooms = std::unordered_set<std::string_view>{};
    auto const starts_in_window = [&](database::PersistentMembership const& membership) {
        return has_since && membership.stream_ordering > since_ordering && membership.stream_ordering <= sync_position;
    };
    for (auto const& membership : store.memberships)
    {
        if (membership.user_id == user && membership.membership == "join")
        {
            joined_rooms.insert(membership.room_id);
            if (starts_in_window(membership))
            {
                newly_joined_rooms.insert(membership.room_id);
            }
        }
    }
    auto visible_users = std::unordered_set<std::string_view>{};
    // Users who started sharing a room with the caller since the token: their presence is news
    // to the caller whenever it last changed.
    auto newly_visible_users = std::unordered_set<std::string_view>{};
    for (auto const& membership : store.memberships)
    {
        if (membership.membership != "join" || !joined_rooms.contains(membership.room_id))
        {
            continue;
        }
        visible_users.insert(membership.user_id);
        if (newly_joined_rooms.contains(membership.room_id) || starts_in_window(membership))
        {
            newly_visible_users.insert(membership.user_id);
        }
    }
    auto emitted = std::size_t{0U};
    for (auto const& row : store.presence_states)
    {
        if (row.user_id == user || !visible_users.contains(row.user_id))
        {
            continue;
        }
        if (row.stream_id <= since_sync_stream_id && !newly_visible_users.contains(row.user_id))
        {
            continue;
        }
        if (!sync::event_passes_filter(filter, "m.presence", row.user_id))
        {
            continue;
        }
        if (filter.limit != 0U && emitted >= filter.limit)
        {
            break;
        }
        auto event = canonicaljson::Object{};
        event.push_back(string_member("type", "m.presence"));
        event.push_back(string_member("sender", row.user_id));
        event.push_back(
            canonicaljson::make_member("content", canonicaljson::Value{presence_event_content(store, row, now_ms)}));
        events.push_back(canonicaljson::Value{std::move(event)});
        ++emitted;
        max_observed_stream_id = std::max(max_observed_stream_id, row.stream_id);
    }
    return events;
}

auto accept_inbound_presence(HomeserverRuntime& runtime, std::string_view origin, std::string_view content_json)
    -> federation::EduDispositionResult
{
    using federation::EduDispositionStatus;
    if (!presence_enabled(runtime))
    {
        return {EduDispositionStatus::accepted, {}};
    }
    auto const parsed = canonicaljson::parse_lossless(std::string{content_json});
    auto const* root = parsed.error == canonicaljson::ParseError::none
                           ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                           : nullptr;
    if (root == nullptr)
    {
        return {EduDispositionStatus::rejected_invalid, "presence content must be an object"};
    }
    auto const* push_value = find_member(*root, "push");
    if (push_value == nullptr)
    {
        return {EduDispositionStatus::accepted, {}};
    }
    auto const* push = std::get_if<canonicaljson::Array>(&push_value->storage());
    if (push == nullptr)
    {
        return {EduDispositionStatus::rejected_invalid, "presence push must be a list"};
    }

    // The sink runs without runtime.mutex: presence rows, the appservice queue and the
    // memberships read below are all guarded by it.
    auto const guard = std::unique_lock<RuntimeMutex>{runtime.mutex};
    auto const& store = runtime.database.persistent_store;

    // Interest: users joined to a room that one of ours is joined to. One pass over each side per
    // EDU, however many entries it names.
    auto rooms_with_local_user = std::unordered_set<std::string_view>{};
    for (auto const& membership : store.memberships)
    {
        if (membership.membership == "join" && is_local_user(runtime, membership.user_id))
        {
            rooms_with_local_user.insert(membership.room_id);
        }
    }
    auto interesting_users = std::unordered_set<std::string_view>{};
    if (!push->empty())
    {
        for (auto const& membership : store.memberships)
        {
            if (membership.membership == "join" && rooms_with_local_user.contains(membership.room_id))
            {
                interesting_users.insert(membership.user_id);
            }
        }
    }

    auto refused = std::size_t{0U};
    auto looked_at = std::size_t{0U};
    for (auto const& entry_value : *push)
    {
        if (looked_at == max_inbound_presence_entries)
        {
            log_presence("presence.inbound.truncated",
                         {
                             {"origin",  std::string{origin},                          false},
                             {"entries", std::to_string(push->size()),                 false},
                             {"limit",   std::to_string(max_inbound_presence_entries), false}
            },
                         observability::LogEventSeverity::warning);
            break;
        }
        ++looked_at;
        auto const* entry = std::get_if<canonicaljson::Object>(&entry_value.storage());
        if (entry == nullptr)
        {
            return {EduDispositionStatus::rejected_invalid, "presence entry must be an object"};
        }
        auto const* user_value = find_member(*entry, "user_id");
        auto const* user_id = user_value == nullptr ? nullptr : std::get_if<std::string>(&user_value->storage());
        if (user_id == nullptr || user_id->empty() || auth::user_id_server_name(*user_id) != origin)
        {
            // A server speaks only for its own users; a claim about anyone else is a spoof.
            return {EduDispositionStatus::rejected_invalid, "presence user_id must belong to the sending origin"};
        }
        auto const* state_value = find_member(*entry, "presence");
        auto const* state = state_value == nullptr ? nullptr : std::get_if<std::string>(&state_value->storage());
        if (state == nullptr || !presence_state_is_valid(*state))
        {
            ++refused;
            continue;
        }
        auto status_msg = std::string{};
        if (auto const* status_value = find_member(*entry, "status_msg"); status_value != nullptr)
        {
            auto const* text = std::get_if<std::string>(&status_value->storage());
            if (text == nullptr || text->size() > max_presence_status_msg_bytes)
            {
                ++refused;
                continue;
            }
            status_msg = *text;
        }
        if (!interesting_users.contains(*user_id))
        {
            continue;
        }
        auto row = database::PersistentPresence{};
        row.user_id = *user_id;
        row.presence = *state;
        row.status_msg = std::move(status_msg);
        if (auto const* ago_value = find_member(*entry, "last_active_ago"); ago_value != nullptr)
        {
            auto const* ago = std::get_if<std::int64_t>(&ago_value->storage());
            if (ago != nullptr && *ago >= 0)
            {
                row.last_active_ago = *ago;
            }
        }
        if (auto const* active_value = find_member(*entry, "currently_active"); active_value != nullptr)
        {
            auto const* active = std::get_if<bool>(&active_value->storage());
            row.currently_active = active != nullptr && *active;
        }
        std::ignore = record_presence(runtime, std::move(row));
    }
    if (refused != 0U)
    {
        log_presence("presence.inbound.refused",
                     {
                         {"origin",  std::string{origin},     false},
                         {"refused", std::to_string(refused), false}
        },
                     observability::LogEventSeverity::warning);
        return {EduDispositionStatus::rejected_invalid, "presence entry has an invalid presence or status_msg"};
    }
    return {EduDispositionStatus::accepted, {}};
}

} // namespace merovingian::homeserver
