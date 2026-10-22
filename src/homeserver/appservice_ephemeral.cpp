// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/homeserver/appservice_ephemeral.hpp"

#include "merovingian/appservice/registration.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/homeserver/appservice_delivery.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/sync/receipt_content_builder.hpp"

#include <algorithm>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{
namespace
{

    // Separates the parts of a coalescing key. A control character no identifier can contain.
    constexpr auto key_separator = char{'\x1f'};

    [[nodiscard]] auto string_member(std::string_view key, std::string_view value) -> canonicaljson::ObjectMember
    {
        return canonicaljson::make_member(std::string{key}, canonicaljson::Value{std::string{value}});
    }

    [[nodiscard]] auto serialize_event(canonicaljson::Object event) -> std::string
    {
        auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(event)});
        return serialized.error == canonicaljson::CanonicalJsonError::none ? serialized.output : std::string{};
    }

    // An appservice that wants ephemeral data and can be sent any: `url: null` means "no traffic is
    // required", so nothing is queued for it.
    [[nodiscard]] auto receives_ephemeral(appservice::AppserviceRegistration const& registration) noexcept -> bool
    {
        return registration.receive_ephemeral && registration.url.has_value();
    }

    [[nodiscard]] auto any_receives_ephemeral(HomeserverRuntime const& runtime) -> bool
    {
        return std::ranges::any_of(runtime.appservices.all(), receives_ephemeral);
    }

    [[nodiscard]] auto find_local_room(HomeserverRuntime const& runtime, std::string_view room_id) -> LocalRoom const*
    {
        auto const found = std::ranges::find_if(runtime.database.rooms, [room_id](LocalRoom const& room) {
            return room.room_id == room_id;
        });
        return found == runtime.database.rooms.end() ? nullptr : &*found;
    }

    // Queues `item` for `registration`, remembering whether anything was queued so the caller wakes
    // the drainer once.
    auto queue_for(HomeserverRuntime& runtime, appservice::AppserviceRegistration const& registration,
                   AppserviceEphemeralItem item, bool& queued) -> void
    {
        auto& queue = runtime.appservice_ephemeral[registration.id];
        auto const dropped_before = queue.dropped;
        push_appservice_ephemeral(queue, std::move(item), max_appservice_ephemeral_queue);
        queued = true;
        if (queue.dropped != dropped_before && queue.dropped == 1U)
        {
            // Once per process and appservice: a steady drop rate would otherwise log per event.
            observability::log_diagnostic("appservice", "appservice.ephemeral.dropped",
                                          {
                                              {"appservice_id", registration.id,                                false},
                                              {"capacity",      std::to_string(max_appservice_ephemeral_queue), false}
            },
                                          observability::LogEventSeverity::warning);
        }
    }

    auto wake_drainer(HomeserverRuntime& runtime) -> void
    {
        if (runtime.appservice_delivery_wake)
        {
            runtime.appservice_delivery_wake();
        }
    }

} // namespace

auto make_typing_ephemeral_event(std::string_view room_id, std::vector<std::string> const& user_ids) -> std::string
{
    auto users = canonicaljson::Array{};
    for (auto const& user_id : user_ids)
    {
        users.emplace_back(canonicaljson::Value{user_id});
    }
    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member("user_ids", canonicaljson::Value{std::move(users)}));
    auto event = canonicaljson::Object{};
    event.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
    event.push_back(string_member("room_id", room_id));
    event.push_back(string_member("type", "m.typing"));
    return serialize_event(std::move(event));
}

auto make_receipt_ephemeral_event(database::PersistentReceipt const& receipt) -> std::string
{
    auto builder = sync::ReceiptContentBuilder{};
    builder.add(receipt);
    auto event = canonicaljson::Object{};
    event.push_back(canonicaljson::make_member("content", canonicaljson::Value{builder.build()}));
    event.push_back(string_member("room_id", receipt.room_id));
    event.push_back(string_member("type", "m.receipt"));
    return serialize_event(std::move(event));
}

auto make_presence_ephemeral_event(database::PersistentPresence const& presence,
                                   std::optional<database::PersistentProfile> const& profile) -> std::string
{
    auto content = canonicaljson::Object{};
    content.push_back(string_member("presence", presence.presence));
    if (!presence.status_msg.empty())
    {
        content.push_back(string_member("status_msg", presence.status_msg));
    }
    content.push_back(canonicaljson::make_member("last_active_ago", canonicaljson::Value{presence.last_active_ago}));
    content.push_back(canonicaljson::make_member("currently_active", canonicaljson::Value{presence.currently_active}));
    // Spec (m.presence): `displayname` and `avatar_url` are the user's current ones, "if any".
    if (profile.has_value())
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
    auto event = canonicaljson::Object{};
    event.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
    event.push_back(string_member("sender", presence.user_id));
    event.push_back(string_member("type", "m.presence"));
    return serialize_event(std::move(event));
}

auto push_appservice_ephemeral(AppserviceEphemeralQueue& queue, AppserviceEphemeralItem item, std::size_t capacity)
    -> void
{
    // The newer item describes the present; the older one with the same key is stale.
    std::erase_if(queue.items, [&item](AppserviceEphemeralItem const& queued) {
        return queued.key == item.key;
    });
    while (!queue.items.empty() && queue.items.size() >= std::max(capacity, std::size_t{1U}))
    {
        queue.items.pop_front();
        ++queue.dropped;
    }
    queue.items.push_back(std::move(item));
}

auto queue_appservice_typing(HomeserverRuntime& runtime, std::string_view room_id) -> void
{
    if (!any_receives_ephemeral(runtime))
    {
        return;
    }
    auto const lock = std::unique_lock<RuntimeMutex>{runtime.mutex};
    auto const* const room = find_local_room(runtime, room_id);
    if (room == nullptr)
    {
        return;
    }
    auto const serialized = make_typing_ephemeral_event(room_id, current_typing_users_in_room(runtime, room_id));
    if (serialized.empty())
    {
        return;
    }
    auto const aliases = appservice_room_aliases(runtime, room_id);
    auto const key = std::string{"typing"} + key_separator + std::string{room_id};
    auto const& server_name = runtime.config.server().server_name;
    auto queued = false;
    for (auto const& registration : runtime.appservices.all())
    {
        if (receives_ephemeral(registration) &&
            appservice::registration_interested_in_room_event(
                registration, server_name,
                {.room_id = room_id, .room_aliases = aliases, .room_members = room->members}))
        {
            queue_for(runtime, registration, {key, serialized}, queued);
        }
    }
    if (queued)
    {
        wake_drainer(runtime);
    }
}

auto queue_appservice_receipt(HomeserverRuntime& runtime, database::PersistentReceipt const& receipt) -> void
{
    if (!any_receives_ephemeral(runtime))
    {
        return;
    }
    auto const lock = std::unique_lock<RuntimeMutex>{runtime.mutex};
    auto const* const room = find_local_room(runtime, receipt.room_id);
    if (room == nullptr)
    {
        return;
    }
    auto const serialized = make_receipt_ephemeral_event(receipt);
    if (serialized.empty())
    {
        return;
    }
    auto const aliases = appservice_room_aliases(runtime, receipt.room_id);
    // Latest wins per (room, user, receipt type, thread): an older receipt of the same user in the
    // same slot says nothing the newer one does not.
    auto const key = std::string{"receipt"} + key_separator + receipt.room_id + key_separator + receipt.user_id +
                     key_separator + receipt.receipt_type + key_separator + receipt.thread_id;
    auto const& server_name = runtime.config.server().server_name;
    auto const is_private = receipt.receipt_type == "m.read.private";
    auto queued = false;
    for (auto const& registration : runtime.appservices.all())
    {
        if (!receives_ephemeral(registration) ||
            !appservice::registration_interested_in_room_event(
                registration, server_name,
                {.room_id = receipt.room_id, .room_aliases = aliases, .room_members = room->members}))
        {
            continue;
        }
        // "Private read receipts MUST only be sent for users matching one of the application
        // service's namespaces." (Normal and threaded read receipts are always sent.)
        if (is_private && !appservice::appservice_owns_user(registration, server_name, receipt.user_id))
        {
            continue;
        }
        queue_for(runtime, registration, {key, serialized}, queued);
    }
    if (queued)
    {
        wake_drainer(runtime);
    }
}

auto queue_appservice_presence(HomeserverRuntime& runtime, database::PersistentPresence const& presence) -> void
{
    if (!any_receives_ephemeral(runtime))
    {
        return;
    }
    auto const lock = std::unique_lock<RuntimeMutex>{runtime.mutex};
    auto const& server_name = runtime.config.server().server_name;

    // "matching one of the application service's namespaces" (a local user only) settles it at once.
    auto relevant = std::vector<appservice::AppserviceRegistration const*>{};
    auto undecided = std::vector<appservice::AppserviceRegistration const*>{};
    for (auto const& registration : runtime.appservices.all())
    {
        if (!receives_ephemeral(registration))
        {
            continue;
        }
        if (appservice::appservice_owns_user(registration, server_name, presence.user_id))
        {
            relevant.push_back(&registration);
        }
        else
        {
            undecided.push_back(&registration);
        }
    }

    // "a user an application service shares a room with". Finding the rooms the subject is in is a
    // string comparison per member and is not charged; the namespace match per member is the
    // expensive part, and it alone spends the budget, so a server with many large rooms the subject
    // is not in still sends presence for the rooms the subject is in.
    auto remaining_checks = max_appservice_presence_member_checks;
    for (auto const& room : runtime.database.rooms)
    {
        if (undecided.empty() || remaining_checks == 0U)
        {
            break;
        }
        if (std::ranges::find(room.members, presence.user_id) == room.members.end())
        {
            continue;
        }
        for (auto candidate = undecided.begin(); candidate != undecided.end() && remaining_checks > 0U;)
        {
            auto shares = false;
            for (auto const& member : room.members)
            {
                if (remaining_checks == 0U)
                {
                    break;
                }
                --remaining_checks;
                if (appservice::appservice_owns_user(**candidate, server_name, member))
                {
                    shares = true;
                    break;
                }
            }
            if (shares)
            {
                relevant.push_back(*candidate);
                candidate = undecided.erase(candidate);
            }
            else
            {
                ++candidate;
            }
        }
    }
    if (relevant.empty())
    {
        return;
    }

    auto const serialized = make_presence_ephemeral_event(
        presence, database::find_profile(runtime.database.persistent_store, presence.user_id));
    if (serialized.empty())
    {
        return;
    }
    auto const key = std::string{"presence"} + key_separator + presence.user_id;
    auto queued = false;
    for (auto const* const registration : relevant)
    {
        queue_for(runtime, *registration, {key, serialized}, queued);
    }
    if (queued)
    {
        wake_drainer(runtime);
    }
}

auto take_appservice_ephemeral(HomeserverRuntime& runtime, std::string_view appservice_id) -> std::vector<std::string>
{
    auto taken = std::vector<std::string>{};
    auto const queue = runtime.appservice_ephemeral.find(appservice_id);
    if (queue == runtime.appservice_ephemeral.end())
    {
        return taken;
    }
    while (!queue->second.items.empty() && taken.size() < max_appservice_ephemeral_per_transaction)
    {
        taken.push_back(std::move(queue->second.items.front().json));
        queue->second.items.pop_front();
    }
    return taken;
}

auto has_appservice_ephemeral(HomeserverRuntime const& runtime, std::string_view appservice_id) -> bool
{
    auto const queue = runtime.appservice_ephemeral.find(appservice_id);
    return queue != runtime.appservice_ephemeral.end() && !queue->second.items.empty();
}

} // namespace merovingian::homeserver
