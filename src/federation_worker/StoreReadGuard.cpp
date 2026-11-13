// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation_worker/StoreReadGuard.hpp"

#include <optional>
#include <shared_mutex>
#include <utility>

namespace merovingian::federation_worker
{
namespace
{

    // Replaces `provider` with one that holds the shared lock for the whole call. The inner provider
    // returns by value, so the result is complete (and owns its data) before the lock is released.
    template <typename Provider>
    auto guard_provider(std::shared_mutex& store_mutex, Provider& provider) -> void
    {
        if (!provider)
        {
            return;
        }
        provider = [&store_mutex, inner = std::move(provider)](auto&&... arguments) {
            auto const reading = std::shared_lock{store_mutex};
            return inner(std::forward<decltype(arguments)>(arguments)...);
        };
    }

} // namespace

auto StoreReadGuard::wrap_store_readers(federation::FederationRuntimeState& state) -> void
{
    guard_provider(store_mutex_, state.room_server_acl_provider);
    guard_provider(store_mutex_, state.room_version_resolver);
    guard_provider(store_mutex_, state.membership_template_provider);
    guard_provider(store_mutex_, state.backfill_provider);
    guard_provider(store_mutex_, state.state_query_provider);
    guard_provider(store_mutex_, state.state_ids_query_provider);
    guard_provider(store_mutex_, state.event_auth_query_provider);
    guard_provider(store_mutex_, state.missing_events_query_provider);
    guard_provider(store_mutex_, state.timestamp_to_event_query_provider);
    guard_provider(store_mutex_, state.space_hierarchy_provider);
}

auto StoreReadGuard::reload_room(database::PersistentStore& store, std::string_view room_id) -> bool
{
    return reload_room_from(store, room_id, [&store](std::string_view room) {
        return database::load_room_snapshot(store, room);
    });
}

auto StoreReadGuard::reload_room_from(
    database::PersistentStore& store, std::string_view room_id,
    std::function<std::optional<database::RoomReloadSnapshot>(std::string_view room_id)> const& read) -> bool
{
    auto const reloading = std::lock_guard{reload_mutex_};
    // No store lock is held across the read: it waits on main.
    auto snapshot = read(room_id);
    if (!snapshot.has_value())
    {
        return false;
    }
    auto const writing = std::unique_lock{store_mutex_};
    database::apply_room_snapshot(store, std::move(*snapshot));
    return true;
}

} // namespace merovingian::federation_worker
