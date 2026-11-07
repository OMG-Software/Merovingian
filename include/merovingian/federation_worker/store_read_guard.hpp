// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/federation/FederationRuntimeState.hpp"

#include <mutex>
#include <shared_mutex>
#include <string_view>

namespace merovingian::federation_worker
{

// F-27 (ADR-0360): the federation worker's PersistentStore is read by many request threads while a
// `room_sync` rewrites one room of it on another. The tables have no lock of their own, a reload
// removes a room's rows and puts them back table by table (so a reader in between sees a room with
// no ACL, no create event, no state), and a view into a table is valid only until the next write.
// This guard gives the worker one reader-writer lock for that:
//
//   * every provider that reads the store runs under a SHARED lock, for the provider's own call
//     only, and returns values it owns, so nothing it hands back points into a table;
//   * a reload reads the database first, with no lock held, and takes the EXCLUSIVE lock only for the
//     in-memory swap, so readers wait for the swap and never for the database.
//
// It is worker-only. The same provider lambdas run in main, where the store is guarded by
// runtime.mutex and a whole-table read must not be moved under it, so they are left as they are and
// only the worker's copies are wrapped. Never hold the shared lock across an IPC round trip or any
// other wait on another process: a pending writer would then block every later reader.
class StoreReadGuard final
{
public:
    StoreReadGuard() = default;
    ~StoreReadGuard() = default;

    StoreReadGuard(StoreReadGuard const&) = delete;
    auto operator=(StoreReadGuard const&) -> StoreReadGuard& = delete;
    StoreReadGuard(StoreReadGuard&&) = delete;
    auto operator=(StoreReadGuard&&) -> StoreReadGuard& = delete;

    // Wraps every provider in `state` that reads the worker's store: the room ACL, the room version,
    // the make_leave/make_knock membership template, /backfill, /state, /state_ids, /event_auth,
    // /get_missing_events, /timestamp_to_event and the space hierarchy. Call it once, after the
    // providers are wired and before any override of a provider that relays to main (a relay holds
    // no store lock). An unset provider stays unset. This guard must outlive `state`.
    auto wrap_store_readers(federation::FederationRuntimeState& state) -> void;

    // database::reload_room with the lock split above. Returns false only when the database read
    // fails, in which case the store is untouched. Reloads are serialised with each other (the last
    // one to run holds the freshest read), never with readers except during the swap.
    [[nodiscard]] auto reload_room(database::PersistentStore& store, std::string_view room_id) -> bool;

private:
    std::shared_mutex store_mutex_{};
    std::mutex reload_mutex_{};
};

} // namespace merovingian::federation_worker
