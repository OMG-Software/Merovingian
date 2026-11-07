// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/retention_sweep.hpp"

#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreBackend.hpp"
#include "merovingian/database/UnusableCredentials.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/local_services.hpp"
#include "merovingian/observability/AuditCategory.hpp"
#include "merovingian/observability/SingleLog.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <tuple>
#include <unordered_set>
#include <vector>

namespace merovingian::homeserver
{

namespace
{

    constexpr auto milliseconds_per_day = std::uint64_t{86'400'000U};

    // Returns true when everything unusable was deleted (or nothing was), false when the sweep stopped early.
    [[nodiscard]] auto sweep_credentials(HomeserverRuntime& runtime, std::chrono::system_clock::time_point now,
                                         StopFlag const& stop) -> bool
    {
        auto pending = database::UnusableCredentials{};
        {
            auto const guard = RuntimeLock{runtime.mutex};
            pending = database::collect_unusable_credentials(runtime.database.persistent_store, now,
                                                             expired_access_token_grace);
        }
        auto deleted = database::UnusableCredentials{};
        auto access_next = std::size_t{0U};
        auto refresh_next = std::size_t{0U};
        auto batches = std::size_t{0U};
        auto failed = false;
        while (
            (access_next < pending.access_token_hashes.size() || refresh_next < pending.refresh_token_hashes.size()) &&
            batches < retention_max_batches && !stop.stop_requested())
        {
            auto const access_count = std::min(retention_batch_rows, pending.access_token_hashes.size() - access_next);
            auto const refresh_count =
                std::min(retention_batch_rows - access_count, pending.refresh_token_hashes.size() - refresh_next);
            auto const access_batch =
                std::span<std::string const>{pending.access_token_hashes}.subspan(access_next, access_count);
            auto const refresh_batch =
                std::span<std::string const>{pending.refresh_token_hashes}.subspan(refresh_next, refresh_count);
            {
                auto const guard = RuntimeLock{runtime.mutex};
                if (!database::delete_credential_rows(runtime.database.persistent_store, access_batch, refresh_batch))
                {
                    failed = true;
                }
            }
            if (failed)
            {
                LOG_WARNING("Retention sweep could not delete a batch of unusable tokens; will retry");
                break;
            }
            deleted.access_token_hashes.insert(deleted.access_token_hashes.end(), access_batch.begin(),
                                               access_batch.end());
            deleted.refresh_token_hashes.insert(deleted.refresh_token_hashes.end(), refresh_batch.begin(),
                                                refresh_batch.end());
            access_next += access_count;
            refresh_next += refresh_count;
            ++batches;
        }
        if (!deleted.access_token_hashes.empty() || !deleted.refresh_token_hashes.empty())
        {
            // Memory follows the database, and only for what the database really lost.
            auto const gone =
                std::unordered_set<std::string>{deleted.access_token_hashes.begin(), deleted.access_token_hashes.end()};
            auto const guard = RuntimeLock{runtime.mutex};
            database::forget_credentials(runtime.database.persistent_store, deleted);
            std::ignore = runtime.database.sessions.erase_if([&gone](LocalSession const& session) {
                return gone.contains(session.access_token_hash);
            });
            LOG_INFO("Retention sweep deleted unusable tokens; access=" +
                     std::to_string(deleted.access_token_hashes.size()) +
                     " refresh=" + std::to_string(deleted.refresh_token_hashes.size()));
        }
        // A failed write is logged and retried at the ordinary interval; only a batch cap asks for a quick return.
        return failed || (access_next >= pending.access_token_hashes.size() &&
                          refresh_next >= pending.refresh_token_hashes.size());
    }

    [[nodiscard]] auto sweep_audit_log(HomeserverRuntime& runtime, std::chrono::system_clock::time_point now,
                                       StopFlag const& stop) -> bool
    {
        auto retention_days = std::uint32_t{0U};
        {
            auto const guard = RuntimeLock{runtime.mutex};
            retention_days = runtime.config.security().audit_log_retention_days;
        }
        if (retention_days == 0U)
        {
            return true;
        }
        auto const now_ms = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count());
        auto const keep_ms = std::uint64_t{retention_days} * milliseconds_per_day;
        if (now_ms <= keep_ms)
        {
            return true;
        }
        auto const cutoff_ms = now_ms - keep_ms;
        auto const& store = runtime.database.persistent_store;
        // Only a memory store's window is read by the probe, and that is read under the lock; a database store
        // reads its own file or server through a connection the probe opens, from fields fixed when it opened.
        auto const rows_remain = [&]() -> std::optional<bool> {
            if (store.backend == database::PersistentStoreBackend::memory)
            {
                auto const guard = RuntimeLock{runtime.mutex};
                return database::audit_rows_older_than_exist(store, cutoff_ms);
            }
            return database::audit_rows_older_than_exist(store, cutoff_ms);
        };
        auto batches = std::size_t{0U};
        auto done = false;
        while (batches < retention_max_batches && !stop.stop_requested())
        {
            auto const remain = rows_remain();
            if (!remain.has_value())
            {
                LOG_WARNING("Retention sweep could not read the audit log; will retry");
                return true;
            }
            if (!*remain)
            {
                done = true;
                break;
            }
            auto const guard = RuntimeLock{runtime.mutex};
            if (!database::delete_audit_rows_older_than(runtime.database.persistent_store, cutoff_ms,
                                                        retention_batch_rows))
            {
                LOG_WARNING("Retention sweep could not delete a batch of audit rows; will retry");
                return true;
            }
            std::ignore = database::forget_audit_events_older_than(runtime.database.persistent_store, cutoff_ms);
            ++batches;
        }
        if (batches != 0U)
        {
            // Deleting evidence is itself recorded, after the deletion and so never deleted by it.
            auto const guard = RuntimeLock{runtime.mutex};
            append_local_audit(runtime.database, observability::AuditCategory::admin, "audit.retention.purged",
                               "server", "audit_log",
                               "rows older than " + std::to_string(cutoff_ms) + " ms since the epoch (" +
                                   std::to_string(retention_days) + " days) deleted in " + std::to_string(batches) +
                                   " batches of up to " + std::to_string(retention_batch_rows));
        }
        return done;
    }

} // namespace

auto run_retention_sweep(HomeserverRuntime& runtime, std::chrono::system_clock::time_point now, StopFlag const& stop)
    -> std::chrono::milliseconds
{
    auto const credentials_done = sweep_credentials(runtime, now, stop);
    auto const audit_done = sweep_audit_log(runtime, now, stop);
    if (credentials_done && audit_done)
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(retention_sweep_interval);
    }
    return std::chrono::duration_cast<std::chrono::milliseconds>(retention_sweep_continue_interval);
}

} // namespace merovingian::homeserver
