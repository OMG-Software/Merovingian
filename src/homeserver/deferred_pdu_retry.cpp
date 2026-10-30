// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/deferred_pdu_retry.hpp"

#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/local_services.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{
namespace
{

    [[nodiscard]] auto wall_clock_ms() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    }

    [[nodiscard]] auto find_row(database::PersistentStore& store, std::string_view event_id)
    {
        return std::ranges::find_if(store.deferred_pdus, [event_id](database::PersistentDeferredPdu const& row) {
            return row.event_id == event_id;
        });
    }

    [[nodiscard]] auto over_age_or_attempt_limit(database::PersistentDeferredPdu const& row,
                                                 std::int64_t now_ms) noexcept -> bool
    {
        auto const max_age_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(database::max_deferred_pdu_age).count();
        return row.attempts >= database::max_deferred_pdu_attempts || now_ms - row.received_at_ms > max_age_ms;
    }

    // Removes a retained PDU that will not be retried again, with the audit trail
    // of why. The caller holds runtime.mutex.
    auto drop_deferral(HomeserverRuntime& runtime, database::PersistentDeferredPdu const& row, std::string_view why)
        -> void
    {
        LOG_WARNING("Dropping a retained federation PDU: " + std::string{why} + "; event_id=" + row.event_id +
                    " room_id=" + row.room_id + " attempts=" + std::to_string(row.attempts));
        append_local_audit(runtime.database, observability::AuditCategory::policy, "federation.pdu_deferral_expired",
                           row.origin, row.event_id, why);
        runtime.deferred_pdu_next_attempt.erase(row.event_id);
        if (!database::remove_deferred_pdu(runtime.database.persistent_store, row.event_id))
        {
            LOG_WARNING("Could not remove a dropped retained federation PDU; event_id=" + row.event_id);
        }
    }

    // True for the outcomes after which the PDU needs no further retry: it is
    // stored (accepted, soft-failed, rejected -- each keeps the event for later
    // authorisation) or can never be placed (rejected as invalid, for instance
    // because this server has since left the room).
    [[nodiscard]] auto retry_is_finished(federation::PduIngestionStatus status) noexcept -> bool
    {
        switch (status)
        {
        case federation::PduIngestionStatus::accepted:
        case federation::PduIngestionStatus::soft_failed:
        case federation::PduIngestionStatus::rejected_auth:
        case federation::PduIngestionStatus::rejected_state_conflict:
        case federation::PduIngestionStatus::rejected_invalid:
        case federation::PduIngestionStatus::already_stored:
            return true;
        case federation::PduIngestionStatus::internal_error:
        case federation::PduIngestionStatus::missing_prev_state:
        case federation::PduIngestionStatus::main_overloaded:
        case federation::PduIngestionStatus::deferred:
            return false;
        }
        return false;
    }

} // namespace

auto deferred_pdu_backoff(std::uint32_t attempts_so_far) noexcept -> std::chrono::milliseconds
{
    auto delay = std::chrono::duration_cast<std::chrono::milliseconds>(deferred_pdu_initial_backoff);
    auto const cap = std::chrono::duration_cast<std::chrono::milliseconds>(deferred_pdu_max_backoff);
    for (auto i = std::uint32_t{1U}; i < attempts_so_far && delay < cap; ++i)
    {
        delay *= 2;
    }
    return std::min(delay, cap);
}

auto defer_unresolved_pdu(HomeserverRuntime& runtime, federation::InboundPduEnvelope const& envelope,
                          std::string const& stored_json) -> bool
{
    // Without the server that sent it there is nowhere to fetch the missing
    // history from, so a retry could only fail the same way.
    if (envelope.origin.empty())
    {
        return false;
    }
    auto& store = runtime.database.persistent_store;
    auto row = database::PersistentDeferredPdu{envelope.event_id, envelope.room_id, envelope.origin,
                                               stored_json,       wall_clock_ms(),  0U};
    if (auto const existing = find_row(store, envelope.event_id); existing != store.deferred_pdus.end())
    {
        row.received_at_ms = existing->received_at_ms;
        row.attempts = existing->attempts;
    }
    switch (database::upsert_deferred_pdu(store, std::move(row)))
    {
    case database::DeferredPduUpsert::inserted:
    case database::DeferredPduUpsert::updated:
        return true;
    case database::DeferredPduUpsert::refused_full:
        LOG_WARNING("Retained federation PDU set is full; not retaining event_id=" + envelope.event_id +
                    " room_id=" + envelope.room_id);
        return false;
    case database::DeferredPduUpsert::persistence_failed:
        LOG_WARNING("Could not persist a retained federation PDU; event_id=" + envelope.event_id);
        return false;
    }
    return false;
}

auto wake_deferred_pdus_waiting_for(HomeserverRuntime& runtime, std::string_view room_id, std::string_view event_id)
    -> void
{
    auto const guard = std::unique_lock<RuntimeMutex>{runtime.mutex};
    auto marked = std::size_t{0U};
    for (auto const& row : runtime.database.persistent_store.deferred_pdus)
    {
        // The stored JSON names the events the PDU is waiting for in its
        // prev_events and auth_events. A bare text match can also hit a PDU that
        // merely mentions the id; waking it early costs one attempt, no more.
        if (row.room_id == room_id && row.event_id != event_id && row.pdu_json.find(event_id) != std::string::npos)
        {
            runtime.deferred_pdu_next_attempt.erase(row.event_id);
            ++marked;
        }
    }
    if (marked != 0U && runtime.deferred_pdu_retry_wake)
    {
        runtime.deferred_pdu_retry_wake();
    }
}

auto retry_deferred_pdus(HomeserverRuntime& runtime, StopFlag const& stop) -> std::chrono::milliseconds
{
    struct DueRow final
    {
        database::PersistentDeferredPdu row{};
        std::string room_version{};
    };

    // Phase 1, under the lock: drop what is over its limits or already stored,
    // and copy out what is due.
    auto due = std::vector<DueRow>{};
    {
        auto const guard = std::unique_lock<RuntimeMutex>{runtime.mutex};
        auto const now = std::chrono::steady_clock::now();
        auto const now_ms = wall_clock_ms();
        auto const rows = database::list_deferred_pdus(runtime.database.persistent_store);
        for (auto const& row : rows)
        {
            if (over_age_or_attempt_limit(row, now_ms))
            {
                drop_deferral(runtime, row,
                              row.attempts >= database::max_deferred_pdu_attempts ? "retry attempts exhausted"
                                                                                  : "retained for too long");
                continue;
            }
            if (database::find_event_status(runtime.database.persistent_store, row.event_id).has_value())
            {
                // Stored by some other path (backfill) since it was retained.
                runtime.deferred_pdu_next_attempt.erase(row.event_id);
                std::ignore = database::remove_deferred_pdu(runtime.database.persistent_store, row.event_id);
                continue;
            }
            auto const scheduled = runtime.deferred_pdu_next_attempt.find(row.event_id);
            if (scheduled != runtime.deferred_pdu_next_attempt.end() && scheduled->second > now)
            {
                continue;
            }
            if (due.size() < deferred_pdu_retry_batch)
            {
                due.push_back({row, runtime.federation.room_version_resolver
                                        ? runtime.federation.room_version_resolver(row.room_id)
                                        : std::string{}});
            }
        }
    }

    // Phase 2, holding nothing: ingestion takes its own locks and may go to the
    // network for the missing history.
    for (auto const& item : due)
    {
        if (stop.stop_requested())
        {
            break;
        }
        auto const& row = item.row;
        auto const envelope = federation::rebuild_inbound_pdu_envelope(row.pdu_json, item.room_version, row.origin);
        if (!envelope.has_value() || envelope->event_id != row.event_id || envelope->room_id != row.room_id)
        {
            auto const guard = std::unique_lock<RuntimeMutex>{runtime.mutex};
            drop_deferral(runtime, row, "retained PDU no longer parses as the event it was kept for");
            continue;
        }
        // The production sink also publishes an accepted event to sync and the
        // push pipeline, which ingest_pdu_event alone does not.
        auto const result =
            runtime.federation.pdu_sink ? runtime.federation.pdu_sink(*envelope) : ingest_pdu_event(runtime, *envelope);

        auto const guard = std::unique_lock<RuntimeMutex>{runtime.mutex};
        if (retry_is_finished(result.status))
        {
            LOG_INFO("Retained federation PDU resolved; event_id=" + row.event_id + " room_id=" + row.room_id +
                     " attempts=" + std::to_string(row.attempts));
            runtime.deferred_pdu_next_attempt.erase(row.event_id);
            std::ignore = database::remove_deferred_pdu(runtime.database.persistent_store, row.event_id);
            continue;
        }
        auto& store = runtime.database.persistent_store;
        auto const current = find_row(store, row.event_id);
        if (current == store.deferred_pdus.end())
        {
            runtime.deferred_pdu_next_attempt.erase(row.event_id);
            continue;
        }
        auto next = *current;
        ++next.attempts;
        std::ignore = database::upsert_deferred_pdu(store, std::move(next));
        runtime.deferred_pdu_next_attempt[row.event_id] =
            std::chrono::steady_clock::now() + deferred_pdu_backoff(row.attempts + 1U);
    }

    // Phase 3: when to come back.
    auto const guard = std::unique_lock<RuntimeMutex>{runtime.mutex};
    auto const now = std::chrono::steady_clock::now();
    auto delay = std::chrono::duration_cast<std::chrono::milliseconds>(deferred_pdu_idle_delay);
    for (auto const& row : runtime.database.persistent_store.deferred_pdus)
    {
        auto const scheduled = runtime.deferred_pdu_next_attempt.find(row.event_id);
        auto const wait = scheduled == runtime.deferred_pdu_next_attempt.end()
                              ? std::chrono::milliseconds{0}
                              : std::chrono::duration_cast<std::chrono::milliseconds>(scheduled->second - now);
        delay = std::min(delay, wait);
    }
    return std::max(delay, std::chrono::milliseconds{1000});
}

DeferredPduRetryJob::DeferredPduRetryJob(HomeserverRuntime& runtime)
    : runtime_{runtime}
    , job_{"deferred-pdu-retry", [&runtime](StopFlag const& stop) {
               return retry_deferred_pdus(runtime, stop);
           }}
{
}

DeferredPduRetryJob::~DeferredPduRetryJob()
{
    stop();
}

auto DeferredPduRetryJob::start() -> bool
{
    {
        auto const guard = std::unique_lock<RuntimeMutex>{runtime_.mutex};
        runtime_.deferred_pdu_retry_wake = [this]() {
            job_.wake();
        };
    }
    if (!job_.start())
    {
        stop();
        return false;
    }
    return true;
}

auto DeferredPduRetryJob::stop() noexcept -> void
{
    {
        auto const guard = std::unique_lock<RuntimeMutex>{runtime_.mutex};
        runtime_.deferred_pdu_retry_wake = nullptr;
    }
    job_.stop();
}

} // namespace merovingian::homeserver
