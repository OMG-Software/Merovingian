// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/homeserver/appservice_delivery.hpp"

#include "merovingian/appservice/appservice_client.hpp"
#include "merovingian/appservice/registration.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/appservice_ephemeral.hpp"
#include "merovingian/homeserver/local_services.hpp"
#include "merovingian/homeserver/request_lock.hpp"
#include "merovingian/http/outbound_client.hpp"
#include "merovingian/observability/observability.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace merovingian::homeserver
{
namespace
{

    using namespace std::chrono_literals;

    // The most transactions one drain sends to one appservice before moving on, so a long backlog
    // for one bridge cannot hold the others (or shutdown) behind it.
    constexpr auto max_transactions_per_appservice_per_drain = std::uint32_t{64U};
    constexpr auto initial_backoff = std::chrono::milliseconds{1000};
    constexpr auto maximum_backoff = std::chrono::milliseconds{5 * 60 * 1000};
    constexpr auto idle_delay = std::chrono::milliseconds{60 * 1000};

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("appservice", event, fields, severity);
    }

    [[nodiscard]] auto object_member(canonicaljson::Object const& object, std::string_view key) noexcept
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

    // Builds one Application Service API ClientEvent from a persisted event row. Nullopt only for
    // a stored row that does not parse, which cannot happen for an event this server persisted.
    [[nodiscard]] auto appservice_transaction_event_for(database::PersistentEvent const& event)
        -> std::optional<appservice::AppserviceTransactionEvent>
    {
        auto const parsed = canonicaljson::parse_lossless(event.json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (root == nullptr)
        {
            return std::nullopt;
        }
        auto out = appservice::AppserviceTransactionEvent{};
        if (auto const* content = object_member(*root, "content"); content != nullptr)
        {
            auto const serialized = canonicaljson::serialize_canonical(*content);
            if (serialized.error == canonicaljson::CanonicalJsonError::none)
            {
                out.content_json = serialized.output;
            }
        }
        out.event_id = event.event_id;
        if (auto const* ts = object_member(*root, "origin_server_ts"); ts != nullptr)
        {
            if (auto const* value = std::get_if<std::int64_t>(&ts->storage()); value != nullptr && *value > 0)
            {
                out.origin_server_ts = static_cast<std::uint64_t>(*value);
            }
        }
        out.room_id = event.room_id;
        out.sender = event.sender_user_id;
        if (auto const* type = object_member(*root, "type"); type != nullptr)
        {
            if (auto const* value = std::get_if<std::string>(&type->storage()); value != nullptr)
            {
                out.type = *value;
            }
        }
        if (auto const* state_key = object_member(*root, "state_key"); state_key != nullptr)
        {
            if (auto const* value = std::get_if<std::string>(&state_key->storage()); value != nullptr)
            {
                out.state_key = *value;
            }
        }
        return out;
    }

    // Newest rows are the likeliest, so look from the back.
    [[nodiscard]] auto find_event_by_id(database::PersistentStore const& store, std::string_view event_id)
        -> database::PersistentEvent const*
    {
        auto const newest_first = store.events | std::views::reverse;
        auto const found = std::ranges::find_if(newest_first, [event_id](database::PersistentEvent const& event) {
            return event.event_id == event_id;
        });
        return found == newest_first.end() ? nullptr : &*found;
    }

    [[nodiscard]] auto find_event_by_stream_ordering(database::PersistentStore const& store,
                                                     std::uint64_t stream_ordering) -> database::PersistentEvent const*
    {
        auto const newest_first = store.events | std::views::reverse;
        auto const found =
            std::ranges::find_if(newest_first, [stream_ordering](database::PersistentEvent const& event) {
                return event.stream_ordering == stream_ordering;
            });
        return found == newest_first.end() ? nullptr : &*found;
    }

    // Every thousandth drop is reported, starting with the first: a bridge that stays down at the
    // cap would otherwise log and audit once per event of every room it is interested in.
    constexpr auto outbox_drop_report_interval = std::uint64_t{1000U};

    // Counts an event that was not queued for `registration` because its outbox is full (ADR-0191)
    // and reports it at warning level, which also writes an audit row naming the appservice.
    auto record_outbox_drop(HomeserverRuntime& runtime, appservice::AppserviceRegistration const& registration,
                            std::string_view event_id) -> void
    {
        auto const dropped = ++runtime.appservice_outbox_dropped[registration.id];
        if ((dropped - 1U) % outbox_drop_report_interval != 0U)
        {
            return;
        }
        auto const reason = "outbox at " + std::to_string(runtime.config.appservice().max_queued_events) +
                            " queued events; events dropped so far: " + std::to_string(dropped);
        log_diagnostic_audit(runtime.database, "appservice", "appservice.outbox.full",
                             {
                                 {"appservice_id", registration.id,                                               false},
                                 {"event_id",      std::string{event_id},                                         false},
                                 {"dropped_total", std::to_string(dropped),                                       false},
                                 {"max_queued",    std::to_string(runtime.config.appservice().max_queued_events), false}
        },
                             observability::LogEventSeverity::warning, observability::AuditCategory::policy,
                             "appservice.outbox.full", registration.id, registration.id, reason);
    }

    struct AppserviceDrainOutcome final
    {
        // Rows are still queued that this call did not reach (the per-call cap), so the caller
        // should run again at once rather than wait out the idle delay.
        bool more_queued{false};
    };

    // Records a failed attempt: the next one waits twice as long as the last, from one second to
    // five minutes. `failed_at` is when the attempt ended.
    auto record_failure(HomeserverRuntime& runtime, std::string const& appservice_id,
                        std::chrono::steady_clock::time_point failed_at) -> void
    {
        auto& backoff = runtime.appservice_delivery_backoff[appservice_id];
        backoff.delay = backoff.delay.count() == 0 ? initial_backoff : std::min(backoff.delay * 2, maximum_backoff);
        backoff.retry_at = failed_at + backoff.delay;
    }

    // Sends `transaction` to the appservice with runtime.mutex released for the call, and advances
    // `clock_now` by how long it took. Called with `lock` held (exactly one level: the drainer is
    // never called under the lock).
    [[nodiscard]] auto send_over_network(HomeserverRuntime& runtime, std::unique_lock<RuntimeMutex>& lock,
                                         appservice::AppserviceRegistration const& registration,
                                         appservice::AppserviceTransaction const& transaction,
                                         std::chrono::steady_clock::time_point& clock_now)
        -> appservice::AppserviceCallResult
    {
        auto const started = std::chrono::steady_clock::now();
        // Built under the lock: it copies the timeouts out of the runtime config.
        auto client = appservice::AppserviceClient{*runtime.outbound_client, *runtime.cached_discovery,
                                                   runtime.config.appservice()};
        auto result = [&]() {
            auto const unlocked = RuntimeLockRelease{lock};
            return client.send_transaction(registration, transaction);
        }();
        clock_now +=
            std::chrono::duration_cast<std::chrono::steady_clock::duration>(std::chrono::steady_clock::now() - started);
        return result;
    }

    auto log_send_failure(std::string const& appservice_id, appservice::AppserviceTransaction const& transaction,
                          appservice::AppserviceCallResult const& result) -> void
    {
        log_diagnostic("appservice.delivery.failed",
                       {
                           {"appservice_id", appservice_id,                                        false},
                           {"txn_id",        transaction.txn_id,                                   false},
                           {"error",         std::string{http::outbound_error_name(result.error)}, false},
                           {"detail",        result.error_detail,                                  false}
        },
                       observability::LogEventSeverity::warning);
    }

    // Sends the ephemeral data of one appservice on its own, in a transaction with no events
    // (ADR-0190), because no event is queued to carry it. `pending` is the data of a transaction
    // that failed before and is sent again under its own ID; otherwise the queue is drained into a
    // fresh transaction whose ID comes from the cursor (its next_txn_id is persisted, nothing
    // else is). Returns false when the attempt failed or could not be made, in which case the
    // caller stops for this appservice until its back-off ends.
    [[nodiscard]] auto send_ephemeral_only(HomeserverRuntime& runtime, std::unique_lock<RuntimeMutex>& lock,
                                           appservice::AppserviceRegistration const& registration,
                                           std::chrono::steady_clock::time_point& clock_now) -> bool
    {
        auto& store = runtime.database.persistent_store;
        auto const& appservice_id = registration.id;
        auto pending = runtime.appservice_pending_ephemeral.find(appservice_id);
        if (pending == runtime.appservice_pending_ephemeral.end() || !pending->second.events_free)
        {
            auto cursor = database::find_appservice_txn_cursor(store, appservice_id);
            auto const txn_id = cursor.next_txn_id;
            cursor.next_txn_id += 1U;
            if (!database::store_appservice_txn_cursor(store, cursor))
            {
                log_diagnostic("appservice.delivery.cursor_write_failed",
                               {
                                   {"appservice_id", appservice_id, false}
                },
                               observability::LogEventSeverity::warning);
                record_failure(runtime, appservice_id, clock_now);
                return false;
            }
            auto items = take_appservice_ephemeral(runtime, appservice_id);
            pending = runtime.appservice_pending_ephemeral
                          .insert_or_assign(appservice_id, AppservicePendingEphemeral{txn_id, true, std::move(items)})
                          .first;
        }

        auto transaction = appservice::AppserviceTransaction{};
        transaction.txn_id = std::to_string(pending->second.txn_id);
        transaction.ephemeral_json = pending->second.items;
        auto const result = send_over_network(runtime, lock, registration, transaction, clock_now);
        if (result.ok || result.disabled)
        {
            runtime.appservice_pending_ephemeral.erase(appservice_id);
            runtime.appservice_delivery_backoff.erase(appservice_id);
            return true;
        }
        log_send_failure(appservice_id, transaction, result);
        record_failure(runtime, appservice_id, clock_now);
        return false;
    }

    // Sends the transactions queued for one appservice. Called with `lock` held; releases it
    // around every network call and holds it again on return.
    auto drain_one_appservice(HomeserverRuntime& runtime, std::unique_lock<RuntimeMutex>& lock,
                              appservice::AppserviceRegistration const& registration, StopFlag const& stop,
                              std::chrono::steady_clock::time_point& clock_now) -> AppserviceDrainOutcome
    {
        auto& store = runtime.database.persistent_store;
        auto const& appservice_id = registration.id;

        for (auto sent = std::uint32_t{0U}; sent < max_transactions_per_appservice_per_drain; ++sent)
        {
            if (stop.stop_requested())
            {
                return {};
            }
            if (auto const backoff = runtime.appservice_delivery_backoff.find(appservice_id);
                backoff != runtime.appservice_delivery_backoff.end() && backoff->second.retry_at > clock_now)
            {
                return {};
            }
            // An events-free transaction that failed before goes first, under its own ID, so its
            // ephemeral items are not reordered behind later ones.
            if (auto const parked = runtime.appservice_pending_ephemeral.find(appservice_id);
                parked != runtime.appservice_pending_ephemeral.end() && parked->second.events_free)
            {
                if (!send_ephemeral_only(runtime, lock, registration, clock_now))
                {
                    return {};
                }
                continue;
            }

            auto cursor = database::find_appservice_txn_cursor(store, appservice_id);
            auto event = std::optional<appservice::AppserviceTransactionEvent>{};
            if (cursor.pending_txn_id != 0U)
            {
                // Sent but never acknowledged: rebuild it from the stored event and send it again
                // under its own ID. This is also how a cursor left pending by the pre-outbox design
                // keeps working after an upgrade.
                auto const* const row = find_event_by_stream_ordering(store, cursor.pending_stream_ordering);
                event = row == nullptr ? std::nullopt : appservice_transaction_event_for(*row);
                if (!event.has_value())
                {
                    // An event this server persisted is never deleted and always parses, so this is
                    // corruption. Dropping the transaction is the lesser harm: leaving it pending
                    // would hold every later event for this appservice behind it for ever.
                    log_diagnostic("appservice.delivery.dropped",
                                   {
                                       {"appservice_id",   appservice_id,                                  false},
                                       {"txn_id",          std::to_string(cursor.pending_txn_id),          false},
                                       {"stream_ordering", std::to_string(cursor.pending_stream_ordering), false},
                                       {"reason",          "pending event missing or unreadable",          false}
                    },
                                   observability::LogEventSeverity::error);
                    if (!database::complete_appservice_delivery(store, appservice_id, cursor.pending_stream_ordering))
                    {
                        record_failure(runtime, appservice_id, clock_now);
                        return {};
                    }
                    continue;
                }
            }
            else
            {
                auto const entry = database::find_first_appservice_outbox_entry(store, appservice_id);
                if (!entry.has_value())
                {
                    // No event is queued; ephemeral data alone is still worth a transaction.
                    if (!has_appservice_ephemeral(runtime, appservice_id))
                    {
                        return {};
                    }
                    if (!send_ephemeral_only(runtime, lock, registration, clock_now))
                    {
                        return {};
                    }
                    continue;
                }
                auto const* const row = find_event_by_id(store, entry->event_id);
                event = row == nullptr ? std::nullopt : appservice_transaction_event_for(*row);
                if (!event.has_value())
                {
                    // As above: drop the row so one unreadable event cannot wedge the queue.
                    log_diagnostic("appservice.delivery.dropped",
                                   {
                                       {"appservice_id",   appservice_id,                          false},
                                       {"event_id",        entry->event_id,                        false},
                                       {"stream_ordering", std::to_string(entry->stream_ordering), false},
                                       {"reason",          "queued event missing or unreadable",   false}
                    },
                                   observability::LogEventSeverity::error);
                    if (!database::complete_appservice_delivery(store, appservice_id, entry->stream_ordering))
                    {
                        record_failure(runtime, appservice_id, clock_now);
                        return {};
                    }
                    continue;
                }
                // Fix the transaction's ID and contents on disk before sending: a retry, in this
                // process or the next, then reuses this ID with this event and nothing else.
                cursor.pending_txn_id = cursor.next_txn_id;
                cursor.next_txn_id += 1U;
                cursor.pending_stream_ordering = entry->stream_ordering;
                if (!database::store_appservice_txn_cursor(store, cursor))
                {
                    log_diagnostic("appservice.delivery.cursor_write_failed",
                                   {
                                       {"appservice_id", appservice_id, false}
                    },
                                   observability::LogEventSeverity::warning);
                    record_failure(runtime, appservice_id, clock_now);
                    return {};
                }
            }

            auto transaction = appservice::AppserviceTransaction{};
            transaction.txn_id = std::to_string(cursor.pending_txn_id);
            transaction.events.push_back(std::move(*event));
            // Ephemeral data (ADR-0190). A retry of this transaction ID carries the items the first
            // attempt carried; a fresh one takes what is queued now. After a restart nothing is
            // remembered, so the re-sent transaction carries its event alone.
            if (auto const parked = runtime.appservice_pending_ephemeral.find(appservice_id);
                parked != runtime.appservice_pending_ephemeral.end() && !parked->second.events_free &&
                parked->second.txn_id == cursor.pending_txn_id)
            {
                transaction.ephemeral_json = parked->second.items;
            }
            else if (registration.receive_ephemeral)
            {
                transaction.ephemeral_json = take_appservice_ephemeral(runtime, appservice_id);
                if (!transaction.ephemeral_json.empty())
                {
                    runtime.appservice_pending_ephemeral.insert_or_assign(
                        appservice_id,
                        AppservicePendingEphemeral{cursor.pending_txn_id, false, transaction.ephemeral_json});
                }
            }

            auto const result = send_over_network(runtime, lock, registration, transaction, clock_now);

            if (result.ok || result.disabled)
            {
                runtime.appservice_pending_ephemeral.erase(appservice_id);
                if (!database::complete_appservice_delivery(store, appservice_id, cursor.pending_stream_ordering))
                {
                    // The appservice has it but the acknowledgement did not reach the database, so
                    // the next attempt re-sends the same transaction ID (idempotent per the spec).
                    log_diagnostic("appservice.delivery.cursor_write_failed",
                                   {
                                       {"appservice_id", appservice_id, false}
                    },
                                   observability::LogEventSeverity::warning);
                    record_failure(runtime, appservice_id, clock_now);
                    return {};
                }
                runtime.appservice_delivery_backoff.erase(appservice_id);
                continue;
            }

            log_send_failure(appservice_id, transaction, result);
            record_failure(runtime, appservice_id, clock_now);
            return {};
        }

        // The cap was reached; whether anything is left decides whether to come straight back.
        auto const pending = database::find_appservice_txn_cursor(store, appservice_id).pending_txn_id != 0U;
        return {pending || database::find_first_appservice_outbox_entry(store, appservice_id).has_value() ||
                has_appservice_ephemeral(runtime, appservice_id)};
    }

} // namespace

auto appservice_room_aliases(HomeserverRuntime const& runtime, std::string_view room_id) -> std::vector<std::string>
{
    auto aliases = std::vector<std::string>{};
    for (auto const& alias : runtime.database.persistent_store.room_aliases)
    {
        if (alias.room_id == room_id)
        {
            aliases.push_back(alias.room_alias);
        }
    }
    return aliases;
}

auto enqueue_appservice_delivery(HomeserverRuntime& runtime, LocalRoom const& room, std::string_view event_id,
                                 std::uint64_t fallback_stream_ordering, std::string_view sender,
                                 std::string_view member_event_target) -> void
{
    enqueue_appservice_delivery(runtime, room.room_id, room.members, event_id, fallback_stream_ordering, sender,
                                member_event_target);
}

auto enqueue_appservice_delivery(HomeserverRuntime& runtime, std::string_view room_id,
                                 std::span<std::string const> room_members, std::string_view event_id,
                                 std::uint64_t fallback_stream_ordering, std::string_view sender,
                                 std::string_view member_event_target) -> void
{
    if (runtime.appservices.empty() || runtime.outbound_client == nullptr || runtime.cached_discovery == nullptr)
    {
        return;
    }
    // Recursive: free for a caller that already holds it. Taken here so the store and the room's
    // member list are never read unguarded.
    auto const lock = std::unique_lock<RuntimeMutex>{runtime.mutex};
    auto& store = runtime.database.persistent_store;
    auto const& server_name = runtime.config.server().server_name;

    auto const* const event_row = find_event_by_id(store, event_id);
    auto const stream_ordering = event_row != nullptr ? event_row->stream_ordering : fallback_stream_ordering;
    if (stream_ordering == 0U)
    {
        log_diagnostic(
            "appservice.delivery.unqueued",
            {
                {"event_id", std::string{event_id},          false},
                {"reason",   "event has no stream ordering", false}
        },
            observability::LogEventSeverity::error);
        return;
    }
    auto const room_aliases = appservice_room_aliases(runtime, room_id);
    auto const facts = appservice::EventInterestFacts{.room_id = room_id,
                                                      .room_aliases = room_aliases,
                                                      .sender = sender,
                                                      .member_event_target = member_event_target,
                                                      .room_members = room_members};

    auto queued = false;
    for (auto const& registration : runtime.appservices.all())
    {
        if (!appservice::registration_interested_in_room_event(registration, server_name, facts))
        {
            continue;
        }
        // ADR-0191: a queue at its cap takes no more rows. A row that is already queued is not a new
        // row, so the repeat of an enqueue that happened is not counted as a drop.
        if (!database::has_appservice_outbox_entry(store, registration.id, stream_ordering) &&
            database::count_appservice_outbox_entries(store, registration.id) >=
                static_cast<std::size_t>(runtime.config.appservice().max_queued_events))
        {
            record_outbox_drop(runtime, registration, event_id);
            continue;
        }
        if (database::enqueue_appservice_event(store, {registration.id, stream_ordering, std::string{event_id}}))
        {
            queued = true;
            continue;
        }
        log_diagnostic("appservice.delivery.unqueued",
                       {
                           {"appservice_id", registration.id,       false},
                           {"event_id",      std::string{event_id}, false},
                           {"reason",        "outbox write failed", false}
        },
                       observability::LogEventSeverity::error);
    }
    if (queued && runtime.appservice_delivery_wake)
    {
        runtime.appservice_delivery_wake();
    }
}

auto drain_appservice_queues(HomeserverRuntime& runtime, StopFlag const& stop,
                             std::chrono::steady_clock::time_point now) -> std::chrono::milliseconds
{
    if (runtime.appservices.empty() || runtime.outbound_client == nullptr || runtime.cached_discovery == nullptr)
    {
        return idle_delay;
    }

    auto lock = std::unique_lock<RuntimeMutex>{runtime.mutex};
    auto more_queued = false;
    for (auto const& registration : runtime.appservices.all())
    {
        if (stop.stop_requested())
        {
            break;
        }
        more_queued = drain_one_appservice(runtime, lock, registration, stop, now).more_queued || more_queued;
    }
    if (more_queued)
    {
        return std::chrono::milliseconds{0};
    }

    auto delay = idle_delay;
    for (auto const& [id, backoff] : runtime.appservice_delivery_backoff)
    {
        if (backoff.retry_at > now)
        {
            delay = std::min(delay, std::chrono::duration_cast<std::chrono::milliseconds>(backoff.retry_at - now));
        }
    }
    // A deadline closer than a millisecond rounds to 0, which would spin; round it up.
    return std::max(delay, std::chrono::milliseconds{1});
}

} // namespace merovingian::homeserver
