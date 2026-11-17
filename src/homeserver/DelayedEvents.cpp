// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/DelayedEvents.hpp"

#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/core/CurrentException.hpp"
#include "merovingian/core/QueryParams.hpp"
#include "merovingian/crypto/Encoding.hpp"
#include "merovingian/crypto/Random.hpp"
#include "merovingian/database/DelayedEventOutcomeResult.hpp"
#include "merovingian/database/DelayedEventStatus.hpp"
#include "merovingian/database/DelayedEventStore.hpp"
#include "merovingian/database/DelayedEventTable.hpp"
#include "merovingian/database/PersistentDelayedEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/events/Event.hpp"
#include "merovingian/events/Limits.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerRuntimeInternal.hpp"
#include "merovingian/homeserver/LocalDatabase.hpp"
#include "merovingian/homeserver/LocalServices.hpp"
#include "merovingian/homeserver/LocalUser.hpp"
#include "merovingian/homeserver/RoomPower.hpp"
#include "merovingian/homeserver/RoomService.hpp"
#include "merovingian/homeserver/RuntimeMutex.hpp"
#include "merovingian/http/RateLimitDecision.hpp"
#include "merovingian/observability/BoundedText.hpp"
#include "merovingian/observability/LogEventSeverity.hpp"
#include "merovingian/observability/Observability.hpp"
#include "merovingian/observability/StructuredLogField.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::homeserver
{
namespace
{

    constexpr auto log_module = std::string_view{"delayed_events"};

    // At most this many events are sent in one run of the job, so other threads get the runtime lock between runs.
    constexpr auto max_sends_per_run = std::size_t{100U};
    // The age prune deletes at most this many finalised rows per run, in one transaction (ADR-0824).
    constexpr auto prune_batch_rows = std::size_t{500U};
    // A finalised row is kept at most this long: 7 days.
    constexpr auto finalised_retention_ms = std::uint64_t{7U} * 24U * 60U * 60U * 1000U;
    // The job never sleeps longer than this, and sleeps this long with nothing scheduled.
    constexpr auto max_job_wait_ms = std::uint64_t{60'000U};
    // The most bytes of an error's reason the stored error object keeps.
    constexpr auto max_error_reason_bytes = std::size_t{255U};
    // The bytes of random behind a delay ID: 128 bits.
    constexpr auto delay_id_random_bytes = std::size_t{16U};
    // The `retry_after_ms` of a refused schedule is at least one second.
    constexpr auto min_retry_after_ms = std::uint64_t{1000U};

    auto log_event(std::string_view event, database::PersistentDelayedEvent const& row,
                   std::vector<observability::StructuredLogField> extra = {},
                   observability::LogEventSeverity severity = observability::LogEventSeverity::info) -> void
    {
        // Never `content_json` and never the state key: a call-membership state key holds a device ID.
        auto fields = std::vector<observability::StructuredLogField>{
            {"delay_id",   row.delay_id,   false},
            {"user_id",    row.user_id,    false},
            {"room_id",    row.room_id,    false},
            {"event_type", row.event_type, false},
        };
        for (auto& field : extra)
        {
            fields.push_back(std::move(field));
        }
        observability::log_diagnostic(log_module, event, fields, severity);
    }

    [[nodiscard]] auto refusal(std::uint16_t status, std::string errcode, std::string reason) -> OperationResult
    {
        auto result = make_operation_result(false, {}, std::move(reason), status);
        result.errcode = std::move(errcode);
        return result;
    }

    // The one answer for a delay ID that is unknown, another user's, empty or over-long.
    [[nodiscard]] auto not_found_result() -> OperationResult
    {
        return refusal(404U, "M_NOT_FOUND", "Delayed event not found.");
    }

    [[nodiscard]] auto conflict_result(std::string reason) -> OperationResult
    {
        return refusal(409U, "M_UNKNOWN", std::move(reason));
    }

    [[nodiscard]] auto ok_result(std::string value = {}) -> OperationResult
    {
        return make_operation_result(true, std::move(value));
    }

    [[nodiscard]] auto contains_nul(std::string_view value) noexcept -> bool
    {
        return value.find('\0') != std::string_view::npos;
    }

    // The bound the finalised rows of one user are kept to, from the configured limit (1 to 1000).
    [[nodiscard]] auto finalised_bound(ClientServerRuntime const& runtime) noexcept -> std::size_t
    {
        return std::max<std::size_t>(runtime.limits.max_finalised_delayed_events_per_user, 1U);
    }

    // A fresh delay ID: 128 random bits in unpadded URL-safe base64 (22 characters). Nullopt if the random source
    // failed.
    [[nodiscard]] auto make_delay_id() -> std::optional<std::string>
    {
        auto const random = crypto::secure_random_bytes(delay_id_random_bytes);
        if (!random.has_value())
        {
            return std::nullopt;
        }
        return crypto::base64_urlsafe_encode(
            std::string_view{reinterpret_cast<char const*>(random->data()), random->size()});
    }

    // The `retry_after_ms` of a refused schedule: the time from `now_ms` to `due_ms`, rounded up to a whole second,
    // at least one second (Delayed events, "MUST").
    [[nodiscard]] auto retry_after_for(std::uint64_t now_ms, std::uint64_t due_ms) noexcept -> std::uint32_t
    {
        auto const wait_ms = due_ms > now_ms ? due_ms - now_ms : std::uint64_t{0U};
        auto const rounded_ms = ((wait_ms + 999U) / 1000U) * 1000U;
        return static_cast<std::uint32_t>(std::min<std::uint64_t>(std::max(rounded_ms, min_retry_after_ms),
                                                                  std::numeric_limits<std::uint32_t>::max()));
    }

    [[nodiscard]] auto json_number(std::uint64_t value) -> canonicaljson::Value
    {
        return canonicaljson::Value{static_cast<std::int64_t>(
            std::min<std::uint64_t>(value, static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())))};
    }

    [[nodiscard]] auto json_text(std::string_view value) -> canonicaljson::Value
    {
        return canonicaljson::Value{std::string{value}};
    }

    // The standard error object `{"errcode", "error"}` that a failed send leaves in its row. The reason is cut to 255
    // bytes on a character boundary; the whole object stays within `max_delayed_event_error_bytes`.
    [[nodiscard]] auto error_object_json(OperationResult const& failure) -> std::string
    {
        auto const errcode =
            failure.errcode.empty() ? std::string{errcode_for_refusal_status(failure.status)} : failure.errcode;
        auto build = [&errcode](std::string_view reason) {
            auto members = canonicaljson::Object{};
            members.push_back(canonicaljson::make_member("errcode", json_text(errcode)));
            members.push_back(canonicaljson::make_member("error", json_text(reason)));
            return canonicaljson::serialize_canonical(canonicaljson::Value{std::move(members)}).output;
        };
        auto json = build(observability::bounded_utf8(failure.reason, max_error_reason_bytes));
        if (json.size() > database::max_delayed_event_error_bytes)
        {
            json = build({});
        }
        return json;
    }

    // The account check the request gate makes, applied when a delayed event is sent: a user who is unknown or
    // deactivated, locked or suspended sends nothing (the answers and messages are the gate's). Nullopt when the
    // account may send. Caller holds runtime.mutex.
    [[nodiscard]] auto account_refusal(HomeserverRuntime const& runtime, std::string_view user_id)
        -> std::optional<OperationResult>
    {
        auto const user = std::ranges::find_if(runtime.database.users, [user_id](LocalUser const& candidate) {
            return candidate.user_id == user_id;
        });
        if (user == runtime.database.users.end() || user->deactivated)
        {
            return refusal(403U, "M_USER_DEACTIVATED", "This account has been deactivated.");
        }
        if (user->locked)
        {
            return refusal(401U, "M_USER_LOCKED", "This account has been locked");
        }
        if (user->suspended)
        {
            return refusal(403U, "M_USER_SUSPENDED", "You cannot perform this action while suspended.");
        }
        return std::nullopt;
    }

    // The path the ordinary `PUT` route of `row`'s event has: `.../send/{eventType}/{txnId}` for a message and
    // `.../state/{eventType}/{stateKey}` for a state event (no key segment for the empty state key).
    [[nodiscard]] auto ordinary_route_path(database::PersistentDelayedEvent const& row) -> std::string
    {
        auto path = std::string{"/_matrix/client/v3/rooms/"};
        path += core::percent_encode_path_component(row.room_id);
        if (row.is_state)
        {
            path += "/state/";
            path += core::percent_encode_path_component(row.event_type);
            if (!row.state_key.empty())
            {
                path += '/';
                path += core::percent_encode_path_component(row.state_key);
            }
            return path;
        }
        path += "/send/";
        path += core::percent_encode_path_component(row.event_type);
        path += '/';
        path += core::percent_encode_path_component(row.txn_id.empty() ? std::string_view{"0"} : row.txn_id);
        return path;
    }

    // The per-user rate limit an ordinary request for `row`'s event would meet, checked at send time (Delayed events:
    // "MUST be subject to rate limits"). The per-address bucket is skipped (an empty first argument); the user's
    // bucket and the policy are the ones `allow()` of the dispatcher builds for an authenticated PUT of that event.
    // A null engine allows. Caller holds runtime.mutex.
    [[nodiscard]] auto send_rate_limit_refusal(ClientServerRuntime& runtime,
                                               database::PersistentDelayedEvent const& row)
        -> std::optional<OperationResult>
    {
        if (runtime.rate_limit_engine == nullptr)
        {
            return std::nullopt;
        }
        auto const path = ordinary_route_path(row);
        auto const route = rate_limit_route_template(path);
        auto user_key = row.user_id;
        user_key.push_back('|');
        user_key.append(route);
        auto const decision = runtime.rate_limit_engine->check({}, route, user_key, path);
        if (decision.allowed)
        {
            return std::nullopt;
        }
        auto result = refusal(429U, "M_LIMIT_EXCEEDED", "Too many requests. Please try again later.");
        result.retry_after_ms = decision.retry_after_ms;
        return result;
    }

    // One send of the scheduled row `row` (design 3.2 steps 2 to 4): the account check, the send-time rate limit, then
    // the ordinary send path, which authorises the event against the room's state now. On success `value` is the
    // event ID. Nothing is recorded here. Caller holds runtime.mutex and has marked the row as being sent.
    [[nodiscard]] auto attempt_send(ClientServerRuntime& runtime, database::PersistentDelayedEvent const& row)
        -> OperationResult
    {
        if (auto account = account_refusal(runtime.homeserver, row.user_id); account.has_value())
        {
            return std::move(*account);
        }
        if (auto limited = send_rate_limit_refusal(runtime, row); limited.has_value())
        {
            return std::move(*limited);
        }
        auto body = row.is_state ? route_event_body(row.event_type, row.content_json, row.state_key)
                                 : route_event_body(row.event_type, row.content_json);
        if (!body.has_value())
        {
            return refusal(400U, "M_BAD_JSON", "event content must be a JSON object");
        }
        return send_event_as_resolved_user(runtime.homeserver, row.user_id, row.room_id, *body, row.via_appservice);
    }

    // Records the outcome of the send `result` of `row` as sent or failed, at `now_ms`, and logs it. A commit failure
    // is logged at error level and the caller carries on (ADR-0825: memory is finalised, the next start sends the
    // event again). Caller holds runtime.mutex.
    auto record_send_outcome(ClientServerRuntime& runtime, database::PersistentDelayedEvent const& row,
                             OperationResult const& result, std::uint64_t now_ms) -> void
    {
        auto& store = runtime.homeserver.database.persistent_store;
        auto const outcome =
            result.ok ? database::record_delayed_event_outcome(store, row.delay_id, database::DelayedEventStatus::sent,
                                                               now_ms, result.value, {}, finalised_bound(runtime))
                      : database::record_delayed_event_outcome(store, row.delay_id,
                                                               database::DelayedEventStatus::failed, now_ms, {},
                                                               error_object_json(result), finalised_bound(runtime));
        if (result.ok)
        {
            log_event("delayed_event.sent", row,
                      {
                          {"event_id", result.value, false}
            });
        }
        else
        {
            log_event(
                "delayed_event.failed", row,
                {
                    {"status",  std::to_string(result.status),                                                         false},
                    {"errcode",
                     result.errcode.empty() ? std::string{errcode_for_refusal_status(result.status)} : result.errcode,
                     false                                                                                                  },
            },
                observability::LogEventSeverity::warning);
        }
        if (outcome != database::DelayedEventOutcomeResult::recorded)
        {
            log_event(
                "delayed_event.finalise_commit_failed", row,
                {
                    {"outcome", outcome == database::DelayedEventOutcomeResult::refused ? "refused" : "commit_failed",
                     false}
            },
                observability::LogEventSeverity::error);
        }
    }

    // Owns the "being sent" mark of one row (memory only) for the length of one send: made with the mark taken, and
    // when it goes out of scope, on every path including an exception, the mark is cleared. Finalising the row already
    // clears it and clearing an unmarked row does nothing, so the destructor clears unconditionally. A record the store
    // refuses is the one case that must keep the mark (the row is then never sent again by this process): that path
    // calls `keep_mark()`.
    class SendMark final
    {
    public:
        SendMark(database::DelayedEventTable& table, std::string delay_id)
            : m_table{&table}
            , m_delay_id{std::move(delay_id)}
            , m_held{table.mark_being_sent(m_delay_id)}
        {
        }

        SendMark(SendMark const&) = delete;
        auto operator=(SendMark const&) -> SendMark& = delete;
        SendMark(SendMark&&) = delete;
        auto operator=(SendMark&&) -> SendMark& = delete;

        ~SendMark() noexcept
        {
            if (m_held)
            {
                std::ignore = m_table->clear_being_sent(m_delay_id);
            }
        }

        // True when this guard took the mark: nobody else was sending the row.
        [[nodiscard]] auto held() const noexcept -> bool
        {
            return m_held;
        }

        // The record of the outcome was refused: leave the mark, so the row is not sent again by this process.
        auto keep_mark() noexcept -> void
        {
            m_held = false;
        }

    private:
        database::DelayedEventTable* m_table;
        std::string m_delay_id;
        bool m_held;
    };

    // Sends the earliest-due row if it is due at `now_ms`, under its own hold of the runtime lock, and records the
    // outcome (any failure is `failed`, never retried). False when nothing was due.
    [[nodiscard]] auto send_next_due(ClientServerRuntime& runtime, std::uint64_t now_ms) -> bool
    {
        auto const guard = RuntimeLock{runtime.homeserver.mutex};
        auto& table = runtime.homeserver.database.persistent_store.delayed_events;
        auto const* next = table.earliest_due();
        if (next == nullptr || database::delayed_event_due_ms(*next) > now_ms)
        {
            return false;
        }
        // A copy: the send and the outcome change the table, which invalidates the pointer.
        auto const row = *next;
        auto mark = SendMark{table, row.delay_id};
        if (!mark.held())
        {
            return false;
        }
        // The catch-all is here because this is a job item, not a request handler: the dispatch boundary's backstop
        // does not cover it, and an attempt that is not recorded is repeated, because PeriodicJob runs a job that
        // throws again a few seconds later, and a throw after the event was stored would send it every time. So an
        // exception is a failed send with status 500, recorded like any other failure. Only the type is logged, never
        // what(), which can carry content.
        auto result = std::optional<OperationResult>{};
        try
        {
            result = attempt_send(runtime, row);
        }
        catch (...)
        {
            log_event("delayed_event.failed", row,
                      {
                          {"status", "500",                               false},
                          {"type",   core::current_exception_type_name(), false},
            },
                      observability::LogEventSeverity::error);
            result = refusal(500U, "M_UNKNOWN", "internal server error");
        }
        // Finalising clears the mark. A record that was refused leaves the row marked, so it is never sent again by
        // this process (and is logged), never in a loop.
        record_send_outcome(runtime, row, *result, now_ms);
        if (table.is_being_sent(row.delay_id))
        {
            mark.keep_mark();
        }
        return true;
    }

} // namespace

auto delayed_event_now_ms(HomeserverRuntime const& runtime) -> std::uint64_t
{
    if (runtime.test_delayed_event_clock_ms.has_value())
    {
        return *runtime.test_delayed_event_clock_ms;
    }
    auto const now =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    return now < 0 ? std::uint64_t{0U} : static_cast<std::uint64_t>(now);
}

auto wake_delayed_events(HomeserverRuntime& runtime) -> void
{
    if (runtime.delayed_events_wake)
    {
        runtime.delayed_events_wake();
    }
}

auto schedule_delayed_event(ClientServerRuntime& runtime, DelayedEventScheduleRequest const& request) -> OperationResult
{
    // 1. The feature switch.
    if (!runtime.limits.delayed_events_enabled)
    {
        return refusal(403U, "M_FORBIDDEN", "Delayed events are not enabled on this homeserver.");
    }
    // 2. The shape: the answers the ordinary `/send` and `/state` routes give.
    if (event_txn_part_is_too_long(request.event_type))
    {
        return refusal(413U, "M_TOO_LARGE", std::string{event_type_too_long_reason});
    }
    if (event_txn_part_is_too_long(request.txn_id))
    {
        return refusal(400U, "M_INVALID_PARAM", std::string{txn_id_too_long_reason});
    }
    if (contains_nul(request.event_type))
    {
        return refusal(400U, "M_INVALID_PARAM", "the event type must not contain NUL");
    }
    if (contains_nul(request.txn_id))
    {
        return refusal(400U, "M_INVALID_PARAM", "the transaction ID must not contain NUL");
    }
    if (request.state_key.has_value())
    {
        if (events::state_key_contains_nul(*request.state_key))
        {
            return invalid_state_key_refusal();
        }
        if (request.state_key->size() > events::max_state_key_length_bytes)
        {
            return event_too_large_refusal();
        }
    }
    if (request.content_json.size() > database::max_delayed_event_content_bytes)
    {
        return event_too_large_refusal();
    }
    {
        auto const parsed = canonicaljson::parse_lossless(request.content_json);
        if (parsed.error != canonicaljson::ParseError::none ||
            std::get_if<canonicaljson::Object>(&parsed.value.storage()) == nullptr)
        {
            return refusal(400U, "M_BAD_JSON", "event content must be a JSON object");
        }
    }
    if (request.delay_ms == 0U)
    {
        return refusal(400U, "M_INVALID_PARAM", "delay_ms must be at least 1");
    }
    // 3. The longest delay.
    if (request.delay_ms > runtime.limits.max_delayed_event_delay_ms)
    {
        return refusal(400U, request.stable_errcode ? "M_DELAY_TOO_LARGE" : "ORG.MATRIX.MSC4140_DELAY_TOO_LARGE",
                       "The requested delay exceeds the allowed maximum.");
    }
    auto& store = runtime.homeserver.database.persistent_store;
    // 4. Idempotency: the same (user, device, room, type, transaction ID) is the same delayed event.
    if (!request.txn_id.empty())
    {
        if (auto const* existing = store.delayed_events.find_by_transaction(
                request.user_id, request.device_id, request.room_id, request.event_type, request.txn_id);
            existing != nullptr)
        {
            return ok_result(existing->delay_id);
        }
    }
    // 5. Could it be sent now: the room and the sender's membership, then for a state event the sender's power.
    if (auto unsendable = room_send_refusal(runtime.homeserver, request.user_id, request.room_id);
        unsendable.has_value())
    {
        return std::move(*unsendable);
    }
    if (request.state_key.has_value() &&
        !may_send_state_event(store, request.room_id, request.user_id, request.event_type))
    {
        return event_authorization_refusal();
    }
    // 6. The per-user cap.
    auto const now_ms = delayed_event_now_ms(runtime.homeserver);
    if (store.delayed_events.scheduled_count(request.user_id) >= runtime.limits.max_scheduled_delayed_events_per_user)
    {
        auto result = refusal(429U, "M_LIMIT_EXCEEDED", "The maximum number of delayed events has been reached.");
        result.retry_after_ms =
            retry_after_for(now_ms, store.delayed_events.earliest_due_ms_of_user(request.user_id).value_or(now_ms));
        return result;
    }

    auto delay_id = make_delay_id();
    if (!delay_id.has_value())
    {
        return refusal(500U, "M_UNKNOWN", "could not generate a delay ID");
    }
    auto row = database::PersistentDelayedEvent{};
    row.delay_id = *delay_id;
    row.user_id = request.user_id;
    row.device_id = request.device_id;
    row.room_id = request.room_id;
    row.event_type = request.event_type;
    row.is_state = request.state_key.has_value();
    row.state_key = request.state_key.value_or(std::string{});
    row.content_json = request.content_json;
    row.txn_id = request.txn_id;
    row.via_appservice = request.via_appservice;
    row.delay_ms = request.delay_ms;
    row.delayed_since_ms = now_ms;
    if (!database::store_delayed_event(store, row))
    {
        return refusal(500U, "M_UNKNOWN", "the delayed event could not be stored");
    }
    log_event("delayed_event.scheduled", row,
              {
                  {"delay_ms", std::to_string(row.delay_ms), false}
    });
    wake_delayed_events(runtime.homeserver);
    return ok_result(*delay_id);
}

auto manage_delayed_event(ClientServerRuntime& runtime, std::string_view user_id, std::string_view delay_id,
                          DelayedEventAction action) -> OperationResult
{
    auto& store = runtime.homeserver.database.persistent_store;
    auto const* found = store.delayed_events.find_owned(user_id, delay_id);
    if (found == nullptr)
    {
        return not_found_result();
    }
    // A copy: every change below invalidates the pointer.
    auto const row = *found;
    auto const now_ms = delayed_event_now_ms(runtime.homeserver);
    if (row.status == database::DelayedEventStatus::scheduled)
    {
        if (store.delayed_events.is_being_sent(row.delay_id))
        {
            return conflict_result("The delayed event is being sent.");
        }
        switch (action)
        {
        case DelayedEventAction::restart:
            if (!database::restart_delayed_event(store, row.delay_id, now_ms))
            {
                return refusal(500U, "M_UNKNOWN", "the delayed event could not be restarted");
            }
            log_event("delayed_event.restarted", row);
            return ok_result();
        case DelayedEventAction::cancel:
            if (!database::cancel_delayed_event(store, row.delay_id, now_ms, finalised_bound(runtime)))
            {
                return refusal(500U, "M_UNKNOWN", "the delayed event could not be cancelled");
            }
            log_event("delayed_event.cancelled", row);
            return ok_result();
        case DelayedEventAction::send: {
            // An exception from the send unwinds through the guard (the mark is cleared, the row stays scheduled with
            // its timer unchanged) to the dispatch boundary's backstop, which answers 500.
            auto mark = SendMark{store.delayed_events, row.delay_id};
            if (!mark.held())
            {
                return conflict_result("The delayed event is being sent.");
            }
            auto result = attempt_send(runtime, row);
            if (!result.ok)
            {
                // The row stays scheduled with its timer unchanged; the caller answers as the send did.
                return result;
            }
            record_send_outcome(runtime, row, result, now_ms);
            if (store.delayed_events.is_being_sent(row.delay_id))
            {
                mark.keep_mark();
            }
            return ok_result();
        }
        }
        return refusal(500U, "M_UNKNOWN", "unknown action");
    }
    if (row.status == database::DelayedEventStatus::sent)
    {
        return action == DelayedEventAction::send ? ok_result()
                                                  : conflict_result("The delayed event has already been sent.");
    }
    // Cancelled by its owner, or cancelled because sending it failed.
    return action == DelayedEventAction::cancel ? ok_result()
                                                : conflict_result("The delayed event has already been cancelled.");
}

auto delayed_event_lookup(ClientServerRuntime& runtime, std::string_view user_id, std::string_view delay_id)
    -> OperationResult
{
    auto const* row = runtime.homeserver.database.persistent_store.delayed_events.find_owned(user_id, delay_id);
    if (row == nullptr)
    {
        return not_found_result();
    }
    auto parsed = canonicaljson::parse_lossless(row->content_json);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        return refusal(500U, "M_UNKNOWN", "the delayed event's content could not be read");
    }
    auto members = canonicaljson::Object{};
    members.push_back(canonicaljson::make_member("delay_id", json_text(row->delay_id)));
    members.push_back(canonicaljson::make_member("room_id", json_text(row->room_id)));
    members.push_back(canonicaljson::make_member("type", json_text(row->event_type)));
    if (row->is_state)
    {
        members.push_back(canonicaljson::make_member("state_key", json_text(row->state_key)));
    }
    members.push_back(canonicaljson::make_member("delay_ms", json_number(row->delay_ms)));
    members.push_back(canonicaljson::make_member("delayed_since_ts", json_number(row->delayed_since_ms)));
    members.push_back(canonicaljson::make_member("content", std::move(parsed.value)));
    if (row->status != database::DelayedEventStatus::scheduled)
    {
        auto finalised = canonicaljson::Object{};
        finalised.push_back(canonicaljson::make_member("finalised_ts", json_number(row->finalised_at_ms)));
        if (row->status == database::DelayedEventStatus::sent)
        {
            finalised.push_back(canonicaljson::make_member("event_id", json_text(row->event_id)));
        }
        if (row->status == database::DelayedEventStatus::failed)
        {
            auto error = canonicaljson::parse_lossless(row->error_json);
            if (error.error == canonicaljson::ParseError::none)
            {
                finalised.push_back(canonicaljson::make_member("error", std::move(error.value)));
            }
        }
        members.push_back(canonicaljson::make_member("finalised", canonicaljson::Value{std::move(finalised)}));
    }
    auto const serialised = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(members)});
    if (serialised.error != canonicaljson::CanonicalJsonError::none)
    {
        return refusal(500U, "M_UNKNOWN", "the delayed event could not be serialised");
    }
    return ok_result(serialised.output);
}

auto send_due_delayed_events(ClientServerRuntime& runtime, std::uint64_t now_ms, StopFlag const& stop)
    -> std::chrono::milliseconds
{
    // One send per hold of the runtime lock, the stop flag read between items, at most `max_sends_per_run` a run.
    auto sent = std::size_t{0U};
    while (sent < max_sends_per_run && !stop.stop_requested() && send_next_due(runtime, now_ms))
    {
        ++sent;
    }
    auto const guard = RuntimeLock{runtime.homeserver.mutex};
    auto& store = runtime.homeserver.database.persistent_store;
    if (!stop.stop_requested())
    {
        // One batch of the age prune, in this hold. A failed commit leaves the rows for the next run.
        auto const cutoff_ms = now_ms > finalised_retention_ms ? now_ms - finalised_retention_ms : std::uint64_t{0U};
        if (!database::prune_finalised_delayed_events(store, cutoff_ms, prune_batch_rows).has_value())
        {
            observability::log_diagnostic(log_module, "delayed_event.prune_failed", {},
                                          observability::LogEventSeverity::warning);
        }
    }
    auto const* next = store.delayed_events.earliest_due();
    if (next == nullptr)
    {
        return std::chrono::milliseconds{max_job_wait_ms};
    }
    auto const due_ms = database::delayed_event_due_ms(*next);
    auto const wait_ms = due_ms > now_ms ? due_ms - now_ms : std::uint64_t{0U};
    return std::chrono::milliseconds{std::min(wait_ms, max_job_wait_ms)};
}

} // namespace merovingian::homeserver
