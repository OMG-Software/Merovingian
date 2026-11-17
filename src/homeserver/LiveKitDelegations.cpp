// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/homeserver/LiveKitDelegations.hpp"

#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/config/LiveKitTokenServiceConfig.hpp"
#include "merovingian/crypto/ConstantTime.hpp"
#include "merovingian/crypto/Encoding.hpp"
#include "merovingian/crypto/LiveKitToken.hpp"
#include "merovingian/crypto/Sha256.hpp"
#include "merovingian/database/DelayedEventStatus.hpp"
#include "merovingian/database/LiveKitDelegationStore.hpp"
#include "merovingian/database/LiveKitDelegationTable.hpp"
#include "merovingian/database/PersistentLiveKitDelegation.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/DelayedEventAction.hpp"
#include "merovingian/homeserver/DelayedEvents.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LiveKitDelegationProgress.hpp"
#include "merovingian/homeserver/LiveKitNames.hpp"
#include "merovingian/homeserver/LiveKitRequestFields.hpp"
#include "merovingian/homeserver/LiveKitRoomService.hpp"
#include "merovingian/homeserver/LiveKitTokenRequest.hpp"
#include "merovingian/homeserver/LiveKitTokenService.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/RequestHeaders.hpp"
#include "merovingian/homeserver/RoomService.hpp"
#include "merovingian/homeserver/RuntimeMutex.hpp"
#include "merovingian/homeserver/StopFlag.hpp"
#include "merovingian/http/OutboundResult.hpp"
#include "merovingian/observability/LogEventSeverity.hpp"
#include "merovingian/observability/SingleLog.hpp"
#include "merovingian/observability/StructuredLogField.hpp"
#include "merovingian/platform/FileMetadataSupport.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
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

    constexpr auto log_module = std::string_view{"livekit"};
    constexpr auto max_delay_id_bytes = std::size_t{64U};
    constexpr auto max_secret_file_bytes = std::size_t{4096U};
    // One GetParticipant call's budget.
    constexpr auto get_participant_timeout_seconds = std::uint32_t{10U};
    constexpr auto shortest_wait = std::chrono::milliseconds{1000};

    [[nodiscard]] auto ok_empty() -> OperationResult
    {
        auto result = OperationResult{};
        result.ok = true;
        result.status = 200U;
        result.value = "{}";
        return result;
    }

    auto log_delegation(std::string_view const event, std::string_view const user_id, std::string_view const room_id,
                        std::string_view const detail,
                        observability::LogEventSeverity const severity = observability::LogEventSeverity::info) -> void
    {
        // Never the delay ID, the slot or the member ID.
        observability::log_diagnostic(log_module, event,
                                      {
                                          {"user_id", std::string{user_id}, false},
                                          {"room_id", std::string{room_id}, false},
                                          {"detail",  std::string{detail},  false},
        },
                                      severity);
    }

    // The progress entry of a stored delegation, created (due now, never seen) with its names when missing. nullopt
    // when the names cannot be derived, which a validated row never gives.
    [[nodiscard]] auto progress_of(HomeserverRuntime& runtime, database::PersistentLiveKitDelegation const& row)
        -> LiveKitDelegationProgress*
    {
        auto found = runtime.livekit_delegation_progress.find(row.delay_id);
        if (found != runtime.livekit_delegation_progress.end())
        {
            return &found->second;
        }
        auto room_name = livekit_room_name(row.room_id, row.slot_id);
        auto identity = livekit_participant_identity(row.user_id, row.member_id);
        if (!room_name.has_value() || !identity.has_value())
        {
            return nullptr;
        }
        auto progress = LiveKitDelegationProgress{};
        progress.room_name = std::move(*room_name);
        progress.identity = std::move(*identity);
        return &runtime.livekit_delegation_progress.emplace(row.delay_id, std::move(progress)).first->second;
    }

    auto wake(HomeserverRuntime& runtime) -> void
    {
        if (runtime.livekit_delegations_wake)
        {
            runtime.livekit_delegations_wake();
        }
    }

    // Deletes the row and its progress. False when the delete did not commit; the row then stays and is dropped at a
    // later run.
    auto drop(HomeserverRuntime& runtime, std::string const& delay_id) -> bool
    {
        if (!database::delete_livekit_delegation(runtime.database.persistent_store, delay_id))
        {
            return false;
        }
        runtime.livekit_delegation_progress.erase(delay_id);
        return true;
    }

    // Why a stored delegation can no longer be acted on, or empty when it can.
    [[nodiscard]] auto drop_reason(HomeserverRuntime const& runtime, database::PersistentLiveKitDelegation const& row)
        -> std::string_view
    {
        auto const& store = runtime.database.persistent_store;
        if (runtime.config.server().rtc.token_service.url.empty())
        {
            return "the token service is off";
        }
        auto const* event = store.delayed_events.find_owned(row.user_id, row.delay_id);
        if (event == nullptr || event->status != database::DelayedEventStatus::scheduled)
        {
            return "the delayed event is no longer scheduled";
        }
        if (current_state_membership(store, row.room_id, row.user_id) != "join")
        {
            return "the user is no longer joined";
        }
        return {};
    }

    enum class Observation
    {
        connected,
        gone,
        unknown,
    };

    [[nodiscard]] auto string_member(canonicaljson::Object const& object, std::string_view const key)
        -> std::string const*
    {
        auto const* value = livekit_member_of(object, key);
        return value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
    }

    // GetParticipant's answer (ADR-0832): a ParticipantInfo whose `state` is not DISCONNECTED (an absent `state` is the
    // protobuf default, JOINING) is connected; Twirp's `not_found`, or DISCONNECTED, is gone; anything else is unknown.
    [[nodiscard]] auto observe(http::OutboundResult const& result) -> Observation
    {
        if (!result.ok)
        {
            return Observation::unknown;
        }
        auto const parsed = canonicaljson::parse_json(result.response.body);
        auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (parsed.error != canonicaljson::ParseError::none || object == nullptr)
        {
            return Observation::unknown;
        }
        if (result.response.status == 200U)
        {
            auto const* state = string_member(*object, "state");
            return state != nullptr && *state == "DISCONNECTED" ? Observation::gone : Observation::connected;
        }
        if (result.response.status == 404U)
        {
            auto const* code = string_member(*object, "code");
            return code != nullptr && *code == "not_found" ? Observation::gone : Observation::unknown;
        }
        return Observation::unknown;
    }

    struct Check final
    {
        std::string delay_id;
        std::string user_id;
        std::string room_id;
        std::string slot_id;
        std::string member_id;
        std::uint64_t created_ms{0U};
        std::string room_name;
        std::string identity;
        Observation observation{Observation::unknown};
    };

    [[nodiscard]] auto wait_until(std::uint64_t const now_ms, std::uint64_t const next_ms) -> std::chrono::milliseconds
    {
        auto const wait = next_ms > now_ms ? std::chrono::milliseconds{next_ms - now_ms} : shortest_wait;
        return std::clamp(wait, shortest_wait, livekit_delegation_check_interval);
    }

    // Applies one check's answer, under the lock, to the delegation it was made for, if it is still that delegation.
    auto apply(ClientServerRuntime& rt, Check const& check, std::uint64_t const now_ms) -> void
    {
        auto& runtime = rt.homeserver;
        auto const& store = runtime.database.persistent_store;
        // The whole delegation, not only its delay ID: one stored again while the lock was free (another slot or
        // member, or the same anew) is not the participant this answer is about.
        auto const* row = store.livekit_delegations.find(check.delay_id);
        if (row == nullptr || row->user_id != check.user_id || row->room_id != check.room_id ||
            row->slot_id != check.slot_id || row->member_id != check.member_id || row->created_ms != check.created_ms)
        {
            return; // dropped or replaced while the lock was free
        }
        auto* progress = progress_of(runtime, *row);
        if (progress != nullptr && (progress->room_name != check.room_name || progress->identity != check.identity))
        {
            return;
        }
        auto const* event = store.delayed_events.find_owned(row->user_id, row->delay_id);
        if (progress == nullptr || event == nullptr || event->status != database::DelayedEventStatus::scheduled)
        {
            return; // the next run drops it
        }
        progress->next_check_ms = now_ms + static_cast<std::uint64_t>(livekit_delegation_check_interval.count());
        switch (check.observation)
        {
        case Observation::connected: {
            progress->last_seen_connected_ms = now_ms;
            auto const due_ms = database::delayed_event_due_ms(*event);
            auto const remaining = due_ms > now_ms ? due_ms - now_ms : 0U;
            if (remaining < event->delay_ms / 2U)
            {
                auto const restarted =
                    manage_delayed_event(rt, row->user_id, row->delay_id, DelayedEventAction::restart);
                if (!restarted.ok)
                {
                    log_delegation("livekit.delegation.restart_failed", row->user_id, row->room_id, restarted.reason,
                                   observability::LogEventSeverity::warning);
                }
            }
            return;
        }
        case Observation::gone: {
            auto const seen = progress->last_seen_connected_ms != 0U;
            if (!seen && now_ms < row->created_ms + livekit_delegation_connect_grace_ms)
            {
                return; // a client still connecting
            }
            // Copies: `row` is erased by drop().
            auto const user_id = row->user_id;
            auto const room_id = row->room_id;
            auto const delay_id = row->delay_id;
            auto const sent = manage_delayed_event(rt, user_id, delay_id, DelayedEventAction::send);
            log_delegation(sent.ok ? "livekit.delegation.sent" : "livekit.delegation.send_failed", user_id, room_id,
                           seen ? "the participant left" : "the participant never connected",
                           sent.ok ? observability::LogEventSeverity::info : observability::LogEventSeverity::warning);
            // Sent or not, the delegation ends: a send that failed leaves the event to its own timer.
            std::ignore = drop(runtime, delay_id);
            return;
        }
        case Observation::unknown:
            return; // no restart: without an answer the event falls back to its own timer
        }
    }

} // namespace

auto delegate_livekit_delayed_leave(ClientServerRuntime& rt, std::string_view const body, std::string const& user_id)
    -> OperationResult
{
    auto& runtime = rt.homeserver;
    auto const& service = runtime.config.server().rtc.token_service;
    if (service.url.empty())
    {
        return livekit_refusal(404U, "M_UNRECOGNIZED", "no LiveKit token service is configured");
    }
    auto const parsed = canonicaljson::parse_json(body);
    auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
    if (parsed.error != canonicaljson::ParseError::none || object == nullptr)
    {
        return livekit_refusal(400U, "M_BAD_JSON", "the body must be a JSON object");
    }
    auto request = LiveKitTokenRequest{};
    if (auto refused = read_livekit_call_members(*object, request))
    {
        return std::move(*refused);
    }
    auto delay_id = std::string{};
    if (auto refused = read_livekit_string(*object, "delay_id", max_delay_id_bytes, delay_id))
    {
        return std::move(*refused);
    }
    if (request.url != service.url)
    {
        return livekit_refusal(400U, "M_INVALID_PARAM", "url is not this server's SFU");
    }
    auto& store = runtime.database.persistent_store;
    if (current_state_membership(store, request.room_id, user_id) != "join")
    {
        log_delegation("livekit.delegation.refused", user_id, request.room_id, "not joined");
        return livekit_refusal(403U, "M_FORBIDDEN", "You are not joined to this room.");
    }
    // MSC4195: an event that cannot be found, or is another room's or user's, is one 400; a delay ID of another user's
    // is looked up as the caller's and so is never confirmed.
    auto const* event = store.delayed_events.find_owned(user_id, delay_id);
    if (event == nullptr || event->room_id != request.room_id ||
        event->status != database::DelayedEventStatus::scheduled || store.delayed_events.is_being_sent(delay_id))
    {
        return livekit_refusal(400U, "M_INVALID_PARAM", "No delayed event of yours in this room can be delegated.");
    }
    if (event->delay_ms < livekit_delegation_min_delay_ms)
    {
        return livekit_refusal(400U, "M_INVALID_PARAM", "The delayed event's delay is too short to delegate.");
    }
    if (!livekit_room_name(request.room_id, request.slot_id).has_value() ||
        !livekit_participant_identity(user_id, request.member_id).has_value())
    {
        return livekit_refusal(400U, "M_INVALID_PARAM", "the room or member cannot be named");
    }
    auto const* same_key =
        store.livekit_delegations.find_by_key(user_id, request.room_id, request.slot_id, request.member_id);
    auto const* same_delay = store.livekit_delegations.find(delay_id);
    if (same_key == nullptr && same_delay == nullptr &&
        store.livekit_delegations.count_of_user(user_id) >= livekit_delegations_per_user)
    {
        return livekit_refusal(429U, "M_LIMIT_EXCEEDED", "Too many delegated delayed events.");
    }
    // The delegations this one replaces lose their progress with their rows.
    auto replaced = std::vector<std::string>{};
    if (same_key != nullptr)
    {
        replaced.push_back(same_key->delay_id);
    }
    auto row = database::PersistentLiveKitDelegation{};
    row.delay_id = delay_id;
    row.user_id = user_id;
    row.room_id = request.room_id;
    row.slot_id = request.slot_id;
    row.member_id = request.member_id;
    row.created_ms = delayed_event_now_ms(runtime);
    if (!database::store_livekit_delegation(store, std::move(row)))
    {
        return livekit_refusal(500U, "M_UNKNOWN", "the delegation could not be stored");
    }
    for (auto const& old : replaced)
    {
        runtime.livekit_delegation_progress.erase(old);
    }
    runtime.livekit_delegation_progress.erase(delay_id);
    if (auto const* stored = store.livekit_delegations.find(delay_id); stored != nullptr)
    {
        std::ignore = progress_of(runtime, *stored);
    }
    log_delegation("livekit.delegation.stored", user_id, request.room_id, {});
    wake(runtime);
    return ok_empty();
}

auto run_livekit_delegations(ClientServerRuntime& rt, std::uint64_t const now_ms, StopFlag const& stop)
    -> std::chrono::milliseconds
{
    auto& runtime = rt.homeserver;
    auto checks = std::vector<Check>{};
    auto next_ms = now_ms + static_cast<std::uint64_t>(livekit_delegation_check_interval.count());
    auto service = config::LiveKitTokenServiceConfig{};
    {
        auto const guard = RuntimeLock{runtime.mutex};
        service = runtime.config.server().rtc.token_service;
        // A copy: drop() changes the table. Each drop is a commit and costs the table's size (an erase renumbers its
        // indexes), so one run drops at most `livekit_delegation_drops_per_run`; the rest go on the next, soon after.
        auto const rows = runtime.database.persistent_store.livekit_delegations.rows();
        auto drops = std::size_t{0U};
        for (auto const& row : rows)
        {
            if (auto const reason = drop_reason(runtime, row); !reason.empty())
            {
                if (drops == livekit_delegation_drops_per_run)
                {
                    next_ms = now_ms;
                    continue;
                }
                ++drops;
                if (drop(runtime, row.delay_id))
                {
                    log_delegation("livekit.delegation.dropped", row.user_id, row.room_id, reason);
                }
                continue;
            }
            auto* progress = progress_of(runtime, row);
            if (progress == nullptr)
            {
                std::ignore = drop(runtime, row.delay_id);
                continue;
            }
            if (progress->next_check_ms <= now_ms && checks.size() < livekit_delegation_checks_per_run)
            {
                checks.push_back(Check{row.delay_id, row.user_id, row.room_id, row.slot_id, row.member_id,
                                       row.created_ms, progress->room_name, progress->identity, Observation::unknown});
            }
            else
            {
                next_ms = std::min(next_ms, std::max(progress->next_check_ms, now_ms));
            }
        }
        // Progress for a row no longer stored (deleted by deactivation, for one) goes too.
        std::erase_if(runtime.livekit_delegation_progress, [&](auto const& entry) {
            return runtime.database.persistent_store.livekit_delegations.find(entry.first) == nullptr;
        });
    }
    if (checks.empty())
    {
        return wait_until(now_ms, next_ms);
    }

    // The calls, with the lock free. One read of the secret serves this run's tokens.
    if (runtime.outbound_client != nullptr && runtime.cached_discovery != nullptr)
    {
        auto const secret = platform::read_secure_secret_line(service.api_secret_file, max_secret_file_bytes);
        auto const now_seconds = static_cast<std::int64_t>(now_ms / 1000U);
        for (auto& check : checks)
        {
            if (stop.stop_requested() || !secret.has_value())
            {
                break;
            }
            auto request = livekit_get_participant_request(service.api_url, service.api_key, secret->bytes(),
                                                           check.room_name, check.identity, now_seconds);
            if (!request.has_value())
            {
                continue;
            }
            check.observation = observe(
                perform_livekit_request(std::move(*request), *runtime.outbound_client, *runtime.cached_discovery,
                                        get_participant_timeout_seconds, runtime.test_livekit_perform));
        }
        if (!secret.has_value())
        {
            log_delegation("livekit.secret_unavailable", {}, {}, "the API secret file is unreadable or too short",
                           observability::LogEventSeverity::error);
        }
    }

    auto const guard = RuntimeLock{runtime.mutex};
    for (auto const& check : checks)
    {
        apply(rt, check, now_ms);
    }
    // Checks still due (more than one run's worth) run again soon.
    auto more_due = false;
    for (auto const& [delay_id, progress] : runtime.livekit_delegation_progress)
    {
        more_due = more_due || progress.next_check_ms <= now_ms;
        next_ms = std::min(next_ms, std::max(progress.next_check_ms, now_ms));
    }
    return more_due ? shortest_wait : wait_until(now_ms, next_ms);
}

namespace
{

    [[nodiscard]] auto unauthorised(std::string_view const reason) -> OperationResult
    {
        log_delegation("livekit.webhook.refused", {}, {}, reason, observability::LogEventSeverity::warning);
        return livekit_refusal(401U, "M_UNAUTHORIZED", "The webhook is not signed by this server's LiveKit.");
    }

    [[nodiscard]] auto int_member(canonicaljson::Object const& object, std::string_view const key)
        -> std::optional<std::int64_t>
    {
        auto const* value = livekit_member_of(object, key);
        auto const* number = value == nullptr ? nullptr : std::get_if<std::int64_t>(&value->storage());
        return number == nullptr ? std::nullopt : std::optional<std::int64_t>{*number};
    }

    // `createdAt` as protobuf JSON writes an int64: a decimal string; a bare integer is taken too.
    [[nodiscard]] auto created_at_of(canonicaljson::Object const& object) -> std::optional<std::int64_t>
    {
        if (auto const number = int_member(object, "createdAt"))
        {
            return number;
        }
        auto const* text = string_member(object, "createdAt");
        if (text == nullptr || text->empty() || text->size() > 18U)
        {
            return std::nullopt;
        }
        auto value = std::int64_t{0};
        for (auto const c : *text)
        {
            if (c < '0' || c > '9')
            {
                return std::nullopt;
            }
            value = value * 10 + (c - '0');
        }
        return value;
    }

    [[nodiscard]] auto nested_string(canonicaljson::Object const& object, std::string_view const outer,
                                     std::string_view const inner) -> std::string const*
    {
        auto const* value = livekit_member_of(object, outer);
        auto const* nested = value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&value->storage());
        return nested == nullptr ? nullptr : string_member(*nested, inner);
    }

} // namespace

auto receive_livekit_webhook(ClientServerRuntime& rt, LocalHttpRequest const& request, std::int64_t const now_seconds)
    -> OperationResult
{
    auto& runtime = rt.homeserver;
    auto const& service = runtime.config.server().rtc.token_service;
    if (service.url.empty())
    {
        return livekit_refusal(404U, "M_UNRECOGNIZED", "Unrecognized request");
    }
    if (request.body.size() > livekit_webhook_max_body_bytes)
    {
        return livekit_refusal(413U, "M_TOO_LARGE", "The webhook body is too large.");
    }
    // ADR-0833: exactly one Authorization header holding LiveKit's JWT, with or without "Bearer ".
    auto const authorizations = request_header_values(request, "Authorization");
    if (authorizations.size() != 1U)
    {
        return unauthorised("no single Authorization header");
    }
    auto token = authorizations.front();
    if (token.starts_with("Bearer "))
    {
        token.remove_prefix(7U);
    }
    if (token.empty() || token.size() > crypto::hs256_token_max_bytes)
    {
        return unauthorised("malformed token");
    }
    auto const secret = platform::read_secure_secret_line(service.api_secret_file, max_secret_file_bytes);
    if (!secret.has_value())
    {
        log_delegation("livekit.secret_unavailable", {}, {}, "the API secret file is unreadable or too short",
                       observability::LogEventSeverity::error);
        return livekit_refusal(500U, "M_UNKNOWN", "The webhook cannot be checked.");
    }
    auto const verified = crypto::verify_hs256_token(token, secret->bytes());
    if (!verified.has_value())
    {
        return unauthorised("bad signature");
    }
    auto const claims_parsed = canonicaljson::parse_json(verified->payload_json);
    auto const* claims = std::get_if<canonicaljson::Object>(&claims_parsed.value.storage());
    if (claims_parsed.error != canonicaljson::ParseError::none || claims == nullptr)
    {
        return unauthorised("unreadable claims");
    }
    auto const* issuer = string_member(*claims, "iss");
    if (issuer == nullptr || !crypto::constant_time_equal_variable_length(*issuer, service.api_key))
    {
        return unauthorised("wrong issuer");
    }
    auto const not_before = int_member(*claims, "nbf");
    auto const expires = int_member(*claims, "exp");
    if (!expires.has_value() || *expires <= now_seconds - livekit_webhook_clock_leeway_seconds ||
        (not_before.has_value() && *not_before > now_seconds + livekit_webhook_clock_leeway_seconds))
    {
        return unauthorised("token not current");
    }
    auto const* body_hash = string_member(*claims, "sha256");
    auto const digest = crypto::sha256(request.body);
    auto const expected = digest.has_value() ? crypto::base64_original_encode(*digest) : std::nullopt;
    if (body_hash == nullptr || !expected.has_value() ||
        !crypto::constant_time_equal_variable_length(*body_hash, *expected))
    {
        return unauthorised("body does not match its signature");
    }

    // Authenticated. From here every answer is 200, so LiveKit does not retry, and an event only prompts a check.
    auto const parsed = canonicaljson::parse_json(request.body);
    auto const* event = std::get_if<canonicaljson::Object>(&parsed.value.storage());
    if (parsed.error != canonicaljson::ParseError::none || event == nullptr)
    {
        return ok_empty();
    }
    auto const* kind = string_member(*event, "event");
    if (kind == nullptr ||
        (*kind != "participant_joined" && *kind != "participant_left" && *kind != "participant_connection_aborted"))
    {
        return ok_empty();
    }
    auto const* id = string_member(*event, "id");
    auto const created_at = created_at_of(*event);
    if (id == nullptr || id->empty() || id->size() > livekit_webhook_max_event_id_bytes || !created_at.has_value() ||
        *created_at < now_seconds - livekit_webhook_max_age_seconds ||
        *created_at > now_seconds + livekit_webhook_clock_leeway_seconds)
    {
        return ok_empty();
    }
    auto& seen = runtime.livekit_webhook_seen_ids;
    if (std::ranges::find(seen, *id) != seen.end())
    {
        return ok_empty();
    }
    seen.push_back(*id);
    if (seen.size() > livekit_webhook_seen_ids)
    {
        seen.pop_front();
    }
    auto const* room_name = nested_string(*event, "room", "name");
    auto const* identity = nested_string(*event, "participant", "identity");
    if (room_name == nullptr || identity == nullptr)
    {
        return ok_empty();
    }
    auto const& delegations = runtime.database.persistent_store.livekit_delegations;
    for (auto& [delay_id, progress] : runtime.livekit_delegation_progress)
    {
        if (progress.room_name != *room_name || progress.identity != *identity)
        {
            continue;
        }
        auto const* row = delegations.find(delay_id);
        if (row == nullptr || static_cast<std::int64_t>(row->created_ms / 1000U) > *created_at)
        {
            continue; // an event from before this delegation existed
        }
        progress.next_check_ms = 0U;
        log_delegation("livekit.webhook.prompted", row->user_id, row->room_id, *kind);
        wake(runtime);
    }
    return ok_empty();
}

} // namespace merovingian::homeserver
