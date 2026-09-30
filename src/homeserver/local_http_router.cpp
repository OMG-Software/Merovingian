// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/local_http_router.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/core/query_params.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/crypto/signing_service.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/events/redaction.hpp"
#include "merovingian/federation/edu_idempotence.hpp"
#include "merovingian/federation/event_query.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/key_query.hpp"
#include "merovingian/federation/outbound_transaction.hpp"
#include "merovingian/federation/remote_key_cache.hpp"
#include "merovingian/federation/security.hpp"
#include "merovingian/federation/server_acl.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/federation_request_routing.hpp"
#include "merovingian/homeserver/media_service.hpp"
#include "merovingian/homeserver/request_lock.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/runtime_signing_key_store.hpp"
#include "merovingian/homeserver/space_hierarchy.hpp"
#include "merovingian/homeserver/state_bookkeeping.hpp"
#include "merovingian/http/client_address.hpp"
#include "merovingian/media/repository.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/rooms/room_version_policy.hpp"
#include "merovingian/trust_safety/policy_engine.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <limits>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::homeserver
{

// Forward declaration — the definition lives outside the anonymous namespace so
// it can be exported in the header, but it is called from lambdas inside it.
[[nodiscard]] auto ingest_pdu_event(HomeserverRuntime& runtime, federation::InboundPduEnvelope const& envelope)
    -> federation::PduIngestionResult;

// Forward declaration — lives in src/homeserver/room_service.cpp and is reused
// here for ADR-0064 phase C outbound backfill request signing.
[[nodiscard]] auto find_active_server_signing_key(HomeserverRuntime const& runtime)
    -> std::optional<database::PersistentServerSigningKey>;

namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        if (auto const* correlation = observability::current_correlation_context(); correlation != nullptr)
        {
            fields = observability::with_correlation_fields(*correlation, std::move(fields));
        }
        observability::log_diagnostic("local_router", event, fields, severity);
    }

    [[nodiscard]] auto traceparent(observability::CorrelationContext const& correlation) -> std::string
    {
        return "00-" + correlation.trace_id + '-' + correlation.span_id + "-01";
    }

    [[nodiscard]] auto observability_headers(observability::CorrelationContext const& correlation,
                                             std::string_view content_type)
        -> std::vector<std::pair<std::string, std::string>>
    {
        return {
            {"Content-Type",             std::string{content_type}},
            {"X-Merovingian-Request-Id", correlation.request_id   },
            {"Traceparent",              traceparent(correlation) },
        };
    }

    // Forward declarations: both are defined later in this anonymous
    // namespace (string_member alongside content_membership;
    // object_member_as_object alongside the local-router query helpers) but
    // are needed by the auth_events-selection machinery below.
    [[nodiscard]] auto string_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::string const*;
    [[nodiscard]] auto object_member_as_object(canonicaljson::Object const& object, std::string_view key)
        -> canonicaljson::Object const*;

    // Builds the auth-event map for an inbound federated PDU from an
    // arbitrary flat state snapshot (current state, the state before an
    // event, or the set of events an event itself names as auth_events —
    // ADR-0064 phase B2 needs all three). Mirrors the same logic used in
    // room_service.cpp for locally-created events so all paths apply
    // identical auth rules.
    // Spec: SS API §authorization-rules — receivers MUST check auth before persisting.
    [[nodiscard]] auto build_auth_event_map_from_entries(
        database::PersistentStore const& store, std::vector<database::PersistentStateGroupStateEntry> const& entries,
        std::string_view sender, std::string_view target_state_key, std::string_view event_type,
        std::string_view third_party_invite_token = {}) -> events::AuthEventMap
    {
        auto load = [&](std::string_view event_id) -> canonicaljson::Value {
            for (auto const& evt : store.events)
            {
                if (evt.event_id == event_id)
                {
                    auto const parsed = canonicaljson::parse_lossless(evt.json);
                    if (parsed.error == canonicaljson::ParseError::none)
                    {
                        return parsed.value;
                    }
                }
            }
            return {};
        };

        auto result = events::AuthEventMap{};
        for (auto const& entry : entries)
        {
            if (entry.event_type == "m.room.create" && entry.state_key.empty())
            {
                result.create = load(entry.event_id);
            }
            else if (entry.event_type == "m.room.power_levels" && entry.state_key.empty())
            {
                result.power_levels = load(entry.event_id);
            }
            else if (entry.event_type == "m.room.join_rules" && entry.state_key.empty())
            {
                result.join_rules = load(entry.event_id);
            }
            else if (entry.event_type == "m.room.member" && entry.state_key == sender)
            {
                result.sender_member = load(entry.event_id);
            }
            else if (entry.event_type == "m.room.member" && event_type == "m.room.member" &&
                     entry.state_key == target_state_key)
            {
                result.target_member = load(entry.event_id);
            }
            else if (entry.event_type == "m.room.third_party_invite" && !third_party_invite_token.empty() &&
                     entry.state_key == third_party_invite_token)
            {
                result.third_party_invite = load(entry.event_id);
            }
        }
        return result;
    }

    // Every (room_id-scoped) row of store.state as flat state-group-style
    // entries, so the current-state auth map (ADR-0064 phase B2 step 6) can
    // share build_auth_event_map_from_entries with the state-before (step 5)
    // and auth_events (step 4) maps below.
    [[nodiscard]] auto state_entries_for_room(database::PersistentStore const& store, std::string_view room_id)
        -> std::vector<database::PersistentStateGroupStateEntry>
    {
        auto entries = std::vector<database::PersistentStateGroupStateEntry>{};
        for (auto const& state : store.state)
        {
            if (state.room_id == room_id)
            {
                entries.push_back({{}, state.event_type, state.state_key, state.event_id});
            }
        }
        return entries;
    }

    // Builds the auth-event map for an inbound federated PDU from the room's
    // currently resolved state (ADR-0064 phase B2 step 6, the soft-fail
    // check).
    [[nodiscard]] auto build_pdu_auth_event_map(database::PersistentStore const& store, std::string_view room_id,
                                                std::string_view sender, std::string_view target_state_key,
                                                std::string_view event_type,
                                                std::string_view third_party_invite_token = {}) -> events::AuthEventMap
    {
        return build_auth_event_map_from_entries(store, state_entries_for_room(store, room_id), sender,
                                                 target_state_key, event_type, third_party_invite_token);
    }

    // Resolves the events a PDU names in `auth_event_ids` to flat state
    // entries (type/state_key/event_id), skipping any id this store has no
    // event for — the caller (validate_auth_events_selection) treats an
    // unresolvable id as its own failure mode before this is used to build
    // an auth map, so silently dropping it here is safe: the map is only
    // ever built after selection has already succeeded.
    [[nodiscard]] auto state_entries_from_named_events(database::PersistentStore const& store,
                                                       std::vector<std::string> const& auth_event_ids)
        -> std::vector<database::PersistentStateGroupStateEntry>
    {
        auto entries = std::vector<database::PersistentStateGroupStateEntry>{};
        entries.reserve(auth_event_ids.size());
        for (auto const& id : auth_event_ids)
        {
            auto const it = std::ranges::find_if(store.events, [&](database::PersistentEvent const& evt) {
                return evt.event_id == id;
            });
            if (it == store.events.end())
            {
                continue;
            }
            auto const parsed = canonicaljson::parse_lossless(it->json);
            auto const* obj = parsed.error == canonicaljson::ParseError::none
                                  ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                                  : nullptr;
            auto const* type = obj != nullptr ? string_member(*obj, "type") : nullptr;
            if (type == nullptr)
            {
                continue;
            }
            auto const* state_key = string_member(*obj, "state_key");
            entries.push_back({{}, *type, state_key != nullptr ? *state_key : std::string{}, id});
        }
        return entries;
    }

    // Result of validate_auth_events_selection (ADR-0064 phase B2, spec
    // "Auth events selection").
    enum class AuthEventsSelectionCheck : std::uint8_t
    {
        ok,
        // An auth_event_id names no event this store has — cannot be
        // verified yet. Per this project's B2 scope, treated the same as a
        // missing prev_event: not a rejection, the transaction still
        // succeeds, and a later phase is expected to fetch the gap.
        unresolvable,
        // A named auth_event_id resolves to an actual event, but it is not
        // one of the spec-permitted (type, state_key) selections for this
        // PDU, or it duplicates an earlier entry's (type, state_key), or it
        // belongs to a different room. Any of these is a rejection.
        disallowed,
    };

    // The (type, state_key) pairs a PDU's auth_events MAY name, per spec
    // "Auth events selection" (server-server-api.md, ~line 1792).
    [[nodiscard]] auto permitted_auth_event_keys(canonicaljson::Value const& pdu,
                                                 rooms::RoomVersionPolicy const& policy, std::string_view event_type,
                                                 std::string_view sender, std::optional<std::string> const& state_key,
                                                 std::string_view third_party_invite_token)
        -> std::vector<std::pair<std::string, std::string>>
    {
        auto permitted = std::vector<std::pair<std::string, std::string>>{};
        // "The auth_events for the m.room.create event in a room is empty."
        if (event_type == "m.room.create")
        {
            return permitted;
        }
        // v12 (MSC4291): the create event is implicit in the room ID and
        // MUST NOT be selected for auth_events.
        // Spec: docs/matrix-v1.19-spec/rooms/v12.md — "The m.room.create
        // event MUST NOT be selected for auth_events on events. The
        // room_id (being the m.room.create event's ID) implies this
        // instead." and rule 3.2: "In this room version, m.room.create
        // MUST NOT be selected" (reject if it is). An inbound v12 event
        // that names it is therefore a rejection, not a tolerated
        // redundancy — do not relax this to "always permitted" again
        // without re-reading rooms/v12.md rule 3.2 first.
        if (!policy.create_event_is_room_id)
        {
            permitted.emplace_back("m.room.create", std::string{});
        }
        // "The current m.room.power_levels event, if any" — unconditional.
        permitted.emplace_back("m.room.power_levels", std::string{});
        // "The sender's current m.room.member event, if any" — unconditional.
        permitted.emplace_back("m.room.member", std::string{sender});

        if (event_type == "m.room.member" && state_key.has_value())
        {
            // "The target's current m.room.member event, if any."
            permitted.emplace_back("m.room.member", *state_key);
            auto const membership = events::extract_content_membership(pdu);
            if (membership == "join" || membership == "invite" || membership == "knock")
            {
                permitted.emplace_back("m.room.join_rules", std::string{});
            }
            if (membership == "invite" && !third_party_invite_token.empty())
            {
                permitted.emplace_back("m.room.third_party_invite", std::string{third_party_invite_token});
            }
            if (membership == "join")
            {
                auto const* obj = std::get_if<canonicaljson::Object>(&pdu.storage());
                auto const* content = obj != nullptr ? object_member_as_object(*obj, "content") : nullptr;
                auto const* authorised =
                    content != nullptr ? string_member(*content, "join_authorised_via_users_server") : nullptr;
                if (authorised != nullptr && !authorised->empty())
                {
                    permitted.emplace_back("m.room.member", *authorised);
                }
            }
        }
        return permitted;
    }

    // Spec: server-server-api.md — "Auth events selection". Validates that
    // every event `auth_event_ids` names is a permitted selection for this
    // PDU: the correct (type, state_key), no duplicates, and from the same
    // room. ADR-0064 phase B2 step 4.
    // Returns the parsed m.room.create event recorded in a room's state, or a
    // null value when the room has none. Room v12 (MSC4291) makes the create
    // event implicit in the room ID and forbids naming it in auth_events, so
    // both receipt paths must fill the auth map's create slot from the room's
    // own state rather than from the event's named auth_events.
    [[nodiscard]] auto create_event_json_for_room(database::PersistentStore const& store, std::string_view room_id)
        -> canonicaljson::Value
    {
        for (auto const& state : store.state)
        {
            if (state.room_id != room_id || state.event_type != "m.room.create" || !state.state_key.empty())
            {
                continue;
            }
            for (auto const& evt : store.events)
            {
                if (evt.event_id != state.event_id)
                {
                    continue;
                }
                auto const parsed = canonicaljson::parse_lossless(evt.json);
                return parsed.error == canonicaljson::ParseError::none ? parsed.value : canonicaljson::Value{};
            }
            break;
        }
        return {};
    }

    // Fills an auth map's create slot from the room's recorded create event
    // when it is missing. Only for maps built from ROOM STATE (the state
    // before an event, and the current state): the create event is part of a
    // room's state by construction, so its absence there is a gap in our own
    // bookkeeping, never a claim by the sender. The map built from an event's
    // NAMED auth_events must not be filled this way for pre-v12 rooms, where
    // the spec requires the sender to name the create event and rejects an
    // event that does not (v12 forbids naming it, and is filled explicitly).
    auto fill_create_from_room_state(events::AuthEventMap& map, database::PersistentStore const& store,
                                     std::string_view room_id) -> void
    {
        if (std::holds_alternative<std::nullptr_t>(map.create.storage()))
        {
            map.create = create_event_json_for_room(store, room_id);
        }
    }

    [[nodiscard]] auto validate_auth_events_selection(
        database::PersistentStore const& store, std::string_view room_id, canonicaljson::Value const& pdu,
        rooms::RoomVersionPolicy const& policy, std::string_view event_type, std::string_view sender,
        std::optional<std::string> const& state_key, std::string_view third_party_invite_token,
        std::vector<std::string> const& auth_event_ids) -> AuthEventsSelectionCheck
    {
        auto const permitted =
            permitted_auth_event_keys(pdu, policy, event_type, sender, state_key, third_party_invite_token);
        auto seen = std::vector<std::pair<std::string, std::string>>{};
        seen.reserve(auth_event_ids.size());
        for (auto const& id : auth_event_ids)
        {
            auto const it = std::ranges::find_if(store.events, [&](database::PersistentEvent const& evt) {
                return evt.event_id == id;
            });
            if (it == store.events.end())
            {
                return AuthEventsSelectionCheck::unresolvable;
            }
            if (it->room_id != room_id)
            {
                return AuthEventsSelectionCheck::disallowed; // auth event from another room
            }
            auto const parsed = canonicaljson::parse_lossless(it->json);
            auto const* obj = parsed.error == canonicaljson::ParseError::none
                                  ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                                  : nullptr;
            auto const* type = obj != nullptr ? string_member(*obj, "type") : nullptr;
            if (type == nullptr)
            {
                return AuthEventsSelectionCheck::disallowed;
            }
            auto const* named_state_key = obj != nullptr ? string_member(*obj, "state_key") : nullptr;
            auto const key = std::make_pair(*type, named_state_key != nullptr ? *named_state_key : std::string{});
            if (std::ranges::find(seen, key) != seen.end())
            {
                return AuthEventsSelectionCheck::disallowed; // duplicate (type, state_key)
            }
            seen.push_back(key);
            if (std::ranges::find(permitted, key) == permitted.end())
            {
                return AuthEventsSelectionCheck::disallowed; // not a permitted selection
            }
        }
        return AuthEventsSelectionCheck::ok;
    }

    [[nodiscard]] auto response(std::uint16_t status, std::string body,
                                std::vector<std::pair<std::string, std::string>> headers = {}) -> LocalHttpResponse
    {
        return {status, std::move(body), std::move(headers)};
    }

    [[nodiscard]] auto response_from_operation(OperationResult const& result, std::uint16_t ok_status = 200U)
        -> LocalHttpResponse
    {
        return result.ok ? response(ok_status, result.value) : response(result.status, result.reason);
    }

    [[nodiscard]] auto response_from_media_operation(OperationResult const& result) -> LocalHttpResponse
    {
        auto out = response(result.status, result.ok ? result.value : result.reason);
        if (result.retry_after_ms > 0U)
        {
            // A throttled result (the client-outbound budget, ADR-0079) carries its
            // delay across the internal boundary as the standard header, in seconds.
            out.headers.emplace_back("Retry-After", std::to_string((result.retry_after_ms + 999U) / 1000U));
        }
        return out;
    }

    // Extracts `access_token` from a request target's query string
    // (`?access_token=...`), percent-decoded. Used by the federation OpenID
    // userinfo endpoint, which -- unlike every other federation route --
    // carries its credential as a query parameter rather than an X-Matrix
    // Authorization header (Matrix v1.19 SS API §OpenID).
    [[nodiscard]] auto access_token_from_query(std::string_view target) -> std::string
    {
        auto const query_pos = target.find('?');
        if (query_pos == std::string_view::npos)
        {
            return {};
        }
        auto query = target.substr(query_pos + 1U);
        while (!query.empty())
        {
            auto const amp = query.find('&');
            auto const pair = query.substr(0U, amp);
            auto const eq = pair.find('=');
            if (eq != std::string_view::npos && pair.substr(0U, eq) == "access_token")
            {
                return core::percent_decode(pair.substr(eq + 1U));
            }
            if (amp == std::string_view::npos)
            {
                break;
            }
            query = query.substr(amp + 1U);
        }
        return {};
    }

    // Serves GET /_matrix/federation/v1/openid/userinfo (Matrix v1.19 SS API
    // §OpenID). Deliberately bypasses the X-Matrix signed-request machinery
    // entirely -- the spec marks this endpoint "Requires authentication: No"
    // because the caller may be any third-party service, not necessarily a
    // homeserver -- and consults only auth_service's federation_openid_
    // userinfo, which in turn only ever reads the openid_tokens table (never
    // access_tokens/sessions; see docs/threat-model.md). "Unknown" and
    // "expired" tokens are intentionally indistinguishable: both hit the
    // std::nullopt branch and get the spec's one 401 M_UNKNOWN_TOKEN body.
    [[nodiscard]] auto federation_openid_userinfo_response(HomeserverRuntime const& runtime,
                                                           LocalHttpRequest const& request) -> LocalHttpResponse
    {
        auto const token = access_token_from_query(request.target);
        auto const user_id = federation_openid_userinfo(runtime, token);
        if (!user_id.has_value())
        {
            auto error_object = canonicaljson::Object{};
            error_object.push_back(
                canonicaljson::make_member("errcode", canonicaljson::Value{std::string{"M_UNKNOWN_TOKEN"}}));
            error_object.push_back(canonicaljson::make_member(
                "error", canonicaljson::Value{std::string{"Access token unknown or expired"}}));
            auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(error_object)});
            return response(401U, serialized.error == canonicaljson::CanonicalJsonError::none ? serialized.output
                                                                                              : std::string{});
        }
        auto sub_object = canonicaljson::Object{};
        sub_object.push_back(canonicaljson::make_member("sub", canonicaljson::Value{*user_id}));
        auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(sub_object)});
        return response(200U, serialized.error == canonicaljson::CanonicalJsonError::none ? serialized.output
                                                                                          : std::string{});
    }

    // Admin-route auth gate for `/_merovingian/admin/*`. Returns std::nullopt
    // when the caller is a confirmed admin (the route proceeds and builds its
    // own success response); otherwise returns the 401/403 denial response —
    // 401 for a missing/invalid token, 403 for a valid non-admin token, per
    // the v1.19 admin-surface consistency fix (mirrors /_matrix/client/v3/admin/*).
    [[nodiscard]] auto admin_auth_denied(HomeserverRuntime& runtime, std::string_view access_token,
                                         observability::CorrelationContext const& correlation)
        -> std::optional<LocalHttpResponse>
    {
        auto const admin = require_admin(runtime, access_token);
        if (admin.user_id.has_value())
        {
            return std::nullopt;
        }
        auto const missing = admin.denial == AdminAuthResult::Denial::missing_token;
        auto const status = static_cast<std::uint16_t>(missing ? 401 : 403);
        auto const body =
            missing ? std::string{"admin authentication required"} : std::string{"admin privileges required"};
        return response(status, body, observability_headers(correlation, "text/plain; charset=utf-8"));
    }

    [[nodiscard]] auto starts_with(std::string_view value, std::string_view prefix) noexcept -> bool
    {
        return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
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

    [[nodiscard]] auto string_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::string const*
    {
        auto const* value = object_member(object, key);
        return value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
    }

    [[nodiscard]] auto content_membership(canonicaljson::Object const& event) noexcept -> std::string const*
    {
        auto const* content_value = object_member(event, "content");
        auto const* content =
            content_value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&content_value->storage());
        return content == nullptr ? nullptr : string_member(*content, "membership");
    }

    [[nodiscard]] auto server_name_from_user_id(std::string_view user_id) -> std::string_view
    {
        auto const colon = user_id.rfind(':');
        return colon == std::string_view::npos ? std::string_view{} : user_id.substr(colon + 1U);
    }

    [[nodiscard]] auto local_user_exists(LocalDatabase const& database, std::string_view user_id) noexcept -> bool
    {
        return std::ranges::any_of(database.users, [&](LocalUser const& user) {
            return user.user_id == user_id;
        });
    }

    [[nodiscard]] auto joined_local_members(LocalDatabase const& database, std::string_view room_id,
                                            std::string_view local_server) -> std::vector<std::string>
    {
        auto members = std::vector<std::string>{};
        auto const room_it = std::ranges::find_if(database.rooms, [room_id](LocalRoom const& room) {
            return room.room_id == room_id;
        });
        if (room_it == database.rooms.end())
        {
            return members;
        }
        for (auto const& member : room_it->members)
        {
            if (server_name_from_user_id(member) == local_server && local_user_exists(database, member))
            {
                members.push_back(member);
            }
        }
        return members;
    }

    auto dispatch_device_list_update(HomeserverRuntime& runtime, std::string_view destination, std::string_view user_id,
                                     std::uint64_t stream_id) -> void
    {
        if (runtime.dispatch_worker == nullptr)
        {
            return;
        }
        auto const& store = runtime.database.persistent_store;
        for (auto const& device : store.devices)
        {
            if (device.user_id != user_id)
            {
                continue;
            }
            auto const has_keys =
                std::ranges::any_of(store.device_keys, [&device, user_id](database::PersistentDeviceKey const& keys) {
                    return keys.user_id == user_id && keys.device_id == device.device_id;
                });
            if (!has_keys)
            {
                continue;
            }
            // Shared with client_server.cpp's broadcast so both carry the
            // device keys with the owner's cross-signing signatures.
            auto const content = federation::build_device_list_update_content(store, user_id, device.device_id,
                                                                              static_cast<std::int64_t>(stream_id));
            if (!content.has_value())
            {
                continue;
            }
            auto const tx_body = federation::build_edu_transaction_body(runtime.config.server().server_name,
                                                                        "m.device_list_update", *content);
            if (!tx_body.has_value())
            {
                continue;
            }
            auto const tx_id = federation::make_federation_transaction_id();
            auto target = "/_matrix/federation/v1/send/" + tx_id;
            auto transaction = federation::make_outbound_transaction(std::string{destination}, "PUT", target,
                                                                     runtime.config.server().server_name, *tx_body);
            transaction.transaction_id = tx_id;
            std::ignore = runtime.dispatch_worker->enqueue(std::move(transaction));
        }
    }

    auto broadcast_local_device_lists_to_remote_joiner(HomeserverRuntime& runtime, std::string_view room_id,
                                                       std::string_view joining_user_id) -> void
    {
        if (runtime.dispatch_worker == nullptr)
        {
            return;
        }
        auto const destination = server_name_from_user_id(joining_user_id);
        if (destination.empty() || destination == runtime.config.server().server_name)
        {
            return;
        }
        auto const stream_id = runtime.database.persistent_store.next_sync_stream_id;
        for (auto const& local_member :
             joined_local_members(runtime.database, room_id, runtime.config.server().server_name))
        {
            dispatch_device_list_update(runtime, destination, local_member, stream_id);
        }
    }

    // Returns the room_version string from the room's m.room.create state event,
    // falling back to "10" for rooms that pre-date version tracking.
    [[nodiscard]] auto room_version_from_store(database::PersistentStore const& store, std::string_view room_id)
        -> std::string
    {
        for (auto const& state : store.state)
        {
            if (state.room_id != room_id || state.event_type != "m.room.create" || !state.state_key.empty())
            {
                continue;
            }
            for (auto const& evt : store.events)
            {
                if (evt.event_id != state.event_id)
                {
                    continue;
                }
                auto const parsed = canonicaljson::parse_lossless(evt.json);
                auto const* obj = std::get_if<canonicaljson::Object>(&parsed.value.storage());
                if (obj == nullptr)
                {
                    break;
                }
                auto const* content = object_member(*obj, "content");
                if (content == nullptr)
                {
                    break;
                }
                auto const* content_obj = std::get_if<canonicaljson::Object>(&content->storage());
                if (content_obj == nullptr)
                {
                    break;
                }
                auto const* rv = string_member(*content_obj, "room_version");
                if (rv != nullptr && !rv->empty())
                {
                    return *rv;
                }
                break;
            }
            break;
        }
        return "10"; // Oldest advertised version; safe fallback for legacy rooms.
    }

    [[nodiscard]] auto upsert_membership(database::PersistentStore& store, std::string_view room_id,
                                         std::string_view user_id, std::string_view membership,
                                         std::uint64_t stream_ordering) -> bool
    {
        auto const result = database::store_membership(
            store, {std::string{room_id}, std::string{user_id}, std::string{membership}, stream_ordering});
        if (result == database::MembershipStoreResult::stored)
        {
            return true;
        }
        if (result == database::MembershipStoreResult::already_exists)
        {
            return database::update_membership(store, room_id, user_id, membership, stream_ordering);
        }
        return false;
    } // end emit_state

    [[nodiscard]] auto membership_for_endpoint(federation::FederationEndpoint endpoint) -> std::string_view
    {
        switch (endpoint)
        {
        case federation::FederationEndpoint::send_join:
            return "join";
        case federation::FederationEndpoint::send_leave:
            return "leave";
        case federation::FederationEndpoint::send_knock:
            return "knock";
        default:
            return {};
        }
    }

    // `content.third_party_invite.signed.token` of an m.room.member event, or
    // empty. The auth rules need the matching m.room.third_party_invite event.
    [[nodiscard]] auto member_event_third_party_token(canonicaljson::Value const& event) -> std::string
    {
        auto const* event_obj = std::get_if<canonicaljson::Object>(&event.storage());
        auto const* content = event_obj == nullptr ? nullptr : object_member_as_object(*event_obj, "content");
        auto const* third_party_invite =
            content == nullptr ? nullptr : object_member_as_object(*content, "third_party_invite");
        auto const* signed_obj =
            third_party_invite == nullptr ? nullptr : object_member_as_object(*third_party_invite, "signed");
        auto const* token = signed_obj == nullptr ? nullptr : string_member(*signed_obj, "token");
        return token == nullptr ? std::string{} : *token;
    }

    // Outcome of authorising an inbound /invite against a room this server holds.
    struct InviteAuthOutcome final
    {
        bool allowed{true};
        std::uint16_t status{200U};
        std::string body{};
    };

    // Audit FED-5. Spec: SS API v1.19 "Inviting to a room" and "Authorisation
    // rules" (m.room.member, membership "invite"): the sender must be joined
    // and hold invite power, and "If the target user is banned, reject". An
    // invite for a room whose current state we hold is authorised against that
    // state; a room we do not hold (an invite to a remote room) cannot be
    // checked here and is left to the caller's stripped-state handling.
    [[nodiscard]] auto authorize_invite_against_local_room(HomeserverRuntime const& runtime, std::string_view room_id,
                                                           std::string_view room_version,
                                                           canonicaljson::Value const& event, std::string_view sender,
                                                           std::string_view target_user) -> InviteAuthOutcome
    {
        auto const& store = runtime.database.persistent_store;
        auto const forbidden = [](std::string_view reason) {
            return InviteAuthOutcome{false, 403U, matrix_error("M_FORBIDDEN", reason)};
        };
        auto const stored_version = room_version_from_store(store, room_id);
        if (!room_version.empty() && room_version != stored_version)
        {
            return InviteAuthOutcome{false, 400U,
                                     matrix_error("M_INVALID_PARAM", "invite room_version does not match the room")};
        }
        auto const* policy = rooms::find_room_version_policy(stored_version);
        if (policy == nullptr)
        {
            return forbidden("invite refused: room version is not supported");
        }
        auto auth_map = build_pdu_auth_event_map(store, room_id, sender, target_user, "m.room.member",
                                                 member_event_third_party_token(event));
        fill_create_from_room_state(auth_map, store, room_id);
        auto const decision = events::authorize_event_against_auth_events(event, *policy, auth_map);
        if (!decision.allowed)
        {
            return forbidden("invite refused by the room's authorization rules: " + decision.reason);
        }
        return {};
    }

    [[nodiscard]] auto sign_invite_event(HomeserverRuntime& runtime, canonicaljson::Value const& event_value,
                                         std::string_view room_version) -> std::optional<std::string>
    {
        // Use the active key record without loading the signing secret. In the main
        // process the secret is held by runtime.crypto_provider. The federation worker
        // never signs (ADR-0078): its invite_handler relays to main, which signs.
        auto key = find_active_server_signing_key(runtime);
        if (!key.has_value() || runtime.crypto_provider == nullptr)
        {
            return std::nullopt;
        }
        auto const* policy = rooms::find_room_version_policy(room_version.empty() ? "12" : room_version);
        if (policy == nullptr)
        {
            return std::nullopt;
        }
        auto key_store = RuntimeSigningKeyStore{runtime.config.server().server_name, *key};
        auto signed_event = events::sign_event_for_server(event_value, *policy, key_store, *runtime.crypto_provider,
                                                          runtime.config.server().server_name);
        return signed_event.error.empty() ? std::optional<std::string>{std::move(signed_event.event_json)}
                                          : std::nullopt;
    }

    [[nodiscard]] auto split_pipe_2(std::string_view body) -> std::optional<std::array<std::string_view, 2U>>
    {
        auto const first = body.find('|');
        if (first == std::string_view::npos || first == 0U || first + 1U >= body.size())
        {
            return std::nullopt;
        }
        return std::array<std::string_view, 2U>{body.substr(0U, first), body.substr(first + 1U)};
    }

    [[nodiscard]] auto split_pipe_3(std::string_view body) -> std::optional<std::array<std::string_view, 3U>>
    {
        auto const first = body.find('|');
        auto const second = first == std::string_view::npos ? std::string_view::npos : body.find('|', first + 1U);
        if (first == std::string_view::npos || first == 0U || second == std::string_view::npos ||
            second == first + 1U || second + 1U >= body.size())
        {
            return std::nullopt;
        }
        return std::array<std::string_view, 3U>{body.substr(0U, first), body.substr(first + 1U, second - first - 1U),
                                                body.substr(second + 1U)};
    }

    [[nodiscard]] auto split_pipe_4(std::string_view body) -> std::optional<std::array<std::string_view, 4U>>
    {
        auto fields = std::array<std::string_view, 4U>{};
        auto remaining = body;
        for (auto index = std::size_t{0U}; index < fields.size(); ++index)
        {
            if (index + 1U == fields.size())
            {
                fields[index] = remaining;
                break;
            }
            auto const separator = remaining.find('|');
            if (separator == std::string_view::npos)
            {
                return std::nullopt;
            }
            fields[index] = remaining.substr(0U, separator);
            remaining = remaining.substr(separator + 1U);
        }
        for (auto const field : fields)
        {
            if (field.empty())
            {
                return std::nullopt;
            }
        }
        return fields;
    }

    [[nodiscard]] auto split_pipe_6(std::string_view body) -> std::optional<std::array<std::string_view, 6U>>
    {
        auto fields = std::array<std::string_view, 6U>{};
        auto remaining = body;
        for (auto index = std::size_t{0U}; index < fields.size(); ++index)
        {
            auto const separator = remaining.find('|');
            if (index + 1U == fields.size())
            {
                fields[index] = remaining;
                break;
            }
            if (separator == std::string_view::npos)
            {
                return std::nullopt;
            }
            fields[index] = remaining.substr(0U, separator);
            remaining = remaining.substr(separator + 1U);
        }
        for (auto const field : fields)
        {
            if (field.empty())
            {
                return std::nullopt;
            }
        }
        return fields;
    }

    [[nodiscard]] auto parse_u64(std::string_view value) noexcept -> std::optional<std::uint64_t>
    {
        if (value.empty())
        {
            return std::nullopt;
        }
        auto result = std::uint64_t{0U};
        for (auto const character : value)
        {
            if (character < '0' || character > '9')
            {
                return std::nullopt;
            }
            auto const digit = static_cast<std::uint64_t>(character - '0');
            if (result > (std::numeric_limits<std::uint64_t>::max() - digit) / 10U)
            {
                return std::nullopt;
            }
            result = (result * 10U) + digit;
        }
        return result;
    }

    [[nodiscard]] auto parse_bool_flag(std::string_view value) noexcept -> std::optional<bool>
    {
        if (value == "canonical" || value == "true" || value == "clean")
        {
            return true;
        }
        if (value == "uncanonical" || value == "false" || value == "dirty")
        {
            return false;
        }
        return std::nullopt;
    }

    // Pipe-delimited federation auth token used by integration-test fixtures:
    // origin|key_id|signature|destination|now_ts|canonical_json_verified.
    [[nodiscard]] auto parse_signed_federation_request(LocalHttpRequest const& request,
                                                       config::ServerConfig const& server)
        -> std::optional<federation::SignedFederationRequest>
    {
        auto const fields = split_pipe_6(request.access_token);
        if (!fields.has_value())
        {
            return std::nullopt;
        }
        auto const now_ts = parse_u64((*fields)[4]);
        auto const canonical_json_verified = parse_bool_flag((*fields)[5]);
        if (!now_ts.has_value() || !canonical_json_verified.has_value())
        {
            return std::nullopt;
        }
        auto signed_request = federation::SignedFederationRequest{};
        signed_request.method = request.method;
        signed_request.target = request.target;
        signed_request.origin = std::string{(*fields)[0]};
        signed_request.key_id = std::string{(*fields)[1]};
        signed_request.signature = std::string{(*fields)[2]};
        signed_request.destination = std::string{(*fields)[3]};
        signed_request.now_ts = *now_ts;
        signed_request.canonical_json_verified = *canonical_json_verified;
        signed_request.body = request.body;
        // Budgets pre-authentication remote-key resolution (#487); see
        // SignedFederationRequest::remote_addr. Resolved through trusted_proxies
        // and IPv6-prefix grouping for the same reason as the federation_proxy
        // path.
        signed_request.remote_addr = rate_limit_client_key(request, server);
        return signed_request;
    }

    [[nodiscard]] auto path_suffix(std::string_view target, std::string_view prefix) noexcept -> std::string_view
    {
        return starts_with(target, prefix) ? target.substr(prefix.size()) : std::string_view{};
    }

    // Tiny, allocation-light query string parser used by the audit-filter
    // handler. Splits on '&', then on '=' once per segment. Empty keys
    // are dropped, empty values are kept. The returned views are
    // substrings of the input — the caller must own the input buffer
    // for the lifetime of the views.
    [[nodiscard]] auto parse_audit_query_string(std::string_view query)
        -> std::vector<std::pair<std::string_view, std::string_view>>
    {
        auto out = std::vector<std::pair<std::string_view, std::string_view>>{};
        auto remaining = query;
        while (!remaining.empty())
        {
            auto const amp = remaining.find('&');
            auto const segment = remaining.substr(0U, amp);
            if (!segment.empty())
            {
                auto const eq = segment.find('=');
                if (eq == std::string_view::npos)
                {
                    out.emplace_back(segment, std::string_view{});
                }
                else
                {
                    out.emplace_back(segment.substr(0U, eq), segment.substr(eq + 1U));
                }
            }
            if (amp == std::string_view::npos)
            {
                break;
            }
            remaining = remaining.substr(amp + 1U);
        }
        return out;
    }

    struct ThumbnailParams final
    {
        std::uint32_t width{0U};
        std::uint32_t height{0U};
        media::ThumbnailMethod method{media::ThumbnailMethod::scale};
    };

    // Parses the Matrix thumbnail query parameters (`width`, `height`, `method`)
    // from a request target. Defaults follow the CS API: method `scale`, and a
    // zero dimension means the request is unusable (the handler then falls back
    // to serving the original media).
    [[nodiscard]] auto parse_thumbnail_params(std::string_view target) -> ThumbnailParams
    {
        auto params = ThumbnailParams{};
        auto const query_start = target.find('?');
        if (query_start == std::string_view::npos)
        {
            return params;
        }
        auto const parse_dimension = [](std::string_view value) -> std::uint32_t {
            auto result = std::uint32_t{0U};
            for (auto const ch : value)
            {
                if (ch < '0' || ch > '9' || result > 429496U)
                {
                    return 0U;
                }
                result = result * 10U + static_cast<std::uint32_t>(ch - '0');
            }
            return result;
        };
        for (auto const& kv : parse_audit_query_string(target.substr(query_start + 1U)))
        {
            if (kv.first == "width")
            {
                params.width = parse_dimension(kv.second);
            }
            else if (kv.first == "height")
            {
                params.height = parse_dimension(kv.second);
            }
            else if (kv.first == "method" && kv.second == "crop")
            {
                params.method = media::ThumbnailMethod::crop;
            }
        }
        return params;
    }

    // What a remote media download or thumbnail needs to know about its request
    // beyond the media it names: which client to count it against
    // (rate_limit_client_key, so trusted_proxies applies) and whether the caller
    // set allow_remote=false. Only a literal `false` opts out, matching the
    // spec's boolean; anything else leaves the default (true).
    [[nodiscard]] auto remote_media_context(LocalHttpRequest const& request,
                                            HomeserverRuntime const& runtime) -> RemoteMediaRequestContext
    {
        auto context = RemoteMediaRequestContext{};
        context.client_key = rate_limit_client_key(request, runtime.config.server());
        auto const query_start = request.target.find('?');
        if (query_start != std::string::npos)
        {
            for (auto const& kv : parse_audit_query_string(std::string_view{request.target}.substr(query_start + 1U)))
            {
                if (kv.first == "allow_remote" && kv.second == "false")
                {
                    context.allow_remote = false;
                }
            }
        }
        return context;
    }

    [[nodiscard]] auto object_member_as_object(canonicaljson::Object const& object, std::string_view key)
        -> canonicaljson::Object const*
    {
        auto const* value = object_member(object, key);
        return value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&value->storage());
    }

    [[nodiscard]] auto object_member_as_string(canonicaljson::Object const& object, std::string_view key)
        -> std::string const*
    {
        auto const* value = object_member(object, key);
        return value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
    }

    [[nodiscard]] auto object_member_as_array(canonicaljson::Object const& object, std::string_view key)
        -> canonicaljson::Array const*
    {
        auto const* value = object_member(object, key);
        return value == nullptr ? nullptr : std::get_if<canonicaljson::Array>(&value->storage());
    }

    [[nodiscard]] auto object_member_as_int(canonicaljson::Object const& object, std::string_view key)
        -> std::int64_t const*
    {
        auto const* value = object_member(object, key);
        return value == nullptr ? nullptr : std::get_if<std::int64_t>(&value->storage());
    }

    [[nodiscard]] auto object_member_as_bool(canonicaljson::Object const& object, std::string_view key) -> bool const*
    {
        auto const* value = object_member(object, key);
        return value == nullptr ? nullptr : std::get_if<bool>(&value->storage());
    }

    [[nodiscard]] auto user_belongs_to_origin(std::string_view user_id, std::string_view origin) -> bool
    {
        return !user_id.empty() && server_name_from_user_id(user_id) == origin;
    }

    // True if this server holds any membership row for the room.
    //
    // 0.12.5 audit, findings 12 and 13: ephemeral federation state (typing,
    // receipts) is only meaningful for a room we are actually in, and gating on
    // it is what bounds those vectors. Without it a peer could mint entries for
    // arbitrary invented room_ids and grow them without limit.
    //
    // Any membership, not only "join": a room we have been invited to or have
    // left still has rows a client may sync, and the gate exists to reject rooms
    // this server has never heard of, not to re-derive visibility rules.
    [[nodiscard]] auto room_has_local_membership(HomeserverRuntime const& runtime, std::string_view room_id) -> bool
    {
        auto const& memberships = runtime.database.persistent_store.memberships;
        return std::ranges::any_of(memberships, [room_id](database::PersistentMembership const& membership) {
            return membership.room_id == room_id;
        });
    }

    // Outcome of a direct_to_device enqueue attempt. `targeted` counts every
    // per-device entry that was well-formed enough to attempt a store;
    // `stored` counts how many of those actually persisted. The two can
    // diverge on a store-layer rejection (e.g. an empty sender/device id) or
    // a backend write failure — callers must not treat targeted > 0 as proof
    // that the key share reached the recipient's queue (#464).
    //
    // The remaining fields say why an EDU (or part of it) was dropped without
    // an attempt (audit FED-3): they are policy drops, not store failures.
    struct DirectToDeviceEnqueueResult final
    {
        std::size_t targeted{0U};
        std::size_t stored{0U};
        // The EDU `sender` is not a user of the sending origin: whole EDU dropped.
        bool sender_not_on_origin{false};
        // message_id absent, not a string, empty or over 32 codepoints: whole EDU dropped.
        bool invalid_message_id{false};
        // (origin, message_id) was already seen inside the replay window: whole EDU dropped.
        bool replay{false};
        // Target entries skipped because the user is not a local, active account.
        std::size_t skipped_non_local{0U};
        // True when the per-EDU delivery cap was reached and the rest dropped.
        bool truncated{false};
    };

    [[nodiscard]] auto is_active_local_user(HomeserverRuntime const& runtime, std::string_view user_id) -> bool
    {
        if (server_name_from_user_id(user_id) != runtime.config.server().server_name)
        {
            return false;
        }
        return std::ranges::any_of(runtime.database.persistent_store.users,
                                   [user_id](database::PersistentUser const& user) {
                                       return user.user_id == user_id && !user.deactivated;
                                   });
    }

    // Active local users who are joined to at least one room that `subject` is
    // also joined to, according to the current membership rows, sorted and
    // unique. Empty when the subject shares no room with any local user.
    [[nodiscard]] auto local_users_sharing_a_joined_room_with(HomeserverRuntime const& runtime,
                                                              std::string_view subject) -> std::vector<std::string>
    {
        auto const& store = runtime.database.persistent_store;
        auto const subject_rooms = [&] {
            auto rooms = std::unordered_set<std::string_view>{};
            for (auto const& membership : store.memberships)
            {
                if (membership.user_id == subject && membership.membership == "join")
                {
                    rooms.insert(membership.room_id);
                }
            }
            return rooms;
        }();
        auto observers = std::vector<std::string>{};
        if (subject_rooms.empty())
        {
            return observers;
        }
        for (auto const& membership : store.memberships)
        {
            if (membership.membership == "join" && membership.user_id != subject &&
                subject_rooms.contains(membership.room_id) &&
                server_name_from_user_id(membership.user_id) == runtime.config.server().server_name)
            {
                observers.push_back(membership.user_id);
            }
        }
        // De-duplicate first: the account check below scans the user table.
        std::ranges::sort(observers);
        auto const duplicates = std::ranges::unique(observers);
        observers.erase(duplicates.begin(), duplicates.end());
        std::erase_if(observers, [&runtime](std::string const& user_id) {
            return !is_active_local_user(runtime, user_id);
        });
        return observers;
    }

    // Queues the messages of an inbound m.direct_to_device EDU for local
    // devices.
    //
    // Spec: SS API v1.19, "Send-to-device messaging". The sending server
    // asserts `sender`, so it must be a user of that server; `message_id` is
    // "used for idempotence"; the target user IDs are named by the sender and
    // only ours may be delivered to (audit FED-3).
    //
    // The replay window lives in memory only (federation::EduIdempotenceWindow):
    // a restart forgets it, so a replay straddling a restart is delivered again.
    // Persisting it would need a migration and is not required for a
    // best-effort EDU.
    auto enqueue_direct_to_device_messages(HomeserverRuntime& runtime, std::string_view origin,
                                           std::string_view content_json) -> DirectToDeviceEnqueueResult
    {
        auto result = DirectToDeviceEnqueueResult{};
        auto const parsed = canonicaljson::parse_lossless(std::string{content_json});
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return result;
        }
        auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (root == nullptr)
        {
            return result;
        }
        auto const* sender = object_member_as_string(*root, "sender");
        auto const* message_type = object_member_as_string(*root, "type");
        auto const* messages = object_member_as_object(*root, "messages");
        if (sender == nullptr || message_type == nullptr || messages == nullptr)
        {
            return result;
        }
        if (!user_belongs_to_origin(*sender, origin))
        {
            result.sender_not_on_origin = true;
            return result;
        }
        auto const* message_id = object_member_as_string(*root, "message_id");
        if (message_id == nullptr || !federation::direct_to_device_message_id_is_valid(*message_id))
        {
            result.invalid_message_id = true;
            return result;
        }
        if (!runtime.inbound_to_device_window.first_sighting(origin, *message_id,
                                                             federation::EduIdempotenceWindow::Clock::now()))
        {
            result.replay = true;
            return result;
        }

        for (auto const& user_entry : *messages)
        {
            auto const* device_map = std::get_if<canonicaljson::Object>(&user_entry.value->storage());
            if (device_map == nullptr)
            {
                continue;
            }
            if (!is_active_local_user(runtime, user_entry.key))
            {
                ++result.skipped_non_local;
                continue;
            }
            for (auto const& device_entry : *device_map)
            {
                if (device_entry.value == nullptr)
                {
                    continue;
                }
                if (result.targeted >= max_inbound_direct_to_device_deliveries)
                {
                    result.truncated = true;
                    return result;
                }
                auto const serialized = canonicaljson::serialize_canonical(*device_entry.value);
                if (serialized.error != canonicaljson::CanonicalJsonError::none)
                {
                    continue;
                }
                ++result.targeted;
                auto message = database::PersistentToDeviceMessage{};
                message.sender_user_id = *sender;
                message.target_user_id = user_entry.key;
                message.target_device_id = device_entry.key;
                message.message_type = *message_type;
                message.content_json = serialized.output;
                if (database::enqueue_to_device_message(runtime.database.persistent_store, std::move(message)))
                {
                    ++result.stored;
                }
            }
        }
        return result;
    }

    [[nodiscard]] auto local_media_download_parts(std::string_view suffix)
        -> std::optional<std::array<std::string_view, 2U>>
    {
        // Matrix media download and thumbnail URLs may carry query parameters
        // such as ?allow_redirect=true or ?width=...&height=... ; the slash
        // separator between server_name and media_id must be looked up in the
        // path only, before any '?'.
        auto const query_pos = suffix.find('?');
        auto const path = query_pos == std::string_view::npos ? suffix : suffix.substr(0U, query_pos);
        auto const separator = path.find('/');
        if (separator == std::string_view::npos || separator == 0U || separator + 1U >= path.size())
        {
            return std::nullopt;
        }
        auto const server_name = path.substr(0U, separator);
        auto const media_id = path.substr(separator + 1U);
        // #444: reject the same traversal/whitespace shapes the repository
        // boundary (media_id_is_safe() in repository.cpp) rejects, so a
        // crafted URL never parses into a media_id any downstream code could
        // mistake for a safe value before the repository layer catches it.
        if (media_id.empty() || media_id.find('/') != std::string_view::npos ||
            media_id.find("..") != std::string_view::npos || media_id.find(' ') != std::string_view::npos)
        {
            return std::nullopt;
        }
        return std::array<std::string_view, 2U>{server_name, media_id};
    }

    // Admin media routes (quarantine/release/remove) take a single path
    // segment with no server_name prefix, unlike the download/thumbnail
    // routes above. Strips any query string, then rejects anything that
    // isn't a safe single path segment: non-empty, no '/', no "..", no
    // embedded space (the same constraints media::upload_local_media applies
    // via media_id_is_safe() in repository.cpp when it mints a media ID).
    // Without this, a request like
    // ".../admin/media/remove/m1_digest?reason=x" would treat the query
    // string as part of the media ID and silently act on the wrong object
    // (or no object at all) instead of rejecting the request outright.
    [[nodiscard]] auto admin_media_id_from_suffix(std::string_view suffix) noexcept -> std::optional<std::string_view>
    {
        auto const query_pos = suffix.find('?');
        auto const media_id = query_pos == std::string_view::npos ? suffix : suffix.substr(0U, query_pos);
        if (media_id.empty() || media_id.find('/') != std::string_view::npos ||
            media_id.find("..") != std::string_view::npos || media_id.find(' ') != std::string_view::npos)
        {
            return std::nullopt;
        }
        return media_id;
    }

    // Wires all FederationRuntimeState callbacks to production implementations.
    // Called lazily on the first federation request so the runtime is already
    // at a stable address when the lambdas capture references to its fields.
    // Idempotent: the pdu_sink check guards against double-wiring.
    auto wire_federation_callbacks_impl(HomeserverRuntime& runtime) -> void
    {
        if (!runtime.federation.config.enabled || runtime.federation.pdu_sink)
        {
            return;
        }
        // Capture the runtime by pointer for all lambdas — safe because the
        // callbacks are stored inside the same runtime object, which outlives
        // every call made through handle_federation_http_request.
        auto* rt = &runtime;
        auto* outbound = runtime.outbound_client.get();
        auto* discovery = runtime.discovery_network.get();
        auto* cached = runtime.cached_discovery.get();
        auto const timeout = runtime.federation.config.remote_timeout_seconds;

        runtime.federation.pdu_sink =
            [rt](federation::InboundPduEnvelope const& envelope) -> federation::PduIngestionResult {
            // ingest_pdu_event reserves the global stream-ordering/sync ids,
            // serializes on the room stripe, and releases only the global mutex
            // for the backend commit so independent rooms can persist in parallel.
            auto result = ingest_pdu_event(*rt, envelope);
            if (result.status == federation::PduIngestionStatus::accepted)
            {
                if (rt->sync_notifier != nullptr)
                {
                    rt->sync_notifier->publish(result.accepted_stream_ordering, result.accepted_sync_stream_id);
                }
                // #479 P1 fix: this is the single convergence point for every
                // accepted federation PDU — both the direct main-process path
                // (inbound_request.cpp calling runtime.pdu_sink) and the
                // worker-relayed path (worker_pool.cpp's pdu_ingest handler
                // calling this same runtime_.federation.pdu_sink) land here
                // exactly once per accepted PDU, so this cannot double-deliver.
                // Without this call, an event from a remote room member never
                // reached the push pipeline at all: send_event() (the only
                // other caller of build_pending_push_deliveries) only runs for
                // locally composed events, so a message from a federated room
                // member produced no /notifications row and no Push Gateway
                // request for a local recipient — the normal federated-room
                // case. See room_service.hpp's deliver_federation_push_
                // notifications doc comment.
                deliver_federation_push_notifications(*rt, envelope, result.accepted_stream_ordering);
            }
            return result;
        };

        runtime.federation.edu_sink =
            [rt](federation::InboundEduEnvelope const& envelope) -> federation::EduDispositionResult {
            switch (envelope.type)
            {
            case federation::EduType::typing: {
                // content: {room_id, user_id, typing}. Parsed with the
                // canonical JSON parser (#425) rather than substring
                // scanning: a user_id containing an escaped quote (e.g.
                // "@a:b\"c") made find('"', ...) stop at the escaped quote,
                // yielding a truncated/arbitrary user_id.
                auto const parsed = canonicaljson::parse_lossless(envelope.content_json);
                auto const* root = parsed.error == canonicaljson::ParseError::none
                                       ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                                       : nullptr;
                auto const* room_id_ptr = root == nullptr ? nullptr : object_member_as_string(*root, "room_id");
                auto const* user_id_ptr = root == nullptr ? nullptr : object_member_as_string(*root, "user_id");
                if (room_id_ptr == nullptr || user_id_ptr == nullptr || room_id_ptr->empty() || user_id_ptr->empty())
                {
                    return {federation::EduDispositionStatus::rejected_invalid, "missing room_id or user_id"};
                }
                auto const* typing_ptr = object_member_as_bool(*root, "typing");
                auto const typing = typing_ptr != nullptr && *typing_ptr;
                auto const& room_id = *room_id_ptr;
                auto const& user_id = *user_id_ptr;
                // Spec: the EDU sender's own homeserver must be the one
                // reporting the user's typing state (SS API #edus) — a
                // remote origin claiming a user_id on a different domain is
                // a cross-origin identity spoof (#425).
                if (!user_belongs_to_origin(user_id, envelope.origin))
                {
                    return {federation::EduDispositionStatus::rejected_invalid,
                            "user_id domain does not match envelope origin"};
                }
                // 0.12.5 audit, finding 12: bound what a peer can put here. The
                // primary bound is membership — this server has no use for
                // typing state in a room it is not in, and without the check a
                // peer could mint an entry for any room_id it invented.
                if (!room_has_local_membership(*rt, room_id))
                {
                    return {federation::EduDispositionStatus::rejected_invalid,
                            "typing EDU for a room this server has no membership in"};
                }
                auto const previous_users = current_typing_users_in_room(*rt, room_id);
                auto existing = std::ranges::find_if(rt->typing_users, [&](auto const& t) {
                    return t.room_id == room_id && t.user_id == user_id;
                });
                if (typing)
                {
                    if (existing != rt->typing_users.end())
                    {
                        existing->typing = true;
                    }
                    else
                    {
                        // Backstop for a peer that is a legitimate member of a
                        // very large room. Typing state is ephemeral, so the
                        // oldest entry is already the least useful one.
                        if (rt->typing_users.size() >= max_inbound_typing_entries)
                        {
                            rt->typing_users.erase(rt->typing_users.begin());
                        }
                        rt->typing_users.push_back({room_id, user_id, true, std::uint64_t{0U}});
                    }
                }
                else
                {
                    if (existing != rt->typing_users.end())
                    {
                        rt->typing_users.erase(existing);
                    }
                }
                auto const room_stream_id = update_room_typing_stream_id_if_changed(*rt, room_id, previous_users);
                if (room_stream_id != std::uint64_t{0U} && rt->sync_notifier != nullptr)
                {
                    rt->sync_notifier->publish(rt->database.next_stream_ordering - 1U,
                                               rt->database.persistent_store.next_sync_stream_id);
                }
                return {federation::EduDispositionStatus::accepted, {}};
            }
            case federation::EduType::receipt: {
                auto const parsed = canonicaljson::parse_lossless(envelope.content_json);
                auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
                if (parsed.error != canonicaljson::ParseError::none || root == nullptr)
                {
                    return {federation::EduDispositionStatus::rejected_invalid, "receipt content must be an object"};
                }
                for (auto const& room_member : *root)
                {
                    auto const* receipt_types = std::get_if<canonicaljson::Object>(&room_member.value->storage());
                    if (receipt_types == nullptr)
                    {
                        return {federation::EduDispositionStatus::rejected_invalid,
                                "receipt room entry must be an object"};
                    }
                    // 0.12.5 audit, finding 13: skip rooms this server holds no
                    // membership in. Skipping rather than rejecting the whole
                    // EDU: a receipt transaction legitimately batches several
                    // rooms, and one stale room_id must not discard the rest.
                    if (!room_has_local_membership(*rt, room_member.key))
                    {
                        continue;
                    }
                    for (auto const& receipt_type_member : *receipt_types)
                    {
                        // Spec (S-S API, m.receipt): "only a single <receipt_type> should be
                        // used: m.read. m.read.private MUST NOT appear in this federated
                        // m.receipt EDU." Any other type from a peer is dropped, not stored, so
                        // a remote server can neither plant a private or fully-read receipt nor
                        // grow the receipt table with invented types (CSAZ-4).
                        if (receipt_type_member.key != "m.read")
                        {
                            continue;
                        }
                        auto const* users = std::get_if<canonicaljson::Object>(&receipt_type_member.value->storage());
                        if (users == nullptr)
                        {
                            return {federation::EduDispositionStatus::rejected_invalid,
                                    "receipt type entry must be an object"};
                        }
                        for (auto const& user_member : *users)
                        {
                            if (!user_belongs_to_origin(user_member.key, envelope.origin))
                            {
                                return {federation::EduDispositionStatus::rejected_invalid,
                                        "receipt user_id must belong to the sending origin"};
                            }
                            auto const* receipt = std::get_if<canonicaljson::Object>(&user_member.value->storage());
                            if (receipt == nullptr)
                            {
                                return {federation::EduDispositionStatus::rejected_invalid,
                                        "receipt user entry must be an object"};
                            }
                            auto const* event_ids = object_member_as_array(*receipt, "event_ids");
                            if (event_ids == nullptr || event_ids->empty())
                            {
                                return {federation::EduDispositionStatus::rejected_invalid,
                                        "receipt event_ids must be a non-empty array"};
                            }
                            auto const* first_event_id = std::get_if<std::string>(&event_ids->front().storage());
                            if (first_event_id == nullptr || first_event_id->empty())
                            {
                                return {federation::EduDispositionStatus::rejected_invalid,
                                        "receipt event_ids entries must be strings"};
                            }
                            auto const* data = object_member_as_object(*receipt, "data");
                            auto const* ts_value = data == nullptr ? nullptr : object_member_as_int(*data, "ts");
                            auto const ts =
                                ts_value != nullptr && *ts_value > 0 ? static_cast<std::uint64_t>(*ts_value) : 0U;
                            auto existing = std::ranges::find_if(rt->receipts, [&](auto const& current) {
                                return current.room_id == room_member.key && current.user_id == user_member.key &&
                                       current.receipt_type == receipt_type_member.key;
                            });
                            auto const stream_id = database::allocate_sync_stream_id(rt->database.persistent_store);
                            if (existing != rt->receipts.end())
                            {
                                existing->event_id = *first_event_id;
                                existing->ts = ts;
                                existing->stream_id = stream_id;
                            }
                            else
                            {
                                // 0.12.5 audit, finding 13. Same shape as the
                                // typing cap: the membership check above is the
                                // real bound, this evicts the oldest read
                                // receipt if a peer floods a room it is in.
                                if (rt->receipts.size() >= max_inbound_receipt_entries)
                                {
                                    rt->receipts.erase(rt->receipts.begin());
                                }
                                rt->receipts.push_back({room_member.key, receipt_type_member.key, user_member.key,
                                                        *first_event_id, ts, stream_id});
                            }
                        }
                    }
                }
                if (rt->sync_notifier != nullptr)
                {
                    rt->sync_notifier->publish(rt->database.next_stream_ordering - 1U,
                                               rt->database.persistent_store.next_sync_stream_id);
                }
                return {federation::EduDispositionStatus::accepted, {}};
            }
            case federation::EduType::presence: {
                auto const parsed = canonicaljson::parse_lossless(envelope.content_json);
                auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
                if (parsed.error != canonicaljson::ParseError::none || root == nullptr)
                {
                    return {federation::EduDispositionStatus::rejected_invalid, "presence content must be an object"};
                }
                auto const* push = object_member_as_array(*root, "push");
                if (push == nullptr)
                {
                    return {federation::EduDispositionStatus::accepted, {}};
                }
                for (auto const& entry : *push)
                {
                    auto const* presence = std::get_if<canonicaljson::Object>(&entry.storage());
                    if (presence == nullptr)
                    {
                        return {federation::EduDispositionStatus::rejected_invalid, "presence entry must be an object"};
                    }
                    auto const* user_id = object_member_as_string(*presence, "user_id");
                    if (user_id == nullptr || !user_belongs_to_origin(*user_id, envelope.origin))
                    {
                        return {federation::EduDispositionStatus::rejected_invalid,
                                "presence user_id must belong to the sending origin"};
                    }
                    auto state = database::PersistentPresence{};
                    state.user_id = *user_id;
                    if (auto const* presence_value = object_member_as_string(*presence, "presence");
                        presence_value != nullptr && !presence_value->empty())
                    {
                        state.presence = *presence_value;
                    }
                    if (auto const* status_msg = object_member_as_string(*presence, "status_msg");
                        status_msg != nullptr)
                    {
                        state.status_msg = *status_msg;
                    }
                    if (auto const* last_active_ago = object_member_as_int(*presence, "last_active_ago");
                        last_active_ago != nullptr && *last_active_ago >= 0)
                    {
                        state.last_active_ago = *last_active_ago;
                    }
                    if (auto const* currently_active = object_member_as_bool(*presence, "currently_active");
                        currently_active != nullptr)
                    {
                        state.currently_active = *currently_active;
                    }
                    std::ignore = database::upsert_presence(rt->database.persistent_store, std::move(state));
                }
                if (rt->sync_notifier != nullptr)
                {
                    rt->sync_notifier->publish(rt->database.next_stream_ordering - 1U,
                                               rt->database.persistent_store.next_sync_stream_id);
                }
                return {federation::EduDispositionStatus::accepted, {}};
            }
            case federation::EduType::direct_to_device: {
                auto const enqueue_result =
                    enqueue_direct_to_device_messages(*rt, envelope.origin, envelope.content_json);
                if (enqueue_result.sender_not_on_origin || enqueue_result.invalid_message_id)
                {
                    // Whole EDU dropped; the transaction itself still succeeds
                    // (EDUs are best-effort).
                    log_diagnostic(
                        "federation.edu.direct_to_device.dropped",
                        {
                            {"origin", envelope.origin,                                                           false},
                            {"reason",
                             enqueue_result.sender_not_on_origin ? "sender_not_on_origin" : "invalid_message_id",
                             false                                                                                     },
                    },
                        observability::LogEventSeverity::warning);
                    return {federation::EduDispositionStatus::rejected_invalid,
                            enqueue_result.sender_not_on_origin
                                ? "direct_to_device sender must belong to the sending origin"
                                : "direct_to_device message_id must be 1 to 32 codepoints"};
                }
                if (enqueue_result.replay)
                {
                    // Idempotent: the first delivery already happened.
                    return {federation::EduDispositionStatus::accepted, {}};
                }
                if (enqueue_result.truncated || enqueue_result.skipped_non_local != 0U)
                {
                    log_diagnostic("federation.edu.direct_to_device.partial",
                                   {
                                       {"origin",            envelope.origin,                                  false},
                                       {"skipped_non_local", std::to_string(enqueue_result.skipped_non_local), false},
                                       {"truncated",         enqueue_result.truncated ? "true" : "false",      false},
                    },
                                   observability::LogEventSeverity::warning);
                }
                if (rt->sync_notifier != nullptr)
                {
                    rt->sync_notifier->publish(rt->database.next_stream_ordering - 1U,
                                               rt->database.persistent_store.next_sync_stream_id);
                }
                // A targeted device whose message did not persist is a lost
                // E2EE room-key share, not a benign no-op. Reporting
                // "accepted" regardless used to hide store failures
                // entirely: edu_dispatched still incremented, edu_dropped
                // never did, and nothing in any log said a share was lost
                // (#464). targeted == 0 (an empty/no-op messages map) still
                // reports accepted — there was nothing to fail.
                if (enqueue_result.stored < enqueue_result.targeted)
                {
                    log_diagnostic("federation.edu.direct_to_device.store_incomplete",
                                   {
                                       {"origin",   envelope.origin,                         false},
                                       {"targeted", std::to_string(enqueue_result.targeted), false},
                                       {"stored",   std::to_string(enqueue_result.stored),   false},
                    },
                                   observability::LogEventSeverity::warning);
                    return {federation::EduDispositionStatus::rejected_invalid,
                            "direct_to_device store incomplete: " + std::to_string(enqueue_result.stored) + "/" +
                                std::to_string(enqueue_result.targeted) + " devices stored"};
                }
                return {federation::EduDispositionStatus::accepted, {}};
            }
            // m.device_list_update (a device changed) and m.signing_key_update
            // (the user's cross-signing keys changed) both mean the same thing
            // to a local client: that remote user's keys must be re-queried.
            // Nothing is cached here — /keys/query always asks the remote
            // server — so the whole job is to put the user in
            // device_lists.changed.
            case federation::EduType::device_list_update:
            case federation::EduType::signing_key_update: {
                auto const parsed = canonicaljson::parse_lossless(envelope.content_json);
                auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
                if (parsed.error != canonicaljson::ParseError::none || root == nullptr)
                {
                    return {federation::EduDispositionStatus::rejected_invalid,
                            envelope.edu_type + " content must be an object"};
                }
                auto const* user_id = object_member_as_string(*root, "user_id");
                if (user_id == nullptr || !user_belongs_to_origin(*user_id, envelope.origin))
                {
                    return {federation::EduDispositionStatus::rejected_invalid,
                            envelope.edu_type + " user_id must belong to the sending origin"};
                }
                if (!user_id->empty())
                {
                    // Audit FED-7. Only a local user who shares a joined room
                    // with the subject has any reason to re-fetch their keys.
                    // Recording a row for every local user let one peer write
                    // (local users) rows per EDU. All rows for this EDU go to
                    // the store as one batch: one stream position, one commit.
                    // A repeat replaces the pair's earlier row, so the table is
                    // bounded by observers x subjects that share a room.
                    auto changes = std::vector<database::PersistentDeviceListChange>{};
                    for (auto& observer : local_users_sharing_a_joined_room_with(*rt, *user_id))
                    {
                        auto change = database::PersistentDeviceListChange{};
                        change.observer_user_id = std::move(observer);
                        change.subject_user_id = *user_id;
                        change.change_type = "changed";
                        changes.push_back(std::move(change));
                    }
                    if (!changes.empty())
                    {
                        std::ignore =
                            database::record_device_list_changes(rt->database.persistent_store, std::move(changes));
                    }
                }
                if (rt->sync_notifier != nullptr)
                {
                    rt->sync_notifier->publish(rt->database.next_stream_ordering - 1U,
                                               rt->database.persistent_store.next_sync_stream_id);
                }
                return {federation::EduDispositionStatus::accepted, {}};
            }
            default:
                return {federation::EduDispositionStatus::dropped_unknown_type, "unhandled EDU type"};
            }
        };

        runtime.federation.membership_template_provider = [rt](federation::FederationEndpoint endpoint,
                                                               std::string_view room_id, std::string_view user_id,
                                                               std::vector<std::string> const& supported_versions)
            -> std::optional<federation::MembershipEventTemplate> {
            auto const& store = rt->database.persistent_store;
            auto const room_it = std::ranges::find_if(store.rooms, [&room_id](database::PersistentRoom const& r) {
                return r.room_id == room_id;
            });
            if (room_it == store.rooms.end())
            {
                return std::nullopt;
            }
            auto const room_version = room_version_from_store(store, room_id);

            // If the joining server advertised which versions it supports, verify
            // the room's actual version is among them. Fall back to lower versions
            // only if the remote explicitly supports them; we never downgrade a room.
            if (!supported_versions.empty() &&
                std::ranges::find(supported_versions, room_version) == supported_versions.end())
            {
                // Signal M_INCOMPATIBLE_ROOM_VERSION so the remote can inform its user.
                auto err = canonicaljson::Object{};
                err.push_back(canonicaljson::make_member(
                    "errcode", canonicaljson::Value{std::string{"M_INCOMPATIBLE_ROOM_VERSION"}}));
                err.push_back(canonicaljson::make_member(
                    "error", canonicaljson::Value{std::string{
                                 "Your homeserver does not support the features required to join this room"}}));
                err.push_back(canonicaljson::make_member("room_version", canonicaljson::Value{room_version}));
                auto tmpl = federation::MembershipEventTemplate{};
                tmpl.room_version = room_version;
                tmpl.reason = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(err)}).output;
                return tmpl;
            }

            auto tmpl = federation::MembershipEventTemplate{};
            tmpl.room_id = std::string{room_id};
            tmpl.user_id = std::string{user_id};
            tmpl.room_version = room_version;
            tmpl.origin = rt->config.server().server_name;
            tmpl.origin_server_ts = static_cast<std::int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                                  std::chrono::system_clock::now().time_since_epoch())
                                                                  .count());
            if (endpoint == federation::FederationEndpoint::make_join)
            {
                tmpl.membership = "join";
            }
            else if (endpoint == federation::FederationEndpoint::make_leave)
            {
                tmpl.membership = "leave";
            }
            else
            {
                tmpl.membership = "knock";
            }
            // Populate auth_events: m.room.power_levels, the user's current
            // membership (e.g. their invite event), and m.room.join_rules for a
            // join or knock only — auth events selection names join_rules for
            // join, invite and knock, and auth rule 3.2 rejects a leave that
            // carries it. For room versions < 12, m.room.create is also included.
            // In room version 12 (MSC4291 / create_event_is_room_id) the create
            // event is the room ID itself and MUST NOT appear in any event's
            // auth_events — Synapse asserts this and crashes with 500 if it does.
            auto const* version_policy = rooms::find_room_version_policy(room_version);
            auto const include_create_in_auth = version_policy == nullptr || !version_policy->create_event_is_room_id;
            for (auto const& s : store.state)
            {
                if (s.room_id != room_id || s.event_id.empty())
                {
                    continue;
                }
                if ((include_create_in_auth && s.event_type == "m.room.create") ||
                    (s.event_type == "m.room.join_rules" && tmpl.membership != "leave") ||
                    s.event_type == "m.room.power_levels" ||
                    (s.event_type == "m.room.member" && s.state_key == user_id))
                {
                    tmpl.auth_events.push_back(s.event_id);
                }
            }
            // Compute the forward extremities: events not referenced as
            // prev_events by any other event in this room. These are the only
            // valid prev_events for a new join template; sending all room events
            // inflates the state snapshot and breaks state resolution at the
            // joining server.
            auto referenced = std::unordered_set<std::string>{};
            for (auto const& evt : store.events)
            {
                if (evt.room_id == room_id)
                {
                    for (auto const& prev_id : evt.prev_event_ids)
                    {
                        referenced.insert(prev_id);
                    }
                }
            }
            auto max_depth = std::int64_t{0};
            for (auto const& evt : store.events)
            {
                if (evt.room_id == room_id && !evt.event_id.empty() &&
                    referenced.find(evt.event_id) == referenced.end())
                {
                    tmpl.prev_events.push_back(evt.event_id);
                    if (static_cast<std::int64_t>(evt.depth) > max_depth)
                    {
                        max_depth = static_cast<std::int64_t>(evt.depth);
                    }
                }
            }
            tmpl.depth = max_depth + 1;
            auto content_obj = canonicaljson::Object{};
            content_obj.push_back(
                canonicaljson::make_member("membership", canonicaljson::Value{std::string{tmpl.membership}}));
            auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(content_obj)});
            tmpl.content_json = serialized.output;
            return tmpl;
        };

        runtime.federation.membership_acceptor =
            [rt](federation::FederationEndpoint endpoint, std::string_view room_id,
                 [[maybe_unused]] std::string_view event_id,
                 federation::InboundPduEnvelope const& envelope) -> federation::MembershipAcceptResult {
            // Locking: this callback mutates store.rooms/state/events and the
            // stream-ordering/sync-stream-id counters, so it needs rt->mutex held.
            // It is invoked from two call sites with different locking states:
            //   - the direct path (handle_federation_http_request) releases
            //     rt->mutex before dispatching into federation::inbound_request.cpp;
            //   - the worker-relay path (worker_pool.cpp's
            //     handle_membership_ingest_request) already holds rt->mutex when
            //     it calls this callback.
            // rt->mutex is a std::recursive_mutex, so acquiring it here is safe in
            // both cases (fresh lock or reentrant re-lock on the same thread).
            // Deliberately taking only the global mutex, not a room stripe mutex:
            // ingest_pdu_event documents a stripe-then-global lock order, and
            // taking a stripe while the worker-relay path already holds the
            // global mutex would acquire them in the reverse order — a classic
            // lock-order inversion that can deadlock against a concurrent
            // ingest_pdu_event call for the same room. There is no in-flight
            // network I/O under this lock (unlike outbound calls elsewhere in
            // this file), so holding the global mutex for the whole callback
            // does not risk blocking on a remote round trip.
            auto guard = std::unique_lock<RuntimeMutex>{rt->mutex};
            auto& store = rt->database.persistent_store;
            auto const room_it = std::ranges::find_if(store.rooms, [&room_id](database::PersistentRoom const& r) {
                return r.room_id == room_id;
            });
            if (room_it == store.rooms.end())
            {
                return {false, 404U, "room not found", {}, {}};
            }
            // M-01: evaluate the room's authorization rules before any part of
            // this event reaches the store. The Ed25519 signature and
            // content-hash checks in federation/inbound_request.cpp already ran
            // before this callback, but they establish only WHO signed the
            // event — never whether that sender is permitted to make this
            // membership transition. Without this gate a remote server holding
            // any valid signing key can join a user into an invite-only room,
            // or move a membership it has no power level to move, just by
            // presenting a correctly signed PDU.
            //
            // This mirrors the equivalent gate in ingest_pdu_event() below,
            // which guards the ordinary /send transaction path. The two paths
            // must stay in step: a rule enforced on only one of them is not
            // enforced at all, because send_join reaches the same store.
            //
            // Spec: docs/matrix-v1.19-spec/server-server-api.md#authorization-rules
            //
            // room_policy is hoisted out of this block (rather than scoped
            // to it, as originally written) because the ADR-0064 state-
            // before computation below also needs it.
            rooms::RoomVersionPolicy const* room_policy = nullptr;
            // ADR-0064 phase B2: the receipt outcome for this membership PDU,
            // decided in the spec's order exactly as ingest_pdu_event does.
            // A rejection is not an early return: spec "Rejection" requires a
            // rejected event still be stored (so later events referencing it
            // can be authorised), just never applied to state and never a
            // forward extremity. The send_join/leave/knock RESPONSE is still
            // an error for a rejected event — the peer asked us to accept it.
            enum class MembershipReceiptOutcome : std::uint8_t
            {
                accepted,
                rejected,
                soft_failed,
            };
            auto outcome = MembershipReceiptOutcome::accepted;
            auto outcome_reason = std::string{};
            auto stored_json = envelope.json;
            // The redacted-or-original PDU and the third-party-invite token,
            // carried out of the block below for the state-before and
            // current-state checks that follow it.
            auto membership_effective_pdu = canonicaljson::Value{};
            auto membership_third_party_token = std::string{};
            {
                auto const pdu_parsed = canonicaljson::parse_lossless(envelope.json);
                if (pdu_parsed.error != canonicaljson::ParseError::none)
                {
                    return {false, 400U, "invalid PDU JSON", {}, {}};
                }
                // Prefer the room version recorded in m.room.create over the one
                // the envelope claims: the sender does not get to choose which
                // rule set its own event is judged by.
                auto room_version = room_version_from_store(store, room_id);
                if (room_version.empty())
                {
                    room_version = envelope.room_version;
                }
                if (room_version.empty())
                {
                    room_version = "12";
                }
                room_policy = rooms::find_room_version_policy(room_version);
                if (room_policy == nullptr)
                {
                    return {false, 400U, "unknown room version", {}, {}};
                }
                // A join may be authorised by a third-party invite; the token in
                // content.third_party_invite.signed.token selects which
                // m.room.third_party_invite state event applies. Extracted the
                // same way ingest_pdu_event does.
                auto const third_party_invite_token = [&]() -> std::string {
                    auto const* const pdu_obj = std::get_if<canonicaljson::Object>(&pdu_parsed.value.storage());
                    auto const* const content =
                        pdu_obj == nullptr ? nullptr : object_member_as_object(*pdu_obj, "content");
                    auto const* const third_party_invite =
                        content == nullptr ? nullptr : object_member_as_object(*content, "third_party_invite");
                    auto const* const signed_obj = third_party_invite == nullptr
                                                       ? nullptr
                                                       : object_member_as_object(*third_party_invite, "signed");
                    auto const* const token = signed_obj == nullptr ? nullptr : string_member(*signed_obj, "token");
                    return token == nullptr ? std::string{} : *token;
                }();
                // Step 3 (hash): a content-hash mismatch REDACTS the event and
                // processing continues with the redacted form, which is what
                // gets stored. It is never a rejection. Mirrors
                // ingest_pdu_event; see spec "Checks performed on receipt of a
                // PDU". The signature check already ran in inbound_request.cpp.
                auto effective_pdu = pdu_parsed.value;
                if (!events::verify_pdu_content_hash(effective_pdu))
                {
                    auto redaction = events::redact_event(effective_pdu, *room_policy);
                    if (!redaction.error.empty())
                    {
                        return {false, 400U, "content hash mismatch and event could not be redacted", {}, {}};
                    }
                    effective_pdu = std::move(redaction.event);
                    auto const serialized = canonicaljson::serialize_canonical(effective_pdu);
                    if (serialized.error != canonicaljson::CanonicalJsonError::none)
                    {
                        return {false, 400U, "failed to serialize redacted event", {}, {}};
                    }
                    stored_json = serialized.output;
                }

                // Step 4: auth_events selection, then the auth rules against
                // the map those named events build.
                auto const selection_check = validate_auth_events_selection(
                    store, room_id, effective_pdu, *room_policy, envelope.event_type, envelope.sender,
                    envelope.state_key, third_party_invite_token, envelope.auth_event_ids);
                if (selection_check == AuthEventsSelectionCheck::unresolvable)
                {
                    return {
                        false, 400U, "an auth_event this PDU names has no recorded event; awaiting backfill", {}, {}};
                }
                if (selection_check == AuthEventsSelectionCheck::disallowed)
                {
                    outcome = MembershipReceiptOutcome::rejected;
                    outcome_reason = "auth_events selection is not permitted for this event";
                }
                if (outcome == MembershipReceiptOutcome::accepted)
                {
                    auto auth_events_map = build_auth_event_map_from_entries(
                        store, state_entries_from_named_events(store, envelope.auth_event_ids), envelope.sender,
                        envelope.state_key.value_or(std::string{}), envelope.event_type, third_party_invite_token);
                    // v12 (MSC4291): the create event is implicit in the room
                    // ID and MUST NOT be named in auth_events, so fill it from
                    // the room's recorded state — same as ingest_pdu_event.
                    if (room_policy->create_event_is_room_id &&
                        std::holds_alternative<std::nullptr_t>(auth_events_map.create.storage()))
                    {
                        auth_events_map.create = create_event_json_for_room(store, room_id);
                    }
                    auto const auth_events_decision =
                        events::authorize_event_against_auth_events(effective_pdu, *room_policy, auth_events_map);
                    if (!auth_events_decision.allowed)
                    {
                        outcome = MembershipReceiptOutcome::rejected;
                        outcome_reason =
                            "event auth denied against its own auth_events: " + auth_events_decision.reason;
                    }
                }
                membership_effective_pdu = std::move(effective_pdu);
                membership_third_party_token = third_party_invite_token;
            }
            // ADR-0064 phase B1: this is an inbound PDU (a remote server's
            // user joining/leaving/knocking on a room WE are resident in) —
            // the same trust boundary as ingest_pdu_event, so it gets the
            // same state-before treatment: fail closed rather than guess
            // when a prev_event has no recorded state group.
            auto const state_before = compute_state_before(store, room_id, *room_policy, envelope.prev_event_ids);
            if (!state_before.ok)
            {
                return {false, 400U, "no recorded state group for a prev_event; awaiting backfill", {}, {}};
            }

            // Step 5: auth against the state immediately before the event.
            if (outcome == MembershipReceiptOutcome::accepted)
            {
                auto state_before_map = build_auth_event_map_from_entries(
                    store, state_before.state, envelope.sender, envelope.state_key.value_or(std::string{}),
                    envelope.event_type, membership_third_party_token);
                fill_create_from_room_state(state_before_map, store, room_id);
                auto const state_before_decision = events::authorize_event_against_auth_events(
                    membership_effective_pdu, *room_policy, state_before_map);
                if (!state_before_decision.allowed)
                {
                    outcome = MembershipReceiptOutcome::rejected;
                    outcome_reason =
                        "event auth denied against state before the event: " + state_before_decision.reason;
                }
            }

            // Step 6: auth against the room's current (resolved) state. Spec
            // "Soft failure": a failure here does NOT reject the event. It is
            // stored and takes part in state resolution, but never updates
            // state, never becomes a forward extremity, and never flips the
            // membership cache — which is what stops a membership that
            // references pre-ban history from evading the ban.
            if (outcome == MembershipReceiptOutcome::accepted)
            {
                auto current_state_map = build_pdu_auth_event_map(store, room_id, envelope.sender,
                                                                  envelope.state_key.value_or(std::string{}),
                                                                  envelope.event_type, membership_third_party_token);
                fill_create_from_room_state(current_state_map, store, room_id);
                auto const current_state_decision = events::authorize_event_against_auth_events(
                    membership_effective_pdu, *room_policy, current_state_map);
                if (!current_state_decision.allowed)
                {
                    outcome = MembershipReceiptOutcome::soft_failed;
                    outcome_reason =
                        "event auth denied against current state (soft failure): " + current_state_decision.reason;
                }
            }

            auto event = database::PersistentEvent{};
            event.event_id = envelope.event_id;
            event.room_id = envelope.room_id;
            event.sender_user_id = envelope.sender;
            event.json = stored_json;
            event.depth = envelope.depth;
            event.stream_ordering = allocate_stream_ordering(rt->database);
            event.prev_event_ids = envelope.prev_event_ids;
            event.auth_event_ids = envelope.auth_event_ids;
            event.status = outcome == MembershipReceiptOutcome::rejected      ? "rejected"
                           : outcome == MembershipReceiptOutcome::soft_failed ? "soft_failed"
                                                                              : "accepted";
            auto const event_stream_ordering = event.stream_ordering;
            auto state = std::optional<database::PersistentStateEvent>{};
            if (envelope.state_key.has_value() && outcome == MembershipReceiptOutcome::accepted)
            {
                // Use envelope.event_id (the computed reference hash) rather
                // than the URL path event_id parameter. Both should be equal for
                // conformant peers, but deriving state from the envelope keeps
                // the stored state consistent with the stored event.
                state = database::PersistentStateEvent{envelope.room_id, envelope.event_type, *envelope.state_key,
                                                       envelope.event_id};
            }
            // Snapshot pre-join state IDs before persistence. The Matrix spec
            // requires the send_join response state to reflect the room *prior
            // to* the new join event. After store_event_with_state the store
            // already contains the join, so we must capture the snapshot first.
            auto pre_join_state_ids = std::vector<std::string>{};
            if (endpoint == federation::FederationEndpoint::send_join)
            {
                for (auto const& s : store.state)
                {
                    if (s.room_id == room_id && !s.event_id.empty())
                    {
                        pre_join_state_ids.push_back(s.event_id);
                    }
                }
            }
            auto const accepted_event_id = event.event_id;
            auto const accepted_prev_event_ids = event.prev_event_ids;
            if (!database::store_event_with_state(store, std::move(event), state))
            {
                return {false, 500U, "event persistence failed", {}, {}};
            }
            // ADR-0064 phase B1: record this event's after-state group and
            // forward-extremity update, then recompute current_state — same
            // sequence ingest_pdu_event runs, and the same non-fatal
            // treatment: the raw event is already durably stored, so a
            // bookkeeping failure here is logged, not turned into a
            // rejection (which would only cause pointless retries).
            {
                auto const event_type = state.has_value() ? state->event_type : std::string{};
                auto const state_key =
                    state.has_value() ? std::optional<std::string>{state->state_key} : std::optional<std::string>{};
                auto const state_after =
                    compute_state_after(state_before.state, accepted_event_id, event_type, state_key);
                auto const state_group = record_event_state(store, room_id, accepted_event_id, accepted_prev_event_ids,
                                                            state_after, outcome == MembershipReceiptOutcome::accepted);
                if (!state_group.has_value())
                {
                    LOG_WARNING("State-group bookkeeping failed after membership PDU was accepted; event_id=" +
                                accepted_event_id + " room_id=" + std::string{room_id});
                }
                else if (!recompute_current_state(store, room_id, *room_policy))
                {
                    LOG_WARNING("Current-state recomputation failed after membership PDU was accepted; event_id=" +
                                accepted_event_id + " room_id=" + std::string{room_id});
                }
            }
            auto membership_changed = false;
            // A rejected or soft-failed membership never flips the live
            // membership view: that is precisely what stops a join that
            // references pre-ban history from re-admitting a banned user.
            if (envelope.event_type == "m.room.member" && envelope.state_key.has_value() &&
                outcome == MembershipReceiptOutcome::accepted)
            {
                auto const membership = membership_for_endpoint(endpoint);
                if (!membership.empty())
                {
                    if (!upsert_membership(store, room_id, *envelope.state_key, membership, event_stream_ordering))
                    {
                        return {false, 500U, "membership persistence failed", {}, {}};
                    }
                    if ((membership == "join" || membership == "leave" || membership == "ban") &&
                        !database::delete_invite(store, room_id, *envelope.state_key))
                    {
                        return {false, 500U, "invite metadata cleanup failed", {}, {}};
                    }
                    apply_runtime_membership(rt->database, room_id, *envelope.state_key, membership);
                    if (membership == "join")
                    {
                        broadcast_local_device_lists_to_remote_joiner(*rt, room_id, *envelope.state_key);
                    }
                    membership_changed = true;
                }
            }
            auto sync_stream_id = rt->database.persistent_store.next_sync_stream_id;
            if (membership_changed)
            {
                sync_stream_id = database::allocate_sync_stream_id(rt->database.persistent_store);
            }
            if (rt->sync_notifier != nullptr)
            {
                rt->sync_notifier->publish(rt->database.next_stream_ordering - 1U, sync_stream_id);
            }
            // The event is now durably stored with its receipt status, so a
            // rejection can be reported to the peer without losing it: spec
            // "Rejection" keeps rejected events available for later events
            // that reference them, while the peer's request still fails.
            if (outcome == MembershipReceiptOutcome::rejected)
            {
                LOG_WARNING("Membership PDU rejected on receipt; event_id=" + accepted_event_id +
                            " room_id=" + std::string{room_id} + " reason=" + outcome_reason);
                return {false, 403U, std::string{"event auth denied: "} + outcome_reason, {}, {}};
            }

            auto auth_chain = std::vector<std::string>{};
            auto state_events = std::vector<std::string>{};
            if (endpoint == federation::FederationEndpoint::send_join)
            {
                // Build auth_chain by walking auth_events from PRE-JOIN state.
                // Per Matrix spec §11.5.1 the state in the response must be the
                // room state prior to the join event. We captured pre_join_state_ids
                // before persisting, so the join event itself is never seeded here,
                // preventing the circular auth_events reference Synapse warns about.
                // All auth_chain events must be state events (have state_key);
                // including non-state events crashes Synapse.
                auto visited = std::unordered_set<std::string>{};
                auto queue = std::vector<std::string>{};
                for (auto const& eid : pre_join_state_ids)
                {
                    if (visited.insert(eid).second)
                    {
                        queue.push_back(eid);
                    }
                }
                // Build a lookup from event_id to PersistentEvent for this room
                auto event_by_id = std::unordered_map<std::string, std::size_t>{};
                for (std::size_t i = 0U; i < store.events.size(); ++i)
                {
                    if (store.events[i].room_id == room_id && !store.events[i].event_id.empty())
                    {
                        event_by_id[store.events[i].event_id] = i;
                    }
                }
                // BFS: follow auth_event_ids from each discovered event
                auto cursor = std::size_t{0U};
                while (cursor < queue.size())
                {
                    auto const& eid = queue[cursor];
                    ++cursor;
                    auto const it = event_by_id.find(eid);
                    if (it == event_by_id.end())
                    {
                        continue;
                    }
                    for (auto const& auth_id : store.events[it->second].auth_event_ids)
                    {
                        if (!auth_id.empty() && visited.insert(auth_id).second)
                        {
                            queue.push_back(auth_id);
                        }
                    }
                }
                // Collect JSON for every event in the auth chain
                for (auto const& eid : queue)
                {
                    auto const it = event_by_id.find(eid);
                    if (it != event_by_id.end() && !store.events[it->second].json.empty())
                    {
                        auth_chain.push_back(store.events[it->second].json);
                    }
                }
                // State events: pre-join snapshot, resolved via the same
                // event_by_id map built above.
                for (auto const& eid : pre_join_state_ids)
                {
                    auto const it = event_by_id.find(eid);
                    if (it != event_by_id.end() && !store.events[it->second].json.empty())
                    {
                        state_events.push_back(store.events[it->second].json);
                    }
                }
            }
            // Pass the raw PDU JSON so the federation layer can echo it back
            // in the send_join v2 "event" field as required by the spec.
            return {true,
                    200U,
                    {},
                    std::move(auth_chain),
                    std::move(state_events),
                    room_version_from_store(store, room_id),
                    std::string{envelope.json}};
        };

        runtime.federation.invite_handler =
            [rt](federation::InviteRequest const& invite) -> federation::InviteAcceptResult {
            // Locking: same reasoning as runtime.federation.membership_acceptor
            // above — this callback mutates store.state/events/memberships and
            // the stream-ordering/sync-stream-id counters with no lock held by
            // its direct-path caller, while the worker-relay path
            // (handle_invite_ingest_request in worker_pool.cpp) already holds
            // rt->mutex. Take only the global recursive mutex, never a room
            // stripe mutex, so the lock order can never invert against
            // ingest_pdu_event's documented stripe-then-global ordering.
            auto guard = std::unique_lock<RuntimeMutex>{rt->mutex};
            auto const parsed = canonicaljson::parse_lossless(invite.invite_event_json);
            auto const* event = std::get_if<canonicaljson::Object>(&parsed.value.storage());
            if (parsed.error != canonicaljson::ParseError::none || event == nullptr)
            {
                return {false, 400U, "malformed invite event", {}};
            }
            auto const* target_user = string_member(*event, "state_key");
            auto const* sender = string_member(*event, "sender");
            auto const* event_room_id = string_member(*event, "room_id");
            auto const* event_type = string_member(*event, "type");
            auto const* membership = content_membership(*event);
            if (target_user == nullptr || target_user->empty() || sender == nullptr || sender->empty() ||
                event_room_id == nullptr || *event_room_id != invite.room_id || event_type == nullptr ||
                *event_type != "m.room.member" || membership == nullptr || *membership != "invite")
            {
                return {false, 400U, "invite event must be an m.room.member invite", {}};
            }
            if (server_name_from_user_id(*target_user) != rt->config.server().server_name ||
                !local_user_exists(rt->database, *target_user))
            {
                return {false, 404U, "invited local user not found", {}};
            }
            // Defense-in-depth (#462): the event sender's server name must match
            // the X-Matrix-authenticated origin. handle_invite already enforces
            // this via authorize_federation_pdu, but the handler asserts it too
            // so a direct caller of invite_handler cannot bypass the check.
            if (!invite.origin.empty() && server_name_from_user_id(*sender) != invite.origin)
            {
                return {false, 400U, "invite event sender is not on the origin server", {}};
            }
            // Audit FED-5: a room whose current state we hold (we have its
            // create event) is authorised against that state before we sign
            // anything. This is what refuses an invite for a banned target.
            auto const room_known_locally = !std::holds_alternative<std::nullptr_t>(
                create_event_json_for_room(rt->database.persistent_store, invite.room_id).storage());
            if (room_known_locally)
            {
                auto const auth = authorize_invite_against_local_room(*rt, invite.room_id, invite.room_version,
                                                                      parsed.value, *sender, *target_user);
                if (!auth.allowed)
                {
                    return {false, auth.status, auth.body, {}};
                }
            }
            // Never replace a ban with an invite, whatever the room state says:
            // only an explicit unban (a leave) lifts a ban. Belt and braces for
            // rooms we do not hold state for, where the check above cannot run.
            {
                auto const& mems = rt->database.persistent_store.memberships;
                auto const banned = std::ranges::any_of(mems, [&](database::PersistentMembership const& m) {
                    return m.room_id == invite.room_id && m.user_id == *target_user && m.membership == "ban";
                });
                if (banned)
                {
                    return {false, 403U, matrix_error("M_FORBIDDEN", "the invited user is banned from the room"), {}};
                }
            }
            auto signed_event = sign_invite_event(*rt, parsed.value, invite.room_version);
            if (!signed_event.has_value())
            {
                return {false, 500U, "invite signing failed", {}};
            }
            // If the target user is already persistently "join" in this room, the
            // remote server's view of room state has diverged from ours. We sign the
            // invite event (to remain cooperative) but MUST NOT overwrite the local
            // "join" membership with "invite": doing so corrupts sync — the room
            // disappears from rooms.join and the user enters an infinite invite loop.
            {
                auto const& mems = rt->database.persistent_store.memberships;
                auto const it = std::ranges::find_if(mems, [&](database::PersistentMembership const& m) {
                    return m.room_id == invite.room_id && m.user_id == *target_user && m.membership == "join";
                });
                if (it != mems.end())
                {
                    // User is already joined: return the signed event without altering state.
                    return {true, 200U, {}, std::move(*signed_event)};
                }
            }
            auto const stream_ordering = allocate_stream_ordering(rt->database);
            if (!upsert_membership(rt->database.persistent_store, invite.room_id, *target_user, "invite",
                                   stream_ordering))
            {
                return {false, 500U, "invite membership persistence failed", {}};
            }
            if (!database::upsert_invite(rt->database.persistent_store,
                                         {invite.room_id, *target_user, *sender, invite.event_id, *signed_event,
                                          invite.invite_room_state_json, stream_ordering}))
            {
                return {false, 500U, "invite metadata persistence failed", {}};
            }
            // For a room whose state we hold, stop here (audit FED-5). Spec: "if
            // the remote homeserver is already in the room, it will receive the
            // invite event twice; once through this endpoint, and again through
            // a federation transaction". The transaction path does the full
            // PDU checks and is what updates room state, and storing the event
            // here would make that later copy fail to persist (the store refuses
            // an event ID it already holds; ADR-0085). The membership row and invite metadata above
            // are all the invitee needs in order to see the invite.
            if (!room_known_locally)
            {
                // Store the invite event in the persistent event graph so it is
                // reachable during auth-chain BFS walks on subsequent send_join
                // calls for this user. Without this, make_join cannot include it
                // in auth_events and send_join cannot return it in the auth_chain.
                auto invite_pdu = database::PersistentEvent{};
                invite_pdu.event_id = invite.event_id;
                invite_pdu.room_id = invite.room_id;
                invite_pdu.sender_user_id = *sender;
                invite_pdu.json = *signed_event;
                invite_pdu.stream_ordering = stream_ordering;
                // ADR-0064 phase B1: this event carries no prev_events (it is
                // stored purely so a future send_join's auth-chain walk can
                // find it, per the comment above) and is never part of this
                // server's own timeline for the room — outlier, like
                // ingest_send_join_state's state/auth-chain events.
                invite_pdu.status = "outlier";
                auto invite_state = std::optional<database::PersistentStateEvent>{
                    database::PersistentStateEvent{invite.room_id, "m.room.member", *target_user, invite.event_id}
                };
                if (!database::store_event_with_state(rt->database.persistent_store, std::move(invite_pdu),
                                                      std::move(invite_state)))
                {
                    return {false, 500U, "invite event persistence failed", {}};
                }
            }
            auto const sync_stream_id = database::allocate_sync_stream_id(rt->database.persistent_store);
            if (rt->sync_notifier != nullptr)
            {
                rt->sync_notifier->publish(rt->database.next_stream_ordering - 1U, sync_stream_id);
            }
            return {true, 200U, {}, std::move(*signed_event)};
        };

        runtime.federation.directory_query_provider =
            [rt](std::string_view room_alias) -> federation::FederationDirectory {
            auto const found = database::find_room_alias(rt->database.persistent_store, room_alias);
            if (!found.has_value())
            {
                return {};
            }
            auto servers = std::vector<std::string>{};
            auto const add = [&servers](std::string_view server) {
                if (!server.empty() && std::ranges::find(servers, server) == servers.end())
                {
                    servers.emplace_back(server);
                }
            };
            add(rt->config.server().server_name);
            for (auto const& membership : rt->database.persistent_store.memberships)
            {
                if (membership.room_id == found->room_id && membership.membership == "join")
                {
                    add(server_name_from_user_id(membership.user_id));
                }
            }
            return {true, found->room_id, std::move(servers)};
        };

        runtime.federation.backfill_provider =
            [rt](federation::BackfillRequest const& req) -> federation::BackfillResult {
            // FED-2: refuses (403) a server with no joined user in the room unless
            // the room is world readable.
            return federation::build_backfill_response(rt->database.persistent_store, req);
        };

        runtime.federation.profile_query_provider = [rt](std::string_view user_id) -> federation::FederationProfile {
            auto const profile = database::find_profile(rt->database.persistent_store, user_id);
            if (profile.has_value())
            {
                return {true, profile->displayname, profile->avatar_url};
            }
            auto const user_exists = std::ranges::any_of(rt->database.persistent_store.users,
                                                         [user_id](database::PersistentUser const& user) {
                                                             return user.user_id == user_id;
                                                         });
            return user_exists ? federation::FederationProfile{true, {}, {}} : federation::FederationProfile{};
        };

        runtime.federation.device_keys_query_provider = [rt](std::string_view body) -> std::string {
            return federation::build_device_keys_query_response(rt->database.persistent_store, body);
        };

        runtime.federation.one_time_keys_claim_provider = [rt](std::string_view body) -> std::string {
            return federation::build_one_time_keys_claim_response(rt->database.persistent_store, body);
        };

        runtime.federation.user_devices_provider = [rt](std::string_view user_id) -> std::string {
            return federation::build_user_devices_response(rt->database.persistent_store, user_id);
        };

        // FED-2: every room-scoped read below takes the X-Matrix-authenticated
        // origin and answers 403 unless that server has a joined user in the room
        // (or the room is world readable). They run against whichever process's
        // store serves the request: the federation worker's room snapshot for
        // state/state_ids/backfill/get_missing_events, main's for /event.
        runtime.federation.event_query_provider = [rt](std::string_view event_id,
                                                       std::string_view origin) -> federation::RoomReadResult {
            return federation::build_event_response(rt->database.persistent_store, event_id,
                                                    rt->config.server().server_name, origin);
        };

        runtime.federation.state_query_provider = [rt](std::string_view room_id, std::string_view event_id,
                                                       std::string_view origin) -> federation::RoomReadResult {
            return federation::build_state_response(rt->database.persistent_store, room_id, event_id, origin);
        };

        runtime.federation.state_ids_query_provider = [rt](std::string_view room_id, std::string_view event_id,
                                                           std::string_view origin) -> federation::RoomReadResult {
            return federation::build_state_ids_response(rt->database.persistent_store, room_id, event_id, origin);
        };

        runtime.federation.missing_events_query_provider = [rt](std::string_view room_id, std::string_view body,
                                                                std::string_view origin) -> federation::RoomReadResult {
            return federation::build_get_missing_events_response(rt->database.persistent_store, room_id, body, origin);
        };

        runtime.federation.space_hierarchy_provider = [rt](std::string_view room_id,
                                                           bool suggested_only) -> std::string {
            return build_federation_space_hierarchy_response(*rt, room_id, suggested_only);
        };

        // Federation media download needs the local media repository, which is
        // only available in the main process. The federation worker does not
        // carry media blobs, so this route is bypassed to main in
        // federation_request_routing.cpp.
        runtime.federation.media_download_provider =
            [rt](std::string_view media_id) -> media::LocalMediaDownloadResult {
            return media::download_local_media(rt->media_repository, rt->config.server().server_name, media_id);
        };

        // Resolve the room version from the stored m.room.create state event so
        // that authorize_federation_pdu uses the correct redaction rules when
        // verifying inbound PDU signatures.  Rooms created before v11 include
        // "origin" in the signing payload; using the wrong (later) version strips
        // it and produces a false signature failure for every inbound event.
        runtime.federation.room_version_resolver = [rt](std::string_view room_id) -> std::string {
            return room_version_from_store(rt->database.persistent_store, room_id);
        };

        // Provide room server ACL enforcement for inbound federation.  The lambda
        // inspects the current m.room.server_acl state for the room and applies
        // MSC4436 rules (deny list, allow list, allow_ip_literals) to the remote
        // server name. Ports are stripped and matching is case-insensitive.
        runtime.federation.room_server_acl_provider = [rt](std::string_view room_id,
                                                           std::string_view server_name) -> bool {
            return federation::room_server_acl_allows(rt->database.persistent_store, room_id, server_name);
        };

        if (outbound && discovery)
        {
            // Prefer the TTL-bounded discovery cache so repeated key resolutions
            // for the same server skip the DNS cascade; fall back to the raw
            // network in test harnesses that wire only discovery_network.
            auto const key_clock = []() -> std::uint64_t {
                return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                      std::chrono::system_clock::now().time_since_epoch())
                                                      .count());
            };
            // Lets the inbound budget tell a cache-served resolution from one
            // that will actually go to the network. Reads the same persistent
            // store and freshness rule the resolver itself consults first, so the
            // two cannot disagree about whether an outbound call is needed.
            runtime.federation.remote_key_cache_probe = [&runtime, key_clock](std::string_view server_name,
                                                                              std::string_view key_id) -> bool {
                auto const cached_key =
                    federation::find_cached_remote_key(runtime.database.persistent_store, server_name, key_id);
                return cached_key.has_value() &&
                       !federation::remote_key_needs_refresh(cached_key->valid_until_ts, key_clock());
            };
            if (cached != nullptr)
            {
                runtime.federation.remote_key_resolver = federation::make_persistent_remote_key_resolver(
                    runtime.database.persistent_store, *outbound, *cached, timeout, key_clock,
                    runtime.config.server().server_name);
            }
            else
            {
                runtime.federation.remote_key_resolver = federation::make_persistent_remote_key_resolver(
                    runtime.database.persistent_store, *outbound, *discovery, timeout, key_clock,
                    runtime.config.server().server_name);
            }
            auto key = ensure_runtime_server_signing_key(runtime);
            auto constexpr expected_secret_bytes = crypto::ed25519_secret_key_bytes;
            if (!key.has_value() || runtime.database.signing_secret_key.bytes().size() != expected_secret_bytes)
            {
                log_diagnostic("dispatch.start.rejected", {
                                                              {"reason", "server signing key unavailable", false}
                });
                return;
            }
            auto dispatch_config = federation::DispatchWorkerConfig{};
            dispatch_config.origin = runtime.config.server().server_name;
            dispatch_config.key_id = key->key_id;
            // Move the signing key into the worker's own mlocked, zeroised
            // SecretBuffer rather than an unpinned std::string. The runtime
            // retains its own SecretBuffer; both are wiped independently.
            dispatch_config.secret_key = core::SecretBuffer{runtime.database.signing_secret_key.bytes()};
            auto* discovery_ptr = discovery;
            auto* cached_ptr = cached;
            auto const discovery_timeout = timeout > 0U ? timeout : 30U;
            auto resolver = [discovery_ptr, cached_ptr, discovery_timeout](
                                std::string_view server_name) -> std::optional<federation::ServerDiscoveryResult> {
                // Prefer the TTL cache; fall back to the raw network for tests.
                auto result = cached_ptr != nullptr
                                  ? cached_ptr->discover(server_name, discovery_timeout)
                                  : federation::discover_server(server_name, *discovery_ptr, discovery_timeout);
                if (!result.discovery_allowed)
                {
                    return std::nullopt;
                }
                return result;
            };
            auto clock = []() -> std::uint64_t {
                return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                      std::chrono::system_clock::now().time_since_epoch())
                                                      .count());
            };
            auto sleep_fn = [](std::chrono::milliseconds ms) {
                std::this_thread::sleep_for(ms);
            };
            if (!runtime.dispatch_worker)
            {
                runtime.dispatch_worker = std::make_unique<federation::DispatchWorker>(
                    std::move(dispatch_config), *outbound, std::move(resolver), std::move(clock), std::move(sleep_fn),
                    &runtime.database.persistent_store);
                std::ignore = runtime.dispatch_worker->replay_pending();
                try
                {
                    runtime.dispatch_worker->start();
                }
                catch (std::system_error const& e)
                {
                    // Thread creation failed (e.g. TasksMax exhausted, RLIMIT_NPROC).
                    // Destroy the worker so the next call re-attempts construction
                    // rather than using a worker stuck in a not-started state.
                    log_diagnostic("dispatch.start.failed",
                                   {
                                       {"reason", e.what(),                         false},
                                       {"code",   std::to_string(e.code().value()), false}
                    });
                    runtime.dispatch_worker.reset();
                    // Do not propagate — let the caller's operation fail cleanly
                    // with a federation-unavailable error rather than an uncaught
                    // exception that kills the thread pool worker.
                    return;
                }
            }
            // No refresh branch here: this function returns early once the federation
            // callbacks exist, so a second call after a rotation never reaches this
            // point. rotate_server_signing_key hands the worker its new identity
            // directly instead.
        }
    }

} // namespace

namespace
{

    // ADR-0064 phase C: per-PDU backfill limits. These bound the work a single
    // inbound PDU can trigger when its prev_events / auth_events are missing,
    // preventing a malicious or delayed origin from driving unbounded outbound
    // fetches.
    constexpr auto k_max_get_missing_events_per_pdu = std::size_t{20U};
    constexpr auto k_max_backfill_outbound_calls = std::size_t{5U};

    // ADR-0064 phase C: /state_ids fallback caps. These bound the size of a
    // remote-claimed snapshot and the work we will do to materialise it.
    constexpr auto k_max_state_ids_per_pdu = std::size_t{1000U};
    constexpr auto k_max_auth_chain_ids_per_pdu = std::size_t{1000U};
    // ADR-0069 option A: real rooms routinely have more than 100 state events,
    // so the snapshot materialisation cap must be sized for real rooms while
    // still bounding a malicious response. The per-event fetches are counted
    // against a separate snapshot budget below, not the general PDU backfill
    // budget, so a large but legitimate snapshot does not starve other gaps.
    constexpr auto k_max_state_snapshot_events_per_pdu = std::size_t{1000U};
    constexpr auto k_max_backfill_recursion_depth = std::size_t{2U};

    // ADR-0069 option A: separate budget for outbound calls made while
    // materialising a /state_ids snapshot. This covers /event/{id} fetches for
    // the named snapshot and auth-chain events plus /event_auth calls for
    // historical state events, and is independent of the general PDU backfill
    // budget so that one large room does not exhaust the cap for the whole
    // inbound transaction.
    constexpr auto k_max_snapshot_outbound_calls = std::size_t{100U};

    // Returns true when the store has an event with this event_id and it has a
    // recorded after-state group (so it can serve as a prev_event for state-
    // before computation). Outliers and pre-ADR-0064 events may exist but have
    // no state group.
    [[nodiscard]] auto event_has_state_group(database::PersistentStore const& store, std::string_view event_id) -> bool
    {
        return database::find_event_state_group(store, event_id).has_value();
    }

    // Returns true when every prev_event of the parsed event has a recorded
    // state group. Used by the /state_ids fallback to decide whether a
    // verification failure is due to a missing state-before (ADR-0069 option A)
    // or some other reason.
    [[nodiscard]] auto prev_events_have_state_groups(database::PersistentStore const& store,
                                                     rooms::RoomVersionPolicy const& policy,
                                                     std::string_view event_json) -> bool
    {
        auto const envelope_opt = federation::parse_inbound_pdu_envelope(std::string{event_json}, policy.id);
        if (!envelope_opt.has_value())
        {
            return false;
        }
        for (auto const& id : envelope_opt->prev_event_ids)
        {
            if (!event_has_state_group(store, id))
            {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] auto array_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Array const*
    {
        auto const* value = object_member(object, key);
        return value == nullptr ? nullptr : std::get_if<canonicaljson::Array>(&value->storage());
    }

    // Returns the IDs of auth_events the store cannot resolve at all, and the
    // IDs of prev_events that are either absent or have no recorded state group.
    [[nodiscard]] auto collect_missing_pdu_references(database::PersistentStore const& store,
                                                      federation::InboundPduEnvelope const& envelope)
        -> std::pair<std::vector<std::string>, std::vector<std::string>>
    {
        auto missing_auth = std::vector<std::string>{};
        for (auto const& id : envelope.auth_event_ids)
        {
            auto const it = std::ranges::find_if(store.events, [&](database::PersistentEvent const& evt) {
                return evt.event_id == id;
            });
            if (it == store.events.end())
            {
                missing_auth.push_back(id);
            }
        }

        auto missing_prev = std::vector<std::string>{};
        for (auto const& id : envelope.prev_event_ids)
        {
            auto const it = std::ranges::find_if(store.events, [&](database::PersistentEvent const& evt) {
                return evt.event_id == id;
            });
            if (it == store.events.end() || !event_has_state_group(store, id))
            {
                missing_prev.push_back(id);
            }
        }
        return {std::move(missing_auth), std::move(missing_prev)};
    }

    [[nodiscard]] auto signing_material_for_backfill(HomeserverRuntime& runtime)
        -> std::pair<std::string, std::span<std::uint8_t const>>
    {
        auto const signing_key = find_active_server_signing_key(runtime);
        if (!signing_key.has_value())
        {
            return {};
        }
        return {signing_key->key_id, runtime.database.signing_secret_key.bytes()};
    }

    // Fetch a list of event JSON bodies from the origin via
    // POST /_matrix/federation/v1/get_missing_events/{roomId}. Returns the parsed
    // "events" array on success. Must be called with runtime.mutex released.
    [[nodiscard]] auto fetch_get_missing_events(HomeserverRuntime& runtime, std::string_view room_id,
                                                std::string_view origin, std::vector<std::string> const& latest_events,
                                                std::vector<std::string> const& earliest_events, std::size_t limit)
        -> std::optional<std::vector<std::string>>
    {
        auto const [key_id, secret_key] = signing_material_for_backfill(runtime);
        if (secret_key.empty())
        {
            LOG_WARNING("Backfill signing key unavailable; cannot fetch missing events");
            return std::nullopt;
        }

        auto request_body = canonicaljson::Object{};
        auto latest = canonicaljson::Array{};
        for (auto const& id : latest_events)
        {
            latest.push_back(canonicaljson::Value{id});
        }
        auto earliest = canonicaljson::Array{};
        for (auto const& id : earliest_events)
        {
            earliest.push_back(canonicaljson::Value{id});
        }
        request_body.push_back(canonicaljson::make_member("latest_events", canonicaljson::Value{std::move(latest)}));
        request_body.push_back(
            canonicaljson::make_member("earliest_events", canonicaljson::Value{std::move(earliest)}));
        request_body.push_back(
            canonicaljson::make_member("limit", canonicaljson::Value{static_cast<std::int64_t>(limit)}));
        request_body.push_back(canonicaljson::make_member("min_depth", canonicaljson::Value{std::int64_t{0}}));
        auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(request_body)});
        if (serialized.error != canonicaljson::CanonicalJsonError::none)
        {
            return std::nullopt;
        }

        auto tx = federation::make_outbound_transaction(
            std::string{origin}, "POST", "/_matrix/federation/v1/get_missing_events/" + std::string{room_id},
            runtime.config.server().server_name, serialized.output);
        auto const [ok, body] = perform_sync_outbound_call(
            runtime, room_id, tx, key_id, secret_key, "federation.backfill.get_missing_events_failed",
            runtime.federation.config.remote_timeout_seconds, 16U * 1024U * 1024U);
        if (!ok)
        {
            return std::nullopt;
        }

        auto const parsed = canonicaljson::parse_json(body);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (root == nullptr)
        {
            return std::nullopt;
        }
        auto const* events = array_member(*root, "events");
        if (events == nullptr)
        {
            return std::nullopt;
        }

        auto result = std::vector<std::string>{};
        result.reserve(events->size());
        for (auto const& entry : *events)
        {
            auto const serialized_entry = canonicaljson::serialize_canonical(entry);
            if (serialized_entry.error == canonicaljson::CanonicalJsonError::none)
            {
                result.push_back(serialized_entry.output);
            }
        }
        return result;
    }

    // Spec: GET /_matrix/federation/v1/event/{eventId} returns a Transaction
    // object whose "pdus" array contains the requested PDU. Extract and return
    // the first PDU as canonical JSON; fall back to returning the raw body when
    // it already looks like a single PDU.
    [[nodiscard]] auto extract_pdu_from_event_response(std::string_view body) -> std::optional<std::string>
    {
        if (body.empty() || body.front() != '{')
        {
            return std::nullopt;
        }
        auto const parsed = canonicaljson::parse_json(body);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (root == nullptr)
        {
            return std::nullopt;
        }
        auto const* pdus = array_member(*root, "pdus");
        if (pdus != nullptr && !pdus->empty())
        {
            auto const serialized = canonicaljson::serialize_canonical(pdus->front());
            if (serialized.error == canonicaljson::CanonicalJsonError::none)
            {
                return serialized.output;
            }
            return std::nullopt;
        }
        // No Transaction wrapper: return the body verbatim if it is a JSON object.
        if (std::holds_alternative<canonicaljson::Object>(parsed.value.storage()))
        {
            return std::string{body};
        }
        return std::nullopt;
    }

    // The PDU a GET /_matrix/federation/v1/event/{eventId} response carries,
    // provided it is the event that was asked for: its ID, computed under the
    // room's version, must equal `requested_event_id`. Anything else is the
    // origin answering a question nobody asked and is dropped rather than
    // stored.
    [[nodiscard]] auto requested_pdu_from_event_response(std::string_view body, std::string_view requested_event_id,
                                                         rooms::RoomVersionPolicy const& policy)
        -> std::optional<std::string>
    {
        auto json = extract_pdu_from_event_response(body);
        if (!json.has_value())
        {
            return std::nullopt;
        }
        auto const parsed = canonicaljson::parse_lossless(*json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto const id = events::make_reference_hash_event_id(parsed.value, policy);
        if (!id.error.empty() || id.event_id != requested_event_id)
        {
            LOG_WARNING("Backfill dropped an /event response that is not the requested event: requested=" +
                        std::string{requested_event_id} + " returned=" + id.event_id);
            return std::nullopt;
        }
        return json;
    }

    // Spec: GET /_matrix/federation/v1/event_auth/{roomId}/{eventId} returns an
    // object with an "auth_chain" array of PDUs. Extract each PDU as canonical
    // JSON and return them in order; reject malformed responses.
    [[nodiscard]] auto extract_pdus_from_auth_chain_response(std::string_view body)
        -> std::optional<std::vector<std::string>>
    {
        if (body.empty() || body.front() != '{')
        {
            return std::nullopt;
        }
        auto const parsed = canonicaljson::parse_json(body);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (root == nullptr)
        {
            return std::nullopt;
        }
        auto const* auth_chain = array_member(*root, "auth_chain");
        if (auth_chain == nullptr)
        {
            return std::nullopt;
        }
        auto result = std::vector<std::string>{};
        result.reserve(auth_chain->size());
        for (auto const& pdu : *auth_chain)
        {
            auto const serialized = canonicaljson::serialize_canonical(pdu);
            if (serialized.error != canonicaljson::CanonicalJsonError::none)
            {
                return std::nullopt;
            }
            result.push_back(std::move(serialized.output));
        }
        return result;
    }

    [[nodiscard]] auto fetch_event_by_id(HomeserverRuntime& runtime, std::string_view room_id, std::string_view origin,
                                         std::string_view event_id, rooms::RoomVersionPolicy const& policy,
                                         std::size_t& outbound_calls) -> std::optional<std::string>
    {
        if (outbound_calls >= k_max_backfill_outbound_calls)
        {
            return std::nullopt;
        }
        auto const [key_id, secret_key] = signing_material_for_backfill(runtime);
        if (secret_key.empty())
        {
            return std::nullopt;
        }
        auto tx = federation::make_outbound_transaction(
            std::string{origin}, "GET", "/_matrix/federation/v1/event/" + core::percent_encode_path_component(event_id),
            runtime.config.server().server_name, "");
        auto const [ok, body] = perform_sync_outbound_call(
            runtime, room_id, tx, key_id, secret_key, "federation.backfill.event_fetch_failed",
            runtime.federation.config.remote_timeout_seconds, 16U * 1024U * 1024U);
        if (!ok)
        {
            return std::nullopt;
        }
        ++outbound_calls;
        return requested_pdu_from_event_response(body, event_id, policy);
    }

    // Snapshot-phase variant of fetch_event_by_id. Uses the separate snapshot
    // budget (ADR-0069 option A) instead of the general PDU backfill budget.
    [[nodiscard]] auto fetch_snapshot_event_by_id(HomeserverRuntime& runtime, std::string_view room_id,
                                                  std::string_view origin, std::string_view event_id,
                                                  rooms::RoomVersionPolicy const& policy, std::size_t& snapshot_calls)
        -> std::optional<std::string>
    {
        if (snapshot_calls >= k_max_snapshot_outbound_calls)
        {
            return std::nullopt;
        }
        auto const [key_id, secret_key] = signing_material_for_backfill(runtime);
        if (secret_key.empty())
        {
            return std::nullopt;
        }
        auto tx = federation::make_outbound_transaction(
            std::string{origin}, "GET", "/_matrix/federation/v1/event/" + core::percent_encode_path_component(event_id),
            runtime.config.server().server_name, "");
        auto const [ok, body] = perform_sync_outbound_call(
            runtime, room_id, tx, key_id, secret_key, "federation.backfill.snapshot_event_fetch_failed",
            runtime.federation.config.remote_timeout_seconds, 16U * 1024U * 1024U);
        if (!ok)
        {
            return std::nullopt;
        }
        ++snapshot_calls;
        return requested_pdu_from_event_response(body, event_id, policy);
    }

    // Parses a JSON object response and returns the string array under `key`,
    // or nullopt when the key is missing or not an array of strings. Used for
    // /state_ids and /event_auth responses.
    [[nodiscard]] auto string_array_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::optional<std::vector<std::string>>
    {
        auto const* value = object_member(object, key);
        if (value == nullptr)
        {
            return std::nullopt;
        }
        auto const* array = std::get_if<canonicaljson::Array>(&value->storage());
        if (array == nullptr)
        {
            return std::nullopt;
        }
        auto result = std::vector<std::string>{};
        result.reserve(array->size());
        for (auto const& entry : *array)
        {
            auto const* str = std::get_if<std::string>(&entry.storage());
            if (str == nullptr)
            {
                return std::nullopt;
            }
            result.push_back(*str);
        }
        return result;
    }

    // Spec: GET /_matrix/federation/v1/state_ids/{roomId}?event_id=...
    // Returns the "pdu_ids" and "auth_chain_ids" arrays on success.
    [[nodiscard]] auto fetch_state_ids(HomeserverRuntime& runtime, std::string_view room_id, std::string_view origin,
                                       std::string_view event_id, std::size_t& outbound_calls)
        -> std::optional<std::pair<std::vector<std::string>, std::vector<std::string>>>
    {
        if (outbound_calls >= k_max_backfill_outbound_calls)
        {
            return std::nullopt;
        }
        auto const [key_id, secret_key] = signing_material_for_backfill(runtime);
        if (secret_key.empty())
        {
            return std::nullopt;
        }
        auto const path = std::string{"/_matrix/federation/v1/state_ids/"} +
                          core::percent_encode_path_component(room_id) +
                          "?event_id=" + core::percent_encode_path_component(event_id);
        auto tx = federation::make_outbound_transaction(std::string{origin}, "GET", path,
                                                        runtime.config.server().server_name, "");
        auto const [ok, body] =
            perform_sync_outbound_call(runtime, room_id, tx, key_id, secret_key, "federation.backfill.state_ids_failed",
                                       runtime.federation.config.remote_timeout_seconds, 16U * 1024U * 1024U);
        if (!ok)
        {
            return std::nullopt;
        }
        ++outbound_calls;

        auto const parsed = canonicaljson::parse_json(body);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (root == nullptr)
        {
            return std::nullopt;
        }
        auto const pdu_ids = string_array_member(*root, "pdu_ids");
        auto const auth_chain_ids = string_array_member(*root, "auth_chain_ids");
        if (!pdu_ids.has_value() || !auth_chain_ids.has_value())
        {
            return std::nullopt;
        }
        return std::make_pair(std::move(*pdu_ids), std::move(*auth_chain_ids));
    }

    // Spec: GET /_matrix/federation/v1/event_auth/{roomId}/{eventId} returns the
    // full auth chain for an event as an array of PDUs. This is used by the
    // /state_ids fallback to verify historical state events whose prev_events
    // have no recorded state groups (ADR-0069 option A).
    [[nodiscard]] auto fetch_event_auth(HomeserverRuntime& runtime, std::string_view room_id, std::string_view origin,
                                        std::string_view event_id, std::size_t& snapshot_calls)
        -> std::optional<std::vector<std::string>>
    {
        if (snapshot_calls >= k_max_snapshot_outbound_calls)
        {
            return std::nullopt;
        }
        auto const [key_id, secret_key] = signing_material_for_backfill(runtime);
        if (secret_key.empty())
        {
            return std::nullopt;
        }
        auto const path = std::string{"/_matrix/federation/v1/event_auth/"} +
                          core::percent_encode_path_component(room_id) + "/" +
                          core::percent_encode_path_component(event_id);
        auto tx = federation::make_outbound_transaction(std::string{origin}, "GET", path,
                                                        runtime.config.server().server_name, "");
        auto const [ok, body] = perform_sync_outbound_call(
            runtime, room_id, tx, key_id, secret_key, "federation.backfill.event_auth_failed",
            runtime.federation.config.remote_timeout_seconds, 16U * 1024U * 1024U);
        if (!ok)
        {
            return std::nullopt;
        }
        ++snapshot_calls;
        return extract_pdus_from_auth_chain_response(body);
    }

    [[nodiscard]] auto sender_domain_from_user_id(std::string_view user_id) noexcept -> std::string_view
    {
        auto const at = user_id.find('@');
        auto const start = at == std::string_view::npos ? std::size_t{0U} : at + 1U;
        auto const colon = user_id.find(':', start);
        if (colon == std::string_view::npos)
        {
            return {};
        }
        return user_id.substr(colon + 1U);
    }

    // Verifies and stores a single backfilled event as an outlier. The event's
    // prev_events MUST already have recorded state groups unless a verified
    // snapshot is supplied in `forced_state_before`; otherwise it is dropped.
    // Returns true when the event was stored (or was already present), false when
    // it failed verification.
    [[nodiscard]] auto verify_and_store_backfilled_event(
        HomeserverRuntime& runtime, std::string_view room_id, std::string_view origin, std::string_view event_json,
        rooms::RoomVersionPolicy const& policy,
        std::optional<std::vector<database::PersistentStateGroupStateEntry>> const& forced_state_before = std::nullopt,
        bool allow_auth_events_only = false) -> bool
    {
        std::ignore = origin;
        if (event_json.empty() || event_json.front() != '{')
        {
            return false;
        }
        auto const version_resolver = [&policy](std::string_view) {
            return std::string{policy.id};
        };
        auto const pdu = federation::parse_federation_pdu(event_json, version_resolver);
        if (pdu.event_id.empty() || pdu.room_id != room_id)
        {
            return false;
        }

        auto const parsed = canonicaljson::parse_lossless(event_json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return false;
        }

        // ADR-0069 option A: an event this server already stores need not be
        // verified again. This lets locally-created genesis events returned in
        // an /event_auth auth chain through, though they carry this server's
        // signature rather than a remote one; such rows are found by the JSON's
        // "event_id" field (fixtures and older rows use textual IDs). The field
        // is the origin's to write and proves nothing on its own, so the stored
        // event must also be the very same event: its reference hash, which
        // binds the full content through the content hash, must equal this
        // one's (0.12.13). Events without the field (every v3+ PDU) are not
        // short-circuited here: a stored outlier must still reach the promotion
        // below when a snapshot supplies its state (ADR-0070).
        auto const supplied_hash = events::make_reference_hash(parsed.value, policy);
        if (supplied_hash.error.empty())
        {
            auto const* raw_obj = std::get_if<canonicaljson::Object>(&parsed.value.storage());
            auto const* raw_event_id = raw_obj == nullptr ? nullptr : string_member(*raw_obj, "event_id");
            auto const stripe = std::hash<std::string>{}(std::string{room_id}) % room_mutex_stripe_count;
            auto stripe_guard = std::unique_lock{runtime.room_stripe_mutexes[stripe]};
            auto global_guard = std::unique_lock<RuntimeMutex>{runtime.mutex};
            auto const same_stored_event = [&](database::PersistentEvent const& evt) {
                if (raw_event_id == nullptr || evt.event_id != *raw_event_id)
                {
                    return false;
                }
                auto const stored = canonicaljson::parse_lossless(evt.json);
                if (stored.error != canonicaljson::ParseError::none)
                {
                    return false;
                }
                auto const stored_hash = events::make_reference_hash(stored.value, policy);
                return stored_hash.error.empty() && stored_hash.sha256 == supplied_hash.sha256;
            };
            if (std::ranges::any_of(runtime.database.persistent_store.events, same_stored_event))
            {
                return true;
            }
        }

        auto effective_pdu = parsed.value;
        auto stored_json = std::string{event_json};
        if (!events::verify_pdu_content_hash(effective_pdu))
        {
            auto const redaction = events::redact_event(effective_pdu, policy);
            if (!redaction.error.empty())
            {
                return false;
            }
            effective_pdu = std::move(redaction.event);
            auto const serialized = canonicaljson::serialize_canonical(effective_pdu);
            if (serialized.error != canonicaljson::CanonicalJsonError::none)
            {
                return false;
            }
            stored_json = serialized.output;
        }

        auto const sender_domain = sender_domain_from_user_id(pdu.sender);
        if (sender_domain.empty())
        {
            return false;
        }
        auto const key_id = [&pdu, sender_domain]() -> std::optional<std::string> {
            for (auto const& sig : pdu.signatures)
            {
                if (sig.server_name == sender_domain)
                {
                    return sig.key_id;
                }
            }
            return std::nullopt;
        }();
        if (!key_id.has_value() || !runtime.federation.remote_key_resolver)
        {
            return false;
        }
        auto const remote = runtime.federation.remote_key_resolver(sender_domain, *key_id);
        if (!remote.has_value())
        {
            return false;
        }
        auto const signature_decision =
            federation::authorize_federation_pdu(pdu, std::string{sender_domain}, remote->signing_key);
        if (!signature_decision.accepted)
        {
            return false;
        }

        auto const envelope_opt = federation::parse_inbound_pdu_envelope(stored_json, policy.id);
        if (!envelope_opt.has_value())
        {
            return false;
        }
        auto const& envelope = *envelope_opt;

        auto const third_party_invite_token = [&effective_pdu]() -> std::string {
            auto const* pdu_obj = std::get_if<canonicaljson::Object>(&effective_pdu.storage());
            auto const* content = pdu_obj == nullptr ? nullptr : object_member_as_object(*pdu_obj, "content");
            auto const* third_party_invite =
                content == nullptr ? nullptr : object_member_as_object(*content, "third_party_invite");
            auto const* signed_obj =
                third_party_invite == nullptr ? nullptr : object_member_as_object(*third_party_invite, "signed");
            auto const* token = signed_obj == nullptr ? nullptr : string_member(*signed_obj, "token");
            return token == nullptr ? std::string{} : *token;
        }();

        // ADR-0064 phase C: drop backfilled events whose own auth_events are
        // unresolvable or disallowed; never use a failed event as state.
        auto const selection_check = validate_auth_events_selection(
            runtime.database.persistent_store, room_id, effective_pdu, policy, envelope.event_type, envelope.sender,
            envelope.state_key, third_party_invite_token, envelope.auth_event_ids);
        if (selection_check != AuthEventsSelectionCheck::ok)
        {
            return false;
        }
        auto auth_events_map = build_auth_event_map_from_entries(
            runtime.database.persistent_store,
            state_entries_from_named_events(runtime.database.persistent_store, envelope.auth_event_ids),
            envelope.sender, envelope.state_key.value_or(std::string{}), envelope.event_type, third_party_invite_token);
        if (policy.create_event_is_room_id && std::holds_alternative<std::nullptr_t>(auth_events_map.create.storage()))
        {
            auth_events_map.create = create_event_json_for_room(runtime.database.persistent_store, room_id);
        }
        auto const auth_events_decision =
            events::authorize_event_against_auth_events(effective_pdu, policy, auth_events_map);
        if (!auth_events_decision.allowed)
        {
            return false;
        }

        // ADR-0064 phase C: mirror the spec's step-5 check from ingest_pdu_event.
        // A backfilled event that passes its own auth_events can still be forged
        // against the state before it; it must then be stored as rejected with
        // after-state equal to state_before so it cannot influence later state.
        enum class BackfillOutcome : std::uint8_t
        {
            accepted,
            rejected,
        };
        auto outcome = BackfillOutcome::accepted;
        auto outcome_reason = std::string{};

        auto const known_state_before = [&]() -> std::optional<std::vector<database::PersistentStateGroupStateEntry>> {
            if (forced_state_before.has_value())
            {
                return *forced_state_before;
            }
            auto const computed =
                compute_state_before(runtime.database.persistent_store, room_id, policy, envelope.prev_event_ids);
            if (!computed.ok)
            {
                return std::nullopt;
            }
            return computed.state;
        }();
        // ADR-0069: historical state events pulled in by the /state_ids
        // fallback may have prev_events whose state groups are not recorded
        // locally. Only for events fetched through /event_auth may we then
        // store the event on the strength of its own auth_events alone.
        // ADR-0070: the state before such an event stays unknown, so it is
        // stored as a true outlier with no after-state (see below).
        auto const state_before_known = known_state_before.has_value();
        if (!state_before_known && !allow_auth_events_only)
        {
            return false;
        }
        auto const state_before = known_state_before.value_or(std::vector<database::PersistentStateGroupStateEntry>{});

        auto state_before_map = events::AuthEventMap{};
        auto state_before_decision = events::EventAuthorizationDecision{};
        if (!state_before_known)
        {
            // No local state-before is available; the auth_events check above
            // has already passed and is the only check that can run.
            state_before_map = auth_events_map;
            state_before_decision = auth_events_decision;
        }
        else
        {
            state_before_map = build_auth_event_map_from_entries(
                runtime.database.persistent_store, state_before, envelope.sender,
                envelope.state_key.value_or(std::string{}), envelope.event_type, third_party_invite_token);
            fill_create_from_room_state(state_before_map, runtime.database.persistent_store, room_id);
            state_before_decision =
                events::authorize_event_against_auth_events(effective_pdu, policy, state_before_map);
        }
        if (!state_before_decision.allowed)
        {
            outcome = BackfillOutcome::rejected;
            outcome_reason = "event auth denied against state before the event: " + state_before_decision.reason;
        }

        // ADR-0070: with no known state-before there is no after-state to
        // record. Deriving one from the event's own auth_events would hand any
        // descendant a thin, origin-chosen state-before instead of the room's
        // real prior state; a PDU that builds on this outlier must fetch the
        // state at it instead (collect_missing_pdu_references treats a
        // prev_event with no state group as missing).
        auto const state_after = [&]() -> std::optional<std::vector<database::PersistentStateGroupStateEntry>> {
            if (!state_before_known)
            {
                return std::nullopt;
            }
            if (outcome == BackfillOutcome::rejected)
            {
                return state_before;
            }
            return compute_state_after(state_before, envelope.event_id, envelope.event_type, envelope.state_key);
        }();

        auto const stripe = std::hash<std::string>{}(std::string{room_id}) % room_mutex_stripe_count;
        auto stripe_guard = std::unique_lock{runtime.room_stripe_mutexes[stripe]};
        auto global_guard = std::unique_lock<RuntimeMutex>{runtime.mutex};

        auto const record_state_group = [&](std::vector<database::PersistentStateGroupStateEntry> const& after) {
            auto const group =
                forced_state_before.has_value()
                    ? record_event_state_with_parent(runtime.database.persistent_store, room_id, envelope.event_id,
                                                     envelope.prev_event_ids, std::nullopt, after, false)
                    : record_event_state(runtime.database.persistent_store, room_id, envelope.event_id,
                                         envelope.prev_event_ids, after, false);
            if (!group.has_value())
            {
                LOG_WARNING("State-group bookkeeping failed for backfilled outlier; event_id=" + envelope.event_id +
                            " room_id=" + std::string{room_id});
            }
        };

        auto const existing =
            std::ranges::find_if(runtime.database.persistent_store.events, [&](database::PersistentEvent const& evt) {
                return evt.event_id == envelope.event_id;
            });
        if (existing != runtime.database.persistent_store.events.end())
        {
            // Room versions 1 and 2 do not derive event IDs from content, so a
            // matching ID alone does not prove it is the same event.
            if (existing->room_id != room_id)
            {
                return false;
            }
            // ADR-0070: an event already stored with no state group (an
            // /event_auth outlier, or an event older than ADR-0064's state
            // groups) gains one once the state before it is known and it
            // passes auth against that state. It keeps its stored status. One
            // that fails is left without state, so nothing can build on it.
            if (!state_after.has_value() || existing->status == "rejected" ||
                event_has_state_group(runtime.database.persistent_store, envelope.event_id))
            {
                return true;
            }
            if (outcome == BackfillOutcome::rejected)
            {
                LOG_WARNING("Stored event failed auth against its now-known state-before; left without state; "
                            "event_id=" +
                            envelope.event_id + " room_id=" + std::string{room_id} + " reason=" + outcome_reason);
                return false;
            }
            record_state_group(*state_after);
            return true;
        }

        auto const [stream_ordering, sync_stream_id] = [&]() {
            auto const ordering = allocate_stream_ordering(runtime.database);
            auto const sync_id = database::allocate_sync_stream_id(runtime.database.persistent_store);
            return std::make_pair(ordering, sync_id);
        }();

        auto event = database::PersistentEvent{};
        event.event_id = envelope.event_id;
        event.room_id = std::string{room_id};
        event.sender_user_id = envelope.sender;
        event.json = std::move(stored_json);
        event.depth = envelope.depth;
        event.stream_ordering = stream_ordering;
        event.prev_event_ids = envelope.prev_event_ids;
        event.auth_event_ids = envelope.auth_event_ids;
        event.signatures = envelope.signatures;
        event.status = outcome == BackfillOutcome::rejected ? "rejected" : "outlier";

        if (outcome == BackfillOutcome::rejected)
        {
            LOG_WARNING("Backfilled event rejected at state-before check; event_id=" + envelope.event_id +
                        " room_id=" + std::string{room_id} + " reason=" + outcome_reason);
        }

        auto prepared = database::prepare_store_event_with_state(runtime.database.persistent_store, std::move(event),
                                                                 std::optional<database::PersistentStateEvent>{});
        if (!prepared.has_value())
        {
            return false;
        }
        auto const committed = [&]() {
            auto const released = RuntimeLockRelease{global_guard};
            std::ignore = released;
            return database::commit_persistent_transaction(runtime.database.persistent_store, prepared->statements);
        }();
        if (!committed)
        {
            return false;
        }
        database::apply_store_event_with_state(runtime.database.persistent_store, *prepared);

        if (state_after.has_value())
        {
            record_state_group(*state_after);
        }
        std::ignore = sync_stream_id;
        return true;
    }

    // ADR-0064 phase C / ADR-0069 option A: /state_ids fallback. When
    // /get_missing_events and per-event fetches cannot close the gap, ask the
    // origin for the resolved state at a missing prev_event. Fetch and verify
    // the named state and auth events; for historical state events whose
    // prev_events have no recorded state groups, fall back to /event_auth to
    // obtain their full auth chain and store them as auth-events-only outliers.
    // Finally verify and store the missing event using the verified snapshot as
    // its state-before. Returns true when the target event was stored.
    [[nodiscard]] auto backfill_state_ids_snapshot(HomeserverRuntime& runtime, std::string_view room_id,
                                                   std::string_view origin, std::string_view target_event_id,
                                                   rooms::RoomVersionPolicy const& policy, std::size_t& outbound_calls,
                                                   std::size_t recursion_depth = 0U) -> bool
    {
        if (outbound_calls >= k_max_backfill_outbound_calls || recursion_depth > k_max_backfill_recursion_depth)
        {
            return false;
        }

        auto const state_ids = fetch_state_ids(runtime, room_id, origin, target_event_id, outbound_calls);
        if (!state_ids.has_value())
        {
            return false;
        }
        auto const& [pdu_ids, auth_chain_ids] = *state_ids;

        if (pdu_ids.size() > k_max_state_ids_per_pdu || auth_chain_ids.size() > k_max_auth_chain_ids_per_pdu)
        {
            LOG_WARNING(
                "backfill_state_ids_snapshot: oversized /state_ids response rejected; room_id=" + std::string{room_id} +
                " target_event_id=" + std::string{target_event_id} + " pdu_ids=" + std::to_string(pdu_ids.size()) +
                " auth_chain_ids=" + std::to_string(auth_chain_ids.size()));
            return false;
        }

        auto needed_ids = std::vector<std::string>{};
        needed_ids.reserve(pdu_ids.size() + auth_chain_ids.size());
        auto snapshot_state_ids = std::unordered_set<std::string>{};
        {
            auto seen = std::unordered_set<std::string>{};
            for (auto const& id : pdu_ids)
            {
                if (id != target_event_id && seen.insert(id).second)
                {
                    needed_ids.push_back(id);
                    snapshot_state_ids.insert(id);
                }
            }
            for (auto const& id : auth_chain_ids)
            {
                if (id != target_event_id && seen.insert(id).second)
                {
                    needed_ids.push_back(id);
                }
            }
        }

        // ADR-0069 option A: snapshot materialisation gets its own outbound budget
        // so that verifying a large legitimate state snapshot does not exhaust
        // the general per-PDU backfill budget.
        auto snapshot_calls = std::size_t{0U};

        if (needed_ids.size() > k_max_state_snapshot_events_per_pdu)
        {
            LOG_WARNING("backfill_state_ids_snapshot: snapshot too large to materialise; room_id=" +
                        std::string{room_id} + " target_event_id=" + std::string{target_event_id} +
                        " needed_events=" + std::to_string(needed_ids.size()));
            return false;
        }

        for (auto const& id : needed_ids)
        {
            {
                auto const stripe = std::hash<std::string>{}(std::string{room_id}) % room_mutex_stripe_count;
                auto stripe_guard = std::unique_lock{runtime.room_stripe_mutexes[stripe]};
                auto global_guard = std::unique_lock<RuntimeMutex>{runtime.mutex};
                // Already stored: it was verified when stored, or was created
                // here. ADR-0070: an /event_auth outlier has no state group,
                // so testing for one would re-fetch and re-verify it on every
                // later snapshot that names it. The snapshot is built below
                // from the stored copies, which are checked for room, rejected
                // status and state-event shape there.
                if (std::ranges::any_of(runtime.database.persistent_store.events,
                                        [&](database::PersistentEvent const& evt) {
                                            return evt.event_id == id;
                                        }))
                {
                    continue;
                }
            }
            if (snapshot_calls >= k_max_snapshot_outbound_calls)
            {
                return false;
            }
            auto const json = fetch_snapshot_event_by_id(runtime, room_id, origin, id, policy, snapshot_calls);
            if (!json.has_value())
            {
                return false;
            }
            if (verify_and_store_backfilled_event(runtime, room_id, origin, *json, policy))
            {
                continue;
            }

            // ADR-0069 option A: a snapshot state event whose prev_events have no
            // recorded state groups is a normal historical gap, not a failure.
            // Fetch the full auth chain via /event_auth, verify and store each
            // returned PDU against its own auth_events alone, then retry the
            // snapshot event as an auth-events-only outlier. If this still fails,
            // or if the event is not a snapshot state event, the snapshot is
            // rejected fail-closed.
            if (!snapshot_state_ids.contains(id))
            {
                LOG_WARNING("backfill_state_ids_snapshot: auth-chain event failed verification; room_id=" +
                            std::string{room_id} + " event_id=" + id);
                return false;
            }
            // Only spend an /event_auth call when the failure is plausibly due to
            // a missing state-before. If all prev_events have state groups, the
            // failure is for another reason (forged signature, bad auth_events,
            // etc.) and the snapshot must be rejected immediately.
            auto prev_events_known = false;
            {
                auto const stripe = std::hash<std::string>{}(std::string{room_id}) % room_mutex_stripe_count;
                auto stripe_guard = std::unique_lock{runtime.room_stripe_mutexes[stripe]};
                auto global_guard = std::unique_lock<RuntimeMutex>{runtime.mutex};
                prev_events_known = prev_events_have_state_groups(runtime.database.persistent_store, policy, *json);
            }
            if (prev_events_known)
            {
                LOG_WARNING(
                    "backfill_state_ids_snapshot: snapshot event failed verification despite known state-before; "
                    "room_id=" +
                    std::string{room_id} + " event_id=" + id);
                return false;
            }
            auto const auth_pdus = fetch_event_auth(runtime, room_id, origin, id, snapshot_calls);
            if (!auth_pdus.has_value())
            {
                LOG_WARNING("backfill_state_ids_snapshot: /event_auth fallback failed; room_id=" +
                            std::string{room_id} + " event_id=" + id);
                return false;
            }
            for (auto const& auth_json : *auth_pdus)
            {
                if (!verify_and_store_backfilled_event(runtime, room_id, origin, auth_json, policy, std::nullopt, true))
                {
                    LOG_WARNING("backfill_state_ids_snapshot: auth-chain PDU failed verification; room_id=" +
                                std::string{room_id} + " snapshot_event_id=" + id);
                    return false;
                }
            }
            if (!verify_and_store_backfilled_event(runtime, room_id, origin, *json, policy, std::nullopt, true))
            {
                LOG_WARNING("backfill_state_ids_snapshot: snapshot event failed verification after /event_auth "
                            "fallback; room_id=" +
                            std::string{room_id} + " event_id=" + id);
                return false;
            }
        }

        // Build the verified snapshot state from pdu_ids. Each pdu_id names a
        // state event in the resolved state at the target event.
        auto snapshot_state = std::vector<database::PersistentStateGroupStateEntry>{};
        {
            auto const stripe = std::hash<std::string>{}(std::string{room_id}) % room_mutex_stripe_count;
            auto stripe_guard = std::unique_lock{runtime.room_stripe_mutexes[stripe]};
            auto global_guard = std::unique_lock<RuntimeMutex>{runtime.mutex};
            snapshot_state.reserve(pdu_ids.size());
            auto seen_keys = std::unordered_set<std::string>{};
            for (auto const& id : pdu_ids)
            {
                if (id == target_event_id)
                {
                    continue;
                }
                auto const it = std::ranges::find_if(runtime.database.persistent_store.events,
                                                     [&](database::PersistentEvent const& e) {
                                                         return e.event_id == id;
                                                     });
                if (it == runtime.database.persistent_store.events.end())
                {
                    return false;
                }
                if (it->room_id != room_id)
                {
                    LOG_WARNING("backfill_state_ids_snapshot: snapshot event belongs to a different room; room_id=" +
                                std::string{room_id} + " event_id=" + id + " event_room_id=" + it->room_id);
                    return false;
                }
                // Spec: server-server-api.md "Rejection" — a rejected event must
                // never be used as state. Soft-failed events, by contrast, still
                // take part in state resolution (spec "Soft failure"), so they
                // are permitted in a /state_ids snapshot.
                if (it->status == "rejected")
                {
                    LOG_WARNING("backfill_state_ids_snapshot: snapshot event was previously rejected; room_id=" +
                                std::string{room_id} + " event_id=" + id);
                    return false;
                }
                auto const parsed = canonicaljson::parse_lossless(it->json);
                if (parsed.error != canonicaljson::ParseError::none)
                {
                    return false;
                }
                auto const* obj = std::get_if<canonicaljson::Object>(&parsed.value.storage());
                if (obj == nullptr)
                {
                    return false;
                }
                auto const* type = string_member(*obj, "type");
                auto const* state_key = string_member(*obj, "state_key");
                if (type == nullptr || state_key == nullptr)
                {
                    LOG_WARNING("backfill_state_ids_snapshot: snapshot event is not a state event; room_id=" +
                                std::string{room_id} + " event_id=" + id);
                    return false;
                }
                auto const key = *type + '\0' + *state_key;
                if (!seen_keys.insert(key).second)
                {
                    LOG_WARNING("backfill_state_ids_snapshot: duplicate (type, state_key) in snapshot; room_id=" +
                                std::string{room_id} + " key=" + *type + " / " + *state_key);
                    return false;
                }
                snapshot_state.push_back({{}, *type, *state_key, id});
            }
        }

        if (snapshot_calls >= k_max_snapshot_outbound_calls)
        {
            return false;
        }
        auto const target_json =
            fetch_snapshot_event_by_id(runtime, room_id, origin, target_event_id, policy, snapshot_calls);
        if (!target_json.has_value())
        {
            return false;
        }

        return verify_and_store_backfilled_event(runtime, room_id, origin, *target_json, policy, snapshot_state);
    }

    // Returns `events` ordered by ascending `depth`, keeping the response order
    // among equal depths. An event whose envelope does not parse sorts last; it
    // will fail verification anyway.
    [[nodiscard]] auto order_by_ascending_depth(std::vector<std::string> const& events,
                                                rooms::RoomVersionPolicy const& policy) -> std::vector<std::string>
    {
        struct DepthKeyed
        {
            std::uint64_t depth{};
            std::string json{};
        };
        auto keyed = std::vector<DepthKeyed>{};
        keyed.reserve(events.size());
        for (auto const& json : events)
        {
            auto const envelope = federation::parse_inbound_pdu_envelope(json, policy.id);
            keyed.push_back({envelope.has_value() ? envelope->depth : std::numeric_limits<std::uint64_t>::max(), json});
        }
        std::ranges::stable_sort(keyed, std::ranges::less{}, &DepthKeyed::depth);
        auto ordered = std::vector<std::string>{};
        ordered.reserve(keyed.size());
        for (auto& entry : keyed)
        {
            ordered.push_back(std::move(entry.json));
        }
        return ordered;
    }

    // ADR-0064 phase C: fetch missing prev_events / auth_events from the sending
    // server, verify each returned event, and store the verified events as
    // outliers with state groups so a later ingestion attempt can resolve state.
    // Returns true when at least one missing event was successfully stored.
    [[nodiscard]] auto backfill_missing_pdu_references(HomeserverRuntime& runtime, std::string_view room_id,
                                                       federation::InboundPduEnvelope const& envelope,
                                                       rooms::RoomVersionPolicy const& policy) -> bool
    {
        auto const stripe = std::hash<std::string>{}(std::string{room_id}) % room_mutex_stripe_count;
        auto collect = [&]() {
            auto stripe_guard = std::unique_lock{runtime.room_stripe_mutexes[stripe]};
            auto global_guard = std::unique_lock<RuntimeMutex>{runtime.mutex};
            std::ignore = stripe_guard;
            std::ignore = global_guard;
            return collect_missing_pdu_references(runtime.database.persistent_store, envelope);
        };
        auto [missing_auth, missing_prev] = collect();
        if (missing_auth.empty() && missing_prev.empty())
        {
            return true;
        }

        auto outbound_calls = std::size_t{0U};
        auto stored_any = false;

        if (!missing_prev.empty() && outbound_calls < k_max_backfill_outbound_calls)
        {
            auto const fetched = fetch_get_missing_events(runtime, room_id, envelope.origin, envelope.prev_event_ids,
                                                          missing_prev, k_max_get_missing_events_per_pdu);
            ++outbound_calls;
            if (fetched.has_value())
            {
                // A backfilled event needs its prev_events' state groups, so
                // parents must be stored before children; the response order
                // is the remote's choice (0.12.13 audit item 9).
                for (auto const& json : order_by_ascending_depth(*fetched, policy))
                {
                    if (verify_and_store_backfilled_event(runtime, room_id, envelope.origin, json, policy))
                    {
                        stored_any = true;
                    }
                }
            }
        }

        std::tie(missing_auth, missing_prev) = collect();

        for (auto const& id : missing_auth)
        {
            if (outbound_calls >= k_max_backfill_outbound_calls)
            {
                break;
            }
            auto const json = fetch_event_by_id(runtime, room_id, envelope.origin, id, policy, outbound_calls);
            if (json.has_value() && verify_and_store_backfilled_event(runtime, room_id, envelope.origin, *json, policy))
            {
                stored_any = true;
            }
        }
        for (auto const& id : missing_prev)
        {
            if (outbound_calls >= k_max_backfill_outbound_calls)
            {
                break;
            }
            auto const json = fetch_event_by_id(runtime, room_id, envelope.origin, id, policy, outbound_calls);
            if (json.has_value() && verify_and_store_backfilled_event(runtime, room_id, envelope.origin, *json, policy))
            {
                stored_any = true;
            }
        }

        std::tie(missing_auth, missing_prev) = collect();

        // ADR-0064 phase C: /state_ids fallback for prev_events that still have
        // no recorded state group after /get_missing_events and /event/{id}.
        for (auto const& id : missing_prev)
        {
            if (outbound_calls >= k_max_backfill_outbound_calls)
            {
                break;
            }
            if (backfill_state_ids_snapshot(runtime, room_id, envelope.origin, id, policy, outbound_calls))
            {
                stored_any = true;
            }
        }

        std::tie(missing_auth, missing_prev) = collect();
        if (!missing_auth.empty() || !missing_prev.empty())
        {
            LOG_WARNING("Backfill could not resolve all missing references for room_id=" + std::string{room_id} +
                        " event_id=" + envelope.event_id);
        }
        return stored_any;
    }

} // namespace

// Signature verification (receipt step 2) is the caller's job, done before
// this function takes any lock because resolving a key may go to the network:
// federation::authorize_federation_pdu() in inbound_request.cpp on the
// same-process path, and handle_pdu_ingest_request() in worker_pool.cpp, with
// main's own remote_key_resolver, for a PDU relayed by a federation worker
// (ADR-0071). This function re-checks authorization and content-hash
// integrity.
auto ingest_pdu_event(HomeserverRuntime& runtime, federation::InboundPduEnvelope const& envelope)
    -> federation::PduIngestionResult
{
    auto const room_id = envelope.room_id;
    if (room_id.empty())
    {
        return {federation::PduIngestionStatus::rejected_invalid, "missing room_id"};
    }

    auto const* room_policy =
        rooms::find_room_version_policy(envelope.room_version.empty() ? "12" : envelope.room_version);
    if (room_policy == nullptr)
    {
        return {federation::PduIngestionStatus::rejected_invalid, "unknown room version"};
    }

    auto const pdu_parsed = canonicaljson::parse_lossless(envelope.json);
    if (pdu_parsed.error != canonicaljson::ParseError::none)
    {
        return {federation::PduIngestionStatus::rejected_invalid, "invalid PDU JSON"};
    }

    // Spec: server-server-api.md — "Checks performed on receipt of a PDU",
    // step 3 (hash). A content-hash mismatch does NOT reject the event: it
    // is redacted per the room version's redaction algorithm and processing
    // continues with the redacted form, which is what gets stored. event_id,
    // sender, and every key the redaction algorithm preserves survive; only
    // `content` (and a few other non-essential keys) are stripped.
    auto effective_pdu = pdu_parsed.value;
    auto stored_json = envelope.json;
    if (!events::verify_pdu_content_hash(effective_pdu))
    {
        auto redaction = events::redact_event(effective_pdu, *room_policy);
        if (!redaction.error.empty())
        {
            return {federation::PduIngestionStatus::rejected_invalid,
                    "content hash mismatch and event could not be redacted: " + redaction.error};
        }
        effective_pdu = std::move(redaction.event);
        auto const serialized = canonicaljson::serialize_canonical(effective_pdu);
        if (serialized.error != canonicaljson::CanonicalJsonError::none)
        {
            return {federation::PduIngestionStatus::rejected_invalid, "failed to serialize redacted event"};
        }
        stored_json = serialized.output;
    }

    // Reserve the global stream-ordering and sync-surface IDs up front under
    // the global mutex. Allocating sync_stream_id writes to the backend, so it
    // must not happen while a room stripe is also held — that would pin the
    // stripe for the whole database write and prevent concurrent progress on
    // unrelated rooms.
    auto const [stream_ordering, sync_stream_id] = [&]() {
        auto global_guard = std::unique_lock<RuntimeMutex>{runtime.mutex};
        auto const ordering = allocate_stream_ordering(runtime.database);
        auto const sync_id = database::allocate_sync_stream_id(runtime.database.persistent_store);
        return std::make_pair(ordering, sync_id);
    }();

    auto const stripe = std::hash<std::string>{}(room_id) % room_mutex_stripe_count;
    auto stripe_guard = std::unique_lock{runtime.room_stripe_mutexes[stripe]};

    // Lock order: room stripe first, then global runtime mutex. The stripe
    // serializes events for this room across the whole prepare/commit/apply
    // sequence so per-room ordering is preserved. The global mutex protects all
    // in-memory PersistentStore / LocalDatabase vectors; it is released only
    // for the backend commit so independent rooms can commit in parallel.
    auto global_guard = std::unique_lock<RuntimeMutex>{runtime.mutex};

    // ADR-0064 phase C: if this PDU names prev_events or auth_events we do not
    // have, release both locks and fetch the gap from the sending server. A
    // single backfill attempt is made; if references remain unresolvable the PDU
    // is held in missing_prev_state without persisting anything, keeping the
    // transaction valid.
    {
        auto [missing_auth, missing_prev] = collect_missing_pdu_references(runtime.database.persistent_store, envelope);
        if (!missing_auth.empty() || !missing_prev.empty())
        {
            if (envelope.origin.empty())
            {
                return {federation::PduIngestionStatus::missing_prev_state,
                        "missing PDU references and no origin to backfill from"};
            }
            struct ScopedStripeReacquire final
            {
                std::unique_lock<std::mutex>& guard;
                explicit ScopedStripeReacquire(std::unique_lock<std::mutex>& g)
                    : guard{g}
                {
                    g.unlock(); // LOCK_RELEASE: reviewed — RAII helper releases the room stripe lock so backfill can
                                // perform outbound I/O without holding any lock.
                }
                ~ScopedStripeReacquire()
                {
                    guard.lock();
                }
                ScopedStripeReacquire(ScopedStripeReacquire const&) = delete;
                auto operator=(ScopedStripeReacquire const&) -> ScopedStripeReacquire& = delete;
            };
            auto const stripe_released = ScopedStripeReacquire{stripe_guard};
            std::ignore = stripe_released;
            auto const global_released = RuntimeLockRelease{global_guard};
            std::ignore = global_released;
            std::ignore = backfill_missing_pdu_references(runtime, room_id, envelope, *room_policy);
        }
    }
    {
        auto [missing_auth, missing_prev] = collect_missing_pdu_references(runtime.database.persistent_store, envelope);
        if (!missing_auth.empty() || !missing_prev.empty())
        {
            return {federation::PduIngestionStatus::missing_prev_state, "missing PDU references remain after backfill"};
        }
    }

    auto const third_party_invite_token = [&]() -> std::string {
        auto const* pdu_obj = std::get_if<canonicaljson::Object>(&effective_pdu.storage());
        auto const* content = pdu_obj == nullptr ? nullptr : object_member_as_object(*pdu_obj, "content");
        auto const* third_party_invite =
            content == nullptr ? nullptr : object_member_as_object(*content, "third_party_invite");
        auto const* signed_obj =
            third_party_invite == nullptr ? nullptr : object_member_as_object(*third_party_invite, "signed");
        auto const* token = signed_obj == nullptr ? nullptr : string_member(*signed_obj, "token");
        return token == nullptr ? std::string{} : *token;
    }();

    // ADR-0064 phase B2: three-way receipt outcome, decided in spec order
    // (steps 4, 5, 6) and carried through to storage below. A rejection is
    // NOT an early return — spec "Rejection" requires the event still be
    // stored (so later events that reference it can still be authorised),
    // just never applied to state and never a forward extremity. Soft
    // failure (step 6) likewise stores the event and lets it take part in
    // state resolution; only steps 4 and 5 (auth against auth_events and
    // against the state before the event) reject.
    enum class ReceiptOutcome : std::uint8_t
    {
        accepted,
        rejected,
        soft_failed,
    };
    auto outcome = ReceiptOutcome::accepted;
    auto outcome_reason = std::string{};

    // Step 4: "Auth events selection" (which auth_events a PDU may legally
    // name) followed by the auth-rule algorithm against the map those named
    // events build. An auth_event_id this store cannot resolve at all is not
    // a decided rejection — it is the same "awaiting backfill" gap as a
    // missing prev_event, so it takes priority over everything else below.
    auto const selection_check = validate_auth_events_selection(
        runtime.database.persistent_store, room_id, effective_pdu, *room_policy, envelope.event_type, envelope.sender,
        envelope.state_key, third_party_invite_token, envelope.auth_event_ids);
    if (selection_check == AuthEventsSelectionCheck::unresolvable)
    {
        return {federation::PduIngestionStatus::missing_prev_state,
                "an auth_event this PDU names has no recorded event; awaiting backfill"};
    }
    if (selection_check == AuthEventsSelectionCheck::disallowed)
    {
        outcome = ReceiptOutcome::rejected;
        outcome_reason = "auth_events selection is not permitted for this event";
    }

    if (outcome == ReceiptOutcome::accepted)
    {
        auto auth_events_map = build_auth_event_map_from_entries(
            runtime.database.persistent_store,
            state_entries_from_named_events(runtime.database.persistent_store, envelope.auth_event_ids),
            envelope.sender, envelope.state_key.value_or(std::string{}), envelope.event_type, third_party_invite_token);
        // v12 (MSC4291): the create event is implicit in the room ID and
        // MUST NOT be listed in auth_events (validate_auth_events_selection
        // rejects a PDU that names it), so it can never come from the named
        // set above. The auth-rule algorithm still needs its content (e.g.
        // the m.federate check), so look it up from the room's own recorded
        // state the same way build_pdu_auth_event_map does for the
        // current-state check below — there is exactly one create event per
        // room, so this cannot be confused with a "selected" entry.
        if (room_policy->create_event_is_room_id &&
            std::holds_alternative<std::nullptr_t>(auth_events_map.create.storage()))
        {
            auth_events_map.create = create_event_json_for_room(runtime.database.persistent_store, room_id);
        }
        auto const auth_events_decision =
            events::authorize_event_against_auth_events(effective_pdu, *room_policy, auth_events_map);
        if (!auth_events_decision.allowed)
        {
            outcome = ReceiptOutcome::rejected;
            outcome_reason = "event auth denied against its own auth_events: " + auth_events_decision.reason;
        }
    }

    // ADR-0064 phase B1: the state immediately before this PDU is the
    // resolution of its prev_events' own after-states. A prev_event with no
    // recorded state group means we cannot determine that state without
    // guessing (which would reintroduce delivery-order dependence) or a gap
    // a later phase must backfill — either way this PDU is not stored, but
    // the transaction it arrived in must still succeed (see
    // PduIngestionStatus::missing_prev_state). This applies regardless of
    // `outcome` above: a rejected event's after-state is still defined as
    // "the state before it", so that state must still be resolvable.
    auto const state_before =
        compute_state_before(runtime.database.persistent_store, room_id, *room_policy, envelope.prev_event_ids);
    if (!state_before.ok)
    {
        return {federation::PduIngestionStatus::missing_prev_state,
                "no recorded state group for a prev_event; awaiting backfill"};
    }

    // Step 5: auth against the state immediately before the event.
    if (outcome == ReceiptOutcome::accepted)
    {
        auto state_before_map = build_auth_event_map_from_entries(
            runtime.database.persistent_store, state_before.state, envelope.sender,
            envelope.state_key.value_or(std::string{}), envelope.event_type, third_party_invite_token);
        fill_create_from_room_state(state_before_map, runtime.database.persistent_store, room_id);
        auto const state_before_decision =
            events::authorize_event_against_auth_events(effective_pdu, *room_policy, state_before_map);
        if (!state_before_decision.allowed)
        {
            outcome = ReceiptOutcome::rejected;
            outcome_reason = "event auth denied against state before the event: " + state_before_decision.reason;
        }
    }

    // Step 6: auth against the room's current (resolved) state. Spec: "Soft
    // failure" — a failure here does not reject the event.
    if (outcome == ReceiptOutcome::accepted)
    {
        auto current_state_map = build_pdu_auth_event_map(runtime.database.persistent_store, room_id, envelope.sender,
                                                          envelope.state_key.value_or(std::string{}),
                                                          envelope.event_type, third_party_invite_token);
        fill_create_from_room_state(current_state_map, runtime.database.persistent_store, room_id);
        auto const current_state_decision =
            events::authorize_event_against_auth_events(effective_pdu, *room_policy, current_state_map);
        if (!current_state_decision.allowed)
        {
            outcome = ReceiptOutcome::soft_failed;
            outcome_reason = "event auth denied against current state (soft failure): " + current_state_decision.reason;
        }
    }

    // The naive immediate current_state write (see recompute_current_state's
    // doc comment on why this is safe: it is always reconciled against the
    // forward-extremity resolution right below) only ever applies to an
    // accepted event. A rejected event must never update state at all; a
    // soft-failed one only enters current_state if resolution later admits
    // it via recompute_current_state, never through this shortcut.
    auto state = std::optional<database::PersistentStateEvent>{};
    if (envelope.state_key.has_value() && outcome == ReceiptOutcome::accepted)
    {
        state = database::PersistentStateEvent{room_id, envelope.event_type, *envelope.state_key, envelope.event_id};
    }

    auto event = database::PersistentEvent{};
    event.event_id = envelope.event_id;
    event.room_id = room_id;
    event.sender_user_id = envelope.sender;
    event.json = stored_json;
    event.depth = envelope.depth;
    event.stream_ordering = stream_ordering;
    event.prev_event_ids = envelope.prev_event_ids;
    event.auth_event_ids = envelope.auth_event_ids;
    event.signatures = envelope.signatures;
    event.status = outcome == ReceiptOutcome::rejected      ? "rejected"
                   : outcome == ReceiptOutcome::soft_failed ? "soft_failed"
                                                            : "accepted";

    auto prepared =
        database::prepare_store_event_with_state(runtime.database.persistent_store, std::move(event), state);
    if (!prepared.has_value())
    {
        return {federation::PduIngestionStatus::internal_error, "event persistence pre-check failed"};
    }

    // Release only the global mutex for the backend commit. Independent rooms
    // can now commit concurrently (each still holds its own stripe), while the
    // in-memory store stays protected against concurrent reads/writes. The
    // early return inside the scope re-acquires on the way out, as does a
    // throw from the backend.
    auto const committed = [&] {
        auto const released = RuntimeLockRelease{global_guard};
        std::ignore = released;
        return database::commit_persistent_transaction(runtime.database.persistent_store, prepared->statements);
    }();
    if (!committed)
    {
        return {federation::PduIngestionStatus::internal_error, "event persistence backend rejected transaction"};
    }

    database::apply_store_event_with_state(runtime.database.persistent_store, *prepared);

    // ADR-0064 phase B1/B2: record this event's after-state group and
    // update forward extremities (only for an accepted event — a rejected
    // or soft-failed one is stored and mapped to a state group but never
    // becomes an extremity), then recompute current_state as the resolution
    // over the (now possibly changed) extremity set. The raw event is
    // already durably stored above; a failure here is logged but does not
    // change `outcome` — the same trade-off the membership-persistence step
    // below already makes; a later phase can repair state-group bookkeeping
    // without re-fetching the event.
    //
    // Spec "Rejection": a rejected event's state is "calculated as normal,
    // except not updating with the rejected event" — so its after-state is
    // state_before, unchanged, even if it is itself a state event. Spec
    // "Soft failure": a soft-failed event "participate[s] in state
    // resolution as normal", so its after-state is the normally-computed
    // compute_state_after result, same as an accepted event.
    {
        auto const state_after =
            outcome == ReceiptOutcome::rejected
                ? state_before.state
                : compute_state_after(state_before.state, envelope.event_id, envelope.event_type, envelope.state_key);
        auto const state_group =
            record_event_state(runtime.database.persistent_store, room_id, envelope.event_id, envelope.prev_event_ids,
                               state_after, outcome == ReceiptOutcome::accepted);
        if (!state_group.has_value())
        {
            LOG_WARNING("State-group bookkeeping failed after PDU was processed; event_id=" + envelope.event_id +
                        " room_id=" + room_id);
        }
        else if (!recompute_current_state(runtime.database.persistent_store, room_id, *room_policy))
        {
            LOG_WARNING("Current-state recomputation failed after PDU was processed; event_id=" + envelope.event_id +
                        " room_id=" + room_id);
        }
    }

    auto result = federation::PduIngestionResult{};
    result.status = outcome == ReceiptOutcome::rejected      ? federation::PduIngestionStatus::rejected_auth
                    : outcome == ReceiptOutcome::soft_failed ? federation::PduIngestionStatus::soft_failed
                                                             : federation::PduIngestionStatus::accepted;
    result.reason = outcome_reason;
    result.accepted_stream_ordering = stream_ordering;
    result.accepted_sync_stream_id = sync_stream_id;

    // Membership bookkeeping (the runtime's live-member cache and
    // store.memberships) mirrors current_state, so it only runs for an
    // event that was actually accepted: a soft-failed or rejected
    // membership change must not flip the live cache directly. A
    // soft-failed one only takes effect through recompute_current_state
    // above, if resolution later admits it.
    if (outcome == ReceiptOutcome::accepted && envelope.event_type == "m.room.member" && envelope.state_key.has_value())
    {
        auto const* mem_obj = std::get_if<canonicaljson::Object>(&effective_pdu.storage());
        auto const* membership_str = mem_obj != nullptr ? content_membership(*mem_obj) : nullptr;
        if (membership_str != nullptr)
        {
            // The PDU has already been committed and applied above. Returning a
            // failure here would tell the upstream server the event was rejected,
            // which is incorrect and can cause retries even though the event is
            // already in our store. Log the error but keep the accepted result.
            auto const store_ok = upsert_membership(runtime.database.persistent_store, room_id, *envelope.state_key,
                                                    *membership_str, stream_ordering);
            if (!store_ok)
            {
                LOG_WARNING("Membership persistence failed after PDU was accepted; event_id=" + envelope.event_id +
                            " room_id=" + room_id + " user_id=" + *envelope.state_key +
                            " membership=" + std::string{*membership_str});
            }
            else
            {
                auto const room_it = std::ranges::find_if(runtime.database.rooms, [&](LocalRoom const& r) {
                    return r.room_id == room_id;
                });
                if (room_it != runtime.database.rooms.end())
                {
                    auto& members = room_it->members;
                    if (*membership_str == "join")
                    {
                        if (!std::ranges::any_of(members, [&](std::string const& m) {
                                return m == *envelope.state_key;
                            }))
                        {
                            members.push_back(*envelope.state_key);
                        }
                        broadcast_local_device_lists_to_remote_joiner(runtime, room_id, *envelope.state_key);
                    }
                    else
                    {
                        auto const to_erase = std::ranges::remove(members, *envelope.state_key);
                        members.erase(to_erase.begin(), to_erase.end());
                    }
                }
            }
        }
    }

    return result;
}

auto apply_runtime_membership(LocalDatabase& database, std::string_view room_id, std::string_view user_id,
                              std::string_view membership) -> void
{
    auto room = std::ranges::find_if(database.rooms, [&](LocalRoom const& current) {
        return current.room_id == room_id;
    });
    if (room == database.rooms.end())
    {
        return;
    }
    auto const member = std::ranges::find_if(room->members, [&](std::string const& member_id) {
        return member_id == user_id;
    });
    if (membership == "join" && member == room->members.end())
    {
        room->members.emplace_back(user_id);
    }
    else if ((membership == "leave" || membership == "ban") && member != room->members.end())
    {
        room->members.erase(member);
    }
}

auto effective_client_ip(LocalHttpRequest const& request, std::vector<std::string> const& trusted_proxies)
    -> std::string
{
    auto const& raw = request.remote_addr;
    if (raw.empty())
    {
        // Test paths that skip the transport layer. "unknown" rather than "" so
        // every such caller shares one bucket instead of bypassing the limit.
        return "unknown";
    }
    auto const is_trusted = [&trusted_proxies](std::string_view address) {
        return std::ranges::find(trusted_proxies, address) != trusted_proxies.end();
    };
    if (!is_trusted(raw))
    {
        return raw;
    }

    // Every X-Forwarded-For line, in order, forms one comma-separated list
    // (RFC 9110 §5.3). Header names compare case-insensitively.
    auto entries = std::vector<std::string_view>{};
    for (auto const& header : request.headers)
    {
        auto lower = header.name;
        std::ranges::transform(lower, lower.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        if (lower != "x-forwarded-for")
        {
            continue;
        }
        auto remaining = std::string_view{header.value};
        while (true)
        {
            auto const comma = remaining.find(',');
            auto entry = remaining.substr(0U, comma);
            while (!entry.empty() && (entry.front() == ' ' || entry.front() == '\t'))
            {
                entry.remove_prefix(1U);
            }
            while (!entry.empty() && (entry.back() == ' ' || entry.back() == '\t'))
            {
                entry.remove_suffix(1U);
            }
            entries.push_back(entry);
            if (comma == std::string_view::npos)
            {
                break;
            }
            remaining.remove_prefix(comma + 1U);
        }
    }

    // 0.12.13 audit item 4 (decided by the user on 2026-09-27): each proxy
    // appends the address it received the request from, so only the entries
    // written by trusted proxies can be believed. Walk from the right past
    // trusted proxies; the first entry that is not one is the client. The
    // leftmost entries are whatever the client itself sent and never choose
    // the key. A trusted proxy is trusted to report an address, not an
    // arbitrary string: a malformed entry at that position falls back to the
    // direct peer, so spoofed values cannot mint fresh rate-limit buckets.
    for (auto it = entries.rbegin(); it != entries.rend(); ++it)
    {
        if (is_trusted(*it))
        {
            continue;
        }
        return federation::ip_address_is_valid(*it) ? std::string{*it} : raw;
    }
    // Every entry is a trusted proxy: the leftmost one originated the request.
    if (!entries.empty() && federation::ip_address_is_valid(entries.front()))
    {
        return std::string{entries.front()};
    }
    return raw;
}

auto rate_limit_client_key(LocalHttpRequest const& request, config::ServerConfig const& server) -> std::string
{
    return http::client_address_key(effective_client_ip(request, server.trusted_proxies),
                                    server.http.ipv6_client_prefix_length);
}

auto wire_federation_callbacks(HomeserverRuntime& runtime) -> void
{
    wire_federation_callbacks_impl(runtime);
}

[[nodiscard]] auto handle_local_http_request(HomeserverRuntime& runtime, LocalHttpRequest const& request)
    -> LocalHttpResponse
{
    auto guard = std::unique_lock<RuntimeMutex>{runtime.mutex};
    // Publish the guard so a blocking network call further down the stack —
    // notably a remote media fetch — can release it for the duration. See
    // RuntimeLockRelease in request_lock.hpp.
    auto const lock_scope = RequestLockScope{guard};
    auto const correlation = observability::make_correlation_context(runtime.next_request_sequence++);
    [[maybe_unused]] auto const correlation_scope = observability::CorrelationScope{correlation};
    log_diagnostic("request.received",
                   {
                       {"method",           request.method,                                       false},
                       {"target",           observability::sanitized_http_target(request.target), false},
                       {"body_bytes",       std::to_string(request.body.size()),                  false},
                       {"has_access_token", request.access_token.empty() ? "false" : "true",      false}
    });
    if (!runtime.started)
    {
        log_diagnostic("request.rejected", {
                                               {"method", request.method,                                       false},
                                               {"target", observability::sanitized_http_target(request.target), false},
                                               {"status", "503",                                                false},
                                               {"reason", "runtime not started",                                false}
        });
        return response(503U, "runtime not started");
    }
    if (request.method == "GET" && request.target == "/_merovingian/admin/health")
    {
        if (auto const denied = admin_auth_denied(runtime, request.access_token, correlation); denied.has_value())
        {
            return *denied;
        }
        return response(200U, admin_health_summary(runtime),
                        observability_headers(correlation, "text/plain; charset=utf-8"));
    }
    if (request.method == "GET" && request.target == "/_merovingian/admin/media/metrics")
    {
        if (auto const denied = admin_auth_denied(runtime, request.access_token, correlation); denied.has_value())
        {
            return *denied;
        }
        return response(200U, media_metrics_summary(runtime),
                        observability_headers(correlation, "text/plain; charset=utf-8"));
    }
    if (request.method == "GET" && request.target == "/_merovingian/admin/metrics")
    {
        if (auto const denied = admin_auth_denied(runtime, request.access_token, correlation); denied.has_value())
        {
            return *denied;
        }
        return response(200U, admin_metrics_summary(runtime),
                        observability_headers(correlation, "text/plain; version=0.0.4; charset=utf-8"));
    }
    if (request.method == "GET" && starts_with(request.target, "/_merovingian/admin/audit"))
    {
        if (auto const denied = admin_auth_denied(runtime, request.access_token, correlation); denied.has_value())
        {
            return *denied;
        }
        // Query string filter for the audit summary (0.5.0). The
        // endpoint accepts `?category=`, `?event_type=` to narrow
        // the result set. Malformed `category=` values return 400;
        // unknown `event_type=` values are treated as a no-match
        // filter and the response is empty (still 200).
        auto const target = std::string_view{request.target};
        auto const query_start = target.find('?');
        auto category_filter = std::optional<observability::AuditCategory>{};
        auto event_type_filter = std::optional<std::string_view>{};
        if (query_start != std::string_view::npos)
        {
            auto const query = target.substr(query_start + 1U);
            for (auto const& kv : parse_audit_query_string(query))
            {
                if (kv.first == "category")
                {
                    auto const parsed = observability::audit_category_from_name(kv.second);
                    if (!parsed.has_value())
                    {
                        return response(400U, std::string{"unknown audit category: "} + std::string{kv.second},
                                        observability_headers(correlation, "text/plain; charset=utf-8"));
                    }
                    category_filter = *parsed;
                }
                else if (kv.first == "event_type")
                {
                    event_type_filter = kv.second;
                }
            }
        }
        // The admin auth gate at the top of this block already returned 401/403
        // for non-admin callers, so reaching here means the caller is an admin.
        return response(200U, admin_audit_summary(runtime, category_filter, event_type_filter),
                        observability_headers(correlation, "text/plain; charset=utf-8"));
    }
    if (request.method == "GET" && request.target.substr(0U, request.target.find('?')) == "/_matrix/key/v2/server")
    {
        return response_from_operation(publish_server_signing_keys(runtime));
    }
    if (request.method == "GET" &&
        request.target.substr(0U, request.target.find('?')) == "/_matrix/federation/v1/openid/userinfo")
    {
        return federation_openid_userinfo_response(runtime, request);
    }
    if (starts_with(request.target, "/_matrix/federation/"))
    {
        auto signed_request = parse_signed_federation_request(request, runtime.config.server());
        if (!signed_request.has_value())
        {
            log_diagnostic("federation.auth.rejected",
                           {
                               {"method", request.method,                                       false},
                               {"target", observability::sanitized_http_target(request.target), false},
                               {"status", "502",                                                false},
                               {"reason", "malformed federation authorization",                 false}
            });
            // 502 rather than 401: Synapse propagates 401 from federation
            // responses to the client, triggering an automatic logout. Returning
            // 502 signals a server-side failure instead.
            return response(502U, "malformed federation authorization");
        }
        // Security: never trust the destination claimed in the (client-supplied)
        // auth token. Pin it to this server's own name — exactly as the production
        // handle_federation_http_request path does — so a request a remote signed
        // for a different server cannot be relayed or replayed here. now_ts and the
        // canonical-verification flag remain caller-supplied because this router is
        // dispatched only in HttpDispatchMode::local_router (the in-process test
        // harness, never wired by main.cpp), where tests must drive expiry and
        // canonical-JSON verification paths.
        signed_request->destination = runtime.config.server().server_name;
        auto const federation_response = [&]() -> federation::FederationResponse {
            auto const local_rule = find_policy_rule(runtime, "federation", signed_request->origin);
            auto const held_for_review = local_rule.has_value() && local_rule->action == "quarantine";
            auto const blocked_by_local_policy =
                local_rule.has_value() && local_rule->action != "allow" && local_rule->action != "quarantine";
            auto const decision = trust_safety::evaluate_federation_policy(
                {signed_request->origin, held_for_review, blocked_by_local_policy,
                 resolve_policy_server_hook(runtime, trust_safety::PolicySurface::federation, signed_request->origin)});
            if (!decision.allowed)
            {
                return {403U,
                        decision.reason.public_summary.empty() ? decision.reason.code : decision.reason.public_summary};
            }
            return federation::handle_inbound_federation_request(runtime.federation, *signed_request);
        }();
        log_diagnostic("federation.dispatched",
                       {
                           {"method", request.method,                                       false},
                           {"target", observability::sanitized_http_target(request.target), false},
                           {"origin", signed_request->origin,                               false},
                           {"status", std::to_string(federation_response.status),           false}
        });
        auto response_headers = std::vector<std::pair<std::string, std::string>>{};
        if (!federation_response.content_type.empty())
        {
            response_headers.emplace_back("Content-Type", federation_response.content_type);
        }
        return response(federation_response.status, federation_response.body, std::move(response_headers));
    }
    if (request.method == "POST" && request.target == "/_matrix/client/v3/register")
    {
        if (auto const fields = split_pipe_3(request.body); fields.has_value())
        {
            return response_from_operation(register_local_user(runtime, (*fields)[0], (*fields)[1], (*fields)[2]),
                                           200U);
        }
        auto const fields = split_pipe_2(request.body);
        return fields.has_value()
                   ? response_from_operation(register_local_user(runtime, (*fields)[0], (*fields)[1]), 200U)
                   : response(400U, "registration body must be localpart|password[|token]");
    }
    if (request.method == "POST" && request.target == "/_matrix/client/v3/login")
    {
        auto const fields = split_pipe_3(request.body);
        return fields.has_value()
                   ? response_from_operation(login_local_user(runtime, (*fields)[0], (*fields)[1], (*fields)[2]), 200U)
                   : response(400U, "login body must be user_id|password|device_id");
    }
    if (request.method == "POST" && request.target == "/_matrix/client/v3/logout")
    {
        auto result = logout_local_user(runtime, request.access_token);
        return result.ok ? response(200U, "logged out") : response(401U, result.reason);
    }
    if (request.method == "POST" && request.target == "/_matrix/media/v3/upload")
    {
        auto const fields = split_pipe_4(request.body);
        if (!fields.has_value())
        {
            return response(400U, "upload body must be declared_mime|sniffed_mime|scanner_clean|bytes");
        }
        auto const scanner_clean = parse_bool_flag((*fields)[2]);
        if (!scanner_clean.has_value())
        {
            return response(400U, "scanner_clean must be clean or dirty");
        }
        auto const result =
            upload_local_media(runtime, request.access_token, (*fields)[0], (*fields)[1], *scanner_clean, (*fields)[3]);
        return response_from_media_operation(result);
    }
    auto constexpr download_prefix = std::string_view{"/_matrix/media/v3/download/"};
    if (request.method == "GET" && starts_with(request.target, download_prefix))
    {
        auto const parts = local_media_download_parts(path_suffix(request.target, download_prefix));
        if (!parts.has_value())
        {
            return response(404U, "route not found");
        }
        auto const result =
            download_local_media(runtime, (*parts)[0], (*parts)[1], true, remote_media_context(request, runtime));
        return response_from_media_operation(result);
    }
    auto constexpr thumbnail_prefix = std::string_view{"/_matrix/media/v3/thumbnail/"};
    if (request.method == "GET" && starts_with(request.target, thumbnail_prefix))
    {
        auto const parts = local_media_download_parts(path_suffix(request.target, thumbnail_prefix));
        if (!parts.has_value())
        {
            return response(404U, "route not found");
        }
        auto const params = parse_thumbnail_params(request.target);
        auto const result =
            download_local_media_thumbnail(runtime, (*parts)[0], (*parts)[1], params.width, params.height,
                                           params.method, true, remote_media_context(request, runtime));
        return response_from_media_operation(result);
    }
    auto constexpr v1_thumbnail_prefix = std::string_view{"/_matrix/client/v1/media/thumbnail/"};
    if (request.method == "GET" && starts_with(request.target, v1_thumbnail_prefix))
    {
        auto const parts = local_media_download_parts(path_suffix(request.target, v1_thumbnail_prefix));
        if (!parts.has_value())
        {
            return response(404U, "route not found");
        }
        auto const params = parse_thumbnail_params(request.target);
        auto const result =
            download_local_media_thumbnail(runtime, (*parts)[0], (*parts)[1], params.width, params.height,
                                           params.method, false, remote_media_context(request, runtime));
        return response_from_media_operation(result);
    }
    auto constexpr v1_download_prefix = std::string_view{"/_matrix/client/v1/media/download/"};
    if (request.method == "GET" && starts_with(request.target, v1_download_prefix))
    {
        auto const parts = local_media_download_parts(path_suffix(request.target, v1_download_prefix));
        if (!parts.has_value())
        {
            return response(404U, "route not found");
        }
        auto const result =
            download_local_media(runtime, (*parts)[0], (*parts)[1], false, remote_media_context(request, runtime));
        return response_from_media_operation(result);
    }
    auto constexpr quarantine_prefix = std::string_view{"/_merovingian/admin/media/quarantine/"};
    if (request.method == "POST" && starts_with(request.target, quarantine_prefix))
    {
        auto const media_id = admin_media_id_from_suffix(path_suffix(request.target, quarantine_prefix));
        if (!media_id.has_value())
        {
            return response(400U, "invalid media id");
        }
        auto const result = admin_quarantine_local_media(runtime, request.access_token, *media_id, request.body);
        return response_from_media_operation(result);
    }
    auto constexpr release_prefix = std::string_view{"/_merovingian/admin/media/release/"};
    if (request.method == "POST" && starts_with(request.target, release_prefix))
    {
        auto const media_id = admin_media_id_from_suffix(path_suffix(request.target, release_prefix));
        if (!media_id.has_value())
        {
            return response(400U, "invalid media id");
        }
        auto const result = admin_release_local_media(runtime, request.access_token, *media_id);
        return response_from_media_operation(result);
    }
    auto constexpr remove_prefix = std::string_view{"/_merovingian/admin/media/remove/"};
    if (request.method == "POST" && starts_with(request.target, remove_prefix))
    {
        auto const media_id = admin_media_id_from_suffix(path_suffix(request.target, remove_prefix));
        if (!media_id.has_value())
        {
            return response(400U, "invalid media id");
        }
        auto const result = admin_remove_local_media(runtime, request.access_token, *media_id, request.body);
        return response_from_media_operation(result);
    }
    if (request.method == "POST" && request.target == "/_matrix/client/v3/createRoom")
    {
        // create_room self-locks (see room_service.cpp); release this
        // handler's own guard first so it is not double-locked, matching the
        // join_room delegation just above and the equivalent client_server.cpp
        // call sites.
        auto const result = [&] {
            auto const released = RuntimeLockRelease{guard};
            std::ignore = released;
            return create_room(runtime, request.access_token);
        }();
        return result.ok ? response(200U, result.value)
                         : response(result.status != 0U ? result.status : 403U, result.reason);
    }

    auto constexpr rooms_prefix = std::string_view{"/_matrix/client/v3/rooms/"};
    if (!starts_with(request.target, rooms_prefix))
    {
        log_diagnostic("request.route_not_found",
                       {
                           {"method", request.method,                                       false},
                           {"target", observability::sanitized_http_target(request.target), false},
                           {"status", "404",                                                false}
        });
        return response(404U, "route not found");
    }
    auto suffix = std::string_view{request.target}.substr(rooms_prefix.size());
    // Split any query string off the path so the suffix routing below still matches;
    // the join handler reads via/server_name candidate servers from it.
    auto request_query = std::string_view{};
    if (auto const query_start = suffix.find('?'); query_start != std::string_view::npos)
    {
        request_query = suffix.substr(query_start + 1U);
        suffix = suffix.substr(0U, query_start);
    }
    auto constexpr join_suffix = std::string_view{"/join"};
    auto constexpr send_suffix = std::string_view{"/send"};
    auto constexpr state_suffix = std::string_view{"/state"};

    if (request.method == "POST" && suffix.size() > join_suffix.size() &&
        suffix.substr(suffix.size() - join_suffix.size()) == join_suffix)
    {
        auto const room_id = core::percent_decode_path_component(suffix.substr(0U, suffix.size() - join_suffix.size()));
        auto const via_servers = parse_join_via_servers(request_query);
        // Keep a copy of the parsed third_party_signed object alive while
        // join_room uses it. The lambda below only returns a pointer into this
        // local storage, so the optional must outlive the join call.
        auto parsed_signed = std::optional<canonicaljson::Object>{};
        auto const* third_party_signed = [&]() -> canonicaljson::Object const* {
            if (request.body.empty())
            {
                return nullptr;
            }
            auto const parsed = canonicaljson::parse_lossless(request.body);
            if (parsed.error != canonicaljson::ParseError::none)
            {
                return nullptr;
            }
            auto const* obj = std::get_if<canonicaljson::Object>(&parsed.value.storage());
            if (obj == nullptr)
            {
                return nullptr;
            }
            auto const* tps = object_member(*obj, "third_party_signed");
            if (tps == nullptr)
            {
                return nullptr;
            }
            auto const* signed_obj = std::get_if<canonicaljson::Object>(&tps->storage());
            if (signed_obj == nullptr)
            {
                return nullptr;
            }
            parsed_signed = *signed_obj;
            return &*parsed_signed;
        }();
        log_diagnostic("room.join.dispatch",
                       {
                           {"room_id",            room_id,                                          false},
                           {"via_count",          std::to_string(via_servers.size()),               false},
                           {"third_party_signed", third_party_signed == nullptr ? "false" : "true", false}
        });
        auto const result = [&] {
            auto const released = RuntimeLockRelease{guard};
            std::ignore = released;
            return join_room(runtime, request.access_token, room_id, via_servers, third_party_signed);
        }();
        log_diagnostic(result.ok ? "room.join.accepted" : "room.join.rejected",
                       {
                           {"room_id", room_id,                                                    false},
                           {"status",  std::to_string(result.status != 0U ? result.status : 403U), false},
                           {"reason",  result.ok ? std::string{"ok"} : result.reason,              false}
        });
        return result.ok ? response(200U, result.value)
                         : response(result.status != 0U ? result.status : 403U, result.reason);
    }
    if (request.method == "POST" && suffix.size() > send_suffix.size() &&
        suffix.substr(suffix.size() - send_suffix.size()) == send_suffix)
    {
        auto const room_id = core::percent_decode_path_component(suffix.substr(0U, suffix.size() - send_suffix.size()));
        log_diagnostic("room.event.dispatch",
                       {
                           {"room_id",    room_id,                             false},
                           {"body_bytes", std::to_string(request.body.size()), false}
        });
        auto result = send_event(runtime, request.access_token, room_id, request.body);
        log_diagnostic(result.ok ? "room.event.accepted" : "room.event.rejected",
                       {
                           {"room_id", room_id,                                                    false},
                           {"status",  std::to_string(result.status != 0U ? result.status : 403U), false},
                           {"reason",  result.ok ? std::string{"ok"} : result.reason,              false}
        });
        return result.ok ? response(200U, result.value)
                         : response(result.status != 0U ? result.status : 403U, result.reason);
    }
    if (request.method == "GET" && suffix.size() > state_suffix.size() &&
        suffix.substr(suffix.size() - state_suffix.size()) == state_suffix)
    {
        auto const room_id =
            core::percent_decode_path_component(suffix.substr(0U, suffix.size() - state_suffix.size()));
        auto result = fetch_room_state(runtime, request.access_token, room_id);
        return result.ok ? response(200U, result.value)
                         : response(result.status != 0U ? result.status : 403U, result.reason);
    }
    log_diagnostic("request.route_not_found",
                   {
                       {"method", request.method,                                       false},
                       {"target", observability::sanitized_http_target(request.target), false},
                       {"status", "404",                                                false}
    });
    return response(404U, "route not found");
}

[[nodiscard]] auto handle_federation_http_request(HomeserverRuntime& runtime, LocalHttpRequest const& request)
    -> LocalHttpResponse
{
    auto signed_request_opt = std::optional<federation::SignedFederationRequest>{};
    auto held_for_review = false;
    auto blocked_by_local_policy = false;

    {
        auto guard = std::unique_lock<RuntimeMutex>{runtime.mutex};
        if (!runtime.started)
        {
            return response(503U, "runtime not started");
        }
        wire_federation_callbacks_impl(runtime);
        if (request.method == "GET" && request.target.substr(0U, request.target.find('?')) == "/_matrix/key/v2/server")
        {
            return response_from_operation(publish_server_signing_keys(runtime));
        }
        if (request.method == "GET" &&
            request.target.substr(0U, request.target.find('?')) == "/_matrix/federation/v1/openid/userinfo")
        {
            return federation_openid_userinfo_response(runtime, request);
        }
        if (request.method == "GET" && is_federation_version_endpoint(request.target))
        {
            auto const body =
                std::string{"{\"server\":{\"name\":\"Merovingian\",\"version\":\""} + MEROVINGIAN_VERSION + "\"}}";
            return response(200U, body);
        }
        if (!starts_with(request.target, "/_matrix/federation/"))
        {
            return response(404U, "route not found");
        }

        if (request.sig_verified)
        {
            // #323: the main process already verified the X-Matrix signature and
            // forwarded only the verified identity over the authenticated IPC
            // channel. Build the signed request directly from the verified
            // fields (no raw signature crosses IPC) and mark it verified so
            // handle_inbound_federation_request skips the crypto check.
            auto req = federation::SignedFederationRequest{};
            req.method = request.method;
            req.target = request.target;
            req.origin = request.verified_origin;
            // The signed request object binds the destination to this server's
            // own name; the verifier must rebuild the payload with our name,
            // not the (untrusted) header claim, or a request signed for a
            // different server would verify here.
            req.destination = runtime.config.server().server_name;
            req.key_id = request.verified_key_id;
            req.now_ts = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                        std::chrono::system_clock::now().time_since_epoch())
                                                        .count());
            req.canonical_json_verified = true;
            req.signature_verified = true;
            req.body = request.body;
            signed_request_opt = std::move(req);
        }
        else
        {
            auto const x_matrix = federation::parse_x_matrix_authorization_header(request.access_token);
            if (x_matrix.has_value())
            {
                auto req = federation::SignedFederationRequest{};
                req.method = request.method;
                req.target = request.target;
                req.origin = x_matrix->origin;
                // The signed request object binds the destination to this server's
                // own name; the verifier must rebuild the payload with our name,
                // not the (untrusted) header claim, or a request signed for a
                // different server would verify here.
                req.destination = runtime.config.server().server_name;
                req.key_id = x_matrix->key_id;
                req.signature = x_matrix->signature;
                req.now_ts = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                            std::chrono::system_clock::now().time_since_epoch())
                                                            .count());
                req.canonical_json_verified = true;
                req.body = request.body;
                signed_request_opt = std::move(req);
            }
        }
        if (!signed_request_opt.has_value())
        {
            // 502 rather than 401: Synapse propagates 401 from federation
            // responses to the client, triggering an automatic logout. Returning
            // 502 signals a server-side failure instead.
            return response(502U, "malformed federation authorization");
        }

        auto const local_rule = find_policy_rule(runtime, "federation", signed_request_opt->origin);
        held_for_review = local_rule.has_value() && local_rule->action == "quarantine";
        blocked_by_local_policy =
            local_rule.has_value() && local_rule->action != "allow" && local_rule->action != "quarantine";
    }

    // #415: the policy-server hook (when trust_safety.enabled and a
    // policy_server_url is configured) performs a synchronous outbound HTTP
    // call via resolve_policy_server_hook() -> OutboundClient::perform(),
    // which can block for up to policy_server_timeout. It MUST run outside
    // runtime.mutex — that mutex guards runtime.started and most
    // client-server dispatch paths that re-enter the runtime, so holding it
    // across a network call to a slow or unreachable policy server would
    // freeze the entire process, not just federation handling.
    auto const decision = trust_safety::evaluate_federation_policy(
        {signed_request_opt->origin, held_for_review, blocked_by_local_policy,
         resolve_policy_server_hook(runtime, trust_safety::PolicySurface::federation, signed_request_opt->origin)});
    if (!decision.allowed)
    {
        auto const body =
            decision.reason.public_summary.empty() ? decision.reason.code : decision.reason.public_summary;
        return response(403U, body);
    }

    // The federation core protects its own bookkeeping, and production
    // callbacks re-enter HomeserverRuntime with narrower locks. Holding the
    // global runtime mutex here would serialize whole /send transactions.
    auto const federation_response =
        federation::handle_inbound_federation_request(runtime.federation, *signed_request_opt);
    auto response_headers = std::vector<std::pair<std::string, std::string>>{};
    if (!federation_response.content_type.empty())
    {
        response_headers.emplace_back("Content-Type", federation_response.content_type);
    }
    return response(federation_response.status, federation_response.body, std::move(response_headers));
}

} // namespace merovingian::homeserver
