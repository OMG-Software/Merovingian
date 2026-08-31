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
#include "merovingian/federation/event_query.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/key_query.hpp"
#include "merovingian/federation/outbound_transaction.hpp"
#include "merovingian/federation/remote_key_cache.hpp"
#include "merovingian/federation/server_acl.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/media_service.hpp"
#include "merovingian/homeserver/request_lock.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/runtime_signing_key_store.hpp"
#include "merovingian/homeserver/space_hierarchy.hpp"
#include "merovingian/media/repository.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/rooms/room_version_policy.hpp"
#include "merovingian/trust_safety/policy_engine.hpp"

#include <algorithm>
#include <array>
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

    // Builds the auth-event map for an inbound federated PDU from the room's
    // currently resolved state. Mirrors the same logic used in room_service.cpp
    // for locally-created events so both paths apply identical auth rules.
    // Spec: SS API §authorization-rules — receivers MUST check auth before persisting.
    [[nodiscard]] auto build_pdu_auth_event_map(database::PersistentStore const& store, std::string_view room_id,
                                                std::string_view sender, std::string_view target_state_key,
                                                std::string_view event_type,
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
        for (auto const& state : store.state)
        {
            if (state.room_id != room_id)
            {
                continue;
            }
            if (state.event_type == "m.room.create" && state.state_key.empty())
            {
                result.create = load(state.event_id);
            }
            else if (state.event_type == "m.room.power_levels" && state.state_key.empty())
            {
                result.power_levels = load(state.event_id);
            }
            else if (state.event_type == "m.room.join_rules" && state.state_key.empty())
            {
                result.join_rules = load(state.event_id);
            }
            else if (state.event_type == "m.room.member" && state.state_key == sender)
            {
                result.sender_member = load(state.event_id);
            }
            else if (state.event_type == "m.room.member" && event_type == "m.room.member" &&
                     state.state_key == target_state_key)
            {
                result.target_member = load(state.event_id);
            }
            else if (state.event_type == "m.room.third_party_invite" && !third_party_invite_token.empty() &&
                     state.state_key == third_party_invite_token)
            {
                result.third_party_invite = load(state.event_id);
            }
        }
        return result;
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
        return response(result.status, result.ok ? result.value : result.reason);
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
            auto const keys_it =
                std::ranges::find_if(store.device_keys, [&device, user_id](database::PersistentDeviceKey const& keys) {
                    return keys.user_id == user_id && keys.device_id == device.device_id;
                });
            if (keys_it == store.device_keys.end())
            {
                continue;
            }
            auto const parsed_keys = canonicaljson::parse_lossless(keys_it->json);
            if (parsed_keys.error != canonicaljson::ParseError::none)
            {
                continue;
            }
            auto content_obj = canonicaljson::Object{};
            content_obj.push_back(canonicaljson::make_member("device_id", canonicaljson::Value{device.device_id}));
            content_obj.push_back(canonicaljson::make_member("keys", parsed_keys.value));
            content_obj.push_back(canonicaljson::make_member("prev_id", canonicaljson::Value{canonicaljson::Array{}}));
            content_obj.push_back(
                canonicaljson::make_member("stream_id", canonicaljson::Value{static_cast<std::int64_t>(stream_id)}));
            content_obj.push_back(canonicaljson::make_member("user_id", canonicaljson::Value{std::string{user_id}}));
            auto const content = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(content_obj)});
            if (content.error != canonicaljson::CanonicalJsonError::none)
            {
                continue;
            }
            auto const tx_body = federation::build_edu_transaction_body(runtime.config.server().server_name,
                                                                        "m.device_list_update", content.output);
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

    [[nodiscard]] auto sign_invite_event(HomeserverRuntime& runtime, canonicaljson::Value const& event_value,
                                         std::string_view room_version) -> std::optional<std::string>
    {
        // Use the active key record without loading the signing secret. In the main
        // process the secret is held by runtime.crypto_provider; in the federation
        // worker it is held by the main process and reached via IPC.
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
    [[nodiscard]] auto parse_signed_federation_request(LocalHttpRequest const& request)
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

    // Outcome of a direct_to_device enqueue attempt. `targeted` counts every
    // per-device entry that was well-formed enough to attempt a store;
    // `stored` counts how many of those actually persisted. The two can
    // diverge on a store-layer rejection (e.g. an empty sender/device id) or
    // a backend write failure — callers must not treat targeted > 0 as proof
    // that the key share reached the recipient's queue (#464).
    struct DirectToDeviceEnqueueResult final
    {
        std::size_t targeted{0U};
        std::size_t stored{0U};
    };

    auto enqueue_direct_to_device_messages(HomeserverRuntime& runtime, std::string_view content_json)
        -> DirectToDeviceEnqueueResult
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

        for (auto const& user_entry : *messages)
        {
            auto const* device_map = std::get_if<canonicaljson::Object>(&user_entry.value->storage());
            if (device_map == nullptr)
            {
                continue;
            }
            for (auto const& device_entry : *device_map)
            {
                if (device_entry.value == nullptr)
                {
                    continue;
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
                    for (auto const& receipt_type_member : *receipt_types)
                    {
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
                auto const enqueue_result = enqueue_direct_to_device_messages(*rt, envelope.content_json);
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
            case federation::EduType::device_list_update: {
                auto const parsed = canonicaljson::parse_lossless(envelope.content_json);
                auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
                if (parsed.error != canonicaljson::ParseError::none || root == nullptr)
                {
                    return {federation::EduDispositionStatus::rejected_invalid,
                            "device list update content must be an object"};
                }
                auto const* user_id = object_member_as_string(*root, "user_id");
                if (user_id == nullptr || !user_belongs_to_origin(*user_id, envelope.origin))
                {
                    return {federation::EduDispositionStatus::rejected_invalid,
                            "device list update user_id must belong to the sending origin"};
                }
                if (!user_id->empty())
                {
                    // Record for all local users who may need to re-fetch keys
                    for (auto const& user : rt->database.persistent_store.users)
                    {
                        auto change = database::PersistentDeviceListChange{};
                        change.observer_user_id = user.user_id;
                        change.subject_user_id = *user_id;
                        change.change_type = "changed";
                        std::ignore =
                            database::record_device_list_change(rt->database.persistent_store, std::move(change));
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

        runtime.federation.state_conflict_resolver =
            [rt](federation::PduStateConflictContext const& context) -> federation::PduIngestionResult {
            return federation::apply_state_resolution_v2(
                context,
                [rt, room_id = context.incoming_pdu.room_id](
                    std::vector<events::StateEventReference> const& resolved) -> bool {
                    for (auto const& ref : resolved)
                    {
                        if (!database::store_state(rt->database.persistent_store,
                                                   {room_id, ref.key.event_type, ref.key.state_key, ref.event_id}))
                        {
                            return false;
                        }
                    }
                    return true;
                });
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
            // Populate auth_events: m.room.join_rules, m.room.power_levels, and
            // the joining user's current membership (e.g. their invite event).
            // For room versions < 12, m.room.create is also included per spec.
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
                    s.event_type == "m.room.join_rules" || s.event_type == "m.room.power_levels" ||
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
            auto& store = rt->database.persistent_store;
            auto const room_it = std::ranges::find_if(store.rooms, [&room_id](database::PersistentRoom const& r) {
                return r.room_id == room_id;
            });
            if (room_it == store.rooms.end())
            {
                return {false, 404U, "room not found", {}, {}};
            }
            auto event = database::PersistentEvent{};
            event.event_id = envelope.event_id;
            event.room_id = envelope.room_id;
            event.sender_user_id = envelope.sender;
            event.json = envelope.json;
            event.depth = envelope.depth;
            event.stream_ordering = allocate_stream_ordering(rt->database);
            event.auth_event_ids = envelope.auth_event_ids;
            auto const event_stream_ordering = event.stream_ordering;
            auto state = std::optional<database::PersistentStateEvent>{};
            if (envelope.state_key.has_value())
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
            if (!database::store_event_with_state(store, std::move(event), state))
            {
                return {false, 500U, "event persistence failed", {}, {}};
            }
            auto membership_changed = false;
            if (envelope.event_type == "m.room.member" && envelope.state_key.has_value())
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
            // Store the invite event in the persistent event graph so it is
            // reachable during auth-chain BFS walks on subsequent send_join
            // calls for this user. Without this, make_join cannot include it
            // in auth_events and send_join cannot return it in the auth_chain.
            {
                auto invite_pdu = database::PersistentEvent{};
                invite_pdu.event_id = invite.event_id;
                invite_pdu.room_id = invite.room_id;
                invite_pdu.sender_user_id = *sender;
                invite_pdu.json = *signed_event;
                invite_pdu.stream_ordering = stream_ordering;
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
            auto const& store = rt->database.persistent_store;
            auto pdus = federation::build_backfill_pdus(store, req.room_id, req.event_ids, req.limit);
            return {true, 200U, {}, std::move(pdus)};
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

        runtime.federation.event_query_provider = [rt](std::string_view event_id) -> std::string {
            return federation::build_event_response(rt->database.persistent_store, event_id,
                                                    rt->config.server().server_name);
        };

        runtime.federation.state_query_provider = [rt](std::string_view room_id,
                                                       std::string_view event_id) -> std::string {
            return federation::build_state_response(rt->database.persistent_store, room_id, event_id);
        };

        runtime.federation.state_ids_query_provider = [rt](std::string_view room_id,
                                                           std::string_view event_id) -> std::string {
            return federation::build_state_ids_response(rt->database.persistent_store, room_id, event_id);
        };

        runtime.federation.missing_events_query_provider = [rt](std::string_view room_id,
                                                                std::string_view body) -> std::string {
            return federation::build_get_missing_events_response(rt->database.persistent_store, room_id, body);
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
            if (cached != nullptr)
            {
                runtime.federation.remote_key_resolver = federation::make_persistent_remote_key_resolver(
                    runtime.database.persistent_store, *outbound, *cached, timeout, key_clock);
            }
            else
            {
                runtime.federation.remote_key_resolver = federation::make_persistent_remote_key_resolver(
                    runtime.database.persistent_store, *outbound, *discovery, timeout, key_clock);
            }
            auto key = ensure_runtime_server_signing_key(runtime);
            auto constexpr expected_secret_bytes = crypto::Ed25519Keypair{}.secret_key.size();
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

// #450 TRUST BOUNDARY: this function (main's pdu_sink) re-checks
// authorization and content-hash integrity below, but it does NOT
// independently re-verify the PDU's Ed25519 signature against the sender's
// published key — that already happened once, before this ever runs, at
// federation::authorize_federation_pdu() (inbound_request.cpp) using a
// remote_key_resolver-fetched key. Whether this call came directly from the
// same-process federation path or was relayed from the federation worker
// over IPC (see worker_pool.cpp's pdu_ingest handler), main trusts that
// prior verification rather than repeating it. See docs/threat-model.md,
// "Main does not re-verify PDU Ed25519 signatures before persisting" for the
// accepted-risk rationale (worker cannot forge peer identity, holds no
// signing secret; re-verifying here would need the raw PDU + a
// main-side-resolved key, a larger shape change than this LOW-severity gap
// warrants).
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

    // Reserve the global stream-ordering and sync-surface IDs up front under
    // the global mutex. Allocating sync_stream_id writes to the backend, so it
    // must not happen while a room stripe is also held — that would pin the
    // stripe for the whole database write and prevent concurrent progress on
    // unrelated rooms.
    auto const [stream_ordering, sync_stream_id] = [&]() {
        auto global_guard = std::unique_lock<std::recursive_mutex>{runtime.mutex};
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
    auto global_guard = std::unique_lock<std::recursive_mutex>{runtime.mutex};

    auto const third_party_invite_token = [&]() -> std::string {
        auto const* pdu_obj = std::get_if<canonicaljson::Object>(&pdu_parsed.value.storage());
        auto const* content = pdu_obj == nullptr ? nullptr : object_member_as_object(*pdu_obj, "content");
        auto const* third_party_invite =
            content == nullptr ? nullptr : object_member_as_object(*content, "third_party_invite");
        auto const* signed_obj =
            third_party_invite == nullptr ? nullptr : object_member_as_object(*third_party_invite, "signed");
        auto const* token = signed_obj == nullptr ? nullptr : string_member(*signed_obj, "token");
        return token == nullptr ? std::string{} : *token;
    }();
    auto const auth_map = build_pdu_auth_event_map(runtime.database.persistent_store, room_id, envelope.sender,
                                                   envelope.state_key.value_or(std::string{}), envelope.event_type,
                                                   third_party_invite_token);
    auto const auth_decision = events::authorize_event_against_auth_events(pdu_parsed.value, *room_policy, auth_map);
    if (!auth_decision.allowed)
    {
        return {federation::PduIngestionStatus::rejected_auth,
                std::string{"event auth denied: "} + auth_decision.reason};
    }

    if (!events::verify_pdu_content_hash(pdu_parsed.value))
    {
        return {federation::PduIngestionStatus::rejected_invalid, "bad content hash"};
    }

    auto state = std::optional<database::PersistentStateEvent>{};
    if (envelope.state_key.has_value())
    {
        state = database::PersistentStateEvent{room_id, envelope.event_type, *envelope.state_key, envelope.event_id};
    }

    auto event = database::PersistentEvent{};
    event.event_id = envelope.event_id;
    event.room_id = room_id;
    event.sender_user_id = envelope.sender;
    event.json = envelope.json;
    event.depth = envelope.depth;
    event.stream_ordering = stream_ordering;
    event.prev_event_ids = envelope.prev_event_ids;
    event.auth_event_ids = envelope.auth_event_ids;
    event.signatures = envelope.signatures;

    auto prepared =
        database::prepare_store_event_with_state(runtime.database.persistent_store, std::move(event), state);
    if (!prepared.has_value())
    {
        return {federation::PduIngestionStatus::internal_error, "event persistence pre-check failed"};
    }

    // Release only the global mutex for the backend commit. Independent rooms
    // can now commit concurrently (each still holds its own stripe), while the
    // in-memory store stays protected against concurrent reads/writes.
    global_guard.unlock();
    if (!database::commit_persistent_transaction(runtime.database.persistent_store, prepared->statements))
    {
        return {federation::PduIngestionStatus::internal_error, "event persistence backend rejected transaction"};
    }
    global_guard.lock();

    database::apply_store_event_with_state(runtime.database.persistent_store, *prepared);

    auto result = federation::PduIngestionResult{};
    result.status = federation::PduIngestionStatus::accepted;
    result.accepted_stream_ordering = stream_ordering;
    result.accepted_sync_stream_id = sync_stream_id;

    if (envelope.event_type == "m.room.member" && envelope.state_key.has_value())
    {
        auto const* mem_obj = std::get_if<canonicaljson::Object>(&pdu_parsed.value.storage());
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

auto wire_federation_callbacks(HomeserverRuntime& runtime) -> void
{
    wire_federation_callbacks_impl(runtime);
}

[[nodiscard]] auto handle_local_http_request(HomeserverRuntime& runtime, LocalHttpRequest const& request)
    -> LocalHttpResponse
{
    auto guard = std::unique_lock<std::recursive_mutex>{runtime.mutex};
    // Publish the guard so a blocking network call further down the stack —
    // notably a remote media fetch — can release it for the duration. See
    // NetworkIoUnlock in request_lock.hpp.
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
        auto signed_request = parse_signed_federation_request(request);
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
        auto const result = download_local_media(runtime, (*parts)[0], (*parts)[1]);
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
        auto const result = download_local_media_thumbnail(runtime, (*parts)[0], (*parts)[1], params.width,
                                                           params.height, params.method);
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
        auto const result = download_local_media_thumbnail(runtime, (*parts)[0], (*parts)[1], params.width,
                                                           params.height, params.method);
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
        auto const result = download_local_media(runtime, (*parts)[0], (*parts)[1]);
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
        guard.unlock();
        auto result = create_room(runtime, request.access_token);
        guard.lock();
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
        guard.unlock();
        auto result = join_room(runtime, request.access_token, room_id, via_servers, third_party_signed);
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
        auto guard = std::unique_lock<std::recursive_mutex>{runtime.mutex};
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
