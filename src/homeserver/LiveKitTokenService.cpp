// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/homeserver/LiveKitTokenService.hpp"

#include "merovingian/auth/Identity.hpp"
#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/config/LiveKitTokenServiceConfig.hpp"
#include "merovingian/core/SecretBuffer.hpp"
#include "merovingian/crypto/LiveKitParticipantGrant.hpp"
#include "merovingian/crypto/LiveKitToken.hpp"
#include "merovingian/database/PersistentMembership.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/federation/OutboundTransactionSupport.hpp"
#include "merovingian/homeserver/BoundedOutboundLimits.hpp"
#include "merovingian/homeserver/ClientOutboundProxy.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LiveKitNames.hpp"
#include "merovingian/homeserver/LiveKitRoomService.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"
#include "merovingian/homeserver/OutboundAnswerTrust.hpp"
#include "merovingian/homeserver/OutboundCallResult.hpp"
#include "merovingian/homeserver/OutboundDeadline.hpp"
#include "merovingian/homeserver/RoomResidency.hpp"
#include "merovingian/homeserver/RoomService.hpp"
#include "merovingian/homeserver/RuntimeLockRelease.hpp"
#include "merovingian/http/OutboundError.hpp"
#include "merovingian/http/OutboundResult.hpp"
#include "merovingian/observability/LogEventSeverity.hpp"
#include "merovingian/observability/SingleLog.hpp"
#include "merovingian/observability/StructuredLogField.hpp"
#include "merovingian/platform/FileMetadataSupport.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>
#include <variant>

namespace merovingian::homeserver
{
namespace
{

    constexpr auto log_module = std::string_view{"livekit"};
    // The API secret's file is read up to this size, first line only (`platform::read_secure_secret_line`).
    constexpr auto max_livekit_secret_file_bytes = std::size_t{4096U};
    // The budget for the one call to LiveKit a token costs, before the operator's `remote_timeout` clamps it.
    constexpr auto livekit_call_deadline_seconds = std::uint32_t{10U};

    [[nodiscard]] auto refusal(std::uint16_t const status, std::string errcode, std::string reason) -> OperationResult
    {
        auto result = OperationResult{};
        result.ok = false;
        result.status = status;
        result.errcode = std::move(errcode);
        result.reason = std::move(reason);
        return result;
    }

    [[nodiscard]] auto member_of(canonicaljson::Object const& object, std::string_view const key)
        -> canonicaljson::Value const*
    {
        for (auto const& member : object)
        {
            if (member.key == key && member.value != nullptr)
            {
                return member.value.get();
            }
        }
        return nullptr;
    }

    // A required string member of at most `max_bytes` bytes, at least one, valid for JSON, copied into `out`. A missing
    // member is `M_MISSING_PARAM`, anything else wrong `M_INVALID_PARAM`; neither echoes the value.
    [[nodiscard]] auto read_required_string(canonicaljson::Object const& object, std::string_view const key,
                                            std::size_t const max_bytes, std::string& out)
        -> std::optional<OperationResult>
    {
        auto const* value = member_of(object, key);
        if (value == nullptr)
        {
            return refusal(400U, "M_MISSING_PARAM", std::string{key} + " is required");
        }
        auto const* text = std::get_if<std::string>(&value->storage());
        if (text == nullptr || text->empty() || text->size() > max_bytes ||
            !canonicaljson::string_is_valid_for_json(*text))
        {
            return refusal(400U, "M_INVALID_PARAM", std::string{key} + " is not valid");
        }
        out = *text;
        return std::nullopt;
    }

    // The required members. `room_id` is held to the shape of a room ID; it is only ever looked up exactly.
    [[nodiscard]] auto read_required_members(canonicaljson::Object const& object, LiveKitTokenRequest& request)
        -> std::optional<OperationResult>
    {
        if (auto refused = read_required_string(object, "url", max_livekit_url_bytes, request.url))
        {
            return refused;
        }
        if (auto refused = read_required_string(object, "room_id", max_livekit_room_id_bytes, request.room_id))
        {
            return refused;
        }
        if (!request.room_id.starts_with('!'))
        {
            return refusal(400U, "M_INVALID_PARAM", "room_id is not valid");
        }
        if (auto refused = read_required_string(object, "slot_id", max_livekit_slot_id_bytes, request.slot_id))
        {
            return refused;
        }
        return read_required_string(object, "member_id", max_livekit_member_id_bytes, request.member_id);
    }

    [[nodiscard]] auto now_seconds() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    }

    auto log_refusal(std::string_view const event, std::string_view const user_id, std::string_view const room_id,
                     std::string_view const reason,
                     observability::LogEventSeverity const severity = observability::LogEventSeverity::info) -> void
    {
        // Never the token, the secret, the slot or the member ID (which carries a device ID).
        observability::log_diagnostic(log_module, event,
                                      {
                                          {"user_id", std::string{user_id}, false},
                                          {"room_id", std::string{room_id}, false},
                                          {"reason",  std::string{reason},  false},
        },
                                      severity);
    }

} // namespace

auto parse_client_livekit_token_request(std::string_view const body) -> LiveKitTokenRequestResult
{
    auto const parsed = canonicaljson::parse_json(body);
    auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
    if (parsed.error != canonicaljson::ParseError::none || object == nullptr)
    {
        return refusal(400U, "M_BAD_JSON", "the body must be a JSON object");
    }
    auto request = LiveKitTokenRequest{};
    if (auto refused = read_required_members(*object, request))
    {
        return std::move(*refused);
    }
    if (auto const* server_name = member_of(*object, "server_name"); server_name != nullptr)
    {
        auto const* text = std::get_if<std::string>(&server_name->storage());
        if (text == nullptr || !auth::server_name_is_valid(*text))
        {
            return refusal(400U, "M_INVALID_PARAM", "server_name is not valid");
        }
        request.server_name = *text;
    }
    return request;
}

namespace
{

    [[nodiscard]] auto jwt_answer(std::string token) -> OperationResult
    {
        auto result = OperationResult{};
        result.ok = true;
        result.status = 200U;
        result.value =
            canonicaljson::serialize_canonical(canonicaljson::Value{canonicaljson::Object{canonicaljson::make_member(
                                                   "jwt", canonicaljson::Value{std::move(token)})}})
                .output;
        return result;
    }

    // A participant token for `identity` in `room_name`, signed with the API secret read for this one token. When the
    // caller publishes, also the `CreateRoom` request, signed with the same read of the secret. nullopt (and an error
    // log naming no secret) when the file cannot be read, the secret is too short, or the API URL is unusable.
    struct SignedToken final
    {
        std::string token;
        std::optional<http::OutboundRequest> create_room;
    };

    [[nodiscard]] auto sign_for(config::LiveKitTokenServiceConfig const& service, std::string const& identity,
                                std::string const& room_name, bool const can_publish, std::string_view const user_id,
                                std::string_view const room_id) -> std::optional<SignedToken>
    {
        // The secret is read for this token into locked memory that wipes itself, and is gone before the response.
        auto const secret = platform::read_secure_secret_line(service.api_secret_file, max_livekit_secret_file_bytes);
        auto const now = now_seconds();
        auto signed_token = std::optional<SignedToken>{};
        if (secret.has_value())
        {
            auto token = crypto::sign_livekit_participant_token(
                service.api_key, secret->bytes(),
                crypto::LiveKitParticipantGrant{.identity = identity,
                                                .room = room_name,
                                                .can_publish = can_publish,
                                                .not_before = now,
                                                .expires =
                                                    now + static_cast<std::int64_t>(service.token_lifetime_seconds)});
            auto create_room = can_publish ? livekit_create_room_request(service.api_url, service.api_key,
                                                                         secret->bytes(), room_name, now)
                                           : std::nullopt;
            if (token.has_value() && (!can_publish || create_room.has_value()))
            {
                signed_token = SignedToken{std::move(*token), std::move(create_room)};
            }
        }
        if (!signed_token.has_value())
        {
            log_refusal("livekit.secret_unavailable", user_id, room_id,
                        "the API secret file is unreadable, too short, or the API URL is unusable",
                        observability::LogEventSeverity::error);
        }
        return signed_token;
    }

    [[nodiscard]] auto client_outbound_refusal(ClientServerRuntime& rt) -> OperationResult
    {
        auto limited = refusal(429U, "M_LIMIT_EXCEEDED", "too many concurrent outbound requests, retry shortly");
        limited.retry_after_ms = rt.homeserver.client_outbound_proxy_policy.retry_after_ms;
        return limited;
    }

    // A `jwt` another server returned: what LiveKit accepts and nothing more, three non-empty base64url segments of
    // at most `hs256_token_max_bytes` in all. Its contents are the other server's to vouch for; this server neither
    // reads nor trusts them, and passes only this string on.
    [[nodiscard]] auto relayed_jwt_is_well_formed(std::string_view const jwt) -> bool
    {
        if (jwt.empty() || jwt.size() > crypto::hs256_token_max_bytes)
        {
            return false;
        }
        auto segments = 1U;
        auto segment_length = std::size_t{0U};
        for (auto const c : jwt)
        {
            if (c == '.')
            {
                if (segment_length == 0U)
                {
                    return false;
                }
                ++segments;
                segment_length = 0U;
                continue;
            }
            auto const is_base64url =
                (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!is_base64url)
            {
                return false;
            }
            ++segment_length;
        }
        return segments == 3U && segment_length != 0U;
    }

    // MSC4195: a client asks for a token for another server's SFU (`server_name` is not ours). The caller is joined
    // here (checked before), and the named server must have a member joined by this server's state; then the request
    // goes to that server over signed federation, under an ADR-0079 slot and one deadline, with runtime.mutex released
    // for the call only (ADR-0831). Its 403 `M_FORBIDDEN` and 400 `M_INVALID_PARAM` are relayed, with this server's own
    // text; anything else is 502 `M_UNKNOWN`. Only a well-formed `jwt` string is taken from the answer.
    [[nodiscard]] auto relay_client_livekit_token(ClientServerRuntime& rt, LocalHttpRequest const& req,
                                                  std::string const& user_id, LiveKitTokenRequest const& request,
                                                  RuntimeLock& guard) -> OperationResult
    {
        auto const* room = find_local_room(rt.homeserver.database, request.room_id);
        if (room == nullptr || !room->members.has_member_of_server(request.server_name))
        {
            log_refusal("livekit.relay.refused", user_id, request.room_id, "server not in room");
            return refusal(403U, "M_FORBIDDEN", "That server is not in this room.");
        }
        if (rt.homeserver.outbound_client == nullptr || rt.homeserver.cached_discovery == nullptr)
        {
            return refusal(502U, "M_UNKNOWN", "this server cannot make outbound requests");
        }
        auto const slot =
            admit_client_outbound_proxy(rt.homeserver, rate_limit_client_key(req, rt.homeserver.config.server()));
        if (!slot.has_value())
        {
            return client_outbound_refusal(rt);
        }
        auto const deadline = effective_client_outbound_deadline(rt.homeserver, livekit_call_deadline_seconds);
        wire_federation_callbacks(rt.homeserver);
        auto const signing_key = ensure_runtime_server_signing_key(rt.homeserver);
        if (!signing_key.has_value())
        {
            return refusal(500U, "M_UNKNOWN", "this server cannot sign federation requests");
        }
        // The MSC4195 federation body: the client's, with `server_name` dropped and the requesting user added.
        auto members = canonicaljson::Object{};
        members.push_back(canonicaljson::make_member("member_id", canonicaljson::Value{request.member_id}));
        members.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{request.room_id}));
        members.push_back(canonicaljson::make_member("slot_id", canonicaljson::Value{request.slot_id}));
        members.push_back(canonicaljson::make_member("url", canonicaljson::Value{request.url}));
        members.push_back(canonicaljson::make_member("user_id", canonicaljson::Value{user_id}));
        auto const body = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(members)});
        if (body.error != canonicaljson::CanonicalJsonError::none)
        {
            return refusal(500U, "M_UNKNOWN", "the request to the other server cannot be written");
        }
        auto const transaction =
            federation::make_outbound_transaction(request.server_name, "POST", federation_livekit_token_path,
                                                  rt.homeserver.config.server().server_name, body.output);
        auto secret = core::SecretBuffer{rt.homeserver.database.signing_secret_key.bytes()};
        auto const limits = std::optional<BoundedOutboundLimits>{
            BoundedOutboundLimits{
                                  OutboundDeadline{deadline},
                                  std::chrono::seconds{rt.homeserver.client_outbound_proxy_policy.worker_margin_seconds}}
        };
        auto const answer = [&] {
            auto const released = RuntimeLockRelease{guard};
            return perform_outbound_call(rt.homeserver, OutboundAnswerTrust::unverified, {}, transaction,
                                         signing_key->key_id, std::move(secret), "livekit.relay", deadline,
                                         livekit_relay_response_max_bytes, limits);
        }();
        if (!answer.ok)
        {
            if (answer.remote_status == 403U && answer.remote_errcode == "M_FORBIDDEN")
            {
                log_refusal("livekit.relay.refused", user_id, request.room_id, "the other server refused");
                return refusal(403U, "M_FORBIDDEN", "The other server refused to issue a token.");
            }
            if (answer.remote_status == 400U && answer.remote_errcode == "M_INVALID_PARAM")
            {
                log_refusal("livekit.relay.refused", user_id, request.room_id, "the other server found it invalid");
                return refusal(400U, "M_INVALID_PARAM", "The other server found the request invalid.");
            }
            log_refusal("livekit.relay.failed", user_id, request.room_id,
                        answer.remote_answered ? "status " + std::to_string(answer.remote_status) : "unreachable",
                        observability::LogEventSeverity::warning);
            return refusal(502U, "M_UNKNOWN", "The other server could not issue a token.");
        }
        auto const parsed = canonicaljson::parse_json(answer.body);
        auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        auto const* jwt_value = object == nullptr ? nullptr : member_of(*object, "jwt");
        auto const* jwt = jwt_value == nullptr ? nullptr : std::get_if<std::string>(&jwt_value->storage());
        if (parsed.error != canonicaljson::ParseError::none || jwt == nullptr || !relayed_jwt_is_well_formed(*jwt))
        {
            log_refusal("livekit.relay.failed", user_id, request.room_id, "malformed answer",
                        observability::LogEventSeverity::warning);
            return refusal(502U, "M_UNKNOWN", "The other server could not issue a token.");
        }
        observability::log_diagnostic(log_module, "livekit.relay.issued",
                                      {
                                          {"user_id",     user_id,             false},
                                          {"room_id",     request.room_id,     false},
                                          {"server_name", request.server_name, false},
        },
                                      observability::LogEventSeverity::info);
        return jwt_answer(*jwt);
    }

    // The federation body: the client form's members without `server_name`, plus `user_id`.
    [[nodiscard]] auto parse_federation_request(std::string_view const body, std::string_view const our_server)
        -> LiveKitTokenRequestResult
    {
        auto const parsed = canonicaljson::parse_json(body);
        auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (parsed.error != canonicaljson::ParseError::none || object == nullptr)
        {
            return refusal(400U, "M_BAD_JSON", "the body must be a JSON object");
        }
        auto request = LiveKitTokenRequest{};
        if (auto refused = read_required_members(*object, request))
        {
            return std::move(*refused);
        }
        if (auto refused = read_required_string(*object, "user_id", max_livekit_user_id_bytes, request.user_id))
        {
            return std::move(*refused);
        }
        if (!auth::user_id_is_valid_federated(request.user_id))
        {
            return refusal(400U, "M_INVALID_PARAM", "user_id is not valid");
        }
        // MSC4195 omits `server_name` here, since it is the receiving server's own. One that names another is refused.
        if (auto const* server_name = member_of(*object, "server_name"); server_name != nullptr)
        {
            auto const* text = std::get_if<std::string>(&server_name->storage());
            if (text == nullptr || *text != our_server)
            {
                return refusal(400U, "M_INVALID_PARAM", "server_name is not this server");
            }
        }
        return request;
    }

} // namespace

auto issue_client_livekit_token(ClientServerRuntime& rt, LocalHttpRequest const& req, std::string const& user_id,
                                RuntimeLock& guard) -> OperationResult
{
    auto const& service = rt.homeserver.config.server().rtc.token_service;
    if (service.url.empty())
    {
        return refusal(404U, "M_UNRECOGNIZED", "no LiveKit token service is configured");
    }
    auto parsed = parse_client_livekit_token_request(req.body);
    if (auto* refused = std::get_if<OperationResult>(&parsed); refused != nullptr)
    {
        return std::move(*refused);
    }
    auto request = std::get<LiveKitTokenRequest>(std::move(parsed));
    auto const& our_server = rt.homeserver.config.server().server_name;
    auto const remote = !request.server_name.empty() && request.server_name != our_server;
    // MSC4195: for this server's own SFU, a `url` that is not it is 400 M_INVALID_PARAM. It is compared byte for byte
    // and never fetched. Another server's `url` is that server's to judge.
    if (!remote && request.url != service.url)
    {
        return refusal(400U, "M_INVALID_PARAM", "url is not this server's SFU");
    }
    // Joined by this server's own current state: the membership row moves with every accepted member event, in the
    // same transaction. An unknown room and a room the user is not joined to are the same answer.
    auto const* membership =
        database::find_membership_row(rt.homeserver.database.persistent_store, request.room_id, user_id);
    if (membership == nullptr || membership->membership != "join")
    {
        log_refusal("livekit.token.refused", user_id, request.room_id, "not joined");
        return refusal(403U, "M_FORBIDDEN", "You are not joined to this room.");
    }
    if (remote)
    {
        return relay_client_livekit_token(rt, req, user_id, request, guard);
    }
    auto const room_name = livekit_room_name(request.room_id, request.slot_id);
    auto const identity = livekit_participant_identity(user_id, request.member_id);
    if (!room_name.has_value() || !identity.has_value())
    {
        return refusal(400U, "M_INVALID_PARAM", "the room or member cannot be named");
    }
    auto signed_token = sign_for(service, *identity, *room_name, true, user_id, request.room_id);
    if (!signed_token.has_value())
    {
        return refusal(500U, "M_UNKNOWN", "LiveKit tokens are unavailable");
    }

    // MSC4195: the room is created before a publishing token is issued, so an SFU that does not create rooms on
    // join still admits the caller. This is a call to another server: an ADR-0079 slot first, one deadline, and
    // runtime.mutex released around the call only.
    if (rt.homeserver.outbound_client == nullptr || rt.homeserver.cached_discovery == nullptr)
    {
        return refusal(502U, "M_UNKNOWN", "this server cannot make outbound requests");
    }
    auto const slot =
        admit_client_outbound_proxy(rt.homeserver, rate_limit_client_key(req, rt.homeserver.config.server()));
    if (!slot.has_value())
    {
        return client_outbound_refusal(rt);
    }
    auto const deadline = effective_client_outbound_deadline(rt.homeserver, livekit_call_deadline_seconds);
    auto& client = *rt.homeserver.outbound_client;
    auto& discovery = *rt.homeserver.cached_discovery;
    auto const test_perform = rt.homeserver.test_livekit_perform;
    auto const created = [&] {
        auto const released = RuntimeLockRelease{guard};
        return perform_livekit_request(std::move(*signed_token->create_room), client, discovery, deadline,
                                       test_perform);
    }();
    if (!created.ok || created.response.status != 200U)
    {
        log_refusal("livekit.create_room_failed", user_id, request.room_id,
                    created.ok ? "status " + std::to_string(created.response.status)
                               : std::string{http::outbound_error_name(created.error)},
                    observability::LogEventSeverity::warning);
        return refusal(502U, "M_UNKNOWN", "the SFU could not be reached");
    }
    observability::log_diagnostic(log_module, "livekit.token.issued",
                                  {
                                      {"user_id", user_id,         false},
                                      {"room_id", request.room_id, false},
    },
                                  observability::LogEventSeverity::info);
    return jwt_answer(std::move(signed_token->token));
}

auto issue_federation_livekit_token(HomeserverRuntime& runtime, std::string_view const origin,
                                    std::string_view const body) -> OperationResult
{
    auto const& service = runtime.config.server().rtc.token_service;
    if (service.url.empty())
    {
        return refusal(404U, "M_UNRECOGNIZED", "no LiveKit token service is configured");
    }
    auto const& our_server = runtime.config.server().server_name;
    auto parsed = parse_federation_request(body, our_server);
    if (auto* refused = std::get_if<OperationResult>(&parsed); refused != nullptr)
    {
        return std::move(*refused);
    }
    auto const& request = std::get<LiveKitTokenRequest>(parsed);
    auto const& store = runtime.database.persistent_store;
    // MSC4195, in its order: this server joined to the room, the user of the origin, the user joined; each 403
    // M_FORBIDDEN with one text, so the answer tells a server nothing about a room it has no member in. All judged by
    // this server's own current state (ADR-0831).
    auto const forbidden = [&](std::string_view const reason) {
        log_refusal("livekit.federation.refused", request.user_id, request.room_id, reason);
        return refusal(403U, "M_FORBIDDEN", "No token can be issued for this user in this room.");
    };
    if (!room_state_is_current(store, request.room_id, our_server))
    {
        return forbidden("this server is not in the room");
    }
    if (auth::user_id_server_name(request.user_id) != origin)
    {
        return forbidden("user_id is not of the origin");
    }
    if (current_state_membership(store, request.room_id, request.user_id) != "join")
    {
        return forbidden("not joined");
    }
    if (request.url != service.url)
    {
        return refusal(400U, "M_INVALID_PARAM", "url is not this server's SFU");
    }
    auto const room_name = livekit_room_name(request.room_id, request.slot_id);
    auto const identity = livekit_participant_identity(request.user_id, request.member_id);
    if (!room_name.has_value() || !identity.has_value())
    {
        return refusal(400U, "M_INVALID_PARAM", "the room or member cannot be named");
    }
    // A user of another server subscribes only (MSC4195 lets a server restrict publishing for them; ADR-0831): no
    // `canPublish`, `canPublishData`, and no CreateRoom call made on another server's behalf.
    auto signed_token = sign_for(service, *identity, *room_name, false, request.user_id, request.room_id);
    if (!signed_token.has_value())
    {
        return refusal(500U, "M_UNKNOWN", "LiveKit tokens are unavailable");
    }
    observability::log_diagnostic(log_module, "livekit.federation.issued",
                                  {
                                      {"origin",  std::string{origin}, false},
                                      {"user_id", request.user_id,     false},
                                      {"room_id", request.room_id,     false},
    },
                                  observability::LogEventSeverity::info);
    return jwt_answer(std::move(signed_token->token));
}

} // namespace merovingian::homeserver
