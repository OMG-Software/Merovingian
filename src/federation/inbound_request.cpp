// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/inbound_request.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/core/query_params.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/membership_endpoints.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <sodium.h>

namespace merovingian::federation
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("federation", event, std::move(fields)));
    }

    [[nodiscard]] auto sodium_is_ready() noexcept -> bool
    {
        static auto const ready = sodium_init() >= 0;
        return ready;
    }

    // Builds the Matrix canonical-JSON object signed for an X-Matrix request:
    // {content?, destination, method, origin, uri}. `content` is the request
    // body parsed as JSON and is omitted entirely for a body-less request.
    // Returns std::nullopt when a non-empty body is not canonical-parseable.
    [[nodiscard]] auto federation_request_payload(std::string_view origin, std::string_view destination,
                                                  std::string_view method, std::string_view uri, std::string_view body)
        -> std::optional<std::string>
    {
        auto object = canonicaljson::Object{};
        if (!body.empty())
        {
            auto parsed = canonicaljson::parse_lossless(body);
            if (parsed.error != canonicaljson::ParseError::none)
            {
                return std::nullopt;
            }
            object.push_back(canonicaljson::make_member("content", std::move(parsed.value)));
        }
        object.push_back(canonicaljson::make_member("destination", canonicaljson::Value{std::string{destination}}));
        object.push_back(canonicaljson::make_member("method", canonicaljson::Value{std::string{method}}));
        object.push_back(canonicaljson::make_member("origin", canonicaljson::Value{std::string{origin}}));
        object.push_back(canonicaljson::make_member("uri", canonicaljson::Value{std::string{uri}}));
        auto serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(object)});
        if (serialized.error != canonicaljson::CanonicalJsonError::none)
        {
            return std::nullopt;
        }
        return serialized.output;
    }

    [[nodiscard]] auto split_fields(std::string_view input, char separator) -> std::vector<std::string>
    {
        auto fields = std::vector<std::string>{};
        while (!input.empty())
        {
            auto const position = input.find(separator);
            auto const field = input.substr(0U, position);
            fields.emplace_back(field);
            if (position == std::string_view::npos)
            {
                break;
            }
            input = input.substr(position + 1U);
        }
        return fields;
    }

    [[nodiscard]] auto find_remote(FederationRuntimeState& runtime, std::string_view server_name)
        -> FederationRemoteRuntime*
    {
        auto const iterator =
            std::ranges::find_if(runtime.remotes, [server_name](FederationRemoteRuntime const& remote) {
                return remote.server_name == server_name;
            });
        return iterator == runtime.remotes.end() ? nullptr : &(*iterator);
    }

    [[nodiscard]] auto find_remote(FederationRuntimeState const& runtime, std::string_view server_name)
        -> FederationRemoteRuntime const*
    {
        auto const iterator =
            std::ranges::find_if(runtime.remotes, [server_name](FederationRemoteRuntime const& remote) {
                return remote.server_name == server_name;
            });
        return iterator == runtime.remotes.end() ? nullptr : &(*iterator);
    }

    [[nodiscard]] auto make_decision(bool accepted, std::uint16_t status, std::string reason) -> FederationDecision
    {
        return {accepted, status, std::move(reason)};
    }

    [[nodiscard]] auto sender_domain(std::string_view sender) noexcept -> std::string_view
    {
        auto const colon = sender.rfind(':');
        if (colon == std::string_view::npos || colon + 1U >= sender.size())
        {
            return {};
        }
        return sender.substr(colon + 1U);
    }

    [[nodiscard]] auto transaction_id_from_send_target(std::string_view target) -> std::string
    {
        auto constexpr prefix = std::string_view{"/_matrix/federation/v1/send/"};
        if (target.size() <= prefix.size() || target.substr(0U, prefix.size()) != prefix)
        {
            return {};
        }
        auto const transaction_id = target.substr(prefix.size());
        return transaction_id.find('/') == std::string_view::npos ? std::string{transaction_id} : std::string{};
    }

    [[nodiscard]] auto transaction_already_accepted(FederationRuntimeState const& runtime, std::string_view origin,
                                                    std::string_view transaction_id) noexcept -> bool
    {
        return std::ranges::any_of(runtime.accepted_transactions,
                                   [origin, transaction_id](FederationAcceptedTransaction const& accepted) {
                                       return accepted.origin == origin && accepted.transaction_id == transaction_id;
                                   });
    }

    auto audit_federation(FederationRuntimeState& runtime, std::string_view event_type, std::string_view origin,
                          std::string_view target, std::string_view reason) -> void
    {
        runtime.audit_events.push_back(observability::make_audit_event(observability::AuditCategory::policy, event_type,
                                                                       origin, target, reason, "federation"));
    }

    struct ParsedTransactionBody final
    {
        bool valid{false};
        std::string origin{};
        bool has_origin_server_ts{false};
        std::vector<std::string> pdus{};
        std::vector<std::pair<std::string, std::string>> edus{}; // (edu_type, content_json)
        std::string error{};
    };

    [[nodiscard]] auto serialize_canonical_value(canonicaljson::Value const& value) -> std::string
    {
        auto const serialized = canonicaljson::serialize_canonical(value);
        return serialized.error == canonicaljson::CanonicalJsonError::none ? serialized.output : std::string{};
    }

    [[nodiscard]] auto find_canonical_member(canonicaljson::Object const& object, std::string_view key) noexcept
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

    [[nodiscard]] auto parse_transaction_body(std::string_view body) -> ParsedTransactionBody
    {
        if (body.empty())
        {
            auto parsed_body = ParsedTransactionBody{};
            parsed_body.error = "transaction body must be a JSON object";
            return parsed_body;
        }

        auto const parsed = canonicaljson::parse_lossless(body);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            auto parsed_body = ParsedTransactionBody{};
            parsed_body.error = "transaction body must be valid canonical JSON";
            return parsed_body;
        }

        auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (root == nullptr)
        {
            auto parsed_body = ParsedTransactionBody{};
            parsed_body.error = "transaction body must be a JSON object";
            return parsed_body;
        }

        auto parsed_body = ParsedTransactionBody{};
        auto const* origin_value = find_canonical_member(*root, "origin");
        auto const* origin_text =
            origin_value == nullptr ? nullptr : std::get_if<std::string>(&origin_value->storage());
        if (origin_text == nullptr || origin_text->empty())
        {
            parsed_body.error = "transaction origin is required";
            return parsed_body;
        }
        parsed_body.origin = *origin_text;

        auto const* origin_server_ts_value = find_canonical_member(*root, "origin_server_ts");
        if (origin_server_ts_value == nullptr ||
            std::get_if<std::int64_t>(&origin_server_ts_value->storage()) == nullptr)
        {
            parsed_body.error = "transaction origin_server_ts is required";
            return parsed_body;
        }
        parsed_body.has_origin_server_ts = true;

        auto const* pdus_value = find_canonical_member(*root, "pdus");
        auto const* pdus_array =
            pdus_value == nullptr ? nullptr : std::get_if<canonicaljson::Array>(&pdus_value->storage());
        if (pdus_array == nullptr)
        {
            parsed_body.error = "transaction pdus must be an array";
            return parsed_body;
        }
        for (auto const& pdu_value : *pdus_array)
        {
            if (auto serialized = serialize_canonical_value(pdu_value); !serialized.empty())
            {
                parsed_body.pdus.push_back(std::move(serialized));
            }
        }

        auto const* edus_value = find_canonical_member(*root, "edus");
        if (edus_value != nullptr)
        {
            auto const* edus_array = std::get_if<canonicaljson::Array>(&edus_value->storage());
            if (edus_array == nullptr)
            {
                parsed_body.error = "transaction edus must be an array";
                return parsed_body;
            }
            for (auto const& edu_value : *edus_array)
            {
                auto const* edu_object = std::get_if<canonicaljson::Object>(&edu_value.storage());
                if (edu_object == nullptr)
                {
                    continue;
                }
                auto const* type_value = find_canonical_member(*edu_object, "edu_type");
                auto const* content_value = find_canonical_member(*edu_object, "content");
                if (type_value == nullptr || content_value == nullptr)
                {
                    continue;
                }
                auto const* type_text = std::get_if<std::string>(&type_value->storage());
                if (type_text == nullptr)
                {
                    continue;
                }
                auto content_canonical = serialize_canonical_value(*content_value);
                if (content_canonical.empty())
                {
                    continue;
                }
                parsed_body.edus.emplace_back(*type_text, std::move(content_canonical));
            }
        }

        parsed_body.valid = true;
        return parsed_body;
    }

    // pdu_is_authorized() was removed in v0.5.23.
    //
    // It used a hardcoded room version "12" and a synthetic power level {50, 0},
    // which made ALL PDUs pass the check regardless of the room's actual auth
    // state (banned senders, insufficient power, bad membership transitions, etc.).
    // It was security theatre, not real authorization.
    //
    // Full Matrix event auth MUST be performed against the actual room state
    // (create event, power_levels, join_rules, sender membership) using
    // events::authorize_event_against_auth_events() before a PDU is persisted.
    // That call belongs at the persistence sink, where the auth state is available.

    [[nodiscard]] auto serialize_response_object(canonicaljson::Object object) -> std::string
    {
        auto const out = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(object)});
        return out.error == canonicaljson::CanonicalJsonError::none ? out.output : std::string{};
    }

    [[nodiscard]] auto build_array_value(std::vector<std::string> const& canonical_json_entries) -> canonicaljson::Value
    {
        auto array = canonicaljson::Array{};
        for (auto const& entry : canonical_json_entries)
        {
            auto parsed = canonicaljson::parse_lossless(entry);
            if (parsed.error == canonicaljson::ParseError::none)
            {
                array.push_back(std::move(parsed.value));
            }
        }
        return canonicaljson::Value{std::move(array)};
    }

    [[nodiscard]] auto parse_supported_versions(std::string_view target) -> std::vector<std::string>
    {
        auto versions = std::vector<std::string>{};
        auto const q_position = target.find('?');
        if (q_position == std::string_view::npos)
        {
            return versions;
        }
        auto query = target.substr(q_position + 1U);
        while (!query.empty())
        {
            auto const amp = query.find('&');
            auto const segment = query.substr(0U, amp);
            auto const eq = segment.find('=');
            auto const key = segment.substr(0U, eq);
            if (key == "ver" && eq != std::string_view::npos)
            {
                auto value = segment.substr(eq + 1U);
                if (!value.empty())
                {
                    versions.emplace_back(value);
                }
            }
            if (amp == std::string_view::npos)
            {
                break;
            }
            query = query.substr(amp + 1U);
        }
        return versions;
    }

    [[nodiscard]] auto build_make_template_response(MembershipEventTemplate const& tmpl) -> std::string
    {
        auto event = canonicaljson::Object{};
        event.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{"m.room.member"}}));
        event.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{tmpl.user_id}));
        event.push_back(canonicaljson::make_member("sender", canonicaljson::Value{tmpl.user_id}));
        event.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{tmpl.room_id}));
        // The origin field was removed from events in room version 4, which
        // introduced hash-based event IDs (EventIdFormat::reference_hash).
        // Room versions 1-3 use server-name-based event IDs and include origin.
        auto const* policy = rooms::find_room_version_policy(tmpl.room_version);
        if (policy != nullptr && policy->event_id_format != rooms::EventIdFormat::reference_hash)
        {
            event.push_back(canonicaljson::make_member("origin", canonicaljson::Value{tmpl.origin}));
        }
        event.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{tmpl.origin_server_ts}));
        event.push_back(
            canonicaljson::make_member("depth", canonicaljson::Value{static_cast<std::int64_t>(tmpl.depth)}));
        auto content_value = canonicaljson::Value{};
        auto content_parsed = canonicaljson::parse_lossless(tmpl.content_json);
        if (content_parsed.error == canonicaljson::ParseError::none)
        {
            content_value = std::move(content_parsed.value);
        }
        else
        {
            auto content_obj = canonicaljson::Object{};
            content_obj.push_back(canonicaljson::make_member("membership", canonicaljson::Value{tmpl.membership}));
            content_value = canonicaljson::Value{std::move(content_obj)};
        }
        event.push_back(canonicaljson::make_member("content", std::move(content_value)));
        auto prev_array = canonicaljson::Array{};
        for (auto const& prev : tmpl.prev_events)
        {
            prev_array.push_back(canonicaljson::Value{prev});
        }
        event.push_back(canonicaljson::make_member("prev_events", canonicaljson::Value{std::move(prev_array)}));
        auto auth_array = canonicaljson::Array{};
        for (auto const& auth : tmpl.auth_events)
        {
            auth_array.push_back(canonicaljson::Value{auth});
        }
        event.push_back(canonicaljson::make_member("auth_events", canonicaljson::Value{std::move(auth_array)}));

        auto response = canonicaljson::Object{};
        response.push_back(canonicaljson::make_member("room_version", canonicaljson::Value{tmpl.room_version}));
        response.push_back(canonicaljson::make_member("event", canonicaljson::Value{std::move(event)}));
        return serialize_response_object(std::move(response));
    }

    [[nodiscard]] auto handle_make_membership(FederationRuntimeState& runtime, SignedFederationRequest const& request,
                                              FederationRoute const& route) -> FederationResponse
    {
        if (!runtime.membership_template_provider)
        {
            return {501U, "make_* not implemented"};
        }
        auto const params = parse_membership_path(route.endpoint, request.target);
        if (!params.has_value())
        {
            return {400U, "membership path is malformed"};
        }
        auto const supported = parse_supported_versions(request.target);
        auto const tmpl =
            runtime.membership_template_provider(route.endpoint, params->room_id, params->subject, supported);
        if (!tmpl.has_value())
        {
            return {404U, "membership template unavailable"};
        }
        auto populated = *tmpl;
        if (populated.origin.empty())
        {
            populated.origin = runtime.config.server_name;
        }
        if (populated.origin_server_ts == 0)
        {
            populated.origin_server_ts =
                static_cast<std::int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                              std::chrono::system_clock::now().time_since_epoch())
                                              .count());
        }
        if (!populated.reason.empty())
        {
            return {400U, populated.reason};
        }
        auto body = build_make_template_response(populated);
        if (body.empty())
        {
            return {500U, "failed to serialize membership template"};
        }
        return {200U, std::move(body)};
    }

    [[nodiscard]] auto handle_send_membership(FederationRuntimeState& runtime, SignedFederationRequest const& request,
                                              FederationRoute const& route) -> FederationResponse
    {
        if (!runtime.membership_acceptor)
        {
            return {501U, "send_* not implemented"};
        }
        auto const params = parse_membership_path(route.endpoint, request.target);
        if (!params.has_value())
        {
            return {400U, "membership path is malformed"};
        }
        auto envelope = parse_inbound_pdu_envelope(request.body);
        if (!envelope.has_value())
        {
            return {400U, "membership event body is not a valid PDU envelope"};
        }
        if (envelope->room_id != params->room_id)
        {
            return {400U, "membership event room_id does not match path"};
        }
        auto const acceptance =
            runtime.membership_acceptor(route.endpoint, params->room_id, params->subject, *envelope);
        if (!acceptance.accepted)
        {
            return {acceptance.status == 0U ? std::uint16_t{400U} : acceptance.status, acceptance.reason};
        }
        // Matrix v2 send_join/send_leave/send_knock responses are a JSON object
        // with `auth_chain` and `state` arrays of signed PDUs. v1 send_join
        // historically used a [status, body] tuple; we always emit the v2 shape
        // which the v1 path tolerates because clients ignore unknown wrappers.
        auto response = canonicaljson::Object{};
        // Echo the room's actual version from the acceptor; fall back to "12" only
        // if the acceptor did not populate it (e.g. in legacy test stubs).
        auto const resp_room_version = acceptance.room_version.empty() ? std::string{"12"} : acceptance.room_version;
        response.push_back(canonicaljson::make_member("room_version", canonicaljson::Value{resp_room_version}));
        if (route.endpoint == FederationEndpoint::send_join)
        {
            response.push_back(canonicaljson::make_member("origin", canonicaljson::Value{runtime.config.server_name}));
            // Spec §11.5.1 (PUT /send_join): members_omitted is a REQUIRED field.
            // Without it Synapse raises a parse error and returns 500 to its
            // joining client, causing an infinite make_join/send_join retry loop.
            // We always include full member events so the value is always false.
            response.push_back(canonicaljson::make_member("members_omitted", canonicaljson::Value{false}));
        }
        response.push_back(canonicaljson::make_member("auth_chain", build_array_value(acceptance.auth_chain_json)));
        response.push_back(canonicaljson::make_member("state", build_array_value(acceptance.state_json)));
        // Per Matrix federation spec §11.5.1, the send_join v2 response MUST
        // include the accepted event under the "event" key. send_leave and
        // send_knock do not carry this field.
        if (route.endpoint == FederationEndpoint::send_join && !acceptance.signed_event_json.empty())
        {
            auto parsed_event = canonicaljson::parse_lossless(acceptance.signed_event_json);
            if (parsed_event.error == canonicaljson::ParseError::none)
            {
                response.push_back(canonicaljson::make_member("event", std::move(parsed_event.value)));
            }
        }
        auto body = serialize_response_object(std::move(response));
        if (body.empty())
        {
            return {500U, "failed to serialize membership response"};
        }
        return {200U, std::move(body)};
    }

    [[nodiscard]] auto handle_invite(FederationRuntimeState& runtime, SignedFederationRequest const& request,
                                     FederationRoute const& route) -> FederationResponse
    {
        if (!runtime.invite_handler)
        {
            return {501U, "invite not implemented"};
        }
        auto const params = parse_membership_path(FederationEndpoint::invite, request.target);
        if (!params.has_value())
        {
            return {400U, "invite path is malformed"};
        }
        auto invite_request =
            parse_invite_body(request.body, params->room_id, params->subject, FederationEndpoint::invite);
        if (!invite_request.has_value())
        {
            return {400U, "invite body is malformed"};
        }
        auto const result = runtime.invite_handler(*invite_request);
        if (!result.accepted)
        {
            return {result.status == 0U ? std::uint16_t{400U} : result.status, result.reason};
        }
        if (route.path_template == "/_matrix/federation/v2/invite/{roomId}/{eventId}")
        {
            auto response = canonicaljson::Object{};
            auto signed_event_value = canonicaljson::Value{};
            auto parsed_event = canonicaljson::parse_lossless(result.signed_event_json);
            if (parsed_event.error == canonicaljson::ParseError::none)
            {
                signed_event_value = std::move(parsed_event.value);
            }
            response.push_back(canonicaljson::make_member("event", std::move(signed_event_value)));
            auto body = serialize_response_object(std::move(response));
            return {200U, body.empty() ? std::string{"{}"} : std::move(body)};
        }
        // v1 invite response is the bare event JSON wrapped in [200, event].
        // Modern peers accept the bare event; emit it directly.
        return {200U, result.signed_event_json};
    }

    [[nodiscard]] auto handle_backfill(FederationRuntimeState& runtime, SignedFederationRequest const& request)
        -> FederationResponse
    {
        if (!runtime.backfill_provider)
        {
            return {501U, "backfill not implemented"};
        }
        auto parsed = parse_backfill_query(request.target);
        if (!parsed.has_value())
        {
            return {400U, "backfill query is malformed"};
        }
        auto const result = runtime.backfill_provider(*parsed);
        if (!result.accepted)
        {
            return {result.status == 0U ? std::uint16_t{500U} : result.status, result.reason};
        }
        auto const now_ms = static_cast<std::int64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count());
        auto response = canonicaljson::Object{};
        response.push_back(canonicaljson::make_member("origin", canonicaljson::Value{runtime.config.server_name}));
        response.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{now_ms}));
        response.push_back(canonicaljson::make_member("pdus", build_array_value(result.pdus_json)));
        auto body = serialize_response_object(std::move(response));
        if (body.empty())
        {
            return {500U, "failed to serialize backfill response"};
        }
        return {200U, std::move(body)};
    }

    // Extracts and percent-decodes a single named parameter from the query
    // string of a request target. Returns an empty string when absent.
    [[nodiscard]] auto query_param_value(std::string_view target, std::string_view name) -> std::string
    {
        auto const query_start = target.find('?');
        if (query_start == std::string_view::npos)
        {
            return {};
        }
        auto remaining = target.substr(query_start + 1U);
        while (!remaining.empty())
        {
            auto const amp = remaining.find('&');
            auto const pair = remaining.substr(0U, amp);
            auto const eq = pair.find('=');
            if (eq != std::string_view::npos && pair.substr(0U, eq) == name)
            {
                return core::percent_decode(pair.substr(eq + 1U));
            }
            if (amp == std::string_view::npos)
            {
                break;
            }
            remaining = remaining.substr(amp + 1U);
        }
        return {};
    }

    [[nodiscard]] auto handle_query_profile(FederationRuntimeState& runtime, SignedFederationRequest const& request)
        -> FederationResponse
    {
        if (!runtime.profile_query_provider)
        {
            return {501U, "query_profile not implemented"};
        }
        auto const user_id = query_param_value(request.target, "user_id");
        if (user_id.empty())
        {
            return {400U, "query/profile requires a user_id parameter"};
        }
        auto const field = query_param_value(request.target, "field");
        if (!field.empty() && field != "displayname" && field != "avatar_url")
        {
            return {400U, "query/profile field must be displayname or avatar_url"};
        }
        auto const profile = runtime.profile_query_provider(user_id);
        if (!profile.found)
        {
            return {404U, homeserver::matrix_error("M_NOT_FOUND", "Profile not found")};
        }
        auto response = canonicaljson::Object{};
        if (field.empty() || field == "displayname")
        {
            response.push_back(canonicaljson::make_member("displayname", canonicaljson::Value{profile.displayname}));
        }
        if (field.empty() || field == "avatar_url")
        {
            response.push_back(canonicaljson::make_member("avatar_url", canonicaljson::Value{profile.avatar_url}));
        }
        auto body = serialize_response_object(std::move(response));
        if (body.empty())
        {
            return {500U, "failed to serialize profile response"};
        }
        return {200U, std::move(body)};
    }

    [[nodiscard]] auto handle_query_keys(FederationRuntimeState& runtime, SignedFederationRequest const& request)
        -> FederationResponse
    {
        if (!runtime.device_keys_query_provider)
        {
            return {501U, "query_keys not implemented"};
        }
        auto body = runtime.device_keys_query_provider(request.body);
        if (body.empty())
        {
            return {400U, "user/keys/query body is malformed"};
        }
        return {200U, std::move(body)};
    }

    [[nodiscard]] auto handle_claim_keys(FederationRuntimeState& runtime, SignedFederationRequest const& request)
        -> FederationResponse
    {
        if (!runtime.one_time_keys_claim_provider)
        {
            return {501U, "claim_keys not implemented"};
        }
        auto body = runtime.one_time_keys_claim_provider(request.body);
        if (body.empty())
        {
            return {400U, "user/keys/claim body is malformed"};
        }
        return {200U, std::move(body)};
    }

    [[nodiscard]] auto handle_user_devices(FederationRuntimeState& runtime, SignedFederationRequest const& request)
        -> FederationResponse
    {
        if (!runtime.user_devices_provider)
        {
            return {501U, "query_user_devices not implemented"};
        }
        auto constexpr prefix = std::string_view{"/_matrix/federation/v1/user/devices/"};
        auto const path = std::string_view{request.target}.substr(0U, request.target.find('?'));
        if (path.size() <= prefix.size() || path.substr(0U, prefix.size()) != prefix)
        {
            return {400U, "user/devices path is malformed"};
        }
        auto const user_id = core::percent_decode(path.substr(prefix.size()));
        auto body = runtime.user_devices_provider(user_id);
        if (body.empty())
        {
            return {404U, homeserver::matrix_error("M_NOT_FOUND", "User has no published devices")};
        }
        return {200U, std::move(body)};
    }

    // Extracts a percent-decoded single path segment that immediately follows
    // `prefix`. Returns an empty string when the target does not start with
    // `prefix` or has no segment after it.
    [[nodiscard]] auto extract_path_segment(std::string_view target, std::string_view prefix) -> std::string
    {
        auto const path = target.substr(0U, target.find('?'));
        if (path.size() <= prefix.size() || path.substr(0U, prefix.size()) != prefix)
        {
            return {};
        }
        return core::percent_decode(path.substr(prefix.size()));
    }

    [[nodiscard]] auto handle_query_event(FederationRuntimeState& runtime, SignedFederationRequest const& request)
        -> FederationResponse
    {
        if (!runtime.event_query_provider)
        {
            return {501U, "query_event not implemented"};
        }
        auto const event_id = extract_path_segment(request.target, "/_matrix/federation/v1/event/");
        if (event_id.empty())
        {
            return {400U, "event path is malformed"};
        }
        auto body = runtime.event_query_provider(event_id);
        if (body.empty())
        {
            return {404U, homeserver::matrix_error("M_NOT_FOUND", "Event not found")};
        }
        return {200U, std::move(body)};
    }

    [[nodiscard]] auto handle_query_state(FederationRuntimeState& runtime, SignedFederationRequest const& request)
        -> FederationResponse
    {
        if (!runtime.state_query_provider)
        {
            return {501U, "query_state not implemented"};
        }
        auto const room_id = extract_path_segment(request.target, "/_matrix/federation/v1/state/");
        if (room_id.empty())
        {
            return {400U, "state path is malformed"};
        }
        auto body = runtime.state_query_provider(room_id);
        if (body.empty())
        {
            return {404U, homeserver::matrix_error("M_NOT_FOUND", "Room state not found")};
        }
        return {200U, std::move(body)};
    }

    [[nodiscard]] auto handle_query_state_ids(FederationRuntimeState& runtime, SignedFederationRequest const& request)
        -> FederationResponse
    {
        if (!runtime.state_ids_query_provider)
        {
            return {501U, "query_state_ids not implemented"};
        }
        auto const room_id = extract_path_segment(request.target, "/_matrix/federation/v1/state_ids/");
        if (room_id.empty())
        {
            return {400U, "state_ids path is malformed"};
        }
        auto body = runtime.state_ids_query_provider(room_id);
        if (body.empty())
        {
            return {404U, homeserver::matrix_error("M_NOT_FOUND", "Room state not found")};
        }
        return {200U, std::move(body)};
    }

    [[nodiscard]] auto handle_get_missing_events(FederationRuntimeState& runtime,
                                                 SignedFederationRequest const& request) -> FederationResponse
    {
        if (!runtime.missing_events_query_provider)
        {
            return {501U, "get_missing_events not implemented"};
        }
        auto const room_id = extract_path_segment(request.target, "/_matrix/federation/v1/get_missing_events/");
        if (room_id.empty())
        {
            return {400U, "get_missing_events path is malformed"};
        }
        auto body = runtime.missing_events_query_provider(room_id, request.body);
        if (body.empty())
        {
            return {400U, "get_missing_events body is malformed"};
        }
        return {200U, std::move(body)};
    }

    [[nodiscard]] auto dispatch_non_transaction_endpoint(FederationRuntimeState& runtime,
                                                         SignedFederationRequest const& request,
                                                         FederationRoute const& route, FederationRemoteRuntime& remote)
        -> FederationResponse
    {
        std::ignore = remote; // remote trust accounting is handled by the caller.
        switch (route.endpoint)
        {
        case FederationEndpoint::make_join:
        case FederationEndpoint::make_leave:
        case FederationEndpoint::make_knock:
            return handle_make_membership(runtime, request, route);
        case FederationEndpoint::send_join:
        case FederationEndpoint::send_leave:
        case FederationEndpoint::send_knock:
            return handle_send_membership(runtime, request, route);
        case FederationEndpoint::invite:
            return handle_invite(runtime, request, route);
        case FederationEndpoint::backfill:
            return handle_backfill(runtime, request);
        case FederationEndpoint::query_profile:
            return handle_query_profile(runtime, request);
        case FederationEndpoint::query_keys:
            return handle_query_keys(runtime, request);
        case FederationEndpoint::claim_keys:
            return handle_claim_keys(runtime, request);
        case FederationEndpoint::query_user_devices:
            return handle_user_devices(runtime, request);
        case FederationEndpoint::query_event:
            return handle_query_event(runtime, request);
        case FederationEndpoint::query_state:
            return handle_query_state(runtime, request);
        case FederationEndpoint::query_state_ids:
            return handle_query_state_ids(runtime, request);
        case FederationEndpoint::get_missing_events:
            return handle_get_missing_events(runtime, request);
        case FederationEndpoint::edu:
            // Plain send_edu requests have always been a 200 stub; ingestion
            // happens through the transaction path which carries EDUs.
            return {200U, "accepted endpoint=" + std::string{federation_endpoint_name(route.endpoint)}};
        case FederationEndpoint::transaction:
            return {500U, "transaction endpoint mis-dispatched"};
        }
        return {500U, "unknown endpoint"};
    }

    class FederationEd25519Verifier final : public crypto::Ed25519Provider
    {
    public:
        [[nodiscard]] auto sign(crypto::Ed25519SecretKeyHandle const&, std::string_view)
            -> crypto::SignatureResult override
        {
            return {{}, "federation verifier does not sign"};
        }

        [[nodiscard]] auto verify(crypto::Ed25519PublicKey const& public_key, std::string_view message,
                                  crypto::Ed25519Signature const& signature) -> crypto::VerificationResult override
        {
            if (!crypto::ed25519_public_key_shape_is_valid(public_key) ||
                !crypto::ed25519_signature_shape_is_valid(signature))
            {
                return {false, "invalid Ed25519 material"};
            }
            auto const ok =
                crypto_sign_verify_detached(reinterpret_cast<unsigned char const*>(signature.bytes.data()),
                                            reinterpret_cast<unsigned char const*>(message.data()), message.size(),
                                            reinterpret_cast<unsigned char const*>(public_key.bytes.data())) == 0;
            return {ok, ok ? std::string{} : std::string{"signature verification failed"}};
        }
    };

} // namespace

auto load_server_signing_key(std::string_view server_name, std::string_view key_id, std::string_view key_material)
    -> FederationSigningKey
{
    if (!server_name_is_valid(server_name) || key_id.empty() || key_material.empty())
    {
        return {};
    }
    return {std::string{server_name}, std::string{key_id}, std::string{key_material}, true};
}

auto signing_key_summary(FederationSigningKey const& key) -> std::string
{
    return "server=" + key.server_name + " key_id=" + key.key_id +
           " loaded=" + std::string{key.loaded ? "true" : "false"};
}

auto make_federation_signature(std::string_view origin, std::string_view destination, std::string_view method,
                               std::string_view target, std::string_view body, std::string_view secret_key)
    -> std::string
{
    if (!sodium_is_ready() || secret_key.size() != crypto_sign_SECRETKEYBYTES)
    {
        // Key size mismatch means no signature can be produced. Log so operators
        // can detect misconfiguration without needing a debugger attached.
        log_diagnostic("signature.key_size_invalid",
                       {
                           {"expected", std::to_string(crypto_sign_SECRETKEYBYTES), false},
                           {"actual",   std::to_string(secret_key.size()),          false},
                           {"origin",   std::string{origin},                        false},
                           {"target",   std::string{target},                        false}
        });
        return {};
    }
    auto const payload = federation_request_payload(origin, destination, method, target, body);
    if (!payload.has_value())
    {
        // Body could not be parsed as canonical JSON — signature will be empty.
        log_diagnostic("signature.payload_build_failed", {
                                                             {"origin",      std::string{origin},         false},
                                                             {"destination", std::string{destination},    false},
                                                             {"method",      std::string{method},         false},
                                                             {"target",      std::string{target},         false},
                                                             {"body_bytes",  std::to_string(body.size()), false}
        });
        return {};
    }
    // libsodium Ed25519 secret keys are [seed(32) | public_key(32)]. Derive and
    // log the embedded public key so operators can compare it against the value
    // published at /_matrix/key/v2/server to catch signing/publishing key mismatches.
    auto const embedded_pk = events::matrix_base64_from_bytes(secret_key.substr(32U));
    log_diagnostic("signature.signing", {
                                            {"origin",        std::string{origin},             false},
                                            {"destination",   std::string{destination},        false},
                                            {"method",        std::string{method},             false},
                                            {"target",        std::string{target},             false},
                                            {"embedded_pk",   embedded_pk,                     false},
                                            {"payload_bytes", std::to_string(payload->size()), false}
    });
    auto signature = std::string(crypto_sign_BYTES, '\0');
    if (crypto_sign_detached(reinterpret_cast<unsigned char*>(signature.data()), nullptr,
                             reinterpret_cast<unsigned char const*>(payload->data()), payload->size(),
                             reinterpret_cast<unsigned char const*>(secret_key.data())) != 0)
    {
        return {};
    }
    return events::matrix_base64_from_bytes(signature);
}

auto parse_x_matrix_authorization_header(std::string_view header_value) -> std::optional<XMatrixCredentials>
{
    auto constexpr prefix = std::string_view{"X-Matrix "};
    if (header_value.size() < prefix.size() || header_value.substr(0U, prefix.size()) != prefix)
    {
        return std::nullopt;
    }
    auto remaining = header_value.substr(prefix.size());
    auto credentials = XMatrixCredentials{};
    auto origin_found = false;
    auto key_found = false;
    auto sig_found = false;
    while (!remaining.empty())
    {
        while (!remaining.empty() && (remaining.front() == ' ' || remaining.front() == '\t'))
        {
            remaining = remaining.substr(1U);
        }
        if (remaining.empty())
        {
            break;
        }
        auto const eq_pos = remaining.find('=');
        if (eq_pos == std::string_view::npos)
        {
            return std::nullopt;
        }
        auto name = remaining.substr(0U, eq_pos);
        while (!name.empty() && (name.back() == ' ' || name.back() == '\t'))
        {
            name = name.substr(0U, name.size() - 1U);
        }
        remaining = remaining.substr(eq_pos + 1U);
        while (!remaining.empty() && (remaining.front() == ' ' || remaining.front() == '\t'))
        {
            remaining = remaining.substr(1U);
        }
        if (remaining.empty() || remaining.front() != '"')
        {
            return std::nullopt;
        }
        remaining = remaining.substr(1U);
        auto const close_pos = remaining.find('"');
        if (close_pos == std::string_view::npos)
        {
            return std::nullopt;
        }
        auto const value = remaining.substr(0U, close_pos);
        remaining = remaining.substr(close_pos + 1U);
        if (name == "origin")
        {
            credentials.origin = std::string{value};
            origin_found = true;
        }
        else if (name == "key")
        {
            credentials.key_id = std::string{value};
            key_found = true;
        }
        else if (name == "sig")
        {
            credentials.signature = std::string{value};
            sig_found = true;
        }
        else if (name == "destination")
        {
            credentials.destination = std::string{value};
        }
        while (!remaining.empty() && (remaining.front() == ' ' || remaining.front() == '\t'))
        {
            remaining = remaining.substr(1U);
        }
        if (!remaining.empty() && remaining.front() == ',')
        {
            remaining = remaining.substr(1U);
        }
    }
    if (!origin_found || !key_found || !sig_found || credentials.origin.empty() || credentials.key_id.empty() ||
        credentials.signature.empty())
    {
        return std::nullopt;
    }
    return credentials;
}

auto verify_signed_federation_request(SignedFederationRequest const& request, FederationKeyRecord const& key)
    -> FederationDecision
{
    if (request.origin != key.server_name || request.key_id != key.key_id)
    {
        return make_decision(false, 403U, "request signing key does not match origin");
    }
    if (key.valid_until_ts != 0U && request.now_ts > key.valid_until_ts)
    {
        return make_decision(false, 403U, "request signing key has expired");
    }
    auto const payload =
        federation_request_payload(request.origin, request.destination, request.method, request.target, request.body);
    auto const signature = events::matrix_bytes_from_base64(request.signature);
    if (!payload.has_value() || !crypto::ed25519_signature_shape_is_valid(crypto::Ed25519Signature{signature}) ||
        !crypto::ed25519_public_key_shape_is_valid(crypto::Ed25519PublicKey{key.public_key_bytes}) ||
        crypto_sign_verify_detached(reinterpret_cast<unsigned char const*>(signature.data()),
                                    reinterpret_cast<unsigned char const*>(payload->data()), payload->size(),
                                    reinterpret_cast<unsigned char const*>(key.public_key_bytes.data())) != 0)
    {
        return make_decision(false, 403U, "request signature verification failed");
    }
    auto const boundary = verify_federation_request_signature(
        {request.origin, request.key_id, request.signature, request.canonical_json_verified});
    if (!boundary.accepted)
    {
        return make_decision(false, 403U, boundary.reason);
    }
    return make_decision(true, 200U, {});
}

auto make_federation_runtime_state(RuntimeFederationConfig config) -> FederationRuntimeState
{
    return {std::move(config), {}, {}, {}};
}

auto upsert_remote(FederationRuntimeState& runtime, FederationRemoteRuntime remote) -> void
{
    auto* existing = find_remote(runtime, remote.server_name);
    if (existing != nullptr)
    {
        *existing = std::move(remote);
        return;
    }
    runtime.remotes.push_back(std::move(remote));
}

auto federation_remote_is_known(FederationRuntimeState const& runtime, std::string_view server_name) noexcept -> bool
{
    return find_remote(runtime, server_name) != nullptr;
}

auto authorize_federation_pdu(FederationPdu const& pdu, std::string_view expected_origin) -> FederationDecision
{
    return authorize_federation_pdu(pdu, expected_origin, std::nullopt);
}

auto authorize_federation_pdu(FederationPdu const& pdu, std::string_view expected_origin,
                              std::optional<FederationKeyRecord> const& key) -> FederationDecision
{
    if (pdu.event_id.empty() || pdu.room_id.empty() || pdu.event_type.empty() || pdu.sender.empty())
    {
        return make_decision(false, 400U, "PDU is missing required fields");
    }
    if (sender_domain(pdu.sender) != expected_origin)
    {
        return make_decision(false, 403U, "PDU sender does not match origin");
    }
    auto const signature = verify_federation_event_signatures(pdu.signatures, expected_origin);
    if (!signature.accepted)
    {
        return make_decision(false, 403U, signature.reason);
    }
    if (key.has_value())
    {
        auto const* room_version = rooms::find_room_version_policy("12");
        if (room_version == nullptr)
        {
            return make_decision(false, 500U, "room version policy is unavailable");
        }
        if (!pdu.json.empty())
        {
            auto const parsed = canonicaljson::parse_lossless(pdu.json);
            if (parsed.error != canonicaljson::ParseError::none)
            {
                return make_decision(false, 400U, "PDU JSON is not canonical-parseable");
            }
            auto const& public_key = key->public_key_bytes;
            auto verifier = FederationEd25519Verifier{};
            auto const verified =
                events::verify_event_signature(parsed.value, *room_version, {std::string{expected_origin}, key->key_id},
                                               crypto::Ed25519PublicKey{public_key}, verifier);
            if (!verified.valid)
            {
                return make_decision(false, 403U, verified.error);
            }
        }
        else
        {
            return make_decision(false, 400U, "comma-delimited PDUs require JSON for cryptographic verification");
        }
    }
    // TODO: full Matrix event auth (authorize_event_against_auth_events) must be
    // called here against the actual room auth state before returning accepted.
    // The shallow pdu_is_authorized() check was removed in v0.5.23 — see the
    // comment block above where it was defined for the security rationale.
    return make_decision(true, 200U, {});
}

auto parse_federation_pdu(std::string_view encoded) -> FederationPdu
{
    if (!encoded.empty() && encoded.front() == '{')
    {
        auto const parsed = canonicaljson::parse_lossless(encoded);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return {};
        }
        auto const envelope = events::parse_event_envelope(parsed.value);
        if (!envelope.error.empty())
        {
            return {};
        }
        auto const* room_version = rooms::find_room_version_policy("12");
        if (room_version == nullptr)
        {
            return {};
        }
        auto id = events::make_reference_hash_event_id(parsed.value, *room_version);
        return {id.event_id,           envelope.event.room_id,    envelope.event.event_type,
                envelope.event.sender, envelope.event.signatures, std::string{encoded}};
    }
    auto const fields = split_fields(encoded, ',');
    if (fields.size() != 7U || fields[6].empty())
    {
        return {};
    }
    return {fields[0], fields[1], fields[2], fields[3], {{fields[4], fields[5], fields[6]}}, {}};
}

auto handle_inbound_federation_request(FederationRuntimeState& runtime, SignedFederationRequest const& request)
    -> FederationResponse
{
    log_diagnostic("request.received", {
                                           {"method",     request.method,                                       false},
                                           {"target",     observability::sanitized_http_target(request.target), false},
                                           {"origin",     request.origin,                                       false},
                                           {"key_id",     request.key_id,                                       false},
                                           {"body_bytes", std::to_string(request.body.size()),                  false}
    });
    auto const route_match = match_federation_route(request.method, request.target);
    if (!route_match.matched)
    {
        log_diagnostic("request.route_not_found",
                       {
                           {"method", request.method,                                       false},
                           {"target", observability::sanitized_http_target(request.target), false},
                           {"origin", request.origin,                                       false},
                           {"status", "404",                                                false},
                           {"reason", route_match.reason,                                   false}
        });
        return {404U, route_match.reason};
    }
    // Reject early when the TLS peer name is known and does not match the
    // X-Matrix origin claim: a relay cannot legitimately present a different
    // server name in the TLS handshake than in the federation auth header.
    if (!request.tls_peer_server_name.empty() && request.tls_peer_server_name != request.origin)
    {
        audit_federation(runtime, "federation.rejected", request.origin, request.target, "TLS origin mismatch");
        return {403U, "TLS peer name does not match request origin"};
    }
    auto const server_policy = federation_server_policy(runtime.config, request.origin);
    if (!server_policy.allowed)
    {
        log_diagnostic("request.rejected", {
                                               {"origin", request.origin,                                       false},
                                               {"target", observability::sanitized_http_target(request.target), false},
                                               {"status", "403",                                                false},
                                               {"reason", server_policy.reason,                                 false}
        });
        audit_federation(runtime, "federation.rejected", request.origin, request.target, server_policy.reason);
        return {403U, server_policy.reason};
    }
    auto* remote = find_remote(runtime, request.origin);
    if (remote == nullptr && runtime.remote_key_resolver)
    {
        // Unknown remote: try the injected resolver to discover, fetch, and
        // verify the remote's published signing keys, then upsert a full
        // runtime record so the discovery/trust policy checks below have
        // something to validate against. The resolver caches through the
        // persistent store, so subsequent requests see the new record
        // without another network round-trip.
        auto resolved = runtime.remote_key_resolver(request.origin, request.key_id);
        if (resolved.has_value())
        {
            if (resolved->server_name.empty())
            {
                resolved->server_name = std::string{request.origin};
            }
            if (resolved->trust.reputation_score == 0U)
            {
                resolved->trust.reputation_score = 100U;
            }
            upsert_remote(runtime, std::move(*resolved));
            remote = find_remote(runtime, request.origin);
        }
    }
    if (remote == nullptr)
    {
        log_diagnostic("request.rejected", {
                                               {"origin", request.origin,                                       false},
                                               {"target", observability::sanitized_http_target(request.target), false},
                                               {"status", "403",                                                false},
                                               {"reason", "remote is unknown",                                  false}
        });
        audit_federation(runtime, "federation.rejected", request.origin, request.target, "remote is unknown");
        return {403U, "remote is unknown"};
    }
    // Known remote, but the cached key doesn't match the request key_id or
    // has expired: try the resolver to refresh before falling back to the
    // stored record. Federation peers rotate keys, so the cache must follow.
    // We keep the existing discovery/trust state and only swap in the new
    // signing key — discovery doesn't change just because a key rotated.
    auto const cached_key_id_mismatches = remote->signing_key.key_id != request.key_id;
    auto const cached_key_expired =
        remote->signing_key.valid_until_ts != 0U && request.now_ts >= remote->signing_key.valid_until_ts;
    if (runtime.remote_key_resolver && (cached_key_id_mismatches || cached_key_expired))
    {
        auto refreshed = runtime.remote_key_resolver(request.origin, request.key_id);
        if (refreshed.has_value() && !refreshed->signing_key.public_key_bytes.empty())
        {
            remote->signing_key = std::move(refreshed->signing_key);
        }
    }
    auto const discovery = federation_discovery_policy(remote->discovery);
    if (!discovery.accepted)
    {
        log_diagnostic("request.rejected", {
                                               {"origin", request.origin,                                       false},
                                               {"target", observability::sanitized_http_target(request.target), false},
                                               {"status", "403",                                                false},
                                               {"reason", discovery.reason,                                     false}
        });
        audit_federation(runtime, "federation.rejected", request.origin, request.target, discovery.reason);
        return {403U, discovery.reason};
    }
    auto const trust = remote_trust_policy(remote->trust);
    if (!trust.accepted)
    {
        log_diagnostic("request.rejected", {
                                               {"origin", request.origin,                                       false},
                                               {"target", observability::sanitized_http_target(request.target), false},
                                               {"status", std::to_string(trust.apply_backoff ? 429U : 403U),    false},
                                               {"reason", trust.reason,                                         false}
        });
        audit_federation(runtime, "federation.rejected", request.origin, request.target, trust.reason);
        auto const status = static_cast<std::uint16_t>(trust.apply_backoff ? 429U : 403U);
        return {status, trust.reason};
    }
    auto const request_signature = verify_signed_federation_request(request, remote->signing_key);
    if (!request_signature.accepted)
    {
        ++remote->trust.consecutive_failures;
        log_diagnostic("request.rejected",
                       {
                           {"origin",               request.origin,                                       false},
                           {"target",               observability::sanitized_http_target(request.target), false},
                           {"status",               std::to_string(request_signature.status),             false},
                           {"reason",               request_signature.reason,                             false},
                           {"consecutive_failures", std::to_string(remote->trust.consecutive_failures),   false}
        });
        audit_federation(runtime, "federation.rejected", request.origin, request.target, request_signature.reason);
        return {request_signature.status, request_signature.reason};
    }
    if (route_match.route.endpoint != FederationEndpoint::transaction)
    {
        auto const non_transaction_response =
            dispatch_non_transaction_endpoint(runtime, request, route_match.route, *remote);
        if (non_transaction_response.status >= 200U && non_transaction_response.status < 300U)
        {
            remote->trust.consecutive_failures = 0U;
            log_diagnostic("request.accepted",
                           {
                               {"origin", request.origin,                                       false},
                               {"target", observability::sanitized_http_target(request.target), false},
                               {"status", std::to_string(non_transaction_response.status),      false}
            });
            audit_federation(runtime, "federation.accepted", request.origin, request.target,
                             federation_route_audit_event(route_match.route, request.origin));
        }
        else
        {
            log_diagnostic("request.rejected",
                           {
                               {"origin", request.origin,                                       false},
                               {"target", observability::sanitized_http_target(request.target), false},
                               {"status", std::to_string(non_transaction_response.status),      false},
                               {"reason", non_transaction_response.body,                        false}
            });
            audit_federation(runtime, "federation.rejected", request.origin, request.target,
                             non_transaction_response.body);
        }
        return non_transaction_response;
    }

    auto const parsed_body = parse_transaction_body(request.body);
    auto const transaction_id = transaction_id_from_send_target(request.target);
    if (!parsed_body.valid)
    {
        ++remote->trust.consecutive_failures;
        log_diagnostic("transaction.rejected", {
                                                   {"origin",         request.origin,    false},
                                                   {"transaction_id", transaction_id,    false},
                                                   {"status",         "400",             false},
                                                   {"reason",         parsed_body.error, false}
        });
        audit_federation(runtime, "federation.rejected", request.origin, request.target, parsed_body.error);
        return {400U, homeserver::matrix_error("M_BAD_JSON", parsed_body.error)};
    }
    if (parsed_body.origin != request.origin)
    {
        auto constexpr reason = "transaction origin does not match request origin";
        ++remote->trust.consecutive_failures;
        log_diagnostic("transaction.rejected", {
                                                   {"origin",         request.origin, false},
                                                   {"transaction_id", transaction_id, false},
                                                   {"status",         "403",          false},
                                                   {"reason",         reason,         false}
        });
        audit_federation(runtime, "federation.rejected", request.origin, request.target, reason);
        return {403U, reason};
    }
    auto transaction = FederationTransaction{};
    transaction.origin = parsed_body.origin;
    transaction.transaction_id = transaction_id;
    transaction.byte_size = request.body.size();
    transaction.pdus = parsed_body.pdus;
    for (auto const& [edu_type, edu_content] : parsed_body.edus)
    {
        transaction.edus.push_back(edu_type);
    }
    auto const transaction_decision =
        validate_federation_transaction(transaction, runtime.config.max_transaction_bytes);
    if (!transaction_decision.accepted)
    {
        ++remote->trust.consecutive_failures;
        log_diagnostic("transaction.rejected", {
                                                   {"origin",         request.origin,                          false},
                                                   {"transaction_id", transaction.transaction_id,              false},
                                                   {"status",         "400",                                   false},
                                                   {"reason",         transaction_decision.reason,             false},
                                                   {"pdu_count",      std::to_string(transaction.pdus.size()), false},
                                                   {"edu_count",      std::to_string(transaction.edus.size()), false}
        });
        audit_federation(runtime, "federation.rejected", request.origin, request.target, transaction_decision.reason);
        return {400U, homeserver::matrix_error("M_BAD_JSON", transaction_decision.reason)};
    }
    if (transaction_already_accepted(runtime, request.origin, transaction.transaction_id))
    {
        remote->trust.consecutive_failures = 0U;
        audit_federation(runtime, "federation.duplicate", request.origin, request.target,
                         "transaction already accepted");
        return {200U, serialize_response_object(canonicaljson::Object{
                          canonicaljson::make_member("pdus", canonicaljson::Value{canonicaljson::Object{}}),
                      })};
    }
    auto pdus_appended = std::size_t{0U};
    auto pdus_state_conflict = std::size_t{0U};
    auto pdus_state_resolved = std::size_t{0U};
    // Per-spec (Matrix federation /send): individual PDU failures must be
    // reported in the response body as {"pdus": {"$id": {"error": "..."}}}
    // rather than as a non-200 HTTP status. Returning 4xx/5xx causes the
    // remote server (e.g. Synapse) to back off the entire destination for a
    // backoff period, blocking all subsequent federation.
    auto pdu_errors = canonicaljson::Object{};
    for (auto const& encoded_pdu : transaction.pdus)
    {
        auto const pdu = parse_federation_pdu(encoded_pdu);
        auto const pdu_decision = authorize_federation_pdu(pdu, request.origin, remote->signing_key);
        if (!pdu_decision.accepted)
        {
            ++remote->trust.consecutive_failures;
            log_diagnostic("pdu.rejected", {
                                               {"origin",         request.origin,                      false},
                                               {"transaction_id", transaction.transaction_id,          false},
                                               {"event_id",       pdu.event_id,                        false},
                                               {"room_id",        pdu.room_id,                         false},
                                               {"event_type",     pdu.event_type,                      false},
                                               {"status",         std::to_string(pdu_decision.status), false},
                                               {"reason",         pdu_decision.reason,                 false}
            });
            audit_federation(runtime, "federation.rejected", request.origin, request.target, pdu_decision.reason);
            // Record the per-PDU error and continue processing remaining PDUs.
            pdu_errors.push_back(canonicaljson::make_member(
                pdu.event_id, canonicaljson::Value{canonicaljson::Object{
                                  canonicaljson::make_member("error", canonicaljson::Value{pdu_decision.reason})}}));
            continue;
        }
        if (!runtime.pdu_sink)
        {
            continue;
        }
        // PDU passed signature and auth checks; hand it to the ingestion
        // sink for persistence. State-resolution conflicts are no longer
        // silently logged: when the sink surfaces a state_conflict context
        // and a `state_conflict_resolver` is wired, we run state-res v2 to
        // merge the forks. Successful merges are audited as
        // `federation.pdu_state_resolved` and counted as accepted.
        auto envelope = parse_inbound_pdu_envelope(encoded_pdu);
        if (!envelope.has_value())
        {
            audit_federation(runtime, "federation.pdu_envelope_unparseable", request.origin, request.target,
                             "ingestion-skip");
            continue;
        }
        auto const ingestion = runtime.pdu_sink(*envelope);
        switch (ingestion.status)
        {
        case PduIngestionStatus::accepted:
            ++pdus_appended;
            break;
        case PduIngestionStatus::rejected_state_conflict: {
            auto merged = false;
            if (runtime.state_conflict_resolver && ingestion.state_conflict.has_value())
            {
                auto const resolution = runtime.state_conflict_resolver(*ingestion.state_conflict);
                if (resolution.status == PduIngestionStatus::accepted)
                {
                    merged = true;
                    ++pdus_appended;
                    ++pdus_state_resolved;
                    audit_federation(runtime, "federation.pdu_state_resolved", request.origin, request.target,
                                     resolution.reason);
                }
                else if (!resolution.reason.empty())
                {
                    audit_federation(runtime, "federation.pdu_state_conflict", request.origin, request.target,
                                     resolution.reason);
                }
            }
            if (!merged)
            {
                ++pdus_state_conflict;
                audit_federation(runtime, "federation.pdu_state_conflict", request.origin, request.target,
                                 ingestion.reason);
            }
            break;
        }
        case PduIngestionStatus::rejected_auth:
            audit_federation(runtime, "federation.pdu_rejected_auth", request.origin, request.target, ingestion.reason);
            break;
        case PduIngestionStatus::rejected_invalid:
            audit_federation(runtime, "federation.pdu_rejected_invalid", request.origin, request.target,
                             ingestion.reason);
            break;
        case PduIngestionStatus::internal_error:
            audit_federation(runtime, "federation.pdu_internal_error", request.origin, request.target,
                             ingestion.reason);
            break;
        }
    }

    auto edus_dispatched = std::size_t{0U};
    auto edus_dropped = std::size_t{0U};
    for (auto const& [edu_type, edu_content] : parsed_body.edus)
    {
        auto envelope = parse_inbound_edu_envelope(edu_type, request.origin, edu_content);
        if (!envelope.has_value())
        {
            ++edus_dropped;
            continue;
        }
        if (!runtime.edu_sink)
        {
            ++edus_dispatched;
            continue;
        }
        auto const disposition = runtime.edu_sink(*envelope);
        if (disposition.status == EduDispositionStatus::accepted)
        {
            ++edus_dispatched;
        }
        else
        {
            ++edus_dropped;
        }
    }

    remote->trust.consecutive_failures = 0U;
    runtime.accepted_transactions.push_back(
        {request.origin, transaction.transaction_id, transaction.pdus.size(), transaction.edus.size()});
    log_diagnostic("transaction.accepted", {
                                               {"origin",              request.origin,                          false},
                                               {"transaction_id",      transaction.transaction_id,              false},
                                               {"pdu_count",           std::to_string(transaction.pdus.size()), false},
                                               {"pdu_appended",        std::to_string(pdus_appended),           false},
                                               {"pdu_state_conflicts", std::to_string(pdus_state_conflict),     false},
                                               {"pdu_state_resolved",  std::to_string(pdus_state_resolved),     false},
                                               {"edu_count",           std::to_string(transaction.edus.size()), false},
                                               {"edu_dispatched",      std::to_string(edus_dispatched),         false},
                                               {"edu_dropped",         std::to_string(edus_dropped),            false}
    });
    audit_federation(runtime, "federation.accepted", request.origin, request.target,
                     federation_route_audit_event(route_match.route, request.origin));
    if (!runtime.pdu_sink && !runtime.edu_sink && transaction.edus.empty())
    {
        return {200U, serialize_response_object(canonicaljson::Object{
                          canonicaljson::make_member("pdus", canonicaljson::Value{std::move(pdu_errors)}),
                      })};
    }
    return {200U, serialize_response_object(canonicaljson::Object{
                      canonicaljson::make_member("pdus", canonicaljson::Value{std::move(pdu_errors)}),
                  })};
}

auto federation_runtime_summary(FederationRuntimeState const& runtime) -> std::string
{
    return "Federation runtime remotes=" + std::to_string(runtime.remotes.size()) +
           " accepted_transactions=" + std::to_string(runtime.accepted_transactions.size()) +
           " audit_events=" + std::to_string(runtime.audit_events.size());
}

auto federation_audit_is_safe(FederationRuntimeState const& runtime) noexcept -> bool
{
    return std::ranges::all_of(runtime.audit_events, [](observability::AuditLogEvent const& event) {
        return event.reason_code.find("sig:v1:") == std::string::npos &&
               event.reason_code.find("verify_token") == std::string::npos;
    });
}

} // namespace merovingian::federation
