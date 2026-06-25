// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// GCC 16 with -O2 and LTO emits a false-positive -Wmaybe-uninitialized warning
// in std::ranges::any_of when inlining DispatchResult's std::string members.
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif

#include "merovingian/homeserver/client_server.hpp"

#include "merovingian/auth/identity.hpp"
#include "merovingian/auth/key_api.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/core/query_params.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/outbound_membership.hpp"
#include "merovingian/federation/outbound_transaction.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/local_services.hpp"
#include "merovingian/homeserver/media_service.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/space_hierarchy.hpp"
#include "merovingian/http/rate_limit.hpp"
#include "merovingian/http/request.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/rooms/room_version_policy.hpp"
#include "merovingian/sync/sliding_sync.hpp"
#include "merovingian/sync/sliding_sync_extensions.hpp"
#include "merovingian/sync/sliding_sync_parser.hpp"
#include "merovingian/sync/sliding_sync_room_builder.hpp"
#include "merovingian/sync/sliding_sync_room_list.hpp"
#include "merovingian/sync/stream_token.hpp"
#include "merovingian/sync/sync_filter.hpp"
#include "merovingian/sync/sync_notifier.hpp"
#include "merovingian/trust_safety/policy_engine.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

#include <sodium.h>

namespace merovingian::homeserver
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("client_server", event, std::move(fields)));
    }

    [[nodiscard]] auto starts_with(std::string_view v, std::string_view p) noexcept -> bool
    {
        return v.size() >= p.size() && v.substr(0U, p.size()) == p;
    }

    [[nodiscard]] auto ends_with(std::string_view v, std::string_view suffix) noexcept -> bool
    {
        return v.size() >= suffix.size() && v.substr(v.size() - suffix.size()) == suffix;
    }

    // Wrap a complete LocalHttpResponse in a DispatchResult.
    [[nodiscard]] auto complete(LocalHttpResponse response) -> DispatchResult
    {
        return DispatchResult{DispatchResult::Status::complete, std::move(response), {}};
    }

    // Convenience wrappers that build a LocalHttpResponse and wrap it in
    // a DispatchResult in one call.
    // Look up a single header in a parsed request. Returns the value or an
    // empty string view when the header is missing. Match is case-insensitive
    // because the wire spelling varies by client.
    [[nodiscard]] auto request_header(LocalHttpRequest const& req, std::string_view name) noexcept -> std::string_view
    {
        for (auto const& header : req.headers)
        {
            if (header.name.size() == name.size())
            {
                auto equal = true;
                for (std::size_t i = 0U; i < header.name.size(); ++i)
                {
                    auto const a = static_cast<unsigned char>(header.name[i]);
                    auto const b = static_cast<unsigned char>(name[i]);
                    auto const lo_a = (a >= 'A' && a <= 'Z') ? static_cast<unsigned char>(a + ('a' - 'A')) : a;
                    auto const lo_b = (b >= 'A' && b <= 'Z') ? static_cast<unsigned char>(b + ('a' - 'A')) : b;
                    if (lo_a != lo_b)
                    {
                        equal = false;
                        break;
                    }
                }
                if (equal)
                {
                    return header.value;
                }
            }
        }
        return {};
    }

    // Determine which `Access-Control-Allow-Origin` value to emit, if any.
    // Returns the empty string when the request's Origin is not in the
    // configured allow-list (CORS spec: the header MUST be absent in that
    // case, not set to a literal `null`).
    [[nodiscard]] auto resolve_allow_origin(LocalHttpRequest const& req, config::CorsConfig const& cors) -> std::string
    {
        if (cors.allowed_origins.empty())
        {
            return {};
        }
        auto const origin = request_header(req, "Origin");
        if (origin.empty())
        {
            // Non-browser request: no Origin header means CORS does not
            // apply, so we omit the response header as well.
            return {};
        }
        for (auto const& allowed : cors.allowed_origins)
        {
            if (allowed == "*")
            {
                return "*";
            }
            if (allowed == origin)
            {
                // Single explicit origin: echo it back so the browser
                // accepts the response.
                return std::string{origin};
            }
        }
        return {};
    }

    // Append an `Access-Control-Allow-*` line to a response. Skips entries
    // that are already present (CORS spec forbids duplicates).
    auto append_header_if_missing(std::vector<std::pair<std::string, std::string>>& headers, std::string_view name,
                                  std::string value) -> void
    {
        if (!http::header_name_is_valid(name) || !http::header_value_is_valid(value))
        {
            return;
        }
        for (auto const& existing : headers)
        {
            if (existing.first == name)
            {
                return;
            }
        }
        headers.emplace_back(std::string{name}, std::move(value));
    }

    // Apply the runtime's CORS policy to a response. Always sets `Vary:
    // Origin` so intermediate caches do not collapse responses across
    // origins. For OPTIONS preflight also attaches the methods, headers,
    // and max-age so the browser can short-circuit the next request.
    auto apply_cors_headers(LocalHttpRequest const& req, LocalHttpResponse& response, config::CorsConfig const& cors)
        -> void
    {
        append_header_if_missing(response.headers, "X-Content-Type-Options", "nosniff");
        if (cors.allowed_origins.empty())
        {
            return;
        }
        auto const allow_origin = resolve_allow_origin(req, cors);
        if (!allow_origin.empty())
        {
            append_header_if_missing(response.headers, "Access-Control-Allow-Origin", allow_origin);
        }
        append_header_if_missing(response.headers, "Vary", "Origin");
        if (req.method == "OPTIONS")
        {
            if (cors.allow_credentials)
            {
                append_header_if_missing(response.headers, "Access-Control-Allow-Credentials", "true");
            }
            if (!cors.allow_methods.empty())
            {
                append_header_if_missing(response.headers, "Access-Control-Allow-Methods", cors.allow_methods);
            }
            if (!cors.allow_headers.empty())
            {
                append_header_if_missing(response.headers, "Access-Control-Allow-Headers", cors.allow_headers);
            }
            append_header_if_missing(response.headers, "Access-Control-Max-Age", std::to_string(cors.max_age));
        }
    }

    [[nodiscard]] auto dispatch_resp(LocalHttpRequest const& req, ClientServerRuntime const& rt, std::uint16_t status,
                                     std::string body) -> DispatchResult
    {
        auto response = LocalHttpResponse{status, std::move(body), {}};
        apply_cors_headers(req, response, rt.cors);
        return DispatchResult{DispatchResult::Status::complete, std::move(response), {}};
    }

    [[nodiscard]] auto dispatch_err(LocalHttpRequest const& req, ClientServerRuntime const& rt, std::uint16_t status,
                                    std::string_view errcode, std::string_view error) -> DispatchResult
    {
        auto response = LocalHttpResponse{status, matrix_error(errcode, error), {}};
        apply_cors_headers(req, response, rt.cors);
        return DispatchResult{DispatchResult::Status::complete, std::move(response), {}};
    }

    // Collect the unique remote server names that have members in a room,

    // Collect the unique remote server names that have members in a room,
    // excluding the local server. Used to federate outbound EDUs and PDUs.
    [[nodiscard]] auto remote_servers_in_room(HomeserverRuntime const& runtime, LocalRoom const& room)
        -> std::vector<std::string>
    {
        auto const& server_name = runtime.config.server().server_name;
        auto servers = std::vector<std::string>{};
        for (auto const& member : room.members)
        {
            auto const colon = member.rfind(':');
            if (colon == std::string::npos)
            {
                continue;
            }
            auto const member_server = member.substr(colon + 1);
            if (member_server != server_name && std::ranges::find(servers, member_server) == servers.end())
            {
                servers.emplace_back(member_server);
            }
        }
        return servers;
    }

    // Dispatch an EDU to all remote servers that have members in the given room.
    // The EDU is wrapped in a federation transaction with empty PDUs. Returns the
    // number of destinations the EDU was enqueued to.
    auto dispatch_outbound_edu(HomeserverRuntime& runtime, LocalRoom const& room, std::string_view edu_type,
                               std::string_view edu_content_json) -> std::size_t
    {
        wire_federation_callbacks(runtime);
        if (runtime.dispatch_worker == nullptr)
        {
            return 0U;
        }
        auto const destinations = remote_servers_in_room(runtime, room);
        if (destinations.empty())
        {
            return 0U;
        }
        auto const& server_name = runtime.config.server().server_name;
        // Build the transaction body through the shared federation helper so the EDU is
        // keyed by "edu_type" per spec; a bare "type" key makes Synapse 500 the transaction.
        auto const tx_body_opt = federation::build_edu_transaction_body(server_name, edu_type, edu_content_json);
        if (!tx_body_opt.has_value())
        {
            return 0U;
        }
        auto const& tx_body = *tx_body_opt;
        auto const tx_id = federation::make_federation_transaction_id();
        auto enqueued = std::size_t{0U};
        for (auto const& destination : destinations)
        {
            auto target = "/_matrix/federation/v1/send/" + tx_id;
            auto transaction = federation::make_outbound_transaction(destination, "PUT", target, server_name, tx_body);
            transaction.transaction_id = tx_id;
            if (runtime.dispatch_worker->enqueue(std::move(transaction)))
            {
                ++enqueued;
            }
        }
        return enqueued;
    }

    // Dispatch a single EDU to a specific remote server without needing a
    // room — used for m.direct_to_device and m.device_list_update delivery
    // where the destinations are known from user IDs rather than room membership.
    auto dispatch_edu_to_server(HomeserverRuntime& runtime, std::string_view destination, std::string_view edu_type,
                                std::string_view edu_content_json) -> bool
    {
        wire_federation_callbacks(runtime);
        if (runtime.dispatch_worker == nullptr)
        {
            return false;
        }
        // Shared builder keys the EDU by "edu_type" per the federation spec.
        auto const& server_name = runtime.config.server().server_name;
        auto const tx_body = federation::build_edu_transaction_body(server_name, edu_type, edu_content_json);
        if (!tx_body.has_value())
        {
            return false;
        }
        auto const tx_id = federation::make_federation_transaction_id();
        auto target = "/_matrix/federation/v1/send/" + tx_id;
        auto transaction =
            federation::make_outbound_transaction(std::string{destination}, "PUT", target, server_name, *tx_body);
        transaction.transaction_id = tx_id;
        return runtime.dispatch_worker->enqueue(std::move(transaction));
    }

    // Collect all unique remote server names across every room that user_id is
    // currently a member of. Used to find destinations for m.device_list_update.
    [[nodiscard]] auto remote_servers_for_user(HomeserverRuntime const& runtime, std::string_view user_id)
        -> std::vector<std::string>
    {
        auto const& server_name = runtime.config.server().server_name;
        auto servers = std::vector<std::string>{};
        for (auto const& room : runtime.database.rooms)
        {
            if (!std::ranges::any_of(room.members, [user_id](auto const& m) {
                    return m == user_id;
                }))
            {
                continue;
            }
            for (auto const& member : room.members)
            {
                auto const colon = member.rfind(':');
                if (colon == std::string::npos)
                {
                    continue;
                }
                auto const server = member.substr(colon + 1U);
                if (server != server_name && std::ranges::find(servers, server) == servers.end())
                {
                    servers.emplace_back(server);
                }
            }
        }
        return servers;
    }

    // Send m.device_list_update EDUs for every device the user owns to each
    // server in destinations. Called after key upload or room join so remote
    // servers learn about the local user's devices and can establish Olm
    // sessions (Matrix spec v1.18 device-list-updates-between-servers).
    auto broadcast_device_list_updates(ClientServerRuntime& rt, std::string_view user_id,
                                       std::vector<std::string> const& destinations) -> void
    {
        if (destinations.empty())
        {
            return;
        }
        auto const& store = rt.homeserver.database.persistent_store;
        // stream_id is a monotonic counter remote servers use to detect gaps;
        // reuse next_sync_stream_id since it is already monotonically bumped
        // on every device list change and to-device enqueue.
        auto const stream_id = static_cast<std::int64_t>(store.next_sync_stream_id);
        for (auto const& device : store.devices)
        {
            if (device.user_id != user_id)
            {
                continue;
            }
            // Build EDU content per spec v1.18 device-list-updates-between-servers.
            auto content_obj = canonicaljson::Object{};
            content_obj.push_back(canonicaljson::make_member("device_id", canonicaljson::Value{device.device_id}));
            // Include device identity keys so the receiving server (e.g. Synapse)
            // updates its cache immediately without a separate GET /user/devices
            // fetch.  Without this field there is a race window between the EDU
            // and the async refetch: if the remote client encrypts during that
            // window it uses stale keys, producing OlmError::MissingCiphertext on
            // the Merovingian-side recipient (Matrix spec v1.18 §m.device_list_update).
            auto const dk_it =
                std::ranges::find_if(store.device_keys, [&device, user_id](database::PersistentDeviceKey const& dk) {
                    return dk.user_id == user_id && dk.device_id == device.device_id;
                });
            if (dk_it != store.device_keys.end())
            {
                auto const parsed_keys = canonicaljson::parse_lossless(dk_it->json);
                if (parsed_keys.error == canonicaljson::ParseError::none)
                {
                    content_obj.push_back(canonicaljson::make_member("keys", parsed_keys.value));
                }
            }
            content_obj.push_back(canonicaljson::make_member("prev_id", canonicaljson::Value{canonicaljson::Array{}}));
            content_obj.push_back(canonicaljson::make_member("stream_id", canonicaljson::Value{stream_id}));
            content_obj.push_back(canonicaljson::make_member("user_id", canonicaljson::Value{std::string{user_id}}));
            auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(content_obj)});
            if (serialized.error != canonicaljson::CanonicalJsonError::none)
            {
                continue;
            }
            for (auto const& destination : destinations)
            {
                std::ignore =
                    dispatch_edu_to_server(rt.homeserver, destination, "m.device_list_update", serialized.output);
            }
        }
    }

    // Generate a 32-character lowercase hex filter ID from 16 random bytes.
    // Uses libsodium so the randomness is cryptographically strong, matching
    // the same pattern used for access tokens.
    [[nodiscard]] auto generate_filter_id() -> std::string
    {
        std::ignore = sodium_init();
        auto bytes = std::array<unsigned char, 16U>{};
        randombytes_buf(bytes.data(), bytes.size());
        auto output = std::string(bytes.size() * 2U + 1U, '\0');
        std::ignore = sodium_bin2hex(output.data(), output.size(), bytes.data(), bytes.size());
        output.pop_back(); // remove the null terminator included by sodium_bin2hex
        return output;
    }

    // Generate a server-side opaque device_id for clients that omit
    // `device_id` from the login body. The spec (Matrix v1.18 §5.3.2
    // login) requires the server to mint a unique opaque id; the
    // previous "MEROVINGIAN" literal caused every device_id-less login
    // to collide on a single shared device record.
    [[nodiscard]] auto generate_device_id() -> std::string
    {
        std::ignore = sodium_init();
        auto bytes = std::array<unsigned char, 16U>{};
        randombytes_buf(bytes.data(), bytes.size());
        auto output = std::string(bytes.size() * 2U + 1U, '\0');
        std::ignore = sodium_bin2hex(output.data(), output.size(), bytes.data(), bytes.size());
        output.pop_back(); // remove the null terminator included by sodium_bin2hex
        return output;
    }

    [[nodiscard]] auto lowercase_hex(unsigned char const* bytes, std::size_t size) -> std::string
    {
        auto output = std::string(size * 2U + 1U, '\0');
        std::ignore = sodium_bin2hex(output.data(), output.size(), bytes, size);
        output.pop_back();
        return output;
    }

    // Thin builder facade over the project's canonical JSON value model.
    // Response paths construct a Value tree and hand it to serialize_canonical
    // so escaping (including control characters as \u00XX) is handled by the
    // shared, audit-friendly serializer instead of a per-call hand-rolled
    // escaper. The canonical key ordering is a side effect; response bodies
    // remain valid JSON and existing tests that match substrings continue to
    // pass.
    [[nodiscard]] auto json_str(std::string_view value) -> canonicaljson::Value
    {
        return canonicaljson::Value{std::string{value}};
    }

    [[nodiscard]] auto json_int(std::int64_t value) -> canonicaljson::Value
    {
        return canonicaljson::Value{value};
    }

    [[nodiscard]] auto json_bool(bool value) -> canonicaljson::Value
    {
        return canonicaljson::Value{value};
    }

    [[nodiscard]] auto json_arr(canonicaljson::Array items) -> canonicaljson::Value
    {
        return canonicaljson::Value{std::move(items)};
    }

    [[nodiscard]] auto json_obj(canonicaljson::Object members) -> canonicaljson::Value
    {
        return canonicaljson::Value{std::move(members)};
    }

    [[nodiscard]] auto json_member(std::string key, canonicaljson::Value value) -> canonicaljson::ObjectMember
    {
        return canonicaljson::make_member(std::move(key), std::move(value));
    }

    [[nodiscard]] auto json_serialize(canonicaljson::Value const& value) -> std::string
    {
        auto const result = canonicaljson::serialize_canonical(value);
        return result.output;
    }

    // 401 with soft_logout=true: token was found-but-expired so the client should
    // use its refresh token rather than clearing its session (spec §5.7.2).
    [[nodiscard]] auto dispatch_err_soft_logout(LocalHttpRequest const& req, ClientServerRuntime const& rt,
                                                std::uint16_t status, std::string_view errcode, std::string_view error)
        -> DispatchResult
    {
        auto body = json_serialize(json_obj({
            json_member("errcode", json_str(errcode)),
            json_member("error", json_str(error)),
            json_member("soft_logout", json_bool(true)),
        }));
        auto response = LocalHttpResponse{status, std::move(body), {}};
        apply_cors_headers(req, response, rt.cors);
        return DispatchResult{DispatchResult::Status::complete, std::move(response), {}};
    }

    // Embeds a pre-built JSON blob (e.g. a stored device key payload) inside
    // a larger response value. The blob is parsed strictly through the
    // canonical JSON parser so any escaping, structure, and UTF-8 issues
    // surface here rather than going onto the wire. On parse failure the
    // caller receives canonicaljson::Value{} (a null), which serializes to
    // "null" and keeps the response body well-formed.
    [[nodiscard]] auto json_embed_raw(std::string_view raw) -> canonicaljson::Value
    {
        auto result = canonicaljson::parse_lossless(raw);
        if (result.error != canonicaljson::ParseError::none)
        {
            return canonicaljson::Value{};
        }
        return std::move(result.value);
    }

    [[nodiscard]] auto push_action_set_tweak(std::string_view tweak) -> canonicaljson::Value
    {
        return json_obj({json_member("set_tweak", json_str(tweak))});
    }

    [[nodiscard]] auto push_action_set_tweak(std::string_view tweak, std::string_view value) -> canonicaljson::Value
    {
        return json_obj({
            json_member("set_tweak", json_str(tweak)),
            json_member("value", json_str(value)),
        });
    }

    [[nodiscard]] auto push_action_set_tweak(std::string_view tweak, bool value) -> canonicaljson::Value
    {
        return json_obj({
            json_member("set_tweak", json_str(tweak)),
            json_member("value", json_bool(value)),
        });
    }

    [[nodiscard]] auto push_condition_event_match(std::string_view key, std::string_view pattern)
        -> canonicaljson::Value
    {
        return json_obj({
            json_member("key", json_str(key)),
            json_member("kind", json_str("event_match")),
            json_member("pattern", json_str(pattern)),
        });
    }

    [[nodiscard]] auto push_condition_event_property_is(std::string_view key, std::string_view value)
        -> canonicaljson::Value
    {
        return json_obj({
            json_member("key", json_str(key)),
            json_member("kind", json_str("event_property_is")),
            json_member("value", json_str(value)),
        });
    }

    [[nodiscard]] auto push_condition_event_property_is(std::string_view key, bool value) -> canonicaljson::Value
    {
        return json_obj({
            json_member("key", json_str(key)),
            json_member("kind", json_str("event_property_is")),
            json_member("value", json_bool(value)),
        });
    }

    [[nodiscard]] auto push_condition_event_property_contains(std::string_view key, std::string_view value)
        -> canonicaljson::Value
    {
        return json_obj({
            json_member("key", json_str(key)),
            json_member("kind", json_str("event_property_contains")),
            json_member("value", json_str(value)),
        });
    }

    [[nodiscard]] auto push_condition_room_member_count(std::string_view member_count) -> canonicaljson::Value
    {
        return json_obj({
            json_member("is", json_str(member_count)),
            json_member("kind", json_str("room_member_count")),
        });
    }

    [[nodiscard]] auto push_condition_sender_notification_permission(std::string_view key) -> canonicaljson::Value
    {
        return json_obj({
            json_member("key", json_str(key)),
            json_member("kind", json_str("sender_notification_permission")),
        });
    }

    // Spec: CS API v1.18 §m.rule.contains_display_name — condition kind that matches when
    // the event body contains the receiving user's current display name (case-insensitive).
    // No additional fields required beyond "kind".
    [[nodiscard]] auto push_condition_contains_display_name() -> canonicaljson::Value
    {
        return json_obj({
            json_member("kind", json_str("contains_display_name")),
        });
    }

    [[nodiscard]] auto push_rule(std::string_view rule_id, bool enabled, canonicaljson::Array conditions,
                                 canonicaljson::Array actions) -> canonicaljson::Value
    {
        return json_obj({
            json_member("actions", json_arr(std::move(actions))),
            json_member("conditions", json_arr(std::move(conditions))),
            json_member("default", json_bool(true)),
            json_member("enabled", json_bool(enabled)),
            json_member("rule_id", json_str(rule_id)),
        });
    }

    [[nodiscard]] auto default_push_ruleset(std::string_view user_id) -> canonicaljson::Object
    {
        auto override_rules = canonicaljson::Array{};
        override_rules.push_back(push_rule(".m.rule.master", false, {}, {}));
        override_rules.push_back(
            push_rule(".m.rule.suppress_notices", true,
                      canonicaljson::Array{push_condition_event_match("content.msgtype", "m.notice")}, {}));
        override_rules.push_back(push_rule(".m.rule.invite_for_me", true,
                                           canonicaljson::Array{
                                               push_condition_event_match("type", "m.room.member"),
                                               push_condition_event_match("content.membership", "invite"),
                                               push_condition_event_match("state_key", user_id),
                                           },
                                           canonicaljson::Array{
                                               json_str("notify"),
                                               push_action_set_tweak("sound", std::string_view{"default"}),
                                               push_action_set_tweak("highlight", false),
                                           }));
        override_rules.push_back(push_rule(".m.rule.member_event", true,
                                           canonicaljson::Array{push_condition_event_match("type", "m.room.member")},
                                           {}));
        override_rules.push_back(push_rule(
            ".m.rule.is_user_mention", true,
            canonicaljson::Array{push_condition_event_property_contains("content.m\\.mentions.user_ids", user_id)},
            canonicaljson::Array{
                json_str("notify"),
                push_action_set_tweak("sound", std::string_view{"default"}),
                push_action_set_tweak("highlight"),
            }));
        override_rules.push_back(push_rule(".m.rule.is_room_mention", true,
                                           canonicaljson::Array{
                                               push_condition_event_property_is("content.m\\.mentions.room", true),
                                               push_condition_sender_notification_permission("room"),
                                           },
                                           canonicaljson::Array{
                                               json_str("notify"),
                                               push_action_set_tweak("highlight"),
                                           }));
        override_rules.push_back(push_rule(".m.rule.tombstone", true,
                                           canonicaljson::Array{
                                               push_condition_event_match("type", "m.room.tombstone"),
                                               push_condition_event_match("state_key", ""),
                                           },
                                           canonicaljson::Array{
                                               json_str("notify"),
                                               push_action_set_tweak("highlight"),
                                           }));
        override_rules.push_back(push_rule(".m.rule.reaction", true,
                                           canonicaljson::Array{push_condition_event_match("type", "m.reaction")}, {}));
        override_rules.push_back(push_rule(".m.rule.room.server_acl", true,
                                           canonicaljson::Array{
                                               push_condition_event_match("type", "m.room.server_acl"),
                                               push_condition_event_match("state_key", ""),
                                           },
                                           {}));
        override_rules.push_back(push_rule(".m.rule.suppress_edits", true,
                                           canonicaljson::Array{push_condition_event_property_is(
                                               "content.m\\.relates_to.rel_type", std::string_view{"m.replace"})},
                                           {}));
        // Spec: CS API v1.18 §.m.rule.contains_display_name — legacy rule for clients that do
        // not use m.mentions; matches messages whose body contains the user's display name.
        override_rules.push_back(push_rule(".m.rule.contains_display_name", true,
                                           canonicaljson::Array{push_condition_contains_display_name()},
                                           canonicaljson::Array{
                                               json_str("notify"),
                                               push_action_set_tweak("sound", std::string_view{"default"}),
                                               push_action_set_tweak("highlight"),
                                           }));
        // Spec: CS API v1.18 §.m.rule.roomnotif — matches messages containing "@room" when
        // the sender has permission to notify the whole room.
        override_rules.push_back(push_rule(".m.rule.roomnotif", true,
                                           canonicaljson::Array{
                                               push_condition_event_match("content.body", "@room"),
                                               push_condition_sender_notification_permission("room"),
                                           },
                                           canonicaljson::Array{
                                               json_str("notify"),
                                               push_action_set_tweak("highlight"),
                                           }));

        auto underride_rules = canonicaljson::Array{};
        underride_rules.push_back(push_rule(".m.rule.call", true,
                                            canonicaljson::Array{push_condition_event_match("type", "m.call.invite")},
                                            canonicaljson::Array{
                                                json_str("notify"),
                                                push_action_set_tweak("sound", std::string_view{"ring"}),
                                                push_action_set_tweak("highlight", false),
                                            }));
        underride_rules.push_back(push_rule(".m.rule.encrypted_room_one_to_one", true,
                                            canonicaljson::Array{
                                                push_condition_room_member_count("2"),
                                                push_condition_event_match("type", "m.room.encrypted"),
                                            },
                                            canonicaljson::Array{
                                                json_str("notify"),
                                                push_action_set_tweak("sound", std::string_view{"default"}),
                                                push_action_set_tweak("highlight", false),
                                            }));
        underride_rules.push_back(push_rule(".m.rule.room_one_to_one", true,
                                            canonicaljson::Array{
                                                push_condition_room_member_count("2"),
                                                push_condition_event_match("type", "m.room.message"),
                                            },
                                            canonicaljson::Array{
                                                json_str("notify"),
                                                push_action_set_tweak("sound", std::string_view{"default"}),
                                                push_action_set_tweak("highlight", false),
                                            }));
        underride_rules.push_back(push_rule(".m.rule.message", true,
                                            canonicaljson::Array{push_condition_event_match("type", "m.room.message")},
                                            canonicaljson::Array{
                                                json_str("notify"),
                                                push_action_set_tweak("highlight", false),
                                            }));
        underride_rules.push_back(push_rule(
            ".m.rule.encrypted", true, canonicaljson::Array{push_condition_event_match("type", "m.room.encrypted")},
            canonicaljson::Array{
                json_str("notify"),
                push_action_set_tweak("highlight", false),
            }));

        return canonicaljson::Object{
            json_member("content", json_arr({})),
            json_member("override", json_arr(std::move(override_rules))),
            json_member("room", json_arr({})),
            json_member("sender", json_arr({})),
            json_member("underride", json_arr(std::move(underride_rules))),
        };
    }

    [[nodiscard]] auto push_rule_array(canonicaljson::Object const& ruleset, std::string_view kind)
        -> canonicaljson::Array const*
    {
        auto const value = std::ranges::find_if(ruleset, [kind](canonicaljson::ObjectMember const& member) {
            return member.key == kind;
        });
        if (value == ruleset.end())
        {
            return nullptr;
        }
        return std::get_if<canonicaljson::Array>(&value->value->storage());
    }

    [[nodiscard]] auto push_rule_object(canonicaljson::Object const& ruleset, std::string_view kind,
                                        std::string_view rule_id) -> canonicaljson::Object const*
    {
        auto const* rules = push_rule_array(ruleset, kind);
        if (rules == nullptr)
        {
            return nullptr;
        }
        for (auto const& rule : *rules)
        {
            auto const* rule_object = std::get_if<canonicaljson::Object>(&rule.storage());
            if (rule_object == nullptr)
            {
                continue;
            }
            auto const member = std::ranges::find_if(*rule_object, [](canonicaljson::ObjectMember const& current) {
                return current.key == "rule_id";
            });
            if (member == rule_object->end())
            {
                continue;
            }
            auto const* current_rule_id = std::get_if<std::string>(&member->value->storage());
            if (current_rule_id != nullptr && *current_rule_id == rule_id)
            {
                return rule_object;
            }
        }
        return nullptr;
    }

    // Convert a stored persistent event to a client-facing event value.
    // Parses the stored signed event JSON and injects the event_id field
    // (room v3+ events do not carry event_id in the wire format, but
    // clients always expect it in /sync responses).
    [[nodiscard]] auto client_event_value(database::PersistentEvent const& event) -> canonicaljson::Value
    {
        auto const parsed = canonicaljson::parse_lossless(event.json);
        if (parsed.error == canonicaljson::ParseError::none)
        {
            auto const* obj = std::get_if<canonicaljson::Object>(&parsed.value.storage());
            if (obj != nullptr)
            {
                auto client_obj = *obj;
                client_obj.push_back(canonicaljson::make_member("event_id", canonicaljson::Value{event.event_id}));
                return canonicaljson::Value{std::move(client_obj)};
            }
        }
        // Fallback: minimal event so /sync never emits a bare null.
        return json_obj({
            json_member("event_id", json_str(event.event_id)),
            json_member("sender", json_str(event.sender_user_id)),
        });
    }

    [[nodiscard]] auto resp(std::uint16_t status, std::string body) -> LocalHttpResponse
    {
        return {status, std::move(body)};
    }

    [[nodiscard]] auto err(std::uint16_t status, std::string_view code, std::string_view message) -> LocalHttpResponse
    {
        return {status, matrix_error(code, message)};
    }

    [[nodiscard]] auto bad_http_request(std::uint16_t status, std::string_view message) -> LocalHttpResponse
    {
        return err(status, "M_BAD_REQUEST", message);
    }

    struct MatrixRegisterBody final
    {
        std::string localpart{};
        std::string password{};
        std::string registration_token{};
        std::string device_id{};
        std::string display_name{};
        bool inhibit_login{false};
    };

    struct MatrixRegisterEmailRequestBody final
    {
        std::string client_secret{};
        std::string email{};
        std::optional<std::string> next_link{};
        std::uint64_t send_attempt{0U};
    };

    struct MatrixRegisterMsisdnRequestBody final
    {
        std::string client_secret{};
        std::string country{};
        std::string phone_number{};
        std::optional<std::string> next_link{};
        std::uint64_t send_attempt{0U};
    };

    struct MatrixAccountThreePidAddBody final
    {
        std::string client_secret{};
        std::string sid{};
        std::optional<std::string> password{};
    };

    struct MatrixAccountThreePidBindBody final
    {
        std::string client_secret{};
        std::string sid{};
        std::string id_server{};
        std::string id_access_token{};
    };

    struct MatrixAccountThreePidDeleteBody final
    {
        std::string address{};
        std::string medium{};
        std::optional<std::string> id_server{};
    };

    struct MatrixLoginBody final
    {
        std::string user_id{};
        std::string password{};
        std::string device_id{};
        std::string display_name{};
        bool supports_refresh_tokens{false};
    };

    struct MatrixRefreshBody final
    {
        std::string refresh_token{};
    };

    struct MatrixDeviceUpdateBody final
    {
        std::string display_name{};
    };

    struct MatrixSafetyReportBody final
    {
        std::string reason{};
    };

    struct MatrixAdminReviewBody final
    {
        std::string reason{"manual_review"};
    };

    struct MatrixAdminPolicyRuleBody final
    {
        std::string action{"deny"};
        std::string reason{"manual_review"};
    };

    struct ReportPathParts final
    {
        std::string room_id{};
        std::string event_id{};
    };

    struct RoomSendPathParts final
    {
        std::string room_id{};
        std::string event_type{};
        std::string txn_id{};
    };

    struct RoomStatePathParts final
    {
        std::string room_id{};
        std::string event_type{};
        std::string state_key{};
    };

    struct RoomEventPathParts final
    {
        std::string room_id{};
        std::string event_id{};
    };

    struct RoomRelationsPathParts final
    {
        std::string room_id{};
        std::string event_id{};
        std::optional<std::string> rel_type{};
        std::optional<std::string> event_type{};
    };

    struct AdminReviewPathParts final
    {
        trust_safety::ReviewTarget target{trust_safety::ReviewTarget::media};
        std::string target_id{};
    };

    struct AdminPolicyRulePathParts final
    {
        std::string scope{};
        std::string entity{};
    };

    struct SendToDevicePathParts final
    {
        std::string event_type{};
        std::string txn_id{};
    };

    struct RoomKeyBackupPathParts final
    {
        std::string room_id{};
        std::optional<std::string> session_id{};
    };

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
        if (value == nullptr)
        {
            return nullptr;
        }
        return std::get_if<std::string>(&value->storage());
    }

    [[nodiscard]] auto boolean_member(canonicaljson::Object const& object, std::string_view key) noexcept -> bool const*
    {
        auto const* value = object_member(object, key);
        if (value == nullptr)
        {
            return nullptr;
        }
        return std::get_if<bool>(&value->storage());
    }

    // Spec v1.18 §"Account suspension": the actions a suspended user MAY
    // perform is an implementation detail, but servers SHOULD permit at least:
    // login + new sessions, /sync and /messages, key verification/cross-signing,
    // key backup, leaving rooms / rejecting invites, redacting their own events,
    // logout, deleting devices, account deactivation, and adding admin contacts.
    // Everything else (joining/knocking, invites, sending messages, profile
    // changes, redacting others' events, creating rooms) is blocked by the
    // request-path gate with M_USER_SUSPENDED. `path` is the query-stripped
    // request path. Best-effort prefix matching; the spec leaves the exact
    // disallowed set to the implementation.
    [[nodiscard]] auto action_allowed_while_suspended(std::string_view method, std::string_view path) noexcept -> bool
    {
        // Login is unauthenticated (handled before the gate) but is listed for
        // completeness: a suspended user creating a new session is permitted.
        if (path == "/_matrix/client/v3/login" || path == "/_matrix/client/v3/sync")
        {
            return true;
        }
        // Logout and logout/all are always permitted (also exempt from locking).
        if (path == "/_matrix/client/v3/logout" || path == "/_matrix/client/v3/logout/all")
        {
            return true;
        }
        // Device key verification / cross-signing / key claiming & querying.
        if (starts_with(path, "/_matrix/client/v3/keys"))
        {
            return true;
        }
        // Server-side room key backup (read + populate).
        if (starts_with(path, "/_matrix/client/v3/room_keys"))
        {
            return true;
        }
        // Cross-signing key storage and device management endpoints.
        if (starts_with(path, "/_matrix/client/v3/keys/device_signing") ||
            starts_with(path, "/_matrix/client/v3/account/deactivate"))
        {
            return true;
        }
        if (path == "/_matrix/client/v3/devices" || path == "/_matrix/client/v3/delete_devices" ||
            starts_with(path, "/_matrix/client/v3/devices/"))
        {
            return true;
        }
        // Per-room allowed actions: leave/reject invites, read /messages, redact.
        if (starts_with(path, "/_matrix/client/v3/rooms/"))
        {
            auto constexpr leave_marker = std::string_view{"/leave"};
            auto constexpr messages_marker = std::string_view{"/messages"};
            auto constexpr redact_marker = std::string_view{"/redact"};
            // PUT /rooms/{roomId}/redact/{eventId} — redacting (own events).
            if (method == "PUT" && path.find(redact_marker) != std::string_view::npos)
            {
                return true;
            }
            // POST /rooms/{roomId}/leave — leave a room or reject an invite.
            if (method == "POST" && path.find(leave_marker) != std::string_view::npos)
            {
                return true;
            }
            // GET /rooms/{roomId}/messages — see and receive messages.
            if (method == "GET" && path.find(messages_marker) != std::string_view::npos)
            {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] auto integer_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::int64_t const*
    {
        auto const* value = object_member(object, key);
        if (value == nullptr)
        {
            return nullptr;
        }
        return std::get_if<std::int64_t>(&value->storage());
    }

    [[nodiscard]] auto string_array_member(canonicaljson::Object const& object, std::string_view key)
        -> std::vector<std::string>
    {
        auto const* value = object_member(object, key);
        auto const* array = value == nullptr ? nullptr : std::get_if<canonicaljson::Array>(&value->storage());
        auto result = std::vector<std::string>{};
        if (array == nullptr)
        {
            return result;
        }
        for (auto const& entry : *array)
        {
            if (auto const* text = std::get_if<std::string>(&entry.storage()); text != nullptr && !text->empty())
            {
                result.push_back(*text);
            }
        }
        return result;
    }

    [[nodiscard]] auto server_name_from_user_id(std::string_view user_id) -> std::string_view
    {
        auto const colon = user_id.rfind(':');
        return colon == std::string_view::npos ? std::string_view{} : user_id.substr(colon + 1U);
    }

    [[nodiscard]] auto event_json_for_id(database::PersistentStore const& store, std::string_view event_id)
        -> std::optional<std::string>
    {
        auto const event = std::ranges::find_if(store.events, [&](database::PersistentEvent const& current) {
            return current.event_id == event_id;
        });
        return event == store.events.end() ? std::nullopt : std::optional<std::string>{event->json};
    }

    [[nodiscard]] auto build_invite_state_events_array(database::PersistentStore const& store, std::string_view room_id,
                                                       std::string_view user_id) -> canonicaljson::Array
    {
        auto result = canonicaljson::Array{};
        auto const invite = database::find_invite(store, room_id, user_id);
        if (!invite.has_value())
        {
            return result;
        }

        auto seen_event_ids = std::vector<std::string>{};
        auto append_event_json = [&](std::string const& event_json) {
            auto parsed = canonicaljson::parse_lossless(event_json);
            if (parsed.error != canonicaljson::ParseError::none)
            {
                return;
            }
            auto const* event = std::get_if<canonicaljson::Object>(&parsed.value.storage());
            if (event == nullptr)
            {
                return;
            }
            if (auto const* event_id = string_member(*event, "event_id"); event_id != nullptr && !event_id->empty())
            {
                if (std::ranges::any_of(seen_event_ids, [event_id](std::string const& seen) {
                        return seen == *event_id;
                    }))
                {
                    return;
                }
                seen_event_ids.push_back(*event_id);
            }
            result.push_back(std::move(parsed.value));
        };

        for (auto const& state_event_json : invite->invite_state_events_json)
        {
            append_event_json(state_event_json);
        }
        append_event_json(invite->signed_event_json);
        return result;
    }

    [[nodiscard]] auto build_knock_state_events_array(database::PersistentStore const& store, std::string_view room_id)
        -> canonicaljson::Array
    {
        auto result = canonicaljson::Array{};
        for (auto const& state : store.state)
        {
            if (state.room_id != room_id)
            {
                continue;
            }
            auto const event_json = event_json_for_id(store, state.event_id);
            if (!event_json.has_value())
            {
                continue;
            }
            auto const parsed = canonicaljson::parse_lossless(*event_json);
            if (parsed.error == canonicaljson::ParseError::none)
            {
                result.push_back(parsed.value);
            }
        }
        return result;
    }

    [[nodiscard]] auto ascii_equal_case_insensitive(std::string_view left, std::string_view right) noexcept -> bool
    {
        if (left.size() != right.size())
        {
            return false;
        }
        for (auto index = std::size_t{0U}; index < left.size(); ++index)
        {
            auto left_char = left[index];
            auto right_char = right[index];
            if (left_char >= 'A' && left_char <= 'Z')
            {
                left_char = static_cast<char>(left_char - 'A' + 'a');
            }
            if (right_char >= 'A' && right_char <= 'Z')
            {
                right_char = static_cast<char>(right_char - 'A' + 'a');
            }
            if (left_char != right_char)
            {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] auto to_lower(std::string_view input) -> std::string
    {
        auto result = std::string{};
        result.reserve(input.size());
        for (auto ch : input)
        {
            if (ch >= 'A' && ch <= 'Z')
            {
                ch = static_cast<char>(ch - 'A' + 'a');
            }
            result.push_back(ch);
        }
        return result;
    }

    [[nodiscard]] auto bearer_access_token(std::vector<http::Header> const& headers) -> std::string
    {
        auto constexpr bearer_prefix = std::string_view{"Bearer "};
        for (auto const& header : headers)
        {
            if (!ascii_equal_case_insensitive(header.name, "authorization"))
            {
                continue;
            }
            if (!starts_with(header.value, bearer_prefix) || header.value.size() == bearer_prefix.size())
            {
                return {};
            }
            return std::string{std::string_view{header.value}.substr(bearer_prefix.size())};
        }
        return {};
    }

    [[nodiscard]] auto object_member_as_object(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Object const*
    {
        auto const* value = object_member(object, key);
        if (value == nullptr)
        {
            return nullptr;
        }
        return std::get_if<canonicaljson::Object>(&value->storage());
    }

    // Returns the room_version string from the room's m.room.create state event.
    // Falls back to "10" for rooms created before version tracking was added.
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
                auto const* content = object_member_as_object(*obj, "content");
                if (content == nullptr)
                {
                    break;
                }
                auto const* version = string_member(*content, "room_version");
                if (version != nullptr && !version->empty())
                {
                    return *version;
                }
                break;
            }
        }
        return "10";
    }

    [[nodiscard]] auto parsed_json_object(std::string_view body) -> std::optional<canonicaljson::Object>
    {
        auto parsed = canonicaljson::parse_lossless(body);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (object == nullptr)
        {
            return std::nullopt;
        }
        return *object;
    }

    // Handles GET/PUT /_matrix/client/v1/admin/lock/{userId} and
    // /_matrix/client/v1/admin/suspend/{userId} (spec v1.18 §"Account locking"
    // and §"Account suspension"). `is_lock` selects the lock endpoint (and the
    // "locked" body/response field); otherwise the suspend endpoint is handled.
    // Authorization (caller MUST be a server admin) is checked before any target
    // lookup to prevent user enumeration. Self-targeting and targeting another
    // administrator are forbidden on PUT (self) and on both verbs (other admin).
    [[nodiscard]] auto handle_account_moderation(ClientServerRuntime& rt, LocalHttpRequest const& req,
                                                 std::string_view request_path, bool is_lock) -> DispatchResult
    {
        auto const admin = authenticated_admin_user(rt.homeserver, req.access_token);
        if (!admin.has_value())
        {
            // Spec MUST: caller MUST be a server admin; checked before lookup.
            return dispatch_err(req, rt, 403U, "M_FORBIDDEN", "Requesting user is not a server administrator.");
        }
        auto constexpr lock_prefix = std::string_view{"/_matrix/client/v1/admin/lock/"};
        auto constexpr suspend_prefix = std::string_view{"/_matrix/client/v1/admin/suspend/"};
        auto const prefix = is_lock ? lock_prefix : suspend_prefix;
        if (!starts_with(request_path, prefix))
        {
            return dispatch_err(req, rt, 404U, "M_UNRECOGNIZED", "route not found");
        }
        auto const encoded_user_id = request_path.substr(prefix.size());
        auto const target_user_id = core::percent_decode_path_component(encoded_user_id);
        // Spec MUST: 400 M_INVALID_PARAM when the userId is not local. A
        // syntactically invalid or non-local ID is rejected without a lookup.
        auto const& local_server = rt.homeserver.config.server().server_name;
        if (!auth::user_id_is_valid(target_user_id) || server_name_from_user_id(target_user_id) != local_server)
        {
            return dispatch_err(req, rt, 400U, "M_INVALID_PARAM", "User does not belong to the local server.");
        }
        // PUT must not target the caller's own account (spec MUST: 403).
        if (req.method == "PUT" && target_user_id == *admin)
        {
            return dispatch_err(req, rt, 403U, "M_FORBIDDEN", "Cannot moderate your own account.");
        }
        // Locate the target user (anti-enumeration: only after caller auth).
        auto const target =
            std::ranges::find_if(rt.homeserver.database.users, [&target_user_id](LocalUser const& current) {
                return current.user_id == target_user_id;
            });
        if (target == rt.homeserver.database.users.end())
        {
            // Spec MUST: 404 M_NOT_FOUND when the user is unknown (or deactivated).
            return dispatch_err(req, rt, 404U, "M_NOT_FOUND", "User not found.");
        }
        // Spec MUST: 403 M_FORBIDDEN when the target is another administrator.
        if (target->admin && target_user_id != *admin)
        {
            return dispatch_err(req, rt, 403U, "M_FORBIDDEN", "Cannot moderate another administrator.");
        }
        auto const field_name = is_lock ? std::string{"locked"} : std::string{"suspended"};
        if (req.method == "GET")
        {
            auto const value = is_lock ? target->locked : target->suspended;
            return dispatch_resp(req, rt, 200U, json_serialize(json_obj({json_member(field_name, json_bool(value))})));
        }
        if (req.method != "PUT")
        {
            return dispatch_err(req, rt, 404U, "M_UNRECOGNIZED", "route not found");
        }
        // PUT: the boolean body member is required (spec MUST: 400 M_BAD_JSON).
        auto const body = parsed_json_object(req.body);
        if (!body.has_value())
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "Request body must be a JSON object.");
        }
        auto const* flag = boolean_member(*body, field_name);
        if (flag == nullptr)
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON",
                                is_lock ? "Missing required 'locked' body member."
                                        : "Missing required 'suspended' body member.");
        }
        // Preserve the other moderation flag when updating one of the two.
        auto const new_suspended = is_lock ? target->suspended : *flag;
        auto const new_locked = is_lock ? *flag : target->locked;
        if (!database::set_user_account_state(rt.homeserver.database.persistent_store, target_user_id, new_suspended,
                                              new_locked))
        {
            return dispatch_err(req, rt, 500U, "M_UNKNOWN", "Failed to persist account state.");
        }
        // Mirror into the in-memory LocalUser vector so the request-path gate
        // (account_state_for_user) and subsequent GET reads see the new state
        // without a restart. set_user_account_state persists + updates the
        // PersistentUser vector; this updates the authoritative LocalUser vector.
        target->suspended = new_suspended;
        target->locked = new_locked;
        auto const audit_event = is_lock ? std::string_view{"account.locked"} : std::string_view{"account.suspended"};
        auto const reason_code = *flag ? (is_lock ? "locked" : "suspended") : (is_lock ? "unlocked" : "unsuspended");
        append_local_audit(rt.homeserver.database, observability::AuditCategory::admin, audit_event, *admin,
                           target_user_id, reason_code);
        return dispatch_resp(req, rt, 200U, json_serialize(json_obj({json_member(field_name, json_bool(*flag))})));
    }

    [[nodiscard]] auto serialized_value(canonicaljson::Value const& value) -> std::optional<std::string>
    {
        auto serialized = canonicaljson::serialize_canonical(value);
        if (serialized.error != canonicaljson::CanonicalJsonError::none)
        {
            return std::nullopt;
        }
        return serialized.output;
    }

    struct MembershipActionBody final
    {
        std::string user_id{};
        std::string reason{};
    };

    [[nodiscard]] auto parse_membership_action_body(std::string_view body) -> std::optional<MembershipActionBody>
    {
        auto const object = parsed_json_object(body);
        if (!object.has_value())
        {
            return std::nullopt;
        }
        auto const* user_id = string_member(*object, "user_id");
        if (user_id == nullptr || user_id->empty())
        {
            return std::nullopt;
        }
        auto const* reason = string_member(*object, "reason");
        return MembershipActionBody{*user_id, reason == nullptr ? std::string{} : *reason};
    }

    [[nodiscard]] auto object_member_object(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Object const*
    {
        auto const* value = object_member(object, key);
        if (value == nullptr)
        {
            return nullptr;
        }
        return std::get_if<canonicaljson::Object>(&value->storage());
    }

    [[nodiscard]] auto parse_register_body(std::string_view body) -> std::optional<MatrixRegisterBody>
    {
        auto const object = parsed_json_object(body);
        if (!object.has_value())
        {
            return std::nullopt;
        }
        auto const* username = string_member(*object, "username");
        if (username == nullptr)
        {
            username = string_member(*object, "user");
        }
        auto const* password = string_member(*object, "password");
        if (username == nullptr || password == nullptr)
        {
            return std::nullopt;
        }
        auto const* token = string_member(*object, "token");
        if (auto const* auth = object_member_object(*object, "auth"); auth != nullptr)
        {
            if (auto const* auth_token = string_member(*auth, "token"); auth_token != nullptr)
            {
                token = auth_token;
            }
        }
        auto const* device_id = string_member(*object, "device_id");
        auto const* display_name = string_member(*object, "initial_device_display_name");
        auto const* inhibit_login = boolean_member(*object, "inhibit_login");
        return MatrixRegisterBody{*username,
                                  *password,
                                  token == nullptr ? std::string{} : *token,
                                  device_id == nullptr ? std::string{} : *device_id,
                                  display_name == nullptr ? std::string{} : *display_name,
                                  inhibit_login != nullptr && *inhibit_login};
    }

    [[nodiscard]] auto query_param_value(std::string_view target, std::string_view key) -> std::optional<std::string>
    {
        auto const query_pos = target.find('?');
        if (query_pos == std::string_view::npos || query_pos + 1U >= target.size())
        {
            return std::nullopt;
        }

        auto query = target.substr(query_pos + 1U);
        while (!query.empty())
        {
            auto const amp = query.find('&');
            auto const pair = query.substr(0U, amp);
            auto const equals = pair.find('=');
            auto const current_key = pair.substr(0U, equals);
            if (current_key == key)
            {
                auto const encoded_value =
                    equals == std::string_view::npos ? std::string_view{} : pair.substr(equals + 1U);
                return core::percent_decode(encoded_value);
            }
            if (amp == std::string_view::npos)
            {
                break;
            }
            query.remove_prefix(amp + 1U);
        }
        return std::nullopt;
    }

    [[nodiscard]] auto server_name_from_room_alias(std::string_view room_alias) noexcept -> std::string_view
    {
        if (room_alias.empty() || room_alias.front() != '#')
        {
            return {};
        }
        auto const colon = room_alias.rfind(':');
        if (colon == std::string_view::npos || colon + 1U >= room_alias.size())
        {
            return {};
        }
        return room_alias.substr(colon + 1U);
    }

    [[nodiscard]] auto parse_join_servers_query(std::string_view query) -> std::vector<std::string>
    {
        auto servers = std::vector<std::string>{};
        while (!query.empty())
        {
            auto const amp = query.find('&');
            auto const pair = query.substr(0U, amp);
            query = amp == std::string_view::npos ? std::string_view{} : query.substr(amp + 1U);
            auto const eq = pair.find('=');
            if (eq == std::string_view::npos)
            {
                continue;
            }
            auto const key = pair.substr(0U, eq);
            if (key != "server_name" && key != "via")
            {
                continue;
            }
            auto decoded = core::percent_decode_path_component(pair.substr(eq + 1U));
            if (!decoded.empty() && std::ranges::find(servers, decoded) == servers.end())
            {
                servers.push_back(std::move(decoded));
            }
        }
        return servers;
    }

    [[nodiscard]] auto room_servers_for_alias(ClientServerRuntime const& rt, std::string_view room_id)
        -> std::vector<std::string>
    {
        auto servers = std::vector<std::string>{};
        auto const add = [&servers](std::string_view server) {
            if (!server.empty() && std::ranges::find(servers, server) == servers.end())
            {
                servers.emplace_back(server);
            }
        };
        add(rt.homeserver.config.server().server_name);
        for (auto const& membership : rt.homeserver.database.persistent_store.memberships)
        {
            if (membership.room_id == room_id && membership.membership == "join")
            {
                add(server_name_from_user_id(membership.user_id));
            }
        }
        return servers;
    }

    struct DirectoryLookupResult final
    {
        bool ok{false};
        std::string room_id{};
        std::vector<std::string> servers{};
    };

    [[nodiscard]] auto parse_directory_lookup_response(std::string_view body) -> std::optional<DirectoryLookupResult>
    {
        auto const parsed = canonicaljson::parse_lossless(body);
        auto const* object = parsed.error == canonicaljson::ParseError::none
                                 ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                                 : nullptr;
        if (object == nullptr)
        {
            return std::nullopt;
        }
        auto const* room_id = string_member(*object, "room_id");
        auto const* servers_value = object_member(*object, "servers");
        auto const* servers_array =
            servers_value == nullptr ? nullptr : std::get_if<canonicaljson::Array>(&servers_value->storage());
        if (room_id == nullptr || servers_array == nullptr)
        {
            return std::nullopt;
        }
        auto result = DirectoryLookupResult{};
        result.ok = true;
        result.room_id = *room_id;
        for (auto const& entry : *servers_array)
        {
            if (auto const* server = std::get_if<std::string>(&entry.storage()); server != nullptr && !server->empty())
            {
                result.servers.push_back(*server);
            }
        }
        return result;
    }

    [[nodiscard]] auto client_secret_is_valid(std::string_view client_secret) noexcept -> bool
    {
        return !client_secret.empty() && client_secret.size() <= 255U &&
               std::ranges::all_of(client_secret, [](char const value) {
                   return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'z') ||
                          (value >= 'A' && value <= 'Z') || value == '.' || value == '=' || value == '_' ||
                          value == '-';
               });
    }

    [[nodiscard]] auto email_address_is_valid(std::string_view email) noexcept -> bool
    {
        auto const at = email.find('@');
        return !email.empty() && email.size() <= 255U && at != std::string_view::npos && at != 0U &&
               at + 1U < email.size() && email.find(' ') == std::string_view::npos;
    }

    [[nodiscard]] auto country_code_is_valid(std::string_view country) noexcept -> bool
    {
        return country.size() == 2U && std::ranges::all_of(country, [](char const value) {
                   return value >= 'A' && value <= 'Z';
               });
    }

    [[nodiscard]] auto phone_number_is_valid(std::string_view phone_number) noexcept -> bool
    {
        return !phone_number.empty() && phone_number.size() <= 32U;
    }

    [[nodiscard]] auto generate_registration_session_id() -> std::string
    {
        std::ignore = sodium_init();
        auto bytes = std::array<unsigned char, 16U>{};
        randombytes_buf(bytes.data(), bytes.size());
        return lowercase_hex(bytes.data(), bytes.size());
    }

    auto constexpr registration_validation_session_ttl_ms = std::uint64_t{15U * 60U * 1000U};
    auto constexpr registration_validation_max_sessions_per_remote = std::size_t{4U};
    auto constexpr registration_validation_max_sessions_global = std::size_t{256U};

    [[nodiscard]] auto wall_clock_milliseconds() -> std::uint64_t
    {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count());
    }

    auto prune_registration_validation_sessions(ClientServerRuntime& rt, std::uint64_t now_ms) -> void
    {
        std::erase_if(rt.registration_validation_sessions, [now_ms](RegistrationValidationSession const& session) {
            return now_ms > session.updated_at_ms &&
                   now_ms - session.updated_at_ms > registration_validation_session_ttl_ms;
        });
    }

    [[nodiscard]] auto normalize_threepid_address(std::string_view medium, std::string_view address) -> std::string
    {
        if (medium == "email")
        {
            return to_lower(address);
        }
        return std::string{address};
    }

    [[nodiscard]] auto find_registration_validation_session(ClientServerRuntime& rt, std::string_view purpose,
                                                            std::string_view medium, std::string_view address,
                                                            std::string_view client_secret,
                                                            std::optional<std::string_view> country = std::nullopt,
                                                            std::optional<std::string_view> user_id = std::nullopt)
        -> RegistrationValidationSession*
    {
        auto const iterator = std::ranges::find_if(
            rt.registration_validation_sessions, [&](RegistrationValidationSession const& session) {
                if (session.purpose != purpose || session.medium != medium || session.address != address ||
                    session.client_secret != client_secret)
                {
                    return false;
                }
                if (user_id.has_value())
                {
                    if (!session.user_id.has_value() || *session.user_id != *user_id)
                    {
                        return false;
                    }
                }
                if (country.has_value())
                {
                    return session.country.has_value() && *session.country == *country;
                }
                return !session.country.has_value();
            });
        return iterator == rt.registration_validation_sessions.end() ? nullptr : &(*iterator);
    }

    [[nodiscard]] auto find_registration_validation_session_by_sid(
        ClientServerRuntime& rt, std::string_view purpose, std::string_view sid, std::string_view client_secret,
        std::optional<std::string_view> user_id = std::nullopt) -> RegistrationValidationSession*
    {
        auto const iterator = std::ranges::find_if(
            rt.registration_validation_sessions, [&](RegistrationValidationSession const& session) {
                if (session.purpose != purpose || session.sid != sid || session.client_secret != client_secret)
                {
                    return false;
                }
                if (user_id.has_value())
                {
                    return session.user_id.has_value() && *session.user_id == *user_id;
                }
                return true;
            });
        return iterator == rt.registration_validation_sessions.end() ? nullptr : &(*iterator);
    }

    [[nodiscard]] auto ensure_registration_validation_session(
        ClientServerRuntime& rt, std::string_view purpose, std::string_view medium, std::string_view address,
        std::string_view client_secret, std::string_view client_ip, std::uint64_t send_attempt,
        std::optional<std::string> next_link = std::nullopt, std::optional<std::string> country = std::nullopt,
        std::optional<std::string> user_id = std::nullopt) -> RegistrationValidationSession*
    {
        auto const now_ms = wall_clock_milliseconds();
        prune_registration_validation_sessions(rt, now_ms);
        auto* existing = find_registration_validation_session(
            rt, purpose, medium, address, client_secret,
            country.has_value() ? std::optional<std::string_view>{*country} : std::nullopt,
            user_id.has_value() ? std::optional<std::string_view>{*user_id} : std::nullopt);
        if (existing != nullptr)
        {
            existing->send_attempt = std::max(existing->send_attempt, send_attempt);
            existing->next_link = next_link;
            existing->client_ip = std::string{client_ip};
            existing->updated_at_ms = now_ms;
            return existing;
        }

        auto const per_remote_sessions = static_cast<std::size_t>(std::ranges::count_if(
            rt.registration_validation_sessions, [client_ip](RegistrationValidationSession const& session) {
                return session.client_ip == client_ip;
            }));
        if (per_remote_sessions >= registration_validation_max_sessions_per_remote ||
            rt.registration_validation_sessions.size() >= registration_validation_max_sessions_global)
        {
            return nullptr;
        }

        rt.registration_validation_sessions.push_back(
            {generate_registration_session_id(), std::string{purpose}, std::string{medium}, std::string{address},
             std::string{client_secret}, std::string{client_ip}, std::move(user_id), std::move(country),
             std::move(next_link), send_attempt, now_ms, now_ms, now_ms});
        return &rt.registration_validation_sessions.back();
    }

    [[nodiscard]] auto find_account_threepid(ClientServerRuntime& rt, std::string_view user_id, std::string_view medium,
                                             std::string_view address) -> AccountThreePid*
    {
        auto const iterator = std::ranges::find_if(rt.account_threepids, [&](AccountThreePid const& current) {
            return current.user_id == user_id && current.medium == medium && current.address == address;
        });
        return iterator == rt.account_threepids.end() ? nullptr : &(*iterator);
    }

    [[nodiscard]] auto threepid_in_use(ClientServerRuntime const& rt, std::string_view medium, std::string_view address,
                                       std::optional<std::string_view> except_user_id = std::nullopt) -> bool
    {
        return std::ranges::any_of(rt.account_threepids, [&](AccountThreePid const& current) {
            return current.medium == medium && current.address == address &&
                   (!except_user_id.has_value() || current.user_id != *except_user_id);
        });
    }

    [[nodiscard]] auto ensure_account_threepid(ClientServerRuntime& rt, std::string_view user_id,
                                               std::string_view medium, std::string_view address,
                                               std::optional<std::string_view> country, std::uint64_t validated_at_ms)
        -> AccountThreePid&
    {
        auto const now_ms = wall_clock_milliseconds();
        auto* existing = find_account_threepid(rt, user_id, medium, address);
        if (existing != nullptr)
        {
            existing->validated_at_ms = validated_at_ms;
            existing->added_at_ms = existing->added_at_ms == 0U ? now_ms : existing->added_at_ms;
            if (country.has_value())
            {
                existing->country = std::string{*country};
            }
            return *existing;
        }

        rt.account_threepids.push_back(AccountThreePid{
            std::string{user_id},
            std::string{medium},
            std::string{address},
            country.has_value() ? std::optional<std::string>{std::string{*country}} : std::nullopt,
            std::nullopt,
            now_ms,
            validated_at_ms,
            false,
        });
        return rt.account_threepids.back();
    }

    [[nodiscard]] auto threepid_unbind_result(AccountThreePid const* record,
                                              std::optional<std::string_view> requested_id_server) -> std::string_view
    {
        if (record == nullptr)
        {
            return requested_id_server.has_value() ? "no-support" : "success";
        }
        if (requested_id_server.has_value() &&
            (!record->id_server.has_value() || *record->id_server != *requested_id_server))
        {
            return "no-support";
        }
        return "success";
    }

    [[nodiscard]] auto parse_register_email_request_body(std::string_view body)
        -> std::optional<MatrixRegisterEmailRequestBody>
    {
        auto const object = parsed_json_object(body);
        if (!object.has_value())
        {
            return std::nullopt;
        }
        auto const* client_secret = string_member(*object, "client_secret");
        auto const* email = string_member(*object, "email");
        auto const* send_attempt = integer_member(*object, "send_attempt");
        if (client_secret == nullptr || email == nullptr || send_attempt == nullptr || *send_attempt < 1)
        {
            return std::nullopt;
        }
        auto const* next_link = string_member(*object, "next_link");
        return MatrixRegisterEmailRequestBody{*client_secret, *email,
                                              next_link == nullptr ? std::optional<std::string>{}
                                                                   : std::optional<std::string>{*next_link},
                                              static_cast<std::uint64_t>(*send_attempt)};
    }

    [[nodiscard]] auto parse_register_msisdn_request_body(std::string_view body)
        -> std::optional<MatrixRegisterMsisdnRequestBody>
    {
        auto const object = parsed_json_object(body);
        if (!object.has_value())
        {
            return std::nullopt;
        }
        auto const* client_secret = string_member(*object, "client_secret");
        auto const* country = string_member(*object, "country");
        auto const* phone_number = string_member(*object, "phone_number");
        auto const* send_attempt = integer_member(*object, "send_attempt");
        if (client_secret == nullptr || country == nullptr || phone_number == nullptr || send_attempt == nullptr ||
            *send_attempt < 1)
        {
            return std::nullopt;
        }
        auto const* next_link = string_member(*object, "next_link");
        return MatrixRegisterMsisdnRequestBody{
            *client_secret,
            *country,
            *phone_number,
            next_link == nullptr ? std::optional<std::string>{} : std::optional<std::string>{*next_link},
            static_cast<std::uint64_t>(*send_attempt),
        };
    }

    [[nodiscard]] auto parse_account_threepid_add_body(std::string_view body)
        -> std::optional<MatrixAccountThreePidAddBody>
    {
        auto const object = parsed_json_object(body);
        if (!object.has_value())
        {
            return std::nullopt;
        }
        auto const* client_secret = string_member(*object, "client_secret");
        auto const* sid = string_member(*object, "sid");
        if (client_secret == nullptr || sid == nullptr || client_secret->empty() || sid->empty())
        {
            return std::nullopt;
        }
        auto password = std::optional<std::string>{};
        if (auto const* auth = object_member_object(*object, "auth"); auth != nullptr)
        {
            auto const* auth_type = string_member(*auth, "type");
            auto const* auth_password = string_member(*auth, "password");
            if (auth_type != nullptr && *auth_type == "m.login.password" && auth_password != nullptr &&
                !auth_password->empty())
            {
                password = *auth_password;
            }
        }
        return MatrixAccountThreePidAddBody{*client_secret, *sid, std::move(password)};
    }

    [[nodiscard]] auto parse_account_threepid_bind_body(std::string_view body)
        -> std::optional<MatrixAccountThreePidBindBody>
    {
        auto const object = parsed_json_object(body);
        if (!object.has_value())
        {
            return std::nullopt;
        }
        auto const* client_secret = string_member(*object, "client_secret");
        auto const* sid = string_member(*object, "sid");
        auto const* id_server = string_member(*object, "id_server");
        auto const* id_access_token = string_member(*object, "id_access_token");
        if (client_secret == nullptr || sid == nullptr || id_server == nullptr || id_access_token == nullptr ||
            client_secret->empty() || sid->empty() || id_server->empty() || id_access_token->empty())
        {
            return std::nullopt;
        }
        return MatrixAccountThreePidBindBody{*client_secret, *sid, *id_server, *id_access_token};
    }

    [[nodiscard]] auto parse_account_threepid_delete_body(std::string_view body)
        -> std::optional<MatrixAccountThreePidDeleteBody>
    {
        auto const object = parsed_json_object(body);
        if (!object.has_value())
        {
            return std::nullopt;
        }
        auto const* address = string_member(*object, "address");
        auto const* medium = string_member(*object, "medium");
        if (address == nullptr || medium == nullptr || address->empty() || medium->empty())
        {
            return std::nullopt;
        }
        auto const* id_server = string_member(*object, "id_server");
        return MatrixAccountThreePidDeleteBody{
            *address,
            *medium,
            id_server == nullptr ? std::optional<std::string>{} : std::optional<std::string>{*id_server},
        };
    }

    [[nodiscard]] auto user_exists(ClientServerRuntime const& rt, std::string_view user_id) noexcept -> bool
    {
        return std::ranges::any_of(rt.homeserver.database.users, [user_id](LocalUser const& current) {
            return current.user_id == user_id;
        });
    }

    [[nodiscard]] auto registration_error_code(std::uint16_t status, std::string_view reason) -> std::string_view
    {
        if (reason == "user already exists")
        {
            return "M_USER_IN_USE";
        }
        if (reason == "invalid user id")
        {
            return "M_INVALID_USERNAME";
        }
        if (status == 403U)
        {
            return "M_FORBIDDEN";
        }
        return "M_UNKNOWN";
    }

    [[nodiscard]] auto configured_registration_token(config::Config const& config) -> std::string
    {
        if (!config.security().registration.require_token || config.security().registration.token_file.empty())
        {
            return {};
        }
        auto input = std::ifstream{config.security().registration.token_file};
        auto token = std::string{};
        std::getline(input, token);
        // Trim trailing CR so CRLF token files compare equal to LF token files.
        if (!token.empty() && token.back() == '\r')
        {
            token.pop_back();
        }
        return token;
    }

    [[nodiscard]] auto registration_request_body(config::Config const& config, std::string_view username,
                                                 std::string_view password) -> std::string
    {
        auto members = canonicaljson::Object{
            json_member("username", json_str(username)),
            json_member("password", json_str(password)),
        };
        if (auto token = configured_registration_token(config); !token.empty())
        {
            members.push_back(json_member("auth", json_obj({
                                                      json_member("type", json_str("m.login.registration_token")),
                                                      json_member("token", json_str(token)),
                                                  })));
        }
        return json_serialize(json_obj(std::move(members)));
    }

    [[nodiscard]] auto matrix_user_id(std::string_view server_name, std::string_view user) -> std::string
    {
        if (user.starts_with("@"))
        {
            return std::string{user};
        }
        return "@" + std::string{user} + ":" + std::string{server_name};
    }

    [[nodiscard]] auto parse_login_body(std::string_view body, std::string_view server_name)
        -> std::optional<MatrixLoginBody>
    {
        auto const object = parsed_json_object(body);
        if (!object.has_value())
        {
            return std::nullopt;
        }
        auto const* type = string_member(*object, "type");
        if (type != nullptr && *type != "m.login.password")
        {
            return std::nullopt;
        }
        auto const* password = string_member(*object, "password");
        auto const* user = string_member(*object, "user");
        if (auto const* identifier = object_member_as_object(*object, "identifier"); identifier != nullptr)
        {
            auto const* identifier_type = string_member(*identifier, "type");
            if (identifier_type != nullptr && *identifier_type != "m.id.user")
            {
                return std::nullopt;
            }
            user = string_member(*identifier, "user");
        }
        if (password == nullptr || user == nullptr)
        {
            return std::nullopt;
        }
        auto const* device_id = string_member(*object, "device_id");
        auto const* display_name = string_member(*object, "initial_device_display_name");
        auto const* supports_refresh_tokens = boolean_member(*object, "refresh_token");
        return MatrixLoginBody{matrix_user_id(server_name, *user), *password,
                               device_id == nullptr ? std::string{} : *device_id,
                               display_name == nullptr ? std::string{} : *display_name,
                               supports_refresh_tokens != nullptr && *supports_refresh_tokens};
    }

    [[nodiscard]] auto parse_refresh_body(std::string_view body) -> std::optional<MatrixRefreshBody>
    {
        auto const object = parsed_json_object(body);
        if (!object.has_value())
        {
            return std::nullopt;
        }
        auto const* refresh_token = string_member(*object, "refresh_token");
        if (refresh_token == nullptr || refresh_token->empty())
        {
            return std::nullopt;
        }
        return MatrixRefreshBody{*refresh_token};
    }

    [[nodiscard]] auto parse_device_update_body(std::string_view body) -> std::optional<MatrixDeviceUpdateBody>
    {
        auto const object = parsed_json_object(body);
        if (!object.has_value())
        {
            return std::nullopt;
        }
        auto const* display_name = string_member(*object, "display_name");
        if (display_name == nullptr)
        {
            return std::nullopt;
        }
        return MatrixDeviceUpdateBody{*display_name};
    }

    [[nodiscard]] auto parse_safety_report_body(std::string_view body) -> std::optional<MatrixSafetyReportBody>
    {
        auto const object = parsed_json_object(body);
        if (!object.has_value())
        {
            return std::nullopt;
        }
        auto const* reason_value = object_member(*object, "reason");
        if (reason_value == nullptr)
        {
            return MatrixSafetyReportBody{};
        }
        auto const* reason = std::get_if<std::string>(&reason_value->storage());
        if (reason == nullptr)
        {
            return std::nullopt;
        }
        return MatrixSafetyReportBody{*reason};
    }

    [[nodiscard]] auto parse_admin_review_body(std::string_view body) -> std::optional<MatrixAdminReviewBody>
    {
        if (body.empty())
        {
            return MatrixAdminReviewBody{};
        }
        auto const object = parsed_json_object(body);
        if (!object.has_value())
        {
            return std::nullopt;
        }
        auto const* reason = string_member(*object, "reason");
        if (reason == nullptr || reason->empty())
        {
            return MatrixAdminReviewBody{};
        }
        return MatrixAdminReviewBody{*reason};
    }

    [[nodiscard]] auto parse_admin_policy_rule_body(std::string_view body) -> std::optional<MatrixAdminPolicyRuleBody>
    {
        auto const object = parsed_json_object(body);
        if (!object.has_value())
        {
            return std::nullopt;
        }
        auto parsed = MatrixAdminPolicyRuleBody{};
        if (auto const* action = string_member(*object, "action"); action != nullptr && !action->empty())
        {
            parsed.action = *action;
        }
        if (auto const* reason = string_member(*object, "reason"); reason != nullptr && !reason->empty())
        {
            parsed.reason = *reason;
        }
        return parsed;
    }

    [[nodiscard]] auto json_value(std::string_view body, std::string_view key) -> std::string
    {
        auto const start = body.find(key);
        if (start == std::string_view::npos)
        {
            return {};
        }
        auto const value_start = start + key.size();
        auto const value_end = body.find('"', value_start);
        if (value_end == std::string_view::npos)
        {
            return {};
        }
        return std::string{body.substr(value_start, value_end - value_start)};
    }

    [[nodiscard]] auto auth(ClientServerRuntime& rt, std::string_view token) -> std::optional<std::string>
    {
        // `authenticated_user` is non-const because the audit-routing
        // helper (0.5.0) writes a row to audit_log on token rejection.
        // The caller has already locked `rt.homeserver.mutex` for the
        // request, so the const cast is safe.
        return authenticated_user(rt.homeserver, token);
    }

    // Wall-clock rate limiter. The cap is `http::RateLimitEngine<Clock>::check`,
    // which honours the per-endpoint policy configured in
    // `config.client_rate_limits()` (or the design-doc defaults if the
    // operator left the block empty). Two independent tiers:
    //   * per-IP,  keyed by the request's source IP + target prefix.
    //   * per-user, keyed by the authenticated user_id (empty on
    //     unauthenticated paths so the per-user tier is silently
    //     skipped). The 5/60s per-user login cap is enforced through
    //     this path.
    // Wall-clock seconds: a quiet server does not freeze the bucket
    // because the bucket rolls over on real time, not on the request
    // counter. The engine is constructed once in `start_client_server`
    // and is wiped by a process restart (in-process state, no on-disk
    // persistence — see the design doc for the operator sign-off).
    // Replace path parameters (roomId, deviceId, userId, etc.) in
    // `target` with a stable placeholder so two different room IDs hit
    // the same rate-limit bucket. The Matrix spec defines a small set
    // of path templates under `/_matrix/client/v3/...`; we only handle
    // the ones the legacy request-counter limiter coalesced, because
    // the per-endpoint caps are the unit the operator reasons about.
    [[nodiscard]] static auto normalized_target(std::string_view target) -> std::string
    {
        // Strip the query string so /sync?x=1 and /sync?x=2 land in the same bucket.
        auto const q = target.find('?');
        auto out = std::string{q == std::string_view::npos ? target : target.substr(0U, q)};
        auto constexpr room_prefix = std::string_view{"/_matrix/client/v3/rooms/"};
        if (starts_with(out, room_prefix))
        {
            // /_matrix/client/v3/rooms/{roomId}/{action}
            auto rest = std::string_view{out}.substr(room_prefix.size());
            auto const slash = rest.find('/');
            if (slash != std::string_view::npos)
            {
                out = std::string{room_prefix} + "{roomId}" + std::string{rest.substr(slash)};
            }
        }
        auto constexpr device_prefix = std::string_view{"/_matrix/client/v3/devices/"};
        if (starts_with(out, device_prefix))
        {
            out = std::string{device_prefix} + "{deviceId}";
        }
        auto constexpr user_prefix = std::string_view{"/_matrix/client/v3/user/"};
        if (starts_with(out, user_prefix))
        {
            // /_matrix/client/v3/user/{userId}/{action}
            auto rest = std::string_view{out}.substr(user_prefix.size());
            auto const slash = rest.find('/');
            if (slash != std::string_view::npos)
            {
                out = std::string{user_prefix} + "{userId}" + std::string{rest.substr(slash)};
            }
        }
        auto constexpr profile_prefix = std::string_view{"/_matrix/client/v3/profile/"};
        if (starts_with(out, profile_prefix))
        {
            out = std::string{profile_prefix} + "{userId}";
        }
        if (starts_with(out, "/_matrix/client/v3/join/"))
        {
            out = "/_matrix/client/v3/join/{roomIdOrAlias}";
        }
        if (starts_with(out, "/_matrix/client/v3/knock/"))
        {
            out = "/_matrix/client/v3/knock/{roomIdOrAlias}";
        }
        return out;
    }

    [[nodiscard]] auto allow(ClientServerRuntime& rt, LocalHttpRequest const& req) -> bool
    {
        if (rt.rate_limit_engine == nullptr)
        {
            // The runtime is in a test-only state with no engine installed
            // (e.g. a stub constructed by a unit test that does not call
            // start_client_server). Permitting the request is the safe
            // default for a fully-validated, body-sized request; the
            // production path always has an engine.
            return true;
        }
        // Resolve the effective client IP for rate-limit keying.
        // When remote_addr is empty (test-only paths that skip the
        // transport layer) we fall back to "unknown" so per-route
        // caps still apply.  When the direct peer is a configured
        // trusted proxy we look for the leftmost X-Forwarded-For
        // address instead, so the bucket isolates each downstream
        // client rather than collapsing all traffic through the
        // proxy into a single bucket.
        auto const& trusted_proxies = rt.homeserver.config.server().trusted_proxies;
        auto effective_ip = [&]() -> std::string {
            auto const& raw = req.remote_addr;
            if (raw.empty())
            {
                return "unknown";
            }
            // Check if the peer is one of the operator-configured trusted proxies.
            auto const is_trusted = std::ranges::find(trusted_proxies, raw) != trusted_proxies.end();
            if (is_trusted)
            {
                // Honour the leftmost non-empty value in X-Forwarded-For.
                // Case-insensitive header name comparison per RFC 7230.
                for (auto const& h : req.headers)
                {
                    auto lower = h.name;
                    std::ranges::transform(lower, lower.begin(), [](unsigned char c) {
                        return static_cast<char>(std::tolower(c));
                    });
                    if (lower == "x-forwarded-for")
                    {
                        auto sv = std::string_view{h.value};
                        auto const comma = sv.find(',');
                        auto first = comma == std::string_view::npos ? sv : sv.substr(0U, comma);
                        // Trim leading and trailing ASCII spaces.
                        while (!first.empty() && first.front() == ' ')
                        {
                            first.remove_prefix(1U);
                        }
                        while (!first.empty() && first.back() == ' ')
                        {
                            first.remove_suffix(1U);
                        }
                        if (!first.empty())
                        {
                            return std::string{first};
                        }
                    }
                }
            }
            return raw;
        }();
        // Per-IP bucket keyed by (effective_ip, normalised_route) so
        // different endpoints get independent counters and route
        // templates (e.g. /rooms/{roomId}/send) coalesce into the
        // same bucket regardless of which room ID appears in the URL.
        auto const norm = normalized_target(req.target);
        auto ip_key = effective_ip;
        ip_key.push_back('|');
        ip_key.append(norm);
        // Per-user bucket: the bearer token is the user identity in this
        // pre-authentication call site (callers have not yet resolved it
        // to a user_id). Unauthenticated paths pass an empty token, so
        // the per-user tier is silently skipped — same behaviour as the
        // 0.4.x limiter's empty-token bucket. We also append the
        // normalized target so a 5/60s cap on /login does not bleed
        // into a 60/60s cap on /sync.
        std::string user_key;
        if (!req.access_token.empty())
        {
            user_key = req.access_token;
            user_key.push_back('|');
            user_key.append(norm);
        }
        auto const decision =
            rt.rate_limit_engine->check(std::string_view{ip_key}, req.target, std::string_view{user_key});
        if (!decision.allowed)
        {
            // Audit-routing: rate-limit denial is one of the five
            // high-signal failure events from the 0.5.0 design doc.
            // We log the structured diagnostic AND write a row to
            // audit_log so `GET /_merovingian/admin/audit?category=policy`
            // surfaces the cap being hit.
            log_diagnostic_audit(rt.homeserver.database, "rate_limit", "rate_limit.exceeded",
                                 {
                                     {"target",         observability::sanitized_http_target(req.target), false},
                                     {"deny_reason",    std::string{decision.deny_reason},                false},
                                     {"requests_seen",  std::to_string(decision.requests_seen),           false},
                                     {"max_requests",   std::to_string(decision.max_requests),            false},
                                     {"window_seconds", std::to_string(decision.window_seconds),          false},
                                     {"per_ip_count",   std::to_string(decision.per_ip_count),            false},
                                     {"per_user_count", std::to_string(decision.per_user_count),          false},
                                     {"effective_ip",   effective_ip,                                     false}
            },
                                 observability::LogEventSeverity::warning, observability::AuditCategory::policy,
                                 "rate_limit.exceeded", req.access_token, req.target,
                                 "max=" + std::to_string(decision.max_requests) + " per " +
                                     std::to_string(decision.window_seconds) + "s");
        }
        return decision.allowed;
    }

    [[nodiscard]] auto find_device(ClientServerRuntime& rt, std::string_view user, std::string_view device)
        -> ClientDevice*
    {
        auto const it = std::ranges::find_if(rt.devices, [user, device](ClientDevice const& d) {
            return d.user_id == user && d.device_id == device;
        });
        return it == rt.devices.end() ? nullptr : &(*it);
    }

    [[nodiscard]] auto authenticated_request_device_id(ClientServerRuntime const& rt, std::string_view access_token)
        -> std::string
    {
        auto const session = authenticated_session(rt.homeserver, access_token);
        return session.has_value() ? session->device_id : std::string{};
    }

    [[nodiscard]] auto devices_json(ClientServerRuntime const& rt, std::string_view user) -> std::string
    {
        auto devices = canonicaljson::Array{};
        for (auto const& d : rt.devices)
        {
            if (d.user_id != user)
            {
                continue;
            }
            devices.push_back(json_obj({
                json_member("device_id", json_str(d.device_id)),
                json_member("display_name", json_str(d.display_name)),
            }));
        }
        return json_serialize(json_obj({json_member("devices", json_arr(std::move(devices)))}));
    }

    [[nodiscard]] auto device_json(ClientDevice const& device) -> std::string
    {
        return json_serialize(json_obj({
            json_member("device_id", json_str(device.device_id)),
            json_member("display_name", json_str(device.display_name)),
        }));
    }

    [[nodiscard]] auto device_delete_uia_challenge(std::string_view session_id) -> std::string
    {
        return json_serialize(json_obj({
            json_member("flows",
                        json_arr({json_obj({json_member("stages", json_arr({json_str("m.login.password")}))})})),
            json_member("params", json_obj({})),
            json_member("session", json_str(session_id)),
        }));
    }

    auto record_shared_room_device_change(ClientServerRuntime& rt, std::string_view user_id) -> void
    {
        for (auto const& room : rt.homeserver.database.rooms)
        {
            auto const is_member = std::ranges::any_of(room.members, [user_id](auto const& member) {
                return member == user_id;
            });
            if (!is_member)
            {
                continue;
            }
            for (auto const& member : room.members)
            {
                if (member == user_id)
                {
                    continue;
                }
                auto const change = database::PersistentDeviceListChange{0U, member, std::string{user_id}, "changed"};
                std::ignore = record_device_list_change(rt, change);
            }
        }
    }

    auto erase_runtime_device(ClientServerRuntime& rt, std::string_view user_id, std::string_view device_id) -> void
    {
        auto const [first, last] = std::ranges::remove_if(rt.devices, [user_id, device_id](ClientDevice const& device) {
            return device.user_id == user_id && device.device_id == device_id;
        });
        rt.devices.erase(first, last);
    }

    [[nodiscard]] auto joined(LocalRoom const& room, std::string_view user) -> bool
    {
        return std::ranges::any_of(room.members, [user](std::string const& member) {
            return member == user;
        });
    }

    // True when the persistent store records a "join" membership for the user in
    // the given room.  Used by handlers that only have a room_id, not a LocalRoom.
    [[nodiscard]] auto user_is_joined(database::PersistentStore const& store, std::string_view room_id,
                                      std::string_view user) noexcept -> bool
    {
        return std::ranges::any_of(store.memberships, [&](database::PersistentMembership const& m) {
            return m.room_id == room_id && m.user_id == user && m.membership == "join";
        });
    }

    // Keyed by (room_id, event_type, state_key) → event_id. Built once per request
    // so all state lookups within the same response are O(log n) rather than O(n).
    using StateIndex = std::map<std::tuple<std::string_view, std::string_view, std::string_view>, std::string_view>;

    [[nodiscard]] auto build_state_index(database::PersistentStore const& store) -> StateIndex
    {
        auto index = StateIndex{};
        for (auto const& entry : store.state)
        {
            // Views into store.state strings — safe for the lifetime of the store reference.
            index.emplace(std::make_tuple(std::string_view{entry.room_id}, std::string_view{entry.event_type},
                                          std::string_view{entry.state_key}),
                          std::string_view{entry.event_id});
        }
        return index;
    }

    [[nodiscard]] auto state_event_json(database::PersistentStore const& store, StateIndex const& index,
                                        std::string_view room_id, std::string_view event_type,
                                        std::string_view state_key = {}) -> std::optional<std::string>
    {
        auto const it = index.find(std::make_tuple(room_id, event_type, state_key));
        if (it == index.end())
        {
            return std::nullopt;
        }
        return event_json_for_id(store, std::string{it->second});
    }

    [[nodiscard]] auto event_content_string(std::string_view event_json, std::string_view key)
        -> std::optional<std::string>
    {
        auto parsed = canonicaljson::parse_lossless(event_json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto const* event = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (event == nullptr)
        {
            return std::nullopt;
        }
        auto const* content = object_member(*event, "content");
        auto const* content_obj =
            content == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&content->storage());
        if (content_obj == nullptr)
        {
            return std::nullopt;
        }
        auto const* value = string_member(*content_obj, key);
        return value == nullptr ? std::nullopt : std::optional<std::string>{*value};
    }

    [[nodiscard]] auto room_state_string(database::PersistentStore const& store, StateIndex const& index,
                                         std::string_view room_id, std::string_view event_type,
                                         std::string_view content_key, std::string_view state_key = {})
        -> std::optional<std::string>
    {
        auto const event_json = state_event_json(store, index, room_id, event_type, state_key);
        if (!event_json.has_value())
        {
            return std::nullopt;
        }
        return event_content_string(*event_json, content_key);
    }

    [[nodiscard]] auto joined_member_count(ClientServerRuntime const& rt, std::string_view room_id) -> std::size_t
    {
        auto const room = std::ranges::find_if(rt.homeserver.database.rooms, [&](LocalRoom const& current) {
            return current.room_id == room_id;
        });
        if (room != rt.homeserver.database.rooms.end())
        {
            return room->members.size();
        }
        return static_cast<std::size_t>(std::ranges::count_if(
            rt.homeserver.database.persistent_store.memberships, [&](database::PersistentMembership const& membership) {
                return membership.room_id == room_id && membership.membership == "join";
            }));
    }

    // Spec: GET/POST /_matrix/client/v3/publicRooms
    // ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3publicrooms
    [[nodiscard]] auto public_rooms_filtered_json(ClientServerRuntime const& rt, std::string const& filter_term,
                                                  std::optional<std::size_t> limit, std::size_t since_offset)
        -> std::string
    {
        auto const icase_contains = [](std::string_view haystack, std::string_view needle) noexcept -> bool {
            return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
                               [](unsigned char a, unsigned char b) noexcept -> bool {
                                   return std::tolower(a) == std::tolower(b);
                               }) != haystack.end();
        };

        auto const& store = rt.homeserver.database.persistent_store;
        auto const index = build_state_index(store);

        auto all_rooms = std::vector<canonicaljson::Object>{};
        for (auto const& room : rt.homeserver.database.rooms)
        {
            auto const join_rule = room_state_string(store, index, room.room_id, "m.room.join_rules", "join_rule");
            if (!join_rule.has_value() || *join_rule != "public")
                continue;

            auto const name = room_state_string(store, index, room.room_id, "m.room.name", "name");
            auto const topic = room_state_string(store, index, room.room_id, "m.room.topic", "topic");
            auto const alias = room_state_string(store, index, room.room_id, "m.room.canonical_alias", "alias");

            if (!filter_term.empty())
            {
                auto const matches = icase_contains(room.room_id, filter_term) ||
                                     (name.has_value() && icase_contains(*name, filter_term)) ||
                                     (topic.has_value() && icase_contains(*topic, filter_term)) ||
                                     (alias.has_value() && icase_contains(*alias, filter_term));
                if (!matches)
                    continue;
            }

            auto room_entry = canonicaljson::Object{};
            room_entry.push_back(json_member("room_id", json_str(room.room_id)));
            room_entry.push_back(json_member(
                "num_joined_members", json_int(static_cast<std::int64_t>(joined_member_count(rt, room.room_id)))));
            room_entry.push_back(json_member("join_rule", json_str(*join_rule)));

            auto const history_visibility =
                room_state_string(store, index, room.room_id, "m.room.history_visibility", "history_visibility");
            room_entry.push_back(json_member("world_readable", json_bool(history_visibility.has_value() &&
                                                                         *history_visibility == "world_readable")));

            auto const guest_access =
                room_state_string(store, index, room.room_id, "m.room.guest_access", "guest_access");
            room_entry.push_back(
                json_member("guest_can_join", json_bool(guest_access.has_value() && *guest_access == "can_join")));

            if (name.has_value())
                room_entry.push_back(json_member("name", json_str(*name)));
            if (topic.has_value())
                room_entry.push_back(json_member("topic", json_str(*topic)));
            if (alias.has_value())
                room_entry.push_back(json_member("canonical_alias", json_str(*alias)));
            if (auto const avatar = room_state_string(store, index, room.room_id, "m.room.avatar", "url");
                avatar.has_value())
                room_entry.push_back(json_member("avatar_url", json_str(*avatar)));

            all_rooms.push_back(std::move(room_entry));
        }

        auto const total = static_cast<std::int64_t>(all_rooms.size());
        auto const start = std::min(since_offset, all_rooms.size());
        auto const end = limit.has_value() ? std::min(start + *limit, all_rooms.size()) : all_rooms.size();

        auto chunk = canonicaljson::Array{};
        for (auto i = start; i < end; ++i)
            chunk.push_back(json_obj(std::move(all_rooms[i])));

        auto response = canonicaljson::Object{};
        response.push_back(json_member("chunk", json_arr(std::move(chunk))));
        response.push_back(json_member("total_room_count_estimate", json_int(total)));
        if (end < all_rooms.size())
            response.push_back(json_member("next_batch", json_str(std::to_string(end))));

        return json_serialize(json_obj(std::move(response)));
    }

    [[nodiscard]] auto public_rooms_json(ClientServerRuntime const& rt) -> std::string
    {
        return public_rooms_filtered_json(rt, {}, std::nullopt, 0U);
    }

    // Builds the federation target path for /_matrix/federation/v1/publicRooms,
    // appending limit and since as query parameters when present.
    [[nodiscard]] auto public_rooms_fed_target(std::optional<std::size_t> limit, std::optional<std::string_view> since)
        -> std::string
    {
        auto target = std::string{"/_matrix/federation/v1/publicRooms"};
        auto sep = char{'?'};
        if (limit.has_value())
        {
            target += sep;
            target += "limit=";
            target += std::to_string(*limit);
            sep = '&';
        }
        if (since.has_value() && !since->empty())
        {
            target += sep;
            target += "since=";
            target += core::percent_encode_path_component(*since);
        }
        return target;
    }

    [[nodiscard]] auto joined_rooms_json(ClientServerRuntime const& rt, std::string_view user) -> std::string
    {
        auto rooms = canonicaljson::Array{};
        auto count = std::size_t{0U};
        for (auto const& room : rt.homeserver.database.rooms)
        {
            if (count >= rt.limits.max_sync_rooms || !joined(room, user))
            {
                continue;
            }
            ++count;
            rooms.push_back(json_str(room.room_id));
        }
        return json_serialize(json_obj({json_member("joined_rooms", json_arr(std::move(rooms)))}));
    }

    [[nodiscard]] auto otk_algorithm(std::string_view key_id) noexcept -> std::string
    {
        auto const colon = key_id.find(':');
        return colon == std::string_view::npos ? std::string{key_id} : std::string{key_id.substr(0U, colon)};
    }

    [[nodiscard]] auto parse_event_json_object(std::string_view encoded) -> canonicaljson::Value
    {
        if (encoded.empty() || encoded.front() != '{')
        {
            return canonicaljson::Value{canonicaljson::Object{}};
        }
        // Room account data (e.g. m.tag) may contain non-canonical JSON doubles,
        // so use the general JSON parser rather than the strict canonical parser.
        auto parsed = canonicaljson::parse_json(encoded);
        if (parsed.error != canonicaljson::ParseError::none ||
            std::get_if<canonicaljson::Object>(&parsed.value.storage()) == nullptr)
        {
            return canonicaljson::Value{canonicaljson::Object{}};
        }
        return std::move(parsed.value);
    }

    // Loads the existing per-room tag object for a user/room, returning the
    // content of the `tags` key from the m.tag room account-data row. The
    // empty object means no tags have been set yet.
    [[nodiscard]] auto room_tag_content(database::PersistentStore const& store, std::string_view user_id,
                                        std::string_view room_id) -> canonicaljson::Object
    {
        for (auto const& data : store.account_data)
        {
            if (data.user_id != user_id || data.room_id != room_id || data.event_type != "m.tag")
            {
                continue;
            }
            auto const parsed = canonicaljson::parse_json(data.content_json);
            if (parsed.error != canonicaljson::ParseError::none)
            {
                break;
            }
            auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
            if (root == nullptr)
            {
                break;
            }
            auto const* tags = object_member_as_object(*root, "tags");
            if (tags == nullptr)
            {
                break;
            }
            return *tags;
        }
        return canonicaljson::Object{};
    }

    // Stores the per-room m.tag account-data row for a user/room. If `tags`
    // is empty the row still exists with {"tags":{}} so clients see an explicit
    // empty tag list.
    [[nodiscard]] auto store_room_tag_content(ClientServerRuntime& runtime, std::string_view user_id,
                                              std::string_view room_id, canonicaljson::Object tags) -> bool
    {
        auto content = canonicaljson::Object{};
        content.push_back(json_member("tags", json_obj(std::move(tags))));
        auto const serialized = json_serialize(json_obj(std::move(content)));
        return set_account_data(runtime, {std::string{user_id}, std::string{room_id}, "m.tag", serialized, 0U});
    }

    [[nodiscard]] auto build_current_state_events_array(database::PersistentStore const& store,
                                                        sync::EventTypeFilter const& filter, std::string_view room_id)
        -> canonicaljson::Array
    {
        auto state_events = canonicaljson::Array{};
        for (auto const& state_entry : store.state)
        {
            if (state_entry.room_id != room_id)
            {
                continue;
            }
            auto const event = std::ranges::find_if(store.events, [&](database::PersistentEvent const& candidate) {
                return candidate.event_id == state_entry.event_id;
            });
            if (event == store.events.end() ||
                !sync::event_passes_filter(filter, state_entry.event_type, event->sender_user_id))
            {
                continue;
            }
            state_events.push_back(client_event_value(*event));
        }
        return state_events;
    }

    [[nodiscard]] auto build_room_ephemeral_events_array(HomeserverRuntime const& runtime, std::string_view room_id,
                                                         std::uint64_t since_sync_stream_id,
                                                         std::uint64_t& max_observed_stream_id) -> canonicaljson::Array
    {
        auto events = canonicaljson::Array{};

        auto const room_typing_id = room_typing_stream_id_for(runtime, room_id);
        if (room_typing_id > since_sync_stream_id)
        {
            auto typing_user_ids = canonicaljson::Array{};
            for (auto const& typing : runtime.typing_users)
            {
                if (typing.room_id != room_id || !typing.typing)
                {
                    continue;
                }
                typing_user_ids.push_back(json_str(typing.user_id));
            }
            // Only emit an empty list for incremental syncs; initial sync omits
            // the event when nobody is typing so the room is not pulled in solely
            // to report no state.
            if (!typing_user_ids.empty() || since_sync_stream_id > std::uint64_t{0U})
            {
                events.push_back(json_obj({
                    json_member("type", json_str("m.typing")),
                    json_member("content", json_obj({json_member("user_ids", json_arr(std::move(typing_user_ids)))})),
                }));
                if (room_typing_id > max_observed_stream_id)
                {
                    max_observed_stream_id = room_typing_id;
                }
            }
        }

        auto receipt_index = std::map<std::string, std::map<std::string, std::map<std::string, std::uint64_t>>>{};
        for (auto const& receipt : runtime.receipts)
        {
            if (receipt.room_id != room_id || receipt.stream_id <= since_sync_stream_id)
            {
                continue;
            }
            receipt_index[receipt.event_id][receipt.receipt_type][receipt.user_id] = receipt.ts;
            if (receipt.stream_id > max_observed_stream_id)
            {
                max_observed_stream_id = receipt.stream_id;
            }
        }
        if (!receipt_index.empty())
        {
            auto content = canonicaljson::Object{};
            for (auto const& [event_id, receipt_types] : receipt_index)
            {
                auto receipt_type_members = canonicaljson::Object{};
                for (auto const& [receipt_type, users] : receipt_types)
                {
                    auto user_members = canonicaljson::Object{};
                    for (auto const& [user_id, ts] : users)
                    {
                        user_members.push_back(json_member(
                            user_id, json_obj({json_member("ts", json_int(static_cast<std::int64_t>(ts)))})));
                    }
                    receipt_type_members.push_back(json_member(receipt_type, json_obj(std::move(user_members))));
                }
                content.push_back(json_member(event_id, json_obj(std::move(receipt_type_members))));
            }
            events.push_back(json_obj(
                {json_member("type", json_str("m.receipt")), json_member("content", json_obj(std::move(content)))}));
        }

        return events;
    }

    [[nodiscard]] auto joined_membership_changed_since(database::PersistentStore const& store, std::string_view room_id,
                                                       std::string_view user_id, std::uint64_t since_ordering) -> bool
    {
        auto const state_entry = std::ranges::find_if(store.state, [&](database::PersistentStateEvent const& state) {
            return state.room_id == room_id && state.event_type == "m.room.member" && state.state_key == user_id;
        });
        if (state_entry == store.state.end())
        {
            return false;
        }
        auto const event = std::ranges::find_if(store.events, [&](database::PersistentEvent const& candidate) {
            return candidate.event_id == state_entry->event_id;
        });
        if (event == store.events.end() || event->stream_ordering <= since_ordering)
        {
            return false;
        }
        auto const parsed = canonicaljson::parse_lossless(event->json);
        auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        auto const* content = object == nullptr ? nullptr : object_member_as_object(*object, "content");
        auto const* membership = content == nullptr ? nullptr : string_member(*content, "membership");
        return membership != nullptr && *membership == "join";
    }

    [[nodiscard]] auto build_to_device_events_array(database::PersistentStore& store, std::string_view user,
                                                    std::string_view device_id, std::uint64_t since_sync_stream_id,
                                                    std::uint64_t sync_stream_upper_bound,
                                                    std::uint64_t& max_observed_stream_id) -> canonicaljson::Array
    {
        auto events = canonicaljson::Array{};
        auto const drained =
            database::drain_to_device_messages(store, user, device_id, since_sync_stream_id, sync_stream_upper_bound);
        for (auto const& message : drained)
        {
            auto event = canonicaljson::Object{};
            event.push_back(json_member("type", json_str(message.message_type)));
            event.push_back(json_member("sender", json_str(message.sender_user_id)));
            event.push_back(json_member("content", parse_event_json_object(message.content_json)));
            events.push_back(canonicaljson::Value{std::move(event)});
            if (message.stream_id > max_observed_stream_id)
            {
                max_observed_stream_id = message.stream_id;
            }
        }
        return events;
    }

    [[nodiscard]] auto build_device_list_arrays(database::PersistentStore const& store, std::string_view user,
                                                std::uint64_t since_sync_stream_id,
                                                std::uint64_t& max_observed_stream_id)
        -> std::pair<canonicaljson::Array, canonicaljson::Array>
    {
        auto changed = canonicaljson::Array{};
        auto left = canonicaljson::Array{};
        for (auto const& change : store.device_list_changes)
        {
            if (change.observer_user_id != user || change.stream_id <= since_sync_stream_id)
            {
                continue;
            }
            if (change.change_type == "left")
            {
                left.push_back(json_str(change.subject_user_id));
            }
            else
            {
                changed.push_back(json_str(change.subject_user_id));
            }
            if (change.stream_id > max_observed_stream_id)
            {
                max_observed_stream_id = change.stream_id;
            }
        }
        return {std::move(changed), std::move(left)};
    }

    [[nodiscard]] auto build_presence_events(database::PersistentStore const& store,
                                             sync::EventTypeFilter const& filter, std::string_view user,
                                             std::uint64_t since_sync_stream_id, std::uint64_t& max_observed_stream_id)
        -> canonicaljson::Array
    {
        auto events = canonicaljson::Array{};
        auto emitted = std::size_t{0U};
        for (auto const& presence : store.presence_states)
        {
            if (presence.user_id == user || presence.stream_id <= since_sync_stream_id)
            {
                continue;
            }
            if (!sync::event_passes_filter(filter, "m.presence", presence.user_id))
            {
                continue;
            }
            if (filter.limit != 0U && emitted >= filter.limit)
            {
                break;
            }
            auto content = canonicaljson::Object{};
            content.push_back(json_member("presence", json_str(presence.presence)));
            if (!presence.status_msg.empty())
            {
                content.push_back(json_member("status_msg", json_str(presence.status_msg)));
            }
            content.push_back(json_member("last_active_ago", json_int(presence.last_active_ago)));
            content.push_back(json_member("currently_active", json_bool(presence.currently_active)));
            auto event = canonicaljson::Object{};
            event.push_back(json_member("type", json_str(std::string{"m.presence"})));
            event.push_back(json_member("sender", json_str(presence.user_id)));
            event.push_back(json_member("content", canonicaljson::Value{std::move(content)}));
            events.push_back(canonicaljson::Value{std::move(event)});
            ++emitted;
            if (presence.stream_id > max_observed_stream_id)
            {
                max_observed_stream_id = presence.stream_id;
            }
        }
        return events;
    }

    [[nodiscard]] auto build_account_data_events(database::PersistentStore const& store,
                                                 sync::EventTypeFilter const& filter, std::string_view user,
                                                 std::string_view room_scope, std::uint64_t since_sync_stream_id,
                                                 std::uint64_t& max_observed_stream_id) -> canonicaljson::Array
    {
        auto events = canonicaljson::Array{};
        auto emitted = std::size_t{0U};
        for (auto const& data : store.account_data)
        {
            if (data.user_id != user || data.room_id != room_scope)
            {
                continue;
            }
            // Incremental /sync: only surface account-data rows whose
            // stream_id strictly exceeds the caller's since token. Initial
            // sync (since_sync_stream_id == 0) returns everything.
            if (data.stream_id <= since_sync_stream_id)
            {
                continue;
            }
            if (!sync::event_passes_filter(filter, data.event_type, user))
            {
                continue;
            }
            if (filter.limit != 0U && emitted >= filter.limit)
            {
                break;
            }
            auto event = canonicaljson::Object{};
            event.push_back(json_member("type", json_str(data.event_type)));
            event.push_back(json_member("content", parse_event_json_object(data.content_json)));
            events.push_back(canonicaljson::Value{std::move(event)});
            ++emitted;
            if (data.stream_id > max_observed_stream_id)
            {
                max_observed_stream_id = data.stream_id;
            }
        }
        return events;
    }

    [[nodiscard]] auto build_otk_counts(database::PersistentStore const& store, std::string_view user,
                                        std::string_view device_id) -> canonicaljson::Object
    {
        auto counts = std::unordered_map<std::string, std::int64_t>{};
        if (!device_id.empty())
        {
            // Fresh devices need an explicit zero count so clients know they
            // must upload signed one-time keys before encrypted rooms can
            // bootstrap cross-device sessions.
            counts.emplace("signed_curve25519", 0);
        }
        for (auto const& key : store.one_time_keys)
        {
            if (key.user_id != user || key.device_id != device_id)
            {
                continue;
            }
            counts[otk_algorithm(key.key_id)] += 1;
        }
        auto out = canonicaljson::Object{};
        for (auto const& [algorithm, count] : counts)
        {
            out.push_back(json_member(algorithm, json_int(count)));
        }
        return out;
    }

    [[nodiscard]] auto build_fallback_key_types(database::PersistentStore const& store, std::string_view user,
                                                std::string_view device_id) -> canonicaljson::Array
    {
        auto types = std::vector<std::string>{};
        for (auto const& key : store.fallback_keys)
        {
            if (key.user_id != user || key.device_id != device_id)
            {
                continue;
            }
            auto const algorithm = otk_algorithm(key.key_id);
            if (std::ranges::find(types, algorithm) == types.end())
            {
                types.push_back(algorithm);
            }
        }
        auto out = canonicaljson::Array{};
        for (auto const& algorithm : types)
        {
            out.push_back(json_str(algorithm));
        }
        return out;
    }

    [[nodiscard]] auto sync_json(ClientServerRuntime& rt, std::string_view user, std::string_view device_id,
                                 core::SyncRequest const& request, bool can_wait = true) -> DispatchResult
    {
        auto const since_token =
            request.since.has_value() ? sync::decode_stream_token(*request.since) : std::optional<sync::StreamToken>{};
        auto const since_ordering = since_token.has_value() ? since_token->event_ordering : std::uint64_t{0U};
        auto const since_sync_stream_id = since_token.has_value() ? since_token->sync_stream_id : std::uint64_t{0U};
        auto const filter =
            request.filter.has_value() ? sync::parse_filter_argument(*request.filter) : sync::SyncFilter{};
        auto& store = rt.homeserver.database.persistent_store;

        // Recover from a counter rollback: if the client's since-token is
        // ahead of the server's sync_stream_id (for example because typing/
        // receipts advanced the in-memory counter before the watermark table
        // existed), advance the counter to the client's position so that future
        // ephemeral events get IDs the client will accept.
        if (since_sync_stream_id > 0U && !database::ensure_sync_stream_id_ahead_of(store, since_sync_stream_id))
        {
            return DispatchResult{
                DispatchResult::Status::complete, err(500U, "M_UNKNOWN", "unable to advance sync stream counter"), {}};
        }

        // Long-poll: when the caller passes `timeout` and there's nothing
        // new to deliver, block until the SyncNotifier fires or the timeout
        // expires. The check is "is anything past since visible?"; we wake
        // when the store's sync stream id advances OR a new event appears
        // in the timeline ordering, both of which the mutator helpers below
        // publish through `ensure_sync_notifier(rt).publish(...)`.
        // Spec §9.4: omitting `timeout` means respond immediately — no default.
        if (can_wait && request.timeout.has_value() && *request.timeout > 0U)
        {
            auto const has_timeline_advance = rt.homeserver.database.next_stream_ordering - 1U > since_ordering;
            auto const has_sync_advance = store.next_sync_stream_id > since_sync_stream_id;
            if (!has_timeline_advance && !has_sync_advance)
            {
                return DispatchResult{
                    DispatchResult::Status::needs_wait,
                    {},
                    {since_ordering, since_sync_stream_id, std::chrono::milliseconds{*request.timeout}}
                };
            }
        }

        auto const sync_stream_upper_bound = store.next_sync_stream_id;
        auto max_observed_sync_stream_id = since_sync_stream_id;
        auto join_members = canonicaljson::Object{};
        auto join_count = std::size_t{0U};

        log_diagnostic("sync.request",
                       {
                           {"user",                    std::string{user},                                   false},
                           {"since_event_ordering",    std::to_string(since_ordering),                      false},
                           {"since_sync_stream_id",    std::to_string(since_sync_stream_id),                false},
                           {"sync_stream_upper_bound", std::to_string(sync_stream_upper_bound),             false},
                           {"filter_present",          filter.present ? "true" : "false",                   false},
                           {"rooms_total",             std::to_string(rt.homeserver.database.rooms.size()), false}
        });

        for (auto const& room : rt.homeserver.database.rooms)
        {
            if (join_count >= rt.limits.max_sync_rooms || !joined(room, user))
            {
                continue;
            }
            if (filter.present && !sync::room_passes_filter(filter.room, room.room_id))
            {
                continue;
            }
            auto const timeline_cap = filter.room.timeline.limit != 0U
                                          ? std::min(filter.room.timeline.limit, rt.limits.max_sync_events_per_room)
                                          : rt.limits.max_sync_events_per_room;

            // Collect this room's timeline-eligible events that are newer than
            // `since`, in stream-ordering order. `limited` and `prev_batch` are
            // derived from THIS window per the Matrix sync spec — never from the
            // room's (or store's) total event count.
            auto matched = std::vector<database::PersistentEvent const*>{};
            for (auto const& event : store.events)
            {
                if (event.room_id != room.room_id)
                {
                    continue;
                }
                if (since_ordering > 0U && event.stream_ordering <= since_ordering)
                {
                    continue;
                }
                if (!sync::event_passes_filter(filter.room.timeline, std::string_view{}, event.sender_user_id))
                {
                    // Event type isn't surfaced on PersistentEvent yet; the
                    // sender filter is the only meaningful per-event predicate
                    // until events expose their type. Passing an empty string
                    // for event_type makes `event_passes_filter` apply the
                    // sender rules without requiring a type match.
                    continue;
                }
                matched.push_back(&event);
            }
            std::ranges::sort(matched, [](auto const* lhs, auto const* rhs) noexcept {
                return lhs->stream_ordering < rhs->stream_ordering;
            });

            // Spec MUST: `limited` is true only when older events were dropped
            // from this window because it exceeded the page size. When so,
            // return the MOST RECENT `timeline_cap` events (clients render
            // newest history first); otherwise return the whole window. The old
            // code compared the store's total event count to the cap, so any
            // room with more total events than the page size reported
            // limited=true on every sync, making matrix-js-sdk discard and
            // re-fetch the timeline endlessly.
            auto const limited = matched.size() > timeline_cap;
            auto const window_begin =
                limited ? matched.end() - static_cast<std::ptrdiff_t>(timeline_cap) : matched.begin();

            auto timeline_events = canonicaljson::Array{};
            for (auto it = window_begin; it != matched.end(); ++it)
            {
                timeline_events.push_back(client_event_value(**it));
            }
            auto const event_count = timeline_events.size();

            // prev_batch lets clients backfill older history via
            // /rooms/{roomId}/messages?from=<prev_batch>&dir=b, which returns
            // events strictly older than the token. Anchor it at the oldest
            // event we return (or the `since` position when the window is empty)
            // so there is neither a gap nor an overlap with this batch.
            auto const prev_batch = window_begin != matched.end() ? std::to_string((*window_begin)->stream_ordering)
                                                                  : std::to_string(since_ordering);
            auto room_account_data = build_account_data_events(store, filter.room.account_data, user, room.room_id,
                                                               since_sync_stream_id, max_observed_sync_stream_id);

            // Build the room's current state events. Initial sync always
            // includes the full state snapshot. Incremental sync also needs
            // that snapshot when the room first becomes joined for this user:
            // without m.room.encryption / power_levels / create state, real
            // clients cannot configure crypto after accepting an invite.
            auto const newly_joined =
                since_token.has_value() && joined_membership_changed_since(store, room.room_id, user, since_ordering);
            auto state_events = canonicaljson::Array{};
            if (!since_token.has_value() || newly_joined)
            {
                state_events = build_current_state_events_array(store, filter.room.state, room.room_id);
            }
            auto ephemeral_events = build_room_ephemeral_events_array(rt.homeserver, room.room_id, since_sync_stream_id,
                                                                      max_observed_sync_stream_id);

            // Incremental sync: suppress rooms that have nothing new to report.
            // Without this check, re-dispatches after a long-poll timeout emit
            // the full membership state of every joined room on every 5-second
            // cycle, causing clients to receive the same stale payload repeatedly
            // and making it appear as if the room is stuck.
            if (since_token.has_value() && timeline_events.empty() && room_account_data.empty() &&
                state_events.empty() && ephemeral_events.empty())
            {
                continue;
            }

            ++join_count;
            join_members.push_back(json_member(
                room.room_id,
                json_obj({
                    json_member("timeline",
                                json_obj({
                                    json_member("events", json_arr(std::move(timeline_events))),
                                    json_member("limited", json_bool(limited)),
                                    json_member("prev_batch", json_str(prev_batch)),
                                    json_member("event_count", json_int(static_cast<std::int64_t>(event_count))),
                                })),
                    json_member("state", json_obj({json_member("events", json_arr(std::move(state_events)))})),
                    json_member("account_data",
                                json_obj({json_member("events", json_arr(std::move(room_account_data)))})),
                    json_member("ephemeral", json_obj({json_member("events", json_arr(std::move(ephemeral_events)))})),
                })));
        }

        // Invite list. `rooms.leave` is suppressed unless the filter opts in
        // via `include_leave: true`; we now actually honour that flag.
        auto invite_members = canonicaljson::Object{};
        auto leave_members = canonicaljson::Object{};
        auto knock_members = canonicaljson::Object{};
        auto invite_count = std::size_t{0U};
        auto leave_count = std::size_t{0U};
        auto knock_count = std::size_t{0U};
        for (auto const& membership : store.memberships)
        {
            if (membership.user_id != user)
            {
                continue;
            }
            if (filter.present && !sync::room_passes_filter(filter.room, membership.room_id))
            {
                continue;
            }
            if (membership.membership == "invite")
            {
                if (invite_count < rt.limits.max_sync_rooms)
                {
                    auto invite_state_events = build_invite_state_events_array(store, membership.room_id, user);
                    invite_members.push_back(json_member(
                        membership.room_id,
                        json_obj({json_member(
                            "invite_state",
                            json_obj({json_member("events", json_arr(std::move(invite_state_events)))}))})));
                    ++invite_count;
                }
            }
            else if (membership.membership == "leave" && filter.room.include_leave)
            {
                if (leave_count < rt.limits.max_sync_rooms)
                {
                    leave_members.push_back(json_member(
                        membership.room_id,
                        json_obj({json_member("timeline", json_obj({json_member("events", json_arr({}))}))})));
                    ++leave_count;
                }
            }
            else if (membership.membership == "knock")
            {
                if (knock_count < rt.limits.max_sync_rooms)
                {
                    knock_members.push_back(json_member(
                        membership.room_id,
                        json_obj({json_member("knock_state",
                                              json_obj({json_member("events", json_arr(build_knock_state_events_array(
                                                                                  store, membership.room_id)))}))})));
                    ++knock_count;
                }
            }
        }

        log_diagnostic("sync.response",
                       {
                           {"user",                 std::string{user},                           false},
                           {"join_count",           std::to_string(join_count),                  false},
                           {"invite_count",         std::to_string(invite_count),                false},
                           {"leave_count",          std::to_string(leave_count),                 false},
                           {"knock_count",          std::to_string(knock_count),                 false},
                           {"max_observed_sync_id", std::to_string(max_observed_sync_stream_id), false}
        });

        auto to_device_events = build_to_device_events_array(store, user, device_id, since_sync_stream_id,
                                                             sync_stream_upper_bound, max_observed_sync_stream_id);
        auto [device_changed, device_left] =
            build_device_list_arrays(store, user, since_sync_stream_id, max_observed_sync_stream_id);
        auto presence_events =
            build_presence_events(store, filter.presence, user, since_sync_stream_id, max_observed_sync_stream_id);
        auto global_account_data = build_account_data_events(store, filter.account_data, user, std::string_view{},
                                                             since_sync_stream_id, max_observed_sync_stream_id);
        auto otk_counts = build_otk_counts(store, user, device_id);
        auto fallback_key_types = build_fallback_key_types(store, user, device_id);

        auto const advanced_sync_stream_id = std::max(max_observed_sync_stream_id, sync_stream_upper_bound);
        auto const next_token =
            sync::StreamToken{rt.homeserver.database.next_stream_ordering - 1U,
                              rt.homeserver.database.next_stream_ordering - 1U, advanced_sync_stream_id};

        auto const body = json_serialize(json_obj({
            json_member("next_batch", json_str(sync::encode_stream_token(next_token))),
            json_member("rooms", json_obj({
                                     json_member("join", json_obj(std::move(join_members))),
                                     json_member("invite", json_obj(std::move(invite_members))),
                                     json_member("leave", json_obj(std::move(leave_members))),
                                     json_member("knock", json_obj(std::move(knock_members))),
                                 })),
            json_member("presence", json_obj({json_member("events", json_arr(std::move(presence_events)))})),
            json_member("account_data", json_obj({json_member("events", json_arr(std::move(global_account_data)))})),
            json_member("to_device", json_obj({json_member("events", json_arr(std::move(to_device_events)))})),
            json_member("device_lists", json_obj({
                                            json_member("changed", json_arr(std::move(device_changed))),
                                            json_member("left", json_arr(std::move(device_left))),
                                        })),
            json_member("device_one_time_keys_count", canonicaljson::Value{std::move(otk_counts)}),
            json_member("device_unused_fallback_key_types", json_arr(std::move(fallback_key_types))),
        }));
        return DispatchResult{
            DispatchResult::Status::complete, {200U, std::move(body)},
             {}
        };
    }

    // ── MSC4186 Sliding Sync serialisation helpers ────────────────────────────

    [[nodiscard]] auto sliding_sync_op_to_value(sync::SlidingSyncOp const& op) -> canonicaljson::Value
    {
        auto obj = canonicaljson::Object{};
        obj.push_back(json_member("op", json_str(op.op)));
        if (op.range.has_value())
        {
            auto range_arr = canonicaljson::Array{};
            range_arr.push_back(json_int(static_cast<std::int64_t>(op.range->start)));
            range_arr.push_back(json_int(static_cast<std::int64_t>(op.range->end)));
            obj.push_back(json_member("range", json_arr(std::move(range_arr))));
        }
        if (!op.room_ids.empty())
        {
            auto ids = canonicaljson::Array{};
            for (auto const& id : op.room_ids)
            {
                ids.push_back(json_str(id));
            }
            obj.push_back(json_member("room_ids", json_arr(std::move(ids))));
        }
        if (op.index.has_value())
        {
            obj.push_back(json_member("index", json_int(static_cast<std::int64_t>(*op.index))));
        }
        if (op.room_id.has_value())
        {
            obj.push_back(json_member("room_id", json_str(*op.room_id)));
        }
        return canonicaljson::Value{std::move(obj)};
    }

    [[nodiscard]] auto sliding_sync_room_to_value(sync::SlidingSyncRoomResponse room) -> canonicaljson::Value
    {
        auto parse_json = [](std::string const& json) -> canonicaljson::Value {
            auto result = canonicaljson::parse_lossless(json);
            return result.error == canonicaljson::ParseError::none ? std::move(result.value)
                                                                   : canonicaljson::Value{canonicaljson::Object{}};
        };

        auto obj = canonicaljson::Object{};
        if (room.name.has_value())
        {
            obj.push_back(json_member("name", json_str(*room.name)));
        }
        if (room.avatar.has_value())
        {
            obj.push_back(json_member("avatar", json_str(*room.avatar)));
        }
        obj.push_back(json_member("initial", json_bool(room.initial)));
        obj.push_back(json_member("is_dm", json_bool(room.is_dm)));
        obj.push_back(json_member("num_live", json_int(static_cast<std::int64_t>(room.num_live))));
        obj.push_back(json_member("timestamp", json_int(static_cast<std::int64_t>(room.timestamp))));
        if (room.joined_count.has_value())
        {
            obj.push_back(json_member("joined_count", json_int(static_cast<std::int64_t>(*room.joined_count))));
        }
        if (room.invited_count.has_value())
        {
            obj.push_back(json_member("invited_count", json_int(static_cast<std::int64_t>(*room.invited_count))));
        }
        if (room.notification_count.has_value())
        {
            obj.push_back(
                json_member("notification_count", json_int(static_cast<std::int64_t>(*room.notification_count))));
        }
        if (room.highlight_count.has_value())
        {
            obj.push_back(json_member("highlight_count", json_int(static_cast<std::int64_t>(*room.highlight_count))));
        }
        if (!room.heroes.empty())
        {
            auto heroes_arr = canonicaljson::Array{};
            for (auto const& hero : room.heroes)
            {
                auto hero_obj = canonicaljson::Object{};
                hero_obj.push_back(json_member("user_id", json_str(hero.user_id)));
                if (hero.display_name.has_value())
                {
                    hero_obj.push_back(json_member("display_name", json_str(*hero.display_name)));
                }
                if (hero.avatar_url.has_value())
                {
                    hero_obj.push_back(json_member("avatar_url", json_str(*hero.avatar_url)));
                }
                heroes_arr.push_back(canonicaljson::Value{std::move(hero_obj)});
            }
            obj.push_back(json_member("heroes", json_arr(std::move(heroes_arr))));
        }
        auto req_state = canonicaljson::Array{};
        for (auto& json : room.required_state_json)
        {
            req_state.push_back(parse_json(json));
        }
        obj.push_back(json_member("required_state", json_arr(std::move(req_state))));
        auto tl_events = canonicaljson::Array{};
        for (auto& json : room.timeline_json)
        {
            tl_events.push_back(parse_json(json));
        }
        auto tl_obj = canonicaljson::Object{};
        tl_obj.push_back(json_member("events", json_arr(std::move(tl_events))));
        tl_obj.push_back(json_member("limited", json_bool(room.limited)));
        if (room.prev_batch.has_value())
        {
            tl_obj.push_back(json_member("prev_batch", json_str(*room.prev_batch)));
        }
        obj.push_back(json_member("timeline", json_obj(std::move(tl_obj))));
        if (room.invite_state_json.has_value())
        {
            auto iv_events = canonicaljson::Array{};
            iv_events.push_back(parse_json(*room.invite_state_json));
            obj.push_back(json_member("invite_state", json_arr(std::move(iv_events))));
        }
        return canonicaljson::Value{std::move(obj)};
    }

    [[nodiscard]] auto sliding_sync_ext_to_value(sync::SlidingSyncExtensionResponses ext) -> canonicaljson::Object
    {
        auto parse_json = [](std::string const& json) -> canonicaljson::Value {
            auto result = canonicaljson::parse_lossless(json);
            return result.error == canonicaljson::ParseError::none ? std::move(result.value)
                                                                   : canonicaljson::Value{canonicaljson::Object{}};
        };

        auto obj = canonicaljson::Object{};

        if (ext.to_device.has_value())
        {
            auto events = canonicaljson::Array{};
            for (auto& json : ext.to_device->events_json)
            {
                events.push_back(parse_json(json));
            }
            auto td = canonicaljson::Object{};
            td.push_back(json_member("events", json_arr(std::move(events))));
            td.push_back(json_member("next_batch", json_str(ext.to_device->next_batch)));
            obj.push_back(json_member("to_device", json_obj(std::move(td))));
        }

        if (ext.e2ee.has_value())
        {
            auto& e = *ext.e2ee;
            auto changed_arr = canonicaljson::Array{};
            for (auto& uid : e.changed)
            {
                changed_arr.push_back(json_str(uid));
            }
            auto left_arr = canonicaljson::Array{};
            for (auto& uid : e.left)
            {
                left_arr.push_back(json_str(uid));
            }
            auto otk_obj = canonicaljson::Object{};
            for (auto const& [algo, count] : e.device_one_time_keys_count)
            {
                otk_obj.push_back(json_member(algo, json_int(static_cast<std::int64_t>(count))));
            }
            auto fallback_arr = canonicaljson::Array{};
            for (auto& algo : e.device_unused_fallback_key_types)
            {
                fallback_arr.push_back(json_str(algo));
            }
            auto dl_obj = canonicaljson::Object{};
            dl_obj.push_back(json_member("changed", json_arr(std::move(changed_arr))));
            dl_obj.push_back(json_member("left", json_arr(std::move(left_arr))));
            auto e2ee_obj = canonicaljson::Object{};
            e2ee_obj.push_back(json_member("device_lists", json_obj(std::move(dl_obj))));
            e2ee_obj.push_back(json_member("device_one_time_keys_count", json_obj(std::move(otk_obj))));
            e2ee_obj.push_back(json_member("device_unused_fallback_key_types", json_arr(std::move(fallback_arr))));
            obj.push_back(json_member("e2ee", json_obj(std::move(e2ee_obj))));
        }

        if (ext.account_data.has_value())
        {
            auto global_arr = canonicaljson::Array{};
            for (auto& json : ext.account_data->global_json)
            {
                global_arr.push_back(parse_json(json));
            }
            auto rooms_obj = canonicaljson::Object{};
            for (auto& [rid, jsons] : ext.account_data->rooms_json)
            {
                auto events = canonicaljson::Array{};
                for (auto& json : jsons)
                {
                    events.push_back(parse_json(json));
                }
                rooms_obj.push_back(json_member(rid, json_arr(std::move(events))));
            }
            auto ad_obj = canonicaljson::Object{};
            ad_obj.push_back(json_member("global", json_arr(std::move(global_arr))));
            ad_obj.push_back(json_member("rooms", json_obj(std::move(rooms_obj))));
            obj.push_back(json_member("account_data", json_obj(std::move(ad_obj))));
        }

        if (ext.receipts.has_value())
        {
            auto rooms_obj = canonicaljson::Object{};
            for (auto& [rid, json] : ext.receipts->rooms_json)
            {
                rooms_obj.push_back(json_member(rid, parse_json(json)));
            }
            auto rec_obj = canonicaljson::Object{};
            rec_obj.push_back(json_member("rooms", json_obj(std::move(rooms_obj))));
            obj.push_back(json_member("receipts", json_obj(std::move(rec_obj))));
        }

        if (ext.typing.has_value())
        {
            auto rooms_obj = canonicaljson::Object{};
            for (auto& [rid, json] : ext.typing->rooms_json)
            {
                rooms_obj.push_back(json_member(rid, parse_json(json)));
            }
            auto typ_obj = canonicaljson::Object{};
            typ_obj.push_back(json_member("rooms", json_obj(std::move(rooms_obj))));
            obj.push_back(json_member("typing", json_obj(std::move(typ_obj))));
        }

        return obj;
    }

    [[nodiscard]] auto sliding_sync_json(ClientServerRuntime& rt, std::string_view user, std::string_view device_id,
                                         sync::SlidingSyncRequest const& ssreq,
                                         std::optional<sync::StreamToken> const& pos, std::uint64_t timeout_ms,
                                         bool can_wait) -> DispatchResult
    {
        auto& store = rt.homeserver.database.persistent_store;

        // Per-connection state keyed user/device/conn_id.  Looked up early so
        // that the since values below can fall back to the connection's last
        // known position when the client omits pos (e.g. timeout=0 polls).
        auto const conn_key = std::string{user} + "/" + std::string{device_id} + "/" +
                              (ssreq.conn_id.has_value() ? *ssreq.conn_id : "__default__");
        auto& conn = rt.homeserver.sliding_sync_connections[conn_key];
        conn.last_used = std::chrono::steady_clock::now();

        // When the client omits pos (a timeout=0 poll that always requests an
        // immediate snapshot without a since-token) but this connection already
        // has state from a previous response, use the connection's last-known
        // cursors rather than 0.  This turns repeated no-pos polls into small
        // delta responses ("nothing new since your last sync") instead of
        // re-delivering the full room history on every cycle, which was
        // causing matrix-rust-sdk to reset its connection state and loop.
        // The first request for a fresh connection (rooms_seen empty) still
        // gets since=0 so the SDK receives the full initial room list.
        auto const since_event_ordering =
            pos.has_value() ? pos->event_ordering
                            : (conn.rooms_seen.empty() ? std::uint64_t{0U} : conn.last_event_ordering);
        auto const since_sync_stream_id =
            pos.has_value() ? pos->sync_stream_id
                            : (conn.rooms_seen.empty() ? std::uint64_t{0U} : conn.last_sync_stream_id);

        // Long-poll: park when nothing relevant to this connection has changed.
        // A sync_stream_id advance from another user uploading device keys fires
        // the global notifier and would otherwise cause an immediate return with
        // empty data, triggering a client reset loop.  We re-wait past irrelevant
        // bumps by advancing the since_sync_stream_id in the needs_wait params.
        if (can_wait && timeout_ms > 0U)
        {
            auto const cur_event = rt.homeserver.database.next_stream_ordering - 1U;
            auto const cur_sync = store.next_sync_stream_id;
            if (cur_event <= since_event_ordering)
            {
                // No new room events.  Only respond early if the sync_stream_id
                // advance contains rows relevant to this user/device:
                //   - device-list changes where this user is the observer
                //   - to-device messages addressed to this device
                //   - account-data rows owned by this user
                //   - receipts or typing updates in any room the user has joined
                // Typing/receipts were previously ignored, so a typing event or
                // read receipt in the user's room would advance sync_stream_id
                // without waking this long-poll, leaving ElementX stale.
                bool const has_relevant_dlc = std::ranges::any_of(store.device_list_changes, [&](auto const& c) {
                    return c.observer_user_id == user && c.stream_id > since_sync_stream_id;
                });
                bool const has_relevant_tdm = std::ranges::any_of(store.to_device_messages, [&](auto const& m) {
                    return m.target_user_id == user && m.target_device_id == device_id &&
                           m.stream_id > since_sync_stream_id;
                });
                bool const has_relevant_ad = std::ranges::any_of(store.account_data, [&](auto const& ad) {
                    return ad.user_id == user && ad.stream_id > since_sync_stream_id;
                });
                bool const has_relevant_receipts = std::ranges::any_of(rt.homeserver.receipts, [&](auto const& r) {
                    return r.stream_id > since_sync_stream_id && user_is_joined(store, r.room_id, user);
                });
                bool const has_relevant_typing =
                    std::ranges::any_of(rt.homeserver.room_typing_stream_id, [&](auto const& kv) {
                        return kv.second > since_sync_stream_id && user_is_joined(store, kv.first, user);
                    });
                if (!has_relevant_dlc && !has_relevant_tdm && !has_relevant_ad && !has_relevant_receipts &&
                    !has_relevant_typing)
                {
                    // Advance the wait cursor past this irrelevant bump so the
                    // notifier must fire again before the next wakeup attempt.
                    return DispatchResult{
                        DispatchResult::Status::needs_wait,
                        {},
                        {since_event_ordering, cur_sync, std::chrono::milliseconds{timeout_ms}}
                    };
                }
            }
        }

        // ── Build list windows ───────────────────────────────────────────────

        auto list_results = std::map<std::string, sync::RoomListResult>{};
        for (auto const& [list_name, list] : ssreq.lists)
        {
            auto const empty_prev = std::vector<std::string>{};
            auto const it = conn.list_prev_windows.find(list_name);
            auto const& prev_win = (it != conn.list_prev_windows.end()) ? it->second : empty_prev;
            list_results[list_name] = sync::compute_room_list(rt.homeserver, user, list, prev_win, store);
        }

        // Collect ordered unique room IDs: lists first, then explicit subscriptions.
        auto response_room_ids = std::vector<std::string>{};
        auto seen_rooms = std::unordered_set<std::string>{};
        for (auto const& [lname, result] : list_results)
        {
            for (auto const& room_id : result.windowed_room_ids)
            {
                if (seen_rooms.insert(room_id).second)
                {
                    response_room_ids.push_back(room_id);
                }
            }
        }
        for (auto const& [room_id, sub_unused] : ssreq.room_subscriptions)
        {
            std::ignore = sub_unused;
            if (seen_rooms.insert(room_id).second)
            {
                response_room_ids.push_back(room_id);
            }
        }

        // ── Per-room responses ───────────────────────────────────────────────

        auto rooms_obj = canonicaljson::Object{};
        auto rooms_skipped = std::size_t{0U};
        for (auto const& room_id : response_room_ids)
        {
            auto sub = sync::SlidingSyncRoomSubscription{};
            if (auto const sit = ssreq.room_subscriptions.find(room_id); sit != ssreq.room_subscriptions.end())
            {
                sub = sit->second;
            }
            else
            {
                for (auto const& [lname, result] : list_results)
                {
                    if (std::ranges::find(result.windowed_room_ids, room_id) != result.windowed_room_ids.end())
                    {
                        if (auto const lit = ssreq.lists.find(lname); lit != ssreq.lists.end())
                        {
                            sub.required_state = lit->second.required_state;
                            sub.timeline_limit = lit->second.timeline_limit;
                            sub.include_heroes = lit->second.include_heroes;
                        }
                        break;
                    }
                }
            }
            auto const room_seen_it = conn.rooms_seen.find(room_id);
            auto const is_initial = room_seen_it == conn.rooms_seen.end();
            auto const room_last_ordering = is_initial ? std::uint64_t{0U} : room_seen_it->second;
            // Use the per-room last inclusion ordering as the delta floor.  This
            // prevents re-delivering a room when the request pos lags behind the
            // ordering at which the room was already returned on this connection,
            // which was causing matrix-rust-sdk / ElementX to see the same payload
            // with a non-advancing pos and reset into a polling loop.
            auto const room_since = std::max(since_event_ordering, room_last_ordering);
            auto room = sync::build_room_response(rt.homeserver, room_id, user, sub, room_since, is_initial, store);
            // Per MSC4186, only include a room in rooms{} when it has actual
            // changes: first appearance (initial), post-pos timeline events, or changed
            // required_state.  Unread counts are sent when the room is included for
            // another reason; they must not pull an unchanged room back into the
            // response, otherwise the client receives identical data under the same
            // pos and may loop.
            auto const has_room_updates =
                is_initial || !room.timeline_json.empty() || !room.required_state_json.empty();
            if (has_room_updates)
            {
                rooms_obj.push_back(json_member(room_id, sliding_sync_room_to_value(std::move(room))));
            }
            else
            {
                ++rooms_skipped;
            }
        }

        // ── Extensions ──────────────────────────────────────────────────────

        auto ext_obj = canonicaljson::Object{};
        if (ssreq.extensions.has_value())
        {
            ext_obj = sliding_sync_ext_to_value(
                sync::build_extensions(rt.homeserver, user, device_id, *ssreq.extensions, since_sync_stream_id,
                                       store.next_sync_stream_id, store, response_room_ids));
        }

        // ── pos token and list op responses ─────────────────────────────────

        auto const cur_event = rt.homeserver.database.next_stream_ordering - 1U;
        auto const cur_sync = store.next_sync_stream_id;
        auto const new_pos = sync::encode_stream_token(sync::StreamToken{cur_event, cur_event, cur_sync});

        auto lists_obj = canonicaljson::Object{};
        for (auto& [lname, result] : list_results)
        {
            auto ops_arr = canonicaljson::Array{};
            for (auto const& op : result.ops)
            {
                ops_arr.push_back(sliding_sync_op_to_value(op));
            }
            auto list_resp = canonicaljson::Object{};
            list_resp.push_back(json_member("count", json_int(static_cast<std::int64_t>(result.count))));
            list_resp.push_back(json_member("ops", json_arr(std::move(ops_arr))));
            lists_obj.push_back(json_member(lname, json_obj(std::move(list_resp))));
        }

        auto const rooms_in_response = rooms_obj.size();

        // ── Assemble response body ───────────────────────────────────────────

        auto response_obj = canonicaljson::Object{};
        response_obj.push_back(json_member("pos", json_str(new_pos)));
        response_obj.push_back(json_member("lists", json_obj(std::move(lists_obj))));
        response_obj.push_back(json_member("rooms", json_obj(std::move(rooms_obj))));
        if (!ext_obj.empty())
        {
            response_obj.push_back(json_member("extensions", json_obj(std::move(ext_obj))));
        }
        auto const body = json_serialize(json_obj(std::move(response_obj)));

        log_diagnostic("sliding_sync.response", {
                                                    {"actor",             std::string{user},                        false},
                                                    {"device_id",         std::string{device_id},                   false},
                                                    {"pos",               new_pos,                                  false},
                                                    {"timeout_ms",        std::to_string(timeout_ms),               false},
                                                    {"rooms_window",      std::to_string(response_room_ids.size()), false},
                                                    {"rooms_in_response", std::to_string(rooms_in_response),        false},
                                                    {"rooms_skipped",     std::to_string(rooms_skipped),            false},
                                                    {"rooms_seen",        std::to_string(conn.rooms_seen.size()),   false},
                                                    {"lists_returned",    std::to_string(list_results.size()),      false}
        });

        // ── Update connection state ──────────────────────────────────────────

        for (auto const& room_id : response_room_ids)
        {
            // Record the snapshot ordering at which this room was last returned to
            // this connection.  Future requests on the same connection will treat
            // this as the delta floor, not the global request pos.
            conn.rooms_seen[room_id] = cur_event;
        }
        for (auto& [lname, result] : list_results)
        {
            conn.list_prev_windows[lname] = std::move(result.windowed_room_ids);
        }
        conn.last_event_ordering = cur_event;
        conn.last_sync_stream_id = cur_sync;

        return DispatchResult{
            DispatchResult::Status::complete, {200U, std::move(body)},
             {}
        };
    }

    [[nodiscard]] auto error_code_for_status(std::uint16_t status) -> std::string_view
    {
        if (status == 404U)
        {
            return "M_NOT_FOUND";
        }
        if (status == 403U)
        {
            return "M_FORBIDDEN";
        }
        if (status == 401U)
        {
            return "M_UNKNOWN_TOKEN";
        }
        return "M_UNKNOWN";
    }

    [[nodiscard]] auto wrap(LocalHttpResponse const& r, std::string_view key) -> LocalHttpResponse
    {
        if (r.status != 200U)
        {
            return err(r.status, error_code_for_status(r.status), r.body);
        }
        return resp(200U, json_serialize(json_obj({json_member(std::string{key}, json_str(r.body))})));
    }

    auto set_object_member(canonicaljson::Object& object, std::string_view key, canonicaljson::Value value) -> void
    {
        auto const existing = std::ranges::find_if(object, [key](canonicaljson::ObjectMember const& member) {
            return member.key == key;
        });
        if (existing != object.end())
        {
            existing->value = std::make_unique<canonicaljson::Value>(std::move(value));
            return;
        }
        object.push_back(json_member(std::string{key}, std::move(value)));
    }

    [[nodiscard]] auto runtime_device_display_name(ClientServerRuntime const& rt, std::string_view user_id,
                                                   std::string_view device_id) -> std::string
    {
        auto const existing = std::ranges::find_if(rt.devices, [user_id, device_id](ClientDevice const& device) {
            return device.user_id == user_id && device.device_id == device_id;
        });
        return existing == rt.devices.end() ? std::string{} : existing->display_name;
    }

    auto normalize_device_key_object_for_client(ClientServerRuntime const& rt, canonicaljson::Object& device_object,
                                                std::string_view user_id, std::string_view device_id) -> void
    {
        set_object_member(device_object, "user_id", json_str(user_id));
        set_object_member(device_object, "device_id", json_str(device_id));

        if (auto const* existing_keys = object_member_as_object(device_object, "keys"); existing_keys != nullptr)
        {
            auto normalized_keys = canonicaljson::Object{};
            auto curve_key = std::optional<std::string>{};
            auto ed_key = std::optional<std::string>{};
            for (auto const& key_member : *existing_keys)
            {
                if (key_member.value == nullptr)
                {
                    continue;
                }
                auto const* key_value = std::get_if<std::string>(&key_member.value->storage());
                if (key_value == nullptr)
                {
                    continue;
                }
                if (key_member.key.starts_with("curve25519:") && !curve_key.has_value())
                {
                    curve_key = *key_value;
                    continue;
                }
                if (key_member.key.starts_with("ed25519:") && !ed_key.has_value())
                {
                    ed_key = *key_value;
                    continue;
                }
                normalized_keys.push_back(json_member(key_member.key, json_str(*key_value)));
            }
            if (curve_key.has_value())
            {
                set_object_member(normalized_keys, "curve25519:" + std::string{device_id}, json_str(*curve_key));
            }
            if (ed_key.has_value())
            {
                set_object_member(normalized_keys, "ed25519:" + std::string{device_id}, json_str(*ed_key));
            }
            set_object_member(device_object, "keys", json_obj(std::move(normalized_keys)));
        }

        auto unsigned_object = canonicaljson::Object{};
        if (auto const* existing_unsigned = object_member_as_object(device_object, "unsigned");
            existing_unsigned != nullptr)
        {
            unsigned_object = *existing_unsigned;
        }
        auto const display_name = runtime_device_display_name(rt, user_id, device_id);
        if (!display_name.empty() && string_member(unsigned_object, "device_display_name") == nullptr)
        {
            set_object_member(unsigned_object, "device_display_name", json_str(display_name));
        }
        if (!unsigned_object.empty())
        {
            set_object_member(device_object, "unsigned", json_obj(std::move(unsigned_object)));
        }
    }

    [[nodiscard]] auto first_key_id_in_key_object(canonicaljson::Object const& object) -> std::optional<std::string>
    {
        auto const* keys = object_member_as_object(object, "keys");
        if (keys == nullptr || keys->empty())
        {
            return std::nullopt;
        }
        return keys->front().key;
    }

    auto merge_signature_members(canonicaljson::Object& target_signatures,
                                 canonicaljson::Object const& source_signatures) -> void
    {
        for (auto const& signer_member : source_signatures)
        {
            auto signer_signatures = canonicaljson::Object{};
            if (auto const* existing_signer = object_member_as_object(target_signatures, signer_member.key);
                existing_signer != nullptr)
            {
                signer_signatures = *existing_signer;
            }
            auto const* source_signer = std::get_if<canonicaljson::Object>(&signer_member.value->storage());
            if (source_signer == nullptr)
            {
                continue;
            }
            for (auto const& signature_member : *source_signer)
            {
                set_object_member(signer_signatures, signature_member.key, *signature_member.value);
            }
            set_object_member(target_signatures, signer_member.key, json_obj(std::move(signer_signatures)));
        }
    }

    auto merge_uploaded_signatures(canonicaljson::Object& target_object, database::PersistentStore const& store,
                                   std::string_view target_user_id, std::string_view target_key_id) -> void
    {
        auto signatures = canonicaljson::Object{};
        if (auto const* existing_signatures = object_member_as_object(target_object, "signatures");
            existing_signatures != nullptr)
        {
            signatures = *existing_signatures;
        }
        for (auto const& stored_signature : store.key_signatures)
        {
            if (stored_signature.target_user_id != target_user_id || stored_signature.target_device_id != target_key_id)
            {
                continue;
            }
            auto const parsed = parsed_json_object(stored_signature.json);
            if (!parsed.has_value())
            {
                continue;
            }
            auto const* uploaded_signatures = object_member_as_object(*parsed, "signatures");
            if (uploaded_signatures == nullptr)
            {
                continue;
            }
            merge_signature_members(signatures, *uploaded_signatures);
        }
        set_object_member(target_object, "signatures", json_obj(std::move(signatures)));
    }

    [[nodiscard]] auto key_backup_version_for_user(database::PersistentStore const& store, std::string_view user_id,
                                                   std::optional<std::string_view> version = std::nullopt)
        -> database::PersistentKeyBackupVersion const*
    {
        if (version.has_value())
        {
            auto const found = std::ranges::find_if(
                store.key_backup_versions, [user_id, version](database::PersistentKeyBackupVersion const& candidate) {
                    return candidate.user_id == user_id && candidate.version == *version;
                });
            return found == store.key_backup_versions.end() ? nullptr : &*found;
        }

        for (auto it = store.key_backup_versions.rbegin(); it != store.key_backup_versions.rend(); ++it)
        {
            if (it->user_id == user_id)
            {
                return &*it;
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto key_backup_session_count(database::PersistentStore const& store, std::string_view user_id,
                                                std::string_view version) -> std::int64_t
    {
        return static_cast<std::int64_t>(std::ranges::count_if(
            store.key_backup_sessions, [user_id, version](database::PersistentKeyBackupSession const& session) {
                return session.user_id == user_id && session.version == version;
            }));
    }

    [[nodiscard]] auto key_backup_etag(database::PersistentStore const& store, std::string_view user_id,
                                       std::string_view version) -> std::string
    {
        auto sessions = std::vector<database::PersistentKeyBackupSession const*>{};
        for (auto const& session : store.key_backup_sessions)
        {
            if (session.user_id == user_id && session.version == version)
            {
                sessions.push_back(&session);
            }
        }
        std::ranges::sort(sessions, [](database::PersistentKeyBackupSession const* lhs,
                                       database::PersistentKeyBackupSession const* rhs) {
            return std::tie(lhs->room_id, lhs->session_id, lhs->json) <
                   std::tie(rhs->room_id, rhs->session_id, rhs->json);
        });

        std::ignore = sodium_init();
        auto state = crypto_generichash_state{};
        if (crypto_generichash_init(&state, nullptr, 0U, crypto_generichash_BYTES) != 0)
        {
            return std::string{"0"};
        }

        auto const update = [&state](std::string_view value) {
            std::ignore =
                crypto_generichash_update(&state, reinterpret_cast<unsigned char const*>(value.data()), value.size());
            auto const separator = static_cast<unsigned char>(0);
            std::ignore = crypto_generichash_update(&state, &separator, 1U);
        };

        update(version);
        for (auto const* session : sessions)
        {
            update(session->room_id);
            update(session->session_id);
            update(session->json);
        }

        auto digest = std::array<unsigned char, crypto_generichash_BYTES>{};
        if (crypto_generichash_final(&state, digest.data(), digest.size()) != 0)
        {
            return std::string{"0"};
        }
        return lowercase_hex(digest.data(), digest.size());
    }

    [[nodiscard]] auto room_keys_update_response(database::PersistentStore const& store, std::string_view user_id,
                                                 std::string_view version) -> std::string
    {
        return json_serialize(json_obj({
            json_member("count", json_int(key_backup_session_count(store, user_id, version))),
            json_member("etag", json_str(key_backup_etag(store, user_id, version))),
            json_member("version", json_str(version)),
        }));
    }

    // Compute the next unique version string for a user's key backup.
    // Finds the highest existing numeric version for this user and returns
    // (max + 1) as a decimal string.  Starts at "1" when none exist.
    [[nodiscard]] auto key_backup_next_version(database::PersistentStore const& store, std::string_view user_id)
        -> std::string
    {
        std::uint64_t max_ver = 0U;
        for (auto const& v : store.key_backup_versions)
        {
            if (v.user_id != user_id)
            {
                continue;
            }
            try
            {
                auto const n = static_cast<std::uint64_t>(std::stoull(v.version));
                if (n > max_ver)
                {
                    max_ver = n;
                }
            }
            catch (...)
            { /* non-numeric version — skip */
            }
        }
        return std::to_string(max_ver + 1U);
    }

    // Extract the value of the `version` query parameter from a request target.
    // Returns an empty string_view if the parameter is absent.
    [[nodiscard]] auto extract_key_backup_version_param(std::string_view target) noexcept -> std::string_view
    {
        auto const query_start = target.find('?');
        if (query_start == std::string_view::npos)
        {
            return {};
        }
        auto query = target.substr(query_start + 1U);
        while (!query.empty())
        {
            auto const amp = query.find('&');
            auto const pair = amp == std::string_view::npos ? query : query.substr(0U, amp);
            auto const eq = pair.find('=');
            if (eq != std::string_view::npos && pair.substr(0U, eq) == "version")
            {
                return pair.substr(eq + 1U);
            }
            if (amp == std::string_view::npos)
            {
                break;
            }
            query = query.substr(amp + 1U);
        }
        return {};
    }

    [[nodiscard]] auto key_backup_metadata_response(database::PersistentStore const& store,
                                                    database::PersistentKeyBackupVersion const& version) -> std::string
    {
        auto metadata = canonicaljson::Object{};
        auto const parsed = canonicaljson::parse_lossless(version.json);
        if (parsed.error == canonicaljson::ParseError::none)
        {
            if (auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage()); object != nullptr)
            {
                metadata = *object;
            }
        }

        set_object_member(metadata, "count",
                          json_int(key_backup_session_count(store, version.user_id, version.version)));
        set_object_member(metadata, "etag", json_str(key_backup_etag(store, version.user_id, version.version)));
        set_object_member(metadata, "version", json_str(version.version));
        return json_serialize(canonicaljson::Value{std::move(metadata)});
    }

    [[nodiscard]] auto key_api_success_body(auth::KeyApiEndpoint endpoint) -> std::string
    {
        switch (endpoint)
        {
        case auth::KeyApiEndpoint::upload_keys:
            return json_serialize(json_obj({json_member("one_time_key_counts", json_obj({}))}));
        case auth::KeyApiEndpoint::query_keys:
            return json_serialize(
                json_obj({json_member("device_keys", json_obj({})), json_member("failures", json_obj({}))}));
        case auth::KeyApiEndpoint::claim_keys:
            return json_serialize(
                json_obj({json_member("one_time_keys", json_obj({})), json_member("failures", json_obj({}))}));
        case auth::KeyApiEndpoint::get_key_backup_version:
            return json_serialize(json_obj({
                json_member("algorithm", json_str("m.megolm_backup.v1")),
                json_member("auth_data", json_obj({})),
                json_member("version", json_str("1")),
            }));
        case auth::KeyApiEndpoint::get_room_key_backup:
            return json_serialize(json_obj({json_member("rooms", json_obj({}))}));
        case auth::KeyApiEndpoint::create_key_backup_version:
            // Spec: POST /room_keys/version MUST return {"version":"<id>"} so
            // clients can reference the backup. Omitting it causes Element to
            // fail key setup with "Unable to set up keys".
            return json_serialize(json_obj({json_member("version", json_str("1"))}));
        case auth::KeyApiEndpoint::upload_signatures:
            return json_serialize(json_obj({json_member("failures", json_obj({}))}));
        case auth::KeyApiEndpoint::device_list_update:
        case auth::KeyApiEndpoint::upload_cross_signing_keys:
        case auth::KeyApiEndpoint::update_key_backup_version:
        case auth::KeyApiEndpoint::delete_key_backup_version:
        case auth::KeyApiEndpoint::put_room_key_backup:
        case auth::KeyApiEndpoint::put_room_key_backup_room:
        case auth::KeyApiEndpoint::delete_room_key_backup_room:
        case auth::KeyApiEndpoint::delete_room_key_backup:
            return "{}";
        case auth::KeyApiEndpoint::put_room_key_backup_batch:
            return json_serialize(json_obj({json_member("version", json_str("1"))}));
        case auth::KeyApiEndpoint::get_key_backup_version_by_id:
        case auth::KeyApiEndpoint::get_room_key_backup_batch:
            return json_serialize(json_obj({json_member("rooms", json_obj({}))}));
        case auth::KeyApiEndpoint::delete_room_key_backup_batch:
            return json_serialize(json_obj({json_member("count", canonicaljson::Value{static_cast<std::int64_t>(0)}),
                                            json_member("etag", json_str("1"))}));
        }
        return "{}";
    }

    auto record_key_api_access(ClientServerRuntime& rt, auth::KeyApiRoute const& route, std::string_view user,
                               std::string_view device_id, std::string_view payload) -> void
    {
        auto const plan = auth::make_key_api_boundary_plan(route, user, device_id);
        rt.key_api_records.push_back({std::string{user}, std::string{device_id},
                                      auth::key_api_endpoint_name(route.endpoint),
                                      auth::redacted_key_payload_summary(payload), plan.database_statements.size()});
        append_local_audit(rt.homeserver.database, observability::AuditCategory::auth, plan.audit_event_type, user,
                           device_id, auth::redacted_key_payload_summary(payload));
    }

    [[nodiscard]] auto one_time_key_count(ClientServerRuntime const& rt, std::string_view user,
                                          std::string_view device_id) noexcept -> std::size_t
    {
        return static_cast<std::size_t>(
            std::ranges::count_if(rt.homeserver.database.persistent_store.one_time_keys,
                                  [user, device_id](database::PersistentOneTimeKey const& key) {
                                      return key.user_id == user && key.device_id == device_id;
                                  }));
    }

    // Holds both the key ID (e.g. "ed25519:DEVICE1") and the base64-encoded
    // public key bytes for a device's own Ed25519 signing key, extracted from
    // a parsed `device_keys` object. Both fields are empty when absent.
    struct DeviceSigningKeyInfo final
    {
        std::string key_id{};
        std::string public_key_b64{};
    };

    // Extract the device's own ed25519 key id AND public key (base64) from a
    // parsed `device_keys` object. The Matrix v1.18 spec requires the device
    // to publish a `keys` map whose ed25519 member is the device's own
    // identity key; every SignedKey (OTK, fallback key) MUST be signed by it.
    // Returns empty strings when the object has no ed25519 member; the caller
    // treats that as "no identity known" and skips the OTK signature check so
    // the device's first /keys/upload still succeeds.
    [[nodiscard]] auto device_signing_key_info_from_device_keys_object(canonicaljson::Object const& device_keys_object)
        -> DeviceSigningKeyInfo
    {
        auto const* keys_map = object_member_as_object(device_keys_object, "keys");
        if (keys_map == nullptr)
        {
            return {};
        }
        for (auto const& member : *keys_map)
        {
            if (member.value == nullptr)
            {
                continue;
            }
            if (member.key.size() > 8U && member.key.substr(0U, 8U) == "ed25519:")
            {
                auto const* val_str = std::get_if<std::string>(&member.value->storage());
                return {member.key, val_str != nullptr ? *val_str : std::string{}};
            }
        }
        return {};
    }

    // Resolve the device's ed25519 signing key info (key ID + base64 public key),
    // preferring the in-body `device_keys` (so the very same /keys/upload that
    // publishes the identity is honored) and falling back to the persisted
    // device_keys row. Returns empty fields if neither source yields an identity.
    [[nodiscard]] auto device_signing_key_info_for_upload(database::PersistentStore const& store, std::string_view user,
                                                          std::string_view device_id,
                                                          canonicaljson::Object const* const in_body_device_keys)
        -> DeviceSigningKeyInfo
    {
        if (in_body_device_keys != nullptr)
        {
            auto const from_body = device_signing_key_info_from_device_keys_object(*in_body_device_keys);
            if (!from_body.key_id.empty())
            {
                return from_body;
            }
        }
        auto const existing = database::find_device_key(store, user, device_id);
        if (!existing.has_value())
        {
            return {};
        }
        auto const parsed = parsed_json_object(existing->json);
        if (!parsed.has_value())
        {
            return {};
        }
        return device_signing_key_info_from_device_keys_object(*parsed);
    }

    // Return true when `key_value` is a well-formed SignedKey that carries a
    // cryptographically valid Ed25519 signature under `signing_key_id`, verified
    // against `ed25519_public_key_b64` (the device's own identity key in Matrix
    // unpadded base64). The signed payload is the canonical JSON of the key
    // object with the `signatures` field removed.
    //
    // An empty `signing_key_id` means no device identity is available; the spec
    // requires all signed_curve25519 keys to be signed, so we reject them.
    [[nodiscard]] auto key_object_is_signed_by(canonicaljson::Value const& key_value, std::string_view signing_key_id,
                                               std::string_view ed25519_public_key_b64) -> bool
    {
        if (signing_key_id.empty())
        {
            return false;
        }
        auto const* key_obj = std::get_if<canonicaljson::Object>(&key_value.storage());
        if (key_obj == nullptr)
        {
            return false;
        }
        auto const* signatures = object_member_as_object(*key_obj, "signatures");
        if (signatures == nullptr || signatures->empty())
        {
            return false;
        }

        // Find the signature bytes for the correct key ID.
        std::string_view sig_b64{};
        for (auto const& user_member : *signatures)
        {
            if (user_member.value == nullptr)
            {
                continue;
            }
            auto const* key_sigs = std::get_if<canonicaljson::Object>(&user_member.value->storage());
            if (key_sigs == nullptr)
            {
                continue;
            }
            for (auto const& key_member : *key_sigs)
            {
                if (key_member.key == signing_key_id && key_member.value != nullptr)
                {
                    auto const* sig_str = std::get_if<std::string>(&key_member.value->storage());
                    if (sig_str != nullptr)
                    {
                        sig_b64 = *sig_str;
                    }
                    break;
                }
            }
            if (!sig_b64.empty())
            {
                break;
            }
        }
        if (sig_b64.empty())
        {
            return false;
        }

        // Decode the signature bytes and validate length.
        auto const sig_bytes = events::matrix_bytes_from_base64(sig_b64);
        if (sig_bytes.size() != crypto_sign_BYTES)
        {
            return false;
        }

        // Decode the device's Ed25519 public key and validate length.
        auto const pubkey_bytes = events::matrix_bytes_from_base64(ed25519_public_key_b64);
        if (pubkey_bytes.size() != crypto_sign_PUBLICKEYBYTES)
        {
            return false;
        }

        // Build the signable payload: canonical JSON of the key object minus
        // the `signatures` field (same convention as event signing).
        auto stripped = canonicaljson::Object{};
        stripped.reserve(key_obj->size());
        for (auto const& m : *key_obj)
        {
            if (m.key != "signatures" && m.value != nullptr)
            {
                stripped.push_back(canonicaljson::make_member(m.key, *m.value));
            }
        }
        auto const payload_value = canonicaljson::Value{std::move(stripped)};
        auto const serialized = canonicaljson::serialize_canonical(payload_value);
        if (serialized.error != canonicaljson::CanonicalJsonError::none)
        {
            return false;
        }

        return crypto_sign_verify_detached(reinterpret_cast<unsigned char const*>(sig_bytes.data()),
                                           reinterpret_cast<unsigned char const*>(serialized.output.data()),
                                           serialized.output.size(),
                                           reinterpret_cast<unsigned char const*>(pubkey_bytes.data())) == 0;
    }

    // Validate that every member of an OTK or fallback-key object is a
    // SignedKey carrying a cryptographically valid signature from the device's
    // own ed25519 identity key.
    // Returns the empty string when every key is valid, or a short reason
    // identifying the first invalid member when at least one fails.
    [[nodiscard]] auto validate_key_object_members(canonicaljson::Object const& object, std::string_view signing_key_id,
                                                   std::string_view ed25519_public_key_b64) -> std::string
    {
        for (auto const& member : object)
        {
            if (member.value == nullptr)
            {
                return std::string{member.key} + ": null value";
            }
            // Only signed_* key types (e.g. signed_curve25519) carry a device signature.
            // Plain curve25519 keys are unsigned and require no verification.
            if (member.key.starts_with("signed_") &&
                !key_object_is_signed_by(*member.value, signing_key_id, ed25519_public_key_b64))
            {
                return std::string{member.key} + ": not signed by device identity";
            }
        }
        return {};
    }

    [[nodiscard]] auto store_key_object_members(ClientServerRuntime& rt, std::string_view user,
                                                std::string_view device_id, canonicaljson::Object const& object,
                                                bool fallback) -> bool
    {
        for (auto const& member : object)
        {
            if (member.value == nullptr)
            {
                return false;
            }
            auto const payload = serialized_value(*member.value);
            if (!payload.has_value())
            {
                return false;
            }
            auto& store = rt.homeserver.database.persistent_store;
            auto const ok = fallback ? database::store_fallback_key(
                                           store, {std::string{user}, std::string{device_id}, member.key, *payload})
                                     : database::store_one_time_key(
                                           store, {std::string{user}, std::string{device_id}, member.key, *payload});
            if (!ok)
            {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] auto validate_device_keys_object(canonicaljson::Object const& object,
                                                   std::string_view authenticated_user,
                                                   std::string_view authenticated_device_id) -> std::string
    {
        auto const* user_id = string_member(object, "user_id");
        if (user_id == nullptr || *user_id != authenticated_user)
        {
            return "device_keys.user_id must match the authenticated user";
        }
        auto const* device_id = string_member(object, "device_id");
        if (device_id == nullptr || *device_id != authenticated_device_id)
        {
            return "device_keys.device_id must match the authenticated device";
        }
        auto const* keys = object_member_as_object(object, "keys");
        if (keys == nullptr)
        {
            return "device_keys.keys must be a JSON object";
        }
        auto const curve_key = string_member(*keys, "curve25519:" + std::string{authenticated_device_id});
        if (curve_key == nullptr || curve_key->empty())
        {
            return "device_keys.keys must contain curve25519:<device_id>";
        }
        auto const ed_key = string_member(*keys, "ed25519:" + std::string{authenticated_device_id});
        if (ed_key == nullptr || ed_key->empty())
        {
            return "device_keys.keys must contain ed25519:<device_id>";
        }
        return {};
    }

    [[nodiscard]] auto handle_key_upload(ClientServerRuntime& rt, std::string_view user, std::string_view device_id,
                                         std::string_view body) -> LocalHttpResponse
    {
        auto const object = parsed_json_object(body);
        if (!object.has_value())
        {
            return err(400U, "M_BAD_JSON", "key upload body must be Matrix JSON");
        }
        auto& store = rt.homeserver.database.persistent_store;
        auto const* raw_device_keys = object_member(*object, "device_keys");
        auto const* device_keys_object = object_member_as_object(*object, "device_keys");
        if (raw_device_keys != nullptr && device_keys_object == nullptr)
        {
            return err(400U, "M_BAD_JSON", "device_keys must be a JSON object");
        }
        if (device_keys_object != nullptr)
        {
            if (auto const reason = validate_device_keys_object(*device_keys_object, user, device_id); !reason.empty())
            {
                return err(400U, "M_INVALID_PARAM", reason);
            }
            auto normalized_device_keys = *device_keys_object;
            normalize_device_key_object_for_client(rt, normalized_device_keys, user, device_id);
            auto const serialized =
                canonicaljson::serialize_canonical(canonicaljson::Value{std::move(normalized_device_keys)});
            if (serialized.error != canonicaljson::CanonicalJsonError::none ||
                !database::store_device_key(store, {std::string{user}, std::string{device_id}, serialized.output}))
            {
                return err(500U, "M_UNKNOWN", "device key persistence failed");
            }
        }
        // Device key uploads change the device identity that other users
        // track; notify every user who shares a room with this user.
        if (device_keys_object != nullptr)
        {
            for (auto const& room : rt.homeserver.database.rooms)
            {
                auto const is_member = std::ranges::any_of(room.members, [user](auto const& m) {
                    return m == user;
                });
                if (!is_member)
                {
                    continue;
                }
                for (auto const& member : room.members)
                {
                    if (member == user)
                    {
                        continue;
                    }
                    auto const change = database::PersistentDeviceListChange{0U, member, std::string{user}, "changed"};
                    std::ignore = record_device_list_change(rt, change);
                }
            }
            // Notify remote servers so they can fetch the updated keys and
            // deliver room keys to this device (spec v1.18 SS4.1).
            broadcast_device_list_updates(rt, user, remote_servers_for_user(rt.homeserver, user));
        }
        // Reject any one-time / fallback key that is not signed by the
        // device's own ed25519 identity. The Matrix v1.18 spec requires
        // every SignedKey to be signed by the device's signing key; an
        // unverifiable key is useless to a peer (it will fail
        // NoSignatureFound at /keys/claim time, blocking the Olm session
        // for the whole room's Megolm distribution) and must not be
        // persisted. The device's signing key id is resolved from the
        // in-body device_keys first, then the persisted device_keys row.
        // When neither is known, the OTK is accepted (the device's very
        // first /keys/upload can't be checked against a prior identity).
        auto const* in_body_device_keys = object_member_object(*object, "device_keys");
        // Resolve both the key ID and the base64 public key so that
        // key_object_is_signed_by can perform real Ed25519 verification.
        auto const signing_info = device_signing_key_info_for_upload(store, user, device_id, in_body_device_keys);
        auto const& device_signing_key_id = signing_info.key_id;
        auto const& device_signing_pubkey = signing_info.public_key_b64;
        if (auto const* keys = object_member_object(*object, "one_time_keys"); keys != nullptr)
        {
            if (auto const reason = validate_key_object_members(*keys, device_signing_key_id, device_signing_pubkey);
                !reason.empty())
            {
                return err(400U, "M_INVALID_SIGNATURE",
                           "one-time key " + reason + " (device signing key " + device_signing_key_id + ")");
            }
            if (!store_key_object_members(rt, user, device_id, *keys, false))
            {
                return err(500U, "M_UNKNOWN", "one-time key persistence failed");
            }
        }
        if (auto const* keys = object_member_object(*object, "fallback_keys"); keys != nullptr)
        {
            if (auto const reason = validate_key_object_members(*keys, device_signing_key_id, device_signing_pubkey);
                !reason.empty())
            {
                return err(400U, "M_INVALID_SIGNATURE",
                           "fallback key " + reason + " (device signing key " + device_signing_key_id + ")");
            }
            if (!store_key_object_members(rt, user, device_id, *keys, true))
            {
                return err(500U, "M_UNKNOWN", "fallback key persistence failed");
            }
        }
        return resp(200U,
                    json_serialize(json_obj({
                        json_member("one_time_key_counts",
                                    json_obj({
                                        json_member("signed_curve25519", json_int(static_cast<std::int64_t>(
                                                                             one_time_key_count(rt, user, device_id)))),
                                    })),
                    })));
    }

    [[nodiscard]] auto handle_key_query(ClientServerRuntime& rt, std::string_view requesting_user,
                                        std::string_view body) -> LocalHttpResponse
    {
        auto const object = parsed_json_object(body);
        if (!object.has_value())
        {
            return err(400U, "M_BAD_JSON", "key query body must be Matrix JSON");
        }
        auto const* requests = object_member_object(*object, "device_keys");
        if (requests == nullptr)
        {
            return err(400U, "M_BAD_JSON", "key query body must contain device_keys");
        }

        auto const& local_server = rt.homeserver.config.server().server_name;
        auto const& store = rt.homeserver.database.persistent_store;

        // remote_by_server accumulates remote user IDs grouped by their home
        // server so we can make a single federation key query per server.
        auto remote_by_server = std::map<std::string, std::vector<std::string>>{};

        auto users = canonicaljson::Object{};
        for (auto const& user_request : *requests)
        {
            auto const* requested_devices = std::get_if<canonicaljson::Array>(&user_request.value->storage());
            if (requested_devices == nullptr)
            {
                return err(400U, "M_BAD_JSON", "device_keys values must be device ID arrays");
            }

            // Remote users are proxied via federation key query.
            auto const colon = user_request.key.rfind(':');
            auto const user_server = colon != std::string::npos ? user_request.key.substr(colon + 1U) : std::string{};
            if (!user_server.empty() && user_server != local_server)
            {
                remote_by_server[user_server].push_back(user_request.key);
                continue;
            }

            auto devices = canonicaljson::Object{};
            if (requested_devices->empty())
            {
                for (auto const& key : store.device_keys)
                {
                    if (key.user_id == user_request.key)
                    {
                        auto value = parsed_json_object(key.json);
                        if (!value.has_value())
                        {
                            continue;
                        }
                        auto device_object = *value;
                        merge_uploaded_signatures(device_object, store, user_request.key, key.device_id);
                        normalize_device_key_object_for_client(rt, device_object, user_request.key, key.device_id);
                        devices.push_back(json_member(key.device_id, json_obj(std::move(device_object))));
                    }
                }
            }
            else
            {
                for (auto const& requested_device : *requested_devices)
                {
                    auto const* requested_device_id = std::get_if<std::string>(&requested_device.storage());
                    if (requested_device_id == nullptr)
                    {
                        return err(400U, "M_BAD_JSON", "device_keys entries must be device IDs");
                    }
                    auto const key = database::find_device_key(store, user_request.key, *requested_device_id);
                    if (key.has_value())
                    {
                        auto value = parsed_json_object(key->json);
                        if (!value.has_value())
                        {
                            continue;
                        }
                        auto device_object = *value;
                        merge_uploaded_signatures(device_object, store, user_request.key, *requested_device_id);
                        normalize_device_key_object_for_client(rt, device_object, user_request.key,
                                                               *requested_device_id);
                        devices.push_back(json_member(*requested_device_id, json_obj(std::move(device_object))));
                    }
                }
            }
            users.push_back(json_member(user_request.key, json_obj(std::move(devices))));
        }
        // Collect cross-signing keys per user for the queried users.
        auto master_keys = canonicaljson::Object{};
        auto self_signing_keys = canonicaljson::Object{};
        auto user_signing_keys = canonicaljson::Object{};
        for (auto const& user_request : *requests)
        {
            for (auto const& cskey : store.cross_signing_keys)
            {
                if (cskey.user_id != user_request.key)
                {
                    continue;
                }
                if (cskey.key_type == "master")
                {
                    auto value = parsed_json_object(cskey.json);
                    if (!value.has_value())
                    {
                        continue;
                    }
                    auto key_object = *value;
                    if (auto const key_id = first_key_id_in_key_object(key_object); key_id.has_value())
                    {
                        merge_uploaded_signatures(key_object, store, user_request.key, *key_id);
                    }
                    master_keys.push_back(json_member(user_request.key, json_obj(std::move(key_object))));
                }
                else if (cskey.key_type == "self_signing")
                {
                    auto value = parsed_json_object(cskey.json);
                    if (!value.has_value())
                    {
                        continue;
                    }
                    auto key_object = *value;
                    if (auto const key_id = first_key_id_in_key_object(key_object); key_id.has_value())
                    {
                        merge_uploaded_signatures(key_object, store, user_request.key, *key_id);
                    }
                    self_signing_keys.push_back(json_member(user_request.key, json_obj(std::move(key_object))));
                }
                // Spec §11.11.3: user_signing_key MUST only be returned to the user themselves.
                else if (cskey.key_type == "user_signing" && user_request.key == requesting_user)
                {
                    auto value = parsed_json_object(cskey.json);
                    if (!value.has_value())
                    {
                        continue;
                    }
                    auto key_object = *value;
                    if (auto const key_id = first_key_id_in_key_object(key_object); key_id.has_value())
                    {
                        merge_uploaded_signatures(key_object, store, user_request.key, *key_id);
                    }
                    user_signing_keys.push_back(json_member(user_request.key, json_obj(std::move(key_object))));
                }
            }
        }

        // Federation proxy: POST /_matrix/federation/v1/user/keys/query for
        // each remote server. Unreachable servers appear in the failures object.
        auto failures = canonicaljson::Object{};
        if (!remote_by_server.empty())
        {
            wire_federation_callbacks(rt.homeserver);
            auto const signing_key = ensure_runtime_server_signing_key(rt.homeserver);
            auto const key_id = signing_key.has_value() ? signing_key->key_id : std::string{};
            auto const secret =
                std::string{reinterpret_cast<char const*>(rt.homeserver.database.signing_secret_key.bytes().data()),
                            rt.homeserver.database.signing_secret_key.bytes().size()};
            for (auto const& [server, uid_list] : remote_by_server)
            {
                auto remote_dk = canonicaljson::Object{};
                for (auto const& uid : uid_list)
                {
                    remote_dk.push_back(json_member(uid, json_arr(canonicaljson::Array{})));
                }
                auto q_body_obj = canonicaljson::Object{};
                q_body_obj.push_back(json_member("device_keys", json_obj(std::move(remote_dk))));
                auto const q_body = json_serialize(json_obj(std::move(q_body_obj)));
                auto const tx = federation::make_outbound_transaction(
                    server, "POST", "/_matrix/federation/v1/user/keys/query", local_server, q_body);
                auto const [ok, resp_body] = perform_sync_outbound_call(rt.homeserver.outbound_client.get(),
                                                                        rt.homeserver.discovery_network.get(), tx,
                                                                        key_id, secret, "key_query.remote");
                if (ok)
                {
                    auto const parsed = canonicaljson::parse_lossless(resp_body);
                    if (parsed.error == canonicaljson::ParseError::none)
                    {
                        auto const* robj = std::get_if<canonicaljson::Object>(&parsed.value.storage());
                        if (robj != nullptr)
                        {
                            if (auto const* rdk = object_member_as_object(*robj, "device_keys"))
                            {
                                for (auto const& ue : *rdk)
                                {
                                    if (auto const* dm = std::get_if<canonicaljson::Object>(&ue.value->storage()))
                                    {
                                        users.push_back(json_member(ue.key, json_obj(*dm)));
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    failures.push_back(json_member(server, json_obj({
                                                               json_member("errcode", json_str("M_UNKNOWN")),
                                                               json_member("error", json_str(resp_body)),
                                                           })));
                }
            }
        }

        auto response = canonicaljson::Object{};
        response.push_back(json_member("device_keys", json_obj(std::move(users))));
        if (!master_keys.empty())
        {
            response.push_back(json_member("master_keys", json_obj(std::move(master_keys))));
        }
        if (!self_signing_keys.empty())
        {
            response.push_back(json_member("self_signing_keys", json_obj(std::move(self_signing_keys))));
        }
        if (!user_signing_keys.empty())
        {
            response.push_back(json_member("user_signing_keys", json_obj(std::move(user_signing_keys))));
        }
        response.push_back(json_member("failures", json_obj(std::move(failures))));
        return resp(200U, json_serialize(json_obj(std::move(response))));
    }

    [[nodiscard]] auto handle_key_claim(ClientServerRuntime& rt, std::string_view body) -> LocalHttpResponse
    {
        auto const object = parsed_json_object(body);
        if (!object.has_value())
        {
            return err(400U, "M_BAD_JSON", "key claim body must be Matrix JSON");
        }
        auto const* requests = object_member_object(*object, "one_time_keys");
        if (requests == nullptr)
        {
            return err(400U, "M_BAD_JSON", "key claim body must contain one_time_keys");
        }

        auto const& local_server = rt.homeserver.config.server().server_name;
        auto& store = rt.homeserver.database.persistent_store;

        // remote_by_server accumulates the raw claim requests grouped by server
        // so a single federation call is made per destination.
        auto remote_by_server = std::map<std::string, canonicaljson::Object>{};

        auto users = canonicaljson::Object{};
        for (auto const& user_request : *requests)
        {
            auto const* requested_devices = std::get_if<canonicaljson::Object>(&user_request.value->storage());
            if (requested_devices == nullptr)
            {
                return err(400U, "M_BAD_JSON", "one_time_keys values must be device maps");
            }

            // Route remote users to their home server.
            auto const colon = user_request.key.rfind(':');
            auto const user_server = colon != std::string::npos ? user_request.key.substr(colon + 1U) : std::string{};
            if (!user_server.empty() && user_server != local_server)
            {
                // Copy the device→algorithm map for the remote request.
                auto device_alg_copy = canonicaljson::Object{};
                for (auto const& de : *requested_devices)
                {
                    if (auto const* alg = std::get_if<std::string>(&de.value->storage()))
                    {
                        device_alg_copy.push_back(json_member(de.key, json_str(*alg)));
                    }
                }
                remote_by_server[user_server].push_back(
                    json_member(user_request.key, json_obj(std::move(device_alg_copy))));
                continue;
            }

            auto devices = canonicaljson::Object{};
            for (auto const& device_request : *requested_devices)
            {
                auto const* algorithm = std::get_if<std::string>(&device_request.value->storage());
                if (algorithm == nullptr || algorithm->empty())
                {
                    return err(400U, "M_BAD_JSON", "one_time_keys entries must name a key algorithm");
                }
                auto keys = canonicaljson::Object{};
                auto claimed = database::claim_one_time_key(store, user_request.key, device_request.key, *algorithm);
                if (claimed.has_value())
                {
                    keys.push_back(json_member(claimed->key_id, json_embed_raw(claimed->json)));
                }
                else
                {
                    auto const fallback =
                        database::find_fallback_key(store, user_request.key, device_request.key, *algorithm);
                    if (fallback.has_value())
                    {
                        keys.push_back(json_member(fallback->key_id, json_embed_raw(fallback->json)));
                    }
                }
                if (!keys.empty())
                {
                    devices.push_back(json_member(device_request.key, json_obj(std::move(keys))));
                }
            }
            if (!devices.empty())
            {
                users.push_back(json_member(user_request.key, json_obj(std::move(devices))));
            }
        }

        // Federation proxy: POST /_matrix/federation/v1/user/keys/claim for
        // each remote server.
        auto failures = canonicaljson::Object{};
        if (!remote_by_server.empty())
        {
            wire_federation_callbacks(rt.homeserver);
            auto const signing_key = ensure_runtime_server_signing_key(rt.homeserver);
            auto const key_id = signing_key.has_value() ? signing_key->key_id : std::string{};
            auto const secret =
                std::string{reinterpret_cast<char const*>(rt.homeserver.database.signing_secret_key.bytes().data()),
                            rt.homeserver.database.signing_secret_key.bytes().size()};
            for (auto& [server, user_claims] : remote_by_server)
            {
                auto claim_body_obj = canonicaljson::Object{};
                claim_body_obj.push_back(json_member("one_time_keys", json_obj(std::move(user_claims))));
                auto const claim_body = json_serialize(json_obj(std::move(claim_body_obj)));
                auto const tx = federation::make_outbound_transaction(
                    server, "POST", "/_matrix/federation/v1/user/keys/claim", local_server, claim_body);
                auto const [ok, resp_body] = perform_sync_outbound_call(rt.homeserver.outbound_client.get(),
                                                                        rt.homeserver.discovery_network.get(), tx,
                                                                        key_id, secret, "key_claim.remote");
                if (ok)
                {
                    auto const parsed = canonicaljson::parse_lossless(resp_body);
                    if (parsed.error == canonicaljson::ParseError::none)
                    {
                        auto const* robj = std::get_if<canonicaljson::Object>(&parsed.value.storage());
                        if (robj != nullptr)
                        {
                            if (auto const* rotk = object_member_as_object(*robj, "one_time_keys"))
                            {
                                for (auto const& ue : *rotk)
                                {
                                    if (auto const* dm = std::get_if<canonicaljson::Object>(&ue.value->storage()))
                                    {
                                        users.push_back(json_member(ue.key, json_obj(*dm)));
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    failures.push_back(json_member(server, json_obj({
                                                               json_member("errcode", json_str("M_UNKNOWN")),
                                                               json_member("error", json_str(resp_body)),
                                                           })));
                }
            }
        }

        return resp(200U, json_serialize(json_obj({
                              json_member("one_time_keys", json_obj(std::move(users))),
                              json_member("failures", json_obj(std::move(failures))),
                          })));
    }

    // PUT /_matrix/client/v3/sendToDevice/{eventType}/{txnId}
    // Parses the event type and client txnId from the path so the same token
    // can be preserved in the outbound federation EDU message_id.
    [[nodiscard]] auto send_to_device_path_parts(std::string_view target) -> std::optional<SendToDevicePathParts>
    {
        auto constexpr prefix = std::string_view{"/_matrix/client/v3/sendToDevice/"};
        if (!starts_with(target, prefix))
        {
            return std::nullopt;
        }
        auto const rest = target.substr(prefix.size());
        // Expect: {eventType}/{txnId}
        auto const slash = rest.find('/');
        if (slash == std::string_view::npos || slash == 0U)
        {
            return std::nullopt;
        }
        auto const event_type = rest.substr(0U, slash);
        auto const txn_id = rest.substr(slash + 1U);
        if (event_type.empty() || txn_id.empty() || txn_id.find('/') != std::string_view::npos)
        {
            return std::nullopt;
        }
        return SendToDevicePathParts{core::percent_decode_path_component(event_type),
                                     core::percent_decode_path_component(txn_id)};
    }

    // Deliver a to-device message to every named target user/device pair.
    // Local targets are enqueued directly for /sync delivery. Remote targets
    // are grouped by destination server and sent as m.direct_to_device EDUs
    // via the federation dispatch worker.
    [[nodiscard]] auto handle_send_to_device(ClientServerRuntime& rt, std::string_view event_type,
                                             std::string_view txn_id, std::string_view sender, std::string_view body)
        -> LocalHttpResponse
    {
        // CS API §10.5.1: idempotent send — replay {} for a seen txn_id.
        // room_id is empty ("") as sentinel for to-device entries.
        if (database::find_client_txn_event_id(rt.homeserver.database.persistent_store, sender, "", event_type, txn_id)
                .has_value())
        {
            return resp(200U, "{}");
        }
        auto const object = parsed_json_object(body);
        if (!object.has_value())
        {
            return err(400U, "M_BAD_JSON", "sendToDevice body must be a JSON object");
        }
        auto const* messages = object_member_object(*object, "messages");
        if (messages == nullptr)
        {
            return err(400U, "M_BAD_JSON", "sendToDevice body must contain a messages object");
        }

        auto const& local_server = rt.homeserver.config.server().server_name;

        // remote_messages: server → { user_id → { device_id → content_json } }
        auto remote_messages = std::map<std::string, std::map<std::string, std::map<std::string, std::string>>>{};

        for (auto const& user_entry : *messages)
        {
            auto const* device_map = std::get_if<canonicaljson::Object>(&user_entry.value->storage());
            if (device_map == nullptr)
            {
                continue;
            }
            auto const colon = user_entry.key.rfind(':');
            auto const user_server = colon != std::string::npos ? user_entry.key.substr(colon + 1U) : std::string{};
            auto const is_local = user_server.empty() || user_server == local_server;

            for (auto const& device_entry : *device_map)
            {
                if (device_entry.value == nullptr)
                {
                    continue;
                }
                auto const content = serialized_value(*device_entry.value);
                if (!content.has_value())
                {
                    continue;
                }
                if (is_local)
                {
                    if (device_entry.key == "*")
                    {
                        // Spec §10.5: "*" delivers to all devices of the target user.
                        for (auto const& dev : rt.homeserver.database.persistent_store.devices)
                        {
                            if (dev.user_id == user_entry.key)
                            {
                                std::ignore =
                                    push_to_device_message(rt, {0U, std::string{sender}, user_entry.key, dev.device_id,
                                                                std::string{event_type}, *content});
                            }
                        }
                    }
                    else
                    {
                        // Enqueue directly; /sync drains it into to_device.events.
                        std::ignore = push_to_device_message(rt, {0U, std::string{sender}, user_entry.key,
                                                                  device_entry.key, std::string{event_type}, *content});
                    }
                }
                else
                {
                    remote_messages[user_server][user_entry.key][device_entry.key] = *content;
                }
            }
        }

        // Send m.direct_to_device EDUs to remote servers.
        if (!remote_messages.empty())
        {
            for (auto& [server, user_map] : remote_messages)
            {
                auto messages_obj = canonicaljson::Object{};
                for (auto& [uid, device_map2] : user_map)
                {
                    auto devices_obj = canonicaljson::Object{};
                    for (auto& [device_id, content_json] : device_map2)
                    {
                        devices_obj.push_back(json_member(device_id, json_embed_raw(content_json)));
                    }
                    messages_obj.push_back(json_member(uid, json_obj(std::move(devices_obj))));
                }
                auto edu_content = canonicaljson::Object{};
                edu_content.push_back(json_member("message_id", json_str(std::string{txn_id})));
                edu_content.push_back(json_member("sender", json_str(std::string{sender})));
                edu_content.push_back(json_member("type", json_str(std::string{event_type})));
                edu_content.push_back(json_member("messages", json_obj(std::move(messages_obj))));
                auto const edu_body = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(edu_content)});
                if (edu_body.error == canonicaljson::CanonicalJsonError::none)
                {
                    std::ignore = dispatch_edu_to_server(rt.homeserver, server, "m.direct_to_device", edu_body.output);
                }
            }
        }

        // Record this txn_id so retries receive the same empty response.
        std::ignore =
            database::store_client_txn(rt.homeserver.database.persistent_store,
                                       {std::string{sender}, "", std::string{event_type}, std::string{txn_id}, ""});
        return resp(200U, "{}");
    }

    // GET /_matrix/client/v3/keys/changes?from={from}&to={to}
    // Returns users whose device lists changed between the two sync stream
    // positions. Clients use this to avoid re-querying /keys/query on every
    // /sync; Element requests it on initial load to detect stale key caches.
    [[nodiscard]] auto handle_keys_changes(ClientServerRuntime const& rt, std::string_view user,
                                           std::string_view target) -> LocalHttpResponse
    {
        // Parse the `from` sync token (may be "s{N}" or plain integer).
        auto const query_start = target.find('?');
        auto const query = query_start != std::string_view::npos ? target.substr(query_start + 1U) : std::string_view{};
        auto const parse_qparam = [&query](std::string_view key) -> std::string_view {
            auto const search = std::string{key} + "=";
            auto const pos = query.find(search);
            if (pos == std::string_view::npos)
            {
                return {};
            }
            auto const val_start = pos + search.size();
            auto const val_end = query.find('&', val_start);
            return val_end == std::string_view::npos ? query.substr(val_start)
                                                     : query.substr(val_start, val_end - val_start);
        };
        auto const raw_from = parse_qparam("from");
        // The `from` parameter is a /sync next_batch token that encodes
        // event_ordering, membership_ordering, and sync_stream_id as three
        // underscore-separated hex components.  We want the sync_stream_id
        // component because device-list changes are tracked by that counter.
        // Fall back to 0 (return all changes) if the token cannot be decoded.
        std::uint64_t from_id = 0U;
        if (auto const decoded = sync::decode_stream_token(raw_from); decoded.has_value())
        {
            from_id = decoded->sync_stream_id;
        }

        auto const& store = rt.homeserver.database.persistent_store;
        auto changed = canonicaljson::Array{};
        auto left = canonicaljson::Array{};
        for (auto const& change : store.device_list_changes)
        {
            if (change.observer_user_id != user || change.stream_id <= from_id)
            {
                continue;
            }
            auto& bucket = (change.change_type == "left") ? left : changed;
            bucket.push_back(canonicaljson::Value{change.subject_user_id});
        }
        return resp(200U, json_serialize(json_obj({
                              json_member("changed", json_arr(std::move(changed))),
                              json_member("left", json_arr(std::move(left))),
                          })));
    }

    [[nodiscard]] auto route_suffix(std::string_view target, std::string_view prefix) noexcept -> std::string_view
    {
        return starts_with(target, prefix) ? target.substr(prefix.size()) : std::string_view{};
    }

    [[nodiscard]] auto parse_query_bool(std::optional<std::string> const& value) -> std::optional<bool>
    {
        if (!value.has_value())
        {
            return std::nullopt;
        }
        if (*value == "true")
        {
            return true;
        }
        if (*value == "false")
        {
            return false;
        }
        return std::nullopt;
    }

    [[nodiscard]] auto parse_query_uint(std::optional<std::string> const& value) -> std::optional<std::uint64_t>
    {
        if (!value.has_value() || value->empty())
        {
            return std::nullopt;
        }
        auto result = std::uint64_t{0U};
        auto const [ptr, error] = std::from_chars(value->data(), value->data() + value->size(), result);
        if (error == std::errc{} && ptr == value->data() + value->size())
        {
            return result;
        }
        return std::nullopt;
    }

    [[nodiscard]] auto room_send_path_parts(std::string_view target) -> std::optional<RoomSendPathParts>
    {
        auto constexpr prefix = std::string_view{"/_matrix/client/v3/rooms/"};
        auto constexpr marker = std::string_view{"/send/"};
        auto const suffix = route_suffix(target, prefix);
        auto const marker_pos = suffix.find(marker);
        if (suffix.empty() || marker_pos == std::string_view::npos || marker_pos == 0U ||
            marker_pos + marker.size() >= suffix.size())
        {
            return std::nullopt;
        }
        auto const event_and_txn = suffix.substr(marker_pos + marker.size());
        auto const separator = event_and_txn.find('/');
        if (separator == std::string_view::npos || separator == 0U || separator + 1U >= event_and_txn.size())
        {
            return std::nullopt;
        }
        return RoomSendPathParts{core::percent_decode_path_component(suffix.substr(0U, marker_pos)),
                                 core::percent_decode_path_component(event_and_txn.substr(0U, separator)),
                                 core::percent_decode_path_component(event_and_txn.substr(separator + 1U))};
    }

    [[nodiscard]] auto room_state_path_parts(std::string_view target) -> std::optional<RoomStatePathParts>
    {
        auto constexpr prefix = std::string_view{"/_matrix/client/v3/rooms/"};
        auto constexpr marker = std::string_view{"/state/"};
        auto const suffix = route_suffix(target, prefix);
        auto const marker_pos = suffix.find(marker);
        if (suffix.empty() || marker_pos == std::string_view::npos || marker_pos == 0U ||
            marker_pos + marker.size() > suffix.size())
        {
            return std::nullopt;
        }
        auto const event_and_state = suffix.substr(marker_pos + marker.size());
        if (event_and_state.empty())
        {
            return std::nullopt;
        }
        auto const separator = event_and_state.find('/');
        auto const event_type =
            separator == std::string_view::npos ? event_and_state : event_and_state.substr(0U, separator);
        auto const state_key =
            separator == std::string_view::npos ? std::string_view{} : event_and_state.substr(separator + 1U);
        if (event_type.empty())
        {
            return std::nullopt;
        }
        return RoomStatePathParts{core::percent_decode_path_component(suffix.substr(0U, marker_pos)),
                                  core::percent_decode_path_component(event_type),
                                  core::percent_decode_path_component(state_key)};
    }

    [[nodiscard]] auto room_event_path_parts(std::string_view target) -> std::optional<RoomEventPathParts>
    {
        auto constexpr prefix = std::string_view{"/_matrix/client/v3/rooms/"};
        auto constexpr marker = std::string_view{"/event/"};
        auto const path = target.substr(0U, target.find('?'));
        auto const suffix = route_suffix(path, prefix);
        auto const marker_pos = suffix.find(marker);
        if (suffix.empty() || marker_pos == std::string_view::npos || marker_pos == 0U ||
            marker_pos + marker.size() >= suffix.size())
        {
            return std::nullopt;
        }
        auto const event_id = suffix.substr(marker_pos + marker.size());
        if (event_id.empty() || event_id.find('/') != std::string_view::npos)
        {
            return std::nullopt;
        }
        return RoomEventPathParts{core::percent_decode_path_component(suffix.substr(0U, marker_pos)),
                                  core::percent_decode_path_component(event_id)};
    }

    [[nodiscard]] auto room_relations_path_parts(std::string_view target) -> std::optional<RoomRelationsPathParts>
    {
        auto constexpr prefix = std::string_view{"/_matrix/client/v1/rooms/"};
        auto constexpr marker = std::string_view{"/relations/"};
        auto const path = target.substr(0U, target.find('?'));
        auto const suffix = route_suffix(path, prefix);
        auto const marker_pos = suffix.find(marker);
        if (suffix.empty() || marker_pos == std::string_view::npos || marker_pos == 0U ||
            marker_pos + marker.size() >= suffix.size())
        {
            return std::nullopt;
        }

        auto const remainder = suffix.substr(marker_pos + marker.size());
        if (remainder.empty() || remainder[0U] == '/')
        {
            return std::nullopt;
        }
        auto segments = std::vector<std::string_view>{};
        {
            auto cursor = std::size_t{0U};
            while (cursor < remainder.size())
            {
                auto const slash = remainder.find('/', cursor);
                if (slash == std::string_view::npos)
                {
                    segments.push_back(remainder.substr(cursor));
                    break;
                }
                if (slash == cursor)
                {
                    return std::nullopt;
                }
                segments.push_back(remainder.substr(cursor, slash - cursor));
                cursor = slash + 1U;
            }
        }
        if (segments.empty() || segments.size() > 3U)
        {
            return std::nullopt;
        }

        auto result = RoomRelationsPathParts{};
        result.room_id = core::percent_decode_path_component(suffix.substr(0U, marker_pos));
        result.event_id = core::percent_decode_path_component(segments[0U]);
        if (segments.size() >= 2U)
        {
            result.rel_type = core::percent_decode_path_component(segments[1U]);
        }
        if (segments.size() == 3U)
        {
            result.event_type = core::percent_decode_path_component(segments[2U]);
        }
        return result;
    }

    [[nodiscard]] auto room_joined_members_path_room_id(std::string_view target) -> std::optional<std::string>
    {
        auto constexpr prefix = std::string_view{"/_matrix/client/v3/rooms/"};
        auto constexpr marker = std::string_view{"/joined_members"};
        auto const path = target.substr(0U, target.find('?'));
        auto const suffix = route_suffix(path, prefix);
        if (suffix.size() <= marker.size() || !suffix.ends_with(marker))
        {
            return std::nullopt;
        }
        auto const room_id = suffix.substr(0U, suffix.size() - marker.size());
        if (room_id.empty() || room_id.find('/') != std::string_view::npos)
        {
            return std::nullopt;
        }
        return core::percent_decode_path_component(room_id);
    }

    struct RoomTypingPathParts final
    {
        std::string room_id{};
        std::string user_id{};
    };

    [[nodiscard]] auto room_typing_path_parts(std::string_view target) -> std::optional<RoomTypingPathParts>
    {
        auto constexpr prefix = std::string_view{"/_matrix/client/v3/rooms/"};
        auto constexpr marker = std::string_view{"/typing/"};
        auto const suffix = route_suffix(target, prefix);
        auto const marker_pos = suffix.find(marker);
        if (suffix.empty() || marker_pos == std::string_view::npos || marker_pos == 0U ||
            marker_pos + marker.size() >= suffix.size())
        {
            return std::nullopt;
        }
        auto const user_segment = suffix.substr(marker_pos + marker.size());
        if (user_segment.find('/') != std::string_view::npos)
        {
            return std::nullopt;
        }
        return RoomTypingPathParts{core::percent_decode_path_component(suffix.substr(0U, marker_pos)),
                                   core::percent_decode_path_component(user_segment)};
    }

    [[nodiscard]] auto room_messages_room_id(std::string_view target) -> std::optional<std::string>
    {
        auto constexpr prefix = std::string_view{"/_matrix/client/v3/rooms/"};
        auto constexpr marker = std::string_view{"/messages"};
        auto const path = target.substr(0U, target.find('?'));
        auto const suffix = route_suffix(path, prefix);
        if (suffix.empty() || suffix.size() <= marker.size() || suffix.substr(suffix.size() - marker.size()) != marker)
        {
            return std::nullopt;
        }
        return core::percent_decode_path_component(suffix.substr(0U, suffix.size() - marker.size()));
    }

    [[nodiscard]] auto room_initial_sync_path_room_id(std::string_view target) -> std::optional<std::string>
    {
        auto constexpr prefix = std::string_view{"/_matrix/client/v3/rooms/"};
        auto constexpr marker = std::string_view{"/initialSync"};
        auto const path = target.substr(0U, target.find('?'));
        auto const suffix = route_suffix(path, prefix);
        if (suffix.empty() || suffix.size() <= marker.size() || suffix.substr(suffix.size() - marker.size()) != marker)
        {
            return std::nullopt;
        }
        auto const room_id = suffix.substr(0U, suffix.size() - marker.size());
        if (room_id.empty() || room_id.find('/') != std::string_view::npos)
        {
            return std::nullopt;
        }
        return core::percent_decode_path_component(room_id);
    }

    [[nodiscard]] auto messages_query_value(std::string_view target, std::string_view name) -> std::string
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

    [[nodiscard]] auto room_key_backup_path_parts(std::string_view target) -> std::optional<RoomKeyBackupPathParts>
    {
        auto constexpr prefix = std::string_view{"/_matrix/client/v3/room_keys/keys/"};
        auto const suffix = route_suffix(target, prefix);
        auto const clean = suffix.substr(0U, suffix.find('?'));
        if (clean.empty())
        {
            return std::nullopt;
        }

        auto const separator = clean.find('/');
        if (separator == std::string_view::npos)
        {
            return RoomKeyBackupPathParts{core::percent_decode_path_component(clean), std::nullopt};
        }
        if (separator == 0U || separator + 1U >= clean.size())
        {
            return std::nullopt;
        }

        return RoomKeyBackupPathParts{
            core::percent_decode_path_component(clean.substr(0U, separator)),
            core::percent_decode_path_component(clean.substr(separator + 1U)),
        };
    }

    [[nodiscard]] auto parse_u64(std::string_view value) noexcept -> std::optional<std::uint64_t>
    {
        if (value.empty())
        {
            return std::nullopt;
        }
        auto parsed = std::uint64_t{0U};
        auto const* begin = value.data();
        auto const* end = value.data() + value.size();
        auto const conv = std::from_chars(begin, end, parsed);
        if (conv.ec != std::errc{} || conv.ptr != end)
        {
            return std::nullopt;
        }
        return parsed;
    }

    [[nodiscard]] auto messages_json(ClientServerRuntime const& rt, std::string_view room_id, std::string_view target)
        -> std::string
    {
        auto const dir = messages_query_value(target, "dir");
        auto const backwards = dir != "f"; // both default and "b" walk backward
        auto const from_token = parse_u64(messages_query_value(target, "from"));
        auto limit = std::size_t{10U};
        if (auto const parsed = parse_u64(messages_query_value(target, "limit")); parsed.has_value())
        {
            limit = static_cast<std::size_t>(std::min<std::uint64_t>(*parsed, std::uint64_t{100U}));
        }
        auto entries = std::vector<database::PersistentEvent const*>{};
        for (auto const& event : rt.homeserver.database.persistent_store.events)
        {
            if (event.room_id == room_id)
            {
                entries.push_back(&event);
            }
        }
        std::ranges::sort(entries, [](auto const* lhs, auto const* rhs) noexcept {
            return lhs->stream_ordering < rhs->stream_ordering;
        });
        auto chunk = canonicaljson::Array{};
        auto start_token = std::string{};
        auto end_token = std::string{};
        auto const append = [&chunk, &start_token, &end_token, limit](database::PersistentEvent const& event) {
            if (chunk.size() >= limit)
            {
                return false;
            }
            if (chunk.empty())
            {
                start_token = std::to_string(event.stream_ordering);
            }
            end_token = std::to_string(event.stream_ordering);
            chunk.push_back(client_event_value(event));
            return true;
        };
        if (backwards)
        {
            for (auto it = entries.rbegin(); it != entries.rend(); ++it)
            {
                if (from_token.has_value() && (*it)->stream_ordering >= *from_token)
                {
                    continue;
                }
                if (!append(**it))
                {
                    break;
                }
            }
        }
        else
        {
            for (auto const* event : entries)
            {
                if (from_token.has_value() && event->stream_ordering <= *from_token)
                {
                    continue;
                }
                if (!append(*event))
                {
                    break;
                }
            }
        }
        auto state =
            build_current_state_events_array(rt.homeserver.database.persistent_store, sync::EventTypeFilter{}, room_id);
        return json_serialize(json_obj({
            json_member("chunk", json_arr(std::move(chunk))),
            json_member("start", json_str(start_token)),
            json_member("end", json_str(end_token)),
            json_member("state", json_arr(std::move(state))),
        }));
    }

    struct InitialSyncMessages final
    {
        canonicaljson::Array chunk{};
        std::string start{};
        std::string end{};
    };

    // Builds the recent-messages chunk for GET /rooms/{roomId}/initialSync.
    // Defaults to the most recent 20 events, capped at 100, and honours the
    // ?limit= query parameter used by Element Web when previewing rooms.
    [[nodiscard]] auto build_initial_sync_messages(ClientServerRuntime const& rt, std::string_view room_id,
                                                   std::string_view target) -> InitialSyncMessages
    {
        auto limit = std::size_t{20U};
        if (auto const parsed = parse_u64(messages_query_value(target, "limit")); parsed.has_value())
        {
            limit = static_cast<std::size_t>(std::min<std::uint64_t>(*parsed, std::uint64_t{100U}));
        }

        auto entries = std::vector<database::PersistentEvent const*>{};
        for (auto const& event : rt.homeserver.database.persistent_store.events)
        {
            if (event.room_id == room_id)
            {
                entries.push_back(&event);
            }
        }
        std::ranges::sort(entries, [](auto const* lhs, auto const* rhs) noexcept {
            return lhs->stream_ordering < rhs->stream_ordering;
        });

        auto chunk = canonicaljson::Array{};
        auto start_token = std::string{};
        auto end_token = std::string{};
        for (auto it = entries.rbegin(); it != entries.rend(); ++it)
        {
            if (chunk.size() >= limit)
            {
                break;
            }
            if (chunk.empty())
            {
                start_token = std::to_string((*it)->stream_ordering);
            }
            end_token = std::to_string((*it)->stream_ordering);
            chunk.push_back(client_event_value(**it));
        }
        return {std::move(chunk), std::move(start_token), std::move(end_token)};
    }

    // Build the RoomInfo response for GET /rooms/{roomId}/initialSync.
    // The caller has already verified that the requester is a current/previous
    // member or is permitted to peek a world_readable room.
    [[nodiscard]] auto room_initial_sync_json(ClientServerRuntime const& rt, std::string_view room_id,
                                              std::string_view user_id, std::string_view target,
                                              std::string_view membership) -> std::string
    {
        auto const& store = rt.homeserver.database.persistent_store;
        auto const index = build_state_index(store);

        auto const messages = build_initial_sync_messages(rt, room_id, target);
        auto state_events = build_current_state_events_array(store, sync::EventTypeFilter{}, room_id);

        auto account_data = canonicaljson::Array{};
        for (auto const& row : store.account_data)
        {
            if (row.user_id != user_id || row.room_id != room_id)
            {
                continue;
            }
            auto parsed = canonicaljson::parse_lossless(row.content_json);
            auto content = parsed.error == canonicaljson::ParseError::none
                               ? std::move(parsed.value)
                               : canonicaljson::Value{canonicaljson::Object{}};
            account_data.push_back(json_obj({
                json_member("type", json_str(row.event_type)),
                json_member("content", std::move(content)),
            }));
        }

        auto const join_rule = room_state_string(store, index, room_id, "m.room.join_rules", "join_rule");
        auto const visibility = (join_rule.has_value() && *join_rule == "public") ? std::string_view{"public"}
                                                                                  : std::string_view{"private"};

        return json_serialize(json_obj({
            json_member("room_id", json_str(room_id)),
            json_member("membership", json_str(membership)),
            json_member("visibility", json_str(visibility)),
            json_member("account_data", json_arr(std::move(account_data))),
            json_member("messages", json_obj({
                                        json_member("chunk", json_arr(std::move(messages.chunk))),
                                        json_member("start", json_str(messages.start)),
                                        json_member("end", json_str(messages.end)),
                                    })),
            json_member("state", json_arr(std::move(state_events))),
        }));
    }

    [[nodiscard]] auto event_body_from_content(std::string_view event_type, std::string_view content,
                                               std::optional<std::string> state_key = std::nullopt)
        -> std::optional<std::string>
    {
        auto parsed_content = canonicaljson::parse_lossless(content);
        if (parsed_content.error != canonicaljson::ParseError::none ||
            std::get_if<canonicaljson::Object>(&parsed_content.value.storage()) == nullptr)
        {
            return std::nullopt;
        }
        auto members = canonicaljson::Object{
            json_member("type", json_str(event_type)),
            json_member("content", std::move(parsed_content.value)),
        };
        if (state_key.has_value())
        {
            members.push_back(json_member("state_key", json_str(*state_key)));
        }
        return json_serialize(json_obj(std::move(members)));
    }

    [[nodiscard]] auto media_upload_response_json(std::string_view operation_value) -> std::string
    {
        auto const content_uri_end = operation_value.find('|');
        auto const content_uri =
            content_uri_end == std::string_view::npos ? operation_value : operation_value.substr(0U, content_uri_end);
        return json_serialize(json_obj({json_member("content_uri", json_str(content_uri))}));
    }

    // The local media router returns successful download/thumbnail results as
    // "content_type|bytes" so that both pieces survive the internal request
    // boundary. This converts that pipe-delimited payload into the raw HTTP
    // response the Matrix spec expects: bytes in the body and Content-Type in a
    // header. Non-200 local responses are turned into Matrix errors.
    [[nodiscard]] auto media_download_dispatch_result(LocalHttpRequest const& req, ClientServerRuntime const& rt,
                                                      LocalHttpResponse const& local_response) -> DispatchResult
    {
        if (local_response.status != 200U)
        {
            return dispatch_err(req, rt, local_response.status,
                                local_response.status == 404U ? "M_NOT_FOUND" : "M_UNKNOWN", local_response.body);
        }
        auto const pipe_pos = local_response.body.find('|');
        if (pipe_pos == std::string::npos)
        {
            return dispatch_err(req, rt, 500U, "M_UNKNOWN", "malformed media download result");
        }
        auto const content_type = std::string_view{local_response.body}.substr(0U, pipe_pos);
        auto const bytes = std::string_view{local_response.body}.substr(pipe_pos + 1U);
        auto response = LocalHttpResponse{200U, std::string{bytes}, {{"Content-Type", std::string{content_type}}}};
        apply_cors_headers(req, response, rt.cors);
        return DispatchResult{DispatchResult::Status::complete, std::move(response), {}};
    }

    [[nodiscard]] auto report_path_parts(std::string_view target) -> std::optional<ReportPathParts>
    {
        auto constexpr prefix = std::string_view{"/_matrix/client/v3/rooms/"};
        auto constexpr separator_text = std::string_view{"/report/"};
        auto const suffix = route_suffix(target, prefix);
        auto const separator = suffix.find(separator_text);
        if (suffix.empty() || separator == std::string_view::npos || separator == 0U ||
            separator + separator_text.size() >= suffix.size())
        {
            return std::nullopt;
        }
        return ReportPathParts{std::string{suffix.substr(0U, separator)},
                               std::string{suffix.substr(separator + separator_text.size())}};
    }

    [[nodiscard]] auto review_target_from_path(std::string_view target) -> std::optional<trust_safety::ReviewTarget>
    {
        if (target == "federation" || target == "federation_server")
        {
            return trust_safety::ReviewTarget::federation_server;
        }
        if (target == "media")
        {
            return trust_safety::ReviewTarget::media;
        }
        if (target == "room")
        {
            return trust_safety::ReviewTarget::room;
        }
        return std::nullopt;
    }

    [[nodiscard]] auto admin_review_path_parts(std::string_view target) -> std::optional<AdminReviewPathParts>
    {
        auto constexpr prefix = std::string_view{"/_matrix/client/v3/admin/safety/review/"};
        auto const suffix = route_suffix(target, prefix);
        auto const separator = suffix.find('/');
        if (suffix.empty() || separator == std::string_view::npos || separator == 0U || separator + 1U >= suffix.size())
        {
            return std::nullopt;
        }
        auto const review_target = review_target_from_path(suffix.substr(0U, separator));
        if (!review_target.has_value())
        {
            return std::nullopt;
        }
        return AdminReviewPathParts{*review_target, std::string{suffix.substr(separator + 1U)}};
    }

    [[nodiscard]] auto admin_policy_rule_path_parts(std::string_view target) -> std::optional<AdminPolicyRulePathParts>
    {
        auto constexpr prefix = std::string_view{"/_matrix/client/v3/admin/safety/policy_rules/"};
        auto const suffix = route_suffix(target, prefix);
        auto const separator = suffix.find('/');
        if (suffix.empty() || separator == std::string_view::npos || separator == 0U || separator + 1U >= suffix.size())
        {
            return std::nullopt;
        }
        return AdminPolicyRulePathParts{std::string{suffix.substr(0U, separator)},
                                        std::string{suffix.substr(separator + 1U)}};
    }

    [[nodiscard]] auto is_valid_policy_rule_action(std::string_view action) noexcept -> bool
    {
        return action == "allow" || action == "deny" || action == "quarantine" || action == "lock_account" ||
               action == "suspend_account";
    }

    auto append_policy_audit(ClientServerRuntime& rt, trust_safety::SafetyAuditEvent const& event) -> void
    {
        append_local_audit(rt.homeserver.database, observability::AuditCategory::policy, event.event_type, event.actor,
                           event.entity, event.reason.code);
    }

    [[nodiscard]] auto policy_rules_json(ClientServerRuntime const& rt) -> std::string
    {
        auto rules = canonicaljson::Array{};
        for (auto const& rule : rt.homeserver.database.persistent_store.policy_rules)
        {
            rules.push_back(json_obj({
                json_member("rule_id", json_str(rule.rule_id)),
                json_member("scope", json_str(rule.scope)),
                json_member("entity", json_str(rule.entity)),
                json_member("action", json_str(rule.action)),
                json_member("reason", json_str(rule.reason)),
            }));
        }
        return json_serialize(json_obj({json_member("policy_rules", json_arr(std::move(rules)))}));
    }

    [[nodiscard]] auto store_key_api_payload(ClientServerRuntime& rt, auth::KeyApiEndpoint endpoint,
                                             std::string_view user, std::string_view /*device_id*/,
                                             LocalHttpRequest const& req, std::string_view version) -> bool
    {
        auto& store = rt.homeserver.database.persistent_store;
        switch (endpoint)
        {
        case auth::KeyApiEndpoint::upload_cross_signing_keys: {
            auto const parsed = canonicaljson::parse_lossless(req.body);
            if (parsed.error != canonicaljson::ParseError::none)
            {
                return false;
            }
            auto const* obj = std::get_if<canonicaljson::Object>(&parsed.value.storage());
            if (obj == nullptr)
            {
                return false;
            }
            auto stored = true;
            for (auto const& [key_type, key_name] : {
                     std::pair<std::string_view, std::string_view>{"master_key",       "master"      },
                     std::pair<std::string_view, std::string_view>{"self_signing_key", "self_signing"},
                     std::pair<std::string_view, std::string_view>{"user_signing_key", "user_signing"},
            })
            {
                auto const* value = object_member(*obj, key_type);
                if (value == nullptr)
                {
                    continue;
                }
                auto const serialized = canonicaljson::serialize_canonical(*value);
                if (serialized.error != canonicaljson::CanonicalJsonError::none)
                {
                    stored = false;
                    continue;
                }
                if (!database::store_cross_signing_key(store,
                                                       {std::string{user}, std::string{key_name}, serialized.output}))
                {
                    stored = false;
                }
            }
            return stored;
        }
        case auth::KeyApiEndpoint::upload_signatures: {
            auto const parsed = parsed_json_object(req.body);
            if (!parsed.has_value())
            {
                return false;
            }
            auto stored = true;
            for (auto const& user_member : *parsed)
            {
                auto const* signed_keys = std::get_if<canonicaljson::Object>(&user_member.value->storage());
                if (signed_keys == nullptr)
                {
                    stored = false;
                    continue;
                }
                for (auto const& key_member : *signed_keys)
                {
                    auto const serialized = canonicaljson::serialize_canonical(*key_member.value);
                    if (serialized.error != canonicaljson::CanonicalJsonError::none)
                    {
                        stored = false;
                        continue;
                    }
                    if (!database::store_key_signature(
                            store, {std::string{user}, user_member.key, key_member.key, serialized.output}))
                    {
                        stored = false;
                    }
                }
            }
            return stored;
        }
        case auth::KeyApiEndpoint::create_key_backup_version:
        case auth::KeyApiEndpoint::update_key_backup_version:
            return database::store_key_backup_version(store, {std::string{user}, std::string{version}, req.body});
        case auth::KeyApiEndpoint::put_room_key_backup: {
            auto const path = room_key_backup_path_parts(req.target);
            if (!path.has_value() || !path->session_id.has_value())
            {
                return false;
            }
            return database::store_key_backup_session(
                store, {std::string{user}, std::string{version}, path->room_id, *path->session_id, req.body});
        }
        case auth::KeyApiEndpoint::put_room_key_backup_room: {
            auto const path = room_key_backup_path_parts(req.target);
            if (!path.has_value() || path->session_id.has_value())
            {
                return false;
            }
            auto const body = parsed_json_object(req.body);
            if (!body.has_value())
            {
                return false;
            }
            auto const* sessions = object_member_as_object(*body, "sessions");
            if (sessions == nullptr)
            {
                return false;
            }
            auto stored = true;
            for (auto const& session : *sessions)
            {
                auto const serialized = canonicaljson::serialize_canonical(*session.value);
                if (serialized.error != canonicaljson::CanonicalJsonError::none)
                {
                    stored = false;
                    continue;
                }
                if (!database::store_key_backup_session(store, {std::string{user}, std::string{version}, path->room_id,
                                                                session.key, serialized.output}))
                {
                    stored = false;
                }
            }
            return stored;
        }
        case auth::KeyApiEndpoint::put_room_key_backup_batch: {
            auto const body = canonicaljson::parse_lossless(req.body);
            auto const* body_obj = std::get_if<canonicaljson::Object>(&body.value.storage());
            if (body_obj == nullptr)
            {
                return false;
            }
            auto const* rooms = object_member_as_object(*body_obj, "rooms");
            if (rooms == nullptr)
            {
                return false;
            }
            for (auto const& room : *rooms)
            {
                if (room.value == nullptr)
                {
                    continue;
                }
                auto const* room_obj = std::get_if<canonicaljson::Object>(&room.value->storage());
                if (room_obj == nullptr)
                {
                    continue;
                }
                auto const* sessions = object_member_as_object(*room_obj, "sessions");
                if (sessions == nullptr)
                {
                    continue;
                }
                for (auto const& session : *sessions)
                {
                    if (session.value == nullptr)
                    {
                        continue;
                    }
                    auto const session_json = canonicaljson::serialize_canonical(*session.value);
                    if (session_json.error != canonicaljson::CanonicalJsonError::none)
                    {
                        continue;
                    }
                    std::ignore = database::store_key_backup_session(
                        store, {std::string{user}, std::string{version}, room.key, session.key, session_json.output});
                }
            }
            return true;
        }
        case auth::KeyApiEndpoint::delete_key_backup_version: {
            auto constexpr prefix = std::string_view{"/_matrix/client/v3/room_keys/version/"};
            auto const version_str = route_suffix(req.target, prefix);
            if (version_str.empty())
                return false;
            return database::delete_key_backup_version(store, user, version_str);
        }
        case auth::KeyApiEndpoint::delete_room_key_backup: {
            auto const path = room_key_backup_path_parts(req.target);
            if (!path.has_value() || !path->session_id.has_value())
            {
                return false;
            }
            return database::delete_key_backup_session(store, user, version, path->room_id, *path->session_id);
        }
        case auth::KeyApiEndpoint::delete_room_key_backup_room: {
            auto const path = room_key_backup_path_parts(req.target);
            if (!path.has_value() || path->session_id.has_value())
            {
                return false;
            }
            return database::delete_key_backup_room_sessions(store, user, version, path->room_id);
        }
        case auth::KeyApiEndpoint::delete_room_key_backup_batch:
            return database::delete_all_key_backup_sessions(store, user);
        case auth::KeyApiEndpoint::upload_keys:
        case auth::KeyApiEndpoint::query_keys:
        case auth::KeyApiEndpoint::claim_keys:
        case auth::KeyApiEndpoint::device_list_update:
        case auth::KeyApiEndpoint::get_key_backup_version:
        case auth::KeyApiEndpoint::get_key_backup_version_by_id:
        case auth::KeyApiEndpoint::get_room_key_backup:
        case auth::KeyApiEndpoint::get_room_key_backup_batch:
            return true;
        }
        return true;
    }

    [[nodiscard]] auto handle_key_api_route(ClientServerRuntime& rt, auth::KeyApiRoute const& route,
                                            std::string_view user, std::string_view device_id,
                                            LocalHttpRequest const& req) -> LocalHttpResponse
    {
        record_key_api_access(rt, route, user, device_id, req.body);
        switch (route.endpoint)
        {
        case auth::KeyApiEndpoint::upload_keys:
            return handle_key_upload(rt, user, device_id, req.body);
        case auth::KeyApiEndpoint::query_keys:
            return handle_key_query(rt, user, req.body);
        case auth::KeyApiEndpoint::claim_keys:
            return handle_key_claim(rt, req.body);
        case auth::KeyApiEndpoint::get_key_backup_version: {
            auto const* version = key_backup_version_for_user(rt.homeserver.database.persistent_store, user);
            if (version == nullptr)
            {
                return resp(404U, matrix_error("M_NOT_FOUND", "key backup version not found"));
            }
            return resp(200U, key_backup_metadata_response(rt.homeserver.database.persistent_store, *version));
        }
        case auth::KeyApiEndpoint::get_key_backup_version_by_id: {
            auto constexpr vprefix = std::string_view{"/_matrix/client/v3/room_keys/version/"};
            auto const vsuffix = route_suffix(req.target, vprefix);
            auto const vid = vsuffix.substr(0U, vsuffix.find('?'));
            if (vid.empty())
            {
                return err(400U, "M_UNRECOGNIZED", "missing version in path");
            }
            auto const* version = key_backup_version_for_user(rt.homeserver.database.persistent_store, user, vid);
            if (version == nullptr)
            {
                return resp(404U, matrix_error("M_NOT_FOUND", "key backup version not found"));
            }
            return resp(200U, key_backup_metadata_response(rt.homeserver.database.persistent_store, *version));
        }
        case auth::KeyApiEndpoint::get_room_key_backup_batch: {
            auto const& all_sessions = rt.homeserver.database.persistent_store.key_backup_sessions;
            auto room_map = std::map<std::string, canonicaljson::Object>{};
            for (auto const& s : all_sessions)
            {
                if (s.user_id == user)
                {
                    room_map[s.room_id].push_back(json_member(s.session_id, json_embed_raw(s.json)));
                }
            }
            auto rooms = canonicaljson::Object{};
            for (auto& [room_id, sess_obj] : room_map)
            {
                rooms.push_back(
                    json_member(room_id, json_obj({json_member("sessions", json_obj(std::move(sess_obj)))})));
            }
            return resp(200U, json_serialize(json_obj({json_member("rooms", json_obj(std::move(rooms)))})));
        }
        case auth::KeyApiEndpoint::get_room_key_backup: {
            if (auto const path = room_key_backup_path_parts(req.target); path.has_value())
            {
                if (!path->session_id.has_value())
                {
                    auto const& all_sessions = rt.homeserver.database.persistent_store.key_backup_sessions;
                    auto sessions_obj = canonicaljson::Object{};
                    for (auto const& s : all_sessions)
                    {
                        if (s.user_id == user && s.room_id == path->room_id)
                        {
                            sessions_obj.push_back(json_member(s.session_id, json_embed_raw(s.json)));
                        }
                    }
                    return resp(200U,
                                json_serialize(json_obj({json_member("sessions", json_obj(std::move(sessions_obj)))})));
                }

                auto const& sessions = rt.homeserver.database.persistent_store.key_backup_sessions;
                auto const it = std::ranges::find_if(sessions, [&](auto const& s) {
                    return s.user_id == user && s.room_id == path->room_id && s.session_id == *path->session_id;
                });
                if (it == sessions.end())
                {
                    return resp(404U, matrix_error("M_NOT_FOUND", "key backup session not found"));
                }
                return resp(200U, it->json);
            }
            auto constexpr kbprefix = std::string_view{"/_matrix/client/v3/room_keys/keys/"};
            auto const suffix = route_suffix(req.target, kbprefix);
            auto const clean = suffix.substr(0U, suffix.find('?'));
            auto const separator = clean.find('/');
            // No slash in clean suffix → room-level GET (/{roomId}), not session-level.
            if (separator == std::string_view::npos || separator + 1U >= clean.size())
            {
                // Return all sessions for the room as {"sessions":{sessionId: data, ...}}.
                auto const room_id = clean;
                auto const& all_sessions = rt.homeserver.database.persistent_store.key_backup_sessions;
                auto sessions_obj = canonicaljson::Object{};
                for (auto const& s : all_sessions)
                {
                    if (s.user_id == user && s.room_id == room_id)
                    {
                        sessions_obj.push_back(json_member(s.session_id, json_embed_raw(s.json)));
                    }
                }
                return resp(200U,
                            json_serialize(json_obj({json_member("sessions", json_obj(std::move(sessions_obj)))})));
            }
            auto const room_id = clean.substr(0U, separator);
            auto const session_id = clean.substr(separator + 1U);
            auto const& sessions = rt.homeserver.database.persistent_store.key_backup_sessions;
            auto const it = std::ranges::find_if(sessions, [&](auto const& s) {
                return s.user_id == user && s.room_id == room_id && s.session_id == session_id;
            });
            if (it == sessions.end())
            {
                return resp(404U, matrix_error("M_NOT_FOUND", "key backup session not found"));
            }
            return resp(200U, it->json);
        }
        case auth::KeyApiEndpoint::upload_cross_signing_keys: {
            // Spec §11.12.1: MUST require UIA (m.login.password) to prevent key takeover.
            auto const cs_uia = json_obj({
                json_member("flows",
                            json_arr({json_obj({json_member("stages", json_arr({json_str("m.login.password")}))})})),
                json_member("params", json_obj({})),
                json_member("session", json_str("cross_signing_upload")),
            });
            auto const cs_body = parsed_json_object(req.body);
            auto const* cs_auth = cs_body.has_value() ? object_member_object(*cs_body, "auth") : nullptr;
            if (cs_auth == nullptr)
            {
                return resp(401U, json_serialize(cs_uia));
            }
            auto const* cs_auth_type = string_member(*cs_auth, "type");
            if (cs_auth_type == nullptr || *cs_auth_type != "m.login.password")
            {
                return resp(401U, json_serialize(cs_uia));
            }
            auto const* cs_password = string_member(*cs_auth, "password");
            if (cs_password == nullptr || cs_password->empty())
            {
                return resp(401U, json_serialize(cs_uia));
            }
            if (!verify_local_user_password(rt.homeserver, req.access_token, *cs_password))
            {
                return resp(401U, json_serialize(cs_uia));
            }
            if (!store_key_api_payload(rt, route.endpoint, user, device_id, req, {}))
            {
                return err(500U, "M_UNKNOWN", "key API persistence failed");
            }
            // Spec §11.11.1: cross-signing key change MUST appear in device_lists.changed.
            // Self-notify so the user's own other devices re-query the new keys (required
            // for verification to complete). Also fan out to room-sharing local users and
            // remote servers.
            {
                std::ignore = record_device_list_change(rt, {0U, std::string{user}, std::string{user}, "changed"});
                for (auto const& room : rt.homeserver.database.rooms)
                {
                    if (!std::ranges::any_of(room.members, [user](auto const& m) {
                            return m == user;
                        }))
                    {
                        continue;
                    }
                    for (auto const& member : room.members)
                    {
                        if (member == user)
                        {
                            continue;
                        }
                        std::ignore = record_device_list_change(rt, {0U, member, std::string{user}, "changed"});
                    }
                }
                broadcast_device_list_updates(rt, user, remote_servers_for_user(rt.homeserver, user));
            }
            return resp(200U, key_api_success_body(route.endpoint));
        }
        case auth::KeyApiEndpoint::upload_signatures:
            if (!store_key_api_payload(rt, route.endpoint, user, device_id, req, {}))
            {
                return err(500U, "M_UNKNOWN", "key API persistence failed");
            }
            // Spec §11.11.1: signature upload changes the verified key graph; MUST propagate
            // device_lists.changed so other devices discover the self-signed state.
            {
                std::ignore = record_device_list_change(rt, {0U, std::string{user}, std::string{user}, "changed"});
                for (auto const& room : rt.homeserver.database.rooms)
                {
                    if (!std::ranges::any_of(room.members, [user](auto const& m) {
                            return m == user;
                        }))
                    {
                        continue;
                    }
                    for (auto const& member : room.members)
                    {
                        if (member == user)
                        {
                            continue;
                        }
                        std::ignore = record_device_list_change(rt, {0U, member, std::string{user}, "changed"});
                    }
                }
                broadcast_device_list_updates(rt, user, remote_servers_for_user(rt.homeserver, user));
            }
            return resp(200U, key_api_success_body(route.endpoint));
        case auth::KeyApiEndpoint::create_key_backup_version: {
            // Generate a unique version for this new backup.
            auto const new_ver = key_backup_next_version(rt.homeserver.database.persistent_store, user);
            if (!store_key_api_payload(rt, route.endpoint, user, device_id, req, new_ver))
            {
                return err(500U, "M_UNKNOWN", "key API persistence failed");
            }
            return resp(200U, json_serialize(json_obj({json_member("version", json_str(new_ver))})));
        }
        case auth::KeyApiEndpoint::update_key_backup_version: {
            // Version comes from the path: PUT /room_keys/version/{version}
            auto constexpr upd_prefix = std::string_view{"/_matrix/client/v3/room_keys/version/"};
            auto const path_ver = route_suffix(req.target, upd_prefix);
            // Strip any query string
            auto const clean_ver = path_ver.substr(0U, path_ver.find('?'));
            if (clean_ver.empty())
            {
                return err(400U, "M_UNRECOGNIZED", "missing version in path");
            }
            if (!store_key_api_payload(rt, route.endpoint, user, device_id, req, clean_ver))
            {
                return err(500U, "M_UNKNOWN", "key API persistence failed");
            }
            return resp(200U, "{}");
        }
        case auth::KeyApiEndpoint::delete_key_backup_version:
            if (!store_key_api_payload(rt, route.endpoint, user, device_id, req, {}))
            {
                return err(500U, "M_UNKNOWN", "key API persistence failed");
            }
            return resp(200U, key_api_success_body(route.endpoint));
        case auth::KeyApiEndpoint::put_room_key_backup:
        case auth::KeyApiEndpoint::put_room_key_backup_room:
        case auth::KeyApiEndpoint::put_room_key_backup_batch:
        case auth::KeyApiEndpoint::delete_room_key_backup_room:
        case auth::KeyApiEndpoint::delete_room_key_backup:
        case auth::KeyApiEndpoint::delete_room_key_backup_batch: {
            // Session operations require ?version= query parameter.
            auto const session_ver = extract_key_backup_version_param(req.target);
            if (session_ver.empty())
            {
                return err(400U, "M_MISSING_PARAM", "version query parameter is required");
            }
            if (!store_key_api_payload(rt, route.endpoint, user, device_id, req, session_ver))
            {
                return err(500U, "M_UNKNOWN", "key API persistence failed");
            }
            return resp(200U, room_keys_update_response(rt.homeserver.database.persistent_store, user, session_ver));
        }
        case auth::KeyApiEndpoint::device_list_update: {
            // PUT /_matrix/client/v3/devices/{deviceId} — update a device's
            // display name and notify all local users who share a room with
            // this user that their device list has changed.
            auto constexpr dev_prefix = std::string_view{"/_matrix/client/v3/devices/"};
            auto const device_id_from_path = req.target.substr(dev_prefix.size());
            auto* device = find_device(rt, user, device_id_from_path);
            if (device == nullptr)
            {
                return err(404U, "M_NOT_FOUND", "device not found");
            }
            auto const body = parse_device_update_body(req.body);
            if (!body.has_value())
            {
                return err(400U, "M_BAD_JSON", "device update body must be Matrix JSON");
            }
            if (!database::update_device_display_name(rt.homeserver.database.persistent_store, user,
                                                      device_id_from_path, body->display_name))
            {
                return err(500U, "M_UNKNOWN", "device update persistence failed");
            }
            device->display_name = body->display_name;
            // Record a device list change for every local user who shares a
            // room with the updated user so their /sync streams surface it.
            for (auto const& room : rt.homeserver.database.rooms)
            {
                auto const is_member = std::ranges::any_of(room.members, [user](auto const& m) {
                    return m == user;
                });
                if (!is_member)
                {
                    continue;
                }
                for (auto const& member : room.members)
                {
                    if (member == user)
                    {
                        continue;
                    }
                    auto const change = database::PersistentDeviceListChange{0U, member, std::string{user}, "changed"};
                    std::ignore = record_device_list_change(rt, change);
                }
            }
            append_local_audit(rt.homeserver.database, observability::AuditCategory::auth, "device.updated", user,
                               device->device_id, "display_name_updated");
            return resp(200U, "{}");
        }
        }
        return err(404U, "M_UNRECOGNIZED", "route not found");
    }

    [[nodiscard]] auto safety_reports_json(ClientServerRuntime const& rt) -> std::string
    {
        auto reports = canonicaljson::Array{};
        for (auto const& event : rt.homeserver.database.persistent_store.audit_log)
        {
            if (!starts_with(event.event_type, "trust_safety."))
            {
                continue;
            }
            reports.push_back(json_obj({
                json_member("event_type", json_str(event.event_type)),
                json_member("actor", json_str(event.actor)),
                json_member("target", json_str(event.target)),
                json_member("reason", json_str(event.reason)),
            }));
        }
        return json_serialize(json_obj({json_member("reports", json_arr(std::move(reports)))}));
    }

    [[nodiscard]] auto handle_safety_report(ClientServerRuntime& rt, std::string_view user, LocalHttpRequest const& req)
        -> LocalHttpResponse
    {
        auto const path = report_path_parts(req.target);
        auto const body = parse_safety_report_body(req.body);
        if (!path.has_value() || !body.has_value())
        {
            return err(400U, "M_BAD_JSON", "report body must be a JSON object with optional string reason");
        }
        auto const decision =
            trust_safety::validate_safety_report({std::string{user}, path->room_id, path->event_id, body->reason, 0});
        auto const audit = trust_safety::make_safety_audit_event(user, path->event_id, decision);
        append_policy_audit(rt, audit);
        if (!decision.allowed)
        {
            return err(400U, "M_BAD_REQUEST", decision.reason.public_summary);
        }
        return resp(200U, "{}");
    }

    [[nodiscard]] auto handle_admin_safety_route(ClientServerRuntime& rt, std::string_view admin_user,
                                                 LocalHttpRequest const& req) -> LocalHttpResponse
    {
        if (req.method == "GET" && req.target == "/_matrix/client/v3/admin/safety/reports")
        {
            return resp(200U, safety_reports_json(rt));
        }
        if (req.method == "GET" && req.target == "/_matrix/client/v3/admin/safety/policy_rules")
        {
            return resp(200U, policy_rules_json(rt));
        }
        if (req.method == "PUT")
        {
            auto const path = admin_policy_rule_path_parts(req.target);
            auto const body = parse_admin_policy_rule_body(req.body);
            if (!path.has_value() || !body.has_value())
            {
                return err(400U, "M_BAD_JSON", "policy rule body must be Matrix JSON");
            }
            if (!is_valid_policy_rule_action(body->action))
            {
                return err(400U, "M_BAD_JSON",
                           "policy rule action must be allow, deny, quarantine, lock_account, or suspend_account");
            }
            auto const rule = database::PersistentPolicyRule{
                path->scope + ':' + path->entity, path->scope, path->entity, body->action, body->reason,
            };
            if (!database::store_policy_rule(rt.homeserver.database.persistent_store, rule))
            {
                return err(500U, "M_UNKNOWN", "policy rule persistence failed");
            }
            if (!database::append_admin_action(
                    rt.homeserver.database.persistent_store,
                    {std::string{admin_user}, "trust_safety.policy_rule.upsert", rule.rule_id}))
            {
                return err(500U, "M_UNKNOWN", "admin action persistence failed");
            }
            append_local_audit(rt.homeserver.database, observability::AuditCategory::policy,
                               "trust_safety.policy_rule.upsert", admin_user, rule.rule_id, rule.action);
            return resp(200U, "{}");
        }
        if (req.method == "DELETE")
        {
            auto const path = admin_policy_rule_path_parts(req.target);
            if (!path.has_value())
            {
                return err(400U, "M_BAD_JSON", "policy rule path must include scope and entity");
            }
            auto const rule_id = path->scope + ':' + path->entity;
            if (!database::delete_policy_rule(rt.homeserver.database.persistent_store, rule_id))
            {
                return err(404U, "M_NOT_FOUND", "policy rule not found");
            }
            if (!database::append_admin_action(rt.homeserver.database.persistent_store,
                                               {std::string{admin_user}, "trust_safety.policy_rule.delete", rule_id}))
            {
                return err(500U, "M_UNKNOWN", "admin action persistence failed");
            }
            append_local_audit(rt.homeserver.database, observability::AuditCategory::policy,
                               "trust_safety.policy_rule.delete", admin_user, rule_id, "deleted");
            return resp(200U, "{}");
        }

        auto const path = admin_review_path_parts(req.target);
        auto const body = parse_admin_review_body(req.body);
        if (!path.has_value() || !body.has_value())
        {
            return err(400U, "M_BAD_JSON", "admin review body must be Matrix JSON");
        }
        auto const reason =
            trust_safety::enforcement_reason(body->reason, "target held for review", "admin marked target for review");
        auto const record = trust_safety::ReviewRecord{path->target, path->target_id, true, reason};
        auto const decision = trust_safety::review_policy(record);
        auto const audit = trust_safety::make_safety_audit_event(admin_user, path->target_id, decision);
        append_policy_audit(rt, audit);
        auto const scope = std::string{trust_safety::policy_surface_name(decision.surface)};
        if (!database::store_policy_rule(rt.homeserver.database.persistent_store,
                                         {scope + ':' + path->target_id, scope, path->target_id,
                                          std::string{trust_safety::policy_action_name(decision.action)},
                                          body->reason}))
        {
            return err(500U, "M_UNKNOWN", "policy rule persistence failed");
        }
        if (!database::append_admin_action(rt.homeserver.database.persistent_store,
                                           {std::string{admin_user}, audit.event_type, path->target_id}))
        {
            return err(500U, "M_UNKNOWN", "admin action persistence failed");
        }
        if (decision.action == trust_safety::PolicyAction::quarantine || decision.allowed)
        {
            return resp(200U, "{}");
        }
        return err(400U, "M_BAD_REQUEST", decision.reason.public_summary);
    }

} // namespace

// Translate the operator-facing `config::ClientRateLimitsConfig` into the
// engine's `http::RateLimitConfig`. The operator writes one map per tier
// keyed by URL prefix; the engine needs the same shape so the only work
// here is to copy the maps and the per-IP default. The conversion is a
// pure function so it is easy to unit test independently of the engine.
[[nodiscard]] static auto to_http_rate_limit_config(config::ClientRateLimitsConfig const& in) -> http::RateLimitConfig
{
    auto out = http::RateLimitConfig{};
    out.per_ip.reserve(in.per_ip.size());
    for (auto const& [k, v] : in.per_ip)
    {
        out.per_ip.emplace(k, v);
    }
    out.per_user.reserve(in.per_user.size());
    for (auto const& [k, v] : in.per_user)
    {
        out.per_user.emplace(k, v);
    }
    out.default_per_ip = in.default_per_ip;
    return out;
}

// Push the operator's `log_modules` map into the process-wide `SingleLog`.
// A special key of `*` sets the default level (the floor every other
// module sees); any other key names an individual module. Levels are
// case-folded to the canonical lowercase form before lookup so the
// operator can write `LOG_MODULES.HOME_SERVER=DEBUG` or
// `log_modules.home_server=debug` interchangeably.
static auto apply_log_modules(config::LogModulesConfig const& cfg) -> void
{
    auto& log = observability::SingleLog::instance();
    for (auto const& [name, level] : cfg.levels)
    {
        if (name == "*")
        {
            log.set_default_log_level(level);
        }
        else
        {
            log.set_module_log_level(name, level);
        }
    }
}

auto install_test_rate_limit_engine(ClientServerRuntime& runtime) -> void
{
    // One request per 60 seconds for every target. The default runtime
    // engine has 60 per 60s on most routes, so this is the minimum
    // cap that still drives a 429 from a single back-to-back request.
    // A real "test for the 429 path" wants the second call to be
    // denied; that is exactly what the cap-of-1 guarantees.
    auto cfg = http::RateLimitConfig{};
    cfg.default_per_ip = {1U, 60U};
    runtime.rate_limit_engine = std::make_unique<http::RateLimitEngine<ClientServerClock>>(cfg, runtime.clock);
}

// Test-only helper: install an engine with both per-IP and per-user
// caps set to 1/60s. Used by the per-user isolation test, which needs
// to verify that alice exhausting her per-user bucket does not
// deplete bob's. The per-user map covers account/whoami so the test
// can hit the per-user tier deterministically.
auto install_test_per_user_rate_limit_engine(ClientServerRuntime& runtime) -> void
{
    auto cfg = http::RateLimitConfig{};
    // Per-IP cap is loose (1000/60s) so it never binds — the test
    // only cares about per-user isolation. Production servers run with
    // 60/60s or tighter; the loose cap here is the simplest way to
    // exercise the per-user tier in isolation.
    cfg.default_per_ip = {1000U, 60U};
    cfg.per_user = {
        {"/_matrix/client/v3/account/whoami", {1U, 60U}},
    };
    runtime.rate_limit_engine = std::make_unique<http::RateLimitEngine<ClientServerClock>>(cfg, runtime.clock);
}

auto start_client_server(config::Config const& config) -> ClientServerStartResult
{
    auto started = start_runtime(config);
    if (!started.started)
    {
        return {false, started.reason, {}};
    }
    auto rt = ClientServerRuntime{};
    rt.homeserver = std::move(started.runtime);
    // Snapshot the CORS policy at startup. CORS is HTTP-behaviour
    // configuration (per docs/configuration.md) and so requires a restart to
    // take effect, matching every other HTTP-behaviour key.
    rt.cors = config.server().cors;
    // Build the wall-clock rate-limit engine from the parsed
    // ClientRateLimitsConfig. The engine borrows the runtime's clock
    // member so a unit test that constructs a `ClientServerRuntime` by
    // hand can swap the clock by giving the runtime a different
    // `ClientServerClock` instance and then creating the engine against
    // the new clock. (In production the clock always reads
    // std::chrono::steady_clock::now() so this is just a default-init.)
    rt.rate_limit_engine = std::make_unique<http::RateLimitEngine<ClientServerClock>>(
        to_http_rate_limit_config(config.client_rate_limits()), rt.clock);
    // Apply the operator's per-module log level overrides. The
    // SingleLog is a process-wide singleton; setting the level map here
    // is the bootstrap that lets the operator silence http_server and
    // bump auth to debug without recompiling. Restart-required; see
    // src/config/reload_policy.cpp.
    apply_log_modules(config.log_modules());
    rt.sync_notifier = std::make_unique<sync::SyncNotifier>();
    rt.homeserver.sync_notifier = rt.sync_notifier.get();
    rt.sync_notifier->publish(rt.homeserver.database.next_stream_ordering - 1U,
                              rt.homeserver.database.persistent_store.next_sync_stream_id);
    rt.devices.reserve(rt.homeserver.database.persistent_store.devices.size());
    for (auto const& device : rt.homeserver.database.persistent_store.devices)
    {
        rt.devices.push_back({device.user_id, device.device_id, device.display_name});
    }

    auto result = ClientServerStartResult{};
    result.started = true;
    result.runtime = std::move(rt);
    // No explicit `install_local_audit_database` call here: the
    // `HomeserverRuntime` member `audit_sink_scope` is installed on
    // construction and cleared on destruction, so the install is
    // already bound to the returned `result.runtime`'s lifetime by
    // the time the caller sees it. C++17 mandatory copy elision
    // guarantees `result` is constructed in the caller's storage,
    // so the address taken by the scope's ctor is the same one the
    // caller will see in `runtime_result.runtime.homeserver.database`.
    return result;
}

auto matrix_error(std::string_view errcode, std::string_view message) -> std::string
{
    return json_serialize(json_obj({
        json_member("errcode", json_str(errcode)),
        json_member("error", json_str(message)),
    }));
}

auto is_matrix_error_response(LocalHttpResponse const& r) noexcept -> bool
{
    return r.status >= 400U && starts_with(r.body, "{\"errcode\":\"");
}

auto handle_client_server_http_request(ClientServerRuntime& rt, std::string_view raw_request) -> LocalHttpResponse
{
    auto const head_end = raw_request.find("\r\n\r\n");
    if (head_end == std::string_view::npos)
    {
        return bad_http_request(400U, "incomplete HTTP request head");
    }

    auto const head = raw_request.substr(0U, head_end + std::string_view{"\r\n\r\n"}.size());
    auto const parsed = http::parse_request_head(head);
    if (parsed.error != http::RequestErrorCode::none)
    {
        return bad_http_request(http::request_error_status(parsed.error), http::request_error_name(parsed.error));
    }

    auto const available_body = raw_request.substr(head.size());
    if (!parsed.request.has_content_length)
    {
        if (!available_body.empty())
        {
            return bad_http_request(400U, "request body requires Content-Length");
        }
        return handle_client_server_request(rt,
                                            {parsed.request.method, parsed.request.target,
                                             bearer_access_token(parsed.request.headers), std::string{available_body},
                                             parsed.request.headers},
                                            false)
            .response;
    }

    if (parsed.request.content_length > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
    {
        return bad_http_request(413U, "request body too large");
    }

    auto const declared_body_size = static_cast<std::size_t>(parsed.request.content_length);
    if (available_body.size() < declared_body_size)
    {
        return bad_http_request(400U, "incomplete request body");
    }
    if (available_body.size() > declared_body_size)
    {
        return bad_http_request(400U, "trailing data after request body");
    }

    return handle_client_server_request(rt,
                                        {parsed.request.method, parsed.request.target,
                                         bearer_access_token(parsed.request.headers), std::string{available_body},
                                         parsed.request.headers},
                                        false)
        .response;
}

// Internal implementation — does NOT guarantee CORS headers on every code
// path (complete() and sync_json() build raw DispatchResult structs).
// All callers MUST go through the public handle_client_server_request wrapper
// which applies CORS at the boundary unconditionally.
static auto handle_client_server_request_impl(ClientServerRuntime& rt, LocalHttpRequest const& req, bool can_wait)
    -> DispatchResult
{
    log_diagnostic("request.received", {
                                           {"method",           req.method,                                       false},
                                           {"target",           observability::sanitized_http_target(req.target), false},
                                           {"body_bytes",       std::to_string(req.body.size()),                  false},
                                           {"has_access_token", req.access_token.empty() ? "false" : "true",      false},
    });
    if (!rt.homeserver.started)
    {
        log_diagnostic_audit(rt.homeserver.database, "client_server", "request.rejected",
                             {
                                 {"method", req.method,                                       false},
                                 {"target", observability::sanitized_http_target(req.target), false},
                                 {"status", "503",                                            false},
                                 {"reason", "runtime not started",                            false}
        },
                             observability::LogEventSeverity::warning, observability::AuditCategory::policy,
                             "request.rejected", req.access_token, req.target, "503:runtime not started");
        return dispatch_err(req, rt, 503U, "M_UNAVAILABLE", "runtime not started");
    }
    // Media upload routes are governed by security.media.max_upload_size rather
    // than the smaller general client-API body cap (64 KiB).  Check which limit
    // applies before enforcing the gate.
    auto const is_media_upload = req.method == "POST" && (req.target == "/_matrix/media/v3/upload" ||
                                                          starts_with(req.target, "/_matrix/media/v3/upload?") ||
                                                          req.target == "/_matrix/client/v1/media/upload" ||
                                                          starts_with(req.target, "/_matrix/client/v1/media/upload?"));
    auto const body_limit = [&]() -> std::size_t {
        if (is_media_upload)
        {
            auto const parsed = config::parse_size_limit(rt.homeserver.config.security().media.max_upload_size);
            auto const raw = parsed.valid ? parsed.bytes : std::uint64_t{104857600U};
            return raw > std::numeric_limits<std::size_t>::max() ? std::numeric_limits<std::size_t>::max()
                                                                 : static_cast<std::size_t>(raw);
        }
        return rt.limits.max_body_bytes;
    }();
    if (req.body.size() > body_limit)
    {
        log_diagnostic_audit(rt.homeserver.database, "client_server", "request.rejected",
                             {
                                 {"method",      req.method,                                       false},
                                 {"target",      observability::sanitized_http_target(req.target), false},
                                 {"status",      "413",                                            false},
                                 {"body_bytes",  std::to_string(req.body.size()),                  false},
                                 {"limit_bytes", std::to_string(body_limit),                       false},
                                 {"reason",      "request body too large",                         false}
        },
                             observability::LogEventSeverity::warning, observability::AuditCategory::policy,
                             "request.rejected", req.access_token, req.target, "413:request body too large");
        return dispatch_err(req, rt, 413U, "M_TOO_LARGE", "request body too large");
    }
    // CORS preflight: browsers send OPTIONS before any cross-origin POST/PUT/DELETE.
    // Must return 200 before the access-token and rate-limit gates. Browsers
    // may emit several preflights for the same route, and counting them
    // against the real request bucket causes 429s before the actual
    // application request is even attempted. The `Access-Control-*`
    // response headers are attached by `dispatch_resp` from the runtime's
    // CORS policy, so deployments behind a reverse proxy (nginx/Apache)
    // no longer need the proxy to add CORS headers.
    if (req.method == "OPTIONS")
    {
        return dispatch_resp(req, rt, 200U, {});
    }

    auto guard = std::unique_lock<std::recursive_mutex>{rt.homeserver.mutex};
    if (!allow(rt, req))
    {
        log_diagnostic_audit(rt.homeserver.database, "client_server", "request.rejected",
                             {
                                 {"method", req.method,                                       false},
                                 {"target", observability::sanitized_http_target(req.target), false},
                                 {"status", "429",                                            false},
                                 {"reason", "rate limit exceeded",                            false}
        },
                             observability::LogEventSeverity::warning, observability::AuditCategory::policy,
                             "request.rejected", req.access_token, req.target, "429:rate limit exceeded");
        return dispatch_err(req, rt, 429U, "M_LIMIT_EXCEEDED", "rate limit exceeded");
    }
    auto call_local = [&](LocalHttpRequest const& inner) {
        guard.unlock();
        auto response = handle_local_http_request(rt.homeserver, inner);
        guard.lock();
        return response;
    };

    // GET /.well-known/matrix/client tells clients where the homeserver lives.
    // Must be served before any auth check; the path is outside /_matrix/ so
    // Apache or nginx may not proxy it unless explicitly configured to do so.
    if (req.method == "GET" && req.target == "/.well-known/matrix/client")
    {
        auto const& base_url = rt.homeserver.config.server().public_baseurl;
        return dispatch_resp(req, rt, 200U,
                             json_serialize(json_obj({
                                 json_member("m.homeserver", json_obj({json_member("base_url", json_str(base_url))})),
                             })));
    }

    // GET /_matrix/client/versions is the unauthenticated discovery endpoint
    // most Matrix clients hit first. It must answer before any auth check so
    // a fresh client can negotiate spec compatibility before it has a token.
    if (req.method == "GET" && req.target == "/_matrix/client/versions")
    {
        auto versions = canonicaljson::Array{};
        for (auto const& spec : {"v1.1", "v1.2", "v1.3", "v1.4", "v1.5", "v1.6", "v1.7", "v1.8", "v1.9", "v1.10",
                                 "v1.11", "v1.12", "v1.13", "v1.14", "v1.15", "v1.16", "v1.17", "v1.18"})
        {
            versions.push_back(json_str(spec));
        }
        return dispatch_resp(
            req, rt, 200U,
            json_serialize(json_obj({
                json_member("versions", json_arr(std::move(versions))),
                json_member("unstable_features", json_obj({
                                                     json_member("org.matrix.msc4186", json_bool(true)),
                                                     json_member("org.matrix.simplified_msc3575", json_bool(true)),
                                                 })),
            })));
    }

    auto const request_path = std::string_view{req.target}.substr(0U, std::string_view{req.target}.find('?'));
    // Spec: GET /_matrix/client/v3/publicRooms
    // ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3publicrooms
    // When ?server= names a remote homeserver the request must be proxied to
    // GET /_matrix/federation/v1/publicRooms on that server.
    if (req.method == "GET" && request_path == "/_matrix/client/v3/publicRooms")
    {
        auto const server_param = query_param_value(req.target, "server");
        auto const& our_server = rt.homeserver.config.server().server_name;
        if (server_param.has_value() && !server_param->empty() && *server_param != our_server)
        {
            wire_federation_callbacks(rt.homeserver);
            auto const signing_key = ensure_runtime_server_signing_key(rt.homeserver);
            auto const key_id = signing_key.has_value() ? signing_key->key_id : std::string{};
            auto const secret =
                std::string{reinterpret_cast<char const*>(rt.homeserver.database.signing_secret_key.bytes().data()),
                            rt.homeserver.database.signing_secret_key.bytes().size()};
            auto* outbound_client = rt.homeserver.outbound_client.get();
            auto* discovery_network = rt.homeserver.discovery_network.get();
            auto limit = std::optional<std::size_t>{};
            if (auto const lv = query_param_value(req.target, "limit"); lv.has_value() && !lv->empty())
            {
                auto result = std::size_t{0U};
                auto const [ptr, ec] = std::from_chars(lv->data(), lv->data() + lv->size(), result);
                if (ec == std::errc{} && result > 0U)
                    limit = result;
            }
            auto const since = query_param_value(req.target, "since");
            auto const since_sv = since.has_value() ? std::optional<std::string_view>{*since} : std::nullopt;
            auto const tx = federation::make_outbound_transaction(
                *server_param, "GET", public_rooms_fed_target(limit, since_sv), our_server, {});
            guard.unlock();
            auto const [ok, body] = perform_sync_outbound_call(outbound_client, discovery_network, tx, key_id, secret,
                                                               "public_rooms.proxy");
            if (!ok)
                return dispatch_err(req, rt, 502U, "M_UNKNOWN", "Failed to fetch public rooms from remote server");
            return dispatch_resp(req, rt, 200U, body);
        }
        return dispatch_resp(req, rt, 200U, public_rooms_json(rt));
    }
    // Spec: POST /_matrix/client/v3/publicRooms
    // ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3publicrooms
    if (req.method == "POST" && request_path == "/_matrix/client/v3/publicRooms")
    {
        auto filter_term = std::string{};
        auto limit = std::optional<std::size_t>{};
        auto since_raw = std::string{};      // raw string; forwarded as-is to remote
        auto since_offset = std::size_t{0U}; // parsed integer for local pagination

        if (auto const body = parsed_json_object(req.body); body.has_value())
        {
            if (auto const* filter_val = object_member(*body, "filter"); filter_val != nullptr)
            {
                if (auto const* filter_obj = std::get_if<canonicaljson::Object>(&filter_val->storage());
                    filter_obj != nullptr)
                {
                    if (auto const* term = string_member(*filter_obj, "generic_search_term"); term != nullptr)
                        filter_term = *term;
                }
            }
            if (auto const* lv = object_member(*body, "limit"); lv != nullptr)
            {
                if (auto const* li = std::get_if<std::int64_t>(&lv->storage()); li != nullptr && *li > 0)
                    limit = static_cast<std::size_t>(*li);
            }
            if (auto const* sv = string_member(*body, "since"); sv != nullptr && !sv->empty())
            {
                since_raw = *sv;
                auto result = std::size_t{0U};
                auto const [ptr, ec] = std::from_chars(sv->data(), sv->data() + sv->size(), result);
                if (ec == std::errc{})
                    since_offset = result;
            }
        }

        auto const server_param = query_param_value(req.target, "server");
        auto const& our_server = rt.homeserver.config.server().server_name;
        if (server_param.has_value() && !server_param->empty() && *server_param != our_server)
        {
            wire_federation_callbacks(rt.homeserver);
            auto const signing_key = ensure_runtime_server_signing_key(rt.homeserver);
            auto const key_id = signing_key.has_value() ? signing_key->key_id : std::string{};
            auto const secret =
                std::string{reinterpret_cast<char const*>(rt.homeserver.database.signing_secret_key.bytes().data()),
                            rt.homeserver.database.signing_secret_key.bytes().size()};
            auto* outbound_client = rt.homeserver.outbound_client.get();
            auto* discovery_network = rt.homeserver.discovery_network.get();
            auto const opt_since = since_raw.empty() ? std::nullopt : std::make_optional<std::string_view>(since_raw);
            // Use POST when filter_term is set so servers supporting
            // POST /_matrix/federation/v1/publicRooms can apply the filter.
            // Fall back to GET for unfiltered requests (wider server compatibility).
            auto fed_body = std::string{};
            auto const fed_method = filter_term.empty() ? std::string_view{"GET"} : std::string_view{"POST"};
            if (!filter_term.empty())
            {
                auto filter_obj = canonicaljson::Object{};
                filter_obj.push_back(json_member("generic_search_term", json_str(filter_term)));
                auto body_obj = canonicaljson::Object{};
                body_obj.push_back(json_member("filter", json_obj(std::move(filter_obj))));
                if (limit.has_value())
                    body_obj.push_back(json_member("limit", json_int(static_cast<std::int64_t>(*limit))));
                if (!since_raw.empty())
                    body_obj.push_back(json_member("since", json_str(since_raw)));
                fed_body = json_serialize(json_obj(std::move(body_obj)));
            }
            auto const tx = federation::make_outbound_transaction(
                *server_param, fed_method, public_rooms_fed_target(limit, opt_since), our_server, fed_body);
            guard.unlock();
            auto const [ok, body] = perform_sync_outbound_call(outbound_client, discovery_network, tx, key_id, secret,
                                                               "public_rooms.proxy");
            if (!ok)
                return dispatch_err(req, rt, 502U, "M_UNKNOWN", "Failed to fetch public rooms from remote server");
            return dispatch_resp(req, rt, 200U, body);
        }
        return dispatch_resp(req, rt, 200U, public_rooms_filtered_json(rt, filter_term, limit, since_offset));
    }
    auto constexpr directory_room_prefix = std::string_view{"/_matrix/client/v3/directory/room/"};
    auto constexpr directory_list_room_prefix = std::string_view{"/_matrix/client/v3/directory/list/room/"};
    if (req.method == "GET" && starts_with(request_path, directory_room_prefix))
    {
        auto const encoded_alias = request_path.substr(directory_room_prefix.size());
        auto const room_alias = core::percent_decode_path_component(encoded_alias);
        auto const& our_server = rt.homeserver.config.server().server_name;
        auto const alias_server = server_name_from_room_alias(room_alias);
        if (!alias_server.empty() && alias_server != our_server)
        {
            wire_federation_callbacks(rt.homeserver);
            auto const signing_key = ensure_runtime_server_signing_key(rt.homeserver);
            auto const key_id = signing_key.has_value() ? signing_key->key_id : std::string{};
            auto const secret =
                std::string{reinterpret_cast<char const*>(rt.homeserver.database.signing_secret_key.bytes().data()),
                            rt.homeserver.database.signing_secret_key.bytes().size()};
            auto* outbound_client = rt.homeserver.outbound_client.get();
            auto* discovery_network = rt.homeserver.discovery_network.get();
            auto const target = std::string{"/_matrix/federation/v1/query/directory?room_alias="} +
                                core::percent_encode_path_component(room_alias);
            auto const tx =
                federation::make_outbound_transaction(std::string{alias_server}, "GET", target, our_server, {});
            guard.unlock();
            auto const [ok, body] = perform_sync_outbound_call(outbound_client, discovery_network, tx, key_id, secret,
                                                               "directory.room.proxy");
            if (!ok)
            {
                return dispatch_err(req, rt, 502U, "M_UNKNOWN", "Failed to resolve room alias on remote server");
            }
            return dispatch_resp(req, rt, 200U, body);
        }
        auto const found = database::find_room_alias(rt.homeserver.database.persistent_store, room_alias);
        if (!found.has_value())
        {
            return dispatch_err(req, rt, 404U, "M_NOT_FOUND", "room alias not found");
        }
        auto servers = canonicaljson::Array{};
        for (auto const& server : room_servers_for_alias(rt, found->room_id))
        {
            servers.push_back(json_str(server));
        }
        return dispatch_resp(req, rt, 200U,
                             json_serialize(json_obj({
                                 json_member("room_id", json_str(found->room_id)),
                                 json_member("servers", json_arr(std::move(servers))),
                             })));
    }
    // GET /_matrix/client/v3/directory/list/room/{roomId}
    // Returns whether the room is listed in the public room directory.
    // Spec: unauthenticated; 404 M_NOT_FOUND if room is unknown.
    if (req.method == "GET" && starts_with(request_path, directory_list_room_prefix))
    {
        auto const room_id =
            core::percent_decode_path_component(request_path.substr(directory_list_room_prefix.size()));
        auto const room_it = std::ranges::find_if(rt.homeserver.database.rooms, [&room_id](LocalRoom const& r) {
            return r.room_id == room_id;
        });
        if (room_it == rt.homeserver.database.rooms.end())
        {
            return dispatch_err(req, rt, 404U, "M_NOT_FOUND", "room not found");
        }
        auto const vis = std::string_view{room_it->directory_public ? "public" : "private"};
        return dispatch_resp(req, rt, 200U, json_serialize(json_obj({json_member("visibility", json_str(vis))})));
    }

    if (req.method == "GET" && request_path == "/_matrix/client/v3/register/available")
    {
        auto const username = query_param_value(req.target, "username");
        if (!username.has_value() || username->empty())
        {
            return dispatch_err(req, rt, 400U, "M_MISSING_PARAM", "username is required");
        }
        if (!auth::localpart_is_valid_new(*username))
        {
            return dispatch_err(req, rt, 400U, "M_INVALID_USERNAME", "desired username is not valid");
        }
        auto const user_id = matrix_user_id(rt.homeserver.config.server().server_name, *username);
        if (user_exists(rt, user_id))
        {
            return dispatch_err(req, rt, 400U, "M_USER_IN_USE", "desired username is already taken");
        }
        return dispatch_resp(req, rt, 200U,
                             json_serialize(json_obj({json_member("available", canonicaljson::Value{true})})));
    }

    if (req.method == "GET" && request_path == "/_matrix/client/v1/register/m.login.registration_token/validity")
    {
        auto const token = query_param_value(req.target, "token");
        if (!token.has_value() || token->empty())
        {
            return dispatch_err(req, rt, 400U, "M_MISSING_PARAM", "token is required");
        }
        // Compare via the Argon2id hash rather than holding the plaintext token on
        // the request path (matches /register).  Only the hash is consulted; a missing
        // or unreadable token file means no token is configured -> valid:false.
        auto const expected_hash = load_hashed_registration_token(rt.homeserver.config.security().registration);
        auto const valid = expected_hash.has_value() && registration_token_matches(*expected_hash, *token);
        return dispatch_resp(req, rt, 200U,
                             json_serialize(json_obj({json_member("valid", canonicaljson::Value{valid})})));
    }

    if (req.method == "POST" && req.target == "/_matrix/client/v3/register/email/requestToken")
    {
        auto const body = parse_register_email_request_body(req.body);
        if (!body.has_value())
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON",
                                "email validation body must contain client_secret, email, and send_attempt");
        }
        if (!client_secret_is_valid(body->client_secret))
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "client_secret must match the Matrix grammar");
        }
        if (!email_address_is_valid(body->email))
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "email must be a plausible address");
        }
        auto* session = ensure_registration_validation_session(
            rt, "register", "email", normalize_threepid_address("email", body->email), body->client_secret,
            req.remote_addr, body->send_attempt, body->next_link);
        if (session == nullptr)
        {
            return dispatch_err(req, rt, 429U, "M_LIMIT_EXCEEDED", "too many outstanding validation sessions");
        }
        return dispatch_resp(req, rt, 200U, json_serialize(json_obj({json_member("sid", json_str(session->sid))})));
    }

    if (req.method == "POST" && req.target == "/_matrix/client/v3/register/msisdn/requestToken")
    {
        auto const body = parse_register_msisdn_request_body(req.body);
        if (!body.has_value())
        {
            return dispatch_err(
                req, rt, 400U, "M_BAD_JSON",
                "msisdn validation body must contain client_secret, country, phone_number, and send_attempt");
        }
        if (!client_secret_is_valid(body->client_secret))
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "client_secret must match the Matrix grammar");
        }
        if (!country_code_is_valid(body->country))
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "country must be a two-letter uppercase code");
        }
        if (!phone_number_is_valid(body->phone_number))
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "phone_number must not be empty");
        }
        auto* session = ensure_registration_validation_session(
            rt, "register", "msisdn", normalize_threepid_address("msisdn", body->phone_number), body->client_secret,
            req.remote_addr, body->send_attempt, body->next_link, body->country);
        if (session == nullptr)
        {
            return dispatch_err(req, rt, 429U, "M_LIMIT_EXCEEDED", "too many outstanding validation sessions");
        }
        return dispatch_resp(req, rt, 200U, json_serialize(json_obj({json_member("sid", json_str(session->sid))})));
    }

    if (req.method == "POST" && req.target == "/_matrix/client/v3/register")
    {
        auto const registration_object = parsed_json_object(req.body);
        if (!registration_object.has_value())
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "registration body must be Matrix JSON");
        }
        // Spec §5.5.1: UIA is only required when the server is configured to
        // require a registration token. When require_token is false the client
        // may register without any auth block.
        auto const require_token = rt.homeserver.config.security().registration.require_token;
        if (require_token)
        {
            // Per spec v1.18 §5.5.1, incomplete credentials MUST receive 401
            // with the challenge — not proceed to registration and fail 403.
            auto const uia_challenge = json_obj({
                json_member(
                    "flows",
                    json_arr({json_obj({json_member("stages", json_arr({json_str("m.login.registration_token")}))})})),
                json_member("params", json_obj({})),
                json_member("session", json_str("merovingian-ui-auth")),
            });
            auto const* auth = object_member_object(*registration_object, "auth");
            if (auth == nullptr)
            {
                return dispatch_resp(req, rt, 401U, json_serialize(uia_challenge));
            }
            auto const* auth_type = string_member(*auth, "type");
            if (auth_type == nullptr || *auth_type != "m.login.registration_token")
            {
                return dispatch_resp(req, rt, 401U, json_serialize(uia_challenge));
            }
            if (string_member(*auth, "token") == nullptr)
            {
                return dispatch_resp(req, rt, 401U, json_serialize(uia_challenge));
            }
        }
        auto const body = parse_register_body(req.body);
        if (!body.has_value())
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "registration body must contain username and password");
        }
        if (!auth::localpart_is_valid_new(body->localpart))
        {
            return dispatch_err(req, rt, 400U, "M_INVALID_USERNAME", "desired username is not valid");
        }
        auto const result =
            register_local_user(rt.homeserver, body->localpart, body->password, body->registration_token);
        if (!result.ok)
        {
            return dispatch_err(req, rt, result.status, registration_error_code(result.status, result.reason),
                                result.reason);
        }
        auto const full_user_id = result.value;
        // Spec §5.5.1: inhibit_login suppresses session creation; return only user_id.
        if (body->inhibit_login)
        {
            return dispatch_resp(req, rt, 200U,
                                 json_serialize(json_obj({json_member("user_id", json_str(full_user_id))})));
        }
        // Use the client-supplied device_id when provided; generate one otherwise.
        auto const reg_device_id = body->device_id.empty() ? generate_device_id() : body->device_id;
        auto const session = login_local_user(rt.homeserver, full_user_id, body->password, reg_device_id);
        if (!session.ok)
        {
            return dispatch_resp(req, rt, 200U,
                                 json_serialize(json_obj({json_member("user_id", json_str(full_user_id))})));
        }
        auto const reg_display_name = body->display_name.empty() ? reg_device_id : body->display_name;
        if (find_device(rt, full_user_id, reg_device_id) == nullptr)
        {
            rt.devices.push_back({full_user_id, reg_device_id, reg_display_name});
        }
        return dispatch_resp(req, rt, 200U,
                             json_serialize(json_obj({
                                 json_member("access_token", json_str(session.value)),
                                 json_member("user_id", json_str(full_user_id)),
                                 json_member("device_id", json_str(reg_device_id)),
                             })));
    }
    if (req.method == "GET" && req.target == "/_matrix/client/v3/login")
    {
        return dispatch_resp(
            req, rt, 200U,
            json_serialize(json_obj({
                json_member("flows", json_arr({json_obj({json_member("type", json_str("m.login.password"))})})),
            })));
    }
    if (req.method == "POST" && req.target == "/_matrix/client/v3/login")
    {
        auto body = parse_login_body(req.body, rt.homeserver.config.server().server_name);
        if (!body.has_value())
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "login body must be Matrix password JSON");
        }
        if (body->device_id.empty())
        {
            body->device_id = generate_device_id();
        }
        auto const result = login_local_user(rt.homeserver, body->user_id, body->password, body->device_id,
                                             body->supports_refresh_tokens);
        if (!result.ok)
        {
            return dispatch_err(req, rt, result.status, "M_FORBIDDEN", result.reason);
        }
        if (find_device(rt, body->user_id, body->device_id) == nullptr)
        {
            auto const dn = body->display_name.empty() ? body->device_id : body->display_name;
            rt.devices.push_back({body->user_id, body->device_id, dn});
        }
        auto response_body = canonicaljson::Object{
            json_member("access_token", json_str(result.value)),
            json_member("user_id", json_str(body->user_id)),
            json_member("device_id", json_str(body->device_id)),
        };
        if (body->supports_refresh_tokens)
        {
            auto const refresh_token = issue_refresh_token_for_session(rt.homeserver, body->user_id, body->device_id);
            if (!refresh_token.ok)
            {
                return dispatch_err(req, rt, refresh_token.status, "M_UNKNOWN", refresh_token.reason);
            }
            response_body.push_back(json_member("refresh_token", json_str(refresh_token.value)));
            response_body.push_back(
                json_member("expires_in_ms", json_int(rt.homeserver.config.security().access_token_lifetime_ms)));
        }
        return dispatch_resp(req, rt, 200U, json_serialize(json_obj(std::move(response_body))));
    }
    if (req.method == "POST" && req.target == "/_matrix/client/v3/refresh")
    {
        auto const body = parse_refresh_body(req.body);
        if (!body.has_value())
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "refresh body must contain refresh_token");
        }
        auto const refreshed = refresh_local_session(rt.homeserver, body->refresh_token);
        if (!refreshed.ok)
        {
            return dispatch_err(req, rt, refreshed.status, refreshed.status == 401U ? "M_UNKNOWN_TOKEN" : "M_UNKNOWN",
                                refreshed.reason);
        }
        if (find_device(rt, refreshed.user_id, refreshed.device_id) == nullptr)
        {
            rt.devices.push_back({refreshed.user_id, refreshed.device_id, refreshed.device_id});
        }
        return dispatch_resp(
            req, rt, 200U,
            json_serialize(json_obj({
                json_member("access_token", json_str(refreshed.access_token)),
                json_member("refresh_token", json_str(refreshed.refresh_token)),
                json_member("expires_in_ms", json_int(rt.homeserver.config.security().access_token_lifetime_ms)),
            })));
    }
    if (req.method == "POST" && req.target == "/_matrix/client/v3/logout")
    {
        auto const r = call_local(req);
        // actor is not yet resolved here (pre-auth gate); log token presence only
        log_diagnostic(r.status == 200U ? "account.logout.accepted" : "account.logout.rejected",
                       {
                           {"has_token", req.access_token.empty() ? "false" : "true", false},
                           {"status",    std::to_string(r.status),                    false}
        });
        return r.status == 200U
                   ? dispatch_resp(req, rt, 200U, "{}")
                   : dispatch_err(req, rt, r.status, r.status == 401U ? "M_UNKNOWN_TOKEN" : "M_UNKNOWN", r.body);
    }

    // MSC2965 OIDC discovery: Cinny and Element probe auth_metadata and
    // auth_issuer before login to detect OIDC support.  We do not implement
    // OIDC, so return 404 for the whole msc2965 namespace before the
    // access-token gate, otherwise the probes produce a misleading 401.
    if (req.method == "GET" && starts_with(req.target, "/_matrix/client/unstable/org.matrix.msc2965/"))
    {
        return dispatch_err(req, rt, 404U, "M_UNRECOGNIZED", "OIDC not supported");
    }
    if (req.method == "GET" && request_path == "/_matrix/client/v1/auth_metadata")
    {
        return dispatch_err(req, rt, 404U, "M_UNRECOGNIZED", "OIDC not supported");
    }

    auto constexpr media_download_prefix = std::string_view{"/_matrix/media/v3/download/"};
    if (req.method == "GET" && starts_with(req.target, media_download_prefix))
    {
        return media_download_dispatch_result(req, rt, call_local(req));
    }

    // GET /_matrix/media/v3/thumbnail/{serverName}/{mediaId}
    // GET /_matrix/client/v1/media/thumbnail/{serverName}/{mediaId}
    // Media thumbnail for locally stored content. Both the unauthenticated v3
    // endpoint and the authenticated v1 endpoint delegate to the local router.
    auto constexpr media_v3_thumbnail_prefix = std::string_view{"/_matrix/media/v3/thumbnail/"};
    auto constexpr media_v1_thumbnail_prefix = std::string_view{"/_matrix/client/v1/media/thumbnail/"};
    if (req.method == "GET" &&
        (starts_with(req.target, media_v3_thumbnail_prefix) || starts_with(req.target, media_v1_thumbnail_prefix)))
    {
        return media_download_dispatch_result(req, rt, call_local(req));
    }

    // GET /_matrix/client/v1/media/download/{serverName}/{mediaId}
    // Authenticated media download. Delegates to the local router.
    auto constexpr media_v1_download_prefix = std::string_view{"/_matrix/client/v1/media/download/"};
    if (req.method == "GET" && starts_with(req.target, media_v1_download_prefix))
    {
        return media_download_dispatch_result(req, rt, call_local(req));
    }

    // GET /_matrix/client/v3/profile/{userId}            (getUserProfile)
    // GET /_matrix/client/v3/profile/{userId}/{keyName}   (getProfileField)
    // Unauthenticated — served before the access-token gate. Returns 404
    // when the user does not exist on this server.
    auto constexpr profile_prefix = std::string_view{"/_matrix/client/v3/profile/"};
    if (req.method == "GET" && starts_with(req.target, profile_prefix))
    {
        auto const path_remainder = std::string_view{req.target}.substr(profile_prefix.size());
        // A sub-path selects a single profile field (Matrix getProfileField);
        // no sub-path returns the whole profile object (getUserProfile).
        auto const slash = path_remainder.find('/');
        auto const encoded_target = slash == std::string_view::npos ? path_remainder : path_remainder.substr(0U, slash);
        auto const field = slash == std::string_view::npos ? std::string_view{} : path_remainder.substr(slash + 1U);
        auto const target_user = core::percent_decode_path_component(encoded_target);
        auto const& store = rt.homeserver.database.persistent_store;
        auto const user_exists = std::ranges::any_of(store.users, [&target_user](database::PersistentUser const& u) {
            return u.user_id == target_user;
        });
        if (!user_exists)
        {
            return dispatch_err(req, rt, 404U, "M_NOT_FOUND", "user not found");
        }
        auto const profile = database::find_profile(store, target_user);
        auto const displayname = profile.has_value() ? profile->displayname : std::string{};
        auto const avatar_url = profile.has_value() ? profile->avatar_url : std::string{};
        if (field.empty())
        {
            return dispatch_resp(req, rt, 200U,
                                 json_serialize(json_obj({
                                     json_member("displayname", json_str(displayname)),
                                     json_member("avatar_url", json_str(avatar_url)),
                                 })));
        }
        // getProfileField returns only the requested key; an unset or unknown
        // field is reported as 404 M_NOT_FOUND per the Matrix spec.
        if (field == "displayname" && !displayname.empty())
        {
            return dispatch_resp(req, rt, 200U,
                                 json_serialize(json_obj({json_member("displayname", json_str(displayname))})));
        }
        if (field == "avatar_url" && !avatar_url.empty())
        {
            return dispatch_resp(req, rt, 200U,
                                 json_serialize(json_obj({json_member("avatar_url", json_str(avatar_url))})));
        }
        return dispatch_err(req, rt, 404U, "M_NOT_FOUND", "profile field not found");
    }

    if (req.method == "POST" && req.target == "/_matrix/client/v3/account/3pid/email/requestToken")
    {
        auto const body = parse_register_email_request_body(req.body);
        if (!body.has_value())
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON",
                                "email validation body must contain client_secret, email, and send_attempt");
        }
        if (!client_secret_is_valid(body->client_secret))
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "client_secret must match the Matrix grammar");
        }
        if (!email_address_is_valid(body->email))
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "email must be a plausible address");
        }
        auto const normalized_address = normalize_threepid_address("email", body->email);
        if (threepid_in_use(rt, "email", normalized_address))
        {
            return dispatch_err(req, rt, 400U, "M_THREEPID_IN_USE",
                                "third-party identifier is already associated with an account");
        }
        auto* session =
            ensure_registration_validation_session(rt, "account-3pid", "email", normalized_address, body->client_secret,
                                                   req.remote_addr, body->send_attempt, body->next_link);
        if (session == nullptr)
        {
            return dispatch_err(req, rt, 429U, "M_LIMIT_EXCEEDED", "too many outstanding validation sessions");
        }
        return dispatch_resp(req, rt, 200U, json_serialize(json_obj({json_member("sid", json_str(session->sid))})));
    }

    if (req.method == "POST" && req.target == "/_matrix/client/v3/account/3pid/msisdn/requestToken")
    {
        auto const body = parse_register_msisdn_request_body(req.body);
        if (!body.has_value())
        {
            return dispatch_err(
                req, rt, 400U, "M_BAD_JSON",
                "msisdn validation body must contain client_secret, country, phone_number, and send_attempt");
        }
        if (!client_secret_is_valid(body->client_secret))
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "client_secret must match the Matrix grammar");
        }
        if (!country_code_is_valid(body->country))
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "country must be a two-letter uppercase code");
        }
        if (!phone_number_is_valid(body->phone_number))
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "phone_number must not be empty");
        }
        auto const normalized_address = normalize_threepid_address("msisdn", body->phone_number);
        if (threepid_in_use(rt, "msisdn", normalized_address))
        {
            return dispatch_err(req, rt, 400U, "M_THREEPID_IN_USE",
                                "third-party identifier is already associated with an account");
        }
        auto* session = ensure_registration_validation_session(rt, "account-3pid", "msisdn", normalized_address,
                                                               body->client_secret, req.remote_addr, body->send_attempt,
                                                               body->next_link, body->country);
        if (session == nullptr)
        {
            return dispatch_err(req, rt, 429U, "M_LIMIT_EXCEEDED", "too many outstanding validation sessions");
        }
        return dispatch_resp(req, rt, 200U, json_serialize(json_obj({json_member("sid", json_str(session->sid))})));
    }

    auto const user = auth(rt, req.access_token);
    if (!user.has_value())
    {
        log_diagnostic("request.auth.rejected", {
                                                    {"method", req.method,                                       false},
                                                    {"target", observability::sanitized_http_target(req.target), false},
                                                    {"status", "401",                                            false},
                                                    {"reason", "unauthenticated",                                false}
        });
        // Spec §5.7.2: M_MISSING_TOKEN when no token is supplied; M_UNKNOWN_TOKEN otherwise.
        // When the token was found-but-expired the client still holds a valid refresh
        // token: include soft_logout=true so it uses /refresh rather than clearing its
        // session entirely (spec §5.7.2).
        auto const errcode = req.access_token.empty() ? "M_MISSING_TOKEN" : "M_UNKNOWN_TOKEN";
        if (!req.access_token.empty() && access_token_is_soft_logout(rt.homeserver, req.access_token))
        {
            return dispatch_err_soft_logout(req, rt, 401U, errcode, "unauthenticated");
        }
        return dispatch_err(req, rt, 401U, errcode, "unauthenticated");
    }
    log_diagnostic("request.auth.accepted", {
                                                {"method", req.method,                                       false},
                                                {"target", observability::sanitized_http_target(req.target), false},
                                                {"actor",  *user,                                            false}
    });
    // Account moderation request-path gate (spec v1.18 §"Account locking" /
    // §"Account suspension"). Enforced after authentication succeeds and before
    // route dispatch. Tokens are NOT revoked — the spec says locking/suspending
    // keep existing sessions intact; enforcement is per-request.
    auto const account_state = account_state_for_user(rt.homeserver, *user);
    if (account_state.has_value())
    {
        // Locked: M_USER_LOCKED with soft_logout:true on all but POST /logout
        // and POST /logout/all (spec MUST). Locked takes precedence over
        // suspended.
        if (*account_state == auth::AccountState::locked &&
            !((req.method == "POST" && request_path == "/_matrix/client/v3/logout") ||
              (req.method == "POST" && request_path == "/_matrix/client/v3/logout/all")))
        {
            log_diagnostic_audit(rt.homeserver.database, "auth", "request.user_locked",
                                 {
                                     {"actor",  *user,                                            false},
                                     {"target", observability::sanitized_http_target(req.target), false},
                                     {"status", "401",                                            false}
            },
                                 observability::LogEventSeverity::warning, observability::AuditCategory::auth,
                                 "request.user_locked", *user, std::string{*user}, "account locked");
            auto const body = json_serialize(json_obj({
                json_member("errcode", json_str("M_USER_LOCKED")),
                json_member("error", json_str("This account has been locked")),
                json_member("soft_logout", json_bool(true)),
            }));
            return dispatch_resp(req, rt, 401U, std::move(body));
        }
        // Suspended: M_USER_SUSPENDED on actions outside the spec's allowlist.
        if (*account_state == auth::AccountState::suspended &&
            !action_allowed_while_suspended(req.method, request_path))
        {
            log_diagnostic_audit(rt.homeserver.database, "auth", "request.user_suspended",
                                 {
                                     {"actor",  *user,                                            false},
                                     {"target", observability::sanitized_http_target(req.target), false},
                                     {"status", "403",                                            false}
            },
                                 observability::LogEventSeverity::warning, observability::AuditCategory::auth,
                                 "request.user_suspended", *user, std::string{*user}, "account suspended");
            return dispatch_err(req, rt, 403U, "M_USER_SUSPENDED", "You cannot perform this action while suspended.");
        }
    }
    if (req.method == "POST" && req.target == "/_matrix/client/v3/logout/all")
    {
        auto const r = logout_all_local_user(rt.homeserver, req.access_token);
        log_diagnostic(r.ok ? "account.logout_all.accepted" : "account.logout_all.rejected",
                       {
                           {"actor",  *user,                    false},
                           {"status", std::to_string(r.status), false}
        });
        return r.ok ? dispatch_resp(req, rt, 200U, "{}")
                    : dispatch_err(req, rt, r.status, r.status == 401U ? "M_UNKNOWN_TOKEN" : "M_UNKNOWN", r.reason);
    }
    if (req.method == "GET" && req.target == "/_matrix/client/v3/account/whoami")
    {
        auto const whoami_device = authenticated_request_device_id(rt, req.access_token);
        log_diagnostic("account.whoami", {
                                             {"actor", *user, false}
        });
        return dispatch_resp(req, rt, 200U,
                             json_serialize(json_obj({
                                 json_member("user_id", json_str(*user)),
                                 json_member("device_id", json_str(whoami_device)),
                             })));
    }
    if (req.method == "PUT" && starts_with(request_path, directory_room_prefix))
    {
        auto const body = parsed_json_object(req.body);
        if (!body.has_value())
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "directory body must be a JSON object");
        }
        auto const* room_id = string_member(*body, "room_id");
        if (room_id == nullptr || room_id->empty())
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "room_id is required");
        }
        auto const room = std::ranges::find_if(rt.homeserver.database.rooms, [room_id](LocalRoom const& current) {
            return current.room_id == *room_id;
        });
        if (room == rt.homeserver.database.rooms.end())
        {
            return dispatch_err(req, rt, 404U, "M_NOT_FOUND", "room not found");
        }
        if (!joined(*room, *user))
        {
            return dispatch_err(req, rt, 403U, "M_FORBIDDEN", "user is not a member of this room");
        }
        auto const room_alias = core::percent_decode_path_component(request_path.substr(directory_room_prefix.size()));
        auto const existing = database::find_room_alias(rt.homeserver.database.persistent_store, room_alias);
        if (existing.has_value())
        {
            return existing->room_id == *room_id
                       ? dispatch_resp(req, rt, 200U, "{}")
                       : dispatch_err(req, rt, 409U, "M_ROOM_IN_USE", "room alias already in use");
        }
        if (!database::store_room_alias(rt.homeserver.database.persistent_store, {room_alias, *room_id}))
        {
            return dispatch_err(req, rt, 500U, "M_UNKNOWN", "failed to persist room alias");
        }
        return dispatch_resp(req, rt, 200U, "{}");
    }
    // PUT /_matrix/client/v3/directory/list/room/{roomId}
    // Sets whether the room appears in the public room directory.
    // Spec: caller must be joined to the room; 400 if visibility is missing/invalid.
    if (req.method == "PUT" && starts_with(request_path, directory_list_room_prefix))
    {
        auto const body = parsed_json_object(req.body);
        if (!body.has_value())
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "body must be a JSON object");
        }
        auto const* vis_str = string_member(*body, "visibility");
        if (vis_str == nullptr || (*vis_str != "public" && *vis_str != "private"))
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "visibility must be 'public' or 'private'");
        }
        auto const room_id =
            core::percent_decode_path_component(request_path.substr(directory_list_room_prefix.size()));
        auto const room_it = std::ranges::find_if(rt.homeserver.database.rooms, [&room_id](LocalRoom const& r) {
            return r.room_id == room_id;
        });
        if (room_it == rt.homeserver.database.rooms.end())
        {
            return dispatch_err(req, rt, 404U, "M_NOT_FOUND", "room not found");
        }
        if (!joined(*room_it, *user))
        {
            return dispatch_err(req, rt, 403U, "M_FORBIDDEN", "user is not a member of the room");
        }
        room_it->directory_public = (*vis_str == "public");
        return dispatch_resp(req, rt, 200U, "{}");
    }
    if (req.method == "POST" && req.target == "/_matrix/client/v3/account/password")
    {
        auto const object = parsed_json_object(req.body);
        if (!object.has_value())
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "password change body must be JSON");
        }
        auto const* new_password = string_member(*object, "new_password");
        if (new_password == nullptr || new_password->empty())
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "new_password is required");
        }
        // Spec §5.5 (UIA): POST /account/password requires m.login.password to
        // prove account ownership. A missing, incomplete, or wrong-credential
        // auth block must return 401 with the UIA challenge — not 403.
        auto const uia_challenge = json_obj({
            json_member("flows",
                        json_arr({json_obj({json_member("stages", json_arr({json_str("m.login.password")}))})})),
            json_member("params", json_obj({})),
            json_member("session", json_str("password_change")),
        });
        auto const* auth = object_member_object(*object, "auth");
        if (auth == nullptr)
        {
            return dispatch_resp(req, rt, 401U, json_serialize(uia_challenge));
        }
        auto const* auth_type = string_member(*auth, "type");
        if (auth_type == nullptr || *auth_type != "m.login.password")
        {
            return dispatch_resp(req, rt, 401U, json_serialize(uia_challenge));
        }
        auto const* current_password = string_member(*auth, "password");
        if (current_password == nullptr || current_password->empty())
        {
            return dispatch_resp(req, rt, 401U, json_serialize(uia_challenge));
        }
        if (!verify_local_user_password(rt.homeserver, req.access_token, *current_password))
        {
            return dispatch_resp(req, rt, 401U, json_serialize(uia_challenge));
        }
        // Spec §5.5: logout_devices defaults to true — the server MUST revoke the
        // access tokens of the user's other devices when the password changes. The
        // caller's own session survives. Explicit false preserves other devices.
        auto const* logout_devices_member = boolean_member(*object, "logout_devices");
        auto const logout_devices = logout_devices_member == nullptr ? true : *logout_devices_member;
        auto const result = change_local_user_password(rt.homeserver, req.access_token, *new_password, logout_devices);
        if (!result.ok)
        {
            return dispatch_err(req, rt, result.status, result.status == 401U ? "M_UNKNOWN_TOKEN" : "M_FORBIDDEN",
                                result.reason);
        }
        return dispatch_resp(req, rt, 200U, "{}");
    }
    if (req.method == "GET" && req.target == "/_matrix/client/v3/account/3pid")
    {
        auto threepids = canonicaljson::Array{};
        for (auto const& record : rt.account_threepids)
        {
            if (record.user_id != *user)
            {
                continue;
            }
            threepids.push_back(json_obj({
                json_member("added_at", json_int(static_cast<std::int64_t>(record.added_at_ms))),
                json_member("address", json_str(record.address)),
                json_member("medium", json_str(record.medium)),
                json_member("validated_at", json_int(static_cast<std::int64_t>(record.validated_at_ms))),
            }));
        }
        return dispatch_resp(req, rt, 200U,
                             json_serialize(json_obj({json_member("threepids", json_arr(std::move(threepids)))})));
    }
    if (req.method == "POST" && req.target == "/_matrix/client/v3/account/3pid/add")
    {
        auto const body = parse_account_threepid_add_body(req.body);
        if (!body.has_value())
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "3PID add body must contain client_secret and sid");
        }
        auto const uia_challenge = json_obj({
            json_member("flows",
                        json_arr({json_obj({json_member("stages", json_arr({json_str("m.login.password")}))})})),
            json_member("params", json_obj({})),
            json_member("session", json_str("account_threepid_add")),
        });
        if (!body->password.has_value() ||
            !verify_local_user_password(rt.homeserver, req.access_token, *body->password))
        {
            return dispatch_resp(req, rt, 401U, json_serialize(uia_challenge));
        }
        auto* session = find_registration_validation_session_by_sid(rt, "account-3pid", body->sid, body->client_secret);
        if (session == nullptr)
        {
            return dispatch_err(req, rt, 400U, "M_SESSION_NOT_VALIDATED", "validation session not found");
        }
        if (threepid_in_use(rt, session->medium, session->address, *user))
        {
            return dispatch_err(req, rt, 400U, "M_THREEPID_IN_USE",
                                "third-party identifier is already associated with an account");
        }
        std::ignore = ensure_account_threepid(
            rt, *user, session->medium, session->address,
            session->country.has_value() ? std::optional<std::string_view>{*session->country} : std::nullopt,
            session->validated_at_ms);
        return dispatch_resp(req, rt, 200U, "{}");
    }
    if (req.method == "POST" && req.target == "/_matrix/client/v3/account/3pid/bind")
    {
        auto const body = parse_account_threepid_bind_body(req.body);
        if (!body.has_value())
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON",
                                "3PID bind body must contain client_secret, sid, id_server, and id_access_token");
        }
        auto* session = find_registration_validation_session_by_sid(rt, "account-3pid", body->sid, body->client_secret);
        if (session == nullptr)
        {
            return dispatch_err(req, rt, 400U, "M_SESSION_NOT_VALIDATED", "validation session not found");
        }
        if (threepid_in_use(rt, session->medium, session->address, *user))
        {
            return dispatch_err(req, rt, 400U, "M_THREEPID_IN_USE",
                                "third-party identifier is already associated with an account");
        }
        auto& record = ensure_account_threepid(
            rt, *user, session->medium, session->address,
            session->country.has_value() ? std::optional<std::string_view>{*session->country} : std::nullopt,
            session->validated_at_ms);
        record.id_server = body->id_server;
        record.bound = true;
        return dispatch_resp(req, rt, 200U, "{}");
    }
    if (req.method == "POST" && req.target == "/_matrix/client/v3/account/3pid")
    {
        auto const object = parsed_json_object(req.body);
        auto const* creds = object.has_value() ? object_member_object(*object, "three_pid_creds") : nullptr;
        if (creds == nullptr)
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "three_pid_creds is required");
        }
        auto const* client_secret = string_member(*creds, "client_secret");
        auto const* sid = string_member(*creds, "sid");
        auto const* id_server = string_member(*creds, "id_server");
        auto const* id_access_token = string_member(*creds, "id_access_token");
        if (client_secret == nullptr || sid == nullptr || id_server == nullptr || id_access_token == nullptr ||
            client_secret->empty() || sid->empty() || id_server->empty() || id_access_token->empty())
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "three_pid_creds must be complete");
        }
        auto* session = find_registration_validation_session_by_sid(rt, "account-3pid", *sid, *client_secret);
        if (session == nullptr)
        {
            return dispatch_err(req, rt, 400U, "M_SESSION_NOT_VALIDATED", "validation session not found");
        }
        if (threepid_in_use(rt, session->medium, session->address, *user))
        {
            return dispatch_err(req, rt, 400U, "M_THREEPID_IN_USE",
                                "third-party identifier is already associated with an account");
        }
        auto& record = ensure_account_threepid(
            rt, *user, session->medium, session->address,
            session->country.has_value() ? std::optional<std::string_view>{*session->country} : std::nullopt,
            session->validated_at_ms);
        record.id_server = *id_server;
        record.bound = true;
        return dispatch_resp(req, rt, 200U, "{}");
    }
    if (req.method == "POST" && req.target == "/_matrix/client/v3/account/3pid/unbind")
    {
        auto const body = parse_account_threepid_delete_body(req.body);
        if (!body.has_value())
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "3PID unbind body must contain address and medium");
        }
        auto const normalized_address = normalize_threepid_address(body->medium, body->address);
        auto* record = find_account_threepid(rt, *user, body->medium, normalized_address);
        auto const result = threepid_unbind_result(
            record, body->id_server.has_value() ? std::optional<std::string_view>{*body->id_server} : std::nullopt);
        if (record != nullptr && result == "success")
        {
            record->bound = false;
            record->id_server.reset();
        }
        return dispatch_resp(req, rt, 200U,
                             json_serialize(json_obj({json_member("id_server_unbind_result", json_str(result))})));
    }
    if (req.method == "POST" && req.target == "/_matrix/client/v3/account/3pid/delete")
    {
        auto const body = parse_account_threepid_delete_body(req.body);
        if (!body.has_value())
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "3PID delete body must contain address and medium");
        }
        auto const normalized_address = normalize_threepid_address(body->medium, body->address);
        auto* record = find_account_threepid(rt, *user, body->medium, normalized_address);
        auto const result = threepid_unbind_result(
            record, body->id_server.has_value() ? std::optional<std::string_view>{*body->id_server} : std::nullopt);
        std::erase_if(rt.account_threepids, [&](AccountThreePid const& current) {
            return current.user_id == *user && current.medium == body->medium && current.address == normalized_address;
        });
        return dispatch_resp(req, rt, 200U,
                             json_serialize(json_obj({json_member("id_server_unbind_result", json_str(result))})));
    }
    // Spec: GET /pushers returns the push notification pushers for the
    // authenticated user. Merovingian does not yet support push
    // subscriptions, so return the spec-required empty list so Element's
    // settings UI does not show a spurious error.
    if (req.method == "GET" && req.target == "/_matrix/client/v3/pushers")
    {
        return dispatch_resp(req, rt, 200U, R"({"pushers":[]})");
    }
    // Clients (Cinny, Element) fetch /capabilities immediately after login to
    // discover what the server supports. Return a minimal stable set; extend
    // as features are implemented.
    if (req.method == "GET" && req.target == "/_matrix/client/v3/capabilities")
    {
        return dispatch_resp(
            req, rt, 200U,
            json_serialize(json_obj(
                {json_member("capabilities",
                             json_obj({
                                 json_member("m.change_password", json_obj({json_member("enabled", json_bool(true))})),
                                 json_member("m.3pid_changes", json_obj({json_member("enabled", json_bool(true))})),
                                 json_member("m.room_versions",
                                             json_obj({
                                                 json_member("default", json_str("12")),
                                                 json_member("available", json_obj({
                                                                              json_member("10", json_str("stable")),
                                                                              json_member("11", json_str("stable")),
                                                                              json_member("12", json_str("stable")),
                                                                          })),
                                             })),
                             }))})));
    }
    // GET /_matrix/client/v3/thirdparty/protocols
    // Spec: CS API v1.18 §third party networks — returns the third-party
    // protocols the server supports as a (possibly empty) JSON object. Merovingian
    // runs no application services, so the map is empty. Returning 404 here made
    // clients (Element) log repeated "Failed to check for protocol support"
    // errors and retry; an empty 200 object is the conformant answer.
    if (req.method == "GET" && request_path == "/_matrix/client/v3/thirdparty/protocols")
    {
        return dispatch_resp(req, rt, 200U, "{}");
    }
    // Clients fetch /pushrules immediately after login to load the
    // server-default rules defined by Matrix v1.18.
    if (req.method == "GET" && request_path == "/_matrix/client/v3/pushrules/")
    {
        auto const ruleset = default_push_ruleset(*user);
        return dispatch_resp(req, rt, 200U, json_serialize(json_obj({json_member("global", json_obj(ruleset))})));
    }
    auto constexpr pushrules_global_prefix = std::string_view{"/_matrix/client/v3/pushrules/global/"};
    if (req.method == "GET" && request_path == pushrules_global_prefix)
    {
        auto const ruleset = default_push_ruleset(*user);
        return dispatch_resp(req, rt, 200U, json_serialize(json_obj(ruleset)));
    }
    if (req.method == "GET" && starts_with(request_path, pushrules_global_prefix))
    {
        auto const suffix = request_path.substr(pushrules_global_prefix.size());
        auto const first_separator = suffix.find('/');
        if (first_separator == std::string_view::npos)
        {
            return dispatch_err(req, rt, 404U, "M_NOT_FOUND", "push rule not found");
        }
        auto const kind = suffix.substr(0U, first_separator);
        auto const remainder = suffix.substr(first_separator + 1U);
        auto const action_suffix = std::string_view{"/actions"};
        auto const enabled_suffix = std::string_view{"/enabled"};
        auto const is_actions = remainder.size() > action_suffix.size() && ends_with(remainder, action_suffix);
        auto const is_enabled =
            !is_actions && remainder.size() > enabled_suffix.size() && ends_with(remainder, enabled_suffix);
        auto const rule_segment =
            is_actions ? remainder.substr(0U, remainder.size() - action_suffix.size())
                       : (is_enabled ? remainder.substr(0U, remainder.size() - enabled_suffix.size()) : remainder);
        auto const rule_id = core::percent_decode_path_component(rule_segment);
        auto const ruleset = default_push_ruleset(*user);
        auto const* rule = push_rule_object(ruleset, kind, rule_id);
        if (rule == nullptr)
        {
            return dispatch_err(req, rt, 404U, "M_NOT_FOUND", "push rule not found");
        }
        if (is_actions)
        {
            auto const action_member = std::ranges::find_if(*rule, [](canonicaljson::ObjectMember const& member) {
                return member.key == "actions";
            });
            if (action_member == rule->end())
            {
                return dispatch_err(req, rt, 500U, "M_UNKNOWN", "push rule actions missing");
            }
            auto const* actions = std::get_if<canonicaljson::Array>(&action_member->value->storage());
            return actions == nullptr
                       ? dispatch_err(req, rt, 500U, "M_UNKNOWN", "push rule actions missing")
                       : dispatch_resp(
                             req, rt, 200U,
                             json_serialize(json_obj({json_member("actions", canonicaljson::Value{*actions})})));
        }
        if (is_enabled)
        {
            auto const enabled_member = std::ranges::find_if(*rule, [](canonicaljson::ObjectMember const& member) {
                return member.key == "enabled";
            });
            if (enabled_member == rule->end())
            {
                return dispatch_err(req, rt, 500U, "M_UNKNOWN", "push rule enabled flag missing");
            }
            auto const* enabled = std::get_if<bool>(&enabled_member->value->storage());
            return enabled == nullptr
                       ? dispatch_err(req, rt, 500U, "M_UNKNOWN", "push rule enabled flag missing")
                       : dispatch_resp(req, rt, 200U,
                                       json_serialize(json_obj({json_member("enabled", json_bool(*enabled))})));
        }
        return dispatch_resp(req, rt, 200U, json_serialize(json_obj(*rule)));
    }
    // PUT /_matrix/client/v3/profile/{userId}/displayname
    // PUT /_matrix/client/v3/profile/{userId}/avatar_url
    // Both endpoints require the authenticated user to match the path userId.
    auto constexpr profile_put_prefix = std::string_view{"/_matrix/client/v3/profile/"};
    if (req.method == "PUT" && starts_with(req.target, profile_put_prefix))
    {
        auto const path_remainder = std::string_view{req.target}.substr(profile_put_prefix.size());
        auto constexpr displayname_suffix = std::string_view{"/displayname"};
        auto constexpr avatar_url_suffix = std::string_view{"/avatar_url"};
        auto const is_displayname = path_remainder.ends_with(displayname_suffix);
        auto const is_avatar_url = !is_displayname && path_remainder.ends_with(avatar_url_suffix);
        if (is_displayname || is_avatar_url)
        {
            auto const sub_len = is_displayname ? displayname_suffix.size() : avatar_url_suffix.size();
            auto const encoded_target = path_remainder.substr(0U, path_remainder.size() - sub_len);
            auto const target_user = core::percent_decode_path_component(encoded_target);
            if (target_user != *user)
            {
                return dispatch_err(req, rt, 403U, "M_FORBIDDEN", "cannot update another user's profile");
            }
            auto const parsed = canonicaljson::parse_lossless(req.body);
            auto const* obj = std::get_if<canonicaljson::Object>(&parsed.value.storage());
            if (parsed.error != canonicaljson::ParseError::none || obj == nullptr)
            {
                return dispatch_err(req, rt, 400U, "M_BAD_JSON", "profile update body must be a JSON object");
            }
            auto& store = rt.homeserver.database.persistent_store;
            if (!database::find_profile(store, *user).has_value())
            {
                std::ignore = database::store_profile(store, {*user, {}, {}});
            }
            if (is_displayname)
            {
                auto const* val = string_member(*obj, "displayname");
                std::ignore = database::update_profile_displayname(store, *user, val != nullptr ? *val : "");
            }
            else
            {
                auto const* val = string_member(*obj, "avatar_url");
                std::ignore = database::update_profile_avatar_url(store, *user, val != nullptr ? *val : "");
            }
            return dispatch_resp(req, rt, 200U, "{}");
        }
    }

    // GET /_matrix/media/v3/config
    // GET /_matrix/client/v1/media/config
    // Reports the maximum upload size so clients know how large a file they
    // may attach. The value is sourced from security.media.max_upload_size so
    // client hints match the repository policy enforced during upload.
    if (req.method == "GET" &&
        (req.target == "/_matrix/media/v3/config" || req.target == "/_matrix/client/v1/media/config"))
    {
        auto const parsed_limit = config::parse_size_limit(rt.homeserver.config.security().media.max_upload_size);
        auto const bounded_limit = std::min(parsed_limit.valid ? parsed_limit.bytes : std::uint64_t{104857600U},
                                            static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()));
        auto const max_upload_bytes = static_cast<std::int64_t>(bounded_limit);
        return dispatch_resp(req, rt, 200U,
                             json_serialize(json_obj({json_member("m.upload.size", json_int(max_upload_bytes))})));
    }
    // Matrix clients upload media as raw binary with a Content-Type header,
    // while the local router expects declared_mime|sniffed_mime|scanner_clean|bytes.
    // Both the unauthenticated v3 endpoint and the authenticated v1 endpoint need
    // the same body translation so encrypted-room attachments work regardless of
    // which path the client prefers.
    auto const is_v3_media_upload = req.method == "POST" && (req.target == "/_matrix/media/v3/upload" ||
                                                             starts_with(req.target, "/_matrix/media/v3/upload?"));
    auto const is_v1_media_upload =
        req.method == "POST" && (req.target == "/_matrix/client/v1/media/upload" ||
                                 starts_with(req.target, "/_matrix/client/v1/media/upload?"));
    if (is_v3_media_upload || is_v1_media_upload)
    {
        auto const ct = request_header(req, "Content-Type");
        auto const declared_mime = ct.empty() ? std::string_view{"application/octet-stream"} : ct;
        auto inner = req;
        inner.target = "/_matrix/media/v3/upload";
        inner.body = std::string{declared_mime} + "|" + std::string{declared_mime} + "|clean|" + req.body;
        auto const r = call_local(inner);
        // 200: stored; 202: stored but quarantined by server policy.
        // Both carry a content_uri. The Matrix spec defines only 200 for this
        // endpoint, so return 200 in both cases — quarantine is internal.
        if (r.status == 200U || r.status == 202U)
        {
            return dispatch_resp(req, rt, 200U, media_upload_response_json(r.body));
        }
        return dispatch_err(req, rt, r.status, r.status == 401U ? "M_UNKNOWN_TOKEN" : "M_BAD_REQUEST", r.body);
    }

    // GET /_matrix/client/v3/voip/turnServer
    // No TURN server is configured.  Return an empty object so clients disable
    // VoIP gracefully rather than treating a 404 as an error.
    if (req.method == "GET" && req.target == "/_matrix/client/v3/voip/turnServer")
    {
        return dispatch_resp(req, rt, 200U, "{}");
    }

    auto const key_route = auth::match_key_api_route(req.method, req.target);
    if (key_route.matched)
    {
        auto const device_id = authenticated_request_device_id(rt, req.access_token);
        return complete(handle_key_api_route(rt, key_route.route, *user, device_id, req));
    }
    if (req.method == "GET" && req.target == "/_matrix/client/v3/devices")
    {
        return dispatch_resp(req, rt, 200U, devices_json(rt, *user));
    }
    auto constexpr dev_prefix = std::string_view{"/_matrix/client/v3/devices/"};
    if (req.method == "GET" && starts_with(req.target, dev_prefix))
    {
        auto const device_id = std::string_view{req.target}.substr(dev_prefix.size());
        auto const* device = find_device(rt, *user, device_id);
        if (device == nullptr)
        {
            return dispatch_err(req, rt, 404U, "M_NOT_FOUND", "device not found");
        }
        return dispatch_resp(req, rt, 200U, device_json(*device));
    }
    if (req.method == "DELETE" && starts_with(req.target, dev_prefix))
    {
        // Spec §10.7.1: DELETE /devices/{deviceId} requires UIA with
        // m.login.password to prove account ownership before deletion.
        auto const uia_challenge = device_delete_uia_challenge("delete_device");
        auto const body_obj = parsed_json_object(req.body);
        if (!body_obj.has_value())
        {
            return dispatch_resp(req, rt, 401U, uia_challenge);
        }
        auto const* auth = object_member_object(*body_obj, "auth");
        if (auth == nullptr)
        {
            return dispatch_resp(req, rt, 401U, uia_challenge);
        }
        auto const* auth_type = string_member(*auth, "type");
        if (auth_type == nullptr || *auth_type != "m.login.password")
        {
            return dispatch_resp(req, rt, 401U, uia_challenge);
        }
        auto const* current_password = string_member(*auth, "password");
        if (current_password == nullptr || current_password->empty())
        {
            return dispatch_resp(req, rt, 401U, uia_challenge);
        }
        if (!verify_local_user_password(rt.homeserver, req.access_token, *current_password))
        {
            return dispatch_resp(req, rt, 401U, uia_challenge);
        }
        auto const device_id = std::string_view{req.target}.substr(dev_prefix.size());
        auto const result = delete_local_device(rt.homeserver, *user, device_id);
        if (!result.ok)
        {
            return dispatch_err(req, rt, result.status, result.status == 404U ? "M_NOT_FOUND" : "M_UNKNOWN",
                                result.reason);
        }
        erase_runtime_device(rt, *user, device_id);
        record_shared_room_device_change(rt, *user);
        return dispatch_resp(req, rt, 200U, "{}");
    }
    if (req.method == "POST" && req.target == "/_matrix/client/v3/delete_devices")
    {
        auto const uia_challenge = device_delete_uia_challenge("delete_devices");
        auto const body_obj = parsed_json_object(req.body);
        if (!body_obj.has_value())
        {
            return dispatch_resp(req, rt, 401U, uia_challenge);
        }
        auto const devices = string_array_member(*body_obj, "devices");
        if (devices.empty())
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "devices must be a non-empty array of device IDs");
        }
        auto const* auth = object_member_object(*body_obj, "auth");
        if (auth == nullptr)
        {
            return dispatch_resp(req, rt, 401U, uia_challenge);
        }
        auto const* auth_type = string_member(*auth, "type");
        if (auth_type == nullptr || *auth_type != "m.login.password")
        {
            return dispatch_resp(req, rt, 401U, uia_challenge);
        }
        auto const* current_password = string_member(*auth, "password");
        if (current_password == nullptr || current_password->empty())
        {
            return dispatch_resp(req, rt, 401U, uia_challenge);
        }
        if (!verify_local_user_password(rt.homeserver, req.access_token, *current_password))
        {
            return dispatch_resp(req, rt, 401U, uia_challenge);
        }
        auto deleted_any = false;
        for (auto const& device_id : devices)
        {
            auto const result = delete_local_device(rt.homeserver, *user, device_id);
            if (!result.ok)
            {
                if (result.status == 404U)
                {
                    continue;
                }
                return dispatch_err(req, rt, result.status, result.status == 400U ? "M_BAD_JSON" : "M_UNKNOWN",
                                    result.reason);
            }
            erase_runtime_device(rt, *user, device_id);
            deleted_any = true;
        }
        if (deleted_any)
        {
            record_shared_room_device_change(rt, *user);
        }
        return dispatch_resp(req, rt, 200U, "{}");
    }
    auto const safety_route = trust_safety::match_reporting_api_route(req.method, req.target);
    if (safety_route.matched)
    {
        if (safety_route.route.requires_admin && !authenticated_admin_user(rt.homeserver, req.access_token).has_value())
        {
            return dispatch_err(req, rt, 403U, "M_FORBIDDEN", "admin authentication required");
        }
        return complete(safety_route.route.requires_admin ? handle_admin_safety_route(rt, *user, req)
                                                          : handle_safety_report(rt, *user, req));
    }
    // PUT /_matrix/client/v3/sendToDevice/{eventType}/{txnId}
    // Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#put_matrixclientv3sendtoeventtypetxnid
    if (req.method == "PUT")
    {
        if (auto const path = send_to_device_path_parts(req.target); path.has_value())
        {
            return complete(handle_send_to_device(rt, path->event_type, path->txn_id, *user, req.body));
        }
    }
    // GET /_matrix/client/v3/keys/changes[?from=...&to=...]
    // Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3keyschanges
    {
        auto constexpr keys_changes_base = std::string_view{"/_matrix/client/v3/keys/changes"};
        if (req.method == "GET" && starts_with(std::string_view{req.target}, keys_changes_base))
        {
            auto const after = std::string_view{req.target}.substr(keys_changes_base.size());
            if (after.empty() || after[0] == '?')
            {
                return complete(handle_keys_changes(rt, *user, req.target));
            }
        }
    }
    if (req.method == "POST" && req.target == "/_matrix/client/v3/createRoom")
    {
        auto const body_object = req.body.empty() ? std::optional<canonicaljson::Object>{canonicaljson::Object{}}
                                                  : parsed_json_object(req.body);
        if (!body_object.has_value())
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "createRoom body must be a JSON object");
        }

        auto const& body = *body_object;
        auto const* preset_value = string_member(body, "preset");
        auto const* visibility_value = string_member(body, "visibility");
        auto const effective_preset = [&]() -> std::string {
            if (preset_value != nullptr && !preset_value->empty())
            {
                return *preset_value;
            }
            if (visibility_value != nullptr && *visibility_value == "public")
            {
                return "public_chat";
            }
            return "private_chat";
        }();
        auto const invitees = string_array_member(body, "invite");
        auto const* room_version_value = string_member(body, "room_version");
        auto const room_version =
            room_version_value != nullptr && !room_version_value->empty() ? *room_version_value : std::string{"12"};
        if (rooms::find_room_version_policy(room_version) == nullptr)
        {
            return dispatch_err(req, rt, 400U, "M_UNSUPPORTED_ROOM_VERSION", "unsupported room version");
        }
        auto const* room_alias_name = string_member(body, "room_alias_name");
        if (room_alias_name != nullptr && !room_alias_name->empty())
        {
            auto const alias = "#" + *room_alias_name + ":" + rt.homeserver.config.server().server_name;
            if (database::find_room_alias(rt.homeserver.database.persistent_store, alias).has_value())
            {
                return dispatch_err(req, rt, 400U, "M_ROOM_IN_USE", "room alias already in use");
            }
        }

        auto options = CreateRoomOptions{};
        options.room_version = room_version;
        options.preset = effective_preset;
        options.invitees = invitees;
        options.trusted_invitees = effective_preset == "trusted_private_chat" ? invitees : std::vector<std::string>{};
        options.name = string_member(body, "name") != nullptr ? *string_member(body, "name") : std::string{};
        options.topic = string_member(body, "topic") != nullptr ? *string_member(body, "topic") : std::string{};
        options.room_alias_name = room_alias_name != nullptr ? *room_alias_name : std::string{};
        options.is_direct = boolean_member(body, "is_direct") != nullptr && *boolean_member(body, "is_direct");
        if (auto const* creation_content = object_member_as_object(body, "creation_content");
            creation_content != nullptr)
        {
            options.creation_content = *creation_content;
        }
        if (auto const* power_override = object_member_as_object(body, "power_level_content_override");
            power_override != nullptr)
        {
            options.power_level_content_override = *power_override;
        }
        if (auto const* initial_state = object_member(body, "initial_state"); initial_state != nullptr)
        {
            if (auto const* array = std::get_if<canonicaljson::Array>(&initial_state->storage()); array != nullptr)
            {
                options.initial_state.assign(array->begin(), array->end());
            }
        }

        auto const create_result = create_room(rt.homeserver, req.access_token, options);
        if (!create_result.ok)
        {
            auto errcode = error_code_for_status(create_result.status);
            if (create_result.status == 400U && create_result.reason == "room alias in use")
            {
                errcode = "M_ROOM_IN_USE";
            }
            log_diagnostic("room.create.rejected", {
                                                       {"actor",  *user,                                false},
                                                       {"status", std::to_string(create_result.status), false},
                                                       {"reason", create_result.reason,                 false}
            });
            return dispatch_err(req, rt, create_result.status, errcode, create_result.reason);
        }
        auto const& room_id = create_result.value;

        for (auto const& invitee : invitees)
        {
            auto const invitee_server = server_name_from_user_id(invitee);
            if (invitee_server.empty() || invitee_server == rt.homeserver.config.server().server_name)
            {
                continue;
            }
            auto const invite_state =
                std::ranges::find_if(rt.homeserver.database.persistent_store.state,
                                     [&room_id, &invitee](database::PersistentStateEvent const& state) {
                                         return state.room_id == room_id && state.event_type == "m.room.member" &&
                                                state.state_key == invitee;
                                     });
            if (invite_state == rt.homeserver.database.persistent_store.state.end())
            {
                continue;
            }
            auto const invite_json = event_json_for_id(rt.homeserver.database.persistent_store, invite_state->event_id);
            if (!invite_json.has_value())
            {
                continue;
            }
            merovingian::homeserver::wire_federation_callbacks(rt.homeserver);
            if (rt.homeserver.dispatch_worker != nullptr)
            {
                auto transaction =
                    federation::make_outbound_invite(invitee_server, rt.homeserver.config.server().server_name, room_id,
                                                     invite_state->event_id, room_version, *invite_json, {});
                transaction.transaction_id = federation::make_federation_transaction_id();
                std::ignore = rt.homeserver.dispatch_worker->enqueue(std::move(transaction));
            }
        }
        log_diagnostic("room.create.accepted", {
                                                   {"actor",   *user,   false},
                                                   {"room_id", room_id, false}
        });
        return dispatch_resp(req, rt, 200U, json_serialize(json_obj({json_member("room_id", json_str(room_id))})));
    }
    if (req.method == "GET" && req.target == "/_matrix/client/v3/joined_rooms")
    {
        log_diagnostic("room.joined_rooms.response", {
                                                         {"actor", *user, false}
        });
        return dispatch_resp(req, rt, 200U, joined_rooms_json(rt, *user));
    }
    auto constexpr sync_prefix = std::string_view{"/_matrix/client/v3/sync"};
    if (req.method == "GET" && starts_with(req.target, sync_prefix))
    {
        // Resolve the session bound to the access token so we key the
        // per-device sync surfaces (to_device, OTK count, fallback keys)
        // on the device that actually issued the request rather than
        // whichever device happens to be first in `rt.devices`.
        auto const session = authenticated_session(rt.homeserver, req.access_token);
        auto const device_id = session.has_value() ? session->device_id : std::string{};
        auto sync_request = merovingian::core::parse_query_params(req.target);

        // Spec: Matrix Client-Server API v1.18 — GET /sync
        // URL: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3sync
        //
        // The ?filter= parameter is either an inline JSON object (starts with '{')
        // or a stored filter ID. Inline JSON is validated immediately; a filter ID
        // is resolved from the database and replaced with the stored JSON so that
        // parse_filter_argument always receives valid inline JSON.
        if (sync_request.filter.has_value() && !sync_request.filter->empty())
        {
            if (sync_request.filter->front() == '{')
            {
                auto const filter_parse = canonicaljson::parse_lossless(*sync_request.filter);
                if (filter_parse.error != canonicaljson::ParseError::none)
                {
                    return dispatch_err(req, rt, 400U, "M_BAD_JSON", "filter parameter is not valid JSON");
                }
            }
            else
            {
                // filter parameter is a stored filter ID — look it up and substitute
                // the stored JSON so downstream parsing sees an inline object.
                auto const stored =
                    database::find_filter(rt.homeserver.database.persistent_store, *user, *sync_request.filter);
                if (!stored.has_value())
                {
                    return dispatch_err(req, rt, 400U, "M_NOT_FOUND", "filter not found");
                }
                sync_request.filter = stored->json;
            }
        }

        log_diagnostic("sync.dispatch", {
                                            {"actor",     *user,     false},
                                            {"device_id", device_id, false}
        });
        return sync_json(rt, *user, device_id, sync_request, can_wait);
    }

    // MSC4186 Simplified Sliding Sync — served at both paths for client compatibility.
    // POST /_matrix/client/unstable/org.matrix.msc4186/sync
    // POST /_matrix/client/unstable/org.matrix.simplified_msc3575/sync  (matrix-rust-sdk alias)
    auto constexpr msc4186_sync_prefix = std::string_view{"/_matrix/client/unstable/org.matrix.msc4186/sync"};
    auto constexpr msc3575_sync_prefix =
        std::string_view{"/_matrix/client/unstable/org.matrix.simplified_msc3575/sync"};
    if (req.method == "POST" &&
        (starts_with(req.target, msc4186_sync_prefix) || starts_with(req.target, msc3575_sync_prefix)))
    {
        auto const session_4186 = authenticated_session(rt.homeserver, req.access_token);
        auto const device_id_4186 = session_4186.has_value() ? session_4186->device_id : std::string{};
        auto const sliding_req = sync::parse_sliding_sync_request(req.body);
        if (!sliding_req.has_value())
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "invalid sliding sync request body");
        }
        auto const pos = sync::parse_sliding_sync_pos(req.target);
        auto const timeout = sync::parse_sliding_sync_timeout(req.target).value_or(0U);
        log_diagnostic("sliding_sync.dispatch", {
                                                    {"actor",     *user,          false},
                                                    {"device_id", device_id_4186, false}
        });
        return sliding_sync_json(rt, *user, device_id_4186, *sliding_req, pos, timeout, can_wait);
    }

    // GET /_matrix/client/v1/rooms/{roomId}/relations/{eventId}[/{relType}[/{eventType}]]
    // Spec: retrieve child events that relate to the given parent event.
    auto constexpr relations_prefix = std::string_view{"/_matrix/client/v1/rooms/"};
    if (req.method == "GET" && starts_with(req.target, relations_prefix))
    {
        if (auto const path = room_relations_path_parts(req.target); path.has_value())
        {
            auto const request = FetchRelationsRequest{
                path->room_id,
                path->event_id,
                path->rel_type,
                path->event_type,
                query_param_value(req.target, "dir"),
                query_param_value(req.target, "from"),
                parse_query_uint(query_param_value(req.target, "limit")),
                parse_query_bool(query_param_value(req.target, "recurse")),
                query_param_value(req.target, "to"),
            };
            auto const result = fetch_relations(rt.homeserver, req.access_token, request);
            if (!result.ok)
            {
                auto const code =
                    result.status == 404U ? std::string_view{"M_NOT_FOUND"} : error_code_for_status(result.status);
                return dispatch_err(req, rt, result.status, code, result.reason);
            }
            return complete({200U, result.value});
        }
    }

    auto constexpr room_prefix = std::string_view{"/_matrix/client/v3/rooms/"};
    if (starts_with(req.target, room_prefix))
    {
        auto constexpr join_s = std::string_view{"/join"};
        auto constexpr send_s = std::string_view{"/send"};
        auto constexpr state_s = std::string_view{"/state"};
        auto constexpr invite_s = std::string_view{"/invite"};
        auto constexpr ban_s = std::string_view{"/ban"};
        auto constexpr kick_s = std::string_view{"/kick"};
        auto constexpr unban_s = std::string_view{"/unban"};
        auto constexpr forget_s = std::string_view{"/forget"};
        auto constexpr leave_s = std::string_view{"/leave"};
        auto constexpr read_markers_s = std::string_view{"/read_markers"};
        auto constexpr receipt_s = std::string_view{"/receipt/"};
        auto constexpr upgrade_s = std::string_view{"/upgrade"};
        auto const suffix = std::string_view{req.target}.substr(room_prefix.size());
        if (req.method == "PUT")
        {
            if (auto const path = room_send_path_parts(req.target); path.has_value())
            {
                // CS API §10.5.1: idempotent send — replay the original response.
                if (auto const cached = database::find_client_txn_event_id(
                        rt.homeserver.database.persistent_store, *user, path->room_id, path->event_type, path->txn_id);
                    cached.has_value())
                {
                    return complete({200U, json_serialize(json_obj({json_member("event_id", json_str(*cached))}))});
                }
                auto rewritten = req;
                auto event_body = event_body_from_content(path->event_type, req.body);
                if (!event_body.has_value())
                {
                    log_diagnostic("room.send_event.rejected",
                                   {
                                       {"actor",      *user,                                 false},
                                       {"room_id",    path->room_id,                         false},
                                       {"event_type", path->event_type,                      false},
                                       {"reason",     "event content must be a JSON object", false}
                    });
                    return dispatch_err(req, rt, 400U, "M_BAD_JSON", "event content must be a JSON object");
                }
                log_diagnostic("room.send_event.dispatch", {
                                                               {"actor",      *user,            false},
                                                               {"room_id",    path->room_id,    false},
                                                               {"event_type", path->event_type, false}
                });
                rewritten.method = "POST";
                rewritten.target = "/_matrix/client/v3/rooms/" + path->room_id + "/send";
                rewritten.body = *event_body;
                auto const result = wrap(call_local(rewritten), "event_id");
                log_diagnostic(result.status == 200U ? "room.send_event.accepted" : "room.send_event.rejected",
                               {
                                   {"actor",      *user,                                                   false},
                                   {"room_id",    path->room_id,                                           false},
                                   {"event_type", path->event_type,                                        false},
                                   {"status",     std::to_string(result.status),                           false},
                                   {"reason",     result.status == 200U ? std::string{"ok"} : result.body, false}
                });
                // CS API §11.12: the server MUST send a stop-typing event when a
                // user sends a message.  Clear local typing state and federate a
                // typing:false EDU so remote servers remove the stale indicator.
                if (result.status == 200U)
                {
                    // Store txn_id → event_id for idempotency replay.
                    auto const parsed = canonicaljson::parse_lossless(result.body);
                    if (auto const* obj = std::get_if<canonicaljson::Object>(&parsed.value.storage()))
                    {
                        auto const eid_it = std::ranges::find_if(*obj, [](canonicaljson::ObjectMember const& m) {
                            return m.key == "event_id";
                        });
                        if (eid_it != obj->end() && eid_it->value != nullptr)
                        {
                            if (auto const* s = std::get_if<std::string>(&eid_it->value->storage()))
                            {
                                std::ignore = database::store_client_txn(
                                    rt.homeserver.database.persistent_store,
                                    {*user, path->room_id, path->event_type, path->txn_id, *s});
                            }
                        }
                    }
                    auto const previous_users = current_typing_users_in_room(rt.homeserver, path->room_id);
                    auto const typing_it =
                        std::ranges::find_if(rt.homeserver.typing_users, [&path, user](auto const& t) {
                            return t.room_id == path->room_id && t.user_id == *user && t.typing;
                        });
                    if (typing_it != rt.homeserver.typing_users.end())
                    {
                        typing_it->typing = false;
                        auto const room_stream_id =
                            update_room_typing_stream_id_if_changed(rt.homeserver, path->room_id, previous_users);
                        // Federate typing:false only if the room has remote members
                        auto const room_it = std::ranges::find_if(rt.homeserver.database.rooms, [&path](auto const& r) {
                            return r.room_id == path->room_id;
                        });
                        if (room_it != rt.homeserver.database.rooms.end())
                        {
                            auto const edu_content = json_serialize(json_obj({
                                json_member("room_id", json_str(path->room_id)),
                                json_member("user_id", json_str(*user)),
                                json_member("typing", canonicaljson::Value{false}),
                            }));
                            auto const enqueued =
                                dispatch_outbound_edu(rt.homeserver, *room_it, "m.typing", edu_content);
                            if (enqueued > 0U)
                            {
                                log_diagnostic("room.typing.cleared_on_send",
                                               {
                                                   {"actor",        *user,                    false},
                                                   {"room_id",      path->room_id,            false},
                                                   {"destinations", std::to_string(enqueued), false}
                                });
                            }
                        }
                        if (room_stream_id != std::uint64_t{0U} && rt.sync_notifier != nullptr)
                        {
                            rt.sync_notifier->publish(rt.homeserver.database.next_stream_ordering - 1U,
                                                      rt.homeserver.database.persistent_store.next_sync_stream_id);
                        }
                    }
                }
                return complete(result);
            }
            if (auto const path = room_state_path_parts(req.target); path.has_value())
            {
                auto rewritten = req;
                auto event_body = event_body_from_content(path->event_type, req.body, path->state_key);
                if (!event_body.has_value())
                {
                    log_diagnostic("room.state_event.rejected",
                                   {
                                       {"actor",      *user,                                 false},
                                       {"room_id",    path->room_id,                         false},
                                       {"event_type", path->event_type,                      false},
                                       {"reason",     "state content must be a JSON object", false}
                    });
                    return dispatch_err(req, rt, 400U, "M_BAD_JSON", "state content must be a JSON object");
                }
                log_diagnostic("room.state_event.dispatch", {
                                                                {"actor",      *user,            false},
                                                                {"room_id",    path->room_id,    false},
                                                                {"event_type", path->event_type, false},
                                                                {"state_key",  path->state_key,  false}
                });
                rewritten.method = "POST";
                rewritten.target = "/_matrix/client/v3/rooms/" + path->room_id + "/send";
                rewritten.body = *event_body;
                auto const result = wrap(call_local(rewritten), "event_id");
                log_diagnostic(result.status == 200U ? "room.state_event.accepted" : "room.state_event.rejected",
                               {
                                   {"actor",      *user,                                                   false},
                                   {"room_id",    path->room_id,                                           false},
                                   {"event_type", path->event_type,                                        false},
                                   {"status",     std::to_string(result.status),                           false},
                                   {"reason",     result.status == 200U ? std::string{"ok"} : result.body, false}
                });
                return complete(result);
            }
        }
        if (req.method == "POST" && suffix.size() > join_s.size() &&
            suffix.substr(suffix.size() - join_s.size()) == join_s)
        {
            auto const room_id = core::percent_decode_path_component(suffix.substr(0U, suffix.size() - join_s.size()));
            log_diagnostic("room.join.dispatch",
                           {
                               {"actor",   *user,                                            false},
                               {"room_id", room_id,                                          false},
                               {"target",  observability::sanitized_http_target(req.target), false}
            });
            auto const result = wrap(call_local(req), "room_id");
            log_diagnostic(result.status == 200U ? "room.join.accepted" : "room.join.rejected",
                           {
                               {"actor",   *user,                                                   false},
                               {"room_id", room_id,                                                 false},
                               {"status",  std::to_string(result.status),                           false},
                               {"reason",  result.status == 200U ? std::string{"ok"} : result.body, false}
            });
            // Notify remote servers that this user's devices now share the room
            // so they can fetch keys and deliver encrypted room keys (spec v1.18).
            if (result.status == 200U)
            {
                broadcast_device_list_updates(rt, *user, remote_servers_for_user(rt.homeserver, *user));
            }
            return complete(result);
        }
        if (req.method == "POST" && suffix.size() > send_s.size() &&
            suffix.substr(suffix.size() - send_s.size()) == send_s)
        {
            auto const room_id = core::percent_decode_path_component(suffix.substr(0U, suffix.size() - send_s.size()));
            log_diagnostic("room.send_event.internal", {
                                                           {"actor",   *user,   false},
                                                           {"room_id", room_id, false}
            });
            auto const result = wrap(call_local(req), "event_id");
            log_diagnostic(result.status == 200U ? "room.send_event.accepted" : "room.send_event.rejected",
                           {
                               {"actor",   *user,                                                   false},
                               {"room_id", room_id,                                                 false},
                               {"status",  std::to_string(result.status),                           false},
                               {"reason",  result.status == 200U ? std::string{"ok"} : result.body, false}
            });
            return complete(result);
        }
        // GET /_matrix/client/v3/rooms/{roomId}/event/{eventId}
        // Spec: returns the full event for a room the requester is a member of.
        if (req.method == "GET")
        {
            if (auto const path = room_event_path_parts(req.target); path.has_value())
            {
                auto const& store = rt.homeserver.database.persistent_store;
                auto const is_joined =
                    std::ranges::any_of(store.memberships, [&](database::PersistentMembership const& membership) {
                        return membership.room_id == path->room_id && membership.user_id == *user &&
                               membership.membership == "join";
                    });
                if (!is_joined)
                {
                    return dispatch_err(req, rt, 403U, "M_FORBIDDEN", "not a member of this room");
                }
                auto const event = std::ranges::find_if(store.events, [&](database::PersistentEvent const& current) {
                    return current.room_id == path->room_id && current.event_id == path->event_id;
                });
                if (event == store.events.end())
                {
                    return dispatch_err(req, rt, 404U, "M_NOT_FOUND", "event not found");
                }
                auto const serialized = canonicaljson::serialize_canonical(client_event_value(*event));
                if (serialized.error != canonicaljson::CanonicalJsonError::none)
                {
                    return dispatch_err(req, rt, 500U, "M_UNKNOWN", "failed to serialize event");
                }
                return complete({200U, serialized.output});
            }
        }
        // GET /rooms/{roomId}/state/{eventType}/{stateKey}
        // Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3roomsroomidstateeventtypestatekey
        // Returns the content object of a single named state event.
        if (req.method == "GET")
        {
            if (auto const path = room_state_path_parts(req.target); path.has_value())
            {
                auto const& store = rt.homeserver.database.persistent_store;
                auto const room_it = std::ranges::find_if(store.rooms, [&](auto const& r) {
                    return r.room_id == path->room_id;
                });
                if (room_it == store.rooms.end())
                {
                    return dispatch_err(req, rt, 403U, "M_FORBIDDEN", "not a member of this room");
                }
                auto const state_it = std::ranges::find_if(store.state, [&](database::PersistentStateEvent const& s) {
                    return s.room_id == path->room_id && s.event_type == path->event_type &&
                           s.state_key == path->state_key;
                });
                if (state_it == store.state.end())
                {
                    return dispatch_err(req, rt, 404U, "M_NOT_FOUND", "state event not found");
                }
                auto const event_it = std::ranges::find_if(store.events, [&](database::PersistentEvent const& e) {
                    return e.event_id == state_it->event_id;
                });
                if (event_it == store.events.end())
                {
                    return dispatch_err(req, rt, 500U, "M_UNKNOWN", "state event missing from event store");
                }
                auto const parsed = canonicaljson::parse_lossless(event_it->json);
                if (parsed.error != canonicaljson::ParseError::none)
                {
                    return dispatch_err(req, rt, 500U, "M_UNKNOWN", "state event JSON is malformed");
                }
                auto const* event_obj = std::get_if<canonicaljson::Object>(&parsed.value.storage());
                if (event_obj == nullptr)
                {
                    return dispatch_err(req, rt, 500U, "M_UNKNOWN", "state event JSON is not an object");
                }
                auto const* content_val = object_member(*event_obj, "content");
                if (content_val == nullptr)
                {
                    return dispatch_err(req, rt, 500U, "M_UNKNOWN", "state event has no content field");
                }
                auto const serialized = canonicaljson::serialize_canonical(*content_val);
                if (serialized.error != canonicaljson::CanonicalJsonError::none)
                {
                    return dispatch_err(req, rt, 500U, "M_UNKNOWN", "failed to serialize state event content");
                }
                return complete({200U, serialized.output});
            }
        }
        if (req.method == "GET" && suffix.size() > state_s.size() &&
            suffix.substr(suffix.size() - state_s.size()) == state_s)
        {
            // Matrix spec: GET /rooms/{roomId}/state returns the array directly.
            auto const room_id = core::percent_decode_path_component(suffix.substr(0U, suffix.size() - state_s.size()));
            auto result = call_local(req);
            log_diagnostic(result.status == 200U ? "room.state.response" : "room.state.rejected",
                           {
                               {"actor",   *user,                         false},
                               {"room_id", room_id,                       false},
                               {"status",  std::to_string(result.status), false}
            });
            if (result.status != 200U)
            {
                return dispatch_err(req, rt, result.status, error_code_for_status(result.status), result.body);
            }
            return complete(result);
        }
        // GET /_matrix/client/v3/rooms/{roomId}/aliases
        // Spec: returns the room aliases currently known to this homeserver.
        if (req.method == "GET")
        {
            auto constexpr aliases_s = std::string_view{"/aliases"};
            auto const path_suffix = suffix.substr(0U, suffix.find('?'));
            if (path_suffix.size() > aliases_s.size() && path_suffix.ends_with(aliases_s))
            {
                auto const encoded_room_id = path_suffix.substr(0U, path_suffix.size() - aliases_s.size());
                auto const room_id = core::percent_decode_path_component(encoded_room_id);
                auto const& store = rt.homeserver.database.persistent_store;
                auto const requester_joined =
                    std::ranges::any_of(store.memberships, [&](database::PersistentMembership const& membership) {
                        return membership.room_id == room_id && membership.user_id == *user &&
                               membership.membership == "join";
                    });
                if (!requester_joined)
                {
                    return dispatch_err(req, rt, 403U, "M_FORBIDDEN", "user is not a member of this room");
                }
                auto aliases = canonicaljson::Array{};
                for (auto const& alias : store.room_aliases)
                {
                    if (alias.room_id == room_id)
                    {
                        aliases.push_back(canonicaljson::Value{alias.room_alias});
                    }
                }
                return dispatch_resp(req, rt, 200U,
                                     json_serialize(json_obj({json_member("aliases", json_arr(std::move(aliases)))})));
            }
        }
        // GET /_matrix/client/v3/rooms/{roomId}/joined_members
        // Spec: returns joined MXIDs mapped to their room profile fields.
        if (req.method == "GET")
        {
            if (auto const room_id = room_joined_members_path_room_id(req.target); room_id.has_value())
            {
                auto const& store = rt.homeserver.database.persistent_store;
                auto const requester_joined =
                    std::ranges::any_of(store.memberships, [&](database::PersistentMembership const& membership) {
                        return membership.room_id == *room_id && membership.user_id == *user &&
                               membership.membership == "join";
                    });
                if (!requester_joined)
                {
                    return dispatch_err(req, rt, 403U, "M_FORBIDDEN", "user is not a member of this room");
                }
                auto joined = canonicaljson::Object{};
                for (auto const& membership : store.memberships)
                {
                    if (membership.room_id != *room_id || membership.membership != "join")
                    {
                        continue;
                    }
                    auto member_info = canonicaljson::Object{};
                    if (auto const profile = database::find_profile(store, membership.user_id); profile.has_value())
                    {
                        if (!profile->avatar_url.empty())
                        {
                            member_info.push_back(json_member("avatar_url", json_str(profile->avatar_url)));
                        }
                        if (!profile->displayname.empty())
                        {
                            member_info.push_back(json_member("display_name", json_str(profile->displayname)));
                        }
                    }
                    joined.push_back(json_member(membership.user_id, json_obj(std::move(member_info))));
                }
                return dispatch_resp(req, rt, 200U,
                                     json_serialize(json_obj({json_member("joined", json_obj(std::move(joined)))})));
            }
        }
        // GET /_matrix/client/v3/rooms/{roomId}/members
        // Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3roomsroomidmembers
        // Returns the current state of the room membership as a chunk of
        // m.room.member events. Optional query params:
        //   membership     - include only this type (join/leave/invite/ban/knock)
        //   not_membership - exclude this type (commonly "leave")
        //   at             - snapshot token (ignored; we return current state)
        {
            auto constexpr members_s = std::string_view{"/members"};
            auto const path_suffix = suffix.substr(0U, suffix.find('?'));
            auto const query_string =
                suffix.size() > path_suffix.size() ? suffix.substr(path_suffix.size() + 1U) : std::string_view{};
            auto const path_ends_with_members = req.method == "GET" && path_suffix.size() > members_s.size() &&
                                                path_suffix.substr(path_suffix.size() - members_s.size()) == members_s;
            if (path_ends_with_members)
            {
                auto const encoded_room_id_with_slash = path_suffix.substr(0U, path_suffix.size() - members_s.size());
                auto const encoded_room_id = encoded_room_id_with_slash.starts_with('/')
                                                 ? encoded_room_id_with_slash.substr(1U)
                                                 : encoded_room_id_with_slash;
                auto const room_id = core::percent_decode_path_component(encoded_room_id);

                auto const parse_qparam = [](std::string_view qs, std::string_view key) -> std::string {
                    auto remaining = qs;
                    while (!remaining.empty())
                    {
                        auto const pair_end = remaining.find('&');
                        auto const pair = remaining.substr(0U, pair_end);
                        auto const equals = pair.find('=');
                        auto const pair_key = pair.substr(0U, equals);
                        if (pair_key == key)
                        {
                            if (equals == std::string_view::npos)
                            {
                                return {};
                            }
                            return std::string{pair.substr(equals + 1U)};
                        }
                        if (pair_end == std::string_view::npos)
                        {
                            break;
                        }
                        remaining.remove_prefix(pair_end + 1U);
                    }
                    return {};
                };
                auto const not_membership = parse_qparam(query_string, "not_membership");
                auto const membership_filter = parse_qparam(query_string, "membership");

                auto const& store = rt.homeserver.database.persistent_store;
                auto const room_it = std::ranges::find_if(store.rooms, [&room_id](auto const& r) {
                    return r.room_id == room_id;
                });
                if (room_it == store.rooms.end())
                {
                    return dispatch_err(req, rt, 404U, "M_NOT_FOUND", "room not found");
                }

                // Spec §GET /rooms/{roomId}/members: 403 if the requester is not a
                // current or previous room member. Check memberships first; fall back to
                // state events so the state-only code path (e.g. regression tests that
                // deliberately clear the membership projection) still works correctly.
                auto const is_or_was_member =
                    std::ranges::any_of(store.memberships,
                                        [&](database::PersistentMembership const& m) {
                                            return m.room_id == room_id && m.user_id == *user;
                                        }) ||
                    std::ranges::any_of(store.state, [&](database::PersistentStateEvent const& s) {
                        return s.room_id == room_id && s.event_type == "m.room.member" && s.state_key == *user;
                    });
                if (!is_or_was_member)
                {
                    log_diagnostic("room.members.rejected",
                                   {
                                       {"actor",   *user,                               false},
                                       {"room_id", room_id,                             false},
                                       {"reason",  "user is not a member of this room", false}
                    });
                    return dispatch_err(req, rt, 403U, "M_FORBIDDEN", "user is not a member of this room");
                }

                auto chunk = canonicaljson::Array{};
                auto state_backed_members = std::vector<std::string>{};
                for (auto const& state_entry : store.state)
                {
                    if (state_entry.room_id != room_id || state_entry.event_type != "m.room.member")
                    {
                        continue;
                    }
                    auto const event_it =
                        std::ranges::find_if(store.events, [&state_entry](database::PersistentEvent const& event) {
                            return event.event_id == state_entry.event_id;
                        });
                    if (event_it == store.events.end())
                    {
                        continue;
                    }
                    auto const parsed = canonicaljson::parse_lossless(event_it->json);
                    auto const* event = parsed.error == canonicaljson::ParseError::none
                                            ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                                            : nullptr;
                    auto const* content = event == nullptr ? nullptr : object_member_as_object(*event, "content");
                    auto const* membership = content == nullptr ? nullptr : string_member(*content, "membership");
                    if (event == nullptr || membership == nullptr)
                    {
                        continue;
                    }
                    if (!not_membership.empty() && *membership == not_membership)
                    {
                        continue;
                    }
                    if (!membership_filter.empty() && *membership != membership_filter)
                    {
                        continue;
                    }
                    chunk.push_back(client_event_value(*event_it));
                    state_backed_members.push_back(state_entry.state_key);
                }
                for (auto const& m : store.memberships)
                {
                    if (m.room_id != room_id)
                        continue;
                    if (!not_membership.empty() && m.membership == not_membership)
                        continue;
                    if (!membership_filter.empty() && m.membership != membership_filter)
                        continue;
                    if (std::ranges::find(state_backed_members, m.user_id) != state_backed_members.end())
                        continue;
                    // Fallback: construct a synthetic m.room.member event from the
                    // membership record only when current state is missing entirely.
                    auto ev = canonicaljson::Object{};
                    ev.push_back(
                        canonicaljson::make_member("type", canonicaljson::Value{std::string{"m.room.member"}}));
                    ev.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{room_id}));
                    ev.push_back(canonicaljson::make_member("sender", canonicaljson::Value{m.user_id}));
                    ev.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{m.user_id}));
                    auto content = canonicaljson::Object{};
                    content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{m.membership}));
                    ev.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
                    chunk.push_back(canonicaljson::Value{std::move(ev)});
                }
                log_diagnostic("room.members.accepted", {
                                                            {"actor",   *user,   false},
                                                            {"room_id", room_id, false}
                });
                return dispatch_resp(req, rt, 200U,
                                     json_serialize(json_obj({json_member("chunk", json_arr(std::move(chunk)))})));
            }
        }
        if (req.method == "PUT")
        {
            if (auto const typing = room_typing_path_parts(req.target); typing.has_value())
            {
                if (typing->user_id != *user)
                {
                    log_diagnostic("room.typing.rejected",
                                   {
                                       {"actor",   *user,                                      false},
                                       {"room_id", typing->room_id,                            false},
                                       {"reason",  "cannot set typing state for another user", false}
                    });
                    return dispatch_err(req, rt, 403U, "M_FORBIDDEN", "cannot set typing state for another user");
                }
                // Spec §11.12: validate room existence and membership before
                // accepting a typing notification.
                auto const room_it = std::ranges::find_if(rt.homeserver.database.rooms, [&typing](auto const& r) {
                    return r.room_id == typing->room_id;
                });
                if (room_it == rt.homeserver.database.rooms.end() || !joined(*room_it, *user))
                {
                    log_diagnostic("room.typing.rejected", {
                                                               {"actor",   *user,           false},
                                                               {"room_id", typing->room_id, false},
                                                               {"reason",  "not a member",  false}
                    });
                    return dispatch_err(req, rt, 403U, "M_FORBIDDEN", "user is not a member of the room");
                }
                // Parse the request body for the typing bool (spec-required) and
                // optional timeout.  Default to true when body is absent so legacy
                // clients that omit it remain compatible, but honour the parsed
                // value when present.
                auto is_typing = true;
                {
                    auto const body_obj = parsed_json_object(req.body);
                    if (body_obj.has_value())
                    {
                        auto const* typing_val = boolean_member(*body_obj, "typing");
                        if (typing_val != nullptr)
                        {
                            is_typing = *typing_val;
                        }
                    }
                }
                log_diagnostic("room.typing.accepted",
                               {
                                   {"actor",   *user,           false},
                                   {"room_id", typing->room_id, false}
                });
                // Federate the typing EDU. Spec §11.12: `typing` MUST be a JSON
                // boolean, not a string.
                {
                    auto const edu_content = json_serialize(json_obj({
                        json_member("room_id", json_str(typing->room_id)),
                        json_member("user_id", json_str(*user)),
                        json_member("typing", canonicaljson::Value{is_typing}),
                    }));
                    auto const enqueued = dispatch_outbound_edu(rt.homeserver, *room_it, "m.typing", edu_content);
                    if (enqueued > 0U)
                    {
                        log_diagnostic("room.typing.dispatched",
                                       {
                                           {"actor",        *user,                    false},
                                           {"room_id",      typing->room_id,          false},
                                           {"destinations", std::to_string(enqueued), false}
                        });
                    }
                }
                // Update local in-memory typing state so /sync returns the
                // change for other local users in the room.  Only advance the
                // per-room typing cursor when the set of typing users actually
                // changes; duplicate refresh requests must not re-emit the same
                // list and starve other sync traffic.
                {
                    auto const previous_users = current_typing_users_in_room(rt.homeserver, typing->room_id);
                    auto existing = std::ranges::find_if(rt.homeserver.typing_users, [&typing, user](auto const& t) {
                        return t.room_id == typing->room_id && t.user_id == *user;
                    });
                    if (existing != rt.homeserver.typing_users.end())
                    {
                        existing->typing = is_typing;
                    }
                    else if (is_typing)
                    {
                        rt.homeserver.typing_users.push_back(
                            {typing->room_id, std::string{*user}, true, std::uint64_t{0U}});
                    }
                    auto const room_stream_id =
                        update_room_typing_stream_id_if_changed(rt.homeserver, typing->room_id, previous_users);
                    if (room_stream_id != std::uint64_t{0U})
                    {
                        log_diagnostic("room.typing.room_stream_id",
                                       {
                                           {"actor",     *user,                          false},
                                           {"room_id",   typing->room_id,                false},
                                           {"stream_id", std::to_string(room_stream_id), false},
                                           {"typing",    is_typing ? "true" : "false",   false}
                        });
                        if (rt.sync_notifier != nullptr)
                        {
                            rt.sync_notifier->publish(rt.homeserver.database.next_stream_ordering - 1U,
                                                      rt.homeserver.database.persistent_store.next_sync_stream_id);
                        }
                    }
                }
                return dispatch_resp(req, rt, 200U, json_serialize(json_obj({})));
            }
        }
        // GET /_matrix/client/v3/rooms/{roomId}/initialSync
        // Spec: ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3roomsroomidinitialsync
        // Returns RoomInfo for members (or previous members) and allows
        // non-member peeking when the room is world_readable.
        if (req.method == "GET")
        {
            if (auto const initial_sync_room = room_initial_sync_path_room_id(req.target);
                initial_sync_room.has_value())
            {
                auto const& store = rt.homeserver.database.persistent_store;

                auto const room_exists = std::ranges::find_if(store.rooms, [&initial_sync_room](auto const& r) {
                                             return r.room_id == *initial_sync_room;
                                         }) != store.rooms.end();
                if (!room_exists)
                {
                    // Spec v1.18 only defines 200 and 403 for this endpoint. A room
                    // that is not resident locally (e.g. a remote public room the
                    // client discovered via the directory) is treated the same as a
                    // non-member request so the client can fall back to joining.
                    log_diagnostic("room.initial_sync.rejected",
                                   {
                                       {"actor",   *user,                               false},
                                       {"room_id", *initial_sync_room,                  false},
                                       {"reason",  "user is not a member of this room", false}
                    });
                    return dispatch_err(req, rt, 403U, "M_FORBIDDEN", "not a member of this room");
                }

                auto membership = std::optional<std::string>{};
                auto const membership_it =
                    std::ranges::find_if(store.memberships, [&initial_sync_room, &user](auto const& m) {
                        return m.room_id == *initial_sync_room && m.user_id == *user;
                    });
                if (membership_it != store.memberships.end())
                {
                    membership = membership_it->membership;
                }
                else
                {
                    // Fall back to the durable m.room.member state event for previous members.
                    auto const state_member =
                        std::ranges::find_if(store.state, [&initial_sync_room, &user](auto const& s) {
                            return s.room_id == *initial_sync_room && s.event_type == "m.room.member" &&
                                   s.state_key == *user;
                        });
                    if (state_member != store.state.end())
                    {
                        auto const member_json = event_json_for_id(store, state_member->event_id);
                        if (member_json.has_value())
                        {
                            membership = event_content_string(*member_json, "membership");
                        }
                    }
                }

                auto const is_banned = membership.has_value() && *membership == "ban";
                auto const is_or_was_member = membership.has_value();

                auto can_peek = false;
                if (!is_or_was_member && !is_banned)
                {
                    auto const index = build_state_index(store);
                    auto const history_visibility = room_state_string(
                        store, index, *initial_sync_room, "m.room.history_visibility", "history_visibility");
                    can_peek = history_visibility.has_value() && *history_visibility == "world_readable";
                }

                if (!is_or_was_member && !can_peek)
                {
                    log_diagnostic("room.initial_sync.rejected",
                                   {
                                       {"actor",   *user,                               false},
                                       {"room_id", *initial_sync_room,                  false},
                                       {"reason",  "user is not a member of this room", false}
                    });
                    return dispatch_err(req, rt, 403U, "M_FORBIDDEN", "not a member of this room");
                }

                auto const membership_value = membership.value_or("leave");
                log_diagnostic("room.initial_sync.response", {
                                                                 {"actor",      *user,              false},
                                                                 {"room_id",    *initial_sync_room, false},
                                                                 {"membership", membership_value,   false}
                });
                return dispatch_resp(
                    req, rt, 200U, room_initial_sync_json(rt, *initial_sync_room, *user, req.target, membership_value));
            }
        }

        if (req.method == "GET")
        {
            if (auto const messages_room = room_messages_room_id(req.target); messages_room.has_value())
            {
                auto const room =
                    std::ranges::find_if(rt.homeserver.database.rooms, [&messages_room](auto const& candidate) {
                        return candidate.room_id == *messages_room;
                    });
                if (room == rt.homeserver.database.rooms.end())
                {
                    log_diagnostic("room.messages.rejected", {
                                                                 {"actor",   *user,            false},
                                                                 {"room_id", *messages_room,   false},
                                                                 {"reason",  "room not found", false}
                    });
                    return dispatch_err(req, rt, 404U, "M_NOT_FOUND", "room not found");
                }
                if (!joined(*room, *user))
                {
                    log_diagnostic("room.messages.rejected",
                                   {
                                       {"actor",   *user,                               false},
                                       {"room_id", *messages_room,                      false},
                                       {"reason",  "user is not a member of this room", false}
                    });
                    return dispatch_err(req, rt, 403U, "M_FORBIDDEN", "user is not a member of this room");
                }
                log_diagnostic("room.messages.response",
                               {
                                   {"actor",   *user,          false},
                                   {"room_id", *messages_room, false}
                });
                return dispatch_resp(req, rt, 200U, messages_json(rt, *messages_room, req.target));
            }
        }
        if (req.method == "POST" && suffix.size() > invite_s.size() &&
            suffix.substr(suffix.size() - invite_s.size()) == invite_s)
        {
            auto const room_id =
                core::percent_decode_path_component(suffix.substr(0U, suffix.size() - invite_s.size()));
            auto const body = parse_membership_action_body(req.body);
            if (!body.has_value())
            {
                return dispatch_err(req, rt, 400U, "M_BAD_JSON", "invite body must contain user_id");
            }
            auto const result = merovingian::homeserver::invite_user(rt.homeserver, req.access_token, room_id,
                                                                     body->user_id, body->reason);
            if (!result.ok)
            {
                return dispatch_err(req, rt, result.status, error_code_for_status(result.status), result.reason);
            }
            // For remote invitees dispatch the federation invite so the remote server
            // learns about the event and can deliver it to the invitee's client.
            auto const invitee_server = server_name_from_user_id(body->user_id);
            if (!invitee_server.empty() && invitee_server != rt.homeserver.config.server().server_name)
            {
                auto const& store = rt.homeserver.database.persistent_store;
                auto const invite_state =
                    std::ranges::find_if(store.state, [&room_id, &body](database::PersistentStateEvent const& s) {
                        return s.room_id == room_id && s.event_type == "m.room.member" && s.state_key == body->user_id;
                    });
                auto const invite_json =
                    invite_state != store.state.end() ? event_json_for_id(store, invite_state->event_id) : std::nullopt;
                if (invite_json.has_value())
                {
                    auto const room_version = room_version_from_store(store, room_id);
                    merovingian::homeserver::wire_federation_callbacks(rt.homeserver);
                    if (rt.homeserver.dispatch_worker != nullptr)
                    {
                        auto transaction = federation::make_outbound_invite(
                            invitee_server, rt.homeserver.config.server().server_name, room_id, invite_state->event_id,
                            room_version, *invite_json, {});
                        transaction.transaction_id = federation::make_federation_transaction_id();
                        std::ignore = rt.homeserver.dispatch_worker->enqueue(std::move(transaction));
                    }
                }
            }
            return dispatch_resp(req, rt, 200U, json_serialize(json_obj({})));
        }
        if (req.method == "POST" && suffix.size() > ban_s.size() &&
            suffix.substr(suffix.size() - ban_s.size()) == ban_s)
        {
            auto const room_id = core::percent_decode_path_component(suffix.substr(0U, suffix.size() - ban_s.size()));
            auto const body = parse_membership_action_body(req.body);
            if (!body.has_value())
            {
                return dispatch_err(req, rt, 400U, "M_BAD_JSON", "ban body must contain user_id");
            }
            auto const result = merovingian::homeserver::ban_user(rt.homeserver, req.access_token, room_id,
                                                                  body->user_id, body->reason);
            if (!result.ok)
            {
                return dispatch_err(req, rt, result.status, error_code_for_status(result.status), result.reason);
            }
            return dispatch_resp(req, rt, 200U, json_serialize(json_obj({})));
        }
        if (req.method == "POST" && suffix.size() > kick_s.size() &&
            suffix.substr(suffix.size() - kick_s.size()) == kick_s)
        {
            auto const room_id = core::percent_decode_path_component(suffix.substr(0U, suffix.size() - kick_s.size()));
            auto const body = parse_membership_action_body(req.body);
            if (!body.has_value())
            {
                return dispatch_err(req, rt, 400U, "M_BAD_JSON", "kick body must contain user_id");
            }
            auto const result = merovingian::homeserver::kick_user(rt.homeserver, req.access_token, room_id,
                                                                   body->user_id, body->reason);
            if (!result.ok)
            {
                return dispatch_err(req, rt, result.status, error_code_for_status(result.status), result.reason);
            }
            return dispatch_resp(req, rt, 200U, json_serialize(json_obj({})));
        }
        if (req.method == "POST" && suffix.size() > unban_s.size() &&
            suffix.substr(suffix.size() - unban_s.size()) == unban_s)
        {
            auto const room_id = core::percent_decode_path_component(suffix.substr(0U, suffix.size() - unban_s.size()));
            auto const body = parse_membership_action_body(req.body);
            if (!body.has_value())
            {
                return dispatch_err(req, rt, 400U, "M_BAD_JSON", "unban body must contain user_id");
            }
            auto const result =
                merovingian::homeserver::unban_user(rt.homeserver, req.access_token, room_id, body->user_id);
            if (!result.ok)
            {
                return dispatch_err(req, rt, result.status, error_code_for_status(result.status), result.reason);
            }
            return dispatch_resp(req, rt, 200U, json_serialize(json_obj({})));
        }
        if (req.method == "POST" && suffix.size() > forget_s.size() &&
            suffix.substr(suffix.size() - forget_s.size()) == forget_s)
        {
            auto const room_id =
                core::percent_decode_path_component(suffix.substr(0U, suffix.size() - forget_s.size()));
            auto const result = merovingian::homeserver::forget_room(rt.homeserver, req.access_token, room_id);
            if (!result.ok)
            {
                return dispatch_err(req, rt, result.status, error_code_for_status(result.status), result.reason);
            }
            return dispatch_resp(req, rt, 200U, json_serialize(json_obj({})));
        }
        // POST /_matrix/client/v3/rooms/{roomId}/leave
        // Removes the caller from the room. Non-members receive 403; unknown rooms 404.
        if (req.method == "POST" && suffix.size() > leave_s.size() &&
            suffix.substr(suffix.size() - leave_s.size()) == leave_s)
        {
            auto const room_id = core::percent_decode_path_component(suffix.substr(0U, suffix.size() - leave_s.size()));
            auto const result = merovingian::homeserver::leave_room(rt.homeserver, req.access_token, room_id);
            if (!result.ok)
            {
                log_diagnostic("room.leave.rejected",
                               {
                                   {"actor",   *user,                                                      false},
                                   {"room_id", room_id,                                                    false},
                                   {"status",  std::to_string(result.status != 0U ? result.status : 403U), false},
                                   {"reason",  result.reason,                                              false}
                });
                return dispatch_err(req, rt, result.status != 0U ? result.status : 403U,
                                    error_code_for_status(result.status != 0U ? result.status : 403U), result.reason);
            }
            log_diagnostic("room.leave.accepted", {
                                                      {"actor",   *user,   false},
                                                      {"room_id", room_id, false}
            });
            return dispatch_resp(req, rt, 200U, json_serialize(json_obj({})));
        }
        // POST /_matrix/client/v3/rooms/{roomId}/read_markers
        // Spec §13.7: the body may contain m.fully_read, m.read, and
        // m.read.private.  m.read is federated as a receipt EDU; m.read.private
        // is local-only and MUST NOT be federated.
        // Spec: non-members receive 403 M_FORBIDDEN.
        if (req.method == "POST" && suffix.size() > read_markers_s.size() &&
            suffix.substr(suffix.size() - read_markers_s.size()) == read_markers_s)
        {
            auto const room_id =
                core::percent_decode_path_component(suffix.substr(0U, suffix.size() - read_markers_s.size()));

            // Bug 10: validate room existence and membership.
            auto const markers_room_it = std::ranges::find_if(rt.homeserver.database.rooms, [&room_id](auto const& r) {
                return r.room_id == room_id;
            });
            if (markers_room_it == rt.homeserver.database.rooms.end() || !joined(*markers_room_it, *user))
            {
                return dispatch_err(req, rt, 403U, "M_FORBIDDEN", "user is not a member of the room");
            }

            auto const receipt_body = canonicaljson::parse_lossless(req.body);
            auto const* body_obj = std::get_if<canonicaljson::Object>(&receipt_body.value.storage());

            auto const now_ts = static_cast<std::int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                              std::chrono::system_clock::now().time_since_epoch())
                                                              .count());

            // Helper: upsert a local receipt entry and notify sync.
            auto upsert_receipt = [&](std::string const& receipt_type, std::string const& event_id) {
                auto existing = std::ranges::find_if(rt.homeserver.receipts, [&](auto const& r) {
                    return r.room_id == room_id && r.user_id == *user && r.receipt_type == receipt_type;
                });
                auto const stream_id = database::allocate_sync_stream_id(rt.homeserver.database.persistent_store);
                if (existing != rt.homeserver.receipts.end())
                {
                    existing->event_id = event_id;
                    existing->ts = static_cast<std::uint64_t>(now_ts);
                    existing->stream_id = stream_id;
                }
                else
                {
                    rt.homeserver.receipts.push_back({std::string{room_id}, receipt_type, std::string{*user}, event_id,
                                                      static_cast<std::uint64_t>(now_ts), stream_id});
                }
                if (rt.sync_notifier != nullptr)
                {
                    rt.sync_notifier->publish(rt.homeserver.database.next_stream_ordering - 1U,
                                              rt.homeserver.database.persistent_store.next_sync_stream_id);
                }
            };

            if (body_obj != nullptr)
            {
                // m.read — federated read receipt.
                auto const* m_read = string_member(*body_obj, "m.read");
                if (m_read != nullptr && !m_read->empty())
                {
                    auto const edu_content_opt =
                        federation::build_receipt_edu_content(room_id, "m.read", *user, *m_read, now_ts);
                    if (edu_content_opt.has_value())
                    {
                        auto const enqueued =
                            dispatch_outbound_edu(rt.homeserver, *markers_room_it, "m.receipt", *edu_content_opt);
                        if (enqueued > 0U)
                        {
                            log_diagnostic("room.read_markers.dispatched",
                                           {
                                               {"actor",        *user,                    false},
                                               {"room_id",      room_id,                  false},
                                               {"destinations", std::to_string(enqueued), false}
                            });
                        }
                    }
                    upsert_receipt("m.read", std::string{*m_read});
                }

                // m.fully_read — local-only account data marker, not a receipt EDU.
                auto const* m_fully_read = string_member(*body_obj, "m.fully_read");
                if (m_fully_read != nullptr && !m_fully_read->empty())
                {
                    upsert_receipt("m.fully_read", std::string{*m_fully_read});
                }

                // m.read.private — local-only receipt, MUST NOT be federated.
                auto const* m_read_private = string_member(*body_obj, "m.read.private");
                if (m_read_private != nullptr && !m_read_private->empty())
                {
                    upsert_receipt("m.read.private", std::string{*m_read_private});
                }
            }

            log_diagnostic("room.read_markers.accepted", {
                                                             {"actor",   *user,   false},
                                                             {"room_id", room_id, false}
            });
            return dispatch_resp(req, rt, 200U, json_serialize(json_obj({})));
        }

        // POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}
        // Sets a receipt in a room per Matrix spec §receipts.
        if (req.method == "POST" && suffix.size() > receipt_s.size())
        {
            auto const receipt_pos = suffix.find(receipt_s);
            if (receipt_pos != std::string_view::npos)
            {
                auto const room_id = core::percent_decode_path_component(suffix.substr(0U, receipt_pos));
                auto const after_receipt = suffix.substr(receipt_pos + receipt_s.size());
                auto const slash_pos = after_receipt.find('/');
                if (slash_pos != std::string_view::npos && slash_pos > 0U)
                {
                    auto const receipt_type = std::string{after_receipt.substr(0U, slash_pos)};
                    // Spec: valid receipt types are m.read, m.read.private, and m.fully_read.
                    if (receipt_type != "m.read" && receipt_type != "m.read.private" && receipt_type != "m.fully_read")
                    {
                        return dispatch_err(req, rt, 400U, "M_INVALID_PARAM",
                                            "receiptType must be one of: m.read, m.read.private, m.fully_read");
                    }
                    auto const event_id = core::percent_decode_path_component(after_receipt.substr(slash_pos + 1U));
                    if (!event_id.empty())
                    {
                        // Bug 10: validate room existence and membership before
                        // storing or federating any receipt state.
                        auto const receipt_room_it =
                            std::ranges::find_if(rt.homeserver.database.rooms, [&room_id](auto const& r) {
                                return r.room_id == room_id;
                            });
                        if (receipt_room_it == rt.homeserver.database.rooms.end() || !joined(*receipt_room_it, *user))
                        {
                            return dispatch_err(req, rt, 403U, "M_FORBIDDEN", "user is not a member of the room");
                        }
                        log_diagnostic("room.receipt.accepted", {
                                                                    {"actor",        *user,        false},
                                                                    {"room_id",      room_id,      false},
                                                                    {"receipt_type", receipt_type, false},
                                                                    {"event_id",     event_id,     false}
                        });
                        auto const now_ts =
                            static_cast<std::int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                          std::chrono::system_clock::now().time_since_epoch())
                                                          .count());
                        // m.read.private MUST NOT be federated (local-only receipt).
                        if (receipt_type != "m.read.private")
                        {
                            auto const edu_content_opt =
                                federation::build_receipt_edu_content(room_id, receipt_type, *user, event_id, now_ts);
                            if (edu_content_opt.has_value())
                            {
                                auto const enqueued = dispatch_outbound_edu(rt.homeserver, *receipt_room_it,
                                                                            "m.receipt", *edu_content_opt);
                                if (enqueued > 0U)
                                {
                                    log_diagnostic("room.receipt.dispatched",
                                                   {
                                                       {"actor",        *user,                    false},
                                                       {"room_id",      room_id,                  false},
                                                       {"destinations", std::to_string(enqueued), false}
                                    });
                                }
                            }
                        }
                        auto existing_receipt = std::ranges::find_if(rt.homeserver.receipts, [&](auto const& r) {
                            return r.room_id == room_id && r.user_id == *user && r.receipt_type == receipt_type;
                        });
                        auto const stream_id =
                            database::allocate_sync_stream_id(rt.homeserver.database.persistent_store);
                        if (existing_receipt != rt.homeserver.receipts.end())
                        {
                            existing_receipt->event_id = std::string{event_id};
                            existing_receipt->ts = static_cast<std::uint64_t>(now_ts);
                            existing_receipt->stream_id = stream_id;
                        }
                        else
                        {
                            rt.homeserver.receipts.push_back({std::string{room_id}, receipt_type, std::string{*user},
                                                              std::string{event_id}, static_cast<std::uint64_t>(now_ts),
                                                              stream_id});
                        }
                        if (rt.sync_notifier != nullptr)
                        {
                            rt.sync_notifier->publish(rt.homeserver.database.next_stream_ordering - 1U,
                                                      rt.homeserver.database.persistent_store.next_sync_stream_id);
                        }
                        return dispatch_resp(req, rt, 200U, json_serialize(json_obj({})));
                    }
                }
            }
        }
        // POST /_matrix/client/v3/rooms/{roomId}/upgrade
        // Spec §10.7: creates a new room at the requested version, sends m.room.tombstone
        // to the old room, and returns {"replacement_room": "!newroomid:server"}.
        if (req.method == "POST" && suffix.size() > upgrade_s.size() &&
            suffix.substr(suffix.size() - upgrade_s.size()) == upgrade_s)
        {
            auto const room_id =
                core::percent_decode_path_component(suffix.substr(0U, suffix.size() - upgrade_s.size()));
            auto const upgrade_body = parsed_json_object(req.body);
            if (!upgrade_body.has_value())
            {
                return dispatch_err(req, rt, 400U, "M_BAD_JSON", "body must be a JSON object");
            }
            auto const* new_version_str = string_member(*upgrade_body, "new_version");
            if (new_version_str == nullptr || new_version_str->empty())
            {
                return dispatch_err(req, rt, 400U, "M_BAD_JSON", "new_version is required");
            }
            if (rooms::find_room_version_policy(*new_version_str) == nullptr)
            {
                return dispatch_err(req, rt, 400U, "M_UNSUPPORTED_ROOM_VERSION", "unsupported room version");
            }
            auto const old_room_it = std::ranges::find_if(rt.homeserver.database.rooms, [&room_id](LocalRoom const& r) {
                return r.room_id == room_id;
            });
            if (old_room_it == rt.homeserver.database.rooms.end())
            {
                return dispatch_err(req, rt, 404U, "M_NOT_FOUND", "room not found");
            }
            if (!joined(*old_room_it, *user))
            {
                return dispatch_err(req, rt, 403U, "M_FORBIDDEN", "user is not a member of the room");
            }
            auto const last_event_id = old_room_it->events.empty() ? std::string{} : old_room_it->events.back();
            auto predecessor = canonicaljson::Object{};
            predecessor.push_back(json_member("room_id", json_str(room_id)));
            if (!last_event_id.empty())
            {
                predecessor.push_back(json_member("event_id", json_str(last_event_id)));
            }
            auto upgrade_options = CreateRoomOptions{};
            upgrade_options.room_version = *new_version_str;
            upgrade_options.creation_content.push_back(json_member("predecessor", json_obj(std::move(predecessor))));
            auto const create_result = create_room(rt.homeserver, req.access_token, upgrade_options);
            if (!create_result.ok)
            {
                return dispatch_err(req, rt, create_result.status, error_code_for_status(create_result.status),
                                    create_result.reason);
            }
            auto const& new_room_id = create_result.value;
            auto const tombstone_content = json_serialize(json_obj({
                json_member("body", json_str("This room has been replaced")),
                json_member("replacement_room", json_str(new_room_id)),
            }));
            auto const tombstone_body = event_body_from_content("m.room.tombstone", tombstone_content, std::string{""});
            if (tombstone_body.has_value())
            {
                auto tombstone_req = req;
                tombstone_req.method = "POST";
                tombstone_req.target = "/_matrix/client/v3/rooms/" + room_id + "/send";
                tombstone_req.body = *tombstone_body;
                call_local(tombstone_req);
            }
            log_diagnostic("room.upgrade.accepted", {
                                                        {"actor",       *user,            false},
                                                        {"old_room_id", room_id,          false},
                                                        {"new_room_id", new_room_id,      false},
                                                        {"new_version", *new_version_str, false}
            });
            return dispatch_resp(req, rt, 200U,
                                 json_serialize(json_obj({json_member("replacement_room", json_str(new_room_id))})));
        }
    }

    // POST /_matrix/client/v3/user_directory/search
    // Searches for users by display name or user ID per Matrix spec §user-directory.
    if (req.method == "POST" && req.target == "/_matrix/client/v3/user_directory/search")
    {
        auto const body = canonicaljson::parse_lossless(req.body);
        auto const* body_obj = std::get_if<canonicaljson::Object>(&body.value.storage());
        auto const* search_term = (body_obj != nullptr) ? string_member(*body_obj, "search_term") : nullptr;
        auto results = canonicaljson::Array{};
        if (search_term != nullptr && !search_term->empty())
        {
            auto const term_lower = to_lower(*search_term);
            for (auto const& profile : rt.homeserver.database.persistent_store.profiles)
            {
                if (to_lower(profile.displayname).find(term_lower) != std::string::npos ||
                    to_lower(profile.user_id).find(term_lower) != std::string::npos)
                {
                    auto user_obj = canonicaljson::Object{};
                    user_obj.push_back(json_member("user_id", json_str(profile.user_id)));
                    user_obj.push_back(json_member("display_name", json_str(profile.displayname)));
                    user_obj.push_back(json_member("avatar_url", json_str(profile.avatar_url)));
                    results.push_back(canonicaljson::Value{std::move(user_obj)});
                }
            }
        }
        return dispatch_resp(req, rt, 200U,
                             json_serialize(json_obj({
                                 json_member("results", json_arr(std::move(results))),
                                 json_member("limited", json_bool(false)),
                             })));
    }

    // PUT /_matrix/client/v3/presence/{userId}/status
    // Sets the presence state for the authenticated user.
    auto constexpr presence_prefix = std::string_view{"/_matrix/client/v3/presence/"};
    auto constexpr presence_suffix = std::string_view{"/status"};
    if (req.method == "PUT" && starts_with(req.target, presence_prefix))
    {
        auto const path_after_prefix = std::string_view{req.target}.substr(presence_prefix.size());
        auto const suffix_pos = path_after_prefix.rfind(presence_suffix);
        if (suffix_pos != std::string_view::npos)
        {
            auto const user_id_target = core::percent_decode_path_component(path_after_prefix.substr(0U, suffix_pos));
            if (user_id_target != *user)
            {
                return dispatch_err(req, rt, 403U, "M_FORBIDDEN", "cannot set presence for another user");
            }
            auto const body = canonicaljson::parse_lossless(req.body);
            auto const* body_obj = std::get_if<canonicaljson::Object>(&body.value.storage());
            if (body_obj == nullptr)
            {
                return dispatch_err(req, rt, 400U, "M_BAD_JSON", "presence body must be Matrix JSON");
            }
            auto const* presence_str = string_member(*body_obj, "presence");
            auto const presence_state = presence_str != nullptr ? *presence_str : std::string{"offline"};
            auto const* status_msg = string_member(*body_obj, "status_msg");
            auto state = database::PersistentPresence{};
            state.stream_id = 0U;
            state.user_id = std::string{*user};
            state.presence = presence_state;
            state.status_msg = status_msg != nullptr ? *status_msg : std::string{};
            state.last_active_ago = 0;
            state.currently_active = (presence_state == "online");
            if (!set_presence(rt, state))
            {
                return dispatch_err(req, rt, 500U, "M_UNKNOWN", "presence persistence failed");
            }
            log_diagnostic("presence.set", {
                                               {"actor",    *user,          false},
                                               {"presence", presence_state, false}
            });
            return dispatch_resp(req, rt, 200U, json_serialize(json_obj({})));
        }
    }

    // POST /_matrix/client/v3/join/{roomIdOrAlias}
    // Joins by room ID or alias. Delegates to the same local join handler as
    // /rooms/{roomId}/join by rewriting the request target.
    auto constexpr join_by_id_prefix = std::string_view{"/_matrix/client/v3/join/"};
    if (req.method == "POST" && starts_with(req.target, join_by_id_prefix))
    {
        auto room_segment = std::string_view{req.target}.substr(join_by_id_prefix.size());
        // Preserve the ?server_name=/?via= query string and forward it on the rewritten
        // target: it carries the candidate resident servers needed to route a federated
        // join. This is the only way to reach a room version 12 room, whose room ID has
        // no server domain (MSC4291).
        auto join_query = std::string_view{};
        if (auto const query_start = room_segment.find('?'); query_start != std::string_view::npos)
        {
            join_query = room_segment.substr(query_start + 1U);
            room_segment = room_segment.substr(0U, query_start);
        }
        if (room_segment.empty())
        {
            log_diagnostic("room.join_by_id.rejected",
                           {
                               {"actor",  *user,                                            false},
                               {"target", observability::sanitized_http_target(req.target), false},
                               {"status", "400",                                            false},
                               {"reason", "room id or alias must not be empty",             false}
            });
            return dispatch_err(req, rt, 400U, "M_INVALID_PARAM", "room id or alias must not be empty");
        }
        auto const decoded_room_segment = core::percent_decode_path_component(room_segment);
        auto resolved_room_id = decoded_room_segment;
        auto resolved_via_servers = parse_join_servers_query(join_query);
        if (!decoded_room_segment.empty() && decoded_room_segment.front() == '#')
        {
            auto const& our_server = rt.homeserver.config.server().server_name;
            auto const alias_server = server_name_from_room_alias(decoded_room_segment);
            if (alias_server == our_server)
            {
                auto const found =
                    database::find_room_alias(rt.homeserver.database.persistent_store, decoded_room_segment);
                if (!found.has_value())
                {
                    return dispatch_err(req, rt, 404U, "M_NOT_FOUND", "room alias not found");
                }
                resolved_room_id = found->room_id;
                for (auto const& server : room_servers_for_alias(rt, found->room_id))
                {
                    if (std::ranges::find(resolved_via_servers, server) == resolved_via_servers.end())
                    {
                        resolved_via_servers.push_back(server);
                    }
                }
            }
            else if (!alias_server.empty())
            {
                wire_federation_callbacks(rt.homeserver);
                auto const signing_key = ensure_runtime_server_signing_key(rt.homeserver);
                auto const key_id = signing_key.has_value() ? signing_key->key_id : std::string{};
                auto const secret =
                    std::string{reinterpret_cast<char const*>(rt.homeserver.database.signing_secret_key.bytes().data()),
                                rt.homeserver.database.signing_secret_key.bytes().size()};
                auto* outbound_client = rt.homeserver.outbound_client.get();
                auto* discovery_network = rt.homeserver.discovery_network.get();
                auto const target = std::string{"/_matrix/federation/v1/query/directory?room_alias="} +
                                    core::percent_encode_path_component(decoded_room_segment);
                auto const tx =
                    federation::make_outbound_transaction(std::string{alias_server}, "GET", target, our_server, {});
                guard.unlock();
                auto const [ok, body] = perform_sync_outbound_call(outbound_client, discovery_network, tx, key_id,
                                                                   secret, "room.join.alias_lookup_failed");
                if (!ok)
                {
                    return dispatch_err(req, rt, 502U, "M_UNKNOWN", "Failed to resolve room alias on remote server");
                }
                auto const directory = parse_directory_lookup_response(body);
                if (!directory.has_value() || !directory->ok || directory->room_id.empty())
                {
                    return dispatch_err(req, rt, 502U, "M_UNKNOWN", "Remote server returned malformed room alias data");
                }
                resolved_room_id = directory->room_id;
                for (auto const& server : directory->servers)
                {
                    if (std::ranges::find(resolved_via_servers, server) == resolved_via_servers.end())
                    {
                        resolved_via_servers.push_back(server);
                    }
                }
            }
        }
        auto rewritten = req;
        rewritten.target = std::string{"/_matrix/client/v3/rooms/"} + resolved_room_id + "/join";
        if (!resolved_via_servers.empty())
        {
            auto first = true;
            for (auto const& server : resolved_via_servers)
            {
                rewritten.target += first ? "?" : "&";
                rewritten.target += "via=" + core::percent_encode_path_component(server);
                first = false;
            }
        }
        log_diagnostic("room.join_by_id.rewrite",
                       {
                           {"actor",            *user,                                                  false},
                           {"room_id_or_alias", decoded_room_segment,                                   false},
                           {"target",           observability::sanitized_http_target(req.target),       false},
                           {"rewritten_target", observability::sanitized_http_target(rewritten.target), false}
        });
        auto const result = wrap(call_local(rewritten), "room_id");
        log_diagnostic(result.status == 200U ? "room.join_by_id.accepted" : "room.join_by_id.rejected",
                       {
                           {"actor",            *user,                                                   false},
                           {"room_id_or_alias", decoded_room_segment,                                    false},
                           {"status",           std::to_string(result.status),                           false},
                           {"reason",           result.status == 200U ? std::string{"ok"} : result.body, false}
        });
        // Notify remote servers that this user's devices now share the room
        // so they can fetch keys and deliver encrypted room keys (spec v1.18).
        if (result.status == 200U)
        {
            broadcast_device_list_updates(rt, *user, remote_servers_for_user(rt.homeserver, *user));
        }
        return complete(result);
    }

    // POST  /_matrix/client/v3/user/{userId}/filter   — upload and store a sync filter
    // GET   /_matrix/client/v3/user/{userId}/filter/{filterId} — retrieve a stored filter
    // PUT   /_matrix/client/v3/user/{userId}/account_data/{type} — store account data
    // GET   /_matrix/client/v3/user/{userId}/account_data/{type} — retrieve account data
    auto constexpr knock_by_id_prefix = std::string_view{"/_matrix/client/v3/knock/"};
    if (req.method == "POST" && starts_with(req.target, knock_by_id_prefix))
    {
        auto const room_id =
            core::percent_decode_path_component(std::string_view{req.target}.substr(knock_by_id_prefix.size()));
        if (room_id.empty())
        {
            return dispatch_err(req, rt, 400U, "M_INVALID_PARAM", "room id or alias must not be empty");
        }
        auto const result = merovingian::homeserver::knock_room(rt.homeserver, req.access_token, room_id);
        if (!result.ok)
        {
            return dispatch_err(req, rt, result.status, error_code_for_status(result.status), result.reason);
        }
        return dispatch_resp(req, rt, 200U, json_serialize(json_obj({json_member("room_id", json_str(result.value))})));
    }

    auto constexpr user_prefix = std::string_view{"/_matrix/client/v3/user/"};
    if (starts_with(req.target, user_prefix))
    {
        auto const suffix = std::string_view{req.target}.substr(user_prefix.size());
        auto constexpr filter_s = std::string_view{"/filter"};
        auto constexpr filter_m = std::string_view{"/filter/"};

        if (req.method == "POST" && ends_with(suffix, filter_s))
        {
            // Extract and decode the userId from the URL path segment
            auto const encoded_user = suffix.substr(0U, suffix.size() - filter_s.size());
            auto const path_user = core::percent_decode_path_component(encoded_user);
            if (path_user != *user)
            {
                return dispatch_err(req, rt, 403U, "M_FORBIDDEN", "cannot upload filter for another user");
            }
            if (req.body.empty())
            {
                return dispatch_err(req, rt, 400U, "M_BAD_JSON", "filter body must not be empty");
            }
            auto const filter_id = generate_filter_id();
            if (!database::store_filter(rt.homeserver.database.persistent_store, {path_user, filter_id, req.body}))
            {
                log_diagnostic("filter.rejected", {
                                                      {"actor",     *user,                      false},
                                                      {"filter_id", filter_id,                  false},
                                                      {"reason",    "failed to persist filter", false}
                });
                return dispatch_err(req, rt, 500U, "M_UNKNOWN", "failed to persist filter");
            }
            log_diagnostic("filter.stored", {
                                                {"actor",     *user,     false},
                                                {"filter_id", filter_id, false}
            });
            return dispatch_resp(req, rt, 200U,
                                 json_serialize(json_obj({json_member("filter_id", json_str(filter_id))})));
        }

        auto const mid_pos = suffix.find(filter_m);
        if (req.method == "GET" && mid_pos != std::string_view::npos)
        {
            auto const encoded_user = suffix.substr(0U, mid_pos);
            auto const path_user = core::percent_decode_path_component(encoded_user);
            if (path_user != *user)
            {
                return dispatch_err(req, rt, 403U, "M_FORBIDDEN", "cannot access filter for another user");
            }
            auto const filter_id = std::string{suffix.substr(mid_pos + filter_m.size())};
            auto const stored = database::find_filter(rt.homeserver.database.persistent_store, path_user, filter_id);
            if (!stored.has_value())
            {
                log_diagnostic("filter.rejected", {
                                                      {"actor",     *user,              false},
                                                      {"filter_id", filter_id,          false},
                                                      {"reason",    "filter not found", false}
                });
                return dispatch_err(req, rt, 404U, "M_NOT_FOUND", "filter not found");
            }
            log_diagnostic("filter.retrieved", {
                                                   {"actor",     *user,     false},
                                                   {"filter_id", filter_id, false}
            });
            return dispatch_resp(req, rt, 200U, stored->json);
        }

        // Global (non-room) account data. The userId path segment is
        // percent-encoded and contains no '/', so a pre-marker segment that
        // contains '/' is room-scoped and falls through to the 404 below
        // until room-scoped account data is implemented.
        auto constexpr account_data_m = std::string_view{"/account_data/"};
        if (auto const ad_pos = suffix.find(account_data_m); ad_pos != std::string_view::npos)
        {
            auto const encoded_user = suffix.substr(0U, ad_pos);
            auto const type = core::percent_decode_path_component(suffix.substr(ad_pos + account_data_m.size()));
            if (encoded_user.find('/') == std::string_view::npos && !type.empty())
            {
                auto const path_user = core::percent_decode_path_component(encoded_user);
                if (path_user != *user)
                {
                    return dispatch_err(req, rt, 403U, "M_FORBIDDEN", "cannot access account data for another user");
                }
                if (req.method == "PUT")
                {
                    if (req.body.empty())
                    {
                        return dispatch_err(req, rt, 400U, "M_BAD_JSON", "account data body must not be empty");
                    }
                    if (!set_account_data(rt, {path_user, std::string{}, type, req.body, 0U}))
                    {
                        log_diagnostic("account_data.rejected",
                                       {
                                           {"actor",  *user,                            false},
                                           {"type",   type,                             false},
                                           {"reason", "failed to persist account data", false}
                        });
                        return dispatch_err(req, rt, 500U, "M_UNKNOWN", "failed to persist account data");
                    }
                    log_diagnostic("account_data.stored", {
                                                              {"actor", *user, false},
                                                              {"type",  type,  false}
                    });
                    return dispatch_resp(req, rt, 200U, "{}");
                }
                if (req.method == "GET")
                {
                    auto const& store = rt.homeserver.database.persistent_store;
                    auto const found = std::ranges::find_if(
                        store.account_data, [&path_user, &type](database::PersistentAccountData const& d) {
                            return d.user_id == path_user && d.room_id.empty() && d.event_type == type;
                        });
                    if (found == store.account_data.end())
                    {
                        log_diagnostic("account_data.rejected", {
                                                                    {"actor",  *user,                    false},
                                                                    {"type",   type,                     false},
                                                                    {"reason", "account data not found", false}
                        });
                        return dispatch_err(req, rt, 404U, "M_NOT_FOUND", "account data not found");
                    }
                    log_diagnostic("account_data.retrieved", {
                                                                 {"actor", *user, false},
                                                                 {"type",  type,  false}
                    });
                    return dispatch_resp(req, rt, 200U, found->content_json);
                }
            }
        }

        // Room-scoped tags: GET /user/{userId}/rooms/{roomId}/tags,
        // PUT /user/{userId}/rooms/{roomId}/tags/{tag},
        // DELETE /user/{userId}/rooms/{roomId}/tags/{tag}.
        // Implemented as room account data with event_type "m.tag" and content
        // {"tags":{"m.favourite":{"order":0.5}, ...}} so /sync surfaces it
        // automatically through the room account-data path.
        auto constexpr rooms_tags_m = std::string_view{"/rooms/"};
        if (auto const rooms_pos = suffix.find(rooms_tags_m); rooms_pos != std::string_view::npos)
        {
            auto const encoded_user = suffix.substr(0U, rooms_pos);
            auto const after_rooms = suffix.substr(rooms_pos + rooms_tags_m.size());
            auto const tags_pos = after_rooms.find("/tags");
            if (tags_pos != std::string_view::npos)
            {
                auto const encoded_room = after_rooms.substr(0U, tags_pos);
                auto const path_user = core::percent_decode_path_component(encoded_user);
                auto const path_room = core::percent_decode_path_component(encoded_room);
                auto const remainder = after_rooms.substr(tags_pos + std::string_view{"/tags"}.size());
                if (path_user != *user)
                {
                    return dispatch_err(req, rt, 403U, "M_FORBIDDEN", "cannot access tags for another user");
                }
                if (path_room.empty())
                {
                    return dispatch_err(req, rt, 400U, "M_INVALID_PARAM", "room id must not be empty");
                }

                // Verify the caller is currently joined to the room; tags are only
                // meaningful for rooms the user participates in.
                auto const room_iter =
                    std::ranges::find_if(rt.homeserver.database.rooms, [&path_room](LocalRoom const& r) {
                        return r.room_id == path_room;
                    });
                auto const* room = room_iter == rt.homeserver.database.rooms.end() ? nullptr : &(*room_iter);
                if (room == nullptr || !joined(*room, *user))
                {
                    return dispatch_err(req, rt, 404U, "M_NOT_FOUND", "room not found or user not joined");
                }

                if (req.method == "GET" && remainder.empty())
                {
                    auto tags = room_tag_content(rt.homeserver.database.persistent_store, path_user, path_room);
                    auto response = canonicaljson::Object{};
                    response.push_back(json_member("tags", json_obj(std::move(tags))));
                    return dispatch_resp(req, rt, 200U, json_serialize(json_obj(std::move(response))));
                }

                if (req.method == "PUT" && remainder.size() > 1U && remainder.front() == '/')
                {
                    auto const tag = core::percent_decode_path_component(remainder.substr(1U));
                    if (tag.empty())
                    {
                        return dispatch_err(req, rt, 400U, "M_INVALID_PARAM", "tag must not be empty");
                    }
                    if (req.body.empty())
                    {
                        return dispatch_err(req, rt, 400U, "M_BAD_JSON", "tag body must not be empty");
                    }
                    auto const parsed = canonicaljson::parse_json(req.body);
                    if (parsed.error != canonicaljson::ParseError::none ||
                        std::get_if<canonicaljson::Object>(&parsed.value.storage()) == nullptr)
                    {
                        return dispatch_err(req, rt, 400U, "M_BAD_JSON", "tag body must be a JSON object");
                    }
                    auto tags = room_tag_content(rt.homeserver.database.persistent_store, path_user, path_room);
                    set_object_member(tags, tag, std::move(parsed.value));
                    if (!store_room_tag_content(rt, path_user, path_room, std::move(tags)))
                    {
                        return dispatch_err(req, rt, 500U, "M_UNKNOWN", "failed to store tag");
                    }
                    return dispatch_resp(req, rt, 200U, "{}");
                }

                if (req.method == "DELETE" && remainder.size() > 1U && remainder.front() == '/')
                {
                    auto const tag = core::percent_decode_path_component(remainder.substr(1U));
                    if (tag.empty())
                    {
                        return dispatch_err(req, rt, 400U, "M_INVALID_PARAM", "tag must not be empty");
                    }
                    auto tags = room_tag_content(rt.homeserver.database.persistent_store, path_user, path_room);
                    std::erase_if(tags, [&tag](canonicaljson::ObjectMember const& member) {
                        return member.key == tag;
                    });
                    if (!store_room_tag_content(rt, path_user, path_room, std::move(tags)))
                    {
                        return dispatch_err(req, rt, 500U, "M_UNKNOWN", "failed to remove tag");
                    }
                    return dispatch_resp(req, rt, 200U, "{}");
                }
            }
        }
    }

    // im.nheko.summary: Nheko probes these unstable endpoints for per-room
    // summary metadata (heroes, joined/invited counts).  Return a summary
    // object derived from the local room membership so Nheko stops hitting
    // 404 on every sync.  Two path shapes are probed:
    //   GET /_matrix/client/unstable/im.nheko.summary/summary/{roomId}
    //   GET /_matrix/client/unstable/im.nheko.summary/rooms/{roomId}/summary
    auto constexpr nheko_summary_prefix = std::string_view{"/_matrix/client/unstable/im.nheko.summary/"};
    if (req.method == "GET" && starts_with(req.target, nheko_summary_prefix))
    {
        auto const remainder = std::string_view{req.target}.substr(nheko_summary_prefix.size());
        auto const query_pos = remainder.find('?');
        auto const path = query_pos == std::string_view::npos ? remainder : remainder.substr(0U, query_pos);
        // Extract room_id from either /summary/{roomId} or /rooms/{roomId}/summary.
        auto room_id = std::string{};
        if (starts_with(path, "summary/"))
        {
            room_id = core::percent_decode_path_component(path.substr(8U));
        }
        else if (starts_with(path, "rooms/"))
        {
            auto const after_rooms = path.substr(6U);
            auto const slash = after_rooms.find("/summary");
            room_id = core::percent_decode_path_component(
                slash == std::string_view::npos ? after_rooms : after_rooms.substr(0U, slash));
        }
        if (!room_id.empty())
        {
            auto const room_iter = std::ranges::find_if(rt.homeserver.database.rooms, [&room_id](LocalRoom const& r) {
                return r.room_id == room_id;
            });
            auto const* room = room_iter == rt.homeserver.database.rooms.end() ? nullptr : &(*room_iter);
            if (room != nullptr && joined(*room, *user))
            {
                auto summary = canonicaljson::Object{};
                summary.push_back(canonicaljson::make_member("room_id", json_str(room_id)));
                auto info = canonicaljson::Object{};
                auto heroes = canonicaljson::Array{};
                for (auto const& member : room->members)
                {
                    if (member != *user)
                    {
                        heroes.push_back(json_str(member));
                    }
                }
                info.push_back(canonicaljson::make_member("m.heroes", canonicaljson::Value{std::move(heroes)}));
                info.push_back(canonicaljson::make_member("m.joined_member_count",
                                                          json_int(static_cast<std::int64_t>(room->members.size()))));
                info.push_back(canonicaljson::make_member("m.invited_member_count", json_int(0)));
                summary.push_back(canonicaljson::make_member("summary", canonicaljson::Value{std::move(info)}));
                auto const body = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(summary)});
                log_diagnostic("room_summary.response", {
                                                            {"room_id", room_id, false},
                                                            {"actor",   *user,   false}
                });
                return dispatch_resp(req, rt, 200U,
                                     body.error == canonicaljson::CanonicalJsonError::none ? body.output : "{}");
            }
        }
        return dispatch_err(req, rt, 404U, "M_NOT_FOUND", "room summary not found");
    }

    // GET /_matrix/client/v1/rooms/{roomId}/hierarchy
    // Spec: returns a paginated depth-first list of rooms in the space hierarchy.
    auto constexpr hierarchy_prefix = std::string_view{"/_matrix/client/v1/rooms/"};
    auto constexpr hierarchy_suffix = std::string_view{"/hierarchy"};
    if (req.method == "GET" && request_path.size() > hierarchy_prefix.size() + hierarchy_suffix.size() &&
        starts_with(request_path, hierarchy_prefix) && request_path.ends_with(hierarchy_suffix))
    {
        auto const encoded_room_id = request_path.substr(
            hierarchy_prefix.size(), request_path.size() - hierarchy_prefix.size() - hierarchy_suffix.size());
        if (encoded_room_id.find('/') == std::string_view::npos)
        {
            auto request = SpaceHierarchyRequest{};
            request.room_id = core::percent_decode_path_component(encoded_room_id);

            if (auto const from = query_param_value(req.target, "from"); from.has_value())
            {
                request.from = *from;
            }
            auto const parse_size = [](std::optional<std::string> const& text) -> std::optional<std::size_t> {
                if (!text.has_value() || text->empty())
                {
                    return std::nullopt;
                }
                try
                {
                    return static_cast<std::size_t>(std::stoull(*text));
                }
                catch (...)
                {
                    return std::nullopt;
                }
            };
            request.limit = parse_size(query_param_value(req.target, "limit"));
            request.max_depth = parse_size(query_param_value(req.target, "max_depth"));
            if (auto const suggested = query_param_value(req.target, "suggested_only"); suggested == "true")
            {
                request.suggested_only = true;
            }

            auto const result = handle_client_space_hierarchy(rt.homeserver, *user, request);
            return dispatch_resp(req, rt, result.status, result.body);
        }
    }

    // Account moderation endpoints (spec v1.18 §"Account locking" / §"Account
    // suspension"). Matched after all other routes; the handler enforces admin
    // auth, anti-enumeration, and lookup rules.
    if (starts_with(request_path, "/_matrix/client/v1/admin/lock/") ||
        starts_with(request_path, "/_matrix/client/v1/admin/suspend/"))
    {
        return handle_account_moderation(rt, req, request_path,
                                         starts_with(request_path, "/_matrix/client/v1/admin/lock/"));
    }

    log_diagnostic("request.route_not_found", {
                                                  {"method", req.method,                                       false},
                                                  {"target", observability::sanitized_http_target(req.target), false},
                                                  {"actor",  *user,                                            false},
                                                  {"status", "404",                                            false}
    });
    return dispatch_err(req, rt, 404U, "M_UNRECOGNIZED", "route not found");
}

// Matrix spec §web-browser-clients (v1.18):
//   "The server MUST add Access-Control-Allow-Origin: * to every response."
//
// This is the single public entry point. The impl above has multiple code paths
// (complete(), sync_json(), direct DispatchResult construction) that return
// without calling apply_cors_headers(). Applying CORS here at the boundary
// covers all of them in one place without touching every return site.
//
// needs_wait responses carry no HTTP response yet — CORS is applied on the
// second call (can_wait=false) after the sync notifier fires, at which point
// status will be complete and this branch runs normally.
auto handle_client_server_request(ClientServerRuntime& rt, LocalHttpRequest const& req, bool can_wait) -> DispatchResult
{
    auto result = handle_client_server_request_impl(rt, req, can_wait);
    if (result.status == DispatchResult::Status::complete)
    {
        apply_cors_headers(req, result.response, rt.cors);
    }
    return result;
}

auto device_count(ClientServerRuntime const& rt, std::string_view user) noexcept -> std::size_t
{
    return static_cast<std::size_t>(std::ranges::count_if(rt.devices, [user](ClientDevice const& d) {
        return d.user_id == user;
    }));
}

auto joined_room_count(ClientServerRuntime const& rt, std::string_view user) noexcept -> std::size_t
{
    return static_cast<std::size_t>(std::ranges::count_if(rt.homeserver.database.rooms, [user](LocalRoom const& room) {
        return joined(room, user);
    }));
}

auto key_api_record_count(ClientServerRuntime const& rt, std::string_view user) noexcept -> std::size_t
{
    return static_cast<std::size_t>(std::ranges::count_if(rt.key_api_records, [user](ClientKeyApiRecord const& record) {
        return record.user_id == user;
    }));
}

auto ensure_sync_notifier(ClientServerRuntime& runtime) -> sync::SyncNotifier&
{
    if (!runtime.sync_notifier)
    {
        runtime.sync_notifier = std::make_unique<sync::SyncNotifier>();
        runtime.homeserver.sync_notifier = runtime.sync_notifier.get();
    }
    auto const& db = runtime.homeserver.database;
    runtime.sync_notifier->publish(db.next_stream_ordering - 1U, db.persistent_store.next_sync_stream_id);
    return *runtime.sync_notifier;
}

auto push_to_device_message(ClientServerRuntime& runtime, database::PersistentToDeviceMessage message) -> bool
{
    auto guard = std::unique_lock<std::recursive_mutex>{runtime.homeserver.mutex};
    auto const stored =
        database::enqueue_to_device_message(runtime.homeserver.database.persistent_store, std::move(message));
    if (stored)
    {
        std::ignore = ensure_sync_notifier(runtime);
    }
    return stored;
}

auto record_device_list_change(ClientServerRuntime& runtime, database::PersistentDeviceListChange change) -> bool
{
    auto guard = std::unique_lock<std::recursive_mutex>{runtime.homeserver.mutex};
    auto const stored =
        database::record_device_list_change(runtime.homeserver.database.persistent_store, std::move(change));
    if (stored)
    {
        std::ignore = ensure_sync_notifier(runtime);
    }
    return stored;
}

auto set_presence(ClientServerRuntime& runtime, database::PersistentPresence state) -> bool
{
    auto guard = std::unique_lock<std::recursive_mutex>{runtime.homeserver.mutex};
    auto const stored = database::upsert_presence(runtime.homeserver.database.persistent_store, std::move(state));
    if (stored)
    {
        std::ignore = ensure_sync_notifier(runtime);
    }
    return stored;
}

auto set_account_data(ClientServerRuntime& runtime, database::PersistentAccountData data) -> bool
{
    auto guard = std::unique_lock<std::recursive_mutex>{runtime.homeserver.mutex};
    // store_account_data advances next_sync_stream_id before persisting,
    // so the ensure_sync_notifier publish below wakes any long-poll
    // /sync waiter that was parked at a since_token below the new row.
    auto const stored = database::store_account_data(runtime.homeserver.database.persistent_store, std::move(data));
    if (stored)
    {
        std::ignore = ensure_sync_notifier(runtime);
    }
    return stored;
}

auto run_client_server_flow(config::Config const& config) -> OperationResult
{
    auto started = start_client_server(config);
    if (!started.started)
    {
        return {false, 400U, {}, started.reason};
    }
    auto& rt = started.runtime;
    auto reg = handle_client_server_request(
        rt, {"POST", "/_matrix/client/v3/register", {}, registration_request_body(config, "alice", "CorrectHorse7!")});
    auto login = handle_client_server_request(
        rt, {"POST",
             "/_matrix/client/v3/login",
             {},
             json_serialize(json_obj({
                 json_member("type", json_str("m.login.password")),
                 json_member("identifier", json_obj({
                                               json_member("type", json_str("m.id.user")),
                                               json_member("user", json_str("@alice:example.org")),
                                           })),
                 json_member("password", json_str("CorrectHorse7!")),
                 json_member("device_id", json_str("DEVICE1")),
             }))});
    auto const token = json_value(login.response.body, "\"access_token\":\"");
    auto whoami = handle_client_server_request(rt, {"GET", "/_matrix/client/v3/account/whoami", token, {}});
    auto room = handle_client_server_request(rt, {"POST", "/_matrix/client/v3/createRoom", token, {}});
    auto const room_id = json_value(room.response.body, "\"room_id\":\"");
    auto send = handle_client_server_request(rt, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/send", token,
                                                  json_serialize(json_obj({
                                                      json_member("type", json_str("m.room.encrypted")),
                                                      json_member("content", json_str("secret")),
                                                  }))});
    auto state = handle_client_server_request(rt, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/state", token, {}});
    auto joined_r = handle_client_server_request(rt, {"GET", "/_matrix/client/v3/joined_rooms", token, {}});
    auto devices = handle_client_server_request(rt, {"GET", "/_matrix/client/v3/devices", token, {}});
    auto sync = handle_client_server_request(rt, {"GET", "/_matrix/client/v3/sync", token, {}});
    if (reg.response.status != 200U || login.response.status != 200U || whoami.response.status != 200U ||
        room.response.status != 200U || send.response.status != 200U || state.response.status != 200U ||
        joined_r.response.status != 200U || devices.response.status != 200U || sync.response.status != 200U)
    {
        return {false, 400U, {}, "client-server flow failed"};
    }
    // Matrix E2EE: the server stores m.room.encrypted events opaquely and
    // relays them through /sync. Clients decrypt locally. The presence of
    // "m.room.encrypted" or ciphertext payloads in sync output is correct
    // behaviour, not a leak — the server never sees plaintext.
    return {true, 200U, sync.response.body, {}};
}

} // namespace merovingian::homeserver
