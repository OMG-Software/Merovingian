// SPDX-License-Identifier: GPL-3.0-or-later

// GCC 16 with -O2 and LTO emits a false-positive -Wmaybe-uninitialized warning
// in std::ranges::any_of when inlining DispatchResult's std::string members.
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif

#include "merovingian/homeserver/client_server.hpp"

#include "local_services.hpp"
#include "merovingian/auth/identity.hpp"
#include "merovingian/auth/key_api.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/core/query_params.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/outbound_membership.hpp"
#include "merovingian/federation/outbound_transaction.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/media_service.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/http/rate_limit.hpp"
#include "merovingian/http/request.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/rooms/room_version_policy.hpp"
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
    [[nodiscard]] auto request_header(LocalHttpRequest const& req, std::string_view name) noexcept
        -> std::string_view
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
    [[nodiscard]] auto resolve_allow_origin(LocalHttpRequest const& req, config::CorsConfig const& cors)
        -> std::string
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
    auto append_header_if_missing(std::vector<std::pair<std::string, std::string>>& headers,
                                  std::string_view name, std::string value) -> void
    {
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
    auto apply_cors_headers(LocalHttpRequest const& req, LocalHttpResponse& response,
                            config::CorsConfig const& cors) -> void
    {
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

    [[nodiscard]] auto dispatch_resp(LocalHttpRequest const& req, ClientServerRuntime const& rt,
                                     std::uint16_t status, std::string body) -> DispatchResult
    {
        auto response = LocalHttpResponse{status, std::move(body), {}};
        apply_cors_headers(req, response, rt.cors);
        return DispatchResult{DispatchResult::Status::complete, std::move(response), {}};
    }

    [[nodiscard]] auto dispatch_err(LocalHttpRequest const& req, ClientServerRuntime const& rt,
                                    std::uint16_t status, std::string_view errcode, std::string_view error)
        -> DispatchResult
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
        auto const tx_body_opt = federation::build_edu_transaction_body(edu_type, edu_content_json);
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

    struct MatrixLoginBody final
    {
        std::string user_id{};
        std::string password{};
        std::string device_id{};
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

    struct ReportPathParts final
    {
        std::string room_id{};
        std::string event_id{};
    };

    struct RoomSendPathParts final
    {
        std::string room_id{};
        std::string event_type{};
    };

    struct RoomStatePathParts final
    {
        std::string room_id{};
        std::string event_type{};
        std::string state_key{};
    };

    struct AdminReviewPathParts final
    {
        trust_safety::ReviewTarget target{trust_safety::ReviewTarget::media};
        std::string target_id{};
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

    [[nodiscard]] auto serialized_value(canonicaljson::Value const& value) -> std::optional<std::string>
    {
        auto serialized = canonicaljson::serialize_canonical(value);
        if (serialized.error != canonicaljson::CanonicalJsonError::none)
        {
            return std::nullopt;
        }
        return serialized.output;
    }

    [[nodiscard]] auto serialized_object_member(canonicaljson::Object const& object, std::string_view key)
        -> std::optional<std::string>
    {
        auto const* value = object_member(object, key);
        if (value == nullptr)
        {
            return std::nullopt;
        }
        return serialized_value(*value);
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
        return MatrixRegisterBody{*username, *password, token == nullptr ? std::string{} : *token};
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

    [[nodiscard]] auto find_registration_validation_session(ClientServerRuntime& rt, std::string_view medium,
                                                            std::string_view address, std::string_view client_secret,
                                                            std::optional<std::string_view> country = std::nullopt)
        -> RegistrationValidationSession*
    {
        auto const iterator = std::ranges::find_if(
            rt.registration_validation_sessions, [&](RegistrationValidationSession const& session) {
                if (session.medium != medium || session.address != address || session.client_secret != client_secret)
                {
                    return false;
                }
                if (country.has_value())
                {
                    return session.country.has_value() && *session.country == *country;
                }
                return !session.country.has_value();
            });
        return iterator == rt.registration_validation_sessions.end() ? nullptr : &(*iterator);
    }

    [[nodiscard]] auto ensure_registration_validation_session(ClientServerRuntime& rt, std::string_view medium,
                                                              std::string_view address, std::string_view client_secret,
                                                              std::uint64_t send_attempt,
                                                              std::optional<std::string> next_link = std::nullopt,
                                                              std::optional<std::string> country = std::nullopt)
        -> RegistrationValidationSession&
    {
        auto* existing = find_registration_validation_session(
            rt, medium, address, client_secret,
            country.has_value() ? std::optional<std::string_view>{*country} : std::nullopt);
        if (existing != nullptr)
        {
            existing->send_attempt = std::max(existing->send_attempt, send_attempt);
            existing->next_link = next_link;
            return *existing;
        }

        rt.registration_validation_sessions.push_back({generate_registration_session_id(), std::string{medium},
                                                       std::string{address}, std::string{client_secret},
                                                       std::move(country), std::move(next_link), send_attempt});
        return rt.registration_validation_sessions.back();
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
        auto const* supports_refresh_tokens = boolean_member(*object, "refresh_token");
        return MatrixLoginBody{matrix_user_id(server_name, *user), *password,
                               device_id == nullptr ? std::string{} : *device_id,
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

    [[nodiscard]] auto auth(ClientServerRuntime const& rt, std::string_view token) -> std::optional<std::string>
    {
        return authenticated_user(rt.homeserver, token);
    }

    [[nodiscard]] auto normalized_bucket(LocalHttpRequest const& req) -> std::string
    {
        auto constexpr room_prefix = std::string_view{"/_matrix/client/v3/rooms/"};
        auto constexpr device_prefix = std::string_view{"/_matrix/client/v3/devices/"};
        // Prefix the bucket with the caller's access token so authenticated
        // endpoints quota each client independently. Unauthenticated routes
        // (login, register, versions, /_matrix/key/v2/server) carry an empty
        // token and still share a global bucket per route; scoping those by
        // remote IP needs `LocalHttpRequest` to grow a `remote_addr` field
        // and is tracked as a follow-up alongside the federation discovery
        // work in `docs/01-progress-tracker.md`.
        auto identity = req.access_token + '|';
        auto target = std::string_view{req.target};
        if (starts_with(target, room_prefix) && ends_with(target, "/join"))
        {
            return identity + req.method + " /_matrix/client/v3/rooms/{roomId}/join";
        }
        if (starts_with(target, room_prefix) && ends_with(target, "/send"))
        {
            return identity + req.method + " /_matrix/client/v3/rooms/{roomId}/send";
        }
        if (starts_with(target, room_prefix) && ends_with(target, "/state"))
        {
            return identity + req.method + " /_matrix/client/v3/rooms/{roomId}/state";
        }
        if (starts_with(target, device_prefix))
        {
            return identity + req.method + " /_matrix/client/v3/devices/{deviceId}";
        }
        auto constexpr user_prefix = std::string_view{"/_matrix/client/v3/user/"};
        if (starts_with(target, user_prefix) && ends_with(target, "/filter"))
        {
            return identity + req.method + " /_matrix/client/v3/user/{userId}/filter";
        }
        if (starts_with(target, user_prefix) && target.find("/filter/") != std::string_view::npos)
        {
            return identity + req.method + " /_matrix/client/v3/user/{userId}/filter/{filterId}";
        }
        if (starts_with(target, user_prefix) && target.find("/account_data/") != std::string_view::npos)
        {
            return identity + req.method + " /_matrix/client/v3/user/{userId}/account_data/{type}";
        }
        if (starts_with(target, "/_matrix/client/v3/join/"))
        {
            return identity + req.method + " /_matrix/client/v3/join/{roomIdOrAlias}";
        }
        auto constexpr profile_prefix = std::string_view{"/_matrix/client/v3/profile/"};
        if (starts_with(target, profile_prefix))
        {
            return identity + req.method + " /_matrix/client/v3/profile/{userId}";
        }
        if (trust_safety::match_reporting_api_route(req.method, target).matched)
        {
            return identity + req.method + " /_matrix/client/v3/trust-safety/{route}";
        }
        return identity + req.method + ' ' + req.target;
    }

    // Per-bucket request limiter. The cap is the lower of the per-endpoint
    // `http::endpoint_default_rate_limit` quota (login and register 5,
    // keys and devices 30, media 20, federation 120, default 60) and the
    // runtime-configured `ClientApiLimits::max_requests_per_bucket` ceiling
    // (which tests use to drive the limiter from a single request). The
    // window length stays in request-count units via
    // `ClientApiLimits::rate_limit_window_requests`; switching the window
    // to wall-clock seconds is a follow-up that needs an injectable time
    // source to remain unit-testable without sleeps.
    [[nodiscard]] auto allow(ClientServerRuntime& rt, LocalHttpRequest const& req) -> bool
    {
        ++rt.request_clock;
        auto const policy = http::endpoint_default_rate_limit(req.method, req.target);
        if (!http::rate_limit_policy_is_valid(policy))
        {
            return false;
        }
        auto const max_requests = std::min(rt.limits.max_requests_per_bucket, policy.max_requests);
        auto const bucket = normalized_bucket(req);
        auto const it = std::ranges::find_if(rt.rate_limits, [&bucket](ClientRateLimitCounter const& c) {
            return c.bucket == bucket;
        });
        if (it == rt.rate_limits.end())
        {
            rt.rate_limits.push_back({bucket, 1U, rt.request_clock});
            return true;
        }
        if (rt.request_clock - it->window_start_request >= rt.limits.rate_limit_window_requests)
        {
            it->count = 0U;
            it->window_start_request = rt.request_clock;
        }
        if (it->count >= max_requests)
        {
            return false;
        }
        ++it->count;
        return true;
    }

    [[nodiscard]] auto find_device(ClientServerRuntime& rt, std::string_view user, std::string_view device)
        -> ClientDevice*
    {
        auto const it = std::ranges::find_if(rt.devices, [user, device](ClientDevice const& d) {
            return d.user_id == user && d.device_id == device;
        });
        return it == rt.devices.end() ? nullptr : &(*it);
    }

    [[nodiscard]] auto first_device_id(ClientServerRuntime const& rt, std::string_view user) -> std::string
    {
        auto const it = std::ranges::find_if(rt.devices, [user](ClientDevice const& d) {
            return d.user_id == user;
        });
        return it == rt.devices.end() ? std::string{} : it->device_id;
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

    [[nodiscard]] auto joined(LocalRoom const& room, std::string_view user) -> bool
    {
        return std::ranges::any_of(room.members, [user](std::string const& member) {
            return member == user;
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

    [[nodiscard]] auto public_rooms_json(ClientServerRuntime const& rt) -> std::string
    {
        auto chunk = canonicaljson::Array{};
        auto const& store = rt.homeserver.database.persistent_store;
        // Build the index once for the whole response — all per-room state lookups below are O(log n).
        auto const index = build_state_index(store);
        for (auto const& room : rt.homeserver.database.rooms)
        {
            auto const join_rule = room_state_string(store, index, room.room_id, "m.room.join_rules", "join_rule");
            if (!join_rule.has_value() || *join_rule != "public")
            {
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

            if (auto const name = room_state_string(store, index, room.room_id, "m.room.name", "name");
                name.has_value())
            {
                room_entry.push_back(json_member("name", json_str(*name)));
            }
            if (auto const topic = room_state_string(store, index, room.room_id, "m.room.topic", "topic");
                topic.has_value())
            {
                room_entry.push_back(json_member("topic", json_str(*topic)));
            }
            if (auto const alias = room_state_string(store, index, room.room_id, "m.room.canonical_alias", "alias");
                alias.has_value())
            {
                room_entry.push_back(json_member("canonical_alias", json_str(*alias)));
            }
            if (auto const avatar = room_state_string(store, index, room.room_id, "m.room.avatar", "url");
                avatar.has_value())
            {
                room_entry.push_back(json_member("avatar_url", json_str(*avatar)));
            }
            chunk.push_back(json_obj(std::move(room_entry)));
        }
        auto const total_room_count = static_cast<std::int64_t>(chunk.size());

        return json_serialize(json_obj({
            json_member("chunk", json_arr(std::move(chunk))),
            json_member("total_room_count_estimate", json_int(total_room_count)),
        }));
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
        auto parsed = canonicaljson::parse_lossless(encoded);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return canonicaljson::Value{canonicaljson::Object{}};
        }
        return std::move(parsed.value);
    }

    [[nodiscard]] auto build_to_device_events_array(database::PersistentStore& store, std::string_view user,
                                                    std::string_view device_id, std::uint64_t since_sync_stream_id,
                                                    std::uint64_t& max_observed_stream_id) -> canonicaljson::Array
    {
        auto events = canonicaljson::Array{};
        auto const drained = database::drain_to_device_messages(store, user, device_id, since_sync_stream_id);
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

        // Long-poll: when the caller passes `timeout` and there's nothing
        // new to deliver, block until the SyncNotifier fires or the timeout
        // expires. The check is "is anything past since visible?"; we wake
        // when the store's sync stream id advances OR a new event appears
        // in the timeline ordering, both of which the mutator helpers below
        // publish through `ensure_sync_notifier(rt).publish(...)`.
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

        auto max_observed_sync_stream_id = since_sync_stream_id;
        auto join_members = canonicaljson::Object{};
        auto join_count = std::size_t{0U};

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
            auto timeline_events = canonicaljson::Array{};
            auto event_count = std::size_t{0U};
            auto const timeline_cap = filter.room.timeline.limit != 0U
                                          ? std::min(filter.room.timeline.limit, rt.limits.max_sync_events_per_room)
                                          : rt.limits.max_sync_events_per_room;

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
                if (event_count >= timeline_cap)
                {
                    break;
                }
                timeline_events.push_back(client_event_value(event));
                ++event_count;
            }

            auto const limited = store.events.size() > timeline_cap;
            auto room_account_data = build_account_data_events(store, filter.room.account_data, user, room.room_id,
                                                               since_sync_stream_id, max_observed_sync_stream_id);

            // Build the room's current state events. For initial sync
            // (no since token) include all current state so clients can
            // derive room version, power levels, join rules, etc. For
            // incremental sync the timeline events already carry any
            // state changes.
            auto state_events = canonicaljson::Array{};
            if (!since_token.has_value())
            {
                for (auto const& state_entry : store.state)
                {
                    if (state_entry.room_id != room.room_id)
                    {
                        continue;
                    }
                    for (auto const& evt : store.events)
                    {
                        if (evt.event_id == state_entry.event_id)
                        {
                            state_events.push_back(client_event_value(evt));
                            break;
                        }
                    }
                }
            }

            // Incremental sync: suppress rooms that have nothing new to report.
            // Without this check, re-dispatches after a long-poll timeout emit
            // the full membership state of every joined room on every 5-second
            // cycle, causing clients to receive the same stale payload repeatedly
            // and making it appear as if the room is stuck.
            if (since_token.has_value() && timeline_events.empty() && room_account_data.empty())
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
                                    json_member("event_count", json_int(static_cast<std::int64_t>(event_count))),
                                })),
                    json_member("state", json_obj({json_member("events", json_arr(std::move(state_events)))})),
                    json_member("account_data",
                                json_obj({json_member("events", json_arr(std::move(room_account_data)))})),
                    json_member("ephemeral", json_obj({json_member("events", json_arr({}))})),
                })));
        }

        // Invite list. `rooms.leave` is suppressed unless the filter opts in
        // via `include_leave: true`; we now actually honour that flag.
        auto invite_members = canonicaljson::Object{};
        auto leave_members = canonicaljson::Object{};
        auto invite_count = std::size_t{0U};
        auto leave_count = std::size_t{0U};
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
        }

        auto to_device_events =
            build_to_device_events_array(store, user, device_id, since_sync_stream_id, max_observed_sync_stream_id);
        auto [device_changed, device_left] =
            build_device_list_arrays(store, user, since_sync_stream_id, max_observed_sync_stream_id);
        auto presence_events =
            build_presence_events(store, filter.presence, user, since_sync_stream_id, max_observed_sync_stream_id);
        auto global_account_data = build_account_data_events(store, filter.account_data, user, std::string_view{},
                                                             since_sync_stream_id, max_observed_sync_stream_id);
        auto otk_counts = build_otk_counts(store, user, device_id);
        auto fallback_key_types = build_fallback_key_types(store, user, device_id);

        auto const advanced_sync_stream_id = std::max(max_observed_sync_stream_id, store.next_sync_stream_id);
        auto const next_token =
            sync::StreamToken{rt.homeserver.database.next_stream_ordering - 1U,
                              rt.homeserver.database.next_stream_ordering - 1U, advanced_sync_stream_id};

        auto const body = json_serialize(json_obj({
            json_member("next_batch", json_str(sync::encode_stream_token(next_token))),
            json_member("rooms", json_obj({
                                     json_member("join", json_obj(std::move(join_members))),
                                     json_member("invite", json_obj(std::move(invite_members))),
                                     json_member("leave", json_obj(std::move(leave_members))),
                                     json_member("knock", json_obj({})),
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
        }));
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

    [[nodiscard]] auto handle_key_upload(ClientServerRuntime& rt, std::string_view user, std::string_view device_id,
                                         std::string_view body) -> LocalHttpResponse
    {
        auto const object = parsed_json_object(body);
        if (!object.has_value())
        {
            return err(400U, "M_BAD_JSON", "key upload body must be Matrix JSON");
        }
        auto& store = rt.homeserver.database.persistent_store;
        if (auto const device_keys = serialized_object_member(*object, "device_keys");
            device_keys.has_value() &&
            !database::store_device_key(store, {std::string{user}, std::string{device_id}, *device_keys}))
        {
            return err(500U, "M_UNKNOWN", "device key persistence failed");
        }
        // Device key uploads change the device identity that other users
        // track; notify every user who shares a room with this user.
        if (serialized_object_member(*object, "device_keys").has_value())
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
        }
        if (auto const* keys = object_member_object(*object, "one_time_keys");
            keys != nullptr && !store_key_object_members(rt, user, device_id, *keys, false))
        {
            return err(500U, "M_UNKNOWN", "one-time key persistence failed");
        }
        if (auto const* keys = object_member_object(*object, "fallback_keys");
            keys != nullptr && !store_key_object_members(rt, user, device_id, *keys, true))
        {
            return err(500U, "M_UNKNOWN", "fallback key persistence failed");
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

    [[nodiscard]] auto handle_key_query(ClientServerRuntime& rt, std::string_view body) -> LocalHttpResponse
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
                else if (cskey.key_type == "user_signing")
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
                std::string{reinterpret_cast<char const*>(rt.homeserver.database.signing_secret_key.data()),
                            rt.homeserver.database.signing_secret_key.size()};
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
                std::string{reinterpret_cast<char const*>(rt.homeserver.database.signing_secret_key.data()),
                            rt.homeserver.database.signing_secret_key.size()};
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

    // Dispatch a single EDU to a specific remote server without needing a
    // room — used for m.direct_to_device delivery where the destinations are
    // known from the recipient user IDs rather than room membership.
    auto dispatch_edu_to_server(HomeserverRuntime& runtime, std::string_view destination, std::string_view edu_type,
                                std::string_view edu_content_json) -> bool
    {
        wire_federation_callbacks(runtime);
        if (runtime.dispatch_worker == nullptr)
        {
            return false;
        }
        // Shared builder keys the EDU by "edu_type" per the federation spec.
        auto const tx_body = federation::build_edu_transaction_body(edu_type, edu_content_json);
        if (!tx_body.has_value())
        {
            return false;
        }
        auto const& server_name = runtime.config.server().server_name;
        auto const tx_id = federation::make_federation_transaction_id();
        auto target = "/_matrix/federation/v1/send/" + tx_id;
        auto transaction =
            federation::make_outbound_transaction(std::string{destination}, "PUT", target, server_name, *tx_body);
        transaction.transaction_id = tx_id;
        return runtime.dispatch_worker->enqueue(std::move(transaction));
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
                    // Enqueue directly; /sync drains it into to_device.events.
                    std::ignore = push_to_device_message(rt, {0U, std::string{sender}, user_entry.key, device_entry.key,
                                                              std::string{event_type}, *content});
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
                                 core::percent_decode_path_component(event_and_txn.substr(0U, separator))};
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
            chunk.push_back(parse_event_json_object(event.json));
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
        return json_serialize(json_obj({
            json_member("chunk", json_arr(std::move(chunk))),
            json_member("start", json_str(start_token)),
            json_member("end", json_str(end_token)),
            json_member("state", json_arr(canonicaljson::Array{})),
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

    auto append_policy_audit(ClientServerRuntime& rt, trust_safety::SafetyAuditEvent const& event) -> void
    {
        append_local_audit(rt.homeserver.database, observability::AuditCategory::policy, event.event_type, event.actor,
                           event.entity, event.reason.code);
    }

    [[nodiscard]] auto store_key_api_payload(ClientServerRuntime& rt, auth::KeyApiEndpoint endpoint,
                                             std::string_view user, std::string_view /*device_id*/,
                                             LocalHttpRequest const& req) -> bool
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
            return database::store_key_backup_version(store, {std::string{user}, "1", req.body});
        case auth::KeyApiEndpoint::put_room_key_backup: {
            auto const path = room_key_backup_path_parts(req.target);
            if (!path.has_value() || !path->session_id.has_value())
            {
                return false;
            }
            return database::store_key_backup_session(
                store, {std::string{user}, "1", path->room_id, *path->session_id, req.body});
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
                if (!database::store_key_backup_session(
                        store, {std::string{user}, "1", path->room_id, session.key, serialized.output}))
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
                        store, {std::string{user}, "1", room.key, session.key, session_json.output});
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
            return database::delete_key_backup_session(store, user, "1", path->room_id, *path->session_id);
        }
        case auth::KeyApiEndpoint::delete_room_key_backup_room: {
            auto const path = room_key_backup_path_parts(req.target);
            if (!path.has_value() || path->session_id.has_value())
            {
                return false;
            }
            return database::delete_key_backup_room_sessions(store, user, "1", path->room_id);
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
            return handle_key_query(rt, req.body);
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
        case auth::KeyApiEndpoint::upload_cross_signing_keys:
        case auth::KeyApiEndpoint::upload_signatures:
        case auth::KeyApiEndpoint::create_key_backup_version:
        case auth::KeyApiEndpoint::update_key_backup_version:
            if (!store_key_api_payload(rt, route.endpoint, user, device_id, req))
            {
                return err(500U, "M_UNKNOWN", "key API persistence failed");
            }
            return resp(200U, key_api_success_body(route.endpoint));
        case auth::KeyApiEndpoint::delete_key_backup_version:
            if (!store_key_api_payload(rt, route.endpoint, user, device_id, req))
            {
                return err(500U, "M_UNKNOWN", "key API persistence failed");
            }
            return resp(200U, key_api_success_body(route.endpoint));
        case auth::KeyApiEndpoint::put_room_key_backup:
        case auth::KeyApiEndpoint::put_room_key_backup_room:
        case auth::KeyApiEndpoint::put_room_key_backup_batch:
        case auth::KeyApiEndpoint::delete_room_key_backup_room:
        case auth::KeyApiEndpoint::delete_room_key_backup:
        case auth::KeyApiEndpoint::delete_room_key_backup_batch:
            if (!store_key_api_payload(rt, route.endpoint, user, device_id, req))
            {
                return err(500U, "M_UNKNOWN", "key API persistence failed");
            }
            return resp(200U, room_keys_update_response(rt.homeserver.database.persistent_store, user, "1"));
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
        return handle_client_server_request(
                   rt, {parsed.request.method, parsed.request.target, bearer_access_token(parsed.request.headers),
                        std::string{available_body}, parsed.request.headers},
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

auto handle_client_server_request(ClientServerRuntime& rt, LocalHttpRequest const& req, bool can_wait) -> DispatchResult
{
    log_diagnostic("request.received", {
                                           {"method",           req.method,                                       false},
                                           {"target",           observability::sanitized_http_target(req.target), false},
                                           {"body_bytes",       std::to_string(req.body.size()),                  false},
                                           {"has_access_token", req.access_token.empty() ? "false" : "true",      false},
    });
    if (!rt.homeserver.started)
    {
        log_diagnostic("request.rejected", {
                                               {"method", req.method,                                       false},
                                               {"target", observability::sanitized_http_target(req.target), false},
                                               {"status", "503",                                            false},
                                               {"reason", "runtime not started",                            false}
        });
        return dispatch_err(req, rt, 503U, "M_UNAVAILABLE", "runtime not started");
    }
    if (req.body.size() > rt.limits.max_body_bytes)
    {
        log_diagnostic("request.rejected", {
                                               {"method",      req.method,                                       false},
                                               {"target",      observability::sanitized_http_target(req.target), false},
                                               {"status",      "413",                                            false},
                                               {"body_bytes",  std::to_string(req.body.size()),                  false},
                                               {"limit_bytes", std::to_string(rt.limits.max_body_bytes),         false},
                                               {"reason",      "request body too large",                         false}
        });
        return dispatch_err(req, rt, 413U, "M_TOO_LARGE", "request body too large");
    }
    auto guard = std::unique_lock<std::recursive_mutex>{rt.homeserver.mutex};
    if (!allow(rt, req))
    {
        log_diagnostic("request.rejected", {
                                               {"method", req.method,                                       false},
                                               {"target", observability::sanitized_http_target(req.target), false},
                                               {"status", "429",                                            false},
                                               {"reason", "rate limit exceeded",                            false}
        });
        return dispatch_err(req, rt, 429U, "M_LIMIT_EXCEEDED", "rate limit exceeded");
    }
    auto call_local = [&](LocalHttpRequest const& inner) {
        guard.unlock();
        auto response = handle_local_http_request(rt.homeserver, inner);
        guard.lock();
        return response;
    };

    // CORS preflight: browsers send OPTIONS before any cross-origin POST/PUT/DELETE.
    // Must return 200 before the access-token gate. The `Access-Control-*`
    // response headers are attached by `dispatch_resp` from the runtime's
    // CORS policy, so deployments behind a reverse proxy (nginx/Apache)
    // no longer need the proxy to add CORS headers.
    if (req.method == "OPTIONS")
    {
        return dispatch_resp(req, rt, 200U, {});
    }

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
        return dispatch_resp(req, rt, 200U, json_serialize(json_obj({
                                       json_member("versions", json_arr(std::move(versions))),
                                       json_member("unstable_features", json_obj({})),
                                   })));
    }

    auto const request_path = std::string_view{req.target}.substr(0U, std::string_view{req.target}.find('?'));
    if (req.method == "GET" && request_path == "/_matrix/client/v3/publicRooms")
    {
        return dispatch_resp(req, rt, 200U, public_rooms_json(rt));
    }
    auto constexpr directory_room_prefix = std::string_view{"/_matrix/client/v3/directory/room/"};
    if (req.method == "GET" && starts_with(request_path, directory_room_prefix))
    {
        auto const encoded_alias = request_path.substr(directory_room_prefix.size());
        auto const room_alias = core::percent_decode_path_component(encoded_alias);
        auto const found = database::find_room_alias(rt.homeserver.database.persistent_store, room_alias);
        if (!found.has_value())
        {
            return dispatch_err(req, rt, 404U, "M_NOT_FOUND", "room alias not found");
        }
        auto servers = canonicaljson::Array{};
        servers.push_back(json_str(rt.homeserver.config.server().server_name));
        return dispatch_resp(req, rt, 200U, json_serialize(json_obj({
                                       json_member("room_id", json_str(found->room_id)),
                                       json_member("servers", json_arr(std::move(servers))),
                                   })));
    }

    if (req.method == "GET" && request_path == "/_matrix/client/v3/register/available")
    {
        auto const username = query_param_value(req.target, "username");
        if (!username.has_value() || username->empty())
        {
            return dispatch_err(req, rt, 400U, "M_MISSING_PARAM", "username is required");
        }
        if (!auth::localpart_is_valid(*username))
        {
            return dispatch_err(req, rt, 400U, "M_INVALID_USERNAME", "desired username is not valid");
        }
        auto const user_id = matrix_user_id(rt.homeserver.config.server().server_name, *username);
        if (user_exists(rt, user_id))
        {
            return dispatch_err(req, rt, 400U, "M_USER_IN_USE", "desired username is already taken");
        }
        return dispatch_resp(req, rt, 200U, json_serialize(json_obj({json_member("available", canonicaljson::Value{true})})));
    }

    if (req.method == "GET" && request_path == "/_matrix/client/v1/register/m.login.registration_token/validity")
    {
        auto const token = query_param_value(req.target, "token");
        if (!token.has_value() || token->empty())
        {
            return dispatch_err(req, rt, 400U, "M_MISSING_PARAM", "token is required");
        }
        auto const configured_token = configured_registration_token(rt.homeserver.config);
        auto const valid = !configured_token.empty() && configured_token == *token;
        return dispatch_resp(req, rt, 200U, json_serialize(json_obj({json_member("valid", canonicaljson::Value{valid})})));
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
        auto& session = ensure_registration_validation_session(rt, "email", body->email, body->client_secret,
                                                               body->send_attempt, body->next_link);
        return dispatch_resp(req, rt, 200U, json_serialize(json_obj({json_member("sid", json_str(session.sid))})));
    }

    if (req.method == "POST" && req.target == "/_matrix/client/v3/register/msisdn/requestToken")
    {
        auto const body = parse_register_msisdn_request_body(req.body);
        if (!body.has_value())
        {
            return dispatch_err(req, rt,
                400U, "M_BAD_JSON",
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
        auto const address = body->country + ":" + body->phone_number;
        auto& session = ensure_registration_validation_session(rt, "msisdn", address, body->client_secret,
                                                               body->send_attempt, body->next_link, body->country);
        return dispatch_resp(req, rt, 200U, json_serialize(json_obj({json_member("sid", json_str(session.sid))})));
    }

    if (req.method == "POST" && req.target == "/_matrix/client/v3/register")
    {
        auto const registration_object = parsed_json_object(req.body);
        if (!registration_object.has_value())
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "registration body must be Matrix JSON");
        }
        // Matrix UI-auth: the auth dict must contain a recognized type with all
        // required parameters.  Per spec v1.18 §5.5.1, incomplete credentials MUST
        // receive 401 with the challenge — not proceed to registration and fail 403.
        auto const uia_challenge = json_obj({
            json_member("flows",
                        json_arr({json_obj({json_member("stages", json_arr({json_str("m.login.registration_token")}))})})),
            json_member("params", json_obj({})),
            json_member("session", json_str("merovingian-ui-auth")),
        });
        auto const* auth = object_member_object(*registration_object, "auth");
        if (auth == nullptr)
        {
            return dispatch_resp(req, rt, 401U, json_serialize(uia_challenge));
        }
        // Validate that auth.type is the expected stage and that the required
        // parameter (token) is present.  Unknown or incomplete types get 401.
        auto const* auth_type = string_member(*auth, "type");
        if (auth_type == nullptr || *auth_type != "m.login.registration_token")
        {
            return dispatch_resp(req, rt, 401U, json_serialize(uia_challenge));
        }
        if (string_member(*auth, "token") == nullptr)
        {
            return dispatch_resp(req, rt, 401U, json_serialize(uia_challenge));
        }
        auto const body = parse_register_body(req.body);
        if (!body.has_value())
        {
            return dispatch_err(req, rt, 400U, "M_BAD_JSON", "registration body must contain username and password");
        }
        if (!auth::localpart_is_valid(body->localpart))
        {
            return dispatch_err(req, rt, 400U, "M_INVALID_USERNAME", "desired username is not valid");
        }
        auto const result =
            register_local_user(rt.homeserver, body->localpart, body->password, body->registration_token);
        if (!result.ok)
        {
            return dispatch_err(req, rt,result.status, registration_error_code(result.status, result.reason), result.reason);
        }
        // Spec §5.5.1: when inhibit_login is false (the default), the response
        // MUST include access_token and device_id.  Create a session immediately
        // so the client can act without a separate /login round trip.
        auto const full_user_id = result.value;
        auto const reg_device_id = std::string{body->localpart} + "_DEVICE";
        auto const session = login_local_user(rt.homeserver, full_user_id, body->password, reg_device_id);
        if (!session.ok)
        {
            // Session creation failed — return user_id only.
            return dispatch_resp(req, rt, 200U, json_serialize(json_obj({json_member("user_id", json_str(full_user_id))})));
        }
        // Note: we intentionally do NOT push to rt.devices here. The registration
        // device is ephemeral; rt.devices is populated only by explicit /login calls
        // so that /devices and device-count queries reflect user-chosen sessions.
        return dispatch_resp(req, rt, 200U, json_serialize(json_obj({
                                       json_member("access_token", json_str(session.value)),
                                       json_member("user_id", json_str(full_user_id)),
                                       json_member("device_id", json_str(reg_device_id)),
                                   })));
    }
    if (req.method == "GET" && req.target == "/_matrix/client/v3/login")
    {
        return dispatch_resp(req, rt,
            200U, json_serialize(json_obj({
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
        auto const result = login_local_user(rt.homeserver, body->user_id, body->password, body->device_id);
        if (!result.ok)
        {
            return dispatch_err(req, rt,result.status, "M_FORBIDDEN", result.reason);
        }
        if (find_device(rt, body->user_id, body->device_id) == nullptr)
        {
            rt.devices.push_back({body->user_id, body->device_id, body->device_id});
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
                return dispatch_err(req, rt,refresh_token.status, "M_UNKNOWN", refresh_token.reason);
            }
            response_body.push_back(json_member("refresh_token", json_str(refresh_token.value)));
            response_body.push_back(json_member("expires_in_ms", json_int(3600000)));
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
            return dispatch_err(req, rt,refreshed.status, refreshed.status == 401U ? "M_UNKNOWN_TOKEN" : "M_UNKNOWN",
                                refreshed.reason);
        }
        if (find_device(rt, refreshed.user_id, refreshed.device_id) == nullptr)
        {
            rt.devices.push_back({refreshed.user_id, refreshed.device_id, refreshed.device_id});
        }
        return dispatch_resp(req, rt, 200U, json_serialize(json_obj({
                                       json_member("access_token", json_str(refreshed.access_token)),
                                       json_member("refresh_token", json_str(refreshed.refresh_token)),
                                       json_member("expires_in_ms", json_int(3600000)),
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
        return r.status == 200U ? dispatch_resp(req, rt, 200U, "{}")
                                : dispatch_err(req, rt,r.status, r.status == 401U ? "M_UNKNOWN_TOKEN" : "M_UNKNOWN", r.body);
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
        auto const r = call_local(req);
        return r.status == 200U ? dispatch_resp(req, rt, 200U, r.body)
                                : dispatch_err(req, rt,r.status, r.status == 404U ? "M_NOT_FOUND" : "M_UNKNOWN", r.body);
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
        auto const r = call_local(req);
        return r.status == 200U ? dispatch_resp(req, rt, 200U, r.body)
                                : dispatch_err(req, rt,r.status, r.status == 404U ? "M_NOT_FOUND" : "M_UNKNOWN", r.body);
    }

    // GET /_matrix/client/v1/media/download/{serverName}/{mediaId}
    // Authenticated media download. Delegates to the local router.
    auto constexpr media_v1_download_prefix = std::string_view{"/_matrix/client/v1/media/download/"};
    if (req.method == "GET" && starts_with(req.target, media_v1_download_prefix))
    {
        auto const r = call_local(req);
        return r.status == 200U ? dispatch_resp(req, rt, 200U, r.body)
                                : dispatch_err(req, rt,r.status, r.status == 404U ? "M_NOT_FOUND" : "M_UNKNOWN", r.body);
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
            return dispatch_resp(req, rt, 200U, json_serialize(json_obj({
                                           json_member("displayname", json_str(displayname)),
                                           json_member("avatar_url", json_str(avatar_url)),
                                       })));
        }
        // getProfileField returns only the requested key; an unset or unknown
        // field is reported as 404 M_NOT_FOUND per the Matrix spec.
        if (field == "displayname" && !displayname.empty())
        {
            return dispatch_resp(req, rt, 200U, json_serialize(json_obj({json_member("displayname", json_str(displayname))})));
        }
        if (field == "avatar_url" && !avatar_url.empty())
        {
            return dispatch_resp(req, rt, 200U, json_serialize(json_obj({json_member("avatar_url", json_str(avatar_url))})));
        }
        return dispatch_err(req, rt, 404U, "M_NOT_FOUND", "profile field not found");
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
        // Spec §5.7.2: M_MISSING_TOKEN when no token is supplied;
        // M_UNKNOWN_TOKEN when a token is present but not recognised.
        return dispatch_err(req, rt,401U, req.access_token.empty() ? "M_MISSING_TOKEN" : "M_UNKNOWN_TOKEN", "unauthenticated");
    }
    log_diagnostic("request.auth.accepted", {
                                                {"method", req.method,                                       false},
                                                {"target", observability::sanitized_http_target(req.target), false},
                                                {"actor",  *user,                                            false}
    });
    if (req.method == "POST" && req.target == "/_matrix/client/v3/logout/all")
    {
        auto const r = logout_all_local_user(rt.homeserver, req.access_token);
        log_diagnostic(r.ok ? "account.logout_all.accepted" : "account.logout_all.rejected",
                       {
                           {"actor",  *user,                    false},
                           {"status", std::to_string(r.status), false}
        });
        return r.ok ? dispatch_resp(req, rt, 200U, "{}")
                    : dispatch_err(req, rt,r.status, r.status == 401U ? "M_UNKNOWN_TOKEN" : "M_UNKNOWN", r.reason);
    }
    if (req.method == "GET" && req.target == "/_matrix/client/v3/account/whoami")
    {
        auto const whoami_device = first_device_id(rt, *user);
        log_diagnostic("account.whoami", {
                                             {"actor", *user, false}
        });
        return dispatch_resp(req, rt, 200U, json_serialize(json_obj({
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
            return existing->room_id == *room_id ? dispatch_resp(req, rt, 200U, "{}")
                                                 : dispatch_err(req, rt, 409U, "M_ROOM_IN_USE", "room alias already in use");
        }
        if (!database::store_room_alias(rt.homeserver.database.persistent_store, {room_alias, *room_id}))
        {
            return dispatch_err(req, rt, 500U, "M_UNKNOWN", "failed to persist room alias");
        }
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
        auto const result = change_local_user_password(rt.homeserver, req.access_token, *new_password);
        if (!result.ok)
        {
            return dispatch_err(req, rt,result.status, result.status == 401U ? "M_UNKNOWN_TOKEN" : "M_FORBIDDEN",
                                result.reason);
        }
        return dispatch_resp(req, rt, 200U, "{}");
    }
    // Spec: GET /account/3pid returns the third-party IDs linked to the
    // authenticated user. Merovingian does not yet support 3PID binding,
    // so return the spec-required empty list so Element's settings UI
    // does not show a spurious error.
    if (req.method == "GET" && req.target == "/_matrix/client/v3/account/3pid")
    {
        return dispatch_resp(req, rt, 200U, R"({"threepids":[]})");
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
        return dispatch_resp(req, rt,
            200U, json_serialize(json_obj({json_member(
                      "capabilities",
                      json_obj({
                          json_member("m.change_password", json_obj({json_member("enabled", json_bool(true))})),
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
                       : dispatch_resp(req, rt,
                             200U, json_serialize(json_obj({json_member("actions", canonicaljson::Value{*actions})})));
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
                       : dispatch_resp(req, rt, 200U, json_serialize(json_obj({json_member("enabled", json_bool(*enabled))})));
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
    // Reports the maximum upload size so clients know how large a file they
    // may attach. The value is sourced from security.media.max_upload_size so
    // client hints match the repository policy enforced during upload.
    if (req.method == "GET" && req.target == "/_matrix/media/v3/config")
    {
        auto const parsed_limit = config::parse_size_limit(rt.homeserver.config.security().media.max_upload_size);
        auto const bounded_limit = std::min(parsed_limit.valid ? parsed_limit.bytes : std::uint64_t{104857600U},
                                            static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()));
        auto const max_upload_bytes = static_cast<std::int64_t>(bounded_limit);
        return dispatch_resp(req, rt, 200U, 
                             json_serialize(json_obj({json_member("m.upload.size", json_int(max_upload_bytes))})));
    }
    if (req.method == "POST" && req.target == "/_matrix/media/v3/upload")
    {
        auto const r = call_local(req);
        return r.status == 200U
                   ? dispatch_resp(req, rt, 200U, media_upload_response_json(r.body))
                   : dispatch_err(req, rt,r.status, r.status == 401U ? "M_UNKNOWN_TOKEN" : "M_BAD_REQUEST", r.body);
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
        auto const device_id = first_device_id(rt, *user);
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
        auto const device_id = std::string_view{req.target}.substr(dev_prefix.size());
        auto const result = delete_local_device(rt.homeserver, *user, device_id);
        if (!result.ok)
        {
            return dispatch_err(req, rt,result.status, result.status == 404U ? "M_NOT_FOUND" : "M_UNKNOWN", result.reason);
        }
        auto const [first, last] = std::ranges::remove_if(rt.devices, [user, device_id](ClientDevice const& device) {
            return device.user_id == *user && device.device_id == device_id;
        });
        rt.devices.erase(first, last);
        // Notify all users who share rooms with this user that the device
        // list has changed so their /sync streams surface the update.
        for (auto const& room : rt.homeserver.database.rooms)
        {
            auto const is_member = std::ranges::any_of(room.members, [user](auto const& m) {
                return m == *user;
            });
            if (!is_member)
            {
                continue;
            }
            for (auto const& member : room.members)
            {
                if (member == *user)
                {
                    continue;
                }
                auto const change = database::PersistentDeviceListChange{0U, member, std::string{*user}, "changed"};
                std::ignore = record_device_list_change(rt, change);
            }
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
    // Spec: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3sendtoeventtypetxnid
    if (req.method == "PUT")
    {
        if (auto const path = send_to_device_path_parts(req.target); path.has_value())
        {
            return complete(handle_send_to_device(rt, path->event_type, path->txn_id, *user, req.body));
        }
    }
    // GET /_matrix/client/v3/keys/changes[?from=...&to=...]
    // Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3keyschanges
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
            return dispatch_err(req, rt,create_result.status, errcode, create_result.reason);
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
        auto const sync_request = merovingian::core::parse_query_params(req.target);
        log_diagnostic("sync.dispatch", {
                                            {"actor",     *user,     false},
                                            {"device_id", device_id, false}
        });
        return sync_json(rt, *user, device_id, sync_request, can_wait);
    }

    auto constexpr room_prefix = std::string_view{"/_matrix/client/v3/rooms/"};
    if (starts_with(req.target, room_prefix))
    {
        auto constexpr join_s = std::string_view{"/join"};
        auto constexpr send_s = std::string_view{"/send"};
        auto constexpr state_s = std::string_view{"/state"};
        auto constexpr leave_s = std::string_view{"/leave"};
        auto constexpr read_markers_s = std::string_view{"/read_markers"};
        auto constexpr receipt_s = std::string_view{"/receipt/"};
        auto const suffix = std::string_view{req.target}.substr(room_prefix.size());
        if (req.method == "PUT")
        {
            if (auto const path = room_send_path_parts(req.target); path.has_value())
            {
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
        // GET /rooms/{roomId}/state/{eventType}/{stateKey}
        // Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3roomsroomidstateeventtypestatekey
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
                return dispatch_err(req, rt,result.status, error_code_for_status(result.status), result.body);
            }
            return complete(result);
        }
        // GET /_matrix/client/v3/rooms/{roomId}/members
        // Spec: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3roomsroomidmembers
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
                auto const encoded_room_id = path_suffix.substr(0U, path_suffix.size() - members_s.size());
                auto const room_id = core::percent_decode_path_component(encoded_room_id);

                auto const parse_qparam = [](std::string_view qs, std::string_view key) -> std::string {
                    auto const search = std::string{key} + "=";
                    auto const pos = qs.find(search);
                    if (pos == std::string_view::npos)
                        return {};
                    auto const val_start = pos + search.size();
                    auto const val_end = qs.find('&', val_start);
                    return std::string{qs.substr(val_start, val_end == std::string_view::npos ? std::string_view::npos
                                                                                              : val_end - val_start)};
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

                auto chunk = canonicaljson::Array{};
                for (auto const& m : store.memberships)
                {
                    if (m.room_id != room_id)
                        continue;
                    if (!not_membership.empty() && m.membership == not_membership)
                        continue;
                    if (!membership_filter.empty() && m.membership != membership_filter)
                        continue;
                    auto const state_it =
                        std::ranges::find_if(store.state, [&](database::PersistentStateEvent const& s) {
                            return s.room_id == room_id && s.event_type == "m.room.member" && s.state_key == m.user_id;
                        });
                    if (state_it != store.state.end())
                    {
                        auto const ev_json = event_json_for_id(store, state_it->event_id);
                        if (ev_json.has_value())
                        {
                            auto const parsed = canonicaljson::parse_lossless(*ev_json);
                            if (parsed.error == canonicaljson::ParseError::none)
                            {
                                chunk.push_back(parsed.value);
                                continue;
                            }
                        }
                    }
                    // Fallback: construct a synthetic m.room.member event from the
                    // membership record when no state event exists (e.g. local join
                    // path stores membership but has not yet persisted the state event).
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
                log_diagnostic("room.typing.accepted",
                               {
                                   {"actor",   *user,           false},
                                   {"room_id", typing->room_id, false}
                });
                // Federate the typing EDU to remote servers in the room.
                auto const room_it = std::ranges::find_if(rt.homeserver.database.rooms, [&typing](auto const& r) {
                    return r.room_id == typing->room_id;
                });
                if (room_it != rt.homeserver.database.rooms.end())
                {
                    auto const edu_content = json_serialize(json_obj({
                        json_member("room_id", json_str(typing->room_id)),
                        json_member("user_id", json_str(*user)),
                        json_member("typing", json_str("true")),
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
                // change for other local users in the room.
                {
                    auto existing = std::ranges::find_if(rt.homeserver.typing_users, [&typing, user](auto const& t) {
                        return t.room_id == typing->room_id && t.user_id == *user;
                    });
                    if (existing != rt.homeserver.typing_users.end())
                    {
                        existing->typing = true;
                    }
                    else
                    {
                        rt.homeserver.typing_users.push_back({typing->room_id, std::string{*user}, true});
                    }
                }
                rt.homeserver.database.persistent_store.next_sync_stream_id += 1U;
                if (rt.sync_notifier != nullptr)
                {
                    rt.sync_notifier->publish(rt.homeserver.database.next_stream_ordering - 1U,
                                              rt.homeserver.database.persistent_store.next_sync_stream_id);
                }
                return dispatch_resp(req, rt, 200U, json_serialize(json_obj({})));
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
        // POST /_matrix/client/v3/rooms/{roomId}/leave
        // Removes the caller from the room. Non-members receive 403; unknown rooms 404.
        if (req.method == "POST" && suffix.size() > leave_s.size() &&
            suffix.substr(suffix.size() - leave_s.size()) == leave_s)
        {
            auto const room_id = core::percent_decode_path_component(suffix.substr(0U, suffix.size() - leave_s.size()));
            auto const room = std::ranges::find_if(rt.homeserver.database.rooms, [&room_id](auto const& r) {
                return r.room_id == room_id;
            });
            if (room == rt.homeserver.database.rooms.end())
            {
                log_diagnostic(
                    "room.leave.rejected",
                    {
                        {"actor",   *user,            false},
                        {"room_id", room_id,          false},
                        {"reason",  "room not found", false}
                });
                return dispatch_err(req, rt, 404U, "M_NOT_FOUND", "room not found");
            }
            if (!joined(*room, *user))
            {
                log_diagnostic("room.leave.rejected", {
                                                          {"actor",   *user,                               false},
                                                          {"room_id", room_id,                             false},
                                                          {"reason",  "user is not a member of this room", false}
                });
                return dispatch_err(req, rt, 403U, "M_FORBIDDEN", "user is not a member of this room");
            }
            if (!database::update_membership(rt.homeserver.database.persistent_store, room_id, *user, "leave"))
            {
                log_diagnostic("room.leave.rejected", {
                                                          {"actor",   *user,                         false},
                                                          {"room_id", room_id,                       false},
                                                          {"reason",  "failed to update membership", false}
                });
                return dispatch_err(req, rt, 500U, "M_UNKNOWN", "failed to update membership");
            }
            // Remove from in-memory member list so joined_rooms reflects the change immediately.
            std::erase(room->members, *user);
            // Membership changes are visible in /sync; advance the sync
            // stream counter so the publish wakes parked sync clients.
            rt.homeserver.database.persistent_store.next_sync_stream_id += 1U;
            if (rt.sync_notifier != nullptr)
            {
                rt.sync_notifier->publish(rt.homeserver.database.next_stream_ordering - 1U,
                                          rt.homeserver.database.persistent_store.next_sync_stream_id);
            }
            log_diagnostic("room.leave.accepted", {
                                                      {"actor",   *user,   false},
                                                      {"room_id", room_id, false}
            });
            return dispatch_resp(req, rt, 200U, json_serialize(json_obj({})));
        }
        // POST /_matrix/client/v3/rooms/{roomId}/read_markers
        // Read receipts are transient client-side state; accept without persisting.
        // Federate m.receipt EDU to remote servers in the room.
        if (req.method == "POST" && suffix.size() > read_markers_s.size() &&
            suffix.substr(suffix.size() - read_markers_s.size()) == read_markers_s)
        {
            auto const room_id =
                core::percent_decode_path_component(suffix.substr(0U, suffix.size() - read_markers_s.size()));
            log_diagnostic("room.read_markers.accepted", {
                                                             {"actor",   *user,   false},
                                                             {"room_id", room_id, false}
            });
            // Extract the m.read event_id from the body to federate as a
            // receipt EDU. The receipt content follows the Matrix spec shape:
            // { "$roomId": { "m.read": { "$userId": { "event_ids": ["$eventId"],
            //   "data": { ... } } } } }
            auto const receipt_body = canonicaljson::parse_lossless(req.body);
            auto const* body_obj = std::get_if<canonicaljson::Object>(&receipt_body.value.storage());
            if (body_obj != nullptr)
            {
                auto const* fully_read = string_member(*body_obj, "m.fully_read");
                auto const event_id = fully_read != nullptr ? std::string{*fully_read} : std::string{};
                if (!event_id.empty())
                {
                    auto const now_ts =
                        static_cast<std::int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                      std::chrono::system_clock::now().time_since_epoch())
                                                      .count());
                    auto const room_it = std::ranges::find_if(rt.homeserver.database.rooms, [&room_id](auto const& r) {
                        return r.room_id == room_id;
                    });
                    if (room_it != rt.homeserver.database.rooms.end())
                    {
                        auto const edu_content_opt =
                            federation::build_receipt_edu_content(room_id, "m.read", *user, event_id, now_ts);
                        if (edu_content_opt.has_value())
                        {
                            auto const enqueued =
                                dispatch_outbound_edu(rt.homeserver, *room_it, "m.receipt", *edu_content_opt);
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
                    }
                    // Update local in-memory receipt state so /sync returns the
                    // change for other local users in the room.
                    auto existing_receipt = std::ranges::find_if(rt.homeserver.receipts, [&](auto const& r) {
                        return r.room_id == room_id && r.user_id == *user;
                    });
                    if (existing_receipt != rt.homeserver.receipts.end())
                    {
                        existing_receipt->event_id = event_id;
                        existing_receipt->ts = static_cast<std::uint64_t>(now_ts);
                    }
                    else
                    {
                        rt.homeserver.receipts.push_back({std::string{room_id}, "m.read", std::string{*user}, event_id,
                                                          static_cast<std::uint64_t>(now_ts)});
                    }
                    rt.homeserver.database.persistent_store.next_sync_stream_id += 1U;
                    if (rt.sync_notifier != nullptr)
                    {
                        rt.sync_notifier->publish(rt.homeserver.database.next_stream_ordering - 1U,
                                                  rt.homeserver.database.persistent_store.next_sync_stream_id);
                    }
                }
            }
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
                    auto const event_id = core::percent_decode_path_component(after_receipt.substr(slash_pos + 1U));
                    if (!event_id.empty())
                    {
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
                        auto const room_it =
                            std::ranges::find_if(rt.homeserver.database.rooms, [&room_id](auto const& r) {
                                return r.room_id == room_id;
                            });
                        if (room_it != rt.homeserver.database.rooms.end())
                        {
                            auto const edu_content_opt =
                                federation::build_receipt_edu_content(room_id, receipt_type, *user, event_id, now_ts);
                            if (edu_content_opt.has_value())
                            {
                                auto const enqueued =
                                    dispatch_outbound_edu(rt.homeserver, *room_it, "m.receipt", *edu_content_opt);
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
                            return r.room_id == room_id && r.user_id == *user;
                        });
                        if (existing_receipt != rt.homeserver.receipts.end())
                        {
                            existing_receipt->receipt_type = receipt_type;
                            existing_receipt->event_id = std::string{event_id};
                            existing_receipt->ts = static_cast<std::uint64_t>(now_ts);
                        }
                        else
                        {
                            rt.homeserver.receipts.push_back({std::string{room_id}, receipt_type, std::string{*user},
                                                              std::string{event_id},
                                                              static_cast<std::uint64_t>(now_ts)});
                        }
                        rt.homeserver.database.persistent_store.next_sync_stream_id += 1U;
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
        return dispatch_resp(req, rt, 200U, json_serialize(json_obj({
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
        auto rewritten = req;
        rewritten.target = std::string{"/_matrix/client/v3/rooms/"} + decoded_room_segment + "/join";
        if (!join_query.empty())
        {
            rewritten.target += "?" + std::string{join_query};
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
        return complete(result);
    }

    // POST  /_matrix/client/v3/user/{userId}/filter   — upload and store a sync filter
    // GET   /_matrix/client/v3/user/{userId}/filter/{filterId} — retrieve a stored filter
    // PUT   /_matrix/client/v3/user/{userId}/account_data/{type} — store account data
    // GET   /_matrix/client/v3/user/{userId}/account_data/{type} — retrieve account data
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
            return dispatch_resp(req, rt, 200U, json_serialize(json_obj({json_member("filter_id", json_str(filter_id))})));
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
            auto const type = std::string{suffix.substr(ad_pos + account_data_m.size())};
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
                return dispatch_resp(req, rt, 200U, body.error == canonicaljson::CanonicalJsonError::none ? body.output : "{}");
            }
        }
        return dispatch_err(req, rt, 404U, "M_NOT_FOUND", "room summary not found");
    }

    log_diagnostic("request.route_not_found", {
                                                  {"method", req.method,                                       false},
                                                  {"target", observability::sanitized_http_target(req.target), false},
                                                  {"actor",  *user,                                            false},
                                                  {"status", "404",                                            false}
    });
    return dispatch_err(req, rt, 404U, "M_UNRECOGNIZED", "route not found");
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
