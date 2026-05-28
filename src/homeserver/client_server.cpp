// SPDX-License-Identifier: GPL-3.0-or-later

// GCC 16 with -O2 and LTO emits a false-positive -Wmaybe-uninitialized warning
// in std::ranges::any_of when inlining DispatchResult's std::string members.
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif

#include "merovingian/homeserver/client_server.hpp"

#include "local_services.hpp"
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
    [[nodiscard]] auto dispatch_resp(std::uint16_t status, std::string body) -> DispatchResult
    {
        return DispatchResult{
            DispatchResult::Status::complete, {status, std::move(body)},
             {}
        };
    }

    [[nodiscard]] auto dispatch_err(std::uint16_t status, std::string_view errcode,
                                    std::string_view error) -> DispatchResult
    {
        return DispatchResult{
            DispatchResult::Status::complete, {status, matrix_error(errcode, error)},
             {}
        };
    }

    // Collect the unique remote server names that have members in a room,
    // excluding the local server. Used to federate outbound EDUs and PDUs.
    [[nodiscard]] auto remote_servers_in_room(HomeserverRuntime const& runtime,
                                              LocalRoom const& room) -> std::vector<std::string>
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
        auto edu_value = canonicaljson::parse_lossless(edu_content_json);
        if (edu_value.error != canonicaljson::ParseError::none)
        {
            return 0U;
        }
        auto edu_obj = canonicaljson::Object{};
        edu_obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{edu_type}}));
        edu_obj.push_back(canonicaljson::make_member("content", std::move(edu_value.value)));
        auto edus_array = canonicaljson::Array{};
        edus_array.push_back(canonicaljson::Value{std::move(edu_obj)});
        auto tx_root = canonicaljson::Object{};
        tx_root.push_back(canonicaljson::make_member("pdus", canonicaljson::Value{canonicaljson::Array{}}));
        tx_root.push_back(canonicaljson::make_member("edus", canonicaljson::Value{std::move(edus_array)}));
        auto const tx_body_result = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(tx_root)});
        if (tx_body_result.error != canonicaljson::CanonicalJsonError::none)
        {
            return 0U;
        }
        auto const& tx_body = tx_body_result.output;
        auto tx_id = std::to_string(runtime.database.next_session_id++);
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

    [[nodiscard]] auto object_member(canonicaljson::Object const& object,
                                     std::string_view key) noexcept -> canonicaljson::Value const*
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

    [[nodiscard]] auto string_member(canonicaljson::Object const& object,
                                     std::string_view key) noexcept -> std::string const*
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

    [[nodiscard]] auto string_array_member(canonicaljson::Object const& object,
                                           std::string_view key) -> std::vector<std::string>
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

    [[nodiscard]] auto event_json_for_id(database::PersistentStore const& store,
                                         std::string_view event_id) -> std::optional<std::string>
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

    [[nodiscard]] auto object_member_as_object(canonicaljson::Object const& object,
                                               std::string_view key) noexcept -> canonicaljson::Object const*
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

    [[nodiscard]] auto serialized_object_member(canonicaljson::Object const& object,
                                                std::string_view key) -> std::optional<std::string>
    {
        auto const* value = object_member(object, key);
        if (value == nullptr)
        {
            return std::nullopt;
        }
        return serialized_value(*value);
    }

    [[nodiscard]] auto object_member_object(canonicaljson::Object const& object,
                                            std::string_view key) noexcept -> canonicaljson::Object const*
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

    [[nodiscard]] auto has_auth_field(std::string_view body) -> bool
    {
        auto const object = parsed_json_object(body);
        return object.has_value() && object_member_object(*object, "auth") != nullptr;
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

    [[nodiscard]] auto parse_login_body(std::string_view body,
                                        std::string_view server_name) -> std::optional<MatrixLoginBody>
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
                               device_id == nullptr ? "MEROVINGIAN" : *device_id,
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

    [[nodiscard]] auto find_device(ClientServerRuntime& rt, std::string_view user,
                                   std::string_view device) -> ClientDevice*
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

    [[nodiscard]] auto event_content_string(std::string_view event_json,
                                            std::string_view key) -> std::optional<std::string>
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
                                         std::string_view content_key,
                                         std::string_view state_key = {}) -> std::optional<std::string>
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

    [[nodiscard]] auto build_device_list_arrays(
        database::PersistentStore const& store, std::string_view user, std::uint64_t since_sync_stream_id,
        std::uint64_t& max_observed_stream_id) -> std::pair<canonicaljson::Array, canonicaljson::Array>
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
                                             std::uint64_t since_sync_stream_id,
                                             std::uint64_t& max_observed_stream_id) -> canonicaljson::Array
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
            auto const member_count = room.members.size();
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
                timeline_events.push_back(json_obj({
                    json_member("event_id", json_str(event.event_id)),
                    json_member("sender", json_str(event.sender_user_id)),
                }));
                ++event_count;
            }

            auto const limited = store.events.size() > timeline_cap;
            auto room_account_data = build_account_data_events(store, filter.room.account_data, user, room.room_id,
                                                               since_sync_stream_id, max_observed_sync_stream_id);

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
                    json_member("state", json_obj({json_member("member_count",
                                                               json_int(static_cast<std::int64_t>(member_count)))})),
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
        case auth::KeyApiEndpoint::delete_room_key_backup:
            return "{}";
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

    [[nodiscard]] auto key_id_matches_algorithm(std::string_view key_id, std::string_view algorithm) -> bool
    {
        return key_id.size() > algorithm.size() && key_id.substr(0U, algorithm.size()) == algorithm &&
               key_id[algorithm.size()] == ':';
    }

    [[nodiscard]] auto handle_key_query(ClientServerRuntime const& rt, std::string_view body) -> LocalHttpResponse
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

        auto users = canonicaljson::Object{};
        auto const& store = rt.homeserver.database.persistent_store;
        for (auto const& user_request : *requests)
        {
            auto const* requested_devices = std::get_if<canonicaljson::Array>(&user_request.value->storage());
            if (requested_devices == nullptr)
            {
                return err(400U, "M_BAD_JSON", "device_keys values must be device ID arrays");
            }

            auto devices = canonicaljson::Object{};
            if (requested_devices->empty())
            {
                for (auto const& key : store.device_keys)
                {
                    if (key.user_id == user_request.key)
                    {
                        devices.push_back(json_member(key.device_id, json_embed_raw(key.json)));
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
                        devices.push_back(json_member(*requested_device_id, json_embed_raw(key->json)));
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
                    master_keys.push_back(json_member(user_request.key, json_embed_raw(cskey.json)));
                }
                else if (cskey.key_type == "self_signing")
                {
                    self_signing_keys.push_back(json_member(user_request.key, json_embed_raw(cskey.json)));
                }
                else if (cskey.key_type == "user_signing")
                {
                    user_signing_keys.push_back(json_member(user_request.key, json_embed_raw(cskey.json)));
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
        // Spec MUST: "failures" object for unreachable remote servers (empty for local-only queries).
        response.push_back(json_member("failures", json_obj({})));
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

        auto& store = rt.homeserver.database.persistent_store;
        auto users = canonicaljson::Object{};
        for (auto const& user_request : *requests)
        {
            auto const* requested_devices = std::get_if<canonicaljson::Object>(&user_request.value->storage());
            if (requested_devices == nullptr)
            {
                return err(400U, "M_BAD_JSON", "one_time_keys values must be device maps");
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
                    auto const fallback = database::find_fallback_key(store, user_request.key, device_request.key);
                    if (fallback.has_value() && key_id_matches_algorithm(fallback->key_id, *algorithm))
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
        // Spec MUST: "failures" object for unreachable remote servers (empty for local-only claims).
        return resp(200U, json_serialize(json_obj({
                              json_member("one_time_keys", json_obj(std::move(users))),
                              json_member("failures", json_obj({})),
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

    [[nodiscard]] auto messages_json(ClientServerRuntime const& rt, std::string_view room_id,
                                     std::string_view target) -> std::string
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
                                             std::string_view user, std::string_view device_id,
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
        case auth::KeyApiEndpoint::upload_signatures:
            return database::store_key_signature(
                store, {std::string{user}, std::string{user}, std::string{device_id}, req.body});
        case auth::KeyApiEndpoint::create_key_backup_version:
        case auth::KeyApiEndpoint::update_key_backup_version:
            return database::store_key_backup_version(store, {std::string{user}, "1", req.body});
        case auth::KeyApiEndpoint::put_room_key_backup: {
            auto constexpr prefix = std::string_view{"/_matrix/client/v3/room_keys/keys/"};
            auto const suffix = route_suffix(req.target, prefix);
            auto const separator = suffix.find('/');
            if (separator == std::string_view::npos || separator == 0U || separator + 1U >= suffix.size())
            {
                return false;
            }
            return database::store_key_backup_session(store, {std::string{user}, "1",
                                                              std::string{suffix.substr(0U, separator)},
                                                              std::string{suffix.substr(separator + 1U)}, req.body});
        }
        case auth::KeyApiEndpoint::delete_key_backup_version: {
            auto constexpr prefix = std::string_view{"/_matrix/client/v3/room_keys/version/"};
            auto const version_str = route_suffix(req.target, prefix);
            if (version_str.empty())
                return false;
            return database::delete_key_backup_version(store, user, version_str);
        }
        case auth::KeyApiEndpoint::upload_keys:
        case auth::KeyApiEndpoint::query_keys:
        case auth::KeyApiEndpoint::claim_keys:
        case auth::KeyApiEndpoint::device_list_update:
        case auth::KeyApiEndpoint::get_key_backup_version:
        case auth::KeyApiEndpoint::get_room_key_backup:
        case auth::KeyApiEndpoint::delete_room_key_backup:
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
        case auth::KeyApiEndpoint::get_key_backup_version:
            if (auto const& versions = rt.homeserver.database.persistent_store.key_backup_versions; !versions.empty())
            {
                auto const& v = versions.front();
                // v.json is the original POST body (algorithm + auth_data only).
                // The spec response MUST also include "version" — inject it here.
                auto parsed = canonicaljson::parse_lossless(v.json);
                if (parsed.error == canonicaljson::ParseError::none)
                {
                    if (auto const* obj = std::get_if<canonicaljson::Object>(&parsed.value.storage()))
                    {
                        auto with_version = *obj;
                        with_version.push_back(
                            {"version", std::make_unique<canonicaljson::Value>(std::string{v.version})});
                        return resp(200U, json_serialize(canonicaljson::Value{std::move(with_version)}));
                    }
                }
                return resp(200U, v.json);
            }
            return resp(404U, matrix_error("M_NOT_FOUND", "key backup version not found"));
        case auth::KeyApiEndpoint::get_room_key_backup:
            return resp(200U, json_serialize(json_obj({json_member("rooms", json_obj({}))})));
        case auth::KeyApiEndpoint::upload_cross_signing_keys:
        case auth::KeyApiEndpoint::upload_signatures:
        case auth::KeyApiEndpoint::create_key_backup_version:
        case auth::KeyApiEndpoint::update_key_backup_version:
        case auth::KeyApiEndpoint::delete_key_backup_version:
        case auth::KeyApiEndpoint::put_room_key_backup:
        case auth::KeyApiEndpoint::delete_room_key_backup:
            if (!store_key_api_payload(rt, route.endpoint, user, device_id, req))
            {
                return err(500U, "M_UNKNOWN", "key API persistence failed");
            }
            return resp(200U, key_api_success_body(route.endpoint));
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

    [[nodiscard]] auto handle_safety_report(ClientServerRuntime& rt, std::string_view user,
                                            LocalHttpRequest const& req) -> LocalHttpResponse
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
                   rt, {parsed.request.method, parsed.request.target, bearer_access_token(parsed.request.headers), {}},
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
                                         bearer_access_token(parsed.request.headers), std::string{available_body}},
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
        return dispatch_err(503U, "M_UNAVAILABLE", "runtime not started");
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
        return dispatch_err(413U, "M_TOO_LARGE", "request body too large");
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
        return dispatch_err(429U, "M_LIMIT_EXCEEDED", "rate limit exceeded");
    }
    auto call_local = [&](LocalHttpRequest const& inner) {
        guard.unlock();
        auto response = handle_local_http_request(rt.homeserver, inner);
        guard.lock();
        return response;
    };

    // CORS preflight: browsers send OPTIONS before any cross-origin POST/PUT/DELETE.
    // Must return 200 before the access-token gate; the reverse proxy (Apache/nginx)
    // is responsible for adding the Access-Control-* response headers.
    if (req.method == "OPTIONS")
    {
        return dispatch_resp(200U, {});
    }

    // GET /.well-known/matrix/client tells clients where the homeserver lives.
    // Must be served before any auth check; the path is outside /_matrix/ so
    // Apache or nginx may not proxy it unless explicitly configured to do so.
    if (req.method == "GET" && req.target == "/.well-known/matrix/client")
    {
        auto const& base_url = rt.homeserver.config.server().public_baseurl;
        return dispatch_resp(200U,
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
        return dispatch_resp(200U, json_serialize(json_obj({
                                       json_member("versions", json_arr(std::move(versions))),
                                       json_member("unstable_features", json_obj({})),
                                   })));
    }

    auto const request_path = std::string_view{req.target}.substr(0U, std::string_view{req.target}.find('?'));
    if (req.method == "GET" && request_path == "/_matrix/client/v3/publicRooms")
    {
        return dispatch_resp(200U, public_rooms_json(rt));
    }
    auto constexpr directory_room_prefix = std::string_view{"/_matrix/client/v3/directory/room/"};
    if (req.method == "GET" && starts_with(request_path, directory_room_prefix))
    {
        auto const encoded_alias = request_path.substr(directory_room_prefix.size());
        auto const room_alias = core::percent_decode_path_component(encoded_alias);
        auto const found = database::find_room_alias(rt.homeserver.database.persistent_store, room_alias);
        if (!found.has_value())
        {
            return dispatch_err(404U, "M_NOT_FOUND", "room alias not found");
        }
        auto servers = canonicaljson::Array{};
        servers.push_back(json_str(rt.homeserver.config.server().server_name));
        return dispatch_resp(200U, json_serialize(json_obj({
                                       json_member("room_id", json_str(found->room_id)),
                                       json_member("servers", json_arr(std::move(servers))),
                                   })));
    }

    if (req.method == "POST" && req.target == "/_matrix/client/v3/register")
    {
        auto const body = parse_register_body(req.body);
        if (!body.has_value())
        {
            return dispatch_err(400U, "M_BAD_JSON", "registration body must be Matrix JSON");
        }
        // Matrix UI-auth: if no auth object is present, return 401 with the available flow.
        if (!has_auth_field(req.body))
        {
            return dispatch_resp(
                401U, json_serialize(json_obj({
                          json_member("flows", json_arr({json_obj({json_member(
                                                   "stages", json_arr({json_str("m.login.registration_token")}))})})),
                          json_member("params", json_obj({})),
                          json_member("session", json_str("merovingian-ui-auth")),
                      })));
        }
        auto const result =
            register_local_user(rt.homeserver, body->localpart, body->password, body->registration_token);
        return result.ok
                   ? dispatch_resp(200U, json_serialize(json_obj({json_member("user_id", json_str(result.value))})))
                   : dispatch_err(result.status, "M_FORBIDDEN", result.reason);
    }
    if (req.method == "GET" && req.target == "/_matrix/client/v3/login")
    {
        return dispatch_resp(
            200U, json_serialize(json_obj({
                      json_member("flows", json_arr({json_obj({json_member("type", json_str("m.login.password"))})})),
                  })));
    }
    if (req.method == "POST" && req.target == "/_matrix/client/v3/login")
    {
        auto const body = parse_login_body(req.body, rt.homeserver.config.server().server_name);
        if (!body.has_value())
        {
            return dispatch_err(400U, "M_BAD_JSON", "login body must be Matrix password JSON");
        }
        auto const result = login_local_user(rt.homeserver, body->user_id, body->password, body->device_id);
        if (!result.ok)
        {
            return dispatch_err(result.status, "M_FORBIDDEN", result.reason);
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
                return dispatch_err(refresh_token.status, "M_UNKNOWN", refresh_token.reason);
            }
            response_body.push_back(json_member("refresh_token", json_str(refresh_token.value)));
            response_body.push_back(json_member("expires_in_ms", json_int(3600000)));
        }
        return dispatch_resp(200U, json_serialize(json_obj(std::move(response_body))));
    }
    if (req.method == "POST" && req.target == "/_matrix/client/v3/refresh")
    {
        auto const body = parse_refresh_body(req.body);
        if (!body.has_value())
        {
            return dispatch_err(400U, "M_BAD_JSON", "refresh body must contain refresh_token");
        }
        auto const refreshed = refresh_local_session(rt.homeserver, body->refresh_token);
        if (!refreshed.ok)
        {
            return dispatch_err(refreshed.status, refreshed.status == 401U ? "M_UNKNOWN_TOKEN" : "M_UNKNOWN",
                                refreshed.reason);
        }
        if (find_device(rt, refreshed.user_id, refreshed.device_id) == nullptr)
        {
            rt.devices.push_back({refreshed.user_id, refreshed.device_id, refreshed.device_id});
        }
        return dispatch_resp(200U, json_serialize(json_obj({
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
        return r.status == 200U ? dispatch_resp(200U, "{}")
                                : dispatch_err(r.status, r.status == 401U ? "M_UNKNOWN_TOKEN" : "M_UNKNOWN", r.body);
    }

    // MSC2965 OIDC discovery: Cinny and Element probe auth_metadata and
    // auth_issuer before login to detect OIDC support.  We do not implement
    // OIDC, so return 404 for the whole msc2965 namespace before the
    // access-token gate, otherwise the probes produce a misleading 401.
    if (req.method == "GET" && starts_with(req.target, "/_matrix/client/unstable/org.matrix.msc2965/"))
    {
        return dispatch_err(404U, "M_UNRECOGNIZED", "OIDC not supported");
    }

    auto constexpr media_download_prefix = std::string_view{"/_matrix/media/v3/download/"};
    if (req.method == "GET" && starts_with(req.target, media_download_prefix))
    {
        auto const r = call_local(req);
        return r.status == 200U ? dispatch_resp(200U, r.body)
                                : dispatch_err(r.status, r.status == 404U ? "M_NOT_FOUND" : "M_UNKNOWN", r.body);
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
            return dispatch_err(404U, "M_NOT_FOUND", "user not found");
        }
        auto const profile = database::find_profile(store, target_user);
        auto const displayname = profile.has_value() ? profile->displayname : std::string{};
        auto const avatar_url = profile.has_value() ? profile->avatar_url : std::string{};
        if (field.empty())
        {
            return dispatch_resp(200U, json_serialize(json_obj({
                                           json_member("displayname", json_str(displayname)),
                                           json_member("avatar_url", json_str(avatar_url)),
                                       })));
        }
        // getProfileField returns only the requested key; an unset or unknown
        // field is reported as 404 M_NOT_FOUND per the Matrix spec.
        if (field == "displayname" && !displayname.empty())
        {
            return dispatch_resp(200U, json_serialize(json_obj({json_member("displayname", json_str(displayname))})));
        }
        if (field == "avatar_url" && !avatar_url.empty())
        {
            return dispatch_resp(200U, json_serialize(json_obj({json_member("avatar_url", json_str(avatar_url))})));
        }
        return dispatch_err(404U, "M_NOT_FOUND", "profile field not found");
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
        return dispatch_err(401U, "M_UNKNOWN_TOKEN", "unauthenticated");
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
        return r.ok ? dispatch_resp(200U, "{}")
                    : dispatch_err(r.status, r.status == 401U ? "M_UNKNOWN_TOKEN" : "M_UNKNOWN", r.reason);
    }
    if (req.method == "GET" && req.target == "/_matrix/client/v3/account/whoami")
    {
        auto const whoami_device = first_device_id(rt, *user);
        log_diagnostic("account.whoami", {
                                             {"actor", *user, false}
        });
        return dispatch_resp(200U, json_serialize(json_obj({
                                       json_member("user_id", json_str(*user)),
                                       json_member("device_id", json_str(whoami_device)),
                                   })));
    }
    if (req.method == "PUT" && starts_with(request_path, directory_room_prefix))
    {
        auto const body = parsed_json_object(req.body);
        if (!body.has_value())
        {
            return dispatch_err(400U, "M_BAD_JSON", "directory body must be a JSON object");
        }
        auto const* room_id = string_member(*body, "room_id");
        if (room_id == nullptr || room_id->empty())
        {
            return dispatch_err(400U, "M_BAD_JSON", "room_id is required");
        }
        auto const room = std::ranges::find_if(rt.homeserver.database.rooms, [room_id](LocalRoom const& current) {
            return current.room_id == *room_id;
        });
        if (room == rt.homeserver.database.rooms.end())
        {
            return dispatch_err(404U, "M_NOT_FOUND", "room not found");
        }
        if (!joined(*room, *user))
        {
            return dispatch_err(403U, "M_FORBIDDEN", "user is not a member of this room");
        }
        auto const room_alias = core::percent_decode_path_component(request_path.substr(directory_room_prefix.size()));
        auto const existing = database::find_room_alias(rt.homeserver.database.persistent_store, room_alias);
        if (existing.has_value())
        {
            return existing->room_id == *room_id ? dispatch_resp(200U, "{}")
                                                 : dispatch_err(409U, "M_ROOM_IN_USE", "room alias already in use");
        }
        if (!database::store_room_alias(rt.homeserver.database.persistent_store, {room_alias, *room_id}))
        {
            return dispatch_err(500U, "M_UNKNOWN", "failed to persist room alias");
        }
        return dispatch_resp(200U, "{}");
    }
    if (req.method == "POST" && req.target == "/_matrix/client/v3/account/password")
    {
        auto const object = parsed_json_object(req.body);
        if (!object.has_value())
        {
            return dispatch_err(400U, "M_BAD_JSON", "password change body must be JSON");
        }
        auto const* new_password = string_member(*object, "new_password");
        if (new_password == nullptr || new_password->empty())
        {
            return dispatch_err(400U, "M_BAD_JSON", "new_password is required");
        }
        auto const result = change_local_user_password(rt.homeserver, req.access_token, *new_password);
        if (!result.ok)
        {
            return dispatch_err(result.status, result.status == 401U ? "M_UNKNOWN_TOKEN" : "M_FORBIDDEN",
                                result.reason);
        }
        return dispatch_resp(200U, "{}");
    }
    // Spec: GET /account/3pid returns the third-party IDs linked to the
    // authenticated user. Merovingian does not yet support 3PID binding,
    // so return the spec-required empty list so Element's settings UI
    // does not show a spurious error.
    if (req.method == "GET" && req.target == "/_matrix/client/v3/account/3pid")
    {
        return dispatch_resp(200U, R"({"threepids":[]})");
    }
    // Spec: GET /pushers returns the push notification pushers for the
    // authenticated user. Merovingian does not yet support push
    // subscriptions, so return the spec-required empty list so Element's
    // settings UI does not show a spurious error.
    if (req.method == "GET" && req.target == "/_matrix/client/v3/pushers")
    {
        return dispatch_resp(200U, R"({"pushers":[]})");
    }
    // Clients (Cinny, Element) fetch /capabilities immediately after login to
    // discover what the server supports. Return a minimal stable set; extend
    // as features are implemented.
    if (req.method == "GET" && req.target == "/_matrix/client/v3/capabilities")
    {
        return dispatch_resp(
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
    // Clients fetch /pushrules/ immediately after login to load notification
    // rules. Push infrastructure is not yet implemented; return an empty
    // global ruleset so clients can proceed to open their sync connection.
    if (req.method == "GET" && req.target == "/_matrix/client/v3/pushrules/")
    {
        return dispatch_resp(200U,
                             json_serialize(json_obj({json_member("global", json_obj({
                                                                                json_member("content", json_arr({})),
                                                                                json_member("override", json_arr({})),
                                                                                json_member("room", json_arr({})),
                                                                                json_member("sender", json_arr({})),
                                                                                json_member("underride", json_arr({})),
                                                                            }))})));
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
                return dispatch_err(403U, "M_FORBIDDEN", "cannot update another user's profile");
            }
            auto const parsed = canonicaljson::parse_lossless(req.body);
            auto const* obj = std::get_if<canonicaljson::Object>(&parsed.value.storage());
            if (parsed.error != canonicaljson::ParseError::none || obj == nullptr)
            {
                return dispatch_err(400U, "M_BAD_JSON", "profile update body must be a JSON object");
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
            return dispatch_resp(200U, "{}");
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
        return dispatch_resp(200U,
                             json_serialize(json_obj({json_member("m.upload.size", json_int(max_upload_bytes))})));
    }
    if (req.method == "POST" && req.target == "/_matrix/media/v3/upload")
    {
        auto const r = call_local(req);
        return r.status == 200U
                   ? dispatch_resp(200U, media_upload_response_json(r.body))
                   : dispatch_err(r.status, r.status == 401U ? "M_UNKNOWN_TOKEN" : "M_BAD_REQUEST", r.body);
    }

    // GET /_matrix/client/v3/voip/turnServer
    // No TURN server is configured.  Return an empty object so clients disable
    // VoIP gracefully rather than treating a 404 as an error.
    if (req.method == "GET" && req.target == "/_matrix/client/v3/voip/turnServer")
    {
        return dispatch_resp(200U, "{}");
    }

    auto const key_route = auth::match_key_api_route(req.method, req.target);
    if (key_route.matched)
    {
        auto const device_id = first_device_id(rt, *user);
        return complete(handle_key_api_route(rt, key_route.route, *user, device_id, req));
    }
    if (req.method == "GET" && req.target == "/_matrix/client/v3/devices")
    {
        return dispatch_resp(200U, devices_json(rt, *user));
    }
    auto constexpr dev_prefix = std::string_view{"/_matrix/client/v3/devices/"};
    if (req.method == "GET" && starts_with(req.target, dev_prefix))
    {
        auto const device_id = std::string_view{req.target}.substr(dev_prefix.size());
        auto const* device = find_device(rt, *user, device_id);
        if (device == nullptr)
        {
            return dispatch_err(404U, "M_NOT_FOUND", "device not found");
        }
        return dispatch_resp(200U, device_json(*device));
    }
    if (req.method == "DELETE" && starts_with(req.target, dev_prefix))
    {
        auto const device_id = std::string_view{req.target}.substr(dev_prefix.size());
        auto const result = delete_local_device(rt.homeserver, *user, device_id);
        if (!result.ok)
        {
            return dispatch_err(result.status, result.status == 404U ? "M_NOT_FOUND" : "M_UNKNOWN", result.reason);
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
        return dispatch_resp(200U, "{}");
    }
    auto const safety_route = trust_safety::match_reporting_api_route(req.method, req.target);
    if (safety_route.matched)
    {
        if (safety_route.route.requires_admin && !authenticated_admin_user(rt.homeserver, req.access_token).has_value())
        {
            return dispatch_err(403U, "M_FORBIDDEN", "admin authentication required");
        }
        return complete(safety_route.route.requires_admin ? handle_admin_safety_route(rt, *user, req)
                                                          : handle_safety_report(rt, *user, req));
    }
    if (req.method == "POST" && req.target == "/_matrix/client/v3/createRoom")
    {
        auto const body_object = req.body.empty() ? std::optional<canonicaljson::Object>{canonicaljson::Object{}}
                                                  : parsed_json_object(req.body);
        if (!body_object.has_value())
        {
            return dispatch_err(400U, "M_BAD_JSON", "createRoom body must be a JSON object");
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
            return dispatch_err(400U, "M_UNSUPPORTED_ROOM_VERSION", "unsupported room version");
        }
        auto const* room_alias_name = string_member(body, "room_alias_name");
        if (room_alias_name != nullptr && !room_alias_name->empty())
        {
            auto const alias = "#" + *room_alias_name + ":" + rt.homeserver.config.server().server_name;
            if (database::find_room_alias(rt.homeserver.database.persistent_store, alias).has_value())
            {
                return dispatch_err(400U, "M_ROOM_IN_USE", "room alias already in use");
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
            return dispatch_err(create_result.status, errcode, create_result.reason);
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
                transaction.transaction_id = std::to_string(rt.homeserver.database.next_session_id++);
                std::ignore = rt.homeserver.dispatch_worker->enqueue(std::move(transaction));
            }
        }
        log_diagnostic("room.create.accepted", {
                                                   {"actor",   *user,   false},
                                                   {"room_id", room_id, false}
        });
        return dispatch_resp(200U, json_serialize(json_obj({json_member("room_id", json_str(room_id))})));
    }
    if (req.method == "GET" && req.target == "/_matrix/client/v3/joined_rooms")
    {
        log_diagnostic("room.joined_rooms.response", {
                                                         {"actor", *user, false}
        });
        return dispatch_resp(200U, joined_rooms_json(rt, *user));
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
                    return dispatch_err(400U, "M_BAD_JSON", "event content must be a JSON object");
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
                    return dispatch_err(400U, "M_BAD_JSON", "state content must be a JSON object");
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
                return dispatch_err(result.status, error_code_for_status(result.status), result.body);
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
                    return dispatch_err(404U, "M_NOT_FOUND", "room not found");
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
                return dispatch_resp(200U,
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
                    return dispatch_err(403U, "M_FORBIDDEN", "cannot set typing state for another user");
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
                return dispatch_resp(200U, json_serialize(json_obj({})));
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
                    return dispatch_err(404U, "M_NOT_FOUND", "room not found");
                }
                if (!joined(*room, *user))
                {
                    log_diagnostic("room.messages.rejected",
                                   {
                                       {"actor",   *user,                               false},
                                       {"room_id", *messages_room,                      false},
                                       {"reason",  "user is not a member of this room", false}
                    });
                    return dispatch_err(403U, "M_FORBIDDEN", "user is not a member of this room");
                }
                log_diagnostic("room.messages.response",
                               {
                                   {"actor",   *user,          false},
                                   {"room_id", *messages_room, false}
                });
                return dispatch_resp(200U, messages_json(rt, *messages_room, req.target));
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
                return dispatch_err(404U, "M_NOT_FOUND", "room not found");
            }
            if (!joined(*room, *user))
            {
                log_diagnostic("room.leave.rejected", {
                                                          {"actor",   *user,                               false},
                                                          {"room_id", room_id,                             false},
                                                          {"reason",  "user is not a member of this room", false}
                });
                return dispatch_err(403U, "M_FORBIDDEN", "user is not a member of this room");
            }
            if (!database::update_membership(rt.homeserver.database.persistent_store, room_id, *user, "leave"))
            {
                log_diagnostic("room.leave.rejected", {
                                                          {"actor",   *user,                         false},
                                                          {"room_id", room_id,                       false},
                                                          {"reason",  "failed to update membership", false}
                });
                return dispatch_err(500U, "M_UNKNOWN", "failed to update membership");
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
            return dispatch_resp(200U, json_serialize(json_obj({})));
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
                        // Build the receipt EDU content per Matrix spec.
                        auto receipt_content = canonicaljson::Object{};
                        auto user_receipts = canonicaljson::Object{};
                        user_receipts.push_back(canonicaljson::make_member(
                            "event_ids", canonicaljson::Value{canonicaljson::Array{canonicaljson::Value{event_id}}}));
                        user_receipts.push_back(canonicaljson::make_member("ts", canonicaljson::Value{now_ts}));
                        auto read_type = canonicaljson::Object{};
                        read_type.push_back(
                            canonicaljson::make_member(*user, canonicaljson::Value{std::move(user_receipts)}));
                        receipt_content.push_back(
                            canonicaljson::make_member(room_id, canonicaljson::Value{std::move(read_type)}));
                        auto const edu_content_result =
                            canonicaljson::serialize_canonical(canonicaljson::Value{std::move(receipt_content)});
                        if (edu_content_result.error == canonicaljson::CanonicalJsonError::none)
                        {
                            auto const enqueued =
                                dispatch_outbound_edu(rt.homeserver, *room_it, "m.receipt", edu_content_result.output);
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
            return dispatch_resp(200U, json_serialize(json_obj({})));
        }
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
                return dispatch_err(403U, "M_FORBIDDEN", "cannot set presence for another user");
            }
            auto const body = canonicaljson::parse_lossless(req.body);
            auto const* body_obj = std::get_if<canonicaljson::Object>(&body.value.storage());
            if (body_obj == nullptr)
            {
                return dispatch_err(400U, "M_BAD_JSON", "presence body must be Matrix JSON");
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
                return dispatch_err(500U, "M_UNKNOWN", "presence persistence failed");
            }
            log_diagnostic("presence.set", {
                                               {"actor",    *user,          false},
                                               {"presence", presence_state, false}
            });
            return dispatch_resp(200U, json_serialize(json_obj({})));
        }
    }

    // POST /_matrix/client/v3/join/{roomIdOrAlias}
    // Joins by room ID or alias. Delegates to the same local join handler as
    // /rooms/{roomId}/join by rewriting the request target.
    auto constexpr join_by_id_prefix = std::string_view{"/_matrix/client/v3/join/"};
    if (req.method == "POST" && starts_with(req.target, join_by_id_prefix))
    {
        auto room_segment = std::string_view{req.target}.substr(join_by_id_prefix.size());
        // Drop any ?server_name=... query string; local joins do not need it.
        if (auto const query = room_segment.find('?'); query != std::string_view::npos)
        {
            room_segment = room_segment.substr(0U, query);
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
            return dispatch_err(400U, "M_INVALID_PARAM", "room id or alias must not be empty");
        }
        auto const decoded_room_segment = core::percent_decode_path_component(room_segment);
        auto rewritten = req;
        rewritten.target = std::string{"/_matrix/client/v3/rooms/"} + decoded_room_segment + "/join";
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
                return dispatch_err(403U, "M_FORBIDDEN", "cannot upload filter for another user");
            }
            if (req.body.empty())
            {
                return dispatch_err(400U, "M_BAD_JSON", "filter body must not be empty");
            }
            auto const filter_id = generate_filter_id();
            if (!database::store_filter(rt.homeserver.database.persistent_store, {path_user, filter_id, req.body}))
            {
                log_diagnostic("filter.rejected", {
                                                      {"actor",     *user,                      false},
                                                      {"filter_id", filter_id,                  false},
                                                      {"reason",    "failed to persist filter", false}
                });
                return dispatch_err(500U, "M_UNKNOWN", "failed to persist filter");
            }
            log_diagnostic("filter.stored", {
                                                {"actor",     *user,     false},
                                                {"filter_id", filter_id, false}
            });
            return dispatch_resp(200U, json_serialize(json_obj({json_member("filter_id", json_str(filter_id))})));
        }

        auto const mid_pos = suffix.find(filter_m);
        if (req.method == "GET" && mid_pos != std::string_view::npos)
        {
            auto const encoded_user = suffix.substr(0U, mid_pos);
            auto const path_user = core::percent_decode_path_component(encoded_user);
            if (path_user != *user)
            {
                return dispatch_err(403U, "M_FORBIDDEN", "cannot access filter for another user");
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
                return dispatch_err(404U, "M_NOT_FOUND", "filter not found");
            }
            log_diagnostic("filter.retrieved", {
                                                   {"actor",     *user,     false},
                                                   {"filter_id", filter_id, false}
            });
            return dispatch_resp(200U, stored->json);
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
                    return dispatch_err(403U, "M_FORBIDDEN", "cannot access account data for another user");
                }
                if (req.method == "PUT")
                {
                    if (req.body.empty())
                    {
                        return dispatch_err(400U, "M_BAD_JSON", "account data body must not be empty");
                    }
                    if (!set_account_data(rt, {path_user, std::string{}, type, req.body, 0U}))
                    {
                        log_diagnostic("account_data.rejected",
                                       {
                                           {"actor",  *user,                            false},
                                           {"type",   type,                             false},
                                           {"reason", "failed to persist account data", false}
                        });
                        return dispatch_err(500U, "M_UNKNOWN", "failed to persist account data");
                    }
                    log_diagnostic("account_data.stored", {
                                                              {"actor", *user, false},
                                                              {"type",  type,  false}
                    });
                    return dispatch_resp(200U, "{}");
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
                        return dispatch_err(404U, "M_NOT_FOUND", "account data not found");
                    }
                    log_diagnostic("account_data.retrieved", {
                                                                 {"actor", *user, false},
                                                                 {"type",  type,  false}
                    });
                    return dispatch_resp(200U, found->content_json);
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
                return dispatch_resp(200U, body.error == canonicaljson::CanonicalJsonError::none ? body.output : "{}");
            }
        }
        return dispatch_err(404U, "M_NOT_FOUND", "room summary not found");
    }

    log_diagnostic("request.route_not_found", {
                                                  {"method", req.method,                                       false},
                                                  {"target", observability::sanitized_http_target(req.target), false},
                                                  {"actor",  *user,                                            false},
                                                  {"status", "404",                                            false}
    });
    return dispatch_err(404U, "M_UNRECOGNIZED", "route not found");
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
    if (sync.response.body.find("secret") != std::string::npos ||
        sync.response.body.find("m.room.encrypted") != std::string::npos)
    {
        return {false, 500U, {}, "sync leaked plaintext event content"};
    }
    return {true, 200U, sync.response.body, {}};
}

} // namespace merovingian::homeserver
