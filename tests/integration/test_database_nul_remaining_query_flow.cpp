// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/core/query_params.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/room_service.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <initializer_list>
#include <optional>
#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace
{
// Declared before the runtime: all SQLite handles close before this cleanup.
class RemainingQuerySqliteFixture final
{
public:
    RemainingQuerySqliteFixture()
        : directory_{
              merovingian::tests::temporary_directory() /
              ("db6-remaining-query-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()))}
        , path_{directory_ / "server.sqlite"}
    {
        if (!std::filesystem::create_directory(directory_))
        {
            throw std::runtime_error{"could not create isolated DB-6 fixture directory"};
        }
    }

    ~RemainingQuerySqliteFixture() noexcept
    {
        auto error = std::error_code{};
        for (auto const suffix : {"", "-wal", "-shm", "-journal"})
        {
            std::ignore = std::filesystem::remove(path_.string() + suffix, error);
        }
        std::ignore = std::filesystem::remove_all(directory_, error);
    }

    RemainingQuerySqliteFixture(RemainingQuerySqliteFixture const&) = delete;
    auto operator=(RemainingQuerySqliteFixture const&) -> RemainingQuerySqliteFixture& = delete;

    [[nodiscard]] auto path() const -> std::filesystem::path const&
    {
        return path_;
    }

private:
    std::filesystem::path directory_;
    std::filesystem::path path_;
};

[[nodiscard]] auto remaining_string_field(merovingian::canonicaljson::Value const& value, std::string_view key)
    -> std::optional<std::string>
{
    namespace json = merovingian::canonicaljson;
    if (!std::holds_alternative<json::Object>(value.storage()))
    {
        return std::nullopt;
    }
    for (auto const& member : std::get<json::Object>(value.storage()))
    {
        if (member.key == key && member.value && std::holds_alternative<std::string>(member.value->storage()))
        {
            return std::get<std::string>(member.value->storage());
        }
    }
    return std::nullopt;
}

[[nodiscard]] auto remaining_json_fields_match(
    std::string const& body, std::initializer_list<std::pair<std::string_view, std::string_view>> expected) -> bool
{
    namespace json = merovingian::canonicaljson;
    auto const parsed = json::parse_lossless(body);
    if (parsed.error != json::ParseError::none || !std::holds_alternative<json::Object>(parsed.value.storage()) ||
        std::get<json::Object>(parsed.value.storage()).size() != expected.size())
    {
        return false;
    }
    return std::ranges::all_of(expected, [&](auto const& field) {
        auto const actual = remaining_string_field(parsed.value, field.first);
        return actual.has_value() && *actual == field.second;
    });
}

[[nodiscard]] auto remaining_canonical_body(std::string const& body) -> std::optional<std::string>
{
    namespace json = merovingian::canonicaljson;
    auto const parsed = json::parse_lossless(body);
    if (parsed.error != json::ParseError::none)
    {
        return std::nullopt;
    }
    auto const serialized = json::serialize_canonical(parsed.value);
    if (serialized.error != json::CanonicalJsonError::none)
    {
        return std::nullopt;
    }
    return serialized.output;
}

[[nodiscard]] auto remaining_state_has_name(std::string const& body, std::string_view name) -> bool
{
    namespace json = merovingian::canonicaljson;
    auto const parsed = json::parse_lossless(body);
    if (parsed.error != json::ParseError::none || !std::holds_alternative<json::Array>(parsed.value.storage()))
    {
        return false;
    }
    return std::ranges::any_of(std::get<json::Array>(parsed.value.storage()), [&](auto const& event) {
        auto const type = remaining_string_field(event, "type");
        auto const state_key = remaining_string_field(event, "state_key");
        if (!type.has_value() || *type != "m.room.name" || !state_key.has_value() || !state_key->empty())
        {
            return false;
        }
        for (auto const& member : std::get<json::Object>(event.storage()))
        {
            if (member.key == "content" && member.value)
            {
                auto const actual = remaining_string_field(*member.value, "name");
                return actual.has_value() && *actual == name;
            }
        }
        return false;
    });
}
} // namespace

// Matrix v1.19 Client-Server API: Profiles, Presence, GET /rooms/{roomId}/state,
// Leaving rooms, Receipts and Fully read markers. This is a dispatcher/SQLite
// regression flow, not a wire-transport or federation conformance test.
SCENARIO("Profile, presence and room identities ignore unrelated raw query text",
         "[database][homeserver][integration][db6][db6-remaining-query-path]")
{
    GIVEN("a real SQLite runtime with a policy-registered and password-authenticated local owner")
    {
        namespace hs = merovingian::homeserver;
        namespace db = merovingian::database;
        namespace json = merovingian::canonicaljson;
        auto security = merovingian::config::SecurityConfig{};
        security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
        merovingian::tests::enable_token_registration(security);
        auto const fixture = RemainingQuerySqliteFixture{};
        auto database = merovingian::config::DatabaseConfig{};
        database.backend = merovingian::config::DatabaseBackend::sqlite;
        database.sqlite_path = fixture.path().string();
        auto started = hs::start_client_server(merovingian::config::Config{
            merovingian::config::ServerConfig{}, merovingian::config::ListenersConfig{}, database, security,
            merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{}});
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const password = std::string(16U, 'r') +
                              std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + char{'A'} +
                              char{'!'};
        auto const owner = hs::register_local_user(runtime.homeserver, "db6_remaining", password,
                                                   merovingian::tests::registration_token);
        REQUIRE(owner.ok);
        auto const session = hs::login_local_user(runtime.homeserver, owner.value, password, "DB6_REMAINING");
        REQUIRE(session.ok);
        auto const profile_path = "/_matrix/client/v3/profile/" + owner.value;
        auto const presence_path = "/_matrix/client/v3/presence/" + owner.value + "/status";

        WHEN("valid profile, presence, state, receipt and leave requests carry unused query values")
        {
            THEN("only the intended path identities are read or persisted and decoder exceptions never escape")
            {
                // No request/body/token is captured in Catch diagnostics. Keep responses
                // optional so an escaping decoder exception cannot cause a later dereference.
                auto const request = [&](std::string method, std::string target, std::string body,
                                         bool authenticated = true) {
                    auto req = hs::LocalHttpRequest{};
                    req.method = std::move(method);
                    req.target = std::move(target);
                    req.body = std::move(body);
                    if (authenticated)
                    {
                        req.access_token = session.value;
                    }
                    auto response = std::optional<hs::LocalHttpResponse>{};
                    auto escaped_invalid_argument = false;
                    try
                    {
                        response = hs::handle_client_server_request(runtime, req).response;
                    }
                    catch (std::invalid_argument const&)
                    {
                        escaped_invalid_argument = true;
                    }
                    CHECK_FALSE(escaped_invalid_argument);
                    CHECK(response.has_value());
                    if (response.has_value())
                    {
                        CHECK(response->status == 200U);
                    }
                    return response;
                };
                auto index = 0U;
                auto const exercise = [&](std::string const& query, bool append_marker) {
                    auto const case_index = index++;
                    INFO("DB-6 flow case index: " << case_index);
                    INFO("query route-marker variant: " << append_marker);
                    auto iteration_ok = true;
                    auto const record = [&](bool okay) {
                        CHECK(okay);
                        iteration_ok = iteration_ok && okay;
                    };
                    auto const send_request = [&](std::string method, std::string target, std::string body,
                                                  bool authenticated = true) {
                        auto response = request(std::move(method), std::move(target), std::move(body), authenticated);
                        iteration_ok = iteration_ok && response.has_value() && response->status == 200U;
                        return response;
                    };
                    auto const with_marker = [&](std::string_view marker) {
                        // No-query controls remain no-query controls, including their path.
                        return query + (append_marker && !query.empty() ? std::string{marker} : std::string{});
                    };
                    auto const suffix = std::to_string(case_index);
                    auto const displayname = "DB-6 owner " + suffix;
                    auto const avatar_url = "mxc://example.org/db6-avatar-" + suffix;
                    auto const presence = case_index % 2U == 0U ? std::string{"unavailable"} : std::string{"online"};
                    auto const status_msg = "DB-6 status " + suffix;
                    auto const display_response =
                        send_request("PUT", profile_path + "/displayname" + with_marker("/displayname"),
                                     "{\"displayname\":\"" + displayname + "\"}");
                    auto const avatar_response =
                        send_request("PUT", profile_path + "/avatar_url" + with_marker("/avatar_url"),
                                     "{\"avatar_url\":\"" + avatar_url + "\"}");
                    std::ignore = display_response;
                    std::ignore = avatar_response;

                    // Explicitly unauthenticated controls exercise the pre-auth profile GET.
                    auto const full_profile = send_request("GET", profile_path + query, {}, false);
                    if (full_profile.has_value())
                    {
                        record(remaining_json_fields_match(
                            full_profile->body, {
                                                    {"displayname", displayname},
                                                    {"avatar_url",  avatar_url }
                        }));
                    }
                    auto const display_field = send_request("GET", profile_path + "/displayname" + query, {}, false);
                    if (display_field.has_value())
                    {
                        record(remaining_json_fields_match(display_field->body, {
                                                                                    {"displayname", displayname}
                        }));
                    }
                    auto const avatar_field = send_request("GET", profile_path + "/avatar_url" + query, {}, false);
                    if (avatar_field.has_value())
                    {
                        record(remaining_json_fields_match(avatar_field->body, {
                                                                                   {"avatar_url", avatar_url}
                        }));
                    }
                    auto const presence_response =
                        send_request("PUT", presence_path + with_marker("/status"),
                                     "{\"presence\":\"" + presence + "\",\"status_msg\":\"" + status_msg + "\"}");
                    std::ignore = presence_response;

                    // Every query/marker pair gets a fresh, real room; leave is last.
                    auto options = hs::CreateRoomOptions{};
                    options.name = "DB-6 room " + suffix;
                    auto const room = hs::create_room(runtime.homeserver, session.value, options);
                    REQUIRE(room.ok);
                    auto const room_path = "/_matrix/client/v3/rooms/" + room.value;
                    auto const joined = std::ranges::any_of(
                        runtime.homeserver.database.persistent_store.memberships, [&](auto const& row) {
                            return row.room_id == room.value && row.user_id == owner.value && row.membership == "join";
                        });
                    REQUIRE(joined);
                    auto const message = send_request("PUT", room_path + "/send/m.room.message/db6-message-" + suffix,
                                                      R"({"body":"DB-6 receipt target","msgtype":"m.text"})");
                    REQUIRE(message.has_value());
                    REQUIRE(message->status == 200U);
                    auto const parsed_message = json::parse_lossless(message->body);
                    auto const valid_message_json = parsed_message.error == json::ParseError::none;
                    REQUIRE(valid_message_json);
                    auto const event_id = remaining_string_field(parsed_message.value, "event_id");
                    REQUIRE(event_id.has_value());
                    REQUIRE_FALSE(event_id->empty());
                    auto const sent_to_intended_room =
                        std::ranges::any_of(runtime.homeserver.database.persistent_store.events, [&](auto const& row) {
                            return row.event_id == *event_id && row.room_id == room.value &&
                                   row.sender_user_id == owner.value;
                        });
                    REQUIRE(sent_to_intended_room);

                    auto const state_control = send_request("GET", room_path + "/state", {});
                    REQUIRE(state_control.has_value());
                    REQUIRE(state_control->status == 200U);
                    auto const canonical_control = remaining_canonical_body(state_control->body);
                    REQUIRE(canonical_control.has_value());
                    auto const control_has_name = remaining_state_has_name(state_control->body, options.name);
                    REQUIRE(control_has_name);
                    auto const state = send_request("GET", room_path + "/state" + with_marker("/state"), {});
                    if (state.has_value())
                    {
                        auto const canonical_state = remaining_canonical_body(state->body);
                        record(canonical_state.has_value() && *canonical_state == *canonical_control);
                        record(remaining_state_has_name(state->body, options.name));
                    }

                    auto const encoded_event = merovingian::core::percent_encode_path_component(*event_id);
                    for (auto const receipt_type : {std::string_view{"m.read"}, std::string_view{"m.read.private"}})
                    {
                        auto const receipt_response = send_request(
                            "POST", room_path + "/receipt/" + std::string{receipt_type} + "/" + encoded_event + query,
                            "{}");
                        std::ignore = receipt_response;
                        // Receipts are in-memory: never invent a durable receipt field.
                        // Exact identity catches both appended query text and double decoding.
                        record(std::ranges::count_if(
                                   runtime.homeserver.database.persistent_store.receipts, [&](auto const& receipt) {
                                       return receipt.room_id == room.value && receipt.user_id == owner.value &&
                                              receipt.receipt_type == receipt_type && receipt.event_id == *event_id;
                                   }) == 1);
                    }
                    auto const fully_read =
                        send_request("POST", room_path + "/receipt/m.fully_read/" + encoded_event + query, "{}");
                    std::ignore = fully_read;
                    record(std::ranges::count_if(
                               runtime.homeserver.database.persistent_store.receipts, [&](auto const& receipt) {
                                   return receipt.room_id == room.value && receipt.user_id == owner.value;
                               }) == 2);

                    auto const leave = send_request("POST", room_path + "/leave" + with_marker("/leave"), "{}");
                    std::ignore = leave;
                    auto const verify_store = [&](db::PersistentStore const& store) {
                        auto const profile = db::find_profile(store, owner.value);
                        record(profile.has_value());
                        if (profile.has_value())
                        {
                            record(profile->user_id == owner.value && profile->displayname == displayname &&
                                   profile->avatar_url == avatar_url);
                        }
                        record(std::ranges::count_if(store.presence_states, [&](auto const& row) {
                                   return row.user_id == owner.value && row.presence == presence &&
                                          row.status_msg == status_msg &&
                                          row.currently_active == (presence == "online");
                               }) == 1);
                        record(std::ranges::count_if(store.memberships, [&](auto const& row) {
                                   return row.room_id == room.value && row.user_id == owner.value &&
                                          row.membership == "leave";
                               }) == 1);
                        auto const marker = std::ranges::find_if(store.account_data, [&](auto const& row) {
                            return row.user_id == owner.value && row.room_id == room.value &&
                                   row.event_type == "m.fully_read";
                        });
                        auto const has_marker = marker != store.account_data.end();
                        record(has_marker);
                        if (has_marker)
                        {
                            record(remaining_json_fields_match(marker->content_json, {
                                                                                         {"event_id", *event_id}
                            }));
                        }
                    };
                    verify_store(runtime.homeserver.database.persistent_store);
                    auto reopened = db::open_sqlite_persistent_store(fixture.path().string());
                    REQUIRE(reopened.ok);
                    verify_store(reopened.store);
                    return iteration_ok;
                };

                // A complete authenticated/public, durable no-query control must
                // succeed before any hostile unused-query value is exercised.
                auto const controls_ok = exercise({}, false);
                REQUIRE(controls_ok);

                auto raw_nul_query = std::string{"?unused=raw"};
                raw_nul_query.push_back('\0');
                raw_nul_query += "text";
                auto const queries = std::vector<std::string>{std::string{}, "?unused=ordinary", "?unused=%00",
                                                              "?unused=%2500", std::move(raw_nul_query)};
                for (auto const& query : queries)
                {
                    // Simple queries expose routing failures; marker-ending values
                    // reach the original decoders instead of stopping at a mere 404.
                    for (auto const append_marker : {false, true})
                    {
                        if (query.empty() && append_marker)
                        {
                            continue;
                        }
                        auto const query_ignored = exercise(query, append_marker);
                        CHECK(query_ignored);
                    }
                }
            }
        }
    }
}

// Matrix v1.19 device management: query text must not change the device selected
// by GET, PUT or password-authenticated DELETE. Real SQLite and real UIA are used.
SCENARIO("Device updates reads and deletion retain their path identity with unused queries",
         "[database][homeserver][integration][db6][db6-nondecoder-device-query]")
{
    GIVEN("a SQLite owner session and separate target device sessions")
    {
        namespace hs = merovingian::homeserver;
        namespace db = merovingian::database;
        namespace json = merovingian::canonicaljson;
        auto security = merovingian::config::SecurityConfig{};
        security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
        merovingian::tests::enable_token_registration(security);
        auto const fixture = RemainingQuerySqliteFixture{};
        auto database = merovingian::config::DatabaseConfig{};
        database.backend = merovingian::config::DatabaseBackend::sqlite;
        database.sqlite_path = fixture.path().string();
        auto started = hs::start_client_server(merovingian::config::Config{
            merovingian::config::ServerConfig{}, merovingian::config::ListenersConfig{}, database, security,
            merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{}});
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const password = std::string(16U, 'd') +
                              std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + char{'A'} +
                              char{'!'};
        auto const owner = hs::register_local_user(runtime.homeserver, "db6_devices", password,
                                                   merovingian::tests::registration_token);
        REQUIRE(owner.ok);
        auto const main_device = std::string{"DB6_QUERY_OWNER"};
        auto const owner_session = hs::login_local_user(runtime.homeserver, owner.value, password, main_device);
        REQUIRE(owner_session.ok);
        auto const password_json = json::serialize_canonical(json::Value{password});
        REQUIRE(password_json.error == json::CanonicalJsonError::none);
        auto const auth_body = "{\"auth\":{\"type\":\"m.login.password\",\"password\":" + password_json.output + "}}";

        WHEN("requests include unrelated query text after the intended device ID")
        {
            THEN("only that device is changed and deleted, with its sessions revoked durably")
            {
                auto index = 0U;
                auto const request = [&](std::string method, std::string target, std::string body,
                                         std::uint32_t expected) {
                    auto response = std::optional<hs::LocalHttpResponse>{};
                    auto escaped = false;
                    try
                    {
                        response = hs::handle_client_server_request(runtime, {std::move(method), std::move(target),
                                                                              owner_session.value, std::move(body)})
                                       .response;
                    }
                    catch (std::exception const&)
                    {
                        escaped = true;
                    }
                    CHECK_FALSE(escaped);
                    CHECK(response.has_value());
                    if (response)
                    {
                        CHECK(response->status == expected);
                    }
                    return response;
                };
                auto const exercise = [&](std::string const& query) {
                    auto const case_index = index++;
                    INFO("device query case index: " << case_index);
                    auto okay = true;
                    auto const record = [&](bool condition) {
                        CHECK(condition);
                        okay = okay && condition;
                    };
                    auto const target_device = "DB6_QUERY_TARGET_" + std::to_string(case_index);
                    // Public login populates both durable device rows and the client's
                    // device cache; local helper login alone does not populate that cache.
                    auto const login_body = json::serialize_canonical(json::Value{
                        json::Object{json::make_member("type", json::Value{std::string{"m.login.password"}}),
                                     json::make_member("user", json::Value{owner.value}),
                                     json::make_member("password", json::Value{password}),
                                     json::make_member("device_id", json::Value{target_device})}
                    });
                    REQUIRE(login_body.error == json::CanonicalJsonError::none);
                    auto const logged_in = request("POST", "/_matrix/client/v3/login", login_body.output, 200U);
                    REQUIRE(logged_in.has_value());
                    REQUIRE(logged_in->status == 200U);
                    auto const login_json = json::parse_lossless(logged_in->body);
                    REQUIRE(login_json.error == json::ParseError::none);
                    auto const target_session = remaining_string_field(login_json.value, "access_token");
                    REQUIRE(target_session.has_value());
                    auto const path = "/_matrix/client/v3/devices/" + target_device;
                    auto const name = "Device query name " + std::to_string(case_index);
                    auto const initial = request("GET", path, {}, 200U);
                    record(initial && remaining_string_field(json::parse_lossless(initial->body).value, "device_id") ==
                                          std::optional<std::string>{target_device});
                    auto const update = request("PUT", path + query, "{\"display_name\":\"" + name + "\"}", 200U);
                    record(update && update->status == 200U);
                    auto const read = request("GET", path + query, {}, 200U);
                    if (read && read->status == 200U)
                    {
                        auto const parsed = json::parse_lossless(read->body);
                        record(parsed.error == json::ParseError::none);
                        record(remaining_string_field(parsed.value, "device_id") ==
                               std::optional<std::string>{target_device});
                        record(remaining_string_field(parsed.value, "display_name") ==
                               std::optional<std::string>{name});
                    }
                    else
                    {
                        record(false);
                    }
                    auto const named_target = [&](db::PersistentStore const& store) {
                        return std::ranges::any_of(store.devices, [&](auto const& device) {
                            return device.user_id == owner.value && device.device_id == target_device &&
                                   device.display_name == name;
                        });
                    };
                    record(named_target(runtime.homeserver.database.persistent_store));
                    {
                        auto reopened = db::open_sqlite_persistent_store(fixture.path().string());
                        REQUIRE(reopened.ok);
                        record(named_target(reopened.store));
                    }
                    // Real password UIA is required: a missing proof cannot be mistaken
                    // for a routing refusal, and the unauthenticated attempt must not delete.
                    auto const challenge = request("DELETE", path + query, "{}", 401U);
                    record(challenge && challenge->status == 401U);
                    record(std::ranges::any_of(
                        runtime.homeserver.database.persistent_store.devices, [&](auto const& device) {
                            return device.user_id == owner.value && device.device_id == target_device;
                        }));
                    auto const removed = request("DELETE", path + query, auth_body, 200U);
                    record(removed && removed->status == 200U);
                    auto const deletion_correct = [&](db::PersistentStore const& store) {
                        auto const target_absent = std::ranges::none_of(store.devices, [&](auto const& device) {
                            return device.user_id == owner.value && device.device_id == target_device;
                        });
                        auto const owner_present = std::ranges::any_of(store.devices, [&](auto const& device) {
                            return device.user_id == owner.value && device.device_id == main_device;
                        });
                        auto const target_sessions_revoked =
                            std::ranges::none_of(store.access_tokens, [&](auto const& token) {
                                return token.user_id == owner.value && token.device_id == target_device &&
                                       !token.revoked;
                            });
                        return target_absent && owner_present && target_sessions_revoked;
                    };
                    record(deletion_correct(runtime.homeserver.database.persistent_store));
                    {
                        auto reopened = db::open_sqlite_persistent_store(fixture.path().string());
                        REQUIRE(reopened.ok);
                        record(deletion_correct(reopened.store));
                    }
                    record(!hs::authenticated_user(runtime.homeserver, *target_session).has_value());
                    record(hs::authenticated_user(runtime.homeserver, owner_session.value).has_value());
                    auto const clean_read = request("GET", path, {}, 404U);
                    record(clean_read && clean_read->status == 404U);
                    return okay;
                };
                REQUIRE(exercise({}));
                auto literal = std::string{"?unused="};
                literal.push_back('\0');
                literal += "/devices";
                auto const queries = std::vector<std::string>{"?unused=ordinary", "?unused=%00/devices",
                                                              "?unused=%2500/devices", literal};
                for (auto const& query : queries)
                {
                    CHECK(exercise(query));
                }
            }
        }
    }
}

// Matrix v1.19 room key backup versions: DELETE must use the version returned
// by creation, not append unrelated query data. Backup encryption/cascade is excluded.
SCENARIO("Deleting a key backup version with unused query text removes the intended durable version",
         "[database][homeserver][integration][db6][db6-nondecoder-backup-query]")
{
    GIVEN("a real SQLite owner and independently created backup version metadata")
    {
        namespace hs = merovingian::homeserver;
        namespace db = merovingian::database;
        namespace json = merovingian::canonicaljson;
        auto security = merovingian::config::SecurityConfig{};
        security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
        merovingian::tests::enable_token_registration(security);
        auto const fixture = RemainingQuerySqliteFixture{};
        auto database = merovingian::config::DatabaseConfig{};
        database.backend = merovingian::config::DatabaseBackend::sqlite;
        database.sqlite_path = fixture.path().string();
        auto started = hs::start_client_server(merovingian::config::Config{
            merovingian::config::ServerConfig{}, merovingian::config::ListenersConfig{}, database, security,
            merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{}});
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const password = std::string(16U, 'b') +
                              std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + char{'A'} +
                              char{'!'};
        auto const owner = hs::register_local_user(runtime.homeserver, "db6_backups", password,
                                                   merovingian::tests::registration_token);
        REQUIRE(owner.ok);
        auto const session = hs::login_local_user(runtime.homeserver, owner.value, password, "DB6_BACKUP_OWNER");
        REQUIRE(session.ok);

        WHEN("DELETE carries unused query values on the created version path")
        {
            THEN("that version disappears in memory and after reopening while a second version survives")
            {
                auto index = 0U;
                auto const request = [&](std::string method, std::string target, std::string body,
                                         std::uint32_t expected) {
                    auto response = std::optional<hs::LocalHttpResponse>{};
                    auto escaped = false;
                    try
                    {
                        response = hs::handle_client_server_request(
                                       runtime, {std::move(method), std::move(target), session.value, std::move(body)})
                                       .response;
                    }
                    catch (std::exception const&)
                    {
                        escaped = true;
                    }
                    CHECK_FALSE(escaped);
                    CHECK(response.has_value());
                    if (response)
                    {
                        CHECK(response->status == expected);
                    }
                    return response;
                };
                auto constexpr prefix = "/_matrix/client/v3/room_keys/version";
                auto const create_version = [&]() {
                    auto const response =
                        request("POST", prefix,
                                "{\"algorithm\":\"m.megolm_backup.v1.curve25519-aes-sha2\",\"auth_data\":{}}", 200U);
                    REQUIRE(response.has_value());
                    REQUIRE(response->status == 200U);
                    auto const parsed = json::parse_lossless(response->body);
                    REQUIRE(parsed.error == json::ParseError::none);
                    auto const version = remaining_string_field(parsed.value, "version");
                    REQUIRE(version.has_value());
                    REQUIRE_FALSE(version->empty());
                    return *version;
                };
                auto const survivor = create_version();
                auto const exercise = [&](std::string const& query) {
                    auto const case_index = index++;
                    INFO("backup query case index: " << case_index);
                    auto okay = true;
                    auto const record = [&](bool condition) {
                        CHECK(condition);
                        okay = okay && condition;
                    };
                    auto const version = create_version();
                    REQUIRE(version != survivor);
                    auto const path = std::string{prefix} + "/" + version;
                    auto const control = request("GET", path, {}, 200U);
                    record(control && remaining_string_field(json::parse_lossless(control->body).value, "version") ==
                                          std::optional<std::string>{version});
                    auto const removed = request("DELETE", path + query, {}, 200U);
                    record(removed && removed->status == 200U);
                    auto const deletion_correct = [&](db::PersistentStore const& store) {
                        return std::ranges::none_of(store.key_backup_versions,
                                                    [&](auto const& row) {
                                                        return row.user_id == owner.value && row.version == version;
                                                    }) &&
                               std::ranges::any_of(store.key_backup_versions, [&](auto const& row) {
                                   return row.user_id == owner.value && row.version == survivor;
                               });
                    };
                    record(deletion_correct(runtime.homeserver.database.persistent_store));
                    {
                        auto reopened = db::open_sqlite_persistent_store(fixture.path().string());
                        REQUIRE(reopened.ok);
                        record(deletion_correct(reopened.store));
                    }
                    auto const clean_read = request("GET", path, {}, 404U);
                    record(clean_read && clean_read->status == 404U);
                    auto const survivor_read = request("GET", std::string{prefix} + "/" + survivor, {}, 200U);
                    record(survivor_read && remaining_string_field(json::parse_lossless(survivor_read->body).value,
                                                                   "version") == std::optional<std::string>{survivor});
                    auto const repeated = request("DELETE", path + query, {}, 200U);
                    record(repeated && repeated->status == 200U);
                    record(deletion_correct(runtime.homeserver.database.persistent_store));
                    return okay;
                };
                REQUIRE(exercise({}));
                auto literal = std::string{"?unused="};
                literal.push_back('\0');
                literal += "/version";
                auto const queries = std::vector<std::string>{"?unused=ordinary", "?unused=%00/version",
                                                              "?unused=%2500/version", literal};
                for (auto const& query : queries)
                {
                    CHECK(exercise(query));
                }
            }
        }
    }
}
