// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
    };
}

[[nodiscard]] auto login_token(std::string const& body) -> std::string
{
    auto const key = std::string{"\"access_token\":\""};
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

[[nodiscard]] auto room_id(std::string const& body) -> std::string
{
    auto const key = std::string{"\"room_id\":\""};
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

[[nodiscard]] auto event_id(std::string const& body) -> std::string
{
    auto const key = std::string{"\"event_id\":\""};
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

[[nodiscard]] auto json_value(std::string const& body, std::string const& key) -> std::string
{
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

} // namespace

SCENARIO("Client-server runtime wraps errors in stable Matrix-style shapes", "[homeserver][client-server]")
{
    GIVEN("a Matrix error")
    {
        WHEN("it is rendered")
        {
            auto const body = merovingian::homeserver::matrix_error("M_FORBIDDEN", "denied");
            auto const response = merovingian::homeserver::LocalHttpResponse{403U, body};

            THEN("the response has a stable Matrix error body")
            {
                REQUIRE(body == R"({"errcode":"M_FORBIDDEN","error":"denied"})");
                REQUIRE(merovingian::homeserver::is_matrix_error_response(response));
            }
        }
    }
}

SCENARIO("Client-server runtime exposes production-named start and flow APIs", "[homeserver][client-server]")
{
    GIVEN("registration-enabled client-server configuration")
    {
        auto const config = registration_enabled_config();

        WHEN("the production client-server runtime and flow APIs are used")
        {
            auto started = merovingian::homeserver::start_client_server(config);
            auto const flow = merovingian::homeserver::run_client_server_flow(config);

            THEN("the runtime starts and the safe client-server flow completes")
            {
                REQUIRE(started.started);
                REQUIRE(flow.ok);
                REQUIRE(flow.value.find("next_batch") != std::string::npos);
                REQUIRE(flow.value.find("secret") == std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server runtime account and device endpoints use real sessions", "[homeserver][client-server]")
{
    GIVEN("a started client-server runtime")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("a user registers and logs in")
        {
            auto const registered = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/register",
                          {},
                          merovingian::tests::registration_json("alice", "CorrectHorse7!")});
            auto const login = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
            auto const token = login_token(login.body);
            auto const whoami = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/whoami", token, {}});
            auto const devices = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/devices", token, {}});
            auto const update = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", "/_matrix/client/v3/devices/DEVICE1", token, R"({"display_name":"Alice laptop"})"});
            auto const updated_devices = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/devices", token, {}});

            THEN("identity, device listing, and device updates work through token validation")
            {
                REQUIRE(registered.status == 200U);
                REQUIRE(login.status == 200U);
                REQUIRE(whoami.status == 200U);
                REQUIRE(whoami.body.find("@alice:example.org") != std::string::npos);
                REQUIRE(devices.status == 200U);
                REQUIRE(devices.body.find("DEVICE1") != std::string::npos);
                REQUIRE(update.status == 200U);
                REQUIRE(updated_devices.body.find("Alice laptop") != std::string::npos);
                REQUIRE(merovingian::homeserver::device_count(runtime, "@alice:example.org") == 1U);
            }
        }
    }
}

SCENARIO("Client-server runtime rejects malformed Matrix JSON request bodies", "[homeserver][client-server]")
{
    GIVEN("a started client-server runtime")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("registration and login receive malformed or incomplete JSON")
        {
            auto const malformed_registration = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/register", {}, R"({"username":"alice","password":)"});
            auto const incomplete_login = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","password":"CorrectHorse7!","auth":{"type":"m.login.registration_token","token":"test-registration-token"}})"});

            THEN("the API fails closed with stable Matrix bad-json errors")
            {
                REQUIRE(malformed_registration.status == 400U);
                REQUIRE(incomplete_login.status == 400U);
                REQUIRE(malformed_registration.body.find("M_BAD_JSON") != std::string::npos);
                REQUIRE(incomplete_login.body.find("M_BAD_JSON") != std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server runtime dispatches complete HTTP requests through Matrix JSON handlers",
         "[homeserver][client-server][http]")
{
    GIVEN("a started client-server runtime")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("registration login and whoami arrive as raw HTTP requests")
        {
            auto const registration_body =
                std::string{merovingian::tests::registration_json("alice", "CorrectHorse7!")};
            auto const registration = merovingian::homeserver::handle_client_server_http_request(
                runtime, "POST /_matrix/client/v3/register HTTP/1.1\r\nHost: example.org\r\nContent-Length: " +
                             std::to_string(registration_body.size()) + "\r\n\r\n" + registration_body);
            auto const login_body = std::string{
                R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"};
            auto const login = merovingian::homeserver::handle_client_server_http_request(
                runtime, "POST /_matrix/client/v3/login HTTP/1.1\r\nHost: example.org\r\nContent-Length: " +
                             std::to_string(login_body.size()) + "\r\n\r\n" + login_body);
            auto const token = login_token(login.body);
            auto const whoami = merovingian::homeserver::handle_client_server_http_request(
                runtime,
                "GET /_matrix/client/v3/account/whoami HTTP/1.1\r\nHost: example.org\r\nAuthorization: Bearer " +
                    token + "\r\nContent-Length: 0\r\n\r\n");

            THEN("the HTTP adapter preserves Matrix status bodies and bearer auth")
            {
                REQUIRE(registration.status == 200U);
                REQUIRE(login.status == 200U);
                REQUIRE(whoami.status == 200U);
                REQUIRE(whoami.body.find("@alice:example.org") != std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server runtime HTTP adapter rejects incomplete and trailing request bodies",
         "[homeserver][client-server][http]")
{
    GIVEN("a started client-server runtime")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("raw HTTP requests do not match their declared content length")
        {
            auto const incomplete = merovingian::homeserver::handle_client_server_http_request(
                runtime,
                "POST /_matrix/client/v3/register HTTP/1.1\r\nHost: example.org\r\nContent-Length: 12\r\n\r\n{}");
            auto const trailing = merovingian::homeserver::handle_client_server_http_request(
                runtime,
                "GET /_matrix/client/v3/account/whoami HTTP/1.1\r\nHost: example.org\r\nContent-Length: 0\r\n\r\nx");

            THEN("the adapter fails closed before route dispatch")
            {
                REQUIRE(incomplete.status == 400U);
                REQUIRE(trailing.status == 400U);
                REQUIRE(incomplete.body.find("M_BAD_REQUEST") != std::string::npos);
                REQUIRE(trailing.body.find("M_BAD_REQUEST") != std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server GET login returns password flow discovery response", "[homeserver][client-server]")
{
    GIVEN("a running client-server homeserver")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("an unauthenticated client queries GET /_matrix/client/v3/login")
        {
            auto const resp = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/login", {}, {}});

            THEN("the server returns 200 with a flows array containing m.login.password")
            {
                REQUIRE(resp.status == 200U);
                REQUIRE(resp.body.find("\"flows\"") != std::string::npos);
                REQUIRE(resp.body.find("\"m.login.password\"") != std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server runtime escapes login and device JSON strings", "[homeserver][client-server]")
{
    GIVEN("a logged-in client-server user with a device value requiring JSON escapes")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .status == 200U);

        WHEN("the device id and display name include quotes and backslashes")
        {
            auto const login = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEV\"\\ICE"})"});
            auto const token = login_token(login.body);
            auto const update = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", R"(/_matrix/client/v3/devices/DEV"\ICE)", token,
                          R"({"display_name":"Alice \"Laptop\" \\ 1"})"});
            auto const devices = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/devices", token, {}});

            THEN("login and device responses remain valid escaped JSON strings")
            {
                REQUIRE(login.status == 200U);
                REQUIRE(login.body.find(R"("device_id":"DEV\"\\ICE")") != std::string::npos);
                REQUIRE(update.status == 200U);
                REQUIRE(devices.status == 200U);
                REQUIRE(devices.body.find(R"("device_id":"DEV\"\\ICE")") != std::string::npos);
                REQUIRE(devices.body.find(R"("display_name":"Alice \"Laptop\" \\ 1")") != std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server runtime room state joined rooms and sync endpoints compose the homeserver path",
         "[homeserver][client-server]")
{
    GIVEN("a logged-in client-server user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.status == 200U);
        auto const token = login_token(login.body);

        WHEN("the user creates a room, sends encrypted-looking content, and syncs")
        {
            auto const room = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
            auto const id = room_id(room.body);
            auto const send = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + id + "/send", token,
                          R"({"type":"m.room.encrypted","content":"secret"})"});
            auto const state = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/rooms/" + id + "/state", token, {}});
            auto const joined = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/joined_rooms", token, {}});
            auto const sync = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync", token, {}});

            THEN("room and sync responses are bounded summaries without plaintext event content")
            {
                REQUIRE(room.status == 200U);
                REQUIRE(send.status == 200U);
                REQUIRE(state.status == 200U);
                REQUIRE(joined.status == 200U);
                REQUIRE(joined.body.find(id) != std::string::npos);
                REQUIRE(sync.status == 200U);
                REQUIRE(sync.body.find(id) != std::string::npos);
                REQUIRE(sync.body.find("event_count") != std::string::npos);
                REQUIRE(sync.body.find("secret") == std::string::npos);
                REQUIRE(sync.body.find("m.room.encrypted") == std::string::npos);
                REQUIRE(merovingian::homeserver::joined_room_count(runtime, "@alice:example.org") == 1U);
            }
        }
    }
}

SCENARIO("Client-server runtime signs sent events and persists their DAG metadata",
         "[homeserver][client-server][events]")
{
    GIVEN("a logged-in client-server user with a room")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.status == 200U);
        auto const token = login_token(login.body);
        auto const room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
        auto const id = room_id(room.body);

        WHEN("state and message events are sent through the runtime")
        {
            auto const state = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/rooms/" + id + "/send", token,
                 R"({"type":"m.room.member","state_key":"@alice:example.org","content":{"membership":"join"}})"});
            auto const message = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + id + "/send", token,
                          R"({"type":"m.room.message","content":{"body":"hi","msgtype":"m.text"}})"});
            auto const state_event_id = event_id(state.body);
            auto const message_event_id = event_id(message.body);
            auto const& store = runtime.homeserver.database.persistent_store;

            THEN("the returned event IDs are reference hashes and persisted rows include signatures and DAG edges")
            {
                REQUIRE(state.status == 200U);
                REQUIRE(message.status == 200U);
                REQUIRE(state_event_id.starts_with("$"));
                REQUIRE(message_event_id.starts_with("$"));
                REQUIRE(state_event_id.find(":") == std::string::npos);
                REQUIRE(message_event_id.find(":") == std::string::npos);
                REQUIRE(store.server_signing_keys.size() == 1U);
                REQUIRE(store.events.size() == 2U);
                REQUIRE(store.events.back().json.find("\"hashes\"") != std::string::npos);
                REQUIRE(store.events.back().json.find("\"signatures\"") != std::string::npos);
                REQUIRE(store.event_signatures.size() == 2U);
                REQUIRE(store.event_edges.size() == 1U);
                REQUIRE(store.event_auth.size() == 1U);
                REQUIRE(store.event_edges.front().event_id == message_event_id);
                REQUIRE(store.event_edges.front().prev_event_id == state_event_id);
                REQUIRE(store.event_auth.front().auth_event_id == state_event_id);
            }
        }
    }
}

SCENARIO("Client-server runtime wires server-blind E2EE key API routes", "[homeserver][client-server][key-api]")
{
    GIVEN("a logged-in client-server device")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.status == 200U);
        auto const token = login_token(login.body);

        WHEN("the device uploads server-blind key material and queries keys")
        {
            auto const upload = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/upload", token,
                          R"({"device_keys":{"sensitive":"curve25519-secret"},"one_time_keys":{}})"});
            auto const query = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/query", token, R"({"device_keys":{}})"});
            auto const unauthenticated = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/upload", {}, R"({"device_keys":{}})"});

            THEN("the runtime path accepts the route without exposing key payloads")
            {
                REQUIRE(upload.status == 200U);
                REQUIRE(query.status == 200U);
                REQUIRE(unauthenticated.status == 401U);
                REQUIRE(upload.body.find("one_time_key_counts") != std::string::npos);
                REQUIRE(query.body.find("device_keys") != std::string::npos);
                REQUIRE(upload.body.find("curve25519-secret") == std::string::npos);
                REQUIRE(merovingian::homeserver::key_api_record_count(runtime, "@alice:example.org") == 2U);
            }
        }
    }
}

SCENARIO("Client-server runtime wires trust and safety report and admin review routes",
         "[homeserver][client-server][trust-safety]")
{
    GIVEN("a logged-in admin client-server user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const admin = merovingian::homeserver::bootstrap_admin_user(runtime.homeserver, "alice", "CorrectHorse7!");
        REQUIRE(admin.ok);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.status == 200U);
        auto const token = login_token(login.body);

        WHEN("the client reports an event and the admin reviews a media target")
        {
            auto const report = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/!room:example.org/report/$event", token,
                          R"({"reason":"spam","score":50})"});
            auto const reports = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/admin/safety/reports", token, {}});
            auto const review = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/admin/safety/review/media/media123", token,
                          R"({"reason":"manual_review"})"});

            THEN("policy decisions are served through runtime auth and persisted as audit/admin rows")
            {
                REQUIRE(report.status == 200U);
                REQUIRE(reports.status == 200U);
                REQUIRE(review.status == 200U);
                REQUIRE(reports.body.find("trust_safety.room.accept_report") != std::string::npos);
                REQUIRE(runtime.homeserver.database.persistent_store.audit_log.size() >= 4U);
                REQUIRE(runtime.homeserver.database.persistent_store.admin_actions.size() == 1U);
                REQUIRE(runtime.homeserver.database.persistent_store.admin_actions.front().action ==
                        "trust_safety.media.quarantine");
            }
        }
    }
}

SCENARIO("Client-server runtime persists client action audit events", "[homeserver][client-server][audit]")
{
    GIVEN("a logged-in client-server device")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.status == 200U);
        auto const token = login_token(login.body);

        WHEN("the device updates metadata and uploads E2EE keys")
        {
            auto const update = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", "/_matrix/client/v3/devices/DEVICE1", token, R"({"display_name":"Alice laptop"})"});
            auto const upload = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/upload", token, R"({"device_keys":{"secret":"value"}})"});

            THEN("client-server audit events are durable and redact key payloads")
            {
                REQUIRE(update.status == 200U);
                REQUIRE(upload.status == 200U);
                auto const& audit = runtime.homeserver.database.persistent_store.audit_log;
                REQUIRE(audit.size() >= 4U);
                REQUIRE(std::ranges::any_of(audit, [](auto const& event) {
                    return event.event_type == "device.updated";
                }));
                REQUIRE(std::ranges::any_of(audit, [](auto const& event) {
                    return event.event_type == "key_api.upload_keys" &&
                           event.reason.find("secret") == std::string::npos;
                }));
            }
        }
    }
}

SCENARIO("Client-server runtime enforces request limits and Matrix-style errors", "[homeserver][client-server]")
{
    GIVEN("a started client-server runtime with tight limits")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.limits.max_body_bytes = 4U;
        runtime.limits.max_requests_per_bucket = 1U;
        runtime.limits.rate_limit_window_requests = 64U;

        WHEN("oversized and repeated requests are sent")
        {
            auto const oversized = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/register",
                          {},
                          merovingian::tests::registration_pipe("alice", "CorrectHorse7!")});
            runtime.limits.max_body_bytes = 4096U;
            auto const first = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/whoami", "bad", {}});
            auto const second = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/whoami", "bad", {}});

            THEN("the client-server API reports stable bounded errors")
            {
                REQUIRE(oversized.status == 413U);
                REQUIRE(merovingian::homeserver::is_matrix_error_response(oversized));
                REQUIRE(first.status == 401U);
                REQUIRE(merovingian::homeserver::is_matrix_error_response(first));
                REQUIRE(second.status == 429U);
                REQUIRE(merovingian::homeserver::is_matrix_error_response(second));
            }
        }
    }
}

SCENARIO("Client-server runtime normalizes route-template rate-limit buckets", "[homeserver][client-server]")
{
    GIVEN("a started client-server runtime with a one-request route bucket")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.limits.max_requests_per_bucket = 1U;
        runtime.limits.rate_limit_window_requests = 64U;

        WHEN("different room IDs hit the same route template")
        {
            auto const first = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/!one:example.org/send", "bad", "{}"});
            auto const second = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/!two:example.org/send", "bad", "{}"});

            THEN("the second request is limited by the normalized route bucket")
            {
                REQUIRE(first.status == 401U);
                REQUIRE(second.status == 429U);
                REQUIRE(runtime.rate_limits.size() == 1U);
            }
        }
    }
}

SCENARIO("Client-server runtime rate-limit buckets reset after the logical window", "[homeserver][client-server]")
{
    GIVEN("a started client-server runtime with a short rate-limit window")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.limits.max_requests_per_bucket = 1U;
        runtime.limits.rate_limit_window_requests = 2U;

        WHEN("a bucket is exhausted and the logical request window advances")
        {
            auto const first = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/whoami", "bad", {}});
            auto const limited = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/whoami", "bad", {}});
            auto const reset = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/whoami", "bad", {}});

            THEN("the bucket becomes available again after the reset window")
            {
                REQUIRE(first.status == 401U);
                REQUIRE(limited.status == 429U);
                REQUIRE(reset.status == 401U);
            }
        }
    }
}

SCENARIO("Sync endpoint returns stream token and event bodies for initial and incremental sync",
         "[homeserver][client-server][sync]")
{
    GIVEN("a logged-in user with a room and a sent event")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const registered = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        auto const token = login_token(login.body);
        auto const room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
        auto const room_id = json_value(room.body, "\"room_id\":\"");
        auto const send = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/send", token,
                      R"({"type":"m.room.message","content":{"body":"hello","msgtype":"m.text"}})"});

        WHEN("initial sync is requested without a since token")
        {
            auto const sync = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync", token, {}});

            THEN("the response contains a stream token next_batch and event bodies in the timeline")
            {
                REQUIRE(sync.status == 200U);
                REQUIRE(sync.body.find("\"next_batch\"") != std::string::npos);
                REQUIRE(sync.body.find("\"events\":") != std::string::npos);
                REQUIRE(sync.body.find("\"timeline\"") != std::string::npos);
                REQUIRE(sync.body.find("\"rooms\"") != std::string::npos);
            }
        }

        WHEN("incremental sync is requested with the stream token from initial sync")
        {
            auto const initial = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync", token, {}});
            auto const since_token = json_value(initial.body, "\"next_batch\":\"");

            auto const incremental = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync?since=" + since_token, token, {}});

            THEN("the incremental response contains a new stream token and no duplicate events")
            {
                REQUIRE(incremental.status == 200U);
                REQUIRE(incremental.body.find("\"next_batch\"") != std::string::npos);
                REQUIRE(incremental.body.find("\"rooms\"") != std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server /versions advertises Matrix spec compatibility to unauthenticated clients",
         "[homeserver][client-server][versions]")
{
    GIVEN("a started client-server runtime")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto runtime = std::move(started.runtime);

        WHEN("an unauthenticated client requests GET /_matrix/client/versions")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/versions", {}, {}});

            THEN("the server answers 200 with a versions array and unstable_features object")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find("\"versions\"") != std::string::npos);
                REQUIRE(response.body.find("\"v1.18\"") != std::string::npos);
                REQUIRE(response.body.find("\"v1.1\"") != std::string::npos);
                REQUIRE(response.body.find("\"unstable_features\"") != std::string::npos);
                REQUIRE_FALSE(merovingian::homeserver::is_matrix_error_response(response));
            }
        }
    }
}

SCENARIO("Sync surfaces invite and leave room categories alongside Matrix-spec top-level stubs",
         "[homeserver][client-server][sync]")
{
    GIVEN("a registered user with an outstanding invite and a left room")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto runtime = std::move(started.runtime);

        auto const register_response = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(register_response.status == 200U);
        auto const user_id = json_value(register_response.body, "\"user_id\":\"");

        auto const login_response = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/login",
                      {},
                      R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":")" + user_id +
                          R"("},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login_response.status == 200U);
        auto const token = login_token(login_response.body);

        runtime.homeserver.database.persistent_store.memberships.push_back(
            {"!invited_room:example.org", user_id, "invite", 0U});
        runtime.homeserver.database.persistent_store.memberships.push_back(
            {"!left_room:example.org", user_id, "leave", 0U});

        WHEN("the user requests /sync")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync", token, {}});

            THEN("the response carries the invite room category and Matrix-spec top-level keys")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find("\"invite\"") != std::string::npos);
                REQUIRE(response.body.find("!invited_room:example.org") != std::string::npos);
                REQUIRE(response.body.find("\"invite_state\"") != std::string::npos);
                REQUIRE(response.body.find("\"account_data\"") != std::string::npos);
                REQUIRE(response.body.find("\"presence\"") != std::string::npos);
                REQUIRE(response.body.find("\"to_device\"") != std::string::npos);
                REQUIRE(response.body.find("\"device_lists\"") != std::string::npos);
                REQUIRE(response.body.find("\"device_one_time_keys_count\"") != std::string::npos);
            }

            THEN("the response keeps rooms.leave as an empty object until include_leave filter support lands")
            {
                REQUIRE(response.body.find("\"leave\":{}") != std::string::npos);
                REQUIRE(response.body.find("!left_room:example.org") == std::string::npos);
            }
        }

        WHEN("the user has more invite memberships than max_sync_rooms")
        {
            runtime.limits.max_sync_rooms = 2U;
            runtime.homeserver.database.persistent_store.memberships.push_back(
                {"!invite2:example.org", user_id, "invite", 0U});
            runtime.homeserver.database.persistent_store.memberships.push_back(
                {"!invite3:example.org", user_id, "invite", 0U});
            runtime.homeserver.database.persistent_store.memberships.push_back(
                {"!invite4:example.org", user_id, "invite", 0U});

            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync", token, {}});

            THEN("the invite section honors the room cap and does not bloat the response")
            {
                REQUIRE(response.status == 200U);
                // First two invites in iteration order should be present
                // (the originally pushed `!invited_room` plus `!invite2`);
                // later invites must be dropped by the cap.
                REQUIRE(response.body.find("!invited_room:example.org") != std::string::npos);
                REQUIRE(response.body.find("!invite2:example.org") != std::string::npos);
                REQUIRE(response.body.find("!invite3:example.org") == std::string::npos);
                REQUIRE(response.body.find("!invite4:example.org") == std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server enforces per-endpoint rate limits with 429 M_LIMIT_EXCEEDED",
         "[homeserver][client-server][rate-limit]")
{
    GIVEN("a started client-server runtime")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto runtime = std::move(started.runtime);

        WHEN("registration is invoked more times than the endpoint policy allows in the window")
        {
            // endpoint_default_rate_limit returns {max_requests=5, window_seconds=60}
            // for POST /_matrix/client/v3/register, so the sixth request inside
            // the wall-clock window must fail closed.
            auto last_status = std::uint16_t{0U};
            auto last_body = std::string{};
            for (auto index = 0; index < 6; ++index)
            {
                auto body = std::string{"{\"username\":\"user"};
                body += std::to_string(index);
                body += "\",\"password\":\"CorrectHorse7!\"}";
                auto const response = merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/register", {}, body});
                last_status = response.status;
                last_body = response.body;
            }

            THEN("the sixth attempt fails closed with 429 and M_LIMIT_EXCEEDED")
            {
                REQUIRE(last_status == 429U);
                REQUIRE(last_body.find("M_LIMIT_EXCEEDED") != std::string::npos);
            }
        }

        WHEN("an unrelated endpoint is hit after exhausting registration's quota")
        {
            for (auto index = 0; index < 6; ++index)
            {
                auto body = std::string{"{\"username\":\"flood"};
                body += std::to_string(index);
                body += "\",\"password\":\"CorrectHorse7!\"}";
                static_cast<void>(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/register", {}, body}));
            }

            auto const versions_response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/versions", {}, {}});

            THEN("the other endpoint runs on its own bucket and is not rate-limited")
            {
                REQUIRE(versions_response.status == 200U);
                REQUIRE_FALSE(merovingian::homeserver::is_matrix_error_response(versions_response));
            }
        }
    }
}

SCENARIO("Rate-limit buckets are scoped per access token to prevent cross-user denial of service",
         "[homeserver][client-server][rate-limit]")
{
    GIVEN("a started runtime with two registered, logged-in users")
    {
        // Register and log in both users with the default loose cap so the
        // setup itself does not collide with the bucket. The tight per-user
        // cap is applied after both users hold valid access tokens.
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const register_alice = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(register_alice.status == 200U);
        auto const register_bob = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("bob", "CorrectHorse7!")});
        REQUIRE(register_bob.status == 200U);

        auto const login_alice = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login_alice.status == 200U);
        auto const alice_token = login_token(login_alice.body);

        auto const login_bob = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@bob:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login_bob.status == 200U);
        auto const bob_token = login_token(login_bob.body);

        runtime.limits.max_requests_per_bucket = 1U;
        runtime.limits.rate_limit_window_requests = 64U;

        WHEN("alice exhausts her authenticated bucket")
        {
            auto const alice_first = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/whoami", alice_token, {}});
            auto const alice_second = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/whoami", alice_token, {}});
            auto const bob_first = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/whoami", bob_token, {}});

            THEN("alice's second request is 429 but bob's first request runs on his own bucket and succeeds")
            {
                REQUIRE(alice_first.status == 200U);
                REQUIRE(alice_second.status == 429U);
                REQUIRE(merovingian::homeserver::is_matrix_error_response(alice_second));
                REQUIRE(bob_first.status == 200U);
            }
        }
    }
}

SCENARIO("Login failures return HTTP 403 M_FORBIDDEN per the Matrix spec", "[homeserver][client-server][login][auth]")
{
    GIVEN("a started client-server runtime with registration enabled")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("login is attempted for a user that does not exist")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@nobody:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});

            THEN("the response is 403 M_FORBIDDEN, not 400")
            {
                REQUIRE(response.status == 403U);
                REQUIRE(response.body.find("M_FORBIDDEN") != std::string::npos);
            }
        }

        WHEN("a user registers and then logs in with the wrong password")
        {
            auto const registered = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/register", {},
                 merovingian::tests::registration_json("alice", "CorrectHorse7!")});
            REQUIRE(registered.status == 200U);

            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"WrongPassword1!","device_id":"DEVICE1"})"});

            THEN("the response is 403 M_FORBIDDEN, not 400")
            {
                REQUIRE(response.status == 403U);
                REQUIRE(response.body.find("M_FORBIDDEN") != std::string::npos);
            }
        }
    }
}

SCENARIO("OPTIONS preflight requests return 200 without requiring an access token",
         "[homeserver][client-server][cors][preflight]")
{
    GIVEN("a started client-server runtime")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("an OPTIONS preflight is sent to the login endpoint without an access token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"OPTIONS", "/_matrix/client/v3/login", {}, {}});

            THEN("the response is 200, not 401, so the browser allows the following POST")
            {
                REQUIRE(response.status == 200U);
            }
        }

        WHEN("an OPTIONS preflight is sent to the register endpoint without an access token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"OPTIONS", "/_matrix/client/v3/register", {}, {}});

            THEN("the response is 200")
            {
                REQUIRE(response.status == 200U);
            }
        }
    }
}

SCENARIO("Well-known client discovery endpoint serves homeserver base URL",
         "[homeserver][client-server][well-known][discovery]")
{
    GIVEN("a started client-server runtime with a configured public base URL")
    {
        auto server = merovingian::config::ServerConfig{};
        server.public_baseurl = "https://matrix.example.org";
        auto security = merovingian::config::SecurityConfig{};
        merovingian::tests::enable_token_registration(security);
        auto config = merovingian::config::Config{server, {}, {}, security};
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("GET /.well-known/matrix/client is requested")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/.well-known/matrix/client", {}, {}});

            THEN("the response is 200 with the homeserver base URL in the Matrix discovery format")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find("m.homeserver") != std::string::npos);
                REQUIRE(response.body.find("https://matrix.example.org") != std::string::npos);
                REQUIRE(response.body.find("base_url") != std::string::npos);
            }
        }
    }
}

SCENARIO("Capabilities endpoint returns server feature flags for authenticated clients",
         "[homeserver][client-server][capabilities]")
{
    GIVEN("a started runtime with a registered and logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/register", {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(reg.status == 200U);

        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST", "/_matrix/client/v3/login", {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.status == 200U);
        auto const token = login_token(login.body);

        WHEN("GET /_matrix/client/v3/capabilities is requested with a valid token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/capabilities", token, {}});

            THEN("the response is 200 with a capabilities object")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find("capabilities") != std::string::npos);
            }
        }

        WHEN("GET /_matrix/client/v3/capabilities is requested without a token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/capabilities", {}, {}});

            THEN("the response is 401")
            {
                REQUIRE(response.status == 401U);
            }
        }
    }
}

SCENARIO("Push rules endpoint returns an empty global ruleset for authenticated clients",
         "[homeserver][client-server][pushrules]")
{
    GIVEN("a started runtime with a registered and logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/register", {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(reg.status == 200U);

        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST", "/_matrix/client/v3/login", {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.status == 200U);
        auto const token = login_token(login.body);

        WHEN("GET /_matrix/client/v3/pushrules/ is requested with a valid token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/pushrules/", token, {}});

            THEN("the response is 200 with a global ruleset")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find("global") != std::string::npos);
            }
        }

        WHEN("GET /_matrix/client/v3/pushrules/ is requested without a token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/pushrules/", {}, {}});

            THEN("the response is 401")
            {
                REQUIRE(response.status == 401U);
            }
        }
    }
}

SCENARIO("User filter API stores and retrieves sync filters", "[homeserver][client-server][filter]")
{
    GIVEN("a started runtime with a registered and logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const reg = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/register", {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(reg.status == 200U);

        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST", "/_matrix/client/v3/login", {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.status == 200U);
        auto const token = login_token(login.body);

        // @alice:example.org percent-encoded as it appears in a real browser URL
        auto constexpr user_filter_url = "/_matrix/client/v3/user/%40alice%3Aexample.org/filter";
        auto constexpr filter_body     = R"({"room":{"timeline":{"limit":50}}})";

        WHEN("POST /user/{userId}/filter is called with a valid filter body")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", user_filter_url, token, filter_body});

            THEN("the response is 200 and contains a filter_id")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find("filter_id") != std::string::npos);
            }
        }

        WHEN("GET /user/{userId}/filter/{filterId} is called with a valid filter_id")
        {
            // Store a filter first so we have a filter_id to look up
            auto const store_resp = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", user_filter_url, token, filter_body});
            REQUIRE(store_resp.status == 200U);
            auto const fid = json_value(store_resp.body, "\"filter_id\":\"");

            auto const get_url  = std::string{user_filter_url} + "/" + fid;
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", get_url, token, {}});

            THEN("the response is 200 and returns the stored filter body")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find("timeline") != std::string::npos);
            }
        }

        WHEN("GET /user/{userId}/filter/{filterId} is called with an unknown filter_id")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", std::string{user_filter_url} + "/nonexistent", token, {}});

            THEN("the response is 404")
            {
                REQUIRE(response.status == 404U);
            }
        }

        WHEN("POST /user/{userId}/filter is called without an access token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", user_filter_url, {}, filter_body});

            THEN("the response is 401")
            {
                REQUIRE(response.status == 401U);
            }
        }
    }
}
